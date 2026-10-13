# RUBY 새 사이트 온보딩 — AI 입력 명세 + 생성 주문서

새 대상 사이트의 설정 파일 5개를 AI에게 생성시킬 때 쓰는 문서입니다.
"문서를 만들어 달라"가 아니라 **"설정 파일을 채워 달라"**고 주문합니다 — 중간 산출물로
문서를 거치면 거기서 설정으로 옮기는 과정에 오류가 한 번 더 들어갑니다.

대상 사이트 ID를 `myapp` 이라고 가정합니다. ID는 `^[a-z][a-z0-9-]{0,31}$` 를
만족해야 합니다 (`defense/app/target_selection.py:22`).

---

## 1. 왜 URL 목록만으로는 부족한가

RUBY 설정은 네 종류의 사실을 요구하는데, URL 목록은 그중 **하나**만 줍니다.

| 요구하는 사실 | URL 목록으로 | 필요한 입력 |
|---|---|---|
| 경로 (routes, loginPath, api_prefixes) | ✅ | URL 목록 |
| JSON 필드명 (emailField, priceField, responseEnvelope) | ❌ | OpenAPI 스펙 |
| JWT 페이로드 구조 (claimMap) | ❌ | 로그인 응답 샘플 |
| DOM 선택자 (login_form_selector 등) | ❌ | 렌더된 HTML |

URL 목록만 주면 체크리스트 22개 항목 중 **완전 충족 7개, 부분 6개, 불가 9개**입니다.
아래 입력 6종을 모두 주면 **~85%**까지 올라갑니다.

---

## 2. 입력 명세

### 입력 ① OpenAPI / Swagger 스펙 — 가장 중요

**얻는 법**: `curl http://<origin>/openapi.json > openapi.json`
(FastAPI·NestJS·Spring 등은 기본 제공. 없으면 Postman 컬렉션이나 라우터 소스로 대체)

**이것으로 채워지는 것**

| 설정 | 소비 코드 |
|---|---|
| `routes[]` 전체 | `defense/app/path_alias.py:314 load_route_document()` |
| `deception.loginPath`, `apiPathPrefixes` | `detection/lib/deceptionEngine.js:269,355` |
| `loginBruteForce.{route, emailField}` | `detection/lib/loginBruteForce.js:53` |
| `passwordResetAbuse.{resetRoute, resetEmailField, securityQuestionRoute, securityQuestionEmailField}` | `detection/lib/passwordResetAbuse.js:63,92` |
| `priceIntegrity.{listRoute, itemRoute, idField, priceField, responseEnvelope}` | `detection/lib/priceIntegrity.js:96,142` |
| `priceTampering.{quantityFields, unitPriceFields, totalFields}` | `detection/lib/priceTampering.js:114` |
| `businessLogic.massAssignmentWhitelist[].fields` | `detection/lib/businessLogicSignatures.js:131` |
| `ordinary_api_prefixes`, `ordinary_api_exact` | `defense/.../deception_headers.py:45-47` |

**없으면**: `priceIntegrity`가 특히 위험합니다. `responseEnvelope.itemsKey`를 틀리면
`ingestProductResponseBody()`가 아무것도 수집하지 않고 `checkPriceDelta()`가 영원히
`{hit:false}`를 돌려줍니다 — **에러 없이 조용히 죽습니다**
(`detection/lib/priceIntegrity.js:58` 주석이 그대로 인정).

---

### 입력 ② 로그인 성공 응답 샘플 (실제 JSON, 토큰 포함)

**얻는 법**
```bash
curl -i -X POST http://<origin>/api/auth/login \
     -H 'Content-Type: application/json' \
     -d '{"email":"test@example.com","password":"..."}'
```
응답 **본문 전체 + `Set-Cookie` 헤더 전부**를 그대로 제공합니다.
JWT는 `payload` 부분만 base64 디코드해서 함께 주면 좋습니다.

> ⚠ **테스트 계정 토큰만** 제공하세요. 운영 계정 토큰이나 실제 사용자 데이터는 주지 않습니다.
> 서명(세 번째 세그먼트)은 지워도 됩니다 — 필요한 건 페이로드의 **키 이름**뿐입니다.

**이것으로 채워지는 것**

| 설정 | 소비 코드 |
|---|---|
| `identity.claimMap.{wrapperKey, id, email, role, basketId}` | `detection/lib/identityMismatch.js:52 decodeClaimedIdentity()` |
| `identity.tokenSources.{bearer, cookieNames}` | `detection/lib/identityMismatch.js:93` |
| `origin_auth_cookies` | `defense/.../overlay.py _origin_headers()` |
| `false_success.py` 수정안 (응답 봉투·쿠키 이름) | `defense/.../sites/account_decoy/false_success.py:16,32,36,74,80` |

**없으면**: `claimMap`이 틀리면 IDOR 탐지(`identityMismatch`)가 죽고,
`roleGatedAccess.js:80`이 `if (!identity.claimMap) return []`로 즉시 빠져나가므로
**권한 우회 탐지까지 연쇄로 무력화**됩니다.

---

### 입력 ③ 렌더된 HTML 2장

**얻는 법**
```bash
curl http://<origin>/ > home.html
# SPA라 서버 HTML이 비어 있으면 브라우저 개발자도구 > Elements 에서 복사
```
- `home.html` — 메인 레이아웃 (네비게이션 메뉴가 보이는 상태)
- `login.html` — 로그인 폼이 **렌더된** 상태

**이것으로 채워지는 것**

| 설정 | 소비 코드 |
|---|---|
| `login_form_selector` | `defense/.../account_recovery.js:73,111,118` |
| `recovery_anchor_selector` | `defense/.../account_recovery.js:120` |
| `menu_selector` | `defense/.../account_recovery.js:132` |

**없으면**: 미끼 UI가 **에러 없이 전혀 뜨지 않습니다**. 오버레이는 정상 동작하는 것처럼
보이는데 에이전트가 미끼를 못 보는 상태가 됩니다.

선택자는 사이트마다 완전히 다릅니다 — 추론이 불가능한 이유:
```
Juice Shop (Angular Material):  "#login-form"  /  "mat-sidenav mat-nav-list"
RUBY Market (React):            ".masthead .session form.inline"  /  "nav.primary"
```

---

### 입력 ④ 프런트엔드 빌드 산출물 1개

**얻는 법**: `index.html`이 로드하는 메인 번들 (`main.js`, `index-*.js` 등) 1개.
크면 앞 200KB만으로도 판정 가능합니다.

**이것으로 채워지는 것**

1. `deception.frontendFlavor` — `"angular-httpclient"` 또는 `"fetch"`
   (`detection/lib/deceptionEngine.js:46 JS_DIALECTS`. 이 둘만 허용 —
   `detection/lib/siteProfile.js:84 FRONTEND_FLAVORS`)

2. **★ Path Alias가 실제로 동작할지 판정** — 가장 교묘한 함정입니다.
   `defense/app/path_alias.py:1314 _context_ok()`는 라우트가 **문자열 리터럴**일 때만
   치환합니다:
   ```js
   fetch("/api/orders")          // ✅ 치환됨
   fetch(`${base}/api/orders`)   // ✅ 치환됨 (템플릿 리터럴)
   fetch("/api/" + resource)     // ❌ 치환 안 됨 → enforce 모드에서 404
   ```
   모르고 `enforce`를 켜면 사이트가 깨집니다.

---

### 입력 ⑤ 서버 스택 정보

평문 몇 줄이면 됩니다.

```
리버스 프록시: nginx 1.27 / Apache 2.4 / Caddy / 없음
앱 서버:       uvicorn(FastAPI) / gunicorn(Django) / Node(Express) / Spring Boot
컨테이너:      Alpine / Debian slim / 베어메탈
실행 사용자:   appuser (uid 10001) / www-data / node
웹루트:        /app / /var/www/html
응답 Server 헤더: (curl -I 결과 그대로)
```

**이것으로 채워지는 것**: CHeaT 사이드카의 `web.server_banner`, `web.x_powered_by`,
`shell.*` 페르소나 (`defense/CHeat-defense-proxy/defense_proxy_v2/profiles.py:PRESETS`).

**없으면**: 배너는 Apache인데 셸 사용자가 node인 식의 모순이 생겨 에이전트가 위장을
눈치챕니다. `preflight.py`가 기동 시 일부 모순을 잡아주지만 전부는 아닙니다.

---

### 입력 ⑥ 권한 모델

```
역할 목록: admin, seller, customer, guest
관리자 전용 라우트:
  GET    /api/admin/users          → admin
  DELETE /api/products/{id}        → admin, seller
  GET    /metrics                  → admin
```

**이것으로 채워지는 것**: `roleGated.sensitiveRoutes[]`의 `requiredRoles`
(`detection/lib/roleGatedAccess.js:47,85`).

**없으면**: `_needsConfirmation`에 `"roleGated"`를 넣고 비활성. 런타임 학습
(`schemaLearning.js:204 observeRoleAccess()`)이 일부 복구하지만 시간이 걸립니다.

---

## 3. 생성 주문서 (복사해서 쓰는 프롬프트)

아래 블록을 그대로 복사하고 `myapp` / `<...>` 부분만 바꿔 넣습니다.
**리포지토리 접근 권한이 있는 AI**에게 주어야 합니다 (CI 테스트 수정과 검증 때문).

````markdown
# 작업: RUBY 프레임워크에 새 대상 사이트 `myapp` 온보딩

## 배경
이 리포지토리(RUBY)는 웹 요청을 탐지(Detection)하고 미끼·지연·경로별칭으로
방어(Defense)하는 시스템입니다. 지금은 Juice Shop과 RUBY Market 두 사이트에
맞춰져 있고, 세 번째 사이트 `myapp`을 추가하려 합니다.

**문서를 만들지 마세요. 설정 파일 자체를 생성하세요.**

## 참고할 기존 사례
`ruby-shop`이 가장 좋은 템플릿입니다 (팀이 직접 온보딩한 두 번째 사이트).
특히 `_needsConfirmation` / `_genericDefaults`로 "확인 안 된 값"을 명시하는 방식을
그대로 따르세요.

- detection/config/site-profiles/ruby-shop.json
- defense/config/ruby-shop-routes.json
- defense/account-response-overlay/config/site-ruby-shop.toml

## 첨부 입력
1. openapi.json — 대상 사이트 API 스펙
2. login-response.txt — 로그인 성공 응답 (헤더 + 본문 + JWT 페이로드 디코드)
3. home.html, login.html — 렌더된 HTML
4. main.js — 프런트엔드 번들
5. stack.txt — 서버 스택 정보
6. roles.txt — 권한 모델

## 산출물 (이 6개만)

### A. 0단계 경로 충돌 보고서 (markdown)
내 사이트의 실제 경로가 RUBY의 미끼 경로와 겹치는지 판정합니다.

대조 대상 1 — `shared/decoy-catalog.json`의 미끼 경로:
  /ftp, /ops, /rest/internal, /internal/ops/runbook,
  /assets/operations.css, /assets/account-recovery.js

대조 대상 2 — `defense/app/decoy_routing.py:24-32 MAZE_DEFAULT_PATTERN`
(이 파일을 직접 읽어 정규식을 그대로 적용할 것)

출력 형식:
- 겹치는 경로 목록
- `DECOY_MAZE_EXCLUDED_ROOT_CHOICES=myapp=<경로들>` 값
- 사이드카용 `MAZE_EXCLUDE=<정규식>` 값 (둘은 쌍으로 설정해야 함)
- `shared/decoy-catalog.json` 수정이 필요한지 여부

### B. detection/config/site-profiles/myapp.json
### C. defense/config/myapp-routes.json
### D. defense/account-response-overlay/config/site-myapp.toml
### E. defense/account-response-overlay/config/overlay-production-myapp-v2.toml
### F. defense/account-response-overlay/config/decoy-production-myapp-v2.toml

## 반드시 지킬 규칙

### 규칙 1 — 추측 금지
입력에 근거가 없는 값은 **채우지 마세요**. 대신:
- Detection 프로파일: 빠진 블록을 `_needsConfirmation` 배열에 명시
- generic.json에서 그대로 가져왔지만 이 사이트에서 검증 안 된 값은
  `_genericDefaults` 배열에 명시

`detection/lib/siteProfile.js:438-443`이 "빠졌는데 `_needsConfirmation`에도 없는"
경우 **로드 시점에 throw** 합니다. 추측해서 채운 값보다 명시적 비활성이 낫습니다.

### 규칙 2 — 경로 문법 (detection/lib/siteProfile.js:101 checkPath)
- 절대경로(`/`로 시작)
- `//`, `\`, CR, LF, `?`, `#` 금지
- 자리표시자는 `:id` 와 `:uuid` 만 (requestMetadata.js:21 normalizePath 결과와 동일)
- `:id`는 경로당 **최대 1개** (numericIdFrom()이 첫 항목만 치환)

### 규칙 3 — Detection 프로파일 스키마
- 파일명 = 대상 ID = `profileId` = `myapp`
- `deception.frontendFlavor` 는 `"angular-httpclient"` 또는 `"fetch"` 만
- 태그는 `^[a-z][a-z0-9-]*(?::[a-z0-9][a-z0-9-]*)+$` ("family:name" 형태)
- 쿠키 이름은 `^[A-Za-z0-9._-]+$` (정규식에 보간되므로)
- `deception.apiPathPrefixes` 는 **뒤 슬래시를 포함** (`"/api/"`).
  `"/api"`로 쓰면 의미가 달라집니다.

### 규칙 4 — routes.json (defense/app/path_alias.py:314)
- 모든 라우트가 `PATH_ALIAS_PREFIXES` 안에 있어야 함 (기본 `/rest/`, `/api/`).
  밖이면 로드 시 ValueError. 다른 접두어가 필요하면 보고서에 적을 것.
- `{var}` = 한 세그먼트, `{tail*}` = 마지막 세그먼트만
- `/__ruby_alias_` 네임스페이스 사용 금지 (예약)
- `"enforce_ready": false` 로 둘 것. 브라우저 실측 전에는 켜지 않습니다.

### 규칙 5 — site TOML (defense/.../site_profile.py:62 __post_init__)
로드 시점에 거부되는 것:
- `login_paths` 가 `decoy_namespaces`(`/ftp`, `/ops`)와 겹침
- `robots_disallow` 가 `decoy_namespaces` **밖**을 가리킴
- `synthetic_success`/`challenge_api` 가 `decoy_namespaces`와 겹침
- `synthetic_success[].kind` 가 다음 5종 밖:
  `ack`, `deluxe_denied`, `empty_basket`, `user_list`, `user_object`

`ordinary_api_prefixes` / `ordinary_api_exact` 를 **반드시 채우세요**.
비우면 모든 2xx API 응답에 미끼 단서 헤더가 붙습니다
(`defense/.../deception_headers.py:45-47`).

`site-generic-example.toml` 을 복사할 경우 `account_api_prefixes` 의
`/api/Users` 는 Juice Shop 잔존물이니 **제거**하세요.

### 규칙 6 — 추가 보고 항목
산출물과 함께 아래를 별도로 보고하세요.

1. **Path Alias 적용 가능 여부**: `main.js`에서 API 경로가 문자열 리터럴로
   나타나는지 확인. 런타임 조립(`"/api/" + x`)이면 enforce 모드를 쓸 수 없으므로
   그 사실과 근거(실제 코드 조각)를 보고.
2. **`false_success.py` 수정 필요 여부**: 입력 ②의 로그인 응답이
   `defense/.../sites/account_decoy/false_success.py:16,32,36,74,80`의 Juice Shop
   형식과 다르면, 어느 줄을 어떻게 바꿔야 하는지 diff로 제시.
3. **CI 계약 테스트 수정안**: 아래 4곳에 `myapp` 추가가 필요합니다.
   - detection/test/siteProfile.test.js:17 `SHIPPED`
   - defense/tests/test_site_profile_contract.py `PAIRED_SITES`, `KNOWN_ROUTE_GAPS`
   - defense/tests/test_decoy_catalog_contract.py `SITE_PROFILES`
   - defense/account-response-overlay/tests/config_reference.json (재생성 명령 안내)
````

---

## 4. 생성 직후 검증

AI 산출물을 받으면 **바로** 돌려보세요. 세 로더 모두 잘못된 값을 로드 시점에 거부합니다.

```bash
cd /home/audrjs/ruby

# ① Detection 프로파일 — 스키마 + 경로 문법 + _needsConfirmation 누락 검사
node -e "
const {loadSiteProfile} = require('./detection/lib/siteProfile');
const p = loadSiteProfile('detection/config/site-profiles/myapp.json');
console.log('OK  disabled:', p.disabledFeatures);
console.log('    generic :', p.genericDefaultFeatures);
"

# ② 경로 별칭 라우트 문서 — 라우트 문법 + 접두어 + enforce_ready 증거
python3 -c "
from defense.app.path_alias import load_route_document
d = load_route_document('defense/config/myapp-routes.json')
print('OK  routes:', len(d.routes), 'enforce_ready:', d.enforce_ready)
"

# ③ 오버레이 사이트 프로파일 — 미끼 네임스페이스 겹침 + synthetic kind 검사
python3 -c "
import sys; sys.path.insert(0, 'defense/account-response-overlay')
from defense.site_profile import load_site_profile
p = load_site_profile('defense/account-response-overlay/config/site-myapp.toml')
print('OK  login:', p.login_paths, 'ordinary:', len(p.ordinary_api_prefixes))
"

# ④ 교차 일치 계약 (대상 추가 후)
python3 -m pytest defense/tests/test_site_profile_contract.py -q
node --test detection/test/siteProfile.test.js
```

`④`가 자동으로 잡아주는 것:
- `myapp.json`의 `deception.loginPath` == `site-myapp.toml`의 `login_paths[0]`
- `identity.tokenSources.cookieNames` ⊆ `origin_auth_cookies`
- `deception.apiPathPrefixes` ⊆ `api_prefixes`
- 프로파일이 선언한 모든 라우트가 `myapp-routes.json`에 존재

마지막 항목이 특히 유용합니다 — 프로파일에 **오타난 라우트**를 적으면 테스트가
잡아내서, 기법이 에러 없이 조용히 무력화되는 상황을 막아 줍니다.

---

## 5. 입력별 충족 매트릭스

어떤 입력을 빠뜨리면 무엇이 안 채워지는지입니다.

| 입력 | 이것만으로 채워지는 항목 | 누적 충족률 |
|---|---|---|
| URL 목록만 | 0단계 충돌 검사, routes.json, 경로 계열 TOML 필드 | ~40% |
| + ① OpenAPI | emailField, priceField, responseEnvelope, massAssignment fields | ~60% |
| + ② 로그인 응답 | claimMap, tokenSources, origin_auth_cookies, false_success 수정안 | ~75% |
| + ③ HTML | 선택자 3종 | ~82% |
| + ④ 번들 | frontendFlavor, **enforce 가능 여부 판정** | ~85% |
| + ⑤ 스택 | CHeaT 페르소나 | ~88% |
| + ⑥ 권한 | roleGated.requiredRoles | ~90% |

**나머지 10%는 AI가 원리적으로 못 하는 영역**입니다.

- `.env` 시크릿 6종 — 운영자가 생성 (`OVERLAY_DETECTOR_KEY`는 정확히 64자 hex,
  재배포 시 값 유지. `defense/.../overlay_bootstrap.py:31`)
- `docker-compose.yml`의 내부 DNS 주소·포트 — 배포 환경
- `enforce_ready` 승격 — 헤드리스 브라우저로 실제 플로우를 돌린 증거가 필요
  (`juice-shop-routes.json`의 `compatibility`가 앱 이미지 sha까지 적어둔 이유)
- 볼륨 초기화 — `OverlayRouteStore.initialize()`가 빈 볼륨만 허용
  (`defense/app/overlay_routing.py:253-255`)

---

## 6. 단계적 적용

설정이 다 만들어져도 한 번에 켜지 마세요. 되돌릴 수 있는 순서가 있습니다.

| 단계 | 설정 | 사이트가 깨질 수 있나 |
|---|---|---|
| 1 | `.env` + compose만, `PATH_ALIAS_MODE=off` | 아니오 |
| 2 | + `site-profiles/myapp.json` | 아니오 |
| 3 | + `myapp-routes.json`, `PATH_ALIAS_MODE=observe` | 아니오 (원본 경로도 통과) |
| 4 | + 사이드카·오버레이, `MAZE_EXCLUDE` 쌍 | 0단계를 빠뜨렸다면 예 |
| 5 | `enforce_ready=true` + `PATH_ALIAS_MODE=enforce` | **예** (원본 경로 404) |

되돌리기는 항상 `PATH_ALIAS_MODE=off`입니다.

1단계 기동 로그에 찍히는 `[siteProfile] profile=myapp feature=... missing -> disabled`
목록이 그대로 2단계 할 일 목록이 됩니다.

---

관련 문서: `ruby-onboarding-guide.html` (설정 파일 작성 절차 상세)
