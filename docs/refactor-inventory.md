# 리팩토링 인벤토리 — Phase 0 기준선 / Phase 1 조사

작성: 2026-10-11 · 기준 커밋: `e8e0ab8`

이 문서는 코드를 수정하지 않는 **조사 보고서**다. 목적은 기능 추가가 아니라
통일·일반화·중복 제거이며, 최종 발표 직전이므로 **기존 동작 보존**이 최우선이다.

조사 결과 지시사항의 전제와 다른 사실 3건이 확인되었다. [전제 수정](#전제-수정) 절을 먼저 볼 것.

---

## 목차

- [전제 수정](#전제-수정)
- [Phase 0. 기준선](#phase-0-기준선)
- [1-A. 미끼 경로 전수 조사](#1-a-미끼-경로-전수-조사)
- [1-B. 중복 로직 목록](#1-b-중복-로직-목록)
- [1-C. 저장소 목록](#1-c-저장소-목록)
- [1-D. Juice Shop 하드코딩 목록](#1-d-juice-shop-하드코딩-목록)
- [1-E. 릴리스 무결성](#1-e-릴리스-무결성)
- [1-F. 환경변수·볼륨·빌드 컨텍스트](#1-f-환경변수볼륨빌드-컨텍스트)
- [1-G. 추가 확인 항목](#1-g-추가-확인-항목)
- [확정된 결정](#확정된-결정)
- [Phase 2~5 설계안](#phase-25-설계안)
- [남은 위험](#남은-위험)

---

## 전제 수정

### (1) `unified.py` / `cycle.py` 는 중복이 아니다 — 합치면 안 된다

`diff -u` 상 **공통 블록이 없다**. 정렬 비교(`comm -12`)로도 겹치는 비공백 줄은
`return {` / `}` / `"""`(unified 쌍 3줄), `return None`(cycle 쌍 1줄) 같은 보일러플레이트뿐이다.
파일명이 같은 base/subclass 2계층이다.

| 파일 | 줄 | 정의 | import |
| --- | --- | --- | --- |
| `defense/unified.py` | 52 | `UnifiedJourney(Journey)` — HMAC proof 상태기계 | `.journey.Journey` |
| `defense/sites/juice_shop/unified.py` | 216 | `UnifiedDefense(Engagement)` — HTTP 정책, `ARCHIVE='/ops/archive'` | `from ...unified import UnifiedJourney` (`:13`) |
| `defense/cycle.py` | 81 | `CycleState`, `CycleJourney(UnifiedJourney)`, `PHASES=4` | `.unified` |
| `defense/sites/juice_shop/cycle.py` | 229 | `CyclicDefense(UnifiedDefense)` | `from ...cycle import CycleJourney, PHASES` + `.unified` |

(경로는 `defense/account-response-overlay/` 기준)

실제 문제는 **디렉터리 이름**이다. `sites/juice_shop/` 의 경로는 전부 `/ops/*`·`/ftp`
(= 오버레이 **자기** 미끼 네임스페이스)이고, 진짜 Juice Shop 종속 파일은
`false_success.py`·`facade.py` **2개뿐**이다. 게다가 `sites/__init__.py:16` 이
`generic` 어댑터조차 `juice_shop.facade` 를 import 하게 만들어 패키지 삭제도 불가능하다.

→ 합치지 말고 `sites/juice_shop/` → `sites/account_decoy/` 로 `git mv` 하고
Juice Shop 종속 2파일만 `sites/juice_shop/` 에 남긴다.

### (2) Defense 의 6개 DB 는 3개 컨테이너에 흩어져 있어 한 파일로 못 합친다

"Node 와 Python 은 다른 컨테이너라 SQLite 파일을 공유하지 않는다"는 근거가
**Python 내부에도 똑같이 적용된다**:

| DB | 컨테이너 | 볼륨 |
| --- | --- | --- |
| `path-alias.sqlite3`, `routes.sqlite3` | `defense` | `defense-alias-data`, `defense-overlay-data` |
| `security.sqlite3`, `events.sqlite3`, `lure-events.sqlite3` | **`overlay-juice` / `overlay-ruby`** (별도 이미지, `read_only: true`, uid 10001) | `overlay-*-data` |
| `defense.db` | **`cheat-juice` / `cheat-ruby`** (별도 이미지, uid 10001) | `cheat-*-data` |

→ "컨테이너당 하나의 DB" 로 재해석해 6개 → 3개로 줄인다.

### (3) `MANIFEST.sha256` 은 이미 깨져 있고, 검증하는 코드가 없다

`sha256sum -c MANIFEST.sha256` → **61개 중 7개 FAILED**:
`INTEGRATION.md`, `README.md`, `defense/account_recovery.js`, `defense/overlay.py`,
`defense/overlay_bootstrap.py`, `tests/test_lure_ui.cjs`, `tests/test_overlay.py`.

추가로 추적 중인 **7개 파일이 아예 커버되지 않는다**:
`config/decoy-production-juice-v2.toml`, `config/decoy-production-ruby-v2.toml`,
`config/overlay-production-juice-v2.toml`, `config/overlay-production-ruby-v2.toml`,
`config/site-ruby-shop.toml`, `tests/test_overlay_bootstrap.py`,
`tests/test_production_config.py` — RUBY Shop 2번째 대상을 추가할 때 갱신 누락.

`grep -rn "MANIFEST.sha256"` → **생성 스크립트·검증 테스트·CI 스텝 전부 없음**.
`grep -rn "RELEASE.json"` → **읽는 코드 0건**. 버전 `0.13.0` 은 `pyproject.toml:3` 과 수동 중복.

→ 현재 이 두 파일은 **거짓 무결성 신호**다. Phase 5 의 "규칙에 맞게 갱신"에는 규칙 자체가 없으므로
생성 스크립트와 CI 검증을 함께 만든다.

---

## Phase 0. 기준선

### 측정 방식: Docker 전용

로컬 호스트에는 의존성이 없고, `defense`(fastapi 0.115 / httpx 0.27.2) 와
overlay(fastapi 0.141.1 / httpx 0.28.1) 는 핀이 충돌해 단일 venv 로 네 스위트를 동시에
돌릴 수 없다. CI 도 Python 3.12(defense·CHeaT) / 3.14(overlay) 로 분리한다.
따라서 호스트를 오염시키지 않고 CI 와 같은 의존성으로 측정한다.
측정 환경: Docker 29.5.3 / Compose v5.1.4.

```bash
# 1) Detection
docker build -t ruby-detection:base ./detection
docker run --rm ruby-detection:base npm test
docker run --rm -e REQUIRE_CRS_BINARY_TESTS=true ruby-detection:base \
  node --test test/crsBinaryIntegration.test.js test/requestInspection.test.js

# 2) Defense — 이미지에 tests/ 가 없으므로 소스 마운트
docker build -t ruby-defense:base ./defense
docker run --rm -v "$PWD:/src" -w /src ruby-defense:base \
  python -m unittest discover -s defense/tests -p 'test_*.py'

# 3) CHeaT v2 — Dockerfile COPY 가 파일 allowlist 라 tests/ 미포함 → 소스 마운트
docker build -t ruby-cheat:base defense/CHeat-defense-proxy/defense_proxy_v2
docker run --rm -v "$PWD/defense/CHeat-defense-proxy/defense_proxy_v2:/src" -w /src \
  ruby-cheat:base python tests/run_all.py

# 4) Overlay — ENTRYPOINT 우회 + pytest 는 test extra 라 실행 시 설치
docker build -t ruby-overlay:base defense/account-response-overlay
docker run --rm --user 0 --entrypoint sh \
  -v "$PWD/defense/account-response-overlay:/src" -w /src ruby-overlay:base \
  -c "pip install --no-cache-dir pytest==9.1.1 pytest-asyncio==1.4.0 pyyaml==6.0.3 && python -m pytest -q"

# 5) 의존성 없는 Node 스위트 — 호스트에서 직접
(cd defense/account-response-overlay && node --test tests/test_lure_ui.cjs)
node --test defense/tests/dashboardPresentation.test.js
node --test defense/tests/capture_api_requests.test.cjs

# 6) 무결성 현황 (Phase 5 비교 기준)
(cd defense/account-response-overlay && sha256sum -c MANIFEST.sha256)
```

### 측정 결과

| 스위트 | 결과 | 비고 |
| --- | --- | --- |
| Detection `npm test` | **237 / 237 pass** ✅ | 이미지 안에서는 CRS 바이너리가 있어 호스트(202개)보다 35개 더 실행된다 |
| Detection CRS 바이너리 (`REQUIRE_CRS_BINARY_TESTS=true`) | **12 / 12 pass** ✅ | |
| Defense `unittest` | **185 / 185 pass** ✅ | `httpx` per-request cookies `DeprecationWarning` 1건 |
| CHeaT v2 `run_all.py` | **17 / 19** ⚠️ | 아래 표 참조 |
| Overlay `pytest -q` | **64 / 64 pass** ✅ | |
| Overlay `test_lure_ui.cjs` | **6 / 6 pass** ✅ | |
| Defense `dashboardPresentation.test.js` | **12 / 12 pass** ✅ | |
| Defense `capture_api_requests.test.cjs` | **6 / 6 pass** ✅ | |
| `sha256sum -c MANIFEST.sha256` | **54 / 61, 7 FAILED** ❌ | **리팩토링 이전부터 깨져 있음** |

### 이미 실패하는 항목 (리팩토링 탓이 아님)

| 항목 | 분류 | 근거 |
| --- | --- | --- |
| CHeaT `test_dashboard_and_preset.py` | **환경 차이** — 컨테이너 기본 사용자(uid 10001)에서만 실패 | `--user 0` 으로 재실행하면 **ALL PASS**. 이 테스트는 `subprocess` 로 `uvicorn dashboard:app` 을 띄우는데, `dashboard.py` 는 운영 이미지 COPY allowlist 에서 의도적으로 제외돼 있고(`Dockerfile:14-16`) 마운트한 소스 트리에 쓰기 권한이 없다 |
| CHeaT `test_xff.py` | **환경 의존 실패 — 보호 단정 5개는 전부 통과, 회귀 확인용 "대조군" 1개만 실패** | 대조군(`tests/test_xff.py:72-74`)은 uvicorn 기본 옵션에서 `X-Forwarded-For` 위조 우회가 **재현되는 것**을 단정한다. 이 환경에서는 `FORWARDED_ALLOW_IPS='*'` 를 줘도 `request.client.host` 가 계속 `127.0.0.1` 로 남아 우회가 재현되지 않는다. 즉 취약점이 없어서 "취약점이 있어야 한다"는 대조군이 실패한다 |
| `MANIFEST.sha256` 7건 | **이미 깨짐** | 전제 수정 (3) 참조 |

> `test_xff.py` 는 GitHub Actions(`ubuntu-26.04`, Python 3.12)에서는 결과가 다를 수 있다.
> 이 환경에 `gh` CLI 가 없어 main 의 CI 상태를 확인하지 못했다. **각 Phase 종료 시 CI 결과로
> 교차 확인**하고, CI 에서도 실패한다면 리팩토링과 무관한 선행 이슈로 별도 처리한다.

**리팩토링 중 깨뜨리면 안 되는 수치**: Detection 237+12, Defense 185, CHeaT 17(root 18),
Overlay 64+6, Defense Node 12+6.

---

## 1-A. 미끼 경로 전수 조사

세 네임스페이스에 **공통 경로가 하나도 없다**. Detection 은 `/rest/internal/*`,
오버레이는 `/ftp` + `/ops/*`, CHeaT 는 프리셋별로 `/internal/`·`/backup/`·`/cgi-bin/`
(apache) 또는 `/_debug/`(nginx) 를 쓴다.

### A-1. Detection — `/rest/internal/*` (Juice Shop `/rest` 차용)

`detection/lib/deceptionEngine.js`

| file:line | 상수 | 값 | 용도 | 사이트 종속 |
| --- | --- | --- | --- | --- |
| `:11` | `INTERNAL_PREFIX` | `/rest/internal` | 트랩 네임스페이스 루트 | **Juice Shop** (`/rest`) |
| `:12` | `TRAP_PREFIX` | `/rest/internal/audit` | 세션별 허니토큰 트랩 링크 | 파생 |
| `:13` | `OPS_PREFIX` | `/rest/internal/ops` | 스크립트·쓰기가능파일 트랩 | 파생 |
| `:14` | `WRITABLE_FILE_PATH` | `/rest/internal/ops/service-backup.conf` | GET→`writable_file_found`, PUT/POST/PATCH→`writable_file_write` | 파생 |
| `:15-18` | `SCRIPT_TRAP_PATHS` | `…/ops/alarm.sh`, `…/ops/disable_crowdstrike.sh` | `script_hint_access` | 파생 |
| `:19` | `SERVED_TRAPS_DIR` | `../deception/served_traps` | 위 2개 본문 | 일반 |
| **`:20`** | **`LOGIN_PATH`** | **`/rest/user/login`** (주석: "Juice Shop 실제 로그인 엔드포인트") | 423 locked 미끼 응답 | **Juice Shop, 하드코딩** |
| `:23` | `FAKE_SSH_CREDS` | `LLM_Admin` / `password123` | 미끼 자격증명 | 일반 |
| `:24-26` | `FAKE_PASSWORD_LIST` | `LLM_*` 8개 | 미끼 비밀번호 목록 | 일반 |
| **`:32`** | **`API_PATH_PREFIXES`** | **`["/rest/", "/api/"]`** | `no_asset_loading` 분모 | **혼합** — `/rest/` 는 Juice, `/api/` 는 RUBY. 뒤 슬래시 때문에 `/rest` 정확히는 불일치 |
| `:33-34` | `API_ASSET_THRESHOLD`, `COVERAGE_MILESTONES` | `3`, `{5,10,15,20,25}` | 임계값 | 일반 |
| `:36-46` | `DECEPTION_SIGNAL_CATALOG` | 9개 신호 | 신호 메타데이터 | 일반 |
| `:54-58` | `TRAP_LINK_VARIANTS` | 3종 라벨/주석 | 트랩 링크 위장 | 일반 |

**경로 재하드코딩**:
`:345` `path.match(/^\/rest\/internal\/audit\/([^/]+)\/([a-f0-9]{12})$/)` — `TRAP_PREFIX`
대신 정규식 리터럴. `:360` 응답 본문 `"…authenticate at /rest/user/login…"` — `LOGIN_PATH`
가 산문 안에 **두 번째로** 박혀 있다. `:518-519` JS 주입에도 스크립트 파일명 재입력.

소비 측 (`detection/server.js`): `:93-98` `PLAINTEXT_BAIT_PATHS` =
`{/robots.txt, /security.txt, /.well-known/security.txt, /metrics}` (일반),
`:1520` HTML 주입, `:1551` plaintext 주입, `:1554` `.js` 주입.

`detection/deception/served_traps/` 는 `alarm.sh`, `disable_crowdstrike.sh` 2개뿐.

미export 상수: `LOGIN_PATH`, `SERVED_TRAPS_DIR`, `API_PATH_PREFIXES`, `TRAP_LINK_VARIANTS`.

### A-2. 오버레이 — `/ftp` + `/ops/*`

경로는 `defense/account-response-overlay/defense/` 기준.

| file:line | 상수 | 값 |
| --- | --- | --- |
| `high_risk.py:17-20` | `RECOVERY`,`MANIFEST`,`LEGACY`,`AUDIT` | `/ops/recovery/accounts`, `/ops/service/manifest`, `/ftp`, `/ops/service/audit` |
| `high_risk.py:24,75` | (인라인) | `/ops/archive` |
| `overlay.py:35-37` | `LURE_SCRIPT_PATH`,`RECOVERY_PATH`,`RECOVERY_LINK` | `/assets/account-recovery.js`, `/ops/recovery/accounts` ← **`high_risk.RECOVERY` 와 중복 정의**, `Link` 헤더 |
| `overlay.py:39` | `DEFAULT_PROFILE_PATH` | `config/site-juice-shop.toml` — **Juice Shop 이 기본값** |
| `sites/juice_shop/engagement.py:18` | `ROOT` | `/ops/recovery` |
| `sites/juice_shop/unified.py:19-20` | `ARCHIVE`,`SERVICE` | `/ops/archive`, `/ops/service` |
| `sites/__init__.py:12-13` | `ProfileSite.docs_path`,`bridge_version` | `/ftp`, `2.4.0` |
| `model.py:46-47` | 기본값 | `/documents`, `/assets/operations.css` |
| `core.py:17` / `facade.py:7` / `gateway_contract.py:4` | 쿠키 | `defense_session` / `defense_auth` / `{defense_session, defense_auth, token}` |

`high_risk.py:21-27` `CONSOLE_CARDS` — 광고되는 미끼 모듈 5개:
`Account Registry→/ops/recovery/accounts`, `Legacy Storage→/ftp`,
`Backup Management→/ops/archive`, `Service Manifest→/ops/service/manifest`,
`Audit Logs→/ops/service/audit`. 브랜드 `Internal Operations Console` (`:31`).

**verbatim 중복 테이블**: 미끼 별칭 매핑이 `high_risk.py:123-125` 와 `overlay.py:275-277`
에 완전히 동일하게 2번 존재 (`/ops/service/session/{login,whoami,logout}` → `profile.login_path`).

`deception_headers.py` 헤더 시나리오 3종: `:37-38` recovery(`X-Recovery-API`),
`:42-43` legacy(`X-Legacy-Storage: /ftp`), `:53-54` service(`X-Internal-API`).
`:46-48` `/swagger`·`/openapi` 의 `startswith` 처리는 **`high_risk.py:175-176` 에 중복**.

`account_recovery.js:9-28` 가 세 경로를 **클라이언트 측에 또 한 번** 재정의.
`facade.py:26` 은 `'User-agent: *\nDisallow: /ftp\n'` 를 하드코딩해
**`profile.robots_disallow` 를 무시**한다.

`overlay.py:290-291` entry/step 판별 집합:
`{/ftp, /ftp/, /ops/recovery/accounts, /ops/service/manifest}` — `/ftp` 는 슬래시 변형을
넣었는데 `/ops/recovery/accounts/` 는 안 넣어서 **`decoy_entry` 가 `decoy_step` 으로
기록되는 실제 버그**가 있다.

### A-3. CHeaT — 프리셋별로 완전히 다름 (이미 설정 주도)

`defense/CHeat-defense-proxy/defense_proxy_v2/profiles.py`:

- `_maze_defaults()` `:43-47` — `paths = ["/internal/","/backup/","/admin/","/config/","/private/"]`,
  `entry_path = "/internal/ops/runbook"`
- `_migration_defaults()` `:68-77` — `api_prefix="/rest/internal"` ← **Detection 의
  `INTERNAL_PREFIX` 와 같은 문자열을 독립적으로 재정의**,
  `login_path="/rest/user/login"` ← **Detection 의 `LOGIN_PATH` 와 같은 문자열 독립 재정의**,
  `bridge_name="legacy-admin-bridge"`, `bridge_version="0.9.3"`,
  `robots_disallow=["/rest/internal/","/admin-bridge/"]`,
  `config_path="/rest/admin/application-configuration"`
- 프리셋 `apache-php` `:82-132` (기본) — `/cgi-bin/`, `/server-status`, `/icons/`,
  Apache 2.4.49 배너, PHP/7.4.19
- 프리셋 `nginx-fastapi` `:144-201` (**검증 안 된 draft**, `:134`) —
  `api_prefix="/api/internal"`, `login_path="/api/auth/login"`, `/_debug/`, `/nginx_status`

`transforms.py`: `:139-140` `MAZE_ENTRY_PATH`/`MAZE_COMMENT_TEXT`,
`:189` `t21_version_path="/rest/admin/application-version"`(**Juice 기본 인자**),
`:426-432` `MAZE_DEFAULT_PATTERN`, `:463-472` `_MAZE_INVENTORY` 가짜 엔드포인트 18개,
`:489` `maze_response(version="Apache/2.4.49 (Unix)")` — **nginx 프리셋에서도 Apache 기본 인자**.

`Defense_proxy.py`: `:412-419` `MAZE_PATHS`←env/프로파일,
`MAZE_ROBOTS_DISALLOW = list(MAZE_PATHS)` (robots 와 판별식이 단일 출처 —
**저장소에서 이미 잘 돼 있는 유일한 사례**), `:428-429` `_MAZE_ROOT_RE`
(주석 `:427`: "`/ftp` 같은 실제 디렉터리를 가리지 않으려고" — 즉 **CHeaT 가 오버레이의
`/ftp` 를 피하려고 의도적으로 제외**), `:1166` 응답에서
`x-ruby-decoy-action`/`x-ruby-decoy-strategies` 제거.

`defense/app/decoy_routing.py`·`defense/app/main.py` 에는 **경로 리터럴이 전혀 없다** —
전략명(`DECOY_STRATEGIES`)과 헤더명(`ACTION_HEADER`, `STRATEGIES_HEADER`, `BLOCK_ACTIONS`)만 있다.

### A-4. 사이트 프로파일 3개 — `robots_disallow` 가 사실상 상수

`defense/account-response-overlay/config/`

| key | `site-juice-shop` | `site-ruby-shop` | `site-generic-example` |
| --- | --- | --- | --- |
| `login_paths` | `["/rest/user/login"]` | `["/api/auth/login"]` | `["/api/auth/login"]` |
| `api_prefixes` | `/api,/rest,/swagger,/openapi` | `/api,/swagger,/openapi` | `/api,/swagger,/openapi` |
| `ordinary_api_prefixes` | `/api/products,/rest/products,/api/quantitys` | `/api/products,/api/search,/api/shops` | `/api/catalog,/api/search` |
| `origin_auth_cookies` | `["token"]` | `["ruby_session","ruby_remember","token"]` | `["session_token"]` |
| **`robots_disallow`** | `/ftp,/ops/recovery/accounts,/ops/service/manifest` | **동일(byte-identical)** | **동일** |
| `decoy_brand` | `Internal Administration` | **`RUBY Market Archive`** | `Internal Administration` |
| `decoy_service` | `Internal Account Registry` | 동일 | 동일 |

`/ftp` 는 `site-ruby-shop.toml:16` 과 `site-generic-example.toml:13` 양쪽에 남은
**Juice Shop 잔재**다. 세 프로파일이 같은 값인 이유는 `site_profile.py:48-50` 이
"`/ftp` 또는 `/ops` 안에 있어야 한다"고 **강제**하기 때문이다.

### A-5. 중복 리터럴 교차 색인

| 리터럴 | 등장 위치 |
| --- | --- |
| `/rest/internal` | `deceptionEngine.js:11`, `:345`(regex); `profiles.py:68,76`; v1 `transforms.py:76-107,289-302` |
| `/rest/user/login` | `deceptionEngine.js:20`, `:360`(산문); `profiles.py:74`; `site-juice-shop.toml:2`; `engagement.py:39`(`/rest/user`) |
| `/ftp` | `high_risk.py:19,88`; `overlay.py:96,290`; `lure_metrics.py:52`; `deception_headers.py:42-43`; `account_recovery.js:20`; `sites/__init__.py:12`; `facade.py:26`; `unified.py:193`; `cycle.py:212`; `site_profile.py:45,48-49`; 3× `site-*.toml`; v1 `transforms.py:259,299` |
| `/ops/recovery/accounts` | `high_risk.py:17`; `overlay.py:36,37,291`; `deception_headers.py:37-38`; `account_recovery.js:14`; 3× `site-*.toml` |
| `/ops/service/manifest` | `high_risk.py:18`; `overlay.py:291`; `deception_headers.py:53-54`; `account_recovery.js:26`; `engagement.py:63`; `unified.py:116`; 3× `site-*.toml` |
| `/assets/operations.css` | `high_risk.py:89`; `overlay.py:98`; `model.py:47`; `facade.py:21` |
| `/internal/ops/runbook` | `profiles.py:44`; `transforms.py:139`; **`.github/workflows/ci.yml:193,219`** |
| `legacy-admin-bridge`, `0.9.3` | `profiles.py:69-70`; v1 `transforms.py:72,287`; `golden_reference.json` 다수 |

---

## 1-B. 중복 로직 목록

### B-1. 미끼 경로 판별 — 4개가 아니라 5개이고, 종류가 서로 다르다

| # | 함수 | 위치 | 반환 | 정규화 | 호출처 |
| --- | --- | --- | --- | --- | --- |
| 1 | `_norm_decoy_path` | `Defense_proxy.py:733-735` | **문자열(집합 키)** | 쿼리/프래그먼트 제거, `/{2,}`→`/`, 뒤 슬래시 전부 제거, **lower()**. `..` 미처리, **퍼센트 디코딩 없음** | `_log_req:826` 1곳 |
| 2 | `_is_local_decoy` | `high_risk.py:87-89` | bool | **전혀 없음** (대소문자 민감) | `high_risk.py:152` 1곳 |
| 3 | `_is_decoy` | `overlay.py:95-98` | bool | **전혀 없음** | `overlay.py:272` 1곳 |
| 4 | `decoy_stage` | `lure_metrics.py:44-52` | **분류 라벨** (`recovery:accounts:7` 등) | 없음. **`re.match`(fullmatch 아님)** → `/ops/recoveryXYZ` 도 매치 | `overlay.py:292` 1곳 |
| **5** | `SiteProfile.__post_init__` Rule 5·6 | `site_profile.py:45,48-49` | 예외 | 없음 | 프로파일 로드 시 |

보너스: `_maze_norm` (`Defense_proxy.py:855-856`) — #1 과 같은 모양이지만
**lower() 도 `//` 축약도 안 한다** (`_MAZE_RE` 가 `re.I` 로 보정).

**#2 와 #3 은 줄바꿈만 다른 완전 복붙**이고, #5 는 #2/#3 에서
`/assets/operations.css` 한 항목만 뺀 사본이다.

#### 합칠 때 반드시 보존해야 할 보안 불변식

- #2/#3 이 정규화를 안 해도 안전한 이유는 **`overlay.py:78-92` `_target()` 이 먼저**
  `//`, `.`/`..` 세그먼트, `\`, `#`, 경로 내 `?`, `%2e/%2f/%5c/%25`(대소문자 무시),
  제어문자, 비-ASCII, 8192바이트 초과를 전부 거부하기 때문이다. `core.py:48-50` 이
  `rb'/[A-Za-z0-9/_.-]*'` 로 한 번 더 거부한다.
  → **공용 모듈로 뽑아 `_target()` 이 없는 곳에서 재사용하면 즉시 우회 가능해진다**
  (`/OPS/...`, `//ops/...`, `/ops/..%2f...`). 공용 함수는 "정규화된 경로를 받는다"는
  전제를 **코드로 강제**해야 한다.
- #1 은 그 게이트가 없어서 인라인으로 lower·`//` 축약을 한다. #1 을 #2/#3 형태로
  바꾸면 대소문자·슬래시 변형으로 **에스컬레이션 카운트를 부풀릴 수 있다**.
- 세그먼트 경계 헬퍼는 이미 있다: `deception_headers.py:12-13 _prefixed(path, prefix)`
  = `path == prefix or path.startswith(prefix + '/')`. 이것을 정본으로 쓴다.
- #4 의 `str.isdecimal()` 은 비-ASCII 숫자를 통과시켜 `emit()` 의
  `[a-zA-Z0-9_:/.-]` 검증에서 `ValueError` 를 던진다. 현재는 `_target()` 의 ASCII
  강제 덕분에 도달 불가. 게이트를 느슨하게 하면 500 이 된다.
- 퍼센트 인코딩은 **5개 중 어디서도 처리하지 않는다**. 유일한 디코딩은
  `_is_traversal_probe` (`Defense_proxy.py:693-712`, 최대 5라운드).

### B-2. `TARGET_CHOICES` 파싱 — 2개 구현, 경계값 불일치

| 항목 | `detection/lib/targetSelection.js` | `defense/app/target_selection.py` |
| --- | --- | --- |
| target ID | `/^[a-z][a-z0-9-]{0,31}$/` (**32자**) `:9` | `[a-z][a-z0-9-]{0,63}` (**64자**) `:19` |
| `runId` | `/^[a-zA-Z0-9:-]{1,100}$/` (**100자**) `:47` | 1–128 `:126`. 단 헤더 경로는 **canonical UUID 강제** `:151-157` |
| `changedAt` | `Date.parse` 유한 `:48` | **길이 1–64만** `:128` |
| 파일 크기 상한 | **없음** | 8192 바이트 `:20,111` |
| URL | `search`/`hash` 금지, 경로 허용, **포트 범위·공백 미검사** | **공백 금지 + 포트 1–65535**, 경로 허용 |
| 파일 없을 때 | **기본값으로 생성** `:76-78` | 기본값 반환, 생성 안 함 `:108` |
| 라벨 | `LABELS` 3개(`legacy`/`ruby-shop`/`juice-shop`) `:10-14` | 없음 |

쓰기: **Detection 만** (`:86-95` temp+rename 원자적, mode 0600).
읽기: Defense 는 `detection-data` 볼륨을 `/app/target-data:ro` 로 마운트 + 요청마다
`X-Ruby-Target-Id`/`X-Ruby-Run-Id` 헤더 (`server.js:1424-1425` → `target_selection.py:139-161`).

### B-3. 오버레이 TOML 16개 → 약 5개

**`config/default.toml` 은 `config/decoy-v2.toml` 과 byte-identical**
(둘 다 sha256 `f3666bb3…aa70fd`, `MANIFEST.sha256:12`·`:13` 에서도 같은 해시).

- **Group 1 — overlay 래퍼 6개(키 6개)**: `max_request_bytes`/`max_response_bytes`/
  `timeout_seconds` 는 **6개 전부 동일**. `origin_url` 3종(4개가 `127.0.0.1:3000` 공유),
  `site_profile` 2종(5:1), `decoy_config` 만 파일별 유일.
  `overlay-v1` vs `overlay-server-v1` 은 **`decoy_config` 1줄만 다르다**.
- **Group 2 — decoy 정책 7개(키 15개)**: **15개 중 11개가 7파일 전부 동일**.
  다른 건 `site_adapter`, `modules`, `secure_cookie`, `run_id`, `audit_path` 5개뿐.
  **결정적**: 7파일의 `[limits]`·`[engagement]`·`[cycle]` 블록 **21개 항목 전부가
  `config.py` 의 dataclass 기본값과 정확히 같다** (`21600/1000/67108864`, `8/4/3`, `3/3`)
  → **77줄이 완전한 no-op**.
- **Group 3 — site 프로파일 3개**: [A-4](#a-4-사이트-프로파일-3개--robots_disallow-가-사실상-상수) 참조.

실제 참조 현황: `overlay-server-v1.toml` 은 **실행 경로에서 참조 0건**
(`INTEGRATION.md:15` 산문만).

### B-4. CHeaT v1 — 실행 참조 0건, 다만 Markdown 참조 16건

`grep -rn "defense_proxy_v1"`(이 문서 제외) → **16건, 전부 `.md` 산문**:

| 파일 | 건수 |
| --- | --- |
| `defense/CHeat-defense-proxy/defense_proxy_v2/REFERENCE.md` | 8 |
| `defense/CHeat-defense-proxy/README.md` | 5 |
| `defense/CHeat-defense-proxy/defense_proxy_v2/README.md` | 1 |
| `defense/CHeat-defense-proxy/defense_proxy_v2/results.md` | 1 |
| `defense/docs/token-gate-plan.md` | 1 |

**비-Markdown 참조는 0건**이다.

그중 `CHeat-defense-proxy/README.md:39` 와 `REFERENCE.md:574-575` 가 가리키는
`defense_proxy_v1/experiments/run_batch9.sh` 는 **이미 깨진 링크**(디렉터리 없음).

빌드·CI·배포는 **전부 v2**: `docker-compose.local.yml:153,173`, `deploy.yml:32`,
`ci.yml:86,89,93`. `docker-compose.yml` 에는 CHeaT 참조 자체가 없다(선빌드 이미지 사용).
`benchmark/` 히트 **0건**. Dockerfile·배포 매니페스트·Python import·JS require **0건**.
v1 디렉터리는 7파일 약 154KB, `tests/`·`Dockerfile` 없음.

→ "참조가 남아 있으면 삭제하지 않는다"는 규칙에 따라 **삭제하지 않고 보고만 한다**.

---

## 1-C. 저장소 목록

### SQLite (실사용 9개 + v1 유물 1개)

| # | 파일 | 소유 컨테이너 | 경로 env | 스키마 | 읽기 | 쓰기 | 볼륨 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `defense.db` | cheat-juice / cheat-ruby | `DEFENSE_DB` (이미지 `ENV /data/defense.db`) | `runs(run,mode,technique,risk_category,action,started)`, `reqs(id,ts,run,method,path,status,defense_action,client_id,defense_plan)` `Defense_proxy.py:785-810` | `dashboard.py:55,89,250-360` (**운영 이미지 제외**) | `init_db:785`, `_log_req:827` (요청마다 새 connect) | prod `cheat-*-data:/data`; **local `/tmp/defense.db`, 볼륨 없음 → 휘발** |
| 2 | `path-alias.sqlite3` | defense | `PATH_ALIAS_DB_PATH` (기본값 없음 → `ValueError`) | `path_alias_client_state`, `path_alias_alias_rows` + 인덱스 3 `path_alias.py:535-556` | `:703,850,897,948,1053` | `:726,750,836,868,908` | `defense-alias-data:/app/alias-data` |
| 3 | `routes.sqlite3` + `.overlay-route-store-initialized` sentinel | defense | `DEFENSE_OVERLAY_STATE_DB` | `overlay_meta(id,key_scope,target_scope)`, `sticky_actor(actor,tier)` `overlay_routing.py:256-261` | `:195,211,215,225` | `:217,262` | `defense-overlay-data:/app/overlay-state` |
| 4 | `security.sqlite3` | **overlay-juice / overlay-ruby** | `DEFENSE_SECURITY_DB` | `security_meta(id,schema_version,store_id,key_scope)`, `quarantine`, `nonces` `security_store.py:28-43` | `detector.py:34,74`, `core.py:100`, `overlay.py:215` | `:93,204,219,229` | `overlay-*-data:/app/state` |
| 5 | `events.sqlite3` | overlay | **env 없음 — TOML `audit_path` 전용** | `events(id,time,kind,run,session,trace,detail)` `audit.py:16-18` | **`cli.py:57` 만** | `core.py:104,203,207` | 같은 `/app/state` |
| 6 | `lure-events.sqlite3` | overlay | **설정 불가 — `security_db` 의 형제로 파생** `overlay.py:216` | `lure_events(id,time,actor,kind,stage)` `lure_metrics.py:17-19` | **운영 독자 0** (테스트만) | `:32-35` | 같은 `/app/state` |
| 7 | `xss-candidates.db` | detection | `XSS_DB_PATH` (compose 미설정) | `cand(key,value,parameter,source,endpoint,origin,first_seen,last_seen,times_seen,byte_size)` + `idx_cand_last` | 자체 모듈 | 자체 모듈 | `detection-data:/app/data` |
| 8 | `xss-confirmed.db` | detection | `XSS_CONFIRMED_DB_PATH` | `evidence(value,parameter,severity,risk_score,origin_session,origin_request,endpoint,first_at,last_at,times,status,note)` | `server.js:907-943` | `server.js:590` | 같은 볼륨 |
| 9 | `xss-reflected.db` | detection | `XSS_REFLECTED_DB_PATH` | 8과 동일 | 같음 | 같음 | 같은 볼륨 |
| — | v1 `defense.db` | (미사용) | `DEFENSE_DB` | `reqs` 에 `client_id`/`defense_plan` 없음 | — | — | — |

### JSON 상태

| 파일 | 소유 | env | 스키마 | 읽기 | 쓰기 |
| --- | --- | --- | --- | --- | --- |
| `target-selection.json` | **detection (유일 writer)** | `TARGET_SELECTION_FILE` | `{targetId, runId, changedAt}` | detection `server.js:461,1407`; **defense `target_selection.py:109` (ro 볼륨)** | `targetSelection.js:86-95` **원자적**(temp+rename, 0600) |
| `schema-learning.json` | detection | `SCHEMA_LEARNING_FILE` | `{version:1, massAssignment, roleGated, identityCandidates}`, 키는 `"<METHOD> <normalizedPath>"` | `businessLogicSignatures.js:126`, `roleGatedAccess.js:123`, `identityMismatch.js:174` | `schemaLearning.js:80` — **비원자적** `writeFileSync`, 2000ms 디바운스 |

`schema-learning.json` 의 `version:1` 은 **읽을 때 검사되지 않는다** (`:66-76`).
`detection/data/` 는 커밋 시 `.gitkeep` 뿐이고 런타임에 위 5개(+WAL/SHM)가 생긴다.

메모리 전용(통합 대상 아님): `defense/app/strategies/state.py` `StrategyStateStore`
(`DEFENSE_STATE_LIMIT`, `DEFENSE_STATE_TTL_SECONDS`), `defense/app/dashboard.py` 이벤트 버퍼.

### 스키마 진화 — 3가지 방식 공존, `schema_migrations` 테이블 없음

1. **`PRAGMA user_version` + fail-closed 검증**
   - `security.sqlite3` — `SCHEMA_VERSION=1`; `_validate()` `:140-168` 이 테이블 집합·
     컬럼 지문·`quick_check`·`store_id`·`key_scope` 를 모두 확인하고 불일치 시 거부.
     `mode=rw` URI 로만 열어 **런타임에 생성·복구하지 않는다**. 파일 0600 + dev/ino 고정.
   - `routes.sqlite3` — `_SCHEMA_VERSION=2` `overlay_routing.py:32`; `initialize()` 는
     **비어있지 않은 디렉터리를 거부**(`:243-244`), **v1→v2 업그레이드 경로 없음**.
2. **`CREATE TABLE IF NOT EXISTS` + 조용한 추가 `ALTER TABLE`** — `defense.db` 뿐.
   저장소 전체에서 `try: ALTER TABLE … except sqlite3.OperationalError` 는
   **`Defense_proxy.py:797-803` 단 한 곳**(`client_id`, `defense_plan` 추가).
   버전 표시 없음, 되돌릴 길 없음, 매 프로세스 시작마다 실행.
   유사 패턴: `dashboard.py:300-307` 이 `SELECT … client_id` 를 try/except 로 감싸고
   5컬럼 `SELECT` 로 폴백.
3. **버전 관리 없음** — `path-alias.sqlite3`(대신 `config_hash` 컬럼으로 재생성 유도;
   **v3 테이블 `path_alias_clients`/`path_alias_client_rows` 가 삭제되지 않고 방치**
   `:533-534`), `events.sqlite3`, `lure-events.sqlite3`, Detection 3종.

### PRAGMA 가 저장소마다 다르다

| 저장소 | WAL | busy_timeout | 기타 |
| --- | --- | --- | --- |
| `defense.db` | ❌ | ❌ | 기본 connect |
| `path-alias.sqlite3` | ✅ | 10000ms | `synchronous=NORMAL`, `BEGIN IMMEDIATE` |
| `routes.sqlite3` | ❌ | ❌ | `timeout=2`, `user_version`, `quick_check` |
| `security.sqlite3` | ❌ | 5000ms | `synchronous=FULL`, `mode=rw` URI, 0600 + dev/ino |
| `events.sqlite3` | `journal_mode=DELETE` | ❌ (`timeout=0.2`) | `max_page_count=16384`, 링버퍼 |
| `lure-events.sqlite3` | ❌ | ❌ (`timeout=1.0`) | 모든 SQLite 예외 무시(텔레메트리) |
| Detection 3종 | ✅ | ❌ | `synchronous=NORMAL`, `node:sqlite` |

---

## 1-D. Juice Shop 하드코딩 목록

### D-1. `policy.json` 에는 knob 이 하나도 없다

`detection/config/policy.json` 의 최상위 키는 `defense.rules` **단 하나**이고, 각 규칙은
`tier`/`min_score`/`max_score`/`min_confirmed_attack_score`/`max_confirmed_attack_score`/
`strategies` 만 갖는다(스키마 검증 `policyEngine.js:14-48`). **라우트 목록·필드
화이트리스트·쿠키명·JWT 클레임명·가격 범위·트랩 경로에 대한 설정 항목이 전무하다.**

유일한 탈-하드코딩 장치는 `schemaLearning.js`(observe→propose→approve) 이고,
**하드코딩이 없을 때만 폴백**으로 쓰인다(`businessLogicSignatures.js:126`,
`roleGatedAccess.js:123`, `identityMismatch.js:174`).
존재하는 env knob 은 deception 전용 3개뿐: `DECEPTION_ENABLED`,
`DECEPTION_TOKEN_TTL_MS`, `DECEPTION_MAX_SESSIONS` (`deceptionEngine.js:115-117`).

### D-2. Detection 모듈별

| 모듈 | 하드코딩 | 비고 |
| --- | --- | --- |
| `businessLogicSignatures.js` | `:35-40` `POST /api/Users`(+trailing-slash 중복 `:36`), `POST /api/Feedbacks`(+`:38`), `PUT /rest/products/:id/reviews`, `PATCH /rest/products/reviews`; `:44` `PUT /api/Products/:id` 필드 `deluxePrice`,`CategoryId`; `:150-153` 범위 `price≥0.01`, **`deluxeprice≥0`**, `quantity 1..100`, `rating 1..5`(주석에 "Zero Stars" 챌린지) | 파일 주석 `:17-21` 이 "WHITELIST/RULES 두 상수만 갈아끼우면 된다"고 **이미 인정**. 상수 export 됨 `:254,257` |
| `roleGatedAccess.js` | `:38-83` `SENSITIVE_ROUTES` 7개 전부 Juice Shop 라우트, `requiredRoles` 전부 리터럴 `'admin'` (`/rest/admin/application-configuration`, `/rest/admin/application-version`, `/metrics`, `/api/Users`, `PUT\|POST\|DELETE /api/Products`) | `:31`→`identityMismatch` 의 JWT 셰이프에 결합, `:104` `claimed.role` |
| `priceTampering.js` | `:34-36` 필드명 집합(`quantity/qty`, `price/unitprice/itemprice`, `totalprice/total/…`), `:39` `AMOUNT_TOLERANCE=0.01` | **라우트 없음**. `:28-31` 이 "Juice Shop 트래픽에서 실제로 관측된 적 없음"을 인정 — 사실상 사문화 |
| `priceIntegrity.js` | `:48-49` `/api/Products`, `/api/Products/:id`; `:52` `PRICE_DROP_RATIO=0.5`; `:77-83` **Juice Shop `{status,data}` JSON 엔벌로프 가정**; `:86-87` `item.id`,`item.price` | 상수 export `:124-126` |
| `loginBruteForce.js` | `:31` `POST /rest/user/login`; `:52` 본문 필드 `email` | `:42` 정확 일치 게이트 → **다른 사이트에서는 전체 기능이 조용히 무력화** |
| `passwordResetAbuse.js` | `:37-38` `POST /rest/user/reset-password`, `GET /rest/user/security-question`; `:65,86` `email` | 같은 무력화 패턴 `:55,80` |
| `identityMismatch.js` | **가장 깊게 결합** — `:63` `payload.data \|\| payload`(Juice Shop `data` 엔벌로프), `:65-68` `data.id`/`data.email`/`data.role`/**`payload.bid`(바스켓 ID, 표준 클레임 아님)**, `:78` **쿠키명 `token`**, `:91,93` `/rest/basket/:id`(정규화 경로 + raw 정규식 **중복**), `:100,102` `/api/Users/:id`(중복), `:116-118` `POST /api/Feedbacks` + 본문 `UserId`, `:136-137` `GET /api/Baskets` + 쿼리 `UserId` | `decodeClaimedIdentity`/`extractToken` 이 `roleGatedAccess.js:31` 에 재export → **한 번 고치면 2개 모듈이 같이 풀린다** |
| `deceptionEngine.js` | [A-1](#a-1-detection--restinternal-juice-shop-rest-차용) 표 전체 + `:318` `LOGIN_PATH` 분기, `:345` 정규식, `:360` 산문, `:516-519` **Angular `this.http.get().subscribe()` 위장** | 서버 측 배선도 하드코딩: `server.js:93-98`, `:1520,1551,1554` |

### D-3. Defense 쪽 사이트 결합

| 위치 | 내용 |
| --- | --- |
| `overlay/defense/config.py:48` | `site_adapter: str = "juice_shop"` — **기본값이 대상 사이트** |
| `config.py:74` | `if self.site_adapter not in {'juice_shop','generic'}` — **닫힌 2값 enum, 사이트 추가 = 코드 수정** |
| `overlay.py:39`, `site_profile.py:74-75`, `deception_headers.py:27` | 기본 프로파일 = `site-juice-shop.toml` |
| `core.py:82,84`, `sites/__init__.py:16` | **모듈 경로 자체가 사이트명**; `generic` 어댑터가 `juice_shop.facade` 를 import |
| `sites/__init__.py:12` | `docs_path: str = '/ftp'` — 챌린지 경로가 dataclass 기본값 |
| `sites/juice_shop/false_success.py:38-40,84-90` | `site_adapter == 'juice_shop'` **런타임 분기** + `/api/Users`, `/api/Users/1`, `/api/Challenges`, `/rest/saveLoginIp`, `/rest/deluxe-membership`, `/rest/basket/1` 및 그 JSON 셰이프 |
| `sites/juice_shop/facade.py:11-12,23,26` | **Juice Shop Challenges JSON 스키마**, `/api/Challenges`, `Disallow: /ftp` 하드코딩 |
| `sites/juice_shop/engagement.py:39-40` | `ctx` 없을 때 폴백 `'/rest/user'`; prefix `('/api/Users','/administration','/account')` |
| `defense/app/path_alias.py:35` | `DEFAULT_PREFIXES=("/rest/","/api/")` — `PATH_ALIAS_PREFIXES` 로 **재정의 가능** ✅ |
| `defense_proxy_v2/transforms.py:189`, `Defense_proxy.py:52` | `t21_version_path="/rest/admin/application-version"` (주석이 "Juice Shop 전용"이라 명시) |
| `defense_proxy_v2/profiles.py` | **이 파일이 탈-하드코딩 장치다** (`TARGET_PRESET`/`TARGET_PROFILE`) ✅ |
| `defense_proxy_v2/dashboard.py:495,812` | `REAL_BACKEND` 기본값 `http://127.0.0.1:3000` (운영 이미지 제외) |

`defense/app/` (메인 Python 프록시) 는 **깨끗하다** — `juice` 리터럴 0건.
대상은 `TARGET_CHOICES`/`TARGET_DEFAULT_ID` 와 `PATH_ALIAS_ROUTES_FILE` 로만 들어온다.

**CI 가 Juice Shop 로직을 전혀 검증하지 않는다**: `integration-check` 는
`python3 -m http.server` 로 `index.html` 하나를 서빙하는 정적 타깃을 쓰고
대상 ID 도 `legacy`/`alternate` 다 (`ci.yml:136-149`).

---

## 1-E. 릴리스 무결성

`defense/account-response-overlay/MANIFEST.sha256` — 61줄, GNU `sha256sum` 형식
(해시 + **공백 2개** + `defense/account-response-overlay/` 기준 상대 경로), 경로 사전순.
커버: 루트 8, `config/` 11, `defense/` 22, `defense/sites/` 9, `deploy/` 3,
`examples/` 1, 패키징 2, `tests/` 5.

`RELEASE.json` — 46줄 평면 JSON. `release: "0.13.0"`(`pyproject.toml:3` 과 **수동 중복**),
`policies: ["unified-v1","cycle-v2"]`, `high_risk_console: "/ops/service"`,
`high_risk_console_cards` 5개 라벨→경로 매핑, `lure_metrics: "state/lure-events.sqlite3"`.
`RELEASE.json` 자체가 매니페스트 `:7` 에 해시로 들어 있다.

현황은 [전제 수정 (3)](#3-manifestsha256-은-이미-깨져-있고-검증하는-코드가-없다) 참조.

Phase 5 에서 재생성이 필요해지는 지점: `sites/juice_shop/` 이름 변경 → 매니페스트
42-48행 무효화; `config/default.toml` 삭제 → 13행; no-op 테이블 삭제 → 9-17행.
**순서 주의**: `RELEASE.json` 이 매니페스트에 해시로 포함되므로 `RELEASE.json` 을 먼저
고치고 매니페스트를 나중에 재생성한다.

---

## 1-F. 환경변수·볼륨·빌드 컨텍스트

| env | 서비스 | prod compose | local compose | 코드 기본값 |
| --- | --- | --- | --- | --- |
| `DEFENSE_DB` | cheat | `/data/defense.db` (`:162,183`) | `/tmp/defense.db` (`:160,180`) | 모듈 디렉터리 (`Defense_proxy.py:140`) |
| `PATH_ALIAS_DB_PATH` | defense | `/app/alias-data/path-alias.sqlite3` (`:105`) | 동일 (`:102`) | 없음 → 오류 |
| `PATH_ALIAS_DB_URL` | — | 미설정 | 미설정 | **거부됨** (`path_alias.py:440-443`). 그런데 `deploy.yml:106,112` 에 `PATH_ALIAS_DB_PASSWORD` 시크릿 배선이 **죽은 채 남아 있다** |
| `DEFENSE_OVERLAY_STATE_DB` | defense | `/app/overlay-state/routes.sqlite3` (`:121`) | 동일 (`:118`) | 같은 값 (`main.py:50`) |
| `DEFENSE_SECURITY_DB` | overlay | `/app/state/security.sqlite3` (`:211,237`) | 동일 (`:206,233`) | `state/security.sqlite3` |
| `DEFENSE_SECRET_FILE` / `DEFENSE_DETECTOR_SECRET_FILE` | overlay | `/app/state/session.key` / `detector.key` | 동일 | `state/*.key` |
| `audit_path` | overlay | **env 아님**, TOML `/app/state/events.sqlite3` | 동일 | `state/events.sqlite3` |
| `OVERLAY_CONFIG` | overlay | `overlay-production-{juice,ruby}-v2.toml` (`:206,232`) | 동일 (`:201,228`) | `config/overlay-v2.toml` |
| `TARGET_SELECTION_FILE` | detection / defense | `/app/data/...` (`:16`) / `/app/target-data/...` (`:96`) | `:13` / `:87` | tmpdir / `None` |
| `SCHEMA_LEARNING_FILE` | detection | `/app/data/schema-learning.json` (`:24`) | 동일 (`:21`) | `detection/data/...` |
| `XSS_DB_PATH`, `XSS_CONFIRMED_DB_PATH`, `XSS_REFLECTED_DB_PATH`, `XSS_STORE`, `POLICY_CONFIG_PATH` | detection | **전부 미설정** (코드 기본값 사용) | 미설정 | `detection/data/*`, `config/policy.json` |
| `PATH_ALIAS_ROUTES_FILE` | defense | `/app/config/juice-shop-routes.json` (`:101`) | 동일 (`:98`) | `""` |

볼륨: `detection-data:/app/data`(detection rw) / `:/app/target-data:ro`(defense),
`defense-alias-data:/app/alias-data`, `defense-overlay-data:/app/overlay-state`,
`cheat-*-data:/data`, `overlay-*-data:/app/state`.
overlay 컨테이너는 `read_only: true` + tmpfs `/tmp` + uid 10001 로 굳어 있다.
prod compose 에는 **bind mount 가 전혀 없다** (named volume 만).

### 빌드 컨텍스트 — Phase 2 의 핵심 제약

| Dockerfile | 컨텍스트 | COPY |
| --- | --- | --- |
| `detection/Dockerfile` | `./detection` | `:66 COPY . .` (트리 전체) |
| `defense/Dockerfile` | `./defense` | `:5 COPY app ./app`, `:6 COPY config ./config` — **allowlist** |
| `account-response-overlay/Dockerfile` | `./defense/account-response-overlay` | `:8 COPY defense ./defense`, `:9 COPY config ./config` — **allowlist** |
| `defense_proxy_v2/Dockerfile` | `./defense/CHeat-defense-proxy/defense_proxy_v2` | `:16 COPY Defense_proxy.py proxy_core.py transforms.py profiles.py preflight.py ./` — **파일 단위 allowlist** |

→ **루트 `shared/` 는 네 이미지 어디에서도 COPY 할 수 없다** (Docker 가 `COPY ../` 금지).
컨텍스트를 루트로 올리려면 두 compose + `ci.yml` 의 4개 `docker build` + `deploy.yml`
매트릭스 + overlay 자체 `deploy/compose.yaml`(이미 `context: ..`) 을 모두 고쳐야 하고,
루트 컨텍스트는 `benchmark/` 까지 끌어오므로 루트 `.dockerignore` 가 새로 필요하다
(현재 루트에 없고 overlay 디렉터리에만 있다).

---

## 1-G. 추가 확인 항목

보고만 하고 임의로 고치지 않는다.

### (a) `X-Ruby-Decoy-Action` / `X-Ruby-Decoy-Strategies` 외부 노출 — 현재 제거됨 ✅

`Defense_proxy.py:1166` 이 응답에서 두 헤더를 제거하고, `defense/app/main.py:1149` 가
`decoy_*` 전략명을 공개 응답에서 제거한다. `ci.yml:210-212` 가
`applied.includes('decoy_maze')` 와 `response.headers.has('x-ruby-decoy-action')` 를
**실패 조건으로 단정**하므로 회귀는 CI 가 잡는다. 조치 불필요.

### (b) 고정 문자열의 미끼 지문 가능성 — 구조적으로는 일부만 시드화 가능 ⚠️

- `legacy-admin-bridge` + `0.9.3`: `profiles.py:69-70` 의 프로파일 값이고
  `_deep_merge`/`build_profile`(`:207,227`) + `TARGET_PROFILE` env 로
  **배포별 치환이 이미 가능**하다. 단 `tests/golden_reference.json` 과
  `tests/test_golden.py` 가 이 값을 골든으로 고정하고 있어 시드화하면 골든 테스트가 깨진다.
- `RUBY Market Archive`: `site-ruby-shop.toml:17` **1곳뿐** → 프로파일 값이므로 안전.
- 반대로 **`Internal Account Registry` 는 3개 프로파일 전부 동일**하고,
  `Internal Operations Console`(`high_risk.py:31`),
  `Account migration records`(`engagement.py:19`),
  `/ops/service/resources/{access-policy.json,release-notes.txt}`(`unified.py:26`),
  `Apache/2.4.49 (Unix)` 기본 인자(`transforms.py:489`)는 **코드 리터럴**이라 현재 시드화 불가.
- 가장 강한 지문은 **경로 자체**(`/ops/recovery/accounts` 등)인데, 이것은 `RELEASE.json` 에도
  적혀 있고 `account_recovery.js` 로 클라이언트에 노출된다. 경로 시드화는 Phase 2 카탈로그가
  생기면 비로소 가능해진다 — **이번 범위 외, 후속 작업으로 제안**.

---

## 확정된 결정

| # | 결정 | 내용 |
| --- | --- | --- |
| D1 | **카탈로그 = 원본 1개 + 생성 사본 + CI drift 검사** | `shared/decoy-catalog.json` 이 유일한 편집 원본. 빌드 컨텍스트는 건드리지 않고 Dockerfile 변경은 CHeaT COPY 1줄만 |
| D2 | **DB = 컨테이너당 1개 (Python 6→3, Node 4→1)** | "Python 6→1" 은 컨테이너 경계를 넘으므로 재해석. 공용 접근 모듈·`schema_migrations` 는 전부 도입 |
| D3 | **`target-selection.json` 소유자 = Detection** | Defense 는 계속 읽기 전용. 양쪽 검증 경계값을 통일하고 계약 테스트로 CI 고정. HTTP API 로 바꾸지 않음 |
| D4 | **Detection 일반화 범위 = `deceptionEngine.js` + 판별 함수까지** | 나머지 7개 모듈은 [1-D](#1-d-juice-shop-하드코딩-목록) 표로 현황만 문서화하고 후속 작업으로 분리 |
| D5 | **`MANIFEST.sha256`/`RELEASE.json` = 재생성 + 생성 스크립트 + CI 검증** | `scripts/gen_manifest.sh` 신규 + `ci.yml` 에 `sha256sum -c` 추가 + 미커버 7파일 포함 |
| D6 | **베이스라인 = Docker 전용** | 로컬 호스트에 의존성 설치하지 않음 |
| D7 | **`INTEGRATION.md` 신규 작성** | 루트에 없던 파일. Phase 5 에서 새로 만든다 |

---

## Phase 2~5 설계안

### Phase 2. 미끼 경로 통일 + 사이트 일반화

#### 2-1. 카탈로그 위치

루트 `shared/` 가 COPY 불가하므로 **단일 편집 원본 + 서비스별 생성 사본 + CI drift 검사**:

```text
shared/decoy-catalog.json                                        ← 사람이 고치는 유일한 원본
scripts/sync-decoy-catalog.sh                                    ← 원본 → 4개 사본 복사/검사
detection/config/decoy-catalog.json                              (생성물, COPY . . 로 자동 포함)
defense/config/decoy-catalog.json                                (생성물, COPY config 로 포함)
defense/account-response-overlay/config/decoy-catalog.json       (생성물, COPY config 로 포함)
defense/CHeat-defense-proxy/defense_proxy_v2/decoy-catalog.json  (생성물, Dockerfile COPY 에 1줄 추가)
```

- Dockerfile 변경은 **CHeaT 의 COPY 줄 1개뿐**. compose·CI·deploy 컨텍스트는 그대로.
- 사본은 커밋하고, CI 에 `scripts/sync-decoy-catalog.sh --check` 스텝을 추가해
  drift 를 실패로 만든다. 사본 상단에 손으로 고치지 말라는 헤더 주석을 넣는다.
- 단일 출처 보장은 "파일이 하나"가 아니라 "CI 가 동일성을 강제"로 달성한다.

#### 2-2. 카탈로그 스키마 (초안)

```jsonc
{
  "schemaVersion": 1,
  "namespaces": {                 // 미끼 네임스페이스 — 소유자별로 분리
    "overlay":   { "roots": ["/ftp", "/ops"], "assets": ["/assets/operations.css",
                                                         "/assets/account-recovery.js"] },
    "detection": { "roots": ["/rest/internal"] },
    "cheat":     { "roots": ["/internal", "/backup", "/admin", "/config", "/private"] }
  },
  "entries": [                    // 진입/단계 경로
    { "path": "/ftp",                     "ns": "overlay", "stage": "entry", "family": "legacy"   },
    { "path": "/ops/recovery/accounts",   "ns": "overlay", "stage": "entry", "family": "recovery" },
    { "path": "/ops/service/manifest",    "ns": "overlay", "stage": "entry", "family": "service"  },
    { "path": "/ops/archive",             "ns": "overlay", "stage": "step",  "family": "archive"  },
    { "path": "/ops/service/audit",       "ns": "overlay", "stage": "step",  "family": "service"  },
    { "path": "/internal/ops/runbook",    "ns": "cheat",   "stage": "entry", "family": "maze"     }
  ],
  "identity": { "service": "Internal Account Registry",
                "consoleBrand": "Internal Operations Console" },
  "headers": { "action": "x-ruby-decoy-action", "strategies": "x-ruby-decoy-strategies",
               "recoveryApi": "X-Recovery-API", "legacyStorage": "X-Legacy-Storage",
               "internalApi": "X-Internal-API" },
  "cookies": { "decoySession": "defense_session", "decoyAuth": "defense_auth" }
}
```

사이트별 차이(`login_paths`, 선택자, `api_prefixes`, `robots_disallow`, `decoy_brand`,
`origin_auth_cookies`)는 **계속 `site-*.toml` 에만** 둔다. 카탈로그는 사이트 무관한
"우리 미끼의 모양"만 담는다. 코드에 `juice`/`ruby` 분기를 두지 않는다.

#### 2-3. 공용 판별 모듈 — Python 1개 / Node 1개

Python `defense/shared/decoy_paths.py` (카탈로그와 같은 사본 방식):

```python
def is_decoy_path(path, *, namespace=None, catalog=CATALOG) -> bool   # B-1 #2/#3/#5 대체
def decoy_stage(path, *, catalog=CATALOG) -> str                       # B-1 #4 대체
def normalize_decoy_key(path) -> str                                   # B-1 #1 대체
```

- 세그먼트 경계는 기존 `deception_headers.py:12-13 _prefixed()` 를 정본으로 사용.
- `is_decoy_path` 는 **정규화된 경로를 전제**한다. 이를 코드로 강제: 입력이
  `rb'/[A-Za-z0-9/_.-]*'`(= `core.py:48-50` 과 동일 규칙)를 벗어나면 `ValueError`.
  → `_target()` 이 없는 곳에서 재사용해도 우회가 불가능해진다.
- `normalize_decoy_key` 는 #1 의 동작(쿼리/프래그먼트 제거, `//` 축약, 뒤 슬래시 제거,
  lower)을 **그대로** 유지한다. 에스컬레이션 카운트 동작 보존이 목적.
- `decoy_stage` 는 `re.match` → **`re.fullmatch`**, `/ftp` 의 bare `startswith` → 세그먼트
  경계, `isdecimal()` → `[0-9]+` 로 고친다. **동작 변경이므로 별도 커밋**으로 분리하고
  테스트를 함께 바꾼다.
- `overlay.py:290-291` 의 entry 집합을 카탈로그의 `stage=="entry"` 로 대체하면
  `/ops/recovery/accounts/` 가 `decoy_entry` 로 올바르게 분류된다 — **동작 변경 커밋 분리**.

Node `detection/lib/decoyPaths.js`: `isDecoyPath(path, ns?)`, `decoyNamespaceOf(path)` —
같은 카탈로그를 읽는다.

#### 2-4. `site_profile.py` 일반화

`SiteProfile` 에 `decoy_namespaces: tuple[str, ...]` 필드를 추가하고
(기본값은 카탈로그의 `namespaces.overlay.roots`), Rule 5·6 을 다시 쓴다:

```python
# Rule 5: 로그인 경로는 선언된 미끼 네임스페이스와 겹칠 수 없다
if any(_prefixed(p, ns) for p in self.login_paths for ns in self.decoy_namespaces):
    raise ValueError('login path must not overlap the decoy namespace')
# Rule 6: robots 단서는 선언된 미끼 네임스페이스 안에 있어야 한다
if any(not any(_prefixed(p, ns) for ns in self.decoy_namespaces)
       for p in self.robots_disallow):
    raise ValueError('robots clues must target the local decoy')
```

Rule 1~4(절대경로, `//` 금지, `\` 금지, 개행 금지, 단순 토큰, 선택자·미끼 신원 필수)는
**문자 그대로 유지**한다. `default_site_profile()` 의 Juice Shop 하드코딩은
`DEFAULT_SITE_PROFILE` env 로 바꾸고 기본값만 Juice 로 둔다(동작 보존).

`site-ruby-shop.toml` / `site-generic-example.toml` 의 `/ftp` 는
`decoy_namespaces = ["/ops"]` + `robots_disallow = ["/ops/recovery/accounts",
"/ops/service/manifest"]` 로 정리한다. **`facade.py:26` 의 하드코딩 robots 도 같이 고친다.**

#### 2-5. Detection 연동 — 기존 deception 파이프라인에 신호 1개 추가

Detection 은 Defense 앞단이라 `/ftp`·`/ops/*`·`/internal/*` 요청을 **먼저 본다**.
새 채점 경로를 만들지 않고 이미 있는 honey 신호 파이프라인에 올린다.

- `deceptionEngine.js` `DECEPTION_SIGNAL_CATALOG` 에
  `decoy_path_hit: { evidenceLevel: "medium", scored: true, scoreTarget: "attack" }` 추가.
- `inspectRequest()` 에서 `isDecoyPath(path)` 가 참이면 이 신호를 발생시킨다.
- `classifier.js` 의 `ATTACK_HONEY_POINTS` 에 `decoy_path_hit` 점수를 추가한다.
  **`ATTACK_HONEY_MAX_POINTS = 35` 상한과 `ATTACK_WEIGHTS.attackHoney = 0.17` 이
  그대로이므로 공격 점수의 최대 기여도는 변하지 않고, 0.5/0.8/0.95 임계값 동작이 깨지지 않는다.**
- `policy.json` 에 **새 최상위 키** `detection.deception.points` 를 추가해
  `AUTOMATION_HONEY_POINTS`/`ATTACK_HONEY_POINTS`/두 MAX 를 덮어쓸 수 있게 한다.
  키가 없으면 현재 코드 상수를 그대로 쓴다(기존 `policy.json` 무수정 시 동작 동일).
  `policyEngine.js:14-48` 의 스키마 검증을 확장한다.

#### 2-6. 계약 테스트 + 문서

- `defense/tests/test_decoy_catalog_contract.py` — 카탈로그의 모든 `entries[].path` 가
  오버레이·CHeaT 양쪽 판별 함수에서 미끼로 인식되는지, `site-juice-shop` /
  `site-ruby-shop` / `site-generic-example` 3개로 **파라미터화**해 검증.
- `detection/test/decoyCatalogContract.test.js` — 같은 카탈로그를 Node 쪽에서 검증 +
  Python 쪽과 동일한 집합을 보는지 비교.
- `scripts/sync-decoy-catalog.sh --check` — 사본 drift 검사.
- `ci.yml` 에 위 3개를 추가. `ci.yml:193,219` 의 `/internal/ops/runbook` 하드코딩은
  카탈로그에서 읽도록 바꾼다.
- `defense/README.md` 에 "새 사이트 추가 = 프로파일 1개 작성" 절차를
  `site-generic-example.toml` 기준으로 추가하고, **D4 로 인한 한계**(Detection 의
  비즈니스 로직 탐지는 여전히 Juice Shop 전용)를 명시한다.

### Phase 3. DB 통일

#### 3-1. 그룹핑 — 컨테이너 경계를 넘지 않는다 (6 → 3)

| 컨테이너 | 통합 전 | 통합 후 | 테이블 |
| --- | --- | --- | --- |
| `defense` | `path-alias.sqlite3`, `routes.sqlite3` | **`/app/state/defense.sqlite3`** | `path_alias_client_state`, `path_alias_alias_rows`, `overlay_meta`, `sticky_actor`, `schema_migrations` |
| `overlay-*` | `security.sqlite3`, `events.sqlite3`, `lure-events.sqlite3` | **`/app/state/overlay.sqlite3`** | `security_meta`, `quarantine`, `nonces`, `events`, `lure_events`, `schema_migrations` |
| `cheat-*` | `defense.db` | 그대로 (이미 1개) | `runs`, `reqs`, `schema_migrations` |
| `detection` | `xss-candidates.db`, `xss-confirmed.db`, `xss-reflected.db`, `schema-learning.json` | **`/app/data/detection.sqlite3`** | `cand`, `evidence_confirmed`, `evidence_reflected`, `schema_learning_*`, `schema_migrations` |

**JSON 으로 남기는 것과 이유**: `target-selection.json`(서비스 간 계약 — Defense 가
읽기 전용 볼륨으로 읽는다. DB 로 바꾸면 컨테이너 경계를 넘는 SQLite 공유가 된다),
`policy.json`·`site-*.toml`·`decoy-catalog.json`(설정 성격, 커밋 대상).

#### 3-2. 접근 계층

- Python `defense/shared/store/` — `connect(path)`(WAL + `busy_timeout=10000`,
  `synchronous` 는 저장소별 지정), `migrate(conn, migrations)`,
  `schema_migrations(version INTEGER PRIMARY KEY, applied_at REAL NOT NULL)`.
- Node `detection/lib/store/` — `node:sqlite` 기반 동일 역할.
- **`security_store.py` 의 fail-closed 특성은 반드시 보존**: `mode=rw` URI, 0600,
  dev/ino 고정, `user_version`/컬럼 지문/`quick_check`/`store_id`/`key_scope` 검증,
  런타임 미생성. 공용 모듈에 "엄격 모드" 플래그로 넣는다.
- `routes.sqlite3` 의 "virgin 디렉터리만 초기화" 규칙도 보존한다.
- `Defense_proxy.py:797-803` 의 `try ALTER TABLE` 을 마이그레이션 2번으로 대체한다.
- `path_alias.py` 의 방치된 v3 테이블(`path_alias_clients`, `path_alias_client_rows`)을
  마이그레이션에서 `DROP` 한다.

#### 3-3. 마이그레이션 스크립트

`defense/scripts/migrate_stores.py`, `detection/scripts/migrate-stores.js`:
구 파일이 있으면 테이블을 통합 DB 로 복사한 뒤 구 파일을 `.migrated` 로 rename,
없으면 빈 DB 를 만든다. `schema_migrations` 로 멱등 보장, 재실행 안전.
**`security.sqlite3` 는 key_scope 바인딩 때문에 특히 조심** — `store_id` 와 `key_scope` 를
그대로 옮기고, 불일치 시 **실패하고 멈춘다**(격리 목록을 조용히 잃지 않게.
`security_store.py:1-6` 의 docstring 원칙).

#### 3-4. 환경변수 정리

신규: `DEFENSE_STORE_DB`, `OVERLAY_STORE_DB`, `DETECTION_STORE_DB`.
구 변수(`PATH_ALIAS_DB_PATH`, `DEFENSE_OVERLAY_STATE_DB`, `DEFENSE_SECURITY_DB`,
`XSS_DB_PATH`, `XSS_CONFIRMED_DB_PATH`, `XSS_REFLECTED_DB_PATH`, `SCHEMA_LEARNING_FILE`,
TOML `audit_path`)는 **deprecation 경고와 함께 계속 읽는다**.
수정 대상: `docker-compose.yml`, `docker-compose.local.yml`, `.env.example`,
`defense/account-response-overlay/deploy/compose.yaml`,
`deploy/live-lab.compose.yaml`, `.github/workflows/deploy.yml`.
**죽은 `PATH_ALIAS_DB_PASSWORD` 배선도 제거**.
볼륨은 통합에 맞춰 줄이되 **기존 named volume 을 유지**해 재배포 시 데이터를 보존한다.

#### 3-5. 이벤트 스키마 통일

미끼 적중·차단·전략 적용 이벤트의 필드명을 하나로 맞춘다: `requestId`, `targetId`,
`runId`, `actor`, `path`, `decoyAction`, `strategies`, `outcome`, `occurredAt`.
현재 `events(kind,run,session,trace,detail)` / `reqs(defense_action,client_id,defense_plan)` /
`lure_events(actor,kind,stage)` 가 서로 다르다. **DB 공유가 아니라 필드명 통일로 해결**한다.

### Phase 4. 중복 제거

1. **`sites/juice_shop/` → `sites/account_decoy/` `git mv`** ([전제 수정 (1)](#1-unifiedpy--cyclepy-는-중복이-아니다--합치면-안-된다)).
   Juice Shop 종속 2파일(`false_success.py`, `facade.py`)만 `sites/juice_shop/` 유지.
   `sites/__init__.py:16` 의 `generic`→`juice_shop` 의존을 끊는다.
2. **미끼 별칭 테이블 중복 제거** — `high_risk.py:123-125` 와 `overlay.py:275-277` 중
   `overlay.py` 를 정본으로 하고 `high_risk.py` 가 import 한다.
3. **`/swagger`·`/openapi` 중복** — `deception_headers.py:46-48` 정본,
   `high_risk.py:175-176` 이 호출한다.
4. **TOML 16 → 5~7**: `default.toml` 삭제(`decoy-v2.toml` 과 byte-identical,
   `cli.py:16` 기본값 변경), no-op `[limits]`/`[engagement]`/`[cycle]` **77줄 삭제**,
   `secure_cookie`/`origin_url`/`run_id`/`audit_path` 를 env 로, `site_adapter` 는
   `site_profile` 에서 유도. **기존 설정 로딩 결과와 새 설정 로딩 결과가 동일한지
   `test_production_config.py` 를 확장해 증명한다.**
5. **CHeaT v1** — 실행 참조는 0건이지만 Markdown 참조 16건이 남아 있다.
   "참조가 남아 있으면 삭제하지 않는다"는 규칙에 따라 **삭제하지 않고
   [B-4](#b-4-cheat-v1--실행-참조-0건-다만-markdown-참조-16건) 표를 보고한 뒤 멈춘다.**
6. **compose Detection env 중복** → YAML anchor. 로컬/운영의 의도된 차이
   (`DEFENSE_DB` `/data` vs `/tmp`, bind mount 유무)는 보존한다.
7. `identityMismatch.js:91/93`, `:100/102` 의 정규화경로+정규식 이중 표현과
   `businessLogicSignatures.js:35/36`, `:37/38` 의 trailing-slash 중복 정리.

### Phase 5. 마무리

- `RELEASE.json` → `MANIFEST.sha256` **순서로** 재생성. **`scripts/gen_manifest.sh` 신규 작성**
  + `ci.yml` `overlay-check` 에 `sha256sum -c MANIFEST.sha256` 스텝 추가 +
  현재 미커버 7파일 포함. (안 하면 지금처럼 즉시 다시 틀어진다)
- `README.md`, `defense/README.md`, `detection/README.md` 를 코드와 일치시킨다.
  방어 정책 표의 0.5/0.8/0.95 는 `policy.json` 과 **현재 일치 확인됨** ✅
- **`INTEGRATION.md` 신규 작성** — Detection↔Defense↔CHeaT↔Overlay 헤더 계약,
  통일된 이벤트 스키마, 경로 흐름.
- 전체 테스트 + `docker compose -f docker-compose.local.yml build` 성공 확인.
- `docs/refactor-summary.md` 작성 — 변경 요약, 삭제한 파일, 바뀐 환경변수와
  마이그레이션 방법, 남은 위험, 되돌리는 방법.

### 단계별 검증

각 Phase 종료 시 [Phase 0](#측정-방식-docker-전용) 의 Docker 명령 6블록을 **전부** 재실행하고
위 수치와 비교한다. 추가로:

| Phase | 추가 검증 |
| --- | --- |
| 2 | 신규 계약 테스트 3개 통과; `sync-decoy-catalog.sh --check` 통과; `docker compose -f docker-compose.local.yml up -d --build --wait` 후 `ci.yml:188-219` 의 미끼 경로 curl 단정 수동 재현 |
| 3 | 구 DB 파일을 가진 볼륨으로 마이그레이션 스크립트 2회 실행(멱등 확인); 구 파일 없는 상태에서 신규 기동 확인; `security.sqlite3` key_scope 불일치 시 **실패**하는지 확인 |
| 4 | 구/신 TOML 로딩 결과 동일성 테스트; `grep -rn defense_proxy_v1` 결과가 산문만인지 |
| 5 | `sha256sum -c MANIFEST.sha256` **0 FAILED**; `docker compose -f docker-compose.local.yml build` 성공 |

---

## 남은 위험

1. **카탈로그 사본 방식**은 CI drift 검사가 없으면 즉시 틀어진다. 검사를 같은 커밋에 넣는다.
2. **`security.sqlite3` 통합**이 가장 위험하다. fail-closed 검증이 촘촘해서 마이그레이션
   실수 시 오버레이가 아예 기동하지 않는다. 이 항목만 별도 커밋 + 롤백 절차를 문서화한다.
3. **`decoy_stage` / entry-step 분류 수정**은 동작 변경이다. 발표 전에 바꿀지
   Phase 2 착수 시 재확인한다.
4. CI 가 Juice Shop 로직을 전혀 검증하지 않으므로 Detection 7개 모듈의 사이트 결합은
   **테스트로 보호되지 않는다**. D4 에 따라 이번 범위에서 제외한다 — 즉
   **"새 사이트 추가 = 프로파일 1개"는 Defense 쪽(오버레이·CHeaT)에서만 성립하고,
   Detection 의 비즈니스 로직 탐지는 여전히 Juice Shop 전용이다.**
5. CHeaT v1 은 Markdown 참조 때문에 삭제하지 않으므로 중복 제거 효과가 그만큼 줄어든다.
6. `test_xff.py` 대조군 실패의 CI 재현 여부를 확인하지 못했다. 각 Phase 에서 CI 결과로
   교차 확인한다.
