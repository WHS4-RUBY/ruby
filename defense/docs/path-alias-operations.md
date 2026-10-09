# 경로 별칭 설치·운영 가이드 (v4, 2026-10-09)

경로 별칭은 **검증된 사이트에 선택적으로 켜는 기능**이다. 기본값은 `PATH_ALIAS_MODE=off`이고, 저장소는 별도 서비스가 필요 없는 SQLite 파일이다. 이 문서는 설치·모드·경로 파일·쿠키 미반환 정책·PostgreSQL 전환 기준을 정리한다. 연구 설계와 실험 기록은 [path-alias-plan.md](path-alias-plan.md), 경로 수집은 [route-discovery-design.md](route-discovery-design.md)에 있다.

## 1. 설치: SQLite 기본

두 Compose(`docker-compose.yml`, `docker-compose.local.yml`)는 다음을 쓴다.

| 항목 | 값 |
|---|---|
| DB 파일 | `PATH_ALIAS_DB_PATH=/app/alias-data/path-alias.sqlite3` |
| 볼륨 | `defense-alias-data:/app/alias-data` (재시작·재배포 후에도 유지) |
| 저널 | WAL, `synchronous=NORMAL`, `busy_timeout=10s` |
| 쓰기 | 발급·교체는 `BEGIN IMMEDIATE` 트랜잭션. 같은 호스트의 여러 worker가 한 파일을 공유 |
| 필요한 비밀값 | 없음 (`PATH_ALIAS_DB_PASSWORD`는 더 이상 필수가 아님) |

PostgreSQL 드라이버는 기본 이미지에 없다. 다중 호스트가 필요할 때만 `docker build --build-arg WITH_POSTGRES=true ./defense`로 빌드하고 `PATH_ALIAS_DB_URL=postgresql://...`을 지정한다. URL이 있으면 SQLite보다 우선한다.

**DB 오류는 원본 우회로 이어지지 않는다.** 별칭 조회가 실패하면 503(`Retry-After`)을 반환하고 백엔드로 보내지 않는다. 응답 치환 중 DB가 실패하거나 클라이언트 상한에 걸리면 enforce에서는 503, observe에서는 원본 응답을 그대로 보내고 `rewrite_skipped=db_error|capacity`를 기록한다(observe는 원래 원본 경로를 막지 않는다). 교체 쓰기만 실패하면 요청 판정(404)은 그대로이고 로그에 `rotation=failed`가 남는다.

## 2. 모드: 영향 없는 점검과 실제 적용을 구분

| 모드 | 응답 본문·`Location` | 별칭 쿠키 | 원본 보호 경로 | DB | 용도 |
|---|---|---|---|---|---|
| `off` | 그대로 | 없음 | 통과 | 사용 안 함 | 기본값 |
| `audit` | **그대로** (치환 건수만 `would_rewrite`로 기록) | 없음 | 통과, `decision=audit` 기록 | 사용 안 함 | 정상 사용자에게 영향 없는 수집·점검 |
| `observe` | **치환함** | 발급 | 통과, `would_block`·`would_rotate` 기록 | 사용 | 실제 브라우저가 별칭을 쓰는지 확인. 사용자가 받는 응답이 바뀐다 |
| `enforce` | 치환함 | 발급 | 404, 사유별 교체 | 사용 | 검증된 사이트·경로에만 |

`observe`도 사용자 응답을 바꾼다는 점이 v3 문서와 다르다. 응답을 바꾸지 않는 사전 점검이 필요하면 `audit`을 쓴다.

**enforce는 경로 파일이 준비 완료를 선언해야 적용된다.** `PATH_ALIAS_MODE=enforce`라도 경로 파일에 `"enforce_ready": true`가 없으면 그 파일의 경로는 `observe`로 동작한다. `enforce_ready`를 쓰려면 `compatibility.verified_flows`(검증한 정상 흐름 목록), `compatibility.refresh`(별칭 교체 뒤 앱이 새 별칭을 받는 방법), `compatibility.refresh_verified: true`가 모두 있어야 하며, 없으면 시작이 실패한다. 시작할 때 `path_alias_config` 이벤트에 `mode`·`default_mode`·`enforce_ready`가 기록된다. 경로별 `"mode": "observe"`로 일부 경로만 낮출 수 있으며, 경로 단위 설정이 파일의 준비 상태를 넘어 enforce로 올리지는 못한다.

**위험 점수로 진행 중인 세션을 갑자기 enforce로 바꾸지 않는다.** 별칭 판정은 설정·경로·별칭 쿠키만 보고 `X-Ruby-*-Score`를 읽지 않는다(`test_risk_scores_never_switch_alias_decisions`).

현재 저장소의 경로 파일 상태:

| 파일 | `enforce_ready` | 근거 |
|---|---|---|
| `juice-shop-routes.json` | true | 2026-10-09 실제 스택 브라우저 검증(아래 7절). 검증하지 않은 기능은 파일의 `compatibility.not_verified`에 적었다 |
| `ruby-shop-routes.json` | false | 소스 선언에서 만든 목록. 브라우저 흐름과 갱신 방식 미검증 |
| `query-routing-example.json` | false | 예시 |

여러 대상을 고르는 배포(`TARGET_CHOICES`)에서는 경로 파일에 `"target_ids": ["juice-shop"]`을 넣어 다른 대상의 `/api/`를 막지 않게 한다. 지정하지 않으면 선택된 모든 대상에 적용된다.

## 3. 경로 파일 형식

```json
{
  "enforce_ready": false,
  "compatibility": {"verified_flows": ["login", "search"], "refresh": "reload", "refresh_verified": true},
  "target_ids": ["shop"],
  "routes": ["/api/items", {"path": "/api/items/{id}", "methods": ["GET"], "mode": "observe"}],
  "query_routes": [{"path": "/gateway", "parameter": "route"}],
  "action_routes": [{"path": "/api.php", "parameter": "action",
                     "actions": {"login": ["POST"], "search": ["GET"]}}],
  "cookieless_channels": [{"name": "partner-api", "routes": ["/api/partner/{tail*}"],
                           "methods": ["POST"], "require_headers": ["authorization"]}]
}
```

- `routes`: 별칭을 줄 실제 경로. `{id}`는 한 구간, `{tail*}`는 끝의 가변 부분.
- `query_routes` **경로 선택형**: `/gateway?route=/api/items`. 값이 보호 경로이면 별칭으로 치환·복원하고, 보호 경로가 아닌 값(`route=/home`, `route=home`)은 그대로 통과한다(v3는 일괄 거부했다). `route=api/items`처럼 앞 `/`가 없는 보호 경로나 `?`·`#`이 붙은 보호 경로는 `direct`/`invalid_query_route`로 본다.
- `action_routes` **기능 선택형**: `/api.php?action=login`. 나열한 기능만 보호하며 별칭은 쿼리 값(`action=__ruby_alias_…`)으로 준다. 나열하지 않은 기능(`action=help`)은 통과한다. 대소문자만 다른 값(`LOGIN`)은 보호 기능의 직접 호출로 본다. 기능별 메서드를 검사한다. 액션 별칭을 경로로 쓰면 거부한다. 최대 256개.
- 같은 dispatcher 키가 두 번 나오고 그중 하나라도 보호 대상이면 `duplicate_query_route`로 거부한다. 모두 보호 대상이 아니면 통과한다.
- **일반 쿼리 보존**: 설정된 키의 값 하나만 바꾸고 나머지 필드의 바이트·순서·중복·빈 값·인코딩은 그대로 보낸다. 쿼리 값은 DB 키와 로그에 들어가지 않는다(로그에는 경로와 설정된 route_id만 남는다).
- **본문 라우팅은 지원하지 않는다.** dispatcher로 오는 64 KiB 이하 form/JSON 본문에 라우팅 키가 있고 그 값이 보호 대상이면 `direct`(`reason=body_routing_unsupported`)로 처리한다(enforce에서 404, 교체 없음). 본문 키가 보호 대상이 아니면 본문을 그대로 전달한다. multipart·대용량 본문은 검사하지 않고 `rewrite_skipped=body_uninspected`로 기록한다.
- **동적 조립**: 문자열 리터럴로 기본 주소를 두고 런타임에 한 구간을 붙이는 형태(`"/rest/track-order"` + `"/"+id`, `` `/rest/continue-code/apply/` ``+code, 끝 슬래시만 있는 `` `/rest/image-captcha/` ``)는 지원한다. `URLSearchParams`로 값을 따로 만들거나 경로를 여러 변수로 조립하는 코드는 치환하지 않는다. 수집기 보고서의 `dynamic_assembly_note`·`unsupported_routing`을 확인한다.
- 넓은 별칭(`/rest/admin/{tail*}`)에 앱이 런타임 접미사를 붙여 더 구체적인 설정 경로(`/rest/admin/application-version`)에 닿으면, v3는 `shadowed_route`로 거부하고 클라이언트 별칭을 전부 교체했다. 실제 브라우저에서 페이지가 깨졌으므로 이제 구체 경로의 메서드로 판정하고 그 경로로 기록한다. 경로 간 분리는 그만큼 약하다.

## 4. 응답 치환 범위

치환은 Defense의 마지막 단계다. 후속 전략의 응답 변형이 끝난 본문에 적용한다. 전략이 직접 만든 즉시 반환 응답(차단·429·미끼 페이지 등)은 앱 경로를 담지 않으므로 치환하지 않고 별칭 쿠키도 주지 않는다. Sidecar(CHeaT·오버레이)를 거친 응답은 Defense로 돌아온 뒤 치환한다.

| 응답 종류 | 치환하는 곳 | 치환하지 않는 곳 |
|---|---|---|
| JSON | 문자열 값 **전체**가 URL인 경우(`"next":"/rest/x?q=1"`, `"https://같은호스트/rest/x"`) | 설명 문장 속 경로(`"Call /rest/x to search"`, `"/rest/x is the API"`) |
| HTML | 속성 값(`href="…"`, `action=/…`), `&quot;`로 감싼 값, 인라인 스크립트의 문자열 | 본문 텍스트(`<p>API는 /rest/x</p>`) |
| JS | 따옴표·백틱 문자열이 경로나 **같은 출처** 절대 URL로 시작하는 경우, `` `${base}/rest/x` `` | 주석, 다른 출처 URL, 경로가 문자열 중간에 있는 경우 |
| `Location` 헤더 | 같은 호스트 또는 상대 URL | 다른 호스트 |

한계: HTML 본문 텍스트 안에 따옴표로 감싼 경로가 있으면 치환될 수 있다. 압축 응답과 8 MiB 초과 응답은 치환하지 않는다(`rewrite_skipped=too_large`). WebSocket 프레임은 치환하지 않는다.

## 5. 교체·만료·여러 탭

| 상황 | 결과 | 교체 |
|---|---|---|
| 원본 보호 경로 직접 호출 (`direct`) | enforce 404 | 예 (기본) |
| 존재하지 않는 별칭 (`unknown_alias`) | 404 | 예 |
| 다른 확인된 클라이언트의 별칭 (`foreign_alias`) | 404 | 예 (요청한 클라이언트만) |
| 잘못된 인자 (`invalid_alias_arguments`) | 404 | 예 |
| 허용되지 않은 메서드 (`method_not_allowed`) | 404 | 아니오 (CORS preflight·앱 차이 가능) |
| 시간 만료된 **자기** 별칭 (`stale_alias`) | GET/HEAD는 307로 현재 별칭에 연결, 그 외 404 | 아니오 |
| 이벤트 교체로 폐기된 자기 별칭 (`revoked_alias`) | 404, 자동 연결 없음 | 아니오 |

- `PATH_ALIAS_ROTATE_ON`은 사유별로 지정한다. `reject`는 모든 거부 사유의 묶음이다. `stale_alias`·`revoked_alias`는 지정할 수 없다. 오래 열어 둔 탭이 교체를 연쇄로 일으키지 않게 하기 위해서다.
- `PATH_ALIAS_ROTATE_MIN_INTERVAL_S`(기본 5초) 안의 추가 교체는 `rotation=suppressed`로 기록하고 쓰기를 하지 않는다.
- **자동 복구는 GET/HEAD만** 한다. POST·결제·작성 요청은 재전송하거나 리다이렉트하지 않고 404로 끝나며, 사용자가 새로고침한 뒤 다시 보내야 한다. 이벤트로 폐기된 별칭은 공격자가 이전 별칭으로 새 별칭을 얻지 못하도록 자동 연결하지 않는다.
- 폐기·만료된 행은 원래 만료 시각 뒤 한 수명 동안 tombstone으로 남는다. 덕분에 오래된 탭(`stale`/`revoked`)과 위조 별칭(`unknown`)을 구분한다.
- 같은 쿠키를 쓰는 여러 탭은 같은 별칭을 공유한다. 쿠키 없이 동시에 열린 첫 방문 탭들은 서로 다른 미확인 클라이언트를 받는다. 브라우저에는 마지막 쿠키만 남는다. 다른 탭의 별칭이 미확인 클라이언트 것이면 `adopted`로 허용하므로 깨지지 않는다(아래 6절).

## 6. 쿠키 미반환 대응

### 6.1 세 쿠키의 역할

| 쿠키 | 발급자 | 서명 | 쓰임 | 쓰지 않는 곳 |
|---|---|---|---|---|
| `dcid` | Detection | HMAC | 정책 키·이력 연결(검증된 클라이언트는 자기 세션·Resolved Actor 이력만 사용) | 별칭 |
| `dlsid` | Detection | 없음 | 관찰 세션 묶음. 다른 `dcid`와 함께 오면 확정 근거로 쓰지 않음 | 정책 확정 |
| `ruby_alias_client` | Defense | 없음 | **별칭 귀속만**. 위조 값은 새 미확인 클라이언트가 될 뿐 | 탐지 점수, 신원, 차단 근거 |

### 6.2 별칭 쪽 정책

- 별칭 쿠키를 돌려주지 않는 클라이언트(curl·에이전트·쿠키 차단)는 응답마다 **미확인(pending) 클라이언트**를 새로 받는다. 같은 쿠키로 다음 요청이 오면 확인(confirmed) 상태가 된다.
- 미확인 클라이언트의 별칭은 쿠키 없이도 쓸 수 있다(`alias_state=adopted`). 별칭을 받은 쪽이 그 쿠키도 같이 받았으므로 귀속 검사로 얻는 것이 없고, 막으면 도구 한계만 측정하게 된다. 확인된 클라이언트의 별칭은 다른 쿠키·쿠키 없음에서 `foreign_alias`로 거부된다.
- **쿠키가 없다는 이유로 원본 보호 경로를 허용하지 않는다.** 쿠키 유무와 무관하게 원본 경로는 enforce에서 404다.
- 쿠키 부재 자체는 점수·차단 근거가 아니다. 공유 IP·지문을 신원으로 쓰지 않는다. 별칭 단계는 IP를 보지 않는다.
- 사전에 명시한 쿠키 없는 API 채널(`cookieless_channels`)은 별칭 쿠키가 없고 지정 헤더가 있는 요청에 한해 원본 경로를 허용한다(`kind=channel`). Detection·CRS·후속 전략은 그대로 적용된다. 헤더는 누구나 붙일 수 있으므로, 이 설정은 해당 경로의 별칭 보호를 포기한다는 운영 결정이다.

**발급 자원 상한과 과부하 정책**

| 설정 | 기본값 | 의미 |
|---|---|---|
| 지연 발급 | 항상 | 응답에 실제로 등장한 경로만 발급. HTML에 경로가 없으면 클라이언트를 만들지 않음 |
| `PATH_ALIAS_PENDING_TTL_S` | 300 | 미확인 클라이언트·행 수명. 만료분은 청소 주기(최대 60초)마다, 그리고 상한에 닿을 때 즉시 회수 |
| `PATH_ALIAS_MAX_PENDING_CLIENTS` | 10000 | 미확인 클라이언트 상한 |
| `PATH_ALIAS_MAX_CLIENTS` | 100000 | 전체 상한 |
| 초과 시 | enforce: 503 `Retry-After: 5`, 쿠키 없음 / observe: 원본 응답, `rewrite_skipped=capacity` | 원본 경로로 우회시키지 않음 |

상한은 앱 전체 기준이다. 쿠키를 돌려주지 않는 요청이 몰리면 새 방문자도 같은 503을 받을 수 있다. PostgreSQL에서는 클라이언트별 잠금이라 동시 발급 시 상한을 약간 넘을 수 있다. SQLite 파일은 행을 지워도 줄어들지 않고 빈 페이지를 재사용한다.

### 6.3 Detection 정책과의 관계 (Detection 코드는 변경하지 않음)

| 상황 | Detection 정책 키·근거 | 실제 스택 관찰 (2026-10-09, Juice Shop) |
|---|---|---|
| 첫 요청 | 후보(IP+HTTP 지문), 이력 없음 | 계획 없음 |
| 매 요청 쿠키 삭제·미반환 공격 | 같은 후보 이력 (`actor-candidate-fallback`) | 공격 요청은 CRS가 현재 요청 근거로 403. 이력 위험도는 0.58~0.65에서 멈춰 `suspected` 미끼(≥0.8)는 **발동하지 않음**. 미끼 단계 도달은 반사 응답을 쓰는 Detection 단위 테스트에서만 확인됨 |
| 변조 `dcid` | 검증 실패 → 새 dcid, 쿠키 없음과 같게 후보 이력 사용 | 위험도 0.58 승계, 우회 안 됨 |
| 위조 `ruby_alias_client` | 새 미확인 클라이언트 | 원본 경로 404 유지 |
| 새 유효 `dcid`를 받아 돌려줌 | 자기 세션·Resolved Actor 이력만 | 같은 UA여도 위험도 0.16 → **후보 이력에서 벗어남** (남는 우회) |
| 지문(UA) 변경 | 새 후보 | 0.16 → **이력 단절** (남는 우회) |
| 같은 NAT, 쿠키 반환 정상 사용자 | 자기 dcid | 공격자 이력 영향 없음 |
| 같은 NAT, 쿠키 미반환, 같은 지문 | 같은 후보 | 공격자 이력을 공유 → 미끼 대상이 될 수 있음 (Detection 테스트가 명시한 NAT 절충) |

정리: **현재 요청 근거 방어**(CRS·별칭 단계의 원본 차단)는 쿠키와 무관하게 동작한다. **이력 기반 방어**(후보·Client Flow 미끼)는 쿠키 미반환 클라이언트를 이어 보지만, 새 유효 DCID나 지문 변경으로 끊을 수 있다. 계획 헤더가 오면 Defense와 CHeaT는 쿠키 없는 후보 키에도 미끼를 실행하고 상태를 유지했다(같은 미로 응답 반복, 별칭 단계가 먼저 원본 경로를 404 처리).

### 6.4 HTTP와 WebSocket

| | HTTP | WebSocket |
|---|---|---|
| 별칭 단계 | 요청 경로·쿼리 복원/거부 | 업그레이드 URL에 같은 규칙. 원본 보호 경로·위조 별칭은 수락 전 거부(브라우저에는 403) |
| 만료 별칭 자동 연결 | GET/HEAD 307 | 없음 (업그레이드는 리다이렉트를 따르지 않음) → 거부 |
| 응답·프레임 치환 | 함 | **하지 않음** |
| 쿠키 없는 Detection 정책 | 후보·Client Flow 이력 | 업그레이드마다 별도 ID, 이웃 이력을 빌리지 않음 |
| 계정 오버레이 대상 | 오버레이로 라우팅 | 업그레이드 거부 |

## 7. 검증 결과

### 7.1 실행 환경

로컬 Docker. Detection(`:8081`) → Defense(SQLite, uvicorn 1 worker) → CHeaT sidecar → Juice Shop 20.2.0(`sha256:73c53fbf442e`). CRS enforce(공격 실험 일부는 observe). 브라우저는 headless Chromium(Playwright). 같은 호스트에서 실행했으므로 지연 수치는 기술적 관찰값이다.

| 항목 | 결과 |
|---|---|
| 단위·통합 테스트 | Defense 190개 통과(그중 PostgreSQL 테이블 테스트 19개는 실제 PostgreSQL 16 컨테이너에서 별도 실행해 통과), 수집기 Node 6개, Detection 230개(실행만, 코드 변경 없음) 모두 통과 |
| HTTP 매트릭스 (enforce) | 17/17. 쿠키 반환 로그인·검색 별칭이 Juice까지 전달, 원본·대소문자·인코딩 변형 6종 404, 직접 호출 뒤 이전 별칭 404·새 별칭 동작, JSON 상품 설명 46건 무변경, 쿠키 없는 도구도 미확인 별칭 사용 가능, 원본 경로는 쿠키 없어도 404 |
| 모드×쿠키 매트릭스 | off·audit: 응답 무변경(`main.js`의 `/rest/` 42곳 그대로)·쿠키 없음·원본 200. observe: 별칭 49종 치환(남은 `/rest/` 4곳은 CHeaT가 넣은 미끼 주석)·쿠키 발급·원본 200. enforce: 원본 404·별칭 200(쿠키 유무 모두). `enforce_ready` 없는 파일 + enforce: observe와 동일 |
| 브라우저 (off/observe/enforce 각 1회) | 회원가입·로그인·검색·장바구니 담기·리뷰 작성·두 번째 탭·뒤로/앞으로·새로고침 9단계 모두 통과. enforce에서 별칭 요청 73건 전부 2xx, 원본 보호 경로 요청 0, 4xx/5xx 0, 페이지 오류 0, 교체 0 |
| 만료 (epoch 20초, 45초 대기) | 14/14. 열린 페이지의 만료 별칭 GET 2건이 307로 복구, 새로고침 후 장바구니 POST 성공, 시간 교체 1회 |
| 재시작 | 같은 별칭이 Defense 재시작 전후 모두 200 |
| 경로형·기능형 dispatcher (실제 HTTP 에코 앱) | 별칭 복원과 다른 필드 바이트 보존(`&x=1&x=&y`), 비보호 값 통과, 원본·상대 경로·대소문자 변형·잘못된 메서드·본문 라우팅 404, 비보호 본문 키는 본문 그대로 전달, 일반 쿼리 `b=2&a=1&a=1&empty=&flag&enc=%2F%41+x` 그대로 |
| WebSocket | Juice socket.io 업그레이드 정상, 원본 보호 경로·위조 별칭 업그레이드 403 |

검증 중 발견해 고친 호환성 문제: 런타임 접미사 리터럴과 끝 슬래시 경로 미치환(3곳), `shadowed_route` 교체로 페이지 전체 별칭 무효화, 로컬 Compose `overlay-alternate` 기본 키 길이 오류, 실험 실행기의 보호 접두사(`/b2b/`) 누락.

### 7.2 SQLite 부하 (Defense 4 worker, 한 파일, Detection 없이 직접)

| 시나리오 | 요청/동시 | 결과 |
|---|---|---|
| 쿠키 미반환 `main.js` 폭주, 미확인 상한 1500 | 2000/32 | 200×1499, 503×500(상한), 502×1(업스트림). 미확인 1500·행 73,500(클라이언트당 49)·DB 23.4 MB. 잠금·DB 오류 0. p50 1445 ms / p95 2030 ms |
| 같은 조건, 별칭 off | 500/32 | p50 1504 ms / p95 1934 ms → 이 호스트의 지연은 1.2 MB 번들 전송이 지배, 치환 비용은 구분되지 않음 |
| 쿠키 반환 클라이언트 `main.js` | 500/32 | 200×500, 클라이언트 32·행 1,568, p50 1299 ms |
| 동시 교체 쓰기(최소 간격 0) | 2000/32 | 2000건 교체, 259 rps, p50 61 ms / p95 321 ms / max 765 ms, 잠금 오류 0 |
| 미확인 TTL 30초, 상한 200 | 250 → 35초 대기 → 150 | 200×200, 503×50 → 만료 회수 후 150건 모두 200, 행 9,800 → 7,350 |

### 7.3 실행하지 못한 검증

- 쿠키 미반환 공격이 실제 Juice Shop에서 `suspected` 미끼 단계까지 가는 경로(위 6.3). 미끼 실행 자체는 계획 헤더를 직접 넣어 확인했다.
- 서비스 워커: Juice Shop은 등록하지 않아 확인할 수 없었다.
- 관리자·2FA·결제·챗봇·파일 업로드 화면, Ruby Shop 전체 흐름.
- 여러 호스트 PostgreSQL 배포와 그 부하, 장시간(30분 이상) 탭 유지.
- 실제 PHP 등 기능 선택형 dispatcher 앱(에코 앱으로만 확인).

## 8. 주소가 각 단계에서 어떻게 보이나 (실측 예)

| 단계 | Juice Shop 검색 | 경로 선택형 | 기능 선택형 |
|---|---|---|---|
| 주소창 | `http://127.0.0.1:8081/#/search?q=apple` (해시 라우트는 서버로 가지 않음, 그대로) | 앱 화면 주소 그대로 | 앱 화면 주소 그대로 |
| Network 탭 (브라우저 → Detection) | `/__ruby_alias_r4nwwpp4d3iluvza3vtiqub2c6?q=apple&q=` | `/gateway?route=%2F__ruby_alias_uh7o…&x=1&x=&y` | `/api.php?action=__ruby_alias_riu5…&q=a+b` |
| Detection이 보는 URL | 같은 별칭 경로 + 같은 쿼리 (CRS는 쿼리·본문을 그대로 검사) | 같음 | 같음 |
| Defense 복원 후 (후속 전략·CHeaT·대상) | `/rest/products/search?q=apple&q=` | `/gateway?route=%2Fapi%2Fitems&x=1&x=&y` | `/api.php?action=search&q=a+b` |
| Defense 로그 | `path=/__ruby_alias_…`, `real_path=/rest/products/search`, `route_id`, 쿼리 값 없음 | `route_id=/api/items` | `route_id=/api.php?action=search` |

Detection은 별칭 경로를 본다. 별칭이 클라이언트마다 달라 Detection의 엔드포인트별 통계·업무 로직 태그는 실제 경로 기준으로 묶이지 않는다. 공격 페이로드 검사(CRS)에는 영향이 없었다(별칭 경로의 SQLi도 403). Detection이 복원 경로를 알아야 한다면 Defense가 복원 결과를 Detection에 알려 주는 별도 연동이 필요하다(Detection 담당 범위).

## 9. PostgreSQL: 언제 전환하고 어떻게 옮기나

### 9.1 전환 기준

SQLite를 유지하는 조건은 **Defense 호스트가 하나**인 것이다. 다음 중 하나가 생기면 PostgreSQL(`PATH_ALIAS_DB_URL`)로 옮긴다.

1. Defense를 두 대 이상의 호스트에 띄우고 고정 세션(sticky) 없이 분산한다. SQLite 파일과 WAL은 네트워크 파일시스템에서 공유할 수 없다.
2. 로그에 `db_error`(SQLite 잠금 시간 초과)가 반복되거나, 교체·발급 p95가 7.2절 측정치(교체 p95 321 ms)보다 계속 크게 나온다.
3. 확인된 클라이언트가 `PATH_ALIAS_MAX_CLIENTS`에 가까워지거나 쿠키 반환 사용자의 신규 발급률이 높아져 쓰기 잠금 대기가 사용자 지연으로 보인다.
4. 백업·복제·장애 조치를 DB 수준에서 해야 한다.

PostgreSQL은 클라이언트별 advisory lock을 써서 서로 다른 사용자의 쓰기가 서로 기다리지 않는다. CI의 `defense-postgres-compat` job이 같은 테이블 테스트를 실제 PostgreSQL로 계속 실행한다.

### 9.2 기존 PostgreSQL 설치에서 SQLite로 전환

1. 서버 `.env`의 `PATH_ALIAS_MODE`를 확인한다. `off`(기본)이면 별칭 DB를 쓰지 않으므로 사용자 영향이 없다.
2. 새 버전을 배포한다. Compose에 `path-alias-db`가 없으므로 기존 PostgreSQL 컨테이너는 고아 컨테이너로 남는다(배포는 `--remove-orphans` 없이 올린다). 볼륨 `path-alias-pg`는 지우지 않는다.
3. Defense 로그의 `path_alias_config`에서 `"backend":"sqlite"`를 확인한다.
4. 롤백 기간이 지나면 `docker stop <project>-path-alias-db-1`로 멈춘다. 볼륨과 GitHub Secret `PATH_ALIAS_DB_PASSWORD`는 롤백 가능성이 없어질 때까지 남겨 둔다.

**기존 별칭 영향**: v4는 새 테이블(`path_alias_client_state`, `path_alias_alias_rows`)을 쓰고 기존 행을 옮기지 않는다. 전환 순간 열려 있던 탭의 별칭은 `unknown_alias`가 된다. enforce에서는 그 탭의 API 호출이 404가 되고 새로고침하면 복구된다. 쿠키 값이 같아도 새 DB에는 클라이언트가 없어 교체 쓰기는 일어나지 않는다. PostgreSQL을 유지하면서 v4로 올려도 테이블 이름이 바뀌므로 영향은 같다. 사용자가 적은 시간에 하거나 전환 동안 `observe`로 낮춘다.

### 9.3 롤백

- 배포 workflow의 자동 롤백은 이전 `docker-compose.yml`과 이미지 태그로 되돌린다. 이전 Compose는 `PATH_ALIAS_DB_PASSWORD`를 요구하므로 workflow는 이 비밀값이 있으면 계속 전달한다. 기존 `path-alias-pg` 볼륨의 v3 행이 그대로 쓰인다.
- 수동 롤백: 이전 Compose 파일과 `IMAGE_TAG`로 `docker compose up -d`, `.env`에 `PATH_ALIAS_DB_PASSWORD`를 넣는다.
- 롤백 뒤 SQLite에서 발급된 별칭은 사라지므로 열린 탭은 한 번 새로고침해야 한다.

### 9.4 PostgreSQL로 옮기기 (확장)

이미지를 `WITH_POSTGRES=true`로 빌드하고 `PATH_ALIAS_DB_URL`을 외부 PostgreSQL로 지정한다. 테이블은 시작 시 만들어진다. SQLite 행은 옮기지 않으므로 영향은 9.2와 같다. 더 이상 쓰지 않는 v3 테이블은 `DROP TABLE path_alias_client_rows, path_alias_clients;`로 지울 수 있다.

## 10. 설정 요약

| 변수 | 기본값 | 설명 |
|---|---|---|
| `PATH_ALIAS_MODE` | `off` | off / audit / observe / enforce |
| `PATH_ALIAS_ROUTES_FILE` | Compose: juice-shop | 경로 파일 |
| `PATH_ALIAS_PREFIXES` | `/rest/,/api/,/b2b/` | 직접 호출을 보는 보호 접두사. 경로 파일의 모든 경로가 이 안에 있어야 함 |
| `PATH_ALIAS_DB_PATH` / `PATH_ALIAS_DB_URL` | SQLite 파일 / 비어 있음 | URL이 있으면 PostgreSQL |
| `PATH_ALIAS_EPOCH_S`, `PATH_ALIAS_GRACE_EPOCHS` | 1800, 1 | 시간 교체와 유예 |
| `PATH_ALIAS_ROTATE_ON` | `direct,unknown_alias,foreign_alias,invalid_alias_arguments` | 사유별 즉시 교체 |
| `PATH_ALIAS_ROTATE_MIN_INTERVAL_S` | 5 | 클라이언트별 교체 최소 간격 |
| `PATH_ALIAS_STALE_REDIRECT` | true | 만료된 자기 별칭 GET/HEAD 307 |
| `PATH_ALIAS_PENDING_TTL_S`, `PATH_ALIAS_MAX_PENDING_CLIENTS`, `PATH_ALIAS_MAX_CLIENTS` | 300, 10000, 100000 | 쿠키 미반환 발급 상한 |
| `PATH_ALIAS_MAX_REWRITE_BYTES` | 8 MiB | 치환할 최대 응답 |
| `PATH_ALIAS_APP_ID` | 비어 있음 | 같은 DB에서 실험·앱 분리 |
| `PATH_ALIAS_COOKIE_SECURE` | false | HTTPS 배포에서 true |
