# 토큰 게이트 구현 기획 v2.1 (별칭 기법 1단계)

> **2026-09-30 후속 변경:** 아래 문서는 v2.1 당시 설계와 검증 이력이다.
> 현재 구현은 토큰 단독 차단을 제거했고, `enforce` 설정도 경고 후 관찰로 처리한다.
> 공격 차단은 Detection의 전달 전 CRS 검사로 옮겼다. 현재 동작은
> [Detection README](../../detection/README.md)와 [Defense README](../README.md)를 따른다.

> 작성: 심형섭 · 2026-09-29
> v2: Codex 교차 검토(15개 항목) 반영
> v2.1: Codex 재검토(보완 5개) 반영
> 상태: Defense 구현 및 4절 검증 완료. 전체 파이프라인·브라우저 실험은 미실행. 구현 담당(Codex 등)은 **맨 아래 "구현 지시" 절을 먼저 읽는다.**

---

## 0. 선행 조건 (통합 실험 전 반드시 해결)

### Detection이 백엔드 `Set-Cookie`로 자기 쿠키를 덮어쓴다

- 위치: `detection/lib/proxyCore.js`의 `responseInterceptor` (`http-proxy-middleware` 2.0.10, `selfHandleResponse: true`)
- 현상: Detection은 `server.js`에서 `res.cookie()`로 `dlsid`, `dcid`를 먼저 설정한다. 그 뒤 응답 인터셉터가 백엔드 헤더를 `setHeader`로 복사하면서 **기존 `Set-Cookie`를 덮어쓴다.**
- 영향: 백엔드(또는 Defense)가 `Set-Cookie`를 보내는 응답에서는 Detection 쿠키가 사라진다. 토큰 게이트는 첫 페이지 응답에서 쿠키를 발급하는데, 이때가 Detection도 새 방문자에게 쿠키를 발급하는 시점이다. 그래서 **새 방문자의 첫 요청마다 Detection의 사용자 연결 기록이 오염**된다.
- 이 문제는 토큰 게이트와 별개로 원래 있던 Detection 버그다. 백엔드가 쿠키를 보내면 언제든 발생한다.
- 해결 방향(탐지팀 제안용): 현재 `onResponse` 훅(`proxyCore.js`의 인터셉터 콜백)은 라이브러리가 백엔드 헤더를 복사한 **뒤**에 실행된다. 그 시점에 `res.getHeader('set-cookie')`를 읽으면 이미 덮어써진 뒤라 늦다. 그래서 **인터셉터가 헤더를 복사하기 전에 Detection 쿠키를 보관**하고(예: 요청 훅 `onProxyReq` 시점에 `res.getHeader('set-cookie')`를 `req`에 저장), **복사 후 백엔드 쿠키와 병합**해서 다시 설정한다.
- **진행 규칙**
  - Defense 구현과 단위·통합 테스트는 이 문제와 무관하게 먼저 진행한다. 기본 모드가 `off`라 팀 실행에 영향이 없다.
  - **Detection을 거치는 observe/enforce 실험은 이 버그가 고쳐진 뒤에 한다.** 고쳐지기 전에 돌린 결과는 "Detection 쿠키 오염 있음"으로 표시하고 **참고용으로만 쓴다. 공식 실험 완료로 인정하지 않는다.**
  - 이 저장소의 `detection/`은 이번 작업에서 수정하지 않는다. 탐지팀에 이슈 또는 별도 PR로 전달한다.

---

## 1. 배경과 목표

### 1.1 처음 아이디어

LLM 공격 에이전트가 기억해둔 주소로 바로 접근하지 못하도록, 주소(별칭)를 주기마다 바꿔서 공급한다.

### 1.2 논의하면서 바뀐 점

| 논의 | 결론 |
|---|---|
| 목표 | **C(탐지 신호) 중심, B(비용 증가)는 부수 효과.** A(차단)는 "토큰 없는 API 요청"에만 조건부로 적용 |
| 적용 범위 | 앱의 경로나 코드를 몰라도 동작해야 함. 단 **지원 조건을 명시**함 (2.1) |
| 정상 사용자 | 페이지 주소, 북마크, 공유 링크는 건드리지 않음. 막힐 수 있는 경우는 실험으로 확인하고 한계로 적음 |
| 탐지팀 의존 | Defense 혼자 동작. 탐지 연동은 3단계에서 PR로 제안 |
| 방식 | 앱별 설정이 필요 없는 **쿠키 토큰 회전**부터 시작. 경로 별칭은 이후 단계 |
| 토큰 갱신 (v2) | **활동 중 자동 갱신.** 주기적인 페이지 재방문을 강제하지 않음 (1.4 참고) |
| 응답 불일치 (v2) | **약한 보조 신호로만 기록.** 차단이나 높은 위험도에 쓰지 않음 (2.6 참고) |

### 1.3 근거로 쓴 관찰 (`defense-proxy` 브랜치 `defense/CHeat-defense-proxy/defense_proxy_v1/results.md`)

- codex는 알려진 API 목록(14개)을 **한 번에 직접 호출**했다. 페이지를 보고 경로를 찾지 않았다.
- codex는 "토큰을 되돌려 보내라"는 관문(T4.2b-login)에 **금방 적응**했고, solved는 1.00×였다. 그래서 토큰으로 비용을 늘리는 효과는 작다고 보고, 목표를 C 중심으로 잡는다.
- 관문은 에이전트가 **반복해서 치는 엔드포인트**에 걸려야 발동한다.
- Juice Shop은 모르는 경로에 404 대신 `200 + index.html`을 돌려준다.

### 1.4 단계 구조 (이 문서의 범위는 1~2단계)

```text
1단계 (A) 토큰 없는 API 요청 → 차단(enforce) 또는 기록(observe)
2단계     토큰은 주기마다 바뀜. 유효·유예 기간 안에 요청을 이어가면 자동 갱신,
          갱신 없이 서버 만료 시각을 넘긴 토큰은 거부
3단계 (C) 신호를 Detection으로 전달 (no_asset_loading 등과 결합)  ← 이번 범위 아님
```

**주의**: 토큰 회전 자체가 주기적인 페이지 재방문이나 공격 비용 증가를 **보장하지 않는다.** 쿠키를 관리하는 클라이언트는 사람이든 에이전트든 요청을 이어가는 한 계속 갱신받는다.

### 1.5 이 기법이 증명하는 것과 증명하지 못하는 것

- 헤더만으로는 **GET 페이지와 GET API를 확실히 구분할 수 없다.** API 호출에 `Accept: text/html`을 붙이면 `page`로 분류돼 토큰 없이 통과하고 토큰까지 받는다. `Sec-Fetch-*`도 흉내 낼 수 있다.
- 그래서 이 기법은 "페이지를 방문했다는 증명"이 아니라, **"페이지처럼 선언하지 않고 API를 직접 호출하는 요청"을 걸러내고 기록하는 장치**다.
- 헤더만 바꾸는 적응은 평가 항목에 포함한다 (5.3).
- 응답을 보고 남기는 기록은 **이미 실행된 요청을 막았다는 의미가 없다.**

---

## 2. 동작 설계

### 2.1 적용 범위와 지원 조건

- 게이트는 **`catch_all`이 백엔드로 프록시하는 HTTP 요청에만** 적용한다. `/healthz`, FastAPI 기본 문서 라우트처럼 별도 라우트로 처리되는 요청은 대상이 아니다.
- Detection은 `Accept`, `Sec-Fetch-*`, `Cookie` 헤더의 **값**을 Defense로 그대로 넘긴다(`detection/lib/rubyPolicy.js`의 제거 목록에 없음). 다만 Detection이 같은 응답에서 새로 발급한 `dcid`·`dlsid`는 그 요청의 `Cookie`에 포함되지 않는다.
- WebSocket은 현재 Detection·Defense 모두 중계하지 않는 기존 한계다. 게이트와 무관하게 따로 기록한다.
- 지원 조건: **동일 origin에서 쿠키를 전송하는 웹 앱.** 다른 origin의 리소스, `credentials: "omit"` 요청, 쿠키 없는 정상 클라이언트(모바일 앱, 외부 연동)는 지원 범위 밖이다.

### 2.2 요청 분류

모든 요청을 백엔드로 넘기기 **전에** 헤더만 보고 분류한다.

| 분류 | 조건 |
|---|---|
| `exempt` | 메서드가 `OPTIONS`, **또는** 경로가 예외 목록과 일치 |
| `page` | 메서드가 `GET`/`HEAD` **이고**, 다음 중 하나: `Accept`에 `text/html` 포함, `Sec-Fetch-Dest: document`, `Sec-Fetch-Mode: navigate` |
| `api` | 나머지 전부. **정적 파일(JS, CSS, 이미지, 폰트)과 `/socket.io/` polling도 포함** |

**예외 목록 비교 규칙**
- 항목이 `/`로 끝나면 하위 경로 접두사: `/__defense/`는 `/__defense/x`와 일치
- 항목이 `/`로 끝나지 않으면 정확한 경로: `/healthz`는 `/healthz`만 일치하고 `/healthz-admin`은 불일치
- 쉼표로 나누고 앞뒤 공백 제거, 빈 항목 제거
- 기본값: `/healthz,/__defense/,/__detection/`
- `classify()`는 예외 목록을 인자로 받는다

### 2.3 토큰

- 쿠키 이름: `__ruby_tg` (Detection의 `dcid`, `dlsid`와 Juice Shop 쿠키와 겹치지 않게)
- 정규 형식: `v1.<epoch>.<mac>`
  - `epoch = floor(now / EPOCH_S)`, 10진수 1~12자리
  - `mac = base64url(HMAC-SHA256(SECRET, "v1.<epoch>"))`의 앞 22자, 패딩 없음, 문자 집합 `[A-Za-z0-9_-]`
  - 파싱: 전체 길이 64자 이하 + 정규식 `^v1\.([0-9]{1,12})\.([A-Za-z0-9_-]{22})$`. 맞지 않으면 모두 `invalid`
  - 비교는 `hmac.compare_digest`
- 사용자, IP, Client-Id에 **묶지 않는다** (이후 단계에서 검토).
- **서버 만료 시각**: `expires_at = (epoch + GRACE_EPOCHS + 1) × EPOCH_S`
- 쿠키 속성: `Path=/; HttpOnly; SameSite=Lax; Max-Age=<max(1, floor(expires_at − now))>`
  - `now`는 요청 진입 시점이 아니라 **응답에 쿠키를 만드는 시점**의 시각이다. `epoch`도 같은 `now`로 계산한다.
  - 고정 `Max-Age`를 쓸 때 생기던 **최대 한 주기의 불일치를 줄인다.** 완전히 없애지는 못한다. 남은 시간이 1초 미만이면 최소값 1초 때문에 서버 만료보다 길게 남고, 응답 전달 시간만큼의 차이도 남는다. 이 구간에 브라우저가 보내는 토큰은 `stale`로 관측될 수 있다.
  - `COOKIE_SECURE=true`면 `Secure` 추가

### 2.4 토큰 상태

| 상태 | 의미 |
|---|---|
| `valid` | 형식과 mac이 맞고, epoch가 현재 주기 |
| `grace` | 형식과 mac이 맞고, epoch가 현재보다 1 ~ `GRACE_EPOCHS`만큼 이전 |
| `stale` | 형식과 mac이 맞지만 유예보다 오래됨. **정상 만료도 포함**하므로 이것만으로 공격자의 재사용이라고 단정하지 않는다 |
| `invalid` | 형식 오류, mac 불일치, 미래 epoch |
| `missing` | 쿠키 없음. 브라우저가 만료된 쿠키를 지운 과거 방문자도 여기에 해당 |

### 2.5 판정표

| 분류 | 토큰 상태 | observe | enforce | 쿠키 발급 |
|---|---|---|---|---|
| exempt | 무관 | 통과 | 통과 | 안 함 |
| page | 무관 | 통과 | 통과 | `valid`가 아니면 발급 |
| api | `valid` | 통과 | 통과 | 안 함 |
| api | `grace` | 통과 | 통과 | 갱신 발급 |
| api | `stale` / `invalid` / `missing` | 통과 + `would_block` 기록 | **403** + `block` 기록 | 안 함 |

**쿠키 발급 규칙**
- 발급은 **백엔드를 거쳐 돌아온 응답**(`proxy_response` 결과)에만 붙인다.
- 게이트 차단(403), 기존 전략의 조기 반환(429 등), 백엔드 연결 실패(502)에는 발급하지 않는다.
- 백엔드 응답 상태가 5xx이면 발급하지 않는다. 그 외 상태(200, 3xx, 304, 4xx)와 HEAD 응답에는 발급한다.
- 백엔드의 기존 `Set-Cookie`는 그대로 두고 **추가**한다.
- 쿠키를 추가한 응답은 `Cache-Control`을 `no-store`로 **덮어쓴다.** 목적은 토큰을 발급한 응답이 HTTP 캐시에 저장되지 않게 하는 것이다.
  - 이 규칙은 **쿠키를 추가한 응답에만** 적용된다. `valid` 토큰으로 받은 페이지에는 적용되지 않는다.
  - 따라서 **캐시·뒤로 가기 캐시·서비스워커에서 복원된 화면의 토큰 재발급을 보장하지 않는다.** 복원 후 동작은 5.2에서 관찰한다.
  - 이 선택이 앱 동작에 주는 영향도 5.1·5.2에서 확인한다.

**차단 응답**
- 상태 403, 본문 `{"error":"token_required"}`, `Content-Type: application/json`, `X-Defense-Applied: token_gate`, `Cache-Control: no-store`
- 토큰 상태와 관계없이 **항상 같게** 만든다.
- 차단된 요청은 **백엔드로 보내지 않는다.**

### 2.6 응답 불일치 관찰 (약한 보조 신호)

- 조건: 분류가 `page`이고, 메서드가 `GET`이고, 백엔드 응답 상태가 `200`이고, 응답 `Content-Type`이 `application/json` 또는 `+json`으로 끝남
- 동작: 로그에 `"observation":"page_declared_json"`를 추가한다. **차단하지 않고, 응답도 바꾸지 않는다.**
- 이 신호가 말해주는 것은 "페이지처럼 요청했지만 JSON이 돌아왔다"까지다. 사람이 API 주소를 주소창에 직접 입력하거나 북마크로 열어도 생긴다. **에이전트라는 증거가 아니다.**
- HEAD, 304, 오류 응답, JSON이 아닌 다른 형식은 이번에 관찰하지 않는다 (`observation: null`).
- 유용성은 이후 "반복적인 API 직접 호출" 같은 다른 관찰과 결합해서 평가한다.

### 2.7 로그

**출력 설정** (Uvicorn 기본 설정은 임의의 logger를 출력하지 않으므로 직접 지정)
- `logging.getLogger("ruby.defense.token_gate")`
- 모드가 `observe`/`enforce`일 때만 설정: `StreamHandler(sys.stdout)` 1개, 레벨 `INFO`, `propagate = False`, 이미 handler가 있으면 추가하지 않음 (중복 출력 방지)
- 메시지는 `json.dumps(record, separators=(",", ":"), ensure_ascii=False)` 한 줄. 그래서 `"event":"token_gate"` 문자열로 필터링할 수 있다.

**형식** (요청당 한 줄, `exempt`는 기록하지 않음)

```json
{"event":"token_gate","ts":1790000000.0,"mode":"observe","client_id":"abc123","method":"GET","path":"/rest/user/login","kind":"api","token_state":"missing","has_sec_fetch":false,"ua_family":"curl","decision":"would_block","upstream_status":200,"observation":null}
```

- `decision`: `pass` / `issue` / `refresh` / `would_block` / `block`
- `upstream_status`: 백엔드로 보냈으면 그 상태, 차단했으면 `null`
- `ua_family`: `curl`, `wget`, `python-requests`, `python-urllib`, `httpx`, `aiohttp`, `go`, `node`, `browser`(Mozilla 포함), `other`, `none`
- **쿠키 값, 요청 본문, 쿼리 문자열은 기록하지 않는다.**
- 로그는 응답을 받은 뒤(차단이면 차단 시점에) 한 번만 남긴다.

### 2.8 설정 (환경변수)

| 변수 | 기본값 | 유효 범위 |
|---|---|---|
| `TOKEN_GATE_MODE` | `off` | `off` / `observe` / `enforce` (대소문자 무시). 그 외 값이면 **시작 실패** |
| `TOKEN_GATE_SECRET` | 빈 값 | 비면 무작위 생성 + 경고. **실험할 때는 반드시 고정값 지정** (`--reload`로 재시작될 때마다 토큰이 무효화되므로) |
| `TOKEN_GATE_EPOCH_S` | `300` | 정수 1 이상. 아니면 시작 실패 |
| `TOKEN_GATE_GRACE_EPOCHS` | `1` | 정수 0~10. 아니면 시작 실패 |
| `TOKEN_GATE_EXEMPT_PREFIXES` | `/healthz,/__defense/,/__detection/` | 2.2 비교 규칙 |
| `TOKEN_GATE_COOKIE_SECURE` | `false` | `true`/`false` |

**`off` 모드 규칙**: `TOKEN_GATE_MODE`만 읽고 나머지 변수는 **읽지도, 검증하지도 않는다.** secret 생성, 경고, logger 설정도 하지 않는다. 기존 동작과 완전히 같아야 한다.

---

## 3. 코드 변경

### 3.1 새 파일 `defense/app/token_gate.py`

`X-Defense-Plan`으로 켜는 전략이 아니라 모든 요청에 먼저 적용되는 전역 게이트이므로 `strategies/`가 아닌 `app/` 바로 아래에 둔다. 순수 함수 위주로 만들고 시간은 인자로 주입한다.

- `TokenGateConfig` (dataclass) + `TokenGateConfig.from_env(environ=os.environ)`
- `make_token(secret: bytes, epoch: int) -> str`
- `token_state(value: str | None, secret: bytes, now: float, cfg) -> str`
- `classify(method: str, path: str, headers, exempt: list[str]) -> str`
- `ua_family(user_agent: str | None) -> str`
- `evaluate(method, path, headers, cookie_value, now, cfg) -> GateDecision`
  - `GateDecision`: `kind`, `token_state`, `decision`, `block: bool`, `issue_cookie: bool`
- `build_set_cookie(cfg, now) -> str`
- `observe_response(decision, method, status, content_type) -> str | None` (2.6)
- `build_log(...) -> dict`, `emit(log: dict)`
- `blocked_response() -> starlette Response`

### 3.2 `defense/app/main.py` 수정 (최소한으로)

1. 모듈 로드 시 `TOKEN_GATE = TokenGateConfig.from_env()`. 테스트에서 patch할 수 있게 모듈 변수로 둔다.
2. `catch_all` 맨 앞, 기존 `plan` 처리 **전에**:
   - `TOKEN_GATE.mode == "off"`면 아무것도 하지 않는다.
   - 아니면 `evaluate(...)`를 호출한다. `block`이면 로그를 남기고 `blocked_response()`를 바로 반환한다.
3. 기존 `plan` 처리, 조기 반환(short_circuit), 502 처리는 **바꾸지 않는다.** 이 경로에서는 쿠키를 발급하지 않고, 게이트 로그는 `upstream_status: null`로 남긴다.
4. `proxy_response(upstream)` 결과에 대해:
   - `issue_cookie`이고 백엔드 상태가 5xx가 아니면 `response.raw_headers.append((b"set-cookie", ...))`로 추가하고, `cache-control`을 `no-store`로 교체한다.
   - `observe_response(...)`를 계산해 로그에 넣고 기록한다.

### 3.3 `docker-compose.local.yml` — defense 서비스 environment에만 추가

```yaml
      TOKEN_GATE_MODE: ${TOKEN_GATE_MODE:-off}
      TOKEN_GATE_SECRET: ${TOKEN_GATE_SECRET:-}
      TOKEN_GATE_EPOCH_S: ${TOKEN_GATE_EPOCH_S:-300}
      TOKEN_GATE_GRACE_EPOCHS: ${TOKEN_GATE_GRACE_EPOCHS:-1}
      TOKEN_GATE_EXEMPT_PREFIXES: ${TOKEN_GATE_EXEMPT_PREFIXES:-/healthz,/__defense/,/__detection/}
      TOKEN_GATE_COOKIE_SECURE: ${TOKEN_GATE_COOKIE_SECURE:-false}
```

운영용 `docker-compose.yml`은 이번에 건드리지 않는다.

### 3.4 스모크 스크립트 `defense/scripts/token_gate_smoke.py`

로컬 파이프라인(`http://localhost:8081`)을 대상으로 한다. 의존성은 기존 `httpx`만 쓴다. **쿠키 저장소를 쓰지 않고, 토큰 문자열을 직접 저장해 명시적으로 보낸다.**

| # | 요청 | enforce 기대 결과 |
|---|---|---|
| 1 | 쿠키 없이 `GET /rest/products/search?q=apple`, `Accept: */*` | 403, 본문 `{"error":"token_required"}`, `X-Defense-Applied: token_gate` |
| 2 | `GET /`, `Accept: text/html` | 200, `__ruby_tg` Set-Cookie, `Max-Age` ≤ `EPOCH_S × (GRACE+1)`, `Cache-Control: no-store` |
| 3 | 2의 토큰을 직접 붙여 1과 같은 요청 | 200 |
| 4 | 위조 토큰 `v1.1.AAAAAAAAAAAAAAAAAAAAAA`로 1 | 1과 같은 403 (본문·헤더까지 동일) |
| 5 | (`--stale`) `EPOCH_S × (GRACE+1)`보다 오래 기다린 뒤 **2에서 저장한 토큰 문자열을 직접 붙여** 1 | 1과 같은 403 |
| 6 | `OPTIONS /rest/products/search` | `off` 모드 기준 응답(`--baseline`)과 **상태가 같고**, `X-Defense-Applied`에 `token_gate` 없음 |
| 7 | `GET /rest/products/search?q=apple`, `Accept: text/html` (헤더 흉내) | 200 (통과. 2.6 관찰 대상) |

- 인자: `--base-url`(기본 `http://localhost:8081`), `--stale`, `--epoch-s`, `--grace`, `--record-baseline PATH`, `--baseline PATH`
  - `--record-baseline`: `off` 모드에서 실행해 6번 요청의 상태와 `Allow`·`Access-Control-Allow-*` 헤더를 JSON으로 저장하고 종료
  - `--baseline`: 저장한 값과 6번 결과를 비교. 지정하지 않으면 6번은 SKIP으로 표시 (PASS로 치지 않음)
- 항목별 PASS/FAIL 출력, 하나라도 실패하면 종료 코드 1
- 5·7의 로그 확인(`token_state=stale`, `observation=page_declared_json`)은 5.2 절차에서 사람이 한다.

---

## 4. 테스트 (unittest, CI와 같은 방식)

저장소 루트에서 실행한다.

```bash
python -m unittest discover -s defense/tests -p 'test_*.py'
cd defense && python -c "import app.main"
```

`defense/tests/test_token_gate.py`에 최소한 다음을 넣는다.

**설정**
- `off`: 다른 변수가 잘못돼 있어도(예: `EPOCH_S=abc`) 시작에 성공하고, secret을 생성하지 않고, 경고를 남기지 않는다
- `observe`/`enforce`: 잘못된 mode, `EPOCH_S` 0·음수·문자, `GRACE` 음수·11 → 예외
- 예외 목록: 빈 항목 제거, 공백 제거

**토큰**
- 같은 secret·epoch면 같은 토큰, 다르면 다른 토큰
- 상태: `valid`, `grace`(1주기 전), `stale`(GRACE+1주기 전), `invalid`(mac 변조, 형식 오류, 13자리 epoch, 65자 이상, 미래 epoch), `missing`
- `GRACE_EPOCHS=0`: 1주기 전 토큰이 `stale`
- **주기 경계**: `now = k × EPOCH_S − 0.001`과 `k × EPOCH_S` 양쪽에서 상태가 규칙대로 바뀜
- `Max-Age`: 주기 시작 직후, 끝나기 직전, 남은 시간이 1초 미만일 때 모두 **`max(1, floor(expires_at − now))` 공식과 일치**. `EPOCH_S=1, GRACE=0`에서도 공식과 일치

**분류**
- 브라우저 페이지 요청 → `page`, `Sec-Fetch-Mode: navigate` → `page`, `POST` + `Accept: text/html` → `api`, `Accept: */*` → `api`, 이미지 요청(`Accept: image/*`) → `api`, `/socket.io/?EIO=4` → `api`, `OPTIONS` → `exempt`
- 예외: `/healthz` → `exempt`, `/healthz-admin` → `api`, `/__defense/x` → `exempt`

**판정·로그**
- observe: api + missing → 통과 + `would_block`
- enforce: api + missing/stale/invalid → `block`, 세 경우 응답(상태·본문·헤더)이 모두 같음
- page + missing → `issue_cookie`, api + grace → `issue_cookie`(갱신)
- 쿠키 문자열: `HttpOnly`, `SameSite=Lax`, `Path=/`, `Max-Age` 포함. `COOKIE_SECURE`일 때만 `Secure`
- 로그 dict에 쿠키 값·쿼리 문자열이 없음. `json.dumps` 결과에 `"event":"token_gate"`가 공백 없이 들어 있음
- `observe_response`: page+GET+200+`application/json` → `page_declared_json`, `application/problem+json`도 해당, HEAD·304·404·`text/html` → `None`

**통합 (`main.py`)**
- starlette `TestClient` 사용. 백엔드 호출은 `defense.app.main.httpx.AsyncClient`를 가짜 클래스로 patch해서 네트워크 없이 테스트한다. 가짜 클래스는 호출 횟수를 센다.
- `off`: 기존 전략(`delay` 등 `X-Defense-Plan`)이 그대로 실행되고, 응답 상태·본문·헤더가 게이트 도입 전과 같고, `Set-Cookie`가 추가되지 않음
- enforce: 쿠키 없는 API 요청 → 403이고 **백엔드 호출 0회**
- page 요청: 백엔드 `Set-Cookie` 2개와 `__ruby_tg`가 **모두** 응답에 있고, `Cache-Control: no-store`
- 백엔드 500 응답·502(연결 실패)·기존 전략 429 조기 반환 → `__ruby_tg` 없음
- HEAD page 요청 → 발급됨
- 백엔드 304 응답(page, 토큰 없음) → 발급됨, 상태 304 유지, 본문 없음
- 백엔드 302 리다이렉트(page, 토큰 없음) → 발급됨, `Location` 헤더 보존
- **OPTIONS**(전략 없음) → 백엔드 호출 **1회**, 백엔드 상태·헤더 보존, `__ruby_tg` 없음, 게이트 로그 없음
- **판정표 전체**: observe·enforce × `page`·`api` × `valid`·`grace`·`stale`·`invalid`·`missing` 조합(20개)을 표 기반 테스트로 돌려서 2.5 판정표와 일치하는지 확인
- **느린 응답 + 주기 경계**: 요청은 주기 k에서 `grace`로 판정되고 백엔드 응답은 주기 k+1에 돌아오는 경우, 발급 쿠키의 epoch가 **응답 시점 기준(k+1)**이고 `Max-Age`도 그 기준인지 확인 (시간은 가짜 시계로 주입)
- **동시 갱신**: 같은 `grace` 토큰으로 동시에 들어온 요청 2개가 모두 통과하고, 같은 주기라면 같은 새 토큰을 받는지 확인
- logger 출력: `assertLogs` 또는 handler 교체로 요청당 한 줄이 실제로 출력되는지 확인

---

## 5. 로컬 확인 절차 (사람이 직접)

**시작 전 공통**
- 0절 Detection 쿠키 문제가 해결됐는지 확인한다. 안 됐으면 결과에 "Detection 쿠키 오염 있음"을 표시하고, 그 결과는 **참고용**이다 (6절 실험 완료로 인정하지 않음).
- secret을 고정한다.

### 5.1 오탐 확인 — observe 모드 + 실제 브라우저

```powershell
# Windows PowerShell
$env:TOKEN_GATE_MODE="observe"; $env:TOKEN_GATE_EPOCH_S="60"; $env:TOKEN_GATE_SECRET="local-test-secret-change-me"
docker compose -f docker-compose.local.yml up --build
```

**① 로그가 실제로 찍히는지 먼저 확인** (안 찍히면 "0건"을 믿을 수 없음)

```powershell
curl.exe -s -o NUL http://localhost:8081/rest/products/search?q=apple
docker logs defense 2>&1 | Select-String '"event":"token_gate"' | Select-Object -Last 1
```

→ `"decision":"would_block"` 한 줄이 나와야 한다.

**② 브라우저로 `http://localhost:8081`에서 다음을 해본다**

- [ ] 첫 화면, 상품 검색, 상품 상세
- [ ] 회원가입, 로그인, 로그아웃
- [ ] 장바구니 담기, 결제 진행
- [ ] 새로고침, 뒤로 가기·앞으로 가기, 새 탭으로 열기
- [ ] 북마크한 주소(예: `/#/search`)로 바로 접속
- [ ] 스크롤로 이미지 지연 로딩

**③ 결과 확인**

```powershell
docker logs defense 2>&1 | Select-String '"event":"token_gate"' | Select-String 'would_block'
```

**기대 결과**: ①에서 만든 한 줄 외에는 `would_block` 0건. 나온 건 경로·`token_state`·`ua_family`를 기록해서 기획에 반영한다.

### 5.2 enforce 모드 — 파이프라인 확인 + 스모크 + 실제 브라우저

**준비: 기준 응답 저장 → enforce로 다시 띄우기**

```powershell
# 1) off 모드로 띄운 상태에서 스모크 6번의 기준 응답 저장
$env:TOKEN_GATE_MODE="off"
docker compose -f docker-compose.local.yml up --build -d
python defense/scripts/token_gate_smoke.py --record-baseline smoke-baseline.json   # 이 파일은 커밋하지 않는다

# 2) enforce 모드로 다시 띄우기
docker compose -f docker-compose.local.yml down
$env:TOKEN_GATE_MODE="enforce"; $env:TOKEN_GATE_EPOCH_S="10"; $env:TOKEN_GATE_SECRET="local-test-secret-change-me"
docker compose -f docker-compose.local.yml up --build -d
```

**① 전체 경로 확인** (0절 해결 후. 쿠키가 없는 새 클라이언트로)

```powershell
curl.exe -s -D - -o NUL -H "Accept: text/html" -H "Sec-Fetch-Mode: navigate" http://localhost:8081/
docker logs defense 2>&1 | Select-String '"event":"token_gate"' | Select-Object -Last 1
```

- 응답 헤더에 `Set-Cookie`가 **`__ruby_tg`, `dcid`, `dlsid` 셋 다** 있어야 한다. 하나라도 없으면 0절 문제가 남아 있는 것이다.
- 로그 마지막 줄이 `"kind":"page"`, `"has_sec_fetch":true`여야 한다. 헤더가 Defense까지 실제로 전달됐다는 확인이다.

**② 스모크**

```powershell
python defense/scripts/token_gate_smoke.py --stale --epoch-s 10 --grace 1 --baseline smoke-baseline.json
docker logs defense 2>&1 | Select-String 'stale|page_declared_json'
```

→ 스모크 전 항목 PASS(6번 포함, SKIP 없이), 5번에 해당하는 `"token_state":"stale"`, 7번에 해당하는 `"observation":"page_declared_json"` 확인

**③ 브라우저 시나리오** (EPOCH 60초로 다시 띄워서 진행)

**정상 흐름 — 통과해야 함 (호환성 기준)**

| 시나리오 | 방법 | 통과 조건 |
|---|---|---|
| 5.1 ②의 정상 흐름 | 그대로 반복 | 403 **0건** |

**한계 시나리오 — 막혀도 실패가 아니라 관찰·기록 대상**

먼저 서비스워커를 쓰는지 확인한다: 개발자 도구 → Application → Service Workers. 등록된 게 있으면 아래 "서비스워커 복원" 행도 진행한다. (현재 Juice Shop의 서비스워커 사용 여부는 **미확인**)

| 시나리오 | 방법 | 기록할 것 |
|---|---|---|
| 장기 방치 | 탭을 3분 이상 두고 버튼 클릭. **개발자 도구 네트워크 탭에서 `/socket.io/` polling이 그동안 계속 갱신했는지 확인** | 403 여부, 갱신 여부 |
| 절전 복귀 | 노트북 절전 3분 → 복귀 후 클릭 | 403 여부, 새로고침으로 복구되는지 |
| 뒤로 가기 | 만료 후 뒤로 가기 → 클릭 | 페이지를 네트워크로 다시 받는지 (`no-store` 효과) |
| 지연 로딩 | 만료 후 스크롤 | 이미지·JS 청크 실패 여부 |
| socket.io 재연결 | 개발자 도구에서 오프라인 전환 3분 → 온라인 | 재연결 성공 여부 |
| 서비스워커 복원 | (서비스워커가 있을 때만) 만료 후 탭을 닫았다가 다시 열기 → 검색 등 API 호출 | 화면이 캐시에서 떴는지, 이후 API 403 여부 |

### 5.3 (선택) 에이전트 관찰

enforce 모드에서 에이전트를 붙여서 다음을 기록한다.

- 403을 받은 뒤 적응하는가, 어떻게 적응하는가 (페이지 요청으로 쿠키 획득 / **API에 `Accept: text/html`만 붙이기** / 포기)
- 적응까지 걸린 요청 수와 시간
- 적응한 뒤 요청 패턴과 `page_declared_json` 발생 횟수 (3단계 신호 설계의 입력)

---

## 6. 완료 기준

**구현 완료 (Codex 담당)**
- [x] 기존 테스트 + 새 테스트 전부 통과 (4절 명령)
- [x] `TOKEN_GATE_MODE=off`에서 기존 동작과 차이 없음 (통합 테스트로 확인)
- [x] 새 의존성 추가 없음 (`defense/requirements.txt` 변경 없음)
- [x] 변경 파일이 3절 목록뿐

**실험 완료 (사람 담당)**

"실험 완료"는 **호환성이 전부 통과했다는 뜻이 아니다.** 정상 흐름은 통과해야 하고, 한계 시나리오는 관찰해서 기록하면 된다.
- [ ] 0절 Detection 쿠키 문제 **해결됨** (미해결 상태에서 수행한 아래 항목은 참고용이며 완료로 인정하지 않음)
- [ ] 5.1 ① 로그 출력 확인
- [ ] 5.1 observe 브라우저 결과 기록 (`would_block` 목록)
- [ ] 5.2 ① 전체 경로 확인 (쿠키 3개 보존, 헤더 전달)
- [ ] 5.2 ② 스모크 전 항목 PASS (6번 포함, SKIP 없이)
- [ ] 5.2 ③ **정상 흐름 403 0건** (호환성 통과)
- [ ] 5.2 ③ 한계 시나리오 관찰 결과 기록 (관찰 완료)

## 7. 알려진 한계 (이번 범위에서 해결하지 않음)

- **헤더 흉내로 우회**: GET API에 `Accept: text/html`을 붙이면 토큰 없이 통과한다 (1.5).
- **응답 관찰은 사후 기록**: `page_declared_json`은 이미 실행된 요청을 막지 못하고, 에이전트라는 증거도 아니다.
- **토큰 회전은 비용 증가를 보장하지 않음**: 요청을 이어가는 클라이언트는 자동 갱신된다 (1.4).
- **브라우저를 조종하는 에이전트**(Playwright 등)는 통과한다.
- **정상 사용자가 막힐 수 있는 경우**: 절전·장기 방치 뒤 만료, 캐시에서 복원된 화면, 지연 로딩. 5.2에서 실제로 확인한다.
- **지원 범위 밖**: 다른 origin 리소스, `credentials: "omit"` 요청, 외부 사이트에서 돌아오는 POST(`SameSite=Lax`), 모바일 앱·외부 연동 같은 쿠키 없는 정상 클라이언트.
- **WebSocket**: 기존 프록시가 중계하지 않는 별도 한계.
- **Detection 쿠키 덮어쓰기**: 0절. 해결 전까지 통합 실험 결과가 오염된다.
- 토큰이 사용자에게 묶여 있지 않아 여러 클라이언트가 공유할 수 있다.
- 로그는 단일 프로세스 stdout이다.

## 8. 다음 단계 (이번 범위 아님)

- 0절 Detection 쿠키 병합 수정 → 탐지팀에 이슈 또는 PR
- 3단계: 신호를 Detection으로 전달 (응답 헤더 + `deceptionEngine.js`에 신호 추가) → 탐지팀과 PR로 협의
- 실험 옵션(기본 off): 토큰 없는 `page` 요청의 JSON 응답을 403으로 바꾸기. 결과 유출은 줄지만 API 주소를 직접 연 사람도 막으므로 5.1 오탐 데이터를 본 뒤 결정
- 토큰을 Client-Id에 묶기
- 경로 자체를 바꾸는 별칭 (2b단계)
- RUBY Market(`feat/benchmark-target-selection`)에서 같은 절차로 확인
- `ruby-defense-grader`로 적응형 공격자 포함 평가

---

## 구현 지시 (Codex 등 구현 에이전트용)

1. **브랜치**: 최신 `main`에서 `feature/defense-token-gate`를 만든다. `main`에 직접 커밋하지 않는다.
2. **줄바꿈 주의**: 이 작업 폴더에는 줄바꿈(CRLF) 차이 때문에 "수정됨"으로 보이는 파일이 많다. `git add -A`나 `git add .`를 쓰지 말고, **이 작업에서 만들거나 고친 파일만 경로를 지정해서** 스테이징한다. 새 파일은 LF로 저장한다. 기존 파일을 고칠 때 파일 전체의 줄바꿈을 바꾸지 않는다.
3. **수정 범위**: `defense/app/token_gate.py`(새 파일), `defense/app/main.py`, `defense/tests/test_token_gate.py`(새 파일), `defense/scripts/token_gate_smoke.py`(새 파일), `docker-compose.local.yml`의 defense environment, 이 기획서(`defense/docs/token-gate-plan.md`). 이 밖의 파일, 특히 `detection/`과 `detection/config/policy.json`은 **절대 수정하지 않는다.**
4. **의존성**: 새 패키지를 추가하지 않는다. 표준 라이브러리 + 기존 `fastapi`/`starlette`/`httpx`만 쓴다. 로컬에 의존성이 없으면 가상환경에 `defense/requirements.txt`만 설치해서 테스트한다.
5. **기존 테스트 형식**: `unittest`와 `from defense.app... import ...` 방식을 따른다 (`defense/tests/test_delay.py` 참고).
6. **검증**: 4절 명령을 실행해 전부 통과하는지 확인하고, 결과를 PR 설명에 적는다. 실행하지 못한 검증이 있으면 그 사실과 이유를 적는다.
7. **모호한 부분**: 이 문서와 코드가 충돌하거나 판단이 필요한 부분은 임의로 정하지 말고, 선택한 내용과 이유를 PR 설명의 "결정 사항" 절에 적는다.

---

## 구현 기록 (2026-09-29, PR 설명용)

### 변경 내용

`feature/defense-token-gate`를 최신 `origin/main` (`4c5cbff`)에서 생성했다. 쿠키 게이트를 기존 전략 처리 전에 적용하며, 활성 모드에서만 판정·로그를 수행한다. 토큰 발급은 응답 시점의 epoch로 계산하고 백엔드 쿠키를 보존한다. Detection과 requirements는 수정하지 않았다.

### 결정 사항

- JSON 관찰은 `Content-Type`의 매개변수(`; charset=utf-8` 등)를 제거하고 대소문자를 정규화한 미디어 타입에 적용한다. 정상 JSON 응답의 표기 차이로 관찰이 누락되지 않게 하기 위함이다.
- 활성 모드의 `COOKIE_SECURE`는 대소문자를 무시한 `true`/`false`만 허용하고 다른 값이면 시작을 실패시킨다. 잘못된 값이 조용히 비보안 설정으로 해석되지 않게 하기 위함이다. `off`에서는 이 값도 읽지 않는다.
- 조기 반환·백엔드 5xx에서는 `decision`을 요청 시점 판정(`issue`/`refresh` 포함)으로 유지하지만 실제 쿠키는 발급하지 않는다. `decision`은 발급 의도이며, 조기 반환은 `upstream_status: null`, 백엔드 5xx는 실제 상태로 구분한다.
- 스모크는 요청마다 독립적인 `httpx.request`를 사용해 자동 쿠키 재전송을 막는다. 3·5번만 최초에 저장한 토큰을 명시적으로 보내며, OPTIONS는 상태와 `Allow`·`Access-Control-Allow-*` 헤더를 모두 기준 응답과 비교한다. 변동하는 Detection 쿠키 등 전체 HTTP 헤더의 동일성은 요구하지 않는다.

### 검증 결과

기존 `defense/requirements.txt`만 `.venv`에 설치해 다음을 실행했다.

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s defense/tests -p 'test_*.py'
# Ran 31 tests ... OK (판정표 20개 조합은 subTest로 추가 검증)

# defense/ 디렉터리에서
..\.venv\Scripts\python.exe -c "import app.main"
# 종료 코드 0

# 저장소 루트에서
docker compose -f docker-compose.local.yml config --quiet
git diff --check
# 각각 종료 코드 0
```

최초 제한 환경 실행에서는 스모크 단위 테스트 2개의 Windows 임시 폴더 접근·정리가 거부됐다. 같은 테스트를 승인된 권한으로 재실행해 전부 통과했다. 스모크 스크립트의 baseline 저장·비교, 최초 토큰 재전송, 실패 종료 코드 및 SKIP 표시는 가짜 HTTP 응답으로 검증했다.

실제 Detection 경유 스모크와 브라우저 실험(5절)은 실행하지 않았다. 0절의 쿠키 병합 수정은 이번 범위 밖이며, 해당 선행 조건이 충족된 뒤 사람 담당 실험을 진행한다.

### 추가 작업: Detection 쿠키 병합 수정

후속 사용자 요청으로 수정 범위를 `detection/lib/proxyCore.js`와 `detection/test/proxyCore.test.js`까지 확대했다. 위 구현 지시의 Detection 수정 금지와 최초 구현 기록은 최초 Defense 작업에 대한 내용이다.

`onProxyRes` 진입 시 Detection 응답 쿠키를 복사해 보관하고, `responseInterceptor`가 백엔드 헤더를 복사한 뒤 보관한 쿠키와 병합한다. 백엔드 쿠키가 없을 때는 기존 Detection 쿠키를 그대로 유지한다. 라이브러리의 기존 백엔드 쿠키 처리와 응답 본문 훅은 유지한다.

- 실제 로컬 HTTP 프록시 회귀 테스트: 8개 통과. Detection 쿠키 2개와 백엔드 쿠키 2개·게이트 쿠키 동시 보존, 한쪽에만 쿠키가 있는 경우, 문자열 쿠키, 동시 응답 격리, 요청 헤더 전달 및 본문 훅을 확인했다.
- Detection 전체 `node --test`: 총 122개, 121개 통과, 실패 0개, SKIP 1개. SKIP은 실제 CRS 바이너리가 필요한 테스트다.
- 로컬 소스의 쿠키 병합은 검증됐지만 기존 프록시 서버에 배포되었는지는 아직 확인하지 않았다. 6절의 공식 실험 완료 항목은 그대로 미완료이며, 해당 서버의 배포 버전과 최종 쿠키 보존을 확인한 뒤 진행한다.
