# proxy_core — 재사용 가능한 패스스루 역방향 프록시 코어

클라이언트 ↔ 백엔드 사이에서 요청/응답을 그대로 중계하는 최소 HTTP 코어와,
계층별 로직을 꽂는 훅(``ProxyHook``) 인터페이스를 제공한다.
관찰(로깅)·탐지(위험도 산정/허니토큰)·방어(차단·변환·지연·기만) 는 모두 이 코어
위에 훅으로 얹어 각각 별도 앱으로 구성한다.
```
from proxy_core import ProxyHook, create_app

class MyHook(ProxyHook):
    async def on_request(self, ctx): ...
    async def on_response(self, ctx): ...

app = create_app([MyHook()])          # uvicorn 으로 기동
```

훅 종류
    on_request(ctx)   : 백엔드로 보내기 전. ``Response`` 를 반환하면 즉시 종료
                        (차단·기만·캐시). ``ctx.body`` / ``ctx.forward_headers`` /
                        ``ctx.target_url`` / ``ctx.meta`` 를 수정해 요청을 변형.
    on_response(ctx)  : 백엔드 응답을 받은 뒤, 클라이언트로 돌려주기 전.
                        ``ctx.response_status`` / ``ctx.response_headers`` /
                        ``ctx.response_body`` 를 수정해 응답을 변형.
    on_error(ctx, exc): 백엔드 연결 실패 시. ``Response`` 를 반환하면 기본 502 대신 사용.

훅은 리스트 순서대로 실행된다. 관찰(로깅) 훅은 보통 맨 앞에 둔다.

계층별 연결 지점 (구현은 각 계층에서 — detection/app, defense/)
    관찰  : on_request / on_response 에서 ctx 를 읽어 로깅·수집.  (packet_proxy.LoggingHook)
    탐지  : on_request 에서 위험도를 산정해 다음 홉으로 전달.
              ctx.forward_headers["X-Risk-Score"] = str(score)
              ctx.meta["risk_score"] = score          # 뒤 훅과 공유
    방어  : on_request 에서
              - 차단 : return Response(status_code=403)          # 백엔드로 안 감
              - 기만 : return JSONResponse(fake_body)            # 가짜 응답
              - 지연 : await asyncio.sleep(n)                    # 타르핏
              - 변환 : ctx.body = rewritten                     # 요청 본문 수정
            on_response 에서
              - 변환 : ctx.response_body / ctx.response_headers 수정 (지문 제거 등)
    (훅이 백엔드를 건너뛰면 ctx.short_circuited 가 True 가 된다.)

``create_app(..., before_catchall=fn)`` 으로 캐치올보다 먼저 매칭돼야 하는 전용
라우트(트랩 엔드포인트 등)를 등록할 수 있다 — ``fn(app)`` 안에서 ``@app.get(...)``.

# Packet Proxy (패킷 가시성 역방향 프록시)

클라이언트와 실제 백엔드 사이에 끼어서, 오가는 **모든 요청/응답 패킷(메서드·URL·헤더·본문)을
터미널에 실시간으로 로깅**하는 최소 역방향 프록시입니다. 탐지·스코어링·DB 저장 같은
제어 로직은 없습니다 — 트래픽을 "있는 그대로 통과시키며 들여다보는" 관찰용 도구입니다.

```
[클라이언트]  ──►  packet_proxy (:3002)  ──►  [백엔드  REAL_BACKEND (:3000)]
 curl/브라우저       │  ▲                        예: OWASP Juice Shop
                     ▼  │  요청·응답을 그대로 stdout 에 로깅
              프록시 터미널 (uvicorn 실행 창)
```

> **핵심**: curl/브라우저는 **프록시 포트(:3002)** 로 보내야 로그가 남습니다.
> 백엔드(:3000) 로 직접 보내면 프록시를 안 거치므로 아무것도 안 찍힙니다.

---

## 1. 구조 — `proxy_core`(엔진) + `packet_proxy`(로깅 훅)

| 파일 | 역할 |
|---|---|
| [`proxy_core.py`](proxy_core.py) | **재사용 엔진.** 요청 중계·헤더 정제·502 처리만 담당. 로깅/탐지/방어는 모름. `ProxyContext` + `ProxyHook` + `create_app()` 제공. |
| [`packet_proxy.py`](packet_proxy.py) | **`proxy_core` + `LoggingHook` 1개.** ctx 를 읽어 `▶`/`◀` 블록만 출력, 트래픽은 무변조 통과. `app` 을 `uvicorn` 으로 기동. |
| `requirements.txt` | 의존성 (`fastapi`, `uvicorn`, `httpx`). |

탐지 계층([`../app/`](../app/))·방어 계층(`../../defense/`)도 **같은 `proxy_core` 에 자기 훅만
꽂아** 별도 앱으로 만듭니다. 그래서 중계 동작(헤더 보존, hop-by-hop, 압축 해제, 502 등)이
계층마다 어긋나지 않습니다.

### `proxy_core` 가 주는 3가지

**`ProxyContext`** — 요청 1건이 프록시를 지나는 동안의 가변 상태. 훅들이 이걸 읽고 고치며
서로 정보를 주고받습니다.

| 필드 | 내용 | 훅이 수정? |
|---|---|---|
| `request`, `trace_id`, `method`, `path` | 원본 요청 정보 | 읽기 |
| `body` | 요청 본문 bytes | ✅ (요청 본문 변조) |
| `forward_headers` | 백엔드로 보낼 헤더 dict | ✅ (예: `X-Risk-Score` 주입) |
| `target_url`, `query_params` | 백엔드 URL·쿼리(중복 키 보존) | ✅ (리라우팅) |
| `response_status` / `response_headers` / `response_body` | 백엔드 응답 후 채워짐 | ✅ (응답 변조) |
| `meta` | `{}` — 훅 간 공유 채널 (`sid`, `risk_score`, `error` …) | ✅ |
| `short_circuited` | 훅이 백엔드를 건너뛰었는가 | 읽기 |

**`ProxyHook`** — 계층별 로직을 꽂는 자리. 필요한 것만 오버라이드.

| 메서드 | 언제 | 반환 |
|---|---|---|
| `on_request(ctx)` | 백엔드로 보내기 **전** | `Response` → 즉시 종료(차단·기만·캐시) / `None` → 계속 |
| `on_response(ctx)` | 클라이언트로 돌려주기 **전** | `None` (ctx 를 수정) |
| `on_error(ctx, exc)` | 백엔드 연결 실패 시 | `Response` → 기본 502 대체 / `None` |

**`create_app(hooks, *, backend, title, timeout, before_catchall)`** — 위를 조립해 FastAPI 앱 반환.
`before_catchall=fn` 을 주면 `fn(app)` 안에서 캐치올보다 **먼저** 매칭될 전용 라우트를
등록할 수 있습니다(트랩 엔드포인트 등).

### 요청 하나가 흐르는 과정 (`create_app` 내부)

```
클라이언트 요청
   │
   │── before_catchall 로 등록된 전용 라우트가 매칭 → 거기서 처리하고 끝
   ▼
캐치올  _proxy(request, "{full_path}")
   1. forward_headers 구성 — _REQUEST_SKIP(hop-by-hop·host·length) 제외,
      accept-encoding: identity 강제(백엔드 응답을 비압축으로 받아 훅이 본문 다루기 쉽게)
   2. ProxyContext 생성 (trace_id 발급, body 읽음, meta={})
   3. for hook in hooks:  await hook.on_request(ctx)
        └ Response 반환 시 → short-circuit, 백엔드 건너뜀
   4. (단축 아니면) httpx 로 ctx.target_url 에 요청
        성공 → ctx.response_* 채움 (_RESPONSE_SKIP=hop-by-hop·length·encoding 제외,
               나머지 — Set-Cookie 다중·Location·보안 헤더 — 전부 보존)
        httpx.HTTPError → ctx.meta["error"] → on_error 훅 → 없으면 502
   5. for hook in hooks:  await hook.on_response(ctx)
        └ 단축·에러 응답도 여기 옴 → ctx.response_* 최종 수정
   6. _response_from(ctx) → starlette Response 조립 (raw_headers 로 다중 Set-Cookie 보존,
      Content-Length 재계산)
   ▼
클라이언트로 반환
```

### `packet_proxy` 의 `LoggingHook`

| 훅 | 하는 일 |
|---|---|
| `on_request` | `▶ [ts] [trace_id] REQUEST …` + 헤더 + 본문을 **한 번의 `print`** 로 (동시 요청 시 줄 안 섞임). `return None` — 중계 그대로 진행 |
| `on_response` | `◀ … RESPONSE STATUS …` + 헤더 + 본문. `meta["error"]` 있으면 `[ERROR]` 줄, 단축이면 `(short-circuit: …)` 태그 |

딸린 부속(로깅 관심사): `MAX_BODY_LOG`(본문 상한), `_looks_textual`/`_format_body`
(텍스트/바이너리 판별, `<Binary Data: N bytes>`, `... (truncated)`). stdout UTF-8 고정은
`proxy_core` import 시점에 처리됩니다.

---

## 2. 설치

```bash
cd detection/proxy
python -m venv .venv
# PowerShell:  .venv\Scripts\Activate.ps1
# cmd:         .venv\Scripts\activate.bat
# bash:        source .venv/bin/activate
pip install -r requirements.txt
```

---

## 3. 빠른 시작 — Juice Shop 으로 패킷 로깅 확인

터미널 **3개**를 씁니다.

### 터미널 1 — 백엔드(Juice Shop) 기동

```powershell
# 이미 만든 컨테이너가 있으면 start, 없으면 run
docker start juice-shop
# 처음이면:
#   docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
```
`http://127.0.0.1:3000` 이 200 을 주면 준비 완료입니다(첫 부팅 30초~2분).
```powershell
# PowerShell / cmd
curl.exe -s -o NUL -w "%{http_code}\n" http://127.0.0.1:3000/
```
```bash
# bash
curl.exe -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:3000/
```

### 터미널 2 — 프록시 기동 (포트 3002)

`detection/proxy` 에서 (백엔드 주소만 환경변수로 지정하는 방식이 셸마다 다릅니다):
```powershell
# PowerShell
$env:REAL_BACKEND = "http://127.0.0.1:3000"
uvicorn packet_proxy:app --host 127.0.0.1 --port 3002 --no-server-header
```
```bat
:: cmd
set REAL_BACKEND=http://127.0.0.1:3000
uvicorn packet_proxy:app --host 127.0.0.1 --port 3002 --no-server-header
```
```bash
# bash
REAL_BACKEND=http://127.0.0.1:3000 uvicorn packet_proxy:app --host 127.0.0.1 --port 3002 --no-server-header
```
아래가 뜨면 대기 상태입니다. **이 창을 닫지 말고 그대로 두세요.**
```
INFO:     Uvicorn running on http://127.0.0.1:3002 (Press CTRL+C to quit)
```
> `--no-server-header` 는 응답의 `Server: uvicorn` 헤더만 제거합니다(로깅과 무관, 생략 가능).
> `--reload` 는 붙이지 마세요(로그 두 번 찍힘).

### 터미널 3 — 요청 보내기 (`curl.exe`)

**① GET — 헤더·경로·쿼리 캡처**
```powershell
curl.exe "http://127.0.0.1:3002/rest/products/search?q=apple" -H "User-Agent: PacketTest/1.0"
```

**② POST — 본문(공격 페이로드) 캡처** — 따옴표 처리가 셸마다 다릅니다.
```powershell
# PowerShell  ( --% 필수: 이거 빼면 파싱 에러로 요청 자체가 안 나감 )
curl.exe --% -X POST http://127.0.0.1:3002/rest/user/login -H "Content-Type: application/json" -d "{\"email\":\"' OR 1=1--\",\"password\":\"x\"}"
```
```bat
:: cmd  ( \" 로 이스케이프, ' 는 그대로 )
curl.exe -X POST http://127.0.0.1:3002/rest/user/login -H "Content-Type: application/json" -d "{\"email\":\"' OR 1=1--\",\"password\":\"x\"}"
```
```bash
# bash  ( 작은따옴표로 감싸고 내부 ' 는 '"'"' 로 )
curl.exe -X POST http://127.0.0.1:3002/rest/user/login -H "Content-Type: application/json" -d '{"email":"'"'"' OR 1=1--","password":"x"}'
```


**③ 브라우저로 통짜 확인**  
<http://127.0.0.1:3002> 접속 → Juice Shop 전체가 프록시를 통해 뜨고, 클릭할 때마다 터미널 2 에 로그가 쌓입니다.

### 정리

```powershell
docker stop juice-shop            # 백엔드 종료 (컨테이너는 남음, 다음엔 docker start)
# 터미널 2 는 Ctrl+C
```

---

## 4. 로그 읽는 법

요청 1건마다 8자리 `trace_id` 가 붙고, `▶ REQUEST` 와 `◀ RESPONSE` 가 같은 id 로 짝지어집니다.
패킷 블록은 한 번의 write 로 출력되므로 동시 요청이 많아도 라인이 섞이지 않습니다.
로그는 **터미널 2(프록시 실행 창)의 화면**에 그대로 출력됩니다(별도 파일 없음).

빠른 시작 ① 요청을 보냈을 때 터미널 2 출력 예시:

```
================================================================================
▶ [2026-08-27T10:46:24.226+09:00] [9af8f386] REQUEST  GET http://127.0.0.1:3002/rest/products/search?q=apple
--------------------------------------------------------------------------------
[Headers]
  host: 127.0.0.1:3002
  user-agent: PacketTest/1.0
  accept: */*
================================================================================

================================================================================
◀ [2026-08-27T10:46:25.024+09:00] [9af8f386] RESPONSE 200  GET http://127.0.0.1:3000/rest/products/search
--------------------------------------------------------------------------------
[Headers]
  x-content-type-options: nosniff
  x-frame-options: SAMEORIGIN
  content-type: application/json; charset=utf-8
  content-length: 921
[Body]
{"status":"success","data":[ ... ]}
================================================================================
INFO:     127.0.0.1:63758 - "GET /rest/products/search?q=apple HTTP/1.1" 200 OK
```

| 줄 | 의미 |
|---|---|
| `▶ [시각] [trace_id] REQUEST  METHOD URL` | 클라이언트→프록시 요청. URL 에 쿼리스트링 포함. |
| 요청 `[Headers]` | 클라이언트가 보낸 헤더 그대로. |
| 요청 `[Body]` | POST/PUT 등의 본문(있을 때만). |
| `◀ [시각] [trace_id] RESPONSE STATUS  METHOD 백엔드URL` | 프록시←백엔드 응답. `trace_id` 로 위 요청과 짝. |
| 응답 `[Headers]` | 백엔드 응답 헤더(hop-by-hop·길이 제외 전부 보존). |
| 응답 `[Body]` | 본문. `MAX_BODY_LOG`(기본 2000B) 초과 시 `... (truncated, total N bytes)`. |
| `INFO: ... "METHOD PATH" STATUS` | uvicorn 기본 액세스 로그(프록시 로깅과 별개). |

- **바이너리 본문**(`image/*`, `application/octet-stream` 등)은 덤프하지 않고
  `<Binary Data: N bytes, Content-Type: image/png>` 로만 표기.
- **백엔드 연결 실패** 시 `[ERROR] [trace_id] 백엔드 연결 실패: ...` 를 찍고 클라이언트에 `502` 반환.

### 로그를 파일로도 저장

```powershell
# PowerShell — 화면 + 파일 동시
uvicorn packet_proxy:app --host 127.0.0.1 --port 3002 --no-server-header *>&1 | Tee-Object proxy.log
```
```bash
# bash — 화면 + 파일 동시
uvicorn packet_proxy:app --port 3002 --no-server-header 2>&1 | tee proxy.log
```
```bat
:: cmd — tee 가 없어 파일로만 (화면에는 안 보임)
uvicorn packet_proxy:app --host 127.0.0.1 --port 3002 --no-server-header > proxy.log 2>&1
```
stdout 을 UTF-8 로 고정하므로 파일로 저장해도 한글·`▶`/`◀` 기호가 깨지지 않습니다.

---

## 5. 실행 옵션 / 환경변수

| 항목 | 기본값 | 설명 |
|---|---|---|
| `--host` / `--port` | — | 프록시 리슨 주소. 이 문서는 `127.0.0.1:3002` 기준. |
| `--no-server-header` | (off) | 응답의 `Server: uvicorn` 헤더 제거. 선택. |
| `REAL_BACKEND` (env) | `http://127.0.0.1:3000` | 요청을 실제로 넘길 백엔드 origin. |
| `MAX_BODY_LOG` (env) | `2000` | 로그에 남길 본문 최대 바이트. `0` 이하이면 전체. |

동작·한계:
- `accept-encoding: identity` 를 강제해 백엔드 응답을 **비압축**으로 받고, 클라이언트엔
  비압축 본문 + 재계산된 `Content-Length` 로 전달합니다.
- hop-by-hop 헤더와 `Content-Length`·`Content-Encoding` 외 응답 헤더는 **모두 전달**
  (`Set-Cookie` 다중 포함).
- `httpx` 특성상 백엔드로 가는 요청 헤더 이름은 소문자로 정규화됩니다.
- WebSocket / SSE 스트리밍 / HTTP trailer 미지원(응답을 통째로 버퍼링). 타임아웃 15초 고정.

---

## 6. 다른 계층에서 재사용 — 훅 직접 만들기

`proxy_core` 를 import 해 훅만 새로 쓰면 됩니다(연결 지점은 1장 표 + `proxy_core.py`
모듈 docstring 참고).

```python
from proxy_core import ProxyHook, ProxyContext, create_app

class MyHook(ProxyHook):
    async def on_request(self, ctx: ProxyContext):
        # 탐지: ctx.forward_headers["X-Risk-Score"] = str(score); ctx.meta["sid"] = ...
        # 방어: return Response(status_code=403)  # 차단 — 백엔드로 안 감
        ...
    async def on_response(self, ctx: ProxyContext):
        # ctx.response_body / ctx.response_headers 를 수정해 응답 변조
        ...

def _extra_routes(app):          # (선택) 캐치올보다 먼저 매칭될 전용 라우트
    @app.get("/__internal/trap/{token}")
    async def trap(token: str): ...

app = create_app([MyHook()], before_catchall=_extra_routes)   # uvicorn 으로 기동
```

훅은 리스트 순서대로 실행되고, 관찰용 `LoggingHook` 은 보통 맨 앞에 둡니다.
훅이 백엔드를 건너뛰면 `ctx.short_circuited` 가 `True` 가 됩니다.
