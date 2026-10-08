# RUBY Detection

RUBY의 진입점에서 모든 HTTP 요청과 응답을 관찰하는 Node.js 리버스 프록시입니다.
기존 요청 횟수 기반 Python 스텁을 `juice-shop-detector`의 탐지 구현으로 교체했으며,
위험도에 따른 방어 전략 선택(Policy)도 이 프록시 안에서 수행합니다. 운영 Compose의
`TARGET_URL`은 공식 Defense를 가리키며, 보호할 대상은 관리 화면에서 선택합니다.

원본 통합 기준은 `kimwm5377/juice-shop-detector`의 `08fbf98` 커밋입니다. 포함된
ModSecurity 및 OWASP CRS의 버전과 라이선스는
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)에 기록했습니다.

## RUBY 요청 흐름

```text
Client -> 서버 공개 :80 -> Detection :8081   # 탐지 + 정책 결정
                             -> Defense :8080   # 속도 제한 등 공식 전략
                                  -> 대상별 CHeaT sidecar :3012 -> Target
관리자 -> SSH 터널 -> 서버 127.0.0.1:8088 -> Detection 관리 리스너 :8080
```

운영 대상은 `juice-shop`과 `ruby-shop`이며, 관리 화면의 **실험 대상**에서 전환합니다.
Detection과 Defense는 같은 `TARGET_CHOICES`와 선택 파일을 사용합니다. 대상 ID와 실행
ID가 이후 요청에 기록되며, WebSocket은 sidecar를 거치지 않고 선택된 Target에 직접
연결됩니다. 벤치마크 선택 화면의 포트 3020은 애플리케이션 직통 경로입니다. 여기에
보낸 요청은 Detection·Defense를 지나지 않아 두 대시보드에 표시되지 않습니다.

로컬 Compose는 공개 테스트 포트 `8081`과 루프백 관리 포트 `18088`을 사용합니다.
sidecar 설정이 없는 독립 실행/legacy 대상은 Defense가 Target에 직접 연결합니다.

별도의 Policy 프록시는 두지 않습니다. 구간별 방어 전략은
[`config/policy.json`](config/policy.json)에 두고 `lib/policyEngine.js`가 읽습니다.

기존 FastAPI 탐지 스텁과 JavaScript 탐지기를 별도 프록시로 겹쳐 두지 않습니다.
대신 Python의 `create_app([ProxyHook])` 구조를 JavaScript로 이식한
`lib/proxyCore.js`에 `detectionHook`을 장착합니다.

```text
Express app
  ├─ 공개 리스너: /healthz, 공개 telemetry, requestInspection → 보호 대상 프록시
  ├─ 관리 리스너: /__detection/*, /__defense/*, /healthz
  └─ proxyCore([detectionHook])       # CRS 검사를 통과한 보호 대상 요청
       ├─ onRequest                   # 식별·이전 이력 기반 정책·검사한 본문 재전송
       └─ onResponse                  # 결과 기록·점수 갱신·Telemetry/Deception 주입
```

따라서 추후 다른 탐지기나 로깅 기능은 `onRequest`와 `onResponse`를 구현해
`hooks` 배열에 추가할 수 있습니다. Defense는 별도 FastAPI 서비스로 유지됩니다.

## HTTP 응답 스트리밍 범위

`proxyCore`의 `maxResponseBodyBytes` 기본값은 4MiB, 완전한 본문을 기다리는
`maxInspectionWaitMs` 기본값은 250ms입니다. SSE, 바이너리, 크기 상한을 넘거나
검사 대기 시간을 넘는 응답은 원본 바이트를 스트림으로 전달합니다. 이때 완전한 응답 본문이
없으므로 본문 기반 XSS 검사와 telemetry·미끼 삽입은 생략합니다. 요청·CRS·응답
헤더와 상태 등 확인 가능한 신호는 계속 기록합니다. 작은 변형 가능 응답만 상한
안에서 본문 전체를 받은 뒤 검사·삽입하며, XSS 본문 검사는 별도
`XSS_MAX_BODY_BYTES` 상한(기본 2,000,000바이트)도 적용합니다.

응답 도중 원본 연결이 끊기는 등 전송 오류가 나면 성공한 응답으로 취급하지 않고
같은 요청 ID에 `responseTransportOutcome=error`와
`responseBodyInspected=false`를 기록합니다. 업스트림이 이미 보낸 HTTP 상태가
있더라도 본문 전송 완료를 뜻하지 않습니다. WebSocket은 별도의 업그레이드·프레임
경로를 사용하며 프레임 내용은 검사하지 않습니다.

Detection은 다음 두 점수를 각각 0~1로 계산합니다.

- `automationScore`: 요청 간격, 반복, 헤더, 브라우저 상호작용, Honey 신호
- `attackScore`: CRS/페이로드, 탐색, IDOR, 인증 남용, 비즈니스 로직, CSRF, Deception 신호와 최근 60분 공격 근거 반복 가점

두 점수는 아래 식으로 하나의 0~1 위험도로 합쳐집니다.

```text
max(현재 automationScore, 누적 최고 attackScore)
```

정책에 사용하는 위험도는 현재 대상 실행에서 직전까지 완료된 요청의 관찰 이력을
기준으로 합니다. 현재 요청의 CRS 차단은 이 위험도와 별개로 전달 전에 결정합니다.
첫 요청이나 유효한 쿠키를 가진 요청도 검사합니다.

### 전달 전 CRS 검사 (2026-09-30)

`CRS_MODE=enforce`이면 `lib/requestInspection.js`가 비동기 검사를 완료한 뒤에만
프록시를 호출합니다. `onProxyReq`에서 비동기 검사를 시작하는 방식이 아닙니다.
ModSecurity는 계속 `DetectionOnly`로 규칙을 평가하며 **Node 미들웨어가 차단을 실행**합니다.

| 검사 결과 | enforce 응답 | 백엔드 전달 |
|---|---|---|
| 완전한 검사, 공격 규칙 점수 < 기준 | 애플리케이션 응답 | 예 |
| 완전한 검사, 공격 규칙 점수 ≥ 기준 | 403 `request_blocked` | 아니요 |
| 검사 시간 초과·사용 불가·엔진 내부 검사 오류 | 503 `request_inspection_incomplete` | 아니요 |
| 검사 본문 제한 초과 | 413 | 아니요 |
| 지원하지 않는 본문 형식·압축·문자 인코딩 | 415 | 아니요 |
| JSON 등 본문 파싱 실패 | 400 `request_body_unreadable` | 아니요 |

본문은 UTF-8 JSON(`+json` 포함), URL-encoded form, `text/plain`을 지원합니다.
텍스트는 검사 엔진에만 JSON 문자열로 감싸 전달해 CRS의 ARGS 규칙으로 검사하고,
백엔드에는 검사 전 원문 바이트를 그대로 전달합니다. Socket.IO polling의 정상 텍스트를
경로 예외 없이 처리하지만, Socket.IO 의미 분석이나 WebSocket 중계까지 제공하지는 않습니다.
multipart·임의 바이너리·압축 요청은 현재 enforce 지원 범위 밖입니다.
본문 제한은 기본 및 상한 1 MiB이며, 텍스트는 JSON 감싸기 이후 크기에도 적용합니다.

`CRS_BLOCK_THRESHOLD`의 기본 5는 helper가 반환하는 **공격 규칙의 심각도 합계**에
적용합니다. 프로토콜 준수 규칙을 포함한 CRS 원래 전체 anomaly score와는 다릅니다.
Authorization/Cookie 원문은 기존 정책대로 검사 helper에 보내지 않습니다.
이 범위의 검사 완료가 모든 공격에 안전하다는 뜻은 아닙니다.

`observe`는 공격·불완전 검사를 기록하고 전달합니다. `off`는 해당 검사를 생략합니다.
로컬 Compose 기본은 `enforce`, 직접 Node 실행 기본은 `observe`입니다. 기존 `BLOCK_MODE`는
이 설정과 독립된 행동 탐지 로그 옵션이며 CRS 차단 스위치가 아닙니다.
거부된 요청도 관찰 이력에 남지만 앱 스키마 학습에는 사용하지 않습니다.
`request_inspection` 로그와 `/__detection/api/crs-status`에서 모드를 확인합니다.

실제 엔진과 HTTP 백엔드를 사용하는 테스트:

```bash
docker compose -f docker-compose.local.yml build detection
docker run --rm -e REQUIRE_CRS_BINARY_TESTS=true ruby-local-detection node --test test/crsBinaryIntegration.test.js test/requestInspection.test.js
```

이 테스트는 공격 요청의 백엔드 도달 건수가 0인지, 정상 요청의 원문 본문이 보존되는지,
검사 실패·제한 초과가 정상 검사로 오인되지 않는지 확인합니다. CI에서도 이미지 빌드 후 실행합니다.

응답 상태와 본문 근거는 응답 후 확정됩니다. 대상 전환 때
새 실행 ID가 발급되므로 이전 실행의 정책 점수와 과거 최고 공격점수는 승계하지 않습니다.
반환·검증된 signed DCID가 있으면
그 클라이언트의 이력을, 없으면 같은 IP·HTTP 지문의 관찰 후보와 한 IP 안에서 이어진
Client Flow 이력을 사용합니다.
브라우저 상호작용 telemetry에는 현재 실행 ID가 없어 실행별 자동 정책 점수에는 반영하지
않습니다. 대시보드의 전체 관찰 분석에는 계속 표시됩니다.
첫 요청은 0이며, 그 요청에서 확정된 신호는 다음 요청부터 반영됩니다. WebSocket은
업그레이드 요청의 이전 HTTP 이력에만 정책을 적용하며 프레임 내용은 분석하거나 점수화하지 않습니다.
Socket.IO polling은 HTTP 요청으로 기록되지만 배경 트래픽은 행동 점수에서 제외합니다.

`config/policy.json`의 규칙은 위에서부터 처음 맞는 하나만 선택하며, 각 규칙의
`tier`는 근거의 확실성 단계를 나타냅니다. 새 방어 전략은 점수 코드를 바꾸지 않고
해당 단계의 `strategies`에 추가합니다.

확정 공격 점수는 **검증된 동일 DCID의 Resolved Actor**에서만 계산합니다. 각 확정 단계는
위험 점수도 표의 하한 이상이어야 합니다.

| 단계 | 위험 점수 | 확정 공격 점수 | 선택 전략 |
|---|---:|---:|---|
| `confirmed` | 0.95 이상 | 0.95 이상 | `rate_limit_strict`(초당 최대 1요청), `account_overlay_high` |
| `confirmed` | 0.8 이상 | 0.8 이상 0.95 미만 | `rate_limit_strict`, `decoy_maze` |
| `confirmed` | 0.5 이상 | 0.5 이상 0.8 미만 | `account_overlay_medium` |
| `suspected` | 0.8 이상 | 0.5 미만 | `decoy_maze`만 적용. 확정된 차단·격리 없음 |
| 없음 | 그 외 | 그 외 | 방어 계획 없음 |

공식 Defense가 속도 제한과 계정 오버레이를 실행하고, 비공개 CHeaT sidecar가
기만 계획을 실행합니다. 위험 점수에 따른 일괄 지연은 선택하지 않지만 미끼에 접촉한
클라이언트에는 CHeaT의 미로·적응형 지연이 적용될 수 있습니다.
공유 IP·HTTP 지문으로 연결된 Candidate/Client Flow의 점수는 `suspected` 미끼 계획에만
사용할 수 있으며 자동 429 또는 계정 오버레이의 근거가 아닙니다. 서명 검증하지 않은
Bearer 값의 그룹 점수도 자동 429 근거가 아닙니다. 한 요청의 공격 신호가 응답 후
확정되면 대응은 후속 요청부터 가능합니다. 429는 `X-Defense-Signal: rate_limited`로
탐지 기록에 남으며, 해당 요청은 sidecar까지 전달되지 않습니다.

공격 근거 반복 가점은 최근 60분의 근거 요청이 4/8/16/32/64건에 도달하면
5/10/15/20/30점을 기존 Attack Score에 더하며 가산점 상한은 30점,
최종 점수 상한은 100점입니다.
정상 반복 요청, 단순 Origin 누락, 숫자 리소스 경로, `role-gated:*` 권한 추정
신호만 있는 요청은 반복 가점 집계에서 제외합니다. 권한 추정 신호의 기본 비즈니스
로직 점수는 유지하며, 같은 요청에 독립된 다른 공격 근거가 있으면 반복 집계에 포함합니다.

### 다음 계층으로 나가는 헤더

| 헤더 | 값 |
|---|---|
| `X-Defense-Plan` | 위험 점수와 확정 공격 점수에 맞는 전략 배열 JSON. Defense가 실행하고 기만 전략만 비공개 sidecar에 다시 전달합니다 |
| `X-Client-Id` | 방어 상태의 키가 되는 가명 식별자 |
| `X-Ruby-Request-Id` | 탐지·방어 기록을 결합할 무작위 요청 ID |
| `X-Ruby-Automation-Score`, `X-Ruby-Attack-Score`, `X-Ruby-Confirmed-Attack-Score`, `X-Ruby-Risk-Score` | 전달 전 완료 이력의 0~1 점수 |
| `X-Ruby-Policy-Source` | 정책 점수의 탐지 출처 |
| `X-Ruby-Defense-Tier` | 선택된 `policy.json` 규칙의 단계(`confirmed`, `suspected`). 계획이 없으면 보내지 않습니다 |
| `X-Ruby-Candidate-Id`, `X-Ruby-Client-Flow-Id` | 요청 당시 관찰 후보와 연결된 Client Flow. 헤더 자체는 Defense 대시보드의 묶음 표시용이며, Detection은 별도로 해당 이력을 `suspected` 판단에 사용합니다 |
| `X-Ruby-Target-Id`, `X-Ruby-Run-Id` | 선택된 대상과 실험 실행의 식별자 |

점수·출처 헤더는 Defense의 관측용 내부 계약입니다. 외부 요청에 같은 이름의 헤더가
있으면 Detection이 제거하고 자체 값을 넣습니다. Defense와 sidecar는 내부 식별·계획
헤더를 Target에 전달하지 않습니다. Detection 대시보드의 요청 타임라인과 JSON에는 요청 ID, 전달 전 정책 점수,
선택 전략, 응답 후 해당 DCID 관측 점수 및 방어 신호가 표시됩니다. 첫 발급 요청은
잠정 클라이언트 관측으로 표시하고, 공유 Candidate/Flow 점수는 별도 집계로 남깁니다.

일반 HTTP 요청의 `X-Client-Id`는 반환·검증된 signed DCID가 있으면 그 가명 ID를
사용합니다. 반환·검증된 DCID가 있는 HTTP 요청의 정책 점수는 그 DCID에 속한 완료
요청만 사용합니다. 다른 사용자와 겹친 Candidate/Flow 점수는 탐지 화면의 관찰값으로
남기며, 반환된 DCID를 가진 사용자의 속도 제한·격리·미끼 계획에는 쓰지 않습니다.

DCID를 돌려주지 않은 요청은 매번 새 DCID를 발급받으므로 서명 ID로 이어 볼 수 없습니다.
세션만 바꿔 가며 보내는 공격이 매번 이력 없음으로 통과하지 않도록, 이 요청은 쿠키와
무관한 같은 IP·HTTP 지문의 Candidate와 한 IP 안에서만 이어진 Client Flow의 완료
이력으로 판단합니다. `X-Client-Id`도 요청마다 바뀌는 DCID 대신 그 Candidate 또는
Client Flow ID를 사용해 방어 상태가 쪼개지지 않게 합니다. 쿠키가 없다는 사실 자체는
점수에 더하거나 빼지 않으며, 확정 공격 점수가 없으므로 `suspected` 단계(미끼)까지만
닿습니다. 같은 NAT 뒤에서 지문이 같은 다른 사용자의 첫 요청(쿠키 발급 전)에도 미끼
계획이 붙을 수 있다는 점은 감수한 트레이드오프이며, 그 사용자가 DCID를 돌려주는
순간부터는 자기 이력만 사용합니다. 요청마다 HTTP 지문이나 IP까지 바꾸는 클라이언트는
매번 새 Candidate가 되므로 이 방식으로도 이어지지 않습니다.

WebSocket 업그레이드는 HTTP 쿠키 발급 경로를 거치지 않으므로 유효한 DCID가 없으면
업그레이드마다 고유한 `websocket:*` ID를 사용하고 Candidate/Flow 점수를 쓰지 않습니다.

클라이언트가 보낸 `X-Ruby-*`, `X-Defense-*`, `X-Client-Id`, `X-Classification`은
Detection에서 제거합니다. 실제 발행하는 위험도 헤더는 `X-Ruby-Risk-Score`입니다.

## 실행 및 확인

저장소 루트에서 전체 파이프라인을 실행합니다.

```bash
docker compose -f docker-compose.local.yml up --build
```

- 로컬 보호 대상: `http://127.0.0.1:8081/`
- 로컬 Detection 상태: `http://127.0.0.1:8081/healthz`
- 로컬 관리 화면: `http://127.0.0.1:18088/__detection/dashboard`
- 로컬 관리 API 예시: `http://127.0.0.1:18088/__detection/api/sessions`

운영 서버에서는 관리자 컴퓨터에서 `ssh -N -L 127.0.0.1:8088:127.0.0.1:8088 USER@SERVER`로 터널을 연 뒤 `http://127.0.0.1:8088/__detection/dashboard`에 접속합니다. 공개 포트 80(로컬 8081)의 대시보드와 관리 API는 404를 반환합니다. 대상 페이지의 브라우저 계측에 필요한 `GET /__detection/static/telemetry.js`와 `POST /__detection/telemetry`만 공개 경로에 남습니다.

`DETECTION_DASHBOARD_PASSWORD`를 설정하면 대시보드 데이터, export와 스키마 학습 관리 API가 로그인 세션으로 보호됩니다. 운영의 기본 설정은 HTTPS와 Secure 쿠키를 요구합니다. 현재 서버처럼 SSH 터널로 HTTP 관리 화면을 열 때는 `ALLOW_INSECURE_DASHBOARD_HTTP=true`, `DETECTION_DASHBOARD_REQUIRE_HTTPS=false`, `DETECTION_DASHBOARD_COOKIE_SECURE=false`를 함께 지정합니다. 관리 리스너는 서버 루프백에만 바인딩됩니다.

Node 단위 테스트는 다음처럼 실행합니다.

```bash
cd detection
npm ci
npm test
```

## 주요 환경 변수

| 변수 | 기본값 | 설명 |
|---|---|---|
| `TARGET_URL` | `http://localhost:3000` | upstream 주소. 운영 Compose에서는 `http://defense:8080` |
| `TARGET_CHOICES` | 없음 | 관리 화면에서 고를 `id=내부 URL` 목록. Defense에도 같은 값 전달 |
| `TARGET_DEFAULT_ID` | `legacy` | 유효한 이전 선택이 없을 때의 대상 ID. `TARGET_CHOICES`에 포함되어야 함 |
| `TARGET_SELECTION_FILE` | 없음 | 대상·실행 ID를 기록하고 Defense와 공유할 파일 |
| `PUBLIC_TARGET_ORIGIN` | 없음 | 관리 화면의 보호 대상 링크에 사용할 공개 포트 80 주소 |
| `PORT` | `8080` | 독립 실행 기본 포트. Compose에서는 공개 리스너 `8081` |
| `ADMIN_PORT` | 없음 | 분리된 관리 리스너 포트. 운영 Compose에서는 컨테이너 `8080`을 서버 루프백 `8088`에 연결 |
| `POLICY_CONFIG_PATH` | `config/policy.json` | 위험도 구간별 방어 전략 정의 |
| `DETECTION_LEVEL` | `medium` | `low` 0.3, `medium` 0.5, `high` 0.7 |
| `SCHEMA_LEARNING_FILE` | 없음 | 승인된 스키마 학습 결과 저장 경로 |
| `CRS_ENABLED` | `true` | ModSecurity/OWASP CRS 활성화 |
| `CRS_MODE` | `observe` (로컬 Compose: `enforce`) | `off` / `observe` / `enforce` |
| `CRS_BLOCK_THRESHOLD` | `5` | 현재 요청의 공격 규칙 점수 차단 기준 |
| `CRS_MAX_BODY_BYTES` | `1048576` | 검사 본문 바이트 한도. native 한도보다 크게 설정해도 1 MiB로 제한 |
| `CRS_SCAN_TIMEOUT_MS` | `2000` | 검사 시간 제한. enforce에서는 실패 시 503 |
| `DECEPTION_ENABLED` | `true` | Honey/Deception 신호 활성화 |
| `TRUST_PROXY` | `false` | 신뢰할 리버스 프록시의 Host/Proto 해석용. X-Forwarded-For는 항상 무시 |
| `FINGERPRINT_SIMILARITY_TTL_MS` | `1800000` | Fingerprint Client Flow 비교 시간, 기본 30분 |
| `FINGERPRINT_CLEANUP_INTERVAL_MS` | `60000` | 만료된 Client Flow 정리 주기 |
| `FINGERPRINT_MAX_FLOW_CANDIDATES` | `3` | 한 Client Flow에 자동 연결할 Candidate 상한 |
| `MAX_CLIENT_FLOWS` | `5000` | 메모리에 유지할 Client Flow 상한 |
| `FINGERPRINT_IP_ROTATION_ENABLED` | `true` | IP가 다른 관찰의 자동 연결 허용 여부 |

클라이언트 IP는 직접 연결된 소켓 주소만 사용합니다. `X-Forwarded-For`는 게이트웨이와
Detection 입력에서 제거하며, Detection과 Defense 모두 HTTP·WebSocket의 하위 전달에서
재생성하지 않습니다. 게이트웨이 뒤의 Detection에는 게이트웨이 IP가 기록됩니다.
서명된 Client ID 기반 식별은 유지되며, 과거 X-Forwarded-For를 이용한 IP 변경 실험은
현재 설정에서 재현되지 않습니다.

## Fingerprint Client Flow 집계

`hfp2` 정확 일치만으로 설명할 수 없는 IP·UA 버전·언어·인코딩 변화를 위해 원본
클라이언트 특징을 `clientObservation` JSON으로 보존합니다. 필드별 기본 가중치는 IP 30,
UA 종류 25, UA 버전 15, 언어 10, Accept-Encoding 10, Client Hints 7, 헤더 순서 3입니다.

같은 IP에서는 UA 종류와 주 버전이 같고 총점이 85점 이상일 때, IP가 다르면 나머지
프로필이 거의 완전히 일치하고 총점이 70점 이상일 때 하나의 Client Flow로 최대 3개
Candidate를 연결합니다. IP가 다른 경로는 오탐 시 무고한 사용자의 위험 점수를
합산시키므로 `FINGERPRINT_IP_ROTATION_ENABLED=false`로 끌 수 있습니다. 공격 점수는 기존 Candidate 점수를 더하지 않고 고유
`requestId` 요청 집합에서 Feature를 다시 추출해 계산합니다. signed DCID는 별도의
`CONFIRMED` Resolved Actor 경계를 유지합니다. 서로 다른 DCID가 같은 Flow에 나타나도
신원을 합치지 않고 하위 흐름으로 함께 표시합니다. 이 연관 점수는 동일 사용자 확률이
아니라 요청 흐름을 연결하기 위한 휴리스틱 점수입니다.

운영 환경에서는 `PAYLOAD_FINGERPRINT_KEY`, `DCID_HMAC_SECRET`,
`ACCOUNT_ID_HASH_KEY`에 충분히 긴 고정 비밀값을 주입해야 합니다. 스키마 학습 결과는
Docker volume에 유지되지만 요청·점수 이력은 현재 인메모리이므로 Detection 재시작 시
초기화됩니다.

## 신원 보존과 XSS 관찰

Session, Candidate, Auth Group, IP 목록에는 각각 기본 50,000개 상한을 적용합니다.
공격·기만 이력이 없는 신원은 30분, 이력이 있는 신원은 24시간 미활동 후 만료됩니다.
HTTP 요청과 공개 telemetry 모두 상한을 적용하며, 주기적 청소가 만료된 세션의
Actor·Auth Group·IP·Client Flow·Resolved Actor 참조도 정리합니다. 처리 중인 요청의
신원은 상한 축출에서 보호합니다. 이력은 보존 상한 내의 관찰이며 영구 감사 로그가 아닙니다.

Reflected XSS 관찰은 요청한 클라이언트에 반영합니다. Stored XSS 후보는 성공한
POST/PUT/PATCH의 작성 요청 식별자를 보관하고, 나중 응답에서 발견되면 보존 중인
작성자 요청과 점수만 갱신합니다. 조회자에게 공격 점수를 부여하지 않으며, 작성 요청이
이미 만료되었으면 복원하지 않습니다. 탐지된 작성 요청의 후보만 제거하므로 다른
작성자의 같은 값과 합치지 않습니다.

10주차 로컬 발표의 XSS SQLite 파일 저장은 이 런타임에 병합되지 않았습니다.
현재 후보는 인메모리로 기본 1시간·2,000건·4MiB 중 먼저 닿는 상한까지 유지되며,
Detection 재시작 시 미확정 후보와 확정된 요청·점수 기록이 모두 사라집니다.
단위 시험은 개수·바이트·TTL 축출과 재생성 후 유실을 확인했습니다. 장기 보존이 필요한
운영에는 별도 영속 저장소와 볼륨·마이그레이션·삭제 정책이 필요합니다.

문자열이 응답에 나타났다는 사실만으로 XSS로 판정하지 않습니다. 일반 이름의
따옴표·괄호, 단순 서식 태그, 명시적인 평문 응답과 JSON script 데이터는 제외합니다.
실행 가능 문맥과 마크업/속성 증거를 함께 보는 휴리스틱이며, 브라우저 실행 판정이나
DOM XSS 탐지를 대체하지 않습니다. 본문 검사 상한을 넘으면 헤더만 검사합니다.

| 환경 변수 | 기본값 | 설명 |
|---|---:|---|
| `DETECTION_ENTITY_TTL_MS` | 1800000 | 일반 신원의 idle TTL |
| `RISKY_ENTITY_TTL_MS` | 86400000 | 공격·기만 이력이 있는 신원의 idle TTL |
| `DETECTION_ENTITY_SWEEP_MS` | 60000 | 주기적 만료 청소 간격 |
| `MAX_SESSIONS`, `MAX_ACTORS`, `MAX_AUTH_GROUPS`, `MAX_IP_ENTRIES` | 각 50000 | 종류별 신원 개수 상한 |
| `XSS_MAX_BODY_BYTES` | 2000000 | 응답 본문 검사 바이트 상한 |
| `XSS_CANDIDATE_TTL_MS` | 3600000 | Stored XSS 후보의 idle TTL |
| `XSS_MAX_CANDIDATES` | 2000 | 후보 개수 상한 |
| `XSS_MAX_CANDIDATE_BYTES` | 4194304 | 후보 직렬화 데이터의 총 바이트 상한 (힙 사용량 자체는 아님) |
| `XSS_MAX_VALUE_BYTES` | 4096 | 후보 값 1개의 UTF-8 바이트 상한; 초과 값은 보관하지 않음 |

운영·로컬 Compose 모두 위 설정을 컨테이너에 전달합니다. 환경 변수 변경 후에는
컨테이너를 재생성해야 하며 동적으로 설정을 다시 읽지는 않습니다.

XSS 서브스코어 가중치는 0.15이며 Payload Signature는 0.20, Attack Honey는 0.17입니다.
XSS 단독 최고 기여도 0.15는 현재 방어 정책의 가장 낮은 위험도·확정 공격 점수 기준 0.50보다
낮습니다. 다른 공격·자동화 신호와 결합해 정책을 결정하므로, 태그가 기록됐다는
사실과 방어가 발동했다는 사실은 구분해야 합니다. 이 가중치는 확률이나 검증된
탐지율이 아니며 실험으로 보정해야 합니다.
