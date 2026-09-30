# RUBY Detection

RUBY의 진입점에서 모든 HTTP 요청과 응답을 관찰하는 Node.js 리버스 프록시입니다.
기존 요청 횟수 기반 Python 스텁을 `juice-shop-detector`의 탐지 구현으로 교체했으며,
위험도에 따른 방어 전략 선택(Policy)도 이 프록시 안에서 수행하며, `TARGET_URL`로
Defense나 보호할 애플리케이션을 직접 가리킵니다.

원본 통합 기준은 `kimwm5377/juice-shop-detector`의 `08fbf98` 커밋입니다. 포함된
ModSecurity 및 OWASP CRS의 버전과 라이선스는
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)에 기록했습니다.

## RUBY 요청 흐름

```text
Client
  -> Detection :8080        # 탐지 + 정책 결정 (X-Defense-Plan 생성)
       -> Defense :8080     # 계획 실행 (지연·차단 등)
            -> benchmark-target :3000
```

별도의 Policy 프록시는 두지 않습니다. 구간별 방어 전략은
[`config/policy.json`](config/policy.json)에 두고 `lib/policyEngine.js`가 읽습니다.

기존 FastAPI 탐지 스텁과 JavaScript 탐지기를 별도 프록시로 겹쳐 두지 않습니다.
대신 Python의 `create_app([ProxyHook])` 구조를 JavaScript로 이식한
`lib/proxyCore.js`에 `detectionHook`을 장착합니다.

```text
Express app
  ├─ /healthz, /__detection/*        # Detection 전용 라우트
  ├─ requestInspection              # 현재 요청의 CRS 검사 완료 → 차단/허용
  └─ proxyCore([detectionHook])       # 허용된 요청만 전달
       ├─ onRequest                   # 이전 이력 기반 정책·검사한 본문 재전송
       └─ onResponse                  # 결과 기록·점수 갱신·Telemetry/Deception 주입
```

따라서 추후 다른 탐지기나 로깅 기능은 `onRequest`와 `onResponse`를 구현해
`hooks` 배열에 추가할 수 있습니다. Defense는 별도 FastAPI 서비스로 유지됩니다.

Detection은 다음 두 점수를 각각 0~1로 계산합니다.

- `automationScore`: 요청 간격, 반복, 헤더, 브라우저 상호작용, Honey 신호
- `attackScore`: CRS/페이로드, 탐색, IDOR, 인증 남용, 비즈니스 로직, CSRF, Deception 신호

두 점수는 아래 식으로 하나의 0~1 위험도로 합쳐집니다.

```text
max(현재 automationScore, 누적 최고 attackScore)
```

기존 지연 전략에 사용하는 위험도는 **해당 Client/Session/Auth Group에서 직전까지
완료된 요청의 관찰 이력**을 기준으로 합니다. 현재 요청의 CRS 차단은 이 위험도와
별개로 전달 전에 결정합니다. 첫 요청이나 유효한 쿠키를 가진 요청도 검사합니다.

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

### 다음 계층으로 나가는 헤더

| 헤더 | 값 |
|---|---|
| `X-Defense-Plan` | 위험도 구간에 해당하는 전략 배열 JSON. Defense가 소비하고 백엔드로 넘기지 않습니다 |
| `X-Client-Id` | 방어 상태의 키가 되는 가명 식별자 |

위험도 점수 자체는 내보내지 않습니다. 위험도에 따른 차이는 `policy.json`의 구간별
파라미터(예: `delay_ms` 200/300/500)가 표현하므로, 정책 판단이 두 계층으로 갈라지지
않게 하기 위함입니다.

`X-Client-Id`는 확인된 가장 넓은 묶음을 안정적으로 가리킵니다
(Resolved Actor > Client Flow > Candidate). 점수가 가장 높은 근거를 따라가면 요청마다
식별자가 바뀌어 방어 카운터가 갈라지기 때문입니다.

`X-Risk-Score`, `X-Client-Id`, `X-Classification`, `X-Defense-Plan`은 클라이언트가
보내더라도 Detection에서 제거합니다.

## 실행 및 확인

저장소 루트에서 전체 파이프라인을 실행합니다.

```bash
docker compose -f docker-compose.local.yml up --build
```

- 애플리케이션: http://localhost:8081
- Detection 상태: http://localhost:8081/healthz
- Detection 대시보드: http://localhost:8081/__detection/dashboard
- 세션 API: http://localhost:8081/__detection/api/sessions
- Client Actor API: http://localhost:8081/__detection/api/actors
- Client Flow API: http://localhost:8081/__detection/api/client-flows
- Auth Group API: http://localhost:8081/__detection/api/auth-groups
- CRS 상태 API: http://localhost:8081/__detection/api/crs-status

Node 단위 테스트는 다음처럼 실행합니다.

```bash
cd detection
npm ci
npm test
```

## 주요 환경 변수

| 변수 | 기본값 | 설명 |
|---|---|---|
| `TARGET_URL` | `http://localhost:3000` | upstream 주소. RUBY에서는 Defense 주소 |
| `PORT` | `8080` | Detection 내부 포트 |
| `POLICY_CONFIG_PATH` | `config/policy.json` | 위험도 구간별 방어 전략 정의 |
| `DETECTION_LEVEL` | `medium` | `low` 0.3, `medium` 0.5, `high` 0.7 |
| `SCHEMA_LEARNING_FILE` | 없음 | 승인된 스키마 학습 결과 저장 경로 |
| `CRS_ENABLED` | `true` | ModSecurity/OWASP CRS 활성화 |
| `CRS_MODE` | `observe` (로컬 Compose: `enforce`) | `off` / `observe` / `enforce` |
| `CRS_BLOCK_THRESHOLD` | `5` | 현재 요청의 공격 규칙 점수 차단 기준 |
| `CRS_MAX_BODY_BYTES` | `1048576` | 검사 본문 바이트 한도. native 한도보다 크게 설정해도 1 MiB로 제한 |
| `CRS_SCAN_TIMEOUT_MS` | `2000` | 검사 시간 제한. enforce에서는 실패 시 503 |
| `DECEPTION_ENABLED` | `true` | Honey/Deception 신호 활성화 |
| `TRUST_PROXY` | `false` | 신뢰할 리버스 프록시가 있을 때만 설정 |
| `FINGERPRINT_SIMILARITY_TTL_MS` | `1800000` | Fingerprint Client Flow 비교 시간, 기본 30분 |
| `FINGERPRINT_CLEANUP_INTERVAL_MS` | `60000` | 만료된 Client Flow 정리 주기 |
| `FINGERPRINT_MAX_FLOW_CANDIDATES` | `3` | 한 Client Flow에 자동 연결할 Candidate 상한 |
| `MAX_CLIENT_FLOWS` | `5000` | 메모리에 유지할 Client Flow 상한 |
| `FINGERPRINT_IP_ROTATION_ENABLED` | `true` | IP가 다른 관찰의 자동 연결 허용 여부 |

## Fingerprint Client Flow 집계

`hfp2` 정확 일치만으로 설명할 수 없는 IP·UA 버전·언어·인코딩 변화를 위해 원본
클라이언트 특징을 `clientObservation` JSON으로 보존합니다. 필드별 기본 가중치는 IP 30,
UA 종류 25, UA 버전 15, 언어 10, Accept-Encoding 10, Client Hints 7, 헤더 순서 3입니다.

같은 IP에서는 UA 종류와 주 버전이 같고 총점이 85점 이상일 때, IP가 다르면 나머지
프로필이 거의 완전히 일치하고 총점이 70점 이상일 때 하나의 Client Flow로 최대 3개
Candidate를 연결합니다. IP가 다른 경로는 오탐 시 무고한 사용자의 위험 점수를
합산시키므로 `FINGERPRINT_IP_ROTATION_ENABLED=false`로 끌 수 있습니다. 공격 점수는 기존 Candidate 점수를 더하지 않고 고유
`requestId` 요청 집합에서 Feature를 다시 추출해 계산합니다. signed DCID는 별도의
`CONFIRMED` Resolved Actor 경계를 유지한다. 서로 다른 DCID가 같은 Flow에 나타나도
신원을 합치지 않고 하위 흐름으로 함께 표시합니다. 이 연관 점수는 동일 사용자 확률이
아니라 요청 흐름을 연결하기 위한 휴리스틱 점수입니다.

운영 환경에서는 `PAYLOAD_FINGERPRINT_KEY`, `DCID_HMAC_SECRET`,
`ACCOUNT_ID_HASH_KEY`에 충분히 긴 고정 비밀값을 주입해야 합니다. 스키마 학습 결과는
Docker volume에 유지되지만 요청·점수 이력은 현재 인메모리이므로 Detection 재시작 시
초기화됩니다.
