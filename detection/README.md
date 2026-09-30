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
  └─ proxyCore([detectionHook])       # 나머지 요청
       ├─ onRequest                   # 식별·사전 점수·CRS 시작
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

정책 결정은 요청을 넘기기 전에 내려야 하는데 일부 탐지 신호(CRS 결과, 응답 상태)는
upstream 응답이 돌아온 뒤에 확정됩니다. 따라서 각 요청에 적용되는 위험도는 **해당
Client/Session/Auth Group에서 직전까지 완료된 요청의 관찰 이력**을 기준으로 합니다.
첫 요청은 0이며, 그 요청에서 확정된 신호는 다음 요청부터 반영됩니다.

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

`DETECTION_DASHBOARD_PASSWORD`를 설정하면 대시보드 데이터, export와 스키마 학습 관리 API가 별도 로그인 세션으로 보호됩니다. 운영에서는 기본적으로 HTTPS와 Secure 쿠키가 필요합니다. 현재 포트 80만 공개된 서버의 HTTP 로그인은 `ALLOW_INSECURE_DASHBOARD_HTTP=true`와 `DETECTION_DASHBOARD_REQUIRE_HTTPS=false`, `DETECTION_DASHBOARD_COOKIE_SECURE=false`를 함께 지정해야 가능합니다. 이 모드에서는 비밀번호와 세션 쿠키가 암호화되지 않으므로 접근 IP를 제한하고 HTTPS를 구성하면 세 설정을 되돌리세요. 대상 페이지의 브라우저 계측에 필요한 `/__detection/static/telemetry.js`와 `/__detection/telemetry`는 인증 없이 접근할 수 있습니다.
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
XSS 단독 최고 기여도 0.15는 현재 지연 정책 시작점 0.20보다 낮습니다. 다른 공격·자동화
신호와 결합해 정책을 결정하므로, 태그가 기록됐다는 사실과 방어가 발동했다는 사실은
구분해야 합니다. 이 가중치는 확률이나 검증된 탐지율이 아니며 실험으로 보정해야 합니다.
