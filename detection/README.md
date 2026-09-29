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

Client Flow의 공격 점수에는 최근 60분 동안 공격 근거가 있는 요청의 반복 가산점(최대
50점)을 더합니다. 첫 요청은 가산하지 않고, 같은 시간 안에 2/4/8/16/32건이 되면
각각 10/20/30/40/50점을 더합니다. 페이로드·비즈니스 로직·CSRF 태그, 공격 대상
Deception 신호, CRS 이상 점수 5점 이상의 요청만 셉니다. 단순 404나 정상 요청 반복은
가산하지 않습니다. 이 가산점은 현재값에 적용되며 기존 과거 최고 Attack 이력은 별도로
유지됩니다.

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
| `CLIENT_FLOW_IDLE_TTL_MS` | `3600000` | 마지막 요청 후 Client Flow 만료 시간, 기본 60분 |
| `FINGERPRINT_CLEANUP_INTERVAL_MS` | `60000` | 만료된 Client Flow 정리 주기 |
| `FINGERPRINT_MAX_FLOW_CANDIDATES` | 사용 안 함 | 이전 설정과의 호환을 위해 남겨 둔 값. Candidate 수로 Flow를 분리하지 않음 |
| `MAX_CLIENT_FLOWS` | `5000` | 메모리에 유지할 Client Flow 상한 |
| `FINGERPRINT_IP_ROTATION_ENABLED` | `true` | IP가 다른 관찰의 자동 연결 허용 여부 |

## Fingerprint Client Flow 집계

`hfp2` 정확 일치만으로 설명할 수 없는 IP·UA 버전·언어·인코딩 변화를 위해 원본
클라이언트 특징을 `clientObservation` JSON으로 보존합니다. 필드별 기본 가중치는 IP 30,
UA 종류 25, UA 버전 15, 언어 10, Accept-Encoding 10, Client Hints 7, 헤더 순서 3입니다.

같은 IP에서는 UA 종류와 주 버전이 같고 총점이 85점 이상일 때, IP가 다르면 나머지
프로필이 거의 완전히 일치하고 총점이 70점 이상일 때 하나의 Client Flow로
Candidate를 연결합니다. 별도 Flow라도 공통 세션이 5개 이상이며 양쪽 세션의 80%
이상을 차지하면 UA가 달라도 연결합니다. 기존 Flow ID는 병합된 Flow를 조회할 수
있는 별칭으로 유지합니다. IP가 다른 Fingerprint 경로는 오탐 시 무고한 사용자의 위험
점수를 합산시키므로 `FINGERPRINT_IP_ROTATION_ENABLED=false`로 끌 수 있습니다.
이 플래그는 Fingerprint 기반 IP 변경 연결에 적용되며, 공통 세션으로 확인된 연결은
별도 근거로 처리합니다.
공격 점수는 기존 Candidate 점수를 더하지 않고 고유
`requestId` 요청 집합에서 Feature를 다시 추출해 계산합니다. signed DCID는 별도의
`CONFIRMED` Resolved Actor 경계를 유지한다. 서로 다른 DCID가 같은 Flow에 나타나도
신원을 합치지 않고 하위 흐름으로 함께 표시합니다. 이 연관 점수는 동일 사용자 확률이
아니라 요청 흐름을 연결하기 위한 휴리스틱 점수입니다.

운영 환경에서는 `PAYLOAD_FINGERPRINT_KEY`, `DCID_HMAC_SECRET`,
`ACCOUNT_ID_HASH_KEY`에 충분히 긴 고정 비밀값을 주입해야 합니다. 스키마 학습 결과는
Docker volume에 유지되지만 요청·점수 이력은 현재 인메모리이므로 Detection 재시작 시
초기화됩니다.
