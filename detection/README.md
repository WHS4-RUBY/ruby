# RUBY Detection

RUBY의 진입점에서 모든 HTTP 요청과 응답을 관찰하는 Node.js 리버스 프록시입니다.
기존 요청 횟수 기반 Python 스텁을 `juice-shop-detector`의 탐지 구현으로 교체했으며,
기본 대상은 OWASP Juice Shop이지만 `TARGET_URL`로 다른 HTTP 서비스나 RUBY Policy를
연결할 수 있습니다.

원본 통합 기준은 `kimwm5377/juice-shop-detector`의 `08fbf98` 커밋입니다. 포함된
ModSecurity 및 OWASP CRS의 버전과 라이선스는
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)에 기록했습니다.

## RUBY 요청 흐름

```text
Client
  -> Detection :8080
       -> Policy :8082
            -> Defense :8080
                 -> benchmark-target :3000
```

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
`hooks` 배열에 추가할 수 있습니다. Policy와 Defense는 기존 FastAPI 서비스로 유지됩니다.

Detection은 다음 두 점수를 각각 0~1로 계산합니다.

- `automationScore`: 요청 간격, 반복, 헤더, 브라우저 상호작용, Honey 신호
- `attackScore`: CRS/페이로드, 탐색, IDOR, 인증 남용, 비즈니스 로직, CSRF, Deception 신호

RUBY Policy의 기존 단일 점수 계약에는 아래 값을 `X-Risk-Score`로 전달합니다.

```text
max(현재 automationScore, 누적 최고 attackScore)
```

Policy가 요청 전에 결정을 내려야 하고 일부 탐지 신호는 upstream 응답이 돌아온 뒤에
확정되므로, 각 요청에 붙는 점수는 **해당 Client/Session/Auth Group에서 직전까지 완료된
요청의 관찰 이력**을 기준으로 합니다. 첫 요청은 0이며, 그 요청에서 확정된 신호는 다음
요청부터 Policy에 반영됩니다. `X-Risk-Score`, `X-Client-Id`, `X-Classification`을
클라이언트가 보내도 Detection에서 제거하고 서버 계산값으로 교체합니다.

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
- Provisional Actor 호환 API: http://localhost:8081/__detection/api/provisional-actors
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
| `TARGET_URL` | `http://localhost:3000` | upstream 주소. RUBY에서는 Policy 주소 |
| `PORT` | `8080` | Detection 내부 포트 |
| `DETECTION_LEVEL` | `medium` | `low` 0.3, `medium` 0.5, `high` 0.7 |
| `SCHEMA_LEARNING_FILE` | 없음 | 승인된 스키마 학습 결과 저장 경로 |
| `CRS_ENABLED` | `true` | ModSecurity/OWASP CRS 활성화 |
| `DECEPTION_ENABLED` | `true` | Honey/Deception 신호 활성화 |
| `TRUST_PROXY` | `false` | 신뢰할 리버스 프록시가 있을 때만 설정 |
| `FINGERPRINT_SIMILARITY_TTL_MS` | `1800000` | Fingerprint Client Flow 비교 시간, 기본 30분 |
| `FINGERPRINT_MAX_PROVISIONAL_CANDIDATES` | `3` | 한 Client Flow에 자동 연결할 Candidate 상한 |
| `MAX_PROVISIONAL_ACTORS` | `5000` | 메모리에 유지할 Client Flow 상한 |

## Fingerprint Client Flow 집계

`hfp2` 정확 일치만으로 설명할 수 없는 IP·UA 버전·언어·인코딩 변화를 위해 원본
클라이언트 특징을 `clientObservation` JSON으로 보존합니다. 필드별 기본 가중치는 IP 30,
UA 종류 25, UA 버전 15, 언어 10, Accept-Encoding 10, Client Hints 7, 헤더 순서 3입니다.

같은 IP에서는 UA 종류와 주 버전이 같고 총점이 85점 이상일 때, IP가 다르면 나머지
프로필이 거의 완전히 일치하고 총점이 70점 이상일 때 하나의 Client Flow로 최대 3개
Candidate를 연결합니다. 공격 점수는 기존 Candidate 점수를 더하지 않고 고유
`requestId` 요청 집합에서 Feature를 다시 추출해 계산합니다. signed DCID는 별도의
`CONFIRMED` Resolved Actor 경계를 유지한다. 서로 다른 DCID가 같은 Flow에 나타나도
신원을 합치지 않고 하위 흐름으로 함께 표시합니다. 이 연관 점수는 동일 사용자 확률이
아니라 요청 흐름을 연결하기 위한 휴리스틱 점수입니다.

운영 환경에서는 `PAYLOAD_FINGERPRINT_KEY`, `DCID_HMAC_SECRET`,
`ACCOUNT_ID_HASH_KEY`에 충분히 긴 고정 비밀값을 주입해야 합니다. 스키마 학습 결과는
Docker volume에 유지되지만 요청·점수 이력은 현재 인메모리이므로 Detection 재시작 시
초기화됩니다.
