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

운영 환경에서는 `PAYLOAD_FINGERPRINT_KEY`, `DCID_HMAC_SECRET`,
`ACCOUNT_ID_HASH_KEY`에 충분히 긴 고정 비밀값을 주입해야 합니다. 스키마 학습 결과는
Docker volume에 유지되지만 요청·점수 이력은 현재 인메모리이므로 Detection 재시작 시
초기화됩니다.
