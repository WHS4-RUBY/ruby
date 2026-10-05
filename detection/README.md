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
- `attackScore`: CRS/페이로드, 탐색, IDOR, 인증 남용, 비즈니스 로직, CSRF, Deception 신호와 최근 60분 공격 근거 반복 가점

두 점수는 아래 식으로 하나의 0~1 위험도로 합쳐집니다.

```text
max(현재 automationScore, 누적 최고 attackScore)
```

정책 결정은 요청을 넘기기 전에 내려야 하는데 일부 탐지 신호(CRS 결과, 응답 상태)는
upstream 응답이 돌아온 뒤에 확정됩니다. 따라서 각 요청에 적용되는 위험도는 **해당
검증된 클라이언트/세션에서 직전까지 완료된 요청의 관찰 이력**을 기준으로 합니다.
첫 요청은 0이며, 그 요청에서 확정된 신호는 다음 요청부터 반영됩니다. WebSocket은
업그레이드 요청의 이전 HTTP 이력에만 정책을 적용하며 프레임 내용은 분석하거나 점수화하지 않습니다.
Socket.IO polling은 HTTP 요청으로 기록되지만 배경 트래픽은 행동 점수에서 제외합니다.

기본 정책은 위험도 0.2/0.5/0.8부터 각각 200/300/500ms 지연합니다. 위험도 0.8
이상이고 **검증된 동일 DCID의 Resolved Actor**에서 Attack Score 0.8 이상이 확인된
경우에만 `rate_limit_strict`(초당 최대 1요청)를 지연 앞에 추가합니다. 공유 IP·curl
지문으로 연결된 Candidate/Client Flow와 서명 검증하지 않은 Bearer 값의 그룹 점수는
자동 429 근거가 아닙니다. 한 요청의 공격 신호가 응답 후 확정되면 제한은 후속 요청부터
가능합니다. 429는 `X-Defense-Signal: rate_limited`로 탐지 기록에 남습니다.

공격 근거 반복 가점은 최근 60분의 근거 요청이 2/4/8/16/32건에 도달하면
10/20/30/40/50점을 기존 Attack Score에 더하며 최종 점수는 100점으로 제한합니다.
정상 반복 요청, 단순 Origin 누락, 숫자 리소스 경로만으로는 가점하지 않습니다.

### 다음 계층으로 나가는 헤더

| 헤더 | 값 |
|---|---|
| `X-Defense-Plan` | 위험도 구간에 해당하는 전략 배열 JSON. Defense가 소비하고 백엔드로 넘기지 않습니다 |
| `X-Client-Id` | 방어 상태의 키가 되는 가명 식별자 |
| `X-Ruby-Request-Id` | 탐지·방어 기록을 결합할 무작위 요청 ID |
| `X-Ruby-Automation-Score`, `X-Ruby-Attack-Score`, `X-Ruby-Risk-Score` | 전달 전 완료 이력의 0~1 점수 |
| `X-Ruby-Policy-Source` | 정책 점수의 탐지 출처 |

점수·출처 헤더는 Defense의 관측용 내부 계약입니다. 외부 요청에 같은 이름의 헤더가
있으면 Detection이 제거하고 자체 값을 넣습니다. Defense는 이를 Target에 전달하지
않습니다. Detection 대시보드의 요청 타임라인과 JSON에는 요청 ID, 전달 전 정책 점수,
선택 전략, 응답 후 해당 DCID 관측 점수 및 방어 신호가 표시됩니다. 첫 발급 요청은
잠정 클라이언트 관측으로 표시하고, 공유 Candidate/Flow 점수는 별도 집계로 남깁니다.

`X-Client-Id`는 signed DCID가 있으면 해당 가명 ID를 사용합니다. 그 외에는 확인된
Resolved Actor, Client Flow, Candidate 순으로 선택합니다. 공유 지문 사용자가
같은 방어 카운터를 쓰지 않게 하는 것이 목적입니다.
DCID가 있는 HTTP 요청의 정책 점수는 그 DCID에 속한 완료 요청만 사용합니다. 다른
사용자와 겹친 Candidate/Flow 점수는 탐지 화면의 관찰값으로 남지만 그 사용자의 지연
또는 429에는 쓰지 않습니다. 쿠키를 계속 버리는 클라이언트는 이 방식의 정책 연속성을
회피할 수 있으므로 장기적으로 인증된 계정·세션 연계가 필요합니다.

`X-Risk-Score`, `X-Client-Id`, `X-Classification`, `X-Defense-Plan`,
`X-Ruby-*`, `X-Defense-Signal`은 클라이언트가 보내더라도 Detection에서 제거합니다.

## 새 대상 연결

`TARGET_PROFILE_FILE`을 지정하면 대상별 경로·권한 관측 규칙·미끼 경로를 JSON 파일로
읽습니다. 파일이 없거나 스키마가 잘못되면 시작에 실패합니다. 지정하지 않으면 기존
Juice Shop 규칙이 그대로 동작합니다. 프로필을 지정하면 Juice Shop 전용 비즈니스 로직,
가격, 스키마 학습, 미끼 규칙은 비활성화되고, 명시한 로그인/비밀번호 재설정/보안질문,
권한 관측, 미끼 규칙과 범용 CRS·페이로드·XSS 검사를 사용합니다.

프로필 형식과 Juice Shop·RUBY Market·제3 사이트 예시는 저장소의
`target-profiles/`와 대상 전환 운영 문서에 있습니다. `permissions`는 JWT role
클레임을 서명 검증 없이 읽는 관측 신호입니다. 실제 접근 권한은 원본 서비스에서
검증해야 하며 opaque 세션을 쓰는 사이트는 이 목록을 비워 두는 편이 안전합니다.
미끼 경로는 대상의 실제 경로와 겹치지 않게 선택해야 합니다.

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
| `TARGET_PROFILE_FILE` | 없음 | 대상별 경로·권한 관측·미끼 JSON 파일. 지정 시 Juice Shop 전용 규칙 비활성화 |
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
XSS 단독 최고 기여도 0.15는 현재 지연 정책 시작점 0.20보다 낮습니다. 다른 공격·자동화
신호와 결합해 정책을 결정하므로, 태그가 기록됐다는 사실과 방어가 발동했다는 사실은
구분해야 합니다. 이 가중치는 확률이나 검증된 탐지율이 아니며 실험으로 보정해야 합니다.
