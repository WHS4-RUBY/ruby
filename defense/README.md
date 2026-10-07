# RUBY Defense

RUBY의 방어 계층을 개발하는 영역입니다. Detection Proxy의 Policy Engine이 X-Defense-Plan 헤더로 넘긴 전략에 따라 요청에 차단, 변환, 지연, 기만 등의 방어 기법을 적용합니다.

## 담당 범위

- Defense Proxy
- 방어 전략 적용기
- 요청 차단·변환·지연·기만 기법
- 기법별 설정과 실행 결과 기록
- 방어 로그와 계층 간 인터페이스 정의
- 방어 기법의 단위·통합 테스트

공격 탐지와 위험도·정책에 따른 전략 선택은 모두 [`detection/`](../detection/)에서 관리합니다 (구간별 전략은 `detection/config/policy.json`).

## Target 연결

Defense는 같은 호스트에서 실행 중인 애플리케이션의 포트 번호로 요청을 전달합니다. 별도 컨테이너나 이미지를 가정하지 않습니다.

| 환경변수 | 기본값 | 설명 |
| --- | --- | --- |
| `TARGET_PORT` | `9000` | Target이 수신하는 포트 번호(1–65535). 정수가 아니거나 범위를 벗어나면 시작 시 오류로 종료합니다. |
| `TARGET_HOST` | `localhost` | Target 호스트. Compose는 컨테이너에서 호스트로 접근하도록 `host.docker.internal`로 지정합니다. |

Compose에서는 루트 `.env`의 `TARGET_PORT`만 바꾸면 됩니다(기본 `3000`). Target은 `127.0.0.1` 전용이 아니라 `0.0.0.0`(또는 Docker 브리지 주소)에 바인딩되어야 컨테이너에서 접근할 수 있습니다. `/readyz`는 Target 포트에 TCP 연결이 되는 동안에만 200을 반환합니다.

## 대시보드

관리 포트 `http://127.0.0.1:18088/__defense/dashboard`에서 접근합니다. 공개 포트 8081에서는 관리 경로를 제공하지 않습니다. 배포 환경에서는 main의 관리 리스너 접근 설정을 따릅니다.

대시보드는 공용 Defense 프로세스가 실제로 처리한 요청만 표시합니다.

- 전체·방어 적용·차단·오류 요청 수
- 방어 지연을 포함한 평균 처리 시간
- 최근 1시간 요청 흐름과 전략별 적용 횟수
- 최근 요청의 클라이언트 ID, 경로, 적용 전략과 처리 결과

`DEFENSE_DASHBOARD_PASSWORD`를 지정하면 관리 API가 로그인 세션으로 보호됩니다. 배포용 Compose는 이 값이 없으면 시작하지 않으며 GitHub Actions에서는 같은 이름의 Repository Secret을 전달합니다. 운영에서는 기본적으로 HTTPS와 Secure 쿠키가 필요합니다. 현재 포트 80만 공개된 서버에서 HTTP 로그인을 사용하려면 `ALLOW_INSECURE_DASHBOARD_HTTP=true`, `DEFENSE_DASHBOARD_REQUIRE_HTTPS=false`, `DEFENSE_DASHBOARD_COOKIE_SECURE=false`를 함께 지정해야 합니다. 이 모드에서는 비밀번호와 세션 쿠키가 암호화되지 않으므로 접근 IP를 제한하고 HTTPS를 구성하면 세 설정을 되돌리세요.

경로 별칭 단독 공격 실험에서는 `DEFENSE_DASHBOARD_ENABLED=false`로 `/__defense/` 화면·관리 API를 모두 404로 숨깁니다. 기본값은 `true`이며, 실험용 Compose에서만 `false`로 설정합니다.

로그인은 클라이언트별 실패 횟수를 제한하고, 세션은 만료 시간과 최대 개수에 따라 정리합니다. 이벤트는 요청 본문이나 인증 정보를 저장하지 않으며, 메모리에 최근 `DEFENSE_EVENT_LIMIT`건만 보관합니다. 단일 Uvicorn 프로세스의 운영 지표이므로 여러 worker로 확장할 때는 외부 저장소로 교체해야 합니다.

## 구현 구조

- `app/main.py`: `X-Defense-Plan` 실행과 Target 전달
- `app/dashboard.py`: 관리 API와 대시보드 라우터
- `app/dashboard_auth.py`: 로그인 제한과 세션 수명 관리
- `app/strategies/`: 방어 전략 구현과 Registry
- `app/monitoring.py`: 상한이 있는 요청 이벤트와 집계
- `app/public/dashboard.html`: Detection 대시보드와 같은 형태의 운영 화면

새 방어 기법은 `DefenseStrategy`를 구현해 Registry에 등록하면 대시보드에 자동으로 집계됩니다.

## 경로 별칭 (클라이언트별 별칭·이벤트 교체 v3, 2026-10-01)

`PATH_ALIAS_ROUTES_FILE`의 경로·템플릿마다 **클라이언트별** 난수 별칭을 발급하고 DB 테이블(운영: PostgreSQL)에서 조회합니다. 클라이언트는 Defense가 발급하는 `ruby_alias_client` 쿠키로 구분하며, 다른 클라이언트의 별칭은 거부합니다.
원래 경로 직접 호출(`direct`)이나 잘못된 별칭(`reject`)을 보낸 클라이언트는 별칭이 즉시 교체되고(`PATH_ALIAS_ROTATE_ON`, enforce에서만), 이벤트가 없어도 `PATH_ALIAS_EPOCH_S`(기본 1800초)마다 교체됩니다.
HTML·JS·JSON 응답과 `Location`에서 설정된 경로를 별칭으로 바꾸고, 들어온 유효 별칭은 원래 경로로 복원합니다.
`PATH_ALIAS_PREFIXES` 아래 원래 주소 직접 요청은 `observe`에서 기록하고 `enforce`에서 404로 막습니다.
기본값은 `PATH_ALIAS_MODE=off`입니다. 로컬 Juice Shop의 경로 예시는 [`config/juice-shop-routes.json`](config/juice-shop-routes.json)에 있습니다.
다른 앱에는 경로 파일·보호 접두사를 바꿔 정상 사용을 먼저 검증해야 합니다. 저장소는 `PATH_ALIAS_DB_URL`(PostgreSQL)이 있으면 그것을, 없으면 `PATH_ALIAS_DB_PATH`(영속 SQLite 파일)를 씁니다. 로컬·배포 Compose는 `path-alias-db`(PostgreSQL 16) 컨테이너와 `path-alias-pg` 볼륨을 쓰며, 배포 Compose는 `PATH_ALIAS_DB_PASSWORD`가 없으면 시작하지 않습니다(GitHub Secret `PATH_ALIAS_DB_PASSWORD` 필요). 같은 DB와 같은 경로 설정을 쓰는 worker·서버는 발급 결과를 공유하고 재시작 후에도 현재 별칭을 유지합니다. 프로세스마다 `PATH_ALIAS_DB_POOL_SIZE`(기본 10)개까지 연결을 재사용합니다. SQLite는 단일 호스트 실험(`benchmark/experiments/path_alias_ab`)과 테스트용으로 남겨 둡니다.
DB는 `(app_id, client_id)`별 세대와 `(app_id, client_id, route_path, generation)`별 별칭을 분리해 저장합니다. 한 사용자의 별칭 교체가 다른 사용자에게 영향을 주지 않으며, 쓰기는 PostgreSQL에서 클라이언트별 advisory lock으로 직렬화하므로 서로 다른 사용자의 발급·교체는 서로 기다리지 않습니다(SQLite는 DB 전체 쓰기 잠금). 만료 행 청소는 프로세스당 최대 `min(EPOCH_S, 60)`초에 한 번, 한 worker만 수행합니다. DB 호출은 이벤트 루프를 막지 않도록 스레드에서 실행합니다. PostgreSQL 테이블 테스트는 `PATH_ALIAS_TEST_DB_URL=postgresql://...`을 지정하면 실행되며 CI에서는 항상 실행합니다.
프록시는 일반 쿼리 필드의 원본 바이트를 보존합니다. `query_routes`로 지정한 API 선택값은 별칭으로 치환·복원하고, 중복 라우팅 키는 거부합니다. 앱의 실제 규칙은 수집 자료 검토와 정상 흐름 검증을 거쳐 확정합니다.
경로 목록을 검토할 때는 별칭 적용 전 앱에서 `python -m defense.scripts.discover_path_alias_routes --fetch http://APP_ORIGIN --asset-dir local-assets --output route-report.json`으로 공개 JS·HTML을 자동 수집할 수 있습니다. 저장한 JS·HTML 또는 브라우저 HAR도 입력 파일로 지정할 수 있습니다. 보고서는 이미 설정된 경로와 동적 접두사, 경로를 담은 쿼리 키를 구분하며 설정 파일을 자동 변경하지 않습니다. HAR 원본에는 세션 정보가 있을 수 있으므로 로컬 임시 경로에 보관하세요.
로그인 후·화면 상호작용 중에만 나타나는 API는 Playwright가 설치된 로컬 테스트 환경에서 `node defense/scripts/capture_api_requests.cjs --origin http://APP_ORIGIN --steps flow.json --output capture.runtime.json`으로 기록합니다. 필요하면 `--storage-state state.json`으로 테스트 계정의 브라우저 세션을 주입합니다. 흐름 파일의 `fill` 단계는 값 대신 환경변수 이름(`valueEnv`)을 받습니다. 생성된 `*.runtime.json`을 수집기의 입력으로 추가하면 관찰된 경로·메서드·응답 상태와 쿼리 라우팅 후보를 합칩니다. 보호 접두사 밖 dispatcher도 쿼리 값에 보호 경로가 있으면 기록합니다. 쿠키·헤더·본문·일반 쿼리 값은 저장하지 않지만 보호 경로를 담은 쿼리 값은 후보로 저장하므로 민감한 식별자가 있는지 검토하세요.

수집 보고서는 운영자가 검토해 경로와 쿼리 라우팅 규칙을 설정합니다. AI 모델 호출과 설정 초안 생성은 제공하지 않으며, 정상 흐름 확인 후 `PATH_ALIAS_ROUTES_FILE`로 적용합니다.
두 도구의 기본 보호 경로 접두사는 `/rest/,/api/`입니다. 다른 앱에서는 두 명령에 같은 `--prefixes /graphql,/v1/` 값을 지정해 해당 앱의 API 경로 관례에 맞춥니다.
설계·검증 결과·한계는 [경로 별칭 설계](docs/path-alias-plan.md), 설치형 경로 수집과 DB 키 설계는 [경로 발견 설계](docs/route-discovery-design.md)를 참고하세요.

### 방어 단계에서의 위치: 1단계 (2026-10-07)

설계상 요청은 탐지 프록시를 거친 뒤 방어 프록시의 4단계를 차례로 통과합니다. 경로 별칭은 방어 프록시에서 **가장 먼저 적용되는 1단계**입니다. 현재 코드는 `catch_all`에서 별칭 해석·차단을 마친 뒤 `X-Defense-Plan`의 전략을 배열 순서대로 실행합니다. 2~4단계를 구분하는 실행기와 각 단계의 구체적인 구성은 아직 구현되어 있지 않습니다.

- **뒤 단계가 진짜 경로를 봅니다.** 1단계에서 복원한 요청 객체를 뒤 전략에 전달합니다. URL·ASGI 경로·라우트 매개변수와 설정된 쿼리 라우팅 값이 복원됩니다. 일반 쿼리 필드와 요청 본문은 유지합니다. 쿼리 라우팅 앱의 후속 전략은 복원된 파라미터를 확인해야 하며 dispatcher의 pathname 자체는 유지됩니다. 별칭 로그에는 원래 들어온 요청을 사용합니다.
- **값싸고 확실한 차단을 먼저 합니다.** DB 조회 한 번으로 발급받은 주소를 아는 클라이언트인지 판정합니다. 원래 주소를 직접 호출하는 스캐너·에이전트를 여기서 404로 막으면 뒤 단계의 부담이 줄어듭니다.
- **교체 신호를 놓치지 않습니다.** 별칭 교체는 `direct`·`reject` 요청을 보고 일어납니다. 앞 단계가 그런 요청을 먼저 막으면 교체가 일어나지 않습니다.
- **응답 치환은 클라이언트에 가장 가까운 곳에서 마지막으로 하는 것이 설계 목표입니다.** 현재는 업스트림 응답의 경로와 `Location`을 치환합니다. 전략의 응답 처리 훅과 역순 실행은 아직 없으며, 전략이 즉시 반환한 응답(`short_circuit`)도 현재 치환 대상이 아닙니다. 뒤 단계가 응답에 미끼 링크 등을 추가하려면 이 응답 처리 구조를 먼저 구현해야 합니다.

단계가 위험도에 따라 올라가는 구조여도 별칭은 **모든 클라이언트에 처음부터 적용**해야 합니다. 이미 원래 경로가 담긴 JS를 받은 클라이언트에게 도중에 별칭을 켜면 앱이 깨지고, 공격자에게 탐지됐다는 신호를 줍니다. 위험도가 오르면 별칭을 새로 켜는 대신 교체 강도를 올립니다(짧은 주기, 유예 0, 즉시 교체). 클라이언트별로 이 값을 다르게 주려면 추가 구현이 필요합니다.

별칭은 **경로를 아는가**만 거릅니다. JS나 브라우저에서 정상 별칭을 얻은 공격자의 요청 내용은 통과하므로, 페이로드 검사(SQLi·XSS 등)는 2단계 이후에 원래 경로를 기준으로 해야 합니다. 경로가 필요 없는 아주 가벼운 차단(IP 차단 등)은 1단계보다 앞에 둘 수 있습니다. 탐지 프록시는 방어 프록시보다 앞에 있으므로 별칭 주소(`/__ruby_alias_...`)를 그대로 봅니다. `path_alias_rotation` 로그의 `direct`·`reject`를 탐지 쪽 공격 신호로 넘길지는 탐지 담당과 정합니다.

## 토큰 관찰과 CRS 차단 (2026-09-30)

토큰이 없거나 만료·변조되었다는 이유만으로 요청을 차단하지 않습니다.
`TOKEN_GATE_MODE=observe`는 쿠키 발급·갱신과 상태 기록만 수행하고, `off`는 이를 끕니다.
예전 `enforce` 설정은 경고와 함께 `observe`로 처리합니다. 토큰은 접근 권한이나
정상 사용자 증명이 아니며, 현재의 시간 구간별 공통 토큰은 개별 세션 식별에도 쓰지 않습니다.
기록에는 Detection이 전달한 `X-Client-Id`를 사용합니다. 탐지 정확도 개선은 아직 미검증입니다.

현재 요청의 SQL 인젝션 등 차단은 앞단 Detection의 `CRS_MODE=enforce`가 수행합니다.
로컬 Compose는 CRS `enforce` + 토큰 `observe`가 기본입니다.
검사 범위·실패 처리·설정은 [Detection README](../detection/README.md#전달-전-crs-검사-2026-09-30)를 참고하세요.

`scripts/token_gate_smoke.py`는 정상 요청이 토큰 유무·만료와 관계없이 통과하는지 확인합니다.
`scripts/verify_request_inspection.py`는 로컬 Compose 네트워크 안에서만 실행하는 Juice Shop 회귀 검사이며,
직접 대상의 양성 대조군, 쿠키 전후 SQLi 차단, 정상 계정 생성·로그인·사용자 확인을 검사합니다.
`--expiry-wait 21`은 테스트용 epoch 10초, grace 1 설정에서 만료 후 동작까지 확인합니다.
`scripts/browser_inspection_regression.cjs`는 Playwright가 설치된 로컬 테스트 이미지에서 실행하며,
화면 5단계와 모든 HTTP 4xx/5xx 응답을 함께 검사합니다. 결과 경로는 `/results`입니다.

`docs/token-gate-plan.md`와 새벽 테스트 기록은 이전 설계의 이력입니다.
이후 검증 결과는 [진행 기록](docs/token-gate-docker-progress.md)에 이어 기록합니다.

## 전략 계약과 요청 추적

Detection이 보낸 `X-Ruby-Request-Id`를 두 대시보드의 요청 ID로 사용합니다. Defense 이벤트는 같은 요청에 사용한 이전 완료 요청 기반 Automation·Attack·Risk 점수, 정책 출처, 실제 실행 전략, 백엔드 HTTP 상태와 `forwarded`·`blocked`·`error` 결과를 기록합니다. 이 내부 메타 헤더와 `X-Defense-Plan`은 Target으로 전달하지 않습니다. `X-Defense-Signal: rate_limited`는 Defense가 429를 반환한 경우에만 Detection으로 되돌립니다. Target이 보낸 같은 이름의 신호 헤더는 제거합니다.

전략의 `apply(request, params, state)`는 요청 단계에서 실행합니다. `DefenseResult`는 즉시 반환할 응답, Target에 보낼 헤더, 백엔드 응답 변형 함수, 다음 클라이언트 상태를 담을 수 있습니다. 상태는 전략 이름과 `X-Client-Id`별로 분리하고, 기본 10분 미사용 시 만료되며 최대 10,000개를 유지합니다. `DEFENSE_STATE_TTL_SECONDS`와 `DEFENSE_STATE_LIMIT`로 조절합니다. 동일 클라이언트의 동시 상태 변경은 순서대로 처리합니다. 해제 뒤에도 새 요청은 Detection에서 다시 점수화되고, 위험 정책이 재선택되면 전략에 재진입합니다. 현재 구현에는 영구적인 `blocked/released` 판정이나 다중 프로세스 공유 상태가 없습니다.

응답 변형 전략이 있으면 백엔드 본문을 받아 변형한 뒤 전송합니다. 본문은 기본 4 MiB까지 허용하며 `DEFENSE_TRANSFORM_BODY_LIMIT`로 조절합니다. 한도를 넘으면 502와 오류 이벤트를 반환합니다. 변형 전략이 없는 응답은 스트리밍합니다. 스트림이 중간에 끊기면 이미 보낸 HTTP 상태를 502로 바꿀 수 없으므로 연결이 중단되고 Defense 이벤트는 `outcome=error`로 남습니다. 이벤트의 `status`는 이미 전송한 백엔드 상태일 수 있으므로 결과와 함께 읽어야 합니다.

WebSocket은 업그레이드 요청 시 정책 전략을 한 번 적용하고 이후 텍스트·바이너리 프레임을 그대로 중계합니다. 프레임별 탐지나 응답 변형은 구현돼 있지 않습니다. `/__defense` 관리 경로는 WebSocket 엔드포인트가 없으므로 업그레이드를 거부합니다.

`X-Client-Id`와 `X-Ruby-*`는 내부 Detection 프록시가 재생성하는 헤더입니다. Defense에 직접 접속할 수 있으면 헤더를 위조할 수 있으므로 배포에서는 Defense 포트를 외부에 공개하지 말고 Detection과 같은 비공개 네트워크에서만 접근시키세요. 이벤트와 전략 상태는 단일 프로세스 메모리에만 보관되고 재시작 시 사라집니다.

## 참여 방법

쿼리로 API 경로를 선택하는 웹은 `PATH_ALIAS_ROUTES_FILE`의 `query_routes`에 진입 경로와 파라미터를 지정한다. 예: `{"path":"/gateway","parameter":"route"}`. 응답의 라우팅 값을 별칭으로 치환하고 요청에서 복원하며, 원본 경로·다른 사용자 별칭·중복 라우팅 키는 enforce에서 차단한다. [설정 예시](config/query-routing-example.json)와 [지원 범위](docs/route-discovery-design.md#쿼리-기반-api-라우팅)를 참고한다.

`main`에 직접 push하지 않고 작업 브랜치에서 변경한 뒤 Pull Request를 제출합니다. 자세한 규칙은 [루트 CONTRIBUTING.md](../CONTRIBUTING.md)를 확인하세요.

## 보안 주의사항

API 키, 토큰, 실제 서버 주소, 원본 공격 로그와 개인정보를 커밋하지 않습니다. 필요한 환경변수는 값이 제거된 `.env.example`로만 공유합니다.
