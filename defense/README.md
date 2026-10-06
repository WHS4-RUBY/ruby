# RUBY Defense

RUBY의 방어 계층을 개발하는 영역입니다. Detection Proxy의 Policy Engine이 X-Defense-Plan 헤더로 넘긴 전략에 따라 요청에 차단, 변환, 지연, 기만 등의 방어 기법을 적용합니다.

## 담당 범위

- Defense Proxy
- 방어 전략 적용기
- 요청 차단·변환·지연·기만 기법
- 기법별 설정과 실행 결과 기록
- 방어 로그와 계층 간 인터페이스 정의
- 방어 기법의 단위·통합 테스트

공격 탐지와 위험도·정책에 따른 전략 선택은 모두 [`detection/`](../detection/)에서 관리합니다 (구간별 전략은 `detection/config/policy.json`). 실험 및 벤치마크 기록은 [`benchmark/`](../benchmark/)에서 관리합니다.

## 대시보드

Detection 프록시를 통해 `http://localhost:8081/__defense/dashboard`에서 접근합니다. 배포 환경에서는 서비스 주소의 `/__defense/dashboard`를 사용합니다.

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
프록시는 쿼리 문자열의 원본 바이트를 업스트림에 전달합니다. 쿼리 값이 경로인 앱에서도 인코딩과 중복 키를 임의로 바꾸지 않습니다. 쿼리 값 자체를 보호 대상 경로로 취급할지는 해당 앱의 라우팅 규칙을 확인한 뒤 별도로 정해야 합니다.
AI가 경로 목록을 검토할 때는 별칭 적용 전 앱에서 `python -m defense.scripts.discover_path_alias_routes --fetch http://APP_ORIGIN --asset-dir local-assets --output route-report.json`으로 공개 JS·HTML을 자동 수집할 수 있습니다. 저장한 JS·HTML 또는 브라우저 HAR도 입력 파일로 지정할 수 있습니다. 보고서는 이미 설정된 경로와 동적 접두사, 경로를 담은 쿼리 키를 구분하며 설정 파일을 자동 변경하지 않습니다. HAR 원본에는 세션 정보가 있을 수 있으므로 로컬 임시 경로에 보관하세요.
설계·검증 결과·한계는 [경로 별칭 설계](docs/path-alias-plan.md), 설치형 경로 수집과 DB 키 설계는 [경로 발견 설계](docs/route-discovery-design.md)를 참고하세요.

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

## 참여 방법

`main`에 직접 push하지 않고 작업 브랜치에서 변경한 뒤 Pull Request를 제출합니다. 자세한 규칙은 [루트 CONTRIBUTING.md](../CONTRIBUTING.md)를 확인하세요.

## 보안 주의사항

API 키, 토큰, 실제 서버 주소, 원본 공격 로그와 개인정보를 커밋하지 않습니다. 필요한 환경변수는 값이 제거된 `.env.example`로만 공유합니다.
