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

로그인은 클라이언트별 실패 횟수를 제한하고, 세션은 만료 시간과 최대 개수에 따라 정리합니다. 이벤트는 요청 본문이나 인증 정보를 저장하지 않으며, 메모리에 최근 `DEFENSE_EVENT_LIMIT`건만 보관합니다. 단일 Uvicorn 프로세스의 운영 지표이므로 여러 worker로 확장할 때는 외부 저장소로 교체해야 합니다.

## 구현 구조

- `app/main.py`: `X-Defense-Plan` 실행과 Target 전달
- `app/dashboard.py`: 관리 API와 대시보드 라우터
- `app/dashboard_auth.py`: 로그인 제한과 세션 수명 관리
- `app/strategies/`: 방어 전략 구현과 Registry
- `app/monitoring.py`: 상한이 있는 요청 이벤트와 집계
- `app/public/dashboard.html`: Detection 대시보드와 같은 형태의 운영 화면

새 방어 기법은 `DefenseStrategy`를 구현해 Registry에 등록하면 대시보드에 자동으로 집계됩니다.

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
