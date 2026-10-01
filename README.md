# RUBY

RUBY는 웹 요청을 관찰해 위험 점수를 계산하고, 정책이 선택한 전략을 적용한 뒤 대상 웹사이트로 전달하는 실험용 프록시입니다. 현재 요청 경로는 **방문자 → 경로 게이트웨이 → Detection(탐지·정책) → Defense(전략 실행) → 선택한 웹사이트**입니다. 두 대시보드는 탐지와 방어 기록을 보여줍니다.

이 저장소는 [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), 자체 실험 사이트인 RUBY Market, 사용자가 소유한 다른 웹사이트를 **한 번에 하나씩** 대상으로 연결합니다. 경로 이름은 현재 선택된 사이트의 공개 별칭입니다. 경로가 생겼다는 이유만으로 두 사이트가 동시에 보호되지는 않습니다.

## 어디에 무엇이 있나

| 위치 | 역할 |
| --- | --- |
| [`detection/`](detection/README.md) | 요청 점수, 대상별 경로·미끼 규칙, 정책 결정, 탐지 대시보드 |
| [`defense/`](defense/README.md) | 선택된 방어 전략 실행, 대상 전달, 방어 대시보드 |
| [`gateway/`](gateway/default.conf.template) | 현재 대상의 이름 경로를 내부 요청 경로로 변환하는 공개 진입점 |
| [`target-profiles/`](target-profiles/site.example.json) | 사이트별 로그인·권한 관측·미끼 규칙 JSON 예시 |
| [`benchmark/`](benchmark/README.md) | RUBY Market과 격리 실험, 평가·재현 자료 |

### 현재 구현 범위

Detection은 Automation/Attack 점수와 확인된 공격 신호로 정책을 고릅니다. 기본 정책은 낮은 위험에서는 그대로 전달하고, 중간 위험에서는 200~300ms, 높은 위험에서는 500ms 지연을 적용합니다. 높은 점수에 **확인된 Attack 점수도 충분한 경우**에는 클라이언트별 엄격한 속도 제한(초당 최대 1회)을 지연과 함께 선택합니다. 자세한 임계값은 [`detection/config/policy.json`](detection/config/policy.json)에 있습니다. 첫 요청에 생긴 탐지 신호는 그 요청의 전달을 되돌리지 않으며, 이후 요청의 정책에 반영됩니다.

현재 등록된 전략은 지연과 엄격한 속도 제한입니다. HTTP 응답 변형용 전략 계약은 있지만 기본 정책이 응답을 변형하지는 않습니다. WebSocket은 업그레이드 시점에 기존 HTTP 이력으로 전략을 선택하고 프레임은 중계합니다. **프레임 내용의 탐지·변형·개별 기록은 하지 않습니다.** 대시보드 기록과 탐지 상태의 일부는 프로세스 메모리에 있고, 재시작·다중 인스턴스에서 공유되지 않습니다. [2026-10-02 파이프라인 확인](benchmark/benchmarks/web-defense-benchmark/docs/team-pipeline-validation-20261002.md)은 소규모 예비 시험이며 일반적인 방어 효과의 근거가 아닙니다.

## 공개 주소와 대상 전환

기본 배포는 Juice Shop을 선택합니다. 서버의 공개 origin이 `http://example.test`라면 화면 주소는 `http://example.test/juice-shop/`입니다. RUBY Market을 선택하면 `http://example.test/ruby-market/`가 됩니다. `/`는 선택된 이름 경로로 이동하고, **선택되지 않은 다른 기본 사이트의 이름 경로는 404**를 반환합니다. 화면이 사용하는 `/api/`, `/rest/`, `/assets/` 같은 루트 경로도 같은 활성 파이프라인을 거칩니다. 탐지 규칙과 대시보드에 남는 경로는 이름 접두사를 제거한 원래 요청 경로입니다.

대시보드는 대상과 관계없이 `/__detection/dashboard`와 `/__defense/dashboard`입니다. 비밀번호는 서버 환경 변수로만 제공하고 저장소, 시험 출력, PR에 기록하지 않습니다. 이전의 `:8088` RUBY Market 직접 주소가 열린다는 사실은 RUBY 파이프라인의 대상 전환을 뜻하지 않습니다. 실제 연결은 **이름 경로를 포함한 공개 진입점**에서 화면·읽기 전용 API와 같은 요청의 탐지·방어 기록을 대조해 확인합니다.

| 선택 | 공개 화면 경로 | Compose 파일 |
| --- | --- | --- |
| Juice Shop(기본) | `/juice-shop/` | `docker-compose.yml` 또는 `docker-compose.target.juice-shop.yml` 추가 |
| RUBY Market | `/ruby-market/` | `docker-compose.yml` + `docker-compose.target.ruby-web.yml` |
| 자신의 웹사이트 | 기본 `/site/`, `RUBY_PUBLIC_NAME`으로 변경 | `docker-compose.yml` + `docker-compose.target.site.yml` |

RUBY Market의 웹 스택을 먼저 실행한 다음 아래처럼 **전체 파이프라인**을 전환합니다. Market 오버레이는 Defense의 대상 주소, Detection의 Market 프로필, 공개 경로를 함께 고르고 번들 Juice Shop을 비활성화합니다. 전환 시 Detection을 재생성해 이전 사이트의 메모리 점수가 섞이지 않도록 합니다. 명령과 내부 네트워크 조건은 [서버 대상 전환](benchmark/benchmarks/web-defense-benchmark/docs/operations/04-server-target-selection.md)에 있습니다.

```bash
docker compose -f docker-compose.yml -f docker-compose.target.ruby-web.yml \
  up -d --wait --remove-orphans --force-recreate
# 이전 Juice Shop 컨테이너가 실행 중이었다면 정지
docker compose -f docker-compose.yml -f docker-compose.target.ruby-web.yml \
  --profile bundled-juice-shop stop benchmark-target
# Juice Shop 복귀
docker compose -f docker-compose.yml -f docker-compose.target.juice-shop.yml \
  up -d --wait --remove-orphans --force-recreate
```

자신의 사이트는 `RUBY_TARGET_URL`(Defense가 접근할 원본 웹 주소), `RUBY_TARGET_PROFILE_FILE`(Detection의 JSON 규칙), 선택 사항인 `RUBY_PUBLIC_NAME`(공개 경로 이름)을 지정합니다. 원본 주소를 RUBY의 공개 주소로 지정하면 순환 전달됩니다. 예시 설정과 인증·쿠키·CSRF·미끼 규칙 점검은 [자신의 웹사이트 연결](benchmark/benchmarks/web-defense-benchmark/docs/operations/05-connect-your-site.md)에 있습니다. 원본 사이트에 직접 공개 접근이 남아 있으면 RUBY를 우회할 수 있으므로 별도 접근 제한이 필요합니다.

이름 경로는 경로 접두사만 제거하는 방식입니다. 기존 사이트가 루트 절대 링크나 루트로 이동하는 응답을 사용하면 브라우저 주소에서 이름이 사라질 수 있으므로 연결 전 실제 화면·로그인·리다이렉트를 확인하세요. 루트 경로로 간 요청도 선택한 대상의 파이프라인을 통과합니다.

## 로컬 실행

Docker Desktop이 실행 중이라면 저장소 루트에서 다음 명령으로 소스를 빌드합니다. 로컬 Compose에는 운영 이미지 레지스트리나 비밀번호가 필요하지 않습니다.

```bash
docker compose -f docker-compose.local.yml up -d --build --wait
curl -I http://localhost:8081/
curl -I http://localhost:8081/juice-shop/
curl http://localhost:8081/healthz
docker compose -f docker-compose.local.yml down
```

브라우저 화면은 `http://localhost:8081/juice-shop/`, 탐지·방어 대시보드는 같은 origin의 위 관리 경로에 있습니다. 첫 Detection 빌드는 ModSecurity/CRS 준비로 시간이 걸릴 수 있습니다. `defense/app`은 로컬 개발에서 자동 다시 불러오지만 Detection 코드는 이미지 재빌드가 필요합니다. 정상 요청과 관리 API 인증 상태를 확인하는 로컬 CI 시험은 [`.github/workflows/ci.yml`](.github/workflows/ci.yml)에 있습니다.

## 운영 배포와 검증

[`.env.example`](.env.example)을 참고해 이미지와 필수 비밀값을 **서버 환경**에 설정합니다. 운영 Compose는 필수 비밀값이 없으면 시작하지 않습니다. HTTPS 뒤에 둘 때는 앞단 프록시만 게이트웨이에 접근하도록 제한하고 `RUBY_FORWARDED_PROTO=https`, 공개 origin에 맞는 `CSRF_ALLOWED_ORIGINS`, 대시보드 Secure 쿠키·HTTPS 설정을 사용합니다. 현재 IP 기반 HTTP 실험 배포는 [배포 workflow](.github/workflows/deploy.yml)에 HTTP 예외가 명시돼 있습니다. 이 예외는 TLS를 제공하지 않습니다.

`main`의 Deploy workflow는 기본 **Juice Shop** 구성을 자동 배포합니다. RUBY Market 또는 자신의 사이트 전환은 운영자가 명시적으로 실행해야 하며, 이후 기본 자동 배포는 다시 Juice Shop을 선택할 수 있습니다. 전환 상태를 유지하려면 배포 자동화의 대상 선택도 함께 설정해야 합니다. 이 브랜치의 변경 사항은 운영 서버에 아직 적용되지 않았습니다.

검증 시 공개 이름 경로의 화면과 읽기 전용 API, 익명 관리 API의 인증 거부, 동일 요청 ID의 탐지·정책·전략·백엔드 결과를 확인하세요. WebSocket 업그레이드와 실제 프레임 교환은 별도로 검사하세요. 공격 성공 여부는 대상 웹의 독립 판정 기준으로 확인하고, 공격 시간·요청·토큰, 방어 측 AI 호출·토큰·실행 비용, 정상 사용자 지연을 각각 기록하세요. [평가 기록 양식](benchmark/templates/ruby-defense-evaluation.md)과 [예비 검증의 한계](benchmark/benchmarks/web-defense-benchmark/docs/team-pipeline-validation-20261002.md)를 참고하세요.

이름 경로의 Juice Shop → RUBY Market → Juice Shop 로컬 왕복과 공개 경로 검사 결과는 [경로 검증 기록](benchmark/benchmarks/web-defense-benchmark/docs/named-path-validation-20261002.md)에 있습니다.

## 기여와 비밀 정보

변경 범위의 시험과 재현 절차를 기록하고 [기여 안내](CONTRIBUTING.md)에 따라 검토받습니다. API 키, 비밀번호, 세션 쿠키, 개인 정보, 운영 서버의 실제 비밀 설정은 커밋하거나 시험 로그에 남기지 않습니다.
