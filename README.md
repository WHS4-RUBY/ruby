# RUBY

RUBY는 웹 요청의 공격 가능성을 탐지하고, 위험도와 정책에 따라 대응 전략을 선택해 방어 기법을 적용하며, 그 성능과 재현성을 검증하는 프로젝트입니다. 탐지, 정책 판단, 방어, 벤치마크에 필요한 코드와 문서를 함께 관리합니다.

## 저장소 구조

```text
RUBY/
├── benchmark/   # 실험 대상, 실행 환경, 결과 및 재현 자료
├── defense/     # 차단·변환·지연·기만 등 방어 계층
├── detection/   # Node.js 탐지 프록시, ModSecurity/CRS, 대시보드, Policy
├── docs/        # 저장소 전체에 걸친 설계·리팩토링 기록
├── shared/      # Detection·Defense 가 함께 쓰는 편집 원본 (미끼 카탈로그, 이벤트 스키마, SQLite 계층)
└── scripts/     # shared/ 사본 동기화
```

`shared/` 가 원본이고 각 서비스 트리에 사본을 함께 커밋한다. 네 이미지의 빌드
컨텍스트가 모두 하위 디렉터리라 Docker 가 `COPY ../` 를 금지하기 때문이다. 원본을
고치면 `scripts/sync-shared.sh` 를 돌리고, 동일성은
`defense/tests/test_shared_sources.py` 가 CI 에서 강제한다.

서비스 간 계약 문서는 [`INTEGRATION.md`](INTEGRATION.md)에 있다.

### `benchmark/`

논문과 오픈소스 프로젝트의 실행 가능성 및 결과 재현성을 검증합니다. 프로젝트별 실험 문서, 공통 실행 환경, 결과 요약과 작성 템플릿을 관리합니다.

자세한 내용은 [`benchmark/README.md`](benchmark/README.md)를 참고하세요.

### `defense/`

탐지 결과에 따라 요청을 차단·변환·지연·기만하는 방어 계층을 개발합니다. 방어 정책, 계층 간 인터페이스, 로그와 테스트를 관리합니다.

자세한 내용은 [`defense/README.md`](defense/README.md)를 참고하세요.

### `detection/`

요청의 특징을 추출해 Automation/Attack 점수를 계산하고 `X-Ruby-Risk-Score`로 전달합니다.
ModSecurity/OWASP CRS, 행동 기반 휴리스틱, Honey/Deception 신호와 실시간 대시보드를 포함합니다.
위험도 점수를 정책에 따라 해석하고 Defense에서 적용할 대응 전략을 선택합니다.


## 작업 방법

1. 최신 `main`에서 작업 브랜치를 만듭니다.
2. 변경 대상에 따라 `benchmark/`, `defense/`, `detection/`에서 작업합니다.
3. 관련 테스트와 재현 절차를 확인하고 문서화합니다.
4. 비밀 정보와 개인정보가 포함되지 않았는지 확인합니다.
5. Pull Request를 생성해 검토받은 뒤 병합합니다.

세부 규칙은 [`CONTRIBUTING.md`](CONTRIBUTING.md)를 참고하세요.

## 서버 배포

서버에서는 [`.env.example`](.env.example)을 `.env`로 복사한 뒤 `IMAGE_PREFIX`, 배포할 `IMAGE_TAG`, `PUBLIC_TARGET_ORIGIN`을 설정합니다. 운영 Compose는 두 대시보드 비밀번호와 `PAYLOAD_FINGERPRINT_KEY`, `DCID_HMAC_SECRET`, `ACCOUNT_ID_HASH_KEY`, `OVERLAY_DETECTOR_KEY`가 없으면 시작하지 않습니다. GitHub Actions 배포에서는 `DEFENSE_DASHBOARD_PASSWORD`를 두 대시보드에 사용하고, 기존 `DCID_HMAC_SECRET`에서 도메인을 분리한 오버레이 서명 키를 파생합니다. 수동 배포에서는 별도의 안정적인 64자 hex `OVERLAY_DETECTOR_KEY`를 설정하고 재배포 때 값을 유지해야 합니다.

운영 대시보드는 기본적으로 HTTPS와 Secure 쿠키가 필요합니다. 서버 앞에 HTTPS reverse proxy를 두는 경우 원래 프로토콜을 `X-Forwarded-Proto`로 전달해야 합니다. 현재 서버의 HTTP 운영 모드는 배포 workflow에서 `ALLOW_INSECURE_DASHBOARD_HTTP=true`와 두 대시보드의 HTTPS/Secure 쿠키 설정 및 `DCID_COOKIE_SECURE=false`를 명시합니다. 관리 리스너는 서버의 `127.0.0.1:8088`에만 바인딩하며 SSH 터널을 통해 사용합니다. 포트 80은 보호 대상과 공개 telemetry만 제공하고 관리 경로는 404를 반환합니다. 관리 리스너는 보호 대상 콘텐츠를 제공하지 않습니다. Actions의 Deploy workflow는 `main` CI가 성공한 커밋만 SHA 태그로 배포하고, health 및 인증 smoke test 실패 시 직전 SHA로 복구합니다.

```bash
cp .env.example .env
# .env의 IMAGE_PREFIX와 IMAGE_TAG를 배포 값으로 수정
# TARGET_CHOICES에 내부 DNS 주소를 ID와 함께 등록하고 TARGET_DEFAULT_ID 지정
# 예: ruby-shop=http://ruby-web-target:8080,juice-shop=http://juice-shop-target:3000
# PUBLIC_TARGET_ORIGIN에는 실제 포트 80 주소 지정
docker compose pull
docker compose up -d
```

보호할 대상을 바꾸려면 사용자 컴퓨터에서 `ssh -L 8088:127.0.0.1:8088 USER@SERVER`를 열고 `http://127.0.0.1:8088/__detection/dashboard`의 **실험 대상**에서 선택합니다. 전환할 때 실행 ID가 새로 발급되며, 이후 `PUBLIC_TARGET_ORIGIN`의 포트 80으로 보낸 요청에 대상 ID와 실행 ID가 기록됩니다. 자동 방어 정책의 점수와 과거 최고 공격점수는 새 실행의 완료된 요청으로 다시 쌓이며 이전 실행에서 승계하지 않습니다. 방어 화면은 같은 관리 주소의 `/__defense/dashboard`입니다. 대시보드의 전체 요약은 보관된 여러 실행을 함께 집계하므로 개별 요청 상세의 ID로 구분합니다.

공개 `:80`의 HTTP 요청은 `Detection → 공식 Defense → 대상별 CHeaT sidecar → 선택된 대상`으로 흐릅니다. Defense는 관리 화면의 대상 ID에 맞는 sidecar를 선택하고, 계정 오버레이 정책이 선택되면 해당 대상의 비공개 오버레이로 라우팅합니다. 현재 자동 정책은 이전에 완료된 요청에서 계산한 위험 점수와 확정 공격 점수를 아래 순서로 평가합니다. `confirmed` 단계의 확정 공격 점수는 반환·검증된 signed `dcid`의 이력에서만 계산합니다.

| 조건 | 방어 단계·경로와 기법 |
| --- | --- |
| 위험·확정 공격 점수 모두 `0.95` 이상 | `confirmed`: `rate_limit_strict` 후 PR #34 고위험 계정 격리. 원본 대상에는 전달하지 않음 |
| 위험 점수 `0.8` 이상, 확정 공격 점수 `0.8` 이상 `0.95` 미만 | `confirmed`: `rate_limit_strict` 후 허용된 요청은 PR #39 CHeaT `decoy_maze`로 전달 |
| 위험 점수 `0.5` 이상, 확정 공격 점수 `0.5` 이상 `0.8` 미만 | `confirmed`: PR #34 중위험 계정 Response Overlay. 원본 응답에 가짜 단서를 더하고 일부 로그인 시도에 가짜 복구 경로를 응답 |
| 위험 점수 `0.8` 이상, 확정 공격 점수 `0.5` 미만 | `suspected`: CHeaT `decoy_maze`만 적용. 속도 제한과 계정 격리는 적용하지 않음 |
| 위 조건에 해당하지 않음 | 선택된 대상 경로로 전달. 자동 방어 계획 없음 |

PR #34 오버레이에 들어간 클라이언트의 경로는 대상·실행 ID·검증된 `dcid`별로 영속 저장합니다. 같은 식별자로 돌아온 중위험 클라이언트는 점수가 내려가도 오버레이를 계속 사용하고, 최상위 점수에 도달하면 원본과 분리된 고위험 격리로 승격됩니다. 따라서 이미 오버레이에 들어간 식별자가 뒤에 `decoy_maze` 점수 구간에 도달해도 CHeaT 미로로 우회하지 않습니다. 쿠키를 삭제하거나 새 실행을 시작하면 별도 식별자로 처리되므로 이 격리가 같은 사람의 모든 재접속을 보장하지는 않습니다. 방어 대시보드는 실제로 통과한 경로의 기법만 기록합니다. `rate_limit_strict`가 429를 반환하면 이후 미끼 경로는 실행하지 않습니다. 프로필 전용 `decoy_t21_shell`·`decoy_migration`과 위험 점수 일괄 지연은 현재 자동 정책에서 선택하지 않습니다.

정책은 **완료된 이전 요청**의 점수를 다음 요청에 적용합니다. 실험 도구는 첫 응답에서 받은 signed `dcid` 쿠키를 이후 요청에도 보내야 확정 공격 점수와 영속 방어 경로를 같은 행위자로 검증할 수 있습니다. 쿠키를 계속 돌려주지 않는 요청은 같은 IP·HTTP 지문의 관찰 후보와 한 IP 안에서 연결된 흐름 이력으로 위험 점수를 판단합니다. 이 경우 확정 공격 점수는 쌓이지 않아 `suspected` 미끼 단계까지만 적용되며, 동일 IP·지문을 공유하는 다른 클라이언트의 첫 요청에도 미끼가 붙을 수 있습니다. 방어 대시보드의 연결된 흐름은 관찰용 묶음이며 동일 클라이언트의 확정 신원을 뜻하지 않습니다.

운영 Compose는 Juice Shop과 RUBY Shop에 대해 대상별 CHeaT와 계정 오버레이를 각각 **비공개 Docker 네트워크**에서 실행하며 호스트 공개 포트는 추가하지 않습니다. WebSocket은 오버레이가 지원하지 않아 격리된 클라이언트에서는 차단하고 정상 클라이언트에서는 기존 대상에 연결합니다. RUBY Shop의 중위험 로그인은 가짜 401 응답이며, 오버레이가 Bearer/인증 쿠키를 원본에 전달하지 않으므로 해당 클라이언트의 인증 API는 401이 될 수 있습니다. 정상 클라이언트의 인증 요청은 기존 경로를 사용합니다.

`TARGET_CHOICES`에는 `juice-shop=http://juice-shop-target:3000`, `ruby-shop=http://ruby-web-target:8080`을 등록해야 합니다. 다른 대상 ID에는 기존 Defense 경로를 사용합니다. 대상별 오버레이 상태 볼륨과 Defense의 경로 상태 볼륨은 재배포 후에도 보존해야 합니다. `main` 병합 뒤 CI가 성공하면 배포 workflow가 네 이미지를 SHA 태그로 배포하고, smoke test가 실패하면 이전 Compose와 이미지 태그로 복구합니다.

## 로컬 테스트

Docker Desktop을 실행한 뒤, 아래 명령으로 로컬 소스를 빌드해 전체 요청 경로를 띄웁니다. 배포용 `docker-compose.yml`과 달리 레지스트리 설정이나 `.env` 파일이 필요 없습니다.

```bash
docker compose -f docker-compose.local.yml up --build
```

두 Compose 는 Detection·Defense 의 공통 환경변수를 `docker-compose.common.yml` 의
base 서비스에서 `extends` 로 가져온다. 각 파일에는 배포별로 **값이 다른** 항목만 있다.

먼저 보호할 애플리케이션을 이 호스트의 포트에서 실행합니다. 기본 포트는 `3000`이며 `.env`나 셸의 `TARGET_PORT`로 바꿀 수 있습니다. 예를 들어 Juice Shop은 `docker run -d -p 3000:3000 bkimminich/juice-shop`으로 띄울 수 있습니다. 로컬 Compose는 이 대상 앞에 비공개 CHeaT와 계정 오버레이를 띄웁니다. 브라우저에서 `http://localhost:8081`로 접속하거나 다음처럼 정상 요청 경로를 확인합니다.

```bash
curl http://localhost:8081/healthz
curl -I http://localhost:8081
```

`defense/app` 변경은 컨테이너가 자동으로 다시 불러옵니다. Detection은 Node.js와 네이티브 CRS scanner를
포함하므로 변경 후 이미지를 다시 빌드해야 합니다. 첫 Detection 빌드는 ModSecurity와 CRS를 준비하므로 시간이 걸릴 수
있습니다. 로컬 탐지 화면은 `http://127.0.0.1:18088/__detection/dashboard`, 방어 화면은 `http://127.0.0.1:18088/__defense/dashboard`에서 확인합니다. 로컬 `.env`에 `DETECTION_DASHBOARD_PASSWORD`를 지정하면 탐지 관리 API도 로그인 세션으로 보호됩니다. 포트 8081은 테스트 트래픽용이며, 대상 페이지가 사용하는 `/__detection/static/telemetry.js`와 `/__detection/telemetry`만 관리 네임스페이스 중 공개됩니다.
종료 및 컨테이너 정리는 다음 명령을 사용합니다.

```bash
docker compose -f docker-compose.local.yml down
```

## 영속 저장소

컨테이너마다 자기 SQLite 파일을 쓰고, 재배포 때 아래 볼륨은 보존해야 합니다.
스키마는 모두 `schema_migrations(component, version, applied_at)` 로 관리합니다.

| 컨테이너 | 볼륨 | 파일 |
| --- | --- | --- |
| `detection` | `detection-data:/app/data` | `detection.sqlite3` (XSS 후보·증거·스키마 학습), `target-selection.json` |
| `defense` | `defense-alias-data`, `defense-overlay-data` | `path-alias.sqlite3`, `routes.sqlite3` |
| `overlay-*` | `overlay-*-data:/app/state` | `security.sqlite3`(격리·재생 방지), `telemetry.sqlite3`(감사+미끼 링), 키 파일 |
| `cheat-*` | `cheat-*-data:/data` | `defense.db` |

`routes.sqlite3` 와 `security.sqlite3` 는 실패가 503 이 되는 fail-closed 저장소라
요청마다 쓰는 저장소와 파일을 공유하지 않습니다. 자세한 내용과 구 파일
마이그레이션 명령은 [`defense/README.md`](defense/README.md)의 "영속 저장소" 절과
[`.env.example`](.env.example)에 있습니다.

## 보안 주의사항

API 키, 토큰, 비밀번호, 실제 서버 식별 정보, 개인정보가 포함된 로그를 커밋하지 않습니다. 필요한 환경 변수는 실제 값이 없는 `.env.example`로만 공유합니다.
