# RUBY

RUBY는 웹 요청의 공격 가능성을 탐지하고, 위험도와 정책에 따라 대응 전략을 선택해 방어 기법을 적용하며, 그 성능과 재현성을 검증하는 프로젝트입니다. 탐지, 정책 판단, 방어, 벤치마크에 필요한 코드와 문서를 함께 관리합니다.

## 저장소 구조

```text
RUBY/
├── benchmark/   # 벤치마크 검증 기록과 방어 기법 실험 하니스
├── defense/     # 차단·변환·지연·기만 등 방어 계층
├── detection/   # Node.js 탐지 프록시, ModSecurity/CRS, 대시보드, Policy
├── docs/        # 저장소 전체에 걸친 리팩토링 기록과 archive/(보관 문서)
├── shared/      # Detection·Defense 가 함께 쓰는 편집 원본 (미끼 카탈로그, 이벤트 스키마, SQLite 계층)
└── scripts/     # shared/ 사본 동기화
```

`shared/` 가 편집 원본이고 각 서비스 트리에 사본을 함께 커밋한다. 원본을 고치면
`scripts/sync-shared.sh` 를 돌린다 — 이유와 원본별 사용처는
[`INTEGRATION.md`](INTEGRATION.md#공유-설정)의 "공유 설정" 절에 있다.

서비스 간 계약(헤더, 대상 선택 파일, 이벤트 필드명, 신뢰 경계)은
[`INTEGRATION.md`](INTEGRATION.md)가 정본이다.

### `benchmark/`

논문과 오픈소스 프로젝트의 실행 가능성 및 결과 재현성을 검증한 기록(4건)과, RUBY 자체 방어 기법의 A/B·호환성 실험 하니스(2건)를 관리합니다. 파이프라인 실행에는 필요하지 않습니다.

자세한 내용은 [`benchmark/README.md`](benchmark/README.md)를 참고하세요.

### `defense/`

탐지 결과에 따라 요청을 차단·변환·지연·기만하는 방어 계층을 개발합니다. 방어 정책, 계층 간 인터페이스, 로그와 테스트를 관리합니다.

자세한 내용은 [`defense/README.md`](defense/README.md)를 참고하세요.

### `detection/`

요청의 특징을 추출해 Automation/Attack 점수를 계산하고 `X-Ruby-Risk-Score`로 전달합니다.
ModSecurity/OWASP CRS, 행동 기반 휴리스틱, Honey/Deception 신호와 실시간 대시보드를 포함합니다.
위험도 점수를 정책에 따라 해석하고 Defense에서 적용할 대응 전략을 선택합니다.

자세한 내용은 [`detection/README.md`](detection/README.md)를 참고하세요.

### `docs/`

저장소 전체에 걸친 리팩토링 기록입니다. 현재 유효한 것은
[`docs/refactor-summary.md`](docs/refactor-summary.md)(미끼 경로·저장소·설정 단일화 최종 보고서)와
[`docs/site-generalization-rollback.md`](docs/site-generalization-rollback.md)(사이트 일반화 되돌리기)
둘이고, 현재 상태를 설명하지 않게 된 문서는 [`docs/archive/`](docs/archive/README.md)에 보관했습니다.


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

공개 `:80`의 HTTP 요청은 `Detection → 공식 Defense → 대상별 CHeaT sidecar → 선택된 대상`으로 흐릅니다. Defense는 관리 화면의 대상 ID에 맞는 sidecar를 선택하고, 계정 오버레이 정책이 선택되면 해당 대상의 비공개 오버레이로 라우팅합니다. 현재 자동 정책은 이전에 완료된 요청에서 계산한 위험 점수와 확정 공격 점수를 위에서부터 평가해 요청마다 하나의 단계를 선택합니다. 확정 공격 점수는 반환·검증된 signed `dcid`의 이력에서만 계산합니다.

| 단계 | 위험 점수 | 확정 공격 점수 | 선택 기법 |
| --- | --- | --- | --- |
| `stage4` | 0.8 이상 | 0.8 이상 | `decoy_maze` + `delay` 700ms → `rate_limit_strict`(초당 최대 1요청) → `account_overlay_high` |
| `stage3` | 0.5 이상 | 0.5 이상 0.8 미만 | `decoy_maze` + `account_overlay_medium` + `delay` 500ms |
| `stage2` | 0.25 이상 | 0.25 이상 0.5 미만 | `decoy_maze` + `account_overlay_medium` + `delay` 300ms |
| `stage1` | 그 외(0점 포함) | 그 외 | `decoy_maze` |

단계가 올라가도 `decoy_maze`는 유지합니다. 2~3단계는 중간 계정 오버레이, 4단계는 이를 대체하는 높은 계정 오버레이를 적용합니다. 지연은 누적하지 않고 현재 단계의 300·500·700ms 중 하나만 적용합니다. 계정 오버레이 행위자의 `GET`/`HEAD` 요청 중 CHeaT 기본 미로 패턴과 대상별 추가 미끼 경로에 해당하는 요청은 CHeaT로 보내며, CHeaT는 실제 대상에 접근하지 않습니다. 실제 `/admin` 경로가 있는 RUBY Shop에서는 이 경로를 미로에서 제외해 오버레이로 보냅니다. 일반 요청은 Defense가 서명해 오버레이로 보냅니다. 따라서 오버레이로 보낸 일반 응답에는 CHeaT가 추가하는 미로 입구 힌트가 새로 삽입되지 않지만, 이미 알려진 미끼 경로는 계속 동작합니다. 운영·로컬 Compose에서는 CHeaT 내부 지연을 꺼서 단계별 지연값이 추가로 늘어나지 않게 합니다. 오버레이에 들어간 클라이언트의 경로는 대상·실행 ID·검증된 `dcid`별로 영속 저장됩니다. 점수가 내려가 1단계 계획이 선택돼도 이미 격리된 같은 식별자는 오버레이에 남습니다. 쿠키를 삭제하거나 새 실행을 시작하면 별도 식별자로 처리됩니다. 4단계 지연은 속도 제한보다 먼저 실행돼 429 응답에도 700ms가 적용됩니다. 사이트별 `decoy_t21_shell`·`decoy_migration`은 자동 정책에서 선택하지 않습니다.

`path_alias`는 단계별 전략 목록과 별도로 현재 요청의 **위험 점수가 0.5 이상일 때** 새 별칭을 발급하고 응답을 치환합니다. 확정 공격 점수가 낮아 정책 계획이 `stage1` 또는 `stage2`여도 이 기준을 넘으면 켜집니다. 운영 Compose에서는 첫 해당 요청부터 검증된 Juice Shop 경로를 enforce로, 브라우저 검증 전인 RUBY Shop 경로를 observe로 처리합니다. 따라서 기존 탭이 원본 API 경로를 계속 호출하면 Juice Shop에서 404를 받을 수 있으며, 새로고침해 새 별칭을 받아야 합니다. 점수가 다시 0.5 미만이 되면 새 발급·치환·원본 경로 차단을 멈추되 기존 별칭 URL은 복원합니다. 별칭으로 들어온 요청의 원래 경로는 Defense가 서명한 응답 피드백을 Detection이 검증한 뒤 완료 이력의 경로별 점수에 반영합니다. 요청을 Defense로 보내기 전 수행하는 CRS의 URL 검사에는 별칭 URL이 사용됩니다. 자세한 제한은 [경로 별칭 운영 가이드](defense/docs/path-alias-operations.md)를 참고하세요.

Juice Shop의 3·4단계에서 원본 `/rest/user/login`으로 보낸 요청은 계정 오버레이보다 먼저 별칭 강제 규칙에 걸려 지연 후 404가 됩니다. 발급된 별칭으로 보낸 로그인 요청은 오버레이로 처리합니다.

정책은 **완료된 이전 요청**의 점수를 다음 요청에 적용합니다. 실험 도구는 첫 응답에서 받은 signed `dcid` 쿠키를 이후 요청에도 보내야 확정 공격 점수와 영속 방어 경로를 같은 행위자로 검증할 수 있습니다. 쿠키를 계속 돌려주지 않는 요청은 같은 IP·HTTP 지문의 관찰 후보와 한 IP 안에서 연결된 흐름 이력으로 위험 점수를 판단합니다. 이 경우 확정 공격 점수는 쌓이지 않아 단계별 전략은 `stage1` 미끼만 선택되지만, 위험 점수가 0.5 이상이면 경로 별칭은 적용됩니다. 동일 IP·지문을 공유하는 다른 클라이언트의 첫 요청에도 미끼와 별칭이 적용될 수 있습니다. 방어 대시보드의 연결된 흐름은 관찰용 묶음이며 동일 클라이언트의 확정 신원을 뜻하지 않습니다.

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

로컬 Compose의 기본 선택 대상과 오버레이 매핑은 `legacy`입니다. `alternate`를 선택하려면 `TARGET_CHOICES`와 `OVERLAY_UPSTREAM_CHOICES`에 두 대상의 주소를 함께 설정해야 합니다. 이미 생성된 `defense-overlay-data`는 대상 ID 집합을 고정하므로 설정만 바꾸면 기동이 거부됩니다. 기존 격리 이력을 보존할 마이그레이션 없이 볼륨을 삭제하지 마세요.

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
