# RUBY

RUBY는 웹 요청의 공격 가능성을 탐지하고, 위험도와 정책에 따라 대응 전략을 선택해 방어 기법을 적용하며, 그 성능과 재현성을 검증하는 프로젝트입니다. 탐지, 정책 판단, 방어, 벤치마크에 필요한 코드와 문서를 함께 관리합니다.

## 저장소 구조

```text
RUBY/
├── benchmark/   # 실험 대상, 실행 환경, 결과 및 재현 자료
├── defense/     # 차단·변환·지연·기만 등 방어 계층
├── detection/   # Node.js 탐지 프록시, ModSecurity/CRS, 대시보드, Policy
```

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

서버에서는 [`.env.example`](.env.example)을 `.env`로 복사한 뒤 `IMAGE_PREFIX`, 배포할 `IMAGE_TAG`, `PUBLIC_TARGET_ORIGIN`을 설정합니다. 운영 Compose는 두 대시보드 비밀번호와 `PAYLOAD_FINGERPRINT_KEY`, `DCID_HMAC_SECRET`, `ACCOUNT_ID_HASH_KEY`가 없으면 시작하지 않습니다. GitHub Actions 배포에서는 `DEFENSE_DASHBOARD_PASSWORD`를 두 대시보드에 사용하고 나머지 세 값을 같은 이름의 Repository Secret에서 가져옵니다.

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

보호할 대상을 바꾸려면 사용자 컴퓨터에서 `ssh -L 8088:127.0.0.1:8088 USER@SERVER`를 열고 `http://127.0.0.1:8088/__detection/dashboard`의 **실험 대상**에서 선택합니다. 전환할 때 실행 ID가 새로 발급되며, 이후 `PUBLIC_TARGET_ORIGIN`의 포트 80으로 보낸 요청에 대상 ID와 실행 ID가 기록됩니다. 방어 화면은 같은 관리 주소의 `/__defense/dashboard`입니다. 대시보드의 전체 요약은 보관된 여러 실행을 함께 집계하므로 개별 요청 상세의 ID로 구분합니다.

기만 방어 경로는 `Detection → 공식 Defense → 대상별 CHeaT sidecar → 벤치마크 대상`입니다. 운영 Compose는 Juice Shop과 RUBY Shop용 sidecar를 각각 내부 Docker 네트워크에만 띄우며, 공개 포트는 추가하지 않습니다. Defense는 관리 화면에서 선택한 대상 ID로 sidecar를 고르고, WebSocket은 기존 대상에 직접 연결합니다. 탐지가 이전 요청들에서 위험도와 확정 공격 점수를 모두 0.8 이상으로 계산한 경우에만 기존 엄격 속도 제한·지연과 함께 공통 `decoy_maze` 계획을 전달합니다. 정상 요청에는 기만 계획이 없고, 프로필에 종속된 `decoy_t21_shell`·`decoy_migration`은 현재 공통 운영 정책에서 자동 선택하지 않습니다. 방어 대시보드의 요청 상세에 실제 sidecar 동작과 전략이 기록됩니다. 실행 ID가 바뀌면 sidecar의 클라이언트별 기만 상태도 분리됩니다.

이 경로를 사용하려면 `TARGET_CHOICES`에 `juice-shop`과 `ruby-shop` ID가 각각 `juice-shop-target:3000`, `ruby-web-target:8080`으로 등록되어 있어야 합니다. 다른 대상 ID에는 sidecar를 적용하지 않고 기존 Defense 경로를 사용합니다. `main` 병합 뒤 CI가 성공하면 배포 workflow가 세 이미지를 SHA 태그로 배포합니다. 새 Compose와 이미지로 띄운 뒤 smoke test가 실패하면 이전 Compose와 이미지 태그로 되돌립니다.

## 로컬 테스트

Docker Desktop을 실행한 뒤, 아래 명령으로 로컬 소스를 빌드해 전체 요청 경로를 띄웁니다. 배포용 `docker-compose.yml`과 달리 레지스트리 설정이나 `.env` 파일이 필요 없습니다.

```bash
docker compose -f docker-compose.local.yml up --build
```

먼저 보호할 애플리케이션을 이 호스트의 포트에서 실행합니다. 기본 포트는 `3000`이며 `.env`나 셸의 `TARGET_PORT`로 바꿀 수 있습니다. 예를 들어 Juice Shop은 `docker run -d -p 3000:3000 bkimminich/juice-shop`으로 띄울 수 있습니다. 로컬 Compose는 이 대상 앞에 두 개의 비공개 테스트 sidecar를 띄웁니다. 브라우저에서 `http://localhost:8081`로 접속하거나, 다음처럼 Detection → Defense → sidecar → Target의 전체 경로를 확인합니다.

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

## 보안 주의사항

API 키, 토큰, 비밀번호, 실제 서버 식별 정보, 개인정보가 포함된 로그를 커밋하지 않습니다. 필요한 환경 변수는 실제 값이 없는 `.env.example`로만 공유합니다.
