# RUBY 취약 웹 실행 환경

정상 업무 흐름, 선택형 취약점, 비공개 평가기와 격리된 데이터 서비스를 Docker Compose로 실행합니다. 간단한 실행에는 상위 디렉터리의 `scripts/benchmark.ps1` 또는 `scripts/benchmark.sh`를 권장합니다.

## 구성

- `frontend`: React 화면과 Nginx 공개 진입점
- `backend`: FastAPI 업무 API와 취약점 모듈
- `postgres`: 업무 계정, SQL 주입 전용 계정, 평가 계정을 분리한 PostgreSQL 17
- `redis`: 세션과 worker 작업 대기열
- `object-store`: RustFS 기반 S3 호환 첨부 저장소
- `worker`: 첨부 객체 확인과 상태 전환
- `evaluator`: 공개 응답과 분리된 내부 사건 판정기
- `attacker`: 저장소에 남아 있는 컨테이너형 공격자와 외부 통신 제한 프록시 자산. 현재 v3 캠페인은 이를 호출하지 않고 호스트 AI CLI와 `ActionExecutor`를 사용합니다.
- `runner`: Stage 2 시험의 상태, 산출물 해시와 정리 결과 원장. 현재 v3 캠페인은 별도 schedule, result와 seal을 쓰고 진행 중에만 복구 checkpoint를 유지합니다.
- `defenses`: 공통 연결 계약을 확인하는 로컬 참조 방어
- `tools/inline_defense_gateway_v2.py`: 방어와 대상 사이의 공통 게이트웨이 및 계측기

공개 서비스는 `http://127.0.0.1:18080`, FastAPI 직접 및 제어용 loopback 포트는 `http://127.0.0.1:18081`입니다. `18081`은 내부 경로만 따로 공개하는 포트가 아니라 같은 FastAPI 전체를 직접 매핑합니다. Nginx를 거치는 `18080`은 `/internal/*`을 전달하지 않습니다. 두 포트 모두 loopback에만 바인딩되며 데이터 서비스는 Compose 내부 네트워크에만 연결됩니다.

## Compose 직접 실행

다음 명령은 이 `app/` 디렉터리에서 실행합니다. 벤치마크 루트에 있다면 먼저 `cd app`으로 이동합니다. 정상 조건은 추가 설정 없이 실행됩니다.

```bash
docker compose up -d --build --wait
docker compose ps
```

취약 조건에는 쉼표로 구분한 모듈과 32자리 소문자 16진수 시험 ID가 모두 필요합니다.

```powershell
$env:RUBY_WEB_VULNERABILITY_MODULES='sql-injection.product-search'
$env:RUBY_WEB_TRIAL_ID=[Guid]::NewGuid().ToString('N')
docker compose up -d --build --wait
```

```bash
RUBY_WEB_VULNERABILITY_MODULES=sql-injection.product-search \
RUBY_WEB_TRIAL_ID=0123456789abcdef0123456789abcdef \
docker compose up -d --build --wait
```

종료 시 볼륨을 보존하려면 `docker compose down`, 데이터도 지우려면 `docker compose down --volumes --remove-orphans`를 사용합니다.

## 팀 서버 런타임

`compose.production.yaml`은 소스 빌드와 호스트 포트 공개 없이 CI가 만든 이미지를
실행합니다. 루트 RUBY 스택이 `ruby_ai-defense-net`을 먼저 생성해야 하며, 이 스택에서는
`web`만 해당 네트워크에 `ruby-web-target`이라는 이름으로 연결됩니다. API, 평가기,
PostgreSQL, Redis와 오브젝트 저장소는 내부 네트워크에만 남습니다.

```bash
cp .env.production.example .env.production
# .env.production의 이미지 태그와 모든 replace-* 값을 실제 배포 값으로 변경
docker compose \
  --env-file .env.production \
  -f compose.production.yaml \
  pull
docker compose \
  --env-file .env.production \
  -f compose.production.yaml \
  up -d --wait
```

배포 이미지 태그에는 `latest` 대신 CI가 발행한 Git 커밋 SHA를 사용합니다. PostgreSQL
비밀번호는 연결 URL에도 들어가므로 `openssl rand -hex 32`처럼 URL에 그대로 사용할 수
있는 값으로 생성합니다. 실제 `.env.production`은 커밋하지 않습니다.

자체 웹을 실험 대상으로 선택할 때 Defense의 전달 주소는 다음과 같습니다.

```text
http://ruby-web-target:8080
```

웹 컨테이너에는 호스트 포트가 없으므로 외부 공격자는 Detection의 공개 포트를 통해서만
접근합니다. 관리 UI는 이 Compose에 포함되지 않으며 별도 운영자 전용 연결을 사용합니다.
평가기와 초기화 API도 공개 진입점에서 전달하지 않습니다.

팀 루트 스택에서 자체 웹과 Juice Shop을 전환하는 명령은
[`서버 벤치마크 대상 전환`](../docs/operations/04-server-target-selection.md)에 정리했습니다.

Defense가 두 대상을 실제로 왕복 전환하는 로컬 검사는 벤치마크 루트에서 실행합니다.
검사는 고유 임시 프로젝트와 네트워크를 만들고 초기화, 비공개 성공 판정과 격리 계약,
자체 웹과 Juice Shop 응답을 확인한 뒤 컨테이너, 볼륨과 네트워크를 정리합니다.

```bash
./scripts/check_target_switch.sh
```

## 개발용 계정

| 역할 | 이메일 | 비밀번호 |
| --- | --- | --- |
| 고객 | `customer@ruby.local` | `RUBY-Development-Only-2026!` |
| 판매자 직원 | `seller@ruby.local` | `RUBY-Development-Only-2026!` |
| 고객지원 직원 | `support@ruby.local` | `RUBY-Development-Only-2026!` |
| 관리자 | `admin@ruby.local` | `RUBY-Operations-Only-2026!` |

전부 합성 계정입니다. 공유 환경에서는 `.env.example`을 `.env`로 복사해 제어 토큰과 비밀번호를 바꿉니다. `.env`는 Git 추적 대상이 아닙니다.

## 실행 중인 스택 검사

프로젝트 루트에서 개발 의존성을 설치한 뒤 실행합니다.

```powershell
$env:PYTHONPATH='app/backend;app/evaluator;app/runner;app/tools'
app\.venv\Scripts\python.exe app\tools\check_running_stack.py
app\.venv\Scripts\python.exe app\tools\check_role_flows.py
```

`.env`에서 초기화 토큰을 바꿨다면 각 명령에 `--reset-token`을 전달합니다.

## 취약점과 자율 캠페인

모듈 29개의 목록과 판정 조건은 `configs/stage3-vulnerability-module-catalog-v1.json`에 있습니다. `configs/stage3a-autonomous-target-registry-v2.json`은 합성 웹 표적 29개와 원본 CVE 표적 5개를 등록합니다. 공격자 지침은 프로필의 `instruction_document`가 선택합니다. 예를 들어 v10은 상위 [`ATTACKER.md`](../ATTACKER.md)를 사용하고 v14, v15와 v16은 [`ATTACKER_MINIMAL.md`](../ATTACKER_MINIMAL.md)를 사용합니다. 공개 brief는 guided처럼 설정된 조건에서만 제공하며 hidden-black-box 조건에는 제공하지 않습니다. 지침과 공개 brief에는 표적별 정답과 비공개 평가기 자료를 포함하지 않습니다.

원본 CVE 표적은 별도 Compose 프로젝트로 실행되고 digest가 고정된 이미지를 요구합니다. 각 시험은 loopback relay와 내부 대상 네트워크를 만들고 종료 시 소유 컨테이너와 네트워크를 정리합니다.

방어는 `configs/stage3a-defense-runtime-registry-v2.json`에 등록하고 `../scripts/defense.ps1` 또는 `../scripts/defense.sh`로 목록, 계약 검사와 smoke test를 실행합니다. 연결 절차는 상위 [`docs/defense-integration.md`](../docs/defense-integration.md)에 있습니다.
