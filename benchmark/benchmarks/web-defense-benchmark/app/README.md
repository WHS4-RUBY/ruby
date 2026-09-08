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
- `attacker`: 자율 공격자와 외부 통신 제한 프록시
- `runner`: 시험 상태, 산출물 해시와 정리 결과 원장
- `defenses`: 공통 연결 계약을 확인하는 로컬 참조 방어
- `tools/inline_defense_gateway_v2.py`: 방어와 대상 사이의 공통 게이트웨이 및 계측기

공개 서비스는 `http://127.0.0.1:18080`, 제어 API는 `http://127.0.0.1:18081`입니다. 두 포트 모두 loopback에만 바인딩되며 데이터 서비스는 Compose 내부 네트워크에만 연결됩니다.

## Compose 직접 실행

정상 조건은 추가 설정 없이 실행됩니다.

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
$env:PYTHONPATH='app/backend;app/evaluator;app/runner'
.venv\Scripts\python.exe app\tools\check_running_stack.py
.venv\Scripts\python.exe app\tools\check_role_flows.py
```

`.env`에서 초기화 토큰을 바꿨다면 각 명령에 `--reset-token`을 전달합니다.

## 취약점과 자율 캠페인

모듈 23개의 목록과 판정 조건은 `configs/stage3-vulnerability-module-catalog-v1.json`, 자율 공격 대상 27개는 `configs/stage3a-autonomous-target-registry-v2.json`에 있습니다. 공격자에게 제공되는 공용 지침은 상위 [`ATTACKER.md`](../ATTACKER.md)이며, 표적별 정답과 비공개 평가기 자료를 포함하지 않습니다.

원본 CVE 표적은 별도 Compose 프로젝트로 실행되고 digest가 고정된 이미지를 요구합니다. 각 시험은 loopback relay와 내부 대상 네트워크를 만들고 종료 시 소유 컨테이너와 네트워크를 정리합니다.

방어는 `configs/stage3a-defense-runtime-registry-v2.json`에 등록하고 `../scripts/defense.ps1` 또는 `../scripts/defense.sh`로 목록, 계약 검사와 smoke test를 실행합니다. 연결 절차는 상위 [`docs/defense-integration.md`](../docs/defense-integration.md)에 있습니다.
