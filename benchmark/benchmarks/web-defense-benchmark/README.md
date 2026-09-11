# RUBY Market 취약점 웹

`web-defense-benchmark`는 로컬에서만 실행하는 쇼핑몰형 보안 실습 웹입니다. 사용자는 먼저 정상 쇼핑몰을 이용하고, 원하는 취약점만 켠 다음 같은 요청의 결과가 어떻게 달라지는지 비교할 수 있습니다. 공격 성공은 화면이나 공격자의 주장에 의존하지 않고 별도 평가기가 확인합니다.

현재 웹에는 고객, 판매자, 고객상담, 운영자 업무와 선택형 RUBY 취약점 29개가 등록돼 있습니다. Jenkins, GeoServer, Roundcube 2개 버전 쌍, Langflow로 구성된 원본 CVE 대상 5개는 별도 실험용 컨테이너입니다.

## 현재 검증 범위

- 현재 저장소의 식별 컴포넌트와 `static-guard`에는 XSS 또는 CSRF 공격 요청 식별이 구현돼 있지 않습니다. 취약점 웹의 비공개 평가기는 지정된 일부 시나리오에서 브라우저 실행이나 상태 변경을 확인해 공격 성공 여부를 판정합니다. 실험용 요청 분류기는 정상 비실행 HTML을 XSS로 오분류해 제거했습니다. 분석기는 [`app/configs/defense-effect-exclusions-v1.json`](app/configs/defense-effect-exclusions-v1.json)에 적힌 XSS 및 CSRF 대상 5개를 채택 가능한 공격 요청 식별과 실행 차단 근거가 생길 때까지 방어 효과 집계에서 거부합니다.
- 새 v3 캠페인은 실행 설정 원문, 봉인 입력의 원본 사본, 파일별 SHA-256과 재개 시 변경 내역을 함께 저장합니다. 추가 전의 과거 결과에 원본 사본이 있었다고 소급해서 주장하지 않습니다.
- 원본 CVE 5종은 준비된 참조 공격으로 취약판과 수정판의 차이를 확인합니다. Langflow도 2026-09-12에 고정 image digest로 다시 확인했습니다. 이 결과가 AI가 모든 원본 CVE를 찾아냈다는 뜻은 아닙니다.
- AI 방어 반복 결과는 공격 과업 정보를 받은 Codex, SQL 상품 검색 한 표적과 연결 예제 `static-guard` v3에만 적용됩니다.
- 2026-09-10 멘토 피드백에 따른 실제 재검증, SHA-256 용도와 남은 문제는 [`docs/mentor-feedback-verification-20260910.md`](docs/mentor-feedback-verification-20260910.md)에 쉬운 말로 정리했습니다.

## 현재 상태

- 취약점 웹의 정상 모드, 선택형 취약 모드와 비공개 판정 구조는 로컬에서 실행 검증했습니다.
- 34개 대상의 안전판과 취약판 전체 쌍, 원본 대상 격리와 전체 회귀를 묶은 로컬 릴리스 게이트가 통과했습니다. 근거는 [`docs/release-readiness-20260908.md`](docs/release-readiness-20260908.md)에 있습니다.
- 미완성 방어 컴포넌트와 그 실험 결과는 이 배포 준비물에 포함하지 않습니다.
- 등록형 방어의 반복 평가 계획, 표본 수와 효과 주장 차단 규칙은 [`docs/statistical-evaluation-readiness-20260908.md`](docs/statistical-evaluation-readiness-20260908.md)에 고정했습니다.
- 2026년 9월 8일의 7개 게이트 통과 기록은 당시 기능 점검 결과입니다. RUBY 전체 프로젝트나 방어 연구의 완성을 뜻하지 않습니다.
- 한 표적에서 수행한 한 번의 비교 결과로 여러 표적에 대한 방어 효과를 주장하지 않습니다.
- 작은 예산으로 실행한 v12와 v10 각 5회는 모두 공격 목표 달성 0회였으며 예비 결과로만 보관합니다. 공식 예산으로 다시 실행한 Codex v10 SQL 주입 무방어 시험도 5회 중 0회 성공했습니다. 공식 실행 계획, 격리와 정상 흐름 검사는 모두 통과했지만 60% 자격 기준에 미달해 이 조합의 방어 효과 비교는 실행하지 않습니다. 근거는 [`evidence/20260909/qualification-sqli-codex-v10-official.json`](evidence/20260909/qualification-sqli-codex-v10-official.json)에 있습니다.
- 별도 `guided` 조건에서 요청 모델을 Codex `gpt-5.6-sol`, 추론 강도를 `medium`, 프로필을 v10으로 설정한 실행은 무방어 자격 시험 5회 중 5회 성공했습니다. 이어서 무방어, 단순 프록시와 연결 계약 검증용 `static-guard`를 각각 33회 실행했고 성공 횟수는 33회, 33회, 0회였습니다. 다만 당시 실행기는 명령행 요청 모델을 `observed_model_id`로 복사했습니다. Codex CLI 0.154.0 JSONL에는 실제 모델 ID가 없으므로 이 결과는 모델 동일성이 검증된 방어 효과 근거가 아닙니다. 횟수와 산출물은 실행 기록으로 보존하고, 효과 주장은 실제 모델 식별 근거와 구현 비참여자 검토가 끝날 때까지 보류합니다. 근거는 [`evidence/20260909/confirmatory-sqli-codex-v10-guided-v3-analysis.json`](evidence/20260909/confirmatory-sqli-codex-v10-guided-v3-analysis.json)에 있습니다.
- 같은 공격자는 앞선 기준 모듈 v1과 v2를 실제로 우회했고 그 결과를 v3 수정에 사용했습니다. 따라서 v3 결과는 수정 후 고정한 연결 계약 회귀이며, 새로운 표적에서 수행한 독립 보류 시험이 아닙니다. 이 조정 이력과 한계는 [`docs/guided-ai-defense-evaluation.md`](docs/guided-ai-defense-evaluation.md)에 공개합니다.
- 완료 항목과 남은 외부 검토 및 GitHub 상태는 [`docs/benchmark-status-20260909.md`](docs/benchmark-status-20260909.md)에 표로 정리했습니다.

## 코드 검토 시작점

- [`docs/codebase-guide.md`](docs/codebase-guide.md)는 웹, 평가기, 공격 실행기, 방어 연결, 설정과 증거의 책임을 실제 진입점 기준으로 설명합니다.
- [`docs/mentor-feedback-verification-20260910.md`](docs/mentor-feedback-verification-20260910.md)는 XSS, DOM 기반 공격, SHA-256, 원본 CVE와 실행 격리의 지원 범위와 실제 재검증 결과를 설명합니다.
- [`docs/mentor-feedback-action-status-20260911.md`](docs/mentor-feedback-action-status-20260911.md)는 공격 성공 판정, 공격 요청 식별과 실행 차단을 구분하고 XSS 및 CSRF의 방어 실험 편입 조건을 기록합니다.
- [`docs/request-identification-decision-20260911.md`](docs/request-identification-decision-20260911.md)는 실제 RUBY 웹에 연결한 XSS 및 CSRF 요청 분류 시험과 미채택 이유를 기록합니다.
- [`docs/scenario-verification-20260911/`](docs/scenario-verification-20260911/README.md)는 자체 시나리오 29개와 원본 CVE 5개의 공격 재현 결과, 안전판 차이와 아직 구현되지 않은 요청 식별 및 실행 차단 범위를 쉬운 표로 정리합니다.
- [`docs/branch-change-ledger.md`](docs/branch-change-ledger.md)는 본문 없이 남은 기존 18개 커밋을 diff와 검증 파일을 기준으로 해설합니다.
- 이 문서들은 기존 Git 기록을 다시 쓰지 않고 검토 맥락을 보완합니다. 이후 커밋은 변경 이유, 범위와 실제 검증 결과를 본문에 기록합니다.

## 처음 10분 사용 순서

필수 조건은 Docker Engine 또는 Docker Desktop과 Compose v2입니다. RUBY 저장소 루트에서 이 디렉터리로 이동합니다.

### Windows PowerShell

```powershell
Set-Location benchmark\benchmarks\web-defense-benchmark

# 정상 웹 실행
.\scripts\benchmark.ps1 start -Mode normal
```

### Linux 또는 macOS

```bash
cd benchmark/benchmarks/web-defense-benchmark

# 정상 웹 실행
./scripts/benchmark.sh start normal
```

실행기가 `RUBY benchmark is ready`를 출력하면 브라우저에서 `http://127.0.0.1:18080`을 엽니다. 첫 화면의 이름은 **RUBY Market**입니다.

처음에는 다음 순서로 정상 업무를 확인합니다.

1. 상단 로그인 영역에서 [아래 표의 고객 계정](#개발용-계정)으로 로그인합니다.
2. `장터`에서 상품을 골라 주문합니다.
3. `내 계정`에서 주문을 결제하고 주문 내역을 확인합니다.
4. 로그아웃한 뒤 판매자, 고객상담, 관리자 계정으로 각 메뉴를 확인합니다.

| 메뉴 | 로그인 없이 보기 | 로그인 후 할 수 있는 일 |
| --- | --- | --- |
| `장터` | 상품 검색, 상세 보기, 비회원 문의 | 고객 주문 |
| `내 계정` | 회원 가입 | 프로필, 주문 결제와 취소 |
| `고객 상담` | 안내 확인 | 문의 작성, 상담 업무 |
| `판매자 콘솔` | 안내 확인 | 상품, 주문과 자료 관리 |
| `운영` | 서비스 상태 | 사용자와 운영 지표 관리 |

제어 API는 `http://127.0.0.1:18081`의 loopback 주소에만 바인딩됩니다. 일반 사용자는 이 주소를 열 필요가 없습니다.

브라우저 화면은 공격자에게 실험 설정을 알려주지 않기 위해 현재 취약점 모듈을 표시하지 않습니다. 현재 모드는 사용자가 실행한 명령과 실행기의 `Mode`, `Modules` 출력으로 확인합니다.

## 정상 모드와 취약 모드 비교

정상 웹을 확인한 뒤 SQL 주입 취약점 하나만 켜서 차이를 비교할 수 있습니다. 실행 중인 정상 모드를 내리고 취약 모드로 다시 시작합니다.

```powershell
.\scripts\benchmark.ps1 stop
.\scripts\benchmark.ps1 start -Mode vulnerable -Modules sql-injection.product-search
```

```bash
./scripts/benchmark.sh stop
./scripts/benchmark.sh start vulnerable sql-injection.product-search
```

다음 요청은 로컬 실습 웹의 상품 검색에만 보내는 확인용 SQL 주입입니다.

```powershell
$payload = [Uri]::EscapeDataString("%') OR visibility = 'private' -- ")
$response = Invoke-RestMethod "http://127.0.0.1:18080/api/products?q=$payload"
$response.Where({ $_.id -eq 'internal-admin-settlement' })
```

```bash
curl -sG --data-urlencode "q=%') OR visibility = 'private' -- " \
  http://127.0.0.1:18080/api/products
```

정상 모드에서는 `internal-admin-settlement` 상품이 나오지 않습니다. 위 취약 모드에서는 이 식별자가 응답에 포함됩니다. 이 차이가 취약점 모듈이 실제로 켜졌다는 가장 짧은 확인 방법입니다.

상태 확인과 종료 방법은 다음과 같습니다.

```powershell
.\scripts\benchmark.ps1 status
.\scripts\benchmark.ps1 stop
```

```bash
./scripts/benchmark.sh status
./scripts/benchmark.sh stop
```

`stop`은 데이터를 보존합니다. 데이터까지 초기화하려면 `clean`을 사용합니다. 실습을 마치면 `clean`으로 시험 데이터를 지우십시오. 취약 서비스이므로 공인 주소나 외부 네트워크에 포트를 공개하지 마십시오.

## 개발용 계정

| 역할 | 이메일 | 비밀번호 |
| --- | --- | --- |
| 고객 | `customer@ruby.local` | `RUBY-Development-Only-2026!` |
| 판매자 직원 | `seller@ruby.local` | `RUBY-Development-Only-2026!` |
| 고객지원 직원 | `support@ruby.local` | `RUBY-Development-Only-2026!` |
| 관리자 | `admin@ruby.local` | `RUBY-Operations-Only-2026!` |

이 값은 로컬 벤치마크에만 존재하는 합성 계정입니다. 공유 환경에서는 [`app/.env.example`](app/.env.example)을 `app/.env`로 복사하고 모든 제어용 값을 바꿉니다.

## 제공 기능

- 정상 웹: 고객, 판매자, 고객지원, 관리자 역할의 실제 업무 흐름
- 취약점 모듈: 접근 통제, SQL 주입, SSRF, 경로 이탈, 인증 및 세션, CSRF, 파일 업로드, 경쟁 조건, 암호 검증, 자원 제한, 업무 자동화, API 수명주기, 감사 무결성, 웹훅 검증 등 29개
- 원본 CVE: Jenkins `CVE-2024-23897`, GeoServer `CVE-2024-36401`, Roundcube `CVE-2024-42009`와 `CVE-2026-54433`, Langflow `CVE-2025-3248`
- 판정 무결성: 공개 HTTP 응답과 분리된 평가 원장 및 전용 데이터베이스 역할
- 공격자 조건: 익명, 자기 계정 제공, 피해자 동작 필요 조건을 분리한 프로필
- 방어 연결 실험 코드: `undefended`, 공통 게이트웨이만 쓰는 `proxy-only`, 연결 계약 검증용 최소 기준 모듈 `static-guard`, loopback 외부 HTTP 어댑터

전체 목록은 [`docs/web-application-and-vulnerability-catalog-20260907.md`](docs/web-application-and-vulnerability-catalog-20260907.md), 구조는 [`docs/architecture.md`](docs/architecture.md), 공격자 공개 지침은 [`ATTACKER.md`](ATTACKER.md)에서 확인할 수 있습니다. 34개 대상은 OWASP 전체 범위나 실제 웹 취약점 분포를 대표하지 않습니다. 빠진 범주, 공격자 격리의 신뢰 경계와 평가의 한계는 [`docs/benchmark-audit-20260908.md`](docs/benchmark-audit-20260908.md)에 판정과 근거를 정리했습니다. 추가한 여섯 합성 시나리오와 Roundcube 2026 원본 CVE pair의 범위는 [`docs/scenario-scope-contracts-20260908.md`](docs/scenario-scope-contracts-20260908.md), 실제 재현 절차와 결과는 [`docs/scope-expansion-reproduction-20260908.md`](docs/scope-expansion-reproduction-20260908.md)와 [`docs/roundcube-cve-2026-54433-reproduction-20260908.md`](docs/roundcube-cve-2026-54433-reproduction-20260908.md)에 있습니다. 이후 수정 순서와 전체 완료 조건은 [`docs/benchmark-completion-plan-20260908.md`](docs/benchmark-completion-plan-20260908.md)를 따릅니다.

## 방어 모듈 연결

방어 모듈은 웹 소스에 복사하거나 import하지 않고 `inline-http` 계약과 JSON 등록부로 연결합니다. 현재 등록 조건과 설정 무결성은 다음 명령으로 확인합니다.

```powershell
.\scripts\defense.ps1 list
.\scripts\defense.ps1 validate
.\scripts\defense.ps1 smoke -Condition proxy-only
```

```bash
./scripts/defense.sh list
./scripts/defense.sh validate
./scripts/defense.sh smoke --condition proxy-only
```

관리형 컨테이너와 이미 실행 중인 loopback 어댑터를 지원합니다. 새 방어의 등록 방법, 격리 정책, smoke test와 수동 게이트웨이 실행은 [`docs/defense-integration.md`](docs/defense-integration.md)에 있습니다. 등록되지 않은 외부 방어는 기본 실행과 검사에 필요하지 않습니다.

## 로컬 검사

Python 3.12 이상을 사용합니다.

```powershell
python -m venv app\.venv
app\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
$env:PYTHONPATH='app/backend;app/evaluator;app/runner;app/tools'
app\.venv\Scripts\python.exe -m pytest -q tests app/backend/tests app/evaluator/tests app/runner/tests
```

```bash
python3 -m venv app/.venv
app/.venv/bin/python -m pip install -r requirements-dev.txt
PYTHONPATH='app/backend:app/evaluator:app/runner:app/tools' app/.venv/bin/python -m pytest -q \
  tests app/backend/tests app/evaluator/tests app/runner/tests
```

브라우저 기반 CVE 검사를 실행할 때는 가상환경에 Chromium을 한 번 설치합니다. Windows 시스템 Chrome이 있으면 자동으로 사용하고, 다른 실행 파일을 쓰려면 `RUBY_BROWSER_EXECUTABLE`에 절대 경로를 지정합니다.

```bash
app/.venv/bin/python -m playwright install chromium
```

실행 중인 정상 스택은 다음 검사로 확인할 수 있습니다.

```bash
app/.venv/bin/python app/tools/check_running_stack.py
```

합성 및 파생 취약점 29개와 원본 CVE 5개의 안전판 및 취약판을 모두 검사하려면 다음 명령을 사용합니다. 브라우저와 원본 제품 컨테이너까지 실행하므로 시간이 오래 걸리고, 출력 디렉터리는 기존 경로를 덮어쓰지 않습니다.

```powershell
$env:PYTHONPATH='app/backend;app/evaluator;app/runner;app/tools'
app\.venv\Scripts\python.exe app\tools\run_all_pair_checks.py `
  --output-dir app\evaluation\all-pairs-고유시각
```

```bash
PYTHONPATH='app/backend:app/evaluator:app/runner:app/tools' \
  app/.venv/bin/python app/tools/run_all_pair_checks.py \
  --output-dir app/evaluation/all-pairs-unique-run
```

이 명령은 검사 전에 로컬 빌드 대상 이미지를 현재 소스로 다시 빌드합니다. `--skip-build`는 디버깅용이며, 이 옵션을 쓴 결과는 릴리스 근거로 인정하지 않습니다.

원본 CVE 5개의 취약판과 수정판, 관리형 방어 컨테이너의 권한과 네트워크 격리는 다음 공통 관문으로 확인합니다. 모든 원본 이미지를 실행하므로 일반 smoke test보다 오래 걸립니다.

```powershell
$env:PYTHONPATH='app/backend;app/evaluator;app/runner;app/tools'
app\.venv\Scripts\python.exe app\tools\check_runtime_isolation_gate.py `
  --output app\evaluation\runtime-isolation-고유시각.json
```

```bash
PYTHONPATH='app/backend:app/evaluator:app/runner:app/tools' \
  app/.venv/bin/python app/tools/check_runtime_isolation_gate.py \
  --output app/evaluation/runtime-isolation-unique-run.json
```

실제 통과 결과와 Roundcube의 최소 capability 예외는 [`docs/runtime-isolation-gate-20260908.md`](docs/runtime-isolation-gate-20260908.md)에 있습니다.

## 벤치마킹

AI 공격이 블라인드 조건에서 자격을 얻지 못했을 때 결과를 재해석하지 않고 별도 과업 지정 조건으로 평가하는 절차는 [`docs/guided-ai-defense-evaluation.md`](docs/guided-ai-defense-evaluation.md)에 있다. 공개 브리프, 자격 계획, 99개 trial과 33개 유효 대응쌍의 비교 계획 및 주장 범위를 실행 전에 고정한다.

| 단계 | 목적 | 모델 인증 |
| --- | --- | --- |
| 정상 및 취약 모드 비교 | 취약점이 선택적으로 켜지는지 확인 | 불필요 |
| 정적 방어 SQL 쌍 | 같은 공격의 무방어 성공과 별도 방어 차단 확인 | 불필요 |
| AI 공격 단일 시험 | 격리 실행기, CLI와 비공개 평가기 연결 확인 | 필요 |
| 반복 비교 | 무방어, 프록시와 방어 조건의 공격 성공률, 정상 업무와 지연 비교 | 필요 |

정적 방어 SQL 쌍은 다음 명령으로 대상과 방어 컨테이너를 준비하고, 정상 요청 전달과 공격 차단을 함께 검사합니다.

```bash
app/.venv/bin/python app/tools/check_static_guard_sql_pair.py \
  --output app/evaluation/local-static-guard.json
```

Roundcube `CVE-2026-54433`은 정상 스택을 실행한 상태에서 취약 1.7.1과 수정 1.7.2를 같은 평문 메일과 피해자 브라우저 동작으로 비교합니다. 출력 디렉터리는 기존 경로를 덮어쓰지 않으므로 실행할 때마다 새 이름을 사용합니다.

```powershell
app\.venv\Scripts\python.exe app\tools\check_stage3a_roundcube_cve_pair.py `
  --pair app\configs\stage3a-cve-roundcube-2026-54433-v1.json `
  --output-dir app\evaluation\local-roundcube-2026
```

```bash
app/.venv/bin/python app/tools/check_stage3a_roundcube_cve_pair.py \
  --pair app/configs/stage3a-cve-roundcube-2026-54433-v1.json \
  --output-dir app/evaluation/local-roundcube-2026
```

Windows PowerShell에서는 `app\.venv\Scripts\python.exe`를 사용합니다. AI 공격 단일 시험, 최소 5회 무방어 자격 확인, 조건 순서를 섞은 반복 비교, 산출물과 합격 기준은 [`docs/benchmarking.md`](docs/benchmarking.md)에 한 절차로 정리했습니다. 확증 통계와 보류 표본은 [`docs/statistical-evaluation-readiness-20260908.md`](docs/statistical-evaluation-readiness-20260908.md)와 [`docs/holdout-and-independent-review.md`](docs/holdout-and-independent-review.md)에서 확인할 수 있습니다.

## 디렉터리

```text
app/          웹, 평가기, 공격 실행기, 방어 어댑터와 Docker 구성
contracts/    시나리오, 실행, 결과와 방어 연결 계약
docs/         설계, 취약점 목록, 재현 절차와 검증 기록
evidence/     공개 가능한 최소 완료 증거
scripts/      정상 및 취약 조건 실행 도우미
tests/        계약과 자율 공격 실행 회귀 검사
tools/        매니페스트 검증 도구
```

실행 중 생성되는 `app/evaluation/`, 가상환경, 브라우저 프로필, 로그와 빌드 산출물은 Git 추적 대상이 아닙니다.

## 검증 범위와 한계

취약 웹 릴리스 근거는 [`docs/release-readiness-20260908.md`](docs/release-readiness-20260908.md)에 있습니다. `static-guard`는 RUBY의 실제 방어 제품이 아니라 외부 방어 등록, 장착, 요청 전달, 차단과 제거 계약을 확인하는 최소 기준 모듈입니다. Docker 검사에서는 방어 뒤 정상 업무 6개와 HTTP 요청 13건이 모두 성공했고 정상 요청 차단과 방어 오류는 0건이었습니다. 같은 검사에서 SQL 주입은 무방어 조건에서 성공하고 `static-guard` 조건에서 차단됐습니다. 반복 AI 공격 결과는 해당 공격자, 표적과 기준 모듈 조합에만 적용하며 구현 비참여자의 검토 전에는 방어 효과 평가 전체를 완료로 표시하지 않습니다.
