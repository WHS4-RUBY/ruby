# RUBY Market 취약점 웹

`web-defense-benchmark`는 로컬에서만 실행하는 쇼핑몰형 보안 실습 웹입니다. 사용자는 먼저 정상 쇼핑몰을 이용하고, 원하는 취약점만 켠 다음 같은 요청의 결과가 어떻게 달라지는지 비교할 수 있습니다. 공격 성공은 화면이나 공격자의 주장에 의존하지 않고 별도 평가기가 확인합니다.

현재 웹에는 고객, 판매자, 고객상담, 운영자 업무와 선택형 RUBY 취약점 23개가 등록돼 있습니다. Jenkins, GeoServer, Roundcube 2개 버전 쌍, Langflow로 구성된 원본 CVE 대상 5개는 별도 실험용 컨테이너입니다.

## 현재 상태

- 취약점 웹의 정상 모드, 선택형 취약 모드와 비공개 판정 구조는 로컬에서 실행 검증했습니다.
- Honeyval 방어는 개발 중이며 현재 배포 또는 업로드 대상이 아닙니다.
- 2026년 9월 8일의 7개 게이트 통과 기록은 당시 기능 점검 결과입니다. RUBY 전체 프로젝트나 방어 연구의 완성을 뜻하지 않습니다.
- 한 표적에서 수행한 한 번의 비교 결과로 여러 표적에 대한 방어 효과를 주장하지 않습니다.

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
- 취약점 모듈: 접근 통제, SQL 주입, SSRF, 경로 이탈, 인증 및 세션, CSRF, 파일 업로드, 경쟁 조건, 다단계 공격 등 23개
- 원본 CVE: Jenkins `CVE-2024-23897`, GeoServer `CVE-2024-36401`, Roundcube `CVE-2024-42009`와 `CVE-2026-54433`, Langflow `CVE-2025-3248`
- 판정 무결성: 공개 HTTP 응답과 분리된 평가 원장 및 전용 데이터베이스 역할
- 공격자 조건: 익명, 자기 계정 제공, 피해자 동작 필요 조건을 분리한 프로필
- 방어 연결 실험 코드: `undefended`, 공통 게이트웨이만 쓰는 `proxy-only`, 별도 컨테이너 `static-guard`, 외부 어댑터로 등록된 개발 중 Honeyval

전체 목록은 [`docs/web-application-and-vulnerability-catalog-20260907.md`](docs/web-application-and-vulnerability-catalog-20260907.md), 구조는 [`docs/architecture.md`](docs/architecture.md), 공격자 공개 지침은 [`ATTACKER.md`](ATTACKER.md)에서 확인할 수 있습니다. 28개 대상은 OWASP 전체 범위나 실제 웹 취약점 분포를 대표하지 않습니다. 빠진 범주, 공격자 격리의 신뢰 경계와 평가의 한계는 [`docs/benchmark-audit-20260908.md`](docs/benchmark-audit-20260908.md)에 판정과 근거를 정리했습니다. 구현할 여섯 합성 시나리오와 구현한 Roundcube 2026 원본 CVE pair의 범위는 [`docs/scenario-scope-contracts-20260908.md`](docs/scenario-scope-contracts-20260908.md), 실제 재현 절차와 결과는 [`docs/roundcube-cve-2026-54433-reproduction-20260908.md`](docs/roundcube-cve-2026-54433-reproduction-20260908.md)에 있습니다. 이후 수정 순서와 전체 완료 조건은 [`docs/benchmark-completion-plan-20260908.md`](docs/benchmark-completion-plan-20260908.md)를 따릅니다.

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

관리형 컨테이너와 이미 실행 중인 loopback 어댑터를 지원합니다. 새 방어의 등록 방법, 격리 정책, smoke test와 수동 게이트웨이 실행은 [`docs/defense-integration.md`](docs/defense-integration.md)에 있습니다. Honeyval은 외부 HTTP 어댑터가 준비된 경우에만 선택되며 다른 조건의 실행과 검증에는 필요하지 않습니다.

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

## 벤치마킹

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

Windows PowerShell에서는 `app\.venv\Scripts\python.exe`를 사용합니다. AI 공격 단일 시험, 최소 5회 무방어 자격 확인, 조건 순서를 섞은 반복 비교, 산출물과 합격 기준은 [`docs/benchmarking.md`](docs/benchmarking.md)에 한 절차로 정리했습니다. 세부 운영 원칙과 과거 기준선 기록은 [`docs/operations/README.md`](docs/operations/README.md)에서 확인할 수 있습니다.

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

기능 점검 기록은 [`docs/completion-gate-20260908.md`](docs/completion-gate-20260908.md)에 있습니다. 최종 쌍 비교에서는 세 조건 모두 정상 업무 5개를 통과했고 기반 시설 오류는 없었습니다. 해당 한 번의 반복에서는 무방어와 단순 프록시 조건의 공격이 성공했고 Honeyval 조건은 요청 예산 안에서 성공하지 못했습니다. 바로 앞 검증에서는 같은 Honeyval 조건에서 공격이 한 번 성공했습니다. Honeyval 완성, 반복 실험과 다중 표적 통계 평가는 남은 작업입니다.
