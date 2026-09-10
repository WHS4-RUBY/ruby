# 코드 구성과 책임 안내

## 이 문서의 범위

이 문서는 `a3b7d67` 시점의 `web-defense-benchmark`를 코드 검토자가 따라갈 수 있도록 설명한다. 파일 이름만 보고 목적을 추측하지 않고 Compose 구성, Python과 TypeScript 진입점, 테스트와 설정의 참조 관계를 확인해 작성했다.

다음 내용은 이 문서의 범위에 포함되지 않는다.

- `feature/benchmark-management-ui`에서 나중에 추가한 관리 화면
- RUBY 팀의 실제 방어 모듈 구현
- 저장소 밖에서 관리하는 모델 자격 증명과 서버 설정

과거 작성자의 의도처럼 코드에서 직접 확인할 수 없는 내용은 [브랜치 변경 이력 해설](branch-change-ledger.md)에서 `회고 해설`로 표시한다.

## 이 코드의 정체

이 디렉터리는 웹 애플리케이션 하나가 아니라 다음 네 묶음을 함께 보관하는 보안 벤치마크 패키지다.

1. 정상 쇼핑몰과 선택형 취약점 29개
2. 원본 제품 CVE 5개를 재현하는 별도 컨테이너
3. 공격, 방어 연결, 반복 실행과 비공개 성공 판정 도구
4. 실험 계약, 테스트, 결과를 검증하는 최소 공개 증거

따라서 `app/tools`, `contracts`, `tests`, `evidence`는 웹 화면을 서비스하는 코드가 아니다. 결과의 재현성과 평가 조건을 보존하기 위한 코드와 기록이다.

### 코드 규모를 읽는 기준

`a3b7d67`의 Git 추적 파일을 줄바꿈 기준으로 센 값은 다음과 같다. 테스트, lockfile과 설정을 어느 그룹에 포함하는지에 따라 전체 줄 수는 달라지므로 파일 수와 집계 범위를 함께 적었다.

| 범위 | 파일 수 | 줄 수 | 해석 |
| --- | ---: | ---: | --- |
| `app/backend/ruby_web` | 12 | 5,213 | 백엔드 애플리케이션 본체 |
| `app/frontend/src` | 8 | 2,260 | 프런트엔드 애플리케이션 본체 |
| 위 두 웹 본체 합계 | 20 | 7,473 | 실제 웹 기능의 중심 코드 |
| `app/tools` | 69 | 26,298 | 실행, 공격, pair 검사, 분석과 증거 생성 도구 |
| `app/configs` | 60 | 5,385 | 표적, 공격자, 방어와 분석 계획 |
| 최상위 `tests` | 17 | 6,616 | 계약과 캠페인 회귀 검사. 각 앱 내부 테스트는 별도 |
| `contracts` | 25 | 2,594 | JSON Schema와 OpenAPI 계약 |

따라서 수만 줄이라는 수치는 웹 본체만 센 값이 아니다. 웹 본체 7,473줄에 실험 통제, 검증과 재현 자산을 더한 값이다.

## 가장 먼저 볼 파일

| 확인 목적 | 시작 파일 | 확인되는 내용 |
| --- | --- | --- |
| 전체 실행 | `README.md`, `scripts/benchmark.ps1`, `scripts/benchmark.sh` | 정상 모드, 취약 모드, 상태 확인과 정리 명령 |
| 컨테이너 구성 | `app/compose.yaml` | 기본 서비스, 포트, 네트워크와 데이터 볼륨 |
| 웹 API | `app/backend/ruby_web/main.py` | 정상 업무 API와 모듈별 안전판 및 취약판 분기 |
| 취약점 선택 | `app/backend/ruby_web/config.py` | 허용된 29개 모듈, 환경변수와 시험 ID 검사 |
| 웹 화면 | `app/frontend/src/main.tsx`, `app/frontend/src/pages/` | 로그인과 고객, 판매자, 상담, 운영 화면 |
| 비공개 판정 | `app/evaluator/ruby_evaluator/main.py`, `core.py` | 내부 사건 조회, 판정식 컴파일과 성공 여부 계산 |
| 실행 원장 | `app/runner/ruby_runner/ledger.py` | 상태 전이, 산출물 해시, 덮어쓰기 방지 |
| 방어 연결 | `app/tools/inline_defense_gateway_v2.py`, `app/tools/defense_runtime_v1.py` | 프록시 및 방어 조건의 요청 경로와 등록된 방어의 수명주기 |
| 전체 범위 | `app/configs/stage3-vulnerability-module-catalog-v1.json`, `app/configs/stage3a-autonomous-target-registry-v2.json` | 합성 취약점과 자율 공격 대상 등록부 |
| 검증 연결 | `docs/contract-traceability.md` | 요구사항, JSON 계약, 구현과 테스트 연결 |

## 기본 실행 구조

`app/compose.yaml`의 기본 스택은 다음 경로로 동작한다.

```text
브라우저 또는 HTTP 클라이언트
              |
              v
web: Nginx와 React 정적 파일, 127.0.0.1:18080
              |
              | edge 네트워크의 api:8000으로 /api 전달
              v
api: FastAPI 업무 API
       |             |              |
       v             v              v
   PostgreSQL      Redis       object-store
       ^             |              ^
       |             v              |
       |          worker -----------+
       |
evaluator: 비공개 판정 API, 호스트 포트 없음

호스트의 127.0.0.1:18081 --------> 같은 api:8000 직접 매핑
```

`mock-integration`은 SSRF, 내부 메타데이터와 서비스 자격 증명 같은 외부 연동 시나리오를 인터넷 대신 로컬에서 재현한다.

### Compose 서비스 책임

| 서비스 | 구현 위치 | 책임 |
| --- | --- | --- |
| `web` | `app/frontend/` | React 빌드 결과 제공, `/api/`를 `api`로 전달 |
| `api` | `app/backend/` | 계정, 상품, 주문, 상담, 판매자와 운영 API 제공 |
| `worker` | `app/backend/ruby_web/worker.py` | Redis 작업을 받아 첨부 객체 상태 처리 |
| `postgres` | `app/postgres/` | 업무 계정, 제한 계정과 판정 계정을 분리한 저장소 |
| `redis` | `app/redis/` | 세션과 worker 대기열 |
| `object-store` | `app/object-store/` | 첨부 파일용 S3 호환 저장소 |
| `mock-integration` | `app/mock-integration/` | 통제된 내부 연동 대상 |
| `evaluator` | `app/evaluator/` | 공격자에게 보이지 않는 내부 사건으로 목표 달성 판정 |

`app/runner`와 `app/attacker`는 기본 Compose 서비스가 아니다. `app/runner`의 `TrialLedger`는 Stage 2 실행기와 자체 테스트에서 사용한다. 현재 v3 캠페인은 별도 schedule, checkpoint, result와 seal 파일을 만든다. `app/attacker`에는 컨테이너형 공격자와 제한 프록시가 남아 있지만 현재 v3 웹 캠페인의 모델 호출은 호스트 AI CLI와 `ActionExecutor` 경로를 사용한다. Jenkins, GeoServer, Roundcube와 Langflow도 기본 스택과 분리된 `app/cve-*` Compose 파일로 실행한다.

### 네트워크와 공개 범위

- `web`은 `edge`와 내부 `attacker` 네트워크에 연결된다.
- `api`는 `edge`와 내부 `data` 네트워크에 연결된다.
- 공격자용 네트워크는 `web`에만 연결되므로 기본 구성에서 데이터베이스와 평가기에 직접 연결되지 않는다.
- `evaluator`는 내부 `control` 네트워크에만 연결되고 호스트 포트를 열지 않는다.
- PostgreSQL은 업무용 `data` 네트워크와 판정용 `control` 네트워크에 함께 연결되며 서로 다른 데이터베이스 역할을 사용한다.
- 호스트에 공개되는 두 포트는 Compose 기본값으로 모두 `127.0.0.1`에만 바인딩된다. 취약 모드에서는 외부 주소로 공개하면 안 된다.

## 웹 애플리케이션 코드

### 백엔드

| 파일 | 책임 |
| --- | --- |
| `app/backend/ruby_web/main.py` | FastAPI 생성, 인증 의존성, 업무 라우트, 모듈별 취약 동작과 내부 초기화 API |
| `app/backend/ruby_web/config.py` | 환경변수 파싱, 모듈 허용목록, 시험 ID 형식과 실행 조건 검사 |
| `app/backend/ruby_web/database.py` | SQLAlchemy 모델과 데이터베이스 세션 |
| `app/backend/ruby_web/schemas.py` | API 요청 및 응답 Pydantic 모델 |
| `app/backend/ruby_web/security.py` | 비밀번호 해시와 실험용 서명 없는 세션 토큰 처리 |
| `app/backend/ruby_web/services.py` | Redis 세션, Redis 대기열, 객체 저장소 인터페이스와 메모리 대체 구현 |
| `app/backend/ruby_web/seed.py` | 합성 사용자, 상품과 업무 상태 초기화 |
| `app/backend/ruby_web/events.py` | 비공개 평가기가 읽는 내부 사건 기록 |
| `app/backend/ruby_web/state.py` | 초기화 결과를 비교할 수 있는 상태 요약 |
| `app/backend/ruby_web/worker.py` | 첨부 파일 비동기 처리 |
| `app/backend/ruby_web/derived_vulnerabilities.py` | 판매자 템플릿과 상담 HTML 파생 시나리오의 안전판 및 취약판 처리 |

`main.py`는 3,575줄이며 HTTP route decorator가 72개다. 백엔드가 큰 가장 직접적인 이유는 계정, 장터, 주문, 상담, 판매자와 운영 API 및 취약 분기를 이 조립 파일 한곳에서 정의하기 때문이다.

`Settings.from_environment()`는 `RUBY_WEB_VULNERABILITY_MODULES`를 허용목록과 비교한다. 등록되지 않은 모듈은 시작 단계에서 거부한다. 모듈을 하나라도 켜면 32자리 소문자 16진수 `RUBY_WEB_TRIAL_ID`가 필요하다. 모듈을 지정하지 않은 상태가 정상 안전판이다.

`main.py`는 별도 취약 웹 사본을 두지 않는다. 같은 업무 라우트에서 현재 모듈 집합을 검사해 안전한 처리와 의도적으로 취약한 처리를 선택한다. 예를 들어 상품 검색은 `sql-injection.product-search`, 보고서 다운로드는 `path-traversal.report-download`, 사용자 목록은 `function-authorization.user-directory`의 활성 여부를 각각 확인한다.

### 프런트엔드

| 파일 | 책임 |
| --- | --- |
| `app/frontend/src/main.tsx` | 해시 기반 화면 전환, 로그인 상태와 전역 알림 |
| `app/frontend/src/api.ts` | 세션 토큰 저장, 공통 HTTP 요청과 오류 처리 |
| `app/frontend/src/pages/Storefront.tsx` | 상품 검색, 상세 확인과 주문 |
| `app/frontend/src/pages/Account.tsx` | 가입, 프로필, 결제, 취소와 주문 내역 |
| `app/frontend/src/pages/Support.tsx` | 고객 문의와 상담 업무 |
| `app/frontend/src/pages/Seller.tsx` | 상품, 주문, 문서와 판매자 업무 |
| `app/frontend/src/pages/Operations.tsx` | 사용자와 운영 상태 관리 |
| `app/frontend/nginx.conf` | 정적 파일 제공과 API 역방향 프록시 |

프런트엔드는 취약점 모듈 이름과 평가기 결과를 표시하지 않는다. 모듈 선택과 성공 판정이 공격자 화면에 노출되는 것을 피하기 위한 구조다.

## 성공 판정과 실행 기록

웹 응답만으로 공격 성공을 판정하지 않는다.

1. 백엔드가 보호 자원 접근이나 권한 변경 같은 내부 사건을 `audit_journal`에 기록한다.
2. 실험 도구가 공격자에게 제공하지 않은 verifier와 판정식 ID를 evaluator에 전달한다.
3. `ruby_evaluator.main`이 판정 전용 데이터베이스 역할로 시험 ID의 사건을 읽는다.
4. `ruby_evaluator.core`가 사건 종류, 주체, 객체, 보호 자원, 발생 시각과 중복 조건을 검사한다.
5. evaluator는 일치한 사건 ID와 원장 digest를 반환한다.

`ruby_runner.ledger.TrialLedger`는 시험 상태를 `preparing`, `running`, 종료 상태 순으로만 전이시킨다. JSON 산출물을 기존 파일 위에 덮어쓰지 않으며, 원장 레코드를 이전 digest와 연결하고 마지막에 파일 매니페스트를 만든다.

이 원장은 Stage 2 실행 경로의 구현이다. `run_autonomous_campaign_v3.py`가 실행하는 현재 캠페인은 schedule, run seal, 각 trial 결과와 campaign summary를 만든다. trial 진행 중에는 복구용 checkpoint를 쓰고 성공하면 삭제한다. 분석 계획, seal, schedule과 summary를 digest로 다시 묶는 작업은 후처리 도구 `make_campaign_smoke_evidence.py`와 분석기가 담당한다.

## 방어 연결 코드

이 디렉터리는 RUBY의 실제 방어 구현을 포함하지 않는다. 여기 있는 `static-guard`는 연결 계약과 평가 경로가 작동하는지 확인하는 기준 구현이다.

| 위치 | 역할 |
| --- | --- |
| `contracts/defense-capability.schema.json` | 방어 종류와 기능 선언 형식 |
| `contracts/attachment-lifecycle.schema.json` | 준비, 초기화, 종료와 실패 처리 계약 |
| `contracts/defense-adapter.openapi.yaml` | `inline-http` 방어의 HTTP 요청 및 응답 형식 |
| `app/configs/stage3a-defense-runtime-registry-v2.json` | 실행 가능한 방어 등록부 |
| `app/tools/manage_defense.py` | 등록부 검사, 목록, 실행과 smoke test 명령 |
| `app/tools/defense_runtime_v1.py` | 관리형 컨테이너와 외부 어댑터의 수명주기 |
| `app/tools/inline_defense_gateway_v2.py` | `proxy-only`와 등록 방어 조건이 사용하는 요청 전달 및 계측 경로 |
| `app/defense-control-relay/` | 호스트 평가 도구의 loopback 호출을 내부 `defense-adapter:8081`로 전달하는 중계기 |
| `app/defenses/static-guard/` | SQL 주입 차단과 연결 검사를 위한 최소 기준 방어 |

웹 백엔드는 방어 코드를 import하지 않는다. 등록부와 HTTP 계약으로 연결하므로 방어 코드를 이 디렉터리에 복사할 필요가 없다.

## `app/tools`를 읽는 방법

`app/tools`에는 실행 단계와 표적별 도구 69개가 있다. 다음은 파일 이름과 호출 관계에서 확인한 책임별 분류다.

| 이름 | 책임 | 대표 파일 |
| --- | --- | --- |
| 표적 pair 검사 | 같은 표적의 안전판과 취약판을 실행하고 기대 차이 확인 | `check_static_guard_sql_pair.py`, `check_stage3a_roundcube_cve_pair.py` |
| 통합 gate 및 준비 검사 | 격리, 계약, 전체 대상과 릴리스 조건을 묶어 검사 | `check_runtime_isolation_gate.py`, `check_release_readiness.py` |
| 단일 trial 실행 | 한 시험의 준비, 실행, 판정과 정리 | `run_stage2_isolated_trial.py`, `autonomous_trial_v2.py` |
| 반복 campaign 실행 | 여러 조건과 반복 순서를 고정해 캠페인 실행 | `run_autonomous_campaign_v3.py` |
| 표적 adapter | 합성 웹과 원본 CVE의 표적별 실행 차이를 공통 인터페이스로 변환 | `autonomous_target_adapters_v2.py`, `autonomous_cve_target_adapters_v3.py` |
| 결과 분석 및 요약 | 완료된 원장과 결과에서 통계 및 상태 요약 생성 | `analyze_confirmatory_campaign.py`, `summarize_condition_campaign.py` |
| 소스 및 계획 고정 | 실행 전 소스와 계획을 고정하고 사후 변경 탐지 | `snapshot_defense_source.py`, `make_holdout_commitment.py` |
| 공격자 버전 평가 | 동결된 공격자 버전 생성, 재생과 자격 평가 | `attacker_strategy_v11.py`, `run_attacker_v11_qualification.py` |
| 비공개 정보 차단 | 비공개 정답과 자격 증명이 공격자 산출물에 섞이는 것을 검사 및 제거 | `oracle_shield.py`, `sanitize_autonomous_artifacts.py` |

파일 이름의 `v1`, `v2`, `v3`은 모두 최신 구현이라는 뜻이 아니다. 해당 버전으로 만든 설정과 증거가 다시 검증되도록 이름을 고정한 경우가 있다. 구버전처럼 보인다는 이유만으로 파일을 삭제하면 과거 실행의 참조가 끊길 수 있다.

## 현재 AI 캠페인 경로

현재 반복 실행의 중심 진입점은 `app/tools/run_autonomous_campaign_v3.py`다.

```text
등록부와 사전 고정 계획
        |
        v
run_autonomous_campaign_v3.py
        |
        +-- 대상 준비: 합성 웹 또는 원본 CVE adapter
        +-- 모델 호출: autonomous_cli_policy_v2.py
        +-- 행동 집행: autonomous_experiment_v2.ActionExecutor
        +-- 시험 반복: autonomous_trial_v2.py
        +-- 비공개 판정: evaluator
        +-- 결과 저장: schedule, trial JSON, 복구 checkpoint, seal, summary
```

- `SubscriptionCLIPolicy`는 Codex 또는 Claude CLI에 지금까지의 관찰을 주고 구조화된 행동 JSON을 받는다. 공개 brief가 설정된 조건에서는 brief도 함께 전달한다.
- AI CLI가 직접 셸과 브라우저를 조작하지 않는다. `ActionExecutor`가 대상 상대경로, HTTP와 브라우저 행동의 허용 범위를 검사한 뒤 실행한다.
- `autonomous_target_adapters_v2.py`는 합성 웹을, `autonomous_cve_target_adapters_v3.py`는 원본 CVE의 제품별 준비와 판정을 공통 시험 인터페이스로 맞춘다.
- 공격 목표는 공개 HTTP 응답이 아니라 비공개 evaluator가 확인한다. 목표가 달성되거나 예산이 끝나면 trial을 종료한다.
- `victim_browser.py`는 판매자 문서 미리보기와 상담 HTML 후처리 시나리오의 배경 피해자 브라우저를 담당한다. CSRF와 원본 Roundcube의 브라우저 동작은 각각 `ActionExecutor`와 원본 CVE action executor의 별도 경로를 사용한다.

`a3b7d67`의 `autonomous_cli_policy_v2._environment()`는 부모 프로세스 환경을 복사한 뒤 알려진 API 키 이름을 제거하는 방식이다. 이름을 예상하지 못한 토큰과 비밀까지 차단하는 허용목록 방식은 아니다. 해당 커밋을 그대로 실행할 서버는 AI CLI 자식 프로세스에 전달되는 환경을 별도로 제한해야 한다.

## 설정, 계약, 증거의 관계

| 디렉터리 | 질문 | 내용 |
| --- | --- | --- |
| `app/configs/` | 이번 실행에서 무엇을 사용할 것인가 | 표적, 공격자 프로필, 취약점 목록, 방어 등록부와 분석 계획의 실제 값 |
| `contracts/` | 설정과 결과가 어떤 형식이어야 하는가 | JSON Schema와 OpenAPI 계약 |
| `tests/` | 잘못된 설정과 결과를 거부하는가 | 계약, 격리, 캠페인, 통계와 릴리스 조건 회귀 검사 |
| `evidence/` | 어떤 검사가 실제로 끝났다고 기록했는가 | 공개 가능한 요약, 일정, seal, digest와 검사 결과 |
| `docs/` | 결과를 어디까지 주장할 수 있는가 | 설계, 절차, 범위, 한계와 재현 안내 |

설정 JSON 하나만 보고 결과를 해석하면 안 된다. 같은 실행의 schema, 실행 전 계획, 결과 seal과 분석 파일을 함께 확인해야 한다.

## 테스트 책임

`a3b7d67`에는 이름이 `test`로 시작하는 Python 파일 25개와 그 안에 정적으로 확인되는 `test_` 함수 282개가 있다. 이 수는 pytest parameter 조합을 펼친 실제 수집 case 수가 아니다. 주요 묶음은 다음과 같다.

| 테스트 위치 | 검증 대상 |
| --- | --- |
| `app/backend/tests/test_normal_flows.py` | 정상 업무 흐름, 역할 경계와 안전판 및 취약판 쌍 |
| `app/backend/tests/test_scope_expansion_pairs.py` | 추가 합성 취약점 6개의 쌍 |
| `app/evaluator/tests/test_evaluator_core.py` | 거짓 공개 응답 배제, 내부 사건과 판정식 |
| `app/runner/tests/test_trial_ledger.py` | 상태 전이, 해시 연결, 덮어쓰기와 경로 제한 |
| `tests/test_contracts.py` | 등록된 시나리오, 배포와 결과 계약 |
| `tests/test_runtime_isolation_gate.py` | 원본 CVE와 관리형 방어의 Docker 격리 규칙 |
| `tests/test_release_readiness.py` | 전체 모듈의 pair checker와 릴리스 결과 형식 |
| `tests/test_autonomous_cli_policy_v2.py` | AI CLI 환경, 경로, 예산과 실행 정책 |
| `tests/test_confirmatory_analysis.py` | 반복 수, 대응표본, 신뢰구간과 효과 주장 조건 |
| `tests/test_holdout_and_review.py` | 보류 표본 고정과 독립 검토 입력 무결성 |

단위 테스트 통과와 Docker 기반 전체 pair 검사 통과는 서로 다른 주장이다. 실제 제품 컨테이너와 브라우저가 필요한 검사는 `run_all_pair_checks.py`, `check_runtime_isolation_gate.py` 같은 별도 게이트가 담당한다.

## 서버 실행에 필요한 것과 저장소에 보존할 것

| 구분 | 대상 | 처리 원칙 |
| --- | --- | --- |
| 정상 업무 실행 | `app/frontend`, `app/backend`의 `api`와 `worker`, `app/postgres`, `app/redis`, `app/object-store`, `app/mock-integration`, `app/compose.yaml` | 쇼핑몰과 첨부 처리에 필요 |
| 벤치마크 성공 판정 | `app/evaluator` | 공격 성공을 비공개 내부 사건으로 채점할 때 필요. 일반 쇼핑몰 화면 제공만으로는 불필요 |
| 선택 실행 | `app/cve-*`, 선택한 방어 어댑터 | 해당 실험에서만 포함 |
| 개발 및 검증 | `tests`, `app/*/tests`, `app/tools`, `contracts`, `requirements-dev.txt` | 실행 서버 이미지에서는 제외할 수 있으나 저장소에는 보존 |
| 연구 기록 | `docs`, `evidence`, 과거 공격자 프로필과 계획, 현재 주 경로에서 사용하지 않는 컨테이너형 공격자 자산 | 운영 서버에는 배포하지 않고 저장소에는 재현 근거로 보존 |
| 로컬 생성물 | `.venv`, `node_modules`, `.pytest_cache`, `app/evaluation`, 로그 | Git에 추가하지 않음 |

## 현재 구조에서 실제로 어려운 점

- `app/backend/ruby_web/main.py`에 대부분의 API와 취약 분기가 모여 있어 한 파일의 검토 범위가 크다.
- `app/tools`는 실행 단계별로 분리돼 있지만 최상위 디렉터리에 69개 파일이 평평하게 놓여 있다.
- 최초 대량 추가 커밋의 본문이 없어 코드가 만들어진 순서와 판단 이유를 Git 기록만으로 복원할 수 없다.
- 버전이 붙은 도구와 설정은 과거 증거가 참조하므로, 중복 제거 전에 참조 관계와 재현 테스트를 먼저 확인해야 한다.
- `app/README.md`와 일부 단계별 문서는 작성 당시 수치를 담고 있어 현재 등록부와 함께 확인하지 않으면 최신 구성으로 오해할 수 있다.
- `defense_runtime_v1.defense_front()`의 `undefended` 경로는 gateway를 만들지 않고, `proxy-only`부터 gateway를 사용한다. 게이트웨이 오버헤드와 방어 어댑터의 영향을 서로 다른 비교로 해석해야 한다.

이 문제는 현재 파일을 대량 삭제해서 해결하지 않는다. 후속 변경에서는 런타임, 실험 실행기와 과거 재현 자산을 디렉터리 수준에서 구분하고, 한 목적씩 커밋하면서 본문에 변경 이유와 검증 결과를 남긴다.
