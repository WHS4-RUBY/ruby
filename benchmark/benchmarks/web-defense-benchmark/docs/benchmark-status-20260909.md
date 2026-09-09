# 벤치마크 취약점 웹 완료 상태

확인일: 2026-09-09 KST

이 문서는 취약점 웹, 방어 모듈 장착 구조, 실제 AI 공격 평가와 GitHub 준비 상태를 구분한다. `static-guard`는 실제 방어 제품이 아니라 외부 방어 연결 계약을 검사하는 최소 기준 모듈이다. Honeyval은 이 결과와 업로드 준비 범위에 포함하지 않는다.

## 판정표

| 구분 | 상태 | 확인 근거 |
| --- | --- | --- |
| 벤치마크 디렉터리 | 완료 | 저장소 기준 경로는 `benchmark/benchmarks/web-defense-benchmark`다. |
| 취약점 웹 로컬 릴리스 | 통과 | 선택형 RUBY 취약점 29개와 원본 CVE 대상 5개의 안전판 및 취약판, 전체 회귀와 문서 검사가 통과했다. [`release-readiness-20260908.md`](release-readiness-20260908.md) |
| 현재 범위의 2026 원본 대상 | 통과 | Roundcube `CVE-2026-54433`의 1.7.1 취약판과 1.7.2 수정판을 실제 컨테이너 쌍으로 재현했다. 이 한 건이 최신 취약점 전체를 대표하지는 않는다. [`roundcube-cve-2026-54433-reproduction-20260908.md`](roundcube-cve-2026-54433-reproduction-20260908.md) |
| 공격자의 구축 환경 접근 제한 | 통과 | 원본 대상 10개 조건과 관리형 방어 조건에서 통제망, 다른 표적, Docker, 호스트 후보와 외부 주소 접근을 검사했고 성공 0건, 종료 후 잔류 자원 0건이었다. [`runtime-isolation-gate-20260908.md`](runtime-isolation-gate-20260908.md) |
| 방어 모듈 장착 구조 | 통과 | JSON 등록부와 `inline-http` 계약으로 관리형 컨테이너 또는 loopback 외부 어댑터를 장착, 상태 확인, 요청 처리, 초기화와 제거할 수 있다. 취약점 웹 소스를 방어마다 복사하거나 수정하지 않는다. [`defense-integration.md`](defense-integration.md) |
| 장착 구조 실제 검사 | 통과 | 무방어와 단순 프록시에서는 같은 SQL 목표가 재현됐고 기준 모듈에서는 차단됐다. 방어 뒤 정상 업무 6개와 HTTP 13건은 모두 성공했고 정상 요청 차단과 방어 오류는 0건이었다. [`../evidence/20260909/static-guard-v3-sql-regression.json`](../evidence/20260909/static-guard-v3-sql-regression.json) |
| 과업 지정 AI 공격자 자격 | 통과 | Codex `gpt-5.6-sol`, 추론 `medium`, 프로필 v10이 무방어 SQL 상품 검색 목표를 5회 중 5회 달성했다. [`../evidence/20260909/qualification-sqli-codex-v10-guided-v3-official.json`](../evidence/20260909/qualification-sqli-codex-v10-guided-v3-official.json) |
| 99회 기준 비교 | 통과 | 무방어 33/33, 프록시 33/33, 기준 모듈 0/33이었다. 유효 대응쌍 33개, 공격 성공률 차이 1.0, 95% 구간 0.85254에서 1.0, McNemar p값 `2.33e-10`이다. [`../evidence/20260909/confirmatory-sqli-codex-v10-guided-v3-analysis.json`](../evidence/20260909/confirmatory-sqli-codex-v10-guided-v3-analysis.json) |
| 기준 모듈 조정 이력 | 공개 | 같은 공격자가 v1과 v2를 우회했고 그 결과를 v3 수정에 사용했다. v3는 수정 뒤 봉인한 회귀 실행이며 새로운 표적의 독립 보류 시험은 아니다. [`guided-ai-defense-evaluation.md`](guided-ai-defense-evaluation.md) |
| 99회 실행 안전성 | 통과 | 전체 일정, 격리, 금지 도구 0건, 정상 흐름, 오류 상태 0건과 Docker 자원 정리 검사가 통과했다. [`../evidence/20260909/confirmatory-sqli-codex-v10-guided-v3-execution-integrity.json`](../evidence/20260909/confirmatory-sqli-codex-v10-guided-v3-execution-integrity.json) |
| 공격자 난이도 등급 | 미부여 | `guided`는 정보 조건이다. 사람 집단과 서로 다른 프론티어 공격자 두 종류 이상의 반복 보정이 없어 `easy`, `medium`, `hard` 등급을 붙이지 않는다. |
| 독립 검토 | 대기 | 필수 입력 경로와 SHA256은 준비했다. 구현에 참여하지 않은 사람이 비공개 판정 경계와 결과를 확인하고 서명해야 한다. [`../evidence/20260909/confirmatory-sqli-codex-v10-guided-v3-independent-review-inputs.json`](../evidence/20260909/confirmatory-sqli-codex-v10-guided-v3-independent-review-inputs.json) |
| GitHub | 업로드 준비, 미전송 | 브랜치는 최신 `origin/main`보다 뒤처진 커밋 0개다. 사용자 허락 전에는 push나 Pull Request를 만들지 않는다. |

## 완료 판정

취약점 웹의 로컬 릴리스와 외부 방어 모듈 장착 및 평가 구조는 완료 기준을 통과했다. 과업 지정 SQL 한 층의 기준 모듈 비교도 기술 검사를 통과했다. 실제 방어 제품의 효과와 여러 취약점 및 공격자에 대한 일반 결론은 아직 검증하지 않았다. 프로젝트 전체의 방어 효과 연구 완료 판정에는 구현 비참여자의 독립 검토가 남아 있다.
