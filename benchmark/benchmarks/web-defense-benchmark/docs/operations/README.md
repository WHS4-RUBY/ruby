# RUBY 웹 벤치마크 운영 문서

확인일: 2026-09-08

이 디렉터리는 취약 웹을 다른 팀원이 실행하고, 공격자와 방어 장치를 같은 조건으로 비교하는 데 필요한 문서를 모아 둔다.

현재 실행 명령, 산출물과 합격 기준은 [`../benchmarking.md`](../benchmarking.md)를 먼저 본다. 아래 문서의 2026년 9월 2일 24개 기준선은 당시 공격자 v11 실행 기록이며 현재 34개 등록 표적 전체의 확정 기준선이 아니다.

## 읽는 순서

1. [`01-unprotected-baseline.md`](01-unprotected-baseline.md)
   - 2026년 9월 2일의 과거 무방어 공격 결과
   - 24개 대상별 성공, 실패, 요청 수, 모델 호출 수와 시간
   - 결과를 해석할 때의 제한
2. [`02-generic-attacker-package.md`](02-generic-attacker-package.md)
   - 공격자 구성 파일과 역할
   - v11의 작동 방식, 확인된 회귀와 사용 제한
   - 새 공격자 개발 시 지켜야 할 경계
3. [`03-experiment-runbook.md`](03-experiment-runbook.md)
   - 실행 전 확인, 새 실행, 관찰, 중단, 재개와 결과 보존 절차
   - 무방어와 방어 비교 시 고정할 조건
4. [`04-defense-integration-contract.md`](04-defense-integration-contract.md)
   - 방어 장치 연결 유형
   - inline HTTP 어댑터 입력과 출력
   - 상태형 기만의 세션 격리와 실패 처리
5. [`../attacker-v12-local-gate-20260902.md`](../attacker-v12-local-gate-20260902.md)
   - v12 범용 구조 변경
   - 외부 실행 전 로컬 검사 결과

웹서비스와 취약점 자체는 [`../web-application-and-vulnerability-catalog-20260907.md`](../web-application-and-vulnerability-catalog-20260907.md)를 먼저 본다.

팀 서버의 Juice Shop/RUBY Market 전환은 [서버 대상 전환](04-server-target-selection.md),
다른 사용자의 웹사이트 연결은 [자신의 웹사이트 연결](05-connect-your-site.md)에 정리했다.

## 현재 판정

| 항목 | 상태 |
|---|---|
| 웹과 취약점 설명 | RUBY 웹 29개와 원본 CVE 5개 등록 |
| 과거 무방어 전체 24개 단일 반복 | Claude Opus 5, medium, v11 결과 존재 |
| 현재 34개 무방어 확정 기준선 | 미완료. 공격자별 5회 이상 자격 확인 필요 |
| 공격자 접근 조건 | 개발용 계정 제공, 익명, 피해자 동작 허용 프로필 분리 |
| 실행기와 격리 | 34개 등록 표적, 자원 기반 병렬 제한, 중단 후 재개 지원 |
| 방어 연결 | 무방어, 단순 프록시, 관리형 기준 방어와 외부 HTTP 어댑터 지원 |
| 방어 기능 확인 | SQL 주입 무방어 성공, 기준 방어 차단, 방어 뒤 정상 업무 6개 성공 |
| 통계 평가 절차 | 분석 계획, 33개 대응쌍 산정, 집계와 주장 게이트 구현 완료 |
| 통계적 방어 효과 비교 | 과업 지정 SQL 한 층의 5회와 99회 실행 기록 보존. 실제 모델 ID가 관측되지 않았고 구현 비참여자 검토도 남아 있어 효과 판정 보류 |

## 문서 갱신 원칙

- 실행 결과는 해당 실행의 `run-seal.json`, `campaign-summary.json`과 `trials/*.json`에서만 가져온다.
- 서로 다른 모델, 공격자 버전, 시드와 예산의 결과를 같은 반복처럼 합치지 않는다.
- 성공률을 수정할 때 성공 건수와 전체 유효 건수를 함께 쓴다.
- `budget-exhausted`를 일반 실패와 분리한다.
- 구조 검사와 취약점 쌍 검증을 자율 공격 성능으로 표현하지 않는다.
- 방어 장치를 연결하면 무방어 조건의 이미지, 데이터, 공격자와 예산 해시가 같은지 먼저 확인한다.
