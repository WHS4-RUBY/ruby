# 2026-09-08 완료 증거

이 디렉터리에는 검토에 필요한 최소 결과만 둡니다.

- `static-guard-sql-pair.json`: SQL 주입 무방어 성공, 별도 정적 방어 차단, 방어 뒤 직렬 및 동시 정상 업무 결과
- `runtime-isolation-gate.json`: 원본 CVE 10개 버전 조건, 관리형 방어와 Compose 계약 격리 검사
- `scope-expansion-pairs.json`: 추가 합성 모듈의 실제 Docker 쌍 검사
- `roundcube-cve-2026-54433-pair.json`: Roundcube 2026 취약판과 수정판 원본 쌍 검사
- `release-readiness.json`: 합성 29개, 원본 CVE 5개, 격리, 방어 장착, 문서와 전체 회귀의 최초 로컬 릴리스 판정. 최신 재검증은 [`../20260909/release-readiness.json`](../20260909/release-readiness.json)이다.
- `evaluation-protocol-readiness.json`: 사전 분석 계획, 33개 대응쌍 표본 수, 정상 트래픽과 효과 주장 차단 판정
- `current-ai-smoke-codex.json`: 실제 Codex 공격자 단일 실행의 봉인, 격리, 금지 도구, 정상 흐름과 공격 결과 요약
- `qualification-sqli-codex-v12.json`: 작은 예산으로 실행한 Codex v12 SQL 주입 무방어 예비 시험 5회의 최소 요약
- `qualification-sqli-codex-v10.json`: 작은 예산으로 실행한 Codex v10 SQL 주입 무방어 예비 시험 5회의 최소 요약

원시 모델 대화, 브라우저 프로필, 인증 디렉터리와 전체 로그는 포함하지 않습니다. 기준 방어 결과는 한 표적의 기능 증거이며 통계적 효과 추정치가 아닙니다.
