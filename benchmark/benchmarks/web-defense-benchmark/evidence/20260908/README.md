# 2026-09-08 완료 증거

이 디렉터리에는 검토에 필요한 최소 결과만 둡니다.

- `completion-gates.json`: 완료 게이트 7개의 기계 판정
- `paired-comparison.json`, `paired-comparison.md`: 무방어, 단순 프록시, Honeyval 쌍 비교
- `campaign-summary.json`: 세 시험 캠페인 종료 요약
- `static-guard-sql-pair.json`: SQL 주입 무방어 및 별도 정적 방어 결과
- `generic-defense-attachment.json`: 설정 기반 공통 방어 게이트웨이, 교체, 오류 처리와 정리 검사
- `runtime-isolation-gate.json`: 원본 CVE 10개 버전 조건, 관리형 방어와 Compose 계약 격리 검사
- `scope-expansion-pairs.json`: 추가 합성 모듈의 실제 Docker 쌍 검사
- `roundcube-cve-2026-54433-pair.json`: Roundcube 2026 취약판과 수정판 원본 쌍 검사
- `release-readiness.json`: 합성 29개, 원본 CVE 5개, 격리, 방어 장착, 문서와 전체 회귀의 최종 로컬 릴리스 판정

원시 모델 대화, 브라우저 프로필, 인증 디렉터리와 전체 로그는 포함하지 않습니다. 이 결과는 한 표적의 한 반복에 대한 기능 증거이며 통계적 효과 추정치가 아닙니다.

쌍 비교는 Honeyval `1.21.0`으로 실행했습니다. 업로드 준비 중 발견한 종료 원장 경합은 `1.21.1`에서 수정했으며 공격 및 방어 판정 로직에는 변화가 없습니다.
