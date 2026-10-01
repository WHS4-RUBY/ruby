# 팀 서버 연결 관찰 (2026-10-01)

PR #19의 이전 [로컬 연결 검사](team-pipeline-runtime-verification-20260923.md)는
당시 Detection 운영 API의 익명 접근 때문에 `pr_ready=false`로 끝났다. 그 실행
기록과 판정은 변경하지 않는다. 이후 팀 `main`의 #22와 #25에서 대시보드 인증과
운영 배포 설정이 추가되었다.

2026-10-01에 팀 서버의 공개 진입점을 읽기 전용으로 확인했다. 실제 주소와
대시보드 비밀번호는 이 문서에 기록하지 않는다.

| 확인 항목 | 관찰 결과 |
| --- | --- |
| Detection 공개 진입점의 `/` | HTTP 200, Juice Shop 화면 |
| 별도 호스트 포트의 RUBY Market `/` | HTTP 200, RUBY Market 화면 |
| 인증 쿠키 없는 `/__detection/api/sessions` | HTTP 401 |
| 인증 쿠키 없는 `/__defense/api/snapshot` | HTTP 401 |

두 운영 API의 익명 조회는 현재 서버에서 거부되었다. 이 확인은 비밀번호 로그인,
관리 API 전체 경로, TLS 설정이나 외부망의 모든 접근 경로를 검증한 결과가 아니다.
별도 포트의 RUBY Market은 응답하지만, Detection 공개 진입점은 여전히 Juice Shop을
보여 준다. 따라서 `Detection -> Defense -> RUBY Market` 운영 연결과 해당 환경의
비공개 평가기 격리는 이 관찰만으로 입증되지 않는다.

PR 브랜치의 `scripts/check_team_pipeline_runtime.py`는 현재 `main`의 운영 인증
설정으로 격리 스택을 시작하고, 익명 관리 API 거부, 로그인 후 접근, 정상 요청과
지연 실행을 검사하도록 갱신했다. 이 스크립트를 실제로 다시 실행하고 대상 전환 후
서버 공개 진입점에서 RUBY Market 응답을 확인해야 연결 준비 판정을 갱신할 수 있다.
