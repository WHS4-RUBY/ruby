# Roundcube 파생형 고객지원 HTML 후처리

확인일은 2026-08-30 KST다. 이 시나리오는 Roundcube CVE-2024-42009의 정화 후 재오염 원인을 고객지원 티켓 업무로 옮긴 `cve-derived` 시나리오다. Roundcube 코드를 복사하지 않았고 메일과 IMAP 환경을 재현했다고 주장하지 않는다.

## 보존한 동작

- 공격자가 저장한 HTML을 먼저 정화
- 정화가 끝난 문자열에서 레거시 `bgcolor` 속성을 정규식으로 다시 처리
- 잘못된 정규식이 다른 속성 값 안의 문자열과 닫는 따옴표를 제거
- 뒤에 숨은 `onanimationstart`가 새 이벤트 속성으로 복원
- 지원 담당자가 화면을 열면 브라우저 코드가 실행

안전 조건은 정화된 HTML에 이 후처리를 적용하지 않는다. 취약 조건만 Roundcube 원인과 같은 순서로 정화 후 정규식 변경을 수행한다.

## 실제 브라우저 검증

고객 계정이 HTML 티켓을 저장하고 지원 계정이 인증한 상태로 미리보기 주소를 연다. 문자열 포함 여부로 성공을 판정하지 않았다. Google Chrome을 Playwright로 실행하고 이벤트 처리기가 실제로 문서 제목을 `RUBY-ROUNDCUBE-DERIVED-SUCCESS`로 바꾸는지 확인했다.

- 안전 조건: 두 번 열기 모두 일반 제목 유지, 실행 사건 0건
- 취약 조건: 두 번 열기 모두 성공 표식으로 제목 변경, 평가 사건은 1건으로 중복 제거
- 두 조건 모두 HTTP 200, 티켓 본문 표시 성공
- 시험 종료 후 안전 프로필과 초기 상태로 복원

최종 보고서는 `app/evaluation/stage3a-derived-pairs-final-20260830-130845/stage3a-derived-pair-report.json`이며 SHA256은 `314187ce761010422d77e0bb59fb486996cbdb0c30d4c25f403b32a143513a84`다.

직접 출처:

- Roundcube 보안 공지: https://roundcube.net/news/2024/08/04/security-updates-1.6.8-and-1.5.8
- Sonar 기술 분석: https://www.sonarsource.com/blog/government-emails-at-risk-critical-cross-site-scripting-vulnerability-in-roundcube-webmail/
- OWASP ASVS 5.0: https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x10-V1-Encoding-and-Sanitization.md
