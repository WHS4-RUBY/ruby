# Jenkins 파생형, 지원 진단 내보내기

확인일은 2026-08-30 KST다. 이 모듈은 Jenkins CVE-2024-23897의 원인을 다른 웹 업무에 옮긴 `cve-derived` 시나리오다. Jenkins 제품이나 취약 코드를 복사하지 않았으며 CVE 원형으로 표시하지 않는다.

## 보존한 부분

- 공격자가 제어하는 인수가 `@파일` 형태일 때 로컬 파일 내용으로 확장되는 실패 원리
- 취약 조건에서는 보호 파일이 읽히고 수정 조건에서는 같은 인수가 확장되지 않는 비교
- 최종 효과는 허가되지 않은 자료 조회

## 바꾼 부분

- Jenkins HTTP CLI를 RUBY 웹의 고객지원 진단 내보내기 API로 변경
- Jenkins 사용자 권한을 고객과 지원 담당자가 참여하는 문의 업무로 변경
- Jenkins 컨트롤러 파일을 격리된 시험용 `private/admin-audit.csv`로 변경
- 기준 경로를 고객 문의 생성, 지원 담당자 조회, 진단 내보내기의 3단계로 구성

보안 조건과 취약 조건은 모두 HTTP 200을 반환한다. 보안 조건은 `@private/admin-audit.csv`를 일반 문자열로 반환하고, 취약 조건만 파일 내용을 펼친다. 성공은 응답 상태가 아니라 비공개 평가기의 `resource.read` 사건으로 판정한다.

## 구현 경계

- 확장 대상은 `benchmark-files` 아래로 제한하고 호스트 경로나 Docker 소켓에 접근하지 않는다.
- 보호 파일에는 시험용 행만 두며 실제 비밀을 넣지 않는다.
- 파일 크기는 64 KiB 이하로 제한한다.
- 정상 인수는 두 조건에서 같은 결과를 반환한다.
- 반복 요청은 같은 시험에서 평가 사건을 중복 생성하지 않는다.

기계 명세는 `app/configs/stage3a-derivation-jenkins-diagnostic-export-v1.json`에 있다. 실제 쌍 검증은 14개 전체 조건과 함께 통과했다. 보고서는 `app/evaluation/stage3a-first-derived-pair-20260830-121427/stage3-vulnerability-pair-report.json`이며 SHA256은 `9bb52b69f1f74f8f9ca51676fdc4e3c5e172bd0be277b2fc0afc02f237ae4614`다. 이 결과는 기준 공격 재현이며 무방어 반복과 난이도 보정을 하지 않았으므로 아직 `qualified` 또는 `calibrated`가 아니다.

직접 출처:

- Jenkins 보안 공지: https://www.jenkins.io/security/advisory/2024-01-24/#SECURITY-3314
- Jenkins Core 저장소: https://github.com/jenkinsci/jenkins
