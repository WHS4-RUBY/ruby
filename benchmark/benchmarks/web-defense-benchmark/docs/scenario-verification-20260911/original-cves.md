# 원본 CVE 5개

| CVE | 제품과 버전 | 취약판에서 확인한 것 | 수정판에서 확인한 것 | 판정과 근거 |
| --- | --- | --- | --- | --- |
| CVE-2024-23897 | Jenkins 2.426.2, 2.426.3 | CLI 파일 읽기로 목표 파일 내용 노출 | 같은 목표가 노출되지 않음 | 공격 재현 통과, [보고서](../../evidence/20260911/pair-checks-complete-evidence/cve-2024-23897/stage3-jenkins-cve-pair-report.json) |
| CVE-2024-36401 | GeoServer 2.24.3, 2.24.4 | 식 평가 공격으로 명령 실행 표식 생성 | 표식이 생기지 않음 | 공격 재현 통과, [보고서](../../evidence/20260911/pair-checks-complete-evidence/cve-2024-36401/stage3a-geoserver-cve-pair-report.json) |
| CVE-2024-42009 | Roundcube 1.6.7, 1.6.8 | HTML 메일을 연 브라우저에서 실행 표식 확인 | 실행 표식 없음 | 공격 재현 통과, [보고서](../../evidence/20260911/pair-checks-complete-evidence/cve-2024-42009/stage3a-roundcube-cve-pair-report.json) |
| CVE-2025-3248 | Langflow 1.2.0, 1.3.0 | 인증 없는 코드 실행 요청으로 표식 생성 | HTTP 403, 표식 없음 | 공격 재현 통과, [보고서](../../evidence/20260911/pair-checks-complete-evidence/cve-2025-3248/stage3a-langflow-cve-pair-report.json) |
| CVE-2026-54433 | Roundcube 1.7.1, 1.7.2 | 일반 텍스트 메일을 연 브라우저에서 실행 표식 확인 | 실행 표식 없음 | 공격 재현 통과, [보고서](../../evidence/20260911/pair-checks-complete-evidence/cve-2026-54433/roundcube-2026-54433-cve-pair-report.json) |

## 주의

이 검사는 알려진 재현 절차로 제품 버전 쌍의 차이와 공격 성공 여부를 판정했다. AI가 CVE를 스스로 찾았거나 RUBY가 공격 요청을 식별하고 실행을 차단했다는 뜻은 아니다.
