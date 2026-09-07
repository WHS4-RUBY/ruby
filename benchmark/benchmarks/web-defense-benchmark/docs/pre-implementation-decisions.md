# 구현 전 결정 대장

계약으로 해결할 수 없는 환경과 연구 선택을 한곳에서 관리한다. 상태가 `미결정`인 항목은 관련 구현 단계에 들어가기 전에 확정한다.

| ID | 결정 항목 | 필요한 시점 | 현재 상태 | 확정 시 남길 근거 |
| --- | --- | --- | --- | --- |
| D-01 | 팀 서버 CPU, 메모리, 저장 공간과 Docker 가용성 | 컨테이너 구현 전 | 로컬만 확인 | `app/docs/stage1-implementation-status-20260829.md`, 팀 서버는 미결정 |
| D-02 | React, FastAPI, PostgreSQL, Redis와 객체 저장소 이미지 버전 | 1단계 시작 전 | 개발용 확정 | `app/docs/stage1-implementation-status-20260829.md`, 봉인 평가는 별도 고정 필요 |
| D-03 | 최초 CVE 원형 제품, 취약 버전, 수정 버전과 amd64 지원 | 3단계 시작 전 | 확정, Jenkins CVE-2024-23897, LTS 2.426.2와 2.426.3 | `stage3-cve-candidate-review-20260830.md`, `app/evaluation/stage3-jenkins-cve-pair-six-families-20260830-024118/stage3-jenkins-cve-pair-report.json` |
| D-04 | 개발 도메인, 포트와 네트워크 대역 | 통합 배포 전 | 미결정 | testbed 네트워크 결정 기록 |
| D-05 | `ruby-testbed` 이관 담당자와 PR 범위 | 저장소 이관 전 | 미결정 | 담당자와 PR 계획 |
| D-06 | 난이도 보정 사람 집단과 프론티어 공격자 두 종류 | 3A단계 전 | 미결정 | cohort manifest |
| D-07 | 첫 방어 장치의 연결 유형과 구현 충실도 | 4단계 전 | 미결정 | defense capability manifest |
| D-08 | 봉인 평가 취약점 조합과 공개 시점 | 3A단계 전 | 미결정 | portfolio 및 공개 정책 기록 |
| D-09 | 서버에서 허용할 동시 시험 수 | 부하 시험 전 | 미결정 | 자원 측정과 안전 상한 |
| D-10 | 두 번째 CVE 원형 제품, 버전, 효과와 로컬 실행 가능성 | 3A단계 | 확정, GeoServer CVE-2024-36401, 2.24.3과 2.24.4 | `stage3a-cve-original-candidate-review-20260830.md`, `app/evaluation/stage3a-geoserver-cve-pair-20260830-030752/stage3a-geoserver-cve-pair-report.json` |
| D-11 | 세 번째 CVE 원형 제품과 피해자 브라우저 실행 방식 | 3A단계 | 확정, Roundcube CVE-2024-42009, 1.6.7과 1.6.8 | `stage3a-cve-original-candidate-review-20260830.md`, `app/evaluation/stage3a-roundcube-cve-pair-20260830-032840/stage3a-roundcube-cve-pair-report.json` |

결정 전에는 임시 값을 최종 계약에 넣지 않는다. 개발용 로컬 기본값이 필요하면 `development` split에만 기록하고 봉인 평가 자료로 승격하지 않는다.
