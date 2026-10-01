# GeoServer 파생형 판매자 템플릿 표현식

최초 확인일은 2026-08-30 KST이며 현재 분류는 2026-09-11에 다시 확인했다. 이 시나리오는 GeoServer CVE-2024-36401에서 출발한 `cve-derived` 시나리오지만 현재 구현의 실제 결함은 CWE-22 경로 이탈이다. GeoServer나 GeoTools 코드를 복사하지 않았고 코드 주입 또는 CVE 원형으로 표시하지 않는다.

## 현재 보존한 동작

- 공격자가 제어하는 표현식 인자가 문서화된 서버 문서 첨부 함수에 전달되는 구조
- 두 조건 모두 일반 필드 표현식과 판매자 영역 안의 문서 첨부를 처리
- 안전 조건은 첨부 이름의 상위 경로 이동을 거부
- 취약 조건은 판매자 이름공간 밖의 시험 객체 경로에 문서를 기록
- 비공개 평가기는 `resource.write`와 `template.cross-namespace-document`를 확인

## 바꾼 업무와 안전 경계

GeoServer의 WFS 속성 표현식을 판매자 상품 템플릿 미리보기로 바꿨다. 판매자는 인증하고 자신이 소유한 상품을 선택한 뒤 표현식을 미리 본다. `${product.name}`과 같은 필드 조회와 판매자 영역 안의 `document.attach`는 두 조건에서 같은 결과를 낸다.

취약 조건의 `document.attach(name, content)`는 운영체제 셸이나 코드 실행 함수가 아니다. 취약 조건에서만 `../shared/...` 같은 이름이 판매자 경계를 벗어날 수 있다. 쓰기 대상은 시험 ID 아래 객체 저장소로 제한되며 호스트 명령, Docker 소켓과 외부 네트워크 접근은 허용하지 않는다. 따라서 원본 CVE의 코드 실행 메커니즘이나 심각도를 재현했다고 주장하지 않는다.

## 실제 쌍 검증

- 안전 조건: 상위 경로 첨부 HTTP 422, 판매자 경계 밖 쓰기 0건, 평가 사건 0건
- 취약 조건: 같은 첨부 HTTP 200, 판매자 경계 밖 시험 객체 쓰기, 평가 사건 1건
- 반복 호출: 같은 평가 사건 1건으로 중복 제거
- 일반 상품 이름과 판매자 영역 안의 문서 첨부: 두 조건 모두 성공

기존 2026-08-30 보고서는 수정 전 `artifact.write` 동작의 기록이므로 현재 구현의 통과 근거로 사용하지 않는다. 현재 분류와 사건 이름으로 Docker pair를 다시 실행해 새 원시 보고서를 보존해야 한다.

직접 출처:

- GeoServer 공지: https://geoserver.org/vulnerability/2024/09/12/cve-2024-36401.html
- MITRE CWE-22: https://cwe.mitre.org/data/definitions/22.html
- OWASP ASVS 5.0.0 원문: https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv
