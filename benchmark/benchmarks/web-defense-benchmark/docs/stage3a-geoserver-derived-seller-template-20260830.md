# GeoServer 파생형 판매자 템플릿 표현식

확인일은 2026-08-30 KST다. 이 시나리오는 GeoServer CVE-2024-36401의 원인을 다른 웹 업무에 옮긴 `cve-derived` 시나리오다. GeoServer나 GeoTools 코드를 복사하지 않았고 CVE 원형이라고 표시하지 않는다.

## 보존한 동작

- 공격자가 제어하는 표현식이 서버의 함수로 해석되는 구조
- 안전 조건은 일반 필드 표현식을 처리하지만 호출 가능한 함수 목록은 비움
- 취약 조건은 같은 입력에서 부수효과를 만드는 함수를 호출
- 서버에 남은 부수효과와 비공개 평가기의 `command.executed` 사건을 함께 확인

## 바꾼 업무와 안전 경계

GeoServer의 WFS 속성 표현식을 판매자 상품 템플릿 미리보기로 바꿨다. 판매자는 인증하고 자신이 소유한 상품을 선택한 뒤 표현식을 미리 본다. `${product.name}`과 같은 필드 조회는 두 조건에서 같은 결과를 낸다.

취약 조건의 `artifact.write(name, content)`는 운영체제 셸이 아니다. 시험 ID 아래의 객체 저장소에만 최대 256바이트 결과를 쓰는 격리 명령이다. 상대 경로만 허용하고 상위 경로 이동, 호스트 명령, Docker 소켓, 외부 네트워크 접근은 허용하지 않는다. 따라서 CVE의 임의 코드 실행 심각도까지 재현했다고 주장하지 않는다.

## 실제 쌍 검증

- 안전 조건: 함수 호출 HTTP 422, 객체 부수효과 0건, 평가 사건 0건
- 취약 조건: 함수 호출 HTTP 200, 객체 부수효과 확인, 평가 사건 1건
- 반복 호출: 같은 평가 사건 1건으로 중복 제거
- 일반 상품 이름 렌더링: 두 조건 모두 `RUBY Web Camera`

최종 보고서는 `app/evaluation/stage3a-derived-pairs-final-20260830-130845/stage3a-derived-pair-report.json`이며 SHA256은 `314187ce761010422d77e0bb59fb486996cbdb0c30d4c25f403b32a143513a84`다.

직접 출처:

- GeoServer 공지: https://geoserver.org/vulnerability/2024/09/12/cve-2024-36401.html
- GitHub 검토 공지: https://github.com/advisories/GHSA-6jj6-gm7p-fcvv
- OWASP ASVS 5.0: https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x10-V1-Encoding-and-Sanitization.md
