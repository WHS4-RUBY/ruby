# 추가 취약점 시나리오 범위 계약

- 기준일: 2026-09-08
- 계약 스키마: [`../contracts/scenario-completion-contract.schema.json`](../contracts/scenario-completion-contract.schema.json)
- 계약 파일: [`../app/configs/scenario-contracts/`](../app/configs/scenario-contracts/)
- 현재 상태: Roundcube 2026 대상과 합성 대상 6개 구현 및 Docker pair 검증 완료

이 문서는 기존 23개 합성 취약점과 원본 CVE 4개에서 부족했던 범위를 보완하기 위해 구현한 대상을 기록한다. 각 JSON 계약은 공격자가 볼 수 있는 시작점, 정상 업무, 비공개 성공 판정, 취약 및 안전 pair의 차이, 실행 예산, 격리 경계, 자원 상한, 분류 근거와 초기화 조건을 함께 기록한다. 여섯 합성 계약과 Roundcube 계약은 구현과 자동 pair 검사를 마쳐 `implemented`로 표시했다.

## 범위 표

| 구현 대상 | 보완하는 범위 | 분류 | 계약 상태 |
| --- | --- | --- | --- |
| 서명 다운로드 위조 | 암호학 실패, 객체 결합 검증 | OWASP A04:2025, CWE-347, ASVS 8.2.2, 9.1.1, 9.2.2 | 구현 및 Docker pair 통과 |
| 보고서 내보내기 fan-out | 제한된 자원 소모와 빈도 제한 | OWASP A06:2025, API4:2023, CWE-770, CWE-799, ASVS 2.1.3, 2.4.1 | 구현 및 Docker pair 통과 |
| 대량 프로모션 중복 사용 | 민감 업무 흐름 자동화와 중복 실행 | OWASP A06:2025, API6:2023, CWE-837, CWE-799, ASVS 2.3.2, 2.4.1 | 구현 및 Docker pair 통과 |
| 폐기된 운영 API | API 목록과 수명주기 관리 | OWASP A02:2025, API9:2023, CWE-749, ASVS 8.2.1, 15.2.3 | 구현 및 Docker pair 통과 |
| 감사 기록 삭제 | 보안 로깅, 변경 방지, 경보 | OWASP A09:2025, CWE-778, ASVS 16.3.3, 16.4.2, 16.4.3 | 구현 및 Docker pair 통과 |
| 서명 없는 파트너 웹훅 | 소프트웨어 및 데이터 무결성, 외부 API 신뢰 | OWASP A08:2025, API10:2023, CWE-353, ASVS 13.2.1 | 구현 및 Docker pair 통과 |
| Roundcube CVE-2026-54433 | 2026년 원본 제품 취약점, plain-text 메시지 저장형 XSS | OWASP A05:2025, CWE-79, ASVS 1.2.1, 3.2.2 | 1.7.1 및 1.7.2 pair 구현 및 실제 검증 완료 |

ASVS 표의 짧은 번호는 계약 파일에 `v5.0.0-번호` 형식으로 저장한다. 여섯 합성 시나리오는 웹 취약점 범주의 공백을 줄이기 위한 벤치마크 설계다. 실제 서비스에서의 발생 빈도나 전체 웹 취약점 분포를 대표한다고 주장하지 않는다.

## 공격자 경계와 성공 판정

모든 계약은 공격자에게 대상의 상대 HTTP 경로만 허용한다. Roundcube XSS는 합성 메일 서버로 제한된 SMTP 전송과 평가기가 동일 브라우저 동작을 재현하기 위한 피해자 브라우저 트리거도 허용한다. 호스트 파일시스템, Docker API, 평가기 API, 데이터베이스, 제어 API, 다른 대상과 외부 네트워크는 모두 금지한다. 리디렉션 자동 추적은 끄고 대상은 상대 경로로만 지정한다.

공격 성공은 별도 평가기가 비공개 자원 키와 이벤트를 확인해 판정한다. 이 값과 판정식은 공개 시작점이나 정상 업무 설명에 넣지 않는다. 정상 기능은 취약 및 안전 variant에서 같은 결과를 내야 한다. 취약 variant는 기준 공격이 성공하고 안전 variant는 동일 공격이 실패해야 한다.

자원 소모 시나리오는 실제 CPU, 메모리 또는 외부 서비스 비용을 고갈시키지 않는다. 합성 비용 단위를 제한된 정수로 누적해 취약한 fan-out과 안전한 상한 적용을 비교한다. 외부 콜백과 호스트의 지속적인 변경도 금지한다. 각 trial은 대상을 다시 생성하고 종료 후 잔여 컨테이너, 네트워크와 상태를 확인해야 한다.

## 2026년 원본 취약점 선정 근거

Roundcube는 2026년 7월 5일 보안 공지에서 CVE-2026-54433을 plain-text 메시지 렌더링의 zero-click 저장형 XSS로 설명하고 1.6.17과 1.7.2에서 수정했다고 밝혔다. 처음 검토한 1.6.16 이미지의 실제 문자열 치환 코드는 공개 기준 공격이 요구하는 `\S+` 패턴과 달라 취약 동작을 재현하지 못했다. 문서상 영향 버전이라는 이유만으로 성공을 가정하지 않고, 공개 PoC와 1.7 계열 수정 commit `5477e979aae0317e111564bfc9971ba7707cc165`을 직접 대조할 수 있는 1.7.1 및 1.7.2를 pair로 고정했다. 2026년 9월 6일 공지가 더 최근이지만 공지 본문에 CVE 식별자가 없으므로 현재 계약의 재현 가능한 CVE pair로 사용하지 않는다. 이 선택은 최신 취약점 전체를 대표한다는 주장이 아니다.

## 계약 검증

다음 명령은 스키마, 비공개 판정값 노출, 전체 격리 경계, ID 중복과 원본 CVE pair를 검사한다.

```powershell
app\.venv\Scripts\python.exe tools\validate_scenario_contracts.py
```

```bash
app/.venv/bin/python tools/validate_scenario_contracts.py
```

검증 성공 시 `valid scenario contracts: 7 files`가 출력된다. 이 검사는 구현 완료 증거가 아니다. 각 시나리오의 `implementation_status`를 `implemented`로 바꾸려면 정상 기능 일치, 취약 variant 성공, 안전 variant 실패, 공격자 격리와 정리 검사를 실제로 통과한 증거가 필요하다.

일곱 계약은 이 조건을 통과해 `implemented`로 변경했다. 여섯 합성 모듈의 26개 Docker 조건 보고서는 [`../evidence/20260908/scope-expansion-pairs.json`](../evidence/20260908/scope-expansion-pairs.json)에 있다. Roundcube 제품 쌍 검증과 자율 어댑터 검증의 원본 JSON은 각각 [`../evidence/20260908/roundcube-cve-2026-54433-pair.json`](../evidence/20260908/roundcube-cve-2026-54433-pair.json), [`../evidence/20260908/roundcube-cve-2026-54433-autonomous-adapter.json`](../evidence/20260908/roundcube-cve-2026-54433-autonomous-adapter.json)에 있다.

## 분류와 제품 버전의 1차 출처

- [OWASP Top 10:2025 원문](https://github.com/OWASP/Top10/blob/master/2025/docs/en/index.md)
- [OWASP API Security Top 10:2023 원문](https://github.com/OWASP/API-Security/tree/master/editions/2023/en)
- [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0)
- [MITRE CWE](https://cwe.mitre.org/data/index.html)
- [Roundcube 2026-07-05 보안 공지](https://roundcube.net/news/2026/07/05/security-updates-1.6.17-and-1.7.2)
- [Roundcube 1.7 계열 수정 commit](https://github.com/roundcube/roundcubemail/commit/5477e979aae0317e111564bfc9971ba7707cc165)

## 색인과 재현 입력의 2차 출처

- [GitHub Advisory Database, GHSA-6hj3-f24f-rwj8](https://github.com/advisories/GHSA-6hj3-f24f-rwj8)
- [NVD, CVE-2026-54433](https://nvd.nist.gov/vuln/detail/CVE-2026-54433)
- [검증에 사용한 공개 PoC revision](https://github.com/aramosf/CVE-2026-54433/tree/93ade06334a28fa83db888623f701d5706ca40ae)
- [Roundcube 2026-09-06 보안 공지](https://roundcube.net/news/2026/09/06/security-updates-1.6.19-and-1.7.4)
