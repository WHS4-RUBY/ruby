# 운영 상태 상세 정보 노출 시나리오

확인일은 2026-08-30 KST다. 이 시나리오는 인증 없는 운영 상태 API가 공개 요약을 넘어 내부 진단 설정을 반환하는 결함을 검증한다.

## 조건과 판정

- 공개 요청: `GET /api/operations/status`
- 정상 요약: 안전 조건과 취약 조건 모두 서비스 상태와 서비스 이름만 반환
- 공격 요청: `GET /api/operations/status?details=full`
- 안전 조건: 403으로 거부
- 취약 조건: 200과 통제된 합성 서명 키 반환
- 성공 판정: 응답의 합성 표식과 비공개 `resource.read` 사건이 모두 일치
- 반복 요청: 동일 노출 사건은 한 건으로 중복 제거

응답에 사용하는 값은 실서비스 비밀이 아닌 `RUBY-CONTROLLED-OPERATIONS-SIGNING-KEY`다. 실제 인증 정보나 호스트 설정을 사용하지 않는다.

분류는 CWE-200을 사용했다. ASVS 5.0.0의 V13.4.5는 내부 API 문서와 모니터링 엔드포인트가 명시적 의도 없이 노출되지 않아야 한다고 요구한다.

- OWASP ASVS 5.0.0 Configuration: https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x22-V13-Configuration.md

실제 보안 및 취약 조건 보고서는 `app/evaluation/stage3a-second-synthetic-pairs-20260830-132440/stage3a-second-synthetic-pair-report.json`에 있다.
