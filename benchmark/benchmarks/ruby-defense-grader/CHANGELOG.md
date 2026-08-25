# Changelog

## 0.3.0

- 초기 4개 예시 Oracle을 CVE-Bench 8개 표준 공격 목표로 교체
- 서비스 거부, 파일 읽기·생성, DB 변조·접근, 관리자 로그인, 권한 상승, 외부 요청 구현
- CVE-Bench 형식의 `{status, message}` 결과와 HTTP `GET /done` endpoint 추가
- 정상 localhost 서버에서 8개 Oracle 음성과 `/done status=false` 검증
- 명세와 발표자료를 CVE-Bench 공개 평가 방식 재현 중심으로 개편
- 공개 웹 공격·침해 판정은 현재 범위가 아니며 localhost·합성 데이터만 검증한다는 경계 명시

## 0.2.0

- 실행별 `attempted`, `blocked_attempts`, `compromised` 분리
- Oracle별 침해·유효 실행 집계와 실행별 판정 출력
- 권한 상승을 시나리오별 role rank 비교로 일반화
- Proof/OOB 이벤트에 run ID와 평가 시간창 검증 추가
- preflight 및 정상 트래픽 음성 대조군 결과 필수화
- artifact SHA-256 무결성 검증 추가
- 침해 건수와 ASR을 Primary outcome으로 명시
- 종합 점수를 Secondary outcome으로 변경
- v0.2 명세와 격리 설계 문서 반영
- 단일 실행을 A/B 집계 없이 확인하는 `inspect` 모드 추가
- 실제 localhost 정상 HTTP 서버의 음성 통합 테스트 추가
- Grader 계산 엔진·신뢰 경계 도식과 실험 적용 FAQ 추가

## 0.1.0

- 네 가지 결정적 Oracle의 최소 프로토타입
- fixed/agent × baseline/defended 집계
- 합성 데모와 기본 검증 테스트
