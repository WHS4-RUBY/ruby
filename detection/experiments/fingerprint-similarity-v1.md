# Fingerprint 유사도 단일 변수 실험

- 실행일: 2026-09-14
- 구현 버전: `fingerprint-similarity-v1`
- 재현 명령: `npm run experiment:fingerprint`
- 주의: 연관 점수는 동일 사용자 확률이 아닌 휴리스틱 점수다.

## 결정적 모듈 실험

| 번호 | 변경 조건 | 점수 | 판정 | Candidate | 자동 잠정 집계 |
|---:|---|---:|---|---|---|
| 1 | 모든 값 동일 | 100.0 | EXACT | 동일 | 불필요 |
| 2 | IP만 변경 | 70.0 | RELATED | 변경 | 적용 |
| 3 | curl 8.10.1 → 8.11.0 | 95.5 | RELATED | 변경 | 적용 |
| 4 | 언어 ko-KR → en-US | 90.0 | RELATED | 변경 | 적용 |
| 5 | gzip, deflate, br → gzip, br | 96.7 | RELATED | 변경 | 적용 |
| 6 | 헤더 순서만 변경 | 98.8 | RELATED | 동일 | 불필요 |
| 7 | 같은 IP에서 버전·언어·인코딩 변경 | 88.2 | RELATED | 변경 | 적용 |
| 8 | 다른 IP에서 나머지 특징 동일 | 70.0 | RELATED | 변경 | 적용 |
| 9 | 같은 전송 헤더에 Claude/Codex 실험 라벨만 변경 | 100.0 | EXACT | 동일 | 불필요 |
| 10 | 유효 DCID 유지, 세션 ID 변경 | 해당 없음 | CONFIRMED | 변경 가능 | DCID 확정 경로 |

9번 결과는 모델 종류 식별을 의미하지 않는다. `X-Experiment-Run-Id`는 비교 입력에서
제외되므로 실제 전송 헤더가 같으면 Claude와 Codex를 구분할 수 없다.

## 로컬 HTTP 스모크 검증

격리된 로컬 프록시에서 `TRUST_PROXY=true`를 설정하고 문서용 공인 IP 대역 두 개를
`X-Forwarded-For`로 전달했다. 그 외 curl 버전, 언어, 인코딩과 헤더 순서는 같게 유지했다.

- 첫 요청 IP: `203.0.113.41`
- 두 번째 요청 IP: `198.51.100.42`
- Candidate: 2개
- Client Flow: 1개
- 연관 점수: 70.0/100
- 판정: `RELATED`
- 변경 필드: `ip`
- 잠정 집계 요청: 2개, `requestId` 중복 없음
- 집계 정책: `FINGERPRINT_CLIENT_FLOW_AUTO`
- 병합 전 최고 Automation Score: 23.5점
- 병합 후 재계산 Automation Score: 24.6점
- Attack Score: 두 요청 모두 공격 신호가 없어 0점
- 대시보드 HTTP 응답: 200

이 스모크 검증은 유사도 집계 경로의 동작 확인이며, 실제 Claude/Codex 네트워크 환경의
정확도나 오탐률을 입증하는 실험은 아니다.
