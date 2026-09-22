# 팀 PR #17과 #18 탐지 연동 반영

확인일: 2026-09-22 KST

## 결론

팀 `main`의 PR #17과 #18을 벤치마크 통합 브랜치에 병합했다. 현재 서버 요청 경로는
`Detection -> Defense -> Target`이다. 별도 Policy 서비스는 없고 Detection이 내부
정책 설정을 읽어 `X-Defense-Plan`과 `X-Client-Id`를 Defense에 전달한다.

자체 취약점 웹은 이 경로의 Target으로 연결할 수 있다. 대상 전환 오버레이는 Defense의
`BENCHMARK_TARGET_URL`만 `http://ruby-web-target:8080`으로 바꾼다. Detection의 다음
홉은 대상 종류와 관계없이 `http://defense:8080`으로 유지한다.

## PR별 영향

| 변경 | 벤치마크 영향 | 반영 |
|---|---|---|
| PR #17 Fingerprint Client Flow | 여러 Candidate의 요청과 점수가 한 흐름으로 누적될 수 있음 | 대상 및 시험 전환 시 Detection 재생성 |
| PR #17 `X-Experiment-Run-ID` 관측 | 실행 식별자는 기록되지만 상태 격리 키는 아님 | 헤더만으로 초기화됐다고 간주하지 않음 |
| PR #18 Policy 내부 통합 | 별도 Policy 컨테이너와 `X-Risk-Score` 전달이 사라짐 | Compose와 CI에서 직접 Detection -> Defense 계약 확인 |
| PR #18 `X-Defense-Plan` | Defense가 실행할 전략 배열을 전달 | Defense가 소비하고 Target에는 전달하지 않음 |
| PR #18 포트 통일 | Defense 내부 포트가 8080으로 고정 | Detection과 대상 전환 오버레이 모두 8080 사용 |

## XSS와 CSRF 해석

현재 Detection에는 XSS 페이로드 서명, CRS 결과, CSRF Origin 및 Referer 신호가 있다.
이는 다음 사실만 의미한다.

- HTTP 요청에서 관측된 특징을 탐지 점수에 사용할 수 있다.
- CSRF 출처 불일치나 출처 누락을 의심 신호로 기록할 수 있다.
- CRS가 관측 가능한 XSS 입력을 규칙으로 표시할 수 있다.

다음 내용은 증명하지 않는다.

- 저장된 문자열이 피해자 브라우저에서 실제 실행됐다는 사실
- 정상 HTML과 모든 XSS 변형을 안정적으로 구분한다는 사실
- CSRF 요청이 사용자의 정상 조작이 아니라 외부 유도로 발생했다는 사실
- DOM 내부에서만 생성된 공격을 서버가 관측했다는 사실
- 현재 지연 정책이 XSS 또는 CSRF 실행을 차단했다는 사실

따라서 판정, 식별과 방어 평가는 계속 분리한다. 2026-09-17에 확정한 XSS 및 CSRF 관련
5개 본 실험 제외 결정도 유지한다.

## 상태 격리

Detection의 Session, Resolved Actor와 Client Flow는 메모리에 누적된다. 스키마 학습
자료는 `detection-data` volume에 남는다. `X-Experiment-Run-ID`는 요청 기록 필드이며
누적 점수를 초기화하지 않는다.

공식 비교 시험은 다음 중 하나를 사용한다.

1. 시험마다 독립 Compose 프로젝트에서 Detection을 시작한다.
2. 공유 서버에서 대상을 바꾼다면 Defense 전환 뒤 Detection을 강제로 재생성한다.

두 번째 방법은 인메모리 점수를 비우지만 스키마 학습 자료는 유지한다. 사용한 학습 파일,
Detection 이미지 SHA, 정책 파일과 대상 이미지 SHA를 실행 설정 원문에 기록한다.

## 검증 경계

저장소 검사에서는 별도 Policy 서비스가 없는지, Detection의 다음 홉이 Defense 8080인지,
Defense 오버레이가 자체 웹 공개 서비스만 선택하는지, 두 Compose 프로젝트가 명시적으로
같은 파이프라인 네트워크를 쓰는지 확인한다.

이번 반영은 실제 팀 서버에 배포하지 않는다. 서버에서 Detection, Defense와 자체 웹을
함께 실행한 왕복 결과나 새 탐지 구조의 방어 효과는 별도 실행 전까지 확인됐다고 쓰지 않는다.
