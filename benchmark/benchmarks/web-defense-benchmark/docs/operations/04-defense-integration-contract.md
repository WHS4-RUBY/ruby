# 방어 장치 연동 계약

확인일: 2026-09-08

## 1. 현재 상태

`inline-http` 계약을 실행하는 공통 게이트웨이와 설정 기반 등록부가 구현돼 있다. 관리형 컨테이너와 이미 실행 중인 loopback HTTP 어댑터를 방어 이름별 소스 분기 없이 연결할 수 있다. 현재 실행 지원 범위는 `inline-http`이며 다른 연결 유형은 아래의 설계 후보다. 실제 등록, 검사와 실행 절차는 [`../defense-integration.md`](../defense-integration.md)를 따른다.

## 2. 연결 위치

```text
공격자 또는 정상 사용자
        |
실험 게이트웨이와 계측기
        |
방어 연결 계층
        |
RUBY 웹 또는 원본 CVE 제품
```

웹 애플리케이션과 벤치마크 실행기는 방어 구현 코드를 import하지 않는다. 방어 코드는 별도 컨테이너 이미지 또는 loopback 어댑터로 실행하고, Testbed가 이미지나 endpoint, 매니페스트와 계약 해시를 연결한다.

## 3. 지원 연결 유형

| 연결 유형 | 용도 | 전송 예시 |
|---|---|---|
| `inline-http` | 요청 차단, 지연, 요청 및 응답 변경 | OpenAPI HTTP |
| `passive-http-mirror` | 요청 복사와 탐지, 원 요청은 그대로 전달 | HTTP 이벤트 스트림 |
| `network-sensor` | IDS, 방화벽과 패킷 관찰 | PCAP 미러 |
| `application-instrumentation` | 허니토큰과 내부 이벤트 센서 | 애플리케이션 이벤트 API |
| `external-decoy` | 별도 허니팟, 미끼 API와 미끼 웹 | 미끼 배포와 라우팅 |
| `asynchronous-stateful` | 세션 기록, 모델 생성 상태와 장기 기만 | 상태 작업 API |

`contracts/defense-adapter.openapi.yaml`은 `inline-http`만 정의하고 공통 실행 계층도 이 유형만 지원한다. 나머지 연결 유형을 동기식 요청 판정 API 하나로 축소하지 않는다.

## 4. inline HTTP 입력

요청 단계와 응답 단계가 각각 `/v2/decision`으로 전달된다.

공통 필드:

| 필드 | 의미 |
|---|---|
| `contract_version` | 현재 `2.0.0` |
| `trial_id` | 격리 시험 식별자 |
| `interaction_id` | 한 요청과 응답을 잇는 식별자 |
| `session_handle` | 시험용 익명 세션 식별자 |
| `principal_handle` | 선택적 익명 사용자 식별자 |
| `device_handle` | 선택적 익명 장치 식별자 |
| `phase` | `request` 또는 `response` |
| `automation_score` | 선택적 자동화 가능성, 0부터 1 |
| `attack_score` | 선택적 공격 가능성, 0부터 1 |
| `http` | HTTP 요청 또는 응답 원문 캡처 |

요청은 메서드, 스킴, 호스트, 경로와 쿼리, 헤더와 본문을 포함한다. 본문은 Base64와 원본 SHA256을 기록하며 최대 1 MiB까지 캡처한다. 잘린 경우 `truncated`와 잘림 정책 해시를 함께 보낸다.

자동화 점수와 공격 점수는 서로 다른 판단값이다. 자동화됐다는 이유만으로 공격으로 처리하지 않는다.

## 5. inline HTTP 출력

방어 장치는 다음 행동 중 하나를 반환한다.

| 행동 | 의미 |
|---|---|
| `pass` | 그대로 전달 |
| `block` | 지정 응답으로 차단 |
| `delay` | 최대 60초 지연 |
| `rewrite-request` | 요청 교체 |
| `replace-response` | 응답 교체 |
| `route-decoy` | 등록된 미끼 대상으로 전달 |
| `terminate-session` | 해당 시험 세션 종료 |

모든 결과에는 기계 판독 가능한 `reason_code`가 필요하다. 응답 교체가 성공처럼 보이더라도 비공개 평가기는 실제 보호 상태가 변했는지 별도로 확인한다.

## 6. 준비, 초기화와 실패 처리

각 방어 구현은 다음 항목을 매니페스트에 기록한다.

- 방어 ID와 버전
- 저장소, revision, 소스 해시와 라이선스
- 논문 구현 충실도
- 연결 유형과 생명주기 계약 해시
- 지원 기능과 제외한 구성요소
- 상태 범위와 시험 간 초기화
- 기만 사용 여부와 격리 정책
- 모델 ID, 프롬프트와 파라미터 해시
- 시간 제한, 재시도와 오류 결과

시간 초과와 내부 오류는 `invalid-defense-error`다. 자동 `pass`로 처리하면 방어가 실패했는데 무방어처럼 진행돼 결과가 왜곡되므로 금지한다.

## 7. 상태형 기만과 미끼의 추가 계약

상태형 기만은 다음을 반드시 선언해야 한다.

- 상태 범위: 요청, 세션, 사용자, 장치 또는 시험 전체
- 미끼 진입 조건과 시점
- 후속 요청을 미끼에 유지하는 기간
- 새 계정, 새 세션과 주소 변경 시 연결 규칙
- 실제 서버 재진입 허용 여부
- 실제 상태와 미끼 상태의 분리 방식
- 계정, 토큰, 파일과 업무 데이터의 일관성 검사

일부 정규식에 맞는 요청만 미끼로 보내고 나머지를 설명 없이 실제 서버로 되돌리면 상태형 기만으로 분류하지 않는다. 제한된 요청 변환 방어로 보고한다.

## 8. 구현 충실도

| 값 | 의미 |
|---|---|
| `native` | 공개 원 구현을 지정 버전과 설정으로 실행 |
| `native-with-adapter` | 원 구현을 유지하고 입출력 연결 계층만 추가 |
| `ported` | 다른 환경으로 이식했지만 핵심 처리 흐름 유지 |
| `reduced-emulation` | 일부 아이디어만 축소 재현 |

논문 결과와 직접 비교하려면 `native` 또는 검증된 `native-with-adapter`여야 한다. 그 외 구현은 RUBY에서 구현한 조건의 결과로만 보고한다.

## 9. 공정 비교에 필요한 산출물

방어 시험 전 다음 파일을 연결하고 SHA256을 고정해야 한다.

- 시나리오
- 공격자 공개 설명
- 비공개 평가기
- 취약 배포와 안전 쌍 배포
- 미끼 등록부와 미끼 배포
- 무방어 실험 설정
- 방어 실험 설정
- 방어 기능 매니페스트
- 연결 생명주기 계약
- 취약점 쌍 검증 보고서

`contracts/comparison-bundle.schema.json`은 위 참조와 해시를 하나의 비교 묶음으로 검사한다.

## 10. 탐지팀과 방어팀 연결 시 결정할 항목

1. Detection Proxy가 `automation_score`와 `attack_score`를 어떤 시점에 확정하는가
2. 점수가 없는 첫 요청을 방어 장치가 어떻게 처리하는가
3. 점수 갱신이 같은 세션과 사용자에 어떻게 이어지는가
4. 방어가 생성한 미끼 상태를 어느 저장소에 보관하는가
5. 응답 생성 지연과 모델 실패를 어떤 결과로 기록하는가
6. 공격자와 정상 사용자 양쪽에 같은 게이트웨이 계측을 적용하는가
7. Defense 로그와 비공개 평가기 결과를 어떤 키로 결합하는가

## 11. 근거 파일

- 전체 구조: `docs/architecture.md`
- 방어 기능 매니페스트: `contracts/defense-capability.schema.json`
- 연결 생명주기: `contracts/attachment-lifecycle.schema.json`
- inline HTTP API: `contracts/defense-adapter.openapi.yaml`
- 비교 묶음: `contracts/comparison-bundle.schema.json`
- 실행 등록부 스키마: `contracts/defense-runtime-registry.schema.json`
- 사용자 연결 절차: `docs/defense-integration.md`
