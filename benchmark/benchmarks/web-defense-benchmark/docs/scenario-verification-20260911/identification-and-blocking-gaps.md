# 식별과 차단의 미구현 및 미검증 항목

## 결론

XSS와 CSRF 취약점의 공격 재현과 성공 판정은 통과했다. 현재 RUBY 식별기는 두 공격 요청을 분류하지 않고, 등록된 `static-guard`도 차단하지 않는다. 일부는 현재 입력만으로 구현할 수 있지만, SMTP나 브라우저 내부에서만 보이는 공격은 관측 경로를 추가해야 한다.

## 직접 확인 결과

2026-09-11 현재 코드에 다음 입력을 넣어 `static-guard` 결정을 확인했다.

| 입력 | 현재 결정 |
| --- | --- |
| `<script>alert(1)</script>`가 든 검색값 | 통과 `static.clean` |
| `<img onerror=...>`가 든 검색값 | 통과 `static.clean` |
| 외부 사이트에서 여는 역할 변경 경로 | 통과 `static.clean` |
| SQL 주입 대조 입력 | 차단 `static.attack-signature` |

`detection/app/main.py`도 요청 횟수로 위험도만 올리는 프록시다. XSS, CSRF, `Origin`, `Sec-Fetch-Site`를 검사하거나 공격 요청 식별값을 만드는 코드가 없다.

입력과 실제 결정, 확인한 소스의 SHA-256은 [현재 XSS 및 CSRF 범위 증거](../../evidence/20260911/current-xss-csrf-coverage.json)에 보존했다.

## 구현 가능성

| 항목 | 현재 상태 | 현재 구조에서 가능한가 | 필요한 검증 |
| --- | --- | --- | --- |
| HTTP 요청에 문자열이 보이는 저장형 XSS 식별 | 미구현 | 가능 | 여러 XSS 변형과 정상 HTML 입력을 함께 시험해야 함 |
| 자체 CSRF 역할 변경 요청 식별 | 미구현 | 가능 | 민감 경로, `Sec-Fetch-Site: cross-site`, 메서드를 함께 보고 같은 사이트 정상 요청의 오탐을 시험해야 함 |
| Roundcube 원본 XSS 요청 식별 | 미구현 | 현재 HTTP 식별기만으로 불가 | SMTP 입력 또는 메일 본문 관측 지점을 따로 연결해야 함 |
| DOM 기반 XSS | 시나리오 없음 | 현재 구조로 불가 | URL fragment나 `postMessage` 입력과 브라우저 실행 관측 시나리오가 필요함 |
| 반사형 XSS | 전용 시나리오 없음 | 구현 가능 | 응답 반사와 실제 브라우저 실행을 확인하는 취약판 및 안전판이 필요함 |
| 일반적인 CSRF 요청 식별 | 미검증 | 요청만으로 항상 식별할 수 없음 | Origin, Fetch Metadata, CSRF 토큰과 업무 맥락을 결합한 범위를 먼저 정해야 함 |
| 34개 전체의 AI 자율 발견 | 미검증 | 실행기는 지원하지만 결과 없음 | 표적별 무방어 반복 시험과 공격자 동일성 확인 필요 |
| 실제 RUBY 방어 효과 | 미검증 | 방어 컴포넌트 연결 후 가능 | 무방어 자격, 반복 비교, 정상 트래픽 오탐, 모델 식별과 독립 검토 필요 |

## XSS와 CSRF를 유지하는 이유

두 취약점은 실제로 작동하고 성공 판정도 가능하므로 벤치마크 표적으로 유지할 수 있다. 다만 공격 요청 식별과 실행 차단 검증이 끝나기 전에는 방어 효과 점수에 넣지 않는다. 현재 제외 목록은 [`defense-effect-exclusions-v1.json`](../../app/configs/defense-effect-exclusions-v1.json)에 있다.
