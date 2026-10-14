# 계층 간 계약

Detection·Defense·CHeaT sidecar·계정 오버레이는 각각 다른 컨테이너다. 이 문서는 그
사이를 오가는 것만 다룬다 — 헤더, 이벤트 필드명, 공유 설정, 신뢰 경계. 각 계층의
내부 동작은 [`detection/README.md`](detection/README.md),
[`defense/README.md`](defense/README.md),
[`defense/account-response-overlay/INTEGRATION.md`](defense/account-response-overlay/INTEGRATION.md)에 있다.

## 요청 흐름

```text
클라이언트 ──▶ Detection(:8081 공개) ──▶ Defense(:8080) ──┬─▶ CHeaT sidecar ──▶ 대상
                                                          ├─▶ 계정 오버레이 ──▶ 대상
                                                          └─▶ 대상 (직접)
```

Defense 는 관리 화면에서 고른 대상 ID 에 맞는 sidecar 와 오버레이를 선택한다. 공개
포트는 Detection 하나뿐이고 나머지는 비공개 Docker 네트워크에만 있다. 관리 리스너는
서버 루프백에만 바인딩한다.

점수와 전략은 **이전에 완료된 요청**에서 계산한다. 어떤 요청도 자기 자신의 점수로
방어되지 않는다 — Detection 이 `onProxyReq` 에서 쓰는 값은 직전까지 기록된 상태다.

## 헤더 계약

### Detection → Defense

| 헤더 | 뜻 |
| --- | --- |
| `X-Ruby-Request-Id` | 두 대시보드를 잇는 조인 키 |
| `X-Ruby-Target-Id` / `X-Ruby-Run-Id` | 선택된 대상과 그 전환마다 새로 발급되는 실행 ID |
| `X-Client-Id` | 정책 키. 검증된 signed `dcid` 또는 관찰 후보 |
| `X-Ruby-Risk-Score` / `X-Ruby-Confirmed-Attack-Score` | 정책 평가에 쓰는 두 점수 |
| `X-Ruby-Automation-Score` / `X-Ruby-Attack-Score` | 표시용 세부 점수 |
| `X-Defense-Plan` | `policy.json` 이 고른 전략 목록(JSON) |
| `X-Ruby-Defense-Tier` | 선택된 정책 단계(`stage1`~`stage4`) |
| `X-Ruby-Policy-Source` | 점수 출처 |
| `X-Ruby-Candidate-Id` / `X-Ruby-Client-Flow-Id` | 관찰 흐름 표시 전용. 전략 선택에 쓰지 않는다 |

클라이언트가 보낸 같은 이름의 헤더는 Detection 이 먼저 지운다. Defense 도
`_DEFENSE_INTERNAL_HEADERS` 로 한 번 더 지우고 대상에게 전달하지 않는다.
`X-Forwarded-For` 는 Detection 이 항상 무시한다.

정책은 위험 점수와 확정 공격 점수를 함께 본다. 둘 다 0.8 이상이면 `stage4`
(`decoy_maze`, `delay` 700ms, `rate_limit_strict`, `account_overlay_high`), 둘 다
0.5 이상이고 확정 공격 점수가 0.8 미만이면 `stage3`(`decoy_maze`,
`account_overlay_medium`, `delay` 500ms), 둘 다 0.25 이상이고 확정 공격 점수가
0.5 미만이면 `stage2`(`decoy_maze`, `account_overlay_medium`, `delay` 300ms)다.
나머지 요청은 0점부터 `stage1`(`decoy_maze`)이다. `decoy_maze`는 모든 단계에서
유지하고 중간 오버레이는 4단계에서 높은 오버레이로 대체한다. 지연은 더하지 않고
선택된 단계의 값 하나만 실행한다. 오버레이 경로는 같은 검증된 행위자에 대해 영속
유지된다.
`path_alias`는 이 전략 계획에 넣지 않고 현재 정책의 **`stage3`(위험 점수 0.5 이상,
확정 공격 점수 0.5 이상 0.8 미만) 또는 `stage4`(두 점수 모두 0.8 이상)**에서
별칭 발급·응답 치환을 시작한다. 두 점수가 모두 0.5 이상이어도 위험 0.6·확정 공격
0.9처럼 두 구간에 들지 않으면 시작하지 않는다. 첫 해당 요청부터 대상별 경로 파일의
`enforce`·`observe` 상한에 따라 원본 경로를 판정한다. 현재 점수 조합이 두 구간에서
벗어나면 새 발급·치환·원본 경로 차단은 중지한다. enforce에서는 유효한 기존 별칭 URL만
복원하고 만료·폐기된 별칭은 404(WS는 거부)로 처리하며 새 307 별칭을 발급하지 않는다.
observe는 기존 별칭 해석·관찰을 유지하고 audit은 요청을 변경하지 않는다.
Defense는 단계 계획의 지연·속도 제한을 먼저 실행하므로
별칭 404·307에도 해당 단계의 지연이 적용된다. 속도 제한이 429를 반환하면 별칭 조회
전에 끝난다.
Defense가 별칭을 복원한 경우에는 원래 경로·쿼리와 요청 ID·대상 ID·실행 ID를
`OVERLAY_DETECTOR_KEY`로 서명해 내부 응답 헤더로 돌려준다. Detection은 서명을
검증해 완료 요청의 경로별 분석에 사용하고, 두 피드백 헤더를 브라우저 응답에서 제거한다.
실제 오버레이로 라우팅된 응답에는 Defense가 내부 `X-Ruby-Overlay-Active: 1`을
붙인다. Detection은 이를 이용해 1단계 계획으로 점수가 내려갔어도 영속 오버레이의
로그인 응답을 미끼 응답으로 바꾸지 않는다. 이 헤더도 브라우저에는 전달하지 않는다.

### Defense → CHeaT sidecar

`X-Defense-Plan` 에서 **기만 전략만** 남겨 전달한다(`decoy_routing.decoy_plan`).
속도 제한과 지연은 Defense 가 직접 실행하고 sidecar 에 넘기지 않는다. 4단계는
지연을 먼저 실행해 429 응답에도 700ms를 적용한다. 속도 제한이 429를 반환하면
sidecar나 오버레이로 보내지 않는다. 운영·로컬 Compose는 CHeaT 내부 지연을 0으로
설정해 Defense 의 300·500·700ms에 추가 지연이 붙지 않게 한다.

Compose는 `DETECTION_POLICY_GATE_ENABLED=true`로 실행한다. Detection이 자체 응답하는
미끼 요청은 본문·자격 증명·미끼 URL을 보내지 않고 인증된
`/__defense/policy-gate`에 정책 식별 정보만 전달한다. Defense는 일반 프록시 요청과
동일한 행위자·실행 ID 상태로 지연과 속도 제한을 실행한다. 이미 오버레이에 들어간
행위자의 로그인 미끼는 Detection이 자체 응답하지 않고 Defense의 오버레이로 보낸다.
CRS가 요청을 먼저 차단한 경우에는 이 미끼 경로와 Defense를 통과하지 않는다.
독립 실행에서 `TARGET_URL`을 앱에 직접 연결하면 이 게이트는 기본적으로 꺼진다.
Juice Shop에서 현재 `stage3`·`stage4`인 원본 로그인 경로는 별칭 강제 규칙이 먼저
지연 후 404로 막으며, 발급된 별칭을 사용한 로그인만 오버레이에 도달한다.

오버레이 행위자의 `GET`/`HEAD` 요청 중 CHeaT 기본 미로 패턴 또는 대상별 추가
미끼 경로에 일치하는 요청은 CHeaT 로 보낸다. 실제 앱 경로와 겹치는 RUBY Shop의
`/admin`은 양쪽에서 제외한다. Defense 는 내부 `X-Defense-Decoy-Only: 1`을 붙이고
sidecar 는 미로 응답을 만들되 실제 대상에는 요청을 보내지 않는다. 미로가 일치하지
않아도 대상에 전달하는 대신 404로 끝낸다. 이외의 요청은 Defense 가 서명해 계정
오버레이로 보낸다. 오버레이가 처리한 일반 응답에는 CHeaT의 `Link`·HTML 주석·
`robots.txt` 미로 힌트가 새로 추가되지 않는다. 이미 알려진 미끼 경로는 계속
접근할 수 있다.

### CHeaT sidecar → Defense

| 헤더 | 뜻 |
| --- | --- |
| `X-Ruby-Decoy-Action` | 실제로 적용한 기만 동작 |
| `X-Ruby-Decoy-Strategies` | 적용된 기만 전략 목록(이전 요청의 sticky 포함) |

**둘 다 클라이언트 응답에서 제거된다.** sidecar 가 자기 응답에서 지우고
(`Defense_proxy.py`), Defense 가 기록한 뒤 공개 응답에서 다시 지운다. `ci.yml` 의
integration 단계가 공개 응답에 이 헤더가 없음을 단정한다. 대상이 보낸 같은 이름의
헤더도 제거한다.

### Defense → 계정 오버레이

Defense 가 HMAC 으로 서명한 라벨을 붙인다(`detector.sign_headers`):
`x-defense-class: agent`, `x-defense-actor`, `x-defense-timestamp`,
`x-defense-nonce`, `x-defense-signature`, 고위험이면 `x-defense-risk`.
서명 대상은 메서드·원본 raw target·본문 해시이며 고위험 등급은 HMAC 에 묶인다.
서명 없는 요청은 오버레이가 403 으로 거부한다.

오버레이는 두 가지 헤더 집합을 쓴다(`gateway_contract.py`):

- `overlay_headers` — 중위험에서 **원본 자격증명을 유지**해 실제 사이트로 전달한다.
- `isolation_headers` — 내부 미끼로 가는 호출. `accept`/`content-type` 과 미끼 자신의
  쿠키(`defense_session`, `defense_auth`, 조건부 `token`)만 통과시킨다. 운영
  Authorization·다른 쿠키·전달 헤더·클라이언트가 보낸 detector 라벨은 모두 제외한다.

### Defense → Detection (응답)

`X-Defense-Signal: rate_limited` 는 Defense 가 429 를 반환한 경우에만 되돌린다.
대상이 보낸 같은 이름의 헤더는 제거한다.

## 공개 응답에서 제거하는 헤더

`x-defense-*` 와 `x-ruby-*` 는 내부 제어 네임스페이스다. **요청 측과 응답 측 모두
접두어로 차단한다** — 요청은 `rubyPolicy.stripDetectionHeaders`, 응답은 Detection 의
마지막 복사 단계(`proxyCore.js` `isPrivateResponseHeader`)다. 이름을 열거하는 방식은
나중에 추가된 내부 헤더를 기본적으로 통과시켜서, 실제로 아래 네 개가 그렇게 샜다.

| 헤더 | 클라이언트가 알게 되는 것 |
| --- | --- |
| `X-Ruby-Resolved-Url` / `X-Ruby-Resolved-Url-Sig` | 별칭의 복원 경로와 그 서명 |
| `X-Ruby-Overlay-Active` | 이미 격리됐다는 사실 |
| `X-Defense-Delay-Ms` | 값이 곧 단계다(300·500·700ms) |
| `X-Defense-Signal` | 방어가 발동했다는 신호 |
| `X-Ruby-Request-Id` | 두 대시보드의 내부 조인 키 |
| `X-Defense-Applied` | 전략 목록만으로 단계가 식별된다 |

새 내부 응답 헤더는 두 네임스페이스 안에 두면 따로 등록하지 않아도 차단된다.
Defense 는 이 헤더들을 계속 Detection 으로 보내고 Detection 이 완료 기록에 남긴다 —
끊는 것은 클라이언트로 가는 중계뿐이라 대시보드 추적성은 그대로다. Detection 이
자기 응답에 직접 실을 수 있는 값도 같은 이유로 싣지 않는다(미끼 응답, 정책 게이트).

네임스페이스 밖이라 따로 다루는 것이 하나 있다. 내부 미끼는 예전에
`X-Request-Id` 로 자기 trace 를 돌려줬는데, 오버레이가 통과시키는 실제 origin
응답에는 그 헤더가 없어서 **미끼 응답만 구분되는 지문**이었다. 지금은 감사 기록에만
남긴다(`core.py`).

`X-Defense-Applied` 는 **upstream 사본만** 지운다. Detection 이 전달 전 검사에서
직접 거부한 요청에 붙이는 `X-Defense-Applied: crs` 는 프록시 앞단에서 끝나 이
복사 단계를 지나지 않으므로 그대로 남고, 운영 점검(`verify_request_inspection.py`)이
그 값을 확인한다. 전략 목록만으로 `none`·`delay`·`path_alias,delay`·
`path_alias,delay,rate_limit_strict` 가 단계와 1:1 이라 지연값만 지우는 것으로는
단계를 가릴 수 없다.

공개 응답에 남는 방어 흔적은 상태 코드와 CRS 거부 표시뿐이다.
`X-Ruby-Request-Id` 를 응답으로 되돌려 받아야 하는 실험·통합 테스트는
`DETECTION_EXPOSE_REQUEST_ID=true` 로만 켠다.

## 대상 선택 파일

Detection 이 유일한 writer 다(`detection/lib/targetSelection.js`, 임시 파일 생성 후
rename 으로 원자적). Defense 는 같은 named volume 을 `:ro` 로 다른 경로에 마운트해
읽는다. 요청마다 `X-Ruby-Target-Id`/`X-Ruby-Run-Id` 헤더로도 전달되고, Defense 는
**둘 다 있으면 헤더를, 없으면 파일을** 쓴다.

소유자와 검증 경계값은 [`shared/target-selection.json`](shared/target-selection.json)
에 선언하고 `defense/tests/test_target_selection_contract.py` 가 두 구현과의 일치를
강제한다: target ID `^[a-z][a-z0-9-]{0,31}$`, `runId` canonical UUID,
`changedAt` 파싱 가능한 ISO, 8192 바이트 상한.

## 이벤트 필드명

미끼 적중·차단·전략 적용 이벤트는 네 곳에서 따로 기록된다. 정본 이름과 저장소별
실제 이름은 [`shared/event-schema.json`](shared/event-schema.json) 한 곳에 선언하고
`defense/tests/test_event_schema.py` 가 선언과 구현의 일치를 강제한다.

정본 9개: `requestId`, `targetId`, `runId`, `actor`, `path`, `decoyAction`,
`strategies`, `outcome`, `occurredAt`.

이름을 강제로 통일하지 않은 두 곳과 이유도 그 선언 파일에 적혀 있다.

- Detection 은 `runId` 를 `targetRunId` 로 부른다 — 자체 실험 실행 ID
  (`experimentRunId`)가 따로 있어서 통일하면 내부에서 모호해진다. 값은
  `X-Ruby-Run-Id` 와 같다.
- CHeaT `reqs` 와 오버레이 링은 SQL 컬럼이라 snake_case 다. 이 테이블들을 경계 밖에서
  읽는 곳이 없어 컬럼 리네임은 마이그레이션 위험만 남는다.

알려진 공백: CHeaT `reqs` 는 `requestId`·`targetId` 를 담지 않아 sidecar 행은 Defense
이벤트와 경로·시각으로만 맞춰볼 수 있다.

## 공유 설정

`shared/` 가 편집 원본이고 각 서비스 트리에 사본을 함께 커밋한다. 네 이미지의 빌드
컨텍스트가 모두 하위 디렉터리라 Docker 가 `COPY ../` 를 금지하기 때문이다.

| 원본 | 쓰는 곳 |
| --- | --- |
| `shared/decoy-catalog.json` | 미끼 네임스페이스·진입 경로·단서 헤더·미끼 쿠키. Detection 의 `decoy_path_hit` 신호와 오버레이의 경로 판별이 같은 값을 본다 |
| `shared/event-schema.json` | 위의 정본 이벤트 필드명 |
| `shared/py/store.py` | SQLite 연결·트랜잭션·마이그레이션 공용 계층 (Python 3곳) |

원본을 고치면 `scripts/sync-shared.sh` 를 돌린다. `--check` 는 불일치 시 실패하고,
`defense/tests/test_shared_sources.py` 가 CI 에서 같은 검사를 한다.

CHeaT 의 미로 경로는 카탈로그가 아니라 `defense_proxy_v2/profiles.py` 의 프리셋
(`TARGET_PRESET`/`TARGET_PROFILE`)이 정한다. 카탈로그는 그 진입 경로를 선언만 하고
두 값의 일치는 계약 테스트가 강제한다.

## 신뢰 경계

Defense 에 직접 접속할 수 있으면 위 헤더를 위조할 수 있다. 배포에서 Defense 포트를
외부에 공개하지 말고 Detection 과 같은 비공개 네트워크에서만 접근시킨다.

`X-Client-Id` 가 검증된 `dcid` 일 때만 확정 공격 점수가 쌓이고 `stage2`~`stage4`의
계정 오버레이·속도 제한이 가능하다. 쿠키를 돌려주지 않는 요청은 같은 IP·HTTP 지문의
관찰 후보로 판단하며, 그 공유 지문은 계정 오버레이·속도 제한·새 경로 별칭 발급에 쓰지
않는다. 확정 공격 점수가 없으면 위험 점수가 0.5 이상이어도 별칭을 시작하지 않는다.
Detection의 요청 전 CRS 검사는 별칭 URL을 보지만, 서명된 피드백을 받은 완료 요청의
경로별 점수는 복원된 URL로 계산한다.

`routes.sqlite3` 와 `security.sqlite3` 는 실패가 503 이 되는 fail-closed 저장소라
요청마다 쓰는 저장소와 파일을 공유하지 않는다. 자세한 이유는
[`defense/README.md`](defense/README.md)의 "영속 저장소" 절에 있다.
