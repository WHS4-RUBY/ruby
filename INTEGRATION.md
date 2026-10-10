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
| `X-Ruby-Defense-Tier` | `confirmed` 또는 `suspected` |
| `X-Ruby-Policy-Source` | 점수 출처 |
| `X-Ruby-Candidate-Id` / `X-Ruby-Client-Flow-Id` | 관찰 흐름 표시 전용. 전략 선택에 쓰지 않는다 |

클라이언트가 보낸 같은 이름의 헤더는 Detection 이 먼저 지운다. Defense 도
`_DEFENSE_INTERNAL_HEADERS` 로 한 번 더 지우고 대상에게 전달하지 않는다.
`X-Forwarded-For` 는 Detection 이 항상 무시한다.

### Defense → CHeaT sidecar

`X-Defense-Plan` 에서 **기만 전략만** 남겨 전달한다(`decoy_routing.decoy_plan`).
속도 제한과 지연은 Defense 가 직접 실행하고 sidecar 에 넘기지 않는다. 속도 제한이
429 를 반환하면 sidecar 로 보내지 않는다.

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

`X-Client-Id` 가 검증된 `dcid` 일 때만 확정 공격 점수가 쌓이고 `confirmed` 단계의
차단·계정 격리가 가능하다. 쿠키를 돌려주지 않는 요청은 같은 IP·HTTP 지문의 관찰
후보로 판단하며, 그 공유 지문은 `suspected` 미끼 단계까지만 쓴다.

`routes.sqlite3` 와 `security.sqlite3` 는 실패가 503 이 되는 fail-closed 저장소라
요청마다 쓰는 저장소와 파일을 공유하지 않는다. 자세한 이유는
[`defense/README.md`](defense/README.md)의 "영속 저장소" 절에 있다.
