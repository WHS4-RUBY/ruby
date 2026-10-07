# 탐지 → 공식 Defense → CHeaT 사이드카 연동 가이드

탐지 프록시가 공식 Defense에 요청을 전달하고, 공식 Defense가 선택한 대상의 CHeaT
사이드카를 내부망에서 호출합니다. 사이드카는 방어 플랜을 적용한 뒤 실제 벤치마크
웹 서비스로 전달합니다. 탐지 설정의 `TARGET_URL`은 공식 Defense를 가리킵니다.

---

## 1. 연결 구조

```
공격자 → 공개 :80 → Detection → 공식 Defense
                                  ├─ Juice Shop CHeaT :3012 → Juice Shop
                                  └─ RUBY Shop CHeaT :3012 → RUBY Shop
```

공식 Defense는 요청의 대상 선택 결과와 CHeaT 플랜을 보고 해당 대상의 사이드카로
보냅니다. 사이드카는 Docker 내부 포트 3012만 사용하며 호스트 포트를 열지 않습니다.
`REAL_BACKEND`는 각 사이드카에서 해당 벤치마크 컨테이너를 가리킵니다.
공식 관리자 대시보드는 8088 루프백 리스너에 유지됩니다. 공개 :3020 벤치마크
선택 화면은 이 공격 실험 경로를 거치지 않습니다.

운영 Compose는 `DEFENSE_MODE=off`, `DECOY_REQUIRE_PLAN=1`,
`CLIENT_ID_FALLBACK=ip`, `UVICORN_PROXY_HEADERS=0`으로 사이드카를 실행합니다.
이 설정에서 플랜이 없는 정상 요청에는 미로·레시피 변조가 적용되지 않습니다.
대상별 `TARGET_PRESET`은 Juice Shop에 `apache-php`, RUBY Shop에
`nginx-fastapi`를 사용합니다. RUBY 프리셋의 미로 목록에서는 실제 웹 라우트가
될 수 있는 `/admin/`을 제외했습니다. 새 벤치마크 경로를 추가할 때는
`MAZE_EXCLUDE`와 preflight 결과를 검토하십시오.

사이드카의 `BACKEND_TIMEOUT_S` 기본값은 30초입니다. 공식 Defense 및
Detection의 타임아웃도 함께 검토해야 긴 미끼 지연이 502로 끊기지 않습니다.
프록시가 응답 전체를 메모리에 버퍼링하므로 대용량 응답과 SSE에는 적합하지
않습니다. WebSocket도 이 사이드카를 통과하지 않습니다.

---

## 2. 전달 헤더

### `X-Client-Id`

```
X-Client-Id: <탐지팀이 계산한 가명 식별자>
```

- 공식 Defense가 내부 헤더를 재발급합니다. 사이드카는 `X-Ruby-Run-Id`와
  `X-Client-Id`를 함께 상태 키로 사용하므로 서로 다른 실험 실행의 미로·레시피·차단
  상태가 섞이지 않습니다. 각 상태는 기본 3600초(`CLIENT_STATE_TTL_S`로 조절)
  동안 요청이 없으면 자동으로 청소됩니다.
- 헤더가 없는 요청(저희 프록시에 직접 붙는 로컬 실험 등)은 접속 IP로 폴백합니다. 탐지 레이어 없이 공격자 하나만
  상대하는 저희 로컬 실험에서는 출발지 IP 가 요청마다 바뀌는 환경이 있어서 `CLIENT_ID_FALLBACK=global`(헤더 없는 요청을
  한 클라이언트로 묶기)을 쓰기도 하는데, **헤더가 있으면 항상 헤더가 우선**이라 연동을 켜는 순간부터는 지금 설명한 대로
  `X-Client-Id` 값별로 분리됩니다. 연동 운영 환경에서는 이 옵션을 쓰지 않습니다.

### `X-Defense-Plan`

```
X-Defense-Plan: [{"name": "delay", "params": {"delay_ms": 300}}, ...]
```

- `detection/lib/policyEngine.js`의 `applyDefensePlan`이 `detection/config/policy.json`의
  `defense.rules`(리스크 점수 구간별 전략 배열)를 그대로 JSON 직렬화해서 보냅니다.
- 공식 Defense가 전체 플랜에서 CHeaT 전략만 사이드카로 전달합니다. 현재
  `policy.json`의 고위험 확정 공격 구간에는 공식 Defense의 `rate_limit_strict`와
  `delay`, CHeaT의 `decoy_maze`가 함께 있습니다. 사이드카는 전달받은
  `decoy_maze`와 아래의 확장 전략을 적용합니다.
- **`maze` 전략(선택)**: `{"name": "maze", "params": {}}` 가 플랜에 있는 클라이언트에게만 가짜 미로
  (robots 미끼·HTML 주석·`Link` 헤더·가짜 경로 응답)를 켜고 싶으면 저희 쪽을 `MAZE_REQUIRE_PLAN=1` 로
  띄웁니다. 플랜에 한 번이라도 실린 클라이언트는 이후 요청에서도 미로가 유지됩니다(입구를 본 뒤 갑자기 사라지면
  이상하므로). `MAZE_REQUIRE_PLAN` 이 꺼져 있으면(기본) 미로는 지금처럼 모든 클라이언트에 적용되고 `maze` 이름은
  기록만 됩니다. 보내실 때 `params` 는 필요 없습니다. 위험 점수가 낮은 정상 사용자에게 미로 입구(주석·헤더)가
  노출되는 것을 피하려는 용도입니다.
- **`decoy_maze` 전략(묶음 1 — 미로 + 적응형, 서버 무관)**: `{"name": "decoy_maze", "params": {}}` 가 플랜에 실린
  클라이언트에게 가짜 미로와 적응형 에스컬레이션(서로 다른 미끼 경로 3개를 물면 이후 모든 요청 지연)을 **함께** 켭니다. 저희 쪽을
  `DECOY_REQUIRE_PLAN=1` 로 띄우면 이 이름이 실린 클라이언트에게만 적용되고, 실리지 않은 클라이언트는 응답이 전혀 바뀌지 않습니다
  (헤더·주석·미로 모두 없음). 약속하는 동작:
  - **한 번 켜지면 유지(sticky)** — 플랜이 끊기거나 위험 점수가 내려가도 해당 클라이언트의 미로·에스컬레이션은 유지됩니다(상태는
    `CLIENT_STATE_TTL_S` 동안 조용하면 청소).
  - **미끼 접촉은 이 전략이 켜진 뒤의 접촉부터 셉니다.** 켜지기 전에 우연히 건드린 경로가 쌓여 있다가 켜지는 순간 즉시 에스컬레이션되는 일은 없습니다.
  - `maze`(미로만)는 그대로 쓸 수 있고, 적응형은 `decoy_maze` 에서만 켜집니다.
  - 클라이언트와 실험 실행별로 격리됩니다(`X-Client-Id`, `X-Ruby-Run-Id`). 다른 실행의 에스컬레이션은 영향이 없습니다.
  - `AMBIG_TRAP`(확정 차단)은 이 묶음에 포함되지 않습니다 — 별도 환경변수이고, 켜져 있으면 `decoy_maze` 가 켜진 클라이언트의 에스컬레이션 신호를 재사용합니다.
  - **`Server` 헤더**: 이 모드에서는 미로가 적용된 클라이언트에게 프로필의 배너(`web.server_banner`)를 `Server` 로 보여 줍니다(대상과 맞는 프리셋을
    고르면 실제 배너와 같습니다). 나중에 레시피 묶음으로 올라가도 배너가 바뀌지 않습니다.
- **묶음 3개 한눈에** — 단계(위험 점수 구간)와 무관하게 아무 요청에서나 아무 묶음을 호출할 수 있고, `delay` 와 한 플랜에 같이 넣어도 됩니다.

  | 전략 이름 | 켜지는 것 | 서버 의존 |
  |---|---|---|
  | `decoy_maze` | 미로 + 적응형 에스컬레이션 | 없음(서버 무관) |
  | `decoy_t21_shell` | `decoy_maze` + **T2.1 레시피**(가짜 Apache 배너·`/server-status`·`/cgi-bin/` traversal 미끼·robots 힌트) + **FAKE_SHELL**(RCE 시도에 가짜 셸) | 프리셋(`TARGET_PRESET`/`TARGET_PROFILE`) |
  | `decoy_migration` | `decoy_maze` + **MIGRATION_TRACES 레시피**(가짜 마이그레이션 브리지 토끼굴·robots 힌트·설정 병합·HTML 메모·로그인 미끼) | 프로필의 `migration.*` |

  레시피 묶음에서 주의해야 할 점:
  - **클라이언트당 레시피는 하나, 먼저 정해진 것이 유지됩니다.** 이미 `decoy_t21_shell` 인 클라이언트에 `decoy_migration` 이 오면(반대도 같음) 레시피·셸은 바뀌지 않고
    미로+적응형만 유지됩니다(프록시 로그에 충돌 안내). 스택 이야기가 다른 두 레시피를 한 클라이언트에게 섞어 주면 에이전트가 모순을 눈치채기 때문입니다.
  - `decoy_maze` → `decoy_t21_shell`/`decoy_migration` **승급은 자연스럽게 됩니다**(`Server` 배너가 바뀌지 않음).
  - 플랜이 없는 클라이언트는 가짜 라우트(`/server-status`, `/cgi-bin/…`, `/rest/internal` 등)·가짜 셸·헤더 위조가 **전혀 적용되지 않고** 요청이 그대로 백엔드로 갑니다.
    다른 레시피 클라이언트의 가짜 라우트도 마찬가지입니다(레시피별로 격리).
  - 가짜 셸은 `decoy_t21_shell` 이 켠 클라이언트에만 적용됩니다(환경변수 `FAKE_SHELL` 은 이 모드에서 무시됩니다). 진입 후 지연은 `POST_RCE_*` 설정을 따릅니다.
  - `AMBIG_TRAP` 은 여전히 묶음과 별개입니다.
- **모르는 전략 이름은 조용히 무시**합니다(로그만 남김, 에러 아님). 탐지팀이 `policy.json`에
  새 전략 이름을 먼저 추가해도 저희 쪽이 그 이름을 등록하기 전까지는 그냥 무시될 뿐 요청이
  깨지지 않습니다.

---

## 3. 앞으로: 새 전략(=CHeaT 기법) 이름 추가하기

탐지팀이 "리스크 점수에 따라 적용할 CHeaT 기법 자체를 전략 이름으로 지정해서 넘기겠다"고
한 부분은 이 틀 위에서 바로 확장 가능합니다.

1. 탐지팀이 `policy.json`에 새 규칙을 추가합니다. 예(미로는 이미 `maze` 이름으로 구현돼 있습니다):
   ```json
   { "min_score": 0.8, "max_score": 1.01,
     "strategies": [{ "name": "maze", "params": {} }] }
   ```
2. 저희가 `Defense_proxy.py`의 `_DEFENSE_PLAN_STRATEGIES` 레지스트리에 그 이름에 대응하는
   핸들러를 등록합니다.


---

## 4. 내부 신뢰 경계

공격자가 공개 :80에서 보낸 `X-Client-Id`, `X-Defense-Plan`, `X-Ruby-*` 등은
Detection 및 공식 Defense에서 제거·재발급해야 합니다. CHeaT 사이드카는
공식 Defense와 같은 내부 Docker 네트워크에서만 접근 가능해야 합니다.
사이드카는 내부 플랜·클라이언트·실험 헤더를 읽되 실제 벤치마크 대상에는
전달하지 않습니다. 공식 Defense가 설정한 공개 `X-Forwarded-Host`와
`X-Forwarded-Proto`만 형식 검증 후 대상에 전달합니다. `Forwarded`와
`X-Forwarded-For`는 버리며, Uvicorn의 프록시 헤더 신뢰도 끕니다.

사이드카는 `X-Ruby-Decoy-Action` 및 `X-Ruby-Decoy-Strategies` 응답 헤더를
공식 Defense에만 돌려줍니다. 대상이 같은 이름의 헤더를 보내더라도 사이드카가
제거한 뒤 직접 기록합니다. 공식 Defense는 이 값을 모니터링에 반영하고 공개
응답에서는 제거합니다. `X-Ruby-Decoy-Strategies`는 이번 요청의 delay와
현재 실험·클라이언트에 유지되는 sticky 미끼 전략을 나타냅니다.

---

## 5. 연동 테스트

로컬에서는 `python tests/test_pipeline_contract.py`로 내부 헤더 차단, 공개
Origin 전달, 대상의 응답 헤더 위조 차단, 실험별 sticky 상태, 텔레메트리를
검증합니다. 전체 CHeaT 회귀 테스트는 `python tests/run_all.py`로 실행합니다.
Compose 통합 테스트는 공개 :80으로 정상 요청과 미끼 요청을 보내고 공식
탐지·방어 대시보드의 동일 request ID/대상/전략/action을 확인합니다.
대상 서비스를 3020으로 직접 호출한 요청은 이 파이프라인의 이벤트가 아닙니다.

---

## 6. 운영 제한

- **응답 지연 상한**: 방어 쪽은 `ADAPTIVE_TRAP` 에스컬레이션 시 모든 요청에 `ESCALATE_DELAY_MS`(기본 16초),
  `FAKE_SHELL` 진입 후 `POST_RCE_DELAY_MS`(8초)/`drop`(응답 없음) 같은 긴 지연을 건다. 탐지 프록시·상위 계층의 요청
  타임아웃과 겹치면 정상 요청이 끊길 수 있다 — 상위 타임아웃을 지연 설정보다 크게 잡거나 지연값을 조정할 것.
- **오탐 시 영향**: 에스컬레이션은 실험 실행·클라이언트별로 유지되고 모든 경로에 걸리며(서로 다른 미끼 경로 3개 기준), AMBIG 차단은
  해제가 없다. 운영 설정의 `DECOY_REQUIRE_PLAN=1`은 플랜 없는 정상 요청에 미로를 보이지 않는다.
- **WebSocket**: 방어 프록시(`proxy_core.py`)에는 HTTP 중계만 구현돼 있고 WebSocket 처리가 없다 — 대상 앱이 쓰면 별도 경로로 우회해야 한다.
