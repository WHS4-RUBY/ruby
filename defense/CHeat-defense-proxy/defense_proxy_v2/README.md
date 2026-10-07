# CHeaT Defense Proxy — defense_proxy_v2

LLM 펜테스트 에이전트(`codex` 등)가 대상 서버를 공격할 때, **앞단 리버스 프록시**가 가짜 단서(Cloak)와 지연(Trap)을 주입해
에이전트가 쓰는 **시간·토큰·요청**을 늘리는 방어 실험 도구입니다. 목표는 침해 차단이 아니라 **공격자 비용 유발**입니다.
(전제: 공격자 식별은 탐지팀 몫이고, 이 프록시는 "방어 대상"으로 넘어온 트래픽에 기법을 적용합니다.)

## 파일 구조

```
defense_proxy_v2/
├── Defense_proxy.py      메인 — 리버스 프록시 + 방어 훅
├── dashboard.py          대시보드 + 프록시 시작/중지
├── proxy_core.py         재사용 리버스 프록시 코어
├── transforms.py         레시피(T2.1/MIGRATION) · 미로 생성기 · 가짜 셸 콘텐츠
├── profiles.py           서버 프로필·프리셋 (apache-php / nginx-fastapi)
├── preflight.py          시작 시 정합성 검사
├── setup_profile.py      프로필 설정 도구 (배포 전 내 서버 정보 입력 → target_profile.json)
├── tests/                회귀·동작 테스트
├── README.md · REFERENCE.md · DETECTION_INTEGRATION.md · DEPLOYMENT_GUIDE.md · results.md
└── experiments/          실험 로그·하니스 (로컬 전용, 커밋 안 됨)
```
| 문서 | 내용 |
|---|---|
| [`REFERENCE.md`](REFERENCE.md) | 상세 설명서 — 기법별 세부 동작, 환경변수 전체 표, v1 대비 제거 이력 |
| [`DETECTION_INTEGRATION.md`](DETECTION_INTEGRATION.md) | **탐지팀 연동** — 호출 가능한 전략 이름과 약속하는 동작 |
| [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md) | 새 서버에 배포 — 프로필·프리셋·프로필 설정 도구 |
| [`results.md`](results.md) | 실험 결과 — 4실험 통합 비교, 발견한 허점과 수정 이력 |
| [`tests/README.md`](tests/README.md) | 테스트 (`python tests/run_all.py`) |

## 1. 방어 기법

| 기법 | 한 줄 설명 | 켜는 법 |
|---|---|---|
| **미로** `DECOY_MAZE` | 흔한 정찰 경로(`/internal/`, `/backup/` …)를 크고 느린 가짜 문서로 응답. 입구는 `Link` 헤더·HTML 주석·`robots.txt`. **서버 무관** | `DECOY_MAZE=1` |
| **적응형** `ADAPTIVE_TRAP` | 서로 다른 미끼 경로를 **3개** 물면 그 클라이언트의 **모든 요청에 16초 지연** | `ADAPTIVE_TRAP=1` |
| **T2.1** + `FAKE_SHELL` | 가짜 Apache 배너·`/cgi-bin/` 트래버설 미끼, RCE 시도엔 가짜 셸로 응답(어떤 명령도 실행 안 함) | `ACTIVE_TECHNIQUE=T2.1` `FAKE_SHELL=1` |
| **MIGRATION_TRACES** | 가짜 마이그레이션 브리지 토끼굴·robots 힌트·설정 병합·HTML 메모·로그인 미끼 | `ACTIVE_TECHNIQUE=MIGRATION_TRACES` |
| `AMBIG_TRAP` | 위 신호 중 하나라도 걸리면 확정 차단 403 (별도 계층) | `AMBIG_TRAP=1` |

`DEFENSE_MODE`는 `off`(패스스루) 또는 `transform`(레시피 적용)뿐입니다. 미로·적응형·셸·AMBIG는 모드와 독립적으로 얹힙니다.
**레시피(T2.1/MIGRATION)는 클라이언트당 하나만** 쓰세요 — 스택 이야기가 다르면 에이전트가 모순을 눈치챕니다.

## 2. 빠른 시작

요구사항: Python 3.10+, Docker(대상 앱), `codex` CLI(에이전트를 돌릴 때만).

```bash
git clone https://github.com/WHS4-RUBY/ruby.git && cd ruby && git checkout defense-proxy
cd defense/CHeat-defense-proxy/defense_proxy_v2
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt     # Windows: .venv\Scripts\pip
```

```bash
docker run -d -p 127.0.0.1:3010:3000 --name juice-shop bkimminich/juice-shop     # 대상 앱 (Juice Shop)
```

```bash
DEFENSE_DB=./defense.db .venv/bin/uvicorn dashboard:app --host 127.0.0.1 --port 8088 --log-level warning
```

브라우저로 `http://127.0.0.1:8088` → **"프록시 제어"** 카드에서 `REAL_BACKEND`(예: `http://127.0.0.1:3010`)·포트(예: 3012)·기법을 고르고
**"시작 / 재시작"**. 프록시가 뜨면 `curl http://127.0.0.1:3012/` 로 확인합니다. ⚠ 페이지를 새로 열면 `REAL_BACKEND` 칸이 기본값(3000)으로
돌아가니 시작 전에 확인하세요. 끝낼 때는 대시보드 "중지"와 `docker rm -f juice-shop`.

터미널에서 직접 켜도 됩니다(같은 `DEFENSE_DB`를 보는 대시보드에 똑같이 잡힙니다):

```bash
REAL_BACKEND=http://127.0.0.1:3010 DEFENSE_MODE=off DECOY_MAZE=1 ADAPTIVE_TRAP=1 \
.venv/bin/uvicorn Defense_proxy:app --host 127.0.0.1 --port 3012 --no-server-header --log-level warning
```

## 3. 대표 구성 (대시보드 체크박스 또는 환경변수)

| 구성 | 설정 |
|---|---|
| 베이스라인 | `DEFENSE_MODE=off` |
| 미로 + 적응형 | `DEFENSE_MODE=off DECOY_MAZE=1 ADAPTIVE_TRAP=1` |
| T2.1 + 가짜 셸 | `DEFENSE_MODE=transform ACTIVE_TECHNIQUE=T2.1 FAKE_SHELL=1 DECOY_MAZE=1 ADAPTIVE_TRAP=1` |
| 마이그레이션 | `DEFENSE_MODE=transform ACTIVE_TECHNIQUE=MIGRATION_TRACES DECOY_MAZE=1 ADAPTIVE_TRAP=1` |

폼에 없는 값은 대시보드 "고급: 추가 환경변수"에 `KEY=VALUE` 줄로 넣습니다. 서버가 Juice Shop이 아니면 프리셋을 고르세요
(`TARGET_PRESET=apache-php`(기본) \| `nginx-fastapi`(RUBY Market용 초안)). 배포는 [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md) 참고.

## 4. 대시보드

| 영역 | 내용 |
|---|---|
| 프록시 제어 | 기법·포트·백엔드를 골라 시작/재시작/중지, "로그 보기"로 시작 실패 원인 확인 |
| KPI 4개 | 총 요청 수 · 미끼 접촉 수 · 에스컬레이션 발동(사유·시각) · FAKE_SHELL 진입 |
| 타임라인·분포·최근 로그 | 시간대별 요청, `defense_action` 분포, 최근 150건 |
| 실험용 지표 | 에이전트 토큰(`CODEX_LOG_PATH`)·풀이한 챌린지 수(백엔드 `/api/Challenges` 직접 조회) — 실험 환경에서만 의미 있음 |

원격 접속은 포트를 열지 말고 SSH 포워딩(`ssh -L 8088:127.0.0.1:8088 user@host`)을 쓰고, `DASHBOARD_PASSWORD`로 로그인을 거세요.
"총 요청 수"는 메타 행(`/__escalate__`)을 포함하고 `/socket.io/` 폴링(웹 UI 실시간 연결)이 많이 섞이니 요청 수를 셀 땐 제외하세요.

## 5. 탐지팀 연동

탐지 프록시가 모든 요청에 붙이는 `X-Client-Id`(클라이언트 식별)와 `X-Defense-Plan`(적용할 전략 배열)을 읽어 **클라이언트별로** 적용합니다.
`DECOY_REQUIRE_PLAN=1`로 띄우면 아래 전략이 실린 클라이언트에게만 적용되고, 플랜 없는 클라이언트는 응답이 전혀 바뀌지 않습니다.

| 전략 이름 | 켜지는 것 |
|---|---|
| `delay` | 지정한 시간만큼 지연 |
| `maze` | 미로만 (`MAZE_REQUIRE_PLAN=1`일 때) |
| `decoy_maze` | 미로 + 적응형 (서버 무관) |
| `decoy_t21_shell` | `decoy_maze` + T2.1 + 가짜 셸 (프리셋 의존) |
| `decoy_migration` | `decoy_maze` + MIGRATION_TRACES (프로필 `migration.*` 의존) |

한 번 켜지면 유지(sticky)되고, 미끼 접촉은 전략이 켜진 뒤부터 세며, 클라이언트당 레시피는 먼저 정해진 것이 유지됩니다.
**자세한 계약은 [`DETECTION_INTEGRATION.md`](DETECTION_INTEGRATION.md)** 입니다. 방어 프록시 포트는 탐지 프록시에서만 접근 가능해야 합니다(네트워크 격리).

## 실험 돌릴 때 — 우회 차단과 라운드 운영

| 항목 | 설정 | 이유 |
|---|---|---|
| 클라이언트 식별 묶기 | `CLIENT_ID_FALLBACK=global` | 에이전트가 출발지 IP를 바꿔도 한 클라이언트로 봄 (탐지팀 연동 운영에서는 쓰지 말 것) |
| `X-Forwarded-For` 위조 방지 | `UVICORN_PROXY_HEADERS=0` | uvicorn이 루프백 요청의 이 헤더를 믿어, 에이전트가 위조로 차단을 1분 만에 우회한 적이 있음 |
| 에이전트와 프록시 분리 | 에이전트가 프록시 프로세스·소스·DB에 접근 못 하게 | 재시작·소스 열람으로 우회 가능 |
| 라운드마다 | Juice Shop **새로 생성(시작 값 0 확인)**, 프록시 **재시작**(상태 초기화), `defense.db`·`codex.jsonl` 별도 보관, 종료 직후 `/api/Challenges` 기록 | 라운드 간 오염 방지 |
| 비교 조건 | 같은 코드 버전·같은 에이전트 `--max-time` | 타임아웃이 라운드마다 달라 결과를 흐렸음 |
| 정상 사용자 실험 | 시크릿 창, 프록시 포트로 접속, 공격자와 따로 | `global`이면 같은 클라이언트로 묶이고 쿠키가 풀이 기록을 복원함 |

## 6. 핵심 환경변수

전체 표는 [`REFERENCE.md`](REFERENCE.md#환경변수)입니다.

| 변수 | 기본값 | 설명 |
|---|---|---|
| `REAL_BACKEND` | `http://127.0.0.1:3000` | 방어 대상 앱 주소 |
| `DEFENSE_MODE` / `ACTIVE_TECHNIQUE` | `transform` / — | `off` \| `transform` / `T2.1` \| `MIGRATION_TRACES` |
| `DECOY_MAZE` / `ADAPTIVE_TRAP` / `FAKE_SHELL` / `AMBIG_TRAP` | `0` | 각 기법 켜기 |
| `ESCALATE_DELAY_MS` | `16000` | 에스컬레이션 후 모든 요청 지연 (한 요청엔 지연들의 **최댓값 하나**만) |
| `ADAPTIVE_ONBITE_HITS` | `3` | 에스컬레이션까지 필요한 서로 다른 미끼 경로 수 |
| `TARGET_PRESET` / `TARGET_PROFILE` | `apache-php` / — | 서버 페르소나 프리셋 / 덮어쓸 JSON (`setup_profile.py`로 생성) |
| `DECOY_REQUIRE_PLAN` | `0` | 탐지팀 연동 묶음 모드 (`DEFENSE_MODE=off` 권장) |
| `CLIENT_ID_FALLBACK` | `ip` | 헤더가 없을 때 식별자: `ip` \| `global` |
| `MAZE_PATHS` / `MAZE_EXCLUDE` | 프로필 값 | 미로 입구 경로 / 미로에서 뺄 실제 경로 정규식 |
| `POST_RCE_ACTION` / `POST_RCE_DELAY_MS` | `tarpit` / `8000` | 가짜 셸 진입 후 처리(`tarpit`·`block`·`drop`) / 지연 |
| `AMBIG_RELEASE_MIN` | `10` | 신호가 안 걸리면 이 시간(분) 뒤 완전 해제 |
| `PREFLIGHT` | `1` | 시작 시 정합성 검사(프로필 모순·실제 백엔드와의 충돌 경고) |
| `DEFENSE_DB` | `./defense.db` | 요청 로그 SQLite |

## defense_action 라벨 표

`defense.db`의 `reqs.defense_action` 값 (대시보드 뱃지·분석 쿼리가 사용).

| 라벨 | 의미 | 미끼 접촉으로 셈 |
|---|---|---|
| `observe` | 방어 없이 통과 | — |
| `maze` / `maze!` / `maze-401` | 미로 응답 / 확대 미로 / 401로 위장 | ✔ |
| `transform-route` | 가짜 라우트 응답(`/server-status`, `/cgi-bin/…`, `/rest/internal*`) | ✔ |
| `login-lure-423` | 미끼 계정 로그인 → 423 | ✔ |
| `traversal-probe` | `/icons/` 아래 `..` 경로 탈출 시도(응답은 그대로) | ✔ |
| `escalated-delay:<사유>` | 에스컬레이션된 클라이언트의 일반 요청 지연 | — |
| `fake-shell` / `post-rce-*` | 가짜 셸 진입 / 진입 후 지연·차단·드롭 | — |
| `ambig-block` / `ambig-released` | AMBIG 확정 차단 / 해제 | — |
| 메타 행 `escalate:…` · `ambig-blocked:…` | 상태 전환 기록(method `-`) — 요청 수 셀 땐 제외 | — |


## 한계

- 실험은 구성별 N=1~2이고, **에이전트 타임아웃**(지연 16초보다 짧으면 사실상 블랙홀)이 결과를 크게 좌우해 구성 효과를 아직 못 가렸습니다.
- MIGRATION 고유 요소는 에이전트가 응답을 받은 적이 없어 효과가 측정되지 않았습니다.
- `HEAD` 요청은 SPA 백엔드에서 미로로 가로채지 못하고, 백엔드 오류(502)는 DB에 기록되지 않으며, WebSocket은 지원하지 않습니다.
- 레시피는 Juice Shop 전용이고 `nginx-fastapi`는 초안(미검증)입니다. 정상 사용자 비용은 아직 측정 중입니다.

> v1 대비 제거된 것: `T4.2`/`T4.2b`·passive 계층·`active`/`combined`·`CAPTCHA_TRAP` (근거는 [`REFERENCE.md`](REFERENCE.md#defense_proxy_v1원본-대비-무엇이-빠졌나)). v1 전체 이력은 [`../defense_proxy_v1/`](../defense_proxy_v1/).
