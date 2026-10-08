# defense_proxy_v2 — 상세 레퍼런스

> 처음 보는 사람은 [`README.md`](README.md)(200줄 이내 요약)를 먼저 읽는다. 이 문서는 예전 README 전체를 그대로 옮긴 **상세 설명서**다 —
> 미로 안전장치 표, 적응형·가짜 셸·AMBIG 세부 동작, 환경변수 전체 표, v1 대비 제거 이력 등이 여기 있다.

LLM 펜테스트 에이전트(`codex` 등)를 상대로 CHeaT(*Cloak · Honey · Trap*, USENIX
Security '25)의 방어 아이디어를 리버스 프록시로 주입해, 에이전트가 소모하는 **시간·토큰·요청·명령
수**가 무방어 대비 얼마나 늘어나는지 측정하는 실험 도구.

## 전제

- **공격자 식별은 하지 않는다.** Policy Engine이 이미 "이 트래픽은 방어 대상"으로 판정했다고 가정.
- **Honey(허니토큰 탐지)는 범위 밖.** Cloak(오도)과 Trap(지연·자원 소모)만 다룬다.
- 침해 차단은 애플리케이션의 몫. 프록시의 목표는 **공격자 비용 유발**이지 차단이 아니다.

## `defense_proxy_v1`(원본) 대비 무엇이 빠졌나

| 제거된 것 | 이유 |
|---|---|
| **transform `T4.2`** (리스트 응답 json_pad, `/api/Feedbacks` ~1MB 플러딩) | INPUT 토큰만 태우고 이후 턴에서 prompt caching 으로 효과 줄어듦 |
| **`escalation_flood()` + `_T42_PAD`** (ADAPTIVE_TRAP 발동 시의 `/api/Feedbacks` 플러딩과 그 데이터) | 위와 같은 캐싱 약점을 그대로 물려받아 완전히 제거 — 발동 시 Trap은 이제 더 큰 tarpit 지연(`ESCALATE_DELAY_MS`)만 사용 |
| **`T4.2b`** (확인응답형 페이지네이션, `T42B*` env 전부) | 단독 효과가 약했고(codex 가 `jq`/`perl` 등으로 체크포인트를 스크립트로 추출·재제출, `../defense_proxy_v1/results.md`) 코드·설정 복잡도 대비 이득이 불분명해 최종 제거. 과거 실험 기록은 `results*.md`에 그대로 남아 있다 |
| **transform `T1.2`/`T4.1`/`T4.3`/`T6.3`** | T2.1/MIGRATION_TRACES 대비 효과가 검증되지 않아 함께 제외 |
| **passive 계층 전체** (`defense_payloads.json`, `DEFENSE_MODE=passive`) | 대부분의 payload 는 Batch 1에서 codex 가 즉시 "프록시가 응답을 변조/인젝션한다"고 판정. 예외로 남겼던 `T4.2-bare`(개발자 메모 주석)는 옛 `T2.2`와 같은 "마이그레이션 중 남은 흔적" 이야기라 `MIGRATION_TRACES` 레시피에 흡수했다 |
| **`active` / `combined` 계층** (`DEFENSE_MODE=active\|combined`, `DEFENSE_ACTION`, `DELAY_MS`) | 모든 요청에 게이트 없이 무조건 tarpit/차단하는 계층. 정상 사용자도 똑같이 느려지거나 막혀서 "미끼를 문 클라이언트에게만 비용을 지운다"는 이 프록시의 방향과 맞지 않아 제거. 지연은 이제 `ADAPTIVE_TRAP` 에스컬레이션·`FAKE_SHELL` 의 `POST_RCE_ACTION`·미로 응답 지연으로만 걸린다. 켜면 시작 시 안내하고 종료한다. 과거 실험 기록(`results*.md`)은 그대로 남아 있다 |

**남은 것**(원본 그대로): `FAKE_SHELL`(RETRIES/GRACE_CMDS/`POST_RCE_ACTION=drop` 포함),
`DECOY_MAZE`, `ADAPTIVE_TRAP`, transform `T2.1`/`MIGRATION_TRACES`(옛 `T2.2` + `T4.2-bare` 합본).
(v1 Batch 9의 FAKE_SHELL × T4.2b × maze/max 3중 결합과 `active` 기반 max 구성은 T4.2b·active 제거로
이 디렉터리에서는 더 이상 그대로 재현되지 않는다 — 필요하면 `../defense_proxy_v1`을 쓴다.)

**v2에서 시도했다가 뺀 것**: `CAPTCHA_TRAP`(사람 확인 미끼) — 한 번도 실제로 시험되지
못했고(AMBIG_TRAP Round 2·3 모두 에이전트가 미끼 경로에 도달 안 함) 유지 비용 대비 근거가
없어 제거했다. 시도 기록의 요약은 `results.md` §6.2.

---

## 요구사항

| 도구 | 용도 |
|---|---|
| Python 3.10+ | 프록시·대시보드 실행 (`requirements.txt`: fastapi · uvicorn · httpx) |
| Docker | 대상 앱 컨테이너 (`bkimminich/juice-shop`) |
| `codex` CLI | 공격 에이전트 (`codex exec --json`) — 대시보드만 써보는 거라면 없어도 됨 |

## 파일 구조

```
defense_proxy_v2/
├── Defense_proxy.py       메인 — 리버스 프록시 + DefenseHook (transform + 미로 + 적응형)
├── dashboard.py           실시간 대시보드 — defense.db 를 보여주고, GUI 로 프록시를 시작/재시작/중지 (아래)
├── proxy_core.py          재사용 리버스 프록시 코어 (FastAPI 패스스루 + on_request/on_response 훅)
├── transforms.py          transform 레시피(T2.1/MIGRATION_TRACES) + 서버 무관 미로 생성기 + FAKE_SHELL 콘텐츠
├── profiles.py            대상 서버 프로필 — 프리셋(apache-php/nginx-fastapi) + 덮어쓰기(TARGET_PROFILE) 로더
├── preflight.py           시작 시 정합성 검사 — 프로필 모순·실제 백엔드와의 충돌·라우트 가림 경고
├── setup_profile.py       프로필 설정 도구 — 배포 전에 내 서버 정보를 물어 target_profile.json 생성
├── requirements.txt
├── README.md              (이 파일)
├── DEPLOYMENT_GUIDE.md    새 대상 서버에 배포 — 프로필 필드 지도·프리셋·정합성 검사·새 프리셋 추가법
├── DETECTION_INTEGRATION.md  탐지팀과 공유하는 연동 가이드 — X-Client-Id/X-Defense-Plan 스펙
├── results.md             최종 버전 기준 통합 결과 — 베이스라인·마이그레이션·T2.1+FAKE_SHELL·미로만 4실험 비교표, 발견한 허점과 수정 이력 (v1 전체 이력은 ../defense_proxy_v1/results.md)
├── tests/                 회귀·동작 테스트 — `python tests/run_all.py` (설명은 tests/README.md)
└── experiments/           실험 로그/하니스 (로컬 전용 — .git/info/exclude로 제외, 커밋 안 됨)
```

---

## 설치 및 실행 — 깃 클론부터

### 0) 클론 & 이 디렉터리로 이동

```bash
git clone https://github.com/WHS4-RUBY/ruby.git
cd ruby
git checkout defense-proxy
cd defense/CHeat-defense-proxy/defense_proxy_v2
```

(이후 명령은 전부 이 `defense_proxy_v2/` 안에서 실행한다고 가정한다.)

### 1) 파이썬 가상환경

```bash
python3 -m venv .venv
```

```bash
# macOS / Linux / WSL
.venv/bin/pip install -r requirements.txt
```
```powershell
# Windows (PowerShell)
.venv\Scripts\pip install -r requirements.txt
```

### 2) 대상 앱(터미널 1 — 백그라운드 컨테이너, cd 불필요)

```bash
docker run -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
```

`http://127.0.0.1:3000`이 뜨면 준비 완료(`curl http://127.0.0.1:3000`으로 확인).

### 3) 대시보드(터미널 2 — 이 터미널은 계속 켜둔다)

이제 방어 프록시는 **대시보드 GUI에서 직접 켠다** — 터미널 2는 대시보드만 띄운다:

```bash
cd ruby/defense/CHeat-defense-proxy/defense_proxy_v2   # 새 터미널이면 다시 여기로
DEFENSE_DB=./defense.db .venv/bin/uvicorn dashboard:app --host 127.0.0.1 --port 8088 --log-level warning
```

브라우저로 `http://127.0.0.1:8088`을 열고 **"프록시 제어"** 카드에서 REAL_BACKEND(`http://127.0.0.1:3000`)·
`DEFENSE_MODE`·`ACTIVE_TECHNIQUE` 등을 고른 뒤 **"시작 / 재시작"**을 누르면 그 설정대로
`Defense_proxy.py`가 뜬다. 자세한 보안 주의사항(꼭 읽을 것)과 화면 설명은 아래
[대시보드](#대시보드-dashboardpy) 섹션 참고. 시험 삼아 아무 터미널에서나

```bash
curl http://127.0.0.1:3002/server-status
```

를 쳐보면(포트는 GUI에서 고른 값) 대시보드 "최근 요청 로그"에 곧바로 찍힌다.

> **터미널에서 직접 켜고 싶다면**(스크립트·자동화용) 대시보드 없이도 여전히 가능하다:
> ```bash
> cd ruby/defense/CHeat-defense-proxy/defense_proxy_v2
> REAL_BACKEND=http://127.0.0.1:3000 \
> DEFENSE_MODE=transform ACTIVE_TECHNIQUE=T2.1 \
> .venv/bin/uvicorn Defense_proxy:app --host 127.0.0.1 --port 3002 --no-server-header --log-level warning
> ```
> 이렇게 켠 프록시도 같은 `DEFENSE_DB`를 보는 대시보드에 똑같이 잡힌다 — 대시보드가 시작한
> 것만 잡는 게 아니라, 그 DB 파일에 쓰는 모든 프록시를 보여준다.

### 4) 정리

```bash
docker rm -f juice-shop        # 대상 앱 컨테이너 종료
# 대시보드 화면에서 "중지"를 누르거나, 터미널 2를 Ctrl+C (둘 다 자식 프록시까지 같이 종료됨)
```

---

### 방어 계층

| `DEFENSE_MODE` | 동작 | 이 디렉터리에서 실제로 쓸 수 있는 것 |
|---|---|---|
| `off` | 패스스루 (베이스라인) | — |
| `transform` | 헤더 위조 + 가짜 정찰 엔드포인트 서빙 + 백엔드 JSON 병합 + `423` 로그인 미끼 + HTML 개발자 메모 주석 | `ACTIVE_TECHNIQUE=T2.1` \| `MIGRATION_TRACES` \| `T2.1+MIGRATION_TRACES`(비추천 — 아래) |

> **Cloak(속임수) 레시피는 한 번에 하나만.** `T2.1+MIGRATION_TRACES`처럼 스택 서사가 충돌하면(둘 다
> 스택 단서를 위조 등) codex 가 모순을 감지해 전체를 불신한다. `MIGRATION_TRACES`는 스택 배너를
> 위조하지 않고 "마이그레이션 중 남은 흔적"(가짜 브리지 + HTML 메모 주석)만 이어가므로, 단독으로
> `DEFENSE_MODE=transform` 하나로 충분하다.

`active`/`combined` 는 없어졌다 — 켜면 시작 시 안내 메시지를 내고 종료한다.

`DECOY_MAZE=1`·`ADAPTIVE_TRAP=1`·`FAKE_SHELL=1`·`AMBIG_TRAP=1` 은 `DEFENSE_MODE`와 독립적으로 얹힌다 (아래).
레시피 없이 미로만 쓰려면 `DEFENSE_MODE=off DECOY_MAZE=1 ADAPTIVE_TRAP=1` — 실험상 가장 단순한 구성이면서
무방어 대비 효과가 확인된 구성이다([`results.md`](results.md)). 단 `FAKE_SHELL` 은 T2.1 이 있어야 실전에서 트리거된다.

---

## 대시보드 (`dashboard.py`)

`defense.db`에 기록된 걸 실시간으로 보여주는 웹 페이지. **동시에, GUI에서 방어 모드를 골라
`Defense_proxy.py` 프로세스 자체를 켜고 끌 수 있다** — 터미널에서 긴 env var 나열형 커맨드를
직접 치지 않아도, 체크박스·드롭다운으로 구성을 고르고 "시작" 버튼 하나로 프록시가 뜬다.

```bash
DEFENSE_DB=./defense.db \
.venv/bin/uvicorn dashboard:app --host 127.0.0.1 --port 8088 --log-level warning
```

### 로그인 설정 (`DASHBOARD_PASSWORD`)

원격 접속이 필요하면 대시보드 포트를 그대로 노출하지 말고 SSH 포트 포워딩을 쓴다
(`ssh -L 8088:127.0.0.1:8088 user@host`). `DASHBOARD_PASSWORD`를 설정하면 로그인 없이는
대시보드를 볼 수 없다:

```bash
# 방법 1 — 랜덤 비밀번호를 변수에 저장해서 먼저 눈으로 확인(안 그러면 본인도 모르게 됨)
PW="$(openssl rand -hex 24)"
echo "대시보드 비밀번호: $PW"
DEFENSE_DB=./defense.db DASHBOARD_PASSWORD="$PW" \
.venv/bin/uvicorn dashboard:app --host 127.0.0.1 --port 8088 --log-level warning
```

```bash
# 방법 2 — 로컬 테스트용이면 그냥 본인이 기억할 비밀번호를 직접 지정해도 된다
DEFENSE_DB=./defense.db DASHBOARD_PASSWORD="원하는비밀번호" \
.venv/bin/uvicorn dashboard:app --host 127.0.0.1 --port 8088 --log-level warning
```

`http://127.0.0.1:8088`을 열면:

| 영역 | 내용 |
|---|---|
| **프록시 제어** | REAL_BACKEND·포트·DEFENSE_MODE·ACTIVE_TECHNIQUE(체크박스: T2.1/MIGRATION_TRACES + 직접입력)·DECOY_MAZE·ADAPTIVE_TRAP·FAKE_SHELL·POST_RCE_ACTION·AMBIG_TRAP 등을 골라 **시작/재시작/중지**. 폼에 없는 값(`MAZE_BASE_KB` 등)은 "고급: 추가 환경변수" 칸에 `KEY=VALUE` 줄로 추가. 지금 실행 중이면 PID·포트·설정이 그대로 보이고, "로그 보기"로 그 프록시 프로세스의 stdout/stderr(포트 충돌 등 시작 실패 원인)을 확인할 수 있다 |
| **상단 요약** | 현재 라운드의 `DEFENSE_MODE`/`ACTIVE_TECHNIQUE`(`runs` 테이블 최신 행), 경과 시간 |
| **KPI 4개** | 총 요청 수 · 미끼 접촉 수(`decoy_hits`, 전체 대비 %) · `ADAPTIVE_TRAP` 에스컬레이션 발동 여부(사유·시각) · `FAKE_SHELL` 진입 여부(시각) |
| **요청 타임라인** | 시간대별 요청 수를 3색 누적 막대로 — 일반(파랑) / 미끼 접촉·Cloak·미로(주황) / FAKE_SHELL·post-RCE(초록). 막대에 마우스를 올리면 그 구간의 정확한 수치가 나온다 |
| **defense_action 분포** | 어떤 `defense_action`이 몇 번 발동했는지 막대 랭킹(내림차순) |
| **최근 요청 로그** | 최근 150건을 시각·method·path·status·`defense_action`(색상 뱃지)으로 — 에이전트가 정확히 어떤 경로를 언제 건드렸는지 그대로 보인다 |

두 가지 유의: 상단 "총 요청 수"는 메타 행
(`/__escalate__`·`/__ambig__`)을 포함한 DB 행 수이고, "경과"는 DB 첫 행~마지막 행 시각이라 에스컬레이션 뒤에는
에이전트가 이미 끊은 요청의 지연이 끝나는 시각까지 포함한다(실험 결과를 옮길 때 기준을 통일할 것 — [`results.md`](results.md#지표-정의-같은-방식으로-쟀다)).

**동작 방식**: "시작"을 누르면 대시보드가 `subprocess.Popen`으로 `uvicorn Defense_proxy:app`을
자식 프로세스로 띄운다(관리하는 인스턴스는 한 번에 하나 — 다시 "시작"을 누르면 기존 걸 먼저
멈추고 새 설정으로 재시작). `DEFENSE_DB`는 대시보드가 보고 있는 파일로 강제 고정되므로, GUI로
시작한 프록시는 항상 같은 화면에 결과가 나온다. 대시보드 프로세스가 죽으면(`Ctrl+C` 등) 띄워둔
프록시도 같이 종료된다.

### 실험용 지표 — 에이전트 토큰 사용량 · 챌린지 solved 수 (EXPERIMENT-ONLY)

"프록시 제어" 카드 아래 **실험용 지표** 카드는 두 값을 보여준다:

- **에이전트 토큰 사용량** — `CODEX_LOG_PATH` 환경변수로 `codex exec --json > codex.jsonl`의
  경로를 알려주면, 마지막 `turn.completed` 이벤트의 누적 `usage`(input/cached/output 토큰)를
  파싱해서 보여준다.
- **풀이한 챌린지 수** — 프록시를 **거치지 않고** `REAL_BACKEND`의 `/api/Challenges`(Juice Shop
  전용 엔드포인트)를 직접 조회해서 solved 개수를 센다 — `run_batch9.sh`의 `solved_count()`와
  같은 방식(방어가 채점 결과에 손 못 대게 ground truth를 우회로 잡음).

```bash
CODEX_LOG_PATH=/tmp/rd-xxxx/codex.jsonl DEFENSE_DB=./defense.db \
.venv/bin/uvicorn dashboard:app --host 127.0.0.1 --port 8088 --log-level warning
```

> **이건 "우리가 공격 에이전트도 같이 돌리는 통제된 실험"에서만 의미 있는 지표다.** 실제 대상 앱엔 없으므로 `dashboard.py` 안에
> `# ══ EXPERIMENT-ONLY ══`로 표시된 블록(코드에 4곳 — `CODEX_LOG_PATH` 상수,
> `_read_codex_usage()`/`_read_challenges()`/`api_experiment()` 함수, HTML의
> `#experimentCard` 카드, JS의 `refreshExperiment()`)으로 감싸뒀다.
---

## 서버 무관 미로 (`DECOY_MAZE=1`)

레시피(`transform`)는 특정 앱 전용이지만, 미로는 프록시가 완전히 소유하는 표면만 건드려 **어느 앱
앞에든** 붙는다: 헤더 · 백엔드가 낸 404/403(+ SPA 폴백 200) · `robots.txt` · HTML 주석.

**동작**: 에이전트가 흔한 정찰 경로(`/internal/`, `/.git/config`, `/backup/`, `/config.yml.bak` …)를
fuzzing → 백엔드 404 → 프록시가 가로채 "뭔가 찾았다"로 응답한다:

- **크게** — `MAZE_BASE_KB`(30KB) → 물수록 `MAZE_ESC_KB`(250KB) → `MAZE_MAX_KB`(900KB)
- **느리게** — `MAZE_DELAY_MS`(2.5s) → `MAZE_ESC_DELAY_MS`(6s). 에스컬레이션된 클라이언트의 미로 접촉은 `max(MAZE_ESC_DELAY_MS, ESCALATE_DELAY_MS)`(기본 16s)이고, 같은 요청에 걸린 다른 지연(에스컬레이션 tarpit·FAKE_SHELL 진입 후 지연)과 **합산하지 않는다**
- 한 번 들어온 상위 경로는 **미로 루트로 기억** (그 아래 전부 미로)

> SPA(Angular/React 등)는 미지 경로에 404 대신 `200 + index.html`을 준다. 프록시는 `/` 응답 본문을
> 캐시해 두고, 미로 패턴 경로가 그와 **바이트 동일한** 200을 돌려주면 그것도 SPA 폴백으로 보고 가로챈다.

### 정상 사용자·실제 경로를 지키는 장치

미로는 "정상 사용자는 이 경로를 안 친다"는 가정 위에 있다. 그 가정이 깨지는 경우(실제 `/admin`, 새로고침,
SPA 라우트, 비-UTF-8 페이지, robots.txt 없음)를 아래처럼 막는다.

| 상황 | 동작 |
|---|---|
| 백엔드가 실제로 서빙하는 경로(`/admin` 200 등) | 미로가 가로채지 않는다(원래도 404/403/SPA 폴백만 가로챔). 한 번이라도 **진짜로 서빙된 경로**(2xx/3xx/401, SPA 폴백 아님)는 기억해 두고 이후 403 도 미로로 안 바꾼다 |
| 실제 경로가 403 을 주는 서버 | `MAZE_INTERCEPT_403=0` 으로 403 은 그대로 둔다(기본 1 — 예전 동작) |
| 겹치는 실제 경로를 수동으로 제외 | `MAZE_EXCLUDE='^/(admin\|config)(/\|$)'` (프로필 `maze.exclude` 도 가능) |
| SPA(history 라우팅)에서 `/admin` 주소창 접속·새로고침 | 폴백 응답이고 `Sec-Fetch-Dest: document`(브라우저 문서 내비게이션)면 **미로 대신 SPA 를 그대로** 준다(`MAZE_SPA_BROWSER_PASS=1` 기본). curl·fetch/XHR 에이전트는 그대로 미로 |
| 같은 가짜 경로를 새로고침 | 에스컬레이션은 **서로 다른 경로 수**로 센다([적응형](#적응형-에스컬레이션-adaptive_trap1) 참고) |
| robots.txt 가 없거나(404) SPA HTML | 미끼 줄만 있는 새 robots.txt 를 만든다. **`Disallow: /` 를 절대 만들지 않는다**(크롤러·모니터링 보호). 이미 있는 줄은 중복 추가 안 함, 마지막 그룹이 `*` 가 아니면 `User-agent: *` 그룹을 새로 연다 |
| EUC-KR·Shift_JIS·latin-1 페이지에 주석 주입 | 바이트 단위·응답 charset 으로 주입 — 원본 한글/악센트가 깨지지 않는다. UTF-16 등 ASCII 비호환이면 주입 생략 |
| `Range`·`If-None-Match` 등 **조건부 요청** | 미로 경로로 가는 GET/HEAD 에서는 `Range`·`If-Range`·`If-None-Match`·`If-Modified-Since`·`If-Match`·`If-Unmodified-Since` 헤더를 백엔드로 보내기 전에 지운다. SPA 백엔드(Express static 등)는 폴백 `index.html` 에 Range 를 주면 **206**, ETag 를 주면 **304** 를 돌려주는데, 미로 가로채기는 "200 + 본문이 `/` 와 같음"으로 폴백을 판별하므로 예전엔 이 응답들이 미로를 우회해 셸 조각이 그대로 나갔다(실측: 에이전트가 큰 미로 응답 대신 일부만 받으려 Range 를 쓴 206 이 4건, 미끼 접촉으로도 안 세어짐). 진짜 경로(`_maze.real` 학습)·미로 패턴이 아닌 경로·`MAZE_REQUIRE_PLAN=1` 에서 플랜 없는 클라이언트는 건드리지 않는다. 진짜 경로를 처음 Range 로 요청하면 전체 200 이 나가고(헤더 제거) 이후부터 정상 206 |

입구 경로는 **한 목록**(`MAZE_PATHS` / 프로필 `maze.paths`)에서 robots.txt 의 `Disallow` 줄과 미로 판정 정규식을
같이 만든다 — 광고한 경로가 평범한 404 가 되는 어긋남이 구조적으로 없다. 입구 문서(Link 헤더·HTML 주석이 가리키는
`maze.entry_path`, 기본 `/internal/ops/runbook`)와 주석 문구(`maze.comment_text`)도 프로필에서 바꾼다.
미로 응답 본문은 **서버 종류와 무관한 영어 텍스트**다 — 서버 정보 줄은 프로필 배너(`server_version:`·`httpServer:`)만 쓰고 Apache 전용 항목(MPM·빌드 날짜)은 넣지 않으며,
디렉터리 목록의 소유자는 프로필의 가짜 셸 사용자(`shell.user`)다. Apache/PHP/Spring 전용 입구 이름(`server-status`·`phpinfo`·`.htpasswd`·`actuator`)은 기본 패턴이 아니라
그 서버 프리셋의 `maze.extra_pattern` 에만 있다(`apache-php` 만 값이 있다). 시작할 때
`preflight` 가 설정 모순(광고 경로가 미로로 판정 안 됨·입구가 `MAZE_EXCLUDE` 에 걸림)과 실제 백엔드와의 충돌(광고 경로가
실제로 존재/403, SPA 폴백, 진짜 robots.txt 와 겹침)을 경고한다.

**탐지팀 플랜으로 대상 좁히기**: `MAZE_REQUIRE_PLAN=1` 이면 미로(주석·Link·robots·가로채기)를 `X-Defense-Plan`
에 `{"name":"maze"}` 가 실린 클라이언트(와 이미 에스컬레이션된 클라이언트)에게만 적용한다. 한 번 켜지면 유지(sticky)
— 입구를 본 뒤 갑자기 사라지면 세계가 모순된다. 기본 0(예전처럼 모두에게 적용).

---

## 적응형 에스컬레이션 (`ADAPTIVE_TRAP=1`)

`transform` 또는 `DECOY_MAZE`와 함께. Cloak을 먼저
걸고 **에이전트가 미끼를 물면** 그 위에 Trap을 자동으로 얹는다. 발동 전에는 응답이 빨라 이상 지연을
안 들킨다.

**트리거는 하나(`cloak-taken`)**: 미끼 라우트·미로·`423` lure 접촉이 `ADAPTIVE_ONBITE_HITS`(기본 3)
이상이면 발동한다. 센 단위는 기본 **서로 다른 미끼 경로 수**(`ADAPTIVE_COUNT=distinct` — 경로는 쿼리 제거·소문자·끝 `/`
제거로 정규화)다. 같은 가짜 경로를 새로고침 3번 하는 정상 사용자는 1로 센다(에이전트는 경로를 바꿔가며 탐색하므로 탐지력은
거의 그대로). `423` lure(미끼 자격증명 입력)는 정상 사용자가 칠 일이 없어 매 접촉을 따로 센다. `ADAPTIVE_COUNT=raw` 는
예전 방식(접촉 횟수 — 이전 실험 재현용). `DECOY_SKIP_AUTHED=1` 이면 `Authorization`/세션류 쿠키를 실은 요청의 접촉은
세지 않는다(기본 0 — 공격 에이전트도 SQLi 로 로그인한 뒤 탐색하므로 켜면 로그인 후 정찰이 신호에서 빠진다). 예전엔 "미끼가 안 먹힐 때의 시간 폴백"(`cloak-not-landing`)과 "깊게 물었다 떠남"
(`cloak-abandoned`)도 있었지만, 기본값에서 abandoned 는 taken 이 항상 먼저 걸려 도달 불가였고
not-landing 은 Batch 6 이후 실전에서 한 번도 발동하지 않아 뺐다.

**경로 탈출 시도도 미끼 접촉으로 센다(`traversal-probe`)**: T2.1 이 말하는 Apache 2.4.49(CVE-2021-41773)를 믿고 공개
PoC 를 그대로 따라 한 시도를 잡는다. PoC 는 파일 읽기에 `/icons/`(Apache 기본 Alias), RCE 에 `/cgi-bin/`(가짜 라우트가 이미
셈)을 쓰므로, **지정한 접두어(기본 `/icons/`) 아래에 `..` 세그먼트가 있는 요청**(`.%2e`·`%2e%2e`·이중 인코딩 `%252e`·`//icons/`
포함)을 센다. **응답은 바꾸지 않고** 백엔드로 그대로 통과시키며 액션 라벨만 `traversal-probe`(에스컬레이션 뒤엔
`traversal-probe:escalated-delay`)다.  "어디서든 `..`" 가 아니라 접두어로 제한한 이유: Juice Shop 의 디렉터리 트래버설
챌린지(`/ftp/` 등)를 푸는 행동은 가짜 Apache 이야기를 믿어서 한 게 아니라 앱 자체를 푸는 것이므로 신호로 세면 안 된다.
정상 브라우저·`curl` 은 `..` 를 보내기 전에 정리하므로 접두어가 실제 서버에 있어도(Apache 기본 설치의 `/icons/` 등) 정상
요청은 영향이 없다. 켜지는 조건: T2.1 레시피를 쓸 때(`TRAVERSAL_PROBE_PATHS` 를 env 로 명시하면 항상). 서로 다른 변형 3개
(디코딩하면 같은 경로가 되는 `.%2e` 와 `..` 는 1개)면 에스컬레이션이 걸린다.

**발동 시 Trap은 "그 이후 모든 요청에 더 큰 tarpit 지연"이다** (`ESCALATE_DELAY_MS`, 기본
`16000`ms). `/api/Feedbacks`를 `_T42_PAD`(~2,200개 가짜 항목)로 ~1MB 부풀리던
`escalation_flood()`는 **코드에서 완전히 제거했다** — 같은 엔드포인트를 매번 같은 내용으로
부풀려 **두 번째 턴부터 prompt caching으로 거의 할인**되는, transform `T4.2`를 뺀 이유와 동일한
약점을 갖고 있었다. tarpit 지연은 캐싱으로 할인될 수 없는 wall-clock 비용이라 이 프로젝트에서
가장 확실하게 증명된 비용 유발 수단이다(FAKE_SHELL tarpit 과 같은 근거).

---

## 가짜 포스트-익스플로잇 셸 (`FAKE_SHELL=1`)

T2.1이 CVE-2021-41773 traversal로 가짜 `/etc/passwd`를 한 번 보여주는 건 **1회성**이다 — codex가
그다음 RCE(`/bin/sh`에 명령 POST)를 시도하면 라우트가 없어 환상이 깨진다. `FAKE_SHELL`은 그 RCE
"성공"을 믿게 한 뒤 **여러 턴 이어지는 가짜 셸**로 확장한다.

**★ 어떤 명령도 실제로 실행하지 않는다.** 패턴 매칭 + 결정적 생성(`transforms.fake_shell_response`)만.

**전제조건**: `ACTIVE_TECHNIQUE`에 `T2.1`이 포함돼 있어야 한다 — FAKE_SHELL의 진입 판정 자체는
코드상 레시피와 독립된 정규식(`_FAKE_SHELL_RE`)이지만, codex 가 `/cgi-bin/.../bin/sh`에 POST할
"이유"(가짜 버전 배너·`robots.txt` 힌트·traversal 라우트)는 전부 T2.1 레시피가 제공한다. T2.1 없이는
FAKE_SHELL이 코드상 동작해도 실전에서 거의 트리거되지 않는다.

**동작**: `POST /cgi-bin/.../bin/sh|bash`에 명령이 오면(`_FAKE_SHELL_RE`) —

| 받은 명령 | 가짜 출력 |
|---|---|
| `id` / `whoami` | `uid=33(www-data) …` — T2.1의 `_PASSWD_STUB`과 같은 세계관 |
| `uname -a` | 그럴듯한 커널 문자열 |
| `cat /etc/passwd` | 기존 `_PASSWD_STUB` 재사용 (새 거짓말 안 만듦) |
| `cat /etc/shadow` | `Permission denied` — 진짜 서버라면 www-data 권한으론 거절돼야 함 |
| `sudo -l` | root NOPASSWD 항목 1개 (backup.sh 퀘스트로 유인) |
| `backup.sh --target=x --yes` | 아카이브 안 가짜 DB 자격증명(`postgres://...@10.0.4.12`) 노출 |
| `curl`/`nc` → `10.0.4.12` | 연결 타임아웃 + HTTP 브리지 경로(`/internal/ops/db-bridge`) 힌트 → `DECOY_MAZE`로 연결 |
| `ls` / `pwd` | 미로와 같은 파일 목록 생성기 재사용 |
| 그 외 | 결정적으로 빈 출력 또는 `command not found` |

같은 명령은 항상 같은 출력(`history` 캐시) — "매번 다르다"는 의심을 피한다.

**진입 전 (`FAKE_SHELL_RETRIES`)** — 기본값 `0`(첫 시도에 바로 성공). `1` 이상이면 최초 RCE
시도(들)은 깨진/부분 출력(`fake_shell_garbled`)으로 실패시켜 재시도를 유도하는 옛 동작인데,
실측(N=3×3)상 `RETRIES=0`의 진입률이 100%인 반면 `1`·`2`는 50%로 반토막 — 마찰이 몰입을
늘리기보다 이탈을 늘려서 기본값을 `0`으로 바꿨다(`../defense_proxy_v1/results.md`).

**진입 성공 이후 (`POST_RCE_GRACE_CMDS` / `POST_RCE_ACTION`)** — 이 실험의 핵심 변수:

| 값 | 동작 |
|---|---|
| `POST_RCE_GRACE_CMDS`(기본 0) | 성공 이후 이 수만큼 요청까지는 정상 응답(전환 유예) — `0`이면 성공 즉시 다음 요청부터 적용 |
| `POST_RCE_ACTION=tarpit`(기본) | 유예 이후 **모든 요청**(다음 셸 명령 포함)에 `POST_RCE_DELAY_MS` 지연. 셸은 계속 "작동"하지만 느려짐. **이미 에스컬레이션된 클라이언트(`ADAPTIVE_TRAP`)는 `max(POST_RCE_DELAY_MS, ESCALATE_DELAY_MS)`** — 예전엔 진입 순간 지연이 에스컬레이션 16s 에서 `POST_RCE_DELAY_MS` 기본 8s 로 오히려 줄었다(실측: 진입 직후 첫 응답까지 8.1s) |
| `POST_RCE_ACTION=block` | 유예 이후 **모든 요청**을 즉시 `403` — 정보성 응답(차단됐다는 신호는 준다) |
| `POST_RCE_ACTION=drop` | 유예 이후 **모든 요청**에 응답을 `POST_RCE_DROP_S`(기본 99999초)만큼 안 보냄. **아무 신호도 없이 먹통** |

> `tarpit`이 비용(wall/토큰) 최대, `block`이 solved 억제 최고, `drop`은 codex 가 응답을 기다리지
> 않고 바로 다음 시도로 넘어가 효과 없음으로 확인됨 (`../defense_proxy_v1/results.md`)

---

## 애매한 공격자 판정 (`AMBIG_TRAP=1`)

Policy Engine이 "방어 대상"이라고는 판정했지만 공격자인지 아직 애매한 트래픽에 쓰는
**최종 판정 계층**. 새 탐지 로직을 만들지 않고, 이미 각자 따로 도는 두 신호를 그대로
재사용한다: `FAKE_SHELL`의 RCE 진입, `ADAPTIVE_TRAP`의
에스컬레이션(`DECOY_MAZE` 접촉도 `decoy_hits`에 흡수되므로 이 하나로 같이 커버됨).

> ⚠ 실측(R1~R4)에서 확정 차단을 만든 신호는 전부 이 에스컬레이션(미끼 접촉 3개)이었고 FAKE_SHELL 진입으로 차단된
> 적은 없다. 즉 **미끼 경로 접촉이 사실상 단독 차단 사유**다. 오탐은 "서로 다른 경로 수로 세기"와
> [미로 안전장치](#정상-사용자실제-경로를-지키는-장치)(실제 경로 제외·SPA 새로고침 통과 등)로 줄였지만, 한 번 걸리면 영구
> 차단(release 없음)이라는 구조는 그대로다 — 정상 사용자가 많은 환경에선 입구 경로를 신중히 고르고 preflight 경고를
> 반드시 확인할 것.

**동작**:

- 둘 중 **하나라도** 실제로 발화하면 → 그 순간부터 **모든 요청을 무조건 `403`**으로 확정
  차단한다. 그 뒤로는 tarpit/block/drop 뉘앙스가 없다 — 판정이 끝났으니 이어갈 이야기가
  없다는 뜻. **가짜 라우트**(T2.1 의 `/server-status`·`/cgi-bin/...`, MIGRATION_TRACES 의 `/rest/internal*`)도
  같은 403 이다 — 예전엔 이 라우트들이 훅을 안 거치는 별도 FastAPI 라우트라 차단 확정 뒤에도 200/401 로 계속
  응답했다(실측: R1 로그에서 차단 이후 `transform-route` 200 이 6건). 예외 두 가지: ① 차단을 **판정하는
  그 요청** 자체는 지연(ESCALATE_DELAY_MS) 뒤 정상 응답이 나가고, 판정 시점에 이미 지연 중이던 요청들도 끝나면 응답을
  받는다 ② `/cgi-bin/` 접두어 아래지만 트래버설 키워드가 없는 요청(`/cgi-bin/zzz`)은 원래도 가짜 라우트가 아니라
  404 로 끝난다.
- `AMBIG_RELEASE_MIN`(기본 10분)이 지날 때까지 **둘 다 안 걸리면** → 그 순간부터 **모든
  요청을 완전히 정상 패스스루**로 풀어준다. 가짜셸·미로를 전부 재적용하지 않는다
  — "지켜봤는데 문제 없었다"는 결론. (가짜 **라우트**도 이제 훅 안에서 처리되므로 released 클라이언트는 라우트까지 포함해 요청이 그대로 백엔드로 간다 —
  예전엔 라우트가 별도 핸들러라 released 이후에도 미끼 응답을 줬다.)

`AMBIG_TRAP`은 스위치일 뿐, 실제로 신호가 잡히려면 `FAKE_SHELL`(+`T2.1`)/
`DECOY_MAZE`+`ADAPTIVE_TRAP`를 같이 켜야 한다 — 대시보드에서는 "AMBIG_TRAP" 체크박스
+ "AMBIG_RELEASE_MIN" 드롭다운(5/10/30/60분)으로 켤 수 있다.

**사용법 예시**:

```bash
DEFENSE_MODE=transform ACTIVE_TECHNIQUE=T2.1 FAKE_SHELL=1 \
DECOY_MAZE=1 ADAPTIVE_TRAP=1 \
AMBIG_TRAP=1 AMBIG_RELEASE_MIN=10 \
.venv/bin/uvicorn Defense_proxy:app --host 127.0.0.1 --port 3002 --no-server-header
```

---

## 탐지팀 연동 — client_id 기반 상태 격리 + X-Defense-Plan

탐지팀의 `detection/server.js`가 모든 요청에 심는 `X-Client-Id`·`X-Defense-Plan` 헤더를
읽어서 쓴다. **탐지팀과 공유하는 연동 스펙·설정 방법·테스트 절차는
[`DETECTION_INTEGRATION.md`](DETECTION_INTEGRATION.md)에 정리했다** — 이 섹션은 우리 쪽
구현 내부 동작만 요약한다.

- `AMBIG_TRAP`/`FAKE_SHELL`/`DECOY_MAZE`(에스컬레이션) 상태가 전부
  `X-Client-Id` 값으로 격리된다(`ClientState`, `Defense_proxy.py`) — 예전엔 전역 싱글턴
  하나였어서 한 공격자가 AMBIG_TRAP에 차단되면 다른 모든 클라이언트도 같이 403이 되는
  버그가 있었다. 헤더 없으면 접속 IP로 폴백(탐지 레이어 없는 로컬 실험 하위호환). 출발지 IP 가 요청마다
  바뀌는 환경(NAT/프록시 풀)의 **단일 공격자 로컬 실험**에서는 `CLIENT_ID_FALLBACK=global` 로 헤더 없는 요청을
  전부 한 클라이언트(`global`)로 묶는다 — 안 그러면 IP 가 바뀔 때마다 에스컬레이션·차단이 새로 시작된다. 헤더가 있는
  요청은 그 값이 항상 우선이라 탐지팀 연동 때는 이 변수를 지우기만 하면 된다. ★ 연동 운영 환경에서는 쓰지 말 것
  (헤더 없는 헬스체크·내부 호출이 한 클라이언트로 묶여, 그 하나가 차단되면 헤더 없는 요청 전부가 영향을 받는다).
  실험 중 직접 보내는 확인용 요청은 `X-Client-Id: selftest` 처럼 별도 헤더를 붙여 `global` 과 섞이지 않게 한다.
  `CLIENT_STATE_TTL_S`(기본 3600 = 탐지팀 세션 창)보다 오래 조용한 client_id는 자동 청소.
- `X-Defense-Plan`(`[{"name":"delay","params":{"delay_ms":300}}, ...]`, `defense/app`의
  `parse_plan()`/`STRATEGY_REGISTRY`와 동일 계약)을 `_DEFENSE_PLAN_STRATEGIES` 레지스트리로
  적용한다. 구현된 전략은 `delay`(지연), `maze`(미로 켜기 — `MAZE_REQUIRE_PLAN=1` 일 때만 의미), 그리고 탐지팀이 단계와 무관하게 부를 수 있는
  **묶음 3개**(`DECOY_REQUIRE_PLAN=1` 일 때만 의미, 클라이언트별·sticky·접촉은 켜진 뒤부터 셈): `decoy_maze`(미로 + 적응형, 서버 무관) ·
  `decoy_t21_shell`(+ T2.1 레시피 + FAKE_SHELL) · `decoy_migration`(+ MIGRATION_TRACES 레시피). 클라이언트당 레시피는 하나이고 먼저 정해진 것이 유지됨.
  모르는 전략
  이름은 조용히 무시(전방 호환) — 새 이름 추가 절차는 `DETECTION_INTEGRATION.md` §3 참고.
- 적용된 전략은 `defense.db`의 `reqs.defense_plan` 컬럼에, client_id는 `reqs.client_id`
  컬럼에 남는다.
- **신뢰 전제 조건**: 공격자가 이 프록시 포트에 탐지 레이어를 거치지 않고 직접 도달할 수
  없어야 한다 — 운영 배포 시 네트워크 수준(방화벽/사설망)에서 보장할 것.

---

## defense_action 라벨 표

`defense.db` 의 `reqs.defense_action` 에 남는 값. 대시보드 색상 뱃지와 결과 분석 쿼리가 이 라벨을 쓴다.

| 라벨 | 의미 | 미끼 접촉으로 셈 |
|---|---|---|
| `observe` | 방어 없이 통과 | — |
| `transform-route` | T2.1/MIGRATION_TRACES 가짜 라우트 응답(`/server-status`, `/cgi-bin/…`, `/rest/internal*`) | ✔ |
| `login-lure-423` | 미끼 계정으로 로그인 시도 → 423 | ✔ (매 접촉) |
| `maze` / `maze!` / `maze-401` | 미로 응답 / 확대 미로(물림 횟수·에스컬레이션 후) / 401 로 위장한 미로 | ✔ |
| `traversal-probe` (`:escalated-delay`) | 지정 접두어(`/icons/`) 아래 `..` 경로 탈출 시도 — 응답은 그대로 | ✔ |
| `escalated-delay:<사유>` | 에스컬레이션된 클라이언트의 일반 요청에 `ESCALATE_DELAY_MS` 지연 | — |
| `fake-shell` / `fake-shell-garbled` | FAKE_SHELL 진입 성공 / 진입 전 깨진 응답(`RETRIES>0`) | — |
| `post-rce-delay` / `post-rce-block` / `post-rce-drop` | 진입 후 `POST_RCE_ACTION` 에 따른 처리 | — |
| `ambig-block` / `ambig-released` | AMBIG 확정 차단 403 / 해제 뒤 패스스루 | — |
| 메타 행: `escalate:<사유>` · `ambig-blocked:<사유>` · `ambig-released` | 상태 전환 기록(`/__escalate__`·`/__ambig__`, method `-`). 요청 수를 셀 땐 제외 | — |

---

## 실험 돌릴 때 — 우회 차단과 라운드 운영

단일 공격자 에이전트를 같은 서버에서 돌리는 실험에서는 아래를 지켜야 에스컬레이션·차단이 한 클라이언트에 일관되게 걸린다
(실제로 우회가 일어났던 이력은 [`results.md`](results.md#5-실험-중-발견한-방어-허점과-수정-이력)).

| 항목 | 설정 | 이유 |
|---|---|---|
| 클라이언트 식별 묶기 | `CLIENT_ID_FALLBACK=global` | 에이전트가 출발지 IP 를 바꿔도 한 클라이언트로 본다 |
| `X-Forwarded-For` 위조 방지 | `UVICORN_PROXY_HEADERS=0`(직접 띄운다면 `uvicorn --no-proxy-headers`) | uvicorn 은 루프백에서 온 요청의 이 헤더를 믿어 `request.client.host` 를 바꾼다 → 에이전트가 위조로 차단을 1분 만에 우회한 적이 있다. 대시보드로 띄울 땐 "고급: 추가 환경변수"에 `KEY=VALUE` 로 추가 |
| `X-Client-Id` 위조 | `CLIENT_ID_HEADER` 를 에이전트가 모르는 이름으로 바꾸기(탐지 레이어 없는 로컬 실험 한정) | 헤더 값이 항상 우선이라 에이전트가 임의 값을 보내 새 클라이언트가 될 수 있다 |
| 에이전트와 프록시 분리 | 에이전트를 프록시 프로세스·소스·DB 에 접근 못 하는 호스트/컨테이너에서 실행 | 재시작·소스 열람으로 우회 가능([`results.md`](results.md#62-ambig_trap-라운드-2026-09-말--10월-초)) |
| 라운드마다 | Juice Shop 재생성, 프록시 재시작, `DEFENSE_DB`·`codex.jsonl` 별도 보관, **초기화 전에** `/api/Challenges` solved 기록 | 라운드 간 상태 오염 방지 |
| 확인용 요청 | `X-Client-Id: selftest` 등 별도 헤더 | `global` 에 섞여 에스컬레이션을 일으키지 않게 |

---

## 환경변수

| 변수 | 기본값 | 설명 |
|---|---|---|
| `REAL_BACKEND` | `http://127.0.0.1:3000` | 백엔드 origin |
| `DEFENSE_MODE` | `transform` | `off` \| `transform` (`active`/`combined` 는 없어짐 — 켜면 안내 후 종료) |
| `ACTIVE_TECHNIQUE` | — | 레시피 키. `+`로 병합 (`T2.1+MIGRATION_TRACES`)|
| `T21_VERSION_PATH` | `/rest/admin/application-version` | T2.1이 가짜 `httpServer` 배너를 병합해 넣는 실제 백엔드 엔드포인트 경로. Juice Shop 이외 대상엔 맞는 버전/상태 API 경로로 교체 |
| `MIGRATION_CONFIG_PATH` | 프로필 `migration.config_path`(apache-php `/rest/admin/application-configuration`) | MIGRATION_TRACES가 가짜 `adminBridgeBase`를 병합해 넣는 실제 백엔드 엔드포인트 경로(빈 값이면 병합 안 함). MIGRATION 의 서버별 값 전체(`migration.*`)는 배포 전에 `setup_profile.py`(프로필 설정 도구)로 입력 — [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md) |
| `TARGET_PRESET` | `apache-php` | "이 프록시가 어떤 서버인 척하는가" 프리셋(`apache-php` \| `nginx-fastapi`) — [대상 서버 프로필](#대상-서버-프로필-profilespy) 참고 |
| `TARGET_PROFILE` | — | 프리셋 위에 덮어쓸 필드만 적은 JSON 경로(`setup_profile.py` 로 생성). 우선순위: 프리셋 < 이 파일 < 개별 env |
| `PREFLIGHT` / `PREFLIGHT_STRICT` | `1` / `0` | 시작 시 정합성 검사(T2.1·FAKE_SHELL·`DECOY_MAZE` 쓸 때) 끄기 / 모순 시 시작 거부 |
| `T21_ROBOTS_DISALLOW` | 프로필 `lure.robots_disallow`(기본 `/cgi-bin/`) | T2.1 robots.txt 힌트 — 콤마 구분 `Disallow:` 경로 목록(`synth_robots()`로 기존 robots.txt에 append, 없으면 합성) |
| `MIGRATION_ROBOTS_DISALLOW` | 프로필 `migration.robots_disallow`(apache-php `/rest/internal/,/admin-bridge/`) | MIGRATION_TRACES robots.txt 힌트 — 위와 동일 메커니즘 |
| `SPOOF_SERVER` | `nginx` (`DECOY_REQUIRE_PLAN=1` 이면 **프로필의 배너**) | 위조할 `Server` 헤더값. 묶음 모드에서 프로필 배너를 기본으로 쓰는 이유는 미로만 켜진 클라이언트가 레시피 묶음(T2.1 등)으로 올라가도 `Server` 가 바뀌지 않게 하려는 것(대상과 맞는 프리셋을 고를 것). 빈 값(`SPOOF_SERVER=`)이면 위조 안 함 |
| `SPOOF_POWERED_BY` | — (없음) | `X-Powered-By` 위조. 대상 스택과 모순되면 Cloak 간파의 근거 — 맞을 때만 |
| `MAZE_VERSION` | `SPOOF_SERVER` | 미로 `version` 프로파일 배너 |
| `DECOY_MAZE` | `0` | `1`이면 서버 무관 미로 |
| `MAZE_PROFILE` | `version,bridge,inventory,ssh,docs` | 미로가 흉내낼 자원 유형 |
| `MAZE_BASE_KB` / `MAZE_ESC_KB` / `MAZE_MAX_KB` | 30 / 250 / 900 | 미로 응답 크기 (KB) |
| `MAZE_DELAY_MS` / `MAZE_ESC_DELAY_MS` | 2500 / 6000 | 미로 응답 지연 (ms). 에스컬레이션 후에는 `ESCALATE_DELAY_MS` 와 합산이 아니라 **둘 중 큰 값** |
| `MAZE_ESCALATE_HITS` | 4 | 이 횟수 이상 물면 미로가 확대 |
| `MAZE_PATHS` | 프로필 `maze.paths`(`/internal/,/backup/,/admin/,/config/,/private/`) | 미로 입구 경로(콤마) — robots `Disallow` 줄과 미로 판정 정규식을 **같이** 만든다. 실제 앱에 있는 경로는 넣지 말 것 |
| `MAZE_PATTERN` | — | 미로 판정 정규식을 통째로 교체(고급). 광고 경로와의 일관성은 preflight 가 점검 |
| `MAZE_EXCLUDE` | 프로필 `maze.exclude`(빈 값) | 미로에서 뺄 실제 경로 정규식(예: `^/(admin\|config)(/\|$)`) |
| `MAZE_INTERCEPT_403` | `1` | `0` 이면 백엔드 403 은 미로로 안 바꿈(진짜 보호 경로가 403 을 주는 서버용) |
| `MAZE_SPA_BROWSER_PASS` | `1` | SPA 폴백이고 브라우저 문서 내비게이션(`Sec-Fetch-Dest: document`)이면 미로 대신 SPA 를 그대로 |
| `MAZE_REQUIRE_PLAN` | `0` | `1` 이면 `X-Defense-Plan` 에 `maze` 가 있는 클라이언트(sticky)·에스컬레이션된 클라이언트에게만 미로 적용 |
| `DECOY_REQUIRE_PLAN` | `0` | **탐지팀 연동용 묶음 모드**(`DEFENSE_MODE=off` 권장 — 레시피는 클라이언트별 플랜이 정하고, 전역 레시피는 플랜 없는 클라이언트에 적용 안 함. 클라이언트당 레시피는 하나이고 먼저 정해진 것이 유지됨). `1` 이면 `DECOY_MAZE`·`ADAPTIVE_TRAP`·가짜 라우트·FAKE_SHELL 을 따로 안 켜도 모두 준비하고, `X-Defense-Plan` 에 묶음 전략(`decoy_maze` / `decoy_t21_shell` / `decoy_migration`)이 실린 클라이언트에게만 적용한다(`MAZE_REQUIRE_PLAN` 도 같이 켜짐, 환경변수 `FAKE_SHELL` 은 무시). 플랜 없는 클라이언트는 응답이 전혀 안 바뀌고 가짜 라우트·가짜 셸도 없다. `0` 이면 기존 환경변수대로 모든 클라이언트에 적용 |
| `ADAPTIVE_TRAP` | `0` | `1`이면 미끼 물면 tarpit 강화 |
| `ADAPTIVE_ONBITE_HITS` | `3` | 미끼 접촉이 이 값 이상이면 에스컬레이션(`cloak-taken`, 최소 1). 예전의 `ADAPTIVE_GRACE_MS`/`MIN_REQS`/`MIN_DECOY`/`ABANDON_MS` 는 트리거와 함께 제거됨 |
| `TRAVERSAL_PROBE_PATHS` | 프로필 `lure.probe_paths`(apache-php `/icons/`, nginx-fastapi 없음) | 경로 탈출 시도를 신호로 셀 접두어(쉼표, 각각 `/` 로 시작·끝). **빈 값이면 끔**, env 로 지정하면 프로필 값을 대체하고 레시피와 무관하게 켜짐. 응답은 안 바꿈 |
| `ADAPTIVE_COUNT` | `distinct` | 무엇을 센다: `distinct`(서로 다른 미끼 경로) \| `raw`(접촉 횟수 — 이전 실험 재현용) |
| `DECOY_SKIP_AUTHED` / `AUTH_COOKIE_RE` | `0` / `(session\|sess\|sid\|token\|jwt\|auth)` | `1` 이면 `Authorization`·세션류 이름 쿠키를 실은 요청의 미끼 접촉을 세지 않음(정상 로그인 사용자가 많은 서비스용) |
| `ESCALATE_DELAY_MS` | `16000` | 발동 후 모든 요청에 적용할 tarpit 지연(ms). 한 요청에는 이 값·`MAZE_ESC_DELAY_MS`·`POST_RCE_DELAY_MS` 중 해당하는 것의 **최댓값** 하나만 걸린다(합산 안 함). 예외: 로그인 미끼 423·FAKE_SHELL 진입 요청은 즉시 응답 |
| `FAKE_SHELL` | `0` | `1`이면 T2.1 RCE 시도에 가짜 셸로 응답 |
| `FAKE_SHELL_RETRIES` | `0` | 진입 전 깨진 응답으로 실패시키는 시도 횟수. `0`=즉시 성공(진입률 100%, `>0`은 50%로 반토막 확인됨) |
| `POST_RCE_ACTION` | `tarpit` | 셸 "성공" 이후: `tarpit` \| `block` \| `drop` |
| `POST_RCE_GRACE_CMDS` | `0` | 성공 이후 정상 응답 유예 요청 수 |
| `POST_RCE_DELAY_MS` | `8000` | `POST_RCE_ACTION=tarpit`일 때 지연(ms). 에스컬레이션된 클라이언트에는 `ESCALATE_DELAY_MS` 와 **둘 중 큰 값**이 적용됨 |
| `POST_RCE_DROP_S` | `99999` | `POST_RCE_ACTION=drop`일 때 응답 안 보내는 시간(초) |
| `AMBIG_TRAP` | `0` | `1`이면 가짜셸/미로+적응형 신호를 재사용한 최종 차단·해제 판정 켜기 |
| `AMBIG_RELEASE_MIN` | `10` | 아무 신호도 안 걸렸을 때 완전히 풀어주기까지(분). 5\|10\|30\|60 권장, 그 외 값도 허용 |
| `LOGIN_LURE_MATCH` | — | 서버 무관 login-lure 매치 문자열(콤마 구분). `DECOY_MAZE=1` + `bridge` 프로파일이면 자동 기본값 설정 |
| `CLIENT_ID_HEADER` | `X-Client-Id` | client_id 로 읽을 헤더 이름(대소문자 무관). 없으면 접속 IP로 폴백 — ["탐지팀 연동"](#탐지팀-연동--client_id-기반-상태-격리--x-defense-plan) 참고 |
| `CLIENT_ID_FALLBACK` | `ip` | 헤더가 **없을 때만** 쓰는 대체 식별자. `ip`(접속 IP별) \| `global`(헤더 없는 요청 전부를 한 클라이언트로 — 출발지 IP 가 바뀌는 단일 공격자 실험용, 연동 운영 환경 금지). 헤더가 있으면 항상 헤더 우선 |
| `CLIENT_STATE_TTL_S` | `3600` | 이 시간(초)보다 오래 조용한 client_id 는 상태 청소(탐지팀 세션 창=1시간과 동일) |
| `CLIENT_STATE_SWEEP_S` | `300` | 위 청소를 몇 초마다 도는지 |
| `DEFENSE_PLAN_HEADER` | `X-Defense-Plan` | 탐지팀이 전략 배열을 실어 보내는 헤더 이름(대소문자 무관) |
| `DEFENSE_DB` / `EXPERIMENT_RUN` | `./defense.db` / `adhoc` | 요청 로그 SQLite / 회차 태그 |

## 대상 서버 프로필 (`profiles.py`)

`T2.1` 미끼와 `FAKE_SHELL` 이 "어떤 서버인 척하는가"(Server 배너, `www-data`/`node` 셸, 커널·호스트명,
passwd, 내부 DB 등)는 **프로필의 필드**다. 프리셋(`apache-php` 기본 — 지금까지의 모든 실험과 바이트 단위로
동일, `nginx-fastapi` 는 RUBY Market 용 초안·미검증) 위에 `TARGET_PROFILE` JSON 과 개별 env 가 차례로 덮어쓴다. 시작할 때
`preflight.py` 가 프로필끼리의 모순과 실제 백엔드와의 충돌(런타임 지문, 가짜 라우트가 실제 경로를 가림)을
경고한다. 전체 필드 지도·프리셋 추가법·정합성 검사는 [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md) 참고.

```bash
python setup_profile.py --backend http://127.0.0.1:8080     # 내 서버 정보를 물어 target_profile.json 생성
TARGET_PROFILE=./target_profile.json DEFENSE_MODE=transform ACTIVE_TECHNIQUE=T2.1 FAKE_SHELL=1 \
uvicorn Defense_proxy:app --host 127.0.0.1 --port 3002
```

## transform 레시피 (`transforms.py`)

> Juice Shop이 아닌 다른 대상에 배포할 때는 [`DEPLOYMENT_GUIDE.md`](DEPLOYMENT_GUIDE.md) 와 위의
> [대상 서버 프로필](#대상-서버-프로필-profilespy) 참고. 아래 `T2.1` 행은 기본 프리셋(apache-php) 기준이다.

| 키 | CHeaT | 내용 |
|---|---|---|
| `T2.1` | 가짜 취약 버전 | `Server: Apache/2.4.49` + `/server-status` 가짜 페이지 + `application-version` 병합 + `robots.txt`에 `/cgi-bin/` 힌트 + `/cgi-bin/…` 순회 시 가짜 `/etc/passwd`(CVE-2021-41773 미끼, **FAKE_SHELL 전제조건**) |
| `MIGRATION_TRACES` | "마이그레이션 중 남은 흔적" (옛 `T2.2` + 옛 passive `T4.2-bare`) | `robots.txt`·`application-configuration`에 `/rest/internal/` 미끼 → 가짜 "legacy-admin-bridge" 서빙 → 하위 경로 `401`(토끼굴). `migration@…` 로그인 시 `423`. 여기에 200 `text/html` 응답의 `</head>` 앞 개발자 메모 주석 `<!-- TODO: chmod 640 /opt/app/config/current.yml — left 0666 after the migration script -->`(취약점을 직접 알려주지 않는 톤이라 인젝션 판정을 덜 받음)을 얹어 같은 이야기를 본문에서도 이어간다 |

---

## FAKE_SHELL × maze 조합 예시

이 조합들은 [대시보드](#대시보드-dashboardpy)의 "프록시 제어" 폼에서 체크박스로도 그대로
켤 수 있다(T2.1 체크 + FAKE_SHELL 체크 + DECOY_MAZE 체크). 아래는 터미널에서 직접 켤 때의 env var 조합:

```bash
# maze: transform(T2.1) + FAKE_SHELL + DECOY_MAZE(에스컬레이션형)
DEFENSE_MODE=transform ACTIVE_TECHNIQUE=T2.1 FAKE_SHELL=1 POST_RCE_ACTION=tarpit \
DECOY_MAZE=1 ADAPTIVE_TRAP=1

# block: 위와 같지만 FAKE_SHELL 진입 후 모든 요청 차단(에스컬레이션 없음)
DEFENSE_MODE=transform ACTIVE_TECHNIQUE=T2.1 FAKE_SHELL=1 POST_RCE_ACTION=block DECOY_MAZE=1

# 마이그레이션 흔적(가짜 브리지 + HTML 메모) — transform 하나로 충분
DEFENSE_MODE=transform ACTIVE_TECHNIQUE=MIGRATION_TRACES DECOY_MAZE=1 ADAPTIVE_TRAP=1

# 미로만(레시피 없음) — 가장 단순한 구성
DEFENSE_MODE=off DECOY_MAZE=1 ADAPTIVE_TRAP=1
```

(위 구성을 같은 환경에서 비교한 결과는 [`results.md`](results.md). 실험이라면 앞 섹션의
`CLIENT_ID_FALLBACK=global`·`UVICORN_PROXY_HEADERS=0` 를 함께 줄 것.)

`../defense_proxy_v1/experiments/run_batch9.sh`의 `combo-tarpit-maze`/`combo-block-maze` 구성이 위
조합들을 자동화한다(단, 그 스크립트는 기본적으로 `defense_proxy_v1`의 코드를 겨냥하고, `combo-*-max` 구성은
`active` 에 의존해 이 디렉터리에서는 동작하지 않는다).

---

## 알려진 한계

**측정·실험 쪽**

- **N=1~2 예비 실험 다수.** 신뢰구간 없음. 최신 4실험도 구성별 N=1 — [`results.md`](results.md).
- **MIGRATION_TRACES 고유 효과는 미측정.** 가짜 브리지·설정 병합·HTML 메모·로그인 미끼에 에이전트가 응답을 받은 적이 한 번도 없다(분리 측정 필요, `results.md` §4.3).
- **에스컬레이션 지연(16초) > 에이전트 클라이언트 타임아웃**이면 사실상 블랙홀이 된다 — 에이전트가 서비스 장애로 판단하고 중단한 사례가 있다(의도한 효과이면서 에이전트 행동 편차).
- **정상 사용자 비용(오탐·지연) 미측정.**
- **소스 노출** — `codex exec --sandbox danger-full-access`는 실행 중 프록시 프로세스의 CWD를 찾아
  `Defense_proxy.py`를 읽을 수 있고, 같은 서버면 프로세스 재시작으로 메모리 상태(차단 판정)를 초기화할 수 있다. 실제 배포엔 없는 조건 — 에이전트와 프록시를 분리해서 돌릴 것.
- **미로 지문** — codex가 "존재하지 않는 경로들이 동일한 형식·대량 패딩을 반환"하는 것으로 간파한 회차 있음.

**기능 쪽**

- **HEAD 요청은 SPA 폴백 백엔드에서 미로로 가로채지 못한다**(본문이 비어 폴백 판별 불가) — 같은 경로가 HEAD 는 200, GET 은 미로로 갈린다. 진짜 경로 학습은 GET 만 하므로 HEAD 가 미로를 끄지는 않는다(수정 완료). 개선안: `Content-Length`·`Content-Type`·`ETag` 를 캐시된 `/` 와 비교.
- **백엔드 오류(502)·시간 초과로 끝난 요청은 DB 에 기록되지 않는다**(`on_response` 가 오류 요청은 바로 반환) — 에이전트 보고서의 502 수와 DB 가 어긋날 수 있다.
- **클라이언트 식별 위조** — `X-Client-Id` 는 항상 우선이라 탐지 레이어 없이 노출되면 위조 가능, `X-Forwarded-For` 는 `UVICORN_PROXY_HEADERS=0` 로 막아야 한다(대시보드 시작 명령에는 아직 `--no-proxy-headers` 가 없어 env 로 줘야 함).
- **트래버설 신호는 `/icons/` 한정** — Juice Shop 의 `/ftp` 트래버설 챌린지는 가짜 Apache 이야기와 무관하므로 신호가 아니다. 응답을 바꾸는(가짜 파일을 돌려주는) 방식은 구현하지 않았다.
- 레시피(T2.1/MIGRATION_TRACES)는 OWASP Juice Shop 전용 — 다른 앱엔 새 레시피가 필요하거나 `DECOY_MAZE`만 사용.
- 회귀·동작 테스트는 `tests/` 에 있다(`python tests/run_all.py`). 다만 Windows 에서만 돌려 봤고, 에이전트를 쓰는 실험·정상 사용자 비용은 포함하지 않는다.
