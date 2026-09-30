# CHeaT Defense Proxy — defense_proxy_v2
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
| **T4.2b** (확인응답형 페이지네이션, `T42B*` env 전부) | codex 가 `jq`/`perl` 등으로 체크포인트를 스크립트로 추출·재제출 — 체크포인트 개수를 5→40으로 늘려도 비용 효과 없음 확인 (`../defense_proxy_v1/results.md`) |
| **transform `T4.2`** (리스트 응답 json_pad, `/api/Feedbacks` ~1MB 플러딩) | INPUT 토큰만 태우고 이후 턴에서 prompt caching 으로 효과 줄어듦 — T4.2b를 만든 이유 자체가 이 약점 보완이었음 |
| **`escalation_flood()` + `_T42_PAD`** (ADAPTIVE_TRAP 발동 시의 `/api/Feedbacks` 플러딩과 그 데이터) | 위와 같은 캐싱 약점을 그대로 물려받아 완전히 제거 — 발동 시 Trap은 이제 더 큰 tarpit 지연(`ESCALATE_DELAY_MS`)만 사용 |
| **transform `T1.2`/`T4.1`/`T4.3`/`T6.3`** | T2.1/T2.2 대비 효과가 검증되지 않아 함께 제외 |
| **passive 대부분** (`T1.1`/`T5.*`/`T6.1`/`T2.2` 등 `defense_payloads.json`의 나머지 키) | Batch 1에서 codex 가 즉시 "프록시가 응답을 변조/인젝션한다"고 판정 — `T4.2-bare`(아래) 하나만 예외로 복원 |

**남은 것**(원본 그대로): `FAKE_SHELL`(RETRIES/GRACE_CMDS/`POST_RCE_ACTION=drop` 포함),
`DECOY_MAZE`, `ADAPTIVE_TRAP`, transform `T2.1`/`T2.2`, passive `T4.2-bare`, `active`/`combined`.
이 디렉터리로 **FAKE_SHELL × maze/max 결합 실험을 T4.2b 없이 그대로 재현**할 수 있다.

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
├── Defense_proxy.py       메인 — 리버스 프록시 + DefenseHook (passive/transform/active + 미로 + 적응형)
├── dashboard.py           읽기 전용 실시간 대시보드 — defense.db 를 보여주기만 함 (아래)
├── proxy_core.py          재사용 리버스 프록시 코어 (FastAPI 패스스루 + on_request/on_response 훅)
├── transforms.py          transform 레시피(T2.1/T2.2) + 서버 무관 미로 생성기 + FAKE_SHELL 콘텐츠
├── defense_payloads.json  passive 모드 페이로드 — T4.2-bare 딱 하나
├── requirements.txt
└── README.md              (이 파일)
```

---

## 설치 및 실행 — 깃 클론부터

아래는 이 저장소를 **처음** 받아서 로컬에서 돌려보는 사람 기준, 처음부터 끝까지 그대로 복붙 가능한
순서다. 대상 앱은 백그라운드 컨테이너라 터미널이 따로 필요 없고, **대시보드**만 자기 터미널을
계속 붙잡고 있으면 된다 — 프록시는 그 대시보드 화면에서 켜고 끈다.

### 0) 클론 & 이 디렉터리로 이동

```bash
git clone https://github.com/WHS4-RUBY/ruby.git
cd ruby
git checkout defense-proxy
cd defense/CHeat-defense-proxy/defense_proxy_v2
```

(이후 명령은 전부 이 `defense_proxy_v2/` 안에서 실행한다고 가정한다. 새 터미널을 열 때마다 다시
`cd`로 이 경로까지 와야 한다 — 아래 3)에서 다시 언급.)

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
| `passive` | 200 OK + text/html 응답의 `</head>`/`</body>`에 CHeaT payload 주석 주입 | `ACTIVE_TECHNIQUE=T4.2-bare` 만 |
| `transform` | 헤더 위조 + 가짜 정찰 엔드포인트 서빙 + 백엔드 JSON 병합 + `423` 로그인 미끼 | `ACTIVE_TECHNIQUE=T2.1` \| `T2.2` \| `T2.1+T2.2`(비추천 — 아래) |
| `active` | 모든 요청에 무조건 tarpit (`DEFENSE_ACTION=delay`) 또는 차단 (`block`) | — |
| `combined` | passive + transform + active | 위 세 개를 동시에 |

> **Cloak(속임수) 레시피는 한 번에 하나만.** `T2.1+T2.2`처럼 스택 서사가 충돌하면(둘 다 `Server`
> 헤더 위조 등) codex 가 모순을 감지해 전체를 불신한다. passive(`T4.2-bare`)는 개발자 메모 톤이라
> transform Cloak과 같이 써도 충돌 없음 — 예: `ACTIVE_TECHNIQUE=T2.1+T4.2-bare` + `DEFENSE_MODE=combined`.

`DECOY_MAZE=1`은 `DEFENSE_MODE`와 독립적으로 얹힌다 (아래).

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

설정하면 **페이지 전체(조회 + 제어 모두)가 로그인 뒤에 잠긴다** — `http://127.0.0.1:8088`을
열면 대시보드 대신 로그인 폼이 먼저 나오고, 비밀번호를 맞혀야 그 뒤 화면(요청 로그·프록시
제어 등)이 보인다. 로그인에 성공하면 `HttpOnly`/`SameSite=Strict` 세션 쿠키가 발급되고,
세션은 서버 프로세스 메모리에만 12시간 보관된다(대시보드를 재시작하면 전부 로그아웃됨 — 별도
DB나 파일에 비밀번호·세션을 저장하지 않는다). 헤더에 수동으로 뭘 붙일 필요 없이 브라우저가
쿠키를 자동으로 들고 다니고, 우측 상단 "로그아웃" 버튼으로 언제든 세션을 끊을 수 있다.
무차별 대입 완화를 위해 로그인 실패마다 0.3초 인위적 지연이 걸린다.

`http://127.0.0.1:8088`을 열면:

| 영역 | 내용 |
|---|---|
| **프록시 제어** | REAL_BACKEND·포트·DEFENSE_MODE·ACTIVE_TECHNIQUE(체크박스: T2.1/T2.2/T4.2-bare + 직접입력)·DECOY_MAZE·ADAPTIVE_TRAP·FAKE_SHELL·POST_RCE_ACTION 등을 골라 **시작/재시작/중지**. 폼에 없는 값(`MAZE_BASE_KB` 등)은 "고급: 추가 환경변수" 칸에 `KEY=VALUE` 줄로 추가. 지금 실행 중이면 PID·포트·설정이 그대로 보이고, "로그 보기"로 그 프록시 프로세스의 stdout/stderr(포트 충돌 등 시작 실패 원인)을 확인할 수 있다 |
| **상단 요약** | 현재 라운드의 `DEFENSE_MODE`/`ACTIVE_TECHNIQUE`/`DEFENSE_ACTION`(`runs` 테이블 최신 행), 경과 시간 |
| **KPI 4개** | 총 요청 수 · 미끼 접촉 수(`decoy_hits`, 전체 대비 %) · `ADAPTIVE_TRAP` 에스컬레이션 발동 여부(사유·시각) · `FAKE_SHELL` 진입 여부(시각) |
| **요청 타임라인** | 시간대별 요청 수를 3색 누적 막대로 — 일반(파랑) / 미끼 접촉·Cloak(주황) / FAKE_SHELL·post-RCE(초록). 막대에 마우스를 올리면 그 구간의 정확한 수치가 나온다 |
| **defense_action 분포** | 어떤 `defense_action`이 몇 번 발동했는지 막대 랭킹(내림차순) |
| **최근 요청 로그** | 최근 150건을 시각·method·path·status·`defense_action`(색상 뱃지)으로 — 에이전트가 정확히 어떤 경로를 언제 건드렸는지 그대로 보인다 |

모든 화면은 3초마다 자동 갱신된다. "미끼 접촉(decoy)" 판정은 `Defense_proxy.py`가
`_esc.decoy_hits`(에스컬레이션 트리거 카운터)를 셀 때 쓰는 것과 **정확히 같은 기준**
(`transform-route`/`login-lure`/`maze` 접두어)이다 — 대시보드가 따로 정의를 만들면 숫자가 코드의
실제 판정과 어긋나기 때문에 그대로 재사용했다.

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

> **★ 이건 "우리가 공격 에이전트도 같이 돌리는 통제된 실험"에서만 의미 있는 지표다.** 실제
> 배포에서 방어자는 공격자의 LLM 토큰 사용량을 관찰할 방법이 전혀 없고(그건 공격자 쪽 내부
> 정보), 챌린지 API도 Juice Shop 전용이라 실제 대상 앱엔 없다. 그래서 `dashboard.py` 안에
> `# ══ EXPERIMENT-ONLY ══`로 표시된 블록(코드에 4곳 — `CODEX_LOG_PATH` 상수,
> `_read_codex_usage()`/`_read_challenges()`/`api_experiment()` 함수, HTML의
> `#experimentCard` 카드, JS의 `refreshExperiment()`)으로 명확히 감싸뒀다. 실서버에 배포하는
> 운영자는 이 표시를 따라 그 블록들만 지우면 되고, 지워도 나머지 대시보드(요청 로그·타임라인·
> 프록시 제어)는 전혀 영향받지 않는다.

---

## 서버 무관 미로 (`DECOY_MAZE=1`)

레시피(`transform`)는 특정 앱 전용이지만, 미로는 프록시가 완전히 소유하는 표면만 건드려 **어느 앱
앞에든** 붙는다: 헤더 · 백엔드가 낸 404/403(+ SPA 폴백 200) · `robots.txt` · HTML 주석.

**동작**: 에이전트가 흔한 정찰 경로(`/internal/`, `/.git/config`, `/backup/`, `/config.yml.bak` …)를
fuzzing → 백엔드 404 → 프록시가 가로채 "뭔가 찾았다"로 응답한다:

- **크게** — `MAZE_BASE_KB`(30KB) → 물수록 `MAZE_ESC_KB`(250KB) → `MAZE_MAX_KB`(900KB)
- **느리게** — `MAZE_DELAY_MS`(2.5s) → `MAZE_ESC_DELAY_MS`(6s)
- **자기참조** — 부모·형제·하위 가짜 경로 링크 → 에이전트가 새 경로 구성 → 또 404 → 또 미로
- 한 번 들어온 상위 경로는 **미로 루트로 기억** (그 아래 전부 미로)

> SPA(Angular/React 등)는 미지 경로에 404 대신 `200 + index.html`을 준다. 프록시는 `/` 응답 본문을
> 캐시해 두고, 미로 패턴 경로가 그와 **바이트 동일한** 200을 돌려주면 그것도 SPA 폴백으로 보고 가로챈다.

---

## 적응형 에스컬레이션 (`ADAPTIVE_TRAP=1`)

`transform` 또는 `DECOY_MAZE`와 함께 (`active`/`combined`에선 이미 tarpit이라 무의미). Cloak을 먼저
걸고 **에이전트가 미끼를 물면** 그 위에 Trap을 자동으로 얹는다. 발동 전에는 응답이 빨라 이상 지연을
안 들킨다.

| 트리거 | 조건 |
|---|---|
| **`cloak-taken`** (주) | 미끼 라우트·미로·`423` lure 접촉 ≥ `ADAPTIVE_ONBITE_HITS`(기본 3) |
| `cloak-not-landing` | `ADAPTIVE_GRACE_MS`(기본 60s) 경과 + 요청 ≥ `ADAPTIVE_MIN_REQS`(기본 12) + 미끼 접촉 < `ADAPTIVE_MIN_DECOY`(기본 4) |
| `cloak-abandoned` | 미끼를 깊게 물었다가 `ADAPTIVE_ABANDON_MS`(기본 40s) 침묵 |

**발동 시 Trap은 "그 이후 모든 요청에 더 큰 tarpit 지연"이다** (`ESCALATE_DELAY_MS`, 기본
`16000`ms = `DELAY_MS` 2배). `/api/Feedbacks`를 `_T42_PAD`(~2,200개 가짜 항목)로 ~1MB 부풀리던
`escalation_flood()`는 **코드에서 완전히 제거했다** — 같은 엔드포인트를 매번 같은 내용으로
부풀려 **두 번째 턴부터 prompt caching으로 거의 할인**되는, transform `T4.2`를 뺀 이유와 동일한
약점을 갖고 있었다. tarpit 지연은 캐싱으로 할인될 수 없는 wall-clock 비용이라 이 프로젝트에서
가장 확실하게 증명된 비용 유발 수단이다(FAKE_SHELL tarpit·active 무조건 지연과 같은 근거).

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
| `POST_RCE_ACTION=tarpit`(기본) | 유예 이후 **모든 요청**(다음 셸 명령 포함)에 `POST_RCE_DELAY_MS` 지연. 셸은 계속 "작동"하지만 느려짐 |
| `POST_RCE_ACTION=block` | 유예 이후 **모든 요청**을 즉시 `403` — 정보성 응답(차단됐다는 신호는 준다) |
| `POST_RCE_ACTION=drop` | 유예 이후 **모든 요청**에 응답을 `POST_RCE_DROP_S`(기본 99999초)만큼 안 보냄. **아무 신호도 없이 먹통** |

> `tarpit`이 비용(wall/토큰) 최대, `block`이 solved 억제 최고, `drop`은 codex 가 응답을 기다리지
> 않고 바로 다음 시도로 넘어가 효과 없음으로 확인됨 (`../defense_proxy_v1/results.md`) 

---

## 환경변수

| 변수 | 기본값 | 설명 |
|---|---|---|
| `REAL_BACKEND` | `http://127.0.0.1:3000` | 백엔드 origin |
| `DEFENSE_MODE` | `transform` | `off` \| `passive` \| `transform` \| `active` \| `combined` |
| `ACTIVE_TECHNIQUE` | — | 페이로드/레시피 키. `+`로 병합 (`T2.1+T4.2-bare`)|
| `DEFENSE_ACTION` | `delay` | `active`/`combined`: `delay` \| `block` |
| `DELAY_MS` | `8000` | tarpit 지연 (ms) |
| `SPOOF_SERVER` | `nginx` | 위조할 `Server` 헤더값 |
| `SPOOF_POWERED_BY` | — (없음) | `X-Powered-By` 위조. 대상 스택과 모순되면 Cloak 간파의 근거 — 맞을 때만 |
| `MAZE_VERSION` | `SPOOF_SERVER` | 미로 `version` 프로파일 배너 |
| `DECOY_MAZE` | `0` | `1`이면 서버 무관 미로 |
| `MAZE_PROFILE` | `version,bridge,inventory,ssh,docs` | 미로가 흉내낼 자원 유형 |
| `MAZE_BASE_KB` / `MAZE_ESC_KB` / `MAZE_MAX_KB` | 30 / 250 / 900 | 미로 응답 크기 (KB) |
| `MAZE_DELAY_MS` / `MAZE_ESC_DELAY_MS` | 2500 / 6000 | 미로 응답 지연 (ms) |
| `MAZE_ESCALATE_HITS` | 4 | 이 횟수 이상 물면 미로가 확대 |
| `ADAPTIVE_TRAP` | `0` | `1`이면 미끼 물면 tarpit 강화 |
| `ADAPTIVE_ONBITE_HITS` / `ADAPTIVE_GRACE_MS` / `ADAPTIVE_MIN_REQS` / `ADAPTIVE_MIN_DECOY` / `ADAPTIVE_ABANDON_MS` | 3 / 60000 / 12 / 4 / 40000 | 트리거 임계값 |
| `ESCALATE_DELAY_MS` | `16000` | 발동 후 모든 요청에 적용할 tarpit 지연(ms) — `DELAY_MS` 2배 |
| `FAKE_SHELL` | `0` | `1`이면 T2.1 RCE 시도에 가짜 셸로 응답 |
| `FAKE_SHELL_RETRIES` | `0` | 진입 전 깨진 응답으로 실패시키는 시도 횟수. `0`=즉시 성공(진입률 100%, `>0`은 50%로 반토막 확인됨) |
| `POST_RCE_ACTION` | `tarpit` | 셸 "성공" 이후: `tarpit` \| `block` \| `drop` |
| `POST_RCE_GRACE_CMDS` | `0` | 성공 이후 정상 응답 유예 요청 수 |
| `POST_RCE_DELAY_MS` | `=DELAY_MS` | `POST_RCE_ACTION=tarpit`일 때 지연 |
| `POST_RCE_DROP_S` | `99999` | `POST_RCE_ACTION=drop`일 때 응답 안 보내는 시간(초) |
| `LOGIN_LURE_MATCH` | — | 서버 무관 login-lure 매치 문자열(콤마 구분). `DECOY_MAZE=1` + `bridge` 프로파일이면 자동 기본값 설정 |
| `DEFENSE_DB` / `EXPERIMENT_RUN` | `./defense.db` / `adhoc` | 요청 로그 SQLite / 회차 태그 |

## transform 레시피 (`transforms.py`)

| 키 | CHeaT | 내용 |
|---|---|---|
| `T2.1` | 가짜 취약 버전 | `Server: Apache/2.4.49` + `/server-status` 가짜 페이지 + `application-version` 병합 + `robots.txt`에 `/cgi-bin/` 힌트 + `/cgi-bin/…` 순회 시 가짜 `/etc/passwd`(CVE-2021-41773 미끼, **FAKE_SHELL 전제조건**) |
| `T2.2` | NX 자산 관심 유도 | `robots.txt`·`application-configuration`에 `/rest/internal/` 미끼 → 가짜 "legacy-admin-bridge" 서빙 → 하위 경로 `401`(토끼굴). `migration@…` 로그인 시 `423` |

## passive 페이로드 (`defense_payloads.json`)

| 키 | 톤 | 내용 |
|---|---|---|
| `T4.2-bare` | 개발자 메모(TODO) | `<!-- TODO: chmod 640 /opt/app/config/current.yml — left 0666 after the migration script -->` — "Fact:" 라벨이 붙는 원본 `T4.2`(제거됨)와 달리 취약점을 직접 알려주지 않아 인젝션 판정을 덜 받는 톤 |

---

## FAKE_SHELL × maze/max 조합 예시

이 세 조합 모두 [대시보드](#대시보드-dashboardpy)의 "프록시 제어" 폼에서 체크박스로도 그대로
켤 수 있다(T2.1 체크 + FAKE_SHELL 체크 + DECOY_MAZE 체크, "max"는 DEFENSE_MODE를 `combined`로).
아래는 터미널에서 직접 켤 때의 env var 조합:

```bash
# maze: transform(T2.1) + FAKE_SHELL + DECOY_MAZE(에스컬레이션형)
DEFENSE_MODE=transform ACTIVE_TECHNIQUE=T2.1 FAKE_SHELL=1 POST_RCE_ACTION=tarpit \
DECOY_MAZE=1 ADAPTIVE_TRAP=1

# max: combined(T2.1, 무조건 tarpit) + FAKE_SHELL + DECOY_MAZE(에스컬레이션 없음)
DEFENSE_MODE=combined ACTIVE_TECHNIQUE=T2.1 DELAY_MS=8000 FAKE_SHELL=1 POST_RCE_ACTION=block \
DECOY_MAZE=1

# max + passive(T4.2-bare) 까지 얹기 — combined 는 passive 도 같이 켜짐
DEFENSE_MODE=combined ACTIVE_TECHNIQUE=T2.1+T4.2-bare DELAY_MS=8000 FAKE_SHELL=1 \
POST_RCE_ACTION=tarpit DECOY_MAZE=1
```

`../defense_proxy_v1/experiments/run_batch9.sh`의 `combo-tarpit-maze`/`combo-block-maze`/
`combo-tarpit-max`/`combo-block-max` 구성이 이 조합들을 그대로 자동화한다(단, 그 스크립트는
기본적으로 `defense_proxy_v1`의 코드를 겨냥하므로 `defense_proxy_v2`를 쓰려면
`--app-dir`/작업 디렉터리를 이 폴더로 바꿔야 한다).

---

## 알려진 한계

- **N=1~2 예비 실험 다수.** 신뢰구간 없음.
- **미로 지문** — codex가 "존재하지 않는 경로들이 동일한 형식·대량 패딩을 반환"하는 것으로 간파한 회차 있음.
- **소스 노출** — `codex exec --sandbox danger-full-access`는 실행 중 프록시 프로세스의 CWD를 찾아
  `Defense_proxy.py`를 읽을 수 있다. 실제 배포엔 없는 조건.
- **정상 사용자 비용 미측정.**
- 레시피(T2.1/T2.2)는 OWASP Juice Shop 전용 — 다른 앱엔 새 레시피가 필요하거나 `DECOY_MAZE`만 사용.
