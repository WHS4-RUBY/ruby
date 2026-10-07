# 새 대상 서버에 배포하기 — 서버 프로필(프리셋 + 내 서버 정보)

이 프록시는 지금까지 전부 **OWASP Juice Shop**을 대상(`REAL_BACKEND`)으로 실험했다. 다른 서버에서 미끼들의 모순들 막기 위해 **프로필**(`profiles.py`)의
필드로 입력받아 3단계로 정해진다(뒤가 앞을 덮어쓴다):

```
프리셋(PRESETS)  <  프로필 파일(TARGET_PROFILE, JSON — 바꿀 필드만)  <  개별 env(T21_* · MIGRATION_* 등)
```

**아무것도 안 하면 기본 프리셋 `apache-php`**

---

## 1) 빠른 시작

```bash
# 대화형 — 백엔드를 물어보고 지문으로 프리셋을 추천한 뒤, 내 서버 정보를 묻는다
python setup_profile.py --backend http://127.0.0.1:8080

# 비대화형 — 프리셋 + 몇 개만 덮어쓰기
python setup_profile.py --preset nginx-fastapi --set shell.hostname=web-01 --out target_profile.json --yes

# 실행
TARGET_PROFILE=./target_profile.json DEFENSE_MODE=transform ACTIVE_TECHNIQUE=T2.1 FAKE_SHELL=1 \
uvicorn Defense_proxy:app --host 127.0.0.1 --port 3002
```

대시보드의 "대상 서버 프로필" 칸(`TARGET_PRESET` 드롭다운 + `TARGET_PROFILE` 경로)으로도 같은 걸 고를 수 있다.

프로필 설정 도구는 호스트명을 바꾸면 `kernel` 문자열 안의 호스트명도, 사용자를 바꾸면 `passwd` 줄도 같이 맞춰서
`hostname`↔`uname -a`, `whoami`↔`/etc/passwd` 모순을 막는다. 끝나면 정합성 검사(§4)를 한 번 돌린다.

## 2) 프리셋 — 미끼와 셸 페르소나를 한 쌍으로

| 프리셋 | 미끼 | 셸 세계 | 상태 |
|---|---|---|---|
| `apache-php` (기본) | Apache 2.4.49 + PHP, `/server-status`, `/cgi-bin/` traversal(CVE-2021-41773) → RCE | `www-data`(uid 33), Ubuntu 5.4 커널, `/var/www/html` | **실측됨** (모든 실험) |
| `nginx-fastapi` | nginx 1.27 + FastAPI(Python), `/nginx_status`, API 업그레이드 때 남은 `/_debug/` 라우터 → exec. `X-Powered-By` 는 없음(실제 스택과 같게) | `appuser`(uid 10001), Alpine 컨테이너(`/bin/ash`, `uname` 끝 `Linux`), `/app` | **초안 — 검증 못 함** (RUBY Market 대상) |

nginx 쪽엔 Apache의 CVE-2021-41773처럼 "배너만 보고 바로 RCE로 이어지는" 대표 CVE가
없어서 `nginx-fastapi` 미끼는 "디버그 라우터가 남아 있다"는 이야기로 만들었다 
알려진 약점: Alpine 컨테이너에는 보통 `sudo`·SUID 헬퍼가 없어 `sudo -l` 퀘스트의 신빙성이 `apache-php` 보다 낮다. 이 프리셋은
RUBY Market 앞에 맞춘 것이고, `X-Powered-By` 를 일부러 비웠기 때문에 preflight 가
"family `python` 의 단서가 배너에 없다"는 INFO 를 한 줄 낸다(정상).

## 3) 프로필 필드 지도

`profiles.py` 의 `PRESETS` 가 정답지다. 프로필 JSON 에는 **바꿀 필드만** 적는다(+ `"preset"`). 알 수 없는
필드는 오타일 가능성이 커서 에러로 알려준다.

| 그룹 | 필드 | 뭘 하나 | 새 서버에선 |
|---|---|---|---|
| `web` | `server_banner` | T2.1 응답의 `Server` 헤더, `/…status` 페이지, 버전 API 병합 값 | 대상 스택과 맞는 배너 |
| | `x_powered_by` | `X-Powered-By` 위조(없으면 `null`) | 대상 런타임과 맞을 때만. 모순이면 역효과 |
| `lure` | `status_page.path/kind` | 가짜 상태 페이지 경로와 형식(`apache`/`nginx`) | 서버 종류에 맞게 |
| | `file_prefix`, `file_match_any` | traversal 미끼 라우트. **이 접두어 아래 경로는 가짜 라우트가 가로챈다** | **실제 앱에 없는** 접두어 (정합성 검사가 존재 여부를 확인) |
| | `probe_paths` | 이 접두어 아래에 `..` 경로 탈출이 오면 미끼 접촉으로 센다(응답은 안 바꿈). 기본 apache-php `["/icons/"]` — CVE-2021-41773 공개 PoC 의 파일 읽기 경로 | 서버 설정에서 확인한 Apache 별칭. 앱 자체 트래버설 챌린지 경로(`/ftp/` 등)는 **넣지 않는다**. 백엔드에 이미 있어도 정상 요청엔 `..` 가 없어 안전 |
| | `shell_entry_regex`, `shell_entry_example` | FAKE_SHELL 이 발동하는 RCE POST 경로와 그 예시(자체 검증용) | 미끼 이야기와 일치하게 |
| | `robots_disallow`, `robots_comment` | robots.txt 힌트 | 위 미끼 경로와 일치 |
| `shell` | `user/uid/gid`, `hostname`, `kernel`, `webroot` | `id`·`whoami`·`hostname`·`uname -a`·`pwd` 의 답 | 대상 환경(컨테이너/VM, 배포판) |
| | `passwd` | `cat /etc/passwd` 의 줄들 (사용자·uid 와 일치해야 함) | 대상 계정 패턴 |
| | `ops_script`, `helper_bin`, `backup_dir`, `sudo_secure_path` | `sudo -l` 퀘스트(backup 스크립트, SUID 헬퍼) | 대상 운영 관례 |
| | `db_host/port/user/password/name`, `bridge_path` | 백업 아카이브 속 가짜 DB 자격증명과 HTTP 브리지 힌트(미로로 이어짐) | 그럴듯한 내부 IP·DB 이름 |
| | `suid_hits` | `find -perm -4000` 결과 | 배포판에 맞는 목록 |
| `maze` | `paths` | DECOY_MAZE 입구 경로 — robots 의 `Disallow` 줄이 되고 같은 목록이 미로 판정에도 합쳐진다 | **실제 앱에 없는** 경로. 있으면 preflight 가 경고 |
| | `entry_path`, `comment_text` | `Link` 헤더·HTML 주석이 가리키는 입구 문서와 주석 문구 | `paths` 아래 경로, 조직 어휘에 맞는 문구 |
| | `exclude` | 미로에서 뺄 실제 경로 정규식 | SPA 의 `/admin` 같은 실제 라우트와 겹칠 때 |
| `migration` | `api_prefix` | MIGRATION_TRACES 가짜 브리지를 둘 API 접두어(끝 `/` 없이). 이 아래를 가짜 라우트가 전부 가로챈다 | **실제 앱에 없는** 접두어, 대상 앱의 API 관례(`/rest`·`/api`)를 따라서(프로필 설정 도구로 입력) |
| | `bridge_name`, `bridge_version`, `rollout_note` | `X-Backend-Bridge` 헤더·상태 JSON 의 서비스 이름·버전·설명 | 대상 앱 버전을 사칭하지 말 것 |
| | `endpoints` | 401 토끼굴 하위 경로 이름(예: `users`·`orders`·`config-dump`) | 대상 앱의 실제 도메인 명사(고객·주문·판매자)에 맞춤 |
| | `lure_match`, `login_path` | 로그인 본문에 이 문자열이 있으면 401 대신 423 locked / 그 POST 경로 | 미끼 계정(대상 도메인 이메일 형식)·실제 로그인 API 경로(프로필 설정 도구로 입력) |
| | `memo_path` | HTML 개발자 메모 주석이 말하는 설정 파일 경로 | 셸 세계(`shell.webroot`)와 어울리는 경로(프로필 설정 도구로 입력) |
| | `robots_disallow`, `config_path` | robots.txt 힌트 / `adminBridgeBase` 를 병합해 넣을 **진짜 JSON 엔드포인트**(빈 값이면 병합 안 함) | 접두어와 일치 / 그 앱에서 JSON 을 주는 경로(없으면 빈 값) |
| 최상위 | `family` | 정합성 검사가 쓰는 스택 태그(`apache`/`nginx`/`php`/`node`/…) | 프리셋과 맞게 유지 |

`migration.*` 값은 배포 전에 `python setup_profile.py`(프로필 설정 도구)로 입력한다(MIGRATION_TRACES 를 쓰겠다고 답하면 `api_prefix`·`login_path`·`lure_match`·
`memo_path`·`config_path` 를 묻고, 접두어를 바꾸면 `robots_disallow` 의 옛 접두어도 같이 바꿔 준다). 비대화형은
`--set migration.api_prefix=/api/internal --set 'migration.lure_match=["svc-sync@shop.example"]'`, 세부 조정은 `target_profile.json` 의
`migration` 그룹을 직접 편집한다. 아무것도 입력하지 않으면 기본값(`apache-php`=Juice Shop 값 그대로, `nginx-fastapi`=`/api/internal` 등)이 쓰인다.

### 개별 env (프로필보다 우선)

| 변수 | 기본값 | 무엇을 하나 |
|---|---|---|
| `T21_VERSION_PATH` | `/rest/admin/application-version` | T2.1이 `httpServer` 배너를 병합해 넣는 **진짜 백엔드 엔드포인트**(JSON 이어야 함). 없으면 조용히 no-op |
| `MIGRATION_CONFIG_PATH` | 프로필 `migration.config_path` | MIGRATION_TRACES 가 `adminBridgeBase` 를 병합해 넣는 진짜 엔드포인트(빈 값이면 병합 안 함) |
| `T21_ROBOTS_DISALLOW` | 프로필 `lure.robots_disallow` | T2.1 robots.txt 힌트(콤마 구분) |
| `MIGRATION_ROBOTS_DISALLOW` | 프로필 `migration.robots_disallow` | MIGRATION_TRACES robots.txt 힌트 |
| `SPOOF_SERVER`/`SPOOF_POWERED_BY` | `nginx` / 없음 | 미끼 응답이 아닌 **그 외 모든 응답**의 `Server`/`X-Powered-By`. T2.1 배너와 다르면 정합성 검사가 INFO 로 알려준다 |

robots.txt 힌트는 `transforms.synth_robots()`(DECOY_MAZE 와 같은 함수)로 백엔드 robots.txt 에 append 한다.
백엔드에 robots.txt 가 없거나 404·SPA HTML 이면 **미끼 줄만 있는** 새 파일을 만들고 `Disallow: /` 는 넣지 않는다.
미로·적응형·AMBIG_TRAP 은 처음부터 서버 무관하다. 미로 관련 환경변수(`MAZE_PATHS`/`MAZE_EXCLUDE`/
`MAZE_INTERCEPT_403`/`MAZE_SPA_BROWSER_PASS`/`MAZE_REQUIRE_PLAN`)는 [`REFERENCE.md`](REFERENCE.md#환경변수)의 환경변수 표 참고.

## 4) 정합성 검사 (preflight) — 시작할 때 자동

T2.1·FAKE_SHELL 을 쓰면 프로필 검사가, `DECOY_MAZE=1` 이면 미로 검사가 돈다(`PREFLIGHT=0` 이면 끔,
`PREFLIGHT_STRICT=1` 이면 프로필/미로 설정 모순 시 시작 거부).
**경고만 찍고 막지 않는다** — 의도한 서사(edge=nginx, internal=apache)일 수 있기 때문이다.

| 단계 | 검사 | 예 |
|---|---|---|
| 프로필 자체 | 사용자↔passwd↔uid/gid, 호스트명↔커널, 배너↔family, 진입 정규식↔예시 경로, 경로 형식 | `whoami` 는 node 인데 passwd 에 없음 |
| 실제 백엔드 | 쿠키·헤더가 드러내는 런타임(PHPSESSID, connect.sid …)이 family 와 충돌하는지 | 백엔드는 Express 인데 프로필은 PHP |
| 실제 백엔드 | 가짜 라우트가 **실제 존재하는 경로**를 가리는지(정상 서비스 파손 위험) — SPA 의 200 폴백은 제외 | `/_debug/` 가 백엔드에 진짜 있음 |
| 실제 백엔드 | 경로 탈출 신호 접두어(`probe_paths`)가 백엔드에 실제로 있는지 — INFO 만(정상 요청 영향 없음). 형식(`/` 시작·끝)은 WARN | `/icons/` 가 진짜 정적 폴더 |
| 미로 설정 | 광고하는 경로·입구 문서가 미로 판정 정규식에 맞는지, `MAZE_EXCLUDE` 에 걸리지 않는지 | `MAZE_PATTERN` 직접 지정 후 `/internal/` 이 미로가 아님 |
| 미로 vs 백엔드 | 광고 경로가 백엔드에 실제로 있는지(200/3xx/401)·403 인지 | `/admin/` 이 진짜 관리자 페이지 |
| 미로 vs 백엔드 | **SPA 폴백 감지** — 없는 경로에도 `200+index.html` 이면 history 라우팅 클라이언트 라우트와의 충돌 위험을 경고하고 `MAZE_EXCLUDE`·`MAZE_SPA_BROWSER_PASS` 를 안내 | `/admin` 새로고침이 미로로 바뀜 |
| 미로 vs 백엔드 | **진짜 robots.txt 와의 겹침** — 이미 Disallow 한 경로를 미로 입구로 쓰면 경고 | 진짜 `Disallow: /admin` 과 입구 `/admin/` |

## 5) 새 프리셋 추가하기

1. `profiles.py` 의 `PRESETS` 에 `apache-php` 를 복사해 새 이름으로 넣고 `family`·`web`·`lure`·`shell` 을 그 스택에 맞게 고친다.
2. `lure.status_page.kind` 가 `apache`/`nginx` 가 아니면 `transforms.py` 의 `_STATUS_PAGES` 에 본문 생성 함수를 추가한다.
3. `python setup_profile.py --preset <새이름> --yes --out /tmp/x.json` 으로 정합성 검사 통과를 확인한다.
4. 가능하면 로컬 스테이징에 `curl` 로 가짜 라우트·셸 응답이 의도대로 나오는지 직접 확인한다.

## 6) 여전히 사람이 써야 하는 것

| 무엇 | 어디 | 이유 |
|---|---|---|
| MIGRATION_TRACES 의 서버별 값(접두어·엔드포인트 이름·로그인 미끼·메모 경로) | 프로필 `migration.*` — **배포 전에 `setup_profile.py`(프로필 설정 도구)로 입력** | 서비스 이름·경로·계정이 대상 앱의 관례와 안 맞으면 의심받는다. 입력하지 않으면 기본값(Juice Shop 기준)이 쓰여 이질적일 수 있다 |
| MIGRATION_TRACES 의 401 본문·로그인 423 문구 | `transforms.py` (`_MIG_401`, 로그인 미끼 `body`) | 문구 자체는 아직 프로필 필드가 아니다(서버별 값만 뺐다) |
| 새 스택의 **미끼 이야기와 셸 퀘스트** | 프리셋 작성(§5) | 필드를 채우는 건 쉬워도, "그 스택에서 그럴듯한 취약점 이야기"는 만들어야 한다 |
| `FAKE_SHELL` 이 인식하는 **명령 종류** | `transforms.py` `_fake_shell_match` | 프리셋과 무관한 공통 로직. 예: `hostname`·`ps`·`env` 같은 명령은 아직 전용 응답이 없다(확률적 빈 출력/not found) |
| 미로 콘텐츠(`deploy` 사용자, 가짜 하위 경로 이름들) | `transforms.py` `_MAZE_*` | 서버 무관하게 설계했다. 입구 경로·입구 문서·주석 문구만 프로필 `maze.*` 로 바꾼다 |

## 7) 레시피 없이 쓰기 — 미로만

다른 앱에는 T2.1·MIGRATION_TRACES 같은 앱 전용 레시피가 맞지 않을 수 있다. 이때는 서버 무관 구성만으로 시작한다:

```bash
DEFENSE_MODE=off DECOY_MAZE=1 ADAPTIVE_TRAP=1 REAL_BACKEND=http://127.0.0.1:8080 \
uvicorn Defense_proxy:app --host 127.0.0.1 --port 3002 --no-server-header
```

Juice Shop 4실험 중 이 구성이 가장 단순하면서 무방어 대비 효과(해결 챌린지 13→3, 요청 속도 0.49배)가 확인됐다
([`results.md`](results.md)). 단 **미로 입구 경로(`maze.paths`)가 실제 앱 경로와 겹치지 않는지**가 핵심이다 — 시작할 때
preflight(§4)의 미로 검사 결과를 반드시 확인하고, SPA 라면 `MAZE_EXCLUDE`·`MAZE_SPA_BROWSER_PASS` 를 점검한다.

## 8) 운영 시 보안 설정

- 에이전트(공격자)가 프록시와 **같은 서버·같은 권한**이면 프로세스 재시작·소스 열람으로 상태 기반 방어를 우회할 수 있다 — 분리해서 운영.
- `uvicorn` 은 `UVICORN_PROXY_HEADERS=0`(또는 `--no-proxy-headers`)로 띄워 `X-Forwarded-For` 위조로 클라이언트가 바뀌는 것을 막는다.
- 탐지 레이어 없이 단일 공격자를 상대하는 실험이면 `CLIENT_ID_FALLBACK=global`, 연동 운영이면 쓰지 않는다.
- 프록시 포트는 탐지 프록시에서만 접근 가능하게(네트워크 격리) — [`DETECTION_INTEGRATION.md`](DETECTION_INTEGRATION.md) §4.

자세한 근거와 실제 우회 사례는 [`README.md`](README.md#실험-돌릴-때--우회-차단과-라운드-운영).

## 체크리스트 (새 대상에 배포하기 전)

1. 대상의 실제 스택(웹서버/언어/프레임워크)을 조사한다 — 응답 헤더·쿠키 이름이 단서다.
2. 가장 가까운 프리셋을 고르고(`setup_profile.py --backend ...` 가 추천) 내 서버 정보로 덮어쓴다.
3. 정합성 검사에 WARN 이 없는지 확인한다(특히 `lure-shadows-real-path`).
4. `T21_VERSION_PATH`/`MIGRATION_CONFIG_PATH` 를 그 앱의 실제 버전/설정 API 경로로 맞춘다(없으면 생략).
5. 로컬 스테이징에서 `/robots.txt`·상태 페이지·가짜 라우트·셸 응답을 `curl` 로 직접 확인한다.
6. 미로 입구 경로가 실제 앱 경로와 겹치지 않는지, SPA 새로고침이 정상인지 확인한다(§4·§7).
7. 서버 반영: 업로드한 `Defense_proxy.py` 등의 해시를 로컬과 대조하고, 재시작 뒤 `/` 요청이 `defense.db` 에 찍히는지 확인한다.
