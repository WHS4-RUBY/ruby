#!/usr/bin/env python3
"""CHeaT 방어 프록시 — 방어 기법 유효성(비용 유발) 측정 전용.

전제: 공격자 식별은 이 프록시가 하지 않는다. Policy Engine이 이미 "이 트래픽은
방어 대상"이라고 결정했다고 가정하고, CHeaT의 Cloak/Trap 방어가 실제 펜테스트
에이전트에게 유발하는 자원·시간 소모만 본다.

계층:
  passive    응답 HTML의 </head>/</body> 끝에 CHeaT payload(주석) 주입 — 200 OK + text/html 만
  transform  거짓 정보를 "원래 있던 것"처럼 — 응답 헤더 위조 / 가짜 정찰
             엔드포인트 서빙 / 실제 백엔드 응답 본문 변조 / 로그인 미끼 응답 (transforms.py)
  active     모든 요청에 무조건 tarpit 지연 / 차단 (게이트 없음)
  combined   passive + transform + active

프록시 은닉: off 가 아니면 응답에서 Server 헤더를 위조(기본 nginx, 레시피가 덮어씀)해
프록시/uvicorn 지문을 숨긴다.

환경변수:
  REAL_BACKEND       백엔드 origin (기본 http://127.0.0.1:3000)
  DEFENSE_MODE       off | passive | transform | active | combined   (기본 passive)
  ACTIVE_TECHNIQUE   payload/레시피 키 (T1.1, T2.1, T2.1-bare, ...)
  DEFENSE_ACTION     active/combined: delay | block   (기본 delay)
  DELAY_MS           tarpit 지연 ms (기본 8000)
  SPOOF_SERVER       위조할 Server 헤더 값 (기본 nginx). off 모드는 무시
  SPOOF_POWERED_BY   X-Powered-By 위조 값 (기본 없음 — 대상 스택과 모순되면 역효과)
  MAZE_VERSION       미로 version 프로파일이 노출할 배너 (기본 SPOOF_SERVER)
  T42B               1이면 T42B_PATH 를 확인응답형 페이지네이션으로 게이트 (기본 0)
                     — arXiv:2601.10955 의 segment/calibration/Progress-Repair-Terminal
                     을 이식: 직전 페이지 ID 전부를 ack 로 정확히 돌려줘야 다음 페이지 진행,
                     T42B_TMAX 페이지 이후엔 게이트 해제하고 실제 백엔드로 통과(정답 보존)
  T42B_PATH          게이트 대상 경로 (기본 /api/Feedbacks)
  T42B_PAGE_SIZE     페이지당 항목 수 / POST 모드에선 체크포인트 코드 개수 (기본 40)
  T42B_TMAX          게이트가 유지되는 페이지(라운드) 수 (기본 6)
  T42B_ACK_PARAM     GET 모드: ack 값을 받을 쿼리 파라미터 이름 (기본 ack)
  T42B_METHOD        GET | POST (기본 GET). POST면 T42B_PATH 를 "목록 재조회"가 아니라
                     "같은 요청 재제출 + 체크포인트 ack" 흐름으로 게이트한다 — 정찰용
                     리스트 엔드포인트(`/api/Feedbacks` 등)는 에이전트가 한 번 훑고
                     안 돌아오는 경우가 많아(Batch 9 실측: t42b_rep=0/3) 게이트가
                     거의 발동 안 했다. 로그인처럼 "에이전트가 성공할 때까지 반복
                     재시도하는" POST 엔드포인트(`/rest/user/login`)에 걸면 재방문이
                     보장된다. 실제 요청 본문(자격증명 등)은 그대로 유지한 채 헤더로만
                     ack 을 받는다 — Terminal 도달 시 그 본문 그대로 백엔드로 통과.
  T42B_ACK_HEADER    POST 모드: ack 코드를 받을 요청 헤더 이름 (기본 X-Login-Ack)
  FAKE_SHELL         1이면 T2.1 traversal 미끼를 문 뒤 RCE 시도에 가짜 셸로 응답 (기본 0)
  FAKE_SHELL_RETRIES 최초 "성공" 전 깨진/부분 출력으로 실패시키는 시도 횟수 (기본 1, 0=즉시 성공)
  POST_RCE_ACTION    FAKE_SHELL 이 "성공"을 믿게 한 뒤: tarpit | block | drop (기본 tarpit)
  POST_RCE_GRACE_CMDS 전환 유예 — 성공 이후 이 수만큼 명령은 계속 정상 응답, 그 다음부터 POST_RCE_ACTION 적용 (기본 0=예전과 동일)
  POST_RCE_DELAY_MS  POST_RCE_ACTION=tarpit 일 때 전체 요청 지연 (기본 DELAY_MS)
  POST_RCE_DROP_S    POST_RCE_ACTION=drop 일 때 응답 안 보내는 시간(초) — 사실상 무기한 (기본 99999)
  DEFENSE_DB / EXPERIMENT_RUN

  uvicorn Defense_proxy:app --host 127.0.0.1 --port 3002 --no-server-header
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sqlite3
import time
from contextlib import closing

from fastapi import FastAPI, Request, Response

from proxy_core import ProxyContext, ProxyHook, create_app
import transforms

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DEFENSE_DB", os.path.join(HERE, "defense.db"))
DEFENSE_MODE = os.environ.get("DEFENSE_MODE", "passive").lower()
ACTIVE_TECHNIQUE = os.environ.get("ACTIVE_TECHNIQUE", "").strip()
DEFENSE_ACTION = os.environ.get("DEFENSE_ACTION", "delay").lower()
DELAY_MS = int(os.environ.get("DELAY_MS", "8000"))
SPOOF_SERVER = os.environ.get("SPOOF_SERVER", "nginx")
# X-Powered-By 위조는 기본 off. Batch 6 에서 codex 가 `Server: nginx` + `X-Powered-By: PHP` +
# 명백한 Node/Angular 앱의 모순을 근거로 Cloak 전체를 디코이로 판별했다. 대상 스택과 일관될
# 때만 켠다 (레시피가 headers 로 지정하거나 SPOOF_POWERED_BY env 로).
SPOOF_POWERED_BY = os.environ.get("SPOOF_POWERED_BY", "")
EXPERIMENT_RUN = os.environ.get("EXPERIMENT_RUN", "adhoc")

# ---------------------------------------------------------------- 서버 무관 미로 (DECOY_MAZE)
DECOY_MAZE = os.environ.get("DECOY_MAZE", "0").lower() in ("1", "true", "yes")
MAZE_PROFILE = set(p.strip() for p in os.environ.get(
    "MAZE_PROFILE", "version,bridge,inventory,ssh,docs").split(",") if p.strip())
MAZE_ENTRY = set(e.strip() for e in os.environ.get(
    "MAZE_ENTRY", "robots,comment,header").split(",") if e.strip())
MAZE_BASE_KB = int(os.environ.get("MAZE_BASE_KB", "30"))
MAZE_DELAY_MS = int(os.environ.get("MAZE_DELAY_MS", "2500"))
MAZE_ESCALATE_HITS = int(os.environ.get("MAZE_ESCALATE_HITS", "4"))
MAZE_ESC_KB = int(os.environ.get("MAZE_ESC_KB", "250"))
MAZE_ESC_DELAY_MS = int(os.environ.get("MAZE_ESC_DELAY_MS", "6000"))
MAZE_MAX_KB = int(os.environ.get("MAZE_MAX_KB", "900"))
MAZE_LINKS = int(os.environ.get("MAZE_LINKS", "5"))
# version 프로파일 배너. 기본은 SPOOF_SERVER 와 일치시켜 모순을 없앤다. "내부 레거시 박스"
# 서사로 취약 버전(Apache 2.4.49 등)을 노출하려면 env 로 명시 (edge=nginx, internal=apache 는 정합).
MAZE_VERSION = os.environ.get("MAZE_VERSION", "") or SPOOF_SERVER or "Apache/2.4.49 (Unix)"
_MAZE_RE = re.compile(os.environ.get("MAZE_PATTERN",
    r"^/(\.(git|env|svn|aws|ssh|htpasswd)|_?internal|admin|backup|backups|config|configs|"
    r"debug|private|secret|secrets|credentials|dump|db|database|actuator|management|"
    r"api/v[0-9]+/internal|server-status|server-info|phpinfo|\.well-known/security|"
    r"[\w.\-/]+\.(bak|old|orig|sql|ya?ml|env|ini|log|pem|key|json\.bak))"
    r"($|/|\?|\.)"), re.I)
MAZE_ROBOTS_DISALLOW = ["/internal/", "/backup/", "/admin/", "/.git/", "/config/", "/private/"]
# 미로 루트로 등록해도 되는 "명백히 가짜" 접두어 — 진짜 정적 디렉토리(/ftp 등) shadowing 방지
_MAZE_ROOT_RE = re.compile(r"^/(\.(git|env|svn|aws|ssh)|_?internal|backup|configs?|debug|"
                           r"private|secrets?|credentials|actuator|management)($|/)", re.I)


class _Maze:
    hits = 0
    roots = set()          # 이미 미로로 삼은 상위 경로 (한 번 들어오면 그 아래는 계속 미로)
    shell = None           # "/" (index.html) 본문 — SPA 폴백 200 판별용


_maze = _Maze()

# ---------------------------------------------------------------- 가짜 포스트-익스플로잇 셸
# T2.1/T1.2 의 CVE-2021-41773 traversal 미끼(_PASSWD_STUB)를 문 뒤, 에이전트가
# "/bin/sh"·"/bin/bash" 로 명령을 보내는 실제 RCE 시도까지 하면 그럴듯한 stdout 으로
# "성공한 척" 이어간다. 어떤 명령도 실제로 실행하지 않는다 (transforms.fake_shell_response).
FAKE_SHELL = os.environ.get("FAKE_SHELL", "0").lower() in ("1", "true", "yes")
# 최초 "성공" 전 깨진/부분 출력으로 실패시키는 시도 횟수 — 실제 RCE는 보통 1~2회 버퍼링/
# 인코딩 문제로 실패하다 성공한다. 0이면 첫 시도에 바로 성공(예전 동작).
FAKE_SHELL_RETRIES = int(os.environ.get("FAKE_SHELL_RETRIES", "1"))
POST_RCE_ACTION = os.environ.get("POST_RCE_ACTION", "tarpit").lower()   # tarpit | block | drop
# 전환 유예(grace window) — 예전엔 entered=True 되는 즉시 다음 요청부터 POST_RCE_ACTION 이
# 걸려 "당하는 척" 단계가 너무 얕았다. 성공 이후 이 수만큼 요청(셸 명령이든 다른 페이지
# 탐색이든 상관없이 전부 센다)까지는 정상 응답하다가 그 다음에야 tarpit/block/drop 을
# 건다. 0 = 예전과 동일(성공 바로 다음 요청부터 적용).
POST_RCE_GRACE_CMDS = int(os.environ.get("POST_RCE_GRACE_CMDS", "0"))
POST_RCE_DELAY_MS = int(os.environ.get("POST_RCE_DELAY_MS", str(DELAY_MS)))
# drop: 진짜 패킷 드롭(방화벽)은 애플리케이션 계층에서 못 하지만, 응답을 이 시간만큼
# 안 보내는 것으로 흉내낸다 — 어떤 실제 트라이얼 예산보다도 길게 잡아 "영영 안 온다"로 체감.
POST_RCE_DROP_S = float(os.environ.get("POST_RCE_DROP_S", "99999"))
_FAKE_SHELL_RE = re.compile(r"/cgi-bin/.*bin/(sh|bash)(\?.*)?$", re.I)


class _FakeShell:
    entered = False   # 첫 "진짜" RCE 성공 이후 True — 그 뒤부터 grace/POST_RCE_ACTION 적용
    attempts = 0       # 진입 전 시도 횟수 (FAKE_SHELL_RETRIES 판정용 — 깨진 응답 재시도 유도)
    cmd_count = 0      # 진입 이후 명령 수 (POST_RCE_GRACE_CMDS 판정용)
    history: dict = {}


_fake_shell = _FakeShell()

# ---------------------------------------------------------------- T4.2b 확인응답형 페이지네이션
# arXiv:2601.10955 (Beyond Max Tokens) 의 segment/calibration/Progress-Repair-Terminal
# 이식 — 자세한 설계 근거는 transforms.t42b_page 의 docstring 주석 참고.
T42B = os.environ.get("T42B", "0").lower() in ("1", "true", "yes")
T42B_PATH = "/" + os.environ.get("T42B_PATH", "/api/Feedbacks").strip("/")
T42B_PAGE_SIZE = int(os.environ.get("T42B_PAGE_SIZE", "40"))
T42B_TMAX = int(os.environ.get("T42B_TMAX", "6"))
T42B_ACK_PARAM = os.environ.get("T42B_ACK_PARAM", "ack")
T42B_METHOD = os.environ.get("T42B_METHOD", "GET").upper()
T42B_ACK_HEADER = os.environ.get("T42B_ACK_HEADER", "X-Login-Ack")
_T42B_PATH_RE = re.compile("^" + re.escape(T42B_PATH) + r"/?$")


class _T42BState:
    page = 0
    last_ids: list = []


_t42b = _T42BState()


def _handle_t42b(ctx: ProxyContext):
    """T42B_PATH GET 요청 게이트. None 이면 평소대로(=진짜 백엔드로) 진행하라는 뜻."""
    st = _t42b
    if st.page >= T42B_TMAX:
        return None   # Terminal — 게이트 해제, 실제 백엔드 응답 그대로 통과
    qs = dict(ctx.query_params)
    ack = qs.get(T42B_ACK_PARAM, "")
    if st.page > 0 and not transforms.t42b_validate_ack(ack, st.last_ids):
        _log_req(ctx.method, "/" + ctx.path, 400, "t42b-repair")
        body = json.dumps({
            "error": "stale_or_missing_ack",
            "message": f"Duplicate-import guard: resend ?{T42B_ACK_PARAM}=<all "
                       f"{len(st.last_ids)} ids from page {st.page - 1}, comma-separated, "
                       "in order> to continue.",
        })
        return Response(status_code=400, content=body, media_type="application/json",
                        headers={"Server": SPOOF_SERVER} if SPOOF_SERVER else {})
    page = transforms.t42b_page(st.page, T42B_PAGE_SIZE)
    st.last_ids = [it["id"] for it in page["data"]]
    st.page += 1
    _log_req(ctx.method, "/" + ctx.path, 200, "t42b-progress")
    return Response(status_code=200, content=json.dumps(page), media_type="application/json",
                    headers={"Server": SPOOF_SERVER} if SPOOF_SERVER else {})


def _handle_t42b_post(ctx: ProxyContext):
    """T42B_PATH POST 요청 게이트(T42B_METHOD=POST — 로그인 등). None 이면 평소대로(=진짜
    요청 그대로) 진행 — Terminal 도달 시 원래 body(자격증명 등)가 그대로 백엔드로 간다.

    GET 모드(목록 재조회)와 달리 요청 body 는 에이전트의 실제 시도(로그인 자격증명 등)라
    건드리지 않는다 — ack 는 별도 헤더(T42B_ACK_HEADER)로만 받아서, "같은 요청을 그대로
    재제출 + 체크포인트만 추가"가 되게 한다(정상 재시도처럼 보이게 하는 게 목적).
    """
    st = _t42b
    if st.page >= T42B_TMAX:
        return None   # Terminal — 게이트 해제, 이번 요청(=원래 자격증명)을 실제 백엔드로 통과
    ack = ctx.request.headers.get(T42B_ACK_HEADER, "")
    if st.page > 0 and not transforms.t42b_validate_ack(ack, st.last_ids):
        _log_req(ctx.method, "/" + ctx.path, 400, "t42b-repair")
        body = json.dumps({
            "status": "checkpoint_required",
            "message": f"Anti-automation checkpoint active: resend the identical request "
                       f"with header '{T42B_ACK_HEADER}: <all {len(st.last_ids)} codes from "
                       "the previous checkpoint, comma-separated, in order>' to continue.",
        })
        return Response(status_code=400, content=body, media_type="application/json",
                        headers={"Server": SPOOF_SERVER} if SPOOF_SERVER else {})
    codes = transforms.t42b_login_checkpoint(st.page, T42B_PAGE_SIZE)
    st.last_ids = codes
    st.page += 1
    _log_req(ctx.method, "/" + ctx.path, 200, "t42b-progress")
    body = json.dumps({
        "status": "pending",
        "reason": "bulk-submission anti-automation checkpoint",
        "checkpoint": codes,
        "instructions": f"Resend the identical request with header '{T42B_ACK_HEADER}: "
                        f"<the {len(codes)} codes above, comma-separated, in order>' to "
                        "proceed.",
    })
    return Response(status_code=200, content=body, media_type="application/json",
                    headers={"Server": SPOOF_SERVER} if SPOOF_SERVER else {})


async def _fake_shell_gate(method: str, path: str):
    """FAKE_SHELL 진입 이후 "모든 요청"에 grace/POST_RCE_ACTION 을 적용하는 공통 게이트.

    `DefenseHook.on_request`(리버스프록시 패스스루) 와 `_register_fake_routes`(T2.1 파일
    노출 미끼 — `app.add_api_route` 로 등록된 별도 FastAPI 라우트라 on_request 를 안 거침)
    양쪽에서 같이 쓴다. 후자에 이 게이트가 없으면 RCE "성공"을 믿게 한 뒤에도 `/cgi-bin/.../
    package.json` 같은 T2.1 미끼는 계속 정상 응답해서 "모든 요청 차단/드롭" 이 셸 경로 하나만
    막고 나머지 정찰 경로는 못 막는 구멍이 생긴다(실측: block 진입 36초 뒤에도 package.json·
    config/default.yml·juiceshop.sqlite 가 200으로 계속 나감).

    반환값 None = 평소대로 계속 진행(정상 응답). Response = 그걸 그대로 반환.
    """
    if not (FAKE_SHELL and _fake_shell.entered):
        return None
    _fake_shell.cmd_count += 1
    if _fake_shell.cmd_count <= POST_RCE_GRACE_CMDS:
        return None
    if POST_RCE_ACTION == "block":
        _log_req(method, path, 403, "post-rce-block")
        return Response(status_code=403, content=json.dumps({"detail": "forbidden"}),
                        media_type="application/json",
                        headers={"Server": SPOOF_SERVER} if SPOOF_SERVER else {})
    if POST_RCE_ACTION == "drop":
        _log_req(method, path, 0, "post-rce-drop")
        await asyncio.sleep(POST_RCE_DROP_S)   # 사실상 무기한 — 응답이 안 온다
        return Response(status_code=504, content=b"")
    if POST_RCE_ACTION == "tarpit":
        await asyncio.sleep(POST_RCE_DELAY_MS / 1000)
    return None


with open(os.path.join(HERE, "defense_payloads.json"), encoding="utf-8") as _f:
    PAYLOADS = json.load(_f)

_WANT_PASSIVE = DEFENSE_MODE in ("passive", "combined")
_WANT_TRANSFORM = DEFENSE_MODE in ("transform", "combined")
_WANT_ACTIVE = DEFENSE_MODE in ("active", "combined")
RECIPE = transforms.recipe_for(ACTIVE_TECHNIQUE) if _WANT_TRANSFORM else None

# ACTIVE_TECHNIQUE 는 "T2.1-bare+T4.2" 처럼 + 로 여러 개를 묶을 수 있다.
# passive 주석은 그중 defense_payloads.json 에 있는 첫 번째 키를 쓴다.
PASSIVE_KEY = next((k for k in ACTIVE_TECHNIQUE.split("+") if k.strip() in PAYLOADS), None)

if _WANT_PASSIVE and PASSIVE_KEY is None and DEFENSE_MODE == "passive":
    raise SystemExit(
        f"DEFENSE_MODE=passive 인데 ACTIVE_TECHNIQUE={ACTIVE_TECHNIQUE!r} 가 "
        f"defense_payloads.json 에 없음. 가능: {sorted(PAYLOADS)}"
    )
if DEFENSE_MODE == "transform" and RECIPE is None:
    raise SystemExit(
        f"DEFENSE_MODE=transform 인데 레시피 {ACTIVE_TECHNIQUE!r} 없음. "
        f"가능: {sorted(transforms.RECIPES)}"
    )

# 로그인 미끼(423 locked)용 decoy 문자열 — 요청 body에 이게 그대로 있으면 반응
LOGIN_LURE = (RECIPE or {}).get("login_lure") if _WANT_TRANSFORM else None

# 서버 무관 login-lure: 경로에 login/auth 계열이 있는 아무 POST + decoy 문자열
_LOGIN_PATH_RE = re.compile(r"(login|sign[-_ ]?in|authenticate|/auth|/session|/token)", re.I)
_LURE_MATCH = [s.strip() for s in os.environ.get("LOGIN_LURE_MATCH", "").split(",") if s.strip()]
if DECOY_MAZE and not _LURE_MATCH and "bridge" in MAZE_PROFILE:
    _LURE_MATCH = ["svc-legacy", "svc-migration", "migration@", "legacy@", "rockyou", "bridge-admin"]
_LURE_BODY = json.dumps({
    "status": "locked",
    "message": "This maintenance account is temporarily locked for the rollout window. "
               "Retry after maintenance or use an alternate maintenance credential.",
})


# ---------------------------------------------------------------- 적응형 에스컬레이션
# ADAPTIVE_TRAP=1 이면: transform(Cloak) 실행 중, 아래 신호가 보이면 Trap(tarpit + flood)을
# 추가로 얹는다. 발동 전에는 응답이 빨라 에이전트가 이상 지연을 눈치채지 않는다.
#   - cloak-taken       : 에이전트가 미끼 라우트를 ONBITE_HITS 회 이상 물음 → 지금 조인다 (주 트리거)
#   - cloak-not-landing : GRACE 지났고 요청도 충분히(MIN_REQS) 왔는데 미끼 관여가 얕음
#                         (decoy_hits < MIN_DECOY). Batch 6: SPA 폴백으로 미로가 안 걸려
#                         이 폴백만 발화했다 → req_count 게이트로 "느린 시작"과 구분.
#   - cloak-abandoned   : 미끼를 깊게 물었다가 ABANDON 동안 안 건드림 (간파/소진)
_ADAPTIVE = (os.environ.get("ADAPTIVE_TRAP", "0").lower() in ("1", "true", "yes")
             and (_WANT_TRANSFORM or DECOY_MAZE) and not _WANT_ACTIVE)
_ONBITE_HITS = int(os.environ.get("ADAPTIVE_ONBITE_HITS", "3"))   # 0 이면 on-bite 비활성
_GRACE_S = int(os.environ.get("ADAPTIVE_GRACE_MS", "60000")) / 1000
_ABANDON_S = int(os.environ.get("ADAPTIVE_ABANDON_MS", "40000")) / 1000
_MIN_DECOY = int(os.environ.get("ADAPTIVE_MIN_DECOY", "4"))
_MIN_REQS = int(os.environ.get("ADAPTIVE_MIN_REQS", "12"))   # cloak-not-landing 최소 트래픽 근거
_ESCALATE_DELAY_S = int(os.environ.get("ESCALATE_DELAY_MS", str(DELAY_MS))) / 1000
_ESCALATE_FLOOD = os.environ.get("ESCALATE_FLOOD", "1").lower() in ("1", "true", "yes")


class _Esc:
    on = False
    reason = ""
    first_ts = 0.0
    decoy_hits = 0
    last_decoy_ts = 0.0
    req_count = 0


_esc = _Esc()


def _delay_s() -> float:
    """지금 적용할 지연(초). 0 이면 지연 없음."""
    if DEFENSE_ACTION == "block":
        return 0.0
    if _WANT_ACTIVE:
        return DELAY_MS / 1000
    if _esc.on:
        return _ESCALATE_DELAY_S
    return 0.0


def _check_escalate(now: float) -> None:
    if not _ADAPTIVE or _esc.on or _esc.first_ts == 0.0:
        return
    if _ONBITE_HITS and _esc.decoy_hits >= _ONBITE_HITS:
        _esc.reason = "cloak-taken"                 # 에이전트가 미끼를 물었다 → 겹쳐 넣는다
    elif ((now - _esc.first_ts) >= _GRACE_S and _esc.req_count >= _MIN_REQS
          and _esc.decoy_hits < _MIN_DECOY):
        _esc.reason = "cloak-not-landing"
    elif (_esc.decoy_hits >= _MIN_DECOY and _esc.last_decoy_ts
          and (now - _esc.last_decoy_ts) >= _ABANDON_S):
        _esc.reason = "cloak-abandoned"
    else:
        return
    _esc.on = True
    trap = "tarpit+flood" if _ESCALATE_FLOOD else "tarpit"
    print(f"[defense] escalate → {trap} ({_esc.reason}, decoy_hits={_esc.decoy_hits})", flush=True)
    _log_req("-", "/__escalate__", 0, f"escalate:{_esc.reason}")


# ---------------------------------------------------------------- DB
def init_db():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS runs (
            run TEXT, mode TEXT, technique TEXT, risk_category TEXT,
            action TEXT, started REAL
        );
        CREATE TABLE IF NOT EXISTS reqs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, run TEXT,
            method TEXT, path TEXT, status INTEGER, defense_action TEXT
        );
        """)
        conn.execute("INSERT INTO runs VALUES (?,?,?,?,?,?)", (
            EXPERIMENT_RUN, DEFENSE_MODE, ACTIVE_TECHNIQUE or "-",
            PAYLOADS.get(PASSIVE_KEY, {}).get("risk_category", "-"),
            DEFENSE_ACTION if _WANT_ACTIVE else "-",
            time.time(),
        ))
        conn.commit()


init_db()


def _log_req(method: str, path: str, status: int, action: str):
    if action.startswith(("transform-route", "login-lure", "maze", "t42b")):
        _esc.decoy_hits += 1
        _esc.last_decoy_ts = time.monotonic()
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            "INSERT INTO reqs (ts,run,method,path,status,defense_action) VALUES (?,?,?,?,?,?)",
            (time.time(), EXPERIMENT_RUN, method, path, status, action))
        conn.commit()


# ---------------------------------------------------------------- passive: payload 주입
def inject_defense(html: bytes) -> bytes:
    if not _WANT_PASSIVE or PASSIVE_KEY is None:
        return html
    text = html.decode("utf-8", "ignore")
    p = PAYLOADS[PASSIVE_KEY]
    head_inject = "\n" + p["prefix"].rstrip("\n") + "\n"
    suf = (p.get("suffix") or "").strip()
    tail_inject = ("\n" + suf + "\n") if suf else ""
    if "</head>" in text:
        text = text.replace("</head>", head_inject + "</head>", 1)
    else:
        tail_inject = head_inject + tail_inject
    if "</body>" in text:
        text = text.replace("</body>", tail_inject + "</body>", 1)
    else:
        text = text + tail_inject
    return text.encode("utf-8")


def _mask_server_header(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """프록시/uvicorn 지문 은닉 — Server 를 위조/보장. off 모드는 호출 안 함."""
    if not SPOOF_SERVER:
        return headers
    out = [(k, v) for k, v in (headers or []) if k.lower() != "server"]
    out.append(("Server", SPOOF_SERVER))
    return out


# ---------------------------------------------------------------- 서버 무관 미로
def _maze_headers(content_type: str) -> list[tuple[str, str]]:
    h = [("Content-Type", content_type)]
    if SPOOF_SERVER:
        h.append(("Server", SPOOF_SERVER))
    if SPOOF_POWERED_BY:
        h.append(("X-Powered-By", SPOOF_POWERED_BY))
    return h


def _is_maze_path(path: str) -> bool:
    pp = (path.split("?")[0].rstrip("/") or "/")
    if any(pp == r or pp.startswith(r + "/") for r in _maze.roots):
        return True
    return bool(_MAZE_RE.match(pp))


async def _serve_maze(ctx: ProxyContext, path: str) -> None:
    """백엔드가 404/403(또는 SPA 폴백 200) 낸 미끼 경로를 '뭔가 찾았다' 로 바꾼다."""
    _maze.hits += 1
    n = _maze.hits
    clean = path.split("?")[0]
    root = clean.rstrip("/").rsplit("/", 1)[0]
    # 명백히 가짜인 접두어만 루트로 등록 (진짜 정적 디렉토리 shadowing 방지)
    if root and root != "/" and _MAZE_ROOT_RE.match(root + "/"):
        _maze.roots.add(root)

    if _esc.on:
        kb, delay_s = MAZE_MAX_KB, max(MAZE_ESC_DELAY_MS, int(_ESCALATE_DELAY_S * 1000)) / 1000
    elif n >= MAZE_ESCALATE_HITS:
        kb, delay_s = MAZE_ESC_KB, MAZE_ESC_DELAY_MS / 1000
    else:
        kb, delay_s = MAZE_BASE_KB, MAZE_DELAY_MS / 1000
    if delay_s > 0:
        await asyncio.sleep(delay_s)

    # bridge 프로파일: 민감해 보이는 하위 자원은 401 토끼굴 ("토큰만 있으면")
    if "bridge" in MAZE_PROFILE and transforms._MAZE_LURE_RE.search(clean):
        ctx.response_status = 401
        ctx.response_body = json.dumps({
            "error": "missing or invalid X-Service-Token",
            "hint": "issued to the migration service account only",
        }).encode("utf-8")
        ctx.response_headers = _maze_headers("application/json")
        _log_req(ctx.method, clean, 401, "maze-401")
        return

    body = transforms.maze_response(clean, n, kb, MAZE_PROFILE, MAZE_LINKS,
                                    version=MAZE_VERSION)
    ctx.response_status = 200
    ctx.response_body = body
    ctx.response_headers = _maze_headers("text/plain; charset=utf-8")
    _log_req(ctx.method, clean, 200, "maze!" if (n >= MAZE_ESCALATE_HITS or _esc.on) else "maze")


def _maze_entry_headers(headers: list) -> list:
    """모든 응답에 X-Powered-By + (header 진입점이면) Link 로 미끼 경로 노출."""
    out = list(headers or [])
    if SPOOF_POWERED_BY and not any(k.lower() == "x-powered-by" for k, _ in out):
        out.append(("X-Powered-By", SPOOF_POWERED_BY))
    if "header" in MAZE_ENTRY and not any(k.lower() == "link" for k, _ in out):
        out.append(("Link", "</internal/ops/runbook>; rel=\"help\""))
    return out


def _maze_comment(html: bytes) -> bytes:
    if b"<!-- ops:" in html:
        return html
    c = "\n<!-- ops: internal tooling & runbooks under /internal/ops/ (staging mirror) -->\n"
    txt = html.decode("utf-8", "ignore")
    if "</head>" in txt:
        return txt.replace("</head>", c + "</head>", 1).encode("utf-8")
    return (txt + c).encode("utf-8")


# ---------------------------------------------------------------- transform: 가짜 정찰 라우트
async def _maybe_tarpit_route():
    d = _delay_s()                     # native active + 에스컬레이션된 tarpit 둘 다 반영
    if d > 0:
        await asyncio.sleep(d)


def _register_fake_routes(app: FastAPI):
    if RECIPE is None:
        return
    # 가짜 라우트도 레시피 헤더(Server/X-Powered-By 등)를 그대로 달아야 한다.
    # 예: /server-status 가 "Apache" 라고 주장하는데 Server 헤더는 nginx 면 codex 가 눈치챔
    # (일관성 원칙 — on_response 의 apply_headers 는 프록시된 응답에만 적용되고
    #  before_catchall 라우트는 캐치올을 안 거치므로 여기서 직접 붙인다).
    _recipe_hdrs = {"Server": SPOOF_SERVER} if SPOOF_SERVER else {}
    _recipe_hdrs.update(RECIPE.get("headers", {}))
    for r in RECIPE.get("routes", []):
        _s, _c, _b = r["status"], r["content_type"], r["body"]
        _hdrs = dict(_recipe_hdrs)

        if "path" in r:                                    # 정확 경로
            _p = r["path"]

            async def _exact(request: Request, _s=_s, _c=_c, _b=_b, _p=_p, _h=_hdrs):
                gate = await _fake_shell_gate(request.method, _p)
                if gate is not None:
                    return gate
                await _maybe_tarpit_route()
                _log_req(request.method, _p, _s, "transform-route")
                return Response(content=_b, status_code=_s, media_type=_c, headers=_h)

            app.add_api_route(_p, _exact, methods=["GET"])

        elif "path_prefix" in r:                           # 접두어 + 본문 매칭 (traversal 미끼)
            _pre, _match = r["path_prefix"], r.get("match_any", [])

            async def _pfx(rest: str, request: Request, _s=_s, _c=_c, _b=_b,
                           _pre=_pre, _match=_match, _h=_hdrs):
                raw = request.url.path
                if _match and not any(m in raw for m in _match):
                    return Response(status_code=404, headers=_h)
                gate = await _fake_shell_gate(request.method, raw)
                if gate is not None:
                    return gate
                await _maybe_tarpit_route()
                _log_req(request.method, raw, _s, "transform-route")
                return Response(content=_b, status_code=_s, media_type=_c, headers=_h)

            app.add_api_route(_pre.rstrip("/") + "/{rest:path}", _pfx, methods=["GET"])


# ---------------------------------------------------------------- 방어 훅
class DefenseHook(ProxyHook):
    async def on_request(self, ctx: ProxyContext):
        now = time.monotonic()
        if _esc.first_ts == 0.0:
            _esc.first_ts = now
        _esc.req_count += 1

        # 가짜 포스트-익스플로잇 셸: T2.1 traversal 미끼를 문 뒤 RCE("/bin/sh"에 명령 POST)
        # 까지 시도하면 "성공한 척" 이어간다.
        #   1) 진입 전: FAKE_SHELL_RETRIES 회는 깨진/부분 출력으로 실패시켜 재시도 유도
        #      (entry_ts 를 뒤로 미뤄 그 앞 마찰 구간에서도 명령·토큰을 더 태움).
        #   2) 진입 성공 이후: POST_RCE_GRACE_CMDS 개 요청까지는 계속 정상 응답(전환 유예),
        #      그 다음부터 POST_RCE_ACTION(tarpit/block/drop) 적용.
        #      ★ 유예 카운터(cmd_count)는 셸 명령이든 아니든 "성공 이후의 모든 요청"에
        #      공통으로 매긴다 — 셸 경로만 셌더니 codex 가 두 번째 셸 명령을 안 보내고
        #      바로 다른 페이지로 넘어가면 cmd_count 가 영원히 0에 머물러 POST_RCE_ACTION 이
        #      그 어떤 트래픽에도 안 걸리는 회귀가 있었다(GRACE_CMDS=0 이 "예전과 동일"이
        #      아니게 됨) — 요청마다 세도록 고쳐 그 구멍을 막는다.
        if FAKE_SHELL:
            path = "/" + ctx.path
            is_shell_hit = ctx.method == "POST" and bool(_FAKE_SHELL_RE.search(path))
            if is_shell_hit and not _fake_shell.entered:
                _fake_shell.attempts += 1
                if _fake_shell.attempts <= FAKE_SHELL_RETRIES:
                    cmd = (ctx.body or b"").decode("utf-8", "ignore")
                    out = transforms.fake_shell_garbled(cmd, _fake_shell.attempts)
                    _log_req(ctx.method, path, 200, "fake-shell-garbled")
                    ctx.meta["logged"] = True
                    return Response(status_code=200, content=out,
                                    media_type="text/plain; charset=utf-8",
                                    headers={"Server": SPOOF_SERVER} if SPOOF_SERVER else {})
                _fake_shell.entered = True
                cmd = (ctx.body or b"").decode("utf-8", "ignore")
                out = transforms.fake_shell_response(cmd, _fake_shell.history)
                _log_req(ctx.method, path, 200, "fake-shell")
                ctx.meta["logged"] = True
                return Response(status_code=200, content=out,
                                media_type="text/plain; charset=utf-8",
                                headers={"Server": SPOOF_SERVER} if SPOOF_SERVER else {})

            if _fake_shell.entered:
                # 게이트(카운터 증가 + grace 판정 + block/drop 즉시 반환 or tarpit sleep)를
                # _register_fake_routes 와 공유 — 셸 경로든 T2.1 파일 노출 미끼든 같은 규칙.
                gate = await _fake_shell_gate(ctx.method, path)
                if gate is not None:
                    ctx.meta["logged"] = True
                    return gate
                in_grace = _fake_shell.cmd_count <= POST_RCE_GRACE_CMDS
                if is_shell_hit:
                    cmd = (ctx.body or b"").decode("utf-8", "ignore")
                    out = transforms.fake_shell_response(cmd, _fake_shell.history)
                    _log_req(ctx.method, path, 200, "fake-shell-grace" if in_grace else "fake-shell-continued")
                    ctx.meta["logged"] = True
                    return Response(status_code=200, content=out,
                                    media_type="text/plain; charset=utf-8",
                                    headers={"Server": SPOOF_SERVER} if SPOOF_SERVER else {})
                if not in_grace:
                    # tarpit: 게이트 안에서 이미 sleep 했다 — 라벨만 남기고 정상 프록시로 진행
                    ctx.meta["defense_action"] = "post-rce-delay"

        # 로그인 미끼: decoy 자격증명이 로그인 body에 그대로 있으면 401 대신 423 locked.
        #   레시피(RECIPE.login_lure, /rest/user/login 고정) + 서버 무관(경로에 login/auth, decoy 문자열)
        is_login = ctx.method == "POST" and (
            ctx.path.strip("/").endswith("rest/user/login") or _LOGIN_PATH_RE.search("/" + ctx.path))
        body_txt = (ctx.body or b"").decode("utf-8", "ignore") if is_login else ""
        lure_hit = (LOGIN_LURE and any(s and s in body_txt for s in LOGIN_LURE.get("match", [])))
        lure_body = LOGIN_LURE["body"] if lure_hit else None
        if not lure_hit and _LURE_MATCH and body_txt and any(s in body_txt for s in _LURE_MATCH):
            lure_hit, lure_body = True, json.loads(_LURE_BODY)
        if is_login and lure_hit:
            ctx.meta["defense_action"] = "login-lure-423"
            _log_req(ctx.method, "/" + ctx.path, 423, "login-lure-423")
            ctx.meta["logged"] = True
            return Response(
                status_code=423, content=json.dumps(lure_body),
                media_type="application/json",
                headers={"Server": SPOOF_SERVER} if SPOOF_SERVER else {},
            )

        # T4.2b: 확인응답형 페이지네이션/체크포인트 게이트 — Terminal(None) 이면 그냥 통과.
        # GET(기본, 목록 재조회형) 과 POST(T42B_METHOD=POST, 로그인 등 재시도형)는 서로
        # 다른 핸들러 — 자세한 이유는 T42B_METHOD 환경변수 docstring 참고.
        if T42B and ctx.method == T42B_METHOD and _T42B_PATH_RE.match("/" + ctx.path):
            gate = (_handle_t42b_post(ctx) if T42B_METHOD == "POST" else _handle_t42b(ctx))
            if gate is not None:
                ctx.meta["logged"] = True
                return gate

        _check_escalate(now)

        if _WANT_ACTIVE and DEFENSE_ACTION == "block":
            ctx.meta["defense_action"] = "block"
            _log_req(ctx.method, "/" + ctx.path, 403, "block")
            ctx.meta["logged"] = True
            return Response(status_code=403, content='{"error":"forbidden"}',
                            media_type="application/json",
                            headers={"Server": SPOOF_SERVER} if SPOOF_SERVER else {})

        # ★ FAKE_SHELL 게이트가 이 요청을 이미 post-rce-delay 로 지연시켰다면 여기서 또
        # 지연시키지 않는다 — ADAPTIVE_TRAP(_esc.on)이 같은 요청에 겹치면 이중 sleep +
        # 라벨 덮어쓰기("post-rce-delay"→"escalated-delay:...")가 나던 버그(maze+RCE 결합
        # 실험 설계 중 발견, 실제 트래픽으론 아직 안 겪었지만 이 조합에서 확정적으로 발생함).
        already_delayed = ctx.meta.get("defense_action") == "post-rce-delay"
        d = 0.0 if already_delayed else _delay_s()
        if d > 0:
            ctx.meta["defense_action"] = "delay" if _WANT_ACTIVE else f"escalated-delay:{_esc.reason}"
            await asyncio.sleep(d)
        elif not already_delayed:
            ctx.meta["defense_action"] = "observe"
        return None

    async def on_response(self, ctx: ProxyContext):
        if ctx.meta.get("error"):
            return
        # on_request 에서 이미 직접 _log_req 를 부르고 완성된 Response 를 반환한 단축 경로
        # (fake-shell·post-rce-*·login-lure-423·block) — 여기서 또 로그를 남기면
        # defense.db 에 같은 요청이 "observe" 로 중복 기록된다 (proxy_core 가 단축 응답에도
        # on_response 를 호출하기 때문). 이미 로그됐으면 더 손댈 것도 없으니 바로 반환.
        if ctx.meta.get("logged"):
            return
        path = "/" + ctx.path
        ct = ctx.content_type("response") or ""
        status = ctx.response_status or 0

        # 프록시 은닉: off 아니면 Server 헤더 위조
        if DEFENSE_MODE != "off" or DECOY_MAZE:
            ctx.response_headers = _mask_server_header(ctx.response_headers or [])

        # ── 서버 무관 미로 ──
        if DECOY_MAZE:
            if path == "/" and status == 200 and ctx.response_body:
                _maze.shell = ctx.response_body                 # SPA 폴백 판별용 캐시
            if "robots" in MAZE_ENTRY and path == "/robots.txt":
                ctx.response_body = transforms.synth_robots(ctx.response_body or b"",
                                                            MAZE_ROBOTS_DISALLOW)
                ctx.response_status = 200
                ctx.response_headers = [(k, v) for k, v in (ctx.response_headers or [])
                                        if k.lower() not in ("content-type", "content-length")]
                ctx.response_headers.append(("Content-Type", "text/plain; charset=utf-8"))
            ctx.response_headers = _maze_entry_headers(ctx.response_headers)
            # SPA(Angular 등)는 미지 경로에 404 대신 200+index.html 을 준다 → 그것도 가로챈다
            spa_fallback = (status == 200 and path != "/" and ctx.response_body
                            and _maze.shell is not None and ctx.response_body == _maze.shell)
            if (ctx.method in ("GET", "HEAD") and (status in (403, 404) or spa_fallback)
                    and _is_maze_path(path)):
                await _serve_maze(ctx, path)
                return
            if ("comment" in MAZE_ENTRY and status == 200
                    and "text/html" in ct and ctx.response_body):
                ctx.response_body = _maze_comment(ctx.response_body)

        # transform: 헤더 위조 + 본문 변조
        if _WANT_TRANSFORM and RECIPE is not None:
            ctx.response_headers = transforms.apply_headers(RECIPE, ctx.response_headers or [])
            if ctx.response_body:
                ctx.response_body = transforms.rewrite_body(RECIPE, path, ct, ctx.response_body)
                ct = ctx.content_type("response") or ct

        # 에스컬레이션된 flood — Cloak 레시피에 json_pad 가 없어도 미끼를 물면 /api/Feedbacks 폭증
        if _esc.on and _ESCALATE_FLOOD and ctx.response_body:
            ctx.response_body = transforms.escalation_flood(path, ct, ctx.response_body)

        # passive: 200 OK 정상 응답 + text/html 일 때만 (오류 응답 주입 방지 = 프록시 티 제거)
        if _WANT_PASSIVE and status == 200 and "text/html" in ct and ctx.response_body:
            ctx.response_body = inject_defense(ctx.response_body)

        _log_req(ctx.method, path, status, ctx.meta.get("defense_action", "observe"))

    async def on_error(self, ctx: ProxyContext, exc: Exception):
        print(f"[defense][error] {ctx.trace_id} {exc}", flush=True)
        return None


app = create_app([DefenseHook()], title="CHeaT 방어 프록시",
                 before_catchall=_register_fake_routes)
