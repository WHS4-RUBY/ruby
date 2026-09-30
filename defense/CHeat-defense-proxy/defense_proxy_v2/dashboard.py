#!/usr/bin/env python3
"""실험 대시보드 — Defense_proxy.py 가 쓰는 defense.db 를 실시간으로 보여주고, GUI에서
방어 모드를 골라 프록시 프로세스 자체를 켜고 끌 수 있다.

★★★ 보안 경고 — 반드시 읽을 것 ★★★
이 앱은 `/api/proxy/start`·`/api/proxy/stop`으로 로컬에서 `uvicorn Defense_proxy:app`
서브프로세스를 실제로 띄우고 끈다. 즉 이 페이지에 접근할 수 있는 사람은 "방어를 끄는 것"까지
포함해 프록시의 동작을 완전히 바꿀 수 있다. 방어 프록시는 그 정의상 신뢰할 수 없는(공격자)
트래픽을 받는 물건이므로, **이 대시보드를 그 공격자와 같은 네트워크에 절대 노출하지 말 것** —
`--host 127.0.0.1`로만 띄우고, 원격에서 봐야 한다면 SSH 포트 포워딩을 쓴다.

`DASHBOARD_PASSWORD` 환경변수를 설정하면 **페이지 전체(조회 + 제어 모두)가 로그인 뒤에
잠긴다** — 비밀번호를 맞히면 서명 없는 랜덤 세션 토큰을 `HttpOnly`/`SameSite=Strict` 쿠키로
내려주고, 그 쿠키 없이는 `/`도 `/api/*`도 401. 세션은 서버 메모리에만 있고(재시작하면 초기화)
12시간 뒤 만료. 설정 안 하면 이전처럼 인증 없이 전부 열려 있으니, 로컬 1인 사용이 아니라면
반드시 설정할 것.

이 앱 자신은 defense.db 에 쓰지 않는다 — 오직 자신이 띄운 프록시 서브프로세스가 그 DB에 쓴다.

사용:
  DEFENSE_DB=./defense.db uvicorn dashboard:app --host 127.0.0.1 --port 8088
  DASHBOARD_PASSWORD=<임의의 긴 문자열> 을 같이 주면 로그인 없이는 아무것도 안 보인다.
  CODEX_LOG_PATH=<codex.jsonl 경로> 를 주면 아래 "EXPERIMENT-ONLY" 표시된 토큰 사용량 KPI가 켜진다.

★ EXPERIMENT-ONLY 안내: 이 파일 안에 "에이전트 토큰 사용량"·"풀이한 챌린지 수" 두 지표가
`# ══ EXPERIMENT-ONLY ══` 주석으로 표시돼 있다. 이건 "우리가 공격 에이전트(codex 등)도 직접
돌리는 통제된 실험"에서만 값이 나오는 지표다 — 실제 배포에서 방어자는 공격자의 LLM 토큰
사용량을 관찰할 방법이 전혀 없고(그건 공격자 쪽 내부 정보), 챌린지 API도 Juice Shop 전용
엔드포인트라 실제 대상 앱엔 없다. 실서버에 배포하는 운영자는 그 주석으로 감싸인 코드
블록(Python 쪽 CODEX_LOG_PATH/_read_codex_usage/_read_challenges/api_experiment, HTML 쪽
실험용 지표 카드와 refreshExperiment())을 통째로 지우면 된다 — 지워도 나머지 대시보드
(요청 로그·타임라인·프록시 제어)는 전혀 영향받지 않는다.
"""
from __future__ import annotations

import atexit
import hmac
import json
import os
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
from contextlib import closing

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DEFENSE_DB", os.path.join(HERE, "defense.db"))
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")
_SESSION_COOKIE = "dashboard_session"
_SESSION_TTL_S = 12 * 3600
# ══ EXPERIMENT-ONLY ══ 아래 상수는 이 파일 하단의 EXPERIMENT-ONLY 블록에서만 쓰인다.
CODEX_LOG_PATH = os.environ.get("CODEX_LOG_PATH", "")
LOG_PATH = os.path.join(HERE, "proxy_stdout.log")

_KNOWN_MODES = {"off", "passive", "transform", "active", "combined"}
_KNOWN_DEFENSE_ACTIONS = {"delay", "block"}
_KNOWN_RCE_ACTIONS = {"tarpit", "block", "drop"}

# Defense_proxy.py 의 _log_req() 가 실제로 남기는 defense_action 접두어를 세 갈래로 분류한다.
# "decoy" 판정은 Defense_proxy.py 자신이 _esc.decoy_hits(에스컬레이션 트리거)를 셀 때 쓰는
# 기준(transform-route/login-lure/maze)과 정확히 맞췄다 — 대시보드가 코드와 다른 정의를
# 쓰면 숫자가 어긋난다. "rce"는 FAKE_SHELL 진입 이후의 포스트-익스플로잇 단계.
_DECOY_PREFIXES = ("transform-route", "login-lure", "maze")
_RCE_PREFIXES = ("fake-shell", "post-rce")


def _classify(action: str) -> str:
    if not action:
        return "normal"
    if action.startswith("escalate:"):
        return "escalate"
    if action.startswith(_RCE_PREFIXES):
        return "rce"
    if action.startswith(_DECOY_PREFIXES):
        return "decoy"
    return "normal"


def _conn():
    return sqlite3.connect(DB_PATH)


def _db_missing():
    return JSONResponse({"error": f"DB 없음: {DB_PATH} — 아래 컨트롤 패널에서 프록시를 먼저 시작하세요."},
                        status_code=404)


# ══════════════════════════════════════════════════════════════════════════
#  프록시 프로세스 제어 — 이 대시보드가 자식으로 띄운 uvicorn 하나만 관리한다
#  (여러 인스턴스 동시 관리는 지원 안 함 — "지금 실험 하나" 워크플로에 맞춤).
# ══════════════════════════════════════════════════════════════════════════
_lock = threading.Lock()
_state = {"proc": None, "logfile": None, "config": None, "port": None, "started_at": None}


def _proc_running() -> bool:
    p = _state["proc"]
    return p is not None and p.poll() is None


def _stop_proxy():
    with _lock:
        p = _state["proc"]
        if p and p.poll() is None:
            try:
                p.terminate()
                p.wait(timeout=5)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        lf = _state["logfile"]
        if lf:
            try:
                lf.close()
            except Exception:
                pass
        _state.update({"proc": None, "logfile": None, "config": None, "port": None, "started_at": None})


atexit.register(_stop_proxy)


def _parse_extra_env(text: str) -> dict:
    """'KEY=VALUE' 줄들(빈 줄/등호 없는 줄은 무시)을 dict 로."""
    out = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        if k:
            out[k] = v.strip()
    return out


def _start_proxy(config: dict, port: int) -> dict:
    """config(문자열 dict)로 uvicorn Defense_proxy:app 을 새로 띄운다. 기존 게 있으면 먼저 멈춘다."""
    _stop_proxy()
    env = os.environ.copy()
    for k, v in config.items():
        if v is None or v == "":
            env.pop(k, None)
        else:
            env[str(k)] = str(v)
    # 대시보드가 보고 있는 DB로 강제 고정 — 안 그러면 "시작은 됐는데 대시보드엔 안 보임" 혼란이 생김
    env["DEFENSE_DB"] = DB_PATH

    logfile = open(LOG_PATH, "w", encoding="utf-8")
    cmd = [sys.executable, "-m", "uvicorn", "Defense_proxy:app",
           "--host", "127.0.0.1", "--port", str(port), "--no-server-header", "--log-level", "warning"]
    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
    proc = subprocess.Popen(cmd, cwd=HERE, env=env, stdout=logfile, stderr=subprocess.STDOUT,
                            creationflags=creationflags)
    with _lock:
        _state.update({"proc": proc, "logfile": logfile, "config": dict(config),
                       "port": port, "started_at": time.time()})

    time.sleep(1.2)   # 바로 죽는지(포트 충돌, 잘못된 ACTIVE_TECHNIQUE 등) 확인할 시간
    if proc.poll() is not None:
        code = proc.returncode
        _stop_proxy()
        return {"ok": False, "error": f"프로세스가 즉시 종료됨 (exit {code}) — 로그 확인",
               "log_tail": _tail_log(40)}
    return {"ok": True}


def _tail_log(n: int = 60) -> str:
    if not os.path.exists(LOG_PATH):
        return ""
    with open(LOG_PATH, encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    return "".join(lines[-n:])


# ══════════════════════════════════════════════════════════════════════════
#  로그인 — DASHBOARD_PASSWORD 가 설정된 경우에만 걸린다(설정 안 하면 전부 통과).
#  세션은 서버 프로세스 메모리에만 있다(재시작하면 전부 로그아웃됨) — 별도 DB/파일
#  없이 "관리자 1명, 로컬 도구" 규모에 맞춘 가장 단순한 형태.
# ══════════════════════════════════════════════════════════════════════════
_sessions_lock = threading.Lock()
_sessions: dict[str, float] = {}   # session token -> 만료 시각(epoch)


def _login_required() -> bool:
    return bool(DASHBOARD_PASSWORD)


def _new_session() -> str:
    token = secrets.token_urlsafe(32)
    with _sessions_lock:
        _sessions[token] = time.time() + _SESSION_TTL_S
    return token


def _drop_session(token: str | None) -> None:
    if not token:
        return
    with _sessions_lock:
        _sessions.pop(token, None)


def _valid_session(token: str | None) -> bool:
    if not token:
        return False
    with _sessions_lock:
        exp = _sessions.get(token)
        if exp is None:
            return False
        if exp < time.time():
            del _sessions[token]
            return False
        return True


def _is_authed(request: Request) -> bool:
    if not _login_required():
        return True
    return _valid_session(request.cookies.get(_SESSION_COOKIE))


def _auth_gate(request: Request):
    """인증 안 됐으면 401 JSONResponse, 됐으면 None — API 핸들러 맨 앞에서 바로 return."""
    if not _is_authed(request):
        return JSONResponse({"error": "로그인이 필요합니다"}, status_code=401)
    return None


app = FastAPI(title="CHeaT Defense Dashboard")


@app.get("/api/summary")
def api_summary(request: Request):
    denied = _auth_gate(request)
    if denied:
        return denied
    if not os.path.exists(DB_PATH):
        return _db_missing()
    with closing(_conn()) as conn:
        run_row = conn.execute(
            "SELECT run, mode, technique, risk_category, action, started "
            "FROM runs ORDER BY started DESC LIMIT 1"
        ).fetchone()
        rows = conn.execute("SELECT ts, defense_action FROM reqs ORDER BY ts").fetchall()

    decoy_hits = sum(1 for _, a in rows if _classify(a) == "decoy")
    rce_hits = sum(1 for _, a in rows if _classify(a) == "rce")
    esc_rows = [(ts, a) for ts, a in rows if a.startswith("escalate:")]
    fake_shell_rows = [(ts, a) for ts, a in rows if a == "fake-shell"]
    first_ts = rows[0][0] if rows else None
    last_ts = rows[-1][0] if rows else None

    return {
        "run": run_row[0] if run_row else None,
        "mode": run_row[1] if run_row else None,
        "technique": run_row[2] if run_row else None,
        "risk_category": run_row[3] if run_row else None,
        "action": run_row[4] if run_row else None,
        "started": run_row[5] if run_row else None,
        "total_requests": len(rows),
        "decoy_hits": decoy_hits,
        "rce_hits": rce_hits,
        "escalated": bool(esc_rows),
        "escalated_at": esc_rows[0][0] if esc_rows else None,
        "escalated_reason": esc_rows[0][1].split(":", 1)[1] if esc_rows else None,
        "fake_shell_entered": bool(fake_shell_rows),
        "fake_shell_entered_at": fake_shell_rows[0][0] if fake_shell_rows else None,
        "first_ts": first_ts,
        "last_ts": last_ts,
        "duration_s": round(last_ts - first_ts, 1) if (first_ts and last_ts) else 0,
    }


@app.get("/api/requests")
def api_requests(request: Request, limit: int = 150):
    denied = _auth_gate(request)
    if denied:
        return denied
    if not os.path.exists(DB_PATH):
        return _db_missing()
    with closing(_conn()) as conn:
        rows = conn.execute(
            "SELECT ts, method, path, status, defense_action FROM reqs ORDER BY ts DESC LIMIT ?",
            (max(1, min(limit, 1000)),),
        ).fetchall()
    return [
        {"ts": ts, "method": m, "path": p, "status": s, "action": a, "category": _classify(a)}
        for ts, m, p, s, a in rows
    ]


@app.get("/api/timeline")
def api_timeline(request: Request, buckets: int = 40):
    denied = _auth_gate(request)
    if denied:
        return denied
    if not os.path.exists(DB_PATH):
        return _db_missing()
    with closing(_conn()) as conn:
        rows = conn.execute("SELECT ts, defense_action FROM reqs ORDER BY ts").fetchall()
    if not rows:
        return {"series": [], "bucket_s": 0}

    t0, t1 = rows[0][0], rows[-1][0]
    span = max(t1 - t0, 1.0)
    bucket_s = max(span / max(buckets, 1), 1.0)
    n = int((t1 - t0) / bucket_s) + 1
    slots = [{"normal": 0, "decoy": 0, "rce": 0} for _ in range(n)]
    for ts, action in rows:
        cat = _classify(action)
        if cat == "escalate":
            continue
        idx = min(int((ts - t0) / bucket_s), n - 1)
        slots[idx][cat if cat in ("decoy", "rce") else "normal"] += 1

    series = [{"t": t0 + i * bucket_s, **slots[i]} for i in range(n)]
    return {"series": series, "bucket_s": bucket_s}


@app.get("/api/actions")
def api_actions(request: Request):
    denied = _auth_gate(request)
    if denied:
        return denied
    if not os.path.exists(DB_PATH):
        return _db_missing()
    with closing(_conn()) as conn:
        rows = conn.execute(
            "SELECT defense_action, COUNT(*) c FROM reqs GROUP BY defense_action ORDER BY c DESC"
        ).fetchall()
    return [{"action": a, "count": c, "category": _classify(a)} for a, c in rows]


# ══════════════════════════════════════════════════════════════════════════
#  ★ EXPERIMENT-ONLY 블록 시작 — 서버 운영자는 이 블록(_read_codex_usage ~
#  api_experiment 끝까지)을 통째로 지워도 된다. 지워도 나머지 대시보드는 전혀
#  영향받지 않는다 (프론트엔드에서 이 API를 부르는 부분도 같은 표시로 아래 _PAGE
#  안에 따로 있으니 같이 지울 것).
#
#  두 지표 다 "우리가 공격 에이전트도 같이 돌리는 통제된 실험"에서만 값이 나온다:
#    - 토큰 사용량: 방어 프록시는 네트워크(HTTP)만 보므로 공격 에이전트의 LLM API
#      호출·토큰 사용량을 원칙적으로 볼 수 없다. 여기서는 "그 에이전트를 codex
#      CLI로 우리가 직접 실행하면서 --json 으로 로그(codex.jsonl)를 남긴다"는
#      실험 전제 하에, 그 파일을 CODEX_LOG_PATH 로 읽어서 보여줄 뿐이다.
#    - 챌린지 solved 수: Juice Shop 전용 `/api/Challenges` 엔드포인트를 프록시를
#      거치지 않고 백엔드에 직접 물어본다(run_batch9.sh의 solved_count()와 동일한
#      방식 — 방어가 채점 결과에 손 못 대게 ground truth를 우회로 잡음). 대상 앱이
#      Juice Shop이 아니면 이 호출은 그냥 실패하고 "available": false 로 남는다.
# ══════════════════════════════════════════════════════════════════════════
def _read_codex_usage() -> dict:
    """CODEX_LOG_PATH 의 codex.jsonl 을 parse_batch9.py 와 같은 방식으로 파싱."""
    if not CODEX_LOG_PATH or not os.path.exists(CODEX_LOG_PATH):
        return {"available": False}
    usage: dict = {}
    cmds = msgs = 0
    try:
        with open(CODEX_LOG_PATH, encoding="utf-8") as f:
            for line in f:
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if ev.get("type") == "turn.completed" and isinstance(ev.get("usage"), dict):
                    usage = ev["usage"]   # 마지막 turn = 누적 합계
                if ev.get("type") == "item.completed":
                    t = ev.get("item", {}).get("type")
                    cmds += t == "command_execution"
                    msgs += t == "agent_message"
    except OSError:
        return {"available": False}
    if not usage:
        return {"available": False}
    inp = usage.get("input_tokens", 0)
    cached = usage.get("cached_input_tokens", 0)
    out = usage.get("output_tokens", 0)
    return {
        "available": True,
        "input_tokens": inp, "cached_input_tokens": cached, "output_tokens": out,
        "total_tokens": inp + out, "eff_tokens": inp - cached + out,
        "commands": cmds, "messages": msgs,
    }


def _read_challenges() -> dict:
    """REAL_BACKEND(대시보드가 띄운 프록시의 설정, 없으면 env)의 /api/Challenges 를
    프록시를 거치지 않고 직접 조회 — Juice Shop 전용."""
    backend = (_state["config"] or {}).get("REAL_BACKEND") or os.environ.get("REAL_BACKEND", "")
    if not backend:
        return {"available": False}
    try:
        url = backend.rstrip("/") + "/api/Challenges"
        with urllib.request.urlopen(url, timeout=2) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        items = data.get("data", [])
        solved = sum(1 for c in items if c.get("solved"))
        return {"available": True, "solved": solved, "total": len(items), "backend": backend}
    except Exception:
        return {"available": False}


@app.get("/api/experiment")
def api_experiment(request: Request):
    denied = _auth_gate(request)
    if denied:
        return denied
    return {"tokens": _read_codex_usage(), "challenges": _read_challenges()}
# ══════════════════════════════════════════════════════════════════════════
#  ★ EXPERIMENT-ONLY 블록 끝
# ══════════════════════════════════════════════════════════════════════════


@app.get("/api/proxy/status")
def api_proxy_status(request: Request):
    denied = _auth_gate(request)
    if denied:
        return denied
    running = _proc_running()
    return {
        "running": running,
        "pid": _state["proc"].pid if running else None,
        "port": _state["port"] if running else None,
        "config": _state["config"] if running else None,
        "started_at": _state["started_at"] if running else None,
    }


@app.get("/api/proxy/log")
def api_proxy_log(request: Request, lines: int = 60):
    denied = _auth_gate(request)
    if denied:
        return denied
    return {"log": _tail_log(max(1, min(lines, 500)))}


@app.post("/api/proxy/start")
async def api_proxy_start(request: Request):
    denied = _auth_gate(request)
    if denied:
        return denied

    body = await request.json()
    mode = (body.get("DEFENSE_MODE") or "transform").strip()
    if mode not in _KNOWN_MODES:
        return JSONResponse({"error": f"DEFENSE_MODE={mode!r} 은 알 수 없음. 가능: {sorted(_KNOWN_MODES)}"},
                            status_code=400)
    defense_action = (body.get("DEFENSE_ACTION") or "delay").strip()
    if defense_action not in _KNOWN_DEFENSE_ACTIONS:
        return JSONResponse({"error": f"DEFENSE_ACTION={defense_action!r} 은 알 수 없음"}, status_code=400)
    rce_action = (body.get("POST_RCE_ACTION") or "tarpit").strip()
    if rce_action not in _KNOWN_RCE_ACTIONS:
        return JSONResponse({"error": f"POST_RCE_ACTION={rce_action!r} 은 알 수 없음"}, status_code=400)
    try:
        port = int(body.get("PORT") or 3002)
        if not (1 <= port <= 65535):
            raise ValueError
    except (TypeError, ValueError):
        return JSONResponse({"error": "PORT가 올바른 포트 번호가 아님"}, status_code=400)

    real_backend = (body.get("REAL_BACKEND") or "http://127.0.0.1:3000").strip()
    technique = (body.get("ACTIVE_TECHNIQUE") or "").strip()
    experiment_run = (body.get("EXPERIMENT_RUN") or "").strip() or time.strftime("gui-%Y%m%d-%H%M%S")

    config = {
        "REAL_BACKEND": real_backend,
        "DEFENSE_MODE": mode,
        "ACTIVE_TECHNIQUE": technique,
        "DEFENSE_ACTION": defense_action,
        "DELAY_MS": str(body.get("DELAY_MS") or "8000"),
        "DECOY_MAZE": "1" if body.get("DECOY_MAZE") else "0",
        "ADAPTIVE_TRAP": "1" if body.get("ADAPTIVE_TRAP") else "0",
        "FAKE_SHELL": "1" if body.get("FAKE_SHELL") else "0",
        "POST_RCE_ACTION": rce_action,
        "FAKE_SHELL_RETRIES": str(body.get("FAKE_SHELL_RETRIES") or "0"),
        "EXPERIMENT_RUN": experiment_run,
    }
    config.update(_parse_extra_env(body.get("EXTRA_ENV") or ""))

    result = _start_proxy(config, port)
    if not result.get("ok"):
        return JSONResponse(result, status_code=400)
    return {"ok": True, "port": port, "config": config}


@app.post("/api/proxy/stop")
def api_proxy_stop(request: Request):
    denied = _auth_gate(request)
    if denied:
        return denied
    _stop_proxy()
    return {"ok": True}


@app.post("/api/login")
async def api_login(request: Request):
    if not _login_required():
        return {"ok": True}
    body = await request.json()
    password = body.get("password") or ""
    time.sleep(0.3)   # 무차별 대입 완화용 인위적 지연
    if not hmac.compare_digest(password, DASHBOARD_PASSWORD):
        return JSONResponse({"error": "비밀번호가 올바르지 않습니다"}, status_code=401)
    token = _new_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(_SESSION_COOKIE, token, httponly=True, samesite="strict", max_age=_SESSION_TTL_S)
    return resp


@app.post("/api/logout")
def api_logout(request: Request):
    _drop_session(request.cookies.get(_SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(_SESSION_COOKIE)
    return resp


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if not _is_authed(request):
        return _LOGIN_PAGE
    return _PAGE


_LOGIN_PAGE = r"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CHeaT Defense Dashboard — 로그인</title>
<style>
:root {
  color-scheme: light;
  --surface-1: #fcfcfb; --page-plane: #f9f9f7; --text-primary: #0b0b0b;
  --text-secondary: #52514e; --text-muted: #898781; --border: rgba(11,11,11,0.10);
  --series-normal: #2a78d6; --status-critical: #d03b3b;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --surface-1: #1a1a19; --page-plane: #0d0d0d; --text-primary: #ffffff;
    --text-secondary: #c3c2b7; --text-muted: #898781; --border: rgba(255,255,255,0.10);
    --series-normal: #3987e5; --status-critical: #e66767;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
  background: var(--page-plane); color: var(--text-primary);
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
}
.login-box {
  background: var(--surface-1); border: 1px solid var(--border); border-radius: 10px;
  padding: 28px; width: 320px;
}
.login-box h1 { font-size: 16px; margin: 0 0 4px; }
.login-box p { font-size: 12px; color: var(--text-secondary); margin: 0 0 18px; line-height: 1.5; }
.login-box input {
  width: 100%; padding: 9px 10px; margin-bottom: 12px; font-size: 13px;
  border-radius: 6px; border: 1px solid var(--border); background: var(--page-plane);
  color: var(--text-primary); font-family: inherit;
}
.login-box button {
  width: 100%; padding: 9px; font-size: 13px; font-weight: 600; border: none;
  border-radius: 6px; background: var(--series-normal); color: #fff; cursor: pointer;
}
.login-box .error { color: var(--status-critical); font-size: 12px; margin-top: 10px; min-height: 14px; }
</style>
</head>
<body>
  <div class="login-box">
    <h1>CHeaT Defense Dashboard</h1>
    <p>이 페이지는 방어 프록시를 켜고 끌 수 있습니다 — 로그인이 필요합니다.</p>
    <form id="loginForm">
      <input type="password" id="pw" placeholder="비밀번호" autofocus>
      <button type="submit">로그인</button>
      <div class="error" id="loginError"></div>
    </form>
  </div>
  <script>
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errBox = document.getElementById('loginError');
      errBox.textContent = '';
      try {
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: document.getElementById('pw').value }),
        });
        const data = await res.json();
        if (res.ok) {
          location.reload();
        } else {
          errBox.textContent = data.error || '로그인 실패';
        }
      } catch (err) {
        errBox.textContent = '요청 실패: ' + err;
      }
    });
  </script>
</body>
</html>
"""


_PAGE = r"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CHeaT Defense Dashboard</title>
<style>
:root {
  color-scheme: light;
  --surface-1:      #fcfcfb;
  --page-plane:      #f9f9f7;
  --text-primary:   #0b0b0b;
  --text-secondary: #52514e;
  --text-muted:     #898781;
  --gridline:       #e1e0d9;
  --baseline:       #c3c2b7;
  --border:         rgba(11,11,11,0.10);
  --series-normal:  #2a78d6;
  --series-decoy:   #eb6834;
  --series-rce:     #1baf7a;
  --status-good:    #0ca30c;
  --status-warning: #fab219;
  --status-critical:#d03b3b;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --surface-1:      #1a1a19;
    --page-plane:      #0d0d0d;
    --text-primary:   #ffffff;
    --text-secondary: #c3c2b7;
    --text-muted:     #898781;
    --gridline:       #2c2c2a;
    --baseline:       #383835;
    --border:         rgba(255,255,255,0.10);
    --series-normal:  #3987e5;
    --series-decoy:   #d95926;
    --series-rce:     #199e70;
    --status-good:    #0ca30c;
    --status-warning: #fab219;
    --status-critical:#e66767;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--page-plane);
  color: var(--text-primary);
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  padding: 20px;
}
.wrap { max-width: 1100px; margin: 0 auto; }
header { display: flex; align-items: baseline; justify-content: space-between; flex-wrap: wrap; gap: 8px; margin-bottom: 16px; }
h1 { font-size: 20px; margin: 0; }
.meta { color: var(--text-secondary); font-size: 13px; }
.meta b { color: var(--text-primary); }
#lastUpdated { color: var(--text-muted); font-size: 12px; }

.card {
  background: var(--surface-1);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 16px;
  margin-bottom: 16px;
}
.card h2 { font-size: 14px; margin: 0 0 12px; color: var(--text-secondary); font-weight: 600; }

.kpi-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
.kpi { background: var(--surface-1); border: 1px solid var(--border); border-radius: 10px; padding: 14px; }
.kpi .label { font-size: 12px; color: var(--text-secondary); }
.kpi .value { font-size: 26px; font-weight: 600; margin-top: 4px; }
.kpi .sub { font-size: 12px; color: var(--text-muted); margin-top: 2px; }
.badge { display: inline-flex; align-items: center; gap: 5px; padding: 2px 8px; border-radius: 20px; font-size: 11px; font-weight: 600; color: #fff; }
.badge.normal   { background: var(--text-muted); }
.badge.decoy    { background: var(--series-decoy); }
.badge.rce      { background: var(--series-rce); }
.badge.escalate { background: var(--status-critical); }
.badge.off      { background: var(--text-muted); }
.badge.on       { background: var(--status-warning); color: #1a1400; }
.badge.running  { background: var(--status-good); }
.badge.stopped  { background: var(--text-muted); }

.legend { display: flex; gap: 16px; font-size: 12px; color: var(--text-secondary); margin-bottom: 8px; }
.legend span { display: inline-flex; align-items: center; gap: 6px; }
.swatch { width: 10px; height: 10px; border-radius: 2px; display: inline-block; }

#timeline { display: flex; align-items: flex-end; gap: 2px; height: 140px; position: relative; }
.tbar { flex: 1; display: flex; flex-direction: column-reverse; min-width: 2px; cursor: pointer; position: relative; }
.tbar .seg { width: 100%; }
.tbar .seg.normal { background: var(--series-normal); }
.tbar .seg.decoy  { background: var(--series-decoy); }
.tbar .seg.rce    { background: var(--series-rce); }
.tbar .seg:first-child { border-radius: 3px 3px 0 0; }
.axis-line { border-top: 1px solid var(--baseline); margin-top: 4px; }

.tooltip {
  position: fixed; background: var(--text-primary); color: var(--page-plane);
  font-size: 12px; padding: 6px 9px; border-radius: 6px; pointer-events: none;
  opacity: 0; transition: opacity .1s; z-index: 10; white-space: nowrap;
}

.actions-list { display: flex; flex-direction: column; gap: 6px; }
.action-row { display: grid; grid-template-columns: 180px 1fr 50px; align-items: center; gap: 10px; font-size: 13px; }
.action-row .name { color: var(--text-secondary); font-family: ui-monospace, monospace; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.action-row .bar-track { height: 16px; background: var(--gridline); border-radius: 3px; overflow: hidden; }
.action-row .bar-fill { height: 100%; background: var(--series-normal); border-radius: 3px 0 0 3px; }
.action-row .count { text-align: right; font-variant-numeric: tabular-nums; color: var(--text-primary); }

table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
th { text-align: left; color: var(--text-muted); font-weight: 600; padding: 6px 8px; border-bottom: 1px solid var(--gridline); position: sticky; top: 0; background: var(--surface-1); }
td { padding: 6px 8px; border-bottom: 1px solid var(--gridline); font-family: ui-monospace, monospace; }
td.ts { color: var(--text-muted); white-space: nowrap; font-variant-numeric: tabular-nums; }
td.path { max-width: 360px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.log-scroll { max-height: 420px; overflow-y: auto; }
.status-2 { color: var(--status-good); }
.status-4 { color: var(--status-warning); }
.status-0 { color: var(--status-critical); }

.error { color: var(--status-critical); font-size: 13px; }

/* 컨트롤 패널 */
.form-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 12px; }
.form-grid label, .form-section label { display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--text-secondary); }
.form-grid input, .form-grid select, .form-section input, .form-section select, .form-section textarea {
  font-family: inherit; font-size: 13px; padding: 6px 8px; border-radius: 6px;
  border: 1px solid var(--border); background: var(--page-plane); color: var(--text-primary);
}
.form-section { margin-bottom: 12px; }
.form-section .section-label { font-size: 12px; font-weight: 600; color: var(--text-secondary); margin-bottom: 6px; }
.checkbox-row { display: flex; align-items: center; gap: 6px; flex-direction: row !important; font-size: 13px; color: var(--text-primary) !important; }
.checkbox-row input { width: auto; }
.checkbox-group { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 8px; }
textarea { width: 100%; resize: vertical; font-family: ui-monospace, monospace; font-size: 12px; }
.btn-row { display: flex; gap: 8px; align-items: center; margin-top: 10px; }
button { font-family: inherit; font-size: 13px; font-weight: 600; padding: 8px 16px; border-radius: 6px; border: none; cursor: pointer; }
#btnStart { background: var(--series-normal); color: #fff; }
#btnStop { background: var(--status-critical); color: #fff; }
button:disabled { opacity: 0.5; cursor: not-allowed; }
.proxy-status-line { font-size: 13px; margin-bottom: 10px; }
.log-view { background: var(--page-plane); border: 1px solid var(--border); border-radius: 6px; padding: 8px; font-family: ui-monospace, monospace; font-size: 11px; max-height: 160px; overflow-y: auto; white-space: pre-wrap; margin-top: 8px; display: none; }

@media (max-width: 720px) {
  .kpi-row { grid-template-columns: repeat(2, 1fr); }
  .action-row { grid-template-columns: 110px 1fr 40px; }
  .form-grid { grid-template-columns: 1fr 1fr; }
}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>CHeaT Defense Dashboard</h1>
    <div style="display:flex; align-items:center; gap:14px;">
      <div id="lastUpdated">-</div>
      <button id="btnLogout" type="button" style="background:var(--gridline); color:var(--text-primary); padding:5px 12px; font-size:12px;">로그아웃</button>
    </div>
  </header>

  <div id="errorBox"></div>

  <div class="card">
    <h2>프록시 제어</h2>
    <div class="proxy-status-line" id="proxyStatusLine">불러오는 중...</div>

    <form id="proxyForm">
      <div class="form-grid">
        <label>REAL_BACKEND <input name="REAL_BACKEND" value="http://127.0.0.1:3000"></label>
        <label>포트(PORT) <input name="PORT" type="number" value="3002"></label>
        <label>DEFENSE_MODE
          <select name="DEFENSE_MODE">
            <option value="off">off (베이스라인)</option>
            <option value="passive">passive</option>
            <option value="transform" selected>transform</option>
            <option value="active">active</option>
            <option value="combined">combined</option>
          </select>
        </label>
        <label>DEFENSE_ACTION (active/combined)
          <select name="DEFENSE_ACTION"><option value="delay" selected>delay</option><option value="block">block</option></select>
        </label>
        <label>DELAY_MS <input name="DELAY_MS" type="number" value="8000"></label>
        <label>EXPERIMENT_RUN <input name="EXPERIMENT_RUN" placeholder="비우면 자동 생성"></label>
      </div>

      <div class="form-section">
        <div class="section-label">ACTIVE_TECHNIQUE (여러 개 선택 시 + 로 결합)</div>
        <div class="checkbox-group">
          <label class="checkbox-row"><input type="checkbox" name="tech_T2.1" checked> T2.1 (가짜 취약 버전 — FAKE_SHELL 전제조건)</label>
          <label class="checkbox-row"><input type="checkbox" name="tech_T2.2"> T2.2 (관심 유도)</label>
          <label class="checkbox-row"><input type="checkbox" name="tech_T4.2-bare"> T4.2-bare (passive 개발자 메모)</label>
        </div>
        <label>직접 입력(위 체크박스와 +로 결합됨) <input name="ACTIVE_TECHNIQUE_EXTRA" placeholder="예: T2.1"></label>
      </div>

      <div class="form-section">
        <div class="section-label">Trap 옵션</div>
        <div class="checkbox-group">
          <label class="checkbox-row"><input type="checkbox" name="DECOY_MAZE"> DECOY_MAZE (서버 무관 미로)</label>
          <label class="checkbox-row"><input type="checkbox" name="ADAPTIVE_TRAP"> ADAPTIVE_TRAP (미끼 물면 tarpit 강화)</label>
          <label class="checkbox-row"><input type="checkbox" name="FAKE_SHELL"> FAKE_SHELL (RCE 미끼 → 가짜 셸)</label>
        </div>
        <div class="form-grid" style="grid-template-columns: repeat(2, 1fr);">
          <label>POST_RCE_ACTION (FAKE_SHELL 진입 후)
            <select name="POST_RCE_ACTION"><option value="tarpit" selected>tarpit</option><option value="block">block</option><option value="drop">drop</option></select>
          </label>
          <label>FAKE_SHELL_RETRIES <input name="FAKE_SHELL_RETRIES" type="number" value="0"></label>
        </div>
      </div>

      <div class="form-section">
        <label>고급: 추가 환경변수 (한 줄에 KEY=VALUE — 예: MAZE_BASE_KB=30)
          <textarea name="EXTRA_ENV" rows="3" placeholder="ESCALATE_DELAY_MS=16000&#10;SPOOF_SERVER=nginx"></textarea>
        </label>
      </div>

      <div class="btn-row">
        <button type="submit" id="btnStart">시작 / 재시작</button>
        <button type="button" id="btnStop">중지</button>
        <button type="button" id="btnLog" style="background:var(--gridline); color:var(--text-primary);">로그 보기</button>
      </div>
    </form>
    <div class="log-view" id="logView"></div>
  </div>

  <div class="card">
    <div class="meta" id="runMeta">불러오는 중...</div>
  </div>

  <div class="kpi-row" id="kpiRow"></div>

  <!-- ═══ EXPERIMENT-ONLY 카드 시작 — 서버 운영자는 이 <div class="card" id="experimentCard">
       전체를 통째로 지워도 된다. 공격 에이전트도 우리가 직접 돌리는 통제된 실험에서만 값이
       나오는 지표(에이전트 토큰 사용량 · Juice Shop 챌린지 solved 수)라, 실제 배포에서는
       의미가 없다. 짝이 되는 JS(refreshExperiment())도 같은 표시로 아래에 있음. ═══ -->
  <div class="card" id="experimentCard">
    <h2>실험용 지표 <span style="font-weight:400; color:var(--text-muted);">(EXPERIMENT-ONLY — 공격 에이전트를 우리가 직접 돌리는 실험 환경에서만 값이 나옴)</span></h2>
    <div class="kpi-row" id="experimentKpiRow"></div>
  </div>
  <!-- ═══ EXPERIMENT-ONLY 카드 끝 ═══ -->

  <div class="card">
    <h2>요청 타임라인</h2>
    <div class="legend">
      <span><span class="swatch" style="background:var(--series-normal)"></span>일반</span>
      <span><span class="swatch" style="background:var(--series-decoy)"></span>미끼 접촉(Cloak)</span>
      <span><span class="swatch" style="background:var(--series-rce)"></span>FAKE_SHELL / post-RCE</span>
    </div>
    <div id="timeline"></div>
    <div class="axis-line"></div>
  </div>

  <div class="card">
    <h2>defense_action 분포</h2>
    <div class="actions-list" id="actionsList"></div>
  </div>

  <div class="card">
    <h2>최근 요청 로그</h2>
    <div class="log-scroll">
      <table>
        <thead><tr><th>시각</th><th>method</th><th>path</th><th>status</th><th>defense_action</th></tr></thead>
        <tbody id="logBody"></tbody>
      </table>
    </div>
  </div>
</div>

<div class="tooltip" id="tooltip"></div>

<script>
const tooltip = document.getElementById('tooltip');
function showTip(e, html) {
  tooltip.innerHTML = html;
  tooltip.style.left = (e.clientX + 12) + 'px';
  tooltip.style.top = (e.clientY + 12) + 'px';
  tooltip.style.opacity = 1;
}
function hideTip() { tooltip.style.opacity = 0; }

function fmtTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString('ko-KR', { hour12: false });
}
function statusClass(s) {
  if (s >= 500 || s === 0) return 'status-0';
  if (s >= 400) return 'status-4';
  return 'status-2';
}

document.getElementById('btnLogout').addEventListener('click', async () => {
  await fetch('/api/logout', { method: 'POST' });
  location.reload();
});

async function refreshProxyStatus() {
  const r = await fetch('/api/proxy/status');
  if (r.status === 401) { location.reload(); return; }
  const st = await r.json();
  const line = document.getElementById('proxyStatusLine');
  if (st.running) {
    const cfg = st.config || {};
    line.innerHTML = `<span class="badge running">실행 중</span> &nbsp; PID ${st.pid} · 포트 ${st.port} &nbsp; ` +
      `<b>DEFENSE_MODE</b>=${cfg.DEFENSE_MODE} <b>ACTIVE_TECHNIQUE</b>=${cfg.ACTIVE_TECHNIQUE || '-'} &nbsp; ` +
      `시작: ${fmtTime(st.started_at)}`;
    document.getElementById('btnStop').disabled = false;
  } else {
    line.innerHTML = `<span class="badge stopped">중지됨</span> &nbsp; 아래에서 설정을 고르고 "시작"을 누르세요.`;
    document.getElementById('btnStop').disabled = true;
  }
}

document.getElementById('proxyForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  const techs = [];
  ['T2.1', 'T2.2', 'T4.2-bare'].forEach(t => {
    if (f.querySelector(`[name="tech_${t}"]`).checked) techs.push(t);
  });
  const extra = f.ACTIVE_TECHNIQUE_EXTRA.value.trim();
  if (extra) techs.push(...extra.split(/[+,]/).map(s => s.trim()).filter(Boolean));

  const body = {
    REAL_BACKEND: f.REAL_BACKEND.value.trim(),
    PORT: parseInt(f.PORT.value, 10),
    DEFENSE_MODE: f.DEFENSE_MODE.value,
    DEFENSE_ACTION: f.DEFENSE_ACTION.value,
    DELAY_MS: f.DELAY_MS.value,
    ACTIVE_TECHNIQUE: techs.join('+'),
    DECOY_MAZE: f.DECOY_MAZE.checked,
    ADAPTIVE_TRAP: f.ADAPTIVE_TRAP.checked,
    FAKE_SHELL: f.FAKE_SHELL.checked,
    POST_RCE_ACTION: f.POST_RCE_ACTION.value,
    FAKE_SHELL_RETRIES: f.FAKE_SHELL_RETRIES.value,
    EXPERIMENT_RUN: f.EXPERIMENT_RUN.value.trim(),
    EXTRA_ENV: f.EXTRA_ENV.value,
  };

  const btn = document.getElementById('btnStart');
  btn.disabled = true; btn.textContent = '시작 중...';
  try {
    const res = await fetch('/api/proxy/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (res.status === 401) { location.reload(); return; }
    const data = await res.json();
    if (!res.ok || data.error) {
      document.getElementById('errorBox').innerHTML =
        `<div class="card"><div class="error">시작 실패: ${data.error || res.status}${data.log_tail ? '<br><pre>' + data.log_tail + '</pre>' : ''}</div></div>`;
    } else {
      document.getElementById('errorBox').innerHTML = '';
    }
  } catch (err) {
    document.getElementById('errorBox').innerHTML = `<div class="card"><div class="error">요청 실패: ${err}</div></div>`;
  }
  btn.disabled = false; btn.textContent = '시작 / 재시작';
  refreshProxyStatus();
});

document.getElementById('btnStop').addEventListener('click', async () => {
  const r = await fetch('/api/proxy/stop', { method: 'POST' });
  if (r.status === 401) { location.reload(); return; }
  refreshProxyStatus();
});

document.getElementById('btnLog').addEventListener('click', async () => {
  const view = document.getElementById('logView');
  if (view.style.display === 'block') { view.style.display = 'none'; return; }
  const data = await fetch('/api/proxy/log?lines=80').then(r => r.json());
  view.textContent = data.log || '(로그 없음)';
  view.style.display = 'block';
});

async function refresh() {
  try {
    const responses = await Promise.all([
      fetch('/api/summary'),
      fetch('/api/requests?limit=150'),
      fetch('/api/timeline?buckets=48'),
      fetch('/api/actions'),
    ]);
    if (responses.some(r => r.status === 401)) { location.reload(); return; }
    const [summary, requests, timeline, actions] = await Promise.all(responses.map(r => r.json()));
    await refreshProxyStatus();

    const errBox = document.getElementById('errorBox');
    if (summary.error) {
      document.getElementById('runMeta').textContent = summary.error;
      document.getElementById('lastUpdated').textContent = new Date().toLocaleTimeString('ko-KR');
      return;
    }

    document.getElementById('runMeta').innerHTML =
      `<b>run</b>=${summary.run ?? '-'} &nbsp; <b>DEFENSE_MODE</b>=${summary.mode ?? '-'} &nbsp; ` +
      `<b>ACTIVE_TECHNIQUE</b>=${summary.technique ?? '-'} &nbsp; <b>DEFENSE_ACTION</b>=${summary.action ?? '-'} &nbsp; ` +
      `<b>경과</b>=${summary.duration_s ?? 0}s`;

    const escBadge = summary.escalated
      ? `<span class="badge on">발동 · ${summary.escalated_reason ?? ''} (${fmtTime(summary.escalated_at)})</span>`
      : `<span class="badge off">미발동</span>`;
    const shellBadge = summary.fake_shell_entered
      ? `<span class="badge on">진입 (${fmtTime(summary.fake_shell_entered_at)})</span>`
      : `<span class="badge off">미진입</span>`;

    document.getElementById('kpiRow').innerHTML = `
      <div class="kpi"><div class="label">총 요청 수</div><div class="value">${summary.total_requests}</div></div>
      <div class="kpi"><div class="label">미끼 접촉 (decoy_hits)</div><div class="value">${summary.decoy_hits}</div>
        <div class="sub">${summary.total_requests ? (100*summary.decoy_hits/summary.total_requests).toFixed(1) : 0}% of 전체</div></div>
      <div class="kpi"><div class="label">에스컬레이션 (ADAPTIVE_TRAP)</div><div class="value" style="font-size:15px">${escBadge}</div></div>
      <div class="kpi"><div class="label">FAKE_SHELL 진입</div><div class="value" style="font-size:15px">${shellBadge}</div></div>
    `;

    // timeline
    const tl = document.getElementById('timeline');
    const maxCount = Math.max(1, ...timeline.series.map(b => b.normal + b.decoy + b.rce));
    tl.innerHTML = timeline.series.map(b => {
      const total = b.normal + b.decoy + b.rce;
      const h = Math.max(total / maxCount * 130, total > 0 ? 2 : 0);
      const parts = [];
      if (b.rce > 0) parts.push(`<div class="seg rce" style="height:${total ? b.rce/total*h : 0}px" data-n="${b.rce}"></div>`);
      if (b.decoy > 0) parts.push(`<div class="seg decoy" style="height:${total ? b.decoy/total*h : 0}px" data-n="${b.decoy}"></div>`);
      if (b.normal > 0) parts.push(`<div class="seg normal" style="height:${total ? b.normal/total*h : 0}px" data-n="${b.normal}"></div>`);
      return `<div class="tbar" style="height:${h}px" data-t="${b.t}" data-normal="${b.normal}" data-decoy="${b.decoy}" data-rce="${b.rce}">${parts.join('')}</div>`;
    }).join('');
    tl.querySelectorAll('.tbar').forEach(el => {
      el.addEventListener('mousemove', e => showTip(e,
        `${fmtTime(parseFloat(el.dataset.t))}<br>일반 ${el.dataset.normal} · 미끼 ${el.dataset.decoy} · RCE ${el.dataset.rce}`));
      el.addEventListener('mouseleave', hideTip);
    });

    // action distribution
    const maxAction = Math.max(1, ...actions.map(a => a.count));
    document.getElementById('actionsList').innerHTML = actions.slice(0, 15).map(a => `
      <div class="action-row">
        <div class="name" title="${a.action}">${a.action}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${(a.count/maxAction*100).toFixed(1)}%"></div></div>
        <div class="count">${a.count}</div>
      </div>
    `).join('') || '<div class="meta">아직 요청 없음</div>';

    // recent log
    document.getElementById('logBody').innerHTML = requests.map(r => `
      <tr>
        <td class="ts">${fmtTime(r.ts)}</td>
        <td>${r.method}</td>
        <td class="path" title="${r.path}">${r.path}</td>
        <td class="${statusClass(r.status)}">${r.status}</td>
        <td><span class="badge ${r.category}">${r.action}</span></td>
      </tr>
    `).join('') || '<tr><td colspan="5" class="meta">아직 요청 없음</td></tr>';

    document.getElementById('lastUpdated').textContent = '갱신: ' + new Date().toLocaleTimeString('ko-KR');
  } catch (e) {
    document.getElementById('errorBox').innerHTML = `<div class="card"><div class="error">불러오기 실패: ${e}</div></div>`;
  }
}

// ══ EXPERIMENT-ONLY 함수 시작 — 서버 운영자는 이 함수 전체와, 위 HTML의
// #experimentCard 카드, refresh() 안에서 이 함수를 부르는 한 줄을 같이 지우면 된다.
// /api/experiment 자체가 없어져도(서버 쪽 EXPERIMENT-ONLY 블록도 지웠다면) fetch가
// 실패할 뿐이라 catch에서 조용히 무시되고 나머지 화면엔 영향 없다.
async function refreshExperiment() {
  try {
    const exp = await fetch('/api/experiment').then(r => r.json());
    const t = exp.tokens, c = exp.challenges;
    const tokenHtml = t.available
      ? `<div class="value">${t.total_tokens.toLocaleString()}</div>
         <div class="sub">유효(eff) ${t.eff_tokens.toLocaleString()} · output ${t.output_tokens.toLocaleString()} · 명령 ${t.commands} · 메시지 ${t.messages}</div>`
      : `<div class="value" style="font-size:13px; color:var(--text-muted);">CODEX_LOG_PATH 미설정 — codex.jsonl 경로를 지정하면 표시됨</div>`;
    const challHtml = c.available
      ? `<div class="value">${c.solved} / ${c.total}</div><div class="sub">${c.backend} · /api/Challenges 직접 조회</div>`
      : `<div class="value" style="font-size:13px; color:var(--text-muted);">백엔드 응답 없음 (Juice Shop이 아니거나 프록시가 안 켜짐)</div>`;
    document.getElementById('experimentKpiRow').innerHTML = `
      <div class="kpi"><div class="label">에이전트 토큰 사용량</div>${tokenHtml}</div>
      <div class="kpi"><div class="label">풀이한 챌린지 수</div>${challHtml}</div>
    `;
  } catch (e) {
    // EXPERIMENT-ONLY 지표는 부가 기능이라 실패해도 나머지 대시보드에 영향 주지 않음
  }
}
// ══ EXPERIMENT-ONLY 함수 끝 ══

refresh();
refreshExperiment();                          // ★ EXPERIMENT-ONLY 호출 — 지울 때 이 줄도 같이
setInterval(refresh, 3000);
setInterval(refreshExperiment, 3000);         // ★ EXPERIMENT-ONLY 호출 — 지울 때 이 줄도 같이
</script>
</body>
</html>
"""
