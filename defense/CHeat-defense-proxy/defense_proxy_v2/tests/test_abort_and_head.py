"""(A) 클라이언트가 지연 중에 연결을 끊어도 그 요청이 DB 에 기록되는가  (B) HEAD 요청이 '진짜 경로' 학습을 오염시켜
이후 GET 미로가 꺼지지 않는가(SPA 폴백 백엔드와 404 백엔드 둘 다)."""
import contextlib
import os
import sqlite3
import subprocess
import sys
import tempfile
import time

import httpx

DEF_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.dirname(os.path.abspath(__file__))
fails = []
_port = [5400]


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"   -> {detail}" if not cond else ""))
    if not cond:
        fails.append(name)


@contextlib.contextmanager
def rig(mode, **env_extra):
    _port[0] += 2
    bport, pport = _port[0], _port[0] + 1
    db = os.path.join(tempfile.gettempdir(), f"ah_{pport}.db")
    if os.path.exists(db):
        os.remove(db)
    env = dict(os.environ)
    env.update({"REAL_BACKEND": f"http://127.0.0.1:{bport}", "DEFENSE_MODE": "off", "DECOY_MAZE": "1",
                "MAZE_DELAY_MS": "0", "DEFENSE_DB": db, "PYTHONUTF8": "1", "PREFLIGHT": "0"})
    env.update({k: str(v) for k, v in env_extra.items()})
    stub = subprocess.Popen([sys.executable, os.path.join(HERE, "stub_srv.py"), str(bport), mode, "none"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proxy = subprocess.Popen([sys.executable, "-m", "uvicorn", "Defense_proxy:app", "--host", "127.0.0.1",
                              "--port", str(pport), "--no-server-header", "--log-level", "warning"],
                             cwd=DEF_DIR, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{pport}"
    try:
        for _ in range(60):
            try:
                httpx.get(base + "/", timeout=1); break
            except Exception:
                time.sleep(0.25)
        yield base, db
    finally:
        proxy.terminate(); stub.terminate(); proxy.wait(timeout=10); stub.wait(timeout=10)


def is_maze(r):
    return r.text.startswith("# /")


print("== (A) 지연 중 연결을 끊은 요청도 기록 ==")
with rig("spa", ADAPTIVE_TRAP="1", MAZE_DELAY_MS="3000", ESCALATE_DELAY_MS="3000") as (B, db):
    for p in ("/backup/a", "/.git/config"):
        try:
            httpx.get(B + p, timeout=1.0)           # 미로 지연(3초)보다 짧게 기다리고 끊는다
            check(f"{p} 를 1초 안에 끊음", False, "끊기지 않음")
        except httpx.TimeoutException:
            check(f"{p} 를 1초 안에 끊음", True)
    time.sleep(6)                                   # 프록시가 지연을 끝낼 시간
    rows = sqlite3.connect(db).execute("SELECT path, status, defense_action FROM reqs ORDER BY id").fetchall()
    check("끊긴 미로 요청이 DB 에 maze 로 기록됨", sum(1 for r in rows if r[2].startswith("maze")) >= 2, rows)

print("== (B) HEAD 가 진짜 경로 학습을 오염시키지 않음 ==")
for mode in ("spa", "404"):
    with rig(mode) as (B, db):
        check(f"[{mode}] HEAD 전 GET /internal/ → 미로", is_maze(httpx.get(B + "/internal/", timeout=10)))
        httpx.head(B + "/backup/", timeout=10)
        check(f"[{mode}] HEAD 직후 같은 경로 GET → 여전히 미로", is_maze(httpx.get(B + "/backup/", timeout=10)))
        httpx.head(B + "/internal/ops/runbook", timeout=10)
        r = httpx.get(B + "/internal/ops/runbook", headers={"X-Client-Id": "other"}, timeout=10)
        check(f"[{mode}] HEAD 뒤 다른 클라이언트 GET → 여전히 미로", is_maze(r), r.text[:30])

print("\nFAILED:" if fails else "\nALL PASS", fails or "")
sys.exit(1 if fails else 0)
