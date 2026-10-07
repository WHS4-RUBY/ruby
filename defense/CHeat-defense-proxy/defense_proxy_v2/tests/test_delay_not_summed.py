"""에스컬레이션 후 미로·가짜 라우트 지연이 합산되지 않고 '둘 중 큰 값'만 걸리는지."""
import contextlib
import os
import sqlite3
import subprocess
import sys
import tempfile
import time

import httpx

DEF_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRATCH = os.path.dirname(os.path.abspath(__file__))
fails = []
_port = [4500]


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"   -> {detail}" if not cond else ""))
    if not cond:
        fails.append(name)


@contextlib.contextmanager
def rig(**env_extra):
    _port[0] += 2
    bport, pport = _port[0], _port[0] + 1
    db = os.path.join(tempfile.gettempdir(), f"dd_{pport}.db")
    if os.path.exists(db):
        os.remove(db)
    stub = subprocess.Popen([sys.executable, os.path.join(SCRATCH, "stub_srv.py"), str(bport), "404", "none"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    env = dict(os.environ)
    env.update({"REAL_BACKEND": f"http://127.0.0.1:{bport}", "DEFENSE_MODE": "off", "DECOY_MAZE": "1",
                "ADAPTIVE_TRAP": "1", "DEFENSE_DB": db, "PYTHONUTF8": "1", "PREFLIGHT": "0"})
    env.update({k: str(v) for k, v in env_extra.items()})
    proxy = subprocess.Popen([sys.executable, "-m", "uvicorn", "Defense_proxy:app", "--host", "127.0.0.1",
                              "--port", str(pport), "--no-server-header", "--log-level", "warning"],
                             cwd=DEF_DIR, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            try:
                httpx.get(f"http://127.0.0.1:{pport}/", timeout=1); break
            except Exception:
                time.sleep(0.25)
        yield f"http://127.0.0.1:{pport}", db
    finally:
        proxy.terminate(); proxy.wait(timeout=10)
        stub.terminate(); stub.wait(timeout=10)


def timed(B, path, cid):
    t = time.time()
    r = httpx.get(B + path, headers={"X-Client-Id": cid}, timeout=60)
    return r, time.time() - t


def overhead(B):
    timed(B, "/api/Products", "warm")
    return min(timed(B, "/api/Products", f"base{i}")[1] for i in range(3))


def escalate(B, cid):
    for p in ("/backup/a", "/internal/b", "/config/c"):
        timed(B, p, cid)
    timed(B, "/api/x", cid)      # 판정이 걸리는 다음 요청


print("== (A) 미로만: 에스컬레이션 1.5s, 미로 확대 지연 0.6s ==")
with rig(ESCALATE_DELAY_MS=1500, MAZE_DELAY_MS=300, MAZE_ESC_DELAY_MS=600) as (B, db):
    oh = overhead(B)
    print(f"  (기본 지연 {oh:.2f}s)")
    r, dt = timed(B, "/backup/p1", "c1")
    check(f"에스컬레이션 전 미로 접촉은 MAZE_DELAY(0.3s) (+{dt - oh:.2f}s)", 0.2 <= dt - oh < 0.7, dt - oh)
    for p in ("/internal/b", "/config/c"):
        timed(B, p, "c1")
    timed(B, "/api/x", "c1")
    r, dtg = timed(B, "/api/Products", "c1")
    check(f"에스컬레이션 후 일반 경로는 기본 지연보다 1.5s 이상 느림 (+{dtg - oh:.2f}s)", dtg - oh >= 1.2, dtg - oh)
    r, dt = timed(B, "/backup/zzz", "c1")
    check(f"에스컬레이션 후 미로 접촉이 일반 경로와 같은 수준 — 합산(+1.5s 더)이 아님 (차 {dt - dtg:+.2f}s)",
          abs(dt - dtg) < 0.8, dt - dtg)
    check("미로 응답이 맞다(maze!)", r.text.startswith("# /"), r.text[:20])
    acts = [a for (a,) in sqlite3.connect(db).execute(
        "SELECT defense_action FROM reqs WHERE client_id='c1' AND path='/backup/zzz'")]
    check("라벨 maze!", acts == ["maze!"], acts)

print("== (B) MAZE_ESC_DELAY(2.5s) > 에스컬레이션(1.5s): 큰 값 2.5s ==")
with rig(ESCALATE_DELAY_MS=1500, MAZE_DELAY_MS=300, MAZE_ESC_DELAY_MS=2500) as (B, db):
    oh = overhead(B)
    escalate(B, "c2")
    r, dt = timed(B, "/backup/zzz", "c2")
    check(f"둘 중 큰 값(2.5s) (+{dt - oh:.2f}s)", 2.3 <= dt - oh < 3.0, dt - oh)

print("== (C) FAKE_SHELL 진입 후 (T2.1): 에스컬레이션 1.5s, POST_RCE 0.3s ==")
with rig(DEFENSE_MODE="transform", ACTIVE_TECHNIQUE="T2.1", FAKE_SHELL="1", POST_RCE_DELAY_MS=300,
         ESCALATE_DELAY_MS=1500, MAZE_DELAY_MS=300, MAZE_ESC_DELAY_MS=600) as (B, db):
    oh = overhead(B)
    escalate(B, "c3")
    httpx.post(B + "/cgi-bin/x/bin/sh", content="id", headers={"X-Client-Id": "c3"}, timeout=60)
    r, dtg = timed(B, "/api/Products", "c3")
    check(f"진입 후 일반 경로는 기본 지연보다 1.5s 이상 느림 (+{dtg - oh:.2f}s)", dtg - oh >= 1.2, dtg - oh)
    r, dt = timed(B, "/backup/zzz", "c3")
    check(f"진입 후 미로 접촉이 일반 경로와 같은 수준 — 합산 아님 (차 {dt - dtg:+.2f}s)", abs(dt - dtg) < 0.8, dt - dtg)
    ohr = min(timed(B, "/server-status", f"rb{i}")[1] for i in range(3))   # 백엔드를 안 거치는 라우트의 기본 지연
    r, dt = timed(B, "/server-status", "c3")
    check(f"진입 후 가짜 라우트 1.5s — 합산 아님 (+{dt - ohr:.2f}s)", 1.3 <= dt - ohr < 2.0, dt - ohr)
    check("가짜 라우트 응답이 맞다", r.status_code == 200, r.status_code)

print("== (D) POST_RCE(3s) > 에스컬레이션(1.5s) ==")
with rig(DEFENSE_MODE="transform", ACTIVE_TECHNIQUE="T2.1", FAKE_SHELL="1", POST_RCE_DELAY_MS=3000,
         ESCALATE_DELAY_MS=1500, MAZE_DELAY_MS=300, MAZE_ESC_DELAY_MS=600) as (B, db):
    oh = overhead(B)
    escalate(B, "c4")
    httpx.post(B + "/cgi-bin/x/bin/sh", content="id", headers={"X-Client-Id": "c4"}, timeout=60)
    ohr = min(timed(B, "/server-status", f"rb{i}")[1] for i in range(3))
    r, dt = timed(B, "/server-status", "c4")
    check(f"가짜 라우트: 큰 값 3.0s — 4.5s 아님 (+{dt - ohr:.2f}s)", 2.7 <= dt - ohr < 3.8, dt - ohr)
    r, dt = timed(B, "/backup/zzz", "c4")
    check(f"미로 접촉: 큰 값 3.0s (+{dt - oh:.2f}s)", 2.7 <= dt - oh < 3.8, dt - oh)

print("\nFAILED:" if fails else "\nALL PASS", fails or "")
sys.exit(1 if fails else 0)
