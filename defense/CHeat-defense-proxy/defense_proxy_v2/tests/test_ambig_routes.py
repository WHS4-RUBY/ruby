"""AMBIG 차단 확정 뒤 가짜 라우트(T2.1·MIGRATION_TRACES)도 403 이 되는지."""
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
_port = [3700]


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"   -> {detail}" if not cond else ""))
    if not cond:
        fails.append(name)


@contextlib.contextmanager
def rig(**env_extra):
    _port[0] += 2
    bport, pport = _port[0], _port[0] + 1
    db = os.path.join(tempfile.gettempdir(), f"ambr_{pport}.db")
    if os.path.exists(db):
        os.remove(db)
    env = dict(os.environ)
    env.update({"REAL_BACKEND": f"http://127.0.0.1:{bport}", "DEFENSE_MODE": "transform", "DECOY_MAZE": "1",
                "ADAPTIVE_TRAP": "1", "AMBIG_TRAP": "1", "MAZE_DELAY_MS": "0", "MAZE_ESC_DELAY_MS": "0",
                "ESCALATE_DELAY_MS": "200", "DEFENSE_DB": db, "PYTHONUTF8": "1", "PREFLIGHT": "0"})
    env.update({k: str(v) for k, v in env_extra.items()})
    stub = subprocess.Popen([sys.executable, os.path.join(SCRATCH, "stub_srv.py"), str(bport), "404", "none"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proxy = subprocess.Popen([sys.executable, "-m", "uvicorn", "Defense_proxy:app", "--host", "127.0.0.1",
                              "--port", str(pport), "--no-server-header", "--log-level", "warning"], cwd=DEF_DIR, env=env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{pport}"
    try:
        for _ in range(60):
            try:
                httpx.get(base + "/", timeout=1)
                break
            except Exception:
                time.sleep(0.25)
        yield base, db
    finally:
        proxy.terminate(); stub.terminate(); proxy.wait(timeout=10); stub.wait(timeout=10)


def g(base, path, cid):
    return httpx.get(base + path, headers={"X-Client-Id": cid}, timeout=20)


def actions(db, cid, path_like):
    return [r[0] for r in sqlite3.connect(db).execute(
        "SELECT defense_action FROM reqs WHERE client_id=? AND path LIKE ? ORDER BY id", (cid, path_like))]


def block_client(base, cid):
    for p in ("/backup/a", "/.git/config", "/config/x.yml"):
        g(base, p, cid)
    g(base, "/", cid)               # 에스컬레이션·차단이 판정되는 요청(이 요청은 200)
    return g(base, "/", cid).status_code


CASES = [
    ("구성 1 (T2.1)", "T2.1",
     [("/server-status", 200), ("/cgi-bin/%2e%2e/%2e%2e/etc/passwd", 200)]),
    ("구성 2 (MIGRATION_TRACES)", "MIGRATION_TRACES",
     [("/rest/internal", 200), ("/rest/internal/status", 200), ("/rest/internal/users", 401)]),
]
for label, tech, probes in CASES:
    print(f"== {label} ==")
    with rig(ACTIVE_TECHNIQUE=tech) as (B, db):
        for i, (p, want) in enumerate(probes):
            r = g(B, p, f"fresh{i}")
            check(f"차단 전(깨끗한 클라이언트): {p} → {want}", r.status_code == want, r.status_code)
        check("일반 경로가 차단 확정됨(다음 요청부터 403)", block_client(B, "bad") == 403)
        for p, _ in probes:
            r = g(B, p, "bad")
            check(f"차단 후: {p} → 403", r.status_code == 403 and '"detail": "forbidden"' in r.text, (r.status_code, r.text[:40]))
        r = g(B, probes[0][0], "bad")
        check("차단 응답에도 Server 헤더 유지(훅의 차단 응답과 같은 모양)", r.headers.get("server") == "nginx", dict(r.headers))
        check("DB 에 ambig-block 으로 기록", "ambig-block" in actions(db, "bad", probes[0][0].split("?")[0] + "%"),
              actions(db, "bad", probes[0][0] + "%"))
        # 훅의 기존 차단 응답과 같은 본문
        h = g(B, "/", "bad")
        check("훅의 차단 응답과 같은 본문", h.status_code == 403 and h.text == g(B, probes[0][0], "bad").text, (h.text,))
        # 다른 클라이언트는 영향 없음
        for i, (p, want) in enumerate(probes):
            r = g(B, p, "other")
            check(f"다른 클라이언트(other)는 그대로: {p} → {want}", r.status_code == want, r.status_code)

print("== AMBIG_TRAP 끄면 가짜 라우트 동작은 그대로 ==")
with rig(ACTIVE_TECHNIQUE="T2.1", AMBIG_TRAP="0") as (B, db):
    block_client(B, "bad")
    r = g(B, "/server-status", "bad")
    check("AMBIG 꺼짐: 에스컬레이션 후에도 /server-status 200(지연만)", r.status_code == 200, r.status_code)

print("\nFAILED:" if fails else "\nALL PASS", fails or "")
sys.exit(1 if fails else 0)
