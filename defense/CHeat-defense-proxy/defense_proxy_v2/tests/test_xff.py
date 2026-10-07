"""X-Forwarded-For 위조로 클라이언트 식별(ip:<주소>)이 바뀌어 AMBIG 차단을 우회하는 문제 —
uvicorn 기본 옵션에서는 우회가 되고(회귀 확인용 대조군), UVICORN_PROXY_HEADERS=0 / FORWARDED_ALLOW_IPS='' 로는 막히는지."""
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
_n = [0]
BAITS = ("/backup/a", "/.git/config", "/config/x.yml")


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"   -> {detail}" if not cond else ""))
    if not cond:
        fails.append(name)


def run(extra_env):
    """미끼 3개 → AMBIG 차단 확정 → X-Forwarded-For 를 바꿔 보낸 요청의 상태코드들과 DB 의 client_id 목록."""
    _n[0] += 2
    bport, pport = 5200 + _n[0], 5201 + _n[0]
    db = os.path.join(tempfile.gettempdir(), f"xff_{pport}.db")
    if os.path.exists(db):
        os.remove(db)
    env = dict(os.environ)
    env.update({"REAL_BACKEND": f"http://127.0.0.1:{bport}", "DEFENSE_MODE": "off", "DECOY_MAZE": "1",
                "ADAPTIVE_TRAP": "1", "AMBIG_TRAP": "1", "MAZE_DELAY_MS": "0", "MAZE_ESC_DELAY_MS": "0",
                "ESCALATE_DELAY_MS": "100", "DEFENSE_DB": db, "PYTHONUTF8": "1", "PREFLIGHT": "0"})
    env.update(extra_env)
    stub = subprocess.Popen([sys.executable, os.path.join(HERE, "stub_srv.py"), str(bport), "404", "none"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proxy = subprocess.Popen([sys.executable, "-m", "uvicorn", "Defense_proxy:app", "--host", "127.0.0.1",
                              "--port", str(pport), "--no-server-header", "--log-level", "warning"],
                             cwd=DEF_DIR, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(60):
            try:
                httpx.get(f"http://127.0.0.1:{pport}/", timeout=1); break
            except Exception:
                time.sleep(0.25)
        B = f"http://127.0.0.1:{pport}"
        for p in BAITS:
            httpx.get(B + p, timeout=15)
        httpx.get(B + "/", timeout=15)                      # 에스컬레이션·차단이 판정되는 요청
        plain = httpx.get(B + "/api/Products", timeout=15).status_code
        spoof = [httpx.get(B + "/api/Products", headers={"X-Forwarded-For": f"198.51.100.{n}"}, timeout=15).status_code
                 for n in (11, 12, 13)]
        ids = sorted(r[0] for r in sqlite3.connect(db).execute("SELECT DISTINCT client_id FROM reqs"))
        return plain, spoof, ids
    finally:
        proxy.terminate(); stub.terminate(); proxy.wait(timeout=10); stub.wait(timeout=10)


plain, spoof, ids = run({"UVICORN_PROXY_HEADERS": "0"})
check("UVICORN_PROXY_HEADERS=0: 차단이 확정됨(403)", plain == 403, plain)
check("UVICORN_PROXY_HEADERS=0: X-Forwarded-For 를 바꿔도 계속 403", spoof == [403, 403, 403], spoof)
check("UVICORN_PROXY_HEADERS=0: 위조한 IP 가 client_id 로 안 쓰임", not any("198.51.100" in i for i in ids), ids)

plain, spoof, ids = run({"FORWARDED_ALLOW_IPS": ""})
check("FORWARDED_ALLOW_IPS='': X-Forwarded-For 를 바꿔도 계속 403", spoof == [403, 403, 403], spoof)

plain, spoof, ids = run({"CLIENT_ID_FALLBACK": "global"})
check("CLIENT_ID_FALLBACK=global: 위조 IP 가 있어도 한 클라이언트(global)로 묶여 403", spoof == [403, 403, 403], (spoof, ids))

plain, spoof, ids = run({})
check("대조군(uvicorn 기본 옵션): X-Forwarded-For 위조로 새 클라이언트가 되어 우회됨 — 이 환경변수들이 필요한 이유",
      any(s != 403 for s in spoof) and any("198.51.100" in i for i in ids), (spoof, ids))

print("\nFAILED:" if fails else "\nALL PASS", fails or "")
sys.exit(1 if fails else 0)
