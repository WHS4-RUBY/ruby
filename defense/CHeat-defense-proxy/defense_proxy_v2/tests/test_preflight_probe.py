import os
import subprocess
import sys
import tempfile
import time

import httpx

DEF_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRATCH = os.path.dirname(os.path.abspath(__file__))
fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"   -> {detail}" if not cond else ""))
    if not cond:
        fails.append(name)


def boot(off, mode="404", **env_extra):
    bport, pport = 3600 + off, 3601 + off
    log = os.path.join(tempfile.gettempdir(), f"pfp_{pport}.log")
    env = dict(os.environ)
    env.update({"REAL_BACKEND": f"http://127.0.0.1:{bport}", "DEFENSE_MODE": "transform", "ACTIVE_TECHNIQUE": "T2.1",
                "DEFENSE_DB": os.path.join(tempfile.gettempdir(), f"pfp_{pport}.db"), "PYTHONUTF8": "1"})
    for k, v in env_extra.items():
        if v is None:
            env.pop(k, None)
        else:
            env[k] = str(v)
    stub = subprocess.Popen([sys.executable, os.path.join(SCRATCH, "stub_srv.py"), str(bport), mode, "none"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proxy = subprocess.Popen([sys.executable, "-u", "-m", "uvicorn", "Defense_proxy:app", "--host", "127.0.0.1",
                              "--port", str(pport), "--log-level", "warning"], cwd=DEF_DIR, env=env,
                             stdout=open(log, "w", encoding="utf-8"), stderr=subprocess.STDOUT)
    try:
        for _ in range(60):
            try:
                httpx.get(f"http://127.0.0.1:{pport}/", timeout=1)
                break
            except Exception:
                time.sleep(0.25)
        time.sleep(1.0)
    finally:
        proxy.terminate(); stub.terminate(); proxy.wait(timeout=10); stub.wait(timeout=10)
    return open(log, encoding="utf-8").read()


out = boot(0)
print(out)
check("기본 /icons/ 가 백엔드에 없으면 probe-path 알림 없음", "probe-path-exists" not in out, out)
out = boot(10, TRAVERSAL_PROBE_PATHS="/admin/")
print(out)
check("지정 접두어가 백엔드에 실제로 있으면 INFO", "probe-path-exists" in out and "/admin/" in out, out)
check("그 알림은 WARN 이 아니라 INFO(정상 요청 영향 없음)", "WARN probe-path" not in out)
out = boot(20, mode="spa")
check("SPA 폴백 백엔드: /icons/ 는 폴백이라 '실제 경로' 로 보지 않음", "probe-path-exists" not in out, out)
out = boot(30, PREFLIGHT="0", TRAVERSAL_PROBE_PATHS="/admin/")
check("PREFLIGHT=0 이면 조용", "[preflight]" not in out, out)
print("\nFAILED:" if fails else "\nALL PASS", fails or "")
sys.exit(1 if fails else 0)
