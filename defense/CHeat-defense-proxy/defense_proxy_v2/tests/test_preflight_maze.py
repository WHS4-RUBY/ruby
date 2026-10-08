"""미로 preflight — 시작 로그에 경고가 제대로 나오는지."""
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


def boot(mode, robots, port_off, **env_extra):
    bport, pport = 3200 + port_off, 3201 + port_off
    log = os.path.join(tempfile.gettempdir(), f"pf_{pport}.log")
    env = dict(os.environ)
    env.update({"REAL_BACKEND": f"http://127.0.0.1:{bport}", "DEFENSE_MODE": "off", "DECOY_MAZE": "1",
                "DEFENSE_DB": os.path.join(tempfile.gettempdir(), f"pf_{pport}.db"), "PYTHONUTF8": "1"})
    env.update({k: str(v) for k, v in env_extra.items()})
    stub = subprocess.Popen([sys.executable, os.path.join(SCRATCH, "stub_srv.py"), str(bport), mode, robots],
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
        proxy.terminate()
        stub.terminate()
        proxy.wait(timeout=10)
        stub.wait(timeout=10)
    return open(log, encoding="utf-8").read()


print("--- 1) SPA 폴백 + 진짜 robots 에 /admin/ ---")
# 스텁 robots=real 은 /secret-real/ 만 Disallow — 겹침 테스트는 MAZE_PATHS 에 /secret-real/ 를 넣어서
out = boot("spa", "real", 0, MAZE_PATHS="/internal/,/secret-real/")
print(out)
check("spa-fallback 경고", "spa-fallback" in out)
check("robots-overlap-real 경고", "robots-overlap-real" in out and "/secret-real/" in out)

print("--- 2) 광고 경로가 백엔드에 실제로 있음(/admin 200), 403(/config) ---")
out = boot("404", "none", 10, MAZE_PATHS="/admin/,/config/,/internal/")
print(out)
check("maze-path-real(/admin)", "maze-path-real" in out and "/admin" in out)
check("maze-path-forbidden(/config)", "maze-path-forbidden" in out and "/config" in out)
check("404 모드에서는 spa-fallback 경고 없음", "spa-fallback" not in out)

print("--- 3) MAZE_PATTERN 직접 지정으로 광고 경로·입구와 어긋남 ---")
out = boot("404", "none", 20, MAZE_PATTERN=r"^/zzz($|/)")
print(out)
check("maze-path-not-maze", "maze-path-not-maze" in out)
check("maze-entry-not-maze", "maze-entry-not-maze" in out)

print("--- 4) MAZE_EXCLUDE 가 입구를 막음 ---")
out = boot("404", "none", 30, MAZE_EXCLUDE=r"^/internal")
print(out)
check("maze-entry-excluded", "maze-entry-excluded" in out)
check("maze-path-excluded", "maze-path-excluded" in out)

print("--- 5) 정상 설정은 경고 없음 ---")
# (스텁은 /admin=200, /config=403 이 진짜라서 기본 경로 목록은 정당하게 경고한다 — 진짜가 없는 경로로 확인)
out = boot("404", "none", 40, MAZE_PATHS="/internal/,/backup/")
print(out)
check("경고 없음", "WARN" not in out)

print("--- 6) PREFLIGHT=0 이면 조용 ---")
out = boot("spa", "real", 50, PREFLIGHT=0)
check("PREFLIGHT=0: preflight 출력 없음", "[preflight]" not in out)

print("--- 7) STRICT: 모순 있으면 시작 거부 ---")
env = dict(os.environ)
env.update({"DECOY_MAZE": "1", "DEFENSE_MODE": "off", "MAZE_PATTERN": r"^/zzz($|/)", "PREFLIGHT_STRICT": "1",
            "DEFENSE_DB": os.path.join(tempfile.gettempdir(), "pf_strict.db"), "PYTHONUTF8": "1"})
p = subprocess.run([sys.executable, "-c", "import Defense_proxy"], cwd=DEF_DIR, env=env,
                   capture_output=True, text=True, encoding="utf-8")
check("STRICT: SystemExit", p.returncode != 0 and "PREFLIGHT_STRICT" in (p.stderr + p.stdout), p.stderr[-300:])

print("\nFAILED:" if fails else "\nALL PASS", fails or "")
sys.exit(1 if fails else 0)
