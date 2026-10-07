"""대시보드(프리셋 선택·프록시 시작/중지·입력 검증)와 nginx-fastapi 프리셋 동작(가짜 상태 페이지·passwd·셸)."""
import os
import socket
import subprocess
import sys
import tempfile
import time

import httpx

DEF_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.dirname(os.path.abspath(__file__))
fails = []


def free_port() -> int:
    """비어 있는 포트 하나(이전 실행이 남긴 프로세스와 부딪히지 않게)."""
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        return sk.getsockname()[1]


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"   -> {detail}" if not cond else ""))
    if not cond:
        fails.append(name)


DASH_PORT, PROXY_PORT, STUB_PORT = free_port(), free_port(), free_port()
print("== 대시보드 ==")
env = dict(os.environ)
env.update({"DEFENSE_DB": os.path.join(tempfile.gettempdir(), "dash_test.db"), "PYTHONUTF8": "1"})
env.pop("DASHBOARD_PASSWORD", None)
if os.path.exists(env["DEFENSE_DB"]):
    os.remove(env["DEFENSE_DB"])
dash = subprocess.Popen([sys.executable, "-m", "uvicorn", "dashboard:app", "--host", "127.0.0.1", "--port", str(DASH_PORT),
                         "--log-level", "warning"], cwd=DEF_DIR, env=env,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
stub = subprocess.Popen([sys.executable, os.path.join(HERE, "stub_srv.py"), str(STUB_PORT), "404", "none"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(40):
        try:
            httpx.get(f"http://127.0.0.1:{DASH_PORT}/", timeout=1); break
        except Exception:
            time.sleep(0.25)
    B = f"http://127.0.0.1:{DASH_PORT}"
    html = httpx.get(B + "/").text
    check("프리셋 드롭다운이 있고 옵션이 채워짐",
          'name="TARGET_PRESET"' in html and 'value="nginx-fastapi"' in html and "__TARGET_PRESET_OPTIONS__" not in html)
    base = {"PORT": PROXY_PORT, "DEFENSE_MODE": "transform", "ACTIVE_TECHNIQUE": "T2.1", "REAL_BACKEND": f"http://127.0.0.1:{STUB_PORT}"}
    r = httpx.post(B + "/api/proxy/start", json={**base, "TARGET_PRESET": "bogus"})
    check("알 수 없는 프리셋 → 400", r.status_code == 400 and "bogus" in r.json().get("error", ""), (r.status_code, r.text[:80]))
    r = httpx.post(B + "/api/proxy/start", json={**base, "TARGET_PRESET": "nginx-fastapi",
                                                  "TARGET_PROFILE": os.path.join(tempfile.gettempdir(), "no_such_profile.json")})
    check("없는 프로필 파일 → 400", r.status_code == 400, (r.status_code, r.text[:80]))
    # 셸 진입 뒤에는 모든 요청에 POST_RCE_DELAY_MS(기본 8초) 지연이 걸리므로 테스트에서는 짧게 준다("고급: 추가 환경변수" 칸과 같은 방식)
    r = httpx.post(B + "/api/proxy/start", json={**base, "FAKE_SHELL": True, "TARGET_PRESET": "nginx-fastapi",
                                                  "EXTRA_ENV": "POST_RCE_DELAY_MS=100"})
    check("정상 시작 → 200", r.status_code == 200 and r.json().get("ok"), (r.status_code, r.text[:80]))
    time.sleep(3)

    print("== nginx-fastapi 프리셋 ==")
    P = f"http://127.0.0.1:{PROXY_PORT}"
    r = httpx.get(P + "/nginx_status", timeout=5)
    check("nginx 형식 가짜 상태 페이지", r.status_code == 200 and "Active connections" in r.text, (r.status_code, r.text[:30]))
    check("가짜 passwd 에 appuser", "appuser:x:10001:10001" in httpx.get(P + "/_debug/x/etc/passwd", timeout=5).text)
    sh = lambda c: httpx.post(P + "/_debug/console/exec", content=c.encode(), timeout=5).text
    check("셸 id → uid=10001(appuser)", "uid=10001(appuser)" in sh("id"))
    check("셸 pwd → /app", sh("pwd").strip() == "/app")
    check("셸 uname → Alpine 형식(끝이 Linux)", sh("uname -a").strip().endswith("x86_64 Linux"), sh("uname -a"))
    check("Apache 미끼(/server-status)는 이 프리셋에서 가짜가 아님", httpx.get(P + "/server-status", timeout=5).status_code == 404)

    check("중지 → 200", httpx.post(B + "/api/proxy/stop").status_code == 200)
finally:
    try:                                  # 대시보드가 띄운 프록시(자식)는 대시보드를 죽여도 안 죽으므로 먼저 중지 요청
        httpx.post(f"http://127.0.0.1:{DASH_PORT}/api/proxy/stop", timeout=5)
    except Exception:
        pass
    dash.terminate(); stub.terminate(); dash.wait(timeout=10); stub.wait(timeout=10)

print("\nFAILED:" if fails else "\nALL PASS", fails or "")
sys.exit(1 if fails else 0)
