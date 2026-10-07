"""② 레시피를 클라이언트별로 적용 — 응답 변조(헤더·robots·병합·메모)·로그인 미끼·Server 배너 일관성·레시피 충돌 규칙.
플랜 전략 이름(decoy_t21_shell 등)은 ③에서 등록하므로, 여기서는 같은 프로세스에서 ClientState.recipe 를 직접 지정한다."""
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import uvicorn

DEF_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"   -> {detail}" if not cond else ""))
    if not cond:
        fails.append(name)


class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ct):
        self.send_response(code); self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/":
            return self._send(200, b"<html><head><title>x</title></head><body>app</body></html>", "text/html; charset=utf-8")
        if p == "/robots.txt":
            return self._send(200, b"User-agent: *\nDisallow: /ftp\n", "text/plain")
        if p == "/rest/admin/application-version":
            return self._send(200, json.dumps({"version": "9.9"}).encode(), "application/json")
        if p == "/rest/admin/application-configuration":
            return self._send(200, json.dumps({"config": {"server": {"port": 3000}}}).encode(), "application/json")
        return self._send(404, b"nf", "text/plain")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); self.rfile.read(n)
        self._send(401, b'{"error":"Invalid email or password."}', "application/json")

    def log_message(self, *a):
        pass


bport, pport = 4900, 4901
srv = HTTPServer(("127.0.0.1", bport), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
os.environ.update({"REAL_BACKEND": f"http://127.0.0.1:{bport}", "DEFENSE_MODE": "off", "DECOY_REQUIRE_PLAN": "1",
                   "DEFENSE_DB": os.path.join(tempfile.gettempdir(), "rpc.db"), "PYTHONUTF8": "1", "PREFLIGHT": "0",
                   "ESCALATE_DELAY_MS": "300", "MAZE_DELAY_MS": "0", "MAZE_ESC_DELAY_MS": "0"})
if os.path.exists(os.environ["DEFENSE_DB"]):
    os.remove(os.environ["DEFENSE_DB"])
sys.path.insert(0, DEF_DIR)
os.chdir(DEF_DIR)
import Defense_proxy as D  # noqa: E402

server = uvicorn.Server(uvicorn.Config(D.app, host="127.0.0.1", port=pport, log_level="warning", server_header=False))
threading.Thread(target=server.run, daemon=True).start()
for _ in range(80):
    try:
        httpx.get(f"http://127.0.0.1:{pport}/", timeout=1); break
    except Exception:
        time.sleep(0.1)
B = f"http://127.0.0.1:{pport}"


def get(path, cid, **kw):
    return httpx.get(B + path, headers={"X-Client-Id": cid}, timeout=30, **kw)


def post_login(cid, email, path="/rest/user/login"):
    return httpx.post(B + path, json={"email": email, "password": "x"}, headers={"X-Client-Id": cid}, timeout=30)


def st(cid):
    return D._get_client(cid)


banner = D.transforms.PROFILE["web"]["server_banner"]
check("묶음 모드의 SPOOF_SERVER 기본값 = 프로필 배너", D.SPOOF_SERVER == banner, D.SPOOF_SERVER)

print("== 플랜 없는 클라이언트: 응답이 전혀 안 바뀜 ==")
r = get("/", "n")
check("Server 헤더 위조 없음(백엔드 그대로)", r.headers.get("server", "") != banner and "bridge" not in str(r.headers).lower(), dict(r.headers))
check("HTML 주석 없음", "<!--" not in r.text, r.text)
check("robots 그대로", get("/robots.txt", "n").text == "User-agent: *\nDisallow: /ftp\n")
check("설정 JSON 병합 없음", "adminBridgeBase" not in get("/rest/admin/application-configuration", "n").text)
check("로그인 미끼 없음(423 아님)", post_login("n", "svc-migration@x").status_code == 401)

print("== T2.1 클라이언트 ==")
st("a").recipe = "T2.1"; st("a").maze_planned = True; st("a").decoy_planned = True
r = get("/", "a")
check("Server 배너 = 프로필 배너", r.headers.get("server") == banner, r.headers.get("server"))
check("X-Powered-By", r.headers.get("x-powered-by", "").startswith("PHP"), r.headers.get("x-powered-by"))
check("robots 에 /cgi-bin/ 힌트", "/cgi-bin/" in get("/robots.txt", "a").text, get("/robots.txt", "a").text)
check("버전 API 에 httpServer 병합", json.loads(get("/rest/admin/application-version", "a").text).get("httpServer") == banner)
check("MIGRATION 요소는 없음", "X-Backend-Bridge".lower() not in r.headers and "chmod" not in r.text)
r = get("/icons/.%2e/.%2e/etc/passwd", "a")
acts = [x for (x,) in sqlite3.connect(os.environ["DEFENSE_DB"]).execute(
    "SELECT defense_action FROM reqs WHERE client_id='a' AND path LIKE '/icons%'")]
check("traversal-probe 신호가 T2.1 클라이언트에 켜짐", any(a.startswith("traversal-probe") for a in acts), acts)
r = get("/icons/.%2e/.%2e/etc/passwd", "n")
acts_n = [x for (x,) in sqlite3.connect(os.environ["DEFENSE_DB"]).execute(
    "SELECT defense_action FROM reqs WHERE client_id='n' AND path LIKE '/icons%'")]
check("플랜 없는 클라이언트에는 traversal-probe 없음", not any(a.startswith("traversal-probe") for a in acts_n), acts_n)

print("== MIGRATION 클라이언트 ==")
st("b").recipe = "MIGRATION_TRACES"; st("b").maze_planned = True; st("b").decoy_planned = True
r = get("/", "b")
check("X-Backend-Bridge 헤더", r.headers.get("x-backend-bridge", "").startswith("legacy-admin-bridge"), dict(r.headers))
check("HTML 개발자 메모 주석", "chmod 640 /opt/app/config/current.yml" in r.text, r.text)
check("robots 에 /rest/internal/", "/rest/internal/" in get("/robots.txt", "b").text)
check("설정 JSON 에 adminBridgeBase 병합", "adminBridgeBase" in get("/rest/admin/application-configuration", "b").text)
check("로그인 미끼 423", post_login("b", "svc-migration@x").status_code == 423)
check("T2.1 요소는 없음(Apache 배너 아님이어도 PHP 헤더 없음)", "x-powered-by" not in r.headers, dict(r.headers))
check("T2.1 클라이언트 a 는 MIGRATION 로그인 미끼를 레시피로는 안 받지만 미로 로그인 미끼는 받음(423)",
      post_login("a", "svc-migration@x").status_code == 423)

print("== 미로만 클라이언트(레시피 없음) ==")
st("c").maze_planned = True; st("c").decoy_planned = True
r1 = get("/", "c")
check("Server 배너 = 프로필 배너(레시피 없이도)", r1.headers.get("server") == banner, r1.headers.get("server"))
check("로그인 미끼(서버 무관): 423", post_login("c", "svc-migration@x").status_code == 423)
st("c").recipe = "T2.1"                                  # 미로만 → T2.1 승급
r2 = get("/", "c")
check("승급 전후 Server 배너 동일(세계관 안 바뀜)", r1.headers.get("server") == r2.headers.get("server") == banner,
      (r1.headers.get("server"), r2.headers.get("server")))

print("== 레시피 충돌 규칙 ==")
check("T2.1 클라이언트에 MIGRATION 지정 시도 → 거부", D._set_client_recipe(st("a"), "MIGRATION_TRACES", "a") is False)
check("거부 후에도 T2.1 유지", st("a").recipe == "T2.1", st("a").recipe)
check("같은 레시피 재지정은 허용", D._set_client_recipe(st("a"), "T2.1", "a") is True)
check("새 클라이언트는 지정 가능", D._set_client_recipe(st("z"), "MIGRATION_TRACES", "z") is True and st("z").recipe == "MIGRATION_TRACES")

print("== 격리 ==")
check("n 은 여전히 변조 없음", "<!--" not in get("/", "n").text and post_login("n", "svc-migration@x").status_code == 401)

server.should_exit = True
print("\nFAILED:" if fails else "\nALL PASS", fails or "")
sys.exit(1 if fails else 0)
