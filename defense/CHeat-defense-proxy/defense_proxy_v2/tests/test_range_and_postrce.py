"""(A) Range/조건부 요청이 미로를 우회하지 못하게 한 수정  (B) FAKE_SHELL 진입 후 지연이 에스컬레이션보다 약해지지 않는 수정."""
import contextlib
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx

DEF_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRATCH = os.path.dirname(os.path.abspath(__file__))
SHELL = b"<html><head><title>x</title></head><body>" + b"hi " * 300 + b"</body></html>"
REAL = b"REAL-ADMIN-PAGE " * 40
ETAG = '"abc123"'
fails = []
_port = [4300]


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"   -> {detail}" if not cond else ""))
    if not cond:
        fails.append(name)


class H(BaseHTTPRequestHandler):
    """Express static 처럼 Range(206)/ETag(304) 를 지원하는 SPA 백엔드. /admin 은 진짜 페이지(비-셸)."""

    def do_GET(self):
        body_full = REAL if self.path.split("?")[0] == "/admin" else SHELL
        if self.headers.get("If-None-Match") == ETAG:
            self.send_response(304); self.send_header("ETag", ETAG); self.end_headers(); return
        rng = self.headers.get("Range")
        if rng and rng.startswith("bytes="):
            a, _, b = rng[6:].partition("-")
            a = int(a or 0); b = int(b) if b else len(body_full) - 1
            body = body_full[a:b + 1]
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {a}-{b}/{len(body_full)}")
        else:
            body = body_full
            self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        self.send_header("ETag", ETAG)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@contextlib.contextmanager
def rig(backend="custom", **env_extra):
    _port[0] += 2
    bport, pport = _port[0], _port[0] + 1
    db = os.path.join(tempfile.gettempdir(), f"rpr_{pport}.db")
    if os.path.exists(db):
        os.remove(db)
    srv = stub = None
    if backend == "custom":
        srv = HTTPServer(("127.0.0.1", bport), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    else:
        stub = subprocess.Popen([sys.executable, os.path.join(SCRATCH, "stub_srv.py"), str(bport), "404", "none"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    env = dict(os.environ)
    env.update({"REAL_BACKEND": f"http://127.0.0.1:{bport}", "DEFENSE_MODE": "off", "DECOY_MAZE": "1",
                "MAZE_DELAY_MS": "0", "MAZE_ESC_DELAY_MS": "0", "DEFENSE_DB": db, "PYTHONUTF8": "1", "PREFLIGHT": "0"})
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
        if srv:
            srv.shutdown()
        if stub:
            stub.terminate(); stub.wait(timeout=10)


def is_maze(r):
    return r.text.startswith("# /")


print("== (A) Range/조건부 요청 ==")
with rig() as (B, db):
    httpx.get(B + "/")                                    # 셸 캐시
    r = httpx.get(B + "/internal/ops/config.yml.bak", headers={"Range": "bytes=0-99"})
    check("미로 경로 + Range → 206 이 아니라 전체 200 미로", r.status_code == 200 and is_maze(r), (r.status_code, r.text[:20]))
    r = httpx.get(B + "/backup/", headers={"Range": "bytes=0-"})
    check("미로 경로 + Range: bytes=0- → 미로", r.status_code == 200 and is_maze(r), (r.status_code, r.text[:20]))
    r = httpx.get(B + "/config/", headers={"If-None-Match": ETAG})
    check("미로 경로 + If-None-Match → 304 가 아니라 미로", r.status_code == 200 and is_maze(r), (r.status_code, r.text[:20]))
    r = httpx.get(B + "/private/", headers={"If-Modified-Since": "Wed, 21 Oct 2099 07:28:00 GMT", "If-Range": ETAG, "Range": "bytes=5-10"})
    check("여러 조건부 헤더를 같이 보내도 미로", r.status_code == 200 and is_maze(r), (r.status_code, r.text[:20]))
    acts = [a for (a,) in sqlite3.connect(db).execute("SELECT defense_action FROM reqs WHERE path!='/' ORDER BY id")]
    check("DB 에 maze 로 기록(미끼 접촉으로 세어짐)", acts and all(a.startswith("maze") for a in acts), acts)
    r = httpx.get(B + "/assets/app.js", headers={"Range": "bytes=0-9"})
    check("미로 패턴이 아닌 경로의 Range 는 그대로 206", r.status_code == 206 and len(r.content) == 10, (r.status_code, len(r.content)))
    r = httpx.get(B + "/assets/app.js", headers={"If-None-Match": ETAG})
    check("미로 패턴이 아닌 경로의 조건부 요청은 그대로 304", r.status_code == 304, r.status_code)
    # 진짜 경로: 첫 요청은 헤더가 제거돼 전체 200(진짜 경로로 학습), 이후엔 Range 가 그대로 206
    r1 = httpx.get(B + "/admin", headers={"Range": "bytes=0-9"})
    # (미로가 켜져 있어 HTML 응답 끝에 ops 주석이 붙으므로 '정확히 같음'이 아니라 '진짜 본문 전체로 시작'으로 본다)
    check("진짜 /admin 의 첫 Range 요청: 전체 200 + 진짜 본문(미로 아님)",
          r1.status_code == 200 and r1.content.startswith(REAL) and not is_maze(r1),
          (r1.status_code, len(r1.content)))
    r2 = httpx.get(B + "/admin", headers={"Range": "bytes=0-9"})
    check("진짜 경로로 학습된 뒤엔 Range 가 그대로 206", r2.status_code == 206 and len(r2.content) == 10, (r2.status_code, len(r2.content)))

with rig(MAZE_REQUIRE_PLAN="1") as (B, db):
    httpx.get(B + "/")
    r = httpx.get(B + "/backup/", headers={"Range": "bytes=0-99"})
    check("MAZE_REQUIRE_PLAN=1 + 플랜 없음: 미로 꺼짐 → Range 그대로 206", r.status_code == 206, r.status_code)
    r = httpx.get(B + "/backup/", headers={"Range": "bytes=0-99", "X-Defense-Plan": '[{"name":"maze"}]'})
    check("플랜에 maze 가 있으면 Range 제거 → 미로", r.status_code == 200 and is_maze(r), (r.status_code, r.text[:20]))
with rig(DECOY_MAZE="0") as (B, db):
    httpx.get(B + "/")
    r = httpx.get(B + "/backup/", headers={"Range": "bytes=0-99"})
    check("DECOY_MAZE=0: 건드리지 않음", r.status_code == 206, r.status_code)


def timed(B, path, cid, **kw):
    t = time.time()
    r = httpx.get(B + path, headers={"X-Client-Id": cid}, timeout=30, **kw)
    return r, time.time() - t


def enter_shell(B, cid):
    return httpx.post(B + "/cgi-bin/x/bin/sh", content="id", headers={"X-Client-Id": cid}, timeout=30)


print("== (B) FAKE_SHELL 진입 후 지연 ==")
common = dict(DEFENSE_MODE="transform", ACTIVE_TECHNIQUE="T2.1", FAKE_SHELL="1", ADAPTIVE_TRAP="1", ESCALATE_DELAY_MS="1500")


def overhead(B):
    """이 PC 의 요청당 기본 지연(지연 방어와 무관한 loopback·uvicorn 오버헤드) — 상대값 비교용."""
    timed(B, "/api/Products", "warm")
    return min(timed(B, "/api/Products", f"base{i}")[1] for i in range(3))


with rig("stub", POST_RCE_DELAY_MS="300", **common) as (B, db):
    oh = overhead(B)
    print(f"  (기본 지연 {oh:.2f}s)")
    for p in ("/backup/a", "/.git/config", "/config/x.yml"):
        httpx.get(B + p, headers={"X-Client-Id": "esc"}, timeout=30)
    timed(B, "/", "esc")                                   # 에스컬레이션이 판정되는 요청
    r = enter_shell(B, "esc")
    check("에스컬레이션된 클라이언트도 셸 진입 성공", r.status_code == 200 and "uid=" in r.text, (r.status_code, r.text[:30]))
    r, dt = timed(B, "/api/Products", "esc")
    check(f"에스컬레이션(1.5s) > POST_RCE(0.3s): 진입 후에도 에스컬레이션만큼 지연 (+{dt - oh:.2f}s)", dt - oh >= 1.3, dt - oh)
    # 진입했지만 에스컬레이션은 안 된 클라이언트는 POST_RCE_DELAY_MS 만
    enter_shell(B, "plain")
    r, dt2 = timed(B, "/api/Products", "plain")
    check(f"에스컬레이션 안 된 클라이언트는 POST_RCE_DELAY(0.3s)만 (+{dt2 - oh:.2f}s)", 0.2 <= dt2 - oh < 0.9, dt2 - oh)
    check("두 클라이언트의 지연 차이가 에스컬레이션분(약 1.2s)에 가까움", dt - dt2 >= 0.9, dt - dt2)
    acts = [a for (a,) in sqlite3.connect(db).execute("SELECT defense_action FROM reqs WHERE client_id='esc' ORDER BY id")]
    check("진입 후 라벨은 post-rce-delay", "post-rce-delay" in acts, acts)
with rig("stub", POST_RCE_DELAY_MS="3000", **common) as (B, db):
    oh = overhead(B)
    for p in ("/backup/a", "/.git/config", "/config/x.yml"):
        httpx.get(B + p, headers={"X-Client-Id": "esc"}, timeout=30)
    timed(B, "/", "esc")
    enter_shell(B, "esc")
    r, dt = timed(B, "/api/Products", "esc")
    check(f"POST_RCE(3s) > 에스컬레이션(1.5s): 더 큰 값(3s) 적용 (+{dt - oh:.2f}s)", 2.7 <= dt - oh < 3.9, dt - oh)

print("\nFAILED:" if fails else "\nALL PASS", fails or "")
sys.exit(1 if fails else 0)
