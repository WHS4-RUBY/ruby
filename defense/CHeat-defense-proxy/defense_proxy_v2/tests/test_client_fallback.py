"""CLIENT_ID_FALLBACK=ip|global — 출발지 IP 가 요청마다 바뀌어도 상태가 이어지는지, 헤더는 항상 우선인지."""
import contextlib
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

import httpx

DEF_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRATCH = os.path.dirname(os.path.abspath(__file__))
fails = []
_port = [3800]
BAITS = ("/backup/a", "/.git/config", "/config/x.yml")


def supports_loopback_aliases():
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.2", 0))
        return True
    except OSError:
        return False
    finally:
        sock.close()


MULTI_LOOPBACK = supports_loopback_aliases()


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"   -> {detail}" if not cond else ""))
    if not cond:
        fails.append(name)


@contextlib.contextmanager
def rig(expect_exit=False, **env_extra):
    _port[0] += 2
    bport, pport = _port[0], _port[0] + 1
    db = os.path.join(tempfile.gettempdir(), f"cfb_{pport}.db")
    if os.path.exists(db):
        os.remove(db)
    env = dict(os.environ)
    env.update({"REAL_BACKEND": f"http://127.0.0.1:{bport}", "DEFENSE_MODE": "off", "DECOY_MAZE": "1",
                "ADAPTIVE_TRAP": "1", "AMBIG_TRAP": "1", "MAZE_DELAY_MS": "0", "MAZE_ESC_DELAY_MS": "0",
                "ESCALATE_DELAY_MS": "100", "DEFENSE_DB": db, "PYTHONUTF8": "1", "PREFLIGHT": "0"})
    env.update({k: str(v) for k, v in env_extra.items()})
    stub = subprocess.Popen([sys.executable, os.path.join(SCRATCH, "stub_srv.py"), str(bport), "404", "none"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proxy = subprocess.Popen([sys.executable, "-u", "-m", "uvicorn", "Defense_proxy:app", "--host", "0.0.0.0",
                              "--port", str(pport), "--no-server-header", "--log-level", "warning"],
                             cwd=DEF_DIR, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        if expect_exit:
            try:
                out, _ = proxy.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                out = b""
            yield proxy.returncode, out.decode("utf-8", "ignore")
            return
        for _ in range(60):
            try:
                httpx.get(f"http://127.0.0.1:{pport}/", timeout=1)
                break
            except Exception:
                time.sleep(0.25)
        yield pport, db
    finally:
        proxy.terminate(); stub.terminate()
        try:
            proxy.wait(timeout=10)
        except Exception:
            pass
        stub.wait(timeout=10)


def get(port, path, src_ip, **headers):
    """src_ip 에서 나가는 요청 — 출발지 IP 가 요청마다 바뀌는 환경을 흉내낸다."""
    # macOS only binds 127.0.0.1 by default; Linux commonly binds 127/8.
    t = httpx.HTTPTransport(local_address=src_ip if MULTI_LOOPBACK else "127.0.0.1")
    with httpx.Client(transport=t, timeout=20) as c:
        return c.get(f"http://127.0.0.1:{port}{path}", headers=headers)


def clients(db):
    return {r[0] for r in sqlite3.connect(db).execute("SELECT DISTINCT client_id FROM reqs")}


def rows(db, cid):
    return [r[0] for r in sqlite3.connect(db).execute(
        "SELECT defense_action FROM reqs WHERE client_id=? ORDER BY id", (cid,))]


print("== 기본(ip): 출발지 IP 마다 별개 클라이언트 ==")
if MULTI_LOOPBACK:
    with rig() as (port, db):
        for ip, p in zip(("127.0.0.1", "127.0.0.2", "127.0.0.3"), BAITS):
            get(port, p, ip)
        for ip in ("127.0.0.1", "127.0.0.2", "127.0.0.3"):
            check(f"기본: {ip} 의 상태는 각자 분리(미끼 1개씩이라 차단 없음)", get(port, "/", ip).status_code == 200)
        check("기본: client_id 가 IP 별로 갈라짐", {"ip:127.0.0.1", "ip:127.0.0.2", "ip:127.0.0.3"} <= clients(db), clients(db))
else:
    # Test the resolver with explicit ASGI peer addresses when the OS cannot
    # originate TCP traffic from loopback aliases. Other cases still run via
    # 127.0.0.1 below; only the multi-IP network integration is unavailable.
    from fastapi import Request
    sys.path.insert(0, DEF_DIR)
    os.environ["DEFENSE_DB"] = os.path.join(tempfile.gettempdir(), "cfb_resolver.db")
    os.environ["DEFENSE_MODE"] = "off"
    os.environ["CLIENT_ID_FALLBACK"] = "ip"
    from Defense_proxy import _resolve_client_id
    identities = [_resolve_client_id(Request({"type": "http", "headers": [], "client": (ip, 1234)}))
                  for ip in ("127.0.0.1", "127.0.0.2", "127.0.0.3")]
    check("기본: ASGI 출발지 IP 별로 식별자 분리", identities == [
        "ip:127.0.0.1", "ip:127.0.0.2", "ip:127.0.0.3"], identities)
    print("SKIP multi-IP TCP integration: this OS cannot bind 127.0.0.2")

print("== global: 헤더 없는 요청을 한 클라이언트로 묶음 ==")
with rig(CLIENT_ID_FALLBACK="global") as (port, db):
    for ip, p in zip(("127.0.0.1", "127.0.0.2", "127.0.0.3"), BAITS):
        get(port, p, ip)                       # 서로 다른 IP 에서 서로 다른 미끼 3개
    r = get(port, "/", "127.0.0.4")            # 에스컬레이션·차단이 판정되는 요청(네 번째 IP)
    check("global: 판정 요청은 정상 응답", r.status_code == 200, r.status_code)
    r = get(port, "/", "127.0.0.5")            # 또 다른 새 IP — 이미 차단 상태여야 한다
    label = ("global: 새 IP(127.0.0.5)에서도 차단 유지" if MULTI_LOOPBACK
             else "global: 같은 loopback에서도 차단 유지")
    check(label, r.status_code == 403, r.status_code)
    check("global: DB 의 client_id 는 'global' 하나", clients(db) == {"global"}, clients(db))
    check("global: 에스컬레이션 기록 있음", any(a.startswith("escalate:") for a in rows(db, "global")), rows(db, "global"))

print("== global 이어도 헤더가 있으면 항상 헤더 우선 (탐지팀 연동과 공존) ==")
with rig(CLIENT_ID_FALLBACK="global") as (port, db):
    for ip, p in zip(("127.0.0.1", "127.0.0.2", "127.0.0.3"), BAITS):
        get(port, p, ip)
    get(port, "/", "127.0.0.4"); get(port, "/", "127.0.0.5")       # global 은 차단 확정
    r = get(port, "/", "127.0.0.6", **{"X-Client-Id": "detection-A"})
    check("헤더 있는 클라이언트(detection-A)는 global 의 차단과 무관하게 정상", r.status_code == 200, r.status_code)
    check("헤더 있는 요청은 헤더 값으로 기록", "detection-A" in clients(db), clients(db))
    for ip, p in zip(("127.0.0.1", "127.0.0.2", "127.0.0.3"), BAITS):
        get(port, p, ip, **{"X-Client-Id": "detection-B"})
    get(port, "/", "127.0.0.4", **{"X-Client-Id": "detection-B"})
    r = get(port, "/", "127.0.0.5", **{"X-Client-Id": "detection-B"})
    check("헤더 값별로 따로 차단 판정(detection-B 차단, detection-A 는 계속 정상)",
          r.status_code == 403 and get(port, "/", "127.0.0.7", **{"X-Client-Id": "detection-A"}).status_code == 200)
    r = get(port, "/", "127.0.0.8", **{"X-Client-Id": "selftest"})
    check("확인용 요청에 별도 헤더를 붙이면 global 과 섞이지 않음", r.status_code == 200, r.status_code)

print("== 설정 검증 ==")
with rig(expect_exit=True, CLIENT_ID_FALLBACK="bogus") as (rc, out):
    check("잘못된 값은 시작 거부", rc not in (0, None) and "CLIENT_ID_FALLBACK" in out, (rc, out[-150:]))
with rig(CLIENT_ID_FALLBACK="GLOBAL") as (port, db):
    get(port, "/", "127.0.0.2")
    check("대소문자 무관(GLOBAL)", "global" in clients(db), clients(db))

print("\nFAILED:" if fails else "\nALL PASS", fails or "")
sys.exit(1 if fails else 0)
