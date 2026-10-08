"""/icons/ 한정 경로 탈출 신호(traversal-probe) 검증 — 원시 소켓으로 `..` 를 정리하지 않고 그대로 보낸다."""
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
_port = [3500]


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"   -> {detail}" if not cond else ""))
    if not cond:
        fails.append(name)


@contextlib.contextmanager
def rig(expect_exit=False, **env_extra):
    _port[0] += 2
    bport, pport = _port[0], _port[0] + 1
    db = os.path.join(tempfile.gettempdir(), f"trav_{pport}.db")
    if os.path.exists(db):
        os.remove(db)
    env = dict(os.environ)
    env.update({"REAL_BACKEND": f"http://127.0.0.1:{bport}", "DEFENSE_MODE": "transform", "ACTIVE_TECHNIQUE": "T2.1",
                "ADAPTIVE_TRAP": "1", "ESCALATE_DELAY_MS": "200", "DEFENSE_DB": db, "PYTHONUTF8": "1",
                "PREFLIGHT": "0"})
    for k in list(env_extra):
        if env_extra[k] is None:
            env.pop(k, None)
            del env_extra[k]
    env.update({k: str(v) for k, v in env_extra.items()})
    stub = subprocess.Popen([sys.executable, os.path.join(SCRATCH, "stub_srv.py"), str(bport), "404", "none"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proxy = subprocess.Popen([sys.executable, "-m", "uvicorn", "Defense_proxy:app", "--host", "127.0.0.1",
                              "--port", str(pport), "--log-level", "warning"], cwd=DEF_DIR, env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
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


def raw_get(port, path, cid):
    s = socket.create_connection(("127.0.0.1", port), timeout=15)
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nX-Client-Id: {cid}\r\nConnection: close\r\n\r\n".encode())
    buf = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    s.close()
    head, _, body = buf.partition(b"\r\n\r\n")
    return int(head.split()[1]), body


def action_of(db, cid):
    rows = sqlite3.connect(db).execute(
        "SELECT defense_action FROM reqs WHERE client_id=? AND defense_action NOT LIKE 'escalate:%' ORDER BY id",
        (cid,)).fetchall()
    return [r[0] for r in rows]


def escalated(db, cid):
    return bool(sqlite3.connect(db).execute(
        "SELECT 1 FROM reqs WHERE defense_action LIKE 'escalate:%' AND client_id=?", (cid,)).fetchall())


PROBES = [
    "/icons/../../../../etc/passwd",
    "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "//icons/../x",
    "/icons/%252e%252e/%252e%252e/etc/hosts",
    "/icons/..%2f..%2f..%2fetc/hosts",
    "/icons/%2e%2e%5c%2e%2e%5cwindows/win.ini",
]
NOT_PROBES = [
    "/ftp/..%2f..%2fetc/passwd",          # Juice Shop 챌린지가 쓰는 /ftp 트래버설 — 신호가 아니다
    "/rest/../x", "/assets/../x", "/..%2f", "/ftp/../etc/passwd",
    "/icons/small/blank.gif", "/icons/a..b", "/a..b/c", "/ftp/file..md", "/icons",
]

print("== 기본(T2.1, apache-php 프로필: /icons/) ==")
with rig() as (port, db):
    for i, p in enumerate(PROBES):
        code, body = raw_get(port, p, f"p{i}")
        act = action_of(db, f"p{i}")
        check(f"신호: {p}", act == ["traversal-probe"] and code == 404 and b"not found" in body,
              (act, code, body[:30]))
    for i, p in enumerate(NOT_PROBES):
        raw_get(port, p, f"n{i}")
        act = action_of(db, f"n{i}")
        check(f"신호 아님: {p}", act == ["observe"], act)

    # 서로 다른 변형 3개 → 에스컬레이션 (확인 요청 1개 더)
    # 디코딩하면 같은 경로가 되는 변형(.%2e 와 ..)은 1개로 센다 — 실제로 서로 다른 대상 파일 3개를 쓴다
    for p in ("/icons/../../../../etc/passwd", "/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/hosts",
              "/icons/..%2f..%2f..%2fproc/self/environ"):
        raw_get(port, p, "agent")
    raw_get(port, "/", "agent")
    check("서로 다른 탈출 시도 3개 → 에스컬레이션", escalated(db, "agent"))
    # 같은 경로 반복 → 에스컬레이션 아님
    for _ in range(6):
        raw_get(port, "/icons/../../../../etc/passwd", "repeat")
    raw_get(port, "/", "repeat")
    check("같은 탈출 경로 6번 반복 → 에스컬레이션 아님", not escalated(db, "repeat"))
    # 에스컬레이션 뒤 라벨
    code, _ = raw_get(port, "/icons/../../z", "agent")
    check("에스컬레이션 뒤 탈출 시도 라벨", action_of(db, "agent")[-1] == "traversal-probe:escalated-delay",
          action_of(db, "agent")[-3:])
    # /ftp 챌린지만 푸는 에이전트는 신호 0 → 에스컬레이션 없음
    for p in ("/ftp/..%2f..%2fetc/passwd", "/ftp/../etc/passwd", "/ftp/a.md%2500.md", "/rest/../x"):
        raw_get(port, p, "solver")
    raw_get(port, "/", "solver")
    check("Juice Shop 챌린지식 /ftp 트래버설만 하는 클라이언트 → 에스컬레이션 없음", not escalated(db, "solver"))

print("== 끄기/설정 ==")
with rig(TRAVERSAL_PROBE_PATHS="") as (port, db):
    raw_get(port, "/icons/../../etc/passwd", "c")
    check("TRAVERSAL_PROBE_PATHS='' → 꺼짐", action_of(db, "c") == ["observe"], action_of(db, "c"))
with rig(DEFENSE_MODE="off") as (port, db):
    raw_get(port, "/icons/../../etc/passwd", "c")
    check("DEFENSE_MODE=off(베이스라인) → 꺼짐", action_of(db, "c") == ["observe"], action_of(db, "c"))
with rig(ACTIVE_TECHNIQUE="MIGRATION_TRACES") as (port, db):
    raw_get(port, "/icons/../../etc/passwd", "c")
    check("T2.1 아닌 레시피(MIGRATION_TRACES) → 기본 꺼짐", action_of(db, "c") == ["observe"], action_of(db, "c"))
with rig(TRAVERSAL_PROBE_PATHS="/manual/,/icons/") as (port, db):
    raw_get(port, "/manual/../x", "a"); raw_get(port, "/icons/../x", "b"); raw_get(port, "/other/../x", "c")
    check("env 로 접두어 추가: /manual/·/icons/ 신호, 그 외 아님",
          action_of(db, "a") == ["traversal-probe"] and action_of(db, "b") == ["traversal-probe"]
          and action_of(db, "c") == ["observe"], (action_of(db, "a"), action_of(db, "b"), action_of(db, "c")))
with rig(TRAVERSAL_PROBE_PATHS="/manual/", DEFENSE_MODE="transform", ACTIVE_TECHNIQUE="MIGRATION_TRACES") as (port, db):
    raw_get(port, "/manual/../x", "a"); raw_get(port, "/icons/../x", "b")
    check("env 명시 시 레시피와 무관하게 켜짐 + 기본 /icons/ 는 env 가 대체", action_of(db, "a") == ["traversal-probe"]
          and action_of(db, "b") == ["observe"], (action_of(db, "a"), action_of(db, "b")))
with rig(TARGET_PRESET="nginx-fastapi") as (port, db):
    raw_get(port, "/icons/../x", "a")
    check("nginx-fastapi 프리셋(probe_paths 비어 있음) → 꺼짐", action_of(db, "a") == ["observe"], action_of(db, "a"))
with rig(expect_exit=True, TRAVERSAL_PROBE_PATHS="icons") as (rc, out):
    check("잘못된 형식은 시작 거부", rc not in (0, None) and "TRAVERSAL_PROBE_PATHS" in out, (rc, out[-200:]))

print("\nFAILED:" if fails else "\nALL PASS", fails or "")
sys.exit(1 if fails else 0)
