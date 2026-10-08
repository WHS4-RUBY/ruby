"""③ 묶음 전략 3개(decoy_maze / decoy_t21_shell / decoy_migration)를 X-Defense-Plan 으로 호출 — 실제 프록시(subprocess)."""
import contextlib
import json
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
_port = [5000]
P_MAZE = '[{"name":"decoy_maze","params":{}}]'
P_T21 = '[{"name":"decoy_t21_shell","params":{}}]'
P_MIG = '[{"name":"decoy_migration","params":{}}]'


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"   -> {detail}" if not cond else ""))
    if not cond:
        fails.append(name)


@contextlib.contextmanager
def rig(**env_extra):
    _port[0] += 2
    bport, pport = _port[0], _port[0] + 1
    db = os.path.join(tempfile.gettempdir(), f"be_{pport}.db")
    if os.path.exists(db):
        os.remove(db)
    stub = subprocess.Popen([sys.executable, os.path.join(SCRATCH, "stub_srv.py"), str(bport), "404", "none"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    env = dict(os.environ)
    env.update({"REAL_BACKEND": f"http://127.0.0.1:{bport}", "DEFENSE_MODE": "off", "DECOY_REQUIRE_PLAN": "1",
                "ESCALATE_DELAY_MS": "300", "MAZE_DELAY_MS": "0", "MAZE_ESC_DELAY_MS": "0", "POST_RCE_DELAY_MS": "0",
                "DEFENSE_DB": db, "PYTHONUTF8": "1", "PREFLIGHT": "0"})
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


def get(B, path, cid, plan=None):
    h = {"X-Client-Id": cid}
    if plan:
        h["X-Defense-Plan"] = plan
    return httpx.get(B + path, headers=h, timeout=30)


def post(B, path, cid, body, plan=None):
    h = {"X-Client-Id": cid}
    if plan:
        h["X-Defense-Plan"] = plan
    return httpx.post(B + path, content=body, headers=h, timeout=30)


def acts(db, cid):
    return [a for (a,) in sqlite3.connect(db).execute(
        "SELECT defense_action FROM reqs WHERE client_id=? AND method!='-' ORDER BY id", (cid,))]


TRAV = "/cgi-bin/.%2e/.%2e/.%2e/etc/passwd"
BAITS = ("/backup/a", "/internal/b", "/config/c")

with rig() as (B, db):
    print("== 플랜 없는 클라이언트 n ==")
    r = get(B, "/server-status", "n")
    check("/server-status 는 백엔드로(가짜 응답 아님)", "Apache" not in r.text and r.status_code != 200, (r.status_code, r.text[:30]))
    r = get(B, TRAV, "n")
    check("/cgi-bin/ traversal 미끼도 백엔드로", "root:x:0:0" not in r.text, r.text[:30])
    r = post(B, "/cgi-bin/x/bin/sh", "n", "id")
    check("RCE POST 도 가짜 셸 아님", "uid=" not in r.text, r.text[:30])
    check("/rest/internal 도 백엔드로", "legacy-admin-bridge" not in get(B, "/rest/internal", "n").text)

    print("== decoy_t21_shell (묶음 2) ==")
    r = get(B, "/server-status", "t", P_T21)
    check("가짜 /server-status 200 + Apache", r.status_code == 200 and "Apache" in r.text, (r.status_code, r.text[:40]))
    check("Server 헤더 Apache 배너", r.headers.get("server", "").startswith("Apache/2.4.49"), r.headers.get("server"))
    r = get(B, TRAV, "t")
    check("traversal 미끼 → 가짜 passwd", r.status_code == 200 and "root:x:0:0" in r.text, (r.status_code, r.text[:30]))
    r = get(B, "/cgi-bin/zzz", "t")
    check("/cgi-bin/ 접두어지만 키워드 없음 → 404(가짜 헤더)", r.status_code == 404 and r.headers.get("server", "").startswith("Apache"),
          (r.status_code, r.headers.get("server")))
    check("robots 에 /cgi-bin/ 힌트", "/cgi-bin/" in get(B, "/robots.txt", "t").text)
    r = post(B, "/cgi-bin/x/bin/sh", "t", "id")
    check("RCE POST → 가짜 셸(uid=...)", r.status_code == 200 and "uid=" in r.text, (r.status_code, r.text[:40]))
    r = post(B, "/cgi-bin/x/bin/sh", "t", "whoami")
    check("가짜 셸 이어짐", r.status_code == 200 and r.text.strip() != "", r.text[:30])
    check("MIGRATION 요소는 없음(/rest/internal → 백엔드)", "legacy-admin-bridge" not in get(B, "/rest/internal", "t").text)
    a = acts(db, "t")
    check("라벨에 transform-route·fake-shell", "transform-route" in a and "fake-shell" in a, a)
    n_rows = sqlite3.connect(db).execute(
        "SELECT COUNT(*) FROM reqs WHERE client_id='t' AND defense_plan LIKE '%decoy_t21_shell%'").fetchone()[0]
    check("defense_plan 에 decoy_t21_shell 기록", n_rows >= 1, n_rows)

    print("== decoy_migration (묶음 3) ==")
    r = get(B, "/rest/internal", "m", P_MIG)
    check("가짜 브리지 상태 200", r.status_code == 200 and "legacy-admin-bridge" in r.text, (r.status_code, r.text[:40]))
    check("토끼굴 401", get(B, "/rest/internal/users", "m").status_code == 401)
    FAKE = get(B, "/server-status", "t").text            # T2.1 의 가짜 상태 페이지 본문
    check("T2.1 요소는 없음(/server-status 가 가짜 상태 페이지가 아님)", get(B, "/server-status", "m").text != FAKE)
    r = post(B, "/cgi-bin/x/bin/sh", "m", "id")
    check("가짜 셸 없음(RCE POST → 백엔드)", "uid=" not in r.text, r.text[:30])
    r = httpx.post(B + "/rest/user/login", json={"email": "svc-migration@x", "password": "x"},
                   headers={"X-Client-Id": "m"}, timeout=30)
    check("로그인 미끼 423", r.status_code == 423, r.status_code)
    check("HTML 메모·robots 힌트", "/rest/internal/" in get(B, "/robots.txt", "m").text)

    print("== 레시피 충돌 / 승급 ==")
    r = get(B, "/rest/internal", "t", P_MIG)               # t 는 이미 T2.1 — MIGRATION 지정은 거부
    check("T2.1 클라이언트에 decoy_migration → 레시피는 T2.1 유지(브리지 없음)", "legacy-admin-bridge" not in r.text, r.text[:30])
    check("충돌 후에도 T2.1 라우트 유지", get(B, "/server-status", "t").status_code == 200)
    r1 = get(B, "/", "u", P_MAZE)                          # 미로만으로 시작
    srv1 = r1.headers.get("server")
    r = get(B, "/server-status", "u")
    check("미로만 단계에서는 가짜 라우트 없음(가짜 상태 페이지가 아님)", r.text != get(B, "/server-status", "t").text, r.text[:30])
    r2 = get(B, "/", "u", P_T21)                           # 같은 클라이언트가 묶음 2 로 승급
    check("승급 후 가짜 라우트 응답", get(B, "/server-status", "u").status_code == 200)
    check("승급 전후 Server 배너 동일", srv1 == r2.headers.get("server"), (srv1, r2.headers.get("server")))

    print("== 격리·sticky ==")
    check("n 은 여전히 가짜 라우트 없음", get(B, "/server-status", "n").status_code != 200)
    check("플랜 없이 와도 t 는 유지(sticky)", get(B, "/server-status", "t").status_code == 200)

    print("== 에스컬레이션이 라우트에도 적용(합산 없이 하나) ==")
    for p in BAITS:
        get(B, p, "e", P_T21)
    get(B, "/api/x", "e", P_T21)
    get(B, "/server-status", "f", P_T21)                  # 에스컬레이션 안 된 T2.1 클라이언트(기준)
    t1 = time.time(); get(B, "/server-status", "f"); dn = time.time() - t1
    t0 = time.time(); r = get(B, "/server-status", "e"); dt = time.time() - t0
    check(f"에스컬레이션 클라이언트의 라우트는 지연(+{dt - dn:.2f}s ≥ 0.2)", dt - dn >= 0.2 and r.status_code == 200, (dt, dn))
    t0 = time.time(); r = get(B, "/server-status", "e"); dt2 = time.time() - t0
    check(f"합산 아님: 두 번째도 같은 수준(차 {dt2 - dt:+.2f}s)", abs(dt2 - dt) < 0.25, (dt, dt2))

print("== AMBIG_TRAP 은 묶음과 별개(켜져 있으면 에스컬레이션 신호를 재사용) ==")
with rig(AMBIG_TRAP="1") as (B, db):
    for p in BAITS:
        get(B, p, "d", P_MAZE)
    get(B, "/api/x", "d", P_MAZE)
    check("decoy_maze 클라이언트는 에스컬레이션 후 AMBIG 차단(403)", get(B, "/api/y", "d").status_code == 403)
    check("플랜 없는 클라이언트는 차단 안 됨", get(B, "/api/y", "n").status_code != 403)
    for p in BAITS:
        get(B, p, "x")                                     # 플랜 없이 미끼 접촉 — 미로·카운트 없음
    get(B, "/api/x", "x")
    check("플랜 없이는 미끼를 물어도 AMBIG 신호 없음", get(B, "/api/y", "x").status_code != 403)

print("\nFAILED:" if fails else "\nALL PASS", fails or "")
sys.exit(1 if fails else 0)
