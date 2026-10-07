"""묶음 1(decoy_maze 전략, DECOY_REQUIRE_PLAN=1): 플랜이 실린 클라이언트에게만 미로 + 적응형이 적용되는지."""
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
_port = [4800]
PLAN_DECOY = '[{"name":"decoy_maze","params":{}}]'
PLAN_MAZE = '[{"name":"maze","params":{}}]'


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"   -> {detail}" if not cond else ""))
    if not cond:
        fails.append(name)


@contextlib.contextmanager
def rig(**env_extra):
    _port[0] += 2
    bport, pport = _port[0], _port[0] + 1
    db = os.path.join(tempfile.gettempdir(), f"dp_{pport}.db")
    if os.path.exists(db):
        os.remove(db)
    stub = subprocess.Popen([sys.executable, os.path.join(SCRATCH, "stub_srv.py"), str(bport), "404", "none"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    env = dict(os.environ)
    env.update({"REAL_BACKEND": f"http://127.0.0.1:{bport}", "DEFENSE_MODE": "off", "ESCALATE_DELAY_MS": "1500",
                "MAZE_DELAY_MS": "300", "MAZE_ESC_DELAY_MS": "600", "DEFENSE_DB": db, "PYTHONUTF8": "1",
                "PREFLIGHT": "0"})
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
    t = time.time()
    r = httpx.get(B + path, headers=h, timeout=60)
    return r, time.time() - t


def is_maze(r):
    return r.text.startswith("# /")


def acts(db, cid):
    return [a for (a,) in sqlite3.connect(db).execute(
        "SELECT defense_action FROM reqs WHERE client_id=? AND method!='-' ORDER BY id", (cid,))]


BAITS = ("/backup/a", "/internal/b", "/config/c")

print("== DECOY_REQUIRE_PLAN=1 ==")
with rig(DECOY_REQUIRE_PLAN="1") as (B, db):
    get(B, "/", "warm")
    oh = min(get(B, "/api/x", f"b{i}")[1] for i in range(3))
    print(f"  (기본 지연 {oh:.2f}s)")

    # 플랜 없는 클라이언트 — 아무 변화 없음
    for p in BAITS:
        r, _ = get(B, p, "n")
    check("플랜 없음: 미끼 경로가 미로로 안 바뀜(백엔드 404 그대로)", r.status_code == 404 and not is_maze(r), (r.status_code, r.text[:20]))
    r, _ = get(B, "/", "n")
    check("플랜 없음: Link 헤더·HTML 주석 없음", "link" not in r.headers and "ops:" not in r.text, dict(r.headers))
    r, dt = get(B, "/api/x", "n")
    check(f"플랜 없음: 미끼 3개 접촉해도 에스컬레이션 없음 (+{dt - oh:.2f}s)", dt - oh < 0.8, dt - oh)
    check("플랜 없음: 라벨 observe", set(acts(db, "n")) == {"observe"}, acts(db, "n"))

    # maze 전략(미로만) — 미로는 켜지지만 적응형은 아님
    for p in BAITS:
        r, _ = get(B, p, "m", PLAN_MAZE)
    check("maze 전략: 미끼 경로가 미로", is_maze(r), (r.status_code, r.text[:20]))
    r, dt = get(B, "/api/x", "m", PLAN_MAZE)
    check(f"maze 전략: 적응형은 꺼져 있음 — 에스컬레이션 없음 (+{dt - oh:.2f}s)", dt - oh < 0.8, dt - oh)

    # decoy_maze 전략 — 미로 + 적응형
    for p in BAITS:
        r, _ = get(B, p, "d", PLAN_DECOY)
    check("decoy_maze: 미끼 경로가 미로", is_maze(r), (r.status_code, r.text[:20]))
    get(B, "/api/x", "d", PLAN_DECOY)                     # 판정이 걸리는 요청
    r, dt = get(B, "/api/Products", "d", PLAN_DECOY)
    check(f"decoy_maze: 미끼 3개 후 에스컬레이션 — 일반 경로 지연 (+{dt - oh:.2f}s)", dt - oh >= 1.2, dt - oh)
    r, dt2 = get(B, "/backup/zzz", "d", PLAN_DECOY)
    check(f"decoy_maze: 에스컬레이션 후 미로 접촉도 큰 값 하나만(합산 아님) (차 {dt2 - dt:+.2f}s)", abs(dt2 - dt) < 0.8, dt2 - dt)
    r, dt = get(B, "/api/Products", "d")                  # 플랜 헤더가 없어도 유지(sticky)
    check(f"sticky: 플랜 없이 와도 에스컬레이션·미로 유지 (+{dt - oh:.2f}s)", dt - oh >= 1.2, dt - oh)
    r, _ = get(B, "/backup/zzz2", "d")
    check("sticky: 플랜 없이 와도 미로 유지", is_maze(r), (r.status_code, r.text[:20]))
    n_plan = sqlite3.connect(db).execute(
        "SELECT COUNT(*) FROM reqs WHERE client_id='d' AND defense_plan LIKE '%decoy_maze%'").fetchone()[0]
    check("defense_plan 컬럼에 decoy_maze 기록(플랜이 실린 요청 중 일부 행)", n_plan >= 1, n_plan)
    check("에스컬레이션 메타 행이 d 에만 기록", sqlite3.connect(db).execute(
        "SELECT COUNT(*) FROM reqs WHERE defense_action LIKE 'escalate:%' AND client_id='d'").fetchone()[0] == 1)

    # 격리 — d 가 에스컬레이션돼도 n 은 영향 없음
    r, dt = get(B, "/api/Products", "n")
    check(f"격리: 플랜 없는 n 은 여전히 빠름 (+{dt - oh:.2f}s)", dt - oh < 0.8, dt - oh)

    # 카운터는 플랜이 켜진 뒤부터 센다
    for p in BAITS:
        get(B, p, "e")                                    # 플랜 없이 미끼 3개 — 센 게 아님
    r, dt = get(B, "/api/x", "e", PLAN_DECOY)             # 이제 플랜이 켜짐
    check(f"카운터: 플랜 이전 접촉은 안 셈 — 켜지는 순간 즉시 에스컬레이션 안 됨 (+{dt - oh:.2f}s)", dt - oh < 0.8, dt - oh)
    r, dt = get(B, "/api/y", "e")
    check(f"카운터: 그 뒤 일반 요청도 아직 빠름 (+{dt - oh:.2f}s)", dt - oh < 0.8, dt - oh)

print("== DECOY_REQUIRE_PLAN 없이(기존 방식) — 환경변수대로 모든 클라이언트 ==")
with rig(DECOY_MAZE="1", ADAPTIVE_TRAP="1") as (B, db):
    get(B, "/", "warm")
    oh = min(get(B, "/api/x", f"b{i}")[1] for i in range(3))
    for p in BAITS:
        r, _ = get(B, p, "z")
    check("기존: 플랜 없이도 미로 적용", is_maze(r), (r.status_code, r.text[:20]))
    get(B, "/api/x", "z")
    r, dt = get(B, "/api/Products", "z")
    check(f"기존: 플랜 없이도 에스컬레이션 (+{dt - oh:.2f}s)", dt - oh >= 1.2, dt - oh)

print("\nFAILED:" if fails else "\nALL PASS", fails or "")
sys.exit(1 if fails else 0)
