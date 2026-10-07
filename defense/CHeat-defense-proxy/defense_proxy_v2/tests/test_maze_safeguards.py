"""미로 보완(1~3단계) 스모크 — 실제 프록시 프로세스 + 스텁 백엔드."""
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
_port = [3140]


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"   -> {detail}" if not cond else ""))
    if not cond:
        fails.append(name)


@contextlib.contextmanager
def rig(mode="404", robots="none", **env_extra):
    _port[0] += 2
    bport, pport = _port[0], _port[0] + 1
    db = os.path.join(tempfile.gettempdir(), f"mazefix_{pport}.db")
    if os.path.exists(db):
        os.remove(db)
    env = dict(os.environ)
    env.update({"REAL_BACKEND": f"http://127.0.0.1:{bport}", "DEFENSE_MODE": "off", "DECOY_MAZE": "1",
                "ADAPTIVE_TRAP": "1", "MAZE_DELAY_MS": "0", "MAZE_ESC_DELAY_MS": "0",
                "ESCALATE_DELAY_MS": "200", "DEFENSE_DB": db, "PYTHONUTF8": "1", "PREFLIGHT": "0"})
    env.update({k: str(v) for k, v in env_extra.items()})
    stub = subprocess.Popen([sys.executable, os.path.join(SCRATCH, "stub_srv.py"), str(bport), mode, robots],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proxy = subprocess.Popen([sys.executable, "-m", "uvicorn", "Defense_proxy:app", "--host", "127.0.0.1",
                              "--port", str(pport), "--log-level", "warning"], cwd=DEF_DIR, env=env,
                             stdout=open(os.path.join(tempfile.gettempdir(), f"proxy_{pport}.log"), "w"), stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{pport}"
    try:
        for _ in range(60):
            try:
                httpx.get(base + "/", timeout=1)
                break
            except Exception:
                time.sleep(0.25)
        yield base, db
    finally:
        proxy.terminate()
        stub.terminate()
        proxy.wait(timeout=10)
        stub.wait(timeout=10)


def esc(base, db, cid):
    """에스컬레이션은 '미끼를 문 다음 요청'의 on_request 에서 판정된다 — 확인 전에 요청 하나를 더 보낸다."""
    httpx.get(base + "/", headers={"X-Client-Id": cid}, timeout=15)
    rows = sqlite3.connect(db).execute(
        "SELECT 1 FROM reqs WHERE defense_action LIKE 'escalate:%' AND client_id=?", (cid,)).fetchall()
    return bool(rows)


def get(base, path, cid, **headers):
    h = {"X-Client-Id": cid}
    h.update(headers)
    return httpx.get(base + path, headers=h, timeout=15)


# ═══ 1단계: robots / 주석 ════════════════════════════════════════════════════════
print("== 1단계 ==")
with rig(mode="404", robots="none") as (B, db):
    r = get(B, "/robots.txt", "c1")
    check("robots 없음(404 백엔드): 200 + Disallow: / 없음", r.status_code == 200 and "Disallow: /\n" not in r.text
          and "Disallow: /internal/" in r.text, r.text)
    check("robots: User-agent: * 로 시작", r.text.startswith("User-agent: *"), r.text)
with rig(mode="spa", robots="html") as (B, db):
    r = get(B, "/robots.txt", "c1")
    check("robots 가 SPA HTML(폴백): Disallow: / 없음 + HTML 안 섞임", "Disallow: /\n" not in r.text
          and "<html" not in r.text.lower() and "Disallow: /internal/" in r.text, r.text)
with rig(mode="404", robots="real") as (B, db):
    r = get(B, "/robots.txt", "c1")
    check("진짜 robots 있으면 append", r.text.startswith("User-agent: *\nDisallow: /secret-real/\nDisallow: /internal/"), r.text)
    r = get(B, "/euckr", "c1")
    check("EUC-KR 페이지: 한글 보존 + 주석 주입", "안녕하세요".encode("euc-kr") in r.content
          and "한글".encode("euc-kr") in r.content and b"<!-- ops:" in r.content, r.content)
    r = get(B, "/", "c1")
    check("UTF-8 페이지: 주석 + Link 헤더", b"<!-- ops: internal tooling" in r.content
          and r.headers.get("link") == '</internal/ops/runbook>; rel="help"', (r.content, r.headers))

# ═══ 2단계: 오탐 ═════════════════════════════════════════════════════════════════
print("== 2단계 (4: distinct) ==")
with rig(mode="404") as (B, db):
    for _ in range(6):
        r = get(B, "/internal/ops/runbook", "refresh")
    check("같은 미끼 경로 새로고침 6번 → 에스컬레이션 없음", r.status_code == 200 and not esc(B, db, "refresh"))
    for q in ("/internal/ops/runbook?x=1", "/internal/ops/runbook/", "/INTERNAL/ops/runbook"):
        get(B, q, "refresh")
    check("쿼리/슬래시/대소문자만 다른 건 같은 경로", not esc(B, db, "refresh"))
    get(B, "/backup/a", "agent")
    get(B, "/.git/config", "agent")
    check("서로 다른 2개 → 아직 없음", not esc(B, db, "agent"))
    get(B, "/config/x.yml", "agent")
    check("서로 다른 3개 → 에스컬레이션", esc(B, db, "agent"))
    check("다른 클라이언트는 영향 없음", not esc(B, db, "refresh"))
with rig(mode="404", ADAPTIVE_COUNT="raw") as (B, db):
    for _ in range(3):
        get(B, "/internal/ops/runbook", "old")
    check("ADAPTIVE_COUNT=raw: 같은 경로 3번 → 에스컬레이션(예전 동작 재현)", esc(B, db, "old"))

print("== 2단계 (5: 실제 경로) ==")
with rig(mode="404") as (B, db):
    r = get(B, "/admin", "u1")
    check("진짜 /admin(200 비-셸): 그대로 통과", r.status_code == 200 and "REAL ADMIN" in r.text, r.text[:80])
    r = get(B, "/config", "u2")
    check("403 인 /config (처음): 미로로 바뀜(기본 MAZE_INTERCEPT_403=1)", r.status_code == 200 and "# /config" in r.text, r.text[:80])
    get(B, "/config", "u3", Authorization="Bearer x")        # 로그인 사용자는 200 → '진짜' 학습
    r = get(B, "/config", "u4")
    check("한 번 진짜 200 을 본 뒤엔 같은 경로의 403 도 미로로 안 바꿈", r.status_code == 403, (r.status_code, r.text[:60]))
with rig(mode="404", MAZE_EXCLUDE=r"^/private(/|$)") as (B, db):
    r = get(B, "/private/x", "u1")
    check("MAZE_EXCLUDE: /private/x 는 진짜 404 그대로", r.status_code == 404, r.status_code)
    r = get(B, "/internal/x", "u1")
    check("MAZE_EXCLUDE 밖: 미로", r.status_code == 200, r.status_code)
with rig(mode="404", MAZE_INTERCEPT_403="0") as (B, db):
    r = get(B, "/config", "u1")
    check("MAZE_INTERCEPT_403=0: 403 은 그대로", r.status_code == 403, r.status_code)

print("== 회귀: HEAD 가 진짜 경로 학습을 오염시키지 않는다 ==")
with rig(mode="spa") as (B, db):
    get(B, "/", "w")                                   # 셸 캐시
    httpx.head(B + "/backup/", headers={"X-Client-Id": "w"}, timeout=10)
    httpx.head(B + "/internal/", headers={"X-Client-Id": "w"}, timeout=10)
    r = get(B, "/backup/", "x")
    check("SPA: HEAD 직후 다른 클라이언트 GET /backup/ → 여전히 미로", "# /backup" in r.text[:30], r.text[:40])
    r = get(B, "/internal/", "w")
    check("SPA: HEAD 한 클라이언트 본인의 GET 도 미로", "# /internal" in r.text[:30], r.text[:40])
with rig(mode="spa") as (B, db):
    r = get(B, "/backup/", "first")                    # 셸 캐시 전 첫 요청 — 폴백을 진짜로 오인하면 안 됨
    r2 = get(B, "/backup/", "second")
    check("SPA: 셸을 아직 모를 때의 첫 GET 이 경로를 '진짜'로 오염시키지 않음", "# /backup" in r2.text[:30] or "# /backup" in r.text[:30],
          (r.text[:30], r2.text[:30]))

print("== 2단계 (6: 인증 요청 카운트) ==")
with rig(mode="404", DECOY_SKIP_AUTHED="1") as (B, db):
    for p in ("/backup/a", "/.git/config", "/config/x.yml", "/internal/y"):
        get(B, p, "authed", Authorization="Bearer abc")
    check("DECOY_SKIP_AUTHED=1: 인증 요청의 미끼 4개 → 에스컬레이션 없음", not esc(B, db, "authed"))
    for p in ("/backup/a", "/.git/config", "/config/x.yml"):
        get(B, p, "anon")
    check("DECOY_SKIP_AUTHED=1: 비인증은 그대로 걸림", esc(B, db, "anon"))
    for p in ("/backup/a", "/.git/config", "/config/x.yml"):
        get(B, p, "cookie", Cookie="language=en; token=abc.def")
    check("세션류 쿠키(token=)도 인증으로 취급", not esc(B, db, "cookie"))
    for p in ("/backup/a", "/.git/config", "/config/x.yml"):
        get(B, p, "cookie2", Cookie="language=en; welcomebanner_status=dismiss")
    check("무관한 쿠키는 인증 아님", esc(B, db, "cookie2"))
with rig(mode="404") as (B, db):
    for p in ("/backup/a", "/.git/config", "/config/x.yml"):
        get(B, p, "authed", Authorization="Bearer abc")
    check("기본(DECOY_SKIP_AUTHED=0): 인증 요청도 센다", esc(B, db, "authed"))

# ═══ 7: 플랜 게이팅 ══════════════════════════════════════════════════════════════
print("== 7: X-Defense-Plan maze ==")
with rig(mode="404", MAZE_REQUIRE_PLAN="1") as (B, db):
    r = get(B, "/", "low")
    check("REQUIRE_PLAN: 플랜 없음 → 주석·Link 없음", b"<!-- ops:" not in r.content and "link" not in r.headers, (r.content, dict(r.headers)))
    r = get(B, "/robots.txt", "low")
    check("REQUIRE_PLAN: 플랜 없음 → robots 미끼 없음", "internal" not in r.text, r.text)
    r = get(B, "/internal/x", "low")
    check("REQUIRE_PLAN: 플랜 없음 → 진짜 404", r.status_code == 404, r.status_code)
    for p in ("/backup/a", "/.git/config", "/config/x.yml"):
        get(B, p, "low")
    check("REQUIRE_PLAN: 플랜 없으면 에스컬레이션도 없음", not esc(B, db, "low"))
    plan = '[{"name":"maze"}]'
    r = get(B, "/", "high", **{"X-Defense-Plan": plan})
    check("REQUIRE_PLAN: 플랜 maze → 주석·Link 적용", b"<!-- ops:" in r.content and "link" in r.headers)
    r = get(B, "/internal/x", "high", **{"X-Defense-Plan": plan})
    check("REQUIRE_PLAN: 플랜 maze → 미로 서빙", r.status_code == 200 and "# /internal/x" in r.text, r.status_code)
    r = get(B, "/internal/x2", "high")
    check("sticky: 이후 플랜 없어도 미로 유지", r.status_code == 200 and "# /internal/x2" in r.text, r.status_code)
    r = get(B, "/", "high")
    check("sticky: 이후 요청에도 Link 유지", "link" in r.headers)
    rows = sqlite3.connect(db).execute("SELECT defense_plan FROM reqs WHERE client_id='high' AND defense_plan!=''").fetchall()
    check("defense_plan 컬럼에 maze 기록", any("maze" in x[0] for x in rows), rows)
    for p in ("/backup/a", "/.git/config"):
        get(B, p, "high", **{"X-Defense-Plan": plan})
    check("플랜 maze 클라이언트는 에스컬레이션 가능", esc(B, db, "high"))
with rig(mode="404") as (B, db):
    r = get(B, "/", "any", **{"X-Defense-Plan": '[{"name":"maze"}]'})
    r2 = get(B, "/internal/x", "noplan")
    check("기본(REQUIRE_PLAN=0): 플랜 없어도 미로(예전 동작)", r2.status_code == 200)

# ═══ 3단계: SPA / robots / 경로 설정 ═══════════════════════════════════════════
print("== 3단계 ==")
with rig(mode="spa") as (B, db):
    r = get(B, "/admin-panel-x", "bot")           # 미로 정규식에 안 맞는 클라이언트 라우트: 영향 없음
    check("SPA: 미로 정규식 밖 경로는 셸 그대로", "<title>x</title>" in r.text, r.text[:60])
    r = get(B, "/config", "bot")                  # curl 류(Sec-Fetch 없음) — 가로챔(403이라 /config 는 백엔드 403)
    r = get(B, "/debug", "bot")                   # SPA 폴백(200 셸) + 미로 패턴
    check("SPA: 에이전트(Sec-Fetch 없음) /debug → 미로", "# /debug" in r.text, r.text[:60])
    r = get(B, "/debug", "human", **{"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate"})
    check("SPA: 브라우저 주소창 접속 /debug → 셸 그대로(새로고침 안전)", "<title>x</title>" in r.text and "# /debug" not in r.text, r.text[:80])
    r = get(B, "/debug", "human2", **{"Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors"})
    check("SPA: fetch/XHR(Sec-Fetch-Dest: empty)은 통과 대상 아님", "# /debug" in r.text, r.text[:80])
with rig(mode="spa", MAZE_SPA_BROWSER_PASS="0") as (B, db):
    r = get(B, "/debug", "human", **{"Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate"})
    check("MAZE_SPA_BROWSER_PASS=0: 예전처럼 미로", "# /debug" in r.text, r.text[:60])
with rig(mode="spa", MAZE_EXCLUDE=r"^/debug(/|$)") as (B, db):
    r = get(B, "/debug", "bot")
    check("SPA + MAZE_EXCLUDE: 제외한 클라이언트 라우트는 셸", "<title>x</title>" in r.text, r.text[:60])

with rig(mode="404", MAZE_PATHS="/_ops/,/internal/") as (B, db):
    r = get(B, "/robots.txt", "c")
    check("MAZE_PATHS: robots 에 /_ops/ 광고", "Disallow: /_ops/" in r.text and "Disallow: /internal/" in r.text, r.text)
    r = get(B, "/_ops/anything", "c")
    check("MAZE_PATHS: /_ops/ 는 미로 판정에도 합쳐짐", r.status_code == 200 and "# /_ops/anything" in r.text, r.status_code)
    r = get(B, "/", "c")
    check("MAZE_PATHS: 기본 입구 문서 그대로", r.headers.get("link") == '</internal/ops/runbook>; rel="help"')

print("\nFAILED:" if fails else "\nALL PASS", fails or "")
sys.exit(1 if fails else 0)
