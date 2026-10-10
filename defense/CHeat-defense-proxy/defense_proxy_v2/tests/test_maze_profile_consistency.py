"""미로 본문이 서버 종류와 무관하고 영어이며 프로필과 어긋나지 않는지 — Apache 전용 줄이 없는지, 클라이언트에게 보이는 한글이 없는지,
소유자명이 가짜 셸 세계와 같은지, 최상위 경로에서 `//` 가 안 생기는지, 서버 전용 입구 이름이 그 서버 프리셋에만 있는지."""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import profiles
import transforms as T

fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  -> {detail}" if not cond else ""))
    if not cond:
        fails.append(name)


HANGUL = re.compile(r"[ㄱ-ㆎ가-힣]")
PATHS = ("/server-status", "/phpinfo", "/id_rsa", "/x.yml", "/internal/ops/", "/a/b/c.sql", "/internal/endpoints", "/.git/config")
PROFILE_SETS = ({"version", "bridge", "inventory", "ssh", "docs"}, {"version", "bridge"}, {"ssh", "bridge"}, {"bridge"}, set())
try:
    for preset in ("apache-php", "nginx-fastapi"):
        prof = profiles.build_profile(preset)
        T.configure(prof)
        banner = prof["web"]["server_banner"]
        owner = prof["shell"]["user"]
        bodies = [T.maze_response(p, n, 1, ps, 5, version=banner).decode() for p in PATHS for ps in PROFILE_SETS for n in (1, 5)]
        text = "\n".join(bodies)
        check(f"{preset}: 응답 본문에 한글이 없다(영어)", not HANGUL.search(text), HANGUL.search(text) and text[HANGUL.search(text).start() - 40:HANGUL.search(text).start() + 40])
        check(f"{preset}: Apache 전용 줄(MPM·빌드 날짜)이 없다", "MPM" not in text and "Aug 11 2021" not in text, "")
        info = T.maze_response("/server-status", 1, 1, {"version", "bridge"}, 5, version=banner).decode()
        check(f"{preset}: 서버 정보 줄에 프로필 배너가 나온다", f"server_version: {banner}" in info and f"httpServer: {banner}" in info, info)
        bad = [ln for b in bodies for ln in b.splitlines() if re.search(r"(?<![:/])//[a-z]", ln)]
        check(f"{preset}: '//' 로 겹친 경로가 없다", not bad, bad[:2])
        listing = T.maze_response("/internal/ops/", 1, 1, {"bridge"}, 5).decode()
        check(f"{preset}: 디렉터리 목록 소유자 = 가짜 셸 사용자({owner})", f"{owner} {owner}" in listing and "deploy deploy" not in listing, listing[:260])

        # 점(.)으로 시작하는 입구는 광고하지 않는다 — main 의 탐지 CRS(enforce)가 방어에 닿기 전에 403 으로 막는다(/.git/*, /.env, /.ssh/*)
        dot = [x for x in prof["maze"]["paths"] if x.startswith("/.")]
        check(f"{preset}: robots 로 광고하는 입구에 점(.) 시작 경로가 없다(CRS 선차단 회피)", not dot, dot)
        rx = re.compile(T.build_maze_pattern(prof["maze"]["paths"], prof["maze"]["extra_pattern"]), re.I)
        generic = ("/internal/x", "/.git/config", "/backup/x", "/config/", "/private/y", "/db.sql.bak")
        check(f"{preset}: 서버 무관 입구는 항상 미로 대상", all(rx.match(p) for p in generic), [p for p in generic if not rx.match(p)])
        server_only = ("/server-status", "/server-info", "/phpinfo", "/.htpasswd", "/actuator/health")
        if preset == "apache-php":
            check(f"{preset}: Apache/PHP/Spring 전용 입구 유지(기존 동작)", all(rx.match(p) for p in server_only), [p for p in server_only if not rx.match(p)])
        else:
            check(f"{preset}: 그 서버에 없는 전용 입구는 미로로 만들지 않는다", not any(rx.match(p) for p in server_only), [p for p in server_only if rx.match(p)])

    # 기본 패턴 자체는 서버 전용 이름을 갖지 않는다
    check("기본 미로 패턴에 서버 전용 이름이 없다", not any(t in T.MAZE_DEFAULT_PATTERN for t in
          ("server-status", "server-info", "phpinfo", "htpasswd", "actuator")), T.MAZE_DEFAULT_PATTERN)
finally:
    T.configure()   # 기본 프로필로 되돌린다

print()
print("FAILED: " + ", ".join(fails) if fails else "ALL PASS")
sys.exit(1 if fails else 0)
