#!/usr/bin/env python3
"""시작 시 정합성 검사 — 프로필이 "스스로 모순되는지", 그리고 "실제 백엔드와 모순되는지".

Batch 6 에서 codex 는 `Server: nginx` + `X-Powered-By: PHP` + Node 앱의 모순만으로 Cloak 전체를
디셉션으로 판정했다. 프로필을 덮어쓸 수 있게 만들면 이런 모순을 관리자가 실수로 만들기 쉬워지므로,
시작할 때 한 번 검사해서 **경고만** 찍는다(막지는 않는다 — 의도한 서사일 수 있다).
`PREFLIGHT_STRICT=1` 이면 프로필 자체의 WARN 이 있을 때 시작을 거부한다. `PREFLIGHT=0` 이면 끈다.

두 단계:
  1) check_profile()   — 네트워크 없이 프로필 필드끼리의 모순 (사용자↔passwd↔uid, 호스트명↔커널,
                         배너↔family, RCE 진입 정규식↔예시 경로 ...)
  2) probe_backend()/check_backend() — 실제 백엔드에 GET 몇 번 던져서 (a) 런타임 지문이 프로필과
                         충돌하는지, (b) 가짜 라우트가 실제 경로를 가리는지(정상 서비스 파손 위험)
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


@dataclass
class Finding:
    level: str   # "WARN" | "INFO"
    code: str
    msg: str

    def __str__(self) -> str:
        return f"[preflight] {self.level:<4} {self.code}: {self.msg}"


# family 태그 -> 배너/X-Powered-By/쿠키에서 그 태그라고 볼 수 있는 단서
_ALIASES = {
    "apache": ("apache",), "nginx": ("nginx",), "iis": ("microsoft-iis", "iis"),
    "php": ("php", "phpsessid"), "node": ("node", "express", "connect.sid"),
    "java": ("tomcat", "jetty", "java", "spring", "jsessionid"),
    "aspnet": ("asp.net", "aspnet", "asp.net_sessionid"),
    "python": ("python", "gunicorn", "uvicorn", "werkzeug", "django", "flask"),
}
_RUNTIMES = {"php", "node", "java", "aspnet", "python"}
_SERVERS = {"apache", "nginx", "iis"}


def _tags_in(text: str) -> set[str]:
    low = (text or "").lower()
    return {tag for tag, keys in _ALIASES.items() if any(k in low for k in keys)}


def check_profile(profile: dict, spoof_server: str = "") -> list[Finding]:
    out: list[Finding] = []
    sh, web, lure = profile["shell"], profile["web"], profile["lure"]
    user, uid, gid = sh["user"], sh["uid"], sh["gid"]

    # 1) 사용자 ↔ passwd ↔ uid/gid
    entry = next((ln.split(":") for ln in sh["passwd"] if ln.split(":")[0] == user), None)
    if entry is None:
        out.append(Finding("WARN", "shell-user-missing",
                           f"shell.user={user!r} 가 shell.passwd 에 없다 — `whoami` 와 `cat /etc/passwd` 가 모순"))
    elif len(entry) > 3 and (entry[2] != str(uid) or entry[3] != str(gid)):
        out.append(Finding("WARN", "shell-uid-mismatch",
                           f"shell.uid/gid={uid}/{gid} 인데 passwd 의 {user} 는 {entry[2]}/{entry[3]} — "
                           "`id` 와 `cat /etc/passwd` 가 모순"))
    # 2) 호스트명 ↔ 커널 문자열
    if sh["hostname"] not in sh["kernel"]:
        out.append(Finding("WARN", "hostname-kernel",
                           f"shell.hostname={sh['hostname']!r} 가 shell.kernel 문자열에 없다 — `hostname` 과 `uname -a` 가 모순"))

    # 3) 배너(+X-Powered-By) ↔ family
    evidence = _tags_in(f"{web['server_banner']} {web.get('x_powered_by') or ''}")
    fam = set(profile.get("family", []))
    for tag in sorted(fam):
        if tag not in evidence:
            # X-Powered-By 를 일부러 비운 프로필(nginx-fastapi 처럼 런타임을 헤더로 안 드러내는 스택)은 런타임 태그의
            # 단서가 배너에 없는 게 정상이라 INFO. 런타임 헤더를 내세웠는데(x_powered_by 있음) 안 맞으면 그대로 WARN.
            hidden_runtime = tag in _RUNTIMES and not web.get("x_powered_by")
            out.append(Finding("INFO" if hidden_runtime else "WARN", "banner-family",
                               f"family 에 {tag!r} 가 있는데 배너({web['server_banner']!r}"
                               f"{', ' + web['x_powered_by'] if web.get('x_powered_by') else ''})에 그 단서가 없다 — "
                               "셸·passwd 세계는 여전히 그 스택인 척한다"))
    for kind, group in (("런타임", _RUNTIMES), ("웹서버", _SERVERS)):
        stray = (evidence & group) - fam
        if stray:
            out.append(Finding("WARN", "banner-conflict",
                               f"배너가 {sorted(stray)} 를 말하는데 family={sorted(fam)} 는 다른 {kind} 계열 — 스택 이야기가 모순"))

    # 4) 미끼 경로/정규식 자체 검증
    try:
        if not re.search(lure["shell_entry_regex"], lure["shell_entry_example"], re.I):
            out.append(Finding("WARN", "shell-entry-example",
                               f"shell_entry_regex 가 자신의 예시 경로 {lure['shell_entry_example']!r} 에 안 맞는다 — "
                               "FAKE_SHELL 이 발동하지 않을 수 있다"))
    except re.error as e:
        out.append(Finding("WARN", "shell-entry-regex", f"shell_entry_regex 가 올바른 정규식이 아니다: {e}"))
    pre = lure["file_prefix"]
    if not (pre.startswith("/") and pre.endswith("/")):
        out.append(Finding("WARN", "file-prefix", f"file_prefix={pre!r} 는 '/' 로 시작하고 '/' 로 끝나야 라우트로 걸린다"))
    for d in lure["robots_disallow"]:
        if not d.startswith("/"):
            out.append(Finding("WARN", "robots-path", f"robots_disallow 항목 {d!r} 가 '/' 로 시작하지 않는다"))
    for d in lure.get("probe_paths", []):
        if not (d.startswith("/") and d.endswith("/")):
            out.append(Finding("WARN", "probe-path-format",
                               f"probe_paths 항목 {d!r} 는 '/' 로 시작하고 '/' 로 끝나야 한다(예: /icons/)"))

    # 5) 일부 응답만 다른 Server 헤더 (의도일 수 있어 INFO)
    banner_l = web["server_banner"].lower()
    if spoof_server and spoof_server.lower() not in banner_l:
        out.append(Finding("INFO", "server-header-split",
                           f"SPOOF_SERVER={spoof_server!r} 인데 T2.1 배너는 {web['server_banner']!r} — 미끼 응답과 그 외 응답의 "
                           "Server 헤더가 다르다. edge/internal 서사로 의도한 게 아니면 SPOOF_SERVER 를 맞춰라"))
    return out


_SPA_PROBE_PATH = "/zz-preflight-no-such-page-8f3a1c"


def probe_backend(base_url: str, profile: dict, timeout: float = 2.0,
                  maze_paths: "list | None" = None, probe_paths: "list | None" = None) -> dict:
    """백엔드에 GET 몇 번. 실패하면 {"ok": False}. 부수효과 없는 GET 만 쓴다.

    maze_paths 를 주면 DECOY_MAZE 점검용으로 (a) 존재하지 않을 경로가 200+index.html 로 응답하는지
    (SPA 폴백), (b) 미로 입구 경로들이 백엔드에 실제로 있는지, (c) 진짜 robots.txt 의 Disallow 를 추가로 본다.
    probe_paths 를 주면 경로 탈출 신호(traversal-probe)용 접두어가 백엔드에 실제로 있는지 본다."""
    import httpx

    res: dict = {"ok": False, "tags": set(), "shadow": [], "spa_fallback": False,
                 "maze_real": [], "robots_disallow": [], "probe_real": []}
    try:
        with httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout, follow_redirects=False) as c:
            r = c.get("/")
            res["ok"] = True
            clues = " ".join([r.headers.get("server", ""), r.headers.get("x-powered-by", ""),
                              " ".join(ck.split("=")[0] for ck in r.headers.get_list("set-cookie"))])
            res["tags"] = _tags_in(clues)
            res["raw_clues"] = clues.strip()
            root_hash = hashlib.md5(r.content).hexdigest()
            lure = profile["lure"]
            candidates = [("status_page", lure["status_page"]["path"]),
                          ("file_prefix", lure["file_prefix"].rstrip("/") + "/probe-" + "x"),
                          ("file_prefix_root", lure["file_prefix"])]
            for label, path in candidates:
                try:
                    rr = c.get(path)
                except httpx.HTTPError:
                    continue
                # SPA 는 모르는 경로에도 200 + index.html 을 준다 — 루트 본문과 같으면 "실제 경로"가 아니다
                if rr.status_code < 400 and hashlib.md5(rr.content).hexdigest() != root_hash:
                    res["shadow"].append((label, path, rr.status_code))

            for path in probe_paths or []:
                # SPA 폴백(루트와 같은 본문)이나 404 가 아니면 "실제로 있는" 경로 — '/icons/' 와 '/icons' 둘 다 본다
                for variant in dict.fromkeys([path, path.rstrip("/") or "/"]):
                    try:
                        pr = c.get(variant)
                    except httpx.HTTPError:
                        continue
                    is_shell = (pr.status_code == 200
                                and hashlib.md5(pr.content).hexdigest() == root_hash)
                    if pr.status_code != 404 and not is_shell:
                        res["probe_real"].append((path, pr.status_code))
                        break

            if maze_paths is not None:
                try:
                    sp = c.get(_SPA_PROBE_PATH)
                    res["spa_fallback"] = (sp.status_code == 200
                                           and hashlib.md5(sp.content).hexdigest() == root_hash)
                except httpx.HTTPError:
                    pass
                for path in maze_paths:
                    # '/admin/' 과 '/admin' 둘 다 — 서버마다 한쪽만 서빙/리다이렉트한다
                    for variant in dict.fromkeys([path, path.rstrip("/") or "/"]):
                        try:
                            mp = c.get(variant)
                        except httpx.HTTPError:
                            continue
                        is_shell = (mp.status_code == 200
                                    and hashlib.md5(mp.content).hexdigest() == root_hash)
                        if mp.status_code != 404 and not is_shell:
                            res["maze_real"].append((path, mp.status_code))
                            break
                try:
                    rb = c.get("/robots.txt")
                    if rb.status_code == 200:
                        import transforms
                        res["robots_disallow"] = transforms.parse_robots_disallow(rb.content)
                except httpx.HTTPError:
                    pass
    except Exception as e:  # noqa: BLE001 — 네트워크 실패는 검사 생략일 뿐
        res["error"] = str(e)
    return res


def check_probe_paths(probe: dict) -> list[Finding]:
    """경로 탈출 신호 접두어가 백엔드에 실제로 있는지 — 있어도 서비스는 안 깨진다(정상 요청에는 `..` 가 없고 응답도
    안 바꾼다). 그 경로를 `..` 와 함께 정상적으로 쓰는 클라이언트가 있다면 TRAVERSAL_PROBE_PATHS 에서 빼라."""
    out: list[Finding] = []
    for path, code in probe.get("probe_real", []):
        out.append(Finding("INFO", "probe-path-exists",
                           f"경로 탈출 신호 접두어 {path} 가 백엔드에 실제로 있다(HTTP {code}) — `..` 가 들어간 요청만 세므로 "
                           "정상 요청은 영향 없다. 이 경로를 `..` 와 함께 정상 사용하는 클라이언트가 있으면 "
                           "TRAVERSAL_PROBE_PATHS(프로필 lure.probe_paths)에서 빼라"))
    return out


def check_maze_config(maze_paths: list, entry_path: str, maze_re, exclude_re=None) -> list[Finding]:
    """DECOY_MAZE 설정끼리의 모순(네트워크 없음) — 광고한 경로·입구 문서가 실제로 미로로 판정되는가."""
    out: list[Finding] = []
    for p in maze_paths:
        if not p.startswith("/"):
            out.append(Finding("WARN", "maze-path-format", f"maze 경로 {p!r} 가 '/' 로 시작하지 않는다"))
            continue
        pp = p.rstrip("/") or "/"
        if not maze_re.match(pp):
            out.append(Finding("WARN", "maze-path-not-maze",
                               f"robots 로 광고하는 {p!r} 가 미로 판정 정규식(MAZE_PATTERN)에 안 맞는다 — "
                               "에이전트가 따라가도 평범한 404 를 받는다. MAZE_PATTERN 을 지우면 자동으로 맞춰진다"))
        elif exclude_re and exclude_re.search(pp):
            out.append(Finding("WARN", "maze-path-excluded",
                               f"광고하는 {p!r} 가 MAZE_EXCLUDE 에 걸려 미로가 안 된다 — 입구를 광고하면서 막은 모순"))
    ep = entry_path.rstrip("/") or "/"
    if not entry_path.startswith("/") or not maze_re.match(ep):
        out.append(Finding("WARN", "maze-entry-not-maze",
                           f"입구 문서 {entry_path!r} 가 미로 판정에 안 맞는다 — Link 헤더·HTML 주석이 가리키는 곳이 "
                           "평범한 404 가 된다. maze.entry_path 를 maze.paths 아래 경로로 둬라"))
    elif exclude_re and exclude_re.search(ep):
        out.append(Finding("WARN", "maze-entry-excluded",
                           f"입구 문서 {entry_path!r} 가 MAZE_EXCLUDE 에 걸린다 — 미끼 입구가 막혀 있다"))
    return out


def check_maze_backend(probe: dict, maze_paths: list) -> list[Finding]:
    """DECOY_MAZE 를 실제 백엔드와 대조 — 실제 경로와의 충돌, SPA 폴백, 진짜 robots.txt 와의 겹침."""
    out: list[Finding] = []
    if not probe.get("ok"):
        return out
    for path, code in probe.get("maze_real", []):
        if code == 403:
            out.append(Finding("WARN", "maze-path-forbidden",
                               f"광고 경로 {path} 에 백엔드가 403 을 준다 — 진짜 보호된 경로일 수 있다. 가짜 입구로 광고하는 "
                               "경로를 바꾸거나, 진짜 경로라면 MAZE_INTERCEPT_403=0 (403 은 미로로 안 바꿈)을 써라"))
        else:
            out.append(Finding("WARN", "maze-path-real",
                               f"광고 경로 {path} 가 백엔드에 실제로 있다(HTTP {code}) — robots 로 진짜 경로를 광고하는 꼴. "
                               "maze.paths(MAZE_PATHS)에서 빼라. (런타임엔 진짜로 서빙된 경로는 자동 제외되므로 서비스는 안 깨진다)"))
    if probe.get("spa_fallback"):
        shown = ", ".join(maze_paths[:6])
        out.append(Finding("WARN", "spa-fallback",
                           "백엔드가 없는 경로에도 200+index.html 을 준다(SPA 폴백) — 미로는 그 응답을 가로챈다. 입구 경로"
                           f"({shown})나 /admin·/config 같은 이름이 SPA 의 실제 클라이언트 라우트라면(history 라우팅) 새로고침이 "
                           "미로로 바뀐다. 기본으로 켜진 MAZE_SPA_BROWSER_PASS=1 이 브라우저 주소창 접속은 통과시키지만, 겹치는 "
                           "라우트가 있으면 MAZE_EXCLUDE='^/(admin|config)(/|$)' 처럼 제외해라. 해시(#/) 라우팅이면 해당 없음"))
    real_dis = probe.get("robots_disallow", [])
    if real_dis:
        mp = [p.rstrip("/").lower() for p in maze_paths]
        clash = []
        for d in real_dis:
            dd = d.rstrip("/").lower()
            if dd and any(m == dd or m.startswith(dd + "/") or dd.startswith(m + "/") for m in mp):
                clash.append(d)
        if clash:
            out.append(Finding("WARN", "robots-overlap-real",
                               f"진짜 robots.txt 가 이미 {clash} 를 Disallow 한다 — 진짜 비공개 경로와 미로 입구가 겹친다. "
                               "그 경로가 실제로 있으면 MAZE_EXCLUDE 로 빼고 다른 입구 이름을 써라 "
                               "(없는 경로면 이미 광고 중인 줄을 중복 추가하지는 않는다)"))
    return out


def check_backend(profile: dict, probe: dict) -> list[Finding]:
    out: list[Finding] = []
    if not probe.get("ok"):
        out.append(Finding("INFO", "backend-unreachable",
                           f"백엔드 지문 검사 생략 ({probe.get('error', '연결 실패')[:80]})"))
        return out
    fam = set(profile.get("family", []))
    seen = probe["tags"]
    for kind, group in (("런타임", _RUNTIMES), ("웹서버", _SERVERS)):
        stray = (seen & group) - fam
        fam_g = fam & group
        if stray and fam_g and kind == "런타임":
            out.append(Finding("WARN", "backend-runtime-conflict",
                               f"백엔드 응답이 {sorted(stray)} 를 드러내는데({probe.get('raw_clues')!r}) 프로필 family={sorted(fam)} — "
                               "쿠키·헤더가 새면 에이전트가 스택 모순을 눈치챈다"))
        elif stray and fam_g and kind == "웹서버":
            out.append(Finding("INFO", "backend-server-differs",
                               f"백엔드 Server 단서 {sorted(stray)} ≠ 프로필 {sorted(fam_g)} — "
                               "edge/internal 서사(프록시 뒤 서버가 다르다)면 정상"))
    for label, path, code in probe.get("shadow", []):
        out.append(Finding("WARN", "lure-shadows-real-path",
                           f"{label}({path}) 가 백엔드에 실제로 존재한다(HTTP {code}) — 가짜 라우트가 정상 서비스를 가린다. "
                           "프로필의 경로를 실제 앱에 없는 것으로 바꿔라"))
    if not out:
        out.append(Finding("INFO", "backend-ok", f"백엔드 지문 검사 통과 (단서: {probe.get('raw_clues') or '없음'})"))
    return out


def report(findings: list[Finding]) -> int:
    """콘솔 출력, WARN 개수 반환."""
    for f in findings:
        print(str(f), flush=True)
    return sum(1 for f in findings if f.level == "WARN")
