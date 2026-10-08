"""1단계 단위 테스트 — synth_robots / inject_html_comment / build_maze_pattern."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import transforms as T

fails = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  {detail}" if not cond else ""))
    if not cond:
        fails.append(name)


D = ["/internal/", "/backup/"]

# ── 1. synth_robots: 절대 Disallow: / 를 만들지 않는다 ─────────────────────────
for label, existing in [("없음(빈 바이트)", b""), ("SPA HTML", b"<!doctype html><html><head></head><body>app</body></html>"),
                        ("HTML 대문자", b"<HTML><HEAD></HEAD></HTML>")]:
    out = T.synth_robots(existing, D)
    lines = out.decode().splitlines()
    check(f"robots/{label}: Disallow: / 없음", "Disallow: /" not in lines, out)
    check(f"robots/{label}: 미끼 줄 있음", "Disallow: /internal/" in lines and lines[0] == "User-agent: *", out)
    check(f"robots/{label}: HTML 안 섞임", b"<" not in out, out)

# 기존 robots 가 * 그룹 → 그대로 append (예전 동작과 동일)
ex = b"User-agent: *\nDisallow: /ftp\n"
out = T.synth_robots(ex, D)
check("robots/기존 * 그룹: 예전과 같은 결과", out == b"User-agent: *\nDisallow: /ftp\nDisallow: /internal/\nDisallow: /backup/\n", out)

# 마지막 그룹이 다른 봇 → * 그룹을 새로 연다
ex = b"User-agent: *\nDisallow: /ftp\n\nUser-agent: GPTBot\nDisallow: /\n"
out = T.synth_robots(ex, D).decode()
check("robots/마지막 그룹이 GPTBot: 새 * 그룹", "User-agent: GPTBot\nDisallow: /\n\nUser-agent: *\nDisallow: /internal/" in out, out)

# 대소문자/Sitemap 만 있는 경우
ex = b"Sitemap: https://x/sitemap.xml\n"
out = T.synth_robots(ex, D).decode()
check("robots/Sitemap 만: 기존 줄 보존 + * 그룹", out.startswith("Sitemap:") and "User-agent: *\nDisallow: /internal/" in out, out)

# 404 의 평문 본문("not found", Cannot GET ...)은 진짜 robots 가 아니다
for junk in (b"not found", b"Cannot GET /robots.txt", b"404 page not found\n"):
    out = T.synth_robots(junk, D)
    check(f"robots/오류 평문 {junk[:12]!r} 무시", out.startswith(b"User-agent: *\nDisallow: /internal/") and junk not in out, out)

# 중복 줄 안 넣음
ex = b"User-agent: *\nDisallow: /Internal\nDisallow: /ftp\n"
out = T.synth_robots(ex, D).decode()
check("robots/중복 Disallow 안 넣음", out.lower().count("disallow: /internal") == 1 and "/backup/" in out, out)

# comment 만 있는 경우 / disallow 빈 목록
out = T.synth_robots(b"", [], "# note")
check("robots/빈 disallow + comment", out == b"User-agent: *\n# note\n", out)

# parse
check("parse_robots_disallow", T.parse_robots_disallow(b"User-agent: *\nDisallow: /a\nDisallow:\nDisallow: /b/\n") == ["/a", "/b/"])
check("parse_robots_disallow HTML", T.parse_robots_disallow(b"<html>Disallow: /x</html>") == [])

# ── 2. inject_html_comment: 바이트 보존·charset ───────────────────────────────────
C = "<!-- ops: test — note -->"
utf8 = "<html><head><title>한글 café</title></head><body>안녕</body></html>".encode("utf-8")
out = T.inject_html_comment(utf8, C, "text/html; charset=utf-8")
check("inject/utf-8: 원본 바이트 보존 + 주석 삽입",
      out.replace(("\n" + C + "\n").encode(), b"") == utf8 and out.index(b"<!-- ops") < out.index(b"</head>"), out)

euckr = "<html><head><title>한글</title></head><body>안녕하세요</body></html>".encode("euc-kr")
out = T.inject_html_comment(euckr, C, "text/html; charset=euc-kr")
check("inject/euc-kr: 한글 안 깨짐", "안녕하세요".encode("euc-kr") in out and "한글".encode("euc-kr") in out, out)
check("inject/euc-kr: 원본 바이트 보존", out.replace(b"\n<!-- ops: test  note -->\n", b"") == euckr or
      euckr[:euckr.index(b"</head>")] in out, out)

latin = "<html><head><title>café</title></head></html>".encode("latin-1")
out = T.inject_html_comment(latin, C, "text/html; charset=iso-8859-1")
check("inject/latin-1: é 보존", "café".encode("latin-1") in out, out)

# meta charset 로만 알려진 경우(헤더에 charset 없음)
sjis = "<html><head><meta charset=\"shift_jis\"><title>日本語</title></head></html>".encode("shift_jis")
out = T.inject_html_comment(sjis, C, "text/html")
check("inject/meta charset shift_jis: 보존", "日本語".encode("shift_jis") in out and b"<!-- ops" in out, out)

# UTF-16 → 주입 안 함(원본 그대로)
u16 = "<html><head></head></html>".encode("utf-16")
check("inject/utf-16: 건드리지 않음", T.inject_html_comment(u16, C, "text/html; charset=utf-16") == u16)
check("inject/BOM utf-16: 건드리지 않음", T.inject_html_comment(u16, C, "text/html") == u16)
# 모르는 charset
check("inject/모르는 charset: 건드리지 않음", T.inject_html_comment(utf8, C, "text/html; charset=x-nope") == utf8)

# </head> 없음 → 끝에 덧붙임, 대문자 </HEAD>
check("inject/</head> 없음: 끝에 덧붙임", T.inject_html_comment(b"<p>x</p>", C, "text/html").endswith(b"-->\n"))
out = T.inject_html_comment(b"<HEAD></HEAD>", C, "")
check("inject/대문자 </HEAD>", out.index(b"<!--") < out.index(b"</HEAD>"), out)

# 예전 구현과 UTF-8 정상 페이지에서 바이트 동일한지
def old_inject(html, comment):
    text = html.decode("utf-8", "ignore")
    block = "\n" + comment.rstrip("\n") + "\n"
    if "</head>" in text:
        text = text.replace("</head>", block + "</head>", 1)
    else:
        text = text + block
    return text.encode("utf-8")

for page in (utf8, b"<html><head></head><body>x</body></html>", b"<p>no head</p>"):
    check("inject/예전 구현과 바이트 동일(정상 UTF-8)", T.inject_html_comment(page, C, "text/html; charset=utf-8") == old_inject(page, C))

# ── 3. 미로 패턴 ────────────────────────────────────────────────────────────────
base = T.MAZE_DEFAULT_PATTERN
check("maze 패턴: 기본 경로 목록이면 기본 패턴 그대로", T.build_maze_pattern(["/internal/", "/backup/", "/admin/", "/.git/", "/config/", "/private/"]) == base)
import re
p = re.compile(T.build_maze_pattern(["/_ops/", "/internal/"]), re.I)
check("maze 패턴: 새 입구 /_ops 가 판정에 포함", bool(p.match("/_ops")) and bool(p.match("/_ops/x")) and not p.match("/_opsx"))
check("maze 패턴: 기본 것 유지", bool(p.match("/.git/config")) and bool(p.match("/admin")))

print("\nFAILED:" if fails else "\nALL PASS", fails or "")
sys.exit(1 if fails else 0)
