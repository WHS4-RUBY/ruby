"""HTTP checks through Detection -> Defense -> CHeaT -> Juice Shop.

Usage: python http_matrix.py <label> [base_url]
Prints one JSON object per check and a summary. Nothing here inspects application secrets.
"""
import json
import re
import sys
import time

import subprocess

import httpx

LABEL = sys.argv[1] if len(sys.argv) > 1 else "run"
BASE = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8081"
ALIAS = re.compile(r"/__ruby_alias_[a-z2-7]{26}")
results = []


def check(name, ok, **info):
    results.append({"check": name, "ok": bool(ok), **info})
    print(json.dumps({"label": LABEL, "check": name, "ok": bool(ok), **info}, ensure_ascii=False))


def main_js(client):
    page = client.get(BASE + "/")
    script = re.search(r'src="(main[^"]*\.js)"', page.text)
    js = client.get(BASE + "/" + script.group(1))
    return page, js


DEFENSE = "ruby-verify-defense-1"


def table_aliases(client_cookie):
    """Test-only introspection: current aliases of one client from the Defense SQLite file."""
    code = ("import sqlite3,json,sys;db=sqlite3.connect('/app/alias-data/path-alias.sqlite3');"
            "print(json.dumps(dict(db.execute(\"SELECT route_path, alias_route FROM path_alias_alias_rows "
            "WHERE client_id=? AND retired_at IS NULL ORDER BY generation\", (sys.argv[1],)).fetchall())))")
    out = subprocess.run(["docker", "exec", DEFENSE, "python", "-c", code, client_cookie],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def login_alias(js_text):
    # Juice Shop: this.http.post(this.hostServer + "/rest/user/login", ...)
    match = re.search(r'(/__ruby_alias_[a-z2-7]{26})",\s*\w+\)\.pipe\(\(0,\s*\w+\.U\)\(\w+ => \(localStorage', js_text)
    return match.group(1) if match else None


def run():
    started = time.time()
    # ---------------------------------------------------------------- browser-like client keeps cookies
    with httpx.Client(timeout=30, follow_redirects=False, headers={"User-Agent": "verify-browser/1.0"}) as c:
        page, js = main_js(c)
        aliases = sorted(set(ALIAS.findall(js.text)))
        check("cookie.page_and_js", page.status_code == 200 and js.status_code == 200,
              page=page.status_code, js=js.status_code, aliases=len(aliases),
              original_login_literal=js.text.count('"/rest/user/login"'),
              cookies=sorted(c.cookies.keys()))
        table = table_aliases(c.cookies["ruby_alias_client"])
        login, search = table.get("/rest/user/login"), table.get("/rest/products/search")
        check("cookie.js_aliases_match_table", login in aliases and search in aliases, issued_rows=len(table))
        r = c.post(BASE + login, json={"email": "nobody@example.invalid", "password": "x"})
        check("cookie.login_alias_reaches_app", r.status_code == 401 and "Invalid email" in r.text,
              status=r.status_code)
        r = c.get(BASE + search, params={"q": "apple"})
        check("cookie.search_alias", r.status_code == 200 and "Apple" in r.text, status=r.status_code)
        r = c.get(BASE + search + "?q=apple&q=&empty=&x=%41") if search else None
        check("cookie.search_query_bytes_forwarded", r is not None and r.status_code == 200,
              status=r.status_code if r else None)
        # JSON prose: product descriptions are left alone (no alias inside "description")
        prods = c.get(BASE + search, params={"q": ""}) if search else None
        descriptions = [p.get("description", "") for p in prods.json().get("data", [])] if prods else []
        check("cookie.json_descriptions_untouched", not any("__ruby_alias_" in d for d in descriptions),
              products=len(descriptions))
        # direct original route: 404 + rotation; old alias then revoked; reload gives new aliases
        direct = c.post(BASE + "/rest/user/login", json={"email": "a@b.c", "password": "x"})
        check("cookie.direct_blocked", direct.status_code == 404, status=direct.status_code)
        old = c.post(BASE + login, json={"email": "a@b.c", "password": "x"}) if login else None
        check("cookie.revoked_alias_blocked", old is not None and old.status_code == 404,
              status=old.status_code if old else None)
        _, js2 = main_js(c)
        new_aliases = set(ALIAS.findall(js2.text))
        new_login = table_aliases(c.cookies["ruby_alias_client"]).get("/rest/user/login")
        check("cookie.reload_issues_new_aliases", login not in new_aliases and new_login in new_aliases)
        r = c.post(BASE + new_login, json={"email": "nobody@example.invalid", "password": "x"})
        check("cookie.new_alias_works", r.status_code == 401, status=r.status_code)
        r = c.post(BASE + new_login + "/x", json={})
        check("cookie.bad_alias_arguments_blocked", r.status_code == 404, status=r.status_code)
        # case/encoding variants of the original route
        variants = ["/REST/user/login", "/%72est/user/login", "//rest/user/login", "/rest;x/user/login",
                    "/rest/./user/login", "/api/../rest/user/login"]
        statuses = {v: c.post(BASE + v, json={}).status_code for v in variants}
        check("cookie.direct_variants_blocked", all(s in (400, 403, 404) for s in statuses.values()),
              statuses=statuses)
        static = c.get(BASE + "/assets/public/images/JuiceShop_Logo.png")
        check("cookie.static_passes", static.status_code == 200, status=static.status_code)

    # ---------------------------------------------------------------- cookieless client (curl-like)
    def fresh():
        return httpx.Client(timeout=30, follow_redirects=False, headers={"User-Agent": "verify-nocookie/1.0"})

    with fresh() as c:
        page = c.get(BASE + "/")
        script = re.search(r'src="(main[^"]*\.js)"', page.text).group(1)
    with fresh() as c:  # every request starts without cookies
        js = c.get(BASE + "/" + script)
        set_cookie = js.headers.get_list("set-cookie")
        pending = re.search(r"ruby_alias_client=([a-z2-7]{26})", " ".join(set_cookie)).group(1)
        login = table_aliases(pending)["/rest/user/login"]
    with fresh() as c:
        r = c.post(BASE + login, json={"email": "nobody@example.invalid", "password": "x"})
        check("nocookie.pending_alias_usable_without_cookie", r.status_code == 401, status=r.status_code,
              alias_cookie_issued=True)
        direct = c.post(BASE + "/rest/user/login", json={"email": "a@b.c", "password": "x"})
        check("nocookie.original_still_blocked", direct.status_code == 404, status=direct.status_code)
        forged = c.get(BASE + "/__ruby_alias_" + "a" * 26)
        check("nocookie.forged_alias_blocked", forged.status_code == 404, status=forged.status_code)

    # ---------------------------------------------------------------- current-request attack, no cookies
    with fresh() as c:
        statuses = []
        for payload in ("')) UNION SELECT id,email,password,'4','5','6','7','8','9' FROM Users--",
                        "<script>alert(1)</script>"):
            r = c.get(BASE + "/rest/products/search", params={"q": payload})
            statuses.append(r.status_code)
        check("nocookie.attack_on_original_route_refused", all(s in (403, 404) for s in statuses), statuses=statuses)
    print(json.dumps({"label": LABEL, "summary": {"passed": sum(r["ok"] for r in results), "total": len(results),
                                                  "seconds": round(time.time() - started, 1)}}))


if __name__ == "__main__":
    run()
