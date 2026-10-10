"""One row per (mode, cookie behaviour): what a client sees through the full stack."""
import json
import re
import subprocess
import sys

import httpx

BASE = "http://127.0.0.1:8081"
MODE = sys.argv[1]
ALIAS = re.compile(r"/__ruby_alias_[a-z2-7]{26}")


def table_alias(client, route):
    code = ("import sqlite3,sys;db=sqlite3.connect('/app/alias-data/path-alias.sqlite3');"
            "r=db.execute(\"SELECT alias_route FROM path_alias_alias_rows WHERE client_id=? AND route_path=? "
            "AND retired_at IS NULL\",(sys.argv[1],sys.argv[2])).fetchone();print(r[0] if r else '')")
    try:
        return subprocess.run(["docker", "exec", "ruby-verify-defense-1", "python", "-c", code, client, route],
                              capture_output=True, text=True, check=True).stdout.strip() or None
    except subprocess.CalledProcessError:
        return None


for cookies in ("returned", "not_returned"):
    row = {"mode": MODE, "cookies": cookies}
    with httpx.Client(timeout=30) as c:
        page = c.get(BASE + "/")
        script = re.search(r'src="(main[^"]*\.js)"', page.text).group(1)
        if cookies == "not_returned":
            c.cookies.clear()
        js = c.get(BASE + "/" + script)
        row["js_aliases"] = len(set(ALIAS.findall(js.text)))
        row["js_original_rest_literals"] = js.text.count('/rest/')
        row["js_etag_kept"] = "etag" in js.headers
        issued = re.search(r"ruby_alias_client=([a-z2-7]{26})", " ".join(js.headers.get_list("set-cookie")))
        alias_cookie = c.cookies.get("ruby_alias_client") or (issued.group(1) if issued else None)
        row["alias_cookie_issued"] = bool(issued) or bool(c.cookies.get("ruby_alias_client"))
        alias = table_alias(alias_cookie, "/rest/products/search") if alias_cookie else None
        if cookies == "not_returned":
            c.cookies.clear()
        row["alias_search"] = c.get(BASE + alias, params={"q": "apple"}).status_code if alias else None
        if cookies == "not_returned":
            c.cookies.clear()
        r = c.get(BASE + "/rest/products/search", params={"q": "apple"})
        row["original_search"] = r.status_code
        if cookies == "not_returned":
            c.cookies.clear()
        r = c.get(BASE + (alias or "/rest/products/search"), params={"q": "')) UNION SELECT 1--"})
        row["sqli_via_route_seen_by_client"] = r.status_code
    print(json.dumps(row))
