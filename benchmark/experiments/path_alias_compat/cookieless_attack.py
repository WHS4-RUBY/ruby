"""Cookie-less attack vs. normal users through the real Detection -> Defense -> CHeaT -> Juice Shop.

Reads the Defense event log (dashboard API on the private admin port) to see which plan,
policy source and strategies Defense actually executed for each phase.
"""
import json
import os
import re
import subprocess
import sys
import time

import httpx

BASE = "http://127.0.0.1:8081"
ADMIN = "http://127.0.0.1:18088"
PASSWORD = os.environ["VERIFY_DASHBOARD_PASSWORD"]
ATTACK_UA = "verify-agent/1.0 (cookieless)"
ATTACK_BODY = {"payload": "union select <script>alert(1)</script>"}


def admin():
    c = httpx.Client(timeout=30)
    c.post(ADMIN + "/__defense/api/login", json={"password": PASSWORD}).raise_for_status()
    return c


def events(client, since):
    items = client.get(ADMIN + "/__defense/api/requests").json()["requests"]
    return [e for e in items if (e.get("timestamp") or 0) >= since]


def summarize(evts, tag):
    keys = {}
    for e in evts:
        k = (e.get("path", "")[:28], e.get("status"), ",".join(e.get("strategies") or []),
             e.get("policySource"), e.get("defenseTier"), e.get("decoyAction"),
             round(e.get("riskScore") or 0, 2), (e.get("clientId") or "")[:18])
        keys[k] = keys.get(k, 0) + 1
    print(json.dumps({"phase": tag, "defense_events": [{"path": k[0], "status": k[1], "strategies": k[2],
                      "source": k[3], "tier": k[4], "decoy": k[5],
                      "risk": k[6], "client_key": k[7], "count": v} for k, v in keys.items()]},
                     ensure_ascii=False))


def nocookie(method, path, **kw):
    with httpx.Client(timeout=30, headers={"User-Agent": ATTACK_UA}) as c:  # fresh jar every time
        return c.request(method, BASE + path, **kw)


def main():
    adm = admin()
    t0 = time.time() - 0.5
    # Phase 1: current-request attack evidence, no cookies, on an unprotected path (CRS sees it)
    statuses = {}
    for i in range(80):
        r = nocookie("POST", f"/api/Feedbacks/{i}", json=ATTACK_BODY)
        statuses[r.status_code] = statuses.get(r.status_code, 0) + 1
    print(json.dumps({"phase": "1_attack_cookieless", "client_statuses": statuses}))
    summarize(events(adm, t0), "1_attack_cookieless")
    # Phase 2: same IP + same fingerprint, still no cookies, harmless requests (history-based policy)
    t1 = time.time() - 0.5
    statuses = {}
    for path in ("/", "/robots.txt", "/ftp", "/internal/ops/runbook"):
        r = nocookie("GET", path)
        statuses[path] = (r.status_code, r.headers.get("x-defense-applied"))
    print(json.dumps({"phase": "2_clean_cookieless_same_fingerprint", "client": statuses}))
    summarize(events(adm, t1), "2_clean_cookieless_same_fingerprint")
    # Phase 3: same IP, different fingerprint (different UA), no cookies
    t2 = time.time() - 0.5
    with httpx.Client(timeout=30, headers={"User-Agent": "Mozilla/5.0 verify-other-user"}) as c:
        r = c.get(BASE + "/internal/ops/runbook")
        c.cookies.clear()
        r2 = c.get(BASE + "/internal/ops/runbook")
    print(json.dumps({"phase": "3_same_ip_other_fingerprint", "client": [r.status_code, r2.status_code]}))
    summarize(events(adm, t2), "3_same_ip_other_fingerprint")
    # Phase 4: same IP + same UA but a browser that returns cookies (signed dcid)
    t3 = time.time() - 0.5
    with httpx.Client(timeout=30, headers={"User-Agent": ATTACK_UA}) as c:
        c.get(BASE + "/")
        r = c.get(BASE + "/internal/ops/runbook")
        print(json.dumps({"phase": "4_same_fingerprint_with_valid_dcid", "client": r.status_code,
                          "cookies": sorted(c.cookies.keys())}))
    summarize(events(adm, t3), "4_same_fingerprint_with_valid_dcid")
    # Phase 5: tampered dcid / swapped cookie values, still the attacker's UA
    t4 = time.time() - 0.5
    with httpx.Client(timeout=30, headers={"User-Agent": ATTACK_UA},
                      cookies={"dcid": "tampered.value", "ruby_alias_client": "a" * 26}) as c:
        r = c.get(BASE + "/internal/ops/runbook")
        d = c.get(BASE + "/rest/products/search", params={"q": "x"})
    print(json.dumps({"phase": "5_tampered_cookies", "client": [r.status_code, d.status_code]}))
    summarize(events(adm, t4), "5_tampered_cookies")
    # Phase 6: attack again with no cookies on a protected original route and on an alias
    with httpx.Client(timeout=30, headers={"User-Agent": ATTACK_UA}) as c:
        page = c.get(BASE + "/")
        script = re.search(r'src="(main[^"]*\.js)"', page.text).group(1)
        js = c.get(BASE + "/" + script)
        cid = re.search(r"ruby_alias_client=([a-z2-7]{26})", " ".join(js.headers.get_list("set-cookie")))
    alias = None
    if cid:
        code = ("import sqlite3,sys;db=sqlite3.connect('/app/alias-data/path-alias.sqlite3');"
                "r=db.execute(\"SELECT alias_route FROM path_alias_alias_rows WHERE client_id=? AND "
                "route_path='/rest/products/search'\",(sys.argv[1],)).fetchone();print(r[0] if r else '')")
        alias = subprocess.run(["docker", "exec", "ruby-verify-defense-1", "python", "-c", code, cid.group(1)],
                               capture_output=True, text=True).stdout.strip()
    sqli = "')) UNION SELECT id,email,password,'4','5','6','7','8','9' FROM Users--"
    out = {"original_route": nocookie("GET", "/rest/products/search", params={"q": sqli}).status_code,
           "alias_route": nocookie("GET", alias, params={"q": sqli}).status_code if alias else None,
           "alias_clean": nocookie("GET", alias, params={"q": "apple"}).status_code if alias else None}
    print(json.dumps({"phase": "6_attack_original_vs_alias", "client": out}))


if __name__ == "__main__":
    main()
