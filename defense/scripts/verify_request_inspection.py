"""Local Juice Shop regression: run inside ruby-local_ai-defense-net, never against a remote site."""

import argparse
import base64
import json
import time
import uuid
from pathlib import Path

import httpx


def admin_claim(response):
    try:
        token = response.json().get("authentication", {}).get("token")
        if not token:
            return False
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return claims.get("data", {}).get("role") == "admin"
    except (ValueError, AttributeError, IndexError):
        return False


def run(args):
    base = "http://detection:8080"
    target = "http://benchmark-target:3000"
    cases = []
    payload = {"email": "' OR 1=1--", "password": "local-test-only"}

    def check(name, response, expected, extra=True):
        passed = response.status_code == expected and extra
        cases.append({"case": name, "status": response.status_code, "expected": expected,
                      "passed": passed, "admin_claim": admin_claim(response),
                      "defense": response.headers.get("x-defense-applied")})
        print(f"{'PASS' if passed else 'FAIL'} {name}: {response.status_code}", flush=True)

    def blocked(name, *, headers=None, body=None):
        response = httpx.post(base + "/rest/user/login", json=body or payload,
                              headers=headers, timeout=30)
        check(name, response, 403, response.headers.get("x-defense-applied") == "crs"
              and not admin_claim(response))

    response = httpx.post(target + "/rest/user/login", json=payload, timeout=30)
    check("positive_control_direct_target", response, 200, admin_claim(response))
    check("benign_without_token", httpx.get(base + "/rest/products/search?q=apple", timeout=30), 200)
    blocked("sqli_without_token")
    blocked("sqli_html_declared", headers={"Accept": "text/html"})

    with httpx.Client(base_url=base, timeout=30) as client:
        response = client.get("/", headers={"Accept": "text/html"})
        check("page_and_cookies", response, 200,
              all(name in client.cookies for name in ("__ruby_tg", "dcid", "dlsid")))
        saved_token = client.cookies.get("__ruby_tg")
        response = client.post("/rest/user/login", json=payload)
        check("sqli_after_page_visit", response, 403,
              response.headers.get("x-defense-applied") == "crs" and not admin_claim(response))
        response = client.get("/rest/products/search", params={"q": "' UNION SELECT 1,2,3--"},
                              headers={"Accept": "text/html"})
        check("get_sqli_declaring_html", response, 403, response.headers.get("x-defense-applied") == "crs")
        response = client.post("/rest/user/login", content=json.dumps(payload),
                               headers={"Content-Type": "application/problem+json"})
        check("sqli_structured_json", response, 403, response.headers.get("x-defense-applied") == "crs")
        response = client.post("/rest/user/login", data=payload)
        check("sqli_form", response, 403, response.headers.get("x-defense-applied") == "crs")

    # A disposable ordinary account lets us verify a real successful login.
    email = f"ruby-verification-{uuid.uuid4().hex}@example.test"
    password = "LocalTest" + uuid.uuid4().hex
    with httpx.Client(base_url=base, timeout=30) as client:
        response = client.post("/api/Users", json={"email": email, "password": password,
                                                   "passwordRepeat": password})
        check("benign_registration", response, 201)
        response = client.post("/rest/user/login", json={"email": email, "password": password})
        auth = response.json().get("authentication", {}) if response.status_code == 200 else {}
        check("benign_login_without_gate_token", response, 200, bool(auth.get("token")) and not admin_claim(response))
        if auth.get("token"):
            # Juice Shop's currentUser route reads the token cookie, not Authorization.
            client.cookies.set("token", auth["token"])
            response = client.get("/rest/user/whoami")
            check("benign_authenticated_identity", response, 200,
                  response.json().get("user", {}).get("email") == email)

    response = httpx.get(base + "/rest/products/search?q=apple", headers={"Cookie": "__ruby_tg=invalid"}, timeout=30)
    check("benign_invalid_gate_token", response, 200)
    response = httpx.post(base + "/rest/user/login", content="uninspected",
                          headers={"Content-Type": "application/octet-stream"}, timeout=30)
    check("unsupported_body_rejected", response, 415)
    response = httpx.post(base + "/rest/user/login", json={"padding": "x" * 1_048_576}, timeout=30)
    check("oversized_body_rejected", response, 413)
    response = httpx.post(base + "/rest/user/login", content='{"email":',
                          headers={"Content-Type": "application/json"}, timeout=30)
    check("malformed_json_rejected", response, 400)

    if args.expiry_wait:
        print(f"Waiting {args.expiry_wait}s for the saved page token to expire", flush=True)
        time.sleep(args.expiry_wait)
        response = httpx.get(base + "/rest/products/search?q=apple",
                             headers={"Cookie": f"__ruby_tg={saved_token}"}, timeout=30)
        check("benign_expired_gate_token", response, 200)
        response = httpx.get(base + "/rest/products/search?q=apple", timeout=30)
        check("benign_cookie_dropped_after_idle", response, 200)

    report = {"cases": cases, "passed": sum(case["passed"] for case in cases), "total": len(cases),
              "scope": "Local fixed regressions; not an attack success rate or LLM evaluation."}
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if all(case["passed"] for case in cases) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--expiry-wait", type=int, default=0)
    args = parser.parse_args()
    if not 0 <= args.expiry_wait <= 60:
        parser.error("--expiry-wait must be 0..60 seconds and exceed the test token lifetime")
    raise SystemExit(run(args))
