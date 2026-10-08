"""Token observation smoke checks; token absence/expiry must not block benign requests."""

import argparse
import json
import sys
import time
from http.cookies import SimpleCookie
from pathlib import Path

import httpx

COOKIE_NAME = "__ruby_tg"
API_PATH = "/rest/products/search?q=apple"
OPTIONS_PATH = "/rest/products/search"


def options_snapshot(response: httpx.Response) -> dict:
    return {
        "status": response.status_code,
        "headers": {
            key.lower(): value for key, value in response.headers.items()
            if key.lower() == "allow" or key.lower().startswith("access-control-allow-")
        },
    }


def request(base_url: str, method: str, path: str, *, accept: str = "*/*",
            token: str | None = None) -> httpx.Response:
    headers = {"Accept": accept}
    if token is not None:
        headers["Cookie"] = f"{COOKIE_NAME}={token}"
    # A fresh request has no shared cookie jar: only explicitly supplied tokens are sent.
    return httpx.request(method, base_url.rstrip("/") + path, headers=headers,
                         timeout=30, follow_redirects=False)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def check_allowed(response: httpx.Response) -> None:
    require(response.status_code == 200, f"expected 200, got {response.status_code}")
    require("token_gate" not in response.headers.get("x-defense-applied", ""), "token state must not block")


def run(args: argparse.Namespace) -> int:
    if args.record_baseline:
        try:
            response = request(args.base_url, "OPTIONS", OPTIONS_PATH)
            require(response.status_code < 500, "baseline upstream failed")
            require("token_gate" not in response.headers.get("x-defense-applied", ""),
                    "baseline must be recorded in off mode")
            Path(args.record_baseline).write_text(
                json.dumps(options_snapshot(response), indent=2) + "\n", encoding="utf-8"
            )
            print(f"PASS baseline saved to {args.record_baseline}")
            return 0
        except (httpx.HTTPError, OSError, AssertionError) as exc:
            print(f"FAIL baseline: {exc}")
            return 1

    baseline = None
    if args.baseline:
        try:
            baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
            require(isinstance(baseline, dict), "baseline must be a JSON object")
            require(type(baseline.get("status")) is int and baseline["status"] < 500,
                    "baseline has no valid status")
            require(isinstance(baseline.get("headers"), dict), "baseline has no headers")
        except (OSError, ValueError, AssertionError) as exc:
            print(f"FAIL baseline: {exc}")
            return 1

    failed = False

    def check(number, title, operation):
        nonlocal failed
        try:
            value = operation()
            print(f"PASS {number}: {title}", flush=True)
            return value
        except (httpx.HTTPError, AssertionError, ValueError) as exc:
            failed = True
            print(f"FAIL {number}: {title}: {exc}", flush=True)
            return None

    def allowed(token=None):
        check_allowed(request(args.base_url, "GET", API_PATH, token=token))

    check(1, "API without a token passes", allowed)

    def page():
        response = request(args.base_url, "GET", "/", accept="text/html")
        require(response.status_code == 200, f"expected page 200, got {response.status_code}")
        require(response.headers.get("cache-control") == "no-store", "page has no no-store")
        for value in response.headers.get_list("set-cookie"):
            cookies = SimpleCookie()
            cookies.load(value)
            if COOKIE_NAME in cookies:
                cookie = cookies[COOKIE_NAME]
                require(bool(cookie.value), "empty gate cookie")
                require(1 <= int(cookie["max-age"]) <= args.epoch_s * (args.grace + 1),
                        "Max-Age is outside the configured lifetime")
                return cookie.value
        raise AssertionError("page did not issue a gate cookie")

    token = check(2, "page issues a cookie", page)

    def valid_api():
        require(token is not None, "page token unavailable")
        response = request(args.base_url, "GET", API_PATH, token=token)
        require(response.status_code == 200, f"expected API 200, got {response.status_code}")

    check(3, "API with the saved token", valid_api)
    check(4, "bad token does not block a benign request", lambda: allowed("v1.1.AAAAAAAAAAAAAAAAAAAAAA"))
    if args.stale:
        def stale_api():
            require(token is not None, "page token unavailable")
            delay = args.epoch_s * (args.grace + 1) + 1
            print(f"WAIT 5: {delay}s before resending the original token", flush=True)
            time.sleep(delay)
            allowed(token)
        check(5, "original token after expiry", stale_api)
    else:
        print("SKIP 5: use --stale to check expiry")

    if baseline is not None:
        def options():
            response = request(args.base_url, "OPTIONS", OPTIONS_PATH)
            require(options_snapshot(response) == baseline, "OPTIONS differs from off baseline")
            require("token_gate" not in response.headers.get("x-defense-applied", ""),
                    "OPTIONS was gated")
        check(6, "OPTIONS matches off baseline", options)
    else:
        print("SKIP 6: use --baseline recorded in off mode")

    def html_api():
        response = request(args.base_url, "GET", API_PATH, accept="text/html")
        require(response.status_code == 200, f"expected API 200, got {response.status_code}")

    check(7, "API declaring HTML passes", html_api)
    return int(failed)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:8081")
    parser.add_argument("--stale", action="store_true")
    parser.add_argument("--epoch-s", type=int, default=300)
    parser.add_argument("--grace", type=int, default=1)
    baseline = parser.add_mutually_exclusive_group()
    baseline.add_argument("--record-baseline", metavar="PATH")
    baseline.add_argument("--baseline", metavar="PATH")
    args = parser.parse_args(argv)
    if args.epoch_s < 1 or not 0 <= args.grace <= 10:
        parser.error("--epoch-s must be >= 1 and --grace must be between 0 and 10")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
