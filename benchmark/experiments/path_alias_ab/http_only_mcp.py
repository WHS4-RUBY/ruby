"""Minimal stdio MCP adapter restricted to one local Juice Shop origin."""

from http.cookiejar import MozillaCookieJar
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (HTTPCookieProcessor, HTTPRedirectHandler, OpenerDirector, ProxyHandler,
                            Request, build_opener)


ORIGIN = os.environ.get("RUBY_MCP_TARGET", "http://127.0.0.1:8081").rstrip("/")
AUDIT = os.environ.get("RUBY_MCP_AUDIT", "")
COOKIE_PATH = os.environ.get("RUBY_MCP_COOKIE_JAR", "")
ALLOWED_HEADERS = {"accept", "authorization", "content-type", "cookie", "origin", "referer",
                   "user-agent", "x-requested-with"}
MAX_BODY_BYTES = 2_000_000


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


# Keep cookies for the session like a browser or `curl -c` would, so a defense that binds state
# to a cookie is measured against a normal client rather than against this tool's limits.
COOKIES = MozillaCookieJar(COOKIE_PATH if COOKIE_PATH else None)
if COOKIE_PATH and Path(COOKIE_PATH).exists():
    COOKIES.load(ignore_discard=True, ignore_expires=True)
OPENER: OpenerDirector = build_opener(ProxyHandler({}), NoRedirect(), HTTPCookieProcessor(COOKIES))


def response_headers(message):
    # A dict would keep only the last of several Set-Cookie headers.
    headers = dict(message.items())
    cookies = message.get_all("Set-Cookie") or []
    if len(cookies) > 1:
        headers["Set-Cookie"] = cookies
    return headers


def emit(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def audit(obj):
    if AUDIT:
        with Path(AUDIT).open("a", encoding="utf-8") as output:
            output.write(json.dumps({"time": time.time(), **obj}, separators=(",", ":")) + "\n")


def get_url(path):
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or "\\" in path:
        raise ValueError("path must be an absolute path on the lab origin")
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc or any(part == ".." for part in parsed.path.split("/")):
        raise ValueError("path cannot leave the lab origin")
    return ORIGIN + path


def request(args):
    method = str(args.get("method", "GET")).upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
        raise ValueError("unsupported HTTP method")
    path = args.get("path", "/")
    url = get_url(path)
    supplied = args.get("headers") or {}
    if not isinstance(supplied, dict):
        raise ValueError("headers must be an object")
    headers = {}
    for key, value in supplied.items():
        if str(key).lower() not in ALLOWED_HEADERS or not isinstance(value, str):
            raise ValueError("header not allowed")
        headers[str(key)] = value
    body = args.get("body")
    if body is not None and not isinstance(body, str):
        raise ValueError("body must be a string")
    raw = body.encode("utf-8") if body is not None else None
    if raw is not None and len(raw) > 100_000:
        raise ValueError("request body too large")
    req = Request(url, data=raw, headers=headers, method=method)
    started = time.perf_counter()
    try:
        with OPENER.open(req, timeout=15) as response:
            status = response.status
            result_headers = response_headers(response.headers)
            content = response.read(MAX_BODY_BYTES + 1)
    except HTTPError as error:
        status = error.code
        result_headers = response_headers(error.headers)
        content = error.read(MAX_BODY_BYTES + 1)
    except URLError as error:
        audit({"method": method, "path": path, "error": str(error)})
        raise ValueError("lab origin request failed") from error
    if COOKIE_PATH:
        COOKIES.save(ignore_discard=True, ignore_expires=True)
    elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
    audit({"method": method, "path": path, "status": status, "elapsed_ms": elapsed_ms})
    text = content[:MAX_BODY_BYTES].decode("utf-8", "replace")
    pattern = args.get("pattern")
    if pattern is not None:
        if not isinstance(pattern, str) or len(pattern) > 200:
            raise ValueError("pattern must be a short regular expression")
        matches = []
        for match in re.finditer(pattern, text):
            matches.append(text[max(0, match.start() - 60):min(len(text), match.end() + 60)])
            if len(matches) >= 100:
                break
        text = "\n---\n".join(matches)
    else:
        limit = min(max(int(args.get("max_chars", 30000)), 1), 100000)
        text = text[:limit]
    return {"status": status, "headers": result_headers, "body": text,
            "body_bytes_read": len(content), "truncated": len(content) > MAX_BODY_BYTES,
            "elapsed_ms": elapsed_ms}


TOOL = {"name": "request", "description": "Send an HTTP request only to the authorized local lab origin. Use path, not a URL. The optional pattern extracts matching response snippets, useful for large JavaScript files.",
        "inputSchema": {"type": "object", "properties": {
            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]},
            "path": {"type": "string", "description": "Path beginning with / on the supplied lab origin"},
            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
            "body": {"type": "string"},
            "pattern": {"type": "string", "description": "Optional regular expression to find response snippets"},
            "max_chars": {"type": "integer"}}, "required": ["path"]}}


def handle(message):
    method = message.get("method")
    if method == "initialize":
        return {"protocolVersion": message.get("params", {}).get("protocolVersion", "2025-06-18"),
                "capabilities": {"tools": {}}, "serverInfo": {"name": "ruby-local-http", "version": "1.0"}}
    if method == "tools/list":
        return {"tools": [TOOL]}
    if method == "tools/call":
        params = message.get("params") or {}
        if params.get("name") != "request":
            raise ValueError("unknown tool")
        return {"content": [{"type": "text", "text": json.dumps(request(params.get("arguments") or {}))}]}
    if method == "ping":
        return {}
    raise ValueError("unsupported method")


for line in sys.stdin:
    try:
        message = json.loads(line)
        if "id" not in message:
            continue
        try:
            result = handle(message)
            emit({"jsonrpc": "2.0", "id": message["id"], "result": result})
        except Exception as error:
            emit({"jsonrpc": "2.0", "id": message["id"], "error": {
                "code": -32602, "message": str(error)}})
    except (ValueError, TypeError):
        continue
