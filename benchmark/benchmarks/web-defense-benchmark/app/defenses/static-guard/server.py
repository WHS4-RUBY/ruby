from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from rules import decision


UPSTREAM = os.environ["RUBY_DEFENSE_UPSTREAM"].rstrip("/")
MANIFEST_DIGEST = os.environ["RUBY_DEFENSE_MANIFEST_DIGEST"]
ADAPTER_ID = "ruby-static-request-guard"
VERSION = "3.0.0"
LOCK = threading.Lock()
METRICS = {
    "observed_requests": 0,
    "blocked_requests": 0,
    "upstream_requests": 0,
    "defense_errors": 0,
    "defense_latency_seconds_total": 0.0,
}


def add_metrics(**values: float) -> None:
    with LOCK:
        for key, value in values.items():
            METRICS[key] += value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self) -> None:
        started = time.monotonic()
        add_metrics(observed_requests=1)
        selected = decision(self.path)
        if selected["action"] == "block":
            add_metrics(blocked_requests=1)
            response = selected["response"]
            body = base64.b64decode(response["body_base64"])
            self.send_response(response["status_code"])
            for name, values in response["headers"].items():
                for value in values:
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            add_metrics(defense_latency_seconds_total=time.monotonic() - started)
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else None
        headers = {
            name: value
            for name, value in self.headers.items()
            if name.lower() not in {"connection", "host", "content-length", "transfer-encoding"}
        }
        request = urllib.request.Request(
            UPSTREAM + self.path,
            data=body,
            headers=headers,
            method=self.command,
        )
        try:
            response = urllib.request.build_opener(NoRedirect).open(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        except Exception:
            add_metrics(defense_errors=1)
            payload = b'{"detail":"defense upstream error"}'
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            add_metrics(defense_latency_seconds_total=time.monotonic() - started)
            return
        payload = response.read()
        self.send_response(response.status)
        for name, value in response.headers.items():
            if name.lower() not in {"connection", "content-length", "transfer-encoding"}:
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)
        add_metrics(
            upstream_requests=1,
            defense_latency_seconds_total=time.monotonic() - started,
        )

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_PATCH = _handle
    do_DELETE = _handle
    do_HEAD = _handle
    do_OPTIONS = _handle

    def log_message(self, format, *args):
        return


class ControlHandler(BaseHTTPRequestHandler):
    def _json(self, status: int, value: object) -> None:
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/v2/health":
            self._json(200, {"status": "ready", "adapter_id": ADAPTER_ID, "version": VERSION, "manifest_digest": MANIFEST_DIGEST})
            return
        if self.path == "/v2/metrics":
            with LOCK:
                metrics = dict(METRICS)
            self._json(200, metrics)
            return
        self._json(404, {"detail": "not found"})

    def do_POST(self) -> None:
        if self.path == "/v2/reset":
            with LOCK:
                for key in METRICS:
                    METRICS[key] = 0.0 if key.endswith("_total") else 0
            self._json(200, {"status": "reset"})
            return
        if self.path == "/v2/decision":
            started = time.monotonic()
            length = int(self.headers.get("Content-Length", "0"))
            try:
                value = json.loads(self.rfile.read(length))
                phase = value.get("phase")
                if phase == "request":
                    selected = decision(str(value["http"]["path_and_query"]))
                    add_metrics(observed_requests=1)
                    if selected["action"] == "block":
                        add_metrics(blocked_requests=1)
                elif phase == "response":
                    selected = {
                        "contract_version": "2.0.0",
                        "action": "pass",
                        "reason_code": "static.response-observed",
                    }
                else:
                    raise ValueError("decision phase is invalid")
                add_metrics(defense_latency_seconds_total=time.monotonic() - started)
                self._json(200, selected)
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                add_metrics(defense_errors=1)
                self._json(422, {"detail": "invalid decision input"})
            return
        self._json(404, {"detail": "not found"})

    def log_message(self, format, *args):
        return


proxy = ThreadingHTTPServer(("0.0.0.0", 8080), ProxyHandler)
control = ThreadingHTTPServer(("0.0.0.0", 8081), ControlHandler)
threading.Thread(target=proxy.serve_forever, daemon=True).start()
control.serve_forever()
