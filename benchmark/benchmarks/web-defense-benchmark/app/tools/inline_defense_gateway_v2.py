from __future__ import annotations

import base64
import hashlib
import http.client
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from uuid import uuid4


MAX_CAPTURE_BYTES = 1024 * 1024
MAX_FORWARD_BYTES = 16 * 1024 * 1024
TRUNCATION_POLICY_DIGEST = "sha256:" + hashlib.sha256(
    b"ruby-inline-defense-capture:first-1048576-bytes:v1"
).hexdigest()
HOP_BY_HOP = {
    "connection",
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


class InlineGatewayError(RuntimeError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


class HttpDefenseAdapter:
    def __init__(
        self,
        *,
        control_origin: str,
        timeout_seconds: float,
        close_callback: Callable[[], None] | None = None,
    ) -> None:
        parsed = urllib.parse.urlsplit(control_origin)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost"}
            or parsed.port is None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise InlineGatewayError("defense adapter endpoint must be a loopback HTTP origin")
        self.control_origin = control_origin.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self._close_callback = close_callback
        self._closed = False

    def _json(
        self,
        method: str,
        path: str,
        value: dict[str, object] | None = None,
    ) -> dict[str, object]:
        body = None
        headers = {"Accept": "application/json"}
        if value is not None:
            body = json.dumps(value, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.control_origin + path,
            data=body,
            headers=headers,
            method=method,
        )
        try:
            response = urllib.request.build_opener(_NoRedirect).open(
                request, timeout=self.timeout_seconds
            )
        except urllib.error.HTTPError as error:
            payload = error.read(2048).decode("utf-8", errors="replace")
            raise InlineGatewayError(
                f"defense adapter {path} returned HTTP {error.code}: {payload}"
            ) from error
        except Exception as error:
            raise InlineGatewayError(f"defense adapter {path} failed: {error}") from error
        with response:
            payload = response.read(2 * 1024 * 1024 + 1)
        if len(payload) > 2 * 1024 * 1024:
            raise InlineGatewayError(f"defense adapter {path} response is too large")
        try:
            result = json.loads(payload)
        except json.JSONDecodeError as error:
            raise InlineGatewayError(
                f"defense adapter {path} returned invalid JSON"
            ) from error
        if not isinstance(result, dict):
            raise InlineGatewayError(f"defense adapter {path} response must be an object")
        return result

    def health(self) -> dict[str, object]:
        return self._json("GET", "/v2/health")

    def reset(self) -> None:
        result = self._json("POST", "/v2/reset", {})
        if result != {"status": "reset"}:
            raise InlineGatewayError("defense adapter reset response is invalid")

    def decision(self, value: dict[str, object]) -> dict[str, object]:
        return self._json("POST", "/v2/decision", value)

    def metrics(self) -> dict[str, object]:
        return self._json("GET", "/v2/metrics")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._close_callback is not None:
            self._close_callback()


def _headers(raw_items: list[tuple[str, str]]) -> dict[str, list[str]]:
    selected: dict[str, list[str]] = {}
    for name, value in raw_items:
        selected.setdefault(name.lower(), []).append(value)
    return selected


def _capture(body: bytes) -> dict[str, object]:
    captured = body[:MAX_CAPTURE_BYTES]
    return {
        "body_base64": base64.b64encode(captured).decode(),
        "captured_bytes": len(captured),
        "original_bytes": len(body),
        "original_sha256": "sha256:" + hashlib.sha256(body).hexdigest(),
        "truncated": len(body) > len(captured),
        "truncation_policy_digest": TRUNCATION_POLICY_DIGEST,
    }


def _replacement(value: object) -> tuple[int, list[tuple[str, str]], bytes]:
    if not isinstance(value, dict):
        raise InlineGatewayError("defense replacement must be an object")
    status = value.get("status_code")
    headers = value.get("headers")
    encoded = value.get("body_base64")
    if not isinstance(status, int) or not 100 <= status <= 599:
        raise InlineGatewayError("defense replacement status is invalid")
    if not isinstance(headers, dict) or not isinstance(encoded, str):
        raise InlineGatewayError("defense replacement headers or body are invalid")
    flattened: list[tuple[str, str]] = []
    for name, values in headers.items():
        if not isinstance(name, str) or not isinstance(values, list):
            raise InlineGatewayError("defense replacement headers are invalid")
        if name.lower() in HOP_BY_HOP:
            continue
        for item in values:
            if not isinstance(item, str) or "\r" in item or "\n" in item:
                raise InlineGatewayError("defense replacement header value is invalid")
            flattened.append((name, item))
    try:
        body = base64.b64decode(encoded, validate=True)
    except ValueError as error:
        raise InlineGatewayError("defense replacement body is not valid base64") from error
    if len(body) > MAX_FORWARD_BYTES:
        raise InlineGatewayError("defense replacement body is too large")
    return status, flattened, body


def _validate_decision(value: dict[str, object]) -> str:
    if value.get("contract_version") != "2.0.0":
        raise InlineGatewayError("defense decision contract version is invalid")
    action = value.get("action")
    if action not in {
        "pass",
        "block",
        "delay",
        "rewrite-request",
        "replace-response",
        "route-decoy",
        "terminate-session",
    }:
        raise InlineGatewayError("defense decision action is invalid")
    reason = value.get("reason_code")
    if not isinstance(reason, str) or len(reason) < 3:
        raise InlineGatewayError("defense decision reason code is invalid")
    return str(action)


class _GatewayServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False


class InlineDefenseGateway:
    def __init__(
        self,
        *,
        upstream_origin: str,
        trial_id: str,
        adapter: HttpDefenseAdapter | None,
        identity: dict[str, object],
        request_timeout_seconds: float,
        decoy_targets: dict[str, str] | None = None,
        listen_port: int = 0,
    ) -> None:
        upstream = urllib.parse.urlsplit(upstream_origin)
        if (
            upstream.scheme not in {"http", "https"}
            or upstream.hostname not in {"127.0.0.1", "localhost"}
            or upstream.port is None
            or upstream.query
            or upstream.fragment
        ):
            raise InlineGatewayError("defense gateway upstream must be a loopback HTTP origin")
        if len(trial_id) != 32 or any(char not in "0123456789abcdef" for char in trial_id):
            raise InlineGatewayError("defense gateway trial id must be 32 lowercase hex characters")
        self.upstream = upstream
        self.trial_id = trial_id
        self.adapter = adapter
        self.identity = dict(identity)
        self.request_timeout_seconds = float(request_timeout_seconds)
        self.decoy_targets = dict(decoy_targets or {})
        self._lock = threading.Lock()
        self._metrics: Counter[str] = Counter()
        self._latency = 0.0
        self._closed = False
        runtime = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _run(self) -> None:
                runtime._handle(self)

            do_GET = _run
            do_POST = _run
            do_PUT = _run
            do_PATCH = _run
            do_DELETE = _run
            do_HEAD = _run
            do_OPTIONS = _run

            def log_message(self, format, *args):
                return

        if not 0 <= listen_port <= 65535:
            raise InlineGatewayError("defense gateway listen port is invalid")
        self._server = _GatewayServer(("127.0.0.1", listen_port), Handler)
        port = int(self._server.server_address[1])
        self.origin = f"http://127.0.0.1:{port}"
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name=f"ruby-defense-gateway-{trial_id[:8]}",
            daemon=True,
        )
        self._thread.start()

    def _increment(self, key: str, value: int = 1) -> None:
        with self._lock:
            self._metrics[key] += value

    def _add_latency(self, seconds: float) -> None:
        with self._lock:
            self._latency += max(0.0, seconds)

    def _session_handle(self, handler: BaseHTTPRequestHandler) -> str:
        material = (
            handler.headers.get("Cookie")
            or handler.headers.get("Authorization")
            or handler.client_address[0]
        )
        return hashlib.sha256(
            (self.trial_id + "\0" + material).encode("utf-8", errors="replace")
        ).hexdigest()

    def _decision(self, value: dict[str, object]) -> dict[str, object]:
        if self.adapter is None:
            return {
                "contract_version": "2.0.0",
                "action": "pass",
                "reason_code": "proxy.no-defense",
            }
        started = time.monotonic()
        try:
            result = self.adapter.decision(value)
            _validate_decision(result)
            self._increment("defense_calls")
            self._increment(f"action_{result['action']}")
            return result
        except Exception:
            raise
        finally:
            self._add_latency(time.monotonic() - started)

    def _read_body(self, handler: BaseHTTPRequestHandler) -> bytes:
        length_text = handler.headers.get("Content-Length", "0")
        if not length_text.isdigit():
            raise InlineGatewayError("request content length is invalid")
        length = int(length_text)
        if length > MAX_FORWARD_BYTES:
            raise InlineGatewayError("request body exceeds the gateway limit")
        return handler.rfile.read(length) if length else b""

    def _request_document(
        self,
        handler: BaseHTTPRequestHandler,
        *,
        interaction_id: str,
        body: bytes,
    ) -> dict[str, object]:
        return {
            "contract_version": "2.0.0",
            "trial_id": self.trial_id,
            "interaction_id": interaction_id,
            "session_handle": self._session_handle(handler),
            "phase": "request",
            "http": {
                "method": handler.command,
                "scheme": self.upstream.scheme,
                "authority": self.upstream.netloc,
                "path_and_query": handler.path,
                "headers": _headers(list(handler.headers.raw_items())),
                "body": _capture(body),
            },
        }

    def _response_document(
        self,
        handler: BaseHTTPRequestHandler,
        *,
        interaction_id: str,
        status: int,
        headers: list[tuple[str, str]],
        body: bytes,
    ) -> dict[str, object]:
        return {
            "contract_version": "2.0.0",
            "trial_id": self.trial_id,
            "interaction_id": interaction_id,
            "session_handle": self._session_handle(handler),
            "phase": "response",
            "http": {
                "status_code": status,
                "headers": _headers(headers),
                "body": _capture(body),
            },
        }

    def _apply_request_decision(
        self,
        decision: dict[str, object],
        *,
        method: str,
        path: str,
        headers: list[tuple[str, str]],
        body: bytes,
    ) -> tuple[str, str, list[tuple[str, str]], bytes] | tuple[int, list[tuple[str, str]], bytes]:
        action = _validate_decision(decision)
        if action == "pass":
            return method, path, headers, body
        if action == "delay":
            delay = decision.get("delay_ms")
            if not isinstance(delay, int) or not 1 <= delay <= 60000:
                raise InlineGatewayError("defense delay is invalid")
            started = time.monotonic()
            time.sleep(delay / 1000.0)
            self._add_latency(time.monotonic() - started)
            return method, path, headers, body
        if action == "block":
            return _replacement(decision.get("response"))
        if action == "terminate-session":
            payload = b'{"detail":"session terminated by defense"}'
            return 403, [("Content-Type", "application/json")], payload
        if action == "route-decoy":
            target_id = decision.get("decoy_target_id")
            if not isinstance(target_id, str) or target_id not in self.decoy_targets:
                raise InlineGatewayError("defense selected an unregistered decoy")
            decoy = urllib.parse.urlsplit(self.decoy_targets[target_id])
            if decoy.scheme != self.upstream.scheme or decoy.netloc != self.upstream.netloc:
                raise InlineGatewayError("decoy target is outside the registered upstream")
            return method, decoy.path.rstrip("/") + path, headers, body
        if action == "rewrite-request":
            replacement = decision.get("request")
            if not isinstance(replacement, dict):
                raise InlineGatewayError("rewritten request is invalid")
            scheme = replacement.get("scheme")
            authority = replacement.get("authority")
            rewritten_method = replacement.get("method")
            rewritten_path = replacement.get("path_and_query")
            if scheme != self.upstream.scheme or authority != self.upstream.netloc:
                raise InlineGatewayError("defense cannot rewrite a request to another origin")
            if not isinstance(rewritten_method, str) or not rewritten_method.isupper():
                raise InlineGatewayError("rewritten request method is invalid")
            if (
                not isinstance(rewritten_path, str)
                or not rewritten_path.startswith("/")
                or rewritten_path.startswith("//")
            ):
                raise InlineGatewayError("rewritten request path is invalid")
            header_map = replacement.get("headers")
            if not isinstance(header_map, dict):
                raise InlineGatewayError("rewritten request headers are invalid")
            rewritten_headers: list[tuple[str, str]] = []
            for name, values in header_map.items():
                if not isinstance(name, str) or not isinstance(values, list):
                    raise InlineGatewayError("rewritten request headers are invalid")
                for value in values:
                    if not isinstance(value, str) or "\r" in value or "\n" in value:
                        raise InlineGatewayError("rewritten request header is invalid")
                    rewritten_headers.append((name, value))
            encoded = replacement.get("body_base64")
            if not isinstance(encoded, str):
                raise InlineGatewayError("rewritten request body is invalid")
            try:
                rewritten_body = base64.b64decode(encoded, validate=True)
            except ValueError as error:
                raise InlineGatewayError("rewritten request body is not base64") from error
            if len(rewritten_body) > MAX_FORWARD_BYTES:
                raise InlineGatewayError("rewritten request body is too large")
            return rewritten_method, rewritten_path, rewritten_headers, rewritten_body
        raise InlineGatewayError(f"action {action} is invalid during request phase")

    def _forward(
        self,
        *,
        method: str,
        path: str,
        headers: list[tuple[str, str]],
        body: bytes,
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        connection_type = (
            http.client.HTTPSConnection
            if self.upstream.scheme == "https"
            else http.client.HTTPConnection
        )
        connection = connection_type(
            self.upstream.hostname,
            self.upstream.port,
            timeout=self.request_timeout_seconds,
        )
        outgoing = {
            name: value
            for name, value in headers
            if name.lower() not in HOP_BY_HOP and name.lower() != "host"
        }
        outgoing["Host"] = self.upstream.netloc
        upstream_path = self.upstream.path.rstrip("/") + path
        try:
            connection.request(method, upstream_path, body=body or None, headers=outgoing)
            response = connection.getresponse()
            payload = response.read(MAX_FORWARD_BYTES + 1)
            if len(payload) > MAX_FORWARD_BYTES:
                raise InlineGatewayError("upstream response exceeds the gateway limit")
            response_headers = [
                (name, value)
                for name, value in response.getheaders()
                if name.lower() not in HOP_BY_HOP
            ]
            self._increment("upstream_requests")
            return response.status, response_headers, payload
        except InlineGatewayError:
            raise
        except Exception as error:
            raise InlineGatewayError(f"gateway upstream request failed: {error}") from error
        finally:
            connection.close()

    def _apply_response_decision(
        self,
        decision: dict[str, object],
        original: tuple[int, list[tuple[str, str]], bytes],
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        action = _validate_decision(decision)
        if action == "pass":
            return original
        if action == "delay":
            delay = decision.get("delay_ms")
            if not isinstance(delay, int) or not 1 <= delay <= 60000:
                raise InlineGatewayError("defense delay is invalid")
            started = time.monotonic()
            time.sleep(delay / 1000.0)
            self._add_latency(time.monotonic() - started)
            return original
        if action in {"block", "replace-response"}:
            return _replacement(decision.get("response"))
        if action == "terminate-session":
            payload = b'{"detail":"session terminated by defense"}'
            return 403, [("Content-Type", "application/json")], payload
        raise InlineGatewayError(f"action {action} is invalid during response phase")

    def _send(
        self,
        handler: BaseHTTPRequestHandler,
        response: tuple[int, list[tuple[str, str]], bytes],
    ) -> None:
        status, headers, body = response
        handler.send_response(status)
        for name, value in headers:
            if name.lower() == "location":
                value = value.replace(
                    urllib.parse.urlunsplit(
                        (self.upstream.scheme, self.upstream.netloc, "", "", "")
                    ),
                    self.origin,
                    1,
                )
            handler.send_header(name, value)
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(body)

    def _send_error(self, handler: BaseHTTPRequestHandler, error: Exception) -> None:
        self._increment("gateway_defense_errors")
        body = json.dumps(
            {"detail": "defense gateway error", "error_type": type(error).__name__},
            separators=(",", ":"),
        ).encode()
        handler.send_response(503)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(body)

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        self._increment("observed_requests")
        interaction_id = uuid4().hex
        try:
            body = self._read_body(handler)
            headers = list(handler.headers.raw_items())
            request_decision = self._decision(
                self._request_document(
                    handler,
                    interaction_id=interaction_id,
                    body=body,
                )
            )
            selected = self._apply_request_decision(
                request_decision,
                method=handler.command,
                path=handler.path,
                headers=headers,
                body=body,
            )
            if isinstance(selected[0], int):
                self._increment("blocked_requests")
                self._send(handler, selected)
                return
            method, path, outgoing_headers, outgoing_body = selected
            upstream_response = self._forward(
                method=method,
                path=path,
                headers=outgoing_headers,
                body=outgoing_body,
            )
            response_decision = self._decision(
                self._response_document(
                    handler,
                    interaction_id=interaction_id,
                    status=upstream_response[0],
                    headers=upstream_response[1],
                    body=upstream_response[2],
                )
            )
            response = self._apply_response_decision(response_decision, upstream_response)
            if response != upstream_response:
                self._increment("modified_responses")
            self._send(handler, response)
        except Exception as error:
            self._send_error(handler, error)

    def metrics(self) -> dict[str, object]:
        with self._lock:
            own = dict(self._metrics)
            latency = self._latency
        adapter_metrics: dict[str, object] = {}
        if self.adapter is not None:
            adapter_metrics = self.adapter.metrics()
        adapter_errors = int(adapter_metrics.get("defense_errors") or 0)
        result: dict[str, object] = {
            **self.identity,
            "observed_requests": int(own.get("observed_requests", 0)),
            "blocked_requests": int(own.get("blocked_requests", 0)),
            "upstream_requests": int(own.get("upstream_requests", 0)),
            "defense_calls": int(own.get("defense_calls", 0)),
            "defense_errors": int(own.get("gateway_defense_errors", 0)) + adapter_errors,
            "defense_latency_seconds_total": latency,
            "defense_request_timeout_seconds": self.request_timeout_seconds,
            "modified_responses": int(own.get("modified_responses", 0)),
            "defense_action_counts": {
                key.removeprefix("action_"): int(value)
                for key, value in own.items()
                if key.startswith("action_")
            },
            "adapter_metrics": adapter_metrics,
        }
        observed_models = list(adapter_metrics.get("defense_model_ids") or ())
        requested_model = self.identity.get("defense_model_requested_id")
        if not observed_models:
            result["defense_model_identity_match"] = None
        elif requested_model == "haiku":
            result["defense_model_identity_match"] = all(
                "haiku" in str(item).lower() for item in observed_models
            )
        else:
            result["defense_model_identity_match"] = all(
                str(item) == str(requested_model) for item in observed_models
            )
        return result

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=10)
        if self._thread.is_alive():
            raise InlineGatewayError("defense gateway thread did not stop")
        if self.adapter is not None:
            self.adapter.close()


__all__ = [
    "HttpDefenseAdapter",
    "InlineDefenseGateway",
    "InlineGatewayError",
    "MAX_CAPTURE_BYTES",
    "TRUNCATION_POLICY_DIGEST",
]
