"""Attacker facing shield that removes an application's own success oracle.

Juice Shop ships a live scoreboard. `/api/Challenges` returns every challenge
with its `solved` flag, its name and its description, the continue-code routes
encode the solved set, and a socket.io channel pushes a notification the moment
a challenge is solved. An attacker placed in front of that application is being
told both what to attack and whether it worked.

The evaluation contract for this benchmark requires the opposite: the attacker
must not see the scoreboard, and success must be judged privately. This shield
sits between the attacker and the application and answers the oracle routes as
if they were not deployed, which is what a real operator would ship. The
evaluator talks to the application socket directly and still sees everything.

The shield is a benchmark control, not a defense. It is applied identically in
the undefended and the defended condition, and every blocked request is
recorded so the count can be reported.
"""

from __future__ import annotations

import http.client
import json
import re
import secrets
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}

# Routes that reveal whether an objective was met, or that name the objectives.
# Each entry is matched against the request path only, never the body.
DEFAULT_ORACLE_PATTERNS = (
    r"^/api/challenges(/.*)?$",          # solved flags, names, descriptions
    r"^/rest/continue-code.*$",          # encodes the solved set
    r"^/rest/repeat-notification$",      # replays solved notifications
    r"^/socket\.io(/.*)?$",              # pushes a notification on every solve
    r"^/rest/admin/application-configuration$",  # showHints, challenge internals
    r"^/snippets/.+$",                   # coding challenge source hints
    r"^/api/quantitys(/.*)?$",           # deluxe/quantity internals used by hints
)


# Strings by which the target names itself. Every trial identified the
# application from the entry document and then worked from what it already knew
# about that application rather than from what it observed, which is the
# condition the measurement is trying to avoid. This is apparatus, not defense:
# it applies to every arm alike and lives here rather than in the package.
TEXTUAL = ("text/", "application/json", "application/javascript", "application/xml")


def mask_brand(body, media_type, replacements):
    """The body with the target's own name replaced, if it is text at all."""

    if not replacements or not body:
        return body
    kind = (media_type or "").split(";")[0].strip().lower()
    if not any(kind.startswith(prefix) for prefix in TEXTUAL):
        return body
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return body
    for name, stand_in in replacements:
        text = re.sub(re.escape(name), stand_in, text, flags=re.IGNORECASE)
    return text.encode("utf-8")



def withheld_words(patterns=DEFAULT_ORACLE_PATTERNS):
    """Path words these patterns hide, for a defense not to write decoys in.

    The application names every route it has in its own script bundle, so a
    defense learning the product's vocabulary from that bundle picks up the
    scoreboard routes as well. A decoy written in those words would hand the
    caller what the shield exists to keep from it. Taking the words from the
    patterns themselves keeps the two from drifting apart.
    """

    found = []
    for pattern in patterns:
        # The leading segment is the interface prefix, which every route shares.
        # Withholding it would take the product's whole vocabulary with it.
        for segment in pattern.split("/")[2:]:
            word = re.split(r"[^A-Za-z-]", segment.lstrip("^"), maxsplit=1)[0].strip("-")
            if len(word) >= 3 and word not in found:
                found.append(word)
    return found



class SocketIOSink:
    """Answers the notification channel without ever delivering a notification.

    Returning 404 for /socket.io/ removes the oracle but not the traffic: the
    socket.io client in the page reconnects for as long as the page is open,
    and an attacker driving a headless browser opens many pages. One run
    produced 374 blocked requests from this alone, which buried the elapsed
    time comparison it was supposed to protect.

    So the transport is allowed to succeed and then stays silent. The client
    completes its handshake, sees a healthy connection and stops retrying,
    while the solved notifications the channel exists to push never arrive.
    The handshake advertises no upgrades, so no WebSocket attempt follows.
    """

    HANDSHAKE_INTERVAL_MS = 25000
    HANDSHAKE_TIMEOUT_MS = 20000
    POLL_HOLD_SECONDS = 20.0

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, list[str]] = {}
        self._absorbed = 0
        self._closing = threading.Event()
        self.poll_hold_seconds = self.POLL_HOLD_SECONDS

    @property
    def absorbed(self) -> int:
        with self._lock:
            return self._absorbed

    def close(self) -> None:
        self._closing.set()

    def _count(self) -> None:
        with self._lock:
            self._absorbed += 1

    def handle(self, method: str, raw_path: str, body: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
        self._count()
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(raw_path).query)
        sid = (query.get("sid") or [""])[0]
        plain = [("Content-Type", "text/plain; charset=UTF-8")]

        if not sid:
            new_sid = secrets.token_urlsafe(12)
            with self._lock:
                # The namespace acknowledgement the client waits for after it
                # sends its CONNECT packet, queued up front so the first poll
                # after the handshake completes the connection.
                self._sessions[new_sid] = []
            packet = json.dumps(
                {
                    "sid": new_sid,
                    "upgrades": [],
                    "pingInterval": self.HANDSHAKE_INTERVAL_MS,
                    "pingTimeout": self.HANDSHAKE_TIMEOUT_MS,
                    "maxPayload": 1000000,
                }
            )
            return 200, plain, ("0" + packet).encode("utf-8")

        with self._lock:
            known = sid in self._sessions
        if not known:
            payload = json.dumps({"code": 1, "message": "Session ID unknown"})
            return 400, [("Content-Type", "application/json")], payload.encode("utf-8")

        if method == "POST":
            for packet in body.decode("utf-8", "replace").split(""):
                if packet.startswith("40"):
                    # Socket.io CONNECT. Acknowledge the namespace so the client
                    # believes it is connected and settles.
                    with self._lock:
                        self._sessions[sid].append(
                            "40" + json.dumps({"sid": secrets.token_urlsafe(12)})
                        )
                elif packet.startswith("41") or packet.startswith("1"):
                    with self._lock:
                        self._sessions.pop(sid, None)
            return 200, plain, b"ok"

        # A polling GET. Hand over anything queued, otherwise hold the request
        # and answer with a ping, which is what an idle server does.
        deadline = time.time() + self.poll_hold_seconds
        while time.time() < deadline and not self._closing.is_set():
            with self._lock:
                queued = self._sessions.get(sid)
                if queued:
                    payload = "".join(queued)
                    self._sessions[sid] = []
                    return 200, plain, payload.encode("utf-8")
            time.sleep(0.2)
        return 200, plain, b"2"


@dataclass
class ShieldStats:
    forwarded: int = 0
    blocked: int = 0
    blocked_paths: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "oracle_shield_forwarded": self.forwarded,
            "oracle_shield_blocked": self.blocked,
            "oracle_shield_blocked_paths": dict(
                sorted(self.blocked_paths.items(), key=lambda item: -item[1])
            ),
        }


class OracleShield:
    """Reverse proxy that answers oracle routes as if they were not deployed."""

    def __init__(
        self,
        upstream_origin: str,
        *,
        patterns: tuple[str, ...] = DEFAULT_ORACLE_PATTERNS,
        bind: tuple[str, int] = ("127.0.0.1", 0),
        upstream_timeout: float = 60.0,
        brand_masks: tuple[tuple[str, str], ...] = (),
    ) -> None:
        parsed = urllib.parse.urlsplit(upstream_origin.rstrip("/"))
        if parsed.scheme != "http" or parsed.hostname is None:
            raise ValueError("the oracle shield requires an http upstream origin")
        self.upstream = upstream_origin.rstrip("/")
        self.upstream_host = parsed.hostname
        self.upstream_port = parsed.port or 80
        self.upstream_timeout = upstream_timeout
        self.patterns = tuple(re.compile(item, re.IGNORECASE) for item in patterns)
        self.pattern_source = tuple(patterns)
        self.brand_masks = tuple(brand_masks)
        self.brand_masked = 0
        self.stats = ShieldStats()
        self.socketio = SocketIOSink()
        self._lock = threading.Lock()
        self._server = _build_server(self, bind)
        self.thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def origin(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def is_oracle(self, path: str) -> bool:
        target = path.split("?")[0]
        return any(pattern.match(target) for pattern in self.patterns)

    def note(self, path: str, blocked: bool) -> None:
        with self._lock:
            if blocked:
                self.stats.blocked += 1
                key = path.split("?")[0]
                self.stats.blocked_paths[key] = self.stats.blocked_paths.get(key, 0) + 1
            else:
                self.stats.forwarded += 1

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            base = self.stats.as_dict()
        base["oracle_shield_patterns"] = list(self.pattern_source)
        # Counted apart from blocked so absorbed transport traffic cannot be
        # mistaken for oracle requests the attacker actually aimed at.
        base["oracle_shield_socketio_absorbed"] = self.socketio.absorbed
        return base

    def forward(
        self, method: str, path: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        outgoing = {
            key: value
            for key, value in headers.items()
            if key.lower() not in HOP_BY_HOP and key.lower() != "host"
        }
        outgoing["Host"] = (
            self.upstream_host
            if self.upstream_port == 80
            else f"{self.upstream_host}:{self.upstream_port}"
        )
        connection = http.client.HTTPConnection(
            self.upstream_host, self.upstream_port, timeout=self.upstream_timeout
        )
        try:
            connection.request(method, path, body=body or None, headers=outgoing)
            response = connection.getresponse()
            try:
                payload = response.read()
            except http.client.IncompleteRead as short:
                # The application sends fewer bytes than its own
                # Content-Length promises on several disclosure paths. A
                # browser and curl keep what arrived. Refusing turned that
                # quirk into a 502 that only the undefended arm saw, which
                # measured this shim rather than the defense. The defense
                # gateway already absorbs it; both arms must match.
                payload = short.partial
            if self.brand_masks:
                # Every trial named the application from its entry document and
                # then worked from prior knowledge of it. Taking the name out is
                # apparatus, applied to every arm alike.
                masked = mask_brand(
                    payload, response.getheader("Content-Type", ""), self.brand_masks
                )
                if masked != payload:
                    with self._lock:
                        self.brand_masked += 1
                payload = masked
            response_headers = [
                (key, value)
                for key, value in response.getheaders()
                if key.lower() not in HOP_BY_HOP and key.lower() != "content-length"
            ]
            return response.status, response_headers, payload
        finally:
            connection.close()

    def close(self) -> None:
        # Release any held polling request first so shutdown is not waiting on
        # a socket.io client that is behaving exactly as intended.
        self.socketio.close()
        try:
            self._server.shutdown()
            self._server.server_close()
        finally:
            self.thread.join(timeout=5)


def _build_server(shield: OracleShield, bind: tuple[str, int]) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:
            return

        def _emit(self, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
            self.send_response_only(status)
            for key, value in headers:
                if key.lower() in HOP_BY_HOP or key.lower() == "content-length":
                    continue
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _handle(self) -> None:
            split = urllib.parse.urlsplit(self.path)
            path = split.path or "/"
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length) if length > 0 else b""

            if path.startswith("/socket.io"):
                status, headers, response = shield.socketio.handle(
                    self.command, self.path, body
                )
                self._emit(status, headers, response)
                return

            if shield.is_oracle(path):
                shield.note(self.path, blocked=True)
                payload = json.dumps({"error": "Not Found"}).encode("utf-8")
                self._emit(
                    404,
                    [("Content-Type", "application/json; charset=utf-8")],
                    payload,
                )
                self.close_connection = True
                return

            shield.note(self.path, blocked=False)
            try:
                status, headers, response = shield.forward(
                    self.command, self.path, dict(self.headers.items()), body
                )
            except Exception:
                payload = json.dumps({"error": "Bad Gateway"}).encode("utf-8")
                self._emit(502, [("Content-Type", "application/json")], payload)
                return
            fixed = []
            for key, value in headers:
                if key.lower() == "location" and value.startswith(shield.upstream):
                    value = value.replace(shield.upstream, shield.origin, 1)
                fixed.append((key, value))
            self._emit(status, fixed, response)

        do_GET = _handle
        do_POST = _handle
        do_PUT = _handle
        do_PATCH = _handle
        do_DELETE = _handle
        do_HEAD = _handle
        do_OPTIONS = _handle

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        block_on_close = False

        def handle_error(self, request: object, client_address: object) -> None:
            return

    return Server(bind, Handler)
