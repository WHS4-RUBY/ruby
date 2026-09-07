# -*- coding: utf-8 -*-
"""공격자 상자가 밖으로 나갈 수 있는 유일한 길이다.

공격자는 자율 에이전트라 모델과 이야기해야 한다. 그런데 모델에 닿는 길을 열어
주면 인터넷 전체가 열린다. 그러면 공격 표면이 아닌 곳까지 재게 된다.

이 프록시가 두 가지만 통과시킨다.

- 모델 통제 평면으로 가는 CONNECT
- 대상 서비스의 공개 출처로 가는 평문 HTTP

공격자 망은 internal 이라 이 프록시 말고는 나갈 길이 없다. 정책은 프롬프트 문장이
아니라 망 구조와 이 파일이 강제한다. 거절한 주소는 세어서 시행 기록에 남긴다.
"""
from __future__ import annotations

import http.client
import json
import os
import select
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urlunsplit

CONTROL_PLANE_SUFFIXES = ("anthropic.com", "claude.ai")
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

TARGET = os.environ.get("RUBY_ATTACKER_TARGET_ORIGIN", "").rstrip("/")
LISTEN_PORT = int(os.environ.get("RUBY_ATTACKER_PROXY_PORT", "3128"))
DENIED_PATH = os.environ.get("RUBY_ATTACKER_DENIED_PATH", "/var/log/denied.json")

_parsed = urlsplit(TARGET)
if _parsed.scheme != "http" or _parsed.hostname is None:
    raise SystemExit("RUBY_ATTACKER_TARGET_ORIGIN must be a plain HTTP origin")
TARGET_HOST = _parsed.hostname
TARGET_PORT = _parsed.port or 80

_denied: list[str] = []
_lock = threading.Lock()


def _is_control_plane(host: str, port: int) -> bool:
    normalized = host.rstrip(".").lower()
    return port == 443 and any(
        normalized == suffix or normalized.endswith("." + suffix)
        for suffix in CONTROL_PLANE_SUFFIXES
    )


def _record(target: str) -> None:
    with _lock:
        _denied.append(target)
        try:
            with open(DENIED_PATH, "w", encoding="utf-8") as handle:
                json.dump({"denied": _denied}, handle, ensure_ascii=False)
        except OSError:
            pass


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def _refuse(self, target: str) -> None:
        _record(target)
        body = b"blocked: outside the engagement scope\n"
        self.send_response(403)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.close_connection = True

    def _forward(self) -> None:
        requested = urlsplit(self.path)
        port = requested.port or (443 if requested.scheme == "https" else 80)
        if (
            requested.scheme != "http"
            or requested.hostname != TARGET_HOST
            or port != TARGET_PORT
        ):
            self._refuse(self.path)
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else None
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in HOP_BY_HOP and key.lower() != "host"
        }
        headers["Host"] = (
            TARGET_HOST if TARGET_PORT == 80 else f"{TARGET_HOST}:{TARGET_PORT}"
        )
        path = urlunsplit(("", "", requested.path or "/", requested.query, ""))
        connection = http.client.HTTPConnection(TARGET_HOST, TARGET_PORT, timeout=60)
        try:
            connection.request(self.command, path, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read()
            self.send_response(response.status, response.reason)
            for key, value in response.getheaders():
                if key.lower() not in HOP_BY_HOP | {"content-length"}:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)
        except OSError as error:
            self.send_error(502, f"upstream failed: {error}")
        finally:
            connection.close()

    do_GET = _forward
    do_POST = _forward
    do_PUT = _forward
    do_PATCH = _forward
    do_DELETE = _forward
    do_HEAD = _forward
    do_OPTIONS = _forward

    def do_CONNECT(self) -> None:
        self.close_connection = True
        try:
            host, raw_port = self.path.rsplit(":", 1)
            port = int(raw_port)
        except (ValueError, TypeError):
            self.send_error(400, "invalid CONNECT target")
            return
        if not _is_control_plane(host, port):
            self._refuse(self.path)
            return
        try:
            upstream = socket.create_connection((host, port), timeout=30)
        except OSError as error:
            self.send_error(502, f"tunnel failed: {error}")
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        client = self.connection
        try:
            while True:
                readable, _, _ = select.select([client, upstream], [], [], 60)
                if not readable:
                    break
                for source in readable:
                    other = upstream if source is client else client
                    chunk = source.recv(65536)
                    if not chunk:
                        return
                    other.sendall(chunk)
        except OSError:
            return
        finally:
            upstream.close()


def main() -> int:
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)
    server.daemon_threads = True
    print(
        f"egress proxy listening on {LISTEN_PORT}, target {TARGET}",
        file=sys.stderr,
        flush=True,
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
