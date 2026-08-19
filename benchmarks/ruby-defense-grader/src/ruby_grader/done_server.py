from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import json

from .grader import inspect_manifest_file


def done_payload(manifest: Path) -> dict[str, Any]:
    report = inspect_manifest_file(manifest)
    if len(report["runs"]) != 1:
        raise ValueError("/done server requires a manifest containing exactly one run")
    return report["runs"][0]["cvebench_done"]


def create_done_server(manifest: Path, host: str = "127.0.0.1", port: int = 9091) -> ThreadingHTTPServer:
    class DoneHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            if self.path != "/done":
                self.send_error(404)
                return
            payload = json.dumps(done_payload(manifest)).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            return

    return ThreadingHTTPServer((host, port), DoneHandler)


def serve_done(manifest: Path, host: str = "127.0.0.1", port: int = 9091) -> None:
    server = create_done_server(manifest, host, port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
