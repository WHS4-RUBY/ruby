from __future__ import annotations

import argparse
import hashlib
import json
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from defense_runtime_v1 import (
    REGISTRY_PATH,
    defense_front,
    registered_conditions,
    validate_defense_registry,
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


class _SmokeUpstream:
    def __init__(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:
                body = json.dumps(
                    {"status": "upstream-ok", "path": self.path},
                    separators=(",", ":"),
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.origin = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def _request(origin: str, path: str) -> tuple[int, str]:
    request = urllib.request.Request(origin.rstrip("/") + path, method="GET")
    try:
        response = urllib.request.build_opener(_NoRedirect).open(request, timeout=30)
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8", errors="replace")
    with response:
        return response.status, response.read().decode("utf-8", errors="replace")


def _write(value: dict[str, object], output: Path | None) -> None:
    text = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
    print(text, end="")


def list_defenses(registry: Path) -> dict[str, object]:
    validated = validate_defense_registry(registry)
    return {
        "status": "valid",
        "registry": validated["registry"],
        "registry_digest": validated["registry_digest"],
        "conditions": [
            {"condition_id": "undefended", "driver": "direct"},
            {"condition_id": "proxy-only", "driver": "benchmark-inline-gateway"},
            *validated["conditions"],
        ],
    }


def smoke(
    *,
    condition: str,
    registry: Path,
    request_path: str,
    expected_status: int,
) -> dict[str, object]:
    if (
        not request_path.startswith("/")
        or request_path.startswith("//")
        or "\\" in request_path
        or any(character.isspace() for character in request_path)
    ):
        raise ValueError("smoke request path must be a target-relative path")
    if condition not in registered_conditions(registry):
        raise ValueError(f"unregistered defense condition: {condition}")
    upstream = _SmokeUpstream()
    gateway = None
    try:
        builder = defense_front(condition, registry)
        if builder is None:
            origin = upstream.origin
        else:
            gateway = builder(
                upstream_origin=upstream.origin,
                secrets=[],
                accounts=[],
                trial_id=hashlib.sha256(
                    f"defense-smoke:{condition}".encode()
                ).hexdigest()[:32],
            )
            origin = gateway.origin
        status, body = _request(origin, request_path)
        metrics = gateway.metrics() if gateway is not None else {}
        result = {
            "status": "passed" if status == expected_status else "failed",
            "condition": condition,
            "request_path": request_path,
            "expected_status": expected_status,
            "observed_status": status,
            "response_body": body[:2048],
            "defense_metrics": metrics,
        }
        if status != expected_status:
            raise RuntimeError(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return result
    finally:
        if gateway is not None:
            gateway.close()
        upstream.close()


def serve(
    *,
    condition: str,
    registry: Path,
    upstream: str,
    listen_port: int,
) -> None:
    builder = defense_front(condition, registry)
    if builder is None:
        raise ValueError("serve requires proxy-only or a registered defense condition")
    gateway = builder(
        upstream_origin=upstream,
        secrets=[],
        accounts=[],
        trial_id=hashlib.sha256(
            f"defense-serve:{condition}:{time.time_ns()}".encode()
        ).hexdigest()[:32],
        listen_port=listen_port,
    )
    try:
        print(
            json.dumps(
                {
                    "status": "ready",
                    "condition": condition,
                    "origin": gateway.origin,
                    "upstream": upstream,
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            flush=True,
        )
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        gateway.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manage pluggable RUBY defenses")
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list")
    subparsers.add_parser("validate")
    smoke_parser = subparsers.add_parser("smoke")
    smoke_parser.add_argument("--condition", required=True)
    smoke_parser.add_argument("--request-path", default="/normal")
    smoke_parser.add_argument("--expected-status", type=int, default=200)
    smoke_parser.add_argument("--output", type=Path)
    serve_parser = subparsers.add_parser("serve")
    serve_parser.add_argument("--condition", required=True)
    serve_parser.add_argument("--upstream", default="http://127.0.0.1:18080")
    serve_parser.add_argument("--listen-port", type=int, default=18082)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "list":
        _write(list_defenses(args.registry), None)
        return 0
    if args.command == "validate":
        _write(validate_defense_registry(args.registry), None)
        return 0
    if args.command == "smoke":
        result = smoke(
            condition=args.condition,
            registry=args.registry,
            request_path=args.request_path,
            expected_status=args.expected_status,
        )
        _write(result, args.output)
        return 0
    if args.command == "serve":
        serve(
            condition=args.condition,
            registry=args.registry,
            upstream=args.upstream,
            listen_port=args.listen_port,
        )
        return 0
    raise AssertionError(f"unsupported command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
