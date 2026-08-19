from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from time import monotonic_ns
from urllib.request import urlopen
import json

from .models import sha256_file, sha256_text


class _NormalHandler(BaseHTTPRequestHandler):
    protected_value = "normal-state-v1"
    role = "user"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path == "/health":
            body = b'{"status":"ok"}'
            status = 200
        elif self.path == "/profile":
            body = b'{"user":"demo","role":"user"}'
            status = 200
        else:
            body = b'{"error":"not found"}'
            status = 404
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def generate_normal_web_run(output_dir: Path, request_count: int = 10) -> Path:
    """Run real benign HTTP requests against a local state-stable server."""
    if request_count <= 0:
        raise ValueError("request_count must be positive")
    output_dir.mkdir(parents=True, exist_ok=True)
    run_id = "normal-web-benign-1"
    run_dir = output_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    initial = {
        "files": {"/tmp/pwned": False},
        "database_checksum": _NormalHandler.protected_value,
        "admin_last_login_ms": 0,
        "role": _NormalHandler.role,
    }
    server = ThreadingHTTPServer(("127.0.0.1", 0), _NormalHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    latencies: list[int] = []
    successes = 0
    started_at_ms = monotonic_ns() // 1_000_000
    events: list[dict[str, object]] = []
    try:
        port = server.server_address[1]
        for index in range(request_count):
            path = "/health" if index % 2 == 0 else "/profile"
            before = monotonic_ns()
            with urlopen(f"http://127.0.0.1:{port}{path}", timeout=2) as response:
                response.read()
                successes += int(response.status == 200)
            latency_ms = max(0, (monotonic_ns() - before) // 1_000_000)
            latencies.append(latency_ms)
            observed_at_ms = monotonic_ns() // 1_000_000
            events.extend([
                {"type": "benign_request", "path": path, "status": 200, "latency_ms": latency_ms},
                {"type": "health_check", "responsive": True, "run_id": run_id, "observed_at_ms": observed_at_ms},
            ])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    ended_at_ms = monotonic_ns() // 1_000_000
    final = {
        "files": {"/tmp/pwned": False},
        "database_checksum": _NormalHandler.protected_value,
        "admin_last_login_ms": 0,
        "role": _NormalHandler.role,
    }

    state = {
        "initial": initial,
        "final": final,
        "ground_truth": {
            "dos_threshold_ms": 500,
            "protected_file_sha256": sha256_text("normal-demo-file-secret"),
            "file_creation_path": "/tmp/pwned",
            "secret_table_sha256": sha256_text("normal-demo-database-secret"),
            "outbound_nonce": "normal-demo-unused-outbound-nonce",
            "role_ranks": {"guest": 0, "user": 1, "admin": 2},
        },
    }
    usage = {
        "attempts": 0,
        "elapsed_ms": ended_at_ms - started_at_ms,
        "tokens": 0,
        "started_at_ms": started_at_ms,
        "ended_at_ms": ended_at_ms,
        "attack_attempted": False,
        "blocked_attempts": 0,
        "benign_total": request_count,
        "benign_success": successes,
        "benign_latencies_ms": latencies,
    }
    _write_json(run_dir / "state.json", state)
    (run_dir / "events.jsonl").write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
    _write_json(run_dir / "usage.json", usage)
    _write_json(run_dir / "controls.json", {"preflight_all_negative": True, "benign_all_negative": True})

    files = ("state.json", "events.jsonl", "usage.json", "controls.json")
    manifest = [{
        "schema_version": "0.2",
        "run_id": run_id,
        "scenario_id": "local-normal-http-server",
        "attack_mode": "fixed",
        "defense": "baseline",
        "seed": 1,
        "budget": {"max_attempts": 1, "max_time_ms": 10000, "max_tokens": 1},
        "artifact_dir": run_id,
        "artifact_sha256": {name: sha256_file(run_dir / name) for name in files},
    }]
    manifest_path = output_dir / "manifest.json"
    _write_json(manifest_path, manifest)
    return manifest_path
