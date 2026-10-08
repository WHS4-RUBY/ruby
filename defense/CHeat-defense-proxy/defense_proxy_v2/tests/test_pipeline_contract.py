"""Official Defense -> private CHeaT sidecar trust and telemetry contract."""

import json
import os
import sqlite3
import sys
import tempfile
import uuid
from pathlib import Path
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
_db_dir = tempfile.TemporaryDirectory()
os.environ.update({
    "DEFENSE_DB": str(Path(_db_dir.name) / "defense.db"),
    "DEFENSE_MODE": "off",
    "DECOY_REQUIRE_PLAN": "1",
    "PREFLIGHT": "0",
    "TARGET_PRESET": "nginx-fastapi",
    "BACKEND_TIMEOUT_S": "30",
    "MAZE_DELAY_MS": "0",
    "MAZE_ESC_DELAY_MS": "0",
    "MAZE_ESCALATE_HITS": "1",
    "MAZE_BASE_KB": "1",
    "MAZE_ESC_KB": "1",
})

import Defense_proxy as defense  # noqa: E402

failures = []


def check(label, condition, detail=""):
    print(("PASS " if condition else "FAIL ") + label + (" " + str(detail) if not condition else ""))
    if not condition:
        failures.append(label)


forwarded = []
timeouts = []
_RealAsyncClient = httpx.AsyncClient


class RecordingAsyncClient(_RealAsyncClient):
    def __init__(self, *args, **kwargs):
        timeouts.append(kwargs.get("timeout"))
        super().__init__(*args, **kwargs)


async def backend_request(client, method, url, **kwargs):
    forwarded.append((method, url, kwargs["headers"].copy()))
    return httpx.Response(404 if url.endswith("/backup/a") else 200, text="backend", headers={
        "content-type": "text/plain",
        "X-Ruby-Decoy-Action": "spoofed-action",
        "X-Ruby-Decoy-Strategies": "spoofed-strategy",
    })


run_a, run_b = str(uuid.uuid4()), str(uuid.uuid4())
base_headers = {
    "X-Client-Id": "same-client",
    "X-Ruby-Request-Id": "request-1",
    "X-Ruby-Target-Id": "ruby-shop",
    "X-Ruby-Risk-Score": "0.9",
    "X-Defense-Signal": "internal",
    "Forwarded": "for=bad",
    "X-Forwarded-For": "198.51.100.9",
    "X-Forwarded-Host": "public.example:80",
    "X-Forwarded-Proto": "http",
    "X-Ordinary": "keep-me",
}
with patch.object(_RealAsyncClient, "request", backend_request), \
        patch("proxy_core.httpx.AsyncClient", RecordingAsyncClient):
    client = TestClient(defense.app)
    first = client.get("/plain", headers={
        **base_headers,
        "X-Ruby-Run-Id": run_a,
        "X-Defense-Plan": json.dumps([{"name": "decoy_migration", "params": {}}]),
    })
    later = client.get("/plain", headers={**base_headers, "X-Ruby-Run-Id": run_a})
    other = client.get("/plain", headers={**base_headers, "X-Ruby-Run-Id": run_b})
    bad_origin = client.get("/plain", headers={
        **base_headers,
        "X-Ruby-Run-Id": run_b,
        "X-Forwarded-Host": "bad.example, attacker.example",
        "X-Forwarded-Proto": "javascript",
    })
    health = client.get("/healthz")
    docs = client.get("/docs")
    maze = client.get("/backup/a", headers={
        **base_headers,
        "X-Client-Id": "maze-client",
        "X-Ruby-Run-Id": run_a,
        "X-Defense-Plan": json.dumps([{"name": "maze", "params": {}}]),
    })
    untouched = client.get("/backup/a", headers={
        **base_headers,
        "X-Client-Id": "maze-client",
        "X-Ruby-Run-Id": run_b,
    })

check("planned strategy reported", first.headers.get("x-ruby-decoy-strategies") == "decoy_migration")
check("sticky strategy reported on later request", later.headers.get("x-ruby-decoy-strategies") == "decoy_migration")
check("same client in another run has no sticky strategy", "x-ruby-decoy-strategies" not in other.headers)
check("backend cannot spoof action telemetry", first.headers.get("x-ruby-decoy-action") == "observe")
check("unplanned response body remains passthrough", other.text == "backend")
check("sidecar backend timeout is 30 seconds below upstream Defense limit", set(timeouts) == {30.0}, timeouts)
check("trusted internal headers do not reach backend", not any(
    key.lower().startswith(("x-ruby-", "x-defense-")) or key.lower() in {
        "x-client-id", "forwarded", "x-forwarded-for"
    }
    for _, _, headers in forwarded for key in headers
))
check("public Host and Proto survive", all(
    headers.get("x-forwarded-host") == "public.example:80"
    and headers.get("x-forwarded-proto") == "http"
    for _, _, headers in forwarded[:3]
), forwarded[:1])
check("malformed public origin discarded", not any(
    key.lower() in {"x-forwarded-host", "x-forwarded-proto"}
    for key in forwarded[3][2]
), forwarded[3][2])
check("ordinary header survives", forwarded[0][2].get("x-ordinary") == "keep-me")
check("private health endpoint works without backend", health.status_code == 204 and len(forwarded) == 7)
check("proxy-generated docs are disabled", docs.text == "backend")
check("maze! action retained for dashboard", maze.headers.get("x-ruby-decoy-action") == "maze!", maze.headers)
check("maze stays isolated to original run", untouched.status_code == 404 and
      untouched.headers.get("x-ruby-decoy-action") == "observe")
check("client state separated by run", (run_a, "same-client") in defense._clients
      and (run_b, "same-client") in defense._clients
      and defense._clients[(run_a, "same-client")].recipe == "MIGRATION_TRACES"
      and defense._clients[(run_b, "same-client")].recipe == "")
with sqlite3.connect(defense.DB_PATH) as conn:
    runs = {row[0] for row in conn.execute("SELECT DISTINCT run FROM reqs WHERE client_id='same-client'")}
check("DB rows retain experiment run IDs", {run_a, run_b} <= runs, runs)
check("maze learning also separated by run", defense._mazes[run_a] is not defense._mazes[run_b])

print("\nFAILED:" if failures else "\nALL PASS", failures or "")
sys.exit(1 if failures else 0)
