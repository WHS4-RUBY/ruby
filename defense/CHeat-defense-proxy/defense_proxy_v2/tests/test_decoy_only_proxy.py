"""An overlay client's marked maze request must never touch the real site."""

import json
import os
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
    "MAZE_DELAY_MS": "0",
    "MAZE_ESC_DELAY_MS": "0",
    "ESCALATE_DELAY_MS": "0",
    "MAZE_BASE_KB": "1",
})

import Defense_proxy as defense  # noqa: E402


forwarded = []


async def backend_request(client, method, url, **kwargs):
    forwarded.append((method, url, kwargs["headers"].copy()))
    return httpx.Response(200, text="real backend")


headers = {
    "X-Client-Id": "overlay-client",
    "X-Ruby-Run-Id": str(uuid.uuid4()),
    "X-Defense-Plan": json.dumps([{"name": "decoy_maze", "params": {}}]),
    "X-Defense-Decoy-Only": "1",
}

with patch.object(httpx.AsyncClient, "request", backend_request):
    client = TestClient(defense.app)
    maze = client.get("/internal/ops/runbook", headers=headers)
    non_maze = client.get("/api/products", headers=headers)
    marked_calls = len(forwarded)
    other_value = client.get("/api/products", headers={
        **headers, "X-Defense-Decoy-Only": "01",
    })

assert maze.status_code == 200 and maze.text.startswith("# /internal/ops/runbook"), (
    maze.status_code, maze.text[:80]
)
assert maze.headers.get("x-ruby-decoy-strategies") == "decoy_maze", maze.headers
assert non_maze.status_code == 404, (non_maze.status_code, non_maze.text[:80])
assert marked_calls == 0, forwarded
assert other_value.status_code == 200 and other_value.text == "real backend"
assert len(forwarded) == 1, forwarded
assert not any(key.lower() == "x-defense-decoy-only" for key in forwarded[0][2]), forwarded

print("PASS decoy-only maze and non-maze paths never reach real backend")
print("PASS exact marker value is required and internal marker stays private")
