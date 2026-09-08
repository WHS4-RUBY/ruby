from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = PROJECT_ROOT / "app"
sys.path.insert(0, str(APP_ROOT / "tools"))

from defense_runtime_v1 import (  # noqa: E402
    DefenseRuntimeError,
    defense_front,
    registered_conditions,
    registered_defense_source_files,
    validate_defense_registry,
)


class _Server:
    def __init__(self, handler_type: type[BaseHTTPRequestHandler]) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler_type)
        self.origin = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class _UpstreamHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = json.dumps({"path": self.path}, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class DefenseRuntimeV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        manifest_path = APP_ROOT / "configs" / "stage3a-defense-static-guard-v1.json"
        self.manifest_digest = "sha256:" + hashlib.sha256(
            manifest_path.read_bytes()
        ).hexdigest()
        self.adapter_state = {
            "reset_count": 0,
            "decision_count": 0,
            "bad_identity": False,
            "invalid_decision": False,
            "trial_ids": [],
        }
        state = self.adapter_state
        manifest_digest = self.manifest_digest

        class AdapterHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _json(self, status: int, value: dict[str, object]) -> None:
                body = json.dumps(value, separators=(",", ":")).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                if self.path == "/v2/health":
                    self._json(
                        200,
                        {
                            "status": "ready",
                            "adapter_id": (
                                "wrong-defense"
                                if state["bad_identity"]
                                else "ruby-static-request-guard"
                            ),
                            "version": "2.0.0",
                            "manifest_digest": manifest_digest,
                        },
                    )
                    return
                if self.path == "/v2/metrics":
                    self._json(
                        200,
                        {
                            "adapter_decisions": state["decision_count"],
                            "adapter_resets": state["reset_count"],
                            "defense_errors": 0,
                        },
                    )
                    return
                self._json(404, {"detail": "not found"})

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                value = json.loads(self.rfile.read(length) or b"{}")
                if self.path == "/v2/reset":
                    state["reset_count"] += 1
                    self._json(200, {"status": "reset"})
                    return
                if self.path != "/v2/decision":
                    self._json(404, {"detail": "not found"})
                    return
                state["decision_count"] += 1
                state["trial_ids"].append(value.get("trial_id"))
                if state["invalid_decision"]:
                    self._json(200, {"action": "pass"})
                    return
                if (
                    value.get("phase") == "request"
                    and "/blocked" in value["http"]["path_and_query"]
                ):
                    body = base64.b64encode(b'{"detail":"blocked"}').decode()
                    self._json(
                        200,
                        {
                            "contract_version": "2.0.0",
                            "action": "block",
                            "reason_code": "test.blocked",
                            "response": {
                                "status_code": 403,
                                "headers": {"content-type": ["application/json"]},
                                "body_base64": body,
                            },
                        },
                    )
                    return
                self._json(
                    200,
                    {
                        "contract_version": "2.0.0",
                        "action": "pass",
                        "reason_code": "test.pass",
                    },
                )

            def log_message(self, format, *args):
                return

        self.adapter = _Server(AdapterHandler)
        self.upstream = _Server(_UpstreamHandler)
        self.temp = tempfile.TemporaryDirectory(dir=PROJECT_ROOT)
        self.registry_path = Path(self.temp.name) / "external-registry.json"
        self.registry_path.write_text(
            json.dumps(
                {
                    "registry_version": 2,
                    "conditions": {
                        "external-test": {
                            "driver": "external-http",
                            "path_scope": "benchmark",
                            "manifest_path": "app/configs/stage3a-defense-static-guard-v1.json",
                            "lifecycle_path": "app/configs/stage3a-inline-defense-lifecycle-v1.json",
                            "endpoint": self.adapter.origin,
                            "secret_env_names": [],
                        }
                    },
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()
        self.adapter.close()
        self.upstream.close()

    @staticmethod
    def _status(url: str) -> tuple[int, str]:
        try:
            response = urllib.request.urlopen(url, timeout=5)
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode()
        with response:
            return response.status, response.read().decode()

    def _gateway(self):
        return defense_front("external-test", self.registry_path)(
            upstream_origin=self.upstream.origin,
            secrets=["must-not-be-sent"],
            accounts=[{"password": "also-private"}],
            trial_id="a" * 32,
        )

    def test_external_adapter_is_attached_by_registry_only(self) -> None:
        report = validate_defense_registry(self.registry_path)
        self.assertEqual("external-test", report["conditions"][0]["condition_id"])
        gateway = self._gateway()
        try:
            self.assertEqual((200, '{"path":"/normal"}'), self._status(gateway.origin + "/normal"))
            self.assertEqual((403, '{"detail":"blocked"}'), self._status(gateway.origin + "/blocked"))
            metrics = gateway.metrics()
            self.assertEqual(0, metrics["defense_errors"])
            self.assertEqual(1, metrics["blocked_requests"])
            self.assertEqual(3, metrics["defense_calls"])
            self.assertEqual({"pass": 2, "block": 1}, metrics["defense_action_counts"])
            self.assertEqual(["a" * 32] * 3, self.adapter_state["trial_ids"])
            self.assertNotIn("must-not-be-sent", json.dumps(self.adapter_state))
            self.assertNotIn("also-private", json.dumps(self.adapter_state))
        finally:
            gateway.close()

    def test_adapter_identity_mismatch_stops_before_gateway(self) -> None:
        self.adapter_state["bad_identity"] = True
        with self.assertRaisesRegex(DefenseRuntimeError, "identity mismatch"):
            self._gateway()

    def test_invalid_adapter_decision_returns_503_and_counts_error(self) -> None:
        self.adapter_state["invalid_decision"] = True
        gateway = self._gateway()
        try:
            status, body = self._status(gateway.origin + "/normal")
            self.assertEqual(503, status)
            self.assertIn("defense gateway error", body)
            self.assertEqual(1, gateway.metrics()["defense_errors"])
        finally:
            gateway.close()

    def test_reset_runs_for_every_new_trial(self) -> None:
        first = self._gateway()
        first.close()
        second = self._gateway()
        second.close()
        self.assertEqual(2, self.adapter_state["reset_count"])

    def test_proxy_only_uses_same_no_defense_source(self) -> None:
        gateway = defense_front("proxy-only", self.registry_path)(
            upstream_origin=self.upstream.origin,
            secrets=[],
            accounts=[],
            trial_id="b" * 32,
        )
        try:
            self.assertEqual(200, self._status(gateway.origin + "/normal")[0])
            self.assertEqual("benchmark-inline-gateway", gateway.metrics()["defense_runtime_driver"])
        finally:
            gateway.close()
        inputs = registered_defense_source_files(
            ["undefended", "proxy-only"], self.registry_path
        )
        self.assertIn(self.registry_path.resolve(), inputs)

    def test_registry_rejects_reserved_condition(self) -> None:
        value = json.loads(self.registry_path.read_text(encoding="utf-8"))
        value["conditions"]["proxy-only"] = value["conditions"].pop("external-test")
        self.registry_path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(DefenseRuntimeError, "reserved"):
            registered_conditions(self.registry_path)


if __name__ == "__main__":
    unittest.main()
