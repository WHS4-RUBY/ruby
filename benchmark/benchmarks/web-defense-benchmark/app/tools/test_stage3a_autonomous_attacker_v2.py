from __future__ import annotations

import json
import unittest

import httpx

from run_stage3a_codex_http_pilot import (
    ATTACKER_PROFILE,
    SCHEMA,
    compact_request_ledger,
    load_attacker_profile,
    request_arguments,
)


class AutonomousAttackerV2Test(unittest.TestCase):
    def test_profile_is_generic_and_has_no_benchmark_answers(self) -> None:
        profile = load_attacker_profile()
        serialized = json.dumps(profile, ensure_ascii=False).lower()
        for forbidden in (
            "mock-integration",
            "internal/metadata",
            "admin-audit.csv",
            "internal-admin-settlement",
            "visibility = 'private'",
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(
            {
                "scenario_specific_endpoints": False,
                "scenario_specific_payloads": False,
                "hidden_resource_names": False,
                "private_evaluator_state": False,
            },
            profile["answer_leakage_policy"],
        )
        self.assertTrue(ATTACKER_PROFILE.is_file())

    def test_action_schema_requires_persistent_memory(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertIn("memory", schema["required"])
        memory = schema["properties"]["memory"]
        self.assertEqual(
            {"observations", "hypotheses", "failed_attempts", "next_steps"},
            set(memory["required"]),
        )
        action = schema["properties"]["actions"]["items"]
        self.assertTrue(
            {"body_json", "body_form", "body_multipart"}.issubset(action["required"])
        )

    def test_request_ledger_preserves_attempt_and_compacts_response(self) -> None:
        ledger = compact_request_ledger(
            [
                {
                    "session": "seller",
                    "method": "POST",
                    "path": "/api/example?q=one",
                    "headers": None,
                    "body_json": '{"value":"probe"}',
                    "body_form": None,
                    "status": 403,
                    "response": "denied\nby policy",
                },
                {
                    "session": "seller",
                    "method": "POST",
                    "path": "/api/example?q=two",
                    "headers": None,
                    "body_json": '{"value":"control"}',
                    "body_form": None,
                    "status": 200,
                    "response": "accepted",
                },
            ],
            [{"round": 1, "reason": "body_json is not valid JSON"}],
        )
        self.assertEqual(
            [{"method": "POST", "route": "/api/example", "statuses": [200, 403]}],
            ledger["observed_endpoints"],
        )
        self.assertEqual("denied by policy", ledger["attempted_requests"][0]["response_signal"])
        self.assertEqual('{"value":"probe"}', ledger["attempted_requests"][0]["body_json"])
        self.assertEqual(1, len(ledger["local_action_rejections"]))

    def test_request_arguments_supports_json_and_form_without_ambiguity(self) -> None:
        self.assertEqual(
            {"json": {"role": "admin"}},
            request_arguments({"body_json": '{"role":"admin"}', "body_form": None}),
        )
        self.assertEqual(
            {
                "content": b"role=admin&remember=true",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            },
            request_arguments(
                {"body_json": None, "body_form": "role=admin&remember=true"}
            ),
        )
        with self.assertRaisesRegex(ValueError, "mutually exclusive"):
            request_arguments({"body_json": "{}", "body_form": "role=admin"})

    def test_request_arguments_builds_bounded_text_multipart(self) -> None:
        arguments = request_arguments(
            {
                "headers": None,
                "body_json": None,
                "body_form": None,
                "body_multipart": {
                    "fields": [{"name": "product_id", "value": "ruby-camera"}],
                    "files": [
                        {
                            "field_name": "document",
                            "filename": "preview.html",
                            "content_type": "text/html",
                            "content_text": "<p>controlled</p>",
                        }
                    ],
                },
            }
        )
        self.assertEqual(
            {
                "files": [
                    ("product_id", (None, "ruby-camera")),
                    (
                        "document",
                        ("preview.html", b"<p>controlled</p>", "text/html"),
                    )
                ],
            },
            arguments,
        )
        captured: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            request.read()
            return httpx.Response(204)

        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            response = client.post("http://local.test/upload", **arguments)
        self.assertEqual(204, response.status_code)
        self.assertTrue(captured[0].headers["content-type"].startswith("multipart/form-data;"))


if __name__ == "__main__":
    unittest.main()
