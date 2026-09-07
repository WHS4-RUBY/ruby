from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from jsonschema import Draft202012Validator

from app.tools.autonomous_experiment_v2 import (
    ActionExecutor,
    classify_trial_status,
    minimum_repetitions_for_margin,
    paired_schedule,
    parse_claude_usage,
    parse_codex_usage,
    redact_value,
    validate_model_identity,
    validate_pair,
    wilson_interval,
)


class AutonomousExperimentV2Tests(unittest.TestCase):
    def test_action_schema_accepts_http_browser_upload_and_concurrency(self) -> None:
        schema = json.loads(
            Path("app/configs/stage3a-attacker-action-v2.schema.json").read_text(
                encoding="utf-8"
            )
        )
        actions = {
            "actions": [
                {
                    "kind": "http",
                    "session": "customer_a",
                    "method": "POST",
                    "path": "/api/upload",
                    "headers": None,
                    "body_json": None,
                    "body_form": None,
                    "body_multipart": {
                        "fields": [{"name": "kind", "value": "document"}],
                        "files": [
                            {
                                "field_name": "file",
                                "filename": "test.html",
                                "content_type": "text/html",
                                "content_text": "<p>test</p>",
                                "content_base64": None,
                                "content_zip_entries": None,
                            }
                        ],
                    },
                    "concurrency_group": "race_a",
                    "browser_html": None,
                    "browser_wait_ms": 0,
                },
                {
                    "kind": "browser",
                    "session": "victim",
                    "method": "GET",
                    "path": "/account",
                    "headers": None,
                    "body_json": None,
                    "body_form": None,
                    "body_multipart": None,
                    "concurrency_group": None,
                    "browser_html": "<form action='{{TARGET_ORIGIN}}/api/action'></form>",
                    "browser_wait_ms": 100,
                },
            ],
            "stop": False,
            "summary": "continue",
            "memory": {
                "observations": [],
                "hypotheses": [],
                "failed_attempts": [],
                "next_steps": [],
            },
        }
        self.assertEqual([], list(Draft202012Validator(schema).iter_errors(actions)))

    def test_redaction_removes_named_and_structured_secrets(self) -> None:
        value = {
            "password": "fixed-password",
            "body": "Authorization: Bearer abc.def.ghi\nCookie: session=hello",
            "nested": ["fixed-password", "safe"],
        }
        redacted = redact_value(value, ("fixed-password",))
        rendered = json.dumps(redacted)
        self.assertNotIn("fixed-password", rendered)
        self.assertNotIn("abc.def.ghi", rendered)
        self.assertNotIn("session=hello", rendered)
        self.assertIn("safe", rendered)

    def test_provider_usage_is_parsed_without_cross_provider_conversion(self) -> None:
        codex = parse_codex_usage(
            '{"type":"turn.completed","usage":{"input_tokens":10,"cached_input_tokens":3,"output_tokens":4,"reasoning_tokens":2}}\n'
        )
        claude, models = parse_claude_usage(
            json.dumps(
                {
                    "modelUsage": {
                        "claude-opus-5": {
                            "inputTokens": 20,
                            "cacheReadInputTokens": 6,
                            "outputTokens": 8,
                        }
                    }
                }
            )
        )
        self.assertEqual((10, 3, 4, 2), tuple(codex.__dict__.values()))
        self.assertEqual((20, 6, 8, 0), tuple(claude.__dict__.values()))
        self.assertEqual(("claude-opus-5",), models)

    def test_model_identity_rules_allow_only_the_sealed_primary_models(self) -> None:
        self.assertEqual(
            "gpt-5.6-sol", validate_model_identity("codex", ["gpt-5.6-sol"])
        )
        self.assertEqual(
            "claude-opus-5-20260801",
            validate_model_identity(
                "claude", ["claude-haiku-4-5", "claude-opus-5-20260801"]
            ),
        )
        with self.assertRaises(ValueError):
            validate_model_identity("codex", ["gpt-5.5"])

    def test_five_runs_are_qualification_not_a_precise_final_estimate(self) -> None:
        lower, upper = wilson_interval(3, 5)
        self.assertLess(lower, 0.25)
        self.assertGreater(upper, 0.85)
        self.assertEqual(97, minimum_repetitions_for_margin(0.1))

    def test_pair_schedule_is_deterministic_and_adjacent(self) -> None:
        first = paired_schedule(["one", "two"], ["codex", "claude"], 2, 991)
        second = paired_schedule(["one", "two"], ["codex", "claude"], 2, 991)
        self.assertEqual(first, second)
        for index in range(0, len(first), 2):
            pair = first[index : index + 2]
            self.assertEqual(pair[0]["pair_id"], pair[1]["pair_id"])
            self.assertEqual({"no-defense", "defense"}, {item["condition"] for item in pair})
            self.assertEqual(pair[0]["normal_traffic_seed"], pair[1]["normal_traffic_seed"])

    def test_pair_validation_rejects_model_drift_and_old_baseline(self) -> None:
        now = datetime.now(UTC)
        first = {
            "pair_id": "pair",
            "condition": "no-defense",
            "observed_model_id": "model-a",
            "normal_traffic_seed": 3,
            "started_at": now.isoformat(),
        }
        second = {
            **first,
            "condition": "defense",
            "started_at": (now + timedelta(hours=25)).isoformat(),
        }
        with self.assertRaisesRegex(ValueError, "too far apart"):
            validate_pair(first, second)
        second["started_at"] = now.isoformat()
        second["observed_model_id"] = "model-b"
        with self.assertRaisesRegex(ValueError, "model identities"):
            validate_pair(first, second)

    def test_failures_are_not_counted_as_attack_failures(self) -> None:
        self.assertEqual("model-error", classify_trial_status(objective=False, model_error=True))
        self.assertEqual(
            "isolation-error", classify_trial_status(objective=False, isolation_error=True)
        )
        self.assertEqual(
            "budget-exhausted",
            classify_trial_status(objective=False, budget_exhausted=True),
        )

    def test_path_rejects_absolute_and_network_paths(self) -> None:
        self.assertEqual("/api/test", ActionExecutor.validate_path("/api/test"))
        for invalid in ("http://outside/", "//outside/path", "/bad path", "/bad\\path"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    ActionExecutor.validate_path(invalid)


if __name__ == "__main__":
    unittest.main()
