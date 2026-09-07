from __future__ import annotations

import json
import unittest
from pathlib import Path

from evaluate_attacker_v11_qualification import evaluate_qualification


ROOT = Path(__file__).resolve().parents[1]
COHORT = json.loads(
    (ROOT / "app/configs/attacker-v11-qualification-cohort-v1.json").read_text(
        encoding="utf-8"
    )
)


def reports(*, failed_provider: str | None = None) -> list[dict[str, object]]:
    values = []
    for target in COHORT["targets"]:
        target_id = target["target_id"]
        for provider in ("codex", "claude"):
            for repetition in range(5):
                success = failed_provider != provider
                values.append(
                    {
                        "trial_key": f"{target_id}-{provider}-{repetition}",
                        "target_id": target_id,
                        "provider": provider,
                        "repetition": repetition,
                        "status": "objective-achieved" if success else "attack-failed",
                        "objective_achieved": success,
                        "attacker_profile_id": "ruby-stage3a-autonomous-web-attacker-v11",
                        "isolation": {
                            "isolated": True,
                            "public_api_prefix": f"/sealed-{repetition}",
                            "account_namespace_sha256": f"account-{repetition}",
                        },
                        "metrics": {
                            "active_http_requests": 40,
                            "model_calls": 10,
                            "terminal_policy_contract_error": False,
                            "decision_contract_rejections": 0,
                            "initial_state_sha256": f"state-{repetition}",
                        },
                        "model_invocations": [],
                    }
                )
    return values


class AttackerV11QualificationTest(unittest.TestCase):
    def test_complete_high_quality_cohort_passes_all_gates(self) -> None:
        result = evaluate_qualification(
            COHORT,
            {"sealed_inputs": {}},
            reports(),
            retry_artifacts=[],
        )
        self.assertTrue(result["passed"])
        self.assertEqual(240, result["observed_trials"])
        self.assertEqual(24, result["targets_qualified_for_both_providers"])

    def test_provider_failure_cannot_be_hidden_by_total_schedule(self) -> None:
        result = evaluate_qualification(
            COHORT,
            {"sealed_inputs": {}},
            reports(failed_provider="claude"),
            retry_artifacts=[],
        )
        self.assertFalse(result["passed"])
        self.assertFalse(result["checks"]["provider_success_rates"])
        self.assertFalse(result["checks"]["target_provider_coverage"])

    def test_any_retry_artifact_fails_the_fixed_cohort(self) -> None:
        result = evaluate_qualification(
            COHORT,
            {"sealed_inputs": {}},
            reports(),
            retry_artifacts=["attempts/one.json"],
        )
        self.assertFalse(result["passed"])
        self.assertFalse(result["checks"]["no_selective_retries"])


if __name__ == "__main__":
    unittest.main()
