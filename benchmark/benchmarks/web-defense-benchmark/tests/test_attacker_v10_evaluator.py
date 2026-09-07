from __future__ import annotations

import json
import unittest
from pathlib import Path

from evaluate_attacker_v10_cohort import evaluate_cohort


PROJECT_ROOT = Path(__file__).resolve().parents[1]
COHORT_PATH = PROJECT_ROOT / "app" / "configs" / "attacker-v10-final-cohort-v1.json"


class AttackerV10EvaluatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cohort = json.loads(COHORT_PATH.read_text(encoding="utf-8"))
        self.seal = {"frozen_files": {}}

    def reports(self) -> list[dict[str, object]]:
        prefixes = self.cohort["fixed_conditions"]["route_prefixes_by_repetition"]
        reports: list[dict[str, object]] = []
        for target in self.cohort["targets"]:
            for provider in self.cohort["fixed_conditions"]["providers"]:
                for repetition, prefix in enumerate(prefixes):
                    label = f"{target['target_id']}:{provider}:{repetition}"
                    reports.append(
                        {
                            "trial_id": label,
                            "trial_key": label,
                            "target_id": target["target_id"],
                            "provider": provider,
                            "repetition": repetition,
                            "status": "objective-achieved",
                            "objective_achieved": True,
                            "isolation": {
                                "isolated": True,
                                "public_api_prefix": prefix,
                                "account_namespace_sha256": f"account:{label}",
                            },
                            "metrics": {
                                "active_http_requests": 40,
                                "model_calls": 12,
                                "initial_state_sha256": f"state:{label}",
                                "terminal_policy_contract_error": False,
                                "decision_contract_rejections": 0,
                                "strategy_policy_deviations": 0,
                            },
                            "model_invocations": [],
                        }
                    )
        return reports

    def test_complete_passing_cohort_satisfies_every_gate(self) -> None:
        result = evaluate_cohort(self.cohort, self.seal, self.reports())

        self.assertTrue(result["passed"])
        self.assertEqual(48, result["observed_trials"])
        self.assertTrue(all(result["checks"].values()))

    def test_infrastructure_error_invalidates_otherwise_passing_cohort(self) -> None:
        reports = self.reports()
        reports[0]["status"] = "runner-error"
        reports[0]["objective_achieved"] = False

        result = evaluate_cohort(self.cohort, self.seal, reports)

        self.assertFalse(result["passed"])
        self.assertFalse(result["checks"]["valid_infrastructure"])

    def test_missing_route_variant_fails_variant_gate(self) -> None:
        reports = self.reports()
        target = reports[0]["target_id"]
        provider = reports[0]["provider"]
        matching = [
            item
            for item in reports
            if item["target_id"] == target and item["provider"] == provider
        ]
        matching[-1]["isolation"]["public_api_prefix"] = matching[0]["isolation"][
            "public_api_prefix"
        ]

        result = evaluate_cohort(self.cohort, self.seal, reports)

        self.assertFalse(result["passed"])
        self.assertFalse(result["checks"]["variant_coverage"])


if __name__ == "__main__":
    unittest.main()
