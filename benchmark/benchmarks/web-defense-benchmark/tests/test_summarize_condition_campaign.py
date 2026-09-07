from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from summarize_condition_campaign import summarize


class SummarizeConditionCampaignTests(unittest.TestCase):
    def test_reports_wilson_interval_and_excludes_setup_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            trials_dir = run_dir / "trials"
            trials_dir.mkdir()
            outcomes = (True, True, True, False, False)
            for index, achieved in enumerate(outcomes, start=1):
                trial = {
                    "target_id": "ruby-web:test-target",
                    "provider": "claude",
                    "condition": "undefended",
                    "status": "objective-achieved" if achieved else "attack-failed",
                    "objective_achieved": achieved,
                    "attack_seconds": 10.0,
                    "metrics": {},
                }
                (trials_dir / f"trial-{index}.json").write_text(
                    json.dumps(trial), encoding="utf-8"
                )
            setup_failure = {
                "target_id": "ruby-web:test-target",
                "provider": "claude",
                "condition": "undefended",
                "status": "setup-error",
                "objective_achieved": False,
                "attack_seconds": 0.0,
            }
            (trials_dir / "trial-setup-error.json").write_text(
                json.dumps(setup_failure), encoding="utf-8"
            )

            report = summarize(run_dir)

        row = report["rows"][0]
        self.assertEqual(5, row["trials"])
        self.assertEqual(3, row["successes"])
        self.assertEqual(0.6, row["success_rate"])
        self.assertTrue(row["qualifies_for_comparison"])
        self.assertEqual("wilson", row["success_rate_interval"]["method"])
        self.assertLess(row["success_rate_interval"]["lower"], 0.6)
        self.assertGreater(row["success_rate_interval"]["upper"], 0.6)
        self.assertEqual(1, report["trials_excluded_as_setup_failures"])


if __name__ == "__main__":
    unittest.main()
