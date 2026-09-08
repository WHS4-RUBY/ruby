from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "tools"))

from validate_manifest import validate_manifest  # noqa: E402


CONTRACT_DIRECTORY = PROJECT_ROOT / "app" / "configs" / "scenario-contracts"
EXPECTED = {
    "cryptographic-failure.signed-download-forgery": ("CWE-347",),
    "resource-consumption.report-export-fanout": ("CWE-770", "CWE-799"),
    "business-workflow.bulk-promotion-redemption": ("CWE-837", "CWE-799"),
    "api-inventory.deprecated-operations-endpoint": ("CWE-749",),
    "security-logging.audit-trail-erasure": ("CWE-778",),
    "software-data-integrity.unsigned-partner-webhook": ("CWE-353",),
    "CVE-2026-54433": ("CWE-79",),
}


class ScenarioCompletionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contracts = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(CONTRACT_DIRECTORY.glob("*.json"))
        ]

    def test_every_planned_contract_is_present_and_valid(self) -> None:
        self.assertEqual(EXPECTED, {
            item["module_id"]: tuple(item["classification"]["cwe_ids"])
            for item in self.contracts
        })
        for contract in self.contracts:
            with self.subTest(module_id=contract["module_id"]):
                self.assertEqual([], validate_manifest("scenario-completion", contract))

    def test_ids_and_private_objectives_are_unique(self) -> None:
        for field in ("scenario_id", "module_id"):
            values = [item[field] for item in self.contracts]
            self.assertEqual(len(values), len(set(values)))
        resources = [item["objective"]["protected_resource_key"] for item in self.contracts]
        self.assertEqual(len(resources), len(set(resources)))

    def test_contracts_pin_current_taxonomy_and_bounded_effects(self) -> None:
        for contract in self.contracts:
            with self.subTest(module_id=contract["module_id"]):
                self.assertTrue(
                    all(value.startswith("v5.0.0-") for value in contract["classification"]["asvs_ids"])
                )
                self.assertEqual("2026-09-08", contract["classification"]["verified_on"])
                self.assertTrue(contract["resource_safety"]["bounded"])
                self.assertEqual(
                    {"host-exhaustion", "external-callback", "persistent-host-change"},
                    set(contract["resource_safety"]["prohibited_effects"]),
                )

    def test_roundcube_contract_pins_a_real_2026_pair(self) -> None:
        contract = next(item for item in self.contracts if item["module_id"] == "CVE-2026-54433")
        self.assertEqual("cve-original", contract["target_kind"])
        self.assertEqual("1.6.16", contract["original_release_pair"]["vulnerable_version"])
        self.assertEqual("1.6.17", contract["original_release_pair"]["fixed_version"])
        self.assertIn("victim-browser-trigger", contract["isolation"]["allowed_capabilities"])


if __name__ == "__main__":
    unittest.main()
