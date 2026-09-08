from __future__ import annotations

import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "app" / "defenses" / "static-guard"))

from rules import decision  # noqa: E402


class StaticGuardRuleTests(unittest.TestCase):
    def test_blocks_observed_autonomous_bypasses(self) -> None:
        bypasses = (
            "/service/products?q=%25%27%29OR%28TRUE%29--%20",
            "/service/products?q=%25%27%29%20OR%2F%2A%2A%2F1%3D1%20--%20",
            "/rest/products?q=%25%27%29OR%281%3D1%29--%20",
            "/service/products?q=%25%27%29%20IS%20NULL%0AOR%0A1%3D1%20AND%20%28%27x%27%20LIKE%20%27",
        )
        for path in bypasses:
            with self.subTest(path=path):
                self.assertEqual("block", decision(path)["action"])

    def test_blocks_encoded_sql_structure_variants(self) -> None:
        attacks = (
            "/service/products?q=%2525%2527%2529OR%2528TRUE%2529--%2520",
            "/service/products?q=x%27%29%20UnIoN%2F%2Aprobe%2A%2FSeLeCt%201--",
            "/service/products?q=x%27%20AND%202%3C1--",
        )
        for path in attacks:
            with self.subTest(path=path):
                self.assertEqual("block", decision(path)["action"])

    def test_preserves_benign_searches(self) -> None:
        benign = (
            "/service/products",
            "/service/products?q=coffee",
            "/service/products?q=orchestra",
            "/service/products?q=reunionselection",
            "/service/products?q=O%27Reilly",
            "/assets/index.js",
        )
        for path in benign:
            with self.subTest(path=path):
                self.assertEqual("pass", decision(path)["action"])

    def test_retains_non_sql_signatures(self) -> None:
        attacks = (
            "/files/../../internal/config",
            "/internal/status",
            "/fetch?url=file%3A%2F%2F%2Fetc%2Fpasswd",
            "/fetch?url=gopher%3A%2F%2F127.0.0.1",
        )
        for path in attacks:
            with self.subTest(path=path):
                self.assertEqual("block", decision(path)["action"])


if __name__ == "__main__":
    unittest.main()
