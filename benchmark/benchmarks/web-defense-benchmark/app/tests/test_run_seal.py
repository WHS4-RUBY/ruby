"""Checks that a run's seal keeps saying what the run actually measured.

A run is stopped and resumed whenever the host runs short of memory, and the
runner rightly skips the trials that already finished. It also re-seals the
defense source on every start, so a resumed run ends up labelled with whatever
the source looked like at the last resume rather than at the first.

One run was resumed four times across two defense versions. Its seal named the
last one, while trials completed before a rule was added still carried chains
that rule forbids. Nothing in the record said so, and the run looked like a
clean comparison.

The seal therefore has to refuse to change under a resume, and say plainly when
the source has moved on.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

APP_ROOT = Path(__file__).resolve().parents[1]
TOOLS = APP_ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from snapshot_defense_source import snapshot  # noqa: E402


class SealStabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.run_dir = Path(self.temp.name) / "run"
        self.run_dir.mkdir()
        self.package = Path(self.temp.name) / "package"
        (self.package / "src" / "defense_adapter").mkdir(parents=True)
        self.module = self.package / "src" / "defense_adapter" / "gateway.py"
        self.module.write_text("VERSION = 1\n", encoding="utf-8")

    def test_a_first_seal_records_the_source(self) -> None:
        manifest = snapshot(self.run_dir, self.package)
        self.assertIn("combined_sha256", manifest)
        self.assertTrue(
            (
                self.run_dir
                / "defense-source"
                / "src"
                / "defense_adapter"
                / "gateway.py"
            ).is_file()
        )

    def test_sealing_again_with_the_same_source_is_the_same_seal(self) -> None:
        first = snapshot(self.run_dir, self.package)
        second = snapshot(self.run_dir, self.package)
        self.assertEqual(first["combined_sha256"], second["combined_sha256"])

    def test_sealing_again_after_an_edit_keeps_the_original(self) -> None:
        """A resumed run still measured what it started with."""

        first = snapshot(self.run_dir, self.package)
        self.module.write_text("VERSION = 2\n", encoding="utf-8")
        second = snapshot(self.run_dir, self.package)
        self.assertEqual(second["combined_sha256"], first["combined_sha256"])
        self.assertEqual(
            (
                self.run_dir
                / "defense-source"
                / "src"
                / "defense_adapter"
                / "gateway.py"
            ).read_text(encoding="utf-8"),
            "VERSION = 1\n",
        )

    def test_an_edit_after_sealing_is_reported(self) -> None:
        snapshot(self.run_dir, self.package)
        self.module.write_text("VERSION = 2\n", encoding="utf-8")
        manifest = snapshot(self.run_dir, self.package)
        self.assertTrue(manifest.get("source_moved_on"))
        self.assertIn("gateway.py", json.dumps(manifest))

    def test_an_unchanged_source_is_not_reported_as_moved(self) -> None:
        snapshot(self.run_dir, self.package)
        manifest = snapshot(self.run_dir, self.package)
        self.assertFalse(manifest.get("source_moved_on"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
