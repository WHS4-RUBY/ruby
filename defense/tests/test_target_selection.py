import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid

from defense.app.target_selection import TargetSelectionError, TargetSelector


class TargetSelectionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.selection_file = Path(self.directory.name) / "selection.json"
        self.environment = {
            "TARGET_CHOICES": (
                "legacy=http://host.docker.internal:3000,"
                "ruby-shop=http://ruby-web-target:8080,"
                "juice-shop=http://juice-shop-target:3000"
            ),
            "TARGET_DEFAULT_ID": "legacy",
            "TARGET_SELECTION_FILE": str(self.selection_file),
        }

    def write_selection(self, value):
        pending = self.selection_file.with_suffix(".pending")
        pending.write_text(json.dumps(value), encoding="utf-8")
        os.replace(pending, self.selection_file)

    def test_missing_file_uses_legacy_and_atomic_replacement_switches_target(self):
        selector = TargetSelector.from_environment(self.environment)
        self.assertEqual(selector.current().public_metadata(), {
            "targetId": "legacy", "runId": None, "changedAt": None,
        })

        # Detection 이 실제로 쓰는 값은 crypto.randomUUID() 와 toISOString() 이다.
        first_run = str(uuid.uuid4())
        self.write_selection({
            "targetId": "ruby-shop", "runId": first_run, "changedAt": "2026-10-07T11:30:00Z",
        })
        selected = selector.current()
        self.assertEqual(selected.url, "http://ruby-web-target:8080")
        self.assertEqual(selected.run_id, first_run)

        second_run = str(uuid.uuid4())
        self.write_selection({
            "targetId": "juice-shop", "runId": second_run, "changedAt": "2026-10-07T11:31:00Z",
            "url": "http://attacker.invalid",
        })
        selected = selector.current()
        self.assertEqual(selected.url, "http://juice-shop-target:3000")
        self.assertEqual(selected.run_id, second_run)

    def test_malformed_and_unlisted_selections_fail_closed(self):
        selector = TargetSelector.from_environment(self.environment)
        self.selection_file.write_text("{invalid", encoding="utf-8")
        with self.assertRaises(TargetSelectionError):
            selector.current()

        self.write_selection({
            "targetId": "http://attacker.invalid", "runId": str(uuid.uuid4()),
            "changedAt": "2026-10-07T11:32:00Z",
        })
        with self.assertRaises(TargetSelectionError):
            selector.current()

        self.write_selection({"targetId": "ruby-shop", "runId": "", "changedAt": "now"})
        with self.assertRaises(TargetSelectionError):
            selector.current()

        # 좁힌 경계값: UUID 가 아닌 runId 와 파싱되지 않는 changedAt 을 거부한다.
        for bad in ({"runId": "run-001"}, {"runId": str(uuid.uuid4()).upper()},
                    {"changedAt": "now"}, {"changedAt": ""}):
            selection = {"targetId": "ruby-shop", "runId": str(uuid.uuid4()),
                         "changedAt": "2026-10-07T11:30:00Z", **bad}
            self.write_selection(selection)
            with self.assertRaises(TargetSelectionError, msg=str(bad)):
                selector.current()

    def test_request_snapshot_survives_a_global_switch(self):
        selector = TargetSelector.from_environment(self.environment)
        run_id = str(uuid.uuid4())
        self.write_selection({
            "targetId": "juice-shop", "runId": str(uuid.uuid4()), "changedAt": "2026-10-07T11:31:00Z",
        })
        selected = selector.for_request({
            "x-ruby-target-id": "ruby-shop", "x-ruby-run-id": run_id,
        })
        self.assertEqual(selected.url, "http://ruby-web-target:8080")
        self.assertEqual(selected.run_id, run_id)
        self.assertIsNone(selected.changed_at)
        self.assertEqual(selector.current().target_id, "juice-shop")

        for headers in (
            {"x-ruby-target-id": "ruby-shop"},
            {"x-ruby-run-id": run_id},
            {"x-ruby-target-id": "attacker", "x-ruby-run-id": run_id},
            {"x-ruby-target-id": "ruby-shop", "x-ruby-run-id": "not-a-uuid"},
        ):
            with self.subTest(headers=headers), self.assertRaises(TargetSelectionError):
                selector.for_request(headers)

    def test_operator_configuration_rejects_invalid_urls_and_defaults(self):
        with self.assertRaises(RuntimeError):
            TargetSelector.from_environment({"TARGET_CHOICES": "ruby-shop=http://web:8080"})
        for url in ("file:///etc/passwd", "http://user:pass@web:8080", "http://web:99999"):
            with self.subTest(url=url), self.assertRaises(RuntimeError):
                TargetSelector.from_environment({"TARGET_CHOICES": f"legacy={url}"})


if __name__ == "__main__":
    unittest.main()
