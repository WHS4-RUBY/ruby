import unittest
from unittest.mock import patch

from defense.app.monitoring import DefenseEventStore


class DefenseEventStoreTests(unittest.TestCase):
    def test_store_is_bounded_and_returns_newest_first(self):
        store = DefenseEventStore(max_events=2)
        for index in range(3):
            store.record(
                method="GET",
                path=f"/item/{index}",
                status=200,
                strategies=[],
                outcome="forwarded",
                duration_ms=index,
                client_id="client",
            )

        self.assertEqual([event["path"] for event in store.recent()], ["/item/2", "/item/1"])
        self.assertEqual(store.summary()["totalRequests"], 2)

    def test_summary_and_actions_distinguish_defense_outcomes(self):
        store = DefenseEventStore(max_events=10)
        store.record(
            method="GET",
            path="/public",
            status=200,
            strategies=[],
            outcome="forwarded",
            duration_ms=10,
            client_id=None,
        )
        store.record(
            method="POST",
            path="/login",
            status=429,
            strategies=["delay", "rate_limit_strict"],
            outcome="blocked",
            duration_ms=210,
            client_id="client-1",
        )

        summary = store.summary()
        self.assertEqual(summary["totalRequests"], 2)
        self.assertEqual(summary["defendedRequests"], 1)
        self.assertEqual(summary["blockedRequests"], 1)
        self.assertEqual(summary["averageDurationMs"], 110)
        self.assertEqual(
            store.action_counts(),
            [
                {"name": "none", "count": 1},
                {"name": "delay", "count": 1},
                {"name": "rate_limit_strict", "count": 1},
            ],
        )

    @patch("defense.app.monitoring.time.time", side_effect=[3500, 3599, 3600])
    def test_timeline_uses_fixed_buckets(self, _time):
        store = DefenseEventStore(max_events=10)
        store.record(
            method="GET",
            path="/",
            status=200,
            strategies=["delay"],
            outcome="forwarded",
            duration_ms=200,
            client_id="client-1",
        )

        buckets = store.timeline(buckets=6, window_seconds=60)
        self.assertEqual(len(buckets), 6)
        self.assertEqual(buckets[-1]["total"], 1)
        self.assertEqual(buckets[-1]["defended"], 1)
        at_end = store._timeline(
            [{"timestamp": 3600, "strategies": [], "outcome": "forwarded"}],
            buckets=6, window_seconds=60, end=3600,
        )
        self.assertEqual(at_end[-1]["total"], 1)

    def test_dashboard_snapshot_uses_one_consistent_event_set(self):
        store = DefenseEventStore(max_events=10)
        store.record(
            method="GET",
            path="/snapshot",
            status=200,
            strategies=["delay"],
            outcome="forwarded",
            duration_ms=50,
            client_id="client-1",
        )

        snapshot = store.dashboard_snapshot(limit=5, buckets=6)

        self.assertEqual(snapshot["summary"]["totalRequests"], 1)
        self.assertEqual(snapshot["requests"][0]["path"], "/snapshot")
        self.assertEqual(snapshot["actions"], [{"name": "delay", "count": 1}])
        self.assertEqual(sum(bucket["total"] for bucket in snapshot["timeline"]), 1)


if __name__ == "__main__":
    unittest.main()
