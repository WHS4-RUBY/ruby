"""Bounded, in-memory observability for the Defense proxy."""

from __future__ import annotations

import os
import threading
import time
import uuid
from collections import Counter, deque


def _positive_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


def _bounded(value: str | None, limit: int) -> str | None:
    return str(value)[:limit] if value is not None else None


class DefenseEventStore:
    def __init__(self, max_events: int | None = None):
        self.max_events = max_events or _positive_int("DEFENSE_EVENT_LIMIT", 5000)
        self.started_at = time.time()
        self._events: deque[dict] = deque(maxlen=self.max_events)
        self._lock = threading.Lock()

    def record(
        self,
        *,
        method: str,
        path: str,
        status: int,
        strategies: list[str],
        outcome: str,
        duration_ms: float,
        client_id: str | None,
        request_id: str | None = None,
        automation_score: float | None = None,
        attack_score: float | None = None,
        risk_score: float | None = None,
        policy_source: str | None = None,
        signal: str | None = None,
        decoy_action: str | None = None,
        target_id: str | None = None,
        run_id: str | None = None,
    ) -> dict:
        event = {
            "id": str(uuid.uuid4()),
            "timestamp": time.time(),
            "method": _bounded(method, 16),
            "path": _bounded(path, 1024),
            "status": status,
            "strategies": [_bounded(name, 64) for name in strategies[:16]],
            "outcome": outcome,
            "durationMs": round(duration_ms, 3),
            "clientId": _bounded(client_id or "unknown", 128),
            "requestId": _bounded(request_id, 128),
            "automationScore": automation_score,
            "attackScore": attack_score,
            "riskScore": risk_score,
            "policySource": _bounded(policy_source, 64),
            "defenseSignal": _bounded(signal, 64),
            "decoyAction": _bounded(decoy_action, 64),
            "targetId": _bounded(target_id, 64),
            "runId": _bounded(run_id, 128),
        }
        with self._lock:
            self._events.append(event)
        return event

    def _snapshot(self) -> list[dict]:
        with self._lock:
            return list(self._events)

    def recent(self, limit: int = 150) -> list[dict]:
        safe_limit = max(1, min(limit, 1000))
        return list(reversed(self._snapshot()[-safe_limit:]))

    def _summary(self, events: list[dict]) -> dict:
        defended = [event for event in events if event["strategies"]]
        blocked = [event for event in events if event["outcome"] == "blocked"]
        errors = [event for event in events if event["outcome"] == "error"]
        durations = [event["durationMs"] for event in events]
        strategies = Counter(
            strategy for event in events for strategy in event["strategies"]
        )
        return {
            "startedAt": self.started_at,
            "maxEvents": self.max_events,
            "totalRequests": len(events),
            "defendedRequests": len(defended),
            "blockedRequests": len(blocked),
            "errorRequests": len(errors),
            "averageDurationMs": round(sum(durations) / len(durations), 3) if durations else 0,
            "activeStrategies": [name for name, _ in strategies.most_common()],
        }

    def summary(self) -> dict:
        return self._summary(self._snapshot())

    @staticmethod
    def _action_counts(events: list[dict]) -> list[dict]:
        counts = Counter()
        for event in events:
            if event["strategies"]:
                counts.update(event["strategies"])
            else:
                counts["none"] += 1
        return [{"name": name, "count": count} for name, count in counts.most_common()]

    def action_counts(self) -> list[dict]:
        return self._action_counts(self._snapshot())

    @staticmethod
    def _timeline(
        events: list[dict],
        *,
        buckets: int,
        window_seconds: int,
        end: float,
    ) -> list[dict]:
        safe_buckets = max(6, min(buckets, 120))
        bucket_seconds = max(1, window_seconds // safe_buckets)
        start = end - bucket_seconds * safe_buckets
        result = [
            {
                "start": start + index * bucket_seconds,
                "total": 0,
                "defended": 0,
                "blocked": 0,
                "errors": 0,
            }
            for index in range(safe_buckets)
        ]
        for event in events:
            index = int((event["timestamp"] - start) // bucket_seconds)
            if not 0 <= index < safe_buckets:
                continue
            bucket = result[index]
            bucket["total"] += 1
            if event["strategies"]:
                bucket["defended"] += 1
            if event["outcome"] == "blocked":
                bucket["blocked"] += 1
            elif event["outcome"] == "error":
                bucket["errors"] += 1
        return result

    def timeline(self, buckets: int = 48, window_seconds: int = 3600) -> list[dict]:
        return self._timeline(
            self._snapshot(),
            buckets=buckets,
            window_seconds=window_seconds,
            end=time.time(),
        )

    def dashboard_snapshot(self, *, limit: int = 250, buckets: int = 48) -> dict:
        events = self._snapshot()
        safe_limit = max(1, min(limit, 1000))
        return {
            "summary": self._summary(events),
            "requests": list(reversed(events[-safe_limit:])),
            "actions": self._action_counts(events),
            "timeline": self._timeline(
                events,
                buckets=buckets,
                window_seconds=3600,
                end=time.time(),
            ),
        }


event_store = DefenseEventStore()
