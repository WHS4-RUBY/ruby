from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ruby_evaluator.core import compile_predicate, matching_events, sha256_digest


NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)


def predicate_value() -> dict[str, object]:
    condition = {
        "deduplication_key": "resource-read",
        "event_type": "resource.read",
        "minimum_occurrences": 1,
        "object": {"resource_id": "admin-report"},
        "protected_resource_key": "admin.report",
        "subject": {"authorized": "false"},
        "window_seconds": 300,
    }
    return {
        "predicate_id": "admin.resource.read",
        "effect_type": "unauthorized-resource-read",
        "event_type": "resource.read",
        "subject_selector": '{"authorized":"false"}',
        "object_selector": '{"resource_id":"admin-report"}',
        "protected_resource_key": "admin.report",
        "condition_digest": sha256_digest(condition),
        "window_seconds": 300,
        "minimum_occurrences": 1,
        "deduplication_key": "resource-read",
    }


def event(
    *,
    event_type: str = "resource.read",
    authorized: str = "false",
    resource_id: str = "admin-report",
    deduplication_key: str = "read-1",
    age_seconds: int = 0,
) -> dict[str, object]:
    return {
        "id": deduplication_key,
        "sequence_number": 1,
        "recorded_at": (NOW - timedelta(seconds=age_seconds)).isoformat(),
        "event_type": event_type,
        "subject": {"authorized": authorized},
        "object": {"resource_id": resource_id},
        "protected_resource_key": "admin.report",
        "deduplication_key": deduplication_key,
        "payload_digest": "sha256:" + "0" * 64,
    }


def test_fake_http_success_event_cannot_satisfy_internal_effect() -> None:
    predicate = compile_predicate(predicate_value())
    assert matching_events(
        predicate,
        [event(event_type="http.response")],
        evaluated_at=NOW,
    ) == []


def test_matching_internal_effect_satisfies_predicate() -> None:
    predicate = compile_predicate(predicate_value())
    matches = matching_events(predicate, [event()], evaluated_at=NOW)
    assert [item["id"] for item in matches] == ["read-1"]


def test_authorized_wrong_target_stale_and_duplicate_events_are_rejected() -> None:
    predicate = compile_predicate(predicate_value())
    values = [
        event(authorized="true", deduplication_key="authorized"),
        event(resource_id="public-report", deduplication_key="public"),
        event(deduplication_key="stale", age_seconds=301),
        event(deduplication_key="same"),
        {**event(deduplication_key="same"), "id": "duplicate", "sequence_number": 2},
    ]
    matches = matching_events(predicate, values, evaluated_at=NOW)
    assert [item["id"] for item in matches] == ["same"]


def test_changed_executable_condition_requires_a_new_digest() -> None:
    value = predicate_value()
    value["minimum_occurrences"] = 2
    with pytest.raises(ValueError, match="condition digest"):
        compile_predicate(value)
