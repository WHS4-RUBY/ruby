from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_digest(value: object) -> str:
    return f"sha256:{hashlib.sha256(canonical_json(value).encode()).hexdigest()}"


def parse_selector(value: str) -> dict[str, str]:
    parsed = json.loads(value)
    if not isinstance(parsed, dict) or any(
        not isinstance(key, str) or not isinstance(item, str)
        for key, item in parsed.items()
    ):
        raise ValueError("selector must be a JSON object containing only string pairs")
    return parsed


@dataclass(frozen=True)
class CompiledPredicate:
    predicate_id: str
    event_type: str
    subject: dict[str, str]
    object_: dict[str, str]
    protected_resource_key: str
    window_seconds: int
    minimum_occurrences: int
    deduplication_key: str

    @property
    def condition_document(self) -> dict[str, object]:
        return {
            "deduplication_key": self.deduplication_key,
            "event_type": self.event_type,
            "minimum_occurrences": self.minimum_occurrences,
            "object": self.object_,
            "protected_resource_key": self.protected_resource_key,
            "subject": self.subject,
            "window_seconds": self.window_seconds,
        }


def compile_predicate(value: dict[str, object]) -> CompiledPredicate:
    predicate = CompiledPredicate(
        predicate_id=str(value["predicate_id"]),
        event_type=str(value["event_type"]),
        subject=parse_selector(str(value["subject_selector"])),
        object_=parse_selector(str(value["object_selector"])),
        protected_resource_key=str(value["protected_resource_key"]),
        window_seconds=int(value["window_seconds"]),
        minimum_occurrences=int(value["minimum_occurrences"]),
        deduplication_key=str(value["deduplication_key"]),
    )
    if value.get("condition_digest") != sha256_digest(predicate.condition_document):
        raise ValueError("predicate condition digest does not match its executable condition")
    return predicate


def _contains(actual: dict[str, str], expected: dict[str, str]) -> bool:
    return all(actual.get(key) == value for key, value in expected.items())


def matching_events(
    predicate: CompiledPredicate,
    events: list[dict[str, object]],
    *,
    evaluated_at: datetime | None = None,
) -> list[dict[str, object]]:
    now = evaluated_at or datetime.now(UTC)
    earliest = now - timedelta(seconds=predicate.window_seconds)
    matches: list[dict[str, object]] = []
    seen: set[str] = set()
    for event in sorted(events, key=lambda item: int(item["sequence_number"])):
        recorded_at = datetime.fromisoformat(str(event["recorded_at"]))
        if recorded_at.tzinfo is None:
            recorded_at = recorded_at.replace(tzinfo=UTC)
        deduplication_value = str(event["deduplication_key"])
        if (
            recorded_at < earliest
            or event["event_type"] != predicate.event_type
            or event["protected_resource_key"] != predicate.protected_resource_key
            or not _contains(event["subject"], predicate.subject)  # type: ignore[arg-type]
            or not _contains(event["object"], predicate.object_)  # type: ignore[arg-type]
            or deduplication_value in seen
        ):
            continue
        seen.add(deduplication_value)
        matches.append(event)
    return matches
