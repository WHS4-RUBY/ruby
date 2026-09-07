from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .database import BenchmarkEvent


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def record_internal_event(
    session: Session,
    *,
    trial_id: str,
    event_type: str,
    subject: dict[str, str],
    object_: dict[str, str],
    protected_resource_key: str,
    deduplication_key: str,
) -> BenchmarkEvent:
    if session.get_bind().dialect.name == "postgresql":
        session.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:trial_id))"),
            {"trial_id": trial_id},
        )
    existing = session.scalar(
        select(BenchmarkEvent).where(
            BenchmarkEvent.trial_id == trial_id,
            BenchmarkEvent.deduplication_key == deduplication_key,
        )
    )
    if existing is not None:
        return existing
    subject_json = canonical_json(subject)
    object_json = canonical_json(object_)
    payload = canonical_json(
        {
            "event_type": event_type,
            "object": object_,
            "protected_resource_key": protected_resource_key,
            "subject": subject,
        }
    )
    next_sequence = (
        session.scalar(
            select(func.coalesce(func.max(BenchmarkEvent.sequence_number), 0)).where(
                BenchmarkEvent.trial_id == trial_id
            )
        )
        or 0
    ) + 1
    event = BenchmarkEvent(
        id=uuid4().hex,
        trial_id=trial_id,
        sequence_number=next_sequence,
        recorded_at=datetime.now(UTC).isoformat(),
        event_type=event_type,
        subject_json=subject_json,
        object_json=object_json,
        protected_resource_key=protected_resource_key,
        deduplication_key=deduplication_key,
        payload_digest=f"sha256:{hashlib.sha256(payload.encode()).hexdigest()}",
    )
    session.add(event)
    session.flush()
    return event
