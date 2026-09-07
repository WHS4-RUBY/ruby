from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from typing import Annotated

import psycopg
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from .core import canonical_json, compile_predicate, matching_events, sha256_digest


class EvaluationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trial_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    predicate_id: str = Field(min_length=3, max_length=128)
    verifier: dict[str, object]


class EvaluationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trial_id: str
    predicate_id: str
    objective_achieved: bool
    matched_event_ids: tuple[str, ...]
    event_ledger_digest: str
    evaluated_at: str


DATABASE_URL = os.environ["RUBY_EVALUATOR_DATABASE_URL"]
EVALUATOR_TOKEN = os.environ["RUBY_EVALUATOR_TOKEN"]
app = FastAPI(title="RUBY Private Evaluator", version="0.1.0")


def require_token(value: Annotated[str | None, Header(alias="X-Ruby-Evaluator-Token")]) -> None:
    if value != EVALUATOR_TOKEN:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "invalid evaluator token")


def _events(trial_id: str) -> list[dict[str, object]]:
    with psycopg.connect(DATABASE_URL) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, sequence_number, recorded_at, event_type, subject_json,
                       object_json, protected_resource_key, deduplication_key, payload_digest
                FROM audit_journal
                WHERE trial_id = %s
                ORDER BY sequence_number
                """,
                (trial_id,),
            )
            return [
                {
                    "id": row[0],
                    "sequence_number": row[1],
                    "recorded_at": row[2],
                    "event_type": row[3],
                    "subject": json.loads(row[4]),
                    "object": json.loads(row[5]),
                    "protected_resource_key": row[6],
                    "deduplication_key": row[7],
                    "payload_digest": row[8],
                }
                for row in cursor.fetchall()
            ]


@app.get("/health/live")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/internal/evaluate", response_model=EvaluationResponse)
def evaluate(
    payload: EvaluationRequest,
    x_ruby_evaluator_token: Annotated[str | None, Header()] = None,
) -> EvaluationResponse:
    require_token(x_ruby_evaluator_token)
    verifier = payload.verifier
    if verifier.get("network_access") != "control-only" or verifier.get("attacker_visible") is not False:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "verifier isolation contract failed")
    predicates = verifier.get("predicates")
    if not isinstance(predicates, list):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "verifier predicates are missing")
    selected = next(
        (item for item in predicates if isinstance(item, dict) and item.get("predicate_id") == payload.predicate_id),
        None,
    )
    if selected is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "predicate not found")
    try:
        predicate = compile_predicate(selected)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(error)) from error
    evaluated_at = datetime.now(UTC)
    ledger = _events(payload.trial_id)
    matches = matching_events(predicate, ledger, evaluated_at=evaluated_at)
    return EvaluationResponse(
        trial_id=payload.trial_id,
        predicate_id=payload.predicate_id,
        objective_achieved=len(matches) >= predicate.minimum_occurrences,
        matched_event_ids=tuple(str(item["id"]) for item in matches),
        event_ledger_digest=sha256_digest(ledger),
        evaluated_at=evaluated_at.isoformat(),
    )
