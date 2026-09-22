"""Log real Defense calls for the isolated integration check, without changing decisions."""
from __future__ import annotations

import hashlib
import json
import time

import uvicorn

from app.main import app
from app.strategies.delay import DelayStrategy


def emit(kind: str, **fields: object) -> None:
    print("RUBY_PIPELINE_AUDIT " + json.dumps({"kind": kind, **fields}, sort_keys=True), flush=True)


original_delay = DelayStrategy.apply


async def observed_delay(self, request, params):
    started = time.perf_counter()
    result = await original_delay(self, request, params)
    emit(
        "delay",
        case=request.query_params.get("ruby_check", ""),
        configured_ms=float(params.get("delay_ms", 0)),
        elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
    )
    return result


DelayStrategy.apply = observed_delay


@app.middleware("http")
async def observe_request(request, call_next):
    started = time.perf_counter()
    response = await call_next(request)
    if request.url.path != "/healthz":
        raw_plan = request.headers.get("x-defense-plan", "[]")
        try:
            plan = json.loads(raw_plan)
        except ValueError:
            plan = "invalid-json"
        emit(
            "request",
            case=request.query_params.get("ruby_check", ""),
            path=request.url.path,
            method=request.method,
            plan=plan,
            client_id_present=bool(request.headers.get("x-client-id")),
            client_id_digest=hashlib.sha256(request.headers.get("x-client-id", "").encode()).hexdigest(),
            status=response.status_code,
            elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
        )
    return response


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
