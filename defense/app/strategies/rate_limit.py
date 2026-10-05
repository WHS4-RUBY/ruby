"""Per-client strict rate limit for policy-selected traffic."""

import time

from starlette.requests import Request
from starlette.responses import Response

from .base import DefenseStrategy, DefenseResult


class RateLimitStrictStrategy(DefenseStrategy):
    name = "rate_limit_strict"

    async def apply(self, request: Request, params: dict, state: dict) -> DefenseResult:
        max_rps = float(params.get("max_rps", 1))
        min_interval = 1.0 / max_rps if max_rps > 0 else 0.0
        now = time.monotonic()
        last = state.get("last_seen")
        next_state = {"last_seen": now}

        if last is not None and (now - last) < min_interval:
            return DefenseResult(
                short_circuit=Response(
                    content=b'{"error": "rate_limited"}',
                    status_code=429,
                    media_type="application/json",
                    headers={"X-Defense-Signal": "rate_limited"},
                ),
                state_update=next_state,
            )

        return DefenseResult(state_update=next_state)
