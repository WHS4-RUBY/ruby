"""
강화된 레이트리밋 전략 - stub.
Detection Proxy의 RequestRateTracker와 별개로, "이미 위험하다고 판단된"
클라이언트에게만 더 엄격한 rps 제한을 거는 2차 방어선 개념.

TODO: 인메모리 대신 공유 저장소(Redis 등)로 교체, 슬라이딩 윈도우 적용.
"""
import time

from starlette.requests import Request
from starlette.responses import Response

from .base import DefenseStrategy, DefenseResult


class RateLimitStrictStrategy(DefenseStrategy):
    name = "rate_limit_strict"

    def __init__(self):
        self._last_seen: dict[str, float] = {}

    async def apply(self, request: Request, params: dict) -> DefenseResult:
        max_rps = float(params.get("max_rps", 1))
        min_interval = 1.0 / max_rps if max_rps > 0 else 0.0

        client_id = request.headers.get("x-client-id") or (
            request.client.host if request.client else "unknown"
        )
        now = time.monotonic()
        last = self._last_seen.get(client_id)
        self._last_seen[client_id] = now

        if last is not None and (now - last) < min_interval:
            return DefenseResult(
                short_circuit=Response(
                    content=b'{"error": "rate_limited"}',
                    status_code=429,
                    media_type="application/json",
                )
            )

        return DefenseResult()