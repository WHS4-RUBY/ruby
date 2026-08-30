"""
risk_score에 비례해 응답을 지연시키는 전략.
지연 시간은 policy/config.yaml 에 명시.
"""
import asyncio

from starlette.requests import Request

from .base import DefenseStrategy, DefenseResult


class DelayStrategy(DefenseStrategy):
    name = "delay"

    async def apply(self, request: Request, params: dict) -> DefenseResult:
        delay_ms = float(params.get("delay_ms", 0))

        # 정책 값은 이름 그대로 밀리초 단위다. asyncio.sleep는 초 단위를
        # 사용하므로 변환하지 않으면 delay_ms: 200이 200초 지연이 된다.
        await asyncio.sleep(delay_ms / 1000)

        return DefenseResult(
            extra_headers={"X-Defense-Delay-Ms": str(int(delay_ms))}
        )
