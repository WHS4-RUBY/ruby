"""
요청 처리를 지연시키는 전략.
지연 시간은 detection/config/policy.json 의 위험도 구간별 delay_ms 로 정해진다.
위험도 비례는 정책 구간이 표현하므로 이 전략은 전달받은 값만 적용한다.
"""
import asyncio

from starlette.requests import Request

from .base import DefenseStrategy, DefenseResult


class DelayStrategy(DefenseStrategy):
    name = "delay"
    uses_state = False

    async def apply(self, request: Request, params: dict, state: dict) -> DefenseResult:
        delay_ms = float(params.get("delay_ms", 0))

        # 정책 값은 이름 그대로 밀리초 단위다. asyncio.sleep는 초 단위를
        # 사용하므로 변환하지 않으면 delay_ms: 200이 200초 지연이 된다.
        await asyncio.sleep(delay_ms / 1000)

        return DefenseResult(
            extra_headers={"X-Defense-Delay-Ms": str(int(delay_ms))}
        )
