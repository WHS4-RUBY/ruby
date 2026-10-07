import unittest
from unittest.mock import AsyncMock, patch

from defense.app.strategies.delay import DelayStrategy


class DelayStrategyTests(unittest.IsolatedAsyncioTestCase):
    async def test_delay_ms_is_converted_to_seconds_for_asyncio(self):
        strategy = DelayStrategy()

        with patch("defense.app.strategies.delay.asyncio.sleep", new_callable=AsyncMock) as sleep:
            result = await strategy.apply(None, {"delay_ms": 200}, {})

        sleep.assert_awaited_once_with(0.2)
        self.assertEqual(result.extra_headers["X-Defense-Delay-Ms"], "200")


if __name__ == "__main__":
    unittest.main()
