import unittest
from unittest.mock import AsyncMock, Mock, patch

import httpx

from defense.app.main import app


class ReadinessTests(unittest.IsolatedAsyncioTestCase):
    async def test_ready_only_when_configured_target_accepts_tcp(self):
        writer = Mock()
        writer.wait_closed = AsyncMock()
        with patch("defense.app.main.TARGET_URL", "http://target.example:3000/base"), patch(
            "defense.app.main.asyncio.open_connection", new_callable=AsyncMock,
            return_value=(object(), writer),
        ) as connect:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://defense"
            ) as client:
                response = await client.get("/readyz")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ready")
        connect.assert_awaited_once_with("target.example", 3000)
        writer.close.assert_called_once_with()
        writer.wait_closed.assert_awaited_once_with()

    async def test_unreachable_target_is_unready_but_process_is_live(self):
        with patch("defense.app.main.TARGET_URL", "http://unreachable.invalid:3000"), patch(
            "defense.app.main.asyncio.open_connection", side_effect=OSError("unreachable")
        ):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://defense"
            ) as client:
                self.assertEqual((await client.get("/readyz")).status_code, 503)
                self.assertEqual((await client.get("/healthz")).status_code, 200)


if __name__ == "__main__":
    unittest.main()
