import unittest
from unittest.mock import AsyncMock, Mock, patch

import httpx

from defense.app.main import app
from defense.app.target_selection import SelectedTarget, TargetSelectionError


class ReadinessTests(unittest.IsolatedAsyncioTestCase):
    async def test_ready_only_when_configured_target_accepts_tcp(self):
        writer = Mock()
        writer.wait_closed = AsyncMock()
        selected = SelectedTarget("ruby-shop", "http://target.example:3000/base", "run-1", "now")
        with patch("defense.app.target_selection.target_selector.current", return_value=selected), patch(
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
        selected = SelectedTarget("juice-shop", "http://unreachable.invalid:3000", "run-2", "now")
        with patch("defense.app.target_selection.target_selector.current", return_value=selected), patch(
            "defense.app.main.asyncio.open_connection", side_effect=OSError("unreachable")
        ):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://defense"
            ) as client:
                self.assertEqual((await client.get("/readyz")).status_code, 503)
                self.assertEqual((await client.get("/healthz")).status_code, 200)

    async def test_unreachable_sidecar_is_unready_for_selected_target(self):
        writer = Mock()
        writer.wait_closed = AsyncMock()
        selected = SelectedTarget("ruby-shop", "http://target.example:3000", "run-3", "now")
        with patch.dict("defense.app.main.DECOY_UPSTREAMS", {"ruby-shop": "http://sidecar:3012"}), patch(
            "defense.app.target_selection.target_selector.current", return_value=selected
        ), patch(
            "defense.app.main.asyncio.open_connection", new_callable=AsyncMock,
            side_effect=[(object(), writer), OSError("sidecar unavailable")],
        ) as connect:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://defense"
            ) as client:
                response = await client.get("/readyz")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(connect.await_count, 2)
        self.assertEqual(connect.await_args_list[0].args, ("target.example", 3000))
        self.assertEqual(connect.await_args_list[1].args, ("sidecar", 3012))
        writer.close.assert_called_once_with()

    async def test_invalid_selection_is_unready(self):
        with patch("defense.app.target_selection.target_selector.current", side_effect=TargetSelectionError("invalid")):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://defense"
            ) as client:
                self.assertEqual((await client.get("/readyz")).status_code, 503)


if __name__ == "__main__":
    unittest.main()
