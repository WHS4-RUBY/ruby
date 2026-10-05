import asyncio
import json
import unittest
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.responses import Response

from defense.app.main import _apply_plan, app
from defense.app.dashboard_auth import DashboardAuthManager
from defense.app.monitoring import event_store
from defense.app.strategies.base import DefenseResult, DefenseStrategy
from defense.app.strategies.state import StrategyStateStore


def request(client_id="client-a"):
    return Request({
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "path": "/item",
        "raw_path": b"/item",
        "query_string": b"",
        "headers": [(b"x-client-id", client_id.encode())],
        "client": ("127.0.0.1", 1234),
        "server": ("defense", 8080),
    })


class CountingStrategy(DefenseStrategy):
    name = "counting"

    async def apply(self, request, params, state):
        count = state.get("count", 0) + 1
        return DefenseResult(extra_headers={"X-Count": str(count)}, state_update={"count": count})


class TransformStrategy(DefenseStrategy):
    name = "test_transform"
    uses_state = False

    async def apply(self, request, params, state):
        return DefenseResult(response_transform=lambda response: Response(
            content=response.body + b" transformed", status_code=response.status_code,
            media_type="text/plain",
        ))


class BlockStrategy(DefenseStrategy):
    name = "test_block"
    uses_state = False

    async def apply(self, request, params, state):
        return DefenseResult(short_circuit=Response(status_code=403))


class StrategyStateTests(unittest.IsolatedAsyncioTestCase):
    async def test_state_is_per_strategy_and_client_and_expires(self):
        now = [100.0]
        store = StrategyStateStore(max_entries=2, ttl_seconds=10, clock=lambda: now[0])
        strategy = CountingStrategy()
        with patch("defense.app.main.strategy_state", store), patch.dict(
            "defense.app.main.STRATEGY_REGISTRY", {"counting": strategy, "counting2": strategy}
        ):
            plan = [{"name": "counting"}]
            self.assertEqual((await _apply_plan(plan, request("a"))).headers["X-Count"], "1")
            self.assertEqual((await _apply_plan(plan, request("a"))).headers["X-Count"], "2")
            self.assertEqual((await _apply_plan(plan, request("b"))).headers["X-Count"], "1")
            self.assertEqual((await _apply_plan([{"name": "counting2"}], request("a"))).headers["X-Count"], "1")
            self.assertEqual(await store.size(), 2)
            now[0] += 11
            self.assertEqual((await _apply_plan(plan, request("a"))).headers["X-Count"], "1")

    async def test_rate_limit_releases_then_detects_reentry(self):
        now = [100.0]
        store = StrategyStateStore(max_entries=3, ttl_seconds=60, clock=lambda: now[0])
        plan = [{"name": "rate_limit_strict", "params": {"max_rps": 1}}]
        with patch("defense.app.main.strategy_state", store), patch(
            "defense.app.strategies.rate_limit.time.monotonic", side_effect=lambda: now[0]
        ):
            self.assertIsNone((await _apply_plan(plan, request("a"))).short_circuit)
            blocked = await _apply_plan(plan, request("a"))
            self.assertEqual(blocked.short_circuit.status_code, 429)
            self.assertEqual(blocked.short_circuit.headers["X-Defense-Signal"], "rate_limited")
            self.assertIsNone((await _apply_plan(plan, request("b"))).short_circuit)
            now[0] += 1.1
            self.assertIsNone((await _apply_plan(plan, request("a"))).short_circuit)
            self.assertEqual((await _apply_plan(plan, request("a"))).short_circuit.status_code, 429)

    async def test_concurrent_requests_share_one_client_state(self):
        store = StrategyStateStore(max_entries=2, ttl_seconds=60)
        with patch("defense.app.main.strategy_state", store), patch.dict(
            "defense.app.main.STRATEGY_REGISTRY", {"counting": CountingStrategy()}
        ):
            results = await asyncio.gather(*[
                _apply_plan([{"name": "counting"}], request("a")) for _ in range(20)
            ])
        self.assertEqual(sorted(int(result.headers["X-Count"]) for result in results), list(range(1, 21)))


class ProxyContractTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        event_store._events.clear()

    async def test_response_transform_runs_after_backend_and_records_correlation(self):
        captured = []

        def backend(req):
            captured.append(req)
            return httpx.Response(200, content=b"backend", headers={"X-Defense-Signal": "spoofed"})

        upstream = httpx.AsyncClient(transport=httpx.MockTransport(backend))
        app.state.http_client = upstream
        async with upstream, httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://defense") as client:
            with patch.dict("defense.app.main.STRATEGY_REGISTRY", {"test_transform": TransformStrategy()}):
                response = await client.get("/item", headers={
                    "X-Defense-Plan": json.dumps([{"name": "test_transform"}]),
                    "X-Ruby-Request-Id": "request-123",
                    "X-Ruby-Automation-Score": "0.2",
                    "X-Ruby-Attack-Score": "0.9",
                    "X-Ruby-Risk-Score": "0.9",
                    "X-Ruby-Policy-Source": "session",
                })

        self.assertEqual(response.text, "backend transformed")
        self.assertEqual(response.headers["X-Defense-Applied"], "test_transform")
        self.assertNotIn("x-defense-signal", response.headers)
        self.assertNotIn("x-ruby-request-id", captured[0].headers)
        self.assertNotIn("x-ruby-attack-score", captured[0].headers)
        event = event_store.recent(1)[0]
        self.assertEqual(event["requestId"], "request-123")
        self.assertEqual(event["attackScore"], 0.9)
        self.assertEqual(event["riskScore"], 0.9)
        self.assertEqual(event["policySource"], "session")
        self.assertEqual(event["outcome"], "forwarded")

    async def test_clean_stream_records_after_completion(self):
        class CompleteStream(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield b"complete"

            async def aclose(self):
                pass

        upstream = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda req: httpx.Response(200, stream=CompleteStream(), headers={"X-Defense-Signal": "spoofed"})
        ))
        app.state.http_client = upstream
        async with upstream, httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://defense") as client:
            response = await client.get("/item")
        self.assertEqual(response.content, b"complete")
        self.assertNotIn("x-defense-signal", response.headers)
        self.assertEqual(event_store.recent(1)[0]["outcome"], "forwarded")

    async def test_transform_body_limit_returns_502_and_records_error(self):
        upstream = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda req: httpx.Response(200, content=b"too large")
        ))
        app.state.http_client = upstream
        async with upstream, httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://defense") as client:
            with patch.dict("defense.app.main.STRATEGY_REGISTRY", {"test_transform": TransformStrategy()}), patch(
                "defense.app.main.TRANSFORM_BODY_LIMIT", 3
            ):
                response = await client.get("/item", headers={
                    "X-Defense-Plan": json.dumps([{"name": "test_transform"}])
                })
        self.assertEqual(response.status_code, 502)
        self.assertEqual(event_store.recent(1)[0]["outcome"], "error")

    async def test_http_rate_limit_blocks_only_selected_client_and_skips_backend(self):
        class BodyStream(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield b"backend"

            async def aclose(self):
                pass

        backend_calls = []

        def backend(req):
            backend_calls.append(req.url.path)
            return httpx.Response(200, stream=BodyStream())

        upstream = httpx.AsyncClient(transport=httpx.MockTransport(backend))
        app.state.http_client = upstream
        store = StrategyStateStore(max_entries=10, ttl_seconds=60)
        plan = json.dumps([{"name": "rate_limit_strict", "params": {"max_rps": 1}}])
        async with upstream, httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://defense") as client:
            with patch("defense.app.main.strategy_state", store):
                first = await client.get("/item", headers={"X-Client-Id": "a", "X-Defense-Plan": plan})
                blocked = await client.get("/item", headers={"X-Client-Id": "a", "X-Defense-Plan": plan})
                other = await client.get("/item", headers={"X-Client-Id": "b", "X-Defense-Plan": plan})

        self.assertEqual([first.status_code, blocked.status_code, other.status_code], [200, 429, 200])
        self.assertEqual(blocked.headers["X-Defense-Signal"], "rate_limited")
        self.assertEqual(backend_calls, ["/item", "/item"])
        self.assertEqual([event["outcome"] for event in reversed(event_store.recent(3))], [
            "forwarded", "blocked", "forwarded"
        ])
        self.assertEqual(event_store.recent(2)[1]["defenseSignal"], "rate_limited")

    async def test_interrupted_stream_is_recorded_as_error(self):
        class BrokenStream(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield b"partial"
                raise httpx.ReadError("upstream interrupted")

            async def aclose(self):
                pass

        upstream = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda req: httpx.Response(200, stream=BrokenStream())
        ))
        app.state.http_client = upstream
        async with upstream, httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://defense") as client:
            with self.assertRaises(Exception):
                await client.get("/item", headers={"X-Ruby-Request-Id": "stream-123"})
        event = event_store.recent(1)[0]
        self.assertEqual(event["requestId"], "stream-123")
        self.assertEqual(event["outcome"], "error")
        # Headers were already sent; the stream is interrupted and cannot become a 502.
        self.assertEqual(event["status"], 200)


class WebSocketContractTests(unittest.TestCase):
    def test_management_upgrade_is_rejected(self):
        manager = DashboardAuthManager(password="test-password")
        with patch("defense.app.main.auth_manager", manager):
            with TestClient(app) as client:
                with self.assertRaises(Exception) as rejected:
                    with client.websocket_connect("/__defense/api/snapshot"):
                        pass
                token = manager.login("test-password", "test-client")
                with self.assertRaises(Exception) as authenticated_rejected:
                    with client.websocket_connect(
                        "/__defense/api/snapshot",
                        headers={"Cookie": f"defense_dashboard_session={token}"},
                    ):
                        pass
        self.assertEqual(rejected.exception.code, 1008)
        self.assertEqual(rejected.exception.reason, "dashboard authentication required")
        self.assertEqual(authenticated_rejected.exception.code, 1008)
        self.assertEqual(authenticated_rejected.exception.reason, "management websocket unsupported")

    def test_blocked_target_upgrade_is_recorded(self):
        event_store._events.clear()
        with patch.dict("defense.app.main.STRATEGY_REGISTRY", {"test_block": BlockStrategy()}):
            with TestClient(app) as client:
                with self.assertRaises(Exception) as rejected:
                    with client.websocket_connect(
                        "/ws", headers={"X-Defense-Plan": json.dumps([{"name": "test_block"}])}
                    ):
                        pass
        self.assertEqual(rejected.exception.code, 1008)
        self.assertEqual(event_store.recent(1)[0]["outcome"], "blocked")


if __name__ == "__main__":
    unittest.main()
