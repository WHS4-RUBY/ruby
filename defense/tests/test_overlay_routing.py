import hashlib
import hmac
import json
import tempfile
from types import SimpleNamespace
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import httpx
from starlette.websockets import WebSocket

from defense.app.main import app, websocket_proxy
from defense.app.monitoring import event_store
from defense.app.overlay_routing import (
    OVERLAY_HIGH, OVERLAY_MEDIUM, OverlayRouteError, OverlayRouteStore,
    actor_id, parse_overlay_upstreams, requested_tier,
)
from defense.app.strategies.state import StrategyStateStore
from defense.app.target_selection import TargetSelector


KEY = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


class BytesStream(httpx.AsyncByteStream):
    def __init__(self, body):
        self.body = body

    async def __aiter__(self):
        yield self.body

    async def aclose(self):
        pass


def plan(*names):
    return json.dumps([{"name": name, "params": {"max_rps": 1} if name == "rate_limit_strict" else {}}
                       for name in names])


class OverlayStoreTests(unittest.TestCase):
    def test_virgin_bootstrap_is_sticky_key_bound_and_run_scoped(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "routes.sqlite3")
            targets = {"juice-shop", "ruby-shop"}
            store = OverlayRouteStore.bootstrap(path, KEY, targets)
            first = actor_id(KEY, "juice-shop", "run-a", "client:one")
            other_run = actor_id(KEY, "juice-shop", "run-b", "client:one")
            other_target = actor_id(KEY, "ruby-shop", "run-a", "client:one")
            self.assertEqual(len(first), 64)
            self.assertNotEqual(first, other_run)
            self.assertNotEqual(first, other_target)
            self.assertEqual(store.observe(first, "medium"), "medium")
            self.assertEqual(store.observe(first, None), "medium")
            self.assertEqual(store.observe(first, "high"), "high")
            self.assertEqual(OverlayRouteStore.bootstrap(path, KEY, targets).observe(first, None), "high")
            self.assertIsNone(store.observe(other_run, None))
            with self.assertRaises(OverlayRouteError):
                OverlayRouteStore.bootstrap(path, b"a" * 32, targets)
            with self.assertRaises(OverlayRouteError):
                OverlayRouteStore.bootstrap(path, KEY, {"juice-shop"})
            with self.assertRaises(OverlayRouteError):
                OverlayRouteStore.bootstrap(path, KEY, ())
            Path(path).unlink()
            with self.assertRaises(OverlayRouteError):
                OverlayRouteStore.bootstrap(path, KEY, targets)

    def test_score_and_plan_must_agree(self):
        medium = [{"name": OVERLAY_MEDIUM, "params": {}}]
        high = [{"name": "rate_limit_strict", "params": {"max_rps": 1}},
                {"name": OVERLAY_HIGH, "params": {}}]
        self.assertEqual(requested_tier(medium, risk_score=0.6, confirmed_attack_score=0.6), "medium")
        self.assertEqual(requested_tier(high, risk_score=0.95, confirmed_attack_score=0.95), "high")
        self.assertIsNone(requested_tier(
            [{"name": "decoy_maze", "params": {}}],
            risk_score=0.9, confirmed_attack_score=0.0,
        ))
        for invalid, risk, confirmed in (
            (medium, 0.6, None), (medium, 0.6, 0.8), (high, 0.95, 0.9),
            (medium + high, 0.99, 0.99),
            ([{"name": OVERLAY_HIGH, "params": {}}], 0.99, 0.99),
            ([], 0.9, 0.9),
        ):
            with self.subTest(invalid=invalid, risk=risk, confirmed=confirmed):
                with self.assertRaises(OverlayRouteError):
                    requested_tier(invalid, risk_score=risk, confirmed_attack_score=confirmed)

    def test_overlay_origins_are_private_fixed_per_configured_target(self):
        self.assertEqual(parse_overlay_upstreams(
            "juice-shop=http://overlay-juice:8080,ruby-shop=http://overlay-ruby:8080",
            {"juice-shop", "ruby-shop"}), {
                "juice-shop": "http://overlay-juice:8080", "ruby-shop": "http://overlay-ruby:8080",
            })
        for invalid in ("juice-shop=http://overlay:8080/subpath",
                        "juice-shop=http://overlay:8080,ruby-shop=http://overlay:8080",
                        "juice-shop=http://u:p@overlay:8080",
                        "unknown=http://overlay:8080"):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                parse_overlay_upstreams(invalid, {"juice-shop", "ruby-shop"})


class OverlayProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        event_store._events.clear()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = OverlayRouteStore.bootstrap(str(Path(self.temporary.name) / "routes.sqlite3"),
                                                 KEY, {"juice-shop"})
        self.run_id = str(uuid.uuid4())
        self.selector = TargetSelector.from_environment({
            "TARGET_CHOICES": "juice-shop=http://juice-shop-target:3000",
            "TARGET_DEFAULT_ID": "juice-shop",
        })
        self.calls = []

        def backend(req):
            self.calls.append(req)
            if req.url.host == "overlay-juice":
                # Independently verify the PR34 signed-header input contract.
                signed = req.headers
                fields = ["agent", signed["x-defense-actor"], signed["x-defense-timestamp"],
                          signed["x-defense-nonce"], req.method,
                          req.url.raw_path.decode("ascii"), hashlib.sha256(req.content).hexdigest()]
                if "x-defense-risk" in signed:
                    fields.append(signed["x-defense-risk"])
                expected = hmac.new(KEY, "\n".join(fields).encode(), hashlib.sha256).hexdigest()
                self.assertEqual(signed["x-defense-signature"], expected)
                return httpx.Response(404 if "x-defense-risk" in signed else 200,
                                      stream=BytesStream(b"overlay"), headers={"X-Defense-Signal": "forged"})
            return httpx.Response(200, stream=BytesStream(b"sidecar"), headers={
                "X-Ruby-Decoy-Action": "maze", "X-Ruby-Decoy-Strategies": "decoy_maze",
            })

        self.upstream = httpx.AsyncClient(transport=httpx.MockTransport(backend))
        app.state.http_client = self.upstream
        self.addAsyncCleanup(self.upstream.aclose)

    def headers(self, client_id, risk, confirmed, defense_plan):
        return {
            "X-Ruby-Target-Id": "juice-shop", "X-Ruby-Run-Id": self.run_id,
            "X-Client-Id": client_id, "X-Ruby-Risk-Score": str(risk),
            "X-Ruby-Confirmed-Attack-Score": str(confirmed),
            "X-Defense-Plan": defense_plan,
            "X-Defense-Class": "forged", "X-Defense-Signature": "forged",
        }

    async def test_startup_rejects_removed_overlay_target_even_when_mapping_is_empty(self):
        path = str(Path(self.temporary.name) / "deployment" / "routes.sqlite3")
        OverlayRouteStore.bootstrap(path, KEY, {"juice-shop", "ruby-shop"})
        self.assertTrue(OverlayRouteStore.exists(path))
        for mappings in ({}, {"juice-shop": "http://overlay-juice:8080"}):
            with self.subTest(mappings=mappings), patch(
                "defense.app.main.OVERLAY_UPSTREAMS", mappings
            ), patch("defense.app.main.OVERLAY_STATE_DB", path), patch(
                "defense.app.main.OVERLAY_DETECTOR_KEY", KEY
            ), self.assertRaises(OverlayRouteError):
                async with app.router.lifespan_context(app):
                    pass

    async def test_medium_sticks_through_cheat_band_high_upgrades_and_429_precedes_proxy(self):
        now = [100.0]
        overlays = {"juice-shop": "http://overlay-juice:8080"}
        decoys = {"juice-shop": "http://cheat-juice:3012"}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://defense") as client:
            with patch("defense.app.target_selection.target_selector", self.selector), patch(
                "defense.app.main.OVERLAY_UPSTREAMS", overlays
            ), patch("defense.app.main.DECOY_UPSTREAMS", decoys), patch(
                "defense.app.main.OVERLAY_DETECTOR_KEY", KEY
            ), patch.object(app.state, "overlay_routes", self.store, create=True), patch(
                "defense.app.main.strategy_state", StrategyStateStore()
            ), patch("defense.app.strategies.rate_limit.time", SimpleNamespace(monotonic=lambda: now[0])):
                medium = await client.post(
                    "/api/search?x=%2B&x=%252F", content=b"a=1",
                    headers=self.headers("resolved:actor-a", 0.6, 0.6, plan(OVERLAY_MEDIUM)),
                )
                now[0] += 2
                sticky_medium = await client.get(
                    "/api/products", headers=self.headers(
                        "resolved:actor-a", 0.85, 0.85,
                        plan("rate_limit_strict", "decoy_maze"),
                    ),
                )
                fresh_cheat = await client.get(
                    "/api/products", headers=self.headers(
                        "resolved:actor-b", 0.85, 0.85,
                        plan("rate_limit_strict", "decoy_maze"),
                    ),
                )
                now[0] += 2
                high = await client.get(
                    "/api/orders", headers=self.headers(
                        "resolved:actor-a", 0.97, 0.97,
                        plan("rate_limit_strict", OVERLAY_HIGH),
                    ),
                )
                blocked = await client.get(
                    "/api/orders", headers=self.headers(
                        "resolved:actor-a", 0.97, 0.97,
                        plan("rate_limit_strict", OVERLAY_HIGH),
                    ),
                )
                sticky_high = await client.get(
                    "/api/orders", headers=self.headers("resolved:actor-a", 0.1, 0.1, plan()),
                )

        self.assertEqual([r.status_code for r in
                          (medium, sticky_medium, fresh_cheat, high, blocked, sticky_high)],
                         [200, 200, 200, 404, 429, 404])
        self.assertEqual([req.url.host for req in self.calls],
                         ["overlay-juice", "overlay-juice", "cheat-juice",
                          "overlay-juice", "overlay-juice"])
        self.assertEqual(self.calls[0].url.raw_path, b"/api/search?x=%2B&x=%252F")
        self.assertEqual(self.calls[0].content, b"a=1")
        self.assertNotEqual(self.calls[0].headers["x-defense-class"], "forged")
        self.assertNotEqual(self.calls[0].headers["x-defense-signature"], "forged")
        self.assertNotIn("x-ruby-confirmed-attack-score", self.calls[0].headers)
        self.assertNotIn("x-defense-risk", self.calls[0].headers)
        self.assertEqual(self.calls[3].headers["x-defense-risk"], "high")
        self.assertEqual(self.calls[4].headers["x-defense-risk"], "high")
        self.assertNotIn("x-defense-signal", high.headers)
        self.assertEqual(medium.headers["x-defense-applied"], "none")
        events = list(reversed(event_store.recent(6)))
        self.assertEqual(events[0]["strategies"], [OVERLAY_MEDIUM])
        self.assertEqual(events[0]["confirmedAttackScore"], 0.6)
        self.assertEqual(events[0]["decoyAction"], "account-overlay-medium")
        self.assertEqual(events[1]["strategies"], ["rate_limit_strict", OVERLAY_MEDIUM])
        self.assertEqual(events[2]["strategies"], ["rate_limit_strict", "decoy_maze"])
        self.assertEqual(events[3]["strategies"], ["rate_limit_strict", OVERLAY_HIGH])
        self.assertEqual(events[3]["confirmedAttackScore"], 0.97)
        self.assertEqual(events[3]["decoyAction"], "account-overlay-high")
        self.assertEqual(events[3]["outcome"], "blocked")
        self.assertEqual(events[4]["strategies"], ["rate_limit_strict"])
        self.assertEqual(events[4]["status"], 429)
        self.assertEqual(events[4]["defenseSignal"], "rate_limited")
        self.assertEqual(events[5]["strategies"], [OVERLAY_HIGH])

    async def test_suspected_candidate_uses_decoy_without_overlay_or_rate_limit(self):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://defense") as client:
            with patch("defense.app.target_selection.target_selector", self.selector), patch(
                "defense.app.main.OVERLAY_UPSTREAMS", {"juice-shop": "http://overlay-juice:8080"}
            ), patch("defense.app.main.DECOY_UPSTREAMS", {"juice-shop": "http://cheat-juice:3012"}), patch(
                "defense.app.main.OVERLAY_DETECTOR_KEY", KEY
            ), patch.object(app.state, "overlay_routes", self.store, create=True):
                headers = self.headers("actor:cookie-less", 0.9, 0.0, plan("decoy_maze"))
                headers.update({
                    "X-Ruby-Defense-Tier": "suspected",
                    "X-Ruby-Candidate-Id": "actor:cookie-less",
                    "X-Ruby-Client-Flow-Id": "client-flow:observed",
                })
                first = await client.get("/api/products", headers=headers)
                second = await client.get("/api/products", headers=headers)

        self.assertEqual([first.status_code, second.status_code], [200, 200])
        self.assertEqual([request.url.host for request in self.calls],
                         ["cheat-juice", "cheat-juice"])
        events = list(reversed(event_store.recent(2)))
        self.assertEqual([event["strategies"] for event in events],
                         [["decoy_maze"], ["decoy_maze"]])
        self.assertTrue(all(event["defenseTier"] == "suspected" for event in events))
        self.assertTrue(all(event["candidateId"] == "actor:cookie-less" for event in events))
        self.assertTrue(all(event["clientFlowId"] == "client-flow:observed" for event in events))

    async def test_first_high_request_is_sticky_even_when_rate_limited(self):
        now = [100.0]
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://defense") as client:
            with patch("defense.app.target_selection.target_selector", self.selector), patch(
                "defense.app.main.OVERLAY_UPSTREAMS", {"juice-shop": "http://overlay-juice:8080"}
            ), patch("defense.app.main.DECOY_UPSTREAMS", {"juice-shop": "http://cheat-juice:3012"}), patch(
                "defense.app.main.OVERLAY_DETECTOR_KEY", KEY
            ), patch.object(app.state, "overlay_routes", self.store, create=True), patch(
                "defense.app.main.strategy_state", StrategyStateStore()
            ), patch("defense.app.strategies.rate_limit.time", SimpleNamespace(monotonic=lambda: now[0])):
                first = await client.get("/api/products", headers=self.headers(
                    "actor-c", 0.85, 0.85, plan("rate_limit_strict", "decoy_maze")))
                blocked_high = await client.get("/api/products", headers=self.headers(
                    "actor-c", 0.97, 0.97, plan("rate_limit_strict", OVERLAY_HIGH)))
                sticky_high = await client.get("/api/products", headers=self.headers(
                    "actor-c", 0.1, 0.1, plan()))

        self.assertEqual([first.status_code, blocked_high.status_code, sticky_high.status_code],
                         [200, 429, 404])
        self.assertEqual([call.url.host for call in self.calls], ["cheat-juice", "overlay-juice"])
        actor = actor_id(KEY, "juice-shop", self.run_id, "actor-c")
        self.assertEqual(self.store.observe(actor, None), "high")
        events = list(reversed(event_store.recent(3)))
        self.assertEqual(events[1]["status"], 429)
        self.assertEqual(events[1]["defenseSignal"], "rate_limited")
        self.assertEqual(events[1]["strategies"], ["rate_limit_strict"])
        self.assertEqual(events[2]["strategies"], [OVERLAY_HIGH])

    async def test_missing_or_malformed_private_plan_and_scores_fail_closed(self):
        variants = []
        low = self.headers("actor-a", 0.1, 0.1, plan())
        for name in ("X-Defense-Plan", "X-Ruby-Risk-Score", "X-Ruby-Confirmed-Attack-Score"):
            headers = dict(low)
            del headers[name]
            variants.append((name, headers))
        variants.extend((
            ("malformed", {**low, "X-Defense-Plan": "{"}),
            ("filtered", {**low, "X-Defense-Plan": '[{"params":{}}]'}),
            ("medium-missing-marker", self.headers("actor-b", 0.6, 0.6, plan())),
            ("cheat-missing-plan", self.headers("actor-c", 0.85, 0.85, plan())),
            ("high-missing-marker", self.headers("actor-d", 0.97, 0.97, plan())),
        ))
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://defense") as client:
            with patch("defense.app.target_selection.target_selector", self.selector), patch(
                "defense.app.main.OVERLAY_UPSTREAMS", {"juice-shop": "http://overlay-juice:8080"}
            ), patch("defense.app.main.DECOY_UPSTREAMS", {"juice-shop": "http://cheat-juice:3012"}), patch(
                "defense.app.main.OVERLAY_DETECTOR_KEY", KEY
            ), patch.object(app.state, "overlay_routes", self.store, create=True):
                for label, headers in variants:
                    with self.subTest(label=label):
                        response = await client.get("/api/products", headers=headers)
                        self.assertEqual(response.status_code, 503)
                normal = await client.get("/api/products", headers=low)
                just_below_high = await client.get("/api/products", headers=self.headers(
                    "actor-boundary", 0.9499999, 0.9499999,
                    plan("rate_limit_strict", "decoy_maze")))
        self.assertEqual(normal.status_code, 200)
        self.assertEqual(just_below_high.status_code, 200)
        self.assertEqual([call.url.host for call in self.calls], ["cheat-juice", "cheat-juice"])

    async def test_overlay_upstream_rejections_and_failures_are_errors(self):
        def backend(req):
            self.calls.append(req)
            if req.url.path == "/unreachable":
                raise httpx.ConnectError("upstream unavailable", request=req)
            status = 403 if req.url.path == "/rejected" else 502
            return httpx.Response(status, stream=BytesStream(b"error"))

        faulty = httpx.AsyncClient(transport=httpx.MockTransport(backend))
        self.addAsyncCleanup(faulty.aclose)
        app.state.http_client = faulty
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://defense") as client:
            with patch("defense.app.target_selection.target_selector", self.selector), patch(
                "defense.app.main.OVERLAY_UPSTREAMS", {"juice-shop": "http://overlay-juice:8080"}
            ), patch("defense.app.main.OVERLAY_DETECTOR_KEY", KEY), patch.object(
                app.state, "overlay_routes", self.store, create=True
            ):
                for path, status in (("/rejected", 403), ("/upstream-error", 502),
                                     ("/unreachable", 502)):
                    with self.subTest(path=path):
                        response = await client.get(path, headers=self.headers(
                            "actor-" + path, 0.6, 0.6, plan(OVERLAY_MEDIUM)))
                        self.assertEqual(response.status_code, status)
                        event = event_store.recent(1)[0]
                        self.assertEqual(event["outcome"], "error")
                        self.assertEqual(event["strategies"], [OVERLAY_MEDIUM])
                        self.assertEqual(event["decoyAction"], "account-overlay-medium")

    async def test_strategy_failure_after_route_selection_records_overlay_attempt(self):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://defense") as client:
            with patch("defense.app.target_selection.target_selector", self.selector), patch(
                "defense.app.main.OVERLAY_UPSTREAMS", {"juice-shop": "http://overlay-juice:8080"}
            ), patch("defense.app.main.OVERLAY_DETECTOR_KEY", KEY), patch.object(
                app.state, "overlay_routes", self.store, create=True
            ), patch("defense.app.main._apply_plan", side_effect=RuntimeError("strategy failed")):
                response = await client.get("/api/products", headers=self.headers(
                    "actor-error", 0.6, 0.6, plan(OVERLAY_MEDIUM)))
        self.assertEqual(response.status_code, 500)
        self.assertEqual(self.calls, [])
        event = event_store.recent(1)[0]
        self.assertEqual(event["outcome"], "error")
        self.assertEqual(event["strategies"], [OVERLAY_MEDIUM])
        self.assertEqual(event["decoyAction"], "account-overlay-medium")

    async def test_missing_key_and_large_body_fail_without_upstream_contact(self):
        overlays = {"juice-shop": "http://overlay-juice:8080"}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://defense") as client:
            with patch("defense.app.target_selection.target_selector", self.selector), patch(
                "defense.app.main.OVERLAY_UPSTREAMS", overlays
            ), patch("defense.app.main.OVERLAY_DETECTOR_KEY", b""), patch.object(
                app.state, "overlay_routes", self.store, create=True
            ):
                missing = await client.get("/api/products", headers=self.headers(
                    "actor-a", 0.6, 0.6, plan(OVERLAY_MEDIUM)))
            with patch("defense.app.target_selection.target_selector", self.selector), patch(
                "defense.app.main.OVERLAY_UPSTREAMS", overlays
            ), patch("defense.app.main.OVERLAY_DETECTOR_KEY", KEY), patch.object(
                app.state, "overlay_routes", self.store, create=True
            ):
                too_large = await client.post("/api/products", content=b"x" * (1_048_576 + 1),
                                              headers=self.headers("actor-a", 0.6, 0.6,
                                                                   plan(OVERLAY_MEDIUM)))
        self.assertEqual(missing.status_code, 503)
        self.assertEqual(too_large.status_code, 413)
        self.assertEqual(self.calls, [])
        self.assertEqual(event_store.recent(1)[0]["strategies"], [OVERLAY_MEDIUM])
        self.assertEqual(event_store.recent(1)[0]["decoyAction"], "account-overlay-medium")

    async def test_missing_trusted_client_id_cannot_take_normal_cheat_route(self):
        # Production Detection always supplies X-Client-Id. If it disappears,
        # Defense cannot check whether this actor was previously isolated.
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://defense") as client:
            with patch("defense.app.target_selection.target_selector", self.selector), patch(
                "defense.app.main.OVERLAY_UPSTREAMS", {"juice-shop": "http://overlay-juice:8080"}
            ), patch("defense.app.main.OVERLAY_DETECTOR_KEY", KEY), patch.object(
                app.state, "overlay_routes", self.store, create=True
            ), patch("defense.app.main.DECOY_UPSTREAMS", {"juice-shop": "http://cheat-juice:3012"}):
                response = await client.get("/api/products", headers={
                    "X-Ruby-Target-Id": "juice-shop", "X-Ruby-Run-Id": self.run_id,
                    "X-Ruby-Risk-Score": "0", "X-Ruby-Confirmed-Attack-Score": "0",
                    "X-Defense-Plan": "[]",
                })
        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.calls, [])

    async def test_high_risk_websocket_is_closed_before_origin_upgrade(self):
        sent = []

        async def receive():
            return {"type": "websocket.connect"}

        async def send(message):
            sent.append(message)

        headers = self.headers("actor-ws", 0.97, 0.97,
                               plan("rate_limit_strict", OVERLAY_HIGH))
        websocket = WebSocket({
            "type": "websocket", "scheme": "ws", "path": "/socket",
            "raw_path": b"/socket", "query_string": b"",
            "headers": [(key.lower().encode(), value.encode()) for key, value in headers.items()],
            "client": ("127.0.0.1", 1234), "server": ("defense", 8080),
        }, receive=receive, send=send)
        with patch("defense.app.target_selection.target_selector", self.selector), patch(
            "defense.app.main.OVERLAY_UPSTREAMS", {"juice-shop": "http://overlay-juice:8080"}
        ), patch("defense.app.main.OVERLAY_DETECTOR_KEY", KEY), patch.object(
            app.state, "overlay_routes", self.store, create=True
        ), patch("defense.app.main.websockets.connect") as connect:
            await websocket_proxy(websocket, "socket")
        connect.assert_not_called()
        self.assertEqual(sent[-1]["code"], 1008)
        self.assertEqual(event_store.recent(1)[0]["strategies"], ["rate_limit_strict", OVERLAY_HIGH])
        self.assertEqual(event_store.recent(1)[0]["outcome"], "blocked")

    async def test_websocket_rate_limit_records_429_and_signal(self):
        sent = []

        async def receive():
            return {"type": "websocket.connect"}

        async def send(message):
            sent.append(message)

        def websocket():
            headers = self.headers("actor-ws", 0.97, 0.97,
                                   plan("rate_limit_strict", OVERLAY_HIGH))
            return WebSocket({
                "type": "websocket", "scheme": "ws", "path": "/socket",
                "raw_path": b"/socket", "query_string": b"",
                "headers": [(key.lower().encode(), value.encode()) for key, value in headers.items()],
                "client": ("127.0.0.1", 1234), "server": ("defense", 8080),
            }, receive=receive, send=send)

        with patch("defense.app.target_selection.target_selector", self.selector), patch(
            "defense.app.main.OVERLAY_UPSTREAMS", {"juice-shop": "http://overlay-juice:8080"}
        ), patch("defense.app.main.OVERLAY_DETECTOR_KEY", KEY), patch.object(
            app.state, "overlay_routes", self.store, create=True
        ), patch("defense.app.main.strategy_state", StrategyStateStore()), patch(
            "defense.app.strategies.rate_limit.time", SimpleNamespace(monotonic=lambda: 100.0)
        ), patch("defense.app.main.websockets.connect") as connect:
            await websocket_proxy(websocket(), "socket")
            await websocket_proxy(websocket(), "socket")

        connect.assert_not_called()
        self.assertEqual(sent[-1]["code"], 1008)
        event = event_store.recent(1)[0]
        self.assertEqual(event["status"], 429)
        self.assertEqual(event["defenseSignal"], "rate_limited")
        self.assertEqual(event["strategies"], ["rate_limit_strict"])


if __name__ == "__main__":
    unittest.main()
