import json
import unittest
import uuid
from unittest.mock import patch

import httpx

from defense.app.decoy_routing import (
    applied_decoy_strategies, decoy_action, parse_decoy_upstreams,
)
from defense.app.main import app
from defense.app.monitoring import event_store
from defense.app.target_selection import TargetSelector


class EmptyStream(httpx.AsyncByteStream):
    async def __aiter__(self):
        yield b""

    async def aclose(self):
        pass


class DecoyConfigurationTests(unittest.TestCase):
    def test_sidecars_are_limited_to_distinct_configured_target_origins(self):
        targets = {"juice-shop", "ruby-shop"}
        self.assertEqual(parse_decoy_upstreams(None, targets), {})
        fixed = "juice-shop=http://cheat-juice:3012,ruby-shop=http://cheat-ruby:3012"
        self.assertEqual(parse_decoy_upstreams(fixed, {"legacy"}), {})
        self.assertEqual(parse_decoy_upstreams(fixed, {"legacy", "juice-shop"}), {
            "juice-shop": "http://cheat-juice:3012",
        })
        self.assertEqual(
            parse_decoy_upstreams(fixed, targets),
            {"juice-shop": "http://cheat-juice:3012", "ruby-shop": "http://cheat-ruby:3012"},
        )
        for invalid in (
            "missing=http://cheat:3012/other",
            "invalid id=http://cheat:3012",
            "juice-shop=http://cheat:3012/other",
            "juice-shop=http://user:pass@cheat:3012",
            "juice-shop=http://cheat:3012,juice-shop=http://other:3012",
            "juice-shop=http://cheat:3012,ruby-shop=http://cheat:3012",
            "missing=http://cheat:3012,missing=http://other:3012",
            "missing=http://cheat:3012,juice-shop=http://cheat:3012",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                parse_decoy_upstreams(invalid, targets)

    def test_sidecar_telemetry_only_accepts_known_bounded_names(self):
        self.assertEqual(decoy_action({"x-ruby-decoy-action": "ambig-block"}), "ambig-block")
        self.assertIsNone(decoy_action({"x-ruby-decoy-action": "blocked\r\nX-Forged: yes"}))
        self.assertEqual(
            applied_decoy_strategies({"x-ruby-decoy-strategies": "decoy_maze,delay,decoy_maze,decoy_t21_shell"}),
            ["decoy_maze", "decoy_t21_shell"],
        )


class DecoyProxyContractTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        event_store._events.clear()
        self.selector = TargetSelector.from_environment({
            "TARGET_CHOICES": (
                "legacy=http://localhost:3000,"
                "juice-shop=http://juice-shop-target:3000,"
                "ruby-shop=http://ruby-web-target:8080"
            )
        })
        self.sidecars = {
            "juice-shop": "http://cheat-juice:3012",
            "ruby-shop": "http://cheat-ruby:3012",
        }

    async def test_selected_http_target_uses_private_sidecar_and_only_decoy_plan(self):
        captured = []

        def backend(req):
            captured.append(req)
            return httpx.Response(
                302,
                headers={
                    "Location": "http://juice-shop-target:3000/login",
                    "X-Ruby-Decoy-Action": "maze",
                    "X-Ruby-Decoy-Strategies": "decoy_maze",
                },
                stream=EmptyStream(),
            )

        upstream = httpx.AsyncClient(transport=httpx.MockTransport(backend))
        app.state.http_client = upstream
        run_id = str(uuid.uuid4())
        plan = [
            {"name": "delay", "params": {"delay_ms": 0}},
            {"name": "decoy_maze", "params": {}},
            {"name": "rate_limit_strict", "params": {"max_rps": 1}},
        ]
        async with upstream, httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://defense"
        ) as client:
            with patch("defense.app.target_selection.target_selector", self.selector), patch(
                "defense.app.main.DECOY_UPSTREAMS", self.sidecars
            ):
                response = await client.get("/item", headers={
                    "X-Ruby-Target-Id": "juice-shop",
                    "X-Ruby-Run-Id": run_id,
                    "X-Ruby-Request-Id": "request-decoy-1",
                    "X-Ruby-Attack-Score": "0.7",
                    "X-Client-Id": "client-a",
                    "X-Defense-Plan": json.dumps(plan),
                    "X-Ruby-Decoy-Action": "ambig-block",
                    "X-Ruby-Decoy-Strategies": "decoy_migration",
                })

        self.assertEqual(str(captured[0].url), "http://cheat-juice:3012/item")
        self.assertEqual(captured[0].headers["x-client-id"], "client-a")
        self.assertEqual(captured[0].headers["x-ruby-run-id"], run_id)
        self.assertEqual(captured[0].headers["x-ruby-request-id"], "request-decoy-1")
        self.assertEqual(captured[0].headers["x-ruby-target-id"], "juice-shop")
        self.assertEqual(json.loads(captured[0].headers["x-defense-plan"]), [plan[1]])
        self.assertNotIn("x-ruby-attack-score", captured[0].headers)
        self.assertNotIn("x-ruby-decoy-action", captured[0].headers)
        self.assertNotIn("x-ruby-decoy-strategies", captured[0].headers)
        self.assertEqual(response.headers["location"], "http://defense/login")
        # 공개 응답에는 미끼 전략 이름이 없다(이벤트 기록에는 있다 — 아래 event["strategies"]).
        self.assertEqual(response.headers["x-defense-applied"], "delay,rate_limit_strict")
        self.assertNotIn("x-ruby-decoy-action", response.headers)
        self.assertNotIn("x-ruby-decoy-strategies", response.headers)
        event = event_store.recent(1)[0]
        self.assertEqual(event["requestId"], "request-decoy-1")
        self.assertEqual(event["targetId"], "juice-shop")
        self.assertEqual(event["runId"], run_id)
        self.assertEqual(event["strategies"], ["delay", "rate_limit_strict", "decoy_maze"])
        self.assertEqual(event["decoyAction"], "maze")
        self.assertEqual(event["outcome"], "forwarded")

    async def test_sidecar_server_headers_reach_the_client_but_target_server_header_does_not(self):
        def sidecar(req):
            return httpx.Response(200, headers={
                "Server": "Apache/2.4.49 (Unix)", "X-Powered-By": "PHP/7.4.19",
                "X-Ruby-Decoy-Action": "transform-route", "X-Ruby-Decoy-Strategies": "decoy_t21_shell",
            }, stream=EmptyStream())

        def direct(req):
            return httpx.Response(200, headers={"Server": "internal-origin/9.9"}, stream=EmptyStream())

        plan = [{"name": "decoy_t21_shell", "params": {}}]
        for handler, sidecars, label in ((sidecar, self.sidecars, "사이드카"), (direct, {}, "직접")):
            upstream = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            app.state.http_client = upstream
            async with upstream, httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://defense"
            ) as client:
                with patch("defense.app.target_selection.target_selector", self.selector), patch(
                    "defense.app.main.DECOY_UPSTREAMS", sidecars
                ):
                    response = await client.get("/server-status", headers={
                        "X-Ruby-Target-Id": "juice-shop", "X-Ruby-Run-Id": str(uuid.uuid4()),
                        "X-Client-Id": "client-s", "X-Defense-Plan": json.dumps(plan),
                    })
            if label == "사이드카":
                self.assertEqual(response.headers["server"], "Apache/2.4.49 (Unix)")
                self.assertEqual(response.headers["x-powered-by"], "PHP/7.4.19")
            else:
                self.assertNotIn("server", response.headers)        # 대상이 직접 내는 Server 는 지금처럼 버린다
            self.assertEqual(response.headers["x-defense-applied"], "none")
            self.assertNotIn("decoy", ",".join(f"{k}:{v}" for k, v in response.headers.items()).lower())

    async def test_sidecar_block_is_recorded_but_direct_target_cannot_spoof_action(self):
        captured = []

        def backend(req):
            captured.append(str(req.url))
            return httpx.Response(403, headers={
                "X-Ruby-Decoy-Action": "ambig-block",
                "X-Ruby-Decoy-Strategies": "decoy_migration",
            }, stream=EmptyStream())

        upstream = httpx.AsyncClient(transport=httpx.MockTransport(backend))
        app.state.http_client = upstream
        async with upstream, httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://defense"
        ) as client:
            with patch("defense.app.target_selection.target_selector", self.selector), patch(
                "defense.app.main.DECOY_UPSTREAMS", self.sidecars
            ):
                sidecar_response = await client.get("/api/orders", headers={
                    "X-Ruby-Target-Id": "ruby-shop",
                    "X-Ruby-Run-Id": str(uuid.uuid4()),
                })
            with patch("defense.app.target_selection.target_selector", self.selector), patch(
                "defense.app.main.DECOY_UPSTREAMS", {}
            ):
                direct_response = await client.get("/api/orders", headers={
                    "X-Ruby-Target-Id": "ruby-shop",
                    "X-Ruby-Run-Id": str(uuid.uuid4()),
                })

        self.assertEqual(captured, [
            "http://cheat-ruby:3012/api/orders",
            "http://ruby-web-target:8080/api/orders",
        ])
        self.assertEqual(sidecar_response.status_code, 403)
        self.assertEqual(direct_response.status_code, 403)
        self.assertNotIn("x-ruby-decoy-action", direct_response.headers)
        direct, sidecar = event_store.recent(2)
        self.assertEqual((sidecar["outcome"], sidecar["decoyAction"]), ("blocked", "ambig-block"))
        self.assertEqual(sidecar["strategies"], ["decoy_migration"])
        self.assertEqual((direct["outcome"], direct["decoyAction"]), ("forwarded", None))
        self.assertEqual(direct["strategies"], [])


if __name__ == "__main__":
    unittest.main()
