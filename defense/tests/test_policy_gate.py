"""The local deception gate shares Defense policy state with proxied traffic."""

import hashlib
import hmac
import json
import time
import unittest
import uuid
from unittest.mock import patch

import httpx

from defense.app.main import app
from defense.app.strategies.base import DefenseResult, DefenseStrategy
from defense.app.strategies.state import StrategyStateStore
from defense.app.target_selection import TargetSelector


KEY = b"policy-gate-secret-0123456789abcdef0123456789abcdef"
RUN_ID = str(uuid.uuid4())
PLANS = {
    1: [{"name": "decoy_maze", "params": {}}],
    2: [
        {"name": "decoy_maze", "params": {}},
        {"name": "account_overlay_medium", "params": {}},
        {"name": "delay", "params": {"delay_ms": 300}},
    ],
    3: [
        {"name": "decoy_maze", "params": {}},
        {"name": "account_overlay_medium", "params": {}},
        {"name": "delay", "params": {"delay_ms": 500}},
    ],
    4: [
        {"name": "decoy_maze", "params": {}},
        {"name": "delay", "params": {"delay_ms": 700}},
        {"name": "rate_limit_strict", "params": {"max_rps": 1}},
        {"name": "account_overlay_high", "params": {}},
    ],
}
SCORES = {1: 0, 2: 0.25, 3: 0.5, 4: 0.8}


class StickyRoutes:
    def __init__(self):
        self.tiers = {}

    def observe(self, actor, requested):
        previous = self.tiers.get(actor)
        tier = "high" if "high" in (previous, requested) else requested or previous
        if tier:
            self.tiers[actor] = tier
        return tier


class InstantDelay(DefenseStrategy):
    name = "delay"
    uses_state = False

    async def apply(self, request, params, state):
        return DefenseResult(extra_headers={"X-Defense-Delay-Ms": str(params["delay_ms"])})


class PolicyGateTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.selector = TargetSelector({"ruby-shop": "http://real.invalid:8080"}, "ruby-shop", None)
        self.routes = StickyRoutes()
        self.state = StrategyStateStore()
        self.patches = [
            patch("defense.app.main.OVERLAY_DETECTOR_KEY", KEY),
            patch("defense.app.main.OVERLAY_UPSTREAMS", {"ruby-shop": "http://overlay.invalid:8080"}),
            patch("defense.app.main.target_selection.target_selector", self.selector),
            patch("defense.app.main.strategy_state", self.state),
            patch.object(app.state, "overlay_routes", self.routes, create=True),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    async def asyncSetUp(self):
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://defense")
        self.addAsyncCleanup(self.client.aclose)

    def payload(self, stage=1, client_id="same-client"):
        return {
            "targetId": "ruby-shop", "runId": RUN_ID, "clientId": client_id,
            "riskScore": SCORES[stage], "confirmedAttackScore": SCORES[stage],
            "plan": PLANS[stage], "requestId": f"request:{uuid.uuid4()}",
            "issuedAt": int(time.time()),
        }

    async def gate(self, payload, *, key=KEY):
        body = json.dumps(payload, separators=(",", ":")).encode()
        signature = hmac.new(key, body, hashlib.sha256).hexdigest()
        return await self.client.post(
            "/__defense/policy-gate", content=body,
            headers={"X-Defense-Policy-Signature": signature,
                     "Content-Type": "application/json"},
        )

    def response_signature(self, payload, status, tier=None, delay=None, signal=None):
        body = json.dumps(payload, separators=(",", ":")).encode()
        fields = ["ruby:policy-gate-response:v1", hashlib.sha256(body).hexdigest(),
                  str(status), tier or "", delay or "", signal or ""]
        return hmac.new(KEY, "\n".join(fields).encode(), hashlib.sha256).hexdigest()

    async def test_stages_apply_one_selected_delay_and_upgrade_sticky_overlay(self):
        for stage, expected_tier, expected_delay in (
            (1, None, None), (2, "medium", "300"),
            (3, "medium", "500"), (4, "high", "700"),
        ):
            payload = self.payload(stage, client_id=f"stage-{stage}")
            started = time.perf_counter()
            response = await self.gate(payload)
            elapsed = time.perf_counter() - started
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {"tier": expected_tier})
            self.assertEqual(response.headers.get("x-defense-delay-ms"), expected_delay)
            self.assertEqual(response.headers["x-defense-policy-response-signature"],
                             self.response_signature(payload, 200, expected_tier,
                                                     expected_delay))
            if expected_delay:
                self.assertGreaterEqual(elapsed, int(expected_delay) / 1000 - 0.025)
                self.assertLess(elapsed, int(expected_delay) / 1000 + 0.5)
        # A low current score does not release an earlier overlay actor.
        self.assertEqual((await self.gate(self.payload(2))).json(), {"tier": "medium"})
        self.assertEqual((await self.gate(self.payload(1))).json(), {"tier": "medium"})

    async def test_stage4_gate_and_normal_proxy_share_one_rate_bucket(self):
        from defense.app.main import STRATEGY_REGISTRY
        with patch.dict(STRATEGY_REGISTRY, {"delay": InstantDelay()}):
            payload = self.payload(4)
            first = await self.gate(payload)
            self.assertEqual(first.status_code, 200)
            ordinary = await self.client.get("/ordinary", headers={
                "X-Client-Id": payload["clientId"],
                "X-Ruby-Target-Id": payload["targetId"],
                "X-Ruby-Run-Id": payload["runId"],
                "X-Ruby-Risk-Score": str(payload["riskScore"]),
                "X-Ruby-Confirmed-Attack-Score": str(payload["confirmedAttackScore"]),
                "X-Defense-Plan": json.dumps(payload["plan"]),
            })
            self.assertEqual(ordinary.status_code, 429)
            self.assertEqual(ordinary.headers["x-defense-signal"], "rate_limited")
            self.assertEqual(ordinary.headers["x-defense-delay-ms"], "700")

    async def test_bad_signature_stale_timestamp_and_invalid_plan_never_consume_state(self):
        payload = self.payload(4)
        self.assertEqual((await self.gate(payload, key=b"wrong" * 8)).status_code, 403)
        stale = {**payload, "issuedAt": int(time.time()) - 31}
        self.assertEqual((await self.gate(stale)).status_code, 400)
        mismatched = {**payload, "plan": PLANS[1]}
        self.assertEqual((await self.gate(mismatched)).status_code, 503)
        bad_target = {**payload, "targetId": "outside"}
        self.assertEqual((await self.gate(bad_target)).status_code, 503)
        self.assertEqual((await self.gate(payload)).status_code, 200)
        blocked = await self.gate(payload)
        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(blocked.headers["x-defense-signal"], "rate_limited")
        self.assertEqual(blocked.headers.get_list("x-defense-delay-ms"), ["700"])
        self.assertEqual(blocked.headers["x-defense-policy-response-signature"],
                         self.response_signature(payload, 429, delay="700",
                                                 signal="rate_limited"))


if __name__ == "__main__":
    unittest.main()
