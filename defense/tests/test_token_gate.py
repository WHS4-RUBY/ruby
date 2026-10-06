import asyncio
import base64
import hashlib
import hmac
import io
import json
import logging
import tempfile
import unittest
from dataclasses import replace
from http.cookies import SimpleCookie
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
from starlette.testclient import TestClient

from defense.app import main, token_gate as tg
from defense.app.strategies.rate_limit import RateLimitStrictStrategy
from defense.scripts import token_gate_smoke as smoke

CFG = tg.TokenGateConfig(mode="enforce", secret=b"test-only-key", epoch_s=10)
NOW = 100.25


def cookie(response):
    for value in response.headers.get_list("set-cookie"):
        parsed = SimpleCookie()
        parsed.load(value)
        if tg.COOKIE_NAME in parsed:
            return parsed[tg.COOKIE_NAME]
    return None


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger(tg.LOGGER_NAME)
        self.previous = (self.logger.handlers[:], self.logger.level, self.logger.propagate)
        self.logger.handlers = []

    def tearDown(self):
        for handler in self.logger.handlers:
            if handler not in self.previous[0]:
                handler.close()
        self.logger.handlers, self.logger.level, self.logger.propagate = self.previous

    def test_off_reads_only_mode_and_does_not_initialize_anything(self):
        class ModeOnly(dict):
            def get(self, key, default=None):
                if key != "TOKEN_GATE_MODE":
                    raise AssertionError(f"off read {key}")
                return "OFF"

        with patch.object(tg.secrets, "token_bytes") as random, patch.object(tg, "_configure_logger") as setup:
            self.assertEqual(tg.TokenGateConfig.from_env(ModeOnly()), tg.TokenGateConfig())
            random.assert_not_called()
            setup.assert_not_called()
        self.assertEqual(self.logger.handlers, [])
        cfg = tg.TokenGateConfig.from_env({"TOKEN_GATE_EPOCH_S": "abc", "TOKEN_GATE_COOKIE_SECURE": "bad"})
        self.assertEqual(cfg.mode, "off")

    def test_active_config_validates_values(self):
        for key, values in {
            "TOKEN_GATE_MODE": ["wrong"], "TOKEN_GATE_EPOCH_S": ["0", "-1", "abc"],
            "TOKEN_GATE_GRACE_EPOCHS": ["-1", "11", "abc"],
            "TOKEN_GATE_COOKIE_SECURE": ["yes"],
        }.items():
            for value in values:
                for mode in ("observe", "enforce"):
                    with self.subTest(key=key, value=value, mode=mode), self.assertRaises(ValueError):
                        tg.TokenGateConfig.from_env({"TOKEN_GATE_MODE": mode, key: value})

    def test_active_config_parses_exempt_secure_and_configures_stdout_once(self):
        env = {"TOKEN_GATE_MODE": "ObServe", "TOKEN_GATE_SECRET": "fixed-test-key",
               "TOKEN_GATE_EXEMPT_PREFIXES": " /healthz, , /test/ ,", "TOKEN_GATE_COOKIE_SECURE": "TRUE"}
        output = io.StringIO()
        with patch.object(tg.sys, "stdout", output):
            cfg = tg.TokenGateConfig.from_env(env)
            tg.TokenGateConfig.from_env(env)
            tg.emit({"event": "token_gate", "label": "test"})
        self.assertEqual(cfg.exempt_prefixes, ("/healthz", "/test/"))
        self.assertEqual(cfg.secret, b"fixed-test-key")
        self.assertTrue(cfg.cookie_secure)
        self.assertEqual(len(self.logger.handlers), 1)
        self.assertEqual(self.logger.level, logging.INFO)
        self.assertFalse(self.logger.propagate)
        self.assertEqual(output.getvalue(), '{"event":"token_gate","label":"test"}\n')

    def test_legacy_enforce_is_observe_with_explicit_warning(self):
        with patch.object(tg.sys, "stdout", new_callable=io.StringIO) as output:
            cfg = tg.TokenGateConfig.from_env({"TOKEN_GATE_MODE": "enforce", "TOKEN_GATE_SECRET": "test"})
        self.assertEqual(cfg.mode, "observe")
        self.assertIn("deprecated", output.getvalue())

    def test_empty_secret_generates_key_and_warns_without_exposing_it(self):
        output = io.StringIO()
        with patch.object(tg.sys, "stdout", output), patch.object(tg.secrets, "token_bytes", return_value=b"private-key"):
            cfg = tg.TokenGateConfig.from_env({"TOKEN_GATE_MODE": "observe"})
        self.assertEqual(cfg.secret, b"private-key")
        self.assertIn("ephemeral key", output.getvalue())
        self.assertNotIn("private-key", output.getvalue())


class TokenTests(unittest.TestCase):
    def test_token_matches_hmac_format_and_is_deterministic(self):
        mac = base64.urlsafe_b64encode(hmac.new(CFG.secret, b"v1.10", hashlib.sha256).digest()).decode()[:22]
        self.assertEqual(tg.make_token(CFG.secret, 10), f"v1.10.{mac}")
        self.assertEqual(tg.make_token(CFG.secret, 10), tg.make_token(CFG.secret, 10))
        self.assertNotEqual(tg.make_token(CFG.secret, 10), tg.make_token(b"other", 10))
        self.assertNotEqual(tg.make_token(CFG.secret, 10), tg.make_token(CFG.secret, 11))

    def test_states_and_malformed_values(self):
        for value, expected in [
            (None, "missing"), (tg.make_token(CFG.secret, 10), "valid"),
            (tg.make_token(CFG.secret, 9), "grace"), (tg.make_token(CFG.secret, 8), "stale"),
            (tg.make_token(CFG.secret, 11), "invalid"), (tg.make_token(b"wrong", 10), "invalid"),
            ("", "invalid"), ("v2.10." + "A" * 22, "invalid"),
            ("v1.1234567890123." + "A" * 22, "invalid"), ("A" * 65, "invalid"),
            ("v1.10." + "!" * 22, "invalid"), (tg.make_token(CFG.secret, 10) + "\n", "invalid"),
        ]:
            with self.subTest(value=value):
                self.assertEqual(tg.token_state(value, CFG.secret, NOW, CFG), expected)

    def test_zero_grace_and_epoch_boundaries(self):
        value = tg.make_token(CFG.secret, 9)
        self.assertEqual(tg.token_state(value, CFG.secret, 99.999, CFG), "valid")
        self.assertEqual(tg.token_state(value, CFG.secret, 100, CFG), "grace")
        self.assertEqual(tg.token_state(value, CFG.secret, 110, CFG), "stale")
        self.assertEqual(tg.token_state(value, CFG.secret, 100, replace(CFG, grace_epochs=0)), "stale")
        self.assertEqual(tg.token_state(value, CFG.secret, 110, replace(CFG, grace_epochs=2)), "grace")

    def test_cookie_lifetime_and_flags(self):
        for cfg, now, expected in [(CFG, 100.001, 19), (CFG, 109.999, 10),
                                   (replace(CFG, grace_epochs=0), 109.999, 1),
                                   (replace(CFG, epoch_s=1, grace_epochs=0), 100.75, 1)]:
            for secure in (False, True):
                with self.subTest(now=now, cfg=cfg, secure=secure):
                    parsed = SimpleCookie()
                    parsed.load(tg.build_set_cookie(replace(cfg, cookie_secure=secure), now))
                    value = parsed[tg.COOKIE_NAME]
                    self.assertEqual(int(value["max-age"]), expected)
                    self.assertEqual(value["path"], "/")
                    self.assertEqual(value["samesite"], "Lax")
                    self.assertTrue(value["httponly"])
                    self.assertEqual(bool(value["secure"]), secure)
                    self.assertEqual(tg.token_state(value.value, cfg.secret, now, cfg), "valid")

    def test_request_classification(self):
        for method, path, headers, expected in [
            ("GET", "/", {"Accept": "text/html,application/xhtml+xml"}, "page"),
            ("HEAD", "/", {"Sec-Fetch-Dest": "document"}, "page"),
            ("GET", "/api", {"Sec-Fetch-Mode": "navigate"}, "page"),
            ("POST", "/", {"Accept": "text/html"}, "api"),
            ("GET", "/", {"Accept": "*/*"}, "api"),
            ("GET", "/image.png", {"Accept": "image/*"}, "api"),
            ("GET", "/socket.io/", {}, "api"), ("OPTIONS", "/api", {}, "exempt"),
            ("GET", "/healthz", {}, "exempt"), ("GET", "/healthz-admin", {}, "api"),
            ("GET", "/__defense/x", {}, "exempt"), ("GET", "/__defense", {}, "api"),
        ]:
            with self.subTest(method=method, path=path, headers=headers):
                self.assertEqual(tg.classify(method, path, headers, CFG.exempt_prefixes), expected)

    def test_user_agent_families(self):
        for value, expected in [(None, "none"), ("", "none"), ("curl/8", "curl"), ("Wget/1", "wget"),
                                ("python-requests/2", "python-requests"), ("Python-urllib/3", "python-urllib"),
                                ("python-httpx/0.27", "httpx"), ("aiohttp/3", "aiohttp"),
                                ("Go-http-client/1.1", "go"), ("node", "node"), ("undici", "node"),
                                ("Mozilla/5.0", "browser"), ("custom", "other")]:
            with self.subTest(value=value):
                self.assertEqual(tg.ua_family(value), expected)

    def test_log_has_only_allowed_metadata(self):
        decision = tg.evaluate("GET", "/api", {}, "private-cookie", NOW, CFG)
        record = tg.build_log(decision, now=NOW, mode="enforce", method="GET", path="/api",
                              headers={"Cookie": "private-cookie", "User-Agent": "curl/8",
                                       "X-Client-Id": "client", "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(set(record), {"event", "ts", "mode", "client_id", "method", "path", "kind",
                                      "token_state", "has_sec_fetch", "ua_family", "decision",
                                      "upstream_status", "observation"})
        self.assertTrue(record["has_sec_fetch"])
        self.assertEqual(record["client_id"], "client")
        self.assertNotIn("private-cookie", json.dumps(record))

    def test_json_observation_is_narrow_and_handles_content_type_parameters(self):
        decision = tg.GateDecision("page", "missing", "issue", issue_cookie=True)
        for method, status, content_type, expected in [
            ("GET", 200, "application/json", "page_declared_json"),
            ("GET", 200, "Application/JSON; charset=utf-8", "page_declared_json"),
            ("GET", 200, "application/problem+json; charset=utf-8", "page_declared_json"),
            ("HEAD", 200, "application/json", None), ("GET", 304, "application/json", None),
            ("GET", 404, "application/json", None), ("GET", 200, "text/html", None),
        ]:
            with self.subTest(method=method, status=status, content_type=content_type):
                self.assertEqual(tg.observe_response(decision, method, status, content_type), expected)
        self.assertIsNone(tg.observe_response(replace(decision, kind="api"), "GET", 200, "application/json"))


class _AsyncBody(httpx.AsyncByteStream):
    def __init__(self, body: bytes):
        self.body = body

    async def __aiter__(self):
        yield self.body


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.clock = NOW
        self.calls = []
        self.upstream = httpx.Response(200, content=b'{"ok":true}', headers={"content-type": "application/json"})
        self.failure = None
        self.on_request = None
        case = self

        class FakeClient:
            def build_request(self, **kwargs):
                return kwargs

            async def send(self, request, stream=False):
                case.calls.append(request)
                if case.on_request:
                    await case.on_request()
                if case.failure:
                    raise case.failure
                # Streamed bodies can be consumed once; hand each request a fresh copy.
                upstream = case.upstream
                return httpx.Response(upstream.status_code, headers=upstream.headers.multi_items(),
                                      stream=_AsyncBody(upstream.read()))

        main.app.state.http_client = FakeClient()
        self.addCleanup(delattr, main.app.state, "http_client")
        self.real_client = httpx.AsyncClient
        self.cfg_patch = patch.object(main, "TOKEN_GATE", CFG)
        self.cfg_patch.start()
        self.addCleanup(self.cfg_patch.stop)
        time_patch = patch.object(main.time, "time", side_effect=lambda: self.clock)
        time_patch.start()
        self.addCleanup(time_patch.stop)
        self.real_emit = tg.emit
        emit_patch = patch.object(tg, "emit")
        self.emitted = emit_patch.start()
        self.addCleanup(emit_patch.stop)
        self.client = TestClient(main.app, follow_redirects=False)
        self.addCleanup(self.client.close)

    def send(self, method="GET", path="/api", headers=None):
        self.client.cookies.clear()
        return self.client.request(method, path, headers=headers or {"Accept": "*/*"})

    def test_full_decision_table_over_http(self):
        values = {"valid": tg.make_token(CFG.secret, 10), "grace": tg.make_token(CFG.secret, 9),
                  "stale": tg.make_token(CFG.secret, 8), "invalid": "wrong", "missing": None}
        for mode in ("observe", "enforce"):
            for kind in ("page", "api"):
                for state, value in values.items():
                    with self.subTest(mode=mode, kind=kind, state=state):
                        main.TOKEN_GATE = replace(CFG, mode=mode)
                        self.calls.clear()
                        self.emitted.reset_mock()
                        headers = {"Accept": "text/html" if kind == "page" else "*/*"}
                        if value is not None:
                            headers["Cookie"] = f"{tg.COOKIE_NAME}={value}"
                        response = self.send(headers=headers)
                        issued = (kind == "page" and state != "valid") or (kind == "api" and state == "grace")
                        self.assertEqual(response.status_code, 200)
                        self.assertEqual(len(self.calls), 1)
                        self.assertEqual(cookie(response) is not None, issued)
                        self.emitted.assert_called_once()
                        record = self.emitted.call_args.args[0]
                        self.assertEqual(record["token_state"], state)
                        expected = ("issue" if kind == "page" and issued else
                                    "refresh" if issued else "observe" if kind == "api" and state != "valid" else "pass")
                        self.assertEqual(record["decision"], expected)
                        self.assertEqual(record["upstream_status"], 200)
                        self.assertEqual(record["observation"], "page_declared_json" if kind == "page" else None)
                        if issued:
                            self.assertEqual(response.headers["cache-control"], "no-store")

    def test_missing_bad_and_expired_tokens_do_not_block_benign_requests(self):
        signatures = []
        for value in (None, "wrong", tg.make_token(CFG.secret, 8)):
            headers = {"Accept": "*/*"}
            if value:
                headers["Cookie"] = f"{tg.COOKIE_NAME}={value}"
            response = self.send(headers=headers)
            smoke.check_allowed(response)
            signatures.append((response.status_code, response.content, list(response.headers.multi_items())))
        self.assertEqual(signatures[0], signatures[1])
        self.assertEqual(signatures[1], signatures[2])
        self.assertEqual(len(self.calls), 3)

    def test_missing_token_preserves_existing_strategy(self):
        with patch("defense.app.strategies.delay.asyncio.sleep", new_callable=AsyncMock) as sleep:
            response = self.send(headers={"X-Defense-Plan": '[{"name":"delay","params":{"delay_ms":200}}]'})
        self.assertEqual(response.status_code, 200)
        sleep.assert_awaited_once_with(0.2)
        self.assertEqual(len(self.calls), 1)

    def test_off_preserves_existing_strategy_and_backend_response(self):
        main.TOKEN_GATE = tg.TokenGateConfig()
        self.upstream = httpx.Response(201, content=b"original", headers=[
            ("Set-Cookie", "first=1; Path=/"), ("Set-Cookie", "second=2; Path=/"),
            ("Cache-Control", "public, max-age=300"), ("X-App", "unchanged"),
        ])
        with patch("defense.app.strategies.delay.asyncio.sleep", new_callable=AsyncMock) as sleep:
            response = self.send("POST", headers={"X-Defense-Plan": '[{"name":"delay","params":{"delay_ms":200}}]'})
        sleep.assert_awaited_once_with(0.2)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.content, b"original")
        self.assertEqual(response.headers.get_list("set-cookie"), ["first=1; Path=/", "second=2; Path=/"])
        self.assertEqual(response.headers["cache-control"], "public, max-age=300")
        self.assertEqual(response.headers["x-app"], "unchanged")
        self.assertEqual(self.calls[0]["headers"]["X-Defense-Applied"], "delay")
        self.assertEqual(self.calls[0]["headers"]["X-Defense-Delay-Ms"], "200")
        self.emitted.assert_not_called()

    def test_page_preserves_multiple_backend_cookies_and_replaces_all_cache_headers(self):
        self.upstream = httpx.Response(200, content=b"html", headers=[
            ("Set-Cookie", "first=1; Path=/"), ("Set-Cookie", "second=2; Path=/"),
            ("Cache-Control", "public"), ("Cache-Control", "max-age=300"),
        ])
        response = self.send(headers={"Accept": "text/html"})
        self.assertEqual(response.headers.get_list("set-cookie")[:2], ["first=1; Path=/", "second=2; Path=/"])
        self.assertEqual(len(response.headers.get_list("set-cookie")), 3)
        self.assertEqual(response.headers.get_list("cache-control"), ["no-store"])

    def test_valid_page_preserves_cache_and_does_not_issue_cookie(self):
        self.upstream = httpx.Response(200, headers={"Cache-Control": "public"})
        response = self.send(headers={"Accept": "text/html", "Cookie": f"{tg.COOKIE_NAME}={tg.make_token(CFG.secret, 10)}"})
        self.assertIsNone(cookie(response))
        self.assertEqual(response.headers["cache-control"], "public")

    def test_head_redirect_304_and_4xx_issue_without_changing_status_or_body(self):
        for method, status in (("HEAD", 200), ("GET", 302), ("GET", 304), ("GET", 404)):
            with self.subTest(method=method, status=status):
                self.upstream = httpx.Response(status, content=b"", headers={"Location": "/next"})
                response = self.send(method, headers={"Accept": "text/html"})
                self.assertEqual(response.status_code, status)
                self.assertEqual(response.content, b"")
                self.assertEqual(response.headers["location"], "/next")
                self.assertIsNotNone(cookie(response))

    def test_backend_5xx_and_connection_failure_do_not_issue(self):
        for status in (500, 502, 503):
            with self.subTest(status=status):
                self.upstream = httpx.Response(status, content=b"error", headers={"Cache-Control": "private"})
                response = self.send(headers={"Accept": "text/html"})
                self.assertEqual(response.status_code, status)
                self.assertIsNone(cookie(response))
                self.assertEqual(response.headers["cache-control"], "private")
                self.assertEqual(self.emitted.call_args.args[0]["upstream_status"], status)
        self.failure = httpx.ConnectError("backend unavailable")
        response = self.send(headers={"Accept": "text/html"})
        self.assertEqual(response.status_code, 502)
        self.assertIsNone(cookie(response))
        self.assertIsNone(self.emitted.call_args.args[0]["upstream_status"])

    def test_existing_rate_limit_short_circuit_is_preserved(self):
        strategy = RateLimitStrictStrategy()
        with patch.dict(main.STRATEGY_REGISTRY, {"rate_limit_strict": strategy}), patch(
            "defense.app.strategies.rate_limit.time.monotonic", return_value=1.0
        ):
            headers = {"Accept": "text/html", "X-Client-Id": "client",
                       "X-Defense-Plan": '[{"name":"rate_limit_strict"}]'}
            self.assertEqual(self.send(headers=headers).status_code, 200)
            response = self.send(headers=headers)
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["x-defense-applied"], "rate_limit_strict")
        self.assertIsNone(cookie(response))
        self.assertEqual(len(self.calls), 1)
        self.assertIsNone(self.emitted.call_args.args[0]["upstream_status"])

    def test_options_and_exempt_requests_preserve_backend_and_skip_logging(self):
        self.upstream = httpx.Response(204, headers={"Allow": "GET, OPTIONS", "Access-Control-Allow-Origin": "*"})
        for method, path in (("OPTIONS", "/api"), ("GET", "/__detection/test")):
            self.calls.clear()
            response = self.send(method, path)
            self.assertEqual(len(self.calls), 1)
            self.assertEqual(response.status_code, 204)
            self.assertEqual(response.headers["allow"], "GET, OPTIONS")
            self.assertEqual(response.headers["access-control-allow-origin"], "*")
            self.assertIsNone(cookie(response))
            self.emitted.assert_not_called()

    def test_separate_routes_bypass_gate(self):
        self.assertEqual(self.send(path="/healthz").status_code, 200)
        self.assertEqual(self.send(path="/docs").status_code, 200)
        self.assertEqual(self.calls, [])
        self.emitted.assert_not_called()

    def test_request_headers_cookie_and_repeated_query_are_preserved(self):
        token = tg.make_token(CFG.secret, 10)
        response = self.send(path="/api?q=one&q=two", headers={"Accept": "*/*", "Sec-Fetch-Site": "same-origin",
                                                              "Cookie": f"{tg.COOKIE_NAME}={token}; app=1"})
        self.assertEqual(response.status_code, 200)
        headers = self.calls[0]["headers"]
        self.assertEqual(headers["accept"], "*/*")
        self.assertEqual(headers["sec-fetch-site"], "same-origin")
        self.assertEqual(headers["cookie"], f"{tg.COOKIE_NAME}={token}; app=1")
        self.assertTrue(self.calls[0]["url"].endswith("/api?q=one&q=two"))
        self.assertNotIn("params", self.calls[0])
        record = self.emitted.call_args.args[0]
        self.assertEqual(record["path"], "/api")
        self.assertNotIn(token, json.dumps(record))
        self.assertNotIn("q=", json.dumps(record))

    def test_slow_backend_issues_cookie_using_response_epoch(self):
        async def finish_later():
            self.clock = 110.25
        self.on_request = finish_later
        response = self.send(headers={"Cookie": f"{tg.COOKIE_NAME}={tg.make_token(CFG.secret, 9)}"})
        value = cookie(response)
        self.assertEqual(value.value, tg.make_token(CFG.secret, 11))
        self.assertEqual(int(value["max-age"]), 19)
        self.assertEqual(self.emitted.call_args.args[0]["token_state"], "grace")

    def test_concurrent_grace_requests_both_refresh(self):
        async def simultaneous():
            arrived = 0
            ready = asyncio.Event()
            async def wait_for_other():
                nonlocal arrived
                arrived += 1
                if arrived == 2:
                    ready.set()
                await asyncio.wait_for(ready.wait(), timeout=2)
            self.on_request = wait_for_other
            async with self.real_client(transport=httpx.ASGITransport(app=main.app), base_url="http://test") as client:
                return await asyncio.gather(*[
                    client.get("/api", headers={"Cookie": f"{tg.COOKIE_NAME}={tg.make_token(CFG.secret, 9)}"})
                    for _ in range(2)
                ])
        responses = asyncio.run(simultaneous())
        self.assertEqual([r.status_code for r in responses], [200, 200])
        self.assertEqual([cookie(r).value for r in responses], [tg.make_token(CFG.secret, 10)] * 2)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.emitted.call_count, 2)

    def test_real_log_handler_emits_one_compact_line(self):
        self.emitted.side_effect = self.real_emit
        output = io.StringIO()
        logger = logging.getLogger(tg.LOGGER_NAME)
        old = logger.handlers[:], logger.level, logger.propagate
        handler = logging.StreamHandler(output)
        logger.handlers, logger.propagate = [handler], False
        logger.setLevel(logging.INFO)
        try:
            self.send(headers={"Accept": "text/html"})
        finally:
            logger.handlers, logger.level, logger.propagate = old
            handler.close()
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertIn('"event":"token_gate"', lines[0])
        self.assertEqual(json.loads(lines[0])["observation"], "page_declared_json")


class SmokeTests(unittest.TestCase):
    def test_all_checks_include_baseline_headers_and_replay_original_token(self):
        calls = []
        token = tg.make_token(CFG.secret, 10)
        def fake_request(method, url, *, headers, **kwargs):
            calls.append((method, url, headers))
            if method == "OPTIONS":
                return httpx.Response(204, headers={"Allow": "GET, OPTIONS", "Access-Control-Allow-Origin": "*"})
            if url.endswith("/"):
                return httpx.Response(200, headers={"Set-Cookie": f"{tg.COOKIE_NAME}={token}; Max-Age=20",
                                                   "Cache-Control": "no-store"})
            return httpx.Response(200)

        with tempfile.TemporaryDirectory() as folder, patch.object(smoke.httpx, "request", side_effect=fake_request), patch.object(
            smoke.time, "sleep"
        ) as sleep, patch("sys.stdout", new_callable=io.StringIO) as output:
            baseline = str(Path(folder) / "baseline.json")
            self.assertEqual(smoke.main(["--record-baseline", baseline]), 0)
            self.assertEqual(smoke.main(["--baseline", baseline, "--stale", "--epoch-s", "10"]), 0)
            self.assertNotIn("SKIP", output.getvalue())
            self.assertEqual(output.getvalue().count("PASS"), 8)
            sleep.assert_called_once_with(21)
        # Baseline, missing, page, valid, forged, stale, OPTIONS, HTML-declared API.
        self.assertEqual(calls[3][2]["Cookie"], calls[5][2]["Cookie"])
        self.assertNotIn("Cookie", calls[1][2])
        self.assertNotIn("Cookie", calls[7][2])

    def test_options_baseline_mismatch_fails_and_missing_baseline_is_skip(self):
        def response(base_url, method, path, **kwargs):
            if method == "OPTIONS":
                return httpx.Response(204, headers={"Allow": "POST"})
            if path == "/":
                return httpx.Response(200, headers={"Set-Cookie": "__ruby_tg=test; Max-Age=20", "Cache-Control": "no-store"})
            return httpx.Response(200)

        def http_response(*args, **kwargs):
            result = response(*args, **kwargs)
            if isinstance(result, httpx.Response):
                return result
            return httpx.Response(result.status_code, content=result.body, headers=result.headers)

        with tempfile.TemporaryDirectory() as folder, patch.object(smoke, "request", side_effect=http_response), patch(
            "sys.stdout", new_callable=io.StringIO
        ) as output:
            baseline = Path(folder) / "baseline.json"
            baseline.write_text(json.dumps({"status": 204, "headers": {"allow": "GET"}}), encoding="utf-8")
            self.assertEqual(smoke.main(["--baseline", str(baseline), "--epoch-s", "10"]), 1)
            self.assertIn("FAIL 6", output.getvalue())
            output.truncate(0)
            output.seek(0)
            self.assertEqual(smoke.main(["--epoch-s", "10"]), 0)
            self.assertIn("SKIP 6", output.getvalue())


if __name__ == "__main__":
    unittest.main()
