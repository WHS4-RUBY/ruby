import io
import json
import unittest
from dataclasses import replace
from unittest.mock import patch

import httpx
from starlette.testclient import TestClient

from defense.app import main, path_alias as pa

SEC = "sixteen-byte-key"  # exactly MIN_SECRET_BYTES
CFG = pa.PathAliasConfig(mode="enforce", secret=b"test-only-key-16b", epoch_s=10, grace_epochs=1)
NOW = 100.25  # epoch 10


def alias(epoch=10, prefix="/rest/"):
    return pa.alias_for(CFG.secret, CFG.app_id, epoch, prefix)


class ConfigTests(unittest.TestCase):
    def test_off_reads_nothing_else(self):
        with patch.object(pa, "_configure_logger") as setup:
            cfg = pa.PathAliasConfig.from_env({"PATH_ALIAS_MODE": "off", "PATH_ALIAS_EPOCH_S": "bad"})
        self.assertEqual(cfg, pa.PathAliasConfig())
        setup.assert_not_called()

    def test_invalid_values_fail_start(self):
        for env in (
            {"PATH_ALIAS_MODE": "block"},
            {"PATH_ALIAS_MODE": "observe", "PATH_ALIAS_EPOCH_S": "0"},
            {"PATH_ALIAS_MODE": "observe", "PATH_ALIAS_GRACE_EPOCHS": "11"},
            {"PATH_ALIAS_MODE": "observe", "PATH_ALIAS_MAX_REWRITE_BYTES": "x"},
            {"PATH_ALIAS_MODE": "observe", "PATH_ALIAS_PREFIXES": "/rest"},
            {"PATH_ALIAS_MODE": "observe", "PATH_ALIAS_PREFIXES": "/"},
            {"PATH_ALIAS_MODE": "observe", "PATH_ALIAS_PREFIXES": " , "},
            {"PATH_ALIAS_MODE": "observe", "PATH_ALIAS_PREFIXES": "/café/"},  # non-ASCII would crash alias_for
            {"PATH_ALIAS_MODE": "observe", "PATH_ALIAS_APP_ID": "café"},
            {"PATH_ALIAS_MODE": "observe", "PATH_ALIAS_SECRET": "short"},     # below MIN_SECRET_BYTES
        ):
            with self.subTest(env=env), self.assertRaises(ValueError):
                pa.PathAliasConfig.from_env({"PATH_ALIAS_SECRET": SEC, **env})

    def test_enforce_requires_secret(self):
        with self.assertRaises(ValueError):
            pa.PathAliasConfig.from_env({"PATH_ALIAS_MODE": "enforce"})

    def test_prefixes_are_normalized_and_longest_first(self):
        cfg = pa.PathAliasConfig.from_env({"PATH_ALIAS_MODE": "OBSERVE", "PATH_ALIAS_SECRET": SEC,
                                           "PATH_ALIAS_PREFIXES": " /API/ ,/api/v2/,/rest/"})
        self.assertEqual(cfg.mode, "observe")
        self.assertEqual(cfg.prefixes, ("/api/v2/", "/rest/", "/api/"))

    def test_empty_secret_in_observe_generates_key_with_warning(self):
        output = io.StringIO()
        with patch.object(pa.sys, "stdout", output):
            pa.logging.getLogger(pa.LOGGER_NAME).handlers.clear()
            cfg = pa.PathAliasConfig.from_env({"PATH_ALIAS_MODE": "observe"})
        self.assertEqual(len(cfg.secret), 32)
        self.assertIn("PATH_ALIAS_SECRET is empty", output.getvalue())
        pa.logging.getLogger(pa.LOGGER_NAME).handlers.clear()

    def test_app_id_changes_alias_for_same_secret(self):
        a = pa.alias_for(CFG.secret, "app-one", 10, "/rest/")
        b = pa.alias_for(CFG.secret, "app-two", 10, "/rest/")
        self.assertNotEqual(a, b)


class AliasTests(unittest.TestCase):
    def test_alias_is_deterministic_and_rotates(self):
        self.assertRegex(alias(), r"^/__ruby_alias_[a-z2-7]{16}/$")
        self.assertEqual(alias(), alias())
        self.assertNotEqual(alias(10), alias(11))
        self.assertNotEqual(alias(10, "/rest/"), alias(10, "/api/"))
        self.assertNotEqual(alias(), pa.alias_for(b"other-key-16byte", CFG.app_id, 10, "/rest/"))

    def test_resolve_alias_states(self):
        for path, state in ((alias(10) + "products/search", "current"),
                            (alias(9) + "products/search", "grace")):
            with self.subTest(path=path):
                result = pa.resolve(path, NOW, CFG)
                self.assertEqual((result.kind, result.alias_state), ("alias", state))
                self.assertEqual(result.upstream_path, "/rest/products/search")
        self.assertEqual(pa.resolve(alias(10, "/api/") + "Products/1", NOW, CFG).upstream_path,
                         "/api/Products/1")
        self.assertEqual(pa.resolve(alias(10).rstrip("/"), NOW, CFG).upstream_path, "/rest/")

    def test_forward_skew_alias_is_accepted(self):
        # One epoch ahead (issuer's clock slightly faster) is still served.
        result = pa.resolve(alias(11) + "x", NOW, CFG)
        self.assertEqual((result.kind, result.alias_state), ("alias", "current"))

    def test_expired_or_forged_alias_is_rejected(self):
        # Alias-shaped but matching no live epoch must be refused, never forwarded.
        for path in (alias(8) + "x", alias(12) + "x", "/__ruby_alias_zzzzzzzzzzzzzzzz/x"):
            with self.subTest(path=path):
                result = pa.resolve(path, NOW, CFG)
                self.assertEqual(result.kind, "reject")
                self.assertEqual(result.reason, "unknown_alias")

    def test_alias_with_traversal_tail_is_rejected(self):
        result = pa.resolve(alias(10, "/api/") + "../rest/secret", NOW, CFG)
        self.assertEqual((result.kind, result.reason), ("reject", "ambiguous_alias_tail"))

    def test_clean_protected_paths_are_direct(self):
        # A clean path on a protected prefix is a direct hit (case-insensitive).
        for path in ("/rest/products/search", "/REST/products", "/Rest/Products/Search",
                     "/rest", "/rest/", "/api/Products/1", "/API/Products"):
            with self.subTest(path=path):
                result = pa.resolve(path, NOW, CFG)
                self.assertEqual(result.kind, "direct")
                self.assertEqual(result.upstream_path, path)

    def test_ambiguous_variants_are_rejected(self):
        # Anything a backend might re-route (encoding, //, .., backslash, trailing dot) is refused
        # instead of guessed at.
        for path in ("//rest/x", "/./rest/x", "/foo/../rest/x", "/%72est/products", "/rest%2fx",
                     "/api%2f..%2fapi/x", "/rest./x", "/rest%2e/x", r"\rest\x", "/%2e/rest/x",
                     "/api%2FProducts", "/rest;x=1/users", "/rest/\u0000", "/ｒｅｓｔ/x"):
            with self.subTest(path=path):
                self.assertEqual(pa.resolve(path, NOW, CFG).kind, "reject")

    def test_unrelated_paths_pass(self):
        for path in ("/", "/restaurant", "/api-docs/", "/socket.io/", "/assets/i18n/en.json",
                     "/foo/rest/x", "/ftp/legal.md", "/main.js"):
            with self.subTest(path=path):
                self.assertEqual(pa.resolve(path, NOW, CFG).kind, "other")

    def test_off_never_resolves(self):
        self.assertEqual(pa.resolve("/rest/x", NOW, replace(CFG, mode="off")).kind, "other")

    def test_decide_by_mode(self):
        observe = replace(CFG, mode="observe")
        direct = pa.resolve("/rest/x", NOW, CFG)
        reject = pa.resolve(alias(8) + "x", NOW, CFG)
        current = pa.resolve(alias() + "x", NOW, CFG)
        self.assertEqual(pa.decide(current, CFG), "translate")
        self.assertEqual(pa.decide(direct, CFG), "block")
        self.assertEqual(pa.decide(reject, CFG), "block")
        self.assertEqual(pa.decide(direct, observe), "would_block")
        self.assertEqual(pa.decide(reject, observe), "would_block")
        self.assertEqual(pa.decide(pa.resolve("/", NOW, CFG), CFG), "pass")


class RewriteTests(unittest.TestCase):
    def setUp(self):
        self.aliases = pa.current_aliases(CFG, NOW)

    def test_rewrites_bundle_forms_seen_in_juice_shop(self):
        body = (b"get(this.hostServer+`/rest/web3`);get(`${this.hostServer}/rest/basket/${e}`);"
                b"host=this.hostServer+`/api/Feedbacks`;u='./rest/x';h=\"/api/Users\"")
        out, count = pa.rewrite_body(body, self.aliases)
        self.assertEqual(count, 5)
        self.assertNotIn(b"/rest/", out)
        self.assertNotIn(b"/api/", out)
        self.assertIn(b"`" + alias().encode() + b"web3`", out)
        self.assertIn(b"./" + alias().lstrip("/").encode() + b"x", out)

    def test_leaves_other_urls_alone(self):
        body = b'"https://example.com/api/v1" "/foo/rest/x" "/restaurant" "/api-docs"'
        out, count = pa.rewrite_body(body, self.aliases)
        self.assertEqual((out, count), (body, 0))

    def test_case_insensitive_like_direct_detection(self):
        out, count = pa.rewrite_body(b'"/API/Products" "/Rest/x"', self.aliases)
        self.assertEqual(count, 2)
        self.assertIn(alias(10, "/api/").encode() + b"Products", out)

    def test_longest_prefix_wins(self):
        aliases = {"/api/": "/pa/", "/api/v2/": "/pb/"}
        out, _ = pa.rewrite_body(b'"/api/v2/x" "/api/x"', aliases)
        self.assertEqual(out, b'"/pb/x" "/pa/x"')

    def test_rewritable_types(self):
        for args, expected in [
            (("text/html; charset=utf-8", "", 200, "GET"), True),
            (("application/javascript", "identity", 200, "GET"), True),
            (("application/problem+json", "", 404, "GET"), True),
            (("image/png", "", 200, "GET"), False),
            (("text/html", "gzip", 200, "GET"), False),
            (("text/html", "", 304, "GET"), False),
            (("text/html", "", 200, "HEAD"), False),
        ]:
            with self.subTest(args=args):
                self.assertEqual(pa.rewritable(*args), expected)

    def test_location_rewrite(self):
        a = alias()
        self.assertEqual(pa.rewrite_location("/rest/x?y=1", self.aliases, "shop"), f"{a}x?y=1")
        self.assertEqual(pa.rewrite_location("http://shop/api/Products", self.aliases, "shop"),
                         "http://shop" + alias(10, "/api/") + "Products")
        self.assertEqual(pa.rewrite_location("https://other/rest/x", self.aliases, "shop"),
                         "https://other/rest/x")
        self.assertEqual(pa.rewrite_location("/#/login", self.aliases, "shop"), "/#/login")


class _AsyncBody(httpx.AsyncByteStream):
    def __init__(self, body: bytes):
        self.body = body

    async def __aiter__(self):
        for index in range(0, len(self.body), 7):
            yield self.body[index:index + 7]


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.upstream = (200, [("content-type", "application/json")], b'{"ok":true}')
        case = self

        class FakeClient:
            def build_request(self, **kwargs):
                return kwargs

            async def send(self, request, stream=False):
                case.calls.append(request)
                status, headers, body = case.upstream
                return httpx.Response(status, headers=headers, stream=_AsyncBody(body))

        main.app.state.http_client = FakeClient()
        self.addCleanup(delattr, main.app.state, "http_client")
        self.cfg_patch = patch.object(main, "PATH_ALIAS", CFG)
        self.cfg_patch.start()
        self.addCleanup(self.cfg_patch.stop)
        time_patch = patch.object(main.time, "time", return_value=NOW)
        time_patch.start()
        self.addCleanup(time_patch.stop)
        self.real_emit = pa.emit
        emit_patch = patch.object(pa, "emit")
        self.emitted = emit_patch.start()
        self.addCleanup(emit_patch.stop)
        self.client = TestClient(main.app, follow_redirects=False)
        self.addCleanup(self.client.close)

    def logs(self):
        return [call.args[0] for call in self.emitted.call_args_list]

    def test_page_body_is_rewritten_and_not_cached(self):
        body = b'<script>fetch("./rest/products/search")</script>'
        self.upstream = (200, [("content-type", "text/html"), ("etag", 'W/"1"'),
                               ("cache-control", "public, max-age=0"), ("x-app", "kept")], body)
        response = self.client.get("/", headers={"If-None-Match": 'W/"1"', "If-Modified-Since": "x"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(alias().lstrip("/"), response.text)
        self.assertNotIn("/rest/", response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertNotIn("etag", response.headers)
        self.assertEqual(response.headers["x-app"], "kept")
        self.assertEqual(int(response.headers["content-length"]), len(response.content))
        sent = {key.lower() for key in self.calls[0]["headers"]}
        self.assertNotIn("if-none-match", sent)
        self.assertNotIn("if-modified-since", sent)
        self.assertEqual(self.logs()[-1]["rewrites"], 1)

    def test_unchanged_body_keeps_cache_headers(self):
        self.upstream = (200, [("content-type", "text/html"), ("etag", 'W/"1"')], b"<p>hello</p>")
        response = self.client.get("/about")
        self.assertEqual(response.headers["etag"], 'W/"1"')
        self.assertEqual(response.content, b"<p>hello</p>")
        self.assertEqual(self.logs(), [])

    def test_binary_is_streamed_untouched(self):
        body = b"\x89PNG/rest/binary"
        self.upstream = (200, [("content-type", "image/png"), ("etag", "x")], body)
        response = self.client.get("/assets/logo.png")
        self.assertEqual(response.content, body)
        self.assertEqual(response.headers["etag"], "x")

    def test_alias_request_is_forwarded_to_real_path(self):
        response = self.client.get(alias() + "products/search", params={"q": "apple"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.calls[0]["url"].endswith("/rest/products/search"))
        self.assertEqual(self.calls[0]["params"], [("q", "apple")])
        self.assertEqual(self.calls[0]["headers"]["X-Defense-Applied"], "path_alias")
        log = self.logs()[-1]
        self.assertEqual((log["kind"], log["alias_state"], log["decision"]), ("alias", "current", "translate"))
        self.assertEqual(log["real_path"], "/rest/products/search")

    def test_enforce_blocks_direct_reject_and_ambiguous_without_forwarding(self):
        for path in ("/rest/products/search", "/REST/products", "/API/Products",
                     alias(8) + "x", "/rest%2fx", "/rest%2e%2e/x"):
            with self.subTest(path=path):
                self.calls.clear()
                response = self.client.get(path)
                self.assertEqual(response.status_code, 404)
                self.assertEqual(response.json(), {"error": "not_found"})
                self.assertEqual(response.headers["cache-control"], "no-store")
                self.assertEqual(self.calls, [])
                self.assertEqual(self.logs()[-1]["decision"], "block")

    def test_observe_forwards_direct_and_reject_with_would_block(self):
        with patch.object(main, "PATH_ALIAS", replace(CFG, mode="observe")):
            direct = self.client.get("/rest/products/search")
            reject = self.client.get("/rest;probe")  # ";" survives ASGI decoding, stays ambiguous
        self.assertEqual([direct.status_code, reject.status_code], [200, 200])
        self.assertTrue(self.calls[0]["url"].endswith("/rest/products/search"))
        self.assertEqual([log["decision"] for log in self.logs()], ["would_block", "would_block"])
        self.assertEqual([log["kind"] for log in self.logs()], ["direct", "reject"])

    def test_json_api_response_is_rewritten(self):
        self.upstream = (200, [("content-type", "application/json")], b'{"next":"/api/Products/2"}')
        response = self.client.get(alias(10, "/api/") + "Products")
        self.assertEqual(response.json()["next"], alias(10, "/api/") + "Products/2")

    def test_location_header_uses_alias(self):
        self.upstream = (302, [("content-type", "text/plain"), ("location", "/rest/next")], b"")
        response = self.client.get(alias() + "start")
        self.assertEqual(response.headers["location"], alias() + "next")

    def test_oversized_body_is_passed_through_and_logged(self):
        body = b'"/rest/x"' * 10
        self.upstream = (200, [("content-type", "application/javascript")], body)
        with patch.object(main, "PATH_ALIAS", replace(CFG, max_rewrite_bytes=20)):
            response = self.client.get("/main.js")
        self.assertEqual(response.content, body)
        self.assertEqual(self.logs()[-1]["rewrite_skipped"], "too_large")

    def test_head_is_not_rewritten(self):
        self.upstream = (200, [("content-type", "text/html")], b"")
        response = self.client.head("/")
        self.assertEqual(response.status_code, 200)

    def test_off_is_plain_proxy(self):
        body = b'fetch("/rest/x")'
        self.upstream = (200, [("content-type", "text/html"), ("etag", "e")], body)
        with patch.object(main, "PATH_ALIAS", pa.PathAliasConfig()):
            page = self.client.get("/", headers={"If-None-Match": "e"})
            direct = self.client.get("/rest/x")
        self.assertEqual(page.content, body)
        self.assertEqual(page.headers["etag"], "e")
        self.assertIn("If-None-Match".lower(), {key.lower() for key in self.calls[0]["headers"]})
        self.assertEqual(direct.status_code, 200)
        self.assertEqual(self.calls[1]["headers"]["X-Defense-Applied"], "none")
        self.assertEqual(self.logs(), [])

    def test_real_log_handler_emits_one_line_without_query(self):
        output = io.StringIO()
        logger = pa.logging.getLogger(pa.LOGGER_NAME)
        logger.handlers.clear()
        with patch.object(pa.sys, "stdout", output):
            pa._configure_logger()
        self.addCleanup(logger.handlers.clear)
        with patch.object(pa, "emit", self.real_emit):
            self.client.get(alias() + "x", params={"q": "secret-value"})
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        record = json.loads(lines[0])
        self.assertEqual((record["event"], record["decision"]), ("path_alias", "translate"))
        self.assertNotIn("secret-value", lines[0])


if __name__ == "__main__":
    unittest.main()
