"""Compatibility, routing and cookieless policies of the path alias stage."""

import json
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
from starlette.responses import Response

from defense.app import main, path_alias as pa
from defense.app.strategies.base import DefenseResult
from defense.tests.test_path_alias import ALICE, BOB, CFG, NOW, IntegrationTests, _AsyncBody

ACTIONS = pa.ActionRoute("/api.php", "action", (("login", ("POST",)), ("search", ("GET",))))


def write_routes(directory: str, document: dict) -> str:
    path = Path(directory) / "routes.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return str(path)


class ConfigFileTests(unittest.TestCase):
    def env(self, directory, document, **extra):
        return {"PATH_ALIAS_MODE": "enforce", "PATH_ALIAS_ROUTES_FILE": write_routes(directory, document),
                "PATH_ALIAS_DB_PATH": str(Path(directory) / "aliases.sqlite3"), **extra}

    def test_enforce_without_verified_refresh_stays_observe(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = pa.PathAliasConfig.from_env(self.env(directory, {"routes": ["/rest/a"]}))
            self.assertEqual((cfg.mode, cfg.default_mode, cfg.enforcing), ("enforce", "observe", False))
            direct = pa.PathAliasTable(cfg).resolve("/rest/a", "GET", NOW, None)
            self.assertEqual(pa.decide(direct, cfg), "would_block")
            for compatibility in ({}, {"verified_flows": ["login"], "refresh": "reload"},
                                  {"verified_flows": [], "refresh": "reload", "refresh_verified": True}):
                with self.subTest(compatibility=compatibility), self.assertRaises(ValueError):
                    pa.PathAliasConfig.from_env(self.env(directory, {
                        "routes": ["/rest/a"], "enforce_ready": True, "compatibility": compatibility}))

    def test_ready_file_enforces_and_route_can_stay_observe(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = pa.PathAliasConfig.from_env(self.env(directory, {
                "routes": ["/rest/a", {"path": "/rest/b", "mode": "observe"}],
                "enforce_ready": True, "target_ids": ["juice-shop"],
                "compatibility": {"verified_flows": ["search"], "refresh": "reload",
                                  "refresh_verified": True}}))
            table = pa.PathAliasTable(cfg)
            self.assertEqual(pa.decide(table.resolve("/rest/a", "GET", NOW), cfg), "block")
            self.assertEqual(pa.decide(table.resolve("/rest/b", "GET", NOW), cfg), "would_block")
            self.assertEqual(pa.decide(table.resolve("/rest/unlisted", "GET", NOW), cfg), "block")
            self.assertTrue(table.applies_to("juice-shop"))
            self.assertFalse(table.applies_to("ruby-shop"))

    def test_audit_needs_no_database_and_sqlite_is_the_default_backend(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.env(directory, {"routes": ["/rest/a"]}, PATH_ALIAS_MODE="audit")
            del env["PATH_ALIAS_DB_PATH"]
            cfg = pa.PathAliasConfig.from_env(env)
            table = pa.PathAliasTable(cfg)
            self.assertIsNone(table._store)
            self.assertEqual(table.describe()["backend"], "none")
            self.assertEqual(pa.decide(table.resolve("/rest/a", "GET", NOW), cfg), "audit")
            env["PATH_ALIAS_MODE"] = "observe"
            with self.assertRaises(ValueError):
                pa.PathAliasConfig.from_env(env)
            env["PATH_ALIAS_DB_PATH"] = str(Path(directory) / "aliases.sqlite3")
            self.assertEqual(pa.PathAliasTable(pa.PathAliasConfig.from_env(env)).describe()["backend"], "sqlite")
            env["PATH_ALIAS_DB_URL"] = "postgresql://ruby@db/ruby"  # removed backend: refuse to start
            with self.assertRaisesRegex(ValueError, "no longer supported"):
                pa.PathAliasConfig.from_env(env)

    def test_shipped_route_files(self):
        config = Path(__file__).resolve().parents[1] / "config"
        juice = pa.load_route_document(str(config / "juice-shop-routes.json"))
        ruby = pa.load_route_document(str(config / "ruby-shop-routes.json"))
        example = pa.load_route_document(str(config / "query-routing-example.json"))
        self.assertTrue(juice.enforce_ready)  # browser flows and refresh verified (see compatibility)
        self.assertEqual(juice.target_ids, ("juice-shop",))  # not applied to other targets
        modes = {route.path: route.mode for route in juice.routes}
        self.assertIsNone(modes["/rest/user/login"])  # used by the verified flows: enforced
        self.assertEqual(modes["/rest/2fa/status"], "observe")  # not verified: observe only
        with tempfile.TemporaryDirectory() as directory:
            env = {"PATH_ALIAS_MODE": "enforce", "PATH_ALIAS_ROUTES_FILE": str(config / "juice-shop-routes.json"),
                   "PATH_ALIAS_PREFIXES": "/rest/,/api/,/b2b/",
                   "PATH_ALIAS_DB_PATH": str(Path(directory) / "a.sqlite3")}
            cfg = pa.PathAliasConfig.from_env(env)
            self.assertEqual(cfg.target_ids, ("juice-shop",))
            table = pa.PathAliasTable(cfg)
            self.assertEqual(pa.decide(table.resolve("/rest/2fa/status", "GET", NOW), cfg), "would_block")
            self.assertEqual(pa.decide(table.resolve("/rest/user/login", "POST", NOW), cfg), "block")
            env["PATH_ALIAS_TARGET_IDS"] = "legacy, juice-shop"
            self.assertEqual(pa.PathAliasConfig.from_env(env).target_ids, ("legacy", "juice-shop"))
            env["PATH_ALIAS_TARGET_IDS"] = "bad id"
            with self.assertRaises(ValueError):
                pa.PathAliasConfig.from_env(env)
        self.assertFalse(ruby.enforce_ready)  # source-only route list: stays at observe
        self.assertFalse(example.enforce_ready)

    def test_rotation_reasons_are_granular(self):
        self.assertEqual(pa._parse_triggers("reject"), pa.REJECT_REASONS)
        self.assertEqual(pa._parse_triggers("direct,foreign_alias"), ("direct", "foreign_alias"))
        for reason in ("stale_alias", "revoked_alias"):
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                pa._parse_triggers(reason)
        self.assertNotIn("method_not_allowed", pa.DEFAULT_ROTATE_ON)

    def test_action_and_channel_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            cfg = pa.PathAliasConfig.from_env(self.env(directory, {
                "routes": ["/api/items"],
                "action_routes": [{"path": "/api.php", "parameter": "action",
                                   "actions": {"login": ["POST"], "search": ["GET"]}}],
                "cookieless_channels": [{"name": "partner", "routes": ["/api/partner/{tail*}"],
                                         "methods": ["POST"], "require_headers": ["Authorization"]}]}))
            self.assertEqual(cfg.action_routes[0].route_id("login"), "/api.php?action=login")
            self.assertEqual(cfg.channels[0].require_headers, ("authorization",))
            for bad in ({"path": "/api.php", "parameter": "action", "actions": {"a b": ["GET"]}},
                        {"path": "/api.php", "parameter": "action", "actions": {"x": ["GET"], "X": ["GET"]}}):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    pa.PathAliasConfig.from_env(self.env(directory, {"routes": ["/api/items"],
                                                                     "action_routes": [bad]}))
            with self.assertRaises(ValueError):  # channel routes must be inside protected prefixes
                pa.PathAliasConfig.from_env(self.env(directory, {
                    "routes": ["/api/items"],
                    "cookieless_channels": [{"name": "x", "routes": ["/partner/{tail*}"]}]}))


class RewriteContextTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.cfg = replace(CFG, db_path=str(Path(directory.name) / "aliases.sqlite3"),
                           action_routes=(ACTIONS,), query_routes=(pa.QueryRoute("/gateway", "route"),))
        self.table = pa.PathAliasTable(self.cfg)
        p = patch.object(pa, "emit")
        p.start()
        self.addCleanup(p.stop)

    def alias(self, route, client=ALICE):
        return self.table.current_aliases(NOW, client)[route]

    def test_json_rewrites_url_values_but_not_prose(self):
        body = (b'{"next":"/rest/products/search?q=1","help":"Call /rest/products/search to search",'
                b'"quoted":"/rest/products/search is the API","abs":"https://shop.example/rest/products/search",'
                b'"other":"https://evil.example/rest/products/search"}')
        output, count = self.table.rewrite_body(body, NOW, ALICE, kind="json",
                                                origins=pa.public_origins("shop.example"))
        alias = self.alias("/rest/products/search").encode()
        self.assertEqual(count, 2)
        self.assertIn(b'"next":"' + alias + b'?q=1"', output)
        self.assertIn(b'"abs":"https://shop.example' + alias + b'"', output)
        self.assertIn(b"Call /rest/products/search to search", output)
        self.assertIn(b'"/rest/products/search is the API"', output)
        self.assertIn(b"https://evil.example/rest/products/search", output)

    def test_html_rewrites_attributes_and_scripts_not_text(self):
        body = (b'<a href="/rest/products/search">x</a><form action=/rest/user/login></form>'
                b'<p>Our API lives at /rest/products/search.</p>'
                b'<script>// see /rest/user/whoami\nfetch(\'/rest/user/whoami\')</script>'
                b'<div data-cfg="{&quot;u&quot;:&quot;/rest/user/whoami&quot;}"></div>')
        output, count = self.table.rewrite_body(body, NOW, ALICE, kind="html")
        self.assertEqual(count, 4)
        self.assertIn(b"Our API lives at /rest/products/search.", output)
        self.assertIn(b"// see /rest/user/whoami", output)
        self.assertIn(b"fetch('" + self.alias("/rest/user/whoami").encode() + b"')", output)

    def test_runtime_prefix_literals_and_trailing_slash(self):
        cfg = replace(self.cfg, routes=(pa.Route("/rest/track-order/{id}"), pa.Route("/rest/captcha"),
                                        pa.Route("/rest/captcha/{id}"), pa.Route("/rest/apply/{code}", ("PUT",))),
                      action_routes=(), query_routes=())
        table = pa.PathAliasTable(cfg)
        body = (b'host=this.hostServer+"/rest/track-order";'
                b'put(this.hostServer+`/rest/apply/`+e,{});get(this.hostServer+`/rest/captcha/`)')
        output, count = table.rewrite_body(body, NOW, ALICE)
        aliases = table.current_aliases(NOW, ALICE)
        self.assertEqual(count, 3)
        self.assertIn(b'"' + aliases["/rest/track-order/{id}"].encode() + b'"', output)
        self.assertIn(b"`" + aliases["/rest/apply/{code}"].encode() + b"/`", output)
        captcha = aliases["/rest/captcha/{id}"]
        self.assertIn(b"`" + captcha.encode() + b"/`", output)
        # what the app then requests at runtime
        self.assertEqual(table.resolve(aliases["/rest/track-order/{id}"] + "/7", "GET", NOW, ALICE).upstream_path,
                         "/rest/track-order/7")
        self.assertEqual(table.resolve(aliases["/rest/apply/{code}"] + "/abc", "PUT", NOW, ALICE).upstream_path,
                         "/rest/apply/abc")
        empty = table.resolve(captcha + "/", "GET", NOW, ALICE)
        self.assertEqual((empty.upstream_path, empty.route_id), ("/rest/captcha/", "/rest/captcha"))
        self.assertEqual(table.resolve(captcha + "/9", "GET", NOW, ALICE).upstream_path, "/rest/captcha/9")

    def test_json_keys_and_comments_are_not_rewritten(self):
        alias = self.alias("/rest/products/search").encode()
        output, count = self.table.rewrite_body(
            b'{"/rest/products/search":"ordinary key", "/rest/products/search" : 1,'
            b' "next":"/rest/products/search"}', NOW, ALICE, kind="json")
        self.assertEqual(count, 1)
        self.assertTrue(output.startswith(b'{"/rest/products/search":"ordinary key"'))
        self.assertIn(b'"next":"' + alias + b'"', output)
        js = (b'// fetch("/rest/products/search")\n/* old: \'/rest/products/search\' */'
              b'var re=/https?:\/\//,u="//cdn";fetch("/rest/products/search")')
        output, count = self.table.rewrite_body(js, NOW, ALICE, kind="js")
        self.assertEqual(count, 1)
        self.assertIn(b'// fetch("/rest/products/search")', output)
        self.assertIn(b"/* old: '/rest/products/search' */", output)
        self.assertTrue(output.endswith(b'fetch("' + alias + b'")'))
        html = (b'<!-- <a href="/rest/products/search"> --><script>// "/rest/products/search"\n'
                b'fetch("/rest/products/search")</script><a href="/rest/products/search">x</a>')
        output, count = self.table.rewrite_body(html, NOW, ALICE, kind="html")
        self.assertEqual(count, 2)
        self.assertIn(b'<!-- <a href="/rest/products/search"> -->', output)
        self.assertIn(b'// "/rest/products/search"', output)

    def test_lazy_issuance_only_for_routes_in_the_response(self):
        self.table.rewrite_body(b'fetch("/rest/user/whoami")', NOW, BOB)
        with self.table._store.connect() as db:
            rows = db.execute("SELECT route_path FROM path_alias_alias_rows WHERE client_id=?", (BOB,)).fetchall()
        self.assertEqual([row["route_path"] for row in rows], ["/rest/user/whoami"])

    def test_action_dispatcher_rewrite_and_count_in_audit(self):
        body = b'fetch("/api.php?action=login&x=1");fetch("/api.php?action=help");fetch("/api.php?action=LOGIN")'
        output, count = self.table.rewrite_body(body, NOW, ALICE)
        token = self.alias("/api.php?action=login").lstrip("/").encode()
        self.assertEqual(count, 1)
        self.assertIn(b"/api.php?action=" + token + b"&x=1", output)
        self.assertIn(b"/api.php?action=help", output)
        self.assertEqual(self.table.count_references(body), 1)


class AliasPolicyIntegrationTests(IntegrationTests):
    def configure(self, **changes):
        cfg = replace(self.cfg, **changes)
        table = pa.PathAliasTable(cfg)
        for name, value in (("PATH_ALIAS", cfg), ("PATH_ALIAS_TABLE", table)):
            p = patch.object(main, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.cfg, self.table = cfg, table

    def test_audit_changes_nothing_and_only_counts(self):
        self.configure(mode="audit")
        self.table = pa.PathAliasTable(self.cfg)
        self.upstream = self.PAGE
        page = self.client.get("/")
        self.assertEqual(page.text, self.PAGE[2].decode())
        self.assertNotIn("set-cookie", page.headers)
        self.assertEqual(page.headers.get("etag"), "one")  # same header policy as a plain proxy
        self.assertEqual(self.logs()[-1]["would_rewrite"], 1)
        self.upstream = self.JSON
        self.assertEqual(self.client.get("/rest/products/search").status_code, 200)
        self.assertEqual(self.logs()[-1]["decision"], "audit")
        self.assertIsNone(self.logs()[-1]["rotation"])

    def test_target_outside_route_file_is_untouched(self):
        self.configure(target_ids=("juice-shop",))
        self.upstream = self.PAGE
        page = self.client.get("/")  # selected target is "legacy" in tests
        self.assertIn("/rest/products/search", page.text)
        self.upstream = self.JSON
        self.assertEqual(self.client.get("/rest/products/search").status_code, 200)

    def test_risk_scores_never_switch_alias_decisions(self):
        self.configure(mode="observe")
        for score in ("0.1", "0.99"):
            with self.subTest(score=score):
                response = self.client.get("/rest/products/search", headers={
                    "x-ruby-risk-score": score, "x-ruby-confirmed-attack-score": score})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(self.logs()[-1]["decision"], "would_block")

    def test_cookieless_page_loads_in_two_tabs_share_nothing_but_still_work(self):
        self.upstream = self.PAGE
        first = self.client.get("/", cookies={})
        cookie_one = first.cookies.get(pa.COOKIE_NAME)
        self.client.cookies.clear()
        second = self.client.get("/")
        cookie_two = second.cookies.get(pa.COOKIE_NAME)
        self.assertNotEqual(cookie_one, cookie_two)
        alias_one = self.table.current_aliases(NOW, cookie_one)["/rest/products/search"]
        self.upstream = self.JSON
        # The browser kept the second cookie; tab one still holds aliases of pending client one.
        self.client.cookies.set(pa.COOKIE_NAME, cookie_two)
        response = self.client.get(alias_one)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.logs()[-1]["alias_state"], "adopted")
        self.assertIsNone(self.logs()[-1]["rotation"])

    def test_cookieless_tool_can_use_aliases_until_pending_ttl(self):
        self.configure(pending_ttl_s=5)  # shorter than the 10 s epoch: rows are still current
        self.upstream = self.PAGE
        page = self.client.get("/")
        cookie = page.cookies.get(pa.COOKIE_NAME)
        alias = self.table.current_aliases(NOW, cookie)["/rest/products/search"]
        self.client.cookies.clear()
        self.upstream = self.JSON
        self.assertEqual(self.client.get(alias).status_code, 200)  # no cookie, pending owner
        later = NOW + self.cfg.pending_ttl_s + 1
        with patch.object(main.time, "time", return_value=later):
            # No sweep has run: the TTL is enforced at lookup, not by deleting rows.
            self.table._next_sweep = later + 3600
            self.assertEqual(self.client.get(alias).status_code, 404)
            self.assertEqual((self.logs()[-1]["reason"], self.logs()[-1]["rotation"]), ("stale_alias", None))
            # the browser that does return the cookie keeps working
            self.client.cookies.set(pa.COOKIE_NAME, cookie)
            self.assertEqual(self.client.get(alias).status_code, 200)
            self.table._next_sweep = 0
            self.table.current_aliases(later, BOB)  # sweep: rows of expired pending clients go
        self.client.cookies.clear()

    def test_pending_client_cap_answers_503_in_enforce_and_original_in_observe(self):
        self.configure(max_pending_clients=2, max_clients=2)
        self.upstream = self.PAGE
        for _ in range(2):
            self.client.cookies.clear()
            self.assertEqual(self.client.get("/").status_code, 200)
        self.client.cookies.clear()
        full = self.client.get("/")
        self.assertEqual((full.status_code, full.headers["retry-after"]), (503, "5"))
        self.assertNotIn("set-cookie", full.headers)
        self.assertEqual(self.logs()[-1]["rewrite_skipped"], "pending")
        self.configure(mode="observe", max_pending_clients=2, max_clients=2)
        self.client.cookies.clear()
        page = self.client.get("/")
        self.assertEqual((page.status_code, page.text), (200, self.PAGE[2].decode()))
        self.assertEqual(self.logs()[-1]["rewrite_skipped"], "capacity")
        stats = self.table.stats()
        self.assertEqual((stats["clients"], stats["pending_clients"]), (2, 2))

    def test_database_failure_fails_closed(self):
        _, _, alias = self.open_page()
        before = len(self.calls)
        with patch.object(self.table, "_lookup", side_effect=sqlite3.OperationalError("locked")):
            response = self.client.get(alias)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(len(self.calls), before)
        with patch.object(self.table, "current_aliases", side_effect=pa.AliasStoreError("db")):
            self.upstream = self.PAGE
            self.client.cookies.clear()
            page = self.client.get("/")
        self.assertEqual(page.status_code, 503)
        self.assertNotIn("/rest/products/search", page.text)

    def test_stale_alias_get_redirects_and_post_is_never_replayed(self):
        _, client, search = self.open_page()
        login = self.table.current_aliases(NOW, client)["/rest/user/login"]
        self.assertEqual(self.client.get(search).status_code, 200)  # confirm the client
        later = NOW + 25  # past grace: both aliases are stale (expired by time)
        with patch.object(main.time, "time", return_value=later):
            before = len(self.calls)
            response = self.client.get(search + "?q=a%20b&q=")
            self.assertEqual(response.status_code, 307)
            fresh = self.table.current_aliases(later, client)["/rest/products/search"]
            self.assertEqual(response.headers["location"], fresh + "?q=a%20b&q=")
            self.assertEqual(self.logs()[-1]["rotation"], None)
            post = self.client.post(login, content=b'{"email":"a"}')
            self.assertEqual(post.status_code, 404)
            self.assertEqual(len(self.calls), before)
            self.assertEqual(self.logs()[-1]["reason"], "stale_alias")
            self.assertIsNone(self.logs()[-1]["rotation"])
            self.assertEqual(self.client.get(fresh).status_code, 200)

    def test_stale_broad_alias_with_suffix_redirects_to_the_specific_route(self):
        self.client.cookies.set(pa.COOKIE_NAME, ALICE)
        broad = self.table.current_aliases(NOW, ALICE, returned=True)["/rest/user/{tail*}"]
        self.table.current_aliases(NOW, ALICE, returned=True)  # confirmed
        self.assertEqual(self.client.get(broad + "/whoami").status_code, 200)
        later = NOW + 25
        with patch.object(main.time, "time", return_value=later):
            response = self.client.get(broad + "/whoami?x=1")
            self.assertEqual(response.status_code, 307)
            whoami = self.table.current_aliases(later, ALICE)["/rest/user/whoami"]
            self.assertEqual(response.headers["location"], whoami + "?x=1")
            self.assertEqual(self.client.get(response.headers["location"]).status_code, 200)
            self.assertIsNone(self.logs()[-1]["rotation"])
        self.assertTrue(self.calls[-1]["url"].endswith("/rest/user/whoami?x=1"))

    def test_event_revoked_alias_is_not_redirected_and_does_not_cascade(self):
        _, client, alias = self.open_page()
        self.assertEqual(self.client.get(alias).status_code, 200)
        self.assertEqual(self.client.get("/rest/products/search").status_code, 404)  # direct: rotate
        self.assertEqual(self.logs()[-1]["rotation"], "rotated")
        for _ in range(2):  # a second tab keeps using the old alias
            response = self.client.get(alias)
            self.assertEqual(response.status_code, 404)
            self.assertEqual(self.logs()[-1]["reason"], "revoked_alias")
            self.assertIsNone(self.logs()[-1]["rotation"])

    def test_rotation_minimum_interval(self):
        self.configure(rotate_min_interval_s=5)
        _, client, alias = self.open_page()
        self.client.get(alias)
        self.client.get("/rest/products/search")
        self.assertEqual(self.logs()[-1]["rotation"], "rotated")
        self.client.get("/rest/user/whoami")
        self.assertEqual(self.logs()[-1]["rotation"], "suppressed")

    def test_short_circuit_response_is_not_rewritten(self):
        strategy = AsyncMock()
        strategy.uses_state = False
        strategy.apply.return_value = DefenseResult(short_circuit=Response(
            b'<script>fetch("/rest/products/search")</script>', media_type="text/html"))
        with patch.dict(main.STRATEGY_REGISTRY, {"stop": strategy}):
            page = self.client.get("/", headers={"x-defense-plan": '[{"name":"stop"}]'})
        self.assertIn("/rest/products/search", page.text)
        self.assertNotIn("set-cookie", page.headers)

    def test_unprotected_dispatcher_values_pass_and_relative_protected_is_direct(self):
        self.configure(query_routes=(pa.QueryRoute("/gateway", "route"),))
        cases = {"route=%2Fhome&route=%2Fabout": 200, "route=home": 200, "route=%2Fstatic%2Fa.css": 200,
                 "route=rest%2Fuser%2Flogin": 404, "route=%2Frest%2Fuser%2Flogin%3Fx%3D1": 404}
        for query, status in cases.items():
            with self.subTest(query=query):
                before = len(self.calls)
                self.assertEqual(self.client.get("/gateway?" + query).status_code, status)
                if status == 200:
                    self.assertEqual(self.calls[-1]["url"], "http://localhost:9000/gateway?" + query)
                else:
                    self.assertEqual(len(self.calls), before)

    def test_action_dispatcher_end_to_end(self):
        self.configure(action_routes=(ACTIONS,))
        self.upstream = (200, [("content-type", "text/html")],
                         b'<form method=post action="/api.php?action=login"></form>'
                         b'<a href="/api.php?action=search&amp;q=a+b">s</a><a href="/api.php?action=help">h</a>')
        page = self.client.get("/")
        client = self.client.cookies.get(pa.COOKIE_NAME)
        aliases = self.table.current_aliases(NOW, client)
        login = aliases["/api.php?action=login"].lstrip("/")
        search = aliases["/api.php?action=search"].lstrip("/")
        self.assertIn("/api.php?action=" + login, page.text)
        self.assertIn("/api.php?action=" + search + "&amp;q=a+b", page.text)
        self.assertIn("/api.php?action=help", page.text)
        self.upstream = self.JSON
        self.assertEqual(self.client.post("/api.php?action=" + login + "&z=%41").status_code, 200)
        self.assertEqual(self.calls[-1]["url"], "http://localhost:9000/api.php?action=login&z=%41")
        self.assertEqual(self.logs()[-1]["route_id"], "/api.php?action=login")
        self.assertEqual(self.client.get("/api.php?action=help&empty=").status_code, 200)
        self.assertEqual(self.calls[-1]["url"], "http://localhost:9000/api.php?action=help&empty=")
        before = len(self.calls)
        for request in (("GET", "/api.php?action=" + login),  # method not allowed
                        ("POST", "/api.php?action=Login"),  # case variant of a protected action
                        ("GET", "/" + search)):  # an action alias is not a path alias
            with self.subTest(request=request):
                self.assertEqual(self.client.request(*request).status_code, 404)
        self.assertEqual(len(self.calls), before)
        self.assertNotIn("Login", json.dumps(self.logs()))

    def test_body_routing_is_reported_and_blocked_for_protected_selectors(self):
        self.configure(action_routes=(ACTIONS,))
        before = len(self.calls)
        response = self.client.post("/api.php", content=b"action=login&user=a",
                                    headers={"content-type": "application/x-www-form-urlencoded"})
        self.assertEqual(response.status_code, 404)
        self.assertEqual(len(self.calls), before)
        self.assertEqual(self.logs()[-1]["reason"], "body_routing_unsupported")
        response = self.client.post("/api.php", content=b'{"action":"help","n":1}',
                                    headers={"content-type": "application/json"})
        self.assertEqual(response.status_code, 200)

        async def forwarded():
            return b"".join([chunk async for chunk in self.calls[-1]["content"]])

        import asyncio
        self.assertEqual(asyncio.run(forwarded()), b'{"action":"help","n":1}')
        multipart = (b'--x\r\nContent-Disposition: form-data; name="action"\r\n\r\nlogin\r\n'
                     b'--x\r\nContent-Disposition: form-data; name="f"; filename="a.txt"\r\n\r\nhi\r\n--x--\r\n')
        before = len(self.calls)
        response = self.client.post("/api.php", content=multipart,
                                    headers={"content-type": "multipart/form-data; boundary=x"})
        self.assertEqual((response.status_code, len(self.calls)), (404, before))
        self.assertEqual(self.logs()[-1]["reason"], "body_routing_unsupported")

    def test_uninspectable_dispatcher_body_is_refused_in_enforce(self):
        self.configure(action_routes=(ACTIONS,), body_inspect_limit=64)
        padded = b"action=login&pad=" + b"x" * 200
        cases = {
            "oversized form": (padded, {"content-type": "application/x-www-form-urlencoded"}),
            "oversized, chunked": ((chunk for chunk in (padded[:50], padded[50:])),
                                   {"content-type": "application/x-www-form-urlencoded"}),
            "unknown type": (b"action=login", {"content-type": "text/plain"}),
            "malformed json": (b'{"action":"login"', {"content-type": "application/json"}),
        }
        for name, (content, headers) in cases.items():
            with self.subTest(name=name):
                before = len(self.calls)
                response = self.client.post("/api.php", content=content, headers=headers)
                self.assertEqual((response.status_code, len(self.calls)), (404, before))
                log = self.logs()[-1]
                self.assertEqual((log["reason"], log["rotation"]), ("body_uninspectable", None))
        # small, parseable and unprotected: forwarded byte for byte
        ok = self.client.post("/api.php?x=1", content=b"action=help&n=1",
                              headers={"content-type": "application/x-www-form-urlencoded"})
        self.assertEqual(ok.status_code, 200)

    def test_uninspectable_body_is_forwarded_intact_in_observe(self):
        self.configure(mode="observe", action_routes=(ACTIONS,), body_inspect_limit=64)
        case, self.received = self, []

        class ReadingClient:  # like httpx: the request body is consumed while sending
            def build_request(self, **kwargs):
                return kwargs

            async def send(self, request, stream=False):
                content = request.get("content")
                case.received.append(b"".join([c async for c in content]) if content is not None else b"")
                return httpx.Response(200, headers=[("content-type", "application/json")],
                                      stream=_AsyncBody(b"{}"))

        main.app.state.http_client = ReadingClient()
        padded = b"action=login&pad=" + b"x" * 200
        response = self.client.post("/api.php", content=(c for c in (padded[:50], padded[50:])),
                                    headers={"content-type": "application/x-www-form-urlencoded"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.received[-1], padded)
        self.assertEqual(self.logs()[-1]["decision"], "would_block")

    def test_cookieless_channel_passes_only_without_alias_cookie(self):
        channel = pa.Channel("partner", (pa.Route("/rest/products/search"),), ("GET",), ("authorization",))
        self.configure(channels=(channel,))
        headers = {"authorization": "Bearer x"}
        self.assertEqual(self.client.get("/rest/products/search", headers=headers).status_code, 200)
        self.assertEqual((self.logs()[-1]["kind"], self.logs()[-1]["reason"]), ("channel", "partner"))
        self.assertEqual(self.client.get("/rest/products/search").status_code, 404)  # header missing
        self.open_page()
        self.assertEqual(self.client.get("/rest/products/search", headers=headers).status_code, 404)

    def test_missing_alias_cookie_never_allows_original_routes(self):
        self.client.cookies.clear()
        for path in ("/rest/products/search", "/rest/user/login", "/api/Products/1"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)


class WebSocketAliasTests(IntegrationTests):
    def test_upgrade_to_protected_route_is_checked(self):
        connected = []

        class FakeUpstream:
            subprotocol = None

            def __init__(self, url, **kwargs):
                connected.append(url)

            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            def __aiter__(self):
                return self

            async def __anext__(self):
                raise StopAsyncIteration

            async def send(self, payload):
                pass

        _, client, _ = self.open_page()
        alias = self.table.current_aliases(NOW, client)["/rest/user/whoami"]
        with patch.object(main.websockets, "connect", FakeUpstream):
            try:
                with self.client.websocket_connect(alias + "?x=1"):
                    pass
            except Exception:
                pass
            self.assertEqual(connected, ["ws://localhost:9000/rest/user/whoami?x=1"])
            with self.assertRaises(Exception):
                with self.client.websocket_connect("/rest/user/whoami") as ws:
                    ws.receive_text()
        self.assertEqual(len(connected), 1)  # the original route never reached the target
        self.assertEqual(self.logs()[-1]["rotation"], "rotated")


def load_tests(loader, tests, pattern):
    """Run only the tests defined here, not the inherited IntegrationTests cases."""
    suite = unittest.TestSuite()
    for case in (ConfigFileTests, RewriteContextTests, AliasPolicyIntegrationTests, WebSocketAliasTests):
        names = [name for name in vars(case) if name.startswith("test_")]
        suite.addTests(case(name) for name in names)
    return suite


if __name__ == "__main__":
    unittest.main()
