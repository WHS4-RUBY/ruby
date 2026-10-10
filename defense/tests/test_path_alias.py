import asyncio
import hashlib
import hmac
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
from starlette.testclient import TestClient

from defense.app import main, path_alias as pa
from defense.app.strategies.base import DefenseResult

ROUTES = (
    pa.Route("/rest/user/login", ("POST",)),
    pa.Route("/rest/user/whoami"),
    pa.Route("/rest/user/{tail*}"),
    pa.Route("/rest/products/search"),
    pa.Route("/rest/basket/{id}/checkout"),
    pa.Route("/api/Products/{tail*}"),
)
CFG = pa.PathAliasConfig(mode="enforce", epoch_s=10, grace_epochs=1, routes=ROUTES)
NOW = 100.25
ALICE = "a" * 26
BOB = "b" * 26


class ConfigTests(unittest.TestCase):
    def test_off_ignores_other_settings(self):
        self.assertEqual(pa.PathAliasConfig.from_env({"PATH_ALIAS_MODE": "off",
                                                      "PATH_ALIAS_EPOCH_S": "bad"}), pa.PathAliasConfig())

    def test_route_file_and_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "routes.json"
            path.write_text(json.dumps({"routes": ["/rest/a", {"path": "/api/Items/{id}",
                                                 "methods": ["GET"]}]}), encoding="utf-8")
            cfg = pa.PathAliasConfig.from_env({"PATH_ALIAS_MODE": "enforce",
                                               "PATH_ALIAS_ROUTES_FILE": str(path),
                                               "PATH_ALIAS_DB_PATH": str(Path(directory) / "aliases.sqlite3"),
                                               "PATH_ALIAS_ROTATE_ON": "direct"})
        self.assertEqual(len(cfg.routes), 2)
        self.assertEqual(next(r.methods for r in cfg.routes if r.path == "/api/Items/{id}"), ("GET",))
        self.assertEqual(cfg.rotate_on, ("direct",))
        self.assertEqual(cfg.epoch_s, 1800)

    def test_invalid_config_fails_at_start(self):
        for env in ({"PATH_ALIAS_MODE": "wrong"},
                    {"PATH_ALIAS_MODE": "enforce"},
                    {"PATH_ALIAS_MODE": "observe", "PATH_ALIAS_EPOCH_S": "0"},
                    {"PATH_ALIAS_MODE": "observe", "PATH_ALIAS_GRACE_EPOCHS": "11"}):
            with self.subTest(env=env), self.assertRaises(ValueError):
                pa.PathAliasConfig.from_env(env)
        with self.assertRaises(ValueError):
            pa._parse_triggers("direct,other")
        self.assertEqual(pa._parse_triggers(""), ())
        for path in ("/", "/rest/{x}/more/{x}", "/rest/{tail*}/more", "/__ruby_alias_real"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                pa.Route(path)

    def test_client_id_format(self):
        self.assertEqual(pa.valid_client_id(ALICE), ALICE)
        self.assertRegex(pa.new_client_id(), r"^[a-z2-7]{26}$")
        for value in (None, "", "A" * 26, "a" * 25, "a" * 27, "a" * 25 + ";"):
            with self.subTest(value=value):
                self.assertIsNone(pa.valid_client_id(value))

    def test_query_route_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "routes.json"
            document = {"routes": ["/api/items"], "query_routes": [
                {"path": "/", "parameter": "rest_route"},
                {"path": "/gateway", "parameter": "route"}]}
            file.write_text(json.dumps(document), encoding="utf-8")
            cfg = pa.PathAliasConfig.from_env({"PATH_ALIAS_MODE": "enforce",
                "PATH_ALIAS_ROUTES_FILE": str(file),
                "PATH_ALIAS_DB_PATH": str(Path(directory) / "db.sqlite")})
            self.assertEqual(cfg.query_routes[0], pa.QueryRoute("/", "rest_route"))
            document["query_routes"].append(document["query_routes"][0])
            file.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(ValueError):
                pa._load_query_routes(str(file))
        for path, key in (("/gateway/{id}", "route"), ("/gateway", "bad&key")):
            with self.assertRaises(ValueError):
                pa.QueryRoute(path, key)


class TableTests(unittest.TestCase):
    def make_cfg(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return replace(CFG, db_path=str(Path(directory.name) / "aliases.sqlite3"))

    def setUp(self):
        self.cfg = self.make_cfg()
        self.table = pa.PathAliasTable(self.cfg)
        p = patch.object(pa, "emit")
        self.emitted = p.start()
        self.addCleanup(p.stop)

    def a(self, route, now=NOW, client=ALICE):
        return self.table.current_aliases(now, client)[route]

    def confirm(self, client=ALICE, now=NOW):
        """The browser returned its cookie: a pending client becomes confirmed."""
        self.table.current_aliases(now, client, returned=True)

    def sql(self, query, params=()):
        with self.table._store.connect() as db:
            return [tuple(row.values()) if isinstance(row, dict) else tuple(row)
                    for row in db.execute(query, params).fetchall()]

    def test_independent_rows_and_server_lookup(self):
        login = self.a("/rest/user/login")
        search = self.a("/rest/products/search")
        self.assertRegex(login, r"^/__ruby_alias_[a-z2-7]{26}$")
        self.assertNotEqual(login, search)
        self.assertEqual(self.table.resolve(login, "POST", NOW, ALICE).upstream_path, "/rest/user/login")
        self.assertEqual(self.table.resolve(search, "GET", NOW, ALICE).upstream_path, "/rest/products/search")
        self.assertEqual(self.table.resolve(login, "GET", NOW, ALICE).reason, "method_not_allowed")
        self.assertEqual(pa.PathAliasTable(self.cfg).resolve(login, "POST", NOW, ALICE).upstream_path,
                         "/rest/user/login")

    def test_aliases_are_bound_to_one_client(self):
        alice = self.a("/rest/products/search")
        bob = self.a("/rest/products/search", client=BOB)
        self.confirm(ALICE)
        self.assertNotEqual(alice, bob)
        self.assertEqual(self.table.resolve(alice, "GET", NOW, BOB).reason, "foreign_alias")
        self.assertEqual(self.table.resolve(alice, "GET", NOW, None).reason, "foreign_alias")
        self.assertEqual(self.table.resolve(bob, "GET", NOW, BOB).kind, "alias")

    def test_event_rotation_is_immediate_and_per_client(self):
        old = self.a("/rest/products/search")
        bob = self.a("/rest/products/search", client=BOB)
        self.assertEqual(self.table.rotate_client(ALICE, NOW + 1, "direct"), "rotated")
        # A tombstone tells an event-replaced alias apart from a forged one (no new rotation).
        self.assertEqual(self.table.resolve(old, "GET", NOW + 1, ALICE).reason, "revoked_alias")
        new = self.a("/rest/products/search", NOW + 1)
        self.assertNotEqual(old, new)
        self.assertEqual(self.table.resolve(new, "GET", NOW + 1, ALICE).alias_state, "current")
        self.assertEqual(self.table.resolve(bob, "GET", NOW + 1, BOB).kind, "alias")
        self.assertFalse(self.table.rotate_client("c" * 26, NOW, "direct"))
        rotation = self.emitted.call_args_list[-1].args[0]
        self.assertEqual((rotation["event"], rotation["reason"]), ("path_alias_rotation", "direct"))
        self.assertNotIn(ALICE, json.dumps(rotation))

    def test_time_backstop_keeps_grace_then_expires(self):
        old = self.a("/rest/products/search")
        new = self.a("/rest/products/search", NOW + 10)
        self.assertNotEqual(old, new)
        self.assertEqual(self.table.resolve(old, "GET", NOW + 10, ALICE).alias_state, "grace")
        self.assertEqual(self.table.resolve(new, "GET", NOW + 10, ALICE).alias_state, "current")
        self.assertEqual(self.table.resolve(old, "GET", NOW + 20, ALICE).reason, "stale_alias")
        self.assertEqual(self.table.resolve(new, "GET", NOW + 20, ALICE).alias_state, "grace")

    def test_event_rotation_drops_grace_rows_too(self):
        old = self.a("/rest/products/search")
        grace = self.a("/rest/products/search", NOW + 10)
        self.assertNotEqual(old, grace)
        self.table.rotate_client(ALICE, NOW + 11, "reject")
        for alias in (old, grace):
            self.assertEqual(self.table.resolve(alias, "GET", NOW + 11, ALICE).reason, "revoked_alias")

    def test_idle_clients_are_cleaned_up(self):
        self.a("/rest/products/search", client=BOB)
        self.confirm(BOB)
        # idle = lifetime (20s) + tombstone (20s) after the last issue
        self.a("/rest/products/search", NOW + 45)  # a new client triggers housekeeping
        clients = {row[0] for row in self.sql("SELECT client_id FROM path_alias_client_state")}
        bob_rows = self.sql("SELECT COUNT(*) FROM path_alias_alias_rows WHERE client_id=?", (BOB,))[0][0]
        self.assertEqual(clients, {ALICE})
        self.assertEqual(bob_rows, 0)

    def test_full_capacity_reclaims_idle_confirmed_clients_without_sweep(self):
        self.cfg = replace(self.cfg, max_clients=1, max_pending_clients=1)
        self.table = pa.PathAliasTable(self.cfg)
        old = self.a("/rest/products/search")
        self.confirm()
        self.table._next_sweep = NOW + 3600
        # Keep the owner while its stale aliases can still be recovered.
        with self.assertRaises(pa.AliasCapacityError) as failure:
            self.a("/rest/products/search", NOW + 39, BOB)
        self.assertEqual(str(failure.exception), "total")
        self.assertEqual(self.table.resolve(old, "GET", NOW + 39, ALICE).reason, "stale_alias")
        new = self.a("/rest/products/search", NOW + 41, BOB)
        self.assertEqual(self.table.resolve(new, "GET", NOW + 41, BOB).kind, "alias")
        self.assertEqual(self.sql("SELECT client_id FROM path_alias_client_state"), [(BOB,)])
        self.assertEqual(self.sql("SELECT COUNT(*) FROM path_alias_alias_rows WHERE client_id=?", (ALICE,)), [(0,)])

    def test_sweep_runs_at_most_once_per_interval(self):
        clients = lambda: {row[0] for row in self.sql("SELECT client_id FROM path_alias_client_state")}
        self.a("/rest/products/search", client=BOB)
        self.confirm(BOB)
        self.table._next_sweep = NOW + 46  # as if another client had just swept
        self.a("/rest/products/search", NOW + 45)
        self.assertEqual(clients(), {ALICE, BOB})  # BOB expired, but the interval has not passed
        self.a("/rest/products/search", NOW + 46, client="c" * 26)
        self.assertEqual(clients(), {ALICE, "c" * 26})

    def test_sweep_failure_does_not_fail_issuance(self):
        with patch.object(self.table, "_sweep", side_effect=RuntimeError("db down")):
            self.assertRegex(self.a("/rest/products/search"), r"^/__ruby_alias_")
        self.assertEqual(self.emitted.call_args.args[0]["event"], "path_alias_rotation")
        events = [call.args[0]["event"] for call in self.emitted.call_args_list]
        self.assertIn("path_alias_sweep_failed", events)

    def test_parallel_instances_share_one_issuance(self):
        tables = [pa.PathAliasTable(self.cfg) for _ in range(6)]
        with ThreadPoolExecutor(max_workers=6) as pool:
            aliases = list(pool.map(lambda table: table.current_aliases(NOW, ALICE), tables))
        self.assertTrue(all(item == aliases[0] for item in aliases))
        rows = self.sql("SELECT COUNT(*) FROM path_alias_alias_rows WHERE client_id=?", (ALICE,))[0][0]
        self.assertEqual(rows, len(self.cfg.routes))

    def test_config_change_invalidates_existing_aliases(self):
        old = self.a("/rest/products/search")
        updated = pa.PathAliasTable(replace(self.cfg, routes=(pa.Route("/rest/new"),)))
        # The old row's route is no longer configured, so nothing can restore it.
        self.assertEqual(updated.resolve(old, "GET", NOW, ALICE).reason, "unknown_alias")
        new = updated.current_aliases(NOW, ALICE)["/rest/new"]
        self.assertEqual(updated.resolve(new, "GET", NOW, ALICE).kind, "alias")

    def test_run_ids_isolate_aliases_in_one_database(self):
        old = self.a("/rest/products/search")
        second = pa.PathAliasTable(replace(self.cfg, app_id="experiment-b"))
        new = second.current_aliases(NOW, ALICE)["/rest/products/search"]
        self.assertNotEqual(old, new)
        self.assertEqual(second.resolve(old, "GET", NOW, ALICE).reason, "unknown_alias")
        self.assertEqual(self.table.resolve(old, "GET", NOW, ALICE).kind, "alias")

    def test_generated_alias_collision_is_retried(self):
        two = replace(self.cfg, routes=(pa.Route("/rest/a"), pa.Route("/rest/b")))
        with patch.object(pa.secrets, "token_bytes", side_effect=[b"\0" * 17, b"\0" * 17,
                                                                 b"\1" * 17]):
            aliases = pa.PathAliasTable(two).current_aliases(NOW, ALICE)
        self.assertNotEqual(aliases["/rest/a"], aliases["/rest/b"])

    def test_template_and_shadowed_wildcard(self):
        basket = self.a("/rest/basket/{id}/checkout")
        self.assertEqual(self.table.resolve(basket + "/5", "POST", NOW, ALICE).upstream_path,
                         "/rest/basket/5/checkout")
        self.assertEqual(self.table.resolve(basket + "/5/../x", "POST", NOW, ALICE).kind, "reject")
        product = self.a("/api/Products/{tail*}")
        self.assertEqual(self.table.resolve(product + "/1/reviews", "GET", NOW, ALICE).upstream_path,
                         "/api/Products/1/reviews")
        self.assertEqual(self.table.resolve(product + "/", "GET", NOW, ALICE).upstream_path,
                         "/api/Products/")
        user = self.a("/rest/user/{tail*}")
        # base alias + runtime suffix reaching a more specific route: that route's rules apply
        login = self.table.resolve(user + "/login", "POST", NOW, ALICE)
        self.assertEqual((login.kind, login.upstream_path, login.route_id),
                         ("alias", "/rest/user/login", "/rest/user/login"))
        self.assertEqual(self.table.resolve(user + "/login", "GET", NOW, ALICE).reason, "method_not_allowed")

    def test_malformed_alias_paths_are_rejected(self):
        login = self.a("/rest/user/login")
        for path in (login + "x", login.upper(), "/__ruby_alias_" + "a" * 26,
                     "/%5f_ruby_alias_" + "a" * 26, "/x/__ruby_alias_" + "a" * 26):
            with self.subTest(path=path):
                self.assertEqual(self.table.resolve(path, "POST", NOW, ALICE).kind, "reject")

    def test_direct_detection_is_scoped(self):
        for path in ("/rest/user/login", "/REST/user/login", "/%72est/user/login",
                     "//rest/user/login", "/rest;x/user/login"):
            with self.subTest(path=path):
                self.assertEqual(self.table.resolve(path, "POST", NOW, ALICE).kind, "direct")
        for path in ("/assets/café.png", "/unrelated;x", "/foo/rest/x"):
            with self.subTest(path=path):
                self.assertEqual(self.table.resolve(path, "GET", NOW, ALICE).kind, "other")

    def test_rewrite_literal_template_and_location(self):
        body = (b'fetch("/rest/products/search?q=x");'
                b'fetch(`/rest/basket/${e}/checkout`);'
                b'host="/api/Products";external="https://other/api/Products";'
                b'notRoute="/rest/products/search/extra";notResource="/api/ProductsExtra"')
        output, count = self.table.rewrite_body(body, NOW, ALICE)
        self.assertEqual(count, 3)
        self.assertIn(self.a("/rest/basket/{id}/checkout").encode() + b"/${e}", output)
        self.assertIn(b"https://other/api/Products", output)
        self.assertIn(b"/rest/products/search/extra", output)
        self.assertIn(b"/api/ProductsExtra", output)
        self.assertEqual(self.table.rewrite_location("/rest/products/search?q=x", "shop", NOW, ALICE),
                         self.a("/rest/products/search") + "?q=x")
        self.assertEqual(self.table.rewrite_location("https://other/rest/products/search", "shop", NOW, ALICE),
                         "https://other/rest/products/search")

    def test_bodies_without_routes_create_no_client(self):
        self.assertEqual(self.table.rewrite_body(b'{"rest":"/restaurant"}', NOW, BOB)[1], 0)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM path_alias_client_state")[0][0], 0)

    def test_observe_and_off(self):
        direct = self.table.resolve("/rest/user/login", "POST", NOW, ALICE)
        self.assertEqual(pa.decide(direct, CFG), "block")
        self.assertEqual(pa.decide(direct, replace(CFG, mode="observe")), "would_block")
        self.assertEqual(pa.PathAliasTable(pa.PathAliasConfig()).resolve("/rest/x", "GET", NOW).kind,
                         "other")



class _AsyncBody(httpx.AsyncByteStream):
    def __init__(self, body):
        self.body = body

    async def __aiter__(self):
        for index in range(0, len(self.body), 7):
            yield self.body[index:index + 7]


class IntegrationTests(unittest.TestCase):
    PAGE = (200, [("content-type", "text/html"), ("etag", "one")],
            b'<script>fetch("/rest/products/search")</script>')
    JSON = (200, [("content-type", "application/json")], b'{"ok":true}')

    def setUp(self):
        self.calls = []
        self.upstream = self.JSON
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
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.cfg = replace(CFG, db_path=str(Path(directory.name) / "aliases.sqlite3"))
        self.table = pa.PathAliasTable(self.cfg)
        for name, value in (("PATH_ALIAS", self.cfg), ("PATH_ALIAS_TABLE", self.table)):
            p = patch.object(main, name, value)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(main.time, "time", return_value=NOW)
        p.start()
        self.addCleanup(p.stop)
        p = patch.object(pa, "emit")
        self.emitted = p.start()
        self.addCleanup(p.stop)
        self.client = TestClient(main.app, follow_redirects=False)
        self.addCleanup(self.client.close)

    def logs(self, event="path_alias"):
        return [c.args[0] for c in self.emitted.call_args_list if c.args[0]["event"] == event]

    def open_page(self):
        self.upstream = self.PAGE
        page = self.client.get("/")
        self.upstream = self.JSON
        client_id = self.client.cookies.get(pa.COOKIE_NAME)
        return page, client_id, self.table.current_aliases(NOW, client_id)["/rest/products/search"]

    def test_page_issues_cookie_and_alias_forwards(self):
        page, client_id, alias = self.open_page()
        self.assertRegex(client_id, r"^[a-z2-7]{26}$")
        self.assertIn(alias, page.text)
        self.assertIn("HttpOnly", page.headers["set-cookie"])
        self.assertEqual(page.headers["cache-control"], "no-store")
        self.assertNotIn("etag", page.headers)
        result = self.client.get(alias, params={"q": "apple"})
        self.assertEqual(result.status_code, 200)
        self.assertNotIn("set-cookie", result.headers)
        self.assertTrue(self.calls[-1]["url"].endswith("/rest/products/search?q=apple"))
        self.assertNotIn("params", self.calls[-1])
        self.assertEqual(self.logs()[-1]["route_id"], "/rest/products/search")
        self.assertNotIn(client_id, json.dumps(self.emitted.call_args_list[-1].args[0]))

    def test_query_path_bytes_survive_alias_translation(self):
        _, _, alias = self.open_page()
        raw_query = "next=%2Fapi%2FProducts%2F1&next=/rest/user/login&empty=&flag"
        result = self.client.get(alias + "?" + raw_query)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.calls[-1]["url"],
                         "http://localhost:9000/rest/products/search?" + raw_query)
        self.assertNotIn("params", self.calls[-1])

    def test_later_strategy_sees_restored_route_and_original_query(self):
        _, _, alias = self.open_page()
        raw_query = "q=apple&next=%2Fapi%2FProducts&empty=&flag"
        strategy = AsyncMock()
        strategy.apply.return_value = DefenseResult()
        with patch.dict(main.STRATEGY_REGISTRY, {"inspect_route": strategy}):
            response = self.client.get(alias + "?" + raw_query, headers={
                "x-defense-plan": '[{"name":"inspect_route"}]',
            })
        self.assertEqual(response.status_code, 200)
        request = strategy.apply.call_args.args[0]
        self.assertEqual(request.url.path, "/rest/products/search")
        self.assertEqual(request.scope["path"], "/rest/products/search")
        self.assertEqual(request.scope["raw_path"], b"/rest/products/search")
        self.assertEqual(request.path_params["full_path"], "rest/products/search")
        self.assertEqual(request.scope["query_string"], raw_query.encode())
        self.assertEqual(self.calls[-1]["url"],
                         "http://localhost:9000/rest/products/search?" + raw_query)

    def test_stage_one_blocks_before_later_strategies(self):
        self.open_page()
        strategy = AsyncMock()
        strategy.apply.return_value = DefenseResult()
        with patch.dict(main.STRATEGY_REGISTRY, {"inspect_route": strategy}):
            response = self.client.get("/rest/products/search", headers={
                "x-defense-plan": '[{"name":"inspect_route"}]',
            })
        self.assertEqual(response.status_code, 404)
        strategy.apply.assert_not_awaited()

    def test_later_strategy_can_read_body_without_losing_forwarded_body(self):
        _, client_id, _ = self.open_page()
        alias = self.table.current_aliases(NOW, client_id)["/rest/user/login"]
        payload = b'{"email":"test@example.invalid","password":"example"}'
        seen = []

        async def inspect(request, params, state):
            seen.append((request.url.path, await request.body()))
            return DefenseResult()

        strategy = AsyncMock()
        strategy.apply.side_effect = inspect
        with patch.dict(main.STRATEGY_REGISTRY, {"inspect_route": strategy}):
            response = self.client.post(alias, content=payload, headers={
                "x-defense-plan": '[{"name":"inspect_route"}]',
            })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(seen, [("/rest/user/login", payload)])

        async def forwarded_body():
            return b"".join([chunk async for chunk in self.calls[-1]["content"]])

        self.assertEqual(asyncio.run(forwarded_body()), payload)

    def test_path_mentioned_in_unconfigured_query_is_not_a_direct_hit(self):
        result = self.client.get("/?next=%2Frest%2Fuser%2Flogin")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.calls[-1]["url"],
                         "http://localhost:9000/?next=%2Frest%2Fuser%2Flogin")
        self.assertEqual(self.logs(), [])

    def configure_query_routes(self):
        cfg = replace(self.cfg, query_routes=(pa.QueryRoute("/gateway", "route"),))
        table = pa.PathAliasTable(cfg)
        for name, value in (("PATH_ALIAS", cfg), ("PATH_ALIAS_TABLE", table)):
            p = patch.object(main, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.cfg, self.table = cfg, table

    def test_query_route_body_and_location_issue_encoded_alias(self):
        self.configure_query_routes()
        url = "/gateway?route=%2Frest%2Fproducts%2Fsearch&empty=&flag"
        self.upstream = (302, [("content-type", "text/html"), ("location", url)],
                         ('<a href="' + url.replace("&", "&amp;") + '">search</a>').encode())
        page = self.client.get("/")
        client = self.client.cookies.get(pa.COOKIE_NAME)
        alias = self.table.current_aliases(NOW, client)["/rest/products/search"]
        self.assertIn("route=%2F" + alias.lstrip("/"), page.headers["location"])
        self.assertIn("&amp;empty=&amp;flag", page.text)
        self.assertNotIn("%2Frest%2F", page.text)
        self.upstream = self.JSON
        response = self.client.get(page.headers["location"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.calls[-1]["url"], "http://localhost:9000" + url)

    def test_query_alias_reaches_later_strategy_and_preserves_other_fields(self):
        self.configure_query_routes()
        _, _, alias = self.open_page()
        strategy = AsyncMock()
        strategy.apply.return_value = DefenseResult()
        query = "route=" + alias + "&q=a%20b&q=a+b&empty=&flag"
        with patch.dict(main.STRATEGY_REGISTRY, {"inspect": strategy}):
            response = self.client.get("/gateway?" + query, headers={
                "x-defense-plan": '[{"name":"inspect"}]'})
        self.assertEqual(response.status_code, 200)
        request = strategy.apply.call_args.args[0]
        self.assertEqual(request.url.path, "/gateway")
        self.assertEqual(request.query_params["route"], "/rest/products/search")
        self.assertTrue(self.calls[-1]["url"].endswith(
            "/gateway?route=/rest/products/search&q=a%20b&q=a+b&empty=&flag"))

    def test_query_direct_foreign_duplicate_and_old_alias_block_before_forward(self):
        self.configure_query_routes()
        _, client, alias = self.open_page()
        foreign = self.table.current_aliases(NOW, BOB)["/rest/products/search"]
        self.table.current_aliases(NOW, BOB, returned=True)  # BOB is a confirmed browser
        for query in ("route=%2Frest%2Fproducts%2Fsearch", "route=" + foreign,
                      "route=" + alias + "&%72oute=" + alias, "route=" + alias):
            with self.subTest(query=query):
                before = len(self.calls)
                response = self.client.get("/gateway?" + query)
                self.assertEqual(response.status_code, 404)
                self.assertEqual(len(self.calls), before)
        self.assertEqual(self.table.resolve(alias, "GET", NOW, client).reason, "revoked_alias")

    def test_query_route_method_and_dynamic_suffix(self):
        self.configure_query_routes()
        _, client, _ = self.open_page()
        aliases = self.table.current_aliases(NOW, client)
        login = aliases["/rest/user/login"]
        self.assertEqual(self.client.get("/gateway?route=" + login).status_code, 404)
        aliases = self.table.current_aliases(NOW, client)
        checkout = aliases["/rest/basket/{id}/checkout"]
        response = self.client.get("/gateway?route=" + checkout + "/42")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.calls[-1]["url"].endswith("route=/rest/basket/42/checkout"))

    def test_query_observe_keeps_restored_dispatcher_and_logs_would_block(self):
        cfg = replace(self.cfg, mode="observe", query_routes=(
            pa.QueryRoute("/rest/user/whoami", "route"),))
        table = pa.PathAliasTable(cfg)
        with patch.object(main, "PATH_ALIAS", cfg), patch.object(main, "PATH_ALIAS_TABLE", table):
            self.client.cookies.set(pa.COOKIE_NAME, ALICE)
            dispatcher = table.current_aliases(NOW, ALICE)["/rest/user/whoami"]
            response = self.client.get(dispatcher + "?route=%2Frest%2Fproducts%2Fsearch")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.calls[-1]["url"].endswith(
            "/rest/user/whoami?route=%2Frest%2Fproducts%2Fsearch"))
        self.assertEqual(self.logs()[-1]["decision"], "would_block")

    def test_alias_without_its_cookie_is_refused(self):
        _, _, alias = self.open_page()
        self.assertEqual(self.client.get(alias).status_code, 200)  # cookie returned: confirmed
        self.client.cookies.clear()
        self.assertEqual(self.client.get(alias).status_code, 404)
        self.assertEqual(self.logs()[-1]["reason"], "foreign_alias")

    def test_restored_alias_uses_selected_target(self):
        _, _, alias = self.open_page()
        selected = main.target_selection.SelectedTarget("alternate", "http://alternate:8080", "run", "now")
        with patch.object(main.target_selection.target_selector, "for_request", return_value=selected):
            response = self.client.get(alias + "?q=a%20b")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.calls[-1]["url"], "http://alternate:8080/rest/products/search?q=a%20b")

    def test_restored_alias_reaches_decoy_sidecar_with_raw_query(self):
        self.client.cookies.set(pa.COOKIE_NAME, ALICE)
        alias = self.table.current_aliases(NOW, ALICE)["/rest/products/search"]
        selected = main.target_selection.SelectedTarget(
            "juice-shop", "http://juice-shop-target:3000", "run", "now")
        raw_query = "next=%2Fapi%2FProducts%2F1&empty=&flag"
        with patch.object(main.target_selection.target_selector, "for_request", return_value=selected), patch.object(
                main, "DECOY_UPSTREAMS", {"juice-shop": "http://cheat-juice:3012"}), patch.object(
                main, "OVERLAY_UPSTREAMS", {}):
            response = self.client.get(alias + "?" + raw_query)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.calls[-1]["url"],
                         "http://cheat-juice:3012/rest/products/search?" + raw_query)
        self.assertEqual(self.logs()[-1]["route_id"], "/rest/products/search")

    def test_restored_alias_reaches_overlay_with_signed_raw_target(self):
        key = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        self.client.cookies.set(pa.COOKIE_NAME, ALICE)
        alias = self.table.current_aliases(NOW, ALICE)["/rest/user/login"]
        selected = main.target_selection.SelectedTarget(
            "juice-shop", "http://juice-shop-target:3000", "run", "now")
        store = main.OverlayRouteStore.bootstrap(
            str(Path(self.cfg.db_path).parent / "overlay" / "routes.sqlite3"), key, {"juice-shop"})
        captured = []

        def backend(request):
            captured.append(request)
            return httpx.Response(200, stream=_AsyncBody(b"overlay"))

        upstream = httpx.AsyncClient(transport=httpx.MockTransport(backend))
        self.addCleanup(lambda: asyncio.run(upstream.aclose()))
        raw_query = "next=%2Fapi%2FProducts%2F1&empty=&flag"
        body = b"email=a%40example.invalid"
        plan = json.dumps([{"name": main.OVERLAY_MEDIUM, "params": {}}])
        with patch.object(main.app.state, "http_client", upstream), patch.object(
                main.target_selection.target_selector, "for_request", return_value=selected), patch.object(
                main, "OVERLAY_UPSTREAMS", {"juice-shop": "http://overlay-juice:8080"}), patch.object(
                main, "OVERLAY_DETECTOR_KEY", key), patch.object(
                main.app.state, "overlay_routes", store, create=True):
            response = self.client.post(alias + "?" + raw_query, content=body, headers={
                "x-client-id": "resolved:alice",
                "x-ruby-risk-score": "0.6",
                "x-ruby-confirmed-attack-score": "0.6",
                "x-defense-plan": plan,
            })

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(captured), 1)
        request = captured[0]
        raw_target = "/rest/user/login?" + raw_query
        self.assertEqual(request.url.raw_path, raw_target.encode("ascii"))
        self.assertEqual(request.content, body)
        signed = request.headers
        fields = ["agent", signed["x-defense-actor"], signed["x-defense-timestamp"],
                  signed["x-defense-nonce"], "POST", raw_target,
                  hashlib.sha256(body).hexdigest()]
        expected = hmac.new(key, "\n".join(fields).encode(), hashlib.sha256).hexdigest()
        self.assertEqual(signed["x-defense-signature"], expected)
        self.assertEqual(self.logs()[-1]["route_id"], "/rest/user/login")

    def test_rewritten_html_strips_forged_defense_headers(self):
        self.upstream = (200, [("content-type", "text/html"),
                               ("x-defense-signal", "forged"),
                               ("x-ruby-decoy-action", "maze")],
                         b'<script>fetch("/rest/products/search")</script>')
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertIn("/__ruby_alias_", page.text)
        self.assertNotIn("x-defense-signal", page.headers)
        self.assertNotIn("x-ruby-decoy-action", page.headers)

    def test_alias_rewrite_runs_after_response_transform(self):
        from starlette.responses import Response
        self.upstream = self.JSON
        strategy = AsyncMock()
        strategy.uses_state = False
        strategy.apply.return_value = DefenseResult(response_transform=lambda response: Response(
            b'<script>fetch("/rest/products/search")</script>', media_type="text/html"))
        with patch.dict(main.STRATEGY_REGISTRY, {"transform": strategy}):
            page = self.client.get("/", headers={"x-defense-plan": '[{"name":"transform"}]'})
        self.assertEqual(page.status_code, 200)
        client = self.client.cookies.get(pa.COOKIE_NAME)
        alias = self.table.current_aliases(NOW, client)["/rest/products/search"]
        self.assertIn(alias, page.text)
        self.assertNotIn("/rest/products/search", page.text)

    def test_direct_hit_rotates_that_clients_aliases(self):
        _, client_id, alias = self.open_page()
        backend_calls = len(self.calls)
        with patch.object(main, "PATH_ALIAS", replace(self.cfg, rotate_on=("direct",))):
            self.assertEqual(self.client.get("/rest/products/search").status_code, 404)
        self.assertEqual(self.logs()[-1]["rotation"], "rotated")
        self.assertEqual(self.client.get(alias).status_code, 404)
        self.assertEqual(len(self.calls), backend_calls)
        page, same_client, fresh = self.open_page()
        self.assertEqual(same_client, client_id)
        self.assertNotEqual(fresh, alias)
        self.assertIn(fresh, page.text)
        self.assertEqual(self.client.get(fresh).status_code, 200)

    def test_direct_and_unknown_alias_never_reach_backend(self):
        self.open_page()
        backend_calls = len(self.calls)
        client_id = self.client.cookies.get(pa.COOKIE_NAME)
        user_alias = self.table.current_aliases(NOW, client_id)["/rest/user/{tail*}"]
        for path in ("/rest/products/search", "/__ruby_alias_" + "a" * 26, user_alias + "/login"):
            with self.subTest(path=path):
                self.assertEqual(self.client.get(path).status_code, 404)
        self.assertEqual(len(self.calls), backend_calls)

    def test_observe_forwards_direct_and_does_not_rotate(self):
        _, _, alias = self.open_page()
        with patch.object(main, "PATH_ALIAS", replace(self.cfg, mode="observe")):
            response = self.client.get("/rest/products/search")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.calls[-1]["url"].endswith("/rest/products/search"))
        log = self.logs()[-1]
        self.assertEqual((log["decision"], log["rotation"]), ("would_block", None))
        self.assertEqual(self.client.get(alias).status_code, 200)

    def test_rotation_triggers_can_be_disabled(self):
        _, _, alias = self.open_page()
        with patch.object(main, "PATH_ALIAS", replace(self.cfg, rotate_on=())):
            self.assertEqual(self.client.get("/rest/products/search").status_code, 404)
        self.assertIsNone(self.logs()[-1]["rotation"])
        self.assertEqual(self.client.get(alias).status_code, 200)

    def test_default_direct_hit_blocks_without_invalidating_open_tabs(self):
        _, client_id, alias = self.open_page()
        before = len(self.calls)
        self.assertEqual(self.client.get("/rest/products/search").status_code, 404)
        self.assertEqual(len(self.calls), before)
        self.assertEqual(self.logs()[-1]["decision"], "block")
        self.assertIsNone(self.logs()[-1]["rotation"])
        self.assertEqual(self.client.get(alias).status_code, 200)
        _, same_client, current = self.open_page()
        self.assertEqual((same_client, current), (client_id, alias))

    def test_oversized_stream_and_off(self):
        body = b'"/rest/products/search"' * 10
        self.upstream = (200, [("content-type", "application/javascript")], body)
        with patch.object(main, "PATH_ALIAS", replace(self.cfg, max_rewrite_bytes=20)):
            response = self.client.get("/main.js")
        self.assertEqual(response.content, body)
        self.assertNotIn("set-cookie", response.headers)
        self.assertEqual(self.logs()[-1]["rewrite_skipped"], "too_large")
        with patch.object(main, "PATH_ALIAS", pa.PathAliasConfig()), patch.object(
                main, "PATH_ALIAS_TABLE", pa.PathAliasTable(pa.PathAliasConfig())):
            response = self.client.get("/rest/products/search")
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
