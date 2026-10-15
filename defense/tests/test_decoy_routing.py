import ast
import importlib.util
import json
from pathlib import Path
import re
import unittest
import uuid
from unittest.mock import patch

import httpx

from defense.app.decoy_routing import (
    MAZE_DEFAULT_PATTERN, applied_decoy_strategies, decoy_action, is_maze_decoy_request,
    parse_decoy_upstreams, parse_maze_excluded_roots, parse_maze_extra_roots,
)
from defense.app.main import app
from defense.app.monitoring import event_store
from defense.app.target_selection import TargetSelector


CHEAT_DIR = Path(__file__).resolve().parents[1] / "CHeat-defense-proxy" / "defense_proxy_v2"
APACHE_EXTRA_ROOTS = ("/.htpasswd", "/actuator", "/server-status", "/server-info", "/phpinfo")


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

    def test_all_generic_get_head_maze_paths_bypass_an_overlay(self):
        for root in ("/internal", "/backup", "/backups", "/admin", "/config", "/configs",
                     "/debug", "/private", "/secret", "/credentials", "/dump", "/db",
                     "/database", "/management", "/.git", "/.env"):
            self.assertTrue(is_maze_decoy_request("GET", root))
            self.assertTrue(is_maze_decoy_request("HEAD", root + "/ops/runbook"))
        for file_path in ("/archive/backup.sql", "/settings.yml", "/var/app.log",
                          "/keys/secret.pem", "/config.json.bak", "/api/v2/internal/ops",
                          "/.well-known/security"):
            self.assertTrue(is_maze_decoy_request("GET", file_path), file_path)
        for method, path in (
            ("POST", "/internal/ops/runbook"), ("GET", "/admin"),
            ("GET", "/internalx"),
            ("GET", "/backup-other"), ("GET", "/"),
        ):
            self.assertFalse(is_maze_decoy_request(method, path, excluded_roots=("/admin",)))
        self.assertTrue(is_maze_decoy_request("GET", "/admin.json",
                                              excluded_roots=("/admin",)))
        self.assertFalse(is_maze_decoy_request("GET", "/admin/backup",
                                               excluded_roots=("/admin",)))
        self.assertTrue(is_maze_decoy_request("GET", "/server-status",
                                              extra_roots=APACHE_EXTRA_ROOTS))
        self.assertTrue(is_maze_decoy_request("HEAD", "/.htpasswd.old",
                                              extra_roots=APACHE_EXTRA_ROOTS))
        self.assertFalse(is_maze_decoy_request("POST", "/server-status",
                                               extra_roots=APACHE_EXTRA_ROOTS))
        self.assertFalse(is_maze_decoy_request("GET", "/server-status-more",
                                               extra_roots=APACHE_EXTRA_ROOTS))

    def test_extra_maze_roots_are_explicit_per_target(self):
        self.assertEqual(parse_maze_extra_roots(
            "juice-shop=/.htpasswd|/server-status,ruby-shop=/staging|/legacy",
            {"juice-shop", "ruby-shop"}
        ), {"juice-shop": ("/.htpasswd", "/server-status"),
            "ruby-shop": ("/staging", "/legacy")})
        self.assertEqual(parse_maze_excluded_roots(
            "ruby-shop=/admin", {"juice-shop", "ruby-shop"}
        ), {"ruby-shop": ("/admin",)})
        for invalid in ("juice-shop=admin", "juice-shop=/", "=/admin", "Juice_Shop=/admin",
                        "juice-shop=/admin/,juice-shop=/other", "juice-shop=/admin|/admin",
                        "juice-shop=/admin?x=1", "juice-shop=/../admin"):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                parse_maze_extra_roots(invalid, {"juice-shop", "ruby-shop"})
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                parse_maze_excluded_roots(invalid, {"juice-shop", "ruby-shop"})

    def test_the_fixed_map_may_name_targets_this_deployment_does_not_enable(self):
        # 두 Compose 는 대상별 고정 맵을 주지만 실제로 활성인 대상은 TARGET_CHOICES 가
        # 정한다. 로컬 Compose 는 legacy·alternate 의 맵을 주면서 기본 TARGET_CHOICES 는
        # 비어 있어 legacy 만 활성이다 — 비활성 항목 때문에 Defense 가 기동에 실패하면
        # 기본값만으로 띄우는 로컬 실행이 막힌다. parse_decoy_upstreams 와 같은 규칙이다.
        apache = "/.htpasswd|/actuator|/server-status|/server-info|/phpinfo"
        self.assertEqual(
            parse_maze_extra_roots(f"legacy={apache},alternate={apache}", {"legacy"}),
            {"legacy": tuple(apache.split("|"))},
        )
        self.assertEqual(
            parse_maze_excluded_roots("ruby-shop=/admin", {"juice-shop"}), {})
        # 비활성 대상이어도 항목 자체가 잘못됐으면 기동 실패로 남는다.
        with self.assertRaises(RuntimeError):
            parse_maze_extra_roots("alternate=admin", {"legacy"})

    def test_generic_pattern_stays_in_sync_with_cheat(self):
        syntax = ast.parse((CHEAT_DIR / "transforms.py").read_text(encoding="utf-8"))
        sidecar_pattern = next(
            ast.literal_eval(node.value) for node in syntax.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "MAZE_DEFAULT_PATTERN"
                    for target in node.targets)
        )
        self.assertEqual(MAZE_DEFAULT_PATTERN, sidecar_pattern)

    def test_target_specific_preset_patterns_match_our_sidecar_routing(self):
        spec = importlib.util.spec_from_file_location("cheat_profiles_for_maze_routing",
                                                    CHEAT_DIR / "profiles.py")
        profile_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(profile_module)
        cases = {
            "apache-php": (APACHE_EXTRA_ROOTS, (),
                           ("/.htpasswd", "/actuator/health", "/server-status",
                            "/server-info.json", "/phpinfo.php")),
            "nginx-fastapi": ((), ("/admin",),
                              ("/internal/ops/runbook", "/db/backup.sql", "/.ssh/id_rsa")),
        }
        for preset, (extra_roots, excluded_roots, paths) in cases.items():
            maze_config = profile_module.PRESETS[preset]["maze"]
            extra_pattern = maze_config.get("extra_pattern", "")
            sidecar_pattern = MAZE_DEFAULT_PATTERN
            if extra_pattern:
                sidecar_pattern += r"|^/(?:" + extra_pattern + r")($|/|\?|\.)"
            compiled = re.compile(sidecar_pattern, re.I)
            for path in (*paths, "/products", "/api/orders", "/server-status"):
                excluded = any(path.lower() == root or path.lower().startswith(root + "/")
                               for root in excluded_roots)
                expected = bool(compiled.match(path) and not excluded)
                actual = is_maze_decoy_request("GET", path, extra_roots=extra_roots,
                                               excluded_roots=excluded_roots)
                with self.subTest(preset=preset, path=path):
                    self.assertEqual(actual, expected)


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
                    "X-Defense-Decoy-Only": "1",
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
        self.assertNotIn("x-defense-decoy-only", captured[0].headers)
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
