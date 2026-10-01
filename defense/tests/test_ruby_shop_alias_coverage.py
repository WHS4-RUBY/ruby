"""RUBY Shop route coverage, without making requests that change target state."""

import re
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import httpx
from starlette.testclient import TestClient

from defense.app import main, path_alias


ROUTES_FILE = Path(__file__).resolve().parents[1] / "config" / "ruby-shop-routes.json"
CLIENT = "a" * 26
OTHER_CLIENT = "b" * 26
NOW = 100.0

# Primary requests of the 26 RUBY Shop targets eligible under the 2026-09-17 policy.
# Query strings are intentionally separate from path-alias matching.
ELIGIBLE_REQUESTS = (
    ("object-authorization.customer-profile", "GET", "/api/customers/{customer_id}/profile"),
    ("function-authorization.user-directory", "GET", "/api/admin/users"),
    ("server-side-request-forgery.image-import", "POST", "/api/seller/image-import"),
    ("path-traversal.report-download", "GET", "/api/seller/reports/{report_path}"),
    ("mass-assignment.profile-role", "PATCH", "/api/me/profile"),
    ("sql-injection.product-search", "GET", "/api/products"),
    ("authentication-session.password-reset-swap", "POST", "/api/auth/password-reset/confirm"),
    ("authentication-session.unsigned-session-token", "GET", "/api/me"),
    ("security-misconfiguration.operations-status-secret", "GET", "/api/operations/status"),
    ("security-misconfiguration.trusted-forwarding-header", "GET", "/api/operations/metrics"),
    ("sensitive-data-exposure.support-error-diagnostic", "GET", "/api/support/tickets/{ticket_id}/error-diagnostic"),
    ("jenkins-derived.diagnostic-export-expansion", "POST", "/api/support/tickets/{ticket_id}/diagnostic-export"),
    ("business-workflow.refund-before-fulfillment", "POST", "/api/orders/{order_id}/refund-request"),
    ("race-condition.inventory-confirmation", "POST", "/api/orders"),
    ("multi-stage.search-leak-session-takeover", "GET", "/api/search"),
    ("multi-stage.image-import-service-credential", "POST", "/api/seller/integration/catalog-flag"),
    ("multi-stage.archive-upload-path-execution", "POST", "/api/seller/archive-hooks/activate"),
    ("multi-stage.cross-shop-refund-chain", "POST", "/api/orders/{order_id}/refund"),
    ("multi-stage.remembered-session-role-chain", "POST", "/api/admin/users/{user_id}/remembered-role-form"),
    ("geoserver-derived.seller-template-expression", "POST", "/api/seller/templates/preview"),
    ("cryptographic-failure.signed-download-forgery", "GET", "/api/me/documents/{document_id}/download"),
    ("resource-consumption.report-export-fanout", "POST", "/api/seller/reports/exports"),
    ("business-workflow.bulk-promotion-redemption", "POST", "/api/promotions/{promotion_code}/redemptions"),
    ("api-inventory.deprecated-operations-endpoint", "GET", "/api/v1/operations/export"),
    ("security-logging.audit-trail-erasure", "DELETE", "/api/support/audit-events/{event_id}"),
    ("software-data-integrity.unsigned-partner-webhook", "POST", "/api/integrations/partner/shipment-events"),
)


class _Body(httpx.AsyncByteStream):
    async def __aiter__(self):
        yield b'{"ok":true}'


class RubyShopCoverageTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        config = path_alias.PathAliasConfig.from_env({
            "PATH_ALIAS_MODE": "enforce",
            "PATH_ALIAS_ROUTES_FILE": str(ROUTES_FILE),
            "PATH_ALIAS_PREFIXES": "/api/",
            "PATH_ALIAS_APP_ID": "ruby-shop-coverage",
            "PATH_ALIAS_DB_PATH": str(Path(directory.name) / "aliases.sqlite3"),
        })
        self.routes = {route.path for route in config.routes}
        self.config = config
        self.table = path_alias.PathAliasTable(config)
        silence = patch.object(path_alias, "emit")
        silence.start()
        self.addCleanup(silence.stop)
        self.aliases = self.table.current_aliases(NOW, CLIENT)

    def check_route(self, route: str, method: str):
        real = re.sub(r"\{[^}]+\}", "sample", route)
        suffix = "/sample" * route.count("{")
        alias = self.aliases[route] + suffix
        result = self.table.resolve(alias, method, NOW, CLIENT)
        self.assertEqual((result.kind, result.upstream_path), ("alias", real))
        self.assertEqual(self.table.resolve(real, method, NOW, CLIENT).kind, "direct")
        foreign = self.table.resolve(alias, method, NOW, OTHER_CLIENT)
        self.assertEqual((foreign.kind, foreign.reason), ("reject", "foreign_alias"))

    def test_all_configured_routes_round_trip(self):
        self.assertEqual(len(self.routes), 63)
        for route in sorted(self.routes):
            with self.subTest(route=route):
                self.check_route(route, "GET")

    def test_all_main_experiment_primary_requests_are_covered(self):
        self.assertEqual(len(ELIGIBLE_REQUESTS), 26)
        for module, method, route in ELIGIBLE_REQUESTS:
            with self.subTest(module=module):
                self.assertIn(route, self.routes)
                self.check_route(route, method)

    def test_all_main_experiment_primary_requests_reach_mock_upstream(self):
        calls = []

        class FakeClient:
            def build_request(self, **kwargs):
                return kwargs

            async def send(self, request, stream=False):
                calls.append(request)
                return httpx.Response(200, headers={"content-type": "application/json"},
                                      stream=_Body())

        previous_client = getattr(main.app.state, "http_client", None)
        main.app.state.http_client = FakeClient()
        if previous_client is None:
            self.addCleanup(delattr, main.app.state, "http_client")
        else:
            self.addCleanup(setattr, main.app.state, "http_client", previous_client)
        with patch.object(main, "PATH_ALIAS", self.config), patch.object(
                main, "PATH_ALIAS_TABLE", self.table), patch.object(
                main.time, "time", return_value=NOW):
            client = TestClient(main.app)
            self.addCleanup(client.close)
            client.cookies.set(path_alias.COOKIE_NAME, CLIENT)
            for module, method, route in ELIGIBLE_REQUESTS:
                with self.subTest(module=module):
                    path = self.aliases[route] + "/sample" * route.count("{")
                    query = {"q": "sample"} if module in {
                        "sql-injection.product-search",
                        "multi-stage.search-leak-session-takeover",
                    } else {"details": "full"} if module == (
                        "security-misconfiguration.operations-status-secret"
                    ) else None
                    response = client.request(method, path, params=query,
                                              json={} if method in {"POST", "PATCH"} else None)
                    self.assertEqual(response.status_code, 200)
                    sent = calls[-1]
                    real = re.sub(r"\{[^}]+\}", "sample", route)
                    self.assertEqual(sent["method"], method)
                    self.assertEqual(sent["url"], main.BENCHMARK_TARGET_URL.rstrip("/") + real)
                    self.assertEqual(sent["params"], list((query or {}).items()))


if __name__ == "__main__":
    unittest.main()
