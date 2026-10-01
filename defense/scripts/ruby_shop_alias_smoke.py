"""Read-only path-alias smoke test against an existing local RUBY Shop."""

import asyncio
import json
import os
from pathlib import Path
import re
import tempfile
import time

import httpx


ROOT = Path(__file__).resolve().parents[2]
TARGET = os.environ.get("RUBY_SHOP_SMOKE_TARGET")


async def check() -> None:
    if not TARGET:
        raise SystemExit("Set RUBY_SHOP_SMOKE_TARGET to an isolated local RUBY Shop URL")
    with tempfile.TemporaryDirectory(prefix="ruby-shop-alias-") as work:
        os.environ.update({
            "BENCHMARK_TARGET_URL": TARGET,
            "PATH_ALIAS_MODE": "enforce",
            "PATH_ALIAS_ROUTES_FILE": str(ROOT / "defense/config/ruby-shop-routes.json"),
            "PATH_ALIAS_DB_PATH": str(Path(work) / "aliases.sqlite3"),
            "PATH_ALIAS_PREFIXES": "/api/",
            "PATH_ALIAS_APP_ID": "ruby-shop-smoke",
            "TOKEN_GATE_MODE": "off",
            "DEFENSE_PUBLIC_TARGET_ONLY": "true",
        })

        from defense.app import main

        transport = httpx.ASGITransport(app=main.app)
        async with main.app.router.lifespan_context(main.app):
            async with httpx.AsyncClient(transport=transport, base_url="http://alias.test") as client:
                home = await client.get("/")
                assert home.status_code == 200, ("home", home.status_code)
                dashboard = await client.get("/__defense/api/snapshot")
                assert dashboard.status_code == 404, ("management API", dashboard.status_code)
                match = re.search(r'src="([^"]+\.js)"', home.text)
                assert match, "RUBY Shop did not publish a JavaScript asset"
                asset_path = match.group(1)

                asset = await client.get(asset_path)
                assert asset.status_code == 200, ("asset", asset.status_code)
                client_id = client.cookies.get("ruby_alias_client")
                assert client_id, "rewritten asset did not issue an alias client cookie"
                product_alias = main.PATH_ALIAS_TABLE.current_aliases(time.time(), client_id)["/api/products"]
                assert product_alias in asset.text, "product alias was not exposed in the app asset"

                products = await client.get(product_alias)
                assert products.status_code == 200, ("product alias", products.status_code)
                assert isinstance(products.json(), list), "product alias did not reach the original list API"
                first_product = products.json()[0]
                detail_alias = main.PATH_ALIAS_TABLE.current_aliases(time.time(), client_id)[
                    "/api/products/{product_id}"
                ] + "/" + first_product["id"]
                detail = await client.get(detail_alias)
                assert detail.status_code == 200, ("product detail alias", detail.status_code)
                assert detail.json()["id"] == first_product["id"]
                search_alias = main.PATH_ALIAS_TABLE.current_aliases(time.time(), client_id)["/api/search"]
                search = await client.get(search_alias, params={"q": "desk"})
                assert search.status_code == 200, ("search alias", search.status_code)
                assert isinstance(search.json(), list)

                read_only_routes = (
                    "/api/admin/users",
                    "/api/customers/{customer_id}/profile",
                    "/api/me",
                    "/api/operations/metrics",
                    "/api/operations/status",
                    "/api/support/tickets/{ticket_id}/error-diagnostic",
                    "/api/me/documents/{document_id}/download",
                )
                read_only_statuses = {}
                async with httpx.AsyncClient(base_url=TARGET) as origin:
                    for route in read_only_routes:
                        real_path = re.sub(r"\{[^}]+\}", "sample", route)
                        alias_path = (main.PATH_ALIAS_TABLE.current_aliases(time.time(), client_id)[route]
                                      + "/sample" * route.count("{"))
                        original = await origin.get(real_path)
                        proxied = await client.get(alias_path)
                        assert proxied.status_code == original.status_code, (
                            route, original.status_code, proxied.status_code
                        )
                        read_only_statuses[route] = proxied.status_code

                exposed_real_paths = sorted(set(re.findall(r"/api/[A-Za-z0-9_/-]+", asset.text)))

                async with httpx.AsyncClient(transport=transport, base_url="http://alias.test") as stranger:
                    foreign = await stranger.get(product_alias)
                    assert foreign.status_code == 404, ("foreign alias", foreign.status_code)

                direct = await client.get("/api/products")
                assert direct.status_code == 404, ("direct product path", direct.status_code)
                expired = await client.get(product_alias)
                assert expired.status_code == 404, ("alias after rotation", expired.status_code)

                refreshed = await client.get(asset_path)
                assert refreshed.status_code == 200, ("refreshed asset", refreshed.status_code)
                new_alias = main.PATH_ALIAS_TABLE.current_aliases(time.time(), client_id)["/api/products"]
                assert new_alias != product_alias, "direct access did not rotate the alias"
                assert new_alias in refreshed.text, "refreshed asset did not expose the new alias"
                new_products = await client.get(new_alias)
                assert new_products.status_code == 200, ("new alias", new_products.status_code)

                print(json.dumps({
                    "target": TARGET,
                    "configured_routes": len(main.PATH_ALIAS.routes),
                    "home": home.status_code,
                    "asset": asset.status_code,
                    "product_alias": products.status_code,
                    "product_detail_alias": detail.status_code,
                    "search_alias": search.status_code,
                    "other_read_only_routes": read_only_statuses,
                    "remaining_real_api_paths_in_asset": exposed_real_paths,
                    "foreign_alias": foreign.status_code,
                    "direct_path": direct.status_code,
                    "old_alias_after_rotation": expired.status_code,
                    "new_alias": new_products.status_code,
                }, ensure_ascii=False))


if __name__ == "__main__":
    asyncio.run(check())
