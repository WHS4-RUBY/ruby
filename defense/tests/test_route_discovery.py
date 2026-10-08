import json
import io
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch

from defense.scripts.discover_path_alias_routes import fetch_assets, inventory


class RouteDiscoveryTests(unittest.TestCase):
    def test_custom_prefixes_find_other_web_api_conventions(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "main.js"
            bundle.write_text('fetch("/graphql"); fetch("/v1/items/42"); fetch("/api/ignored")')
            report = inventory([bundle], prefixes=("/graphql", "/v1/"))
        self.assertEqual([item["path"] for item in report["candidates"]],
                         ["/graphql", "/v1/items/42"])

    def test_runtime_capture_adds_observed_methods_without_query_values(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "shop.runtime.json"
            capture.write_text(json.dumps({
                "format": "ruby-runtime-requests-v1", "origin": "http://shop.example",
                "requests": [
                    {"path": "/rest/basket/7", "method": "POST", "query_keys": ["token"]},
                    {"path": "/api/Products", "method": "GET", "query_keys": []},
                ], "steps": [{"passed": True}], "page_errors": [],
            }), encoding="utf-8")
            report = inventory([capture], origin="http://shop.example")
            partial = json.loads(capture.read_text(encoding="utf-8"))
            partial["steps"][0]["passed"] = False
            capture.write_text(json.dumps(partial), encoding="utf-8")
            partial_report = inventory([capture], origin="http://shop.example")
        by_path = {item["path"]: item for item in report["candidates"]}
        self.assertEqual(by_path["/rest/basket/7"]["observed_methods"], ["POST"])
        self.assertEqual(by_path["/api/Products"]["observed_methods"], ["GET"])
        self.assertNotIn("token", json.dumps(report))
        self.assertEqual(report["incomplete_runtime_captures"], [])
        self.assertEqual(partial_report["incomplete_runtime_captures"], [capture.name])

    def test_fetches_same_origin_scripts_and_lazy_chunks(self):
        payloads = {
            "http://shop.example/": ("text/html", b'<script src="/main.js"></script>'
                                     b'<script src="https://other.example/x.js"></script>'),
            "http://shop.example/main.js": ("text/javascript",
                                            b'import("./chunk.js"); fetch("/rest/user/login")'),
            "http://shop.example/chunk.js": ("text/javascript", b'fetch("/api/Products")'),
        }
        called = []

        class Response(io.BytesIO):
            def __init__(self, url, media_type, data):
                super().__init__(data)
                self.url = url
                self.headers = Message()
                self.headers["Content-Type"] = media_type

            def geturl(self):
                return self.url

        def open_asset(request, timeout):
            called.append(request.full_url)
            media_type, data = payloads[request.full_url]
            return Response(request.full_url, media_type, data)

        with tempfile.TemporaryDirectory() as directory, patch(
                "defense.scripts.discover_path_alias_routes.urlopen", side_effect=open_asset):
            files = fetch_assets("http://shop.example", Path(directory))
            self.assertEqual(len(files), 3)
            self.assertTrue(all(file.exists() for file in files))
        self.assertEqual(called, list(payloads))

    def test_assets_and_har_report_query_paths_without_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            routes = root / "routes.json"
            routes.write_text(json.dumps({"routes": ["/rest/user/login",
                                                      "/rest/image-captcha/{id}"]}))
            bundle = root / "main.js"
            bundle.write_text('fetch("/rest/user/login"); const image="/rest/image-captcha/"+id;'
                              'const next="?next=%2Frest%2Fuser%2Flogin";')
            har = root / "browser.har"
            har.write_text(json.dumps({"log": {"entries": [
                {"request": {"url": "http://shop.example/rest/user/login", "method": "POST"}},
                {"request": {"url": "http://other.example/rest/foreign", "method": "GET"}},
                {"request": {"url":
                 "http://shop.example/?next=%2Frest%2Fuser%2Flogin&token=secret"}}]}}))
            report = inventory([bundle, har], routes, "http://shop.example")
            fresh_install = inventory([bundle], None)

        paths = {item["path"]: item for item in report["candidates"]}
        self.assertEqual(paths["/rest/user/login"]["covered_by"], ["/rest/user/login"])
        self.assertNotIn("/rest/foreign", paths)
        self.assertEqual(paths["/rest/user/login"]["observed_methods"], ["POST"])
        self.assertEqual(paths["/rest/image-captcha/"]["dynamic_prefix_of"],
                         ["/rest/image-captcha/{id}"])
        self.assertEqual(report["query_path_candidates"][0]["key"], "next")
        self.assertEqual(report["query_path_candidates"][0]["path"], "/rest/user/login")
        self.assertNotIn("secret", json.dumps(report))
        self.assertTrue(all(not item["covered_by"] for item in fresh_install["candidates"]))


if __name__ == "__main__":
    unittest.main()
