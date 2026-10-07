import unittest

import httpx
from starlette.requests import Request
from starlette.websockets import WebSocket

from defense.app.main import _websocket_headers, build_upstream_headers, proxy_response, streaming_proxy_response


class ProxyResponseTests(unittest.TestCase):
    @staticmethod
    def request(headers=None):
        raw_headers = [
            (key.lower().encode("latin-1"), value.encode("latin-1"))
            for key, value in (headers or {}).items()
        ]
        return Request(
            {
                "type": "http",
                "method": "GET",
                "scheme": "http",
                "path": "/",
                "raw_path": b"/",
                "query_string": b"",
                "headers": raw_headers,
                "client": ("172.18.0.2", 12345),
                "server": ("defense", 8080),
            }
        )

    def test_hop_metadata_is_rebuilt_and_repeated_headers_are_preserved(self):
        upstream = httpx.Response(
            200,
            content=b"ok",
            headers=[
                ("Date", "Sun, 13 Sep 2026 00:00:00 GMT"),
                ("Server", "upstream"),
                ("Content-Length", "999"),
                ("Content-Type", "text/plain"),
                ("Set-Cookie", "first=1; Path=/"),
                ("Set-Cookie", "second=2; Path=/"),
            ],
        )

        response = proxy_response(upstream)

        self.assertNotIn("date", response.headers)
        self.assertNotIn("server", response.headers)
        self.assertEqual(response.headers["content-length"], "2")
        self.assertEqual(response.headers["content-type"], "text/plain")
        self.assertEqual(
            response.headers.getlist("set-cookie"),
            ["first=1; Path=/", "second=2; Path=/"],
        )

    def test_forwarded_headers_are_rebuilt_for_the_target(self):
        request = self.request(
            {
                "host": "ruby.example.com",
                "x-forwarded-for": "203.0.113.7",
                "x-forwarded-proto": "https",
                "x-defense-plan": "untrusted",
                "x-client-id": "policy-client",
            }
        )

        headers = build_upstream_headers(request, {
            "X-Defense-Applied": "delay", "X-Client-Id": "strategy-override",
            "X-Forwarded-For": "198.51.100.9",
        })

        self.assertNotIn("host", headers)
        self.assertNotIn("x-defense-plan", headers)
        self.assertNotIn("x-client-id", {key.lower() for key in headers})
        self.assertNotIn("x-forwarded-for", {key.lower() for key in headers})
        self.assertEqual(headers["x-forwarded-host"], "ruby.example.com")
        self.assertEqual(headers["x-forwarded-proto"], "https")
        self.assertEqual(headers["X-Defense-Applied"], "delay")

    def test_websocket_policy_key_stays_internal(self):
        websocket = WebSocket(
            {
                "type": "websocket",
                "scheme": "ws",
                "path": "/ws",
                "query_string": b"",
                "headers": [
                    (b"host", b"ruby.example.com"),
                    (b"x-client-id", b"policy-client"),
                    (b"x-defense-plan", b"[]"),
                    (b"x-forwarded-for", b"203.0.113.7"),
                ],
                "client": ("172.18.0.2", 12345),
                "server": ("defense", 8080),
            },
            receive=lambda: None,
            send=lambda message: None,
        )

        headers = _websocket_headers(websocket, {
            "X-Defense-Applied": "delay", "X-Client-Id": "strategy-override",
            "X-Forwarded-For": "198.51.100.9",
        })

        self.assertNotIn("x-client-id", {key.lower() for key in headers})
        self.assertNotIn("x-defense-plan", headers)
        self.assertNotIn("x-forwarded-for", {key.lower() for key in headers})
        self.assertEqual(headers["x-forwarded-host"], "ruby.example.com")
        self.assertEqual(headers["X-Defense-Applied"], "delay")

    def test_streaming_response_preserves_encoding_and_rewrites_proxy_metadata(self):
        request = self.request(
            {
                "host": "ruby.example.com",
                "x-forwarded-proto": "https",
                "x-forwarded-host": "ruby.example.com",
            }
        )
        upstream = httpx.Response(
            302,
            headers=[
                ("Location", "http://localhost:9000/login"),
                ("Content-Encoding", "gzip"),
                ("Set-Cookie", "sid=1; Domain=localhost; Path=/"),
            ],
            request=httpx.Request("GET", "http://localhost:9000/"),
        )

        response = streaming_proxy_response(upstream, request)

        self.assertEqual(response.headers["location"], "https://ruby.example.com/login")
        self.assertEqual(response.headers["content-encoding"], "gzip")
        self.assertEqual(response.headers["set-cookie"], "sid=1; Path=/")


if __name__ == "__main__":
    unittest.main()
