import unittest

import httpx

from defense.app.main import proxy_response


class ProxyResponseTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
