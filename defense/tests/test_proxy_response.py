import unittest

import httpx
from starlette.requests import Request
from starlette.websockets import WebSocket

from defense.app import path_alias, token_gate
from defense.app.main import (
    _websocket_headers, build_upstream_headers, proxy_response, streaming_proxy_response,
)


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


class ReservedCookieNames(unittest.TestCase):
    """대상이 Defense 의 쿠키 이름을 쓰면 그 Set-Cookie 는 전달하지 않는다.

    별칭·토큰 게이트 쿠키는 보호 대상과 **같은 origin** 에 나간다. 이름이 겹치면
    브라우저가 대상의 값으로 덮어써서 별칭 귀속이 매 응답 새 미확인 클라이언트로
    떨어진다(`path-alias-operations.md` 6절). Detection 이 dlsid·dcid 에 하는 것과
    같은 보호이고, 이름을 일반적인 쪽으로 바꿀 때 필요해졌다.
    """

    def upstream(self, cookies):
        return httpx.Response(200, content=b"ok",
                              headers=[("Set-Cookie", value) for value in cookies])

    def test_the_target_cannot_overwrite_the_alias_or_token_gate_cookie(self):
        reserved = [f"{path_alias.COOKIE_NAME}=target-wins; Path=/",
                    f"{token_gate.COOKIE_NAME}=target-wins; Path=/"]
        upstream = self.upstream([*reserved, "app_session=keep; Path=/"])

        for response in (proxy_response(upstream),
                         streaming_proxy_response(upstream, ProxyResponseTests.request())):
            with self.subTest(kind=type(response).__name__):
                self.assertEqual(response.headers.getlist("set-cookie"),
                                 ["app_session=keep; Path=/"])

    def test_a_different_name_is_forwarded_even_when_it_shares_a_prefix(self):
        # 접두어 규칙이 아니라 정확한 이름만 막는다 — 대상의 평범한 쿠키를 삼키지 않는다.
        similar = [f"{path_alias.COOKIE_NAME}_extra=1; Path=/",
                   f"prefix_{token_gate.COOKIE_NAME}=1; Path=/"]
        response = proxy_response(self.upstream(similar))

        self.assertEqual(response.headers.getlist("set-cookie"), similar)


if __name__ == "__main__":
    unittest.main()
