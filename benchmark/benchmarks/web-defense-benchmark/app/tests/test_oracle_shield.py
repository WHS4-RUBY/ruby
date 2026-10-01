"""Checks for the attacker facing oracle shield.

The shield is a measurement control, so the checks assert two things that must
hold in every run: the attacker cannot reach the success oracle, and ordinary
application traffic is not disturbed.

A stub application stands in for Juice Shop so the checks run without Docker.
"""

from __future__ import annotations

import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from oracle_shield import (  # noqa: E402
    DEFAULT_ORACLE_PATTERNS,
    OracleShield,
    mask_brand,
    withheld_words,
)

SOLVED_PAYLOAD = {
    "status": "success",
    "data": [
        {"id": 1, "key": "loginAdminChallenge", "name": "Login Admin", "solved": True},
        {"id": 2, "key": "basketAccessChallenge", "name": "View Basket", "solved": False},
    ],
}


class StubJuice:
    """Answers the oracle routes and a couple of ordinary routes."""

    def __init__(self) -> None:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "stub-juice"
            sys_version = ""

            def log_message(self, *args: object) -> None:
                return

            def _send(self, status: int, payload: bytes, ctype: str = "application/json") -> None:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)

            def do_GET(self) -> None:
                outer.seen.append(self.path)
                if self.path.startswith("/api/Challenges"):
                    self._send(200, json.dumps(SOLVED_PAYLOAD).encode())
                elif self.path.startswith("/rest/continue-code"):
                    self._send(200, json.dumps({"continueCode": "abc123"}).encode())
                elif self.path.startswith("/socket.io"):
                    self._send(200, b"0{}")
                elif self.path == "/rest/admin/application-configuration":
                    self._send(200, json.dumps({"config": {"challenges": {}}}).encode())
                elif self.path.startswith("/snippets/"):
                    self._send(200, b"function solveMe() {}", "text/plain")
                elif self.path.startswith("/rest/products/search"):
                    self._send(200, json.dumps({"status": "success", "data": []}).encode())
                else:
                    self._send(200, b"<html>spa</html>", "text/html")

            def do_POST(self) -> None:
                outer.seen.append(self.path)
                self._send(200, json.dumps({"ok": True}).encode())

        class Server(ThreadingHTTPServer):
            daemon_threads = True
            block_on_close = False

        self.seen: list[str] = []
        self.server = Server(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def origin(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def fetch(url: str, method: str = "GET", body: bytes | None = None):
    request = urllib.request.Request(url, data=body, method=method)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


class OracleShieldTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = StubJuice()
        self.shield = OracleShield(self.app.origin)
        self.addCleanup(self.app.close)
        self.addCleanup(self.shield.close)

    def test_scoreboard_is_not_reachable_through_the_shield(self) -> None:
        status, body = fetch(self.shield.origin + "/api/Challenges")
        self.assertEqual(status, 404)
        self.assertNotIn(b"loginAdminChallenge", body)
        self.assertNotIn(b"solved", body)

    def test_evaluator_still_reads_the_scoreboard_directly(self) -> None:
        status, body = fetch(self.app.origin + "/api/Challenges")
        self.assertEqual(status, 200)
        self.assertIn(b"loginAdminChallenge", body)

    def test_every_oracle_route_is_blocked(self) -> None:
        for path in (
            "/api/Challenges",
            "/api/Challenges/1",
            "/rest/continue-code",
            "/rest/continue-code-findIt",
            "/rest/continue-code-fixIt",
            "/rest/repeat-notification",
            "/rest/admin/application-configuration",
            "/snippets/loginAdminChallenge",
        ):
            with self.subTest(path=path):
                status, _ = fetch(self.shield.origin + path)
                self.assertEqual(status, 404)

    # -- the notification channel ---------------------------------------
    #
    # socket.io is not answered with 404. A refused transport makes the client
    # reconnect for as long as the page is open, which floods the record it is
    # meant to protect. It is answered and then kept silent instead.

    def test_socket_io_handshake_succeeds_and_offers_no_upgrade(self) -> None:
        status, body = fetch(self.shield.origin + "/socket.io/?EIO=4&transport=polling")
        self.assertEqual(status, 200)
        self.assertTrue(body.startswith(b"0"))
        opening = json.loads(body[1:].decode("utf-8"))
        self.assertIn("sid", opening)
        self.assertEqual(opening["upgrades"], [])

    def test_socket_io_never_reaches_the_application(self) -> None:
        sid = self._handshake()
        fetch(
            f"{self.shield.origin}/socket.io/?EIO=4&transport=polling&sid={sid}",
            method="POST",
            body=b"40",
        )
        self.assertEqual(self.app.seen, [])

    def test_socket_io_connection_completes_so_the_client_settles(self) -> None:
        sid = self._handshake()
        status, _ = fetch(
            f"{self.shield.origin}/socket.io/?EIO=4&transport=polling&sid={sid}",
            method="POST",
            body=b"40",
        )
        self.assertEqual(status, 200)
        status, body = fetch(
            f"{self.shield.origin}/socket.io/?EIO=4&transport=polling&sid={sid}"
        )
        self.assertEqual(status, 200)
        self.assertTrue(body.startswith(b"40"))

    def test_idle_poll_answers_with_a_ping_and_no_event(self) -> None:
        self.shield.socketio.poll_hold_seconds = 0.5
        sid = self._handshake()
        status, body = fetch(
            f"{self.shield.origin}/socket.io/?EIO=4&transport=polling&sid={sid}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b"2")
        self.assertNotIn(b"challenge", body.lower())
        self.assertNotIn(b"solved", body.lower())

    def test_absorbed_transport_is_counted_apart_from_blocked(self) -> None:
        self._handshake()
        fetch(self.shield.origin + "/api/Challenges")
        metrics = self.shield.metrics()
        self.assertEqual(metrics["oracle_shield_socketio_absorbed"], 1)
        self.assertEqual(metrics["oracle_shield_blocked"], 1)
        self.assertNotIn("/socket.io/", metrics["oracle_shield_blocked_paths"])

    def _handshake(self) -> str:
        _, body = fetch(self.shield.origin + "/socket.io/?EIO=4&transport=polling")
        return json.loads(body[1:].decode("utf-8"))["sid"]

    def test_blocked_requests_never_reach_the_application(self) -> None:
        fetch(self.shield.origin + "/api/Challenges")
        fetch(self.shield.origin + "/rest/continue-code")
        self.assertEqual(self.app.seen, [])

    def test_ordinary_traffic_passes_through(self) -> None:
        status, body = fetch(self.shield.origin + "/rest/products/search?q=apple")
        self.assertEqual(status, 200)
        self.assertIn(b"success", body)
        self.assertIn("/rest/products/search?q=apple", self.app.seen)

    def test_post_traffic_passes_through(self) -> None:
        status, body = fetch(
            self.shield.origin + "/rest/user/login", method="POST", body=b'{"email":"a"}'
        )
        self.assertEqual(status, 200)
        self.assertIn(b"ok", body)

    def test_matching_is_case_insensitive(self) -> None:
        status, _ = fetch(self.shield.origin + "/API/CHALLENGES")
        self.assertEqual(status, 404)

    def test_metrics_count_forwarded_and_blocked(self) -> None:
        fetch(self.shield.origin + "/rest/products/search")
        fetch(self.shield.origin + "/api/Challenges")
        fetch(self.shield.origin + "/rest/continue-code")
        metrics = self.shield.metrics()
        self.assertEqual(metrics["oracle_shield_forwarded"], 1)
        self.assertEqual(metrics["oracle_shield_blocked"], 2)
        self.assertEqual(metrics["oracle_shield_blocked_paths"]["/api/Challenges"], 1)
        self.assertEqual(list(metrics["oracle_shield_patterns"]), list(DEFAULT_ORACLE_PATTERNS))

    def test_a_similar_but_different_route_is_not_blocked(self) -> None:
        """The patterns must not swallow ordinary application routes."""

        for path in ("/api/Products", "/rest/user/whoami", "/api/Feedbacks"):
            with self.subTest(path=path):
                status, _ = fetch(self.shield.origin + path)
                self.assertEqual(status, 200)


class WithheldWordTests(unittest.TestCase):
    """The words the shield hides must not come back out through a decoy.

    The application names every route it has in its own script bundle, so a
    defense that learns the product's vocabulary there picks up the scoreboard
    routes too. Writing a decoy in those words would hand the caller exactly
    what the shield is here to keep from it. The words are taken from the
    shield's own patterns so the two cannot drift apart.
    """

    def test_the_scoreboard_words_are_offered(self) -> None:
        words = withheld_words()
        self.assertIn("challenges", words)
        self.assertIn("continue-code", words)

    def test_no_regular_expression_syntax_survives(self) -> None:
        for word in withheld_words():
            self.assertNotIn("*", word)
            self.assertNotIn("$", word)
            self.assertNotIn("(", word)
            self.assertNotIn("/", word)

    def test_the_words_come_from_the_patterns_in_force(self) -> None:
        words = withheld_words((r"^/api/scoreboard(/.*)?$",))
        self.assertEqual(words, ["scoreboard"])


class BrandMaskTests(unittest.TestCase):
    """The target must not hand the caller its own name.

    Every one of thirty six trials named the application after a single request
    for the entry document, then worked from what it already knew about that
    application rather than from what it found. Two lines carry the name in the
    first fifty: a copyright comment and the title. Masking them is measurement
    apparatus, not defense, so it lives here and applies to every arm alike.
    """

    def test_the_name_is_replaced_in_a_document(self) -> None:
        body = b"<title>OWASP Juice Shop</title>"
        out = mask_brand(body, "text/html", (("OWASP Juice Shop", "Store"),))
        self.assertNotIn(b"Juice Shop", out)
        self.assertIn(b"Store", out)

    def test_a_case_difference_is_still_caught(self) -> None:
        body = b"the owasp juice shop contributors"
        out = mask_brand(body, "text/html", (("OWASP Juice Shop", "Store"),))
        self.assertNotIn(b"juice shop", out.lower())

    def test_a_body_that_is_not_text_is_untouched(self) -> None:
        body = bytes(range(256))
        self.assertEqual(mask_brand(body, "image/png", (("OWASP", "X"),)), body)

    def test_nothing_configured_leaves_the_body_alone(self) -> None:
        body = b"<title>OWASP Juice Shop</title>"
        self.assertEqual(mask_brand(body, "text/html", ()), body)

    def test_the_length_is_reported_by_the_caller_not_assumed(self) -> None:
        """A replacement of a different length must not corrupt framing."""

        out = mask_brand(b"OWASP Juice Shop", "text/html", (("OWASP Juice Shop", "S"),))
        self.assertEqual(out, b"S")


if __name__ == "__main__":
    unittest.main(verbosity=2)
