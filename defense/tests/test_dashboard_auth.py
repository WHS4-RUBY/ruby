import unittest
import os
from unittest.mock import patch

from fastapi.testclient import TestClient

from defense.app.dashboard_auth import (
    DashboardAuthManager,
    InvalidCredentialsError,
    LoginRateLimitedError,
)
from defense.app.main import app
from defense.app.monitoring import event_store


class DashboardAuthManagerTests(unittest.TestCase):
    def test_rate_limit_and_expired_session_cleanup(self):
        now = [1000.0]
        manager = DashboardAuthManager(
            password="secret",
            session_ttl_seconds=60,
            max_sessions=2,
            max_attempts=2,
            attempt_window_seconds=30,
            clock=lambda: now[0],
        )

        with self.assertRaises(InvalidCredentialsError):
            manager.login("wrong", "client-a")
        with self.assertRaises(InvalidCredentialsError):
            manager.login("wrong", "client-a")
        with self.assertRaises(LoginRateLimitedError):
            manager.login("secret", "client-a")

        token = manager.login("secret", "client-b")
        self.assertTrue(manager.is_authenticated(token))
        now[0] += 61
        self.assertFalse(manager.is_authenticated(token))
        self.assertEqual(manager.session_count(), 0)

    def test_session_count_is_bounded(self):
        manager = DashboardAuthManager(password="secret", max_sessions=2)
        tokens = [manager.login("secret", f"client-{index}") for index in range(3)]

        self.assertEqual(manager.session_count(), 2)
        self.assertFalse(manager.is_authenticated(tokens[0]))
        self.assertTrue(manager.is_authenticated(tokens[-1]))

    def test_failed_client_tracking_is_bounded(self):
        manager = DashboardAuthManager(password="secret", max_sessions=1, max_attempts=5)
        for index in range(4):
            with self.assertRaises(InvalidCredentialsError):
                manager.login("wrong", f"client-{index}")

        self.assertLessEqual(len(manager._failures), 2)


class DashboardApiTests(unittest.TestCase):
    def test_dashboard_can_be_hidden_for_isolated_attack_experiment(self):
        with patch.dict(os.environ, {"DEFENSE_DASHBOARD_ENABLED": "false"}):
            with TestClient(app) as client:
                for path in ("/__defense", "/__defense/dashboard",
                             "/__defense/api/auth/status", "/__defense/api/snapshot",
                             "/__defense/api/config", "/__defense/not-a-route"):
                    self.assertEqual(client.get(path).status_code, 404, path)
                self.assertEqual(client.post("/__defense/api/login", json={"password": ""}).status_code, 404)
                self.assertEqual(client.get("/healthz").status_code, 200)

    def test_login_snapshot_and_logout(self):
        manager = DashboardAuthManager(password="secret", max_attempts=3)
        with patch("defense.app.dashboard.auth_manager", manager):
            with TestClient(app) as client:
                self.assertEqual(client.get("/__defense/api/snapshot").status_code, 401)
                self.assertEqual(
                    client.post("/__defense/api/login", json={"password": "wrong"}).status_code,
                    401,
                )

                login = client.post("/__defense/api/login", json={"password": "secret"})
                self.assertEqual(login.status_code, 204)
                self.assertIn("HttpOnly", login.headers["set-cookie"])
                self.assertIn("SameSite=strict", login.headers["set-cookie"])

                snapshot = client.get("/__defense/api/snapshot")
                self.assertEqual(snapshot.status_code, 200)
                self.assertEqual(snapshot.headers["cache-control"], "no-store")
                self.assertIn("summary", snapshot.json())
                event_count = event_store.summary()["totalRequests"]
                self.assertEqual(client.get("/__defense/not-a-route").status_code, 404)
                self.assertEqual(event_store.summary()["totalRequests"], event_count)

                self.assertEqual(client.post("/__defense/api/logout").status_code, 204)
                self.assertEqual(client.get("/__defense/api/snapshot").status_code, 401)


if __name__ == "__main__":
    unittest.main()
