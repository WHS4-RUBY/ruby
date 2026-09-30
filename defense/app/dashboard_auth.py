"""Bounded password authentication for the Defense dashboard."""

from __future__ import annotations

import hmac
import secrets
import threading
import time
from collections import deque
from collections.abc import Callable


class InvalidCredentialsError(Exception):
    pass


class LoginRateLimitedError(Exception):
    def __init__(self, retry_after: int):
        super().__init__("too many login attempts")
        self.retry_after = retry_after


class DashboardAuthManager:
    def __init__(
        self,
        *,
        password: str,
        session_ttl_seconds: int = 12 * 60 * 60,
        max_sessions: int = 1000,
        max_attempts: int = 5,
        attempt_window_seconds: int = 300,
        clock: Callable[[], float] = time.time,
    ):
        self.password = password
        self.session_ttl_seconds = max(60, session_ttl_seconds)
        self.max_sessions = max(1, max_sessions)
        self.max_attempts = max(1, max_attempts)
        self.attempt_window_seconds = max(1, attempt_window_seconds)
        self.max_failure_clients = self.max_sessions * 2
        self._clock = clock
        self._sessions: dict[str, float] = {}
        self._failures: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return bool(self.password)

    def _cleanup(self, now: float) -> None:
        expired_tokens = [token for token, expires_at in self._sessions.items() if expires_at <= now]
        for token in expired_tokens:
            self._sessions.pop(token, None)

        cutoff = now - self.attempt_window_seconds
        for client_key, failures in list(self._failures.items()):
            while failures and failures[0] <= cutoff:
                failures.popleft()
            if not failures:
                self._failures.pop(client_key, None)

    def is_authenticated(self, token: str | None) -> bool:
        if not self.enabled:
            return True
        now = self._clock()
        with self._lock:
            self._cleanup(now)
            return bool(token and self._sessions.get(token, 0) > now)

    def login(self, password: str, client_key: str) -> str | None:
        if not self.enabled:
            return None

        now = self._clock()
        key = client_key or "unknown"
        with self._lock:
            self._cleanup(now)
            while key not in self._failures and len(self._failures) >= self.max_failure_clients:
                self._failures.pop(next(iter(self._failures)))
            failures = self._failures.setdefault(key, deque())
            if len(failures) >= self.max_attempts:
                retry_after = max(1, int(failures[0] + self.attempt_window_seconds - now))
                raise LoginRateLimitedError(retry_after)

            if not hmac.compare_digest(password, self.password):
                failures.append(now)
                raise InvalidCredentialsError

            self._failures.pop(key, None)
            while len(self._sessions) >= self.max_sessions:
                oldest = min(self._sessions, key=self._sessions.get)
                self._sessions.pop(oldest, None)

            token = secrets.token_urlsafe(32)
            self._sessions[token] = now + self.session_ttl_seconds
            return token

    def logout(self, token: str | None) -> None:
        if not token:
            return
        with self._lock:
            self._sessions.pop(token, None)

    def session_count(self) -> int:
        with self._lock:
            self._cleanup(self._clock())
            return len(self._sessions)
