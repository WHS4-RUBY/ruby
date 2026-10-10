"""Private, signed routing contract for the account response overlay.

The overlay never accepts an unsigned request. Routing state is durable so an
isolated actor cannot return to the real target after Defense restarts.
"""

from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import time
from urllib.parse import urlsplit

from . import store
from .target_selection import _TARGET_ID, _validate_url


OVERLAY_MEDIUM = "account_overlay_medium"
OVERLAY_HIGH = "account_overlay_high"
OVERLAY_NAMES = frozenset({OVERLAY_MEDIUM, OVERLAY_HIGH})
MAX_OVERLAY_BODY = 1_048_576
MAX_OVERLAY_TARGET = 8192
MAX_STICKY_ACTORS = 100_000
_SCHEMA_VERSION = 2
_SENTINEL = ".overlay-route-store-initialized"


class OverlayRouteError(RuntimeError):
    """An overlay request must fail closed, rather than reach an origin."""


def parse_overlay_upstreams(raw: str | None, target_ids) -> dict[str, str]:
    if not raw or not raw.strip():
        return {}
    allowed = set(target_ids)
    configured: dict[str, str] = {}
    for item in raw.split(","):
        target_id, separator, url = item.strip().partition("=")
        if (not separator or not _TARGET_ID.fullmatch(target_id)
                or target_id in configured or target_id not in allowed):
            raise RuntimeError("OVERLAY_UPSTREAM_CHOICES must contain unique valid id=url entries")
        origin = _validate_url(url)
        if urlsplit(origin).path not in {"", "/"}:
            raise RuntimeError("OVERLAY_UPSTREAM_CHOICES URLs must be origins without paths")
        configured[target_id] = origin
    if len(set(configured.values())) != len(configured):
        raise RuntimeError("Each overlay target must have a separate private origin")
    return configured


def requested_tier(plan: list[dict], *, risk_score: float | None,
                   confirmed_attack_score: float | None) -> str | None:
    """Require the trusted plan and its completed-history score to agree."""
    if risk_score is None or confirmed_attack_score is None:
        raise OverlayRouteError("overlay score missing")
    markers = [step for step in plan if step.get("name") in OVERLAY_NAMES]
    if len(markers) > 1 or any(step.get("params", {}) != {} for step in markers):
        raise OverlayRouteError("invalid overlay plan")
    if risk_score >= 0.95 and confirmed_attack_score >= 0.95:
        expected = {"rate_limit_strict", OVERLAY_HIGH}
        tier = "high"
    elif risk_score >= 0.8 and 0.8 <= confirmed_attack_score < 0.95:
        expected = {"rate_limit_strict", "decoy_maze"}
        tier = None
    elif risk_score >= 0.5 and 0.5 <= confirmed_attack_score < 0.8:
        expected = {OVERLAY_MEDIUM}
        tier = "medium"
    else:
        if markers:
            raise OverlayRouteError("overlay marker score mismatch")
        return None
    names = [step.get("name") for step in plan]
    if set(names) != expected or len(names) != len(expected):
        raise OverlayRouteError("selected defense plan does not match score tier")
    if "rate_limit_strict" in expected and not any(
        step.get("name") == "rate_limit_strict" and
        step.get("params") == {"max_rps": 1}
        for step in plan
    ):
        raise OverlayRouteError("strict rate limit plan is invalid")
    return tier


def raw_target(scope: dict) -> str:
    """Return the exact ASCII path and query that the overlay verifier signs."""
    try:
        raw = scope["raw_path"]
        query = scope.get("query_string", b"")
        path = raw.decode("ascii")
        suffix = query.decode("ascii")
    except (KeyError, AttributeError, UnicodeError) as exc:
        raise OverlayRouteError("invalid raw target") from exc
    if (not path.startswith("/") or path.startswith("//") or "\\" in path
            or "//" in path or any(segment in {".", ".."} for segment in path.split("/"))
            or re.search(r"(?i)%(?:2e|2f|5c|25)", path)
            or "#" in path or "?" in path
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in path + suffix)
            or len(raw) + len(query) > MAX_OVERLAY_TARGET):
        raise OverlayRouteError("noncanonical raw target")
    return path + ("?" + suffix if query else "")


def actor_id(secret: bytes, target_id: str, run_id: str | None, client_id: str) -> str:
    if not client_id or len(client_id) > 128:
        raise OverlayRouteError("stable client identity required")
    scope = "\0".join((target_id, run_id or "default", client_id)).encode("utf-8")
    return hmac.new(secret, b"ruby-overlay-actor:v1\0" + scope, hashlib.sha256).hexdigest()


def signed_headers(secret: bytes, actor: str, method: str, target: str,
                   body: bytes, *, tier: str) -> dict[str, str]:
    """Byte-compatible with account-response-overlay.defense.detector.sign_headers."""
    if len(secret) < 32 or tier not in {"medium", "high"}:
        raise OverlayRouteError("invalid overlay signing configuration")
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    fields = ["agent", actor, timestamp, nonce, method.upper(), target,
              hashlib.sha256(body).hexdigest()]
    if tier == "high":
        fields.append("high")
    signature = hmac.new(secret, "\n".join(fields).encode(), hashlib.sha256).hexdigest()
    headers = {
        "x-defense-class": "agent",
        "x-defense-actor": actor,
        "x-defense-timestamp": timestamp,
        "x-defense-nonce": nonce,
        "x-defense-signature": signature,
    }
    if tier == "high":
        headers["x-defense-risk"] = "high"
    return headers


def _key_scope(secret: bytes) -> str:
    return hmac.new(secret, b"ruby-overlay-route-store:v1", hashlib.sha256).hexdigest()


def _target_scope(secret: bytes, target_ids) -> str:
    identifiers = set(target_ids)
    if any(not isinstance(value, str) or not _TARGET_ID.fullmatch(value) for value in identifiers):
        raise OverlayRouteError("invalid overlay target set")
    canonical = json.dumps(sorted(identifiers), separators=(",", ":")).encode("ascii")
    return hmac.new(secret, b"ruby-overlay-target-set:v1\0" + canonical, hashlib.sha256).hexdigest()


class OverlayRouteStore:
    """Key-bound SQLite state with explicit first-run initialization."""

    def __init__(self, path: str, secret: bytes, target_ids=()):
        if not path or len(secret) < 32:
            raise OverlayRouteError("overlay route store and key required")
        self.path = Path(path).absolute()
        self.sentinel = self.path.parent / _SENTINEL
        self.key_scope = _key_scope(secret)
        self.target_scope = _target_scope(secret, target_ids)
        self._check_sentinel()
        self._identity = self._file_identity()
        with self._transaction() as conn:
            self._validate(conn, integrity=True)

    def _check_sentinel(self) -> None:
        try:
            info = self.sentinel.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
                raise OverlayRouteError("overlay route sentinel must be a mode-0600 regular file")
            with self.sentinel.open("rb") as stream:
                scope = stream.read(65)
            if not hmac.compare_digest(scope, self.key_scope.encode("ascii")):
                raise OverlayRouteError("overlay route sentinel key changed")
        except OSError as exc:
            raise OverlayRouteError("overlay route sentinel unavailable") from exc

    def _file_identity(self) -> tuple[int, int]:
        try:
            info = self.path.lstat()
        except OSError as exc:
            raise OverlayRouteError("overlay route store unavailable") from exc
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise OverlayRouteError("overlay route store must be a mode-0600 regular file")
        return info.st_dev, info.st_ino

    def _validate(self, conn: sqlite3.Connection, *, integrity: bool = False) -> None:
        if conn.execute("PRAGMA user_version").fetchone()[0] != _SCHEMA_VERSION:
            raise OverlayRouteError("overlay route store schema mismatch")
        if integrity and conn.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
            raise OverlayRouteError("overlay route store integrity check failed")
        meta = conn.execute("SELECT key_scope,target_scope FROM overlay_meta WHERE id=1").fetchall()
        if len(meta) != 1 or not isinstance(meta[0][0], str) or not hmac.compare_digest(meta[0][0], self.key_scope):
            raise OverlayRouteError("overlay route store key changed")
        if not isinstance(meta[0][1], str) or not hmac.compare_digest(meta[0][1], self.target_scope):
            raise OverlayRouteError("overlay target set changed")

    def _transaction(self, *, write: bool = False):
        return _RouteTransaction(self, write=write)

    def observe(self, actor: str, requested: str | None) -> str | None:
        if not re.fullmatch(r"[0-9a-f]{64}", actor) or requested not in {None, "medium", "high"}:
            raise OverlayRouteError("invalid overlay route")
        self._check_sentinel()
        try:
            with self._transaction(write=requested is not None) as conn:
                self._validate(conn)
                row = conn.execute("SELECT tier FROM sticky_actor WHERE actor=?", (actor,)).fetchone()
                existing = row[0] if row else None
                if requested is not None and (existing is None or
                                              (existing == "medium" and requested == "high")):
                    if row is None and conn.execute("SELECT COUNT(*) FROM sticky_actor").fetchone()[0] >= MAX_STICKY_ACTORS:
                        raise OverlayRouteError("overlay actor capacity reached")
                    conn.execute("INSERT INTO sticky_actor(actor,tier) VALUES (?,?) "
                                 "ON CONFLICT(actor) DO UPDATE SET tier=excluded.tier",
                                 (actor, requested))
                    return requested
                return existing
        except (OSError, sqlite3.Error) as exc:
            raise OverlayRouteError("overlay route store unavailable") from exc

    def health(self) -> None:
        self._check_sentinel()
        try:
            with self._transaction() as conn:
                self._validate(conn, integrity=True)
        except (OSError, sqlite3.Error) as exc:
            raise OverlayRouteError("overlay route store unavailable") from exc

    @staticmethod
    def initialize(path: str, secret: bytes, target_ids=()) -> None:
        if not path or len(secret) < 32:
            raise OverlayRouteError("overlay route store and key required")
        target_ids = tuple(target_ids)
        target = Path(path).absolute()
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        sentinel = target.parent / _SENTINEL
        # Only an empty, new volume may be initialized. A missing DB on an
        # established volume must never silently forget a quarantined actor.
        if any(target.parent.iterdir()):
            raise OverlayRouteError("overlay route volume is not virgin")
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(target, flags, 0o600)
        except OSError as exc:
            raise OverlayRouteError("overlay route store already exists or cannot be created") from exc
        os.close(descriptor)
        try:
            with closing(sqlite3.connect(target)) as conn:
                with conn:
                    conn.executescript("""
                        CREATE TABLE overlay_meta(id INTEGER PRIMARY KEY CHECK(id=1),
                            key_scope TEXT NOT NULL, target_scope TEXT NOT NULL);
                        CREATE TABLE sticky_actor(actor TEXT PRIMARY KEY, tier TEXT NOT NULL
                            CHECK(tier IN ('medium','high')));
                    """)
                    conn.execute("INSERT INTO overlay_meta VALUES (1,?,?)",
                                 (_key_scope(secret), _target_scope(secret, target_ids)))
                    conn.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
            sentinel_fd = os.open(sentinel, flags, 0o600)
            with os.fdopen(sentinel_fd, "w") as stream:
                stream.write(_key_scope(secret))
            OverlayRouteStore(path, secret, target_ids)
        except Exception:
            target.unlink(missing_ok=True)
            sentinel.unlink(missing_ok=True)
            raise

    @staticmethod
    def bootstrap(path: str, secret: bytes, target_ids=()) -> "OverlayRouteStore":
        if not path or len(secret) < 32:
            raise OverlayRouteError("overlay route store and key required")
        target_ids = tuple(target_ids)
        target = Path(path).absolute()
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not any(target.parent.iterdir()):
            OverlayRouteStore.initialize(path, secret, target_ids)
        return OverlayRouteStore(path, secret, target_ids)

    @staticmethod
    def exists(path: str) -> bool:
        target = Path(path).absolute()
        return os.path.lexists(target) or os.path.lexists(target.parent / _SENTINEL)


class _RouteTransaction:
    def __init__(self, store: OverlayRouteStore, *, write: bool = False):
        self.store = store
        self.write = write
        self.conn: sqlite3.Connection | None = None

    def __enter__(self) -> sqlite3.Connection:
        if self.store._file_identity() != self.store._identity:
            raise OverlayRouteError("overlay route store was replaced")
        try:
            # 이 저장소는 자기 파일을 유지한다(통합하지 않는다). 요청마다 쓰는
            # path-alias 와 파일을 공유하면 그쪽 쓰기 락이 이 fail-closed 경로를
            # SQLITE_BUSY 로 떨어뜨리고, main.py 는 그걸 503 으로 돌려준다.
            self.conn = store.connect(self.store.path, timeout=2, journal_mode=None,
                                      synchronous=None)
            self.conn.execute("BEGIN IMMEDIATE" if self.write else "BEGIN")
            return self.conn
        except sqlite3.Error as exc:
            if self.conn is not None:
                self.conn.close()
                self.conn = None
            raise OverlayRouteError("overlay route store unavailable") from exc

    def __exit__(self, exc_type, exc, _tb):
        if self.conn is None:
            return False
        try:
            if exc_type is None:
                if self.store._file_identity() != self.store._identity:
                    raise OverlayRouteError("overlay route store was replaced")
                self.conn.commit()
            else:
                self.conn.rollback()
        finally:
            self.conn.close()
        return False


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["init"])
    parser.add_argument("--database", required=True)
    parser.add_argument("--target-id", action="append", default=[])
    args = parser.parse_args()
    key = os.getenv("OVERLAY_DETECTOR_KEY", "").encode("utf-8")
    OverlayRouteStore.initialize(args.database, key, args.target_id)


if __name__ == "__main__":
    main()
