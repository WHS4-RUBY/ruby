"""Server-owned, per-client aliases for configured web routes, rotated on suspicious events."""

import base64
import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import threading
from collections.abc import Iterator, Mapping
from contextlib import closing, contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import quote, unquote, unquote_plus, urlsplit, urlunsplit

LOGGER_NAME = "ruby.defense.path_alias"
DEFAULT_PREFIXES = ("/rest/", "/api/")
REWRITABLE_TYPES = frozenset({
    "text/html", "application/javascript", "text/javascript",
    "application/x-javascript", "application/json",
})
COOKIE_NAME = "ruby_alias_client"
ROTATION_TRIGGERS = ("direct", "reject")
_ALIAS_MARKER = "__ruby_alias_"
_TOKEN_LEN = 26
_ALIAS_PATH = re.compile(r"^(/" + _ALIAS_MARKER + r"[a-z2-7]{26})(/.*)?$")
_CLIENT_ID = re.compile(r"^[a-z2-7]{26}$")
_VAR = re.compile(r"^\{([A-Za-z][A-Za-z0-9_]*)(\*)?\}$")
_BODY_VAR = rb"(\$\{[^}/]+\}|[^/?#\"'`\s]+)"
_BODY_BOUNDARY = rb"(?=$|[?#\"'`\s,;)}])"


def _configure_logger() -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    return logger


def _parse_prefixes(raw: str) -> tuple[str, ...]:
    prefixes = []
    for item in raw.split(","):
        item = item.strip().lower()
        if not item:
            continue
        if not (item.startswith("/") and item.endswith("/")) or item == "/":
            raise ValueError("PATH_ALIAS_PREFIXES entries must look like /name/")
        if not item.isascii():
            raise ValueError("PATH_ALIAS_PREFIXES entries must be ASCII")
        prefixes.append(item)
    if not prefixes:
        raise ValueError("PATH_ALIAS_PREFIXES must not be empty")
    return tuple(sorted(set(prefixes), key=len, reverse=True))


def _parse_triggers(raw: str) -> tuple[str, ...]:
    triggers = {item.strip().lower() for item in raw.split(",") if item.strip()}
    if not triggers <= set(ROTATION_TRIGGERS):
        raise ValueError("PATH_ALIAS_ROTATE_ON entries must be direct or reject")
    return tuple(t for t in ROTATION_TRIGGERS if t in triggers)


def _random_token() -> str:
    return base64.b32encode(secrets.token_bytes(17)).decode("ascii").lower()[:_TOKEN_LEN]


def new_client_id() -> str:
    return _random_token()


def valid_client_id(value: str | None) -> str | None:
    return value if value and _CLIENT_ID.fullmatch(value) else None


def client_ref(client_id: str | None) -> str | None:
    """Short, non-reversible handle for logs; the cookie value itself is never logged."""
    return hashlib.sha256(client_id.encode("ascii")).hexdigest()[:12] if client_id else None


@dataclass(frozen=True)
class Route:
    path: str
    methods: tuple[str, ...] = ("*",)

    def __post_init__(self):
        if not self.path.startswith("/") or self.path == "/" or "?" in self.path or "#" in self.path:
            raise ValueError(f"Invalid alias route: {self.path!r}")
        if self.path.startswith("/" + _ALIAS_MARKER):
            raise ValueError("A real route cannot use the reserved alias namespace")
        if "//" in self.path or ".." in self.path.split("/"):
            raise ValueError(f"Noncanonical alias route: {self.path!r}")
        names = []
        parts = self.parts
        for index, part in enumerate(parts):
            if "{" in part or "}" in part:
                match = _VAR.fullmatch(part)
                if not match or (match.group(2) and index != len(parts) - 1):
                    raise ValueError(f"Invalid route template: {self.path!r}")
                names.append(match.group(1))
        if len(set(names)) != len(names):
            raise ValueError(f"Duplicate route variable: {self.path!r}")
        if not self.methods or any(m != "*" and not re.fullmatch(r"[A-Z]+", m) for m in self.methods):
            raise ValueError(f"Invalid route methods: {self.methods!r}")

    @property
    def parts(self) -> tuple[str, ...]:
        return tuple(self.path.lstrip("/").split("/"))

    @property
    def specificity(self) -> tuple[int, int]:
        return (sum(not _VAR.fullmatch(p) for p in self.parts), len(self.path))

    @property
    def variables(self) -> tuple[re.Match, ...]:
        return tuple(m for p in self.parts if (m := _VAR.fullmatch(p)))

    def real_pattern(self) -> re.Pattern[str]:
        chunks = []
        for part in self.parts:
            match = _VAR.fullmatch(part)
            if match and match.group(2):
                chunks.append(f"(?:/(?P<{match.group(1)}>.*))?")
            elif match:
                chunks.append(f"/(?P<{match.group(1)}>[^/]+)")
            else:
                chunks.append("/" + re.escape(part))
        return re.compile("^" + "".join(chunks) + "$", re.I)

    def body_pattern(self) -> re.Pattern[bytes]:
        chunks = []
        wildcard = bool(self.variables and self.variables[-1].group(2))
        for part in self.parts:
            match = _VAR.fullmatch(part)
            if match and match.group(2):
                break  # The runtime suffix is appended to the rewritten base.
            chunks.append(b"/" + (_BODY_VAR if match else re.escape(part.encode("utf-8"))))
        return re.compile(rb"(?<![A-Za-z0-9_-])(" + b"".join(chunks) + b")" +
                          (rb"(?![A-Za-z0-9_-])" if wildcard else _BODY_BOUNDARY), re.I)


def _load_routes(file_name: str) -> tuple[Route, ...]:
    if not file_name:
        raise ValueError("PATH_ALIAS_ROUTES_FILE is required when path aliases are enabled")
    document = json.loads(Path(file_name).read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("routes"), list):
        raise ValueError("Path alias route file needs a routes array")
    routes = []
    for item in document["routes"]:
        if isinstance(item, str):
            routes.append(Route(item))
        elif isinstance(item, dict) and isinstance(item.get("path"), str):
            methods = item.get("methods", ["*"])
            if not isinstance(methods, list) or not all(isinstance(m, str) for m in methods):
                raise ValueError("Route methods must be an array of strings")
            routes.append(Route(item["path"], tuple(methods)))
        else:
            raise ValueError("Each route must be a path or a path/methods object")
    if not routes or len({route.path.lower() for route in routes}) != len(routes):
        raise ValueError("Path alias routes must be nonempty and unique")
    return tuple(sorted(routes, key=lambda r: r.specificity, reverse=True))


@dataclass(frozen=True)
class QueryRoute:
    """An application dispatcher whose named query value selects a protected path."""
    path: str
    parameter: str

    def __post_init__(self):
        if self.path != "/":
            Route(self.path)
        if "{" in self.path or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", self.parameter):
            raise ValueError("Query routes require an exact path and a parameter name")


def _load_query_routes(file_name: str) -> tuple[QueryRoute, ...]:
    items = json.loads(Path(file_name).read_text(encoding="utf-8")).get("query_routes", [])
    if not isinstance(items, list):
        raise ValueError("query_routes must be an array")
    rules = []
    for item in items:
        if not isinstance(item, dict) or not all(isinstance(item.get(k), str) for k in ("path", "parameter")):
            raise ValueError("Query routes require path and parameter strings")
        rules.append(QueryRoute(item["path"], item["parameter"]))
    if len(set((r.path, r.parameter) for r in rules)) != len(rules):
        raise ValueError("Query routes must be unique")
    return tuple(rules)


@dataclass(frozen=True)
class PathAliasConfig:
    mode: str = "off"
    epoch_s: int = 1800
    grace_epochs: int = 1
    prefixes: tuple[str, ...] = DEFAULT_PREFIXES
    routes: tuple[Route, ...] = ()
    max_rewrite_bytes: int = 8 * 1024 * 1024
    app_id: str = ""
    db_path: str = ""
    rotate_on: tuple[str, ...] = ROTATION_TRIGGERS
    cookie_secure: bool = False
    db_url: str = ""  # postgresql://... ; takes precedence over db_path
    db_pool_size: int = 10
    query_routes: tuple[QueryRoute, ...] = ()

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ) -> "PathAliasConfig":
        mode = environ.get("PATH_ALIAS_MODE", "off").strip().lower()
        if mode not in {"off", "observe", "enforce"}:
            raise ValueError("PATH_ALIAS_MODE must be off, observe or enforce")
        if mode == "off":
            return cls()
        try:
            epoch_s = int(environ.get("PATH_ALIAS_EPOCH_S", "1800"))
            grace = int(environ.get("PATH_ALIAS_GRACE_EPOCHS", "1"))
            max_bytes = int(environ.get("PATH_ALIAS_MAX_REWRITE_BYTES", str(8 * 1024 * 1024)))
            pool_size = int(environ.get("PATH_ALIAS_DB_POOL_SIZE", "10"))
        except ValueError as exc:
            raise ValueError("Path alias epoch, grace, size limit and pool size must be integers") from exc
        if epoch_s < 1 or not 0 <= grace <= 10 or max_bytes < 1 or pool_size < 1:
            raise ValueError("Path alias requires epoch >= 1, grace 0..10, a positive size limit "
                             "and a positive pool size")
        prefixes = _parse_prefixes(environ.get("PATH_ALIAS_PREFIXES", ",".join(DEFAULT_PREFIXES)))
        routes = _load_routes(environ.get("PATH_ALIAS_ROUTES_FILE", ""))
        query_routes = _load_query_routes(environ.get("PATH_ALIAS_ROUTES_FILE", ""))
        for route in routes:
            if not any(route.path.lower() == p.rstrip("/") or route.path.lower().startswith(p) for p in prefixes):
                raise ValueError(f"Route {route.path!r} is outside protected prefixes")
        app_id = environ.get("PATH_ALIAS_APP_ID", "").strip()
        db_url = environ.get("PATH_ALIAS_DB_URL", "").strip()
        db_path = environ.get("PATH_ALIAS_DB_PATH", "").strip()
        if db_url:
            if not db_url.startswith(("postgresql://", "postgres://")):
                raise ValueError("PATH_ALIAS_DB_URL must be a postgresql:// URL")
        elif not db_path or db_path == ":memory:":
            raise ValueError("Set PATH_ALIAS_DB_URL (PostgreSQL) or PATH_ALIAS_DB_PATH "
                             "(persistent SQLite file)")
        rotate_on = _parse_triggers(environ.get("PATH_ALIAS_ROTATE_ON", ",".join(ROTATION_TRIGGERS)))
        secure = environ.get("PATH_ALIAS_COOKIE_SECURE", "false").strip().lower()
        if secure not in {"true", "false"}:
            raise ValueError("PATH_ALIAS_COOKIE_SECURE must be true or false")
        _configure_logger()
        return cls(mode, epoch_s, grace, prefixes, routes, max_bytes, app_id, db_path,
                   rotate_on, secure == "true", db_url, pool_size, query_routes)


@dataclass(frozen=True)
class Resolution:
    kind: str  # alias | direct | reject | other
    upstream_path: str
    prefix: str | None = None
    alias_state: str | None = None
    reason: str | None = None
    route_id: str | None = None
    generation: int | None = None
    query_string: bytes | None = None


def _ambiguous(path: str) -> bool:
    return bool(re.search(r"[%\\;\x00-\x20]", path) or path in {".", ".."} or path.endswith("."))


def _canonical(path: str) -> str:
    for _ in range(3):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    parts = []
    for part in path.replace("\\", "/").split("/"):
        part = part.split(";", 1)[0].rstrip(" ").lower()
        if part == "..":
            if parts:
                parts.pop()
        elif part and part != ".":
            parts.append(part.rstrip("."))
    return "/" + "/".join(parts) + ("/" if path.endswith("/") else "")


# Portable DDL: SQLite maps BIGINT/DOUBLE PRECISION to INTEGER/REAL affinity.
_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS path_alias_clients (
        app_id TEXT NOT NULL, client_id TEXT NOT NULL,
        generation BIGINT NOT NULL, issued_at DOUBLE PRECISION NOT NULL,
        config_hash TEXT NOT NULL, PRIMARY KEY(app_id, client_id))""",
    """CREATE TABLE IF NOT EXISTS path_alias_client_rows (
        alias_route TEXT PRIMARY KEY, app_id TEXT NOT NULL,
        client_id TEXT NOT NULL, route_path TEXT NOT NULL,
        generation BIGINT NOT NULL, issued_at DOUBLE PRECISION NOT NULL,
        expires_at DOUBLE PRECISION NOT NULL,
        UNIQUE(app_id, client_id, route_path, generation))""",
    """CREATE INDEX IF NOT EXISTS path_alias_client_rows_expiry
        ON path_alias_client_rows(app_id, expires_at)""",
    """CREATE INDEX IF NOT EXISTS path_alias_clients_issued
        ON path_alias_clients(app_id, issued_at)""",
)


def _lock_key(*parts: str) -> int:
    """Signed 64-bit key for PostgreSQL advisory locks."""
    digest = hashlib.sha256("\0".join(parts).encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


class _SQLiteStore:
    """One database file shared by workers; every write takes the database-wide write lock."""

    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            self.begin_write(db, "schema")
            try:
                for statement in _SCHEMA:
                    db.execute(statement)
                db.commit()
            except Exception:
                db.rollback()
                raise

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self.path, timeout=10.0, isolation_level=None)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA busy_timeout=10000")
            yield db

    def begin_write(self, db, key: str) -> None:
        db.execute("BEGIN IMMEDIATE")

    def try_begin_sweep(self, db, app_id: str) -> bool:
        db.execute("BEGIN IMMEDIATE")
        return True


class _PostgresConnection:
    """sqlite3-shaped facade so table code runs unchanged: qmark placeholders, explicit BEGIN."""

    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql: str, params: tuple = ()):
        return self._conn.execute(sql.replace("?", "%s"), params)

    def commit(self) -> None:
        self._conn.execute("COMMIT")

    def rollback(self) -> None:
        self._conn.execute("ROLLBACK")


_PG_POOLS: dict[tuple[str, int], object] = {}
_PG_POOLS_LOCK = threading.Lock()


class _PostgresStore:
    """Shared server database. Writers serialize per client (advisory lock), not database-wide."""

    def __init__(self, url: str, pool_size: int):
        from psycopg.rows import dict_row
        from psycopg_pool import ConnectionPool

        with _PG_POOLS_LOCK:  # one pool per process, however many tables share the URL
            pool = _PG_POOLS.get((url, pool_size))
            if pool is None:
                pool = ConnectionPool(url, min_size=1, max_size=pool_size, open=True,
                                      kwargs={"autocommit": True, "row_factory": dict_row},
                                      name="path-alias")
                _PG_POOLS[(url, pool_size)] = pool
        self._pool = pool
        with self.connect() as db:
            self.begin_write(db, "schema")  # concurrent CREATE IF NOT EXISTS can still collide
            try:
                for statement in _SCHEMA:
                    db.execute(statement)
                db.commit()
            except Exception:
                db.rollback()
                raise

    @contextmanager
    def connect(self) -> Iterator[_PostgresConnection]:
        with self._pool.connection() as conn:
            yield _PostgresConnection(conn)

    def begin_write(self, db: _PostgresConnection, key: str) -> None:
        db.execute("BEGIN")
        db.execute("SELECT pg_advisory_xact_lock(?)", (_lock_key("path_alias", key),))

    def try_begin_sweep(self, db: _PostgresConnection, app_id: str) -> bool:
        """Only one worker sweeps at a time; two concurrent bulk deletes could deadlock."""
        db.execute("BEGIN")
        row = db.execute("SELECT pg_try_advisory_xact_lock(?) AS locked",
                         (_lock_key("path_alias_sweep", app_id),)).fetchone()
        if not row["locked"]:
            db.rollback()
        return row["locked"]


class PathAliasTable:
    """Authoritative table of per-client aliases in a database shared by every worker.

    PostgreSQL (``PATH_ALIAS_DB_URL``) is the multi-user deployment backend; a SQLite file
    (``PATH_ALIAS_DB_PATH``) remains for single-host experiments and tests.

    Each client (identified by the ``ruby_alias_client`` cookie) owns one alias per configured
    route. A client's aliases are replaced immediately when it triggers a configured event
    (``rotate_client``) and, as a backstop, every ``epoch_s`` seconds with ``grace_epochs`` of
    overlap. Old aliases from an event rotation get no grace period.
    """

    def __init__(self, cfg: PathAliasConfig):
        self.cfg = cfg
        self._routes_by_path = {route.path: route for route in cfg.routes}
        self._lifetime = (cfg.grace_epochs + 1) * cfg.epoch_s
        config_data = {
            "epoch_s": cfg.epoch_s, "grace_epochs": cfg.grace_epochs,
            "prefixes": sorted(cfg.prefixes),
            "routes": sorted((route.path, route.methods) for route in cfg.routes),
            "query_routes": sorted((rule.path, rule.parameter) for rule in cfg.query_routes),
        }
        self._config_hash = hashlib.sha256(json.dumps(config_data, sort_keys=True).encode()).hexdigest()
        prefixes = b"|".join(re.escape(p.rstrip("/").encode("ascii")) for p in cfg.prefixes)
        self._body_candidates = re.compile(rb"(?<![A-Za-z0-9_-])(?:" + prefixes + rb")", re.I)
        self._body_patterns = [(route, route.body_pattern()) for route in cfg.routes]
        self._real_patterns = {route.path: route.real_pattern() for route in cfg.routes}
        # Expired rows are swept at most once per interval per process, not on every new client:
        # cookieless traffic creates a client per request.
        self._sweep_interval = min(cfg.epoch_s, 60)
        self._next_sweep = 0.0
        self._store = None
        if cfg.mode != "off":
            if cfg.db_url:
                self._store = _PostgresStore(cfg.db_url, cfg.db_pool_size)
            elif cfg.db_path and cfg.db_path != ":memory:":
                self._store = _SQLiteStore(cfg.db_path)
            else:
                raise ValueError("Active path aliases require PostgreSQL or a persistent SQLite file")

    def _write_lock(self, db, client_id: str) -> None:
        self._store.begin_write(db, f"{self.cfg.app_id}\0{client_id}")

    def _client(self, db, client_id: str):
        return db.execute("""SELECT generation, issued_at, config_hash FROM path_alias_clients
            WHERE app_id=? AND client_id=?""", (self.cfg.app_id, client_id)).fetchone()

    def _current_rows(self, db, client_id: str, generation: int, now: float) -> dict[str, str]:
        rows = db.execute("""SELECT route_path, alias_route FROM path_alias_client_rows
            WHERE app_id=? AND client_id=? AND generation=? AND expires_at>?""",
                          (self.cfg.app_id, client_id, generation, now)).fetchall()
        return {row["route_path"]: row["alias_route"] for row in rows
                if row["route_path"] in self._routes_by_path}

    def _issue(self, db, client_id: str, now: float) -> tuple[dict[str, str], dict | None]:
        """Bring a client's current generation up to date. Caller holds this client's write lock."""
        app_id = self.cfg.app_id
        client = self._client(db, client_id)
        previous = client["generation"] if client else None
        if client is None or client["config_hash"] != self._config_hash:
            reason = "new" if client is None else "config"
            generation, issued_at = (0 if client is None else previous + 1), now
            db.execute("DELETE FROM path_alias_client_rows WHERE app_id=? AND client_id=?", (app_id, client_id))
        elif now >= client["issued_at"] + self.cfg.epoch_s:
            reason, generation, issued_at = "time", previous + 1, now
            db.execute("""DELETE FROM path_alias_client_rows WHERE app_id=? AND client_id=?
                AND (generation<? OR expires_at<=?)""",
                       (app_id, client_id, generation - self.cfg.grace_epochs, now))
        else:
            reason, generation, issued_at = None, previous, client["issued_at"]
        if reason:
            db.execute("""INSERT INTO path_alias_clients(app_id, client_id, generation, issued_at, config_hash)
                VALUES (?, ?, ?, ?, ?) ON CONFLICT(app_id, client_id) DO UPDATE SET
                generation=excluded.generation, issued_at=excluded.issued_at,
                config_hash=excluded.config_hash""",
                       (app_id, client_id, generation, issued_at, self._config_hash))
        db.execute("""DELETE FROM path_alias_client_rows WHERE app_id=? AND client_id=?
            AND generation=? AND expires_at<=?""", (app_id, client_id, generation, now))
        aliases = self._current_rows(db, client_id, generation, now)
        for route in self.cfg.routes:
            if route.path in aliases:
                continue
            while True:
                alias = "/" + _ALIAS_MARKER + _random_token()
                # DO NOTHING instead of catching the error: in PostgreSQL a failed statement
                # aborts the whole transaction.
                inserted = db.execute("""INSERT INTO path_alias_client_rows
                    (alias_route, app_id, client_id, route_path, generation, issued_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(alias_route) DO NOTHING""",
                                      (alias, app_id, client_id, route.path, generation, issued_at,
                                       issued_at + self._lifetime)).rowcount
                if inserted:
                    aliases[route.path] = alias
                    break
                # token collision: retry with fresh randomness
        rotation = None
        if reason:
            rotation = {"event": "path_alias_rotation", "ts": now, "app_id": app_id,
                        "client_ref": client_ref(client_id), "reason": reason,
                        "previous_generation": previous, "generation": generation,
                        "current_routes": len(self.cfg.routes)}
        return aliases, rotation

    def current_aliases(self, now: float, client_id: str) -> dict[str, str]:
        """Aliases this client should receive now, issuing or time-rotating them if needed."""
        if self.cfg.mode == "off":
            return {}
        rotation = None
        with self._store.connect() as db:
            try:
                db.execute("BEGIN")
                client = self._client(db, client_id)
                if (client is not None and client["config_hash"] == self._config_hash
                        and now < client["issued_at"] + self.cfg.epoch_s):
                    aliases = self._current_rows(db, client_id, client["generation"], now)
                    if len(aliases) == len(self.cfg.routes):
                        db.commit()
                        return aliases
                db.rollback()
                # Recheck under the write lock: another worker may have issued meanwhile.
                self._write_lock(db, client_id)
                aliases, rotation = self._issue(db, client_id, now)
                db.commit()
            except Exception:
                db.rollback()
                raise
            if rotation and now >= self._next_sweep:
                self._next_sweep = now + self._sweep_interval
                try:
                    self._sweep(db, now)
                except Exception as exc:  # housekeeping must not fail the issuing request
                    emit({"event": "path_alias_sweep_failed", "ts": now, "app_id": self.cfg.app_id,
                          "error": type(exc).__name__})
        if rotation:
            emit(rotation)
        return aliases

    def _sweep(self, db, now: float) -> None:
        """Drop every row and client that can no longer be valid, in its own transaction."""
        if not self._store.try_begin_sweep(db, self.cfg.app_id):
            return
        try:
            db.execute("DELETE FROM path_alias_client_rows WHERE app_id=? AND expires_at<=?",
                       (self.cfg.app_id, now))
            db.execute("DELETE FROM path_alias_clients WHERE app_id=? AND issued_at<=?",
                       (self.cfg.app_id, now - self._lifetime))
            db.commit()
        except Exception:
            db.rollback()
            raise

    def rotate_client(self, client_id: str, now: float, reason: str) -> bool:
        """Invalidate every alias of a known client at once; new ones are issued on next delivery."""
        if self.cfg.mode == "off":
            return False
        with self._store.connect() as db:
            try:
                self._write_lock(db, client_id)
                client = self._client(db, client_id)
                if client is None:
                    db.commit()
                    return False
                previous = client["generation"]
                db.execute("DELETE FROM path_alias_client_rows WHERE app_id=? AND client_id=?",
                           (self.cfg.app_id, client_id))
                db.execute("""UPDATE path_alias_clients SET generation=?, issued_at=?
                    WHERE app_id=? AND client_id=?""",
                           (previous + 1, now, self.cfg.app_id, client_id))
                db.commit()
            except Exception:
                db.rollback()
                raise
        emit({"event": "path_alias_rotation", "ts": now, "app_id": self.cfg.app_id,
              "client_ref": client_ref(client_id), "reason": reason,
              "previous_generation": previous, "generation": previous + 1,
              "current_routes": len(self.cfg.routes)})
        return True

    def resolve(self, path: str, method: str, now: float, client_id: str | None = None) -> Resolution:
        if self.cfg.mode == "off":
            return Resolution("other", path)
        match = _ALIAS_PATH.fullmatch(path)
        if match:
            base = match.group(1)
            with self._store.connect() as db:
                row = db.execute("""SELECT r.client_id, r.route_path, r.generation, r.expires_at,
                    c.generation AS client_generation, c.issued_at AS client_issued_at, c.config_hash
                    FROM path_alias_client_rows r JOIN path_alias_clients c
                    ON c.app_id=r.app_id AND c.client_id=r.client_id
                    WHERE r.alias_route=? AND r.app_id=?""", (base, self.cfg.app_id)).fetchone()
            if (row is None or row["expires_at"] <= now or row["config_hash"] != self._config_hash
                    or row["route_path"] not in self._routes_by_path):
                return Resolution("reject", path, reason="unknown_alias")
            if row["client_id"] != client_id:
                return Resolution("reject", path, reason="foreign_alias")
            route = self._routes_by_path[row["route_path"]]
            if method.upper() not in route.methods and "*" not in route.methods:
                return Resolution("reject", path, reason="method_not_allowed")
            suffix = path[len(base):]
            variables = route.variables
            if variables:
                pieces = suffix.lstrip("/").split("/") if suffix.startswith("/") else []
                wildcard = bool(variables[-1].group(2))
                if len(pieces) < len(variables) - wildcard or (not wildcard and len(pieces) != len(variables)):
                    return Resolution("reject", path, reason="invalid_alias_arguments")
                if any(_ambiguous(piece) or (not piece and not (wildcard and suffix == "/"))
                       for piece in pieces):
                    return Resolution("reject", path, reason="invalid_alias_arguments")
                values = {}
                for i, variable in enumerate(variables):
                    values[variable.group(1)] = "/".join(pieces[i:]) if variable.group(2) else pieces[i]
                real_parts = []
                for part in route.parts:
                    variable = _VAR.fullmatch(part)
                    if variable:
                        value = values[variable.group(1)]
                        if not variable.group(2) or suffix:
                            real_parts.append(value)
                    else:
                        real_parts.append(part)
                real = "/" + "/".join(real_parts)
            else:
                if suffix:
                    return Resolution("reject", path, reason="invalid_alias_arguments")
                real = route.path
            if any(other.path != route.path and other.specificity > route.specificity
                   and self._real_patterns[other.path].fullmatch(real) for other in self.cfg.routes):
                return Resolution("reject", path, reason="shadowed_route")
            current = (row["generation"] == row["client_generation"]
                       and now < row["client_issued_at"] + self.cfg.epoch_s)
            return Resolution("alias", real, alias_state="current" if current else "grace",
                              route_id=route.path, generation=row["generation"])
        if _ALIAS_MARKER in _canonical(path):  # any spelling of the reserved namespace
            return Resolution("reject", path, reason="unknown_alias")
        normalized = _canonical(path)
        for prefix in self.cfg.prefixes:
            if normalized == prefix.rstrip("/") or normalized.startswith(prefix):
                return Resolution("direct", path, prefix)
        return Resolution("other", path)

    def resolve_request(self, path: str, query: bytes, method: str, now: float,
                        client_id: str | None = None) -> Resolution:
        outer = self.resolve(path, method, now, client_id)
        if self.cfg.mode == "off" or outer.kind in ("direct", "reject"):
            return outer
        rules = [r for r in self.cfg.query_routes if r.path == outer.upstream_path]
        if not rules:
            return outer
        # Only replace configured values. Every other byte (including duplicate keys,
        # blanks and escape spelling) stays untouched.
        fields = query.decode("ascii", errors="surrogateescape").split("&")
        selected = outer
        for rule in rules:
            indexes = [i for i, field in enumerate(fields)
                       if unquote_plus(field.partition("=")[0]) == rule.parameter]
            if len(indexes) > 1:
                return replace(outer, kind="reject", reason="duplicate_query_route", query_string=query)
            if not indexes:
                continue
            i = indexes[0]
            key, separator, raw_value = fields[i].partition("=")
            value = unquote_plus(raw_value)
            if not separator or not value.startswith("/") or any(c in value for c in "?#"):
                return replace(outer, kind="reject", reason="invalid_query_route", query_string=query)
            inner = self.resolve(value, method, now, client_id)
            if inner.kind in ("direct", "reject"):
                return replace(inner, upstream_path=outer.upstream_path, query_string=query)
            if inner.kind != "alias":
                return replace(outer, kind="reject", reason="unprotected_query_route", query_string=query)
            fields[i] = key + "=" + quote(inner.upstream_path, safe="" if "%" in raw_value else "/")
            selected = replace(inner, upstream_path=outer.upstream_path)
        return replace(selected, query_string="&".join(fields).encode("ascii", errors="surrogateescape"))

    def _rewrite_query(self, path: str, query: str, now: float, client_id: str) -> str:
        parameters = {r.parameter for r in self.cfg.query_routes if r.path == path}
        if not parameters:
            return query
        fields = query.split("&")
        for i, field in enumerate(fields):
            key, separator, raw = field.partition("=")
            if separator and unquote_plus(key) in parameters:
                value = unquote_plus(raw)
                if not value.startswith("/") or any(c in value for c in "?#"):
                    continue
                alias = self.rewrite_location(value, "", now, client_id)
                if alias != value:
                    fields[i] = key + "=" + quote(alias, safe="" if "%" in raw else "/")
        return "&".join(fields)

    def rewrite_body(self, body: bytes, now: float, client_id: str) -> tuple[bytes, int]:
        if not body:
            return body, 0
        query_count = 0
        for dispatcher in sorted({r.path for r in self.cfg.query_routes}, key=len, reverse=True):
            pattern = re.compile(rb'(?<![A-Za-z0-9_:/.-])' + re.escape(dispatcher.encode()) +
                                 rb'\?[^\s\x22\x27`<>\)]+')
            def rewrite_query_url(match):
                nonlocal query_count
                try:
                    original = match.group().decode("utf-8")
                except UnicodeDecodeError:
                    return match.group()
                value = original.replace("&amp;", "&")
                rewritten = self.rewrite_location(value, "", now, client_id)
                if rewritten == value:
                    return match.group()
                query_count += 1
                if "&amp;" in original:
                    rewritten = rewritten.replace("&", "&amp;")
                return rewritten.encode("utf-8")
            body = pattern.sub(rewrite_query_url, body)
        aliases = None  # issued lazily, so bodies without routes never create a client
        count = 0
        output, copied_until = [], 0
        for candidate in self._body_candidates.finditer(body):
            start = candidate.start()
            if start < copied_until:
                continue
            for route, pattern in self._body_patterns:
                match = pattern.match(body, start)
                if not match:
                    continue
                if aliases is None:
                    aliases = self.current_aliases(now, client_id)
                alias = aliases[route.path].encode("ascii")
                if route.variables and not route.variables[-1].group(2):
                    captured = match.group(1).split(b"/")
                    values = [captured[i + 1] for i, p in enumerate(route.parts)
                              if (m := _VAR.fullmatch(p)) and not m.group(2)]
                    alias += b"/" + b"/".join(values)
                output.extend((body[copied_until:start], alias))
                copied_until = match.end()
                count += 1
                break
        if not count:
            return body, query_count
        output.append(body[copied_until:])
        return b"".join(output), count + query_count

    def rewrite_location(self, value: str, public_host: str, now: float, client_id: str) -> str:
        parts = urlsplit(value)
        if parts.netloc and parts.netloc.lower() != public_host.lower():
            return value
        query = self._rewrite_query(parts.path, parts.query, now, client_id)
        for route in self.cfg.routes:
            match = self._real_patterns[route.path].fullmatch(parts.path)
            if not match:
                continue
            values = [match.group(m.group(1)) for m in route.variables]
            suffix = "/" + "/".join(v for v in values if v) if any(values) else ""
            if route.variables and route.variables[-1].group(2) and parts.path.endswith("/") and not suffix:
                suffix = "/"
            alias_path = self.current_aliases(now, client_id)[route.path] + suffix
            return urlunsplit((parts.scheme, parts.netloc, alias_path, query, parts.fragment))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment)) if query != parts.query else value


def decide(resolution: Resolution, cfg: PathAliasConfig) -> str:
    if resolution.kind == "alias":
        return "translate"
    if resolution.kind in ("direct", "reject"):
        return "block" if cfg.mode == "enforce" else "would_block"
    return "pass"


def build_set_cookie(cfg: PathAliasConfig, client_id: str) -> str:
    # Session cookie: the server forgets idle clients on its own, and an unknown id is simply reissued.
    value = f"{COOKIE_NAME}={client_id}; Path=/; HttpOnly; SameSite=Lax"
    return value + ("; Secure" if cfg.cookie_secure else "")


def rewritable(content_type: str, content_encoding: str, status: int, method: str) -> bool:
    media_type = content_type.split(";", 1)[0].strip().lower()
    return (method.upper() != "HEAD" and status not in (204, 304)
            and content_encoding.strip().lower() in ("", "identity")
            and (media_type in REWRITABLE_TYPES or media_type.endswith("+json")))


def build_log(resolution: Resolution, decision: str, *, now: float, mode: str, method: str,
              path: str, headers: Mapping[str, str], upstream_status: int | None = None,
              rewrites: int = 0, rewrite_skipped: str | None = None, ua_family: str = "none",
              alias_client: str | None = None, rotation: str | None = None) -> dict:
    return {
        "event": "path_alias", "ts": now, "mode": mode,
        "client_id": {k.lower(): v for k, v in headers.items()}.get("x-client-id"),
        "alias_client_ref": client_ref(alias_client),
        "method": method, "path": path, "real_path": resolution.upstream_path,
        "kind": resolution.kind, "alias_state": resolution.alias_state, "decision": decision,
        "reason": resolution.reason, "rotation": rotation,
        "route_id": resolution.route_id, "generation": resolution.generation,
        "upstream_status": upstream_status, "rewrites": rewrites,
        "rewrite_skipped": rewrite_skipped, "ua_family": ua_family,
    }


def emit(log: dict) -> None:
    logging.getLogger(LOGGER_NAME).info(json.dumps(log, separators=(",", ":"), ensure_ascii=False))
