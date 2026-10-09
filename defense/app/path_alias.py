"""Server-owned, per-client aliases for configured web routes, rotated on suspicious events.

Modes, from least to most intrusive:

* ``off``     - nothing runs.
* ``audit``   - no response or request is changed and no database is used. Requests to
                protected prefixes and route references in responses are only counted.
* ``observe`` - responses are rewritten and the alias cookie is issued (this *does* change
                what browsers see), but original routes are still forwarded.
* ``enforce`` - original protected routes and bad aliases are refused before forwarding.

A route file must declare ``enforce_ready`` (with verified flows and a verified refresh
method) before ``enforce`` applies to it; otherwise its routes stay at ``observe``.
"""

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
from collections.abc import Callable, Iterator, Mapping
from contextlib import closing, contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import parse_qsl, quote, unquote, unquote_plus, urlsplit, urlunsplit

LOGGER_NAME = "ruby.defense.path_alias"
DEFAULT_PREFIXES = ("/rest/", "/api/")
REWRITABLE_TYPES = frozenset({
    "text/html", "application/javascript", "text/javascript",
    "application/x-javascript", "application/json",
})
COOKIE_NAME = "ruby_alias_client"
MODES = ("off", "audit", "observe", "enforce")
_RANK = {mode: index for index, mode in enumerate(MODES)}
# Reasons an alias request is refused. ``stale_alias`` (expired or replaced by time/config)
# and ``revoked_alias`` (replaced by an event) are deliberately absent: an old tab or the
# back button produces them, and rotating on them would cascade across a user's tabs.
REJECT_REASONS = ("unknown_alias", "foreign_alias", "method_not_allowed",
                  "invalid_alias_arguments", "shadowed_route",
                  "invalid_query_route", "duplicate_query_route")
ROTATION_REASONS = ("direct",) + REJECT_REASONS
DEFAULT_ROTATE_ON = ("direct", "unknown_alias", "foreign_alias", "invalid_alias_arguments")
_ALIAS_MARKER = "__ruby_alias_"
_TOKEN_LEN = 26
_ALIAS_PATH = re.compile(r"^(/" + _ALIAS_MARKER + r"[a-z2-7]{26})(/.*)?$")
_ALIAS_VALUE = re.compile(r"^" + _ALIAS_MARKER + r"[a-z2-7]{26}$")
_CLIENT_ID = re.compile(r"^[a-z2-7]{26}$")
_VAR = re.compile(r"^\{([A-Za-z][A-Za-z0-9_]*)(\*)?\}$")
_ACTION_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_BODY_VAR = rb"(\$\{[^}/]+\}|[^/?#\"'`\s]+)"
_BODY_BOUNDARY = rb"(?=$|[?#\"'`\s,;)}])"
_DISPATCH_TAIL = rb"\?[^\s\x22\x27`<>\)]+"
BODY_ROUTING_LIMIT = 64 * 1024


class AliasStoreError(RuntimeError):
    """The alias database failed. Callers must not fall back to forwarding original routes."""


class AliasCapacityError(AliasStoreError):
    """Issuing a new client would exceed the configured client limits."""


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
    """``reject`` expands to every reject reason; stale and revoked aliases never rotate."""
    expanded = set()
    for item in {item.strip().lower() for item in raw.split(",") if item.strip()}:
        if item == "reject":
            expanded |= set(REJECT_REASONS)
        elif item in ROTATION_REASONS:
            expanded.add(item)
        else:
            raise ValueError("PATH_ALIAS_ROTATE_ON entries must be direct, reject or one of "
                             + ", ".join(REJECT_REASONS))
    return tuple(reason for reason in ROTATION_REASONS if reason in expanded)


def _random_token() -> str:
    return base64.b32encode(secrets.token_bytes(17)).decode("ascii").lower()[:_TOKEN_LEN]


def new_client_id() -> str:
    return _random_token()


def valid_client_id(value: str | None) -> str | None:
    return value if value and _CLIENT_ID.fullmatch(value) else None


def client_ref(client_id: str | None) -> str | None:
    """Short, non-reversible handle for logs; the cookie value itself is never logged."""
    return hashlib.sha256(client_id.encode("ascii")).hexdigest()[:12] if client_id else None


def _cap_mode(mode: str, cap: str | None) -> str:
    return mode if cap is None or _RANK[cap] >= _RANK[mode] else cap


@dataclass(frozen=True)
class Route:
    path: str
    methods: tuple[str, ...] = ("*",)
    mode: str | None = None  # optional per-route ceiling: observe or enforce

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
        if self.mode not in (None, "observe", "enforce"):
            raise ValueError(f"Route mode must be observe or enforce: {self.path!r}")

    @property
    def parts(self) -> tuple[str, ...]:
        return tuple(self.path.lstrip("/").split("/"))

    @property
    def specificity(self) -> tuple[int, int]:
        return (sum(not _VAR.fullmatch(p) for p in self.parts), len(self.path))

    @property
    def variables(self) -> tuple[re.Match, ...]:
        return tuple(m for p in self.parts if (m := _VAR.fullmatch(p)))

    def allows(self, method: str) -> bool:
        return "*" in self.methods or method.upper() in self.methods

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
        # No lookbehind: the caller's context check decides what may precede the path
        # (a quote, an attribute "=", `${...}` or this site's own origin).
        return re.compile(rb"(" + b"".join(chunks) + b")" +
                          (rb"(?![A-Za-z0-9_-])" if wildcard else _BODY_BOUNDARY), re.I)


def _route_from_item(item) -> Route:
    if isinstance(item, str):
        return Route(item)
    if isinstance(item, dict) and isinstance(item.get("path"), str):
        methods = item.get("methods", ["*"])
        if not isinstance(methods, list) or not all(isinstance(m, str) for m in methods):
            raise ValueError("Route methods must be an array of strings")
        mode = item.get("mode")
        if mode is not None and not isinstance(mode, str):
            raise ValueError("Route mode must be a string")
        return Route(item["path"], tuple(methods), mode)
    raise ValueError("Each route must be a path or a path/methods object")


@dataclass(frozen=True)
class QueryRoute:
    """A dispatcher whose named query value is a path selecting a protected route."""
    path: str
    parameter: str

    def __post_init__(self):
        if self.path != "/":
            Route(self.path)
        if "{" in self.path or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", self.parameter):
            raise ValueError("Query routes require an exact path and a parameter name")


@dataclass(frozen=True)
class ActionRoute:
    """A dispatcher whose named query value is a function name (``/api.php?action=login``).

    Only the listed actions are protected; every other value passes unchanged.
    """
    path: str
    parameter: str
    actions: tuple[tuple[str, tuple[str, ...]], ...]  # (name, methods)
    mode: str | None = None

    def __post_init__(self):
        QueryRoute(self.path, self.parameter)
        if not self.actions or len(self.actions) > 256:
            raise ValueError("Action routes need 1..256 actions")
        names = [name for name, _ in self.actions]
        if len(set(n.lower() for n in names)) != len(names):
            raise ValueError("Action names must be unique (case-insensitively)")
        for name, methods in self.actions:
            if not _ACTION_NAME.fullmatch(name):
                raise ValueError(f"Invalid action name: {name!r}")
            Route("/x", methods)  # same method validation
        if self.mode not in (None, "observe", "enforce"):
            raise ValueError("Action route mode must be observe or enforce")

    def route_id(self, action: str) -> str:
        return f"{self.path}?{self.parameter}={action}"

    def find(self, value: str) -> str | None:
        """Configured action whose name equals ``value`` ignoring case (apps may fold case)."""
        folded = value.casefold()
        return next((name for name, _ in self.actions if name.casefold() == folded), None)

    def methods(self, action: str) -> tuple[str, ...]:
        return dict(self.actions)[action]


@dataclass(frozen=True)
class Channel:
    """An operator-declared cookieless API channel exempt from aliasing (not from other defenses)."""
    name: str
    routes: tuple[Route, ...]
    methods: tuple[str, ...] = ("*",)
    require_headers: tuple[str, ...] = ()

    def matches(self, path: str, method: str, headers: Mapping[str, str]) -> bool:
        lowered = {key.lower() for key in headers.keys()}
        return (("*" in self.methods or method.upper() in self.methods)
                and all(name in lowered for name in self.require_headers)
                and any(route.real_pattern().fullmatch(_canonical(path)) for route in self.routes))


@dataclass(frozen=True)
class RouteDocument:
    routes: tuple[Route, ...] = ()
    query_routes: tuple[QueryRoute, ...] = ()
    action_routes: tuple[ActionRoute, ...] = ()
    channels: tuple[Channel, ...] = ()
    target_ids: tuple[str, ...] = ()
    enforce_ready: bool = False


def _str_list(value, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be an array of strings")
    return value


def load_route_document(file_name: str) -> RouteDocument:
    if not file_name:
        raise ValueError("PATH_ALIAS_ROUTES_FILE is required when path aliases are enabled")
    document = json.loads(Path(file_name).read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not isinstance(document.get("routes"), list):
        raise ValueError("Path alias route file needs a routes array")
    routes = [_route_from_item(item) for item in document["routes"]]
    if not routes or len({route.path.lower() for route in routes}) != len(routes):
        raise ValueError("Path alias routes must be nonempty and unique")
    query_routes = []
    for item in document.get("query_routes", []) or []:
        if not isinstance(item, dict) or not all(isinstance(item.get(k), str) for k in ("path", "parameter")):
            raise ValueError("Query routes require path and parameter strings")
        query_routes.append(QueryRoute(item["path"], item["parameter"]))
    if not isinstance(document.get("query_routes", []), list):
        raise ValueError("query_routes must be an array")
    action_routes = []
    for item in document.get("action_routes", []) or []:
        if (not isinstance(item, dict) or not all(isinstance(item.get(k), str) for k in ("path", "parameter"))
                or not isinstance(item.get("actions"), dict)):
            raise ValueError("Action routes require path, parameter and an actions object")
        actions = tuple((name, tuple(_str_list(methods, "Action methods")))
                        for name, methods in item["actions"].items())
        action_routes.append(ActionRoute(item["path"], item["parameter"], actions, item.get("mode")))
    dispatchers = [(r.path, r.parameter) for r in query_routes] + [(r.path, r.parameter) for r in action_routes]
    if len(set(dispatchers)) != len(dispatchers):
        raise ValueError("Query routes must be unique")
    channels = []
    for item in document.get("cookieless_channels", []) or []:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            raise ValueError("Cookieless channels need a name")
        channel_routes = tuple(Route(path) for path in _str_list(item.get("routes"), "Channel routes"))
        if not channel_routes:
            raise ValueError("Cookieless channels need at least one route")
        methods = tuple(_str_list(item.get("methods", ["*"]), "Channel methods"))
        Route("/x", methods)
        headers = tuple(h.lower() for h in _str_list(item.get("require_headers", []), "Channel headers"))
        channels.append(Channel(item["name"], channel_routes, methods, headers))
    target_ids = tuple(_str_list(document.get("target_ids", []), "target_ids"))
    enforce_ready = document.get("enforce_ready", False)
    if not isinstance(enforce_ready, bool):
        raise ValueError("enforce_ready must be true or false")
    if enforce_ready:
        compatibility = document.get("compatibility")
        if (not isinstance(compatibility, dict)
                or compatibility.get("refresh_verified") is not True
                or not isinstance(compatibility.get("refresh"), str)
                or not compatibility.get("verified_flows")):
            raise ValueError("enforce_ready requires compatibility.verified_flows, compatibility.refresh "
                             "and compatibility.refresh_verified=true")
    return RouteDocument(tuple(sorted(routes, key=lambda r: r.specificity, reverse=True)),
                         tuple(query_routes), tuple(action_routes), tuple(channels),
                         target_ids, enforce_ready)


def _load_routes(file_name: str) -> tuple[Route, ...]:
    return load_route_document(file_name).routes


def _load_query_routes(file_name: str) -> tuple[QueryRoute, ...]:
    return load_route_document(file_name).query_routes


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
    rotate_on: tuple[str, ...] = DEFAULT_ROTATE_ON
    cookie_secure: bool = False
    db_url: str = ""  # postgresql://... ; optional scale-out backend, takes precedence over db_path
    db_pool_size: int = 10
    query_routes: tuple[QueryRoute, ...] = ()
    action_routes: tuple[ActionRoute, ...] = ()
    channels: tuple[Channel, ...] = ()
    target_ids: tuple[str, ...] = ()
    # Programmatic configs vouch for themselves; route files must opt in explicitly.
    enforce_ready: bool = True
    rotate_min_interval_s: float = 0.0
    pending_ttl_s: int = 300
    max_pending_clients: int = 10_000
    max_clients: int = 100_000
    stale_redirect: bool = True

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ) -> "PathAliasConfig":
        mode = environ.get("PATH_ALIAS_MODE", "off").strip().lower()
        if mode not in MODES:
            raise ValueError("PATH_ALIAS_MODE must be off, audit, observe or enforce")
        if mode == "off":
            return cls()
        try:
            epoch_s = int(environ.get("PATH_ALIAS_EPOCH_S", "1800"))
            grace = int(environ.get("PATH_ALIAS_GRACE_EPOCHS", "1"))
            max_bytes = int(environ.get("PATH_ALIAS_MAX_REWRITE_BYTES", str(8 * 1024 * 1024)))
            pool_size = int(environ.get("PATH_ALIAS_DB_POOL_SIZE", "10"))
            min_interval = float(environ.get("PATH_ALIAS_ROTATE_MIN_INTERVAL_S", "5"))
            pending_ttl = int(environ.get("PATH_ALIAS_PENDING_TTL_S", "300"))
            max_pending = int(environ.get("PATH_ALIAS_MAX_PENDING_CLIENTS", "10000"))
            max_clients = int(environ.get("PATH_ALIAS_MAX_CLIENTS", "100000"))
        except ValueError as exc:
            raise ValueError("Path alias numeric settings must be numbers") from exc
        if epoch_s < 1 or not 0 <= grace <= 10 or max_bytes < 1 or pool_size < 1:
            raise ValueError("Path alias requires epoch >= 1, grace 0..10, a positive size limit "
                             "and a positive pool size")
        if min_interval < 0 or pending_ttl < 1 or max_pending < 1 or max_clients < max_pending:
            raise ValueError("Path alias needs a non-negative rotation interval, a positive pending "
                             "TTL and max_clients >= max_pending_clients >= 1")
        prefixes = _parse_prefixes(environ.get("PATH_ALIAS_PREFIXES", ",".join(DEFAULT_PREFIXES)))
        document = load_route_document(environ.get("PATH_ALIAS_ROUTES_FILE", ""))
        for route in document.routes + tuple(r for c in document.channels for r in c.routes):
            if not any(route.path.lower() == p.rstrip("/") or route.path.lower().startswith(p) for p in prefixes):
                raise ValueError(f"Route {route.path!r} is outside protected prefixes")
        app_id = environ.get("PATH_ALIAS_APP_ID", "").strip()
        db_url = environ.get("PATH_ALIAS_DB_URL", "").strip()
        db_path = environ.get("PATH_ALIAS_DB_PATH", "").strip()
        if mode != "audit":
            if db_url:
                if not db_url.startswith(("postgresql://", "postgres://")):
                    raise ValueError("PATH_ALIAS_DB_URL must be a postgresql:// URL")
            elif not db_path or db_path == ":memory:":
                raise ValueError("Set PATH_ALIAS_DB_PATH (persistent SQLite file) or "
                                 "PATH_ALIAS_DB_URL (PostgreSQL)")
        rotate_on = _parse_triggers(environ.get("PATH_ALIAS_ROTATE_ON", ",".join(DEFAULT_ROTATE_ON)))
        flags = {}
        for name, default in (("PATH_ALIAS_COOKIE_SECURE", "false"), ("PATH_ALIAS_STALE_REDIRECT", "true")):
            value = environ.get(name, default).strip().lower()
            if value not in {"true", "false"}:
                raise ValueError(f"{name} must be true or false")
            flags[name] = value == "true"
        _configure_logger()
        return cls(mode, epoch_s, grace, prefixes, document.routes, max_bytes, app_id, db_path,
                   rotate_on, flags["PATH_ALIAS_COOKIE_SECURE"], db_url, pool_size,
                   document.query_routes, document.action_routes, document.channels,
                   document.target_ids, document.enforce_ready, min_interval, pending_ttl,
                   max_pending, max_clients, flags["PATH_ALIAS_STALE_REDIRECT"])

    @property
    def default_mode(self) -> str:
        """Mode for routes without their own ceiling and for unlisted protected paths."""
        if self.mode == "enforce" and not self.enforce_ready:
            return "observe"
        return self.mode

    def route_mode(self, route: Route | ActionRoute | None) -> str:
        """A route's own ``mode`` can only lower the file's mode (e.g. keep one route at observe)."""
        if route is None or self.mode in ("off", "audit"):
            return self.default_mode
        return _cap_mode(self.default_mode, route.mode)

    @property
    def rewrites(self) -> bool:
        return self.mode in ("observe", "enforce")

    @property
    def enforcing(self) -> bool:
        return self.default_mode == "enforce"


@dataclass(frozen=True)
class Resolution:
    kind: str  # alias | stale | direct | reject | channel | other
    upstream_path: str
    prefix: str | None = None
    alias_state: str | None = None
    reason: str | None = None
    route_id: str | None = None
    generation: int | None = None
    query_string: bytes | None = None
    mode: str | None = None  # effective mode of the route that decided this request
    owner_ok: bool = True  # the request's cookie owns the alias (for stale redirects)
    suffix: str = ""  # dynamic part after the alias (for stale redirects)


def _ambiguous(path: str) -> bool:
    # ``path`` is already percent-decoded by the server: a remaining "%" is double encoding.
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
# v4 tables: v3's path_alias_clients/path_alias_client_rows are no longer read.
_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS path_alias_client_state (
        app_id TEXT NOT NULL, client_id TEXT NOT NULL,
        generation BIGINT NOT NULL, issued_at DOUBLE PRECISION NOT NULL,
        config_hash TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL,
        confirmed INTEGER NOT NULL DEFAULT 0,
        last_event_at DOUBLE PRECISION NOT NULL DEFAULT 0,
        PRIMARY KEY(app_id, client_id))""",
    """CREATE TABLE IF NOT EXISTS path_alias_alias_rows (
        alias_route TEXT PRIMARY KEY, app_id TEXT NOT NULL,
        client_id TEXT NOT NULL, route_path TEXT NOT NULL,
        generation BIGINT NOT NULL, issued_at DOUBLE PRECISION NOT NULL,
        expires_at DOUBLE PRECISION NOT NULL,
        retired_at DOUBLE PRECISION, retired_reason TEXT,
        UNIQUE(app_id, client_id, route_path, generation))""",
    """CREATE INDEX IF NOT EXISTS path_alias_alias_rows_expiry
        ON path_alias_alias_rows(app_id, expires_at)""",
    """CREATE INDEX IF NOT EXISTS path_alias_alias_rows_client
        ON path_alias_alias_rows(app_id, client_id)""",
    """CREATE INDEX IF NOT EXISTS path_alias_client_state_pending
        ON path_alias_client_state(app_id, confirmed, created_at)""",
)


def _lock_key(*parts: str) -> int:
    """Signed 64-bit key for PostgreSQL advisory locks."""
    digest = hashlib.sha256("\0".join(parts).encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


class _SQLiteStore:
    """One database file shared by the workers of one host; writes take the database-wide lock."""

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
            # WAL + NORMAL survives process crashes; only an OS crash can lose the last commits,
            # which costs users a page reload, not a security property.
            db.execute("PRAGMA synchronous=NORMAL")
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
    """Optional shared server database for several hosts. Writers serialize per client."""

    def __init__(self, url: str, pool_size: int):
        try:
            from psycopg.rows import dict_row
            from psycopg_pool import ConnectionPool
        except ImportError as exc:  # pragma: no cover - depends on the image
            raise ValueError("PATH_ALIAS_DB_URL needs the optional PostgreSQL packages "
                             "(defense/requirements-postgres.txt)") from exc

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


def _store_errors() -> tuple[type[BaseException], ...]:
    errors: list[type[BaseException]] = [sqlite3.Error]
    try:
        import psycopg
        import psycopg_pool
        errors += [psycopg.Error, psycopg_pool.PoolTimeout]
    except ImportError:
        pass
    return tuple(errors)


_STORE_ERRORS = _store_errors()


def _guard(method):
    """Turn driver errors into AliasStoreError so callers can fail closed explicitly."""
    def wrapper(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except AliasStoreError:
            raise
        except _STORE_ERRORS as exc:
            raise AliasStoreError(type(exc).__name__) from exc
    wrapper.__name__ = method.__name__
    wrapper.__doc__ = method.__doc__
    return wrapper


class _Collect:
    """Lookup stand-in used to learn which routes a rewrite needs before touching the DB."""

    placeholder = "/" + _ALIAS_MARKER + "a" * _TOKEN_LEN

    def __init__(self):
        self.ids: set[str] = set()

    def __call__(self, route_id: str) -> str:
        self.ids.add(route_id)
        return self.placeholder


class PathAliasTable:
    """Authoritative table of per-client aliases in a database shared by every worker.

    A SQLite file (``PATH_ALIAS_DB_PATH``) is the default for one host. PostgreSQL
    (``PATH_ALIAS_DB_URL``) is the optional backend for several hosts or heavy writes.

    Each client (identified by the ``ruby_alias_client`` cookie) owns at most one alias per
    configured route, issued lazily when a response first needs it. A client stays *pending*
    until it returns its cookie; pending clients are capped and expire after
    ``pending_ttl_s``, so cookieless traffic cannot grow the table without bound.
    A client's aliases are retired immediately when it triggers a configured event
    (``rotate_client``) and, as a backstop, every ``epoch_s`` seconds with ``grace_epochs``
    of overlap. Retired rows remain as tombstones until they would have expired, so an old
    tab is told apart from a forged alias and does not trigger another rotation.
    """

    def __init__(self, cfg: PathAliasConfig):
        self.cfg = cfg
        self._routes_by_path = {route.path: route for route in cfg.routes}
        self._actions_by_id = {rule.route_id(name): (rule, name)
                               for rule in cfg.action_routes for name, _ in rule.actions}
        self._issuable = tuple(self._routes_by_path) + tuple(self._actions_by_id)
        self._lifetime = (cfg.grace_epochs + 1) * cfg.epoch_s
        self._tombstone = self._lifetime
        config_data = {
            "epoch_s": cfg.epoch_s, "grace_epochs": cfg.grace_epochs,
            "prefixes": sorted(cfg.prefixes),
            "routes": sorted((route.path, route.methods) for route in cfg.routes),
            "query_routes": sorted((rule.path, rule.parameter) for rule in cfg.query_routes),
            "action_routes": sorted((rule.path, rule.parameter, rule.actions) for rule in cfg.action_routes),
        }
        self._config_hash = hashlib.sha256(json.dumps(config_data, sort_keys=True).encode()).hexdigest()
        prefixes = b"|".join(re.escape(p.rstrip("/").encode("ascii")) for p in cfg.prefixes)
        self._body_candidates = re.compile(rb"(?:" + prefixes + rb")", re.I)
        self._body_patterns = [(route, route.body_pattern()) for route in cfg.routes]
        # String literals that end where the app appends one runtime segment:
        # `/rest/track-order` + "/" + id, `/rest/continue-code/apply/` + code, `/rest/image-captcha/`.
        # With a trailing slash the template is chosen (the app appends a segment); without one,
        # a static route of the same path wins. A template alias + "/" alone restores the static
        # route + "/" (see resolve).
        self._static_routes = {route.path.lower(): route for route in cfg.routes if not route.variables}
        self._template_prefixes = {}
        for route in cfg.routes:
            variables = route.variables
            if len(variables) == 1 and not variables[0].group(2) and _VAR.fullmatch(route.parts[-1]):
                self._template_prefixes.setdefault(("/" + "/".join(route.parts[:-1])).lower(), route)
        literals = set(self._static_routes) | set(self._template_prefixes)
        self._prefix_pattern = re.compile(
            rb"(" + b"|".join(re.escape(p.encode()) for p in sorted(literals, key=len, reverse=True))
            + rb")(/?)(?=[\x22\x27`])", re.I) if literals else None
        self._real_patterns = {route.path: route.real_pattern() for route in cfg.routes}
        dispatchers = sorted({r.path for r in cfg.query_routes + cfg.action_routes}, key=len, reverse=True)
        self._dispatch_patterns = [re.compile(re.escape(d.encode()) + _DISPATCH_TAIL)
                                   for d in dispatchers]
        # Expired rows are swept at most once per interval per process, not on every new client:
        # cookieless traffic creates a client per response that needs aliases.
        self._sweep_interval = min(cfg.epoch_s, 60, cfg.pending_ttl_s)
        self._next_sweep = 0.0
        self._store = None
        if cfg.rewrites:
            if cfg.db_url:
                self._store = _PostgresStore(cfg.db_url, cfg.db_pool_size)
            elif cfg.db_path and cfg.db_path != ":memory:":
                self._store = _SQLiteStore(cfg.db_path)
            else:
                raise ValueError("Active path aliases require a persistent SQLite file or PostgreSQL")

    # ----------------------------------------------------------------- applicability
    def applies_to(self, target_id: str | None) -> bool:
        return self.cfg.mode != "off" and (not self.cfg.target_ids or target_id in self.cfg.target_ids)

    def describe(self) -> dict:
        """Startup summary; contains configuration only, never client data."""
        return {"event": "path_alias_config", "mode": self.cfg.mode,
                "default_mode": self.cfg.default_mode, "enforce_ready": self.cfg.enforce_ready,
                "routes": len(self.cfg.routes), "query_routes": len(self.cfg.query_routes),
                "action_routes": len(self.cfg.action_routes), "channels": [c.name for c in self.cfg.channels],
                "target_ids": list(self.cfg.target_ids), "rotate_on": list(self.cfg.rotate_on),
                "backend": "postgresql" if self.cfg.db_url else ("sqlite" if self._store else "none")}

    # ----------------------------------------------------------------- storage
    def _write_lock(self, db, client_id: str) -> None:
        self._store.begin_write(db, f"{self.cfg.app_id}\0{client_id}")

    def _client(self, db, client_id: str):
        return db.execute("""SELECT generation, issued_at, config_hash, confirmed, last_event_at
            FROM path_alias_client_state WHERE app_id=? AND client_id=?""",
                          (self.cfg.app_id, client_id)).fetchone()

    def _current_rows(self, db, client_id: str, generation: int, now: float) -> dict[str, str]:
        rows = db.execute("""SELECT route_path, alias_route FROM path_alias_alias_rows
            WHERE app_id=? AND client_id=? AND generation=? AND expires_at>? AND retired_at IS NULL""",
                          (self.cfg.app_id, client_id, generation, now)).fetchall()
        return {row["route_path"]: row["alias_route"] for row in rows if row["route_path"] in self._issuable}

    def _check_capacity(self, db, now: float) -> None:
        row = db.execute("""SELECT COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN confirmed=0 THEN 1 ELSE 0 END), 0) AS pending
            FROM path_alias_client_state WHERE app_id=?""", (self.cfg.app_id,)).fetchone()
        if row["pending"] < self.cfg.max_pending_clients and row["total"] < self.cfg.max_clients:
            return
        # Expired pending clients are free capacity; reclaim them before refusing.
        self._delete_pending(db, now)
        row = db.execute("""SELECT COUNT(*) AS total,
            COALESCE(SUM(CASE WHEN confirmed=0 THEN 1 ELSE 0 END), 0) AS pending
            FROM path_alias_client_state WHERE app_id=?""", (self.cfg.app_id,)).fetchone()
        if row["pending"] >= self.cfg.max_pending_clients or row["total"] >= self.cfg.max_clients:
            raise AliasCapacityError("pending" if row["pending"] >= self.cfg.max_pending_clients else "total")

    def _delete_pending(self, db, now: float) -> None:
        cutoff = now - self.cfg.pending_ttl_s
        db.execute("""DELETE FROM path_alias_alias_rows WHERE app_id=? AND client_id IN (
            SELECT client_id FROM path_alias_client_state
            WHERE app_id=? AND confirmed=0 AND created_at<=?)""", (self.cfg.app_id, self.cfg.app_id, cutoff))
        db.execute("""DELETE FROM path_alias_client_state
            WHERE app_id=? AND confirmed=0 AND created_at<=?""", (self.cfg.app_id, cutoff))

    def _issue(self, db, client_id: str, now: float, needed: tuple[str, ...],
               returned: bool) -> tuple[dict[str, str], dict | None]:
        """Bring a client's current generation up to date. Caller holds this client's write lock."""
        app_id = self.cfg.app_id
        client = self._client(db, client_id)
        previous = client["generation"] if client else None
        if client is None:
            self._check_capacity(db, now)
            reason, generation, issued_at = "new", 0, now
            # A cookie the server does not know is a new, unconfirmed client.
            db.execute("""INSERT INTO path_alias_client_state
                (app_id, client_id, generation, issued_at, config_hash, created_at, confirmed)
                VALUES (?, ?, 0, ?, ?, ?, 0)""", (app_id, client_id, now, self._config_hash, now))
        elif client["config_hash"] != self._config_hash:
            reason, generation, issued_at = "config", previous + 1, now
            db.execute("""UPDATE path_alias_alias_rows SET retired_at=?, retired_reason='config'
                WHERE app_id=? AND client_id=? AND retired_at IS NULL""", (now, app_id, client_id))
        elif now >= client["issued_at"] + self.cfg.epoch_s:
            # Older rows keep working until their own expiry (the grace period).
            reason, generation, issued_at = "time", previous + 1, now
        else:
            reason, generation, issued_at = None, previous, client["issued_at"]
        if reason and reason != "new":
            db.execute("""UPDATE path_alias_client_state SET generation=?, issued_at=?, config_hash=?
                WHERE app_id=? AND client_id=?""", (generation, issued_at, self._config_hash, app_id, client_id))
        if client is not None and returned and not client["confirmed"]:
            db.execute("UPDATE path_alias_client_state SET confirmed=1 WHERE app_id=? AND client_id=?",
                       (app_id, client_id))
        aliases = self._current_rows(db, client_id, generation, now)
        for route_id in needed:
            if route_id in aliases:
                continue
            while True:
                alias = "/" + _ALIAS_MARKER + _random_token()
                # DO NOTHING instead of catching the error: in PostgreSQL a failed statement
                # aborts the whole transaction.
                inserted = db.execute("""INSERT INTO path_alias_alias_rows
                    (alias_route, app_id, client_id, route_path, generation, issued_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(alias_route) DO NOTHING""",
                                      (alias, app_id, client_id, route_id, generation, issued_at,
                                       issued_at + self._lifetime)).rowcount
                if inserted:
                    aliases[route_id] = alias
                    break
                # token collision: retry with fresh randomness
        rotation = None
        if reason:
            rotation = {"event": "path_alias_rotation", "ts": now, "app_id": app_id,
                        "client_ref": client_ref(client_id), "reason": reason,
                        "previous_generation": previous, "generation": generation,
                        "current_routes": len(aliases)}
        return aliases, rotation

    @_guard
    def current_aliases(self, now: float, client_id: str, routes=None, *, returned: bool = False) -> dict[str, str]:
        """Aliases this client should use now for ``routes`` (default: every configured route).

        ``returned`` means the client id arrived in the request cookie, which confirms a
        pending client. Missing aliases are issued; a client is time-rotated when due.
        """
        if not self.cfg.rewrites:
            return {}
        needed = tuple(self._issuable if routes is None else
                       (r for r in self._issuable if r in set(routes)))
        rotation = None
        with self._store.connect() as db:
            try:
                db.execute("BEGIN")
                client = self._client(db, client_id)
                if (client is not None and client["config_hash"] == self._config_hash
                        and now < client["issued_at"] + self.cfg.epoch_s
                        and (client["confirmed"] or not returned)):
                    aliases = self._current_rows(db, client_id, client["generation"], now)
                    if all(route_id in aliases for route_id in needed):
                        db.commit()
                        return {r: aliases[r] for r in needed}
                db.rollback()
                # Recheck under the write lock: another worker may have issued meanwhile.
                self._write_lock(db, client_id)
                aliases, rotation = self._issue(db, client_id, now, needed, returned)
                db.commit()
            except Exception:
                db.rollback()
                raise
            if now >= self._next_sweep:
                self._next_sweep = now + self._sweep_interval
                try:
                    self._sweep(db, now)
                except Exception as exc:  # housekeeping must not fail the issuing request
                    emit({"event": "path_alias_sweep_failed", "ts": now, "app_id": self.cfg.app_id,
                          "error": type(exc).__name__})
        if rotation:
            emit(rotation)
        return {r: aliases[r] for r in needed}

    def _sweep(self, db, now: float) -> None:
        """Drop rows past their tombstone period, idle clients and expired pending clients."""
        if not self._store.try_begin_sweep(db, self.cfg.app_id):
            return
        try:
            db.execute("DELETE FROM path_alias_alias_rows WHERE app_id=? AND expires_at<=?",
                       (self.cfg.app_id, now - self._tombstone))
            idle = now - self._lifetime - self._tombstone
            db.execute("""DELETE FROM path_alias_alias_rows WHERE app_id=? AND client_id IN (
                SELECT client_id FROM path_alias_client_state WHERE app_id=? AND issued_at<=?)""",
                       (self.cfg.app_id, self.cfg.app_id, idle))
            db.execute("DELETE FROM path_alias_client_state WHERE app_id=? AND issued_at<=?",
                       (self.cfg.app_id, idle))
            self._delete_pending(db, now)
            db.commit()
        except Exception:
            db.rollback()
            raise

    @_guard
    def stats(self) -> dict:
        """Row counts for capacity monitoring (no identifiers)."""
        if self._store is None:
            return {}
        with self._store.connect() as db:
            clients = db.execute("""SELECT COUNT(*) AS total,
                COALESCE(SUM(CASE WHEN confirmed=0 THEN 1 ELSE 0 END), 0) AS pending
                FROM path_alias_client_state WHERE app_id=?""", (self.cfg.app_id,)).fetchone()
            rows = db.execute("SELECT COUNT(*) AS n FROM path_alias_alias_rows WHERE app_id=?",
                              (self.cfg.app_id,)).fetchone()
        return {"clients": clients["total"], "pending_clients": clients["pending"], "alias_rows": rows["n"]}

    @_guard
    def rotate_client(self, client_id: str, now: float, reason: str) -> str | None:
        """Retire every alias of a known client at once; new ones are issued on next delivery.

        Returns ``"rotated"``, ``"suppressed"`` (within the minimum interval) or None (unknown client).
        """
        if not self.cfg.rewrites:
            return None
        with self._store.connect() as db:
            try:
                self._write_lock(db, client_id)
                client = self._client(db, client_id)
                if client is None:
                    db.commit()
                    return None
                if now - client["last_event_at"] < self.cfg.rotate_min_interval_s:
                    db.commit()
                    return "suppressed"
                previous = client["generation"]
                db.execute("""UPDATE path_alias_alias_rows SET retired_at=?, retired_reason='event'
                    WHERE app_id=? AND client_id=? AND retired_at IS NULL""",
                           (now, self.cfg.app_id, client_id))
                db.execute("""UPDATE path_alias_client_state SET generation=?, issued_at=?, last_event_at=?
                    WHERE app_id=? AND client_id=?""",
                           (previous + 1, now, now, self.cfg.app_id, client_id))
                db.commit()
            except Exception:
                db.rollback()
                raise
        emit({"event": "path_alias_rotation", "ts": now, "app_id": self.cfg.app_id,
              "client_ref": client_ref(client_id), "reason": reason,
              "previous_generation": previous, "generation": previous + 1,
              "current_routes": len(self._issuable)})
        return "rotated"

    # ----------------------------------------------------------------- request resolution
    def _lookup(self, alias: str):
        with self._store.connect() as db:
            row = db.execute("""SELECT r.client_id, r.route_path, r.generation, r.expires_at,
                r.retired_at, r.retired_reason,
                c.generation AS client_generation, c.issued_at AS client_issued_at,
                c.config_hash, c.confirmed
                FROM path_alias_alias_rows r LEFT JOIN path_alias_client_state c
                ON c.app_id=r.app_id AND c.client_id=r.client_id
                WHERE r.alias_route=? AND r.app_id=?""", (alias, self.cfg.app_id)).fetchone()
        return row

    def _confirm(self, client_id: str) -> None:
        with self._store.connect() as db:
            try:
                self._write_lock(db, client_id)
                db.execute("UPDATE path_alias_client_state SET confirmed=1 WHERE app_id=? AND client_id=?",
                           (self.cfg.app_id, client_id))
                db.commit()
            except Exception:
                db.rollback()
                raise

    def _row_state(self, row, now: float) -> str:
        """current | grace | stale | revoked for a row that exists."""
        if row["retired_at"] is not None:
            return "revoked" if row["retired_reason"] == "event" else "stale"
        if row["expires_at"] <= now or row["config_hash"] != self._config_hash:
            return "stale"
        current = (row["generation"] == row["client_generation"]
                   and now < row["client_issued_at"] + self.cfg.epoch_s)
        return "current" if current else "grace"

    def _owner(self, row, client_id: str | None, state: str) -> str:
        """owner | adopted | foreign. A pending owner never returned its cookie, so whoever
        holds the alias also received that cookie: binding adds nothing there, and refusing
        would only break concurrent first-visit tabs or cookieless tools."""
        if row["client_id"] == client_id:
            return "owner"
        if row["confirmed"] == 0 and state in ("current", "grace"):
            return "adopted"
        return "foreign"

    @_guard
    def resolve(self, path: str, method: str, now: float, client_id: str | None = None) -> Resolution:
        if self.cfg.mode == "off":
            return Resolution("other", path)
        default_mode = self.cfg.default_mode
        match = _ALIAS_PATH.fullmatch(path)
        if match and self._store is not None:
            base = match.group(1)
            row = self._lookup(base)
            if row is None or row["route_path"] not in self._routes_by_path:
                # Action aliases are query values only; as a path they are malformed.
                reason = "invalid_alias_arguments" if row is not None and row["route_path"] in self._actions_by_id \
                    else "unknown_alias"
                return Resolution("reject", path, reason=reason, mode=default_mode)
            route = self._routes_by_path[row["route_path"]]
            mode = self.cfg.route_mode(route)
            state = self._row_state(row, now)
            owner = self._owner(row, client_id, state)
            if owner == "foreign":
                return Resolution("reject", path, reason="foreign_alias", route_id=route.path, mode=mode)
            if not route.allows(method):
                return Resolution("reject", path, reason="method_not_allowed", route_id=route.path, mode=mode)
            suffix = path[len(base):]
            static = self._static_routes.get(("/" + "/".join(route.parts[:-1])).lower()) \
                if suffix == "/" and len(route.variables) == 1 else None
            if static is not None and not route.variables[0].group(2):
                route = static  # `/x/` from a template prefix literal is the static `/x/`
                if not route.allows(method):
                    return Resolution("reject", path, reason="method_not_allowed", route_id=route.path, mode=mode)
            real = self._restore(route, suffix)
            if real is None:
                return Resolution("reject", path, reason="invalid_alias_arguments", route_id=route.path, mode=mode)
            # Apps compose a broad alias with a runtime suffix ("/rest/admin" + "/application-version").
            # The restored path then belongs to the most specific configured route: use its methods
            # and report it as that route. (v3 refused this as shadowed_route and rotated the client,
            # which broke every other alias on the page.)
            specific = next((other for other in self.cfg.routes
                             if other.specificity > route.specificity and other.path != route.path
                             and self._real_patterns[other.path].fullmatch(real)), None)
            if specific is not None:
                if not specific.allows(method):
                    return Resolution("reject", path, reason="method_not_allowed",
                                      route_id=specific.path, mode=mode)
                route = specific
            if state in ("stale", "revoked"):
                return Resolution("stale", real, reason=f"{state}_alias", route_id=route.path,
                                  generation=row["generation"], mode=mode, owner_ok=owner == "owner",
                                  suffix=suffix)
            if owner == "owner" and row["confirmed"] == 0:
                self._confirm(client_id)
            return Resolution("alias", real, alias_state=state if owner == "owner" else "adopted",
                              route_id=route.path, generation=row["generation"], mode=mode)
        canonical = _canonical(path)
        if _ALIAS_MARKER in canonical:  # any spelling of the reserved namespace
            return Resolution("reject", path, reason="unknown_alias", mode=default_mode)
        for prefix in self.cfg.prefixes:
            if canonical == prefix.rstrip("/") or canonical.startswith(prefix):
                route = self._match_route(canonical)
                return Resolution("direct", path, prefix, route_id=route[0].path if route else None,
                                  mode=self.cfg.route_mode(route[0] if route else None))
        return Resolution("other", path)

    def _restore(self, route: Route, suffix: str) -> str | None:
        variables = route.variables
        if not variables:
            # A trailing slash is the same resource for most routers (`/rest/image-captcha/`).
            return route.path + "/" if suffix == "/" else (None if suffix else route.path)
        pieces = suffix.lstrip("/").split("/") if suffix.startswith("/") else []
        wildcard = bool(variables[-1].group(2))
        if len(pieces) < len(variables) - wildcard or (not wildcard and len(pieces) != len(variables)):
            return None
        if any(_ambiguous(piece) or (not piece and not (wildcard and suffix == "/")) for piece in pieces):
            return None
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
        return "/" + "/".join(real_parts)

    def _match_route(self, path: str) -> tuple[Route, str] | None:
        """Configured route for a real path, with the alias suffix that reproduces it."""
        for route in self.cfg.routes:
            match = self._real_patterns[route.path].fullmatch(path)
            if not match:
                continue
            values = [match.group(m.group(1)) for m in route.variables]
            suffix = "/" + "/".join(v for v in values if v) if any(values) else ""
            if route.variables and route.variables[-1].group(2) and path.endswith("/") and not suffix:
                suffix = "/"
            return route, suffix
        return None

    def _resolve_action(self, rule: ActionRoute, value: str, method: str, now: float,
                        client_id: str | None, path: str) -> tuple[Resolution, str | None]:
        """Resolution and the restored action name (None keeps the value)."""
        if _ALIAS_VALUE.fullmatch(value) and self._store is not None:
            row = self._lookup("/" + value)
            entry = self._actions_by_id.get(row["route_path"]) if row is not None else None
            if entry is None or entry[0] != rule:
                return Resolution("reject", path, reason="unknown_alias", mode=self.cfg.default_mode), None
            action = entry[1]
            mode = self.cfg.route_mode(rule)
            route_id = rule.route_id(action)
            state = self._row_state(row, now)
            owner = self._owner(row, client_id, state)
            if owner == "foreign":
                return Resolution("reject", path, reason="foreign_alias", route_id=route_id, mode=mode), None
            if "*" not in rule.methods(action) and method.upper() not in rule.methods(action):
                return Resolution("reject", path, reason="method_not_allowed", route_id=route_id, mode=mode), None
            if state in ("stale", "revoked"):
                # No redirect for actions: the safe method set is app-specific.
                return Resolution("stale", path, reason=f"{state}_alias", route_id=route_id,
                                  mode=mode, owner_ok=False), action
            if owner == "owner" and row["confirmed"] == 0:
                self._confirm(client_id)
            return Resolution("alias", path, alias_state=state if owner == "owner" else "adopted",
                              route_id=route_id, generation=row["generation"], mode=mode), action
        if _ALIAS_MARKER in value:
            return Resolution("reject", path, reason="unknown_alias", mode=self.cfg.default_mode), None
        action = rule.find(value)
        if action is not None:
            return Resolution("direct", path, route_id=rule.route_id(action),
                              mode=self.cfg.route_mode(rule)), None
        return Resolution("other", path), None

    def _classify_path_value(self, value: str, method: str, now: float,
                             client_id: str | None) -> Resolution:
        """Resolution for a path-selector query value. Unprotected values pass untouched."""
        path, _, rest = value.partition("?")
        if "#" in path:
            path = path.split("#", 1)[0]
        absolute = path if path.startswith("/") else "/" + path
        inner = self.resolve(absolute, method, now, client_id)
        if inner.kind == "other":
            return inner
        if not value.startswith("/") or "?" in value or "#" in value or value.startswith("//"):
            # A protected target spelled in a way this dispatcher may or may not accept.
            return replace(inner, kind="reject" if inner.kind in ("alias", "stale") else inner.kind,
                           reason="invalid_query_route" if inner.kind in ("alias", "stale") else inner.reason)
        return inner

    @_guard
    def resolve_request(self, path: str, query: bytes, method: str, now: float,
                        client_id: str | None = None, headers: Mapping[str, str] | None = None) -> Resolution:
        outer = self.resolve(path, method, now, client_id)
        if self.cfg.mode == "off":
            return outer
        if outer.kind == "direct" and client_id is None and headers is not None:
            for channel in self.cfg.channels:
                if channel.matches(path, method, headers):
                    return Resolution("channel", path, outer.prefix, reason=channel.name, route_id=outer.route_id)
        if outer.kind in ("direct", "reject", "stale"):
            return outer
        dispatch_path = outer.upstream_path
        rules = [r for r in self.cfg.query_routes if r.path == dispatch_path]
        actions = [r for r in self.cfg.action_routes if r.path == dispatch_path]
        if not rules and not actions:
            return outer
        # Only replace configured values. Every other byte (including duplicate keys,
        # blanks, ordering and escape spelling) stays untouched.
        fields = query.decode("ascii", errors="surrogateescape").split("&")
        selected = outer
        for rule in rules + actions:
            indexes = [i for i, item in enumerate(fields)
                       if unquote_plus(item.partition("=")[0]) == rule.parameter]
            decisions = []
            for i in indexes:
                key, separator, raw_value = fields[i].partition("=")
                value = unquote_plus(raw_value)
                if isinstance(rule, ActionRoute):
                    inner, restored = self._resolve_action(rule, value, method, now, client_id, dispatch_path)
                    replacement = (key + "=" + quote(restored, safe="")) if restored else None
                else:
                    inner = self._classify_path_value(value, method, now, client_id)
                    replacement = None
                    if inner.kind in ("alias", "stale"):
                        replacement = key + "=" + quote(inner.upstream_path, safe="" if "%" in raw_value else "/")
                decisions.append((i, inner, replacement))
            relevant = [item for item in decisions if item[1].kind != "other"]
            if not relevant:
                continue
            if len(indexes) > 1:
                return replace(outer, kind="reject", reason="duplicate_query_route", query_string=query,
                               mode=relevant[0][1].mode)
            i, inner, replacement = relevant[0]
            if inner.kind in ("direct", "reject"):
                return replace(inner, upstream_path=dispatch_path, query_string=query)
            if replacement is not None:
                fields[i] = replacement
            # A stale query value is not redirected: the Location would need the dispatcher URL.
            selected = replace(inner, upstream_path=dispatch_path,
                               owner_ok=inner.owner_ok and inner.kind != "stale")
        return replace(selected, query_string="&".join(fields).encode("ascii", errors="surrogateescape"))

    def body_selector(self, path: str, content_type: str, body: bytes, method: str, now: float,
                      client_id: str | None) -> Resolution | None:
        """Classify a routing selector carried in a form/JSON body of a configured dispatcher.

        Body routing cannot be aliased; a protected selector there is reported as ``direct``
        with reason ``body_routing_unsupported``. Values are never logged.
        """
        rules = [r for r in self.cfg.query_routes + self.cfg.action_routes if r.path == _canonical(path)
                 or r.path == path]
        if not rules or not body:
            return None
        media = content_type.split(";", 1)[0].strip().lower()
        values: dict[str, list[str]] = {}
        try:
            if media == "application/x-www-form-urlencoded":
                for key, value in parse_qsl(body.decode("utf-8"), keep_blank_values=True):
                    values.setdefault(key, []).append(value)
            elif media == "application/json" or media.endswith("+json"):
                document = json.loads(body)
                if isinstance(document, dict):
                    values = {k: [v] for k, v in document.items() if isinstance(v, str)}
            else:
                return None
        except (UnicodeDecodeError, ValueError):
            return None
        for rule in rules:
            for value in values.get(rule.parameter, []):
                if isinstance(rule, ActionRoute):
                    protected = rule.find(value) is not None or _ALIAS_MARKER in value
                    mode = self.cfg.route_mode(rule)
                else:
                    inner = self._classify_path_value(value, method, now, client_id)
                    protected, mode = inner.kind != "other", inner.mode
                if protected:
                    return Resolution("direct", path, reason="body_routing_unsupported", mode=mode)
        return None

    # ----------------------------------------------------------------- response rewriting
    def _context_ok(self, body: bytes, start: int, end: int, kind: str,
                    origins: tuple[bytes, ...]) -> tuple[bool, int]:
        """Is the URL at ``body[start:end]`` a supported URL expression? Returns (ok, url_start).

        Supported: a string literal or attribute value that *starts* with the path or with
        this site's own origin. Prose, comments and other origins are left alone.
        """
        url_start = start
        for origin in origins:
            if body.startswith(origin, max(0, start - len(origin))) and start >= len(origin):
                url_start = start - len(origin)
                break
        before = body[url_start - 1:url_start] if url_start else b""
        if kind == "json":
            if before != b'"':
                return False, start
            close = body.find(b'"', end)
            value = body[url_start:close if close != -1 else len(body)]
            return close != -1 and not re.search(rb"\s|\\u0020", value), url_start
        if before in (b'"', b"'", b"`"):
            return True, url_start
        if kind == "html" and (before == b"=" or body.endswith((b"&quot;", b"&#34;", b"&#39;"), 0, url_start)):
            return True, url_start
        if before == b"}" and url_start == start:
            # `${base}/rest/...` inside a template literal
            line_start = body.rfind(b"\n", 0, start) + 1
            return body.rfind(b"${", line_start, start) != -1, url_start
        return False, start

    def _references(self, body: bytes, kind: str, origins: tuple[bytes, ...]):
        """Supported route references: (start, end, route or None, matched bytes)."""
        found = []
        spans = []
        for pattern in self._dispatch_patterns:
            for match in pattern.finditer(body):
                ok, _ = self._context_ok(body, match.start(), match.end(), kind, origins)
                if ok:
                    found.append((match.start(), match.end(), None, match.group()))
                    spans.append((match.start(), match.end()))
        copied_until = 0
        for candidate in self._body_candidates.finditer(body):
            start = candidate.start()
            if start < copied_until or any(s <= start < e for s, e in spans):
                continue
            for route, pattern in self._body_patterns:
                match = pattern.match(body, start)
                if not match:
                    continue
                if self._context_ok(body, start, match.end(), kind, origins)[0]:
                    found.append((start, match.end(), route, match.group(1)))
                    copied_until = match.end()
                break
            else:
                match = self._prefix_pattern.match(body, start) if self._prefix_pattern else None
                if match and self._context_ok(body, start, match.end(), kind, origins)[0]:
                    base, slash = match.group(1).decode().lower(), match.group(2)
                    route = (self._template_prefixes.get(base) or self._static_routes.get(base)) if slash \
                        else (self._static_routes.get(base) or self._template_prefixes.get(base))
                    found.append((start, match.end(), route, b"\0prefix" + slash))
                    copied_until = match.end()
        return sorted(found, key=lambda item: item[0])

    def count_references(self, body: bytes, kind: str = "js", origins: tuple[bytes, ...] = ()) -> int:
        """Audit mode: how many references a rewrite would change. Uses no database."""
        collect = _Collect()
        count = 0
        for start, end, route, matched in self._references(body, kind, origins):
            if route is not None:
                count += 1
            elif self._rewrite_dispatch(matched, collect) != matched:
                count += 1
        return count

    def _rewrite_dispatch(self, matched: bytes, lookup: Callable[[str], str]) -> bytes:
        try:
            original = matched.decode("utf-8")
        except UnicodeDecodeError:
            return matched
        value = original.replace("&amp;", "&")
        rewritten = self._rewrite_url(value, "", lookup)
        if rewritten == value:
            return matched
        if "&amp;" in original:
            rewritten = rewritten.replace("&", "&amp;")
        return rewritten.encode("utf-8")

    @_guard
    def rewrite_body(self, body: bytes, now: float, client_id: str, *, kind: str = "js",
                     origins: tuple[bytes, ...] = (), returned: bool = False) -> tuple[bytes, int]:
        if not body or not self.cfg.rewrites:
            return body, 0
        refs = self._references(body, kind, origins)
        if not refs:
            return body, 0  # bodies without routes never create a client
        collect = _Collect()
        for _, _, route, matched in refs:
            if route is not None:
                collect(route.path)
            else:
                self._rewrite_dispatch(matched, collect)
        if not collect.ids:
            return body, 0
        aliases = self.current_aliases(now, client_id, collect.ids, returned=returned)
        lookup = aliases.__getitem__
        output, copied_until, count = [], 0, 0
        for start, end, route, matched in refs:
            if route is None:
                replacement = self._rewrite_dispatch(matched, lookup)
                if replacement == matched:
                    continue
            elif matched.startswith(b"\0prefix"):
                # keep the literal's own trailing slash; the app appends the rest at runtime
                replacement = aliases[route.path].encode("ascii") + matched[len(b"\0prefix"):]
            else:
                replacement = aliases[route.path].encode("ascii")
                if route.variables and not route.variables[-1].group(2):
                    captured = matched.split(b"/")
                    values = [captured[i + 1] for i, p in enumerate(route.parts)
                              if (m := _VAR.fullmatch(p)) and not m.group(2)]
                    replacement += b"/" + b"/".join(values)
            output.extend((body[copied_until:start], replacement))
            copied_until = end
            count += 1
        output.append(body[copied_until:])
        return b"".join(output), count

    def _rewrite_query(self, path: str, query: str, lookup: Callable[[str], str]) -> str:
        parameters = {r.parameter: r for r in self.cfg.query_routes + self.cfg.action_routes if r.path == path}
        if not parameters:
            return query
        fields = query.split("&")
        for i, item in enumerate(fields):
            key, separator, raw = item.partition("=")
            rule = parameters.get(unquote_plus(key)) if separator else None
            if rule is None:
                continue
            value = unquote_plus(raw)
            if isinstance(rule, ActionRoute):
                action = rule.find(value)
                if action is not None and action == value:
                    fields[i] = key + "=" + lookup(rule.route_id(action)).lstrip("/")
                continue
            if not value.startswith("/") or any(c in value for c in "?#"):
                continue
            alias = self._rewrite_url(value, "", lookup)
            if alias != value:
                fields[i] = key + "=" + quote(alias, safe="" if "%" in raw else "/")
        return "&".join(fields)

    def _rewrite_url(self, value: str, public_host: str, lookup: Callable[[str], str]) -> str:
        parts = urlsplit(value)
        if parts.netloc and parts.netloc.lower() != public_host.lower():
            return value
        query = self._rewrite_query(parts.path, parts.query, lookup)
        matched = self._match_route(parts.path)
        if matched:
            route, suffix = matched
            return urlunsplit((parts.scheme, parts.netloc, lookup(route.path) + suffix, query, parts.fragment))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment)) if query != parts.query else value

    @_guard
    def rewrite_location(self, value: str, public_host: str, now: float, client_id: str,
                         *, returned: bool = False) -> str:
        if not self.cfg.rewrites:
            return value
        collect = _Collect()
        if self._rewrite_url(value, public_host, collect) == value or not collect.ids:
            return value
        aliases = self.current_aliases(now, client_id, collect.ids, returned=returned)
        return self._rewrite_url(value, public_host, aliases.__getitem__)

    @_guard
    def redirect_target(self, resolution: Resolution, now: float, client_id: str) -> str | None:
        """Current alias path for a stale alias of this client (auto-recovery for GET/HEAD)."""
        route = self._routes_by_path.get(resolution.route_id or "")
        if route is None or resolution.reason != "stale_alias" or not resolution.owner_ok:
            return None
        return self.current_aliases(now, client_id, (route.path,), returned=True)[route.path] + resolution.suffix


def effective_mode(resolution: Resolution, cfg: PathAliasConfig) -> str:
    """The route's mode, never above the configured default (e.g. observe stays observe)."""
    return _cap_mode(cfg.default_mode, resolution.mode) if cfg.mode not in ("off", "audit") else cfg.mode


def decide(resolution: Resolution, cfg: PathAliasConfig, method: str = "GET") -> str:
    mode = effective_mode(resolution, cfg)
    if cfg.mode == "audit":
        return "audit" if resolution.kind in ("direct", "reject") else "pass"
    if resolution.kind == "alias":
        return "translate"
    if resolution.kind == "stale":
        if mode != "enforce":
            return "translate"  # observe would forward the original route anyway
        if (cfg.stale_redirect and resolution.owner_ok and resolution.reason == "stale_alias"
                and method.upper() in ("GET", "HEAD")):
            return "redirect"
        return "block"
    if resolution.kind in ("direct", "reject"):
        return "block" if mode == "enforce" else "would_block"
    return "pass"


def rotation_reason(resolution: Resolution) -> str | None:
    if resolution.kind == "direct" and resolution.reason is None:
        return "direct"
    if resolution.kind == "reject":
        return resolution.reason
    return None


def build_set_cookie(cfg: PathAliasConfig, client_id: str) -> str:
    # Session cookie: the server forgets idle clients on its own, and an unknown id is simply reissued.
    value = f"{COOKIE_NAME}={client_id}; Path=/; HttpOnly; SameSite=Lax"
    return value + ("; Secure" if cfg.cookie_secure else "")


def media_kind(content_type: str) -> str:
    media_type = content_type.split(";", 1)[0].strip().lower()
    if media_type == "text/html":
        return "html"
    if media_type == "application/json" or media_type.endswith("+json"):
        return "json"
    return "js"


def rewritable(content_type: str, content_encoding: str, status: int, method: str) -> bool:
    media_type = content_type.split(";", 1)[0].strip().lower()
    return (method.upper() != "HEAD" and status not in (204, 304)
            and content_encoding.strip().lower() in ("", "identity")
            and (media_type in REWRITABLE_TYPES or media_type.endswith("+json")))


def public_origins(host: str) -> tuple[bytes, ...]:
    if not host or not re.fullmatch(r"[A-Za-z0-9.\-:\[\]]+", host):
        return ()
    encoded = host.encode("ascii")
    return (b"https://" + encoded, b"http://" + encoded, b"//" + encoded)


def build_log(resolution: Resolution, decision: str, *, now: float, mode: str, method: str,
              path: str, headers: Mapping[str, str], upstream_status: int | None = None,
              rewrites: int = 0, rewrite_skipped: str | None = None, ua_family: str = "none",
              alias_client: str | None = None, rotation: str | None = None,
              cookie_returned: bool | None = None, target_id: str | None = None) -> dict:
    """One request record. Query strings and bodies are never included."""
    return {
        "event": "path_alias", "ts": now, "mode": mode, "effective_mode": resolution.mode,
        "client_id": {k.lower(): v for k, v in headers.items()}.get("x-client-id"),
        "alias_client_ref": client_ref(alias_client), "cookie_returned": cookie_returned,
        "target_id": target_id,
        "method": method, "path": path, "real_path": resolution.upstream_path,
        "kind": resolution.kind, "alias_state": resolution.alias_state, "decision": decision,
        "reason": resolution.reason, "rotation": rotation,
        "route_id": resolution.route_id, "generation": resolution.generation,
        "upstream_status": upstream_status, "rewrites": rewrites,
        "rewrite_skipped": rewrite_skipped, "ua_family": ua_family,
    }


def emit(log: dict) -> None:
    logging.getLogger(LOGGER_NAME).info(json.dumps(log, separators=(",", ":"), ensure_ascii=False))
