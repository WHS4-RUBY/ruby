"""Durable detector security state; runtime access never creates or repairs a DB.

Initialize once through ``initialize_security_store``. Quarantine has no expiry or
removal API. A store is bound to its first detector key: rotating that key requires
an explicit, reviewed migration rather than silently forgetting quarantined actors.
"""
from contextlib import contextmanager
import hashlib
import hmac
import os
from pathlib import Path
import re
import sqlite3
import stat
import uuid

from . import store


SCHEMA_VERSION = 1
MAX_NONCES = 8192
NONCE_RETENTION_SECONDS = 61
MAX_HIGH_RISK_ACTORS = 10000


class SecurityStoreError(RuntimeError):
    """Security state is unavailable; callers must never choose the normal route."""


_SCHEMA = """
CREATE TABLE security_meta (
    id INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
    schema_version INTEGER NOT NULL,
    store_id TEXT NOT NULL,
    key_scope TEXT
);
CREATE TABLE quarantine (
    actor_hash TEXT NOT NULL PRIMARY KEY,
    first_seen REAL NOT NULL
);
CREATE TABLE nonces (
    nonce_hash TEXT NOT NULL PRIMARY KEY,
    expires_at REAL NOT NULL
);
"""
_COLUMNS = {
    'security_meta': [('id', 'INTEGER', 1, 1), ('schema_version', 'INTEGER', 1, 0),
                      ('store_id', 'TEXT', 1, 0), ('key_scope', 'TEXT', 0, 0)],
    'quarantine': [('actor_hash', 'TEXT', 1, 1), ('first_seen', 'REAL', 1, 0)],
    'nonces': [('nonce_hash', 'TEXT', 1, 1), ('expires_at', 'REAL', 1, 0)],
}


def _path(value: str) -> Path:
    if not isinstance(value, (str, os.PathLike)) or not os.fspath(value).strip():
        raise SecurityStoreError('a persistent security store path is required')
    if os.fspath(value) == ':memory:' or os.fspath(value).startswith('file:'):
        raise SecurityStoreError('security store must be a filesystem path')
    return Path(value).expanduser().absolute()


def _file_identity(path: Path) -> tuple[int, int]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise SecurityStoreError('security store is missing or inaccessible') from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise SecurityStoreError('security store must be a regular file with mode 0600')
    return info.st_dev, info.st_ino


def _connect_existing(path: Path) -> sqlite3.Connection:
    """Open an existing store only. create=False keeps this fail-closed: a missing or
    unreadable store is an error, never a silently recreated empty one. This store keeps
    its own durability policy (synchronous=FULL, no WAL, 5s) and its own file — it is not
    merged with the audit or lure telemetry rings, whose writes would otherwise contend
    for the lock that the isolation decision needs."""
    try:
        return store.connect(path, create=False, timeout=5, journal_mode=None,
                             synchronous='FULL')
    except store.StoreError as exc:
        raise SecurityStoreError('security store is missing or unreadable') from exc


def initialize_security_store(path: str) -> None:
    """Explicitly create a new mode-0600 store; never overwrite an existing file.

    The parent directory must already exist. Runtime constructors use mode=rw and
    reject missing/corrupt/wrong-version stores instead of recreating them.
    """
    target = _path(path)
    descriptor = None
    identity = None
    connection = None
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.fchmod(descriptor, 0o600)
        created = os.fstat(descriptor)
        identity = created.st_dev, created.st_ino
        os.close(descriptor)
        descriptor = None
        connection = _connect_existing(target)
        connection.executescript('BEGIN IMMEDIATE;\n' + _SCHEMA)
        connection.execute('INSERT INTO security_meta VALUES (1, ?, ?, NULL)',
                           (SCHEMA_VERSION, uuid.uuid4().hex))
        connection.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
        connection.commit()
        if _file_identity(target) != identity:
            raise SecurityStoreError('security store changed during initialization')
    except (OSError, sqlite3.Error, SecurityStoreError) as exc:
        if connection is not None:
            connection.close()
            connection = None
        if identity is not None:
            try:
                if _file_identity(target) == identity:
                    target.unlink()
            except (OSError, SecurityStoreError):
                pass
        raise SecurityStoreError('security store initialization failed; existing files are never overwritten') from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if connection is not None:
            connection.close()


class SecurityStore:
    def __init__(self, path: str, secret: bytes):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError('detector secret must contain at least 32 bytes')
        self.path = _path(path)
        self._identity = _file_identity(self.path)
        self._scope = hmac.new(secret, b'defense-store:key-scope:v1', hashlib.sha256).hexdigest()
        self._store_id = None
        with self._transaction(bind_scope=True):
            pass

    def _check_file(self):
        if _file_identity(self.path) != self._identity:
            raise SecurityStoreError('security store was replaced')

    def _validate(self, connection, *, bind_scope):
        if connection.execute('PRAGMA user_version').fetchone()[0] != SCHEMA_VERSION:
            raise SecurityStoreError('unsupported security store schema')
        objects = connection.execute(
            "SELECT name, type FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' AND type != 'index'"
        ).fetchall()
        if set(objects) != {(name, 'table') for name in _COLUMNS}:
            raise SecurityStoreError('unexpected security store schema')
        for name, expected in _COLUMNS.items():
            columns = connection.execute(f'PRAGMA table_info({name})').fetchall()
            if [(r[1], r[2], r[3], r[5]) for r in columns] != expected:
                raise SecurityStoreError('unexpected security store columns')
        if connection.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            raise SecurityStoreError('security store integrity check failed')
        rows = connection.execute('SELECT id, schema_version, store_id, key_scope FROM security_meta').fetchall()
        if (len(rows) != 1 or rows[0][0:2] != (1, SCHEMA_VERSION)
                or not isinstance(rows[0][2], str) or not re.fullmatch('[0-9a-f]{32}', rows[0][2])):
            raise SecurityStoreError('invalid security store metadata')
        _, _, store_id, scope = rows[0]
        if self._store_id is not None and self._store_id != store_id:
            raise SecurityStoreError('security store identity changed')
        if scope is None and bind_scope:
            if (connection.execute('SELECT COUNT(*) FROM quarantine').fetchone()[0]
                    or connection.execute('SELECT COUNT(*) FROM nonces').fetchone()[0]):
                raise SecurityStoreError('unbound security store contains existing state')
            connection.execute('UPDATE security_meta SET key_scope=? WHERE id=1', (self._scope,))
        elif not isinstance(scope, str) or not hmac.compare_digest(scope, self._scope):
            raise SecurityStoreError('security store key scope mismatch; explicit migration required')
        self._store_id = store_id

    @contextmanager
    def _transaction(self, *, bind_scope=False):
        connection = None
        try:
            self._check_file()
            connection = _connect_existing(self.path)
            connection.execute('BEGIN IMMEDIATE')
            self._check_file()
            self._validate(connection, bind_scope=bind_scope)
            yield connection
            self._check_file()
            connection.commit()
            self._check_file()
        except (OSError, sqlite3.Error) as exc:
            raise SecurityStoreError('security store is unavailable') from exc
        finally:
            if connection is not None:
                connection.close()  # rolls back any transaction that failed before commit

    def should_isolate(self, actor_hash: str, suspicious: bool, *, max_actors: int, now: float) -> bool:
        with self._transaction() as connection:
            if connection.execute('SELECT 1 FROM quarantine WHERE actor_hash=?', (actor_hash,)).fetchone():
                isolate = True
            else:
                # High-risk sticky markers share this durable table but do not
                # consume the detector's ordinary Agent quarantine capacity.
                count = connection.execute(
                    "SELECT COUNT(*) FROM quarantine WHERE actor_hash NOT LIKE 'high:%'"
                ).fetchone()[0]
                if count >= max_actors:
                    # Permanent quarantine cannot evict old records to admit new actors.
                    raise SecurityStoreError('quarantine capacity reached')
                isolate = suspicious
                if isolate:
                    connection.execute('INSERT INTO quarantine VALUES (?, ?)', (actor_hash, now))
        return isolate

    def mark_high_risk(self, marker: str, *, now: float) -> None:
        if not re.fullmatch(r'high:[0-9a-f]{64}', marker):
            raise ValueError('invalid high-risk actor marker')
        with self._transaction() as connection:
            if connection.execute('SELECT 1 FROM quarantine WHERE actor_hash=?',
                                  (marker,)).fetchone():
                return
            count = connection.execute(
                "SELECT COUNT(*) FROM quarantine WHERE actor_hash LIKE 'high:%'"
            ).fetchone()[0]
            if count >= MAX_HIGH_RISK_ACTORS:
                raise SecurityStoreError('high-risk actor capacity reached')
            connection.execute('INSERT INTO quarantine VALUES (?, ?)', (marker, now))

    def is_high_risk(self, marker: str) -> bool:
        if not re.fullmatch(r'high:[0-9a-f]{64}', marker):
            raise ValueError('invalid high-risk actor marker')
        with self._transaction() as connection:
            return bool(connection.execute('SELECT 1 FROM quarantine WHERE actor_hash=?',
                                           (marker,)).fetchone())

    def consume_nonce(self, nonce_hash: str, *, now: float) -> bool:
        with self._transaction() as connection:
            connection.execute('DELETE FROM nonces WHERE expires_at <= ?', (now,))
            duplicate = connection.execute('SELECT 1 FROM nonces WHERE nonce_hash=?', (nonce_hash,)).fetchone()
            count = connection.execute('SELECT COUNT(*) FROM nonces').fetchone()[0]
            accepted = duplicate is None and count < MAX_NONCES
            if accepted:
                connection.execute('INSERT INTO nonces VALUES (?, ?)',
                                   (nonce_hash, now + NONCE_RETENTION_SECONDS))
        return accepted
