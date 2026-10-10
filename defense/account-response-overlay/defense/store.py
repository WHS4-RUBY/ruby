"""One connection, transaction and migration layer for this repository's SQLite stores.

Before this module each store opened SQLite its own way: path-alias used WAL with a
10s busy timeout, the overlay route store used a 2s timeout and `PRAGMA user_version`,
the security store used `synchronous=FULL` with a mode=rw URI, the audit and lure
rings used `journal_mode=DELETE` with sub-second timeouts, and the sidecar used plain
`sqlite3.connect` plus a `try: ALTER TABLE / except OperationalError` pass for schema
changes. Three different schema-evolution strategies coexisted and none recorded what
had been applied.

Migrations here are component-scoped, so one database file can host several
components that version independently — that is what lets a container collapse its
stores into one file without entangling their schema histories.

The editable original is `shared/py/store.py`. Service trees carry generated copies
because every image's build context is a subdirectory and Docker forbids `COPY ../`;
`scripts/sync-shared.sh` regenerates them and a contract test fails on drift.
"""
from contextlib import closing, contextmanager
import os
from pathlib import Path
import sqlite3
import time

MIGRATIONS_TABLE = 'schema_migrations'
_MIGRATIONS_DDL = (
    f'CREATE TABLE IF NOT EXISTS {MIGRATIONS_TABLE} ('
    'component TEXT NOT NULL, version INTEGER NOT NULL, applied_at REAL NOT NULL, '
    f'PRIMARY KEY(component, version))'
)


class StoreError(RuntimeError):
    """A store could not be opened, migrated or validated."""


def connect(path, *, timeout: float = 10.0, journal_mode: str = 'WAL',
            synchronous: str = 'NORMAL', create: bool = True, private: bool = False,
            row_factory=None, check_same_thread: bool = True,
            max_page_count: int | None = None) -> sqlite3.Connection:
    """Open one store with explicit durability settings.

    `create=False` opens an existing file only (mode=rw), so a store that must never
    be silently re-created keeps failing closed. `private=True` enforces mode 0600,
    creating the parent directory with 0700 when this call creates the file.
    """
    target = Path(path)
    if create:
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700 if private else 0o777)
        existed = target.exists()
        conn = sqlite3.connect(str(target), timeout=timeout, isolation_level=None,
                               check_same_thread=check_same_thread)
        if private and not existed:
            os.chmod(target, 0o600)
    else:
        if not target.exists():
            raise StoreError(f'store does not exist: {target}')
        conn = sqlite3.connect(f'{target.as_uri()}?mode=rw', uri=True, timeout=timeout,
                               isolation_level=None, check_same_thread=check_same_thread)
    if row_factory is not None:
        conn.row_factory = row_factory
    try:
        conn.execute(f'PRAGMA busy_timeout={int(timeout * 1000)}')
        if journal_mode:
            conn.execute(f'PRAGMA journal_mode={journal_mode}')
        if synchronous:
            conn.execute(f'PRAGMA synchronous={synchronous}')
        if max_page_count is not None:
            conn.execute(f'PRAGMA max_page_count={int(max_page_count)}')
    except sqlite3.Error as exc:
        conn.close()
        raise StoreError(f'cannot configure store at {target}: {exc}') from exc
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection, *, write: bool = False):
    """One explicit transaction. Writers take the database lock immediately."""
    conn.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
    try:
        yield conn
    except BaseException:
        conn.rollback()
        raise
    else:
        conn.commit()


def applied_versions(conn: sqlite3.Connection, component: str) -> frozenset[int]:
    conn.execute(_MIGRATIONS_DDL)
    rows = conn.execute(f'SELECT version FROM {MIGRATIONS_TABLE} WHERE component=?',
                        (component,)).fetchall()
    return frozenset(int(row[0]) for row in rows)


def apply_migrations(conn: sqlite3.Connection, component: str, migrations, *,
                     now=time.time) -> tuple[int, ...]:
    """Run the migrations this component has not recorded yet, in version order.

    `migrations` is an ordered sequence of `(version, (statement, ...))`. Each version
    is applied inside one transaction together with its bookkeeping row, so a crash
    never leaves a half-applied version recorded as done. Re-running is a no-op.
    """
    ordered = sorted(migrations, key=lambda item: item[0])
    versions = [version for version, _ in ordered]
    if len(set(versions)) != len(versions):
        raise StoreError(f'duplicate migration version for {component}')
    if any(version < 1 for version in versions):
        raise StoreError(f'migration versions for {component} must start at 1')
    done = applied_versions(conn, component)
    newly: list[int] = []
    for version, statements in ordered:
        if version in done:
            continue
        try:
            with transaction(conn, write=True):
                for statement in statements:
                    conn.execute(statement)
                conn.execute(
                    f'INSERT INTO {MIGRATIONS_TABLE}(component,version,applied_at) VALUES (?,?,?)',
                    (component, version, float(now())))
        except sqlite3.Error as exc:
            raise StoreError(f'migration {component} v{version} failed: {exc}') from exc
        newly.append(version)
    return tuple(newly)


@contextmanager
def opened(path, **kwargs):
    """`connect` as a context manager that always closes the connection."""
    with closing(connect(path, **kwargs)) as conn:
        yield conn
