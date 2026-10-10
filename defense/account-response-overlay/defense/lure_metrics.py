"""Bounded, defender-only Agent lure and decoy progression measurements."""
from datetime import datetime, timezone
import hashlib
import hmac
import re
import sqlite3

from . import store
from .decoy_paths import decoy_stage  # noqa: F401  (기존 import 경로 유지)


COMPONENT = 'overlay_lure'
MIGRATIONS = (
    (1, ('CREATE TABLE IF NOT EXISTS lure_events ('
         'id INTEGER PRIMARY KEY, time TEXT NOT NULL, actor TEXT NOT NULL, '
         'kind TEXT NOT NULL, stage TEXT NOT NULL)',)),
)


class LureMetrics:
    """Shares the telemetry database with the audit ring. Writes never change a
    response or an isolation decision, so every SQLite error here is swallowed."""

    def __init__(self, path: str, secret: bytes, max_rows: int = 50000):
        self.db = store.connect(path, timeout=1.0, journal_mode=None, synchronous=None,
                                private=True, check_same_thread=False, max_page_count=16384)
        store.apply_migrations(self.db, COMPONENT, MIGRATIONS)
        self.secret = secret
        self.max_rows = max_rows

    def emit(self, actor: str, kind: str, stage: str = ''):
        if kind not in {'login', 'robots', 'recon', 'api', 'decoy_entry', 'decoy_step'}:
            raise ValueError('unknown lure event')
        if len(stage) > 80 or not re.fullmatch(r'[a-zA-Z0-9_:/.-]*', stage):
            raise ValueError('invalid lure stage')
        identifier = hmac.new(self.secret, actor.encode(), hashlib.sha256).hexdigest()[:24]
        try:
            with self.db:
                self.db.execute('INSERT INTO lure_events(time,actor,kind,stage) VALUES (?,?,?,?)',
                                (datetime.now(timezone.utc).isoformat(), identifier, kind, stage))
                self.db.execute('DELETE FROM lure_events WHERE id <= '
                                '(SELECT max(id) - ? FROM lure_events)', (self.max_rows,))
        except sqlite3.Error:
            # Telemetry must never change the response or the isolation decision.
            pass

    def close(self):
        self.db.close()
