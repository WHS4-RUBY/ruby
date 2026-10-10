"""Defender-only bounded audit store. Never exposed through public HTTP routes.

Shares one telemetry database with the lure ring. Both are bounded rings whose rows
only the defender reads, so they are cheap to keep together; the security store stays
in its own file because the isolation decision must not contend for this lock.
A failed audit write returns 503 (core.py), so the timeout here stays as tight as
before — the lure ring's writes are a single INSERT plus a bounded DELETE, orders of
magnitude shorter than this timeout.
"""
from datetime import datetime, timezone
import json

from . import store

COMPONENT = 'overlay_audit'
MIGRATIONS = (
    (1, ('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, '
         'time TEXT NOT NULL, kind TEXT NOT NULL, run TEXT NOT NULL, '
         'session TEXT, trace TEXT, detail TEXT NOT NULL)',)),
)


class Audit:
    def __init__(self, path: str, max_rows: int):
        self.db = store.connect(path, timeout=0.2, journal_mode='DELETE', synchronous=None,
                                private=True, max_page_count=16384)  # ~64 MiB at 4 KiB pages
        store.apply_migrations(self.db, COMPONENT, MIGRATIONS)
        self.max_rows = max_rows

    def emit(self, kind: str, run: str, session: str | None = None,
             trace: str | None = None, **detail):
        payload = json.dumps(detail, ensure_ascii=True, separators=(',', ':'))
        if len(payload) > 2048:
            raise ValueError('audit record exceeds limit')
        with self.db:
            self.db.execute('INSERT INTO events(time,kind,run,session,trace,detail) VALUES (?,?,?,?,?,?)',
                            (datetime.now(timezone.utc).isoformat(), kind, run, session, trace, payload))
            self.db.execute('DELETE FROM events WHERE id <= '
                            '(SELECT max(id) - ? FROM events)', (self.max_rows,))

    def close(self):
        self.db.close()
