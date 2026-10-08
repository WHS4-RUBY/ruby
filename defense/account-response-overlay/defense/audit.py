"""Defender-only bounded audit store. Never exposed through public HTTP routes."""
from datetime import datetime, timezone
from pathlib import Path
import json
import sqlite3
import os


class Audit:
    def __init__(self, path: str, max_rows: int):
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(path, timeout=0.2)
        os.chmod(path, 0o600)
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('PRAGMA max_page_count=16384')  # ~64 MiB at default 4 KiB page size.
        self.db.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, '
                        'time TEXT NOT NULL, kind TEXT NOT NULL, run TEXT NOT NULL, '
                        'session TEXT, trace TEXT, detail TEXT NOT NULL)')
        self.db.commit()
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
