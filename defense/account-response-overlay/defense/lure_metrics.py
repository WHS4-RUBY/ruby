"""Bounded, defender-only Agent lure and decoy progression measurements."""
from datetime import datetime, timezone
import hashlib
import hmac
import os
from pathlib import Path
import re
import sqlite3


class LureMetrics:
    def __init__(self, path: str, secret: bytes, max_rows: int = 50000):
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(path, timeout=1.0, check_same_thread=False)
        os.chmod(path, 0o600)
        self.db.execute('PRAGMA max_page_count=16384')
        self.db.execute('CREATE TABLE IF NOT EXISTS lure_events ('
                        'id INTEGER PRIMARY KEY, time TEXT NOT NULL, actor TEXT NOT NULL, '
                        'kind TEXT NOT NULL, stage TEXT NOT NULL)')
        self.db.commit()
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


def decoy_stage(path: str) -> str:
    """Record only the path family and numeric step, never tokens or payloads."""
    match = re.match(r'^/ops/(recovery|archive|service)(?:/([^/]+))?(?:/([^/]+))?', path)
    if match:
        family, branch, step = match.groups()
        if branch == 'accounts' and step and step.isdecimal():
            return f'{family}:accounts:{step[:9]}'
        return f'{family}:{branch}' if branch and re.fullmatch(r'[a-zA-Z_-]+', branch) else family
    return 'ftp' if path.startswith('/ftp') else 'decoy'
