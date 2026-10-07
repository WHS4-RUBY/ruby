"""Local defender control plane; deliberately has no HTTP equivalent."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
from .audit import Audit
from .config import load
from .security_store import initialize_security_store


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default='config/default.toml')
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init')
    init.add_argument('--key', default='state/session.key')
    init_security = sub.add_parser('init-security', help='Create a NEW durable isolation/replay database')
    init_security.add_argument('--database', default='state/security.sqlite3')
    observe = sub.add_parser('observe')
    observe.add_argument('--kind', choices=['agent_completion', 'origin_goal'], required=True)
    observe.add_argument('--session', required=True)
    observe.add_argument('--value', choices=['true', 'false', 'unknown'], required=True)
    observe.add_argument('--goal', required=True)
    observe.add_argument('--evidence', required=True, help='Defender evidence reference, not raw secrets')
    events = sub.add_parser('events')
    events.add_argument('--limit', type=int, default=50)
    events.add_argument('--all-runs', action='store_true')
    args = parser.parse_args()
    if args.command == 'init-security':
        initialize_security_store(args.database)
        print('Created security database; preserve it across restarts and backups.')
        return
    cfg = load(args.config)
    if args.command == 'init':
        path = Path(args.key)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(secrets.token_bytes(32))
        print(f'Created {path}; keep this file private.')
    elif args.command == 'observe':
        if not re.fullmatch('[0-9a-f]{32}', args.session) or len(args.evidence) > 256 or len(args.goal) > 64:
            parser.error('invalid session or evidence/goal length')
        audit = Audit(cfg.audit_path, cfg.limits.audit_rows)
        try:
            audit.emit(args.kind, cfg.run_id, args.session,
                       value={'true': True, 'false': False, 'unknown': None}[args.value],
                       goal=args.goal, evidence=args.evidence, source='defender_observation')
        finally:
            audit.close()
    else:
        if not 1 <= args.limit <= 1000:
            parser.error('limit must be 1..1000')
        db = sqlite3.connect(Path(cfg.audit_path).resolve().as_uri() + '?mode=ro', uri=True)
        db.row_factory = sqlite3.Row
        try:
            rows = db.execute('SELECT * FROM events' + ('' if args.all_runs else ' WHERE run=?') +
                              ' ORDER BY id DESC LIMIT ?', (args.limit,) if args.all_runs else
                              (cfg.run_id, args.limit)).fetchall()
            for row in reversed(rows):
                item = dict(row)
                item['detail'] = json.loads(item['detail'])
                print(json.dumps(item, ensure_ascii=False))
        finally:
            db.close()


if __name__ == '__main__':
    main()
