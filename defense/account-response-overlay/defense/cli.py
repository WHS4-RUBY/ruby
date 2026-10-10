"""Local defender control plane; deliberately has no HTTP equivalent."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
from . import store
from .audit import Audit, COMPONENT as AUDIT_COMPONENT, MIGRATIONS as AUDIT_MIGRATIONS
from .config import load
from .lure_metrics import COMPONENT as LURE_COMPONENT, MIGRATIONS as LURE_MIGRATIONS
from .security_store import initialize_security_store

# 구 파일 -> 통합 텔레메트리 DB. (파일 이름, 테이블, 컴포넌트, 마이그레이션)
_TELEMETRY_SOURCES = (
    ('events.sqlite3', 'events', AUDIT_COMPONENT, AUDIT_MIGRATIONS),
    ('lure-events.sqlite3', 'lure_events', LURE_COMPONENT, LURE_MIGRATIONS),
)


def migrate_telemetry(target_path: str, source_dir: Path, *, dry_run: bool = False) -> int:
    """구 감사·미끼 링 파일의 행을 통합 텔레메트리 DB 로 옮긴다.

    구 파일이 없으면 아무것도 하지 않는다(새로 시작하는 배포). 옮긴 파일은
    <이름>.migrated 로 바꿔 두므로 재실행해도 안전하다. 멱등하다.
    """
    pending = [spec for spec in _TELEMETRY_SOURCES if (source_dir / spec[0]).exists()]
    if not pending:
        print(f'옮길 구 텔레메트리 파일이 없다 ({source_dir}). {target_path} 에서 새로 시작한다.')
        return 0
    if dry_run:
        for name, table, _, _ in pending:
            print(f'[dry-run] {name} ({table}) -> {Path(target_path).name} ({table})')
        return 0
    moved_total = 0
    with store.opened(target_path, timeout=10.0, journal_mode='DELETE', synchronous=None,
                      private=True) as target:
        for name, table, component, migrations in pending:
            store.apply_migrations(target, component, migrations)
            source_path = source_dir / name
            with store.opened(source_path, create=False, timeout=10.0, journal_mode=None,
                              synchronous=None) as source:
                rows = source.execute(f'SELECT * FROM {table}').fetchall()
                columns = [column[0] for column in source.execute(
                    f'SELECT * FROM {table} LIMIT 0').description]
            if rows:
                placeholders = ','.join('?' for _ in columns)
                with store.transaction(target, write=True):
                    for row in rows:
                        # id 는 그대로 옮긴다. 이미 있는 id 는 건너뛴다(재실행·부분 이전).
                        target.execute(
                            f'INSERT OR IGNORE INTO {table}({",".join(columns)}) '
                            f'VALUES ({placeholders})', tuple(row))
            moved_total += len(rows)
            print(f'{name} ({table}) -> {table}: {len(rows)}행')
            for suffix in ('', '-wal', '-shm'):
                candidate = Path(str(source_path) + suffix)
                if candidate.exists():
                    candidate.rename(str(candidate) + '.migrated')
    print(f'완료. 구 파일은 .migrated 로 바꿔 두었다. 통합 텔레메트리 DB: {target_path}')
    return moved_total


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
    migrate = sub.add_parser('migrate-telemetry',
                             help='Move the old audit and lure rings into one telemetry database')
    migrate.add_argument('--source-dir', default=None,
                         help='Directory holding events.sqlite3 / lure-events.sqlite3')
    migrate.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    if args.command == 'init-security':
        initialize_security_store(args.database)
        print('Created security database; preserve it across restarts and backups.')
        return
    cfg = load(args.config)
    if args.command == 'migrate-telemetry':
        source = Path(args.source_dir) if args.source_dir else Path(cfg.audit_path).parent
        migrate_telemetry(cfg.audit_path, source, dry_run=args.dry_run)
        return
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
