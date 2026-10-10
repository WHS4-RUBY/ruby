"""감사 링과 미끼 링이 텔레메트리 DB 하나를 쓰고, 구 파일 두 개가 그리로 옮겨지는지."""
import sqlite3

import pytest

from defense import store
from defense.audit import Audit
from defense.cli import migrate_telemetry
from defense.lure_metrics import LureMetrics

SECRET = b'k' * 32


def _legacy_audit(path, rows):
    db = sqlite3.connect(path)
    db.execute('CREATE TABLE events (id INTEGER PRIMARY KEY, time TEXT NOT NULL, '
               'kind TEXT NOT NULL, run TEXT NOT NULL, session TEXT, trace TEXT, '
               'detail TEXT NOT NULL)')
    for index in range(rows):
        db.execute('INSERT INTO events(time,kind,run,session,trace,detail) VALUES (?,?,?,?,?,?)',
                   ('2026-01-01T00:00:00+00:00', 'request', 'run-1', None, None, '{}'))
    db.commit()
    db.close()


def _legacy_lure(path, rows):
    db = sqlite3.connect(path)
    db.execute('CREATE TABLE lure_events (id INTEGER PRIMARY KEY, time TEXT NOT NULL, '
               'actor TEXT NOT NULL, kind TEXT NOT NULL, stage TEXT NOT NULL)')
    for index in range(rows):
        db.execute('INSERT INTO lure_events(time,actor,kind,stage) VALUES (?,?,?,?)',
                   ('2026-01-01T00:00:00+00:00', 'a' * 24, 'robots', ''))
    db.commit()
    db.close()


def _tables(path):
    db = sqlite3.connect(path)
    try:
        return {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        db.close()


def test_both_rings_share_one_file_with_independent_components(tmp_path):
    telemetry = tmp_path / 'telemetry.sqlite3'
    audit = Audit(str(telemetry), 10)
    metrics = LureMetrics(str(telemetry), SECRET)
    try:
        audit.emit('request', 'run-1', 'a' * 32, goal='g')
        metrics.emit('actor-a', 'robots')
    finally:
        audit.close()
        metrics.close()

    assert {'events', 'lure_events', store.MIGRATIONS_TABLE} <= _tables(telemetry)
    db = sqlite3.connect(telemetry)
    try:
        components = {row[0] for row in db.execute(
            f'SELECT component FROM {store.MIGRATIONS_TABLE}')}
        assert components == {'overlay_audit', 'overlay_lure'}
        assert db.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 1
        assert db.execute('SELECT COUNT(*) FROM lure_events').fetchone()[0] == 1
    finally:
        db.close()
    assert telemetry.stat().st_mode & 0o777 == 0o600


def test_each_ring_stays_bounded(tmp_path):
    telemetry = tmp_path / 'telemetry.sqlite3'
    audit = Audit(str(telemetry), 3)
    metrics = LureMetrics(str(telemetry), SECRET, max_rows=2)
    try:
        for _ in range(6):
            audit.emit('request', 'run-1')
            metrics.emit('actor-a', 'api')
    finally:
        audit.close()
        metrics.close()
    db = sqlite3.connect(telemetry)
    try:
        assert db.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 3
        assert db.execute('SELECT COUNT(*) FROM lure_events').fetchone()[0] == 2
    finally:
        db.close()


def test_nothing_to_migrate_is_a_success(tmp_path):
    assert migrate_telemetry(str(tmp_path / 'telemetry.sqlite3'), tmp_path) == 0
    assert not (tmp_path / 'telemetry.sqlite3').exists()


def test_old_rings_move_into_the_telemetry_database(tmp_path):
    _legacy_audit(tmp_path / 'events.sqlite3', 4)
    _legacy_lure(tmp_path / 'lure-events.sqlite3', 3)
    telemetry = tmp_path / 'telemetry.sqlite3'

    assert migrate_telemetry(str(telemetry), tmp_path) == 7
    db = sqlite3.connect(telemetry)
    try:
        assert db.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 4
        assert db.execute('SELECT COUNT(*) FROM lure_events').fetchone()[0] == 3
    finally:
        db.close()
    for name in ('events.sqlite3', 'lure-events.sqlite3'):
        assert not (tmp_path / name).exists()
        assert (tmp_path / f'{name}.migrated').exists()


def test_rerunning_the_migration_does_not_duplicate_rows(tmp_path):
    _legacy_audit(tmp_path / 'events.sqlite3', 2)
    telemetry = tmp_path / 'telemetry.sqlite3'
    migrate_telemetry(str(telemetry), tmp_path)
    before = sqlite3.connect(telemetry).execute('SELECT COUNT(*) FROM events').fetchone()[0]
    assert migrate_telemetry(str(telemetry), tmp_path) == 0
    after = sqlite3.connect(telemetry).execute('SELECT COUNT(*) FROM events').fetchone()[0]
    assert before == after == 2


def test_a_dry_run_changes_nothing(tmp_path):
    _legacy_lure(tmp_path / 'lure-events.sqlite3', 1)
    telemetry = tmp_path / 'telemetry.sqlite3'
    assert migrate_telemetry(str(telemetry), tmp_path, dry_run=True) == 0
    assert (tmp_path / 'lure-events.sqlite3').exists()
    assert not telemetry.exists()


def test_the_security_store_is_never_part_of_the_telemetry_file(tmp_path):
    # 격리 판단 경로가 텔레메트리 쓰기 락과 다투지 않아야 한다.
    from defense.security_store import initialize_security_store
    security = tmp_path / 'security.sqlite3'
    initialize_security_store(str(security))
    telemetry = tmp_path / 'telemetry.sqlite3'
    audit = Audit(str(telemetry), 5)
    try:
        audit.emit('request', 'run-1')
    finally:
        audit.close()
    assert security.exists() and telemetry.exists()
    assert 'quarantine' not in _tables(telemetry)
    assert 'events' not in _tables(security)
