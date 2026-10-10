"""공용 SQLite 접근 계층: 연결 설정, 트랜잭션, 컴포넌트별 마이그레이션."""
import importlib
import importlib.util
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

from defense.app import store

OVERLAY_ROOT = Path(__file__).resolve().parents[2] / 'defense/account-response-overlay'


def _load_overlay_module(name: str):
    """오버레이 패키지를 별칭으로 import 한다(패키지 이름이 defense 라서 가려진다)."""
    alias = 'overlay_pkg_store_test'
    if alias not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            alias, OVERLAY_ROOT / 'defense/__init__.py',
            submodule_search_locations=[str(OVERLAY_ROOT / 'defense')])
        module = importlib.util.module_from_spec(spec)
        sys.modules[alias] = module
        spec.loader.exec_module(module)
    return importlib.import_module(f'{alias}.{name}')


V1 = (1, ('CREATE TABLE widget(id INTEGER PRIMARY KEY, name TEXT NOT NULL)',))
V2 = (2, ('ALTER TABLE widget ADD COLUMN size INTEGER NOT NULL DEFAULT 0',))


class ConnectionSettings(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def test_pragmas_come_from_the_arguments(self):
        with store.opened(self.dir / 'a.sqlite3', timeout=3.5) as conn:
            self.assertEqual('wal', conn.execute('PRAGMA journal_mode').fetchone()[0])
            self.assertEqual(3500, conn.execute('PRAGMA busy_timeout').fetchone()[0])
            self.assertEqual(1, conn.execute('PRAGMA synchronous').fetchone()[0])

    def test_a_store_can_ask_for_full_durability_and_no_wal(self):
        with store.opened(self.dir / 'b.sqlite3', journal_mode='DELETE',
                          synchronous='FULL') as conn:
            self.assertEqual('delete', conn.execute('PRAGMA journal_mode').fetchone()[0])
            self.assertEqual(2, conn.execute('PRAGMA synchronous').fetchone()[0])

    def test_a_private_store_is_created_mode_0600(self):
        target = self.dir / 'nested/private.sqlite3'
        with store.opened(target, private=True):
            pass
        self.assertEqual(0o600, target.stat().st_mode & 0o777)
        self.assertEqual(0o700, target.parent.stat().st_mode & 0o777)

    def test_a_store_that_must_not_be_created_fails_closed(self):
        missing = self.dir / 'absent.sqlite3'
        with self.assertRaises(store.StoreError):
            store.connect(missing, create=False)
        self.assertFalse(missing.exists(), '열기 실패가 파일을 만들어서는 안 된다')

    def test_an_existing_store_opens_without_creating(self):
        target = self.dir / 'present.sqlite3'
        with store.opened(target):
            pass
        with store.opened(target, create=False) as conn:
            self.assertEqual(1, conn.execute('SELECT 1').fetchone()[0])

    def test_a_page_limit_can_bound_a_ring_buffer(self):
        with store.opened(self.dir / 'ring.sqlite3', max_page_count=16384) as conn:
            self.assertEqual(16384, conn.execute('PRAGMA max_page_count').fetchone()[0])


class Transactions(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.conn = store.connect(self.dir / 'tx.sqlite3')
        self.conn.execute('CREATE TABLE t(v INTEGER)')

    def tearDown(self):
        self.conn.close()

    def test_a_write_commits(self):
        with store.transaction(self.conn, write=True):
            self.conn.execute('INSERT INTO t(v) VALUES (1)')
        self.assertEqual(1, self.conn.execute('SELECT COUNT(*) FROM t').fetchone()[0])

    def test_a_failed_write_rolls_back(self):
        with self.assertRaises(ValueError):
            with store.transaction(self.conn, write=True):
                self.conn.execute('INSERT INTO t(v) VALUES (2)')
                raise ValueError('boom')
        self.assertEqual(0, self.conn.execute('SELECT COUNT(*) FROM t').fetchone()[0])


class Migrations(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.conn = store.connect(self.dir / 'm.sqlite3')

    def tearDown(self):
        self.conn.close()

    def test_migrations_apply_once_and_are_recorded(self):
        self.assertEqual((1, 2), store.apply_migrations(self.conn, 'widgets', [V1, V2]))
        self.assertEqual(frozenset({1, 2}), store.applied_versions(self.conn, 'widgets'))
        self.assertEqual((), store.apply_migrations(self.conn, 'widgets', [V1, V2]))
        columns = {row[1] for row in self.conn.execute('PRAGMA table_info(widget)')}
        self.assertEqual({'id', 'name', 'size'}, columns)

    def test_a_later_version_applies_on_top_of_an_existing_store(self):
        store.apply_migrations(self.conn, 'widgets', [V1])
        self.assertEqual((2,), store.apply_migrations(self.conn, 'widgets', [V1, V2]))

    def test_components_version_independently_in_one_file(self):
        # 한 파일에 여러 컴포넌트를 담아야 컨테이너별 통합이 가능하다.
        store.apply_migrations(self.conn, 'alpha', [V1])
        store.apply_migrations(self.conn, 'beta', [(1, ('CREATE TABLE gadget(id INTEGER)',))])
        self.assertEqual(frozenset({1}), store.applied_versions(self.conn, 'alpha'))
        self.assertEqual(frozenset({1}), store.applied_versions(self.conn, 'beta'))
        tables = {row[0] for row in
                  self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn('widget', tables)
        self.assertIn('gadget', tables)
        self.assertIn(store.MIGRATIONS_TABLE, tables)

    def test_a_failing_migration_records_nothing(self):
        broken = (1, ('CREATE TABLE ok(id INTEGER)', 'THIS IS NOT SQL'))
        with self.assertRaises(store.StoreError):
            store.apply_migrations(self.conn, 'broken', [broken])
        self.assertEqual(frozenset(), store.applied_versions(self.conn, 'broken'))
        tables = {row[0] for row in
                  self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertNotIn('ok', tables, '실패한 버전의 일부가 남아서는 안 된다')

    def test_bad_version_sets_are_rejected(self):
        with self.assertRaises(store.StoreError):
            store.apply_migrations(self.conn, 'dup', [V1, (1, ('SELECT 1',))])
        with self.assertRaises(store.StoreError):
            store.apply_migrations(self.conn, 'zero', [(0, ('SELECT 1',))])

    def test_the_bookkeeping_table_survives_an_unrelated_connection(self):
        store.apply_migrations(self.conn, 'widgets', [V1])
        with store.opened(self.dir / 'm.sqlite3') as other:
            self.assertEqual(frozenset({1}), store.applied_versions(other, 'widgets'))


class PathAliasStoreAdoptsExistingVolumes(unittest.TestCase):
    """마이그레이션 도입 전에 만들어진 경로 별칭 볼륨을 그대로 이어받는지."""

    def setUp(self):
        from defense.app import path_alias
        self.path_alias = path_alias
        self.dir = Path(tempfile.mkdtemp())
        self.db = self.dir / 'path-alias.sqlite3'

    def _legacy_volume(self, *, with_v3_tables: bool):
        """v4 테이블을 직접 만들어 schema_migrations 가 없는 기존 볼륨을 재현한다."""
        with sqlite3.connect(self.db) as conn:
            for statement in self.path_alias._V1:
                conn.execute(statement)
            if with_v3_tables:
                conn.execute('CREATE TABLE path_alias_clients(app_id TEXT, client_id TEXT)')
                conn.execute('CREATE TABLE path_alias_client_rows(alias_route TEXT)')
                conn.execute("INSERT INTO path_alias_clients VALUES ('a','c')")
            conn.execute(
                'INSERT INTO path_alias_client_state VALUES (?,?,?,?,?,?,?,?)',
                ('app', 'client', 1, 1.0, 'hash', 1.0, 0, 0.0))

    def _tables(self) -> set[str]:
        with sqlite3.connect(self.db) as conn:
            return {row[0] for row in
                    conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}

    def test_a_fresh_volume_gets_every_version(self):
        self.path_alias._SQLiteStore(str(self.db))
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(frozenset({1, 2}), store.applied_versions(conn, 'path_alias'))
        self.assertIn('path_alias_alias_rows', self._tables())

    def test_an_existing_volume_keeps_its_rows_and_adopts_v1(self):
        self._legacy_volume(with_v3_tables=False)
        self.path_alias._SQLiteStore(str(self.db))
        with sqlite3.connect(self.db) as conn:
            self.assertEqual(frozenset({1, 2}), store.applied_versions(conn, 'path_alias'))
            self.assertEqual(1, conn.execute(
                'SELECT COUNT(*) FROM path_alias_client_state').fetchone()[0])

    def test_the_abandoned_v3_tables_are_dropped(self):
        self._legacy_volume(with_v3_tables=True)
        self.assertIn('path_alias_clients', self._tables())
        self.path_alias._SQLiteStore(str(self.db))
        tables = self._tables()
        self.assertNotIn('path_alias_clients', tables)
        self.assertNotIn('path_alias_client_rows', tables)
        self.assertIn('path_alias_client_state', tables)

    def test_reopening_is_idempotent(self):
        self._legacy_volume(with_v3_tables=True)
        self.path_alias._SQLiteStore(str(self.db))
        first = self._tables()
        self.path_alias._SQLiteStore(str(self.db))
        self.assertEqual(first, self._tables())


class SecurityStoreStaysFailClosed(unittest.TestCase):
    """보안 저장소는 공용 connect 를 쓰면서도 런타임에 파일을 만들지 않는다."""

    def test_opening_a_missing_store_does_not_create_it(self):
        # 오버레이 패키지도 이름이 defense 라서 sys.path 에 올리면 이 디렉터리의 다른
        # 테스트가 쓰는 defense.app 임포트를 가린다 — 별칭으로 로드한다.
        security_store = _load_overlay_module('security_store')
        missing = Path(tempfile.mkdtemp()) / 'security.sqlite3'
        with self.assertRaises(security_store.SecurityStoreError):
            security_store._connect_existing(missing)
        self.assertFalse(missing.exists())


if __name__ == '__main__':
    unittest.main()
