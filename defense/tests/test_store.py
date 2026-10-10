"""공용 SQLite 접근 계층: 연결 설정, 트랜잭션, 컴포넌트별 마이그레이션."""
import sqlite3
import tempfile
import unittest
from pathlib import Path

from defense.app import store

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


if __name__ == '__main__':
    unittest.main()
