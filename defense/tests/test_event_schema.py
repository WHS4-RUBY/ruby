"""선언된 정본 이벤트 필드명과 각 저장소의 실제 이름이 일치하는지.

같은 개념에 다른 이름을 쓰면 두 대시보드와 sidecar 텔레메트리를 맞춰볼 수 없다.
정본은 shared/event-schema.json 한 곳에 있고 이 테스트가 선언과 구현의 drift 를 막는다.
"""
import importlib
import importlib.util
import json
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / 'shared/event-schema.json').read_text(encoding='utf-8'))
CANONICAL = SCHEMA['canonical']
STORES = SCHEMA['stores']
OVERLAY_ROOT = ROOT / 'defense/account-response-overlay'


def _load_overlay(name: str):
    alias = 'overlay_pkg_event_test'
    if alias not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            alias, OVERLAY_ROOT / 'defense/__init__.py',
            submodule_search_locations=[str(OVERLAY_ROOT / 'defense')])
        module = importlib.util.module_from_spec(spec)
        sys.modules[alias] = module
        spec.loader.exec_module(module)
    return importlib.import_module(f'{alias}.{name}')


class TheDeclarationIsWellFormed(unittest.TestCase):
    def test_every_alias_names_a_canonical_field(self):
        for name, spec in STORES.items():
            for field in spec['aliases']:
                with self.subTest(store=name, field=field):
                    self.assertIn(field, CANONICAL)

    def test_every_canonical_field_is_carried_somewhere(self):
        carried = {field for spec in STORES.values() for field in spec['aliases']}
        self.assertEqual(set(CANONICAL), carried,
                         '선언만 있고 어느 저장소도 담지 않는 필드가 있다')

    def test_the_detection_copy_matches_the_original(self):
        copy = json.loads((ROOT / 'detection/config/event-schema.json').read_text(encoding='utf-8'))
        self.assertEqual(SCHEMA, copy)


class DefenseDashboardUsesTheCanonicalNames(unittest.TestCase):
    def test_a_recorded_event_carries_every_declared_alias(self):
        from defense.app.monitoring import DefenseEventStore
        monitor = DefenseEventStore()
        event = monitor.record(
            method='GET', path='/ops/recovery/accounts', status=200,
            strategies=['decoy_maze'], outcome='forwarded', duration_ms=1.0,
            client_id='client-1', request_id='req-1', decoy_action='maze',
            target_id='legacy', run_id='run-1')
        for field, alias in STORES['defense_dashboard']['aliases'].items():
            with self.subTest(field=field):
                self.assertIn(alias, event, f'{field} -> {alias} 가 이벤트에 없다')
        self.assertEqual('maze', event['decoyAction'])
        self.assertEqual(['decoy_maze'], event['strategies'])
        self.assertEqual('forwarded', event['outcome'])


class DetectionRequestRecordUsesTheDeclaredAliases(unittest.TestCase):
    """Node 소스에서 레코드 필드 이름을 읽어 선언과 비교한다(값이 아니라 이름 계약)."""

    def test_the_record_declares_each_alias(self):
        source = (ROOT / 'detection/lib/sessionStore.js').read_text(encoding='utf-8')
        for field, alias in STORES['detection_request']['aliases'].items():
            with self.subTest(field=field):
                # 실패 메시지에 파일 전체를 싣지 않도록 bool 로 단정한다.
                found = re.search(rf'^\s+{re.escape(alias)}[,:]', source, re.M) is not None
                self.assertTrue(found,
                                f'{field} -> {alias} 를 sessionStore 레코드에서 찾지 못했다')

    def test_detection_keeps_its_own_experiment_run_id_separate(self):
        # runId 를 targetRunId 로 부르는 이유. 이름을 통일하면 내부에서 모호해진다.
        source = (ROOT / 'detection/lib/sessionStore.js').read_text(encoding='utf-8')
        self.assertIn('experimentRunId', source)
        self.assertIn('targetRunId', source)


class SidecarAndOverlayColumnsMatchTheDeclaration(unittest.TestCase):
    def _columns(self, create_sql: str, table: str) -> set[str]:
        with sqlite3.connect(':memory:') as conn:
            conn.execute(create_sql)
            return {row[1] for row in conn.execute(f'PRAGMA table_info({table})')}

    def test_the_sidecar_request_table_matches(self):
        spec = importlib.util.spec_from_file_location(
            'cheat_proxy_src', ROOT / 'defense/CHeat-defense-proxy/defense_proxy_v2/Defense_proxy.py')
        # 모듈 import 는 fastapi 를 필요로 하므로 마이그레이션 DDL 만 소스에서 읽는다.
        source = spec.origin and Path(spec.origin).read_text(encoding='utf-8')
        columns = set()
        for statement in re.findall(r'CREATE TABLE IF NOT EXISTS reqs \((.*?)\)"""', source, re.S):
            columns |= {part.strip().split()[0] for part in statement.split(',') if part.strip()}
        for added in re.findall(r'ALTER TABLE reqs ADD COLUMN (\w+)', source):
            columns.add(added)
        for field, alias in STORES['cheat_reqs']['aliases'].items():
            with self.subTest(field=field):
                self.assertIn(alias, columns, f'{field} -> {alias} 가 reqs 에 없다')

    def test_the_overlay_rings_match(self):
        audit = _load_overlay('audit')
        lure = _load_overlay('lure_metrics')
        pairs = (('overlay_audit', audit.MIGRATIONS, 'events'),
                 ('overlay_lure', lure.MIGRATIONS, 'lure_events'))
        for store_name, migrations, table in pairs:
            columns = self._columns(migrations[0][1][0], table)
            for field, alias in STORES[store_name]['aliases'].items():
                with self.subTest(store=store_name, field=field):
                    self.assertIn(alias, columns, f'{field} -> {alias} 가 {table} 에 없다')

    def test_the_lure_ring_records_a_decoy_hit(self):
        lure = _load_overlay('lure_metrics')
        telemetry = Path(tempfile.mkdtemp()) / 'telemetry.sqlite3'
        metrics = lure.LureMetrics(str(telemetry), b'k' * 32)
        try:
            metrics.emit('actor-a', 'decoy_entry', 'recovery:accounts')
        finally:
            metrics.close()
        with sqlite3.connect(telemetry) as conn:
            row = conn.execute('SELECT kind,stage FROM lure_events').fetchone()
        self.assertEqual(('decoy_entry', 'recovery:accounts'), row)


if __name__ == '__main__':
    unittest.main()
