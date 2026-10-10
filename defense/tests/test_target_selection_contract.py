"""target-selection.json 의 소유자와 검증 경계값이 양쪽에서 같은지.

Detection 이 유일한 writer 이고 Defense 는 같은 named volume 을 :ro 로 읽는다.
같은 파일을 서로 다른 규칙으로 검증하고 있었다 — target ID 32자 vs 64자,
runId 100자 charset vs 128자 길이만, changedAt 날짜 파싱 vs 길이만, 크기 상한
없음 vs 8192. 정본은 shared/target-selection.json 이고 이 테스트가 두 구현을 묶는다.
"""
import json
from pathlib import Path
import re
import unittest
import uuid

from defense.app import target_selection as defense_side

ROOT = Path(__file__).resolve().parents[2]
CONTRACT = json.loads((ROOT / 'shared/target-selection.json').read_text(encoding='utf-8'))
BOUNDS = CONTRACT['bounds']
DETECTION_SOURCE = (ROOT / 'detection/lib/targetSelection.js').read_text(encoding='utf-8')


class TheDeclarationNamesOneOwner(unittest.TestCase):
    def test_detection_is_the_only_writer(self):
        self.assertEqual('detection', CONTRACT['owner'])
        self.assertEqual('detection/lib/targetSelection.js', CONTRACT['file']['writer'])
        self.assertIn('defense/app/target_selection.py', CONTRACT['file']['readers'])

    def test_defense_never_writes_the_file(self):
        source = (ROOT / 'defense/app/target_selection.py').read_text(encoding='utf-8')
        for forbidden in ("open(", "write_text", "json.dump"):
            if forbidden == "open(":
                # 읽기 전용으로만 연다.
                self.assertNotIn("'w'", source)
                self.assertNotIn('"w"', source)
            else:
                self.assertNotIn(forbidden, source)


class BothSidesUseTheDeclaredBounds(unittest.TestCase):
    def test_the_target_id_pattern_is_the_same(self):
        declared = BOUNDS['idPattern']
        # Defense: re 패턴, Detection: JS 리터럴
        self.assertEqual(declared.strip('^$'), defense_side._TARGET_ID.pattern.replace(r'\Z', ''))
        self.assertIn(f'const TARGET_ID = /{declared}/;', DETECTION_SOURCE)

    def test_the_size_limit_is_the_same(self):
        limit = BOUNDS['maxBytes']
        self.assertEqual(limit, defense_side._MAX_SELECTION_BYTES)
        self.assertIn(f'const MAX_SELECTION_BYTES = {limit};', DETECTION_SOURCE)

    def test_both_sides_require_a_canonical_uuid_run_id(self):
        self.assertEqual('uuid-canonical-lowercase', BOUNDS['runIdFormat'])
        self.assertIn('CANONICAL_UUID', DETECTION_SOURCE)
        good = str(uuid.uuid4())
        self.assertTrue(defense_side._is_canonical_uuid(good))
        for bad in (good.upper(), 'run-001', '', 'x' * 36, None, good + 'a'):
            with self.subTest(value=bad):
                self.assertFalse(defense_side._is_canonical_uuid(bad))

    def test_both_sides_require_a_parseable_timestamp(self):
        self.assertEqual('iso8601-parseable', BOUNDS['changedAtFormat'])
        self.assertIn('Date.parse(value.changedAt)', DETECTION_SOURCE)
        for good in ('2026-10-07T11:30:00Z', '2026-10-07T11:30:00+00:00', '2026-10-07'):
            with self.subTest(value=good):
                self.assertTrue(defense_side._is_iso_timestamp(good))
        for bad in ('now', '', None, 'yesterday'):
            with self.subTest(value=bad):
                self.assertFalse(defense_side._is_iso_timestamp(bad))

    def test_the_header_path_uses_the_same_run_id_rule_as_the_file(self):
        # 예전에는 헤더만 canonical UUID 를 강제하고 파일은 길이만 봤다.
        source = (ROOT / 'defense/app/target_selection.py').read_text(encoding='utf-8')
        self.assertEqual(2, source.count('_is_canonical_uuid(run_id)'),
                         '파일 경로와 헤더 경로가 같은 검사를 써야 한다')


class WhatDetectionWritesIsWhatDefenseAccepts(unittest.TestCase):
    """실제 writer 가 만드는 모양을 reader 가 받아들이는지 — 양쪽 규칙의 교차 확인."""

    def _selector(self, tmp):
        return defense_side.TargetSelector.from_environment({
            'TARGET_CHOICES': 'legacy=http://legacy.invalid:3000',
            'TARGET_DEFAULT_ID': 'legacy',
            'TARGET_SELECTION_FILE': str(tmp),
        })

    def test_a_selection_in_detection_shape_is_accepted(self):
        import tempfile
        path = Path(tempfile.mkdtemp()) / 'target-selection.json'
        run_id = str(uuid.uuid4())
        # Detection 의 _write 와 같은 모양: 세 필드 + 끝 개행
        path.write_text(json.dumps({'targetId': 'legacy', 'runId': run_id,
                                    'changedAt': '2026-10-11T02:00:00.000Z'}) + '\n',
                        encoding='utf-8')
        selected = self._selector(path).current()
        self.assertEqual('legacy', selected.target_id)
        self.assertEqual(run_id, selected.run_id)

    def test_an_id_detection_would_refuse_is_also_refused_here(self):
        pattern = re.compile(BOUNDS['idPattern'])
        for bad_id in ('Legacy', '1legacy', 'legacy_x', 'a' * 33, ''):
            with self.subTest(target_id=bad_id):
                self.assertIsNone(pattern.match(bad_id), bad_id)
                with self.assertRaises(RuntimeError):
                    defense_side.TargetSelector.from_environment({
                        'TARGET_CHOICES': f'{bad_id}=http://x.invalid:3000',
                        'TARGET_DEFAULT_ID': bad_id,
                    })


if __name__ == '__main__':
    unittest.main()
