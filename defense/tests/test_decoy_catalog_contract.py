"""미끼 경로 카탈로그가 Detection·CHeaT·오버레이 세 곳에서 모두 같은 뜻인지 검증한다.

루트 shared/ 는 네 Dockerfile 어디서도 COPY 할 수 없어(전부 하위 빌드 컨텍스트) 편집
원본 하나와 서비스별 사본을 함께 커밋한다. 동일성은 파일 구조가 아니라 이 테스트가
강제한다. 세 서비스의 판별 모듈은 모두 순수 표준 라이브러리라 defense 의존성만 있는
이 job 에서 함께 import 할 수 있다.
"""
import importlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SHARED = ROOT / 'shared/decoy-catalog.json'
COPIES = {
    'detection': ROOT / 'detection/config/decoy-catalog.json',
    'overlay': ROOT / 'defense/account-response-overlay/config/decoy-catalog.json',
}
OVERLAY_ROOT = ROOT / 'defense/account-response-overlay'
SITE_PROFILES = ('site-juice-shop.toml', 'site-ruby-shop.toml', 'site-generic-example.toml')


def _load_module(name: str, path: Path, *, package_dir: Path | None = None):
    """Import by file path under an alias name.

    The overlay package is also called `defense`, which is the repository's own
    namespace package here. Putting its directory on sys.path would shadow
    `defense.app` for every other test in this directory, so it is loaded under
    an alias instead and its relative imports resolve inside that alias.
    """
    locations = [str(package_dir)] if package_dir else None
    spec = importlib.util.spec_from_file_location(name, path, submodule_search_locations=locations)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_load_module('overlay_pkg', OVERLAY_ROOT / 'defense/__init__.py',
             package_dir=OVERLAY_ROOT / 'defense')
decoy_paths = importlib.import_module('overlay_pkg.decoy_paths')
load_site_profile = importlib.import_module('overlay_pkg.site_profile').load_site_profile


# CHeaT sidecar 의 프로필은 fastapi 없이 import 된다(의도된 성질이고 여기서 그걸 쓴다).
cheat_profiles = _load_module(
    'cheat_profiles', ROOT / 'defense/CHeat-defense-proxy/defense_proxy_v2/profiles.py')


class DecoyCatalogCopies(unittest.TestCase):
    def test_every_service_copy_matches_the_shared_original(self):
        original = SHARED.read_bytes()
        for service, copy_path in COPIES.items():
            with self.subTest(service=service):
                self.assertTrue(copy_path.exists(), f'{copy_path} 사본이 없다')
                self.assertEqual(
                    original, copy_path.read_bytes(),
                    'scripts/sync-decoy-catalog.sh 로 사본을 다시 만들어야 한다')

    def test_the_overlay_module_loads_the_copy_next_to_its_package(self):
        self.assertEqual(json.loads(COPIES['overlay'].read_text(encoding='utf-8')),
                         decoy_paths.CATALOG)


class OverlayRecognizesEveryCatalogPath(unittest.TestCase):
    def test_declared_paths_are_part_of_the_local_decoy_namespace(self):
        # 미끼 스크립트는 판별식보다 앞선 전용 분기(overlay/high_risk)에서 서빙하므로
        # 네임스페이스 판별 대상이 아니다. 스타일시트는 반대로 판별식에 들어 있다.
        served_before_the_predicate = {decoy_paths.LURE_SCRIPT}
        for name, path in decoy_paths.OVERLAY_PATHS.items():
            if path in served_before_the_predicate:
                continue
            with self.subTest(path=name):
                self.assertTrue(decoy_paths.is_overlay_decoy(path), path)
        self.assertFalse(decoy_paths.is_overlay_decoy(decoy_paths.LURE_SCRIPT))
        self.assertTrue(decoy_paths.is_overlay_decoy(decoy_paths.OPERATIONS_CSS))

    def test_declared_entries_are_entries_and_deeper_paths_are_steps(self):
        for path in decoy_paths.ENTRIES:
            with self.subTest(path=path):
                self.assertTrue(decoy_paths.is_entry(path))
        self.assertFalse(decoy_paths.is_entry(decoy_paths.RECOVERY + '/1/' + 'a' * 24))

    def test_every_stage_label_stays_inside_the_declared_families(self):
        allowed = set(decoy_paths.STAGE_FAMILIES) | {'ftp', 'decoy'}
        for path in (*decoy_paths.ENTRIES, decoy_paths.ARCHIVE, decoy_paths.AUDIT,
                     decoy_paths.RECOVERY + '/1'):
            with self.subTest(path=path):
                self.assertIn(decoy_paths.decoy_stage(path).split(':', 1)[0], allowed)

    def test_clue_headers_point_at_catalog_paths(self):
        for kind in decoy_paths.CATALOG['clueHeaders']:
            with self.subTest(kind=kind):
                headers = decoy_paths.clue_headers(kind)
                path = decoy_paths.OVERLAY_PATHS[
                    decoy_paths.CATALOG['clueHeaders'][kind]['pathKey']]
                self.assertEqual(headers['Link'].split('>', 1)[0], '<' + path)
                self.assertIn(path, headers.values())


class CheatSidecarAgreesWithTheCatalog(unittest.TestCase):
    def test_the_maze_entry_path_is_the_one_the_catalog_declares(self):
        declared = decoy_paths.CATALOG['namespaces']['cheat']['entryPath']
        for preset in sorted(cheat_profiles.PRESETS):
            with self.subTest(preset=preset):
                profile = cheat_profiles.build_profile(preset)
                self.assertEqual(declared, profile['maze']['entry_path'])

    def test_maze_roots_never_shadow_the_overlay_namespace(self):
        # Defense_proxy 는 /ftp 같은 실제 디렉터리를 미로가 가리지 않게 일부러 피한다.
        for preset in sorted(cheat_profiles.PRESETS):
            for maze_root in cheat_profiles.build_profile(preset)['maze']['paths']:
                with self.subTest(preset=preset, root=maze_root):
                    bare = '/' + maze_root.strip('/')
                    for overlay_root in decoy_paths.OVERLAY_ROOTS:
                        self.assertFalse(decoy_paths.prefixed(bare, overlay_root))
                        self.assertFalse(decoy_paths.prefixed(overlay_root, bare))


class DetectionSharesTheSameCatalog(unittest.TestCase):
    def test_the_detection_copy_declares_the_scored_namespaces(self):
        catalog = json.loads(COPIES['detection'].read_text(encoding='utf-8'))
        self.assertEqual(catalog, decoy_paths.CATALOG)
        scored = {name for name, spec in catalog['namespaces'].items()
                  if spec.get('detectionSignal')}
        self.assertEqual({'overlay', 'cheat'}, scored,
                         'Detection 자신의 트랩은 이미 채점되므로 신호 대상이 아니다')


class SiteProfilesStayInsideTheDecoyNamespace(unittest.TestCase):
    def test_robots_clues_and_login_paths_respect_the_namespace(self):
        for name in SITE_PROFILES:
            with self.subTest(profile=name):
                profile = load_site_profile(str(OVERLAY_ROOT / 'config' / name))
                for clue in profile.robots_disallow:
                    self.assertTrue(decoy_paths.is_overlay_decoy(clue), clue)
                for login_path in profile.login_paths:
                    self.assertFalse(decoy_paths.is_overlay_decoy(login_path), login_path)


class DecoyNamespaceIsDeclaredByTheProfile(unittest.TestCase):
    """사이트 추가가 프로파일 작성만으로 끝나는지 — 코드에 /ftp·/ops 분기가 없어야 한다."""

    def _juice_fields(self) -> dict:
        profile = load_site_profile(str(OVERLAY_ROOT / 'config/site-juice-shop.toml'))
        return dict(vars(profile))

    def test_every_shipped_profile_declares_its_namespace(self):
        for name in SITE_PROFILES:
            with self.subTest(profile=name):
                profile = load_site_profile(str(OVERLAY_ROOT / 'config' / name))
                self.assertEqual(tuple(decoy_paths.OVERLAY_ROOTS), profile.decoy_namespaces)

    def test_a_site_may_relocate_the_decoy_namespace(self):
        site_profile = importlib.import_module('overlay_pkg.site_profile')
        relocated = site_profile.SiteProfile(**{**self._juice_fields(),
                                                'decoy_namespaces': ('/archive',),
                                                'robots_disallow': ('/archive/accounts',)})
        self.assertEqual(('/archive',), relocated.decoy_namespaces)

    def test_the_declared_namespace_still_gates_robots_and_login_paths(self):
        site_profile = importlib.import_module('overlay_pkg.site_profile')
        fields = self._juice_fields()
        for label, override in (
                ('robots clue outside the namespace', {'robots_disallow': ('/elsewhere',)}),
                ('login path inside the namespace', {'login_paths': ('/ops/login',)}),
                ('no namespace at all', {'decoy_namespaces': ()}),
                ('relative namespace', {'decoy_namespaces': ('ops',)})):
            with self.subTest(case=label):
                with self.assertRaises(ValueError):
                    site_profile.SiteProfile(**{**fields, **override})


class StageAndEntryClassification(unittest.TestCase):
    """교정된 분류 동작. 교정 전에는 접두어만 맞아도 미끼 패밀리로 기록됐다."""

    def test_a_family_name_must_end_on_a_segment_boundary(self):
        for path, expected in ((decoy_paths.RECOVERY, 'recovery:accounts'),
                               (decoy_paths.ARCHIVE, 'archive'),
                               ('/ops/recoveryXYZ', 'decoy'),
                               ('/ops/archiveZ/1', 'decoy')):
            with self.subTest(path=path):
                self.assertEqual(expected, decoy_paths.decoy_stage(path))

    def test_the_legacy_root_also_needs_a_segment_boundary(self):
        self.assertEqual('ftp', decoy_paths.decoy_stage(decoy_paths.LEGACY))
        self.assertEqual('ftp', decoy_paths.decoy_stage(decoy_paths.LEGACY + '/old'))
        for near_miss in (decoy_paths.LEGACY + 'x', decoy_paths.LEGACY + '.bak'):
            with self.subTest(path=near_miss):
                self.assertEqual('decoy', decoy_paths.decoy_stage(near_miss))

    def test_a_record_step_keeps_its_number_and_stays_a_step(self):
        record = decoy_paths.RECOVERY + '/1/' + 'a' * 24
        self.assertEqual('recovery:accounts:1', decoy_paths.decoy_stage(record))
        self.assertFalse(decoy_paths.is_entry(record))

    def test_only_ascii_digits_become_a_step_number(self):
        # 비-ASCII 숫자가 통과하면 LureMetrics.emit 의 stage 검증에서 ValueError 가 된다.
        self.assertEqual('recovery:accounts',
                         decoy_paths.decoy_stage(decoy_paths.RECOVERY + '/\u0661'))

    def test_every_stage_label_is_emittable_as_lure_telemetry(self):
        emit_pattern = re.compile(r'[a-zA-Z0-9_:/.-]*')
        paths = [*decoy_paths.ENTRIES, *decoy_paths.OVERLAY_PATHS.values(),
                 decoy_paths.RECOVERY + '/1', decoy_paths.RECOVERY + '/\u0661',
                 '/ops/recoveryXYZ', decoy_paths.LEGACY + 'x']
        for path in paths:
            with self.subTest(path=path):
                stage = decoy_paths.decoy_stage(path)
                self.assertLessEqual(len(stage), 80)
                self.assertTrue(emit_pattern.fullmatch(stage), stage)

    def test_a_trailing_slash_does_not_turn_an_entry_into_a_step(self):
        for entry in decoy_paths.ENTRIES:
            with self.subTest(entry=entry):
                self.assertTrue(decoy_paths.is_entry(entry))
                self.assertTrue(decoy_paths.is_entry(entry + '/'))


class PathPredicatePrecondition(unittest.TestCase):
    """판별식은 정규화된 경로를 전제한다. 그 전제를 테스트로 적어 둔다."""

    def test_the_canonical_gate_rejects_the_shapes_the_predicate_cannot_see(self):
        for path in ('//ops/x', '/ops/../x', '/ops/./x', '/ops/a b', '/ops/a%2fb'):
            with self.subTest(path=path):
                self.assertFalse(decoy_paths.is_canonical_path(path))
        for path in ('/ops', '/ops/recovery/accounts', '/ftp', '/assets/operations.css'):
            with self.subTest(path=path):
                self.assertTrue(decoy_paths.is_canonical_path(path))

    def test_case_variants_are_not_recognized_without_normalization(self):
        self.assertFalse(decoy_paths.is_overlay_decoy('/OPS/x'))
        self.assertEqual('/ops/x', decoy_paths.normalize_decoy_key('//OPS/x/'))


if __name__ == '__main__':
    unittest.main()
