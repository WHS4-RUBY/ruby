"""Detection 사이트 프로파일과 Defense 설정이 같은 사실을 말하는지.

Detection 의 `detection/config/site-profiles/*.json` 은 Detection 이 유일한 reader 다
(JWT 클레임 맵·mass-assignment 화이트리스트·가격 필드명을 읽는 Defense 컴포넌트는 없다).
그래서 `shared/` 사본 방식이 아니라 `shared/target-selection.json` 선례를 따랐다 —
선언은 한쪽이 소유하고, 경계를 넘는 일치는 계약 테스트가 강제한다.

이 테스트가 Python 쪽에 있는 이유: Node 22 에는 stdlib TOML 파서가 없고
`detection/package.json` 은 devDependencies 가 0개다(규칙 7). Python 3.12 의 `tomllib`
는 stdlib 이고, 오버레이의 `site_profile.py` 가 이미 그것을 쓴다. 그리고
`defense/tests` 는 이미 `detection/config/*.json` 과 `detection/lib/*.js` 소스를 읽는
계약 테스트가 셋 있다(test_event_schema, test_decoy_catalog_contract,
test_target_selection_contract).
"""
from pathlib import Path
import json
import re
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
PROFILES_DIR = ROOT / 'detection/config/site-profiles'
OVERLAY_CONFIG = ROOT / 'defense/account-response-overlay/config'
DEFENSE_CONFIG = ROOT / 'defense/config'
SITE_PROFILE_JS = ROOT / 'detection/lib/siteProfile.js'
TARGET_SELECTION_CONTRACT = ROOT / 'shared/target-selection.json'

# 대상 사이트별로 Detection 프로파일과 짝이 되는 Defense 설정.
PAIRED_SITES = ('juice-shop', 'ruby-shop')

# path_alias.py 의 DEFAULT_PREFIXES. 이 접두어 밖의 경로는 경로 별칭 대상이 아니므로
# 라우트 문서에 없는 것이 정상이다(예: /metrics).
ALIAS_PREFIXES = ('/rest/', '/api/')

# juice-shop-routes.json 에 없지만 Detection 이 규칙을 가진 라우트.
# 묶어서 무시하지 않고 하나씩 적는다 — 새로 생기면 테스트가 실패해야 한다.
KNOWN_ROUTE_GAPS = {
    'juice-shop': {
        # Juice Shop 에 실제로 있는 Sequelize 자동 라우트인데 경로 별칭 문서에는
        # /api/BasketItems/{tail*} 와 /rest/basket/{id} 만 있고 이 컬렉션이 빠져 있다.
        # Detection 의 identity-mismatch:baskets-query 규칙이 이 라우트를 본다.
        # Defense 쪽 라우트 문서의 공백이며 이 작업의 범위가 아니다(규칙 7).
        '/api/baskets',
    },
    'ruby-shop': set(),
}


def _profiles():
    return {path.stem: json.loads(path.read_text(encoding='utf-8'))
            for path in sorted(PROFILES_DIR.glob('*.json'))}


def _overlay_profile(site):
    return tomllib.loads((OVERLAY_CONFIG / f'site-{site}.toml').read_text(encoding='utf-8'))


def _route_paths(site):
    document = json.loads((DEFENSE_CONFIG / f'{site}-routes.json').read_text(encoding='utf-8'))
    return [item if isinstance(item, str) else item['path'] for item in document['routes']]


def _normalize(path):
    """경로 별칭의 {var}/{tail*} 와 Detection 의 :id/:uuid 를 같은 자리표시자로 모은다."""
    path = re.sub(r'\{[^}]*\}', '*', path)
    path = re.sub(r':(id|uuid)\b', '*', path)
    return path.rstrip('/').lower() or '/'


def _declared_routes(profile):
    """프로파일이 선언한 (어디, 경로) 전부."""
    found = []
    deception = profile.get('deception', {})
    if 'loginPath' in deception:
        found.append(('deception.loginPath', deception['loginPath']))
    if 'loginBruteForce' in profile:
        found.append(('loginBruteForce.route', profile['loginBruteForce']['route']['normalizedPath']))
    reset = profile.get('passwordResetAbuse', {})
    for key in ('resetRoute', 'securityQuestionRoute'):
        if key in reset:
            found.append((f'passwordResetAbuse.{key}', reset[key]['normalizedPath']))
    integrity = profile.get('priceIntegrity', {})
    for key in ('listRoute', 'itemRoute'):
        if key in integrity:
            found.append((f'priceIntegrity.{key}', integrity[key]))
    for entry in profile.get('businessLogic', {}).get('massAssignmentWhitelist', []):
        found.append(('businessLogic.massAssignmentWhitelist', entry['route'].split(' ', 1)[1]))
    identity = profile.get('identity', {})
    for key in ('routeRules', 'bodyRules', 'queryRules'):
        for entry in identity.get(key, []):
            found.append((f'identity.{key}', entry['normalizedPath']))
    for entry in profile.get('roleGated', {}).get('sensitiveRoutes', []):
        found.append(('roleGated.sensitiveRoutes', entry['normalizedPath']))
    return found


def _covered_by(path, route_paths):
    """컬렉션 루트는 그 하위를 덮는 {tail*} 라우트가 덮는 것으로 본다."""
    wanted = _normalize(path)
    for route in route_paths:
        normalized = _normalize(route)
        if normalized == wanted:
            return True
        if normalized.endswith('/*'):
            parent = normalized[:-2]
            if wanted == parent or wanted.startswith(parent + '/'):
                return True
    return False


class ProfilesLoadAndDeclareTheirGaps(unittest.TestCase):
    def test_the_three_profiles_are_shipped(self):
        self.assertEqual(sorted(_profiles()), ['generic', 'juice-shop', 'ruby-shop'])

    def test_every_profile_names_itself_after_its_file(self):
        for name, profile in _profiles().items():
            with self.subTest(profile=name):
                self.assertEqual(profile['profileId'], name)
                self.assertEqual(profile['schemaVersion'], 1)

    def test_the_profile_id_pattern_matches_the_target_id_pattern(self):
        # 대상 ID 가 곧 프로파일 파일명이므로 두 패턴이 어긋나면 고를 수 없는 대상이 생긴다.
        declared = json.loads(TARGET_SELECTION_CONTRACT.read_text(encoding='utf-8'))
        pattern = declared['bounds']['idPattern']
        source = SITE_PROFILE_JS.read_text(encoding='utf-8')
        self.assertIn(f'const PROFILE_ID = /{pattern}/;', source,
                      'siteProfile.js 의 PROFILE_ID 가 shared/target-selection.json 의 '
                      'bounds.idPattern 과 다르다')
        for name in _profiles():
            with self.subTest(profile=name):
                self.assertRegex(name, pattern)

    def test_needs_confirmation_names_only_real_features(self):
        source = SITE_PROFILE_JS.read_text(encoding='utf-8')
        block = re.search(r'const FEATURE_PATHS = Object\.freeze\(\[(.*?)\]\);', source, re.DOTALL)
        self.assertTrue(block, 'siteProfile.js 에서 FEATURE_PATHS 를 찾지 못했다')
        features = set(re.findall(r'"([^"]+)"', block.group(1)))
        self.assertIn('roleGated', features)
        for name, profile in _profiles().items():
            for key in ('_needsConfirmation', '_genericDefaults'):
                for entry in profile.get(key, []):
                    with self.subTest(profile=name, entry=entry):
                        self.assertIn(entry, features)

    def test_generic_declares_no_route_bound_feature(self):
        # D3-R: generic 에는 지금 라우트 무관하게 도는 기능만 들어간다. 라우트에 묶인
        # 기능이 들어오면 프로파일 없는 대상의 동작이 바뀐다.
        generic = _profiles()['generic']
        self.assertNotIn('loginBruteForce', generic)
        self.assertNotIn('passwordResetAbuse', generic)
        self.assertNotIn('priceIntegrity', generic)
        self.assertNotIn('roleGated', generic)
        self.assertNotIn('loginPath', generic['deception'])
        self.assertNotIn('massAssignmentWhitelist', generic['businessLogic'])
        for key in ('routeRules', 'bodyRules', 'queryRules'):
            self.assertNotIn(key, generic['identity'])
        # 반대로 라우트 무관한 것은 반드시 있어야 한다.
        self.assertIn('priceTampering', generic)
        self.assertIn('claimMap', generic['identity'])
        self.assertIn('apiPathPrefixes', generic['deception'])


class ProfilesAgreeWithTheOverlayProfiles(unittest.TestCase):
    """겹치는 값의 정본은 오버레이 TOML 이다. 관계가 전부 '같다'는 아니다."""

    def test_the_login_path_is_the_overlay_login_path(self):
        for site in PAIRED_SITES:
            with self.subTest(site=site):
                profile = _profiles()[site]
                overlay = _overlay_profile(site)
                self.assertEqual(profile['deception']['loginPath'], overlay['login_paths'][0],
                                 f'site-{site}.toml 의 login_paths[0] 가 정본이다')

    def test_the_auth_cookie_names_are_a_subset_of_the_overlay_cookies(self):
        # 같다가 아니라 부분집합이다: origin_auth_cookies 는 "격리 클라이언트에게 원본으로
        # 넘기지 않을 쿠키" 이고, Detection 이 보는 것은 "디코딩 가능한 JWT 를 담은 쿠키" 다.
        # 이름이 겹치지만 뜻이 다르므로 더 강하게 묶지 않는다.
        for site in PAIRED_SITES:
            with self.subTest(site=site):
                profile = _profiles()[site]
                sources = profile.get('identity', {}).get('tokenSources')
                if not sources:
                    continue
                self.assertLessEqual(set(sources['cookieNames']),
                                     set(_overlay_profile(site)['origin_auth_cookies']))

    def test_the_api_prefixes_are_a_subset_of_the_overlay_prefixes(self):
        # 역시 부분집합이다: Detection 은 no_asset_loading·coverage 자동화 신호의 분모로
        # "API 성 요청" 을 세고, 오버레이는 단서 헤더 선택을 위해 응답을 분류한다.
        # Detection 은 뒤 슬래시로 세그먼트 경계를 만들고 오버레이는 그러지 않는다.
        for site in PAIRED_SITES:
            with self.subTest(site=site):
                detection = {p.strip('/') for p in _profiles()[site]['deception']['apiPathPrefixes']}
                overlay = {p.strip('/') for p in _overlay_profile(site)['api_prefixes']}
                self.assertLessEqual(detection, overlay)

    def test_the_overlay_ships_a_profile_for_every_paired_detection_profile(self):
        for site in PAIRED_SITES:
            with self.subTest(site=site):
                self.assertTrue((OVERLAY_CONFIG / f'site-{site}.toml').is_file())
                self.assertTrue((DEFENSE_CONFIG / f'{site}-routes.json').is_file())


class DeclaredRoutesExistInThePathAliasDocument(unittest.TestCase):
    """오타난 라우트로 조용히 무력화되는 것을 구조적으로 막는다."""

    def test_every_declared_route_is_covered_or_a_known_gap(self):
        for site in PAIRED_SITES:
            route_paths = _route_paths(site)
            for where, path in _declared_routes(_profiles()[site]):
                with self.subTest(site=site, where=where, path=path):
                    if not path.startswith(ALIAS_PREFIXES):
                        continue  # 경로 별칭 대상이 아니다
                    if _normalize(path) in KNOWN_ROUTE_GAPS[site]:
                        continue
                    self.assertTrue(
                        _covered_by(path, route_paths),
                        f'{site} 프로파일의 {where} 가 선언한 {path} 가 '
                        f'defense/config/{site}-routes.json 에 없다',
                    )

    def test_the_known_gaps_are_still_gaps(self):
        # 공백이 메워지면 예외 목록을 지워야 한다 — 그래야 목록이 썩지 않는다.
        for site, gaps in KNOWN_ROUTE_GAPS.items():
            route_paths = _route_paths(site)
            for gap in gaps:
                with self.subTest(site=site, gap=gap):
                    self.assertFalse(
                        _covered_by(gap, route_paths),
                        f'{gap} 가 이제 {site}-routes.json 에 있다. '
                        f'KNOWN_ROUTE_GAPS 에서 지워라',
                    )


class ProfilePathsSatisfyTheOverlayPathRules(unittest.TestCase):
    """Detection 검증기의 경로 규칙이 Defense site_profile.py 규칙 1 과 같은지."""

    def test_every_declared_path_is_absolute_and_canonical(self):
        for name, profile in _profiles().items():
            paths = [path for _, path in _declared_routes(profile)]
            paths += profile.get('deception', {}).get('apiPathPrefixes', [])
            paths += profile.get('deception', {}).get('plaintextBaitPaths', [])
            for path in paths:
                with self.subTest(profile=name, path=path):
                    # site_profile.py.__post_init__ 규칙 1 과 같은 네 조건.
                    self.assertTrue(path.startswith('/'))
                    self.assertNotIn('//', path)
                    self.assertNotIn('\\', path)
                    self.assertNotIn('\r', path)
                    self.assertNotIn('\n', path)

    def test_the_decoy_namespace_stays_out_of_the_profiles(self):
        # 미끼 경로는 shared/decoy-catalog.json 소관이다. 프로파일에 /ftp·/ops·
        # /rest/internal 이 들어오면 두 출처가 생긴다.
        catalog = json.loads((ROOT / 'shared/decoy-catalog.json').read_text(encoding='utf-8'))
        roots = [root for spec in catalog['namespaces'].values()
                 for root in spec.get('roots', [])]
        self.assertIn('/rest/internal', roots)
        for name, profile in _profiles().items():
            body = json.dumps(profile)
            for root in roots:
                with self.subTest(profile=name, root=root):
                    self.assertNotIn(f'"{root}', body,
                                     f'{name} 프로파일이 미끼 네임스페이스 {root} 를 선언한다')


if __name__ == '__main__':
    unittest.main()
