"""CHeaT sidecar 의 프리셋 경로가 다른 곳의 같은 선언과 어긋나지 않는지.

`defense_proxy_v2/profiles.py` 는 "이 프록시가 어떤 서버인 척할지" 를 정하는 **별개**
장치다(`TARGET_PRESET`/`TARGET_PROFILE`). 그런데 그 프리셋 안에 다른 곳에도 적혀 있는
값 셋이 들어 있다:

- `migration.api_prefix` = `/rest/internal` — Detection 의 미끼 네임스페이스와 같은 문자열.
  정본은 `shared/decoy-catalog.json` 의 `namespaces.detection.roots[0]` 다.
- `migration.login_path` — 대상 사이트의 실제 로그인 경로. 정본은 오버레이의
  `config/site-*.toml` 의 `login_paths[0]` 다.
- `migration.config_path` 와 `transforms.build_recipes` 의 `t21_version_path` 기본값 —
  대상 사이트의 관리 API 경로. 정본은 같은 TOML 의 `ordinary_api_exact` 다.

런타임에 읽어 파생시키지 않는 이유: CHeaT 의 Dockerfile COPY 는 **파일 단위
allowlist** 이고 오버레이 TOML 은 그 빌드 컨텍스트 밖이다. 카탈로그를 네 번째 서비스로
동기화하는 플러밍을 더하는 대신, 이미 이 저장소가 쓰는 방식을 쓴다 — 선언은 각자
두고 경계를 넘는 일치는 계약 테스트가 강제한다(`shared/target-selection.json` 선례,
그리고 CHeaT 의 미로 진입 경로에 대해 `test_decoy_catalog_contract.py` 가 이미 그렇게
한다).

어긋나면 무슨 일이 생기나: 접두어가 갈라지면 CHeaT 가 Detection 의 트랩 네임스페이스와
다른 경로를 광고하고, 로그인 경로가 갈라지면 CHeaT 의 login_lure 가 실제 로그인이
아닌 경로에서만 동작해 조용히 무력화된다.
"""
from pathlib import Path
import importlib.util
import json
import re
import sys
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHEAT = ROOT / 'defense/CHeat-defense-proxy/defense_proxy_v2'
OVERLAY_CONFIG = ROOT / 'defense/account-response-overlay/config'

# 프리셋 이름과 그 프리셋이 위장하는 대상의 사이트 프로파일.
PRESET_SITES = {
    'apache-php': 'site-juice-shop.toml',
    'nginx-fastapi': 'site-ruby-shop.toml',
}


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# profiles.py 는 fastapi 없이 import 된다(의도된 성질이고 여기서 그걸 쓴다).
# transforms.py 는 `import profiles` 로 형제 모듈을 평평하게 가져오므로 alias import 가
# 되지 않는다 — sys.modules 에 'profiles' 를 심으면 같은 실행의 다른 테스트를 오염시킨다.
# 그래서 거기 기본 인자는 소스에서 읽는다(test_target_selection_contract.py 와 같은 수법).
cheat_profiles = _load('cheat_profiles_contract', CHEAT / 'profiles.py')


def _t21_version_path_default() -> str:
    source = (CHEAT / 'transforms.py').read_text(encoding='utf-8')
    found = re.search(r't21_version_path: str = "([^"]+)"', source)
    assert found, 'transforms.py 에서 t21_version_path 기본값을 찾지 못했다'
    return found.group(1)


def _site(name: str) -> dict:
    return tomllib.loads((OVERLAY_CONFIG / name).read_text(encoding='utf-8'))


def _catalog() -> dict:
    return json.loads((ROOT / 'shared/decoy-catalog.json').read_text(encoding='utf-8'))


class PresetsAgreeWithTheDecoyCatalog(unittest.TestCase):
    def test_the_migration_api_prefix_is_the_detection_decoy_namespace(self):
        # Detection 의 deceptionEngine 이 이 값을 카탈로그에서 읽는다. CHeaT 가 다른
        # 접두어를 광고하면 둘이 서로 다른 네임스페이스를 쓰게 된다.
        declared = _catalog()['namespaces']['detection']['roots'][0]
        preset = cheat_profiles.get_preset('apache-php')
        self.assertEqual(preset['migration']['api_prefix'], declared)

    def test_every_preset_keeps_the_migration_prefix_out_of_the_overlay_namespace(self):
        # 미끼끼리 같은 경로를 다투지 않아야 한다. 오버레이의 네임스페이스는
        # 카탈로그가 선언한다.
        overlay_roots = _catalog()['namespaces']['overlay']['roots']
        for name in PRESET_SITES:
            prefix = cheat_profiles.get_preset(name)['migration']['api_prefix']
            for root in overlay_roots:
                with self.subTest(preset=name, root=root):
                    self.assertFalse(prefix == root or prefix.startswith(root + '/'),
                                     f'{name} 의 api_prefix 가 오버레이 네임스페이스와 겹친다')


class PresetsAgreeWithTheSiteProfiles(unittest.TestCase):
    def test_each_preset_login_path_is_its_sites_login_path(self):
        for name, site in PRESET_SITES.items():
            with self.subTest(preset=name):
                declared = _site(site)['login_paths'][0]
                preset = cheat_profiles.get_preset(name)
                self.assertEqual(
                    preset['migration']['login_path'], declared,
                    f'{name} 프리셋의 login_path 가 {site} 의 login_paths[0] 와 다르다 — '
                    f'CHeaT 의 login_lure 가 실제 로그인 경로에서 동작하지 않는다')

    def test_the_migration_config_path_is_an_ordinary_api_of_its_site(self):
        for name, site in PRESET_SITES.items():
            config_path = cheat_profiles.get_preset(name)['migration']['config_path']
            if not config_path:
                continue  # 빈 값은 "이 대상에는 그런 엔드포인트가 없다" 는 뜻이다
            with self.subTest(preset=name):
                self.assertIn(config_path, _site(site)['ordinary_api_exact'],
                              f'{name} 의 config_path 가 {site} 에 선언된 API 가 아니다')

    def test_the_t21_version_path_default_is_an_ordinary_api_of_juice_shop(self):
        # transforms.build_recipes 의 기본 인자는 Juice Shop 전용이라고 주석이 밝히고
        # 있다. 그 사실을 기계적으로 묶어 둔다 — 다른 대상에 배포할 때는
        # T21_VERSION_PATH env 로 바꿔야 효과가 난다.
        default = _t21_version_path_default()
        self.assertIn(default, _site('site-juice-shop.toml')['ordinary_api_exact'])


class TheMazeBannerFollowsThePreset(unittest.TestCase):
    """미로의 version 페이지가 프리셋과 모순되지 않는지.

    `MAZE_VERSION` 의 마지막 폴백이 Apache 리터럴이었다. `SPOOF_SERVER=` (빈 값,
    "위조하지 않음") 으로 두면 어떤 프리셋을 골랐든 미로만 Apache 를 주장했다.
    """

    def test_no_preset_banner_contradicts_its_family(self):
        for name in PRESET_SITES:
            preset = cheat_profiles.get_preset(name)
            banner = preset['web']['server_banner']
            with self.subTest(preset=name):
                self.assertTrue(banner, f'{name} 에 배너가 없으면 폴백이 다시 생긴다')
                expected = 'Apache' if name.startswith('apache') else 'nginx'
                self.assertIn(expected, banner)

    def test_the_maze_banner_chain_has_no_hardcoded_server(self):
        source = (CHEAT / 'Defense_proxy.py').read_text(encoding='utf-8')
        line = next(l for l in source.splitlines() if l.startswith('MAZE_VERSION ='))
        self.assertNotIn('Apache', line,
                         'MAZE_VERSION 의 폴백이 다시 특정 서버로 박혔다 — 프리셋 배너를 써야 한다')
        self.assertIn('server_banner', line + source.split('MAZE_VERSION =')[1][:200])


if __name__ == '__main__':
    unittest.main()
