"""미끼 패키지가 특정 사이트에 묶이지 않는지.

디렉터리 이름이 juice_shop 이던 동안 generic 어댑터도 그 패키지의 fallback 을
import 했고, Juice Shop 에만 있는 /api/Challenges 응답을 모든 사이트가 받았다.

그 뒤로도 `settings.site_adapter` 닫힌 2값 enum 이 남아 있어 사이트 추가가 코드 수정
이었다. 이제 사이트별 능력은 프로파일이 선언하고(challenge_api, synthetic_success,
account_api_prefixes) 코드에 사이트 이름이 없다 — 그래서 이 파일도 어댑터 이름이
아니라 **프로파일**을 돈다.
"""
from dataclasses import dataclass
from pathlib import Path

import pytest

from defense import decoy_paths
from defense.config import load as load_decoy_config
from defense.site_profile import load_site_profile
from defense.sites import ProfileSite, get_site
from defense.sites.account_decoy.facade import AUTH_COOKIE, fallback

ROOT = Path(__file__).resolve().parents[1]


@dataclass
class _Settings:
    profile: object


@dataclass
class _Request:
    query_params: dict


@dataclass
class _Ctx:
    path: str
    method: str
    settings: _Settings
    request: _Request


PROFILES = {name: load_site_profile(str(ROOT / f'config/site-{name}.toml'))
            for name in ('juice-shop', 'ruby-shop')}


def _ctx(path, site, method='GET'):
    return _Ctx(path, method, _Settings(PROFILES[site]), _Request({}))


def test_the_decoy_package_name_no_longer_claims_a_site():
    # 패키지 경로에 사이트 이름이 없어야 generic 어댑터가 그걸 import 하지 않는다.
    import defense.sites.account_decoy as package
    assert 'juice_shop' not in package.__name__
    source = (ROOT / 'defense/sites/__init__.py').read_text(encoding='utf-8')
    assert 'juice_shop' not in source
    assert 'account_decoy' in source


def test_no_module_branches_on_a_site_name():
    """코드에 사이트 이름 분기가 남아 있지 않은지 — 사이트 추가가 프로파일로 끝나는 조건.

    주석은 "예전에는 이랬다" 를 설명해야 하므로 사이트 이름을 쓸 수 있다. 검사 대상은
    주석과 문자열 리터럴을 뺀 **코드 토큰**이다.
    """
    import io
    import tokenize

    for module in sorted((ROOT / 'defense').rglob('*.py')):
        source = module.read_text(encoding='utf-8')
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        body = ' '.join(text for kind, text, _, _, _ in tokens
                        if kind not in {tokenize.COMMENT, tokenize.STRING})
        for name in ('site_adapter', 'juice_shop', 'juice-shop', 'ruby_shop', 'ruby-shop'):
            assert name not in body, f'{module.name} 에 {name} 분기가 남아 있다'


def test_the_shared_fallback_serves_the_decoy_stylesheet_for_every_site():
    for site in PROFILES:
        response = fallback(_ctx(decoy_paths.OPERATIONS_CSS, site))
        assert response.status_code == 200, site
        assert response.media_type == 'text/css', site


def test_robots_comes_from_the_profile_for_every_site():
    for site in PROFILES:
        body = fallback(_ctx('/robots.txt', site)).body.decode('utf-8')
        assert 'Disallow: /ftp' in body, site
        assert 'Disallow: /ops/service/manifest' in body, site


def test_only_the_site_that_declares_a_challenge_api_gets_that_reply():
    # juice-shop 프로파일만 challenge_api 를 선언한다.
    juice = fallback(_ctx(PROFILES['juice-shop'].challenge_api, 'juice-shop'))
    assert juice.status_code == 200
    assert b'loginAdminChallenge' in juice.body
    # 선언하지 않은 사이트에서는 같은 경로가 404 다.
    assert not PROFILES['ruby-shop'].challenge_api
    other = fallback(_ctx(PROFILES['juice-shop'].challenge_api, 'ruby-shop'))
    assert other.status_code == 404, '다른 사이트에 없는 엔드포인트를 만들어 주지 않는다'


def test_the_decoy_cookie_name_comes_from_the_catalog():
    assert AUTH_COOKIE == decoy_paths.DECOY_COOKIES['auth']


def test_the_site_object_identity_comes_from_the_profile_not_the_package():
    settings = load_decoy_config(str(ROOT / 'config/decoy-production-ruby-v2.toml'))
    site = get_site(settings)
    assert isinstance(site, ProfileSite)
    assert site.brand == settings.profile.decoy_brand
    assert site.docs_path == decoy_paths.LEGACY
