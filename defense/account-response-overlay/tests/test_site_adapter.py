"""미끼 패키지가 특정 사이트에 묶이지 않는지.

디렉터리 이름이 juice_shop 이던 동안 generic 어댑터도 그 패키지의 fallback 을
import 했고, Juice Shop 에만 있는 /api/Challenges 응답을 모든 사이트가 받았다.
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
    site_adapter: str
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


def _ctx(path, adapter, method='GET'):
    profile = load_site_profile(str(ROOT / 'config/site-juice-shop.toml'))
    return _Ctx(path, method, _Settings(adapter, profile), _Request({}))


def test_the_decoy_package_name_no_longer_claims_a_site():
    # 패키지 경로에 사이트 이름이 없어야 generic 어댑터가 그걸 import 하지 않는다.
    import defense.sites.account_decoy as package
    assert 'juice_shop' not in package.__name__
    source = (ROOT / 'defense/sites/__init__.py').read_text(encoding='utf-8')
    assert 'juice_shop' not in source
    assert 'account_decoy' in source


def test_the_shared_fallback_serves_the_decoy_stylesheet_for_every_site():
    for adapter in ('juice_shop', 'generic'):
        response = fallback(_ctx(decoy_paths.OPERATIONS_CSS, adapter))
        assert response.status_code == 200, adapter
        assert response.media_type == 'text/css', adapter


def test_robots_comes_from_the_profile_for_every_site():
    for adapter in ('juice_shop', 'generic'):
        body = fallback(_ctx('/robots.txt', adapter)).body.decode('utf-8')
        assert 'Disallow: /ftp' in body, adapter
        assert 'Disallow: /ops/service/manifest' in body, adapter


def test_only_juice_shop_gets_the_juice_shop_challenge_reply():
    juice = fallback(_ctx('/api/Challenges', 'juice_shop'))
    assert juice.status_code == 200
    assert b'loginAdminChallenge' in juice.body
    generic = fallback(_ctx('/api/Challenges', 'generic'))
    assert generic.status_code == 404, '다른 사이트에 없는 엔드포인트를 만들어 주지 않는다'


def test_the_decoy_cookie_name_comes_from_the_catalog():
    assert AUTH_COOKIE == decoy_paths.DECOY_COOKIES['auth']


def test_the_site_object_identity_comes_from_the_profile_not_the_package():
    settings = load_decoy_config(str(ROOT / 'config/decoy-production-ruby-v2.toml'))
    site = get_site(settings)
    assert isinstance(site, ProfileSite)
    assert site.brand == settings.profile.decoy_brand
    assert site.docs_path == decoy_paths.LEGACY
