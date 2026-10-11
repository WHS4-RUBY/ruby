"""사이트별 미끼 능력이 어디서 오는지 — 특성화와 계약.

예전에는 `settings.site_adapter` 가 닫힌 2값 enum(`juice_shop`/`generic`)이고 세 곳에서
런타임 분기했다 — 사이트를 하나 더 붙이려면 코드를 고쳐야 했다. 이제 프로파일이
`challenge_api`·`synthetic_success`·`account_api_prefixes` 로 선언하고 코드는 그 선언만
본다. 이 파일의 단정은 리팩토링 전후로 같아야 한다.
"""
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from defense import decoy_paths
from defense.config import Limits, load as load_decoy_config
from defense.site_profile import load_site_profile
from defense.sites import ProfileSite, get_site
from defense.sites.account_decoy.engagement import Engagement
from defense.sites.account_decoy.false_success import FalseSuccess

ROOT = Path(__file__).resolve().parents[1]

JUICE = load_site_profile(str(ROOT / 'config/site-juice-shop.toml'))
RUBY = load_site_profile(str(ROOT / 'config/site-ruby-shop.toml'))

# Juice Shop 에서만 미끼가 "성공한 척" 응답하는 여섯 경로.
JUICE_ONLY_ROUTES = (
    '/api/Users', '/api/Users/1', '/api/Challenges',
    '/rest/saveLoginIp', '/rest/deluxe-membership', '/rest/basket/1',
)


@dataclass
class _Session:
    authenticated: bool = True
    auth_token: str = 'token-for-tests'
    login_completed: bool = False
    journey: dict = field(default_factory=dict)


@dataclass
class _Request:
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    query_params: dict = field(default_factory=dict)


@dataclass
class _Settings:
    profile: object
    secure_cookie: bool = False
    limits: Limits = field(default_factory=Limits)


@dataclass
class _Ctx:
    path: str
    method: str
    settings: _Settings
    session: _Session = field(default_factory=_Session)
    request: _Request = field(default_factory=_Request)
    meta: dict = field(default_factory=dict)


def _ctx(path, *, profile=JUICE, method='GET', authenticated=True):
    session = _Session(authenticated=authenticated)
    request = _Request(
        headers={'authorization': 'Bearer ' + session.auth_token} if authenticated else {},
    )
    return _Ctx(path, method, _Settings(profile), session, request)


async def _claims(hook, ctx):
    """FalseSuccess 가 이 경로를 자기 것으로 주장하는지(None 이 아니면 주장)."""
    return await hook.on_request(ctx) is not None


# ---------------------------------------------------------------------------
# 합성 성공 응답 — 어느 경로를 미끼가 가로채는가
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_the_profile_derived_account_routes_are_claimed_for_every_site():
    """로그인 경로에서 파생되는 네 라우트는 사이트와 무관하게 주장한다."""
    hook = FalseSuccess()
    for profile in (JUICE, RUBY):
        root = profile.login_path.rsplit('/', 1)[0]
        for path in (profile.login_path, root + '/whoami',
                     root + '/logout', root + '/authentication-details'):
            method = 'POST' if path.endswith(('/login', '/logout')) else 'GET'
            assert await _claims(hook, _ctx(path, profile=profile, method=method)), \
                f'{profile.login_path}: {path}'


@pytest.mark.asyncio
async def test_the_juice_shop_only_routes_are_claimed_only_there():
    hook = FalseSuccess()
    for path in JUICE_ONLY_ROUTES:
        assert await _claims(hook, _ctx(path, profile=JUICE)), path
        assert not await _claims(hook, _ctx(path, profile=RUBY)), \
            f'{path} 가 선언하지 않은 사이트에서도 주장됐다'


@pytest.mark.asyncio
async def test_the_juice_shop_response_shapes():
    """각 경로의 응답 모양. 사이트마다 다른 셰이프이므로 그대로 고정한다."""
    import json

    hook = FalseSuccess()

    basket = await hook.on_request(_ctx('/rest/basket/1'))
    assert json.loads(basket.body) == {'status': 'success', 'data': {'id': 1, 'Products': []}}

    deluxe = await hook.on_request(_ctx('/rest/deluxe-membership'))
    assert json.loads(deluxe.body) == {'status': 'success', 'data': False}

    save_ip = await hook.on_request(_ctx('/rest/saveLoginIp'))
    assert json.loads(save_ip.body) == {'status': 'success'}

    # /api/Users 는 목록, /api/Users/1 은 객체 하나.
    users = json.loads((await hook.on_request(_ctx('/api/Users'))).body)
    assert isinstance(users['data'], list) and len(users['data']) == 1
    one = json.loads((await hook.on_request(_ctx('/api/Users/1'))).body)
    assert isinstance(one['data'], dict) and one['data']['id'] == 1

    # 로그인 경로에서 파생되는 authentication-details 는 프로파일이 선언하지 않지만
    # 분기 끝의 catch-all 이 사용자 목록을 돌려준다. 처음 특성화에서 빠뜨렸던 항목이고
    # 리팩토링이 KeyError 로 드러내 준 덕에 여기 고정한다.
    for profile in (JUICE, RUBY):
        root = profile.login_path.rsplit('/', 1)[0]
        details = json.loads(
            (await hook.on_request(_ctx(root + '/authentication-details', profile=profile))).body)
        assert isinstance(details['data'], list) and len(details['data']) == 1, profile.login_path

    # 챌린지 응답은 인증을 요구하지 않는다 — 인증 검사보다 **먼저** 처리된다.
    challenges = await hook.on_request(_ctx('/api/Challenges', authenticated=False))
    assert challenges.status_code == 200
    assert b'loginAdminChallenge' in challenges.body


@pytest.mark.asyncio
async def test_unauthenticated_requests_are_refused_except_the_challenge_api():
    hook = FalseSuccess()
    for path in ('/api/Users', '/api/Users/1', '/rest/basket/1',
                 '/rest/deluxe-membership', '/rest/saveLoginIp'):
        response = await hook.on_request(_ctx(path, authenticated=False))
        assert response.status_code == 401, path


# ---------------------------------------------------------------------------
# engagement 의 계정 경로 판별
# ---------------------------------------------------------------------------

def test_the_account_family_prefixes():
    hook = Engagement()
    juice_ctx = _ctx('/x', profile=JUICE)
    # 로그인 경로에서 파생되는 접두어.
    assert hook.family('/rest/user/login', juice_ctx) == 'accounts'
    # 프로파일과 무관하게 박혀 있는 세 접두어.
    for path in ('/api/Users', '/administration', '/account'):
        assert hook.family(path, juice_ctx) == 'accounts', path
    assert hook.family('/products', juice_ctx) is None

    # 다른 사이트에서도 그 세 접두어가 그대로 계정 경로로 잡힌다.
    ruby_ctx = _ctx('/x', profile=RUBY)
    assert hook.family('/api/auth/login', ruby_ctx) == 'accounts'
    for path in ('/api/Users', '/administration', '/account'):
        assert hook.family(path, ruby_ctx) == 'accounts', path


def test_the_account_family_needs_a_context():
    """**동작 변경**: ctx 가 없으면 어떤 사이트인지 알 수 없으므로 판정하지 않는다.

    예전에는 Juice Shop 의 로그인 루트(`/rest/user`)를 가정했다 — "모르면 Juice Shop"
    이라는 숨은 기본값이었다. 실제 호출부 네 곳은 모두 ctx 를 넘기므로(cycle.py:171,201,
    engagement.py:118,204) 이 분기는 운영에서 도달하지 않는다.
    """
    hook = Engagement()
    assert hook.family('/rest/user/login', None) is None
    assert hook.family('/api/auth/login', None) is None


# ---------------------------------------------------------------------------
# 미끼 문서 경로의 출처
# ---------------------------------------------------------------------------

def test_the_docs_path_source():
    """지금은 공용 카탈로그에서 온다 — 프로파일의 네임스페이스 선언을 보지 않는다."""
    settings = load_decoy_config(str(ROOT / 'config/decoy-production-ruby-v2.toml'))
    site = get_site(settings)
    assert isinstance(site, ProfileSite)
    assert site.docs_path == decoy_paths.LEGACY


# ---------------------------------------------------------------------------
# 레지스트리 계약
# ---------------------------------------------------------------------------

def test_the_response_kind_sets_agree():
    """프로파일 검증기와 구현이 같은 종류 집합을 본다.

    `site_profile` 이 `false_success` 를 import 하면 순환이 되므로 집합이 두 곳에
    적혀 있다. 어긋나면 프로파일이 통과한 종류를 구현이 모르는(KeyError) 상태가 된다.
    """
    from defense.site_profile import SYNTHETIC_RESPONSE_KINDS
    from defense.sites.account_decoy.false_success import SYNTHETIC_RESPONSES

    assert set(SYNTHETIC_RESPONSES) == set(SYNTHETIC_RESPONSE_KINDS)


def test_an_unknown_response_kind_fails_at_load():
    """오타난 종류가 "그냥 안 되는" 게 아니라 로드 시점에 터져야 한다."""
    from dataclasses import replace as dataclass_replace

    with pytest.raises(ValueError, match='synthetic_success kinds'):
        dataclass_replace(JUICE, synthetic_success=(('/api/Users', 'no_such_kind'),))
    with pytest.raises(ValueError, match='declares a path twice'):
        dataclass_replace(JUICE, synthetic_success=(('/a', 'ack'), ('/a', 'ack')))


def test_site_routes_may_not_claim_the_decoy_namespace():
    """사이트의 실제 경로가 미끼 네임스페이스를 침범하면 둘이 같은 경로를 다툰다."""
    from dataclasses import replace as dataclass_replace

    with pytest.raises(ValueError, match='must not overlap the decoy namespace'):
        dataclass_replace(JUICE, synthetic_success=(('/ops/service/manifest', 'ack'),))
    with pytest.raises(ValueError, match='must not overlap the decoy namespace'):
        dataclass_replace(JUICE, challenge_api='/ftp/challenges')
