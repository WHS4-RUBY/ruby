"""Site-specific entry points and presentation, loaded from one TOML profile."""
from dataclasses import dataclass, field
from functools import lru_cache
import os
from pathlib import Path
import re
import tomllib

from .decoy_paths import OVERLAY_ROOTS, prefixed


# false_success.SYNTHETIC_RESPONSES 가 구현하는 응답 종류. 여기 두는 이유는
# site_profile -> sites.account_decoy.false_success 를 import 하면 순환이 되기 때문이고,
# 양쪽이 같은 집합을 보는지는 tests/test_site_capabilities.py 가 강제한다.
SYNTHETIC_RESPONSE_KINDS = frozenset({
    'ack', 'deluxe_denied', 'empty_basket', 'user_list', 'user_object',
})


@dataclass(frozen=True)
class SiteProfile:
    login_paths: tuple[str, ...]
    login_form_selector: str
    recovery_anchor_selector: str
    menu_selector: str
    account_terms: tuple[str, ...]
    recon_segments: tuple[str, ...]
    recon_html_paths: tuple[str, ...]
    api_prefixes: tuple[str, ...]
    ordinary_api_prefixes: tuple[str, ...]
    ordinary_api_exact: tuple[str, ...]
    origin_auth_cookies: tuple[str, ...]
    robots_disallow: tuple[str, ...]
    decoy_brand: str
    decoy_admin_email: str
    decoy_service: str
    decoy_profile_image: str
    # 이 사이트에서 미끼가 차지하는 경로 네임스페이스. 선언하지 않으면 공용 카탈로그의
    # 값을 쓴다. 코드에 /ftp·/ops 를 박아두는 대신 프로파일이 선언한다.
    decoy_namespaces: tuple[str, ...] = field(default_factory=lambda: OVERLAY_ROOTS)

    # --- 사이트별 미끼 능력 -------------------------------------------------
    # 예전에는 settings.site_adapter 가 닫힌 2값 enum('juice_shop'/'generic')이었고
    # 세 곳에서 런타임 분기했다 — 사이트를 하나 더 붙이려면 코드를 고쳐야 했다.
    # 이제 프로파일이 "이 사이트에 무엇이 있는지" 를 선언하고 코드는 그 선언만 본다
    # (decoy_namespaces 와 같은 방식).

    # 이 사이트의 챌린지 API 경로. 빈 문자열이면 그런 엔드포인트가 없다는 뜻이고
    # 미끼는 404 를 준다 — 없는 엔드포인트를 만들어 주지 않는다.
    challenge_api: str = ''
    # 미끼가 "성공한 척" 응답할 추가 경로. 각 항목은 (경로, 응답 종류) 다.
    # 응답 종류는 코드가 구현하고(false_success.SYNTHETIC_RESPONSES) 프로파일은
    # 어느 경로에 어느 종류를 쓸지만 고른다 — 응답 본문을 TOML 에 적지 않는다.
    synthetic_success: tuple[tuple[str, str], ...] = ()
    # 계정 관련으로 취급할 추가 경로 접두어. 로그인 경로에서 파생되는 접두어에 더해진다.
    account_api_prefixes: tuple[str, ...] = ()

    def __post_init__(self):
        synthetic_paths = tuple(path for path, _ in self.synthetic_success)
        challenge = (self.challenge_api,) if self.challenge_api else ()
        path_lists = (self.login_paths, self.recon_html_paths, self.api_prefixes, self.ordinary_api_prefixes,
                      self.ordinary_api_exact, self.robots_disallow, self.decoy_namespaces,
                      synthetic_paths, challenge, self.account_api_prefixes)
        if not self.login_paths or any(not p.startswith('/') or '//' in p or '\\' in p
                                       or '\r' in p or '\n' in p for group in path_lists for p in group):
            raise ValueError('site profile paths must be absolute and canonical')
        if not all((self.login_form_selector, self.recovery_anchor_selector,
                    self.menu_selector, self.decoy_brand, self.decoy_admin_email,
                    self.decoy_service)):
            raise ValueError('site profile selectors and decoy identity are required')
        if any(not re.fullmatch(r'[A-Za-z0-9._-]+', token)
               for token in (*self.account_terms, *self.recon_segments, *self.origin_auth_cookies)):
            raise ValueError('site profile terms and cookie names must be simple tokens')
        if any('\r' in value or '\n' in value for value in
               (self.decoy_brand, self.decoy_admin_email, self.decoy_service,
                self.decoy_profile_image)):
            raise ValueError('invalid decoy identity')
        if not self.decoy_namespaces:
            raise ValueError('site profile must declare at least one decoy namespace')
        if any(prefixed(p, namespace) for p in self.login_paths
               for namespace in self.decoy_namespaces):
            raise ValueError('login path must not overlap the decoy namespace')
        if any(not any(prefixed(p, namespace) for namespace in self.decoy_namespaces)
               for p in self.robots_disallow):
            raise ValueError('robots clues must target the local decoy')
        # 응답 종류는 코드가 구현한 것만 쓸 수 있다. 오타난 종류가 "그냥 안 되는" 게
        # 아니라 로드 시점에 터져야 한다.
        if any(kind not in SYNTHETIC_RESPONSE_KINDS for _, kind in self.synthetic_success):
            raise ValueError(f'synthetic_success kinds must be one of '
                             f'{sorted(SYNTHETIC_RESPONSE_KINDS)}')
        if len(synthetic_paths) != len(set(synthetic_paths)):
            raise ValueError('synthetic_success declares a path twice')
        # 미끼 네임스페이스는 공용 카탈로그 소관이다. 사이트의 실제 경로가 그 안에
        # 들어오면 미끼와 원본이 같은 경로를 다투게 된다.
        if any(prefixed(p, namespace) for p in synthetic_paths + challenge
               for namespace in self.decoy_namespaces):
            raise ValueError('site routes must not overlap the decoy namespace')

    @property
    def login_path(self) -> str:
        return self.login_paths[0]

    def js_config(self) -> dict:
        return {'loginPaths': self.login_paths,
                'loginFormSelector': self.login_form_selector,
                'recoveryAnchorSelector': self.recovery_anchor_selector,
                'menuSelector': self.menu_selector}


@lru_cache(maxsize=16)
def load_site_profile(path: str) -> SiteProfile:
    data = tomllib.loads(Path(path).read_text())
    for key in ('login_paths', 'account_terms', 'recon_segments', 'recon_html_paths', 'api_prefixes',
                'ordinary_api_prefixes', 'ordinary_api_exact', 'origin_auth_cookies',
                'robots_disallow', 'decoy_namespaces', 'account_api_prefixes'):
        if key in data:
            data[key] = tuple(data[key])
    # synthetic_success 는 TOML 의 인라인 테이블 배열로 적는다 — 경로와 응답 종류가
    # 짝이어야 하므로 평평한 목록으로는 표현할 수 없다.
    if 'synthetic_success' in data:
        rows = data['synthetic_success']
        if not all(isinstance(row, dict) and set(row) == {'path', 'kind'} for row in rows):
            raise ValueError('synthetic_success rows need exactly path and kind')
        data['synthetic_success'] = tuple((row['path'], row['kind']) for row in rows)
    return SiteProfile(**data)


# 프로파일을 아무도 지정하지 않았을 때의 경로. DEFAULT_SITE_PROFILE 로 바꿀 수 있고,
# 기본값만 Juice Shop 으로 둔다(기존 동작 보존).
BUILTIN_PROFILE_PATH = str(Path(__file__).resolve().parent.parent / 'config/site-juice-shop.toml')


def default_site_profile_path() -> str:
    """DEFAULT_SITE_PROFILE 환경변수, 없으면 내장 기본 경로."""
    return os.environ.get('DEFAULT_SITE_PROFILE', '').strip() or BUILTIN_PROFILE_PATH


def default_site_profile() -> SiteProfile:
    return load_site_profile(default_site_profile_path())
