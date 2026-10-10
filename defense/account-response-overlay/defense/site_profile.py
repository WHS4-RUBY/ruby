"""Site-specific entry points and presentation, loaded from one TOML profile."""
from dataclasses import dataclass, field
from functools import lru_cache
import os
from pathlib import Path
import re
import tomllib

from .decoy_paths import OVERLAY_ROOTS, prefixed


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

    def __post_init__(self):
        path_lists = (self.login_paths, self.recon_html_paths, self.api_prefixes, self.ordinary_api_prefixes,
                      self.ordinary_api_exact, self.robots_disallow, self.decoy_namespaces)
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
                'robots_disallow', 'decoy_namespaces'):
        if key in data:
            data[key] = tuple(data[key])
    return SiteProfile(**data)


def default_site_profile() -> SiteProfile:
    configured = os.environ.get('DEFAULT_SITE_PROFILE', '').strip()
    return load_site_profile(configured or str(Path(__file__).resolve().parent.parent /
                                               'config/site-juice-shop.toml'))
