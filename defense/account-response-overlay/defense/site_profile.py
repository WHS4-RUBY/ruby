"""Site-specific entry points and presentation, loaded from one TOML profile."""
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import re
import tomllib


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

    def __post_init__(self):
        path_lists = (self.login_paths, self.recon_html_paths, self.api_prefixes, self.ordinary_api_prefixes,
                      self.ordinary_api_exact, self.robots_disallow)
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
        if any(p == '/ftp' or p.startswith('/ftp/') or p == '/ops' or p.startswith('/ops/')
               for p in self.login_paths):
            raise ValueError('login path must not overlap the decoy namespace')
        if any(not (p == '/ftp' or p.startswith('/ftp/') or
                    p == '/ops' or p.startswith('/ops/')) for p in self.robots_disallow):
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
                'robots_disallow'):
        data[key] = tuple(data[key])
    return SiteProfile(**data)


def default_site_profile() -> SiteProfile:
    return load_site_profile(str(Path(__file__).resolve().parent.parent /
                                 'config/site-juice-shop.toml'))
