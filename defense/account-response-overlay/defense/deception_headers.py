"""Choose one Agent-only deception scenario from an actual origin response."""
from .decoy_paths import clue_headers, prefixed as _prefixed
from .site_profile import SiteProfile, default_site_profile

STATIC_CONTENT = ('image/', 'font/', 'audio/', 'video/')
STATIC_TYPES = {'text/css', 'text/javascript', 'application/javascript',
                'application/x-javascript', 'application/font-woff', 'application/wasm'}
STATIC_SUFFIXES = ('.css', '.js', '.mjs', '.map', '.png', '.jpg', '.jpeg', '.gif',
                   '.webp', '.avif', '.svg', '.ico', '.woff', '.woff2', '.ttf',
                   '.otf', '.eot')


def _recon(path: str, profile: SiteProfile) -> bool:
    # The segment boundary also recognizes /backup.zip and /.env.local.
    return any(segment == term or segment.startswith(term + suffix)
               for segment in path.split('/') for term in profile.recon_segments
               for suffix in ('.', '_', '-')) or any(
                   segment in profile.recon_segments for segment in path.split('/'))


def select_deception_headers(path: str, method: str, status_code: int,
                             content_type: str, profile: SiteProfile | None = None) -> dict[str, str]:
    """Return one pair of clue headers, or an empty mapping."""
    profile = profile or default_site_profile()
    if method.upper() == 'OPTIONS':
        return {}
    lowered = path.lower()
    media_type = content_type.split(';', 1)[0].strip().lower()
    if (media_type.startswith(STATIC_CONTENT) or media_type in STATIC_TYPES
            or lowered.endswith(STATIC_SUFFIXES)):
        return {}
    is_account = any(term in lowered for term in profile.account_terms)
    if is_account and status_code in {401, 403}:
        return clue_headers('recovery')
    html_recon = any(_prefixed(lowered, prefix) for prefix in profile.recon_html_paths)
    if _recon(lowered, profile) and (status_code in {403, 404} or
                                    (html_recon and 200 <= status_code < 300 and media_type == 'text/html')):
        return clue_headers('legacy')
    if is_account or not 200 <= status_code < 300:
        return {}
    if not any(_prefixed(lowered, prefix) or
               (prefix in {'/swagger', '/openapi'} and lowered.startswith(prefix))
               for prefix in profile.api_prefixes):
        return {}
    if (lowered in profile.ordinary_api_exact or
            any(_prefixed(lowered, prefix) for prefix in profile.ordinary_api_prefixes)):
        return {}
    return clue_headers('service')
