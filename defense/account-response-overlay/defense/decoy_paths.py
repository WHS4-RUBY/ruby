"""One source for this package's decoy paths, loaded from the shared catalog.

The same five-way decoy predicate used to live in `overlay._is_decoy`,
`high_risk._is_local_decoy` and (minus one arm) `site_profile`'s validation, the
entry/step split lived as a fourth literal set in `overlay`, and robots.txt was
generated in three places. They are all here now, driven by
`config/decoy-catalog.json`, whose editable original is `shared/decoy-catalog.json`.

This module is deliberately standard-library only so a cross-service contract
test can import it without the overlay's pinned fastapi.

Precondition for the path predicates: callers pass an already canonical path.
`overlay._target()` rejects `//`, `.`/`..` segments, `\\`, `#`, `?`, `%2e/%2f/%5c/%25`
and non-ASCII before any of these run, and `core.Boundary` re-rejects anything
outside `/[A-Za-z0-9/_.-]*` for the inner decoy. The predicates stay
case-sensitive and un-normalized because of that, so reusing them anywhere
without an equivalent gate would be bypassable — check `is_canonical_path()`
first at any new call site.
"""
import json
from pathlib import Path
import re

CATALOG_PATH = Path(__file__).resolve().parent.parent / 'config/decoy-catalog.json'
CATALOG = json.loads(CATALOG_PATH.read_text(encoding='utf-8'))

_OVERLAY = CATALOG['namespaces']['overlay']
OVERLAY_ROOTS: tuple[str, ...] = tuple(_OVERLAY['roots'])
OVERLAY_ASSETS: tuple[str, ...] = tuple(_OVERLAY['assets'])
OVERLAY_PATHS: dict[str, str] = dict(CATALOG['overlayPaths'])
ENTRIES: tuple[str, ...] = tuple(CATALOG['overlayEntries'])
SESSION_ALIAS_ROOT: str = CATALOG['sessionAliasRoot']
STAGE_FAMILIES: tuple[str, ...] = tuple(CATALOG['stageFamilies'])
IDENTITY: dict[str, str] = dict(CATALOG['identity'])
DECOY_COOKIES: dict[str, str] = dict(CATALOG['decoyCookies'])

LEGACY = OVERLAY_PATHS['legacy']
RECOVERY = OVERLAY_PATHS['recovery']
MANIFEST = OVERLAY_PATHS['manifest']
AUDIT = OVERLAY_PATHS['audit']
ARCHIVE = OVERLAY_PATHS['archive']
SERVICE = OVERLAY_PATHS['service']
OPERATIONS_CSS = OVERLAY_PATHS['operationsCss']
LURE_SCRIPT = OVERLAY_PATHS['lureScript']

# The decoy entry set historically carried the trailing-slash variant of /ftp only.
# Generalizing that is a behavior change and is handled in its own commit.
_ENTRY_EXACT = frozenset(ENTRIES) | {LEGACY + '/'}

# Verbatim in overlay.py and high_risk.py before this module existed.
HOP_HEADERS = frozenset({'connection', 'proxy-connection', 'keep-alive', 'proxy-authenticate',
                         'proxy-authorization', 'te', 'trailer', 'transfer-encoding',
                         'upgrade', 'host'})

_CANONICAL = re.compile(r'/[A-Za-z0-9/_.-]*\Z')
_STAGE = re.compile(r'^/ops/(' + '|'.join(STAGE_FAMILIES) + r')(?:/([^/]+))?(?:/([^/]+))?')


def is_canonical_path(path: str) -> bool:
    """The gate `core.Boundary` applies, for call sites without `_target()`."""
    return bool(_CANONICAL.fullmatch(path)) and '//' not in path and not any(
        segment in {'.', '..'} for segment in path.split('/'))


def prefixed(path: str, prefix: str) -> bool:
    """Segment boundary match. Also recognizes /backup.zip and /.env.local callers."""
    return path == prefix or path.startswith(prefix + '/')


def is_overlay_decoy(path: str) -> bool:
    """The decoy namespace this package serves locally, plus its own stylesheet."""
    return any(prefixed(path, root) for root in OVERLAY_ROOTS) or path == OPERATIONS_CSS


def is_entry(path: str) -> bool:
    """A landing page of the decoy rather than a step inside one."""
    return path in _ENTRY_EXACT


def session_aliases(login_path: str) -> dict[str, str]:
    """Decoy session routes mapped onto the site's real authentication paths."""
    base = login_path.rsplit('/', 1)[0]
    return {SESSION_ALIAS_ROOT + '/login': login_path,
            SESSION_ALIAS_ROOT + '/whoami': base + '/whoami',
            SESSION_ALIAS_ROOT + '/logout': base + '/logout'}


def clue_headers(kind: str) -> dict[str, str]:
    """One Link header plus its scenario-specific companion header."""
    spec = CATALOG['clueHeaders'][kind]
    path = OVERLAY_PATHS[spec['pathKey']]
    return {'Link': f'<{path}>; rel="related"; title="{spec["title"]}"', spec['header']: path}


def lure_script_config() -> dict[str, dict[str, str]]:
    """Paths and clue header names the browser lure script matches against."""
    return {kind: {'path': OVERLAY_PATHS[spec['pathKey']], 'header': spec['header']}
            for kind, spec in CATALOG['clueHeaders'].items()}


def robots_body(disallow, *, origin: bytes = b'') -> bytes:
    """Append the retained decoy locations to whatever the origin supplied."""
    base = origin.rstrip(b'\r\n')
    if base:
        base += b'\n\n'
    lines = ['# Retained service locations', 'User-agent: *']
    lines.extend('Disallow: ' + path for path in disallow)
    return base + ('\n'.join(lines) + '\n').encode('utf-8')


def decoy_stage(path: str) -> str:
    """Record only the path family and numeric step, never tokens or payloads."""
    match = _STAGE.match(path)
    if match:
        family, branch, step = match.groups()
        if branch == 'accounts' and step and step.isdecimal():
            return f'{family}:accounts:{step[:9]}'
        return f'{family}:{branch}' if branch and re.fullmatch(r'[a-zA-Z_-]+', branch) else family
    return 'ftp' if path.startswith(LEGACY) else 'decoy'


def normalize_decoy_key(path: str) -> str:
    """Collapse a path to one escalation-counting key, as the sidecar does."""
    bare = path.split('?', 1)[0].split('#', 1)[0]
    return re.sub(r'/{2,}', '/', bare).rstrip('/').lower() or '/'
