"""High-risk Agent responses. This module has no origin address or origin client."""
from html import escape

import httpx
from fastapi import Request
from starlette.responses import JSONResponse, Response

from .deception_headers import _recon
from .decoy_paths import (ARCHIVE, AUDIT, HOP_HEADERS, IDENTITY, LEGACY, LURE_SCRIPT, MANIFEST,
                          RECOVERY, SERVICE, is_overlay_decoy, prefixed, robots_body,
                          session_aliases)
from .detector import sign_headers
from .gateway_contract import isolation_headers
from .model import page
from .site_profile import SiteProfile

CONSOLE_CARDS = (
    ('Account Registry', RECOVERY, 'Review account records and pending access references.'),
    ('Legacy Storage', LEGACY, 'Browse retained files and older service records.'),
    ('Backup Management', ARCHIVE, 'Inspect archived source documents and revisions.'),
    ('Service Manifest', MANIFEST, 'View the internal service inventory and references.'),
    ('Audit Logs', AUDIT, 'Review the retained operations event index.'),
)
CONSOLE_BRAND = IDENTITY['consoleBrand']


def _local_page(title: str, body: str, *, head: bool) -> Response:
    response = page(title, body, brand=CONSOLE_BRAND,
                    home_label='Dashboard', docs_path=LEGACY)
    response.headers.update({
        'Cache-Control': 'no-store, private',
        'X-Content-Type-Options': 'nosniff',
        'X-Robots-Tag': 'noindex, nofollow, noarchive',
        'Content-Security-Policy': "default-src 'none'; style-src 'self' 'unsafe-inline'; "
                                   "frame-ancestors 'none'; base-uri 'none'",
    })
    if head:
        response.body = b''
    return response


def _console(*, head: bool) -> Response:
    cards = ''.join(
        '<a class="console-card" href="' + escape(path, quote=True) + '">'
        '<span class="console-label">MODULE ' + f'{index:02d}' + '</span>'
        '<h2>' + escape(label) + '</h2><p>' + escape(description) + '</p>'
        '<span class="console-open">Open →</span></a>'
        for index, (label, path, description) in enumerate(CONSOLE_CARDS, 1)
    )
    body = (
        '<style>.console-intro{color:#c9d0d4;max-width:680px;margin:0 0 26px}'
        '.console-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(245px,1fr));'
        'gap:14px}.console-card{display:flex;flex-direction:column;min-height:172px;'
        'padding:19px 20px;border:1px solid #586064;border-radius:8px;background:#252a2c;'
        'color:#e8ecef;text-decoration:none}.console-card:hover,.console-card:focus-visible{'
        'border-color:#c4de86;background:#2c3431;outline:2px solid #c4de86;outline-offset:2px}'
        '.console-card h2{margin:9px 0 6px;font-size:19px}.console-card p{margin:0 0 18px;'
        'color:#c2cbd0;font-size:14px;line-height:1.5}.console-label{font-size:11px;'
        'letter-spacing:.12em;color:#c4de86;font-weight:700}.console-open{margin-top:auto;'
        'font-size:14px;font-weight:700;color:#c4de86}</style>'
        '<p class="console-intro">Select an operations area to review retained service '
        'records and pending references.</p><nav class="console-grid" aria-label="Operations modules">'
        + cards + '</nav>'
    )
    return _local_page(CONSOLE_BRAND, body, head=head)


def _audit_index(*, head: bool) -> Response:
    # Synthetic index only. The defender's private audit database is never read here.
    rows = (
        ('Account reconciliation', RECOVERY, 'Pending review'),
        ('Archived source verification', ARCHIVE, 'Reference available'),
        ('Service inventory check', MANIFEST, 'Reference available'),
    )
    table = ''.join('<tr><td>' + escape(event) + '</td><td>' + escape(status) +
                    '</td><td><a href="' + escape(path, quote=True) + '">View record</a></td></tr>'
                    for event, path, status in rows)
    body = ('<p>Retained operations events are indexed by their source records.</p>'
            '<table><thead><tr><th>Event</th><th>Status</th><th>Reference</th></tr></thead>'
            '<tbody>' + table + '</tbody></table>')
    return _local_page('Audit Logs', body, head=head)


def _inner_response(result: httpx.Response, *, head: bool) -> Response:
    response = Response(b'' if head else result.content, status_code=result.status_code)
    response.raw_headers = [(name, value) for name, value in result.headers.raw
                            if name.decode('latin-1').lower() not in HOP_HEADERS
                            and not name.lower().startswith(b'x-defense-')]
    return response


def _html_error(status: int, title: str, target: str, label: str, *, head: bool) -> Response:
    body = ('<!doctype html><html><head><meta charset="utf-8"><title>' + escape(title) +
            '</title></head><body><main><h1>' + escape(title) + '</h1><p>' +
            escape('A retained service may contain the requested record.') +
            '</p><a href="' + escape(target, quote=True) + '">' + escape(label) +
            '</a></main></body></html>').encode()
    return Response(b'' if head else body, status_code=status, media_type='text/html',
                    headers={'Cache-Control': 'no-store, private',
                             'Link': f'<{target}>; rel="related"'})


class HighRiskIsolation:
    """Handles every high-risk URL locally or through the existing ASGI decoy."""

    def __init__(self, decoy, profile: SiteProfile, detector_secret: bytes, script: bytes):
        self.decoy = decoy
        self.profile = profile
        self.detector_secret = detector_secret
        self.script = script

    async def _decoy(self, request: Request, actor: str, target: str, body: bytes,
                     *, mapped: str | None = None) -> Response:
        path = request.url.path
        aliases = session_aliases(self.profile.login_path)
        inner_target = mapped or aliases.get(path) or target
        signed = sign_headers(self.detector_secret, actor, request.method, inner_target, body)
        pairs = [(name.decode('latin-1'), value.decode('latin-1'))
                 for name, value in request.scope.get('headers', [])]
        try:
            headers = isolation_headers(pairs, signed)
        except ValueError:
            return Response('Invalid decoy headers', status_code=400)
        # ASGITransport dispatches inside this process. No socket or origin URL exists here.
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.decoy),
                                         base_url='http://decoy.local', trust_env=False,
                                         follow_redirects=False) as client:
                result = await client.request(request.method, inner_target, headers=headers,
                                              content=body)
        except (httpx.HTTPError, OSError):
            return Response('Decoy unavailable', status_code=502)
        return _inner_response(result, head=request.method == 'HEAD')

    async def handle(self, request: Request, actor: str, target: str, body: bytes) -> Response:
        path, method = request.url.path, request.method
        head = method == 'HEAD'
        if method in {'GET', 'HEAD'} and path in {'/', '/index.html', SERVICE, SERVICE + '/'}:
            return _console(head=head)
        if method in {'GET', 'HEAD'} and path in {AUDIT, AUDIT + '/'}:
            return _audit_index(head=head)
        if is_overlay_decoy(path):
            return await self._decoy(request, actor, target, body)
        if path == LURE_SCRIPT and method in {'GET', 'HEAD'}:
            return Response(b'' if head else self.script, media_type='application/javascript',
                            headers={'Cache-Control': 'no-store, private'})
        if path == '/robots.txt' and method in {'GET', 'HEAD'}:
            content = robots_body(self.profile.robots_disallow).decode('utf-8')
            return Response('' if head else content, media_type='text/plain',
                            headers={'Cache-Control': 'no-store, private'})
        login_path = path in self.profile.login_paths or path in {'/login', '/signin', '/sign-in'}
        if login_path and method in {'GET', 'HEAD'}:
            return await self._decoy(request, actor, target, body, mapped=RECOVERY)
        if login_path and method == 'POST':
            return _html_error(401, 'Account recovery required', RECOVERY,
                               'Open account recovery records', head=head)
        if method in {'GET', 'HEAD'} and path in {'/admin', '/administration'}:
            return await self._decoy(request, actor, target, body, mapped=LEGACY)
        lowered = path.lower()
        if _recon(lowered, self.profile):
            return _html_error(404, 'Resource not found', LEGACY, 'Open legacy storage',
                               head=head)
        api = any(prefixed(lowered, prefix) or
                  (prefix in {'/swagger', '/openapi'} and lowered.startswith(prefix))
                  for prefix in self.profile.api_prefixes)
        if api:
            if method in {'GET', 'HEAD'} and lowered.startswith(('/swagger', '/openapi')):
                return await self._decoy(request, actor, target, body, mapped=MANIFEST)
            account = any(term in lowered for term in self.profile.account_terms)
            target_path = RECOVERY if account else MANIFEST
            content = {'status': 'unavailable', 'related_service': target_path}
            response = JSONResponse(content, status_code=401 if account else 404,
                                    headers={'Cache-Control': 'no-store, private',
                                             'Link': f'<{target_path}>; rel="related"'})
            if head:
                response.body = b''
            return response
        return _html_error(404, 'Resource not found', MANIFEST,
                           'Open service manifest', head=head)
