"""Agent-only proxy with separate medium overlay and high isolation branches.

The detector gateway routes signed, sticky Agent traffic here. Medium risk
receives origin responses with local leads; high risk never dispatches origin.
"""
import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from http.cookies import CookieError, SimpleCookie
import json
import os
from pathlib import Path
import re
import tomllib
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, Request
from starlette.responses import Response

from .config import load as load_decoy_config
from .core import create_app as create_decoy_app, METHODS
from .deception_headers import select_deception_headers
from .detector import DetectorVerifier, sign_headers
from .gateway_contract import isolation_headers
from .high_risk import HighRiskIsolation
from .lure_metrics import LureMetrics, decoy_stage
from .security_store import SecurityStoreError
from .site_profile import SiteProfile, load_site_profile


HOP_HEADERS = frozenset({'connection', 'proxy-connection', 'keep-alive', 'proxy-authenticate',
                         'proxy-authorization', 'te', 'trailer', 'transfer-encoding',
                         'upgrade', 'host'})
LURE_SCRIPT_PATH = '/assets/account-recovery.js'
RECOVERY_PATH = '/ops/recovery/accounts'
RECOVERY_LINK = '</ops/recovery/accounts>; rel="related"; title="Account recovery records"'
LURE_SCRIPT_TEMPLATE = Path(__file__).with_name('account_recovery.js').read_bytes()
DEFAULT_PROFILE_PATH = str(Path(__file__).resolve().parent.parent / 'config/site-juice-shop.toml')


@dataclass(frozen=True)
class OverlaySettings:
    origin_url: str
    decoy_config: str
    site_profile: str = DEFAULT_PROFILE_PATH
    max_request_bytes: int = 1_048_576
    max_response_bytes: int = 16_777_216
    timeout_seconds: float = 10.0

    def __post_init__(self):
        parsed = urlsplit(self.origin_url)
        if (parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username
                or parsed.password or parsed.path not in {'', '/'} or parsed.query or parsed.fragment):
            raise ValueError('origin_url must be a fixed HTTP(S) origin with no path or credentials')
        if not self.decoy_config:
            raise ValueError('decoy_config required')
        if not self.site_profile:
            raise ValueError('site_profile required')
        if not 1 <= self.max_request_bytes <= 1_048_576 or not 4096 <= self.max_response_bytes <= 33_554_432:
            raise ValueError('invalid proxy body limits')
        if not 0 < self.timeout_seconds <= 30:
            raise ValueError('invalid origin timeout')


def load_overlay(path: str) -> OverlaySettings:
    source = Path(path).resolve()
    data = tomllib.loads(source.read_text())
    data['origin_url'] = os.environ.get('OVERLAY_ORIGIN_URL', data['origin_url'])
    decoy = Path(data['decoy_config'])
    data['decoy_config'] = str(decoy if decoy.is_absolute() else source.parent / decoy)
    if 'site_profile' in data:
        profile = Path(data['site_profile'])
        data['site_profile'] = str(profile if profile.is_absolute() else source.parent / profile)
    return OverlaySettings(**data)


def _target(request: Request) -> str:
    raw = request.scope.get('raw_path', b'')
    query = request.scope.get('query_string', b'')
    try:
        path = raw.decode('ascii')
        suffix = query.decode('ascii')
    except UnicodeError as exc:
        raise ValueError('non-ASCII request target') from exc
    if (not path.startswith('/') or path.startswith('//') or '\\' in path or '//' in path
            or any(segment in {'.', '..'} for segment in path.split('/'))
            or re.search(r'(?i)%(?:2e|2f|5c|25)', path) or '#' in path or '?' in path
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in path + suffix)
            or len(raw) + len(query) > 8192):
        raise ValueError('noncanonical request target')
    return path + ('?' + suffix if query else '')


def _is_decoy(path: str) -> bool:
    return (path == '/ftp' or path.startswith('/ftp/')
            or path == '/ops' or path.startswith('/ops/')
            or path == '/assets/operations.css')


def _header_pairs(request: Request) -> list[tuple[str, str]]:
    return [(name.decode('latin-1'), value.decode('latin-1'))
            for name, value in request.scope.get('headers', [])]


def _origin_headers(request: Request, profile: SiteProfile) -> list[tuple[str, str]]:
    result = []
    connection_tokens = {item.strip().lower() for value in request.headers.getlist('connection')
                         for item in value.split(',')}
    for key, value in _header_pairs(request):
        lower = key.lower()
        if (lower in HOP_HEADERS or lower in connection_tokens
                or lower in {'content-length', 'accept-encoding'}
                or (request.method == 'GET'
                    and (request.url.path in {'/', '/index.html'}
                         or 'text/html' in request.headers.get('accept', ''))
                    and lower in {'if-none-match', 'if-modified-since', 'if-range'})
                or lower.startswith('x-defense-') or lower.startswith('x-forwarded-')):
            continue
        if lower == 'cookie':
            parsed = SimpleCookie()
            try:
                parsed.load(value)
            except CookieError as exc:
                raise ValueError('Malformed cookie') from exc
            if value and not parsed:
                raise ValueError('Malformed cookie')
            parts = []
            for morsel in parsed.values():
                if morsel.key in {'defense_session', 'defense_auth', *profile.origin_auth_cookies}:
                    continue
                parts.append(morsel.OutputString())
            if parts:
                result.append(('cookie', '; '.join(parts)))
        elif lower == 'authorization':
            continue
        else:
            result.append((key, value))
    result.append(('accept-encoding', 'identity'))
    return result


def _response(upstream: httpx.Response, body: bytes, *,
              extra: list[tuple[bytes, bytes]] | None = None, head: bool = False,
              rewritten: bool = False) -> Response:
    output = Response(content=b'' if head else body, status_code=upstream.status_code)
    headers = []
    connection_tokens = {item.strip().lower() for value in upstream.headers.get_list('connection')
                         for item in value.split(',')}
    for key, value in upstream.headers.raw:
        lower = key.decode('latin-1').lower()
        if (lower in HOP_HEADERS or lower in connection_tokens or lower.startswith('x-defense-')
                or (extra or rewritten) and lower in {'cache-control', 'etag', 'last-modified', 'expires'}
                or rewritten and lower in {'content-length', 'content-encoding', 'content-md5',
                                           'digest', 'accept-ranges', 'content-range'}):
            continue
        headers.append((key, value))
    if extra or rewritten:
        headers.append((b'cache-control', b'no-store, private'))
    if rewritten:
        headers.append((b'content-length', str(len(body)).encode('ascii')))
    if extra:
        headers.extend(extra)
    output.raw_headers = headers
    return output


def _login_lure_response() -> Response:
    return Response('Invalid email or password. Account recovery records are available at '
                    + RECOVERY_PATH + '.', status_code=401, media_type='text/html',
                    headers={'Link': RECOVERY_LINK,
                             'X-Recovery-API': RECOVERY_PATH,
                             'Cache-Control': 'no-store, private'})


def _agent_robots(body: bytes, profile: SiteProfile) -> bytes:
    base = body.rstrip(b'\r\n')
    if base:
        base += b'\n\n'
    lines = ['# Retained service locations', 'User-agent: *']
    lines.extend('Disallow: ' + path for path in profile.robots_disallow)
    return base + ('\n'.join(lines) + '\n').encode('utf-8')


def _script_for(profile: SiteProfile) -> bytes:
    config = json.dumps(profile.js_config(), ensure_ascii=True, separators=(',', ':'))
    return LURE_SCRIPT_TEMPLATE.replace(b'__LURE_CONFIG_JSON__', config.encode('ascii'))


def _inject_agent_script(body: bytes, selected: dict[str, str]) -> bytes | None:
    marker = re.search(rb'</head\s*>', body, re.IGNORECASE)
    if marker is None:
        return None
    scenario = ('recovery' if 'X-Recovery-API' in selected else
                'legacy' if 'X-Legacy-Storage' in selected else
                'service' if 'X-Internal-API' in selected else '')
    attribute = f' data-deception="{scenario}"' if scenario else ''
    tag = (f'<script src="{LURE_SCRIPT_PATH}"{attribute}></script>').encode('ascii')
    return body[:marker.start()] + tag + body[marker.start():]


def create_overlay_app(settings: OverlaySettings, session_secret: bytes, detector_secret: bytes,
                       *, security_db: str, origin_transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    if len(session_secret) < 32 or len(detector_secret) < 32:
        raise ValueError('session and detector secrets must contain at least 32 bytes')
    profile = load_site_profile(settings.site_profile)
    script = _script_for(profile)
    decoy_settings = replace(load_decoy_config(settings.decoy_config), profile=profile)
    if not decoy_settings.detector_required or decoy_settings.frontend_dir:
        raise ValueError('overlay decoy must require detector signatures and have no frontend snapshot')
    decoy = create_decoy_app(decoy_settings, session_secret, detector_secret=detector_secret,
                             security_db=security_db)
    high_risk = HighRiskIsolation(decoy, profile, detector_secret, script)
    verifier = DetectorVerifier(detector_secret, store_path=security_db)
    metrics = LureMetrics(str(Path(security_db).with_name('lure-events.sqlite3')), detector_secret)
    semaphore = asyncio.Semaphore(8)

    @asynccontextmanager
    async def lifespan(app):
        async with decoy.router.lifespan_context(decoy):
            try:
                yield
            finally:
                metrics.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None,
                  redirect_slashes=False)
    app.state.lure_metrics = metrics

    @app.api_route('/{path:path}', methods=sorted(METHODS))
    async def proxy(request: Request, path: str):
        try:
            target = _target(request)
        except ValueError:
            return Response('Invalid target', status_code=400)
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > settings.max_request_bytes:
                return Response('Request too large', status_code=413)
            body.extend(chunk)
        try:
            risk_headers = request.headers.getlist('x-defense-risk')
            is_high_risk = bool(risk_headers)
            actor = verifier.verify(request, bytes(body),
                                    required_risk='high' if is_high_risk else None)
        except (UnicodeError, SecurityStoreError):
            return Response('Detector state unavailable', status_code=503)
        if actor is None:
            return Response('Signed Agent decision required', status_code=403)
        try:
            if is_high_risk:
                verifier.mark_high_risk(actor)
            elif verifier.is_high_risk(actor):
                # A later medium signature cannot downgrade an isolated actor.
                is_high_risk = True
        except SecurityStoreError:
            return Response('Detector state unavailable', status_code=503)
        async with semaphore:
            if is_high_risk:
                # This branch ends before any origin URL/client is constructed.
                return await high_risk.handle(request, actor, target, bytes(body))
            if request.url.path == LURE_SCRIPT_PATH and request.method in {'GET', 'HEAD'}:
                return Response(b'' if request.method == 'HEAD' else script,
                                media_type='application/javascript',
                                headers={'Cache-Control': 'no-store, private'})
            if request.url.path in profile.login_paths and request.method == 'POST':
                # A successful SQL-injection login must not bypass the lure or
                # return a real origin token to an already-classified Agent.
                metrics.emit(actor, 'login')
                return _login_lure_response()
            if _is_decoy(request.url.path):
                # Re-sign for the inner verifier. The outer nonce was consumed.
                inner_target = target
                aliases = {'/ops/service/session/login': profile.login_path,
                           '/ops/service/session/whoami': profile.login_path.rsplit('/', 1)[0] + '/whoami',
                           '/ops/service/session/logout': profile.login_path.rsplit('/', 1)[0] + '/logout'}
                if mapped := aliases.get(request.url.path):
                    inner_target = mapped + ('?' + target.split('?', 1)[1] if '?' in target else '')
                signed = sign_headers(detector_secret, actor, request.method, inner_target, bytes(body))
                try:
                    forwarded = isolation_headers(_header_pairs(request), signed)
                except ValueError:
                    return Response('Invalid decoy headers', status_code=400)
                transport = httpx.ASGITransport(app=decoy)
                async with httpx.AsyncClient(transport=transport, base_url='http://decoy.local',
                                             trust_env=False, follow_redirects=False) as client:
                    result = await client.request(request.method, inner_target, headers=forwarded,
                                                  content=bytes(body))
                metrics.emit(actor, 'decoy_entry' if request.url.path in {'/ftp', '/ftp/',
                             '/ops/recovery/accounts', '/ops/service/manifest'} else 'decoy_step',
                             decoy_stage(request.url.path))
                return _response(result, result.content, head=request.method == 'HEAD')
            url = httpx.URL(settings.origin_url).copy_with(raw_path=target.encode('ascii'))
            try:
                origin_headers = _origin_headers(request, profile)
            except ValueError:
                return Response('Invalid origin headers', status_code=400)
            try:
                async with httpx.AsyncClient(transport=origin_transport, trust_env=False,
                                             follow_redirects=False, timeout=settings.timeout_seconds) as client:
                    async with client.stream(request.method, url, headers=origin_headers,
                                             content=bytes(body)) as result:
                        chunks, size = [], 0
                        async for chunk in result.aiter_raw():
                            size += len(chunk)
                            if size > settings.max_response_bytes:
                                return Response('Origin response too large', status_code=502)
                            chunks.append(chunk)
                        raw_body = b''.join(chunks)
                        if request.url.path == '/robots.txt' and request.method in {'GET', 'HEAD'}:
                            media_type = result.headers.get('content-type', '').lower()
                            supplied = (result.status_code == 200 and 'text/plain' in media_type and
                                        not result.headers.get('content-encoding'))
                            spa_fallback = result.status_code == 200 and 'text/html' in media_type
                            if result.status_code == 404 or supplied or spa_fallback:
                                robots = _agent_robots(raw_body if supplied else b'', profile)
                                metrics.emit(actor, 'robots')
                                if not supplied:
                                    return Response(b'' if request.method == 'HEAD' else robots,
                                                    media_type='text/plain', headers={
                                                        'Cache-Control': 'no-store, private'})
                                return _response(result, robots, head=request.method == 'HEAD', rewritten=True)
                        selected = select_deception_headers(request.url.path, request.method,
                                                            result.status_code,
                                                            result.headers.get('content-type', ''), profile)
                        if 'X-Recovery-API' in selected:
                            metrics.emit(actor, 'login')
                        elif 'X-Legacy-Storage' in selected:
                            metrics.emit(actor, 'recon')
                        elif 'X-Internal-API' in selected:
                            metrics.emit(actor, 'api')
                        rewritten = False
                        if (request.method == 'GET' and result.status_code < 500
                                and 'text/html' in result.headers.get('content-type', '').lower()
                                and not result.headers.get('content-encoding')):
                            injected = _inject_agent_script(raw_body, selected)
                            if injected is not None:
                                raw_body, rewritten = injected, True
                        extra = [(key.encode('ascii'), value.encode('latin-1'))
                                 for key, value in selected.items()]
                        return _response(result, raw_body, extra=extra,
                                         head=request.method == 'HEAD', rewritten=rewritten)
            except (httpx.HTTPError, OSError):
                return Response('Origin unavailable', status_code=502)

    return app


def app_factory() -> FastAPI:
    settings = load_overlay(os.environ.get('OVERLAY_CONFIG', 'config/overlay-v2.toml'))
    session_secret = Path(os.environ.get('DEFENSE_SECRET_FILE', 'state/session.key')).read_bytes()
    detector_secret = Path(os.environ.get('DEFENSE_DETECTOR_SECRET_FILE', 'state/detector.key')).read_bytes()
    security_db = os.environ.get('DEFENSE_SECURITY_DB', 'state/security.sqlite3')
    return create_overlay_app(settings, session_secret, detector_secret, security_db=security_db)
