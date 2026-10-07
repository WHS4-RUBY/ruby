"""Sealed isolation runtime: local state, local site adapter, no origin HTTP client."""
import asyncio
from contextlib import asynccontextmanager
import re
import secrets
import sqlite3
import time
from fastapi import FastAPI, Request
from .audit import Audit
from .config import Settings
from .sites import get_site
from .model import ProxyContext, error
from .state import State, CapacityError
from .detector import DetectorVerifier
from .security_store import SecurityStoreError

COOKIE = 'defense_session'
METHODS = {'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'}


class Boundary:
    """Bound HTTP admission before routing, buffering, hooks, and artificial sleeps."""
    def __init__(self, app, state):
        self.app, self.state = app, state

    async def __call__(self, scope, receive, send):
        if scope['type'] == 'websocket':
            await send({'type': 'websocket.close', 'code': 1008})
            return
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        limits, state = self.state.limits, self.state
        code, message = 0, ''
        headers = scope.get('headers', [])
        raw = scope.get('raw_path', b'')
        query = scope.get('query_string', b'')
        peer = (scope.get('client') or ('unknown', 0))[0]
        if not state.admit_peer(peer):
            code, message = 429, 'Request rate exceeded'
        elif state.inflight >= limits.concurrent:
            code, message = 503, 'Gateway busy'
        elif len(raw) + len(query) > limits.url_bytes:
            code, message = 414, 'URL limit exceeded'
        elif sum(len(k) + len(v) + 4 for k, v in headers) > limits.header_bytes:
            code, message = 431, 'Header limit exceeded'
        elif scope['method'] not in METHODS or any(k == b'upgrade' for k, _ in headers):
            code, message = 405, 'Protocol or method not supported'
        elif raw not in getattr(state, 'frontend_paths', set()) and (not re.fullmatch(rb'/[A-Za-z0-9/_.-]*', raw) or b'//' in raw
              or any(part in {b'.', b'..'} for part in raw.split(b'/'))):
            code, message = 400, 'Noncanonical path'
        elif any(k == b'content-encoding' and v.lower() != b'identity' for k, v in headers):
            code, message = 415, 'Encoded request bodies are not accepted'
        if code:
            response = error(code, message)
            response.headers['cache-control'] = 'no-store'
            response.headers['connection'] = 'close'
            return await response(scope, receive, send)
        state.inflight += 1
        started = False

        async def tracked_send(message):
            nonlocal started
            if message['type'] == 'http.response.start':
                started = True
            await send(message)

        try:
            async with asyncio.timeout(limits.request_seconds):
                await self.app(scope, receive, tracked_send)
        except TimeoutError:
            if not started:
                response = error(504, 'Request deadline exceeded')
                response.headers['connection'] = 'close'
                response.headers['cache-control'] = 'no-store'
                await response(scope, receive, send)
        finally:
            state.inflight -= 1


def build_hooks(settings, site):
    if settings.modules == ('unified',):
        from .sites.juice_shop.unified import UnifiedDefense
        return [UnifiedDefense()]
    from .sites.juice_shop.cycle import CyclicDefense
    return [CyclicDefense()]


def create_app(settings: Settings, secret: bytes, *, transport=None, detector_secret: bytes | None = None,
               security_db: str = '') -> FastAPI:
    if len(secret) < 32:
        raise ValueError('session secret must contain at least 32 bytes')
    state = State(secret, settings.limits)
    site = get_site(settings)
    hooks = build_hooks(settings, site)
    # This package's decoy never serves a copied frontend. The overlay fetches
    # the real UI and static assets from its configured origin.
    if settings.frontend_dir:
        raise ValueError('The response-overlay decoy must be headless')
    state.frontend_paths = set()
    verifier = DetectorVerifier(detector_secret or b'', store_path=security_db) if settings.detector_required else None

    @asynccontextmanager
    async def lifespan(app):
        audit = Audit(settings.audit_path, settings.limits.audit_rows)
        app.state.audit = audit
        try:
            yield
        finally:
            audit.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None,
                  redirect_slashes=False)
    app.state.defense = state
    app.state.settings = settings
    app.state.site = site
    app.add_middleware(Boundary, state=state)

    @app.api_route('/{path:path}', methods=sorted(METHODS))
    async def proxy(request: Request, path: str):
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > settings.limits.request_bytes:
                response = error(413, 'Request body limit exceeded')
                response.headers['connection'] = 'close'
                return response
            body.extend(chunk)
        actor = None
        if verifier is not None:
            try:
                actor = verifier.verify(request, bytes(body))
            except UnicodeError:
                actor = None
            except SecurityStoreError:
                return error(503, "Detection state unavailable")
            if actor is None:
                return error(404, 'Resource not found')
        request_settings, selected_hooks, arm, purpose = settings, hooks, 'configured', 'validation'
        try:
            session = state.get_session(request.cookies.get(COOKIE), actor=actor)
        except CapacityError:
            return error(503, 'Session capacity reached')
        if session.policy is not None and session.policy != request_settings.modules:
            return error(503, 'Start a new actor when changing defense policy')
        session.policy = request_settings.modules
        if session.active >= settings.limits.session_concurrent:
            return error(429, 'Session has a request in progress')
        if session.requests >= settings.limits.session_requests or session.bytes_sent >= settings.limits.session_bytes:
            return error(429, 'Session budget exhausted')
        session.active += 1
        session.requests += 1
        trace = secrets.token_hex(8)
        ctx = ProxyContext(request, trace, request.method, request.url.path, bytes(body), session, request_settings)
        ctx.meta['site'] = site
        started = time.monotonic()
        try:
            try:
                for hook in selected_hooks:
                    ctx.response = await hook.on_request(ctx)
                    if ctx.response is not None:
                        ctx.short_circuited = True
                        break
                if ctx.response is None:
                    ctx.response = site.fallback(ctx)
                for hook in selected_hooks:
                    await hook.on_response(ctx)
            except ValueError as exc:
                ctx.meta['error'] = type(exc).__name__
                ctx.response = None
                for hook in selected_hooks:
                    ctx.response = await hook.on_error(ctx, exc)
                    if ctx.response is not None:
                        break
                if ctx.response is None:
                    ctx.response = error(502, 'Gateway operation failed')
            response = ctx.response
            if len(response.body) > settings.limits.response_bytes:
                response = error(503, 'Response budget exceeded')
            if session.bytes_sent + len(response.body) > settings.limits.session_bytes:
                session.bytes_sent = settings.limits.session_bytes
                response = error(429, 'Session byte budget exceeded')
            else:
                session.bytes_sent += len(response.body)
            response.headers['cache-control'] = 'no-store, private'
            response.headers['x-content-type-options'] = 'nosniff'
            response.headers['x-robots-tag'] = 'noindex, nofollow, noarchive'
            response.headers['referrer-policy'] = 'no-referrer'
            response.headers['content-security-policy'] = (
                "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; "
                "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            response.headers['x-request-id'] = trace
            response.set_cookie(COOKIE, state.sign(session.sid), httponly=True, samesite='strict',
                                secure=settings.secure_cookie, max_age=settings.limits.session_ttl, path='/')
            common = {'module': ctx.meta.get('module', 'facade'), 'http_status': response.status_code,
                      'arm': arm, 'purpose': purpose, 'request_index': session.requests,
                      'origin_dispatched': ctx.meta.get('origin_dispatched', False),
                      'agent_completion': None, 'origin_goal_achieved': None,
                      'duration_ms': round((time.monotonic() - started) * 1000, 2),
                      'bytes': len(response.body), 'method': request.method}
            if 'engagement_event' in ctx.meta:
                # Finite enums/counts only; never log proof values, credentials or raw payloads.
                common['engagement'] = ctx.meta['engagement_event']
            # Do not log URL query, cookies, authorization, input body, credentials, or raw IP.
            app.state.audit.emit('request', request_settings.run_id, session.sid, trace, **common,
                                 node=ctx.meta.get('node'), revisit=ctx.meta.get('revisit'))
            if result := ctx.meta.get('synthetic_result'):
                if response.status_code < 300:
                    app.state.audit.emit('synthetic_result', request_settings.run_id, session.sid, trace,
                                         delivery='prepared', **result)
            if request.method == 'HEAD':
                response.body = b''  # Preserve the GET representation length; conservative byte charging.
            return response
        except (sqlite3.Error, OSError):
            return error(503, 'Audit storage unavailable')
        finally:
            session.active -= 1

    return app
