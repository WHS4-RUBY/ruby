"""Production HTTP configs and RUBY's real login/Bearer contract."""
from dataclasses import replace
import json
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, Request
from starlette.responses import JSONResponse, Response

from defense.config import load as load_decoy_config
from defense.detector import sign_headers
from defense.overlay import create_overlay_app, load_overlay
from defense.security_store import initialize_security_store
from defense.site_profile import load_site_profile


ROOT = Path(__file__).resolve().parents[1]
KEY = b'detector-key-for-tests-only-0123456789'
SESSION = b'session-key-for-tests-only-0123456789'


def _test_settings(tmp_path, name):
    settings = load_overlay(str(ROOT / 'config' / name))
    decoy = load_decoy_config(settings.decoy_config)
    assert decoy.detector_required and not decoy.secure_cookie
    assert decoy.audit_path == '/app/state/telemetry.sqlite3'
    assert decoy.site_adapter == ('generic' if 'ruby' in name else 'juice_shop')
    assert settings.origin_url == ('http://ruby-web-target:8080' if 'ruby' in name
                                   else 'http://juice-shop-target:3000')
    copy = tmp_path / 'decoy.toml'
    copy.write_text(Path(settings.decoy_config).read_text().replace(
        '/app/state/events.sqlite3', str(tmp_path / 'events.sqlite3')))
    return replace(settings, origin_url='http://origin.invalid', decoy_config=str(copy))


def _make_overlay(tmp_path, name, origin):
    security = tmp_path / 'security.sqlite3'
    initialize_security_store(str(security))
    return create_overlay_app(_test_settings(tmp_path, name), SESSION, KEY,
                              security_db=str(security),
                              origin_transport=httpx.ASGITransport(app=origin))


def _signed(method, target, body=b'', *, risk=None, actor='actor-a'):
    return sign_headers(KEY, actor, method, target, body, risk=risk)


@pytest.mark.asyncio
async def test_juice_production_config_keeps_existing_signed_login_lure(tmp_path):
    seen = []
    origin = FastAPI()

    @origin.api_route('/{path:path}', methods=['GET', 'POST'])
    async def real(request: Request, path: str):
        seen.append((request.method, request.url.path))
        if path == '':
            return Response('<html><head></head><body>Juice Shop</body></html>',
                            media_type='text/html')
        return JSONResponse({'authentication': {'token': 'real-token'}})

    app = _make_overlay(tmp_path, 'overlay-production-juice-v2.toml', origin)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url='http://overlay') as client:
            assert (await client.get('/')).status_code == 403
            assert (await client.get('/healthz')).status_code == 403
            page = await client.get('/', headers=_signed('GET', '/'))
            assert page.status_code == 200
            assert b'/assets/account-recovery.js' in page.content
            body = b'{"email":"agent@example.test","password":"wrong"}'
            login = await client.post('/rest/user/login', content=body,
                                      headers=_signed('POST', '/rest/user/login', body))
            assert login.status_code == 401
            assert login.headers['x-recovery-api'] == '/ops/recovery/accounts'
            assert 'real-token' not in login.text
    assert seen == [('GET', '/')]


@pytest.mark.asyncio
async def test_ruby_production_profile_removes_real_credentials_and_isolates_login(tmp_path):
    seen = []
    origin = FastAPI()

    @origin.api_route('/{path:path}', methods=['GET', 'POST'])
    async def real(request: Request, path: str):
        seen.append((request.method, request.url.path, dict(request.headers)))
        if path == '':
            # Current RUBY/Vite index has no explicit head or body tags.
            return Response('<div id="root"></div><script type="module" src="/src/main.tsx"></script>',
                            media_type='text/html', headers={'etag': 'origin-index'})
        if path == 'api/auth/login':
            return JSONResponse({'token': 'real-ruby-token'})
        if path == 'api/me':
            return JSONResponse({'detail': 'authentication required'}, status_code=401)
        return JSONResponse({'status': 'ok'})

    settings = _test_settings(tmp_path, 'overlay-production-ruby-v2.toml')
    profile = load_site_profile(settings.site_profile)
    assert profile.login_paths == ('/api/auth/login',)
    assert {'ruby_session', 'ruby_remember', 'token'} <= set(profile.origin_auth_cookies)
    security = tmp_path / 'security.sqlite3'
    initialize_security_store(str(security))
    app = create_overlay_app(settings, SESSION, KEY, security_db=str(security),
                             origin_transport=httpx.ASGITransport(app=origin))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url='http://overlay') as client:
            headers = {**_signed('GET', '/'),
                       'authorization': 'Bearer production-token',
                       'cookie': 'ruby_session=real; ruby_remember=remember; token=decoy; locale=ko',
                       'x-defense-plan': '[{"name":"bypass"}]'}
            page = await client.get('/', headers=headers)
            assert page.status_code == 200
            assert page.content == (
                b'<div id="root"></div><script type="module" src="/src/main.tsx"></script>'
                b'<script src="/assets/account-recovery.js"></script>')
            assert page.headers['content-length'] == str(len(page.content))
            assert page.headers['cache-control'] == 'no-store, private'
            assert 'etag' not in page.headers
            script = await client.get('/assets/account-recovery.js',
                                      headers=_signed('GET', '/assets/account-recovery.js'))
            assert b'/api/auth/login' in script.content
            assert b'.masthead .session form.inline' in script.content
            assert b'nav.primary' in script.content

            body = json.dumps({'email': 'admin@example.test', 'password': 'wrong'}).encode()
            login = await client.post('/api/auth/login', content=body,
                                      headers={**_signed('POST', '/api/auth/login', body),
                                               'authorization': 'Bearer production-token',
                                               'content-type': 'application/json'})
            assert login.status_code == 401
            assert login.headers['x-recovery-api'] == '/ops/recovery/accounts'
            assert 'real-ruby-token' not in login.text
            assert 'ruby_session=' not in login.headers.get('set-cookie', '')

            me = await client.get('/api/me', headers={**_signed('GET', '/api/me'),
                'authorization': 'Bearer production-token', 'cookie': 'ruby_session=real'})
            assert me.status_code == 401
            service = await client.get('/api/operations/status',
                                       headers=_signed('GET', '/api/operations/status'))
            assert service.headers['x-internal-api'] == '/ops/service/manifest'
            decoy = await client.get('/ftp', headers=_signed('GET', '/ftp'))
            assert decoy.status_code == 200
            assert 'RUBY Market Archive' in decoy.text

            high = await client.get('/api/me', headers=_signed('GET', '/api/me',
                                                                 risk='high', actor='high-ruby'))
            assert high.status_code in {401, 404}
            downgraded = await client.get('/api/me',
                                          headers=_signed('GET', '/api/me', actor='high-ruby'))
            assert downgraded.status_code == high.status_code

    assert [(method, path) for method, path, _ in seen] == [
        ('GET', '/'), ('GET', '/api/me'), ('GET', '/api/operations/status')]
    assert 'authorization' not in seen[0][2]
    assert seen[0][2].get('cookie') == 'locale=ko'
    assert not any(name.startswith('x-defense-') for name in seen[0][2])
    assert 'authorization' not in seen[1][2]
    assert 'cookie' not in seen[1][2]
