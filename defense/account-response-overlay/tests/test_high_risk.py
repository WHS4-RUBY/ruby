"""High-risk requests must never reach the configured real-origin transport."""
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI, Request
from starlette.responses import JSONResponse

from defense.detector import BotScoreRouter, DetectorVerifier, sign_headers
from defense.live_lab_gateway import create_lab_gateway
from defense.overlay import OverlaySettings, create_overlay_app
from defense.security_store import SecurityStoreError, initialize_security_store
from examples.detector_integration import plan_high_risk_request

KEY = b'detector-key-for-tests-only-0123456789'
SESSION = b'session-key-for-tests-only-0123456789'


def test_detector_high_risk_plan_uses_same_proxy_with_signed_tier():
    plan = plan_high_risk_request(secret=KEY, actor='high-actor', method='GET',
                                  raw_target='/api/Products', body=b'',
                                  client_headers=[('X-Defense-Risk', 'medium'), ('Accept', 'application/json')],
                                  overlay_upstream='http://overlay.internal')
    assert plan.route == 'high_isolation'
    assert plan.upstream == 'http://overlay.internal'
    assert sum(name.lower() == 'x-defense-risk' for name, _ in plan.headers) == 1
    assert ('x-defense-risk', 'high') in plan.headers


def test_high_risk_markers_do_not_consume_medium_detector_capacity(tmp_path):
    security = tmp_path / 'security.sqlite3'
    initialize_security_store(str(security))
    DetectorVerifier(KEY, store_path=str(security)).mark_high_risk('high-actor')
    router = BotScoreRouter(KEY, 0.8, store_path=str(security), max_actors=1)
    assert router.decide('medium-actor', 0.9, 'GET', '/').route == 'isolation'
    with pytest.raises(SecurityStoreError):
        router.decide('second-medium-actor', 0.9, 'GET', '/')


class SignedHighActor(httpx.Auth):
    requires_request_body = True

    def auth_flow(self, request):
        request.headers.update(sign_headers(KEY, 'high-actor', request.method,
                                            request.url.raw_path.decode(), request.content,
                                            risk='high'))
        yield request


def make_app(tmp_path, policy, origin):
    security = tmp_path / 'security.sqlite3'
    initialize_security_store(str(security))
    template = Path('config') / f'decoy-{policy}.toml'
    decoy = tmp_path / template.name
    decoy.write_text(template.read_text().replace('state/events.sqlite3',
                                                  str(tmp_path / 'events.sqlite3')))
    return create_overlay_app(OverlaySettings('http://origin.invalid', str(decoy)),
                              SESSION, KEY, security_db=str(security),
                              origin_transport=httpx.ASGITransport(app=origin))


@pytest.mark.asyncio
async def test_local_gateway_high_mode_never_contacts_origin(tmp_path):
    origin, seen = FastAPI(), []

    @origin.get('/api/Products')
    async def real():
        seen.append('origin')
        return JSONResponse({'REAL_ORIGIN': True})

    overlay = make_app(tmp_path, 'v2', origin)
    gateway = create_lab_gateway(overlay_url='http://overlay.internal', detector_secret=KEY,
                                 risk='high', transport=httpx.ASGITransport(app=overlay))
    async with overlay.router.lifespan_context(overlay):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway),
                                     base_url='http://lab') as client:
            response = await client.get('/api/Products')
            assert response.status_code == 404
            assert response.json()['related_service'] == '/ops/service/manifest'
    assert seen == []


@pytest.mark.parametrize('policy', ['v1', 'v2'])
@pytest.mark.asyncio
async def test_high_risk_all_paths_are_local_and_existing_decoy_is_reused(tmp_path, policy):
    origin, seen = FastAPI(), []

    @origin.api_route('/{path:path}', methods=['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
    async def real(request: Request, path: str):
        seen.append((request.method, request.url.path, await request.body()))
        return JSONResponse({'REAL_ORIGIN': True})

    app = make_app(tmp_path, policy, origin)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url='http://overlay', auth=SignedHighActor()) as client:
            for path in ('/ftp', '/ftp/', '/ops/recovery/accounts', '/ops/service/manifest'):
                reply = await client.get(path)
                assert reply.status_code == 200, (path, reply.text)
                assert 'REAL_ORIGIN' not in reply.text
            assert (await client.get('/')).status_code == 200
            login_page = await client.get('/login')
            assert login_page.status_code == 200
            assert '/ops/recovery/accounts' in login_page.text
            configured_login = await client.get('/rest/user/login')
            assert configured_login.status_code == 200
            assert '/ops/recovery/accounts' in configured_login.text
            admin = await client.get('/admin')
            assert admin.status_code == 200 and '/ops/recovery/accounts' in admin.text
            api = await client.get('/api/Products')
            assert api.status_code == 404
            assert api.json()['related_service'] == '/ops/service/manifest'
            account_api = await client.get('/rest/user/whoami')
            assert account_api.status_code == 401
            assert account_api.json()['related_service'] == '/ops/recovery/accounts'
            assert (await client.get('/swagger')).json()['service'] == 'Internal Account Registry'
            recon = await client.get('/.env')
            assert recon.status_code == 404 and '/ftp' in recon.text
            assert (await client.get('/products/1')).status_code == 404
            assert (await client.get('/assets/main.js')).status_code == 404
            assert (await client.get('/assets/operations.css')).status_code == 200
            assert (await client.get('/assets/account-recovery.js')).status_code == 200
            robots = await client.get('/robots.txt')
            assert robots.status_code == 200 and 'Disallow: /ftp' in robots.text
            bad_login = await client.post('/rest/user/login', json={'email': 'admin', 'password': 'x'})
            assert bad_login.status_code == 401 and '/ops/recovery/accounts' in bad_login.text
            assert (await client.post('/login', json={'password': 'x'})).status_code == 401
            assert (await client.post('/api/cart', json={'item': 1})).status_code == 404
            assert (await client.put('/products/1', content=b'change')).status_code == 404
            assert (await client.get('/ops/archive/accounts/1/not-a-real-record')).status_code == 404
    assert seen == [], f'high-risk request escaped to origin: {seen}'


@pytest.mark.asyncio
async def test_risk_signature_is_required_and_medium_behavior_is_unchanged(tmp_path):
    origin, seen = FastAPI(), []

    @origin.get('/api/Products')
    async def real():
        seen.append('/api/Products')
        return JSONResponse({'REAL_ORIGIN': True})

    app = make_app(tmp_path, 'v2', origin)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url='http://overlay') as client:
            assert (await client.get('/api/Products')).status_code == 403
            forged = sign_headers(KEY, 'actor-x', 'GET', '/api/Products', risk='high')
            forged['x-defense-risk'] = 'medium'
            assert (await client.get('/api/Products', headers=forged)).status_code == 403
            stripped = sign_headers(KEY, 'actor-x', 'GET', '/api/Products', risk='high')
            stripped.pop('x-defense-risk')
            assert (await client.get('/api/Products', headers=stripped)).status_code == 403
            medium = sign_headers(KEY, 'actor-x', 'GET', '/api/Products')
            medium['x-defense-risk'] = 'high'
            assert (await client.get('/api/Products', headers=medium)).status_code == 403
            assert seen == []
            medium = await client.get('/api/Products', headers=sign_headers(
                KEY, 'actor-x', 'GET', '/api/Products'))
            assert medium.status_code == 200 and medium.json() == {'REAL_ORIGIN': True}
            high = await client.get('/api/Products', headers=sign_headers(
                KEY, 'high-actor', 'GET', '/api/Products', risk='high'))
            assert high.status_code == 404 and high.json()['related_service'] == '/ops/service/manifest'
            downgraded = await client.get('/api/Products', headers=sign_headers(
                KEY, 'high-actor', 'GET', '/api/Products'))
            assert downgraded.status_code == 404
    assert seen == ['/api/Products']

    # The high-risk marker is durable; restarting the proxy cannot reopen origin access.
    restored = create_overlay_app(OverlaySettings('http://origin.invalid',
                                  str(tmp_path / 'decoy-v2.toml')), SESSION, KEY,
                                  security_db=str(tmp_path / 'security.sqlite3'),
                                  origin_transport=httpx.ASGITransport(app=origin))
    async with restored.router.lifespan_context(restored):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=restored),
                                     base_url='http://overlay') as client:
            reply = await client.get('/api/Products', headers=sign_headers(
                KEY, 'high-actor', 'GET', '/api/Products'))
            assert reply.status_code == 404
    assert seen == ['/api/Products']


@pytest.mark.parametrize('policy', ['v1', 'v2'])
@pytest.mark.asyncio
async def test_high_risk_console_cards_use_local_decoy_paths_without_changing_medium(tmp_path, policy):
    origin, seen = FastAPI(), []

    @origin.get('/{path:path}')
    async def real(path: str):
        seen.append(path)
        return JSONResponse({'REAL_ORIGIN': True})

    app = make_app(tmp_path, policy, origin)
    expected = {
        'Account Registry': '/ops/recovery/accounts',
        'Legacy Storage': '/ftp',
        'Backup Management': '/ops/archive',
        'Service Manifest': '/ops/service/manifest',
        'Audit Logs': '/ops/service/audit',
    }
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url='http://overlay', auth=SignedHighActor()) as high:
            root = await high.get('/')
            direct = await high.get('/ops/service')
            assert root.status_code == direct.status_code == 200
            assert root.text == direct.text
            assert '<h1>Internal Operations Console</h1>' in direct.text
            assert direct.text.count('class="console-card"') == 5
            assert 'Juice Shop' not in direct.text and 'juice-sh.op' not in direct.text
            for label, path in expected.items():
                assert f'<h2>{label}</h2>' in direct.text
                assert f'href="{path}"' in direct.text
                destination = await high.get(path)
                assert destination.status_code == 200, (label, path, destination.text)
            audit = await high.get(expected['Audit Logs'])
            assert '<h1>Audit Logs</h1>' in audit.text
            assert '/ops/archive' in audit.text
            head = await high.head('/ops/service')
            assert head.status_code == 200 and head.content == b''
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url='http://overlay') as medium:
            response = await medium.get('/ops/service', headers=sign_headers(
                KEY, 'medium-actor', 'GET', '/ops/service'))
            assert response.status_code == 200
            assert 'Internal Operations Console' not in response.text
            audit = await medium.get('/ops/service/audit', headers=sign_headers(
                KEY, 'medium-actor', 'GET', '/ops/service/audit'))
            assert audit.status_code == 404
    assert seen == []
