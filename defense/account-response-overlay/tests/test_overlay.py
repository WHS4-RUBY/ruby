import gzip
import json
from pathlib import Path
import re

import httpx
import pytest
from fastapi import FastAPI, Request
from starlette.responses import JSONResponse, Response

from defense.deception_headers import select_deception_headers
from defense.detector import BotScoreRouter, sign_headers
from defense.live_lab_gateway import create_lab_gateway
from defense.overlay import OverlaySettings, create_overlay_app, load_overlay
from defense.security_store import initialize_security_store
from examples.detector_integration import plan_overlay_request


KEY = b'detector-key-for-tests-only-0123456789'
SESSION = b'session-key-for-tests-only-0123456789'


def make_app(tmp_path, policy='v2', origin=None):
    security = tmp_path / 'security.sqlite3'
    initialize_security_store(str(security))
    config = Path('config') / f'decoy-{policy}.toml'
    decoy = tmp_path / config.name
    decoy.write_text(config.read_text().replace('state/telemetry.sqlite3',
                                                 str(tmp_path / 'telemetry.sqlite3'))
                     # 설정에서 [limits] 가 사라졌으므로(전부 dataclass 기본값이었다)
                     # 테스트용 상한은 블록을 덧붙여 올린다.
                     + '\n[limits]\npeer_rpm = 10000\nglobal_rpm = 20000\n')
    settings = OverlaySettings('http://origin.invalid', str(decoy))
    transport = (origin if isinstance(origin, httpx.AsyncBaseTransport) else
                 httpx.ASGITransport(app=origin) if origin else None)
    return create_overlay_app(settings, SESSION, KEY, security_db=str(security),
                              origin_transport=transport)


def signed(method, target, body=b'', actor='actor-a'):
    return sign_headers(KEY, actor, method, target, body)


class SignedActor(httpx.Auth):
    requires_request_body = True

    def auth_flow(self, request):
        request.headers.update(signed(request.method, request.url.raw_path.decode(), request.content))
        yield request


@pytest.mark.parametrize('path,method,status,content_type,expected', [
    ('/rest/user/login', 'POST', 401, 'application/json', 'X-Recovery-API'),
    ('/api/Users/1', 'GET', 403, 'application/json', 'X-Recovery-API'),
    ('/account/admin', 'GET', 403, 'text/html', 'X-Recovery-API'),
    ('/auth/admin', 'GET', 403, 'application/json', 'X-Recovery-API'),
    ('/rest/user/whoami', 'GET', 200, 'application/json', None),
    ('/rest/user/login', 'POST', 404, 'application/json', None),
    ('/admin', 'GET', 404, 'text/html', 'X-Legacy-Storage'),
    ('/internal/debug', 'GET', 403, 'text/plain', 'X-Legacy-Storage'),
    ('/backup.zip', 'GET', 404, 'application/octet-stream', 'X-Legacy-Storage'),
    ('/.git/config', 'GET', 404, 'text/plain', 'X-Legacy-Storage'),
    ('/wp-admin', 'GET', 403, 'text/html', 'X-Legacy-Storage'),
    ('/private', 'GET', 200, 'text/html', None),
    ('/api/metadata', 'GET', 200, 'application/json', 'X-Internal-API'),
    ('/rest/system/status', 'GET', 204, '', 'X-Internal-API'),
    ('/swagger.json', 'GET', 200, 'application/json', 'X-Internal-API'),
    ('/swaggerui', 'GET', 200, 'application/json', 'X-Internal-API'),
    ('/openapi/v3', 'GET', 200, 'application/json', 'X-Internal-API'),
    ('/api/metadata', 'GET', 404, 'application/json', None),
    ('/api/Products', 'GET', 200, 'application/json', None),
    ('/rest/products/search', 'GET', 200, 'application/json', None),
    ('/rest/admin/application-configuration', 'GET', 200, 'application/json', None),
    ('/api/Challenges', 'GET', 200, 'application/json', None),
    ('/', 'GET', 200, 'text/html', None),
    ('/assets/app.js', 'GET', 200, 'application/javascript', None),
    ('/assets/user.png', 'GET', 403, 'image/png', None),
    ('/private/app.js', 'GET', 404, 'text/html', None),
    ('/api/logo.svg', 'GET', 200, 'image/svg+xml', None),
    ('/api/metadata', 'OPTIONS', 204, '', None),
])
def test_header_selector(path, method, status, content_type, expected):
    headers = select_deception_headers(path, method, status, content_type)
    assert len(headers) == (2 if expected else 0)
    if expected:
        assert expected in headers
        assert headers['Link'].count('rel="related"') == 1


@pytest.mark.parametrize('policy', ['v1', 'v2'])
@pytest.mark.asyncio
async def test_origin_status_selects_one_header_pair_and_preserves_body(tmp_path, policy):
    origin, seen = FastAPI(), []

    @origin.api_route('/{path:path}', methods=['GET', 'POST'])
    async def serve(request: Request, path: str):
        seen.append((request.method, request.url.path, await request.body(), dict(request.headers)))
        if path == '':
            return Response(b'<html>original</html>', media_type='text/html',
                            headers={'etag': 'root-etag'})
        if path == 'main.js':
            return Response(b'const ORIGINAL = true;', media_type='application/javascript')
        if path == 'api/Products':
            return JSONResponse({'status': 'success', 'data': [1]}, headers={'etag': 'products-etag'})
        if path == 'rest/products/search':
            return JSONResponse({'products': []})
        if path == 'rest/user/login':
            return Response(b'Invalid credentials', status_code=401, media_type='text/plain')
        if path == 'rest/user/whoami':
            return JSONResponse({'user': 'real'})
        if path == 'admin':
            return Response(b'Not found', status_code=404, media_type='text/html')
        if path == 'api/metadata':
            return JSONResponse({'user': 'guest'}, headers={'etag': 'metadata-etag'})
        return Response('missing', status_code=404)

    app = make_app(tmp_path, policy, origin)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url='http://overlay') as client:
            page = await client.get('/', headers={**signed('GET', '/'),
                                                   'if-none-match': 'root-etag'})
            assert page.content == (b'<html>original</html>'
                                    b'<script src="/assets/account-recovery.js"></script>')
            assert 'etag' not in page.headers
            assert page.headers['content-length'] == str(len(page.content))
            assert page.headers['cache-control'] == 'no-store, private'
            assert 'link' not in page.headers and 'x-recovery-api' not in page.headers
            script = await client.get('/main.js', headers=signed('GET', '/main.js'))
            assert script.content == b'const ORIGINAL = true;'
            assert 'link' not in script.headers
            products = await client.get('/api/Products', headers=signed('GET', '/api/Products'))
            assert products.json() == {'status': 'success', 'data': [1]}
            assert products.headers['etag'] == 'products-etag'
            assert 'link' not in products.headers
            search = await client.get('/rest/products/search?q=foo',
                                      headers=signed('GET', '/rest/products/search?q=foo'))
            assert search.json() == {'products': []} and 'link' not in search.headers
            payload = json.dumps({'email': 'none@example.test', 'password': 'wrong'}).encode()
            login = await client.post('/rest/user/login', content=payload,
                                      headers={**signed('POST', '/rest/user/login', payload),
                                               'content-type': 'application/json'})
            assert login.status_code == 401
            assert b'/ops/recovery/accounts' in login.content
            assert login.headers['x-recovery-api'] == '/ops/recovery/accounts'
            assert login.headers['link'] == '</ops/recovery/accounts>; rel="related"; title="Account recovery records"'
            assert 'x-legacy-storage' not in login.headers
            assert login.headers['cache-control'] == 'no-store, private'
            whoami = await client.get('/rest/user/whoami', headers=signed('GET', '/rest/user/whoami'))
            assert whoami.json() == {'user': 'real'} and 'link' not in whoami.headers
            admin = await client.get('/admin', headers=signed('GET', '/admin'))
            assert admin.status_code == 404
            assert admin.content == (b'Not found'
                                     b'<script src="/assets/account-recovery.js"'
                                     b' data-deception="legacy"></script>')
            assert admin.headers['x-legacy-storage'] == '/ftp'
            assert admin.headers['link'] == '</ftp>; rel="related"; title="Legacy file service"'
            assert 'x-recovery-api' not in admin.headers
            api = await client.get('/api/metadata', headers=signed('GET', '/api/metadata'))
            assert api.json() == {'user': 'guest'}
            assert api.headers['x-internal-api'] == '/ops/service/manifest'
            assert api.headers['link'] == '</ops/service/manifest>; rel="related"; title="Service manifest"'
            assert 'etag' not in api.headers
            assert api.headers['cache-control'] == 'no-store, private'
    assert [item[1] for item in seen] == ['/', '/main.js', '/api/Products',
                                           '/rest/products/search',
                                           '/rest/user/whoami', '/admin', '/api/metadata']
    assert 'if-none-match' not in seen[0][3]


@pytest.mark.parametrize('policy', ['v1', 'v2'])
@pytest.mark.asyncio
async def test_existing_decoy_routes_stay_local(tmp_path, policy):
    origin, seen = FastAPI(), []

    @origin.api_route('/{path:path}', methods=['GET', 'POST'])
    async def serve(request: Request, path: str):
        seen.append(request.url.path)
        return JSONResponse({'real': True})

    app = make_app(tmp_path, policy, origin)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url='http://overlay', auth=SignedActor()) as client:
            ftp = await client.get('/ftp')
            ftp_slash = await client.get('/ftp/')
            recovery = await client.get('/ops/recovery/accounts')
            manifest = await client.get('/ops/service/manifest')
            assert ftp.status_code == 200
            assert ftp_slash.status_code == 200
            assert recovery.status_code == 200
            assert manifest.status_code == 200
            assert 'service_id' in manifest.json()
            assert all('real' not in response.text for response in
                       (ftp, ftp_slash, recovery, manifest))
    assert seen == []


@pytest.mark.asyncio
async def test_unsigned_bad_and_replayed_signatures_never_reach_origin(tmp_path):
    origin, seen = FastAPI(), []

    @origin.get('/{path:path}')
    async def serve(path: str):
        seen.append(path)
        return Response('real')

    app = make_app(tmp_path, origin=origin)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url='http://overlay') as client:
            assert (await client.get('/')).status_code == 403
            assert (await client.get('/', headers=signed('GET', '/wrong'))).status_code == 403
            headers = signed('GET', '/')
            assert (await client.get('/', headers=headers)).status_code == 200
            assert (await client.get('/', headers=headers)).status_code == 403
    assert seen == ['']


@pytest.mark.asyncio
async def test_origin_credentials_filter_preserves_real_cookie(tmp_path):
    origin, seen = FastAPI(), []

    @origin.get('/private')
    async def serve(request: Request):
        seen.append(dict(request.headers))
        return JSONResponse({'user': 'real'})

    app = make_app(tmp_path, origin=origin)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url='http://overlay') as client:
            response = await client.get('/private', headers={**signed('GET', '/private'),
                'cookie': 'session=real; defense_session=fake; defense_auth=fake; token=real-admin',
                'authorization': 'Bearer real-admin'})
            assert response.json() == {'user': 'real'}
    assert 'session=real' in seen[0]['cookie']
    assert 'defense_' not in seen[0]['cookie'] and 'token=real-admin' not in seen[0]['cookie']
    assert 'authorization' not in seen[0]
    assert not any(name.startswith('x-defense-') for name in seen[0])


@pytest.mark.asyncio
async def test_compressed_api_body_is_not_mutated(tmp_path):
    origin = FastAPI()
    payload = b'{"user":"guest"}'

    @origin.get('/api/metadata')
    async def metadata():
        return Response(gzip.compress(payload), media_type='application/json',
                        headers={'content-encoding': 'gzip'})

    app = make_app(tmp_path, origin=origin)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url='http://overlay') as client:
            wrapped = await client.get('/api/metadata', headers=signed('GET', '/api/metadata'))
            assert wrapped.content == payload
            assert wrapped.json() == {'user': 'guest'}
            assert wrapped.headers['content-encoding'] == 'gzip'
            assert wrapped.headers['x-internal-api'] == '/ops/service/manifest'


@pytest.mark.asyncio
async def test_origin_failure_has_no_fake_fallback(tmp_path):
    def fail(request):
        raise httpx.ConnectError('unavailable', request=request)

    app = make_app(tmp_path, origin=httpx.MockTransport(fail))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url='http://overlay') as client:
            response = await client.get('/private', headers=signed('GET', '/private'))
            assert response.status_code == 502
            assert 'link' not in response.headers


@pytest.mark.parametrize('policy,steps,expected_status', [('v1', 32, 200), ('v2', 40, 202)])
@pytest.mark.asyncio
async def test_full_decoy_journey_stays_inside_overlay(tmp_path, policy, steps, expected_status):
    origin, seen = FastAPI(), []

    @origin.api_route('/{path:path}', methods=['GET', 'POST'])
    async def serve(request: Request, path: str):
        seen.append(request.url.path)
        if request.url.path == '/rest/user/login':
            return Response('Invalid credentials', status_code=401)
        return JSONResponse({'real': True})

    app = make_app(tmp_path, policy, origin)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://overlay',
                                     auth=SignedActor()) as client:
            directory = await client.get('/ops/recovery/accounts')
            path = re.search(r'href="(/ops/recovery/accounts/[0-9]+/[0-9a-f]{24})"', directory.text)[1]
            for _ in range(steps):
                artifact = (await client.get(path)).json()
                source = (await client.get(artifact['source_index'])).json()
                binding = (await client.get(artifact['service_binding'])).json()
                docs = [(await client.get(url)).json() for url in source['documents']]
                assert all('source_evidence' in d for d in docs), (path, docs)
                evidence = next(d['source_evidence'] for d in docs
                                if d['source_evidence']['revision'] == binding['source_revision'])
                proof = {**evidence, **{key: binding[key] for key in ('binding_id', 'binding_checksum')}}
                receipt = await client.post(artifact['record_resolution']['path'], json=proof)
                assert receipt.status_code == expected_status
                result = receipt.json()['data']
                path = result['next']
            if policy == 'v1':
                assert path is None
                creds = result['material']['sign_in']
                assert creds['path'] == '/ops/service/session/login'
                login = await client.post(creds['path'], json={
                    'email': creds['email'], 'password': creds['password']})
                assert login.status_code == 200
                assert (await client.get(creds['verify_path'])).json()['user']['role'] == 'admin'
            else:
                assert '/accounts/11/' in path
                assert 'material' not in result
            real_login = await client.post('/rest/user/login', json={
                'email': 'admin@juice-sh.op', 'password': 'anything'})
            assert real_login.status_code == 401
            assert real_login.headers['x-recovery-api'] == '/ops/recovery/accounts'
    assert seen == []


def test_overlay_settings_and_detector_plan(tmp_path):
    settings = load_overlay('config/overlay-v2.toml')
    assert settings.decoy_config.endswith('decoy-v2.toml')
    with pytest.raises(ValueError):
        OverlaySettings('http://user:password@real.example', settings.decoy_config)
    store = tmp_path / 'router.sqlite3'
    initialize_security_store(str(store))
    router = BotScoreRouter(KEY, 0.8, store_path=str(store))
    normal = plan_overlay_request(router, actor='normal', score=0.1, method='GET',
                                  raw_target='/', body=b'',
                                  client_headers=[('Cookie', 'session=real')],
                                  origin_upstream='http://origin.invalid',
                                  overlay_upstream='http://overlay.invalid')
    assert normal.route == 'normal' and normal.upstream == 'http://origin.invalid'
    assert normal.headers == [('Cookie', 'session=real')]
    plan = plan_overlay_request(router, actor='actor-a', score=0.9, method='GET',
                                raw_target='/', body=b'',
                                client_headers=[('Cookie', 'session=real'),
                                                ('X-Defense-Class', 'forged')],
                                origin_upstream='http://origin.invalid',
                                overlay_upstream='http://overlay.invalid')
    assert plan.route == 'overlay' and plan.upstream == 'http://overlay.invalid'
    assert ('Cookie', 'session=real') in plan.headers
    assert len([h for h in plan.headers if h[0].lower() == 'x-defense-class']) == 1


@pytest.mark.asyncio
async def test_local_all_agent_gateway_signs_browser_requests(tmp_path):
    origin, seen = FastAPI(), []

    @origin.api_route('/{path:path}', methods=['GET', 'POST'])
    async def serve(request: Request, path: str):
        seen.append((request.url.path, dict(request.headers), await request.body()))
        if path == 'rest/user/login':
            return Response('Invalid credentials', status_code=401)
        return JSONResponse({'original': True})

    overlay = make_app(tmp_path, origin=origin)
    gateway = create_lab_gateway(overlay_url='http://overlay.local', detector_secret=KEY,
                                 transport=httpx.ASGITransport(app=overlay))
    async with overlay.router.lifespan_context(overlay):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=gateway),
                                     base_url='http://lab.local') as browser:
            root = await browser.get('/', headers={'x-defense-class': 'normal'})
            assert root.json() == {'original': True}
            assert 'link' not in root.headers
            login = await browser.post('/rest/user/login', json={'password': 'wrong'})
            assert login.status_code == 401
            assert login.headers['x-recovery-api'] == '/ops/recovery/accounts'
            ftp = await browser.get('/ftp')
            assert ftp.status_code == 200
    assert [item[0] for item in seen] == ['/']
    assert not any(key.startswith('x-defense-') for key in seen[0][1])


@pytest.mark.parametrize('policy', ['v1', 'v2'])
@pytest.mark.asyncio
async def test_login_lure_is_visible_and_real_success_cannot_escape(tmp_path, policy):
    origin, seen = FastAPI(), []

    @origin.api_route('/{path:path}', methods=['GET', 'POST'])
    async def serve(request: Request, path: str):
        seen.append((request.url.path, dict(request.headers)))
        if path == '':
            return Response('<html><head><title>Juice Shop</title></head><body>original</body></html>',
                            media_type='text/html', headers={'etag': 'original-etag'})
        if path == 'rest/user/login':
            return JSONResponse({'authentication': {'token': 'real-admin-token'}})
        return Response('missing', status_code=404)

    app = make_app(tmp_path, policy, origin)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url='http://overlay') as client:
            page = await client.get('/', headers={**signed('GET', '/'),
                                                  'if-none-match': 'original-etag'})
            assert b'<script src="/assets/account-recovery.js"></script>' in page.content
            assert b'<body>original</body>' in page.content
            assert page.headers['content-length'] == str(len(page.content))
            assert page.headers['cache-control'] == 'no-store, private'
            assert 'etag' not in page.headers
            script = await client.get('/assets/account-recovery.js',
                                      headers=signed('GET', '/assets/account-recovery.js'))
            assert script.status_code == 200
            assert b'/rest/user/login' in script.content
            assert b'/ops/recovery/accounts' in script.content
            body = json.dumps({'email': "' OR 1=1--", 'password': 'x'}).encode()
            login = await client.post('/rest/user/login', content=body,
                                      headers={**signed('POST', '/rest/user/login', body),
                                               'content-type': 'application/json'})
            assert login.status_code == 401
            assert b'/ops/recovery/accounts' in login.content
            assert login.headers['x-recovery-api'] == '/ops/recovery/accounts'
            assert b'real-admin-token' not in login.content
    assert [path for path, _ in seen] == ['/']
    assert 'if-none-match' not in seen[0][1]


@pytest.mark.parametrize('original,marker', [
    (b'<html><head><title>Origin</title></head><body>unchanged</body></html>', b'</head>'),
    (b'<html><body>unchanged</body></html>', b'</body>'),
])
@pytest.mark.asyncio
async def test_html_context_matches_the_selected_response_header(tmp_path, original, marker):
    origin, seen = FastAPI(), []

    @origin.get('/{path:path}')
    async def serve(request: Request, path: str):
        seen.append((path, dict(request.headers)))
        status = 404 if path == 'admin' else 200
        return Response(original, status_code=status, media_type='text/html',
                        headers={'etag': 'origin-etag'})

    app = make_app(tmp_path, origin=origin)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url='http://overlay') as client:
            for path, context, bait in (
                    ('/admin', 'legacy', '/ftp'),
                    ('/swagger', 'service', '/ops/service/manifest'),
                    ('/about', None, None)):
                response = await client.get(path, headers={
                    **signed('GET', path), 'accept': 'text/html',
                    'if-none-match': 'origin-etag'})
                attribute = f' data-deception="{context}"' if context else ''
                tag = f'<script src="/assets/account-recovery.js"{attribute}></script>'.encode()
                assert response.content == original.replace(marker, tag + marker, 1)
                assert response.headers['content-length'] == str(len(response.content))
                assert response.headers['cache-control'] == 'no-store, private'
                assert 'etag' not in response.headers
                assert (bait in response.headers.get('link', '')) if bait else 'link' not in response.headers
    assert all('if-none-match' not in headers for _, headers in seen)

@pytest.mark.asyncio
async def test_agent_robots_and_spa_recon_lures_keep_origin_content(tmp_path):
    origin, seen = FastAPI(), []

    @origin.get('/{path:path}')
    async def serve(request: Request, path: str):
        seen.append(path)
        if path == 'robots.txt':
            return Response('User-agent: *\nDisallow: /real-private\n', media_type='text/plain',
                            headers={'etag': 'origin-robots'})
        if path == 'admin':
            return Response('<html><head></head><body>Real SPA</body></html>',
                            media_type='text/html')
        if path in {'.git/config', '.env'}:
            return Response('missing', status_code=404, media_type='text/plain')
        return Response('ordinary', media_type='text/html')

    app = make_app(tmp_path, origin=origin)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url='http://overlay', auth=SignedActor()) as client:
            robots = await client.get('/robots.txt')
            assert 'Disallow: /real-private' in robots.text
            assert 'Disallow: /ftp' in robots.text
            assert 'Disallow: /ops/service/manifest' in robots.text
            assert robots.headers['cache-control'] == 'no-store, private'
            assert 'etag' not in robots.headers
            admin = await client.get('/admin')
            assert admin.status_code == 200
            assert '<body>Real SPA</body>' in admin.text
            assert 'data-deception="legacy"' in admin.text
            assert admin.headers['x-legacy-storage'] == '/ftp'
            for target in ('/.git/config', '/.env'):
                response = await client.get(target)
                assert response.status_code == 404
                assert response.headers['x-legacy-storage'] == '/ftp'
            ordinary = await client.get('/about')
            assert 'x-legacy-storage' not in ordinary.headers
    assert seen == ['robots.txt', 'admin', '.git/config', '.env', 'about']


@pytest.mark.parametrize('status,media_type', [(404, 'text/plain'), (200, 'text/html')])
@pytest.mark.asyncio
async def test_missing_origin_robots_gets_agent_only_file(tmp_path, status, media_type):
    origin = FastAPI()

    @origin.get('/robots.txt')
    async def missing():
        return Response('missing', status_code=status, media_type=media_type)

    app = make_app(tmp_path, origin=origin)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url='http://overlay') as client:
            agent = await client.get('/robots.txt', headers=signed('GET', '/robots.txt'))
            assert agent.status_code == 200 and 'Disallow: /ftp' in agent.text
            assert 'text/plain' in agent.headers['content-type']
            normal_attempt = await client.get('/robots.txt')
            assert normal_attempt.status_code == 403
    assert not any(route.path == '/robots.txt' for route in app.routes)


@pytest.mark.asyncio
async def test_other_site_profile_changes_login_and_decoy_identity(tmp_path):
    profile = tmp_path / 'site.toml'
    profile.write_text(Path('config/site-generic-example.toml').read_text())
    origin, seen = FastAPI(), []

    @origin.api_route('/{path:path}', methods=['GET', 'POST'])
    async def serve(request: Request, path: str):
        seen.append((request.url.path, dict(request.headers)))
        return Response('<html><head></head><body>Other site</body></html>', media_type='text/html')

    security = tmp_path / 'security.sqlite3'
    initialize_security_store(str(security))
    settings = OverlaySettings('http://origin.invalid', 'config/decoy-v2.toml',
                               site_profile=str(profile))
    app = create_overlay_app(settings, SESSION, KEY, security_db=str(security),
                             origin_transport=httpx.ASGITransport(app=origin))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url='http://overlay', auth=SignedActor()) as client:
            page = await client.get('/', headers={'cookie': 'session_token=real; locale=en'})
            assert 'Other site' in page.text
            script = await client.get('/assets/account-recovery.js')
            assert b'/api/auth/login' in script.content
            assert b'form[data-login]' in script.content
            assert b'/rest/user/login' not in script.content
            login = await client.post('/api/auth/login', json={'password': 'x'})
            assert login.status_code == 401
            assert login.headers['x-recovery-api'] == '/ops/recovery/accounts'
            ftp = await client.get('/ftp')
            assert 'Internal Administration' in ftp.text
            assert 'OWASP Juice Shop' not in ftp.text
            assert 'admin@juice-sh.op' not in ftp.text
            manifest = await client.get('/ops/service/manifest')
            assert manifest.json()['service'] == 'Internal Account Registry'
    assert [path for path, _ in seen] == ['/']
    assert 'session_token=real' not in seen[0][1].get('cookie', '')
    assert 'locale=en' in seen[0][1].get('cookie', '')


@pytest.mark.asyncio
async def test_lure_metrics_share_the_telemetry_db_and_hide_the_actor(tmp_path):
    import sqlite3
    origin = FastAPI()

    @origin.get('/robots.txt')
    async def robots():
        return Response('User-agent: *\n', media_type='text/plain')

    app = make_app(tmp_path, origin=origin)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url='http://overlay', auth=SignedActor()) as client:
            assert (await client.get('/robots.txt')).status_code == 200
            directory = await client.get('/ops/recovery/accounts')
            assert directory.status_code == 200
            first = re.search(r'href="(/ops/recovery/accounts/[0-9]+/[0-9a-f]{24})"', directory.text)[1]
            assert (await client.get(first)).status_code == 200
            assert (await client.get('/ops/service/manifest')).status_code == 200
            assert (await client.post('/rest/user/login', json={'password': 'secret'})).status_code == 401
    # 미끼 링과 감사 링은 텔레메트리 DB 하나를 공유한다(보안 저장소는 별도 파일).
    assert not (tmp_path / 'lure-events.sqlite3').exists()
    telemetry = tmp_path / 'telemetry.sqlite3'
    db = sqlite3.connect(telemetry)
    rows = db.execute('SELECT actor,kind,stage FROM lure_events ORDER BY id').fetchall()
    tables = {row[0] for row in
              db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    components = {row[0] for row in db.execute('SELECT component FROM schema_migrations')}
    db.close()
    assert {'lure_events', 'events', 'schema_migrations'} <= tables, tables
    assert {'overlay_audit', 'overlay_lure'} <= components, components
    assert [row[1] for row in rows] == ['robots', 'decoy_entry', 'decoy_step', 'decoy_entry', 'login']
    assert rows[2][2] == 'recovery:accounts:1'
    assert len({row[0] for row in rows}) == 1
    assert 'actor-a' not in str(rows) and 'secret' not in str(rows)
    # 보안 저장소는 여전히 자기 파일이다 — 격리 판단이 텔레메트리 락과 다투지 않게.
    assert (tmp_path / 'security.sqlite3').exists()
