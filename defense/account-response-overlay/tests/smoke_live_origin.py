"""Optional smoke test against a locally running official Juice Shop origin."""
import asyncio
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx

from defense.detector import sign_headers
from defense.overlay import OverlaySettings, create_overlay_app
from defense.security_store import initialize_security_store


KEY = b'detector-smoke-key-for-local-only-12345'
SESSION = b'session-smoke-key-for-local-only-12345'


async def main():
    origin = os.environ['OVERLAY_TEST_ORIGIN']
    async with httpx.AsyncClient(timeout=10, trust_env=False) as direct:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            decoy = root / 'decoy.toml'
            decoy.write_text(Path('config/decoy-v2.toml').read_text()
                             .replace('state/events.sqlite3', str(root / 'events.sqlite3')))
            db = root / 'security.sqlite3'
            initialize_security_store(str(db))
            app = create_overlay_app(OverlaySettings(origin, str(decoy)), SESSION, KEY,
                                     security_db=str(db))
            async with app.router.lifespan_context(app):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                             base_url='http://overlay.local', trust_env=False) as overlay:
                    def signed(method, path, body=b''):
                        return sign_headers(KEY, 'smoke-actor', method, path, body)

                    for path in ('/', '/main.js', '/api/Products', '/rest/products/search?q=apple'):
                        source = await direct.get(origin + path, headers={'accept-encoding': 'identity'})
                        response = await overlay.get(path, headers=signed('GET', path))
                        assert source.status_code == response.status_code, path
                        if path == '/':
                            assert b'<script src="/assets/account-recovery.js"></script>' in response.content
                            assert source.content.replace(b'</head>',
                                b'<script src="/assets/account-recovery.js"></script></head>', 1) == response.content
                        else:
                            assert source.content == response.content, path
                        assert 'link' not in response.headers, path
                        assert 'x-recovery-api' not in response.headers, path
                        assert 'x-internal-api' not in response.headers, path

                    body = json.dumps({'email': 'nobody@example.invalid',
                                       'password': 'invalid-password'}).encode()
                    path = '/rest/user/login'
                    response = await overlay.post(path, content=body,
                                                  headers={**signed('POST', path, body),
                                                           'content-type': 'application/json'})
                    assert response.status_code in {401, 403}, response.status_code
                    assert response.headers['x-recovery-api'] == '/ops/recovery/accounts'
                    assert '/ops/recovery/accounts' in response.headers['link']

                    for bait_path in ('/ftp', '/ops/recovery/accounts', '/ops/service/manifest'):
                        bait = await overlay.get(bait_path, headers=signed('GET', bait_path))
                        assert bait.status_code == 200, bait_path
    print('Official Juice Shop login lure, unchanged assets, and local decoy routes verified')


if __name__ == '__main__':
    asyncio.run(main())
