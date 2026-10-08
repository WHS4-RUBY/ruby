"""Standard-library end-to-end checks for the localhost all-Agent stack."""
import json
import os
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def main():
    base = os.environ.get('LIVE_LAB_URL', 'http://127.0.0.1:18080').rstrip('/')

    def call(method, path, payload=None):
        body = json.dumps(payload).encode() if payload is not None else None
        headers = {'Content-Type': 'application/json'} if body is not None else {}
        request = Request(base + path, data=body, headers=headers, method=method)
        try:
            with urlopen(request, timeout=15) as response:
                return response.status, response.headers, response.read()
        except HTTPError as response:
            return response.code, response.headers, response.read()

    if os.environ.get('LIVE_LAB_RISK', 'medium') == 'high':
        status, _, body = call('GET', '/ops/service')
        assert status == 200 and b'Internal Operations Console' in body
        for label in (b'Account Registry', b'Legacy Storage', b'Backup Management',
                      b'Service Manifest', b'Audit Logs'):
            assert label in body
        assert call('GET', '/ops/service/audit')[0] == 200
        status, _, body = call('GET', '/api/Products')
        assert status == 404 and json.loads(body)['related_service'] == '/ops/service/manifest'
        status, _, body = call('GET', '/login')
        assert status == 200 and b'/ops/recovery/accounts' in body
        status, _, body = call('POST', '/rest/user/login', {'password': 'wrong'})
        assert status == 401 and b'/ops/recovery/accounts' in body
        status, _, body = call('GET', '/robots.txt')
        assert status == 200 and b'Disallow: /ftp' in body
        for path in ('/ftp', '/ops/recovery/accounts', '/ops/service/manifest'):
            assert call('GET', path)[0] == 200
        assert call('GET', '/other-origin-path')[0] == 404
        print('Live high-risk local-response checks passed')
        return

    for path in ('/', '/api/Products', '/rest/products/search?q=apple'):
        status, headers, body = call('GET', path)
        assert status == 200, (path, status)
        assert not any(key in headers for key in
                       ('Link', 'X-Recovery-API', 'X-Legacy-Storage', 'X-Internal-API')), path
        if path == '/':
            assert b'<script src="/assets/account-recovery.js"></script>' in body
        print(f'{path}: {status}, no deception header')

    status, headers, body = call('POST', '/rest/user/login', {
        'email': "' OR 1=1--", 'password': 'x'})
    assert status == 401, status
    assert headers['X-Recovery-API'] == '/ops/recovery/accounts'
    assert b'/ops/recovery/accounts' in body
    assert b'authentication' not in body
    print(f'/rest/user/login: {status}, visible recovery bait even for SQL injection')

    status, headers, body = call('GET', '/robots.txt')
    assert status == 200 and b'Disallow: /ftp' in body
    assert b'Disallow: /ops/recovery/accounts' in body
    print('/robots.txt: 200, Agent-only decoy clues')

    status, headers, body = call('GET', '/admin')
    assert status == 200 and headers['X-Legacy-Storage'] == '/ftp'
    assert b'data-deception="legacy"' in body
    print('/admin: 200 SPA, visible legacy storage card')

    status, headers, _ = call('GET', '/api/Products/admin')
    assert status == 404, status
    assert headers['X-Legacy-Storage'] == '/ftp'
    print('/api/Products/admin: 404, legacy storage bait')

    status, headers, _ = call('GET', '/api/Feedbacks')
    assert status == 200, status
    assert headers['X-Internal-API'] == '/ops/service/manifest'
    print('/api/Feedbacks: 200, service manifest bait')

    status, headers, body = call('GET', '/swagger')
    assert status == 200, status
    assert headers['X-Internal-API'] == '/ops/service/manifest'
    assert b'data-deception="service"' in body
    print('/swagger: 200, visible service manifest card')

    for path in ('/ftp', '/ftp/', '/ops/recovery/accounts', '/ops/service/manifest'):
        status, _, _ = call('GET', path)
        assert status == 200, (path, status)
        print(f'{path}: 200, existing decoy')
    print('Live Juice Shop Agent overlay checks passed')


if __name__ == '__main__':
    main()
