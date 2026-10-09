const { test } = require('node:test');
const assert = require('node:assert/strict');
const { parseArgs, cleanRequest, validateSteps, bodySelectorKeys } = require('../scripts/capture_api_requests.cjs');

test('captures only same-origin API paths and removes query values', () => {
  const item = cleanRequest('https://shop.example/rest/basket/7?token=secret&q=apple',
    'post', 'fetch', 'https://shop.example');
  assert.deepEqual(item, { path: '/rest/basket/7', method: 'POST', resource_type: 'fetch',
    protected: true, query_keys: ['q', 'token'] });
  assert.equal(JSON.stringify(item).includes('secret'), false);
  assert.equal(cleanRequest('https://other.example/api/Users?token=secret', 'GET', 'fetch',
    'https://shop.example'), null);
  assert.equal(cleanRequest('https://shop.example/dashboard', 'GET', 'document',
    'https://shop.example'), null);
  assert.equal(cleanRequest('https://shop.example/graphql?token=secret', 'POST', 'fetch',
    'https://shop.example', ['/graphql']).path, '/graphql');
});

test('same-origin fetch/XHR outside protected prefixes are candidates without values', () => {
  const item = cleanRequest('https://shop.example/api.php?action=login&token=secret',
    'POST', 'xhr', 'https://shop.example');
  assert.deepEqual(item, { path: '/api.php', method: 'POST', resource_type: 'xhr', protected: false,
    query_keys: ['action', 'token'] });
  assert.equal(cleanRequest('https://shop.example/logo.png?v=1', 'GET', 'image',
    'https://shop.example'), null);
});

test('declared routing keys separate path selectors from action selectors', () => {
  const keys = ['route', 'action'];
  const path = cleanRequest('https://shop.example/gateway?route=%2Fapi%2Fitems&q=private',
    'GET', 'fetch', 'https://shop.example', undefined, keys);
  assert.deepEqual(path.route_selectors, [{ key: 'route', kind: 'path', value: '/api/items' }]);
  const action = cleanRequest('https://shop.example/api.php?action=login&q=private',
    'POST', 'fetch', 'https://shop.example', undefined, keys);
  assert.deepEqual(action.route_selectors, [{ key: 'action', kind: 'action', value: 'login' }]);
  const opaque = cleanRequest('https://shop.example/api.php?action=a%20b%3Cc&q=private',
    'GET', 'fetch', 'https://shop.example', undefined, keys);
  assert.deepEqual(opaque.route_selectors, [{ key: 'action', kind: 'opaque' }]);
  for (const item of [path, action, opaque]) assert.equal(JSON.stringify(item).includes('private'), false);
});

test('routing keys in request bodies are reported by name only', () => {
  assert.deepEqual(bodySelectorKeys('action=login&password=secret', 'application/x-www-form-urlencoded',
    ['action']), ['action']);
  assert.deepEqual(bodySelectorKeys('{"route":"/api/items","x":1}', 'application/json', ['route']), ['route']);
  assert.deepEqual(bodySelectorKeys('not json', 'application/json', ['route']), []);
  const item = cleanRequest('https://shop.example/api.php', 'POST', 'fetch', 'https://shop.example',
    undefined, ['action'], { postData: 'action=login&password=secret',
      contentType: 'application/x-www-form-urlencoded' });
  assert.deepEqual(item.body_selector_keys, ['action']);
  assert.equal(JSON.stringify(item).includes('secret'), false);
  assert.equal(JSON.stringify(item).includes('login'), false);
});

test('requires an explicit bounded flow and same-origin navigation', () => {
  const options = parseArgs(['--origin', 'https://shop.example', '--steps', 'flow.json',
    '--output', 'capture.runtime.json']);
  assert.equal(options.origin, 'https://shop.example');
  assert.deepEqual(options.route_keys, []);
  assert.deepEqual(parseArgs(['--origin', 'https://shop.example', '--steps', 'flow.json',
    '--output', 'capture.runtime.json', '--prefixes', '/graphql,/v1/']).prefixes,
  ['/graphql', '/v1/']);
  assert.deepEqual(parseArgs(['--origin', 'https://shop.example', '--steps', 'flow.json',
    '--output', 'capture.runtime.json', '--route-keys', 'route,action']).route_keys, ['route', 'action']);
  assert.throws(() => parseArgs(['--origin', 'https://shop.example', '--steps', 'flow.json',
    '--output', 'capture.runtime.json', '--route-keys', 'bad key']), /route-keys/);
  assert.deepEqual(validateSteps([{ action: 'goto', path: '/#/search' },
    { action: 'fill', selector: '#email', valueEnv: 'TEST_EMAIL' }], options.origin).length, 2);
  assert.throws(() => validateSteps([{ action: 'goto', path: 'https://other.example/' }],
    options.origin), /Cross-origin/);
  assert.throws(() => validateSteps([{ action: 'fill', selector: '#password', value: 'secret' }],
    options.origin), /valueEnv/);
});

test('captures query path candidates on dispatchers outside API prefixes', () => {
  const item = cleanRequest('https://shop.example/gateway?route=%2Fapi%2Fitems&token=secret',
    'GET', 'fetch', 'https://shop.example');
  assert.equal(item.path, '/gateway');
  assert.deepEqual(item.query_path_candidates, [{ key: 'route', path: '/api/items' }]);
  assert.equal(JSON.stringify(item).includes('secret'), false);
  // Not a protected path value: the request is still a same-origin fetch, without values.
  for (const url of ['https://shop.example/gateway?route=https://other.example/api/items',
    'https://shop.example/gateway?route=%2Fapi%2Fitems%3Ftoken%3Dsecret']) {
    const other = cleanRequest(url, 'GET', 'fetch', 'https://shop.example');
    assert.equal(other.query_path_candidates, undefined);
    assert.equal(JSON.stringify(other).includes('secret'), false);
  }
});
