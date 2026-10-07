const { test } = require('node:test');
const assert = require('node:assert/strict');
const { parseArgs, cleanRequest, validateSteps } = require('../scripts/capture_api_requests.cjs');

test('captures only same-origin API paths and removes query values', () => {
  const item = cleanRequest('https://shop.example/rest/basket/7?token=secret&q=apple',
    'post', 'fetch', 'https://shop.example');
  assert.deepEqual(item, { path: '/rest/basket/7', method: 'POST', resource_type: 'fetch',
    query_keys: ['q', 'token'] });
  assert.equal(JSON.stringify(item).includes('secret'), false);
  assert.equal(cleanRequest('https://other.example/api/Users?token=secret', 'GET', 'fetch',
    'https://shop.example'), null);
  assert.equal(cleanRequest('https://shop.example/dashboard', 'GET', 'document',
    'https://shop.example'), null);
  assert.equal(cleanRequest('https://shop.example/graphql?token=secret', 'POST', 'fetch',
    'https://shop.example', ['/graphql']).path, '/graphql');
});

test('requires an explicit bounded flow and same-origin navigation', () => {
  const options = parseArgs(['--origin', 'https://shop.example', '--steps', 'flow.json',
    '--output', 'capture.runtime.json']);
  assert.equal(options.origin, 'https://shop.example');
  assert.deepEqual(parseArgs(['--origin', 'https://shop.example', '--steps', 'flow.json',
    '--output', 'capture.runtime.json', '--prefixes', '/graphql,/v1/']).prefixes,
  ['/graphql', '/v1/']);
  assert.deepEqual(validateSteps([{ action: 'goto', path: '/#/search' },
    { action: 'fill', selector: '#email', valueEnv: 'TEST_EMAIL' }], options.origin).length, 2);
  assert.throws(() => validateSteps([{ action: 'goto', path: 'https://other.example/' }],
    options.origin), /Cross-origin/);
  assert.throws(() => validateSteps([{ action: 'fill', selector: '#password', value: 'secret' }],
    options.origin), /valueEnv/);
});
