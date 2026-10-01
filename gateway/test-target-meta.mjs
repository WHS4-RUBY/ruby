import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const template = readFileSync(new URL('./default.conf.template', import.meta.url), 'utf8');

for (const name of ['juice-shop', 'ruby-market', 'my-site']) {
  test(`the ${name} gateway metadata matches its routed public path`, () => {
    const config = template.replaceAll('@PUBLIC_NAME@', name).replaceAll('@FORWARDED_PROTO@', 'http');
    const metadataLocation = config.match(/location = \/__ruby\/target \{([\s\S]*?)\n    \}/)?.[1];
    assert.ok(metadataLocation, 'gateway metadata must have its own exact route');
    assert.doesNotMatch(metadataLocation, /proxy_pass/, 'metadata must not reach Detection or Defense');
    assert.match(metadataLocation, /\$request_method != GET/);
    assert.match(metadataLocation, /add_header Cache-Control "no-store" always;/);
    assert.match(metadataLocation, /add_header X-Content-Type-Options "nosniff" always;/);

    const body = metadataLocation.match(/return 200 '([^']+)';/)?.[1];
    assert.ok(body, 'gateway metadata must return JSON');
    assert.deepEqual(JSON.parse(body), { publicPath: `/${name}/` });
    assert.match(config, new RegExp(`location \\^~ /${name}/ \\{\\s*proxy_pass http://detection:8080/;`));
    assert.match(config, new RegExp(`location = / \\{\\s*return 302 /${name}/;`));
  });
}
