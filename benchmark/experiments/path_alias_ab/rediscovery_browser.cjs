// Cache-neutral public-page rediscovery and alias protocol checks; no exploit inputs.
const { chromium } = require('playwright');
const fs = require('node:fs');
const { performance } = require('node:perf_hooks');

const base = 'http://defense:8080';
const scenario = process.env.TEST_SCENARIO || 'normal';
const mode = process.env.TEST_ALIAS_MODE || 'off';
const duration = Number(process.env.TEST_DURATION || 900);
const interval = Number(process.env.TEST_INTERVAL || 45);
const out = '/results';
if (!['rediscovery'].includes(scenario) ||
    !['off', 'enforce'].includes(mode) || !Number.isFinite(duration) || duration < 1)
  throw new Error('Invalid test configuration');
const stream = fs.createWriteStream(`${out}/events.jsonl`, { flags: 'wx' });
const record = value => stream.write(JSON.stringify({ at: new Date().toISOString(), ...value }) + '\n');
const pause = ms => new Promise(resolve => setTimeout(resolve, Math.max(0, ms)));
const quantile = (values, p) => {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.max(0, Math.ceil(sorted.length * p) - 1)];
};
const metrics = { cycles: [], checks: [], requestLatenciesMs: [], httpStatuses: {}, recoveriesMs: [], rediscoveries: [],
  navigationCancellations: 0 };
let running = false;
let stopping = false;
let deadline;

async function dismiss(page) {
  const welcome = page.locator('mat-dialog-container').getByText('Dismiss', { exact: true });
  if (await welcome.isVisible().catch(() => false)) await welcome.click({ timeout: 3000 });
  const cookies = page.getByText('Me want it!', { exact: true });
  if (await cookies.isVisible().catch(() => false)) {
    try {
      await cookies.click({ timeout: 1500 });
    } catch (error) {
      // The asynchronously loaded welcome dialog may appear after the first check.
      if (await welcome.isVisible().catch(() => false)) await welcome.click({ timeout: 3000 });
      if (await cookies.isVisible().catch(() => false)) await cookies.click({ timeout: 3000 });
    }
  }
}

async function discover(user) {
  user.searchPath = null;
  await user.page.goto(`${base}/`, { waitUntil: 'domcontentloaded' });
  await user.page.getByText('All Products', { exact: true }).waitFor();
  await dismiss(user.page);
  await user.page.goto(`${base}/#/search?q=apple`, { waitUntil: 'domcontentloaded' });
  await user.page.getByText('Apple Juice (1000ml)', { exact: true }).waitFor();
  await dismiss(user.page);
  if (!user.searchPath) throw new Error('Product search route was not observed');
}

async function normalFlow(user) {
  await discover(user);
  await user.page.getByText('Apple Juice (1000ml)', { exact: true }).click();
  await user.page.locator('mat-dialog-container').waitFor();
  await user.page.keyboard.press('Escape');
  await user.page.goto(`${base}/#/login`, { waitUntil: 'domcontentloaded' });
  await user.page.locator('#email').waitFor();
  await user.page.goBack({ waitUntil: 'domcontentloaded' });
  await user.page.getByText('Apple Juice (1000ml)', { exact: true }).waitFor();
  await user.page.goForward({ waitUntil: 'domcontentloaded' });
  await user.page.locator('#email').waitFor();
  if (user.errors.length) throw new Error(user.errors.join('; '));
}

async function check(user, name, path, expected) {
  if (stopping) return;
  const start = performance.now();
  const response = await user.context.request.get(base + path, { timeout: 10000 });
  const status = response.status();
  const result = { type: 'check', user: user.id, name, expected, status,
    passed: status === expected, elapsedMs: performance.now() - start };
  metrics.checks.push(result);
  metrics.requestLatenciesMs.push(result.elapsedMs);
  record(result);
  await response.dispose();
  if (!result.passed) throw new Error(`${name}: expected ${expected}, got ${status}`);
}

async function recover(user, previous) {
  const start = performance.now();
  const capture = { browserRequests: 0, mainJsRequests: 0, jsRequests: 0,
    networkBytes: 0, jsBytes: 0 };
  user.capture = capture;
  try {
    await discover(user);
    const changed = user.searchPath !== previous;
    const expectedChange = mode === 'enforce';
    const result = { type: 'check', user: user.id, name: 'route_reissued',
      changed, expectedChange, passed: changed === expectedChange };
    metrics.checks.push(result);
    record(result);
    if (!result.passed) throw new Error('Unexpected alias reissue behavior');
    await check(user, 'recovered_search', user.searchPath + '?q=apple', 200);
    // CDP loadingFinished can arrive just after Playwright's DOM checks.
    await pause(100);
    const elapsedMs = performance.now() - start;
    metrics.recoveriesMs.push(elapsedMs);
    const measurement = { type: 'rediscovery', user: user.id, elapsedMs,
      changed, expectedChange, success: true, validationRequests: 1,
      browserRequests: capture.browserRequests, mainJsRequests: capture.mainJsRequests,
      jsRequests: capture.jsRequests, networkBytes: capture.networkBytes, jsBytes: capture.jsBytes };
    metrics.rediscoveries.push(measurement);
    record(measurement);
  } finally {
    user.capture = null;
  }
}

async function protocol(user, otherUsers) {
  const old = user.searchPath;
  await check(user, 'valid_search', old + '?q=apple', 200);
  const issued = (await user.context.cookies()).some(c => c.name === 'ruby_alias_client');
  const issuance = { type: 'check', user: user.id, name: 'client_cookie_issued',
    passed: issued === (mode === 'enforce'), issued };
  metrics.checks.push(issuance);
  record(issuance);
  if (!issuance.passed) throw new Error('Unexpected client cookie issuance');
  await check(user, 'direct_search', '/rest/products/search?q=apple', mode === 'enforce' ? 404 : 200);
  await check(user, 'previous_route_after_direct', old + '?q=apple', mode === 'enforce' ? 404 : 200);
  for (const other of otherUsers)
    await check(other, 'other_session_survives_direct', other.searchPath + '?q=apple', 200);
  await recover(user, old);
  if (scenario === 'lifecycle') {
    const fresh = user.searchPath;
    // Juice Shop's SPA fallback returns its HTML with 200 when aliases are off.
    await check(user, 'unknown_alias', '/__ruby_alias_' + 'z'.repeat(26), mode === 'enforce' ? 404 : 200);
    await check(user, 'previous_route_after_reject', fresh + '?q=apple', mode === 'enforce' ? 404 : 200);
    await recover(user, fresh);
  }
}

async function runUser(user, others) {
  let cycle = 0;
  while (!stopping && performance.now() < deadline) {
    cycle++;
    const start = performance.now();
    user.errors = [];
    try {
      await normalFlow(user);
      if (scenario === 'rediscovery' && user.id === 1)
        await protocol(user, others);
      if (stopping) break;
      if (user.errors.length) throw new Error(user.errors.join('; '));
      const result = { type: 'cycle', user: user.id, cycle, passed: true,
        elapsedMs: performance.now() - start };
      metrics.cycles.push(result);
      record(result);
    } catch (error) {
      if (stopping) break;
      const result = { type: 'cycle', user: user.id, cycle, passed: false,
        elapsedMs: performance.now() - start, error: String(error).slice(0, 1000) };
      metrics.cycles.push(result);
      record(result);
      // Attempt to recover at the next cycle; keep failures in the result.
    }
    await pause(Math.min(interval * 1000 - (performance.now() - start), deadline - performance.now()));
  }
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  const users = [];
  let complete = false;
  let fatal = null;
  let startedAt = null;
  let start = null;
  let timer;
  try {
    const count = 3;
    for (let id = 1; id <= count; id++) {
      const context = await browser.newContext({ serviceWorkers: 'block' });
      const page = await context.newPage();
      const cdp = await context.newCDPSession(page);
      await cdp.send('Network.enable');
      await cdp.send('Network.setCacheDisabled', { cacheDisabled: true });
      page.setDefaultTimeout(10000);
      const user = { id, context, page, searchPath: null, errors: [], capture: null,
        requestsById: new Map() };
      users.push(user);
      cdp.on('Network.responseReceived', event => {
        if (!running || !user.capture) return;
        const url = new URL(event.response.url);
        if (url.origin !== base) return;
        const capture = user.capture;
        const isJs = url.pathname.endsWith('.js');
        capture.browserRequests++;
        if (isJs) capture.jsRequests++;
        if (url.pathname.endsWith('/main.js')) capture.mainJsRequests++;
        user.requestsById.set(event.requestId, { capture, isJs });
      });
      cdp.on('Network.loadingFinished', event => {
        const item = user.requestsById.get(event.requestId);
        if (!item) return;
        user.requestsById.delete(event.requestId);
        const bytes = Math.max(0, event.encodedDataLength || 0);
        item.capture.networkBytes += bytes;
        if (item.isJs) item.capture.jsBytes += bytes;
      });
      cdp.on('Network.loadingFailed', event => user.requestsById.delete(event.requestId));
      page.on('request', request => {
        const url = new URL(request.url());
        if (url.origin === base && url.searchParams.has('q') &&
            (url.pathname === '/rest/products/search' || url.pathname.startsWith('/__ruby_alias_')))
          user.searchPath = url.pathname;
      });
      page.on('response', response => {
        if (running && response.url().startsWith(base)) {
          const status = response.status();
          metrics.httpStatuses[status] = (metrics.httpStatuses[status] || 0) + 1;
          if (status >= 400) user.errors.push(`browser HTTP ${status}`);
        }
      });
      page.on('requestfinished', request => {
        if (running && request.url().startsWith(base)) {
          const ms = request.timing().responseEnd;
          if (ms >= 0) metrics.requestLatenciesMs.push(ms);
        }
      });
      page.on('requestfailed', request => {
        if (running && !stopping && request.url().startsWith(base)) {
          const reason = request.failure()?.errorText;
          if (reason === 'net::ERR_ABORTED') metrics.navigationCancellations++;
          else user.errors.push(`network failure: ${reason}`);
        }
      });
      page.on('pageerror', error => { if (running) user.errors.push(String(error)); });
      await discover(user);
    }
    record({ type: 'warmup_complete', users: users.length });
    start = performance.now();
    deadline = start + duration * 1000;
    startedAt = new Date().toISOString();
    running = true;
    record({ type: 'start', scenario, mode, durationSeconds: duration, intervalSeconds: interval });
    const work = Promise.all(users.map(user => runUser(user,
      scenario === 'rediscovery' && user.id === 1 ? users.slice(1) : [])));
    await new Promise(resolve => { timer = setTimeout(resolve, duration * 1000); });
    stopping = true;
    running = false;
    await Promise.all(users.map(user => user.context.close()));
    await work;
    complete = true;
  } catch (error) {
    fatal = String(error);
    record({ type: 'fatal', error: fatal });
    process.exitCode = 2;
  } finally {
    clearTimeout(timer);
    stopping = true;
    running = false;
    await browser.close();
    const failures = metrics.cycles.filter(x => !x.passed).length;
    const checkFailures = metrics.checks.filter(x => !x.passed).length;
    const summary = { scenario, mode, complete, fatal, durationSeconds: duration,
      startedAt, endedAt: new Date().toISOString(),
      elapsedSeconds: start === null ? 0 : (performance.now() - start) / 1000,
      users: users.length, cycles: metrics.cycles.length, failures,
      protocolChecks: metrics.checks.length, protocolFailures: checkFailures,
      requestLatencyMs: { samples: metrics.requestLatenciesMs.length,
        p50: quantile(metrics.requestLatenciesMs, .5), p95: quantile(metrics.requestLatenciesMs, .95) },
      recoveryMs: { samples: metrics.recoveriesMs.length,
        p50: quantile(metrics.recoveriesMs, .5), p95: quantile(metrics.recoveriesMs, .95) },
      rediscovery: { samples: metrics.rediscoveries.length,
        elapsedMsP50: quantile(metrics.rediscoveries.map(x => x.elapsedMs), .5),
        elapsedMsP95: quantile(metrics.rediscoveries.map(x => x.elapsedMs), .95),
        browserRequestsP50: quantile(metrics.rediscoveries.map(x => x.browserRequests), .5),
        mainJsRequests: metrics.rediscoveries.reduce((n, x) => n + x.mainJsRequests, 0),
        networkBytes: metrics.rediscoveries.reduce((n, x) => n + x.networkBytes, 0),
        jsBytes: metrics.rediscoveries.reduce((n, x) => n + x.jsBytes, 0) },
      browserHttpStatuses: metrics.httpStatuses,
      browserCache304: metrics.httpStatuses[304] || 0,
      navigationCancellations: metrics.navigationCancellations,
      perUser: users.map(user => ({ user: user.id,
        cycles: metrics.cycles.filter(x => x.user === user.id).length,
        failures: metrics.cycles.filter(x => x.user === user.id && !x.passed).length })),
    };
    fs.writeFileSync(`${out}/summary.json`, JSON.stringify(summary, null, 2) + '\n');
    record({ type: 'summary', ...summary });
    await new Promise(resolve => stream.end(resolve));
    console.log(JSON.stringify(summary));
    if (!complete || failures || checkFailures || summary.browserCache304 || users.some(user =>
      !metrics.cycles.some(x => x.user === user.id))) process.exitCode = process.exitCode || 1;
  }
})().catch(error => { console.error(error); process.exitCode = 2; stream.end(); });
