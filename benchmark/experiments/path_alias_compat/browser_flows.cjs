// Normal-user flows through Detection -> Defense -> CHeaT -> Juice Shop with a real browser.
// Usage: node browser_flows.cjs <label> [base] [--mode off|audit|observe|enforce] [--wait-expiry seconds]
// Exits non-zero when any step fails, any same-origin response is 4xx/5xx, the page throws,
// or (with aliases on) the app requests an original protected route.
const { chromium } = require('/runner/node_modules/playwright');

const LABEL = process.argv[2] || 'run';
const BASE = process.argv[3] || 'http://host.docker.internal:8081';
const WAIT = process.argv.includes('--wait-expiry') ? Number(process.argv[process.argv.indexOf('--wait-expiry') + 1]) : 0;
const MODE = process.argv.includes('--mode') ? process.argv[process.argv.indexOf('--mode') + 1] : 'enforce';
const ALIASES_ON = MODE === 'observe' || MODE === 'enforce';
const PROTECTED = /^\/(rest|api|b2b)\//i;
const results = [];
const net = { alias: 0, direct: 0, redirects: 0, errors4xx: [], errors5xx: [], aliasStatuses: {}, failed: [], cancelled: [] };

function log(step, ok, info = {}) {
  results.push({ step, ok, ...info });
  console.log(JSON.stringify({ label: LABEL, step, ok, ...info }));
}

let currentPage = null;

async function step(name, fn) {
  try {
    const info = await fn();
    // Let in-flight XHRs finish so the next navigation does not cancel them (ERR_ABORTED).
    if (currentPage) await currentPage.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
    log(name, true, info || {});
    return true;
  }
  catch (error) { log(name, false, { error: String(error.message || error).slice(0, 200) }); return false; }
}

function watch(page) {
  page.on('requestfailed', (request) => {
    if (!request.url().startsWith(BASE)) return;
    const entry = `${request.failure()?.errorText} ${new URL(request.url()).pathname.slice(0, 40)}`;
    // ERR_ABORTED = the app or a navigation cancelled the request (Juice Shop's review dialog
    // does this with aliases off too). Reported separately; every other failure fails the run.
    (request.failure()?.errorText === 'net::ERR_ABORTED' ? net.cancelled : net.failed).push(entry);
  });
  page.on('response', (response) => {
    const url = new URL(response.url());
    if (!url.href.startsWith(BASE)) return;
    const status = response.status();
    if (url.pathname.startsWith('/__ruby_alias_')) {
      net.alias++;
      net.aliasStatuses[status] = (net.aliasStatuses[status] || 0) + 1;
    }
    if (PROTECTED.test(url.pathname)) net.direct++;
    if (status === 307) net.redirects++;
    if (status >= 500) net.errors5xx.push(`${status} ${url.pathname.slice(0, 40)}`);
    else if (status >= 400) net.errors4xx.push(`${status} ${url.pathname.slice(0, 40)}`);
  });
}

async function dismiss(page) {
  await page.waitForTimeout(500);
  for (const selector of ['button[aria-label="Close Welcome Banner"]', 'a[aria-label="dismiss cookie message"]']) {
    const item = page.locator(selector).first();
    if (await item.isVisible().catch(() => false)) await item.click().catch(() => {});
  }
  await page.locator('.cdk-overlay-backdrop').first().waitFor({ state: 'detached', timeout: 3000 }).catch(() => {});
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ serviceWorkers: 'allow' });
  const page = await context.newPage();
  currentPage = page;
  page.setDefaultTimeout(15000);
  let pageErrors = 0;
  page.on('pageerror', () => { pageErrors++; });
  watch(page);
  const email = `user${Date.now()}@example.invalid`;
  const password = 'Verify-Pass-123';

  await step('home', async () => {
    await page.goto(BASE + '/', { waitUntil: 'networkidle' });
    await dismiss(page);
    await page.locator('mat-card').first().waitFor();
    return { products: await page.locator('mat-card').count() };
  });
  await step('register', async () => {
    await page.goto(BASE + '/#/register', { waitUntil: 'networkidle' });
    await dismiss(page);
    await page.fill('#emailControl', email);
    await page.fill('#passwordControl', password);
    await page.fill('#repeatPasswordControl', password);
    await page.locator('mat-select[name="securityQuestion"]').click({ force: true });
    await page.locator('mat-option').first().click();
    await page.fill('#securityAnswerControl', 'blue');
    await page.click('#registerButton');
    await page.waitForURL(/#\/login/);
  });
  await step('login', async () => {
    await page.fill('#email', email);
    await page.fill('#password', password);
    await page.click('#loginButton');
    await page.waitForURL(/#\/search/);
    return { token: Boolean(await page.evaluate(() => localStorage.getItem('token'))) };
  });
  await step('search', async () => {
    await page.goto(BASE + '/#/search?q=apple');
    await page.locator('mat-card').first().waitFor();
    return { results: await page.locator('mat-card').count() };
  });
  await step('add_to_basket', async () => {
    await page.goto(BASE + '/#/search');
    await dismiss(page);
    await page.locator('mat-card').first().waitFor();
    const add = page.waitForResponse((r) => r.request().method() === 'POST' && r.status() < 300 &&
      /BasketItems|__ruby_alias_/.test(r.url()), { timeout: 15000 });
    await page.locator('button[aria-label="Add to Basket"]').first().click({ force: true });
    const added = await add;
    await page.goto(BASE + '/#/basket');
    await page.locator('mat-row, .mat-mdc-row').first().waitFor({ timeout: 20000 });
    return { add_status: added.status(), rows: await page.locator('mat-row, .mat-mdc-row').count() };
  });
  await step('write_review', async () => {
    await page.goto(BASE + '/#/search');
    await dismiss(page);
    await page.locator('mat-card img').first().click();
    const box = page.locator('textarea[aria-label="Text field to review a product"]');
    await box.click({ force: true });
    await box.pressSequentially('verification review ' + Date.now());
    await page.locator('#submitButton').click({ force: true });
    await page.locator('simple-snack-bar, .mat-mdc-snack-bar-label').first().waitFor();
    await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
    await page.keyboard.press('Escape');
  });
  await step('second_tab_same_cookie', async () => {
    const tab = await context.newPage();
    watch(tab);
    await tab.goto(BASE + '/#/search?q=banana', { waitUntil: 'networkidle' });
    await tab.locator('mat-card').first().waitFor();
    await page.goto(BASE + '/#/basket');
    await page.locator('mat-row, .mat-mdc-row').first().waitFor();
    await tab.close();
  });
  await step('back_forward', async () => {
    await page.goto(BASE + '/#/search?q=apple');
    await page.locator('mat-card').first().waitFor();
    await page.goBack();
    await page.locator('mat-row, .mat-mdc-row').first().waitFor();
    await page.goForward();
    await page.locator('mat-card').first().waitFor();
  });
  await step('cache_and_service_worker', async () => {
    await page.reload({ waitUntil: 'networkidle' });
    await page.locator('mat-card').first().waitFor();
    return { serviceWorker: await page.evaluate(() => Boolean(navigator.serviceWorker && navigator.serviceWorker.controller)),
      cookie: (await context.cookies()).some((c) => c.name === 'ruby_alias_client') };
  });
  if (WAIT > 0) {
    await step('expiry_wait', async () => { await page.waitForTimeout(WAIT * 1000); return { seconds: WAIT }; });
    await step('after_expiry_spa_search_without_reload', async () => {
      await page.goto(BASE + '/#/search?q=apple');
      await page.locator('mat-card').first().waitFor();
      return { redirects: net.redirects };
    });
    await step('after_expiry_basket_get', async () => {
      await page.goto(BASE + '/#/basket');
      await page.locator('mat-row, .mat-mdc-row').first().waitFor();
    });
    await step('after_expiry_reload_then_add', async () => {
      await page.reload({ waitUntil: 'networkidle' });
      await page.goto(BASE + '/#/search');
      await page.locator('button[aria-label="Add to Basket"]').nth(1).click();
      await page.locator('simple-snack-bar, .mat-mdc-snack-bar-label').first().waitFor();
    });
  }
  log('network', (!ALIASES_ON || net.direct === 0) && net.errors4xx.length === 0 &&
    net.errors5xx.length === 0 && net.failed.length === 0 && pageErrors === 0, {
    mode: MODE, alias_requests: net.alias, alias_statuses: net.aliasStatuses, direct_protected_requests: net.direct,
    redirects: net.redirects, errors4xx: net.errors4xx, errors5xx: net.errors5xx, failed_requests: net.failed, cancelled_requests: net.cancelled,
    page_errors: pageErrors });
  const passed = results.filter((r) => r.ok).length;
  console.log(JSON.stringify({ label: LABEL, summary: { passed, total: results.length } }));
  await browser.close();
  if (passed !== results.length) process.exitCode = 1;
})().catch((error) => { console.error(error); process.exitCode = 1; });
