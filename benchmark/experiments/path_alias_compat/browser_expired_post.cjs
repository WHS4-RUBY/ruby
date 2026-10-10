// Expired-tab POSTs in a real browser: add to basket and place an order from a page whose
// aliases have expired (no reload). A 307 is an expected intermediate step, not a failure.
// Reports, per POST, the status chain the page saw and the final status; the caller checks the
// Defense log for how many times each POST was forwarded to the target.
// Usage: node browser_expired_post.cjs <label> <base> <wait-seconds> <expect: redirect|refuse>
const { chromium } = require('/runner/node_modules/playwright');

const [LABEL, BASE, WAIT_S, EXPECT] = process.argv.slice(2);
const WAIT = Number(WAIT_S) * 1000;
const results = [];
let p;

function log(check, ok, info = {}) {
  results.push({ check, ok, ...info });
  console.log(JSON.stringify({ label: LABEL, check, ok, ...info }));
}

async function step(check, fn) {
  try { log(check, true, (await fn()) || {}); return true; }
  catch (e) { log(check, false, { error: String(e.message).slice(0, 300), url: p.url() }); return false; }
}

async function dismiss() {
  await p.waitForTimeout(500);
  for (const s of ['button[aria-label="Close Welcome Banner"]', 'a[aria-label="dismiss cookie message"]'])
    if (await p.locator(s).first().isVisible().catch(() => false)) await p.locator(s).first().click().catch(() => {});
}

async function goto(route) { await p.goto(BASE + '/#/' + route, { waitUntil: 'networkidle' }); await dismiss(); }

// Every POST of the action, in order: [{path, status}], plus the final status.
async function postChain(action) {
  const chain = [];
  const listener = (r) => {
    if (r.request().method() === 'POST' && r.url().startsWith(BASE))
      chain.push({ path: new URL(r.url()).pathname, status: r.status() });
  };
  p.on('response', listener);
  await action();
  await p.waitForLoadState('networkidle', { timeout: 10000 }).catch(() => {});
  await p.waitForTimeout(500);
  p.off('response', listener);
  return { chain, final: chain.length ? chain.at(-1).status : null };
}

function judge(result) {
  const statuses = result.chain.map((x) => x.status);
  if (EXPECT === 'redirect') {
    // exactly one 307 followed by exactly one successful POST
    return statuses.length === 2 && statuses[0] === 307 && statuses[1] >= 200 && statuses[1] < 300;
  }
  return statuses.length === 1 && statuses[0] === 404;
}

(async () => {
  const b = await chromium.launch({ headless: true });
  const c = await b.newContext();
  p = await c.newPage();
  p.setDefaultTimeout(20000);
  const email = `expired${Date.now()}@example.invalid`, password = 'Verify-Pass-123';

  await step('setup_register_login', async () => {
    await goto('register');
    await p.fill('#emailControl', email);
    await p.fill('#passwordControl', password);
    await p.fill('#repeatPasswordControl', password);
    await p.locator('mat-select[name="securityQuestion"]').click({ force: true });
    await p.locator('mat-option').first().click();
    await p.fill('#securityAnswerControl', 'blue');
    await p.click('#registerButton');
    await p.waitForURL(/#\/login/);
    await p.fill('#email', email);
    await p.fill('#password', password);
    await p.click('#loginButton');
    await p.waitForURL(/#\/search/);
  });
  if (EXPECT === 'redirect') {
    await step('setup_address_and_card', async () => {
      await goto('address/create');
      const inputs = p.locator('#address-form input');
      for (const [i, v] of ['Korea', 'Verify User', '1012345678', '12345', 'Seoul', 'Seoul'].entries()) await inputs.nth(i).fill(v);
      await p.fill('#address', '123 Verify Street');
      const address = p.waitForResponse((r) => r.request().method() === 'POST' && r.url().startsWith(BASE));
      await p.locator('#submitButton').click();
      if ((await address).status() >= 300) throw new Error('address POST ' + (await address).status());
      // The app navigates to the saved-address list itself; let that finish before moving on.
      await p.waitForURL(/address\/saved/, { timeout: 10000 }).catch(() => {});
      await p.waitForLoadState('networkidle', { timeout: 10000 }).catch(() => {});
      await goto('saved-payment-methods');
      await p.waitForTimeout(1000);
      await p.locator('mat-expansion-panel-header').first().click();
      await p.locator('app-payment-method input').nth(0).fill('Verify User');
      await p.locator('app-payment-method input').nth(1).fill('4111111111111111');
      await p.locator('app-payment-method select').nth(0).selectOption('12');
      await p.locator('app-payment-method select').nth(1).selectOption({ index: 2 });
      const card = p.waitForResponse((r) => r.request().method() === 'POST' && r.url().startsWith(BASE));
      await p.locator('#submitButton').click();
      if ((await card).status() >= 300) throw new Error('card POST ' + (await card).status());
      await goto('saved-payment-methods');
      await p.locator('app-payment-method mat-row').first().waitFor();
    });
  }
  // Fresh aliases, then leave the tab open until they expire.
  await step('open_search_then_idle', async () => {
    await p.reload({ waitUntil: 'networkidle' });
    await goto('search');
    await p.locator('button[aria-label="Add to Basket"]').first().waitFor();
    await p.waitForTimeout(WAIT);
    return { idle_seconds: Number(WAIT_S) };
  });
  const add = await postChain(() => p.locator('button[aria-label="Add to Basket"]').first().click());
  log('expired_add_to_basket', judge(add), add);
  if (EXPECT === 'redirect') {
    await step('basket_has_one_item_after_expiry', async () => {
      await goto('basket');  // SPA navigation: GETs on expired aliases are 307-recovered
      await p.locator('mat-row').first().waitFor();
      const rows = await p.locator('mat-row').count();
      if (rows !== 1) throw new Error(`basket rows ${rows}`);
      return { rows };
    });
    await step('checkout_to_summary', async () => {
      await p.click('#checkoutButton');
      await p.locator('mat-radio-button').first().click();
      await p.locator('button[aria-label="Proceed to payment selection"]').click();
      await p.waitForURL(/delivery-method/);
      await p.locator('mat-radio-button').first().click();
      await p.locator('button.nextButton').click();
      await p.waitForURL(/payment/);
      await p.locator('app-payment-method mat-radio-button').first().click();
      await p.locator('button[aria-label="Proceed to review"]').click();
      await p.waitForURL(/order-summary/);
      await p.waitForTimeout(WAIT);  // the order POST will use an expired alias
      return { idle_seconds: Number(WAIT_S) };
    });
    const order = await postChain(async () => {
      await p.locator('button[aria-label="Complete your purchase"]').click();
      await p.waitForURL(/order-completion/, { timeout: 20000 }).catch(() => {});
    });
    log('expired_place_order', judge(order) && /order-completion/.test(p.url()), { ...order, url: p.url() });
    await step('order_history_has_exactly_one_order', async () => {
      await p.reload({ waitUntil: 'networkidle' });
      await goto('order-history');
      await p.locator('.orders-container .table-container').first().waitFor();
      const orders = await p.locator('.orders-container .table-container').count();
      if (orders !== 1) throw new Error(`orders ${orders}`);
      return { orders };
    });
  }
  const passed = results.filter((r) => r.ok).length;
  console.log(JSON.stringify({ label: LABEL, summary: { passed, total: results.length } }));
  await b.close();
  if (passed !== results.length) process.exitCode = 1;
})().catch((e) => { console.error(e); process.exitCode = 1; });
