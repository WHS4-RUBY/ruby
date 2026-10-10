// Opens Juice Shop screens beyond the core flow as a normal registered user and reports, per
// screen, the same-origin API traffic. Exit code 1 if any screen requests an original protected
// route (with aliases on), gets a 5xx, a Defense 404 ({"error":"not_found"}) or a page error.
// Usage: node browser_screens.cjs <label> [base] [--mode off|observe|enforce]
const { chromium } = require('/runner/node_modules/playwright');

const LABEL = process.argv[2] || 'run';
const BASE = process.argv[3] && !process.argv[3].startsWith('--') ? process.argv[3] : 'http://host.docker.internal:8081';
const MODE = process.argv.includes('--mode') ? process.argv[process.argv.indexOf('--mode') + 1] : 'enforce';
const ALIASES_ON = MODE === 'observe' || MODE === 'enforce';
const PROTECTED = /^\/(rest|api|b2b)\//i;
const SCREENS = [
  '/#/privacy-security/two-factor-authentication', '/#/deluxe-membership', '/#/wallet', '/#/chatbot',
  '/#/complain', '/#/privacy-security/data-export', '/#/privacy-security/change-password',
  '/#/privacy-security/last-login-ip', '/#/address/saved', '/#/saved-payment-methods', '/#/order-history',
  '/#/recycle', '/#/photo-wall', '/#/score-board', '/#/contact', '/#/track-result?id=5267-a1b2c3d4e5f6a7b8',
  '/#/basket',
];

async function dismiss(page) {
  await page.waitForTimeout(500);
  for (const selector of ['button[aria-label="Close Welcome Banner"]', 'a[aria-label="dismiss cookie message"]']) {
    const item = page.locator(selector).first();
    if (await item.isVisible().catch(() => false)) await item.click().catch(() => {});
  }
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();
  page.setDefaultTimeout(15000);
  let current = null;
  const stats = {};
  const bucket = () => (stats[current] ||= { api: 0, alias: 0, direct: 0, status: {}, defense404: 0, failed: 0, pageErrors: 0 });
  page.on('pageerror', () => { if (current) bucket().pageErrors++; });
  page.on('requestfailed', (r) => {
    if (current && r.url().startsWith(BASE) && r.failure()?.errorText !== 'net::ERR_ABORTED') bucket().failed++;
  });
  page.on('response', async (response) => {
    if (!current || !response.url().startsWith(BASE)) return;
    const path = new URL(response.url()).pathname;
    const isAlias = path.startsWith('/__ruby_alias_');
    if (!isAlias && !PROTECTED.test(path)) return;
    const b = bucket();
    b.api++;
    if (isAlias) b.alias++; else b.direct++;
    b.status[response.status()] = (b.status[response.status()] || 0) + 1;
    if (response.status() === 404) {
      const text = await response.text().catch(() => '');
      if (text.includes('"error":"not_found"')) b.defense404++;
    }
  });

  // Register and log in a fresh normal user (not a privileged account).
  const email = `screens${Date.now()}@example.invalid`, password = 'Verify-Pass-123';
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
  await page.fill('#email', email);
  await page.fill('#password', password);
  await page.click('#loginButton');
  await page.waitForURL(/#\/search/);

  for (const screen of [...SCREENS, 'logout:/#/forgot-password']) {
    current = screen;
    bucket();
    if (screen.startsWith('logout:')) {
      await page.evaluate(() => localStorage.removeItem('token'));
      await page.goto(BASE + screen.slice(7), { waitUntil: 'networkidle' }).catch(() => {});
      await page.fill('#email', email).catch(() => {});  // triggers /rest/user/security-question
      await page.waitForTimeout(1500);
    } else {
      await page.goto(BASE + screen, { waitUntil: 'networkidle' }).catch(() => {});
      await page.waitForTimeout(800);
    }
    await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
  }
  current = null;
  let failures = 0;
  for (const [screen, b] of Object.entries(stats)) {
    const ok = (!ALIASES_ON || b.direct === 0) && b.defense404 === 0 && b.failed === 0 && b.pageErrors === 0 &&
      !Object.keys(b.status).some((s) => Number(s) >= 500);
    if (!ok) failures++;
    console.log(JSON.stringify({ label: LABEL, screen, ok, ...b }));
  }
  console.log(JSON.stringify({ label: LABEL, summary: { screens: Object.keys(stats).length, failures } }));
  await browser.close();
  if (failures) process.exitCode = 1;
})().catch((error) => { console.error(error); process.exitCode = 1; });
