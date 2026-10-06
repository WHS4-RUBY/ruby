// Run in the local Playwright test image on ruby-local_ai-defense-net.
const { chromium } = require('playwright');
const fs = require('node:fs');
const base = process.env.BROWSER_TEST_BASE || 'http://detection:8080';

(async () => {
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    const responses = [], errors = [], steps = [];
    page.on('response', response => {
      if (response.url().startsWith(base)) responses.push({ path: response.url().slice(base.length),
        status: response.status(), resourceType: response.request().resourceType() });
    });
    page.on('pageerror', error => errors.push(String(error)));
    async function dismissPopups() {
      const dismiss = page.locator('mat-dialog-container').getByText('Dismiss', { exact: true });
      if (await dismiss.isVisible().catch(() => false)) await dismiss.click();
      const cookies = page.getByText('Me want it!', { exact: true });
      if (await cookies.isVisible().catch(() => false)) {
        try { await cookies.click({ timeout: 1500 }); }
        catch (error) {
          // The welcome dialog can appear between the visibility check and cookie click.
          if (!await dismiss.isVisible().catch(() => false)) throw error;
          await dismiss.click();
          await cookies.click();
        }
      }
    }
    async function step(name, operation) {
      const started = performance.now();
      try { await operation(); steps.push({ name, passed: true,
        durationMs: Math.round((performance.now() - started) * 1000) / 1000 }); }
      catch (error) { steps.push({ name, passed: false, error: String(error),
        durationMs: Math.round((performance.now() - started) * 1000) / 1000 }); }
    }
    await step('first_page', async () => {
      await page.goto(base, { waitUntil: 'domcontentloaded' });
      await page.getByText('All Products', { exact: true }).waitFor();
      await dismissPopups();
    });
    await step('search', async () => {
      await page.goto(base + '/#/search?q=apple', { waitUntil: 'domcontentloaded' });
      await page.getByText('Apple Juice (1000ml)', { exact: true }).waitFor();
    });
    await step('product_detail', async () => {
      await dismissPopups();
      await page.getByText('Apple Juice (1000ml)', { exact: true }).click();
      await page.locator('mat-dialog-container').waitFor();
      await page.keyboard.press('Escape');
    });
    await step('reload', async () => {
      await page.reload({ waitUntil: 'domcontentloaded' });
      await page.getByText('Apple Juice (1000ml)', { exact: true }).waitFor();
    });
    await step('back_forward', async () => {
      await page.goto(base + '/#/login', { waitUntil: 'domcontentloaded' });
      await page.locator('#email').waitFor();
      await page.goBack({ waitUntil: 'domcontentloaded' });
      await page.getByText('Apple Juice (1000ml)', { exact: true }).waitFor();
      await page.goForward({ waitUntil: 'domcontentloaded' });
      await page.locator('#email').waitFor();
    });
    const failedResponses = responses.filter(r => r.status >= 400);
    const report = { steps, errors, failedResponses, responses,
      cookieNames: (await context.cookies()).map(cookie => cookie.name) };
    fs.writeFileSync('/results/browser-regression.json', JSON.stringify(report, null, 2));
    console.log(JSON.stringify({ steps, errors, failedResponses }));
    process.exitCode = steps.every(s => s.passed) && !errors.length && !failedResponses.length ? 0 : 1;
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
