// Capture same-origin API paths during an explicitly supplied browser flow.
// Run with Node and Playwright installed, or in the local Playwright test image.
const fs = require('node:fs');
const { URL } = require('node:url');

const FORMAT = 'ruby-runtime-requests-v1';
const ACTIONS = new Set(['goto', 'click', 'fill', 'press', 'waitFor', 'wait', 'reload', 'back', 'forward']);
const DEFAULT_PREFIXES = ['/rest/', '/api/'];

function parsePrefixes(value) {
  const prefixes = value ? value.split(',').map(item => item.trim()) : DEFAULT_PREFIXES;
  if (!prefixes.length || prefixes.length > 16 || prefixes.some(prefix =>
      !/^\/[A-Za-z0-9_./-]+$/.test(prefix) || prefix.includes('..')))
    throw new Error('Invalid --prefixes; use comma-separated URL path prefixes');
  return prefixes;
}

function protectedPath(path, prefixes) {
  return prefixes.some(prefix => prefix.endsWith('/') ? path.startsWith(prefix) :
    path === prefix || path.startsWith(prefix + '/'));
}

function parseArgs(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    if (!['--origin', '--steps', '--output', '--storage-state', '--prefixes'].includes(key) || !argv[i + 1])
      throw new Error(`Invalid argument: ${key || '(missing)'}`);
    options[key.slice(2).replace('-', '_')] = argv[i + 1];
  }
  if (!options.origin || !options.steps || !options.output)
    throw new Error('Required: --origin URL --steps flow.json --output capture.runtime.json');
  const origin = new URL(options.origin);
  if (!['http:', 'https:'].includes(origin.protocol) || origin.pathname !== '/' || origin.search || origin.hash ||
      origin.username || origin.password)
    throw new Error('--origin must be a plain HTTP(S) origin');
  if (!options.output.endsWith('.runtime.json'))
    throw new Error('--output must end in .runtime.json');
  options.origin = origin.origin;
  options.prefixes = parsePrefixes(options.prefixes);
  return options;
}

function cleanRequest(rawUrl, method, resourceType, origin, prefixes = DEFAULT_PREFIXES) {
  let parsed;
  try { parsed = new URL(rawUrl); } catch { return null; }
  if (parsed.origin !== origin || !protectedPath(parsed.pathname, prefixes)) return null;
  return { path: parsed.pathname, method: method.toUpperCase(), resource_type: resourceType,
    query_keys: [...new Set(parsed.searchParams.keys())].sort() };
}

function validateSteps(raw, origin) {
  if (!Array.isArray(raw) || raw.length > 100 || !raw.length)
    throw new Error('Flow must contain 1–100 steps');
  return raw.map((step, index) => {
    if (!step || !ACTIONS.has(step.action)) throw new Error(`Invalid action at step ${index + 1}`);
    if (step.action === 'goto') {
      if (typeof step.path !== 'string') throw new Error(`Missing path at step ${index + 1}`);
      const target = new URL(step.path, origin + '/');
      if (target.origin !== origin) throw new Error(`Cross-origin navigation at step ${index + 1}`);
    }
    if (['click', 'fill', 'press', 'waitFor'].includes(step.action) &&
        (typeof step.selector !== 'string' || !step.selector))
      throw new Error(`Missing selector at step ${index + 1}`);
    if (step.action === 'fill' && (typeof step.valueEnv !== 'string' || !step.valueEnv))
      throw new Error(`fill requires valueEnv at step ${index + 1}`);
    if (step.action === 'press' && (typeof step.key !== 'string' || !step.key))
      throw new Error(`press requires key at step ${index + 1}`);
    if (step.action === 'wait' && (!Number.isInteger(step.ms) || step.ms < 0 || step.ms > 10000))
      throw new Error(`wait must be 0–10000 ms at step ${index + 1}`);
    return step;
  });
}

async function perform(page, step, origin) {
  switch (step.action) {
    case 'goto': return page.goto(new URL(step.path, origin + '/').href, { waitUntil: 'domcontentloaded' });
    case 'click': return page.locator(step.selector).click();
    case 'fill': {
      const value = process.env[step.valueEnv];
      if (value === undefined) throw new Error(`Missing environment variable: ${step.valueEnv}`);
      return page.locator(step.selector).fill(value);
    }
    case 'press': return page.locator(step.selector).press(step.key);
    case 'waitFor': return page.locator(step.selector).first().waitFor();
    case 'wait': return page.waitForTimeout(step.ms);
    case 'reload': return page.reload({ waitUntil: 'domcontentloaded' });
    case 'back': return page.goBack({ waitUntil: 'domcontentloaded' });
    case 'forward': return page.goForward({ waitUntil: 'domcontentloaded' });
    default: throw new Error(`Unsupported action: ${step.action}`);
  }
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const steps = validateSteps(JSON.parse(fs.readFileSync(options.steps, 'utf8')), options.origin);
  const { chromium } = require('playwright');
  const browser = await chromium.launch({ headless: true });
  const report = { format: FORMAT, origin: options.origin, protected_prefixes: options.prefixes, requests: [],
    steps: [], page_error_count: 0 };
  try {
    const context = await browser.newContext(options.storage_state ?
      { storageState: options.storage_state, serviceWorkers: 'block' } :
      { serviceWorkers: 'block' });
    const page = await context.newPage();
    page.setDefaultTimeout(10000);
    context.on('request', request => {
      const item = cleanRequest(request.url(), request.method(), request.resourceType(),
        options.origin, options.prefixes);
      if (item) report.requests.push(item);
    });
    page.on('pageerror', () => { report.page_error_count++; });
    for (const [index, step] of steps.entries()) {
      try {
        await perform(page, step, options.origin);
        report.steps.push({ index: index + 1, action: step.action, passed: true });
      } catch (error) {
        report.steps.push({ index: index + 1, action: step.action, passed: false,
          error_type: error.name || 'Error' });
        process.exitCode = 1;
        break;
      }
    }
    await page.waitForTimeout(250);
    if (report.page_error_count) process.exitCode = 1;
    await context.close();
  } finally {
    await browser.close();
    fs.writeFileSync(options.output, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
    console.log(JSON.stringify({ requests: report.requests.length, steps: report.steps.length,
      passed: report.steps.every(step => step.passed), output: options.output }));
  }
}

module.exports = { parseArgs, cleanRequest, validateSteps, main };
if (require.main === module) main().catch(error => { console.error(String(error)); process.exitCode = 1; });
