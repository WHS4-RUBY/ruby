// 자동화 툴/스크립트/헤드리스 브라우저에서 흔히 보이는 User-Agent 패턴
const AUTOMATION_UA_PATTERNS = [
  /python-requests/i,
  /python-urllib/i,
  /curl\//i,
  /wget\//i,
  /Go-http-client/i,
  /okhttp/i,
  /axios\//i,
  /node-fetch/i,
  /libwww-perl/i,
  /HeadlessChrome/i,
  /PhantomJS/i,
  /Playwright/i,
  /Puppeteer/i,
  /Selenium/i,
  /Scrapy/i,
  /^Mozilla\/5\.0$/i, // 최소값만 채워 넣은 조작된 UA
  /bot|crawler|spider/i,
  /^$/, // UA 없음
];

// 실제 브라우저(특히 Chromium 계열)는 Fetch Metadata 헤더(Sec-Fetch-*)를 항상 보낸다.
// 스크립트/HTTP 클라이언트 라이브러리는 대부분 이를 보내지 않는다.
const EXPECTED_BROWSER_HEADERS = [
  "accept-language",
  "sec-fetch-site",
  "sec-fetch-mode",
  "sec-fetch-dest",
];

function isAutomationUA(userAgent = "") {
  return AUTOMATION_UA_PATTERNS.some((re) => re.test(userAgent));
}

function missingBrowserHeaders(headers = {}) {
  const lower = Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])
  );
  return EXPECTED_BROWSER_HEADERS.filter((h) => !lower[h]);
}

module.exports = { isAutomationUA, missingBrowserHeaders, EXPECTED_BROWSER_HEADERS };
