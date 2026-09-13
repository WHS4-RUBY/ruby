const crypto = require("crypto");

const OMITTED_HEADER_NAMES = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "content-length",
  "x-attacker-id",
  "x-experiment-run-id",
]);

function clean(value) {
  return String(value || "").trim().replace(/\s+/g, " ").toLowerCase();
}

function sortedTokens(value) {
  return clean(value)
    .split(",")
    .map((item) => item.trim().split(";")[0])
    .filter(Boolean)
    .sort();
}

function primaryLanguage(value) {
  const first = clean(value).split(",")[0].split(";")[0];
  return first || "unknown";
}

function userAgentProduct(value) {
  const ua = String(value || "");
  const matchers = [
    ["edge", /Edg\/([0-9]+)/],
    ["chrome", /(?:Chrome|CriOS)\/([0-9]+)/],
    ["firefox", /(?:Firefox|FxiOS)\/([0-9]+)/],
    ["safari", /Version\/([0-9]+).*Safari\//],
    ["curl", /curl\/([0-9]+)/i],
    ["wget", /Wget\/([0-9]+)/i],
    ["python-urllib", /Python-urllib\/([0-9]+)/i],
    ["python-requests", /python-requests\/([0-9]+)/i],
  ];
  for (const [family, matcher] of matchers) {
    const match = ua.match(matcher);
    if (match) return { family, major: match[1] };
  }
  const product = ua.match(/^([^\s/]+)(?:\/([0-9]+))?/);
  return {
    family: product ? product[1].toLowerCase() : "unknown",
    major: product?.[2] || "0",
  };
}

function headerNamesInOrder(rawHeaders, headers) {
  const names = [];
  if (Array.isArray(rawHeaders) && rawHeaders.length) {
    for (let index = 0; index < rawHeaders.length; index += 2) {
      const name = clean(rawHeaders[index]);
      if (name && !OMITTED_HEADER_NAMES.has(name)) names.push(name);
    }
    return names;
  }
  return Object.keys(headers || {})
    .map(clean)
    .filter((name) => name && !OMITTED_HEADER_NAMES.has(name));
}

function hash(value) {
  return crypto.createHash("sha256").update(value).digest("hex").slice(0, 16);
}

function canonical(value) {
  return JSON.stringify(value);
}

function acceptClass(value) {
  const accept = clean(value);
  if (!accept || accept === "*/*") return "any";
  if (accept.includes("text/html")) return "document";
  if (accept.includes("application/json")) return "json";
  if (accept.includes("image/")) return "image";
  if (accept.includes("text/css")) return "style";
  if (accept.includes("javascript")) return "script";
  return "other";
}

function buildHttpFingerprint({ headers = {}, rawHeaders = [], httpVersion = "", method = "" } = {}) {
  const product = userAgentProduct(headers["user-agent"]);
  const clientComponents = {
    version: 2,
    userAgentFamily: product.family,
    userAgentMajor: product.major,
    userAgent: clean(headers["user-agent"]),
    primaryLanguage: primaryLanguage(headers["accept-language"]),
    acceptEncodings: sortedTokens(headers["accept-encoding"]),
    clientHints: {
      brands: clean(headers["sec-ch-ua"]),
      mobile: clean(headers["sec-ch-ua-mobile"]),
      platform: clean(headers["sec-ch-ua-platform"]),
    },
  };
  // Client Hints는 요청 종류와 브라우저 정책에 따라 생략될 수 있으므로 관찰값으로만
  // 보존한다. 안정 후보 지문에는 UA/언어/압축 협상만 사용한다.
  const stableClientComponents = {
    version: clientComponents.version,
    userAgentFamily: clientComponents.userAgentFamily,
    userAgentMajor: clientComponents.userAgentMajor,
    userAgent: clientComponents.userAgent,
    primaryLanguage: clientComponents.primaryLanguage,
    acceptEncodings: clientComponents.acceptEncodings,
  };
  const orderedHeaderNames = headerNamesInOrder(rawHeaders, headers);
  const requestComponents = {
    version: 2,
    method: String(method || "").toUpperCase(),
    httpVersion: String(httpVersion || "unknown"),
    acceptClass: acceptClass(headers.accept),
    contentType: clean(headers["content-type"]).split(";")[0] || "none",
    hasReferer: Boolean(headers.referer),
    hasCookie: Boolean(headers.cookie),
    headerNames: orderedHeaderNames,
  };
  return {
    version: 2,
    clientFingerprint: `hfp2:${hash(canonical(stableClientComponents))}`,
    requestFingerprint: `hrq2:${hash(canonical(requestComponents))}`,
    headerOrderFingerprint: `hho2:${hash(canonical(orderedHeaderNames))}`,
    clientComponents,
    requestComponents,
  };
}

module.exports = {
  OMITTED_HEADER_NAMES,
  acceptClass,
  buildHttpFingerprint,
  headerNamesInOrder,
  primaryLanguage,
  userAgentProduct,
};
