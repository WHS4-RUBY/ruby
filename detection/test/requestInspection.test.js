const assert = require("node:assert/strict");
const http = require("node:http");
const test = require("node:test");
const express = require("express");
const { existsSync } = require("node:fs");
const { CrsScanner } = require("../lib/crsScanner");
const { createProxyCore } = require("../lib/proxyCore");
const { loadInspectionConfig, createRequestInspection, replayInspectedBody } = require("../lib/requestInspection");

const clean = { available: true, inspectionComplete: true, anomalyScore: 0, hits: [], categories: [] };
const attack = { ...clean, anomalyScore: 5, categories: ["sqli"], hits: [{ ruleId: "942100" }] };

async function listen(t, app) {
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }));
  return `http://127.0.0.1:${server.address().port}`;
}

function request(url, { method = "GET", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(url, { method, headers }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers,
        body: Buffer.concat(chunks).toString() }));
      res.on("error", reject);
    });
    req.on("error", reject);
    req.end(body);
  });
}

async function fixture(t, { mode = "enforce", scan = async () => clean, maximumBodyBytes = 1024 } = {}) {
  const received = [], scans = [], rejected = [], decisions = [];
  const target = await listen(t, (req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      received.push({ method: req.method, url: req.url, body: Buffer.concat(chunks).toString(), headers: req.headers });
      res.setHeader("Content-Type", "application/json");
      res.end('{"ok":true}');
    });
  });
  const app = express();
  const verify = (req, _res, buffer) => { req.detectionRequestBodyBuffer = Buffer.from(buffer); };
  app.use(express.json({ type: ["application/json", "application/*+json"], verify }));
  app.use(express.urlencoded({ extended: true, verify }));
  app.use(express.text({ type: "text/plain", verify }));
  app.use(createRequestInspection({
    scanner: { maximumBodyBytes, async scan(req) { scans.push(req); return scan(req); } },
    config: { mode, threshold: 5 },
    onRejected(req, result) { rejected.push(result); },
    onDecision(req, decision) { decisions.push(decision); },
  }));
  app.use(createProxyCore({ target, hooks: [{ onRequest({ proxyReq, req }) { replayInspectedBody(proxyReq, req); } }] }));
  app.use((error, _req, res, _next) => res.status(error.status || 500).json({ error: "invalid_request" }));
  return { base: await listen(t, app), received, scans, rejected, decisions };
}

test("inspection finishes before any upstream request is dispatched", async (t) => {
  let finishScan, scanStarted;
  const started = new Promise((resolve) => { scanStarted = resolve; });
  const result = new Promise((resolve) => { finishScan = resolve; });
  const f = await fixture(t, { scan: () => { scanStarted(); return result; } });
  const response = request(f.base + "/first-request");
  await started;
  assert.equal(f.received.length, 0);
  finishScan(attack);
  assert.equal((await response).status, 403);
  assert.equal(f.received.length, 0);
  assert.equal(f.rejected[0].upstreamReached, false);
});

test("HTML-declared requests and token-bearing requests receive the same attack inspection", async (t) => {
  const f = await fixture(t, { scan: async () => attack });
  for (const headers of [{}, { Accept: "text/html" }, { Cookie: "__ruby_tg=valid-test-token; dcid=identity" },
    { "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document" }]) {
    const response = await request(f.base + "/any-path", { headers });
    assert.equal(response.status, 403);
    assert.equal(response.headers["x-defense-applied"], "crs");
    assert.equal(response.headers["cache-control"], "no-store");
  }
  assert.equal(f.scans.length, 4);
  assert.equal(f.received.length, 0);
});

test("benign bodies are forwarded byte-for-byte for JSON, +json and forms, without a token", async (t) => {
  const f = await fixture(t);
  for (const [type, body] of [
    ["application/json", '{ "email" : "normal@example.com", "password" : "ordinary" }'],
    ["application/problem+json", '{ "value": "한글", "nested": [1,2] }'],
    ["application/x-www-form-urlencoded", "q=apple&q=pear&text=hello%20world"],
    ["text/plain;charset=UTF-8", "40"],
  ]) {
    const response = await request(f.base + "/unknown?q=one&q=two", { method: "POST",
      headers: { "Content-Type": type, "Content-Length": Buffer.byteLength(body) }, body });
    assert.equal(response.status, 200);
    assert.equal(f.received.at(-1).body, body);
    assert.equal(f.received.at(-1).url, "/unknown?q=one&q=two");
    assert.equal(f.scans.at(-1).detectionRequestBodyBuffer.toString(), body);
  }
});

test("inspection failure, timeout result, invalid score and incomplete native scan fail closed", async (t) => {
  const results = [() => { throw new Error("scanner failed"); },
    () => ({ available: false, error: "timeout" }), () => ({ ...clean, anomalyScore: NaN }),
    () => ({ ...clean, inspectionComplete: false }), () => ({ ...clean, inspectionComplete: undefined }),
    () => ({ ...clean, bodyTruncated: true }), () => null];
  for (const [index, scan] of results.entries()) {
    const f = await fixture(t, { scan });
    assert.equal((await request(f.base)).status, index === 5 ? 413 : 503);
    assert.equal(f.received.length, 0);
  }
});

test("unsupported and oversized bodies are rejected before scanning or forwarding", async (t) => {
  const f = await fixture(t, { maximumBodyBytes: 16 });
  for (const [type, body, expected] of [
    ["application/octet-stream", "uninspected", 415],
    ["multipart/form-data; boundary=x", "--x--", 415],
    ["application/json", '{"value":"too long to inspect"}', 413],
  ]) {
    const response = await request(f.base, { method: "POST", headers: { "Content-Type": type }, body });
    assert.equal(response.status, expected);
  }
  assert.equal(f.scans.length, 0);
  assert.equal(f.received.length, 0);
});

test("malformed JSON never reaches scanner or upstream", async (t) => {
  const f = await fixture(t);
  const response = await request(f.base, { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"x":' });
  assert.equal(response.status, 400);
  assert.equal(f.scans.length, 0);
  assert.equal(f.received.length, 0);
});

test("compressed bodies are explicitly unsupported in enforce mode", async (t) => {
  const f = await fixture(t);
  const body = require("node:zlib").gzipSync('{"value":"normal"}');
  const response = await request(f.base, { method: "POST", headers: {
    "Content-Type": "application/json", "Content-Encoding": "gzip", "Content-Length": body.length,
  }, body });
  assert.equal(response.status, 415);
  assert.equal(f.scans.length, 0);
  assert.equal(f.received.length, 0);
});

test("observe records attack and incomplete states but forwards; off skips scanning", async (t) => {
  const f = await fixture(t, { mode: "observe", scan: async () => attack });
  assert.equal((await request(f.base)).status, 200);
  assert.equal(f.decisions[0].action, "would_block");
  assert.equal((await request(f.base, { method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: "hello" })).status, 200);
  assert.equal(f.decisions[1].action, "observe_incomplete");
  assert.equal(f.received[1].body, "hello");
  const off = await fixture(t, { mode: "off", scan: () => { throw new Error("must not scan"); } });
  assert.equal((await request(off.base)).status, 200);
  assert.equal(off.scans.length, 0);
});

test("configuration rejects contradictory or invalid enforcement settings", () => {
  assert.deepEqual(loadInspectionConfig({}), { mode: "observe", threshold: 5 });
  for (const env of [{ CRS_MODE: "bad" }, { CRS_BLOCK_THRESHOLD: "0" },
    { CRS_BLOCK_THRESHOLD: "NaN" }, { CRS_MODE: "enforce", CRS_ENABLED: "false" }]) {
    assert.throws(() => loadInspectionConfig(env));
  }
});

test("real CRS blocks first-request SQLi before the HTTP backend and preserves benign requests", {
  skip: !existsSync(process.env.MODSECURITY_SCANNER_PATH || "/app/bin/modsecurity-scanner"),
}, async (t) => {
  const scanner = new CrsScanner();
  t.after(() => scanner.child?.kill());
  const f = await fixture(t, { maximumBodyBytes: scanner.maximumBodyBytes,
    scan: (req) => scanner.scan(req, "127.0.0.1") });
  for (const headers of [{}, { Accept: "text/html" }, { Cookie: "__ruby_tg=token; dcid=client" }]) {
    for (const type of ["application/json", "application/problem+json", "application/x-www-form-urlencoded"]) {
      const body = type.endsWith("urlencoded") ? "email=%27+OR+1%3D1--&password=x"
        : JSON.stringify({ email: "' OR 1=1--", password: "x" });
      const response = await request(f.base + "/arbitrary/login", { method: "POST",
        headers: { ...headers, "Content-Type": type }, body });
      assert.equal(response.status, 403, `${type}: ${response.body}`);
    }
  }
  assert.equal((await request(f.base + "/search?q=" + encodeURIComponent("' UNION SELECT 1,2,3--"),
    { headers: { Accept: "text/html" } })).status, 403);
  assert.equal(f.received.length, 0, "blocked requests must never reach the backend");
  assert.equal((await request(f.base + "/plain", { method: "POST", headers: { "Content-Type": "text/plain" },
    body: "' OR 1=1--" })).status, 403);
  assert.equal(f.received.length, 0);
  const body = '{ "email": "normal@example.com", "password": "ordinary-value" }';
  assert.equal((await request(f.base + "/arbitrary/login", { method: "POST",
    headers: { "Content-Type": "application/json" }, body })).status, 200);
  assert.equal(f.received[0].body, body);
  assert.equal((await request(f.base + "/search?q=apple", { headers: { Cookie: "__ruby_tg=expired" } })).status, 200);
  assert.equal(f.received.length, 2);
  assert.equal((await request(f.base + "/plain", { method: "POST", headers: { "Content-Type": "text/plain" }, body: "40" })).status, 200);
  assert.equal(f.received[2].body, "40");
});
