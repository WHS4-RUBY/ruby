const assert = require("node:assert/strict");
const test = require("node:test");
const { XssCandidateStore } = require("../lib/xssCandidateStore");
const { analyzeExchange, findingSummary } = require("../lib/xssReflection");
const { attributeStoredFindings } = require("../lib/xssAttribution");
const { extractFeatures } = require("../lib/featureExtractor");
const { classify } = require("../lib/classifier");
const store = require("../lib/sessionStore");

test("normal names, parentheses and harmless formatting do not become XSS evidence", () => {
  for (const value of ["O'Reilly", "Hello (world)", "<b>review marker</b>"]) {
    const result = analyzeExchange({
      url: `/?name=${encodeURIComponent(value)}`, responseContentType: "text/html",
    }, `<html><p>${value}</p></html>`, {});
    assert.deepEqual(result.tags, []);
    assert.equal(result.maxRisk, 0);
  }
});

test("plain text and ordinary header reflection do not count as HTML execution", () => {
  const result = analyzeExchange({
    url: "/?name=O%27Reilly", responseContentType: "text/plain",
  }, "<html>O'Reilly</html>", { "Content-Disposition": "attachment; filename=O'Reilly" });
  assert.deepEqual(result.tags, []);
});

test("script markup evidence is scored while inert JSON script content is excluded", () => {
  // String-only parser fixtures; no browser or JavaScript execution.
  const markup = '<script src="/static/review-marker.js"></script>';
  const result = analyzeExchange({ url: `/?value=${encodeURIComponent(markup)}`, responseContentType: "text/html" },
    `<html>${markup}</html>`, {});
  assert.deepEqual(result.reflected.tags, ["xss:reflected-critical"]);
  assert.ok(result.reflected.maxRisk > 0);
  const inert = '<script type="application/json">{"name":"review marker"}</script>';
  assert.deepEqual(analyzeExchange({ url: `/?value=${encodeURIComponent(inert)}`, responseContentType: "text/html" },
    `<html>${inert}</html>`, {}).tags, []);
});

test("candidate storage preserves independent writers and enforces byte, count and idle limits", () => {
  let now = 1000;
  const candidates = new XssCandidateStore({ maxEntries: 2, maxBytes: 1024, maxValueBytes: 32, ttlMs: 100, now: () => now });
  const value = "O'Reilly";
  candidates.observe([{ value }], "/comments", { requestId: "write-a", sessionId: "writer-a" });
  candidates.observe([{ value }], "/comments", { requestId: "write-b", sessionId: "writer-b" });
  assert.equal(candidates.size(), 2);
  assert.deepEqual(new Set(candidates.all().map((entry) => entry.origin.sessionId)), new Set(["writer-a", "writer-b"]));
  for (let i = 0; i < 20; i++) candidates.observe([{ value }], "/comments", { requestId: "write-b", sessionId: "writer-b" });
  assert.equal(candidates.bytes, candidates.all().reduce((total, entry) => {
    const { byteSize, ...serialized } = entry;
    return total + Buffer.byteLength(JSON.stringify(serialized), "utf8");
  }, 0));
  candidates.delete(candidates.all()[0].candidateKey);
  assert.equal(candidates.size(), 1);
  candidates.observe([{ value: "'".repeat(33) }], "/comments");
  assert.equal(candidates.size(), 1);
  for (let i = 0; i < 8; i++) candidates.observe([{ value: `test '${i}'` }], "/comments");
  assert.ok(candidates.size() <= 2);
  assert.ok(candidates.bytes <= 1024);
  now += 101;
  assert.equal(candidates.size(), 0);
  assert.equal(candidates.bytes, 0);
});

test("stored findings update retained writer records while the reader remains unchanged", () => {
  const writer = store.recordRequest("xss-writer", "192.0.2.101", {
    method: "POST", url: "/comments", status: 201, headers: { "user-agent": "writer/1.0" }, authGroupId: "writer-auth",
  });
  const reader = store.recordRequest("xss-reader", "192.0.2.102", {
    method: "GET", url: "/comments", status: 200, headers: { "user-agent": "reader/1.0" },
  });
  const origin = writer.requests[0];
  // Synthetic detector evidence verifies attribution and scoring without executable payloads.
  const finding = { vulnerabilityType: "stored", severity: "critical", riskScore: 100, origin };
  let refreshed = 0;
  const callbacks = {
    attachFinding: store.attachStoredXssFinding,
    refreshOrigin: (identity) => {
      refreshed++;
      assert.equal(identity.sessionId, writer.id);
      store.updateAttackScoreHistory({ sessionId: writer.id, scores: { session: classify(extractFeatures(writer)).attackScore } });
    },
  };
  assert.equal(attributeStoredFindings([finding], callbacks), 1);
  assert.equal(refreshed, 1);
  assert.equal(classify(extractFeatures(writer)).attackScore, 0.15);
  assert.equal(writer.attackHistory.maxAttackScore, 0.15);
  assert.equal(classify(extractFeatures(reader)).attackScore, 0);
  assert.deepEqual(reader.requests[0].xssTags, []);
  for (const entity of [store.getActor(origin.actorId), store.getAuthGroup("writer-auth"), store.getIpEntry(origin.ip)]) {
    assert.deepEqual(entity.requests[0].xssTags, ["xss:stored-critical"]);
  }
  assert.equal(findingSummary([]).maxRisk, 0);
  assert.equal(attributeStoredFindings([{ ...finding, origin: { requestId: "expired", sessionId: "expired" } }], callbacks), 0);
  assert.equal(store.getSession("expired"), undefined);
});
