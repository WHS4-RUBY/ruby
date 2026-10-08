const test = require("node:test");
const assert = require("node:assert/strict");
const { createRunScopedPolicyAnalyzer } = require("../lib/runScopedPolicy");
const { buildHttpFingerprint } = require("../lib/httpFingerprint");

const RUN_A = "11111111-1111-4111-8111-111111111111";
const RUN_B = "22222222-2222-4222-8222-222222222222";

function request({ runId, targetId = "ruby-shop", ts, sessionId = "session-a",
  ip = "203.0.113.10", attack = false, deceptionEvents = [] }) {
  return {
    requestId: `request:${targetId}:${runId}:${ts}`,
    targetId, targetRunId: runId, ts, sessionId, ip,
    method: "GET", url: `/api/products/${ts}`, normalizedPath: "/api/products/:id",
    operation: "GET /api/products/:id", status: attack ? 404 : 200,
    tags: attack ? ["sqli", "path-traversal", "command-injection"] : [],
    blTags: [], csrfTags: [], xssTags: [], deceptionEvents,
    attackDetection: attack
      ? { available: true, anomalyScore: 20, ruleHitCount: 1, hits: [{ ruleId: "942100" }] }
      : { available: true, anomalyScore: 0, ruleHitCount: 0, hits: [] },
  };
}

test("Candidate policy excludes the previous run's payload and deception evidence", () => {
  const analyzer = createRunScopedPolicyAnalyzer();
  const oldAttack = request({ runId: RUN_A, ts: 1000, attack: true,
    deceptionEvents: [{ signal: "writable_file_write" }] });
  const current = request({ runId: RUN_B, ts: 2000, sessionId: "session-b" });
  const actor = {
    id: "actor:one", requests: [oldAttack, current],
    sessionIds: new Set(["session-a", "session-b"]),
    headerSample: { "user-agent": "curl/8.0" }, userAgent: "curl/8.0",
    attackHistory: { maxAttackScore: 1 },
    deceptionHistory: { distinctSignals: ["writable_file_write"] },
  };
  const old = analyzer.analyze({ source: "candidate", entity: actor,
    targetId: "ruby-shop", runId: RUN_A });
  const next = analyzer.analyze({ source: "candidate", entity: actor,
    targetId: "ruby-shop", runId: RUN_B });

  assert.ok(old.attackScore > 0.2);
  assert.equal(next.features.totalRequests, 1);
  assert.equal(next.features.attack.payloadSignatureHits, 0);
  assert.deepEqual(next.features.deception.distinctSignals, []);
  assert.equal(next.attackScore, 0);
  assert.equal(next.detection.effectiveAttackScore, 0);
  assert.equal(next.features.client.sessionChurn, 1);
  assert.deepEqual(next.observedIps, ["203.0.113.10"]);
  assert.equal(actor.attackHistory.maxAttackScore, 1, "global dashboard history is untouched");
});

test("Client Flow and resolved actor classify only matching run requests", () => {
  const analyzer = createRunScopedPolicyAnalyzer();
  const previous = request({ runId: RUN_A, ts: 1000, sessionId: "previous", attack: true,
    deceptionEvents: [{ signal: "ssh_cred_reuse" }] });
  const current = request({ runId: RUN_B, ts: 2000, sessionId: "current", ip: "203.0.113.20" });
  const aggregate = {
    id: "client-flow:one", requests: [previous, current],
    sessionIds: ["previous", "current"],
    memberSessions: [
      { id: "previous", lastSeen: 1000, headerSample: { "user-agent": "old" }, userAgent: "old" },
      { id: "current", lastSeen: 2000, headerSample: { "user-agent": "new" }, userAgent: "new" },
    ],
    attackHistory: { maxAttackScore: 0.99 },
  };
  for (const source of ["clientFlow", "resolved"]) {
    const analysis = analyzer.analyze({ source, entity: aggregate,
      targetId: "ruby-shop", runId: RUN_B });
    assert.equal(analysis.features.totalRequests, 1);
    assert.equal(analysis.features.attack.repeatedEvidence.count, 0);
    assert.deepEqual(analysis.features.deception.distinctSignals, []);
    assert.equal(analysis.features.client.sessionChurn, 1);
    assert.equal(analysis.detection.effectiveAttackScore, 0);
    assert.deepEqual(analysis.observedIps, ["203.0.113.20"]);
  }
});

test("a reused session derives header evidence from the active run", () => {
  const analyzer = createRunScopedPolicyAnalyzer();
  const old = request({ runId: RUN_A, ts: 1000 });
  old.httpFingerprint = buildHttpFingerprint({ headers: { "user-agent": "curl/8.0" } });
  const current = request({ runId: RUN_B, ts: 2000 });
  current.httpFingerprint = buildHttpFingerprint({ headers: {
    "user-agent": "Mozilla/5.0 Browser", "accept-language": "ko-KR",
    "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document",
  } });
  const session = {
    id: "session-a", requests: [old, current],
    headerSample: { "user-agent": "curl/8.0" }, userAgent: "curl/8.0",
  };
  const result = analyzer.analyze({ source: "session", entity: session,
    targetId: "ruby-shop", runId: RUN_B });
  assert.equal(result.features.client.automationUA, false);
  assert.equal(result.features.client.missingHeaderCount, 0);
  assert.equal(result.features.client.browserInteraction.hasTelemetry, false,
    "global session telemetry is never borrowed across runs");
});

test("run-specific historical maximum survives request retention but expires with the cache", () => {
  let clock = 1000;
  const analyzer = createRunScopedPolicyAnalyzer({ now: () => clock,
    maxEntries: 2, idleTtlMs: 100 });
  const actor = { id: "actor:peak", requests: [request({ runId: RUN_A, ts: 1, attack: true })],
    headerSample: null, userAgent: "" };
  const options = { source: "candidate", entity: actor, targetId: "ruby-shop", runId: RUN_A };
  const peak = analyzer.analyze(options);
  assert.ok(peak.attackScore > 0);
  actor.requests = [request({ runId: RUN_A, ts: 2 })];
  clock += 10;
  const retained = analyzer.analyze(options);
  assert.equal(retained.attackScore, 0);
  assert.equal(retained.detection.effectiveAttackScore, peak.attackScore);
  clock += 101;
  const expired = analyzer.analyze(options);
  assert.equal(expired.detection.effectiveAttackScore, 0);

  actor.requests = [request({ runId: RUN_B, ts: 3 })];
  analyzer.analyze({ ...options, runId: RUN_B });
  analyzer.analyze({ ...options, targetId: "juice-shop", entity: {
    ...actor, requests: [request({ runId: RUN_B, targetId: "juice-shop", ts: 4 })],
  }, runId: RUN_B });
  assert.equal(analyzer.cacheSize(), 2, "LRU cache stays bounded");
  analyzer.clear();
  assert.equal(analyzer.cacheSize(), 0);
});

test("a missing run or target never falls back to global request history", () => {
  const analyzer = createRunScopedPolicyAnalyzer();
  const actor = { id: "actor:one", requests: [request({ runId: RUN_A, ts: 1 })] };
  assert.equal(analyzer.analyze({ source: "candidate", entity: actor,
    targetId: "ruby-shop", runId: RUN_B }), null);
  assert.throws(() => analyzer.analyze({ source: "candidate", entity: actor,
    targetId: "ruby-shop" }), /targetId and runId/);
});
