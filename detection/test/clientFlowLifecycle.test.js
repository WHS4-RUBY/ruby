const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const store = require("../lib/sessionStore");
const { checkCsrf } = require("../lib/csrfDetection");
const { classify } = require("../lib/classifier");
const { extractActorFeatures, extractResolvedActorFeatures } = require("../lib/featureExtractor");
const { assessDetection } = require("../lib/riskPolicy");
const { selectEffectiveDetection } = require("../lib/detectionPolicy");
const { buildPolicyDecision } = require("../lib/rubyPolicy");

test("정상 CLI POST 32건은 Origin 부재 태그가 있어도 반복 공격 가산을 받지 않는다", (t) => {
  const now = 1_700_000_000_000;
  t.mock.method(Date, "now", () => now);
  let session;
  for (let index = 0; index < 32; index++) {
    const csrfTags = checkCsrf({ method: "POST", normalizedPath: "/rest/user/login" }, ["http://example.test"])
      .map((hit) => hit.tag);
    session = store.recordRequest("normal-cli-post", "203.0.113.90", {
      method: "POST", url: "/rest/user/login", status: 200,
      headers: { "user-agent": "curl/90.0.0" },
      tags: [], blTags: [], csrfTags, ts: now + index,
    });
  }
  const id = session.requests.at(-1).clientFlowId;
  const aggregate = store.getClientFlowAggregate(id);
  assert.deepEqual(aggregate.attackRepetition, { qualifyingRequests: 0, bonusPoints: 0, windowMs: 3_600_000 });
  assert.equal(aggregate.scoringApplied, false);
  assert.equal(store.getClientFlowPolicyState(id).scoringApplied, false);
  assert.equal(classify(extractResolvedActorFeatures(aggregate)).attackScore, 0.063);
});

test("반복 가산 만료 후에도 활성 Flow의 최고 공격 점수와 정책 출처를 유지한다", (t) => {
  let now = 1_700_000_000_000;
  t.mock.method(Date, "now", () => now);
  const record = (tags = []) => store.recordRequest("flow-attack-history", "203.0.113.91", {
    method: "GET", url: "/api/test", status: 200,
    headers: { "user-agent": "curl/91.0.0" }, tags, ts: now,
  });
  let session;
  for (let index = 0; index < 32; index++) session = record(["sqli"]);
  const { actorId, clientFlowId } = session.requests.at(-1);
  const before = store.getClientFlowAggregate(clientFlowId);
  const base = classify(extractResolvedActorFeatures(before)).attackScore;
  const peak = Math.min(1, base + before.attackRepetition.bonusPoints / 100);
  assert.equal(peak, 0.71);
  store.updateAttackScoreHistory({
    sessionId: session.id, actorId, clientFlowId,
    scores: { session: base, actor: base, clientFlow: peak },
  });
  now += 30 * 60_000;
  record();
  now += 31 * 60_000;
  record();
  const state = store.getClientFlowPolicyState(actorId);
  const aggregate = store.getClientFlowAggregate(clientFlowId);
  assert.equal(state.attackRepetition.bonusPoints, 0);
  assert.equal(state.scoringApplied, true);
  assert.equal(aggregate.scoringApplied, true);
  assert.equal(aggregate.attackHistory.maxAttackScore, peak);
  assert.ok(store.getAllClientFlowAggregates().some((flow) => flow.id === clientFlowId));
  const actor = store.getActor(actorId);
  const candidate = classify(extractActorFeatures(actor, store.getSession));
  const current = classify(extractResolvedActorFeatures(aggregate));
  const flowAnalysis = {
    ...current,
    detection: assessDetection({ ...current, maxAttackScore: aggregate.attackHistory.maxAttackScore }),
    features: extractResolvedActorFeatures(aggregate),
  };
  assert.equal(current.attackScore, 0.21);
  assert.equal(flowAnalysis.detection.attackDetected, true);
  const [source, analysis] = selectEffectiveDetection({ candidate, clientFlow: flowAnalysis });
  assert.equal(source, "fingerprint-client-flow");
  assert.equal(buildPolicyDecision({ source, analysis, clientId: clientFlowId }).riskScore, peak);
  const html = fs.readFileSync(path.join(__dirname, "..", "public", "dashboard.html"), "utf8");
  const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  const context = {
    localStorage: { getItem() { return null; } },
    document: {
      getElementById() { return { addEventListener() {} }; },
      addEventListener() {}, querySelectorAll() { return []; },
    },
  };
  vm.createContext(context);
  vm.runInContext(script.slice(0, script.lastIndexOf("initializeTheme();")), context);
  const rows = context.buildUserRows([], [{ ...actor, actorId }], [{
    ...aggregate, ...current, clientFlowId,
  }]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].kind, "client-flows");
  assert.equal(context.detectionFor(rows[0]).maxAttackScore, 71);
  assert.match(context.attackHistoryCell(rows[0].attackHistory), /최고 71/);
  now += 61 * 60_000;
  assert.equal(store.getClientFlowPolicyState(clientFlowId), null);
  store.pruneExpiredClientFlows();
  assert.equal(store.getClientFlowAggregate(clientFlowId), null);
});
