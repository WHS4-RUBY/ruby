const assert = require("node:assert/strict");
const test = require("node:test");

const { extractStreamFeatures } = require("../lib/featureExtractor");
const { classify, AUTOMATION_WEIGHTS, ATTACK_WEIGHTS } = require("../lib/classifier");
const { loadPolicyRules, selectRule, selectStrategies } = require("../lib/policyEngine");
const { classifyBackgroundTraffic } = require("../lib/backgroundTraffic");

const telemetry = {
  mouseMoveCount: 0,
  scrollCount: 0,
  routeChangeCount: 0,
  domEventTypes: new Set(),
  pageLoads: 0,
  currentUrl: null,
  lastTelemetryAt: null,
};

function buildFeatures(tags = []) {
  const requests = Array.from({ length: 60 }, (_, index) => ({
    ts: index * 100,
    method: "GET",
    url: `/api/Users/${index}?q=${index}`,
    normalizedPath: "/api/Users/:id",
    operation: "GET /api/Users/:id",
    status: index >= 50 && index < 55 ? 404 : 200,
    tags,
    experimentRunId: null,
  }));
  return extractStreamFeatures({
    requests,
    headerSample: { "user-agent": "curl/8.0" },
    fingerprint: "test",
    userAgent: "curl/8.0",
    telemetry,
    firstSeen: 0,
    lastSeen: 5_900,
    sessionChurn: 1,
  });
}

test("Feature window와 normalized operation 기반 Behavior 값을 적용한다", () => {
  const features = buildFeatures();
  assert.equal(features.temporal.timingSampleSize, 50);
  assert.equal(features.behavior.recentSequence.length, 10);
  assert.equal(features.behavior.repeatSampleSize, 20);
  assert.equal(features.behavior.pathDiversity, 1 / 50);
  assert.equal(features.exploration.sampleSize, 50);
  assert.equal(features.exploration.notFoundCount, 5);
});

test("Payload Signature는 Attack Score만 올리고 Automation Score에는 영향을 주지 않는다", () => {
  const clean = classify(buildFeatures());
  const attack = classify(buildFeatures(["sqli"]));
  assert.equal(clean.automationScore, attack.automationScore);
  assert.ok(attack.attackScore > clean.attackScore);
  assert.equal(attack.score, undefined);
  assert.equal(attack.label, undefined);
  assert.deepEqual(Object.keys(AUTOMATION_WEIGHTS), Object.keys(attack.automationBreakdown));
  assert.deepEqual(Object.keys(ATTACK_WEIGHTS), Object.keys(attack.attackBreakdown));
});

test("표시 배점은 정규화 값이 아닌 최종 점수 기여분이며 허니 상한과 가산점을 구분한다", () => {
  const features = buildFeatures(["sqli"]);
  features.deception = {
    distinctSignals: ["trap_trigger", "no_asset_loading", "watermark_reuse", "writable_file_write"],
    coverageEligible: true,
    recentUniqueApiPaths: 20,
  };
  features.attack.repeatedEvidence = { count: 8 };
  const result = classify(features);
  assert.equal(result.automationBreakdown.headerAnomaly, 1);
  assert.equal(result.automationPointBreakdown.headerAnomaly, 15);
  assert.equal(result.automationPointBreakdown.automationHoney, 35);
  assert.equal(result.honeyBreakdown.attack.totalPoints, 35);
  assert.equal(result.attackPointBreakdown.attackHoney, 17);
  assert.equal(result.attackPointBreakdown.repeatedEvidenceBonus, 10);
  assert.equal(result.attackEvidenceBonus, 0.1);
  assert.equal(result.scoreMaximumPoints.attack.attackHoney, 17);
  assert.equal(result.scoreMaximumPoints.automation.headerAnomaly, 15);
  const automationTotal = Object.values(result.automationPointBreakdown).reduce((a, b) => a + b, 0);
  const attackTotal = Object.values(result.attackPointBreakdown).reduce((a, b) => a + b, 0);
  assert.ok(Math.abs(automationTotal - result.automationScore * 100) <= 0.1);
  assert.ok(Math.abs(Math.min(100, attackTotal) - result.attackScore * 100) <= 0.1);
});

test("신규 Attack 서브스코어 4개를 독립적으로 계산한다", () => {
  const requests = Array.from({ length: 10 }, (_, index) => ({
    ts: index * 100,
    method: "POST",
    url: `/api/Users/${index + 1}`,
    normalizedPath: "/rest/user/login",
    operation: "POST /rest/user/login",
    status: 401,
    tags: [],
    blTags: index === 0 ? ["mass-assignment"] : [],
    csrfTags: index === 0 ? ["csrf:missing-origin"] : [],
    loginAttemptEmail: "target@example.test",
  }));
  const features = extractStreamFeatures({
    requests,
    headerSample: { "user-agent": "curl/8.0" },
    fingerprint: "new-attack-subscores",
    userAgent: "curl/8.0",
    telemetry,
    firstSeen: 0,
    lastSeen: 900,
    sessionChurn: 1,
  });
  const result = classify(features);
  assert.equal(features.attack.idorWalk.maxDistinctIdsPerResource, 10);
  assert.equal(features.attack.loginBruteForce.maxAttemptsPerEmail, 10);
  assert.equal(result.attackBreakdown.idorWalk, 1);
  assert.equal(result.attackBreakdown.loginBruteForce, 1);
  assert.equal(result.attackBreakdown.businessLogicViolation, 0.7);
  assert.equal(result.attackBreakdown.csrf, 0.7);
});

test("Automation과 Attack 가중치는 각각 100%이고 XSS 가중치는 15%다", () => {
  const sum = (weights) => Object.values(weights).reduce((total, value) => total + value, 0);
  assert.equal(Number(sum(AUTOMATION_WEIGHTS).toFixed(3)), 1);
  assert.equal(Number(sum(ATTACK_WEIGHTS).toFixed(3)), 1);
  assert.equal(AUTOMATION_WEIGHTS.automationHoney, 0.35);
  assert.equal(ATTACK_WEIGHTS.attackHoney, 0.17);
  assert.equal(ATTACK_WEIGHTS.reflectedXss, 0.15);
  assert.equal(ATTACK_WEIGHTS.payloadSignature, 0.2);
});

test("60분 내 근거 있는 반복 공격만 4/8/16/32/64건 구간별로 최대 30점 가점한다", () => {
  const build = (count, fields) => extractStreamFeatures({
    requests: Array.from({ length: count }, (_, index) => ({
      ts: index * 1000, method: "GET", url: `/search?q=${index}`,
      normalizedPath: "/search", operation: "GET /search", status: 200,
      ...fields,
    })),
    headerSample: { "user-agent": "curl/8.0" }, fingerprint: "repeat-test",
    userAgent: "curl/8.0", telemetry, firstSeen: 0, lastSeen: count * 1000,
    sessionChurn: 1,
  });
  for (const [count, bonus] of [
    [1, 0], [2, 0], [3, 0], [4, 0.05], [7, 0.05], [8, 0.1],
    [15, 0.1], [16, 0.15], [31, 0.15], [32, 0.2],
    [63, 0.2], [64, 0.3], [128, 0.3],
  ]) {
    assert.equal(classify(build(count, { tags: ["sqli"] })).attackEvidenceBonus, bonus);
  }
  assert.equal(classify(build(32, { tags: [], csrfTags: ["csrf:missing-origin"] })).attackEvidenceBonus, 0);
  assert.equal(classify(build(32, { tags: ["idor-probe"] })).attackEvidenceBonus, 0);
  for (const blTags of [
    ["role-gated:admin-config"], ["role-gated:admin-version"],
    ["role-gated:learned"], ["role-gated:admin-config", "role-gated:admin-version"],
  ]) {
    const features = build(64, { tags: [], blTags });
    assert.equal(features.attack.businessLogicHits, 64 * blTags.length);
    assert.equal(features.attack.repeatedEvidence.count, 0);
    assert.equal(classify(features).attackEvidenceBonus, 0);
    assert.ok(classify(features).attackBreakdown.businessLogicViolation > 0);
  }
  for (const fields of [
    { tags: ["sqli"], blTags: ["role-gated:admin-config"] },
    { tags: [], blTags: ["role-gated:admin-config", "mass-assignment"] },
    { tags: [], blTags: ["role-gated:admin-config"], attackDetection: { available: true, anomalyScore: 5 } },
  ]) {
    const features = build(64, fields);
    assert.equal(features.attack.repeatedEvidence.count, 64);
    assert.equal(classify(features).attackEvidenceBonus, 0.3);
  }
  const expired = build(4, { tags: ["sqli"] });
  expired.attack.repeatedEvidence.count = 0;
  assert.equal(classify(expired).attackEvidenceBonus, 0);
});

test("64건 반복 공격 + 독립 증거가 실제 0.8 정책 구간에 도달한다", () => {
  const requests = Array.from({ length: 64 }, (_, index) => ({
    ts: index * 1000, method: "GET", url: `/api/orders/${index + 1}`,
    normalizedPath: "/api/orders/:id", operation: "GET /api/orders/:id", status: 404,
    tags: ["sqli", "xss", "command-injection", "nosql-injection"],
    blTags: ["mass-assignment", "numeric-abuse", "role-gated:admin"],
    xssTags: ["xss:reflected-critical"], xssMaxRisk: 100,
  }));
  const features = extractStreamFeatures({ requests,
    headerSample: { "user-agent": "curl/8.0" }, fingerprint: "high-attack-test",
    userAgent: "curl/8.0", telemetry, firstSeen: 0, lastSeen: 63_000, sessionChurn: 1 });
  const result = classify(features);
  assert.equal(result.attackEvidenceBonus, 0.3);
  const score = result.attackScore;
  assert.ok(score >= 0.8);
  const plan = selectStrategies(score, loadPolicyRules(), { confirmedAttackScore: score });
  assert.deepEqual(plan.map((step) => step.name), score >= 0.95
    ? ["rate_limit_strict", "account_overlay_high"]
    : ["rate_limit_strict", "decoy_maze"]);
});

test("Automation Honey는 trap, no-asset, 조건부 coverage를 합쳐 최대 35점을 반영한다", () => {
  const cleanFeatures = buildFeatures();
  const honeyFeatures = buildFeatures();
  honeyFeatures.deception = {
    distinctSignals: ["trap_trigger", "no_asset_loading", "coverage"],
    signalCounts: { trap_trigger: 4, no_asset_loading: 1, coverage: 3 },
    recentUniqueApiPaths: 20,
    coverageEligible: true,
  };
  const clean = classify(cleanFeatures);
  const honey = classify(honeyFeatures);

  assert.equal(honey.honeyBreakdown.automation.totalPoints, 35);
  assert.equal(honey.automationBreakdown.automationHoney, 1);
  assert.equal(honey.attackBreakdown.attackHoney, 0);
  assert.equal(Number((honey.automationScore - clean.automationScore).toFixed(3)), 0.35);
  assert.equal(honey.attackScore, clean.attackScore);
});

test("coverage는 조건이 충족되지 않으면 Automation Honey에 반영하지 않는다", () => {
  const features = buildFeatures();
  features.deception = {
    distinctSignals: ["coverage"],
    signalCounts: { coverage: 4 },
    recentUniqueApiPaths: 25,
    coverageEligible: false,
  };
  const verdict = classify(features);
  assert.equal(verdict.honeyBreakdown.automation.contributions.coverage, 0);
  assert.equal(verdict.automationBreakdown.automationHoney, 0);
});

test("Attack Honey는 고유 신호만 합산하고 최대 35점으로 제한한다", () => {
  const cleanFeatures = buildFeatures();
  const honeyFeatures = buildFeatures();
  honeyFeatures.deception = {
    distinctSignals: ["watermark_reuse", "writable_file_write", "ssh_cred_reuse"],
    signalCounts: { watermark_reuse: 5, writable_file_write: 2, ssh_cred_reuse: 3 },
    recentUniqueApiPaths: 1,
    coverageEligible: true,
  };
  const clean = classify(cleanFeatures);
  const honey = classify(honeyFeatures);

  assert.equal(honey.honeyBreakdown.attack.rawPoints, 52);
  assert.equal(honey.honeyBreakdown.attack.totalPoints, 35);
  assert.equal(honey.attackBreakdown.attackHoney, 1);
  assert.equal(honey.automationBreakdown.automationHoney, 0);
  assert.ok(honey.attackScore > clean.attackScore);
  assert.equal(honey.automationScore, clean.automationScore);
});

test("Socket.IO polling은 Automation 행동 Feature를 바꾸지 않고 원본·Attack 관찰에는 남는다", () => {
  const meaningful = [0, 1, 2, 3, 4].map((index) => ({
    ts: index * 1_000,
    method: "GET",
    url: `/api/Products/${index}`,
    normalizedPath: "/api/Products/:id",
    operation: "GET /api/Products/:id",
    status: 200,
    tags: [],
    experimentRunId: null,
  }));
  const socketRequests = Array.from({ length: 60 }, (_, index) => ({
    ts: 4_100 + index * 100,
    method: index % 2 ? "POST" : "GET",
    url: `/socket.io/?EIO=4&transport=polling&t=${index}&sid=test-socket`,
    normalizedPath: "/socket.io/",
    operation: `${index % 2 ? "POST" : "GET"} /socket.io/`,
    status: 200,
    tags: index === 59 ? ["xss"] : [],
    attackDetection: index === 59
      ? { available: true, anomalyScore: 5, ruleHitCount: 1, hits: [{ ruleId: "941100" }] }
      : { available: true, anomalyScore: 0, ruleHitCount: 0, hits: [] },
    backgroundTraffic: classifyBackgroundTraffic(
      `/socket.io/?EIO=4&transport=polling&t=${index}&sid=test-socket`
    ),
    experimentRunId: null,
  }));
  const options = {
    headerSample: { "user-agent": "Mozilla/5.0" },
    fingerprint: "browser",
    userAgent: "Mozilla/5.0",
    telemetry,
    firstSeen: 0,
    lastSeen: 10_000,
    sessionChurn: 1,
  };
  const baseline = extractStreamFeatures({ ...options, requests: meaningful });
  const withPolling = extractStreamFeatures({ ...options, requests: [...meaningful, ...socketRequests] });

  assert.equal(withPolling.totalRequests, 65);
  assert.equal(withPolling.behaviorAnalyzedRequests, 5);
  assert.equal(withPolling.backgroundRequests, 60);
  assert.deepEqual(withPolling.requestAccounting.backgroundByCategory, { socket_io_polling: 60 });
  assert.deepEqual(withPolling.temporal, baseline.temporal);
  assert.deepEqual(withPolling.behavior, baseline.behavior);
  assert.deepEqual(withPolling.exploration, baseline.exploration);
  assert.equal(classify(withPolling).automationScore, classify(baseline).automationScore);
  assert.equal(withPolling.attack.payloadSignatureHits, 1);
  assert.equal(withPolling.attack.crsRuleHits, 1);
  assert.deepEqual(withPolling.attack.matchedRuleIds, ["941100"]);
});

test("단일 신호로는 0.8에 못 미치고, 인젝션·XSS·경로 탐색·미끼를 합쳐야 방어 단계에 닿는다", () => {
  const telemetryless = {
    mouseMoveCount: 0, scrollCount: 0, routeChangeCount: 0,
    domEventTypes: new Set(), pageLoads: 0, currentUrl: null, lastTelemetryAt: null,
  };
  const build = ({ tags = [], xss = false, deceptionHistory = null }) => {
    const requests = Array.from({ length: 64 }, (_, index) => ({
      ts: index * 1000, method: "GET", url: `/api/target/${index}`,
      normalizedPath: "/api/target/:id", operation: "GET /api/target/:id", status: 404,
      tags, blTags: [],
      xssTags: xss ? ["xss:reflected-critical"] : [], xssMaxRisk: xss ? 100 : 0,
    }));
    return classify(extractStreamFeatures({ requests, headerSample: { "user-agent": "curl/8.0" },
      fingerprint: "combined-signal", userAgent: "curl/8.0", telemetry: telemetryless,
      firstSeen: 0, lastSeen: 63_000, sessionChurn: 1, deceptionHistory }));
  };
  const honey = {
    distinctSignals: ["watermark_reuse", "trap_trigger", "script_hint_access", "no_asset_loading"],
    signalCounts: { watermark_reuse: 2, trap_trigger: 3, script_hint_access: 1, no_asset_loading: 1 },
    recentUniqueApiPaths: 20, coverageEligible: true,
  };
  const rules = loadPolicyRules();
  const tierFor = (score, { confirmed = 0 } = {}) =>
    selectRule(score, rules, { confirmedAttackScore: confirmed })?.tier ?? null;

  const injectionOnly = build({ tags: ["sqli"] });
  assert.ok(injectionOnly.attackScore < 0.8);
  assert.equal(tierFor(injectionOnly.attackScore), null);

  const payloadsOnly = build({ tags: ["sqli", "path-traversal", "command-injection"], xss: true });
  assert.ok(payloadsOnly.attackScore > injectionOnly.attackScore);
  assert.ok(payloadsOnly.attackScore < 0.8, "서명 기반 신호만으로는 방어 경계에 닿지 않는다");

  const withHoney = build({ tags: ["sqli", "path-traversal", "command-injection"], xss: true,
    deceptionHistory: honey });
  assert.ok(withHoney.attackScore >= 0.8, `combined attack score=${withHoney.attackScore}`);

  // 같은 점수라도 확정 공격 점수(검증된 DCID의 Resolved Actor)가 있어야 429 단계에 닿는다.
  assert.equal(tierFor(withHoney.attackScore), "suspected");
  assert.deepEqual(selectStrategies(withHoney.attackScore, rules).map((step) => step.name),
    ["decoy_maze"]);
  assert.equal(tierFor(withHoney.attackScore, { confirmed: withHoney.attackScore }), "confirmed");
  assert.deepEqual(
    selectStrategies(withHoney.attackScore, rules, { confirmedAttackScore: withHoney.attackScore })
      .map((step) => step.name),
    ["rate_limit_strict", "decoy_maze"]);
});

// 기존 buildFeatures 에 미끼 신호만 얹는다. coverage 는 조건을 끄고 자동화 쪽 신호가
// 섞이지 않게 해 공격 허니 기여분만 본다.
function withDeception(distinctSignals) {
  const features = buildFeatures();
  features.deception = {
    distinctSignals,
    signalCounts: Object.fromEntries(distinctSignals.map((signal) => [signal, 1])),
    recentUniqueApiPaths: 0,
    coverageEligible: false,
  };
  return features;
}

test("미끼 경로 적중은 공격 허니에 8점을 더하고 허니 상한은 그대로다", () => {
  const { ATTACK_HONEY_POINTS, ATTACK_HONEY_MAX_POINTS } = require("../lib/classifier");
  assert.equal(ATTACK_HONEY_POINTS.decoy_path_hit, 8);
  assert.equal(ATTACK_HONEY_MAX_POINTS, 35);

  const clean = classify(withDeception([]));
  const hit = classify(withDeception(["decoy_path_hit"]));
  assert.equal(hit.honeyBreakdown.attack.contributions.decoy_path_hit, 8);
  assert.equal(clean.honeyBreakdown.attack.contributions.decoy_path_hit, 0);
  assert.equal(hit.honeyBreakdown.attack.totalPoints, 8);
  // 허니가 공격 점수에 더할 수 있는 최대치(0.17)는 바뀌지 않는다.
  assert.equal(hit.scoreMaximumPoints.attack.attackHoney, 17);
  assert.equal(Number((hit.attackScore - clean.attackScore).toFixed(3)),
    Number((8 / 35 * 0.17).toFixed(3)));
  // 자동화 점수는 움직이지 않는다.
  assert.equal(hit.automationScore, clean.automationScore);
});

test("미끼 배점은 policy.json 의 detection.deception.points 로 조정된다", () => {
  const classifier = require("../lib/classifier");
  try {
    classifier.configure({ honey: { attackPoints: { decoy_path_hit: 0 } } });
    const muted = classify(withDeception(["decoy_path_hit"]));
    assert.equal(muted.honeyBreakdown.attack.contributions.decoy_path_hit, 0);
    // 표는 신호 단위로 병합되므로 다른 신호의 배점은 남아 있다.
    assert.equal(muted.honeyBreakdown.attack.contributions.watermark_reuse, 0);
    const other = classify(withDeception(["watermark_reuse"]));
    assert.equal(other.honeyBreakdown.attack.contributions.watermark_reuse, 20);
  } finally {
    classifier.configure();
  }
  const restored = classify(withDeception(["decoy_path_hit"]));
  assert.equal(restored.honeyBreakdown.attack.contributions.decoy_path_hit, 8);
});
