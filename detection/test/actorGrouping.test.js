const assert = require("node:assert/strict");
const test = require("node:test");

const store = require("../lib/sessionStore");
const { classify } = require("../lib/classifier");
const {
  extractFeatures,
  extractActorFeatures,
  extractResolvedActorFeatures,
} = require("../lib/featureExtractor");

const browserHeaders = {
  "user-agent": "Mozilla/5.0 TestBrowser/1.0",
  accept: "text/html,application/xhtml+xml",
  "accept-language": "ko-KR,ko;q=0.9",
  "accept-encoding": "gzip, deflate, br",
};

const cliHeaders = {
  "user-agent": "curl/8.0",
  accept: "*/*",
};

function record(sessionId, ip, url, headers) {
  return store.recordRequest(sessionId, ip, {
    method: "GET",
    url,
    status: 200,
    headers,
    tags: [],
    authGroupId: null,
  });
}

test("동일 IP에서도 헤더 fingerprint가 다르면 별도 Actor로 분리된다", () => {
  const ip = "::ffff:10.10.0.1";
  const browserSession = record("actor-browser-a", ip, "/browser/a", browserHeaders);
  record("actor-browser-b", ip, "/browser/b", browserHeaders);
  const cliSession = record("actor-cli-a", ip, "/cli/a", cliHeaders);

  const browserActorId = browserSession.actorId;
  const cliActorId = cliSession.actorId;
  assert.notEqual(browserActorId, cliActorId);

  const browserActor = store.getActor(browserActorId);
  const cliActor = store.getActor(cliActorId);
  assert.equal(browserActor.totalRequests, 2);
  assert.equal(browserActor.sessionIds.size, 2);
  assert.equal(cliActor.totalRequests, 1);
  assert.equal(cliActor.sessionIds.size, 1);
});

test("Accept가 자원별로 달라도 V2 Client Profile은 동일 Actor로 묶는다", () => {
  const ip = "::ffff:10.10.0.11";
  const document = record("v2-document", ip, "/", {
    ...browserHeaders,
    accept: "text/html,application/xhtml+xml",
  });
  const api = record("v2-api", ip, "/api/Products/", {
    ...browserHeaders,
    accept: "application/json",
  });

  assert.equal(document.actorId, api.actorId);
  assert.notEqual(document.requests[0].legacyActorId, api.requests[0].legacyActorId);
  assert.equal(store.getActor(document.actorId).totalRequests, 2);
});

test("Session feature는 Actor의 다른 세션 요청을 물려받지 않는다", () => {
  const ip = "::ffff:10.10.0.2";
  const first = record("isolated-session-a", ip, "/one", cliHeaders);
  record("isolated-session-b", ip, "/two", cliHeaders);
  record("isolated-session-b", ip, "/three", cliHeaders);

  const sessionFeatures = extractFeatures(first);
  const actor = store.getActor(first.actorId);
  const actorFeatures = extractActorFeatures(actor, store.getSession);

  assert.equal(sessionFeatures.totalRequests, 1);
  assert.equal(sessionFeatures.client.sessionChurn, 1);
  assert.equal(actorFeatures.totalRequests, 3);
  assert.equal(actorFeatures.client.sessionChurn, 2);
});

test("IP Entry는 Actor를 합쳐 관찰하지만 Session과 Actor 요청 수는 오염시키지 않는다", () => {
  const ip = "::ffff:10.10.0.3";
  const browserSession = record("ip-observe-browser", ip, "/browser", browserHeaders);
  record("ip-observe-cli", ip, "/cli/a", cliHeaders);
  record("ip-observe-cli", ip, "/cli/b", cliHeaders);

  const ipEntry = store.getIpEntry(ip);
  assert.equal(ipEntry.totalRequests, 3);
  assert.equal(ipEntry.sessionIds.size, 2);
  assert.equal(ipEntry.actorIds.size, 2);
  assert.equal(browserSession.requests.length, 1);
  assert.equal(store.getActor(browserSession.actorId).totalRequests, 1);
});

test("IP가 바뀐 고유사도 Candidate는 Client Flow 요청으로 중복 없이 자동 집계된다", () => {
  const headers = {
    "user-agent": "curl/99.42.1",
    accept: "*/*",
    "accept-language": "ko-KR",
    "accept-encoding": "gzip, br",
  };
  const first = record("similarity-integration-a", "203.0.113.81", "/step/one", headers);
  const second = record("similarity-integration-b", "198.51.100.82", "/step/two", headers);
  assert.notEqual(first.actorId, second.actorId);

  const aggregate = store.getClientFlowAggregate(first.actorId);
  assert.equal(aggregate.aggregationEnabled, true);
  assert.equal(aggregate.aggregationPolicy, "FINGERPRINT_CLIENT_FLOW_AUTO");
  assert.equal(aggregate.candidateCount, 2);
  assert.equal(aggregate.totalRequests, 2);
  assert.equal(new Set(aggregate.requests.map((request) => request.requestId)).size, 2);
  assert.equal(extractResolvedActorFeatures(aggregate).totalRequests, 2);
});

test("dlsid와 dcid가 모두 바뀌어도 같은 Candidate의 요청은 하나의 Client Flow로 이어진다", () => {
  const headers = {
    "user-agent": "FlowBrowser/71.3",
    accept: "text/html",
    "accept-language": "ko-KR",
    "accept-encoding": "gzip, br",
  };
  const first = store.recordRequest("client-flow-cookie-a", "203.0.113.171", {
    method: "GET",
    url: "/flow/one",
    status: 200,
    headers,
    tags: [],
    authGroupId: null,
    clientIdentity: {
      valid: true,
      continuityVerified: true,
      source: "verified",
      clientId: "dcid:client-flow-a",
    },
  });
  const second = store.recordRequest("client-flow-cookie-b", "203.0.113.171", {
    method: "GET",
    url: "/flow/two",
    status: 200,
    headers,
    tags: [],
    authGroupId: null,
    clientIdentity: {
      valid: true,
      continuityVerified: true,
      source: "verified",
      clientId: "dcid:client-flow-b",
    },
  });

  assert.equal(first.actorId, second.actorId);
  assert.notEqual(first.resolvedActorId, second.resolvedActorId);
  const flow = store.getClientFlowAggregate(first.actorId);
  assert.equal(flow.flowLinked, true);
  assert.equal(flow.candidateCount, 1);
  assert.equal(flow.sessionCount, 2);
  assert.equal(flow.verifiedClientCount, 2);
  assert.equal(flow.totalRequests, 2);
  assert.deepEqual(flow.conflicts, []);
});

test("분리된 Client Flow가 세션을 공유하면 과거 요청도 병합된 Flow ID로 조회된다", () => {
  const first = record("flow-overlap-a", "203.0.113.251", "/flow/a", {
    "user-agent": "curl/44.0", accept: "*/*",
  });
  const second = record("flow-overlap-b", "198.51.100.252", "/flow/b", {
    "user-agent": "python-requests/44.0", accept: "*/*",
  });
  const firstFlowId = first.requests[0].clientFlowId;
  const secondFlowId = second.requests[0].clientFlowId;
  assert.notEqual(firstFlowId, secondFlowId);
  record("flow-overlap-a", "198.51.100.252", "/flow/c", {
    "user-agent": "python-requests/44.0", accept: "*/*",
  });

  const aggregate = store.getClientFlowAggregate(firstFlowId);
  assert.equal(aggregate.id, store.getClientFlowAggregate(secondFlowId).id);
  assert.equal(aggregate.totalRequests, 3);
  assert.equal(new Set(aggregate.requests.map((request) => request.requestId)).size, 3);
  assert.deepEqual(new Set(aggregate.requests.map((request) => request.clientFlowId)), new Set([aggregate.id]));
  assert.equal(store.getSession("flow-overlap-b").clientFlowId, aggregate.id);
  assert.notEqual(first.actorId, second.actorId);
});

test("동일 세션 쿠키와 curl 지문을 공유해도 signed dcid별 공격 이력은 분리한다", () => {
  const headers = { "user-agent": "curl/77.77", accept: "*/*" };
  const a = store.recordRequest("shared-cookie-two-users", "203.0.113.221", {
    method: "GET", url: "/api/search?probe=1", status: 200, headers,
    tags: ["sqli"], clientIdentity: { valid: true, continuityVerified: true,
      source: "verified", clientId: "dcid:user-a" },
  });
  const first = a.requests.at(-1);
  store.updateAttackScoreHistory({ resolvedActorId: first.resolvedActorId,
    scores: { resolved: 0.9 } });
  const b = store.recordRequest("shared-cookie-two-users", "203.0.113.221", {
    method: "GET", url: "/", status: 200, headers, tags: [],
    clientIdentity: { valid: true, continuityVerified: true,
      source: "verified", clientId: "dcid:user-b" },
  });
  const second = b.requests.at(-1);
  assert.equal(first.actorId, second.actorId);
  assert.notEqual(first.resolvedActorId, second.resolvedActorId);
  const actorA = store.getResolvedActorByClientId("dcid:user-a");
  const actorB = store.getResolvedActorByClientId("dcid:user-b");
  assert.deepEqual(actorA.requests.map((request) => request.requestId), [first.requestId]);
  assert.deepEqual(actorB.requests.map((request) => request.requestId), [second.requestId]);
  assert.equal(actorA.attackHistory.maxAttackScore, 0.9);
  assert.equal(actorB.attackHistory.maxAttackScore, 0);
});

test("Candidate에 분산된 IDOR 흐름은 Client Flow 요청에서 Attack Score를 다시 계산한다", () => {
  const headers = {
    "user-agent": "curl/98.7.1",
    accept: "*/*",
    "accept-language": "ko-KR",
    "accept-encoding": "gzip, br",
  };
  const first = record("similarity-score-a", "203.0.113.91", "/api/orders/1", headers);
  const second = record("similarity-score-b", "198.51.100.92", "/api/orders/2", headers);
  record("similarity-score-b", "198.51.100.92", "/api/orders/3", headers);

  const firstActor = store.getActor(first.actorId);
  const secondActor = store.getActor(second.actorId);
  const aggregate = store.getClientFlowAggregate(first.actorId);
  const candidateMaximum = Math.max(
    classify(extractActorFeatures(firstActor, store.getSession)).attackScore,
    classify(extractActorFeatures(secondActor, store.getSession)).attackScore
  );
  const mergedFeatures = extractResolvedActorFeatures(aggregate);
  const merged = classify(mergedFeatures);
  assert.equal(mergedFeatures.attack.idorWalk.maxDistinctIdsPerResource, 3);
  assert.ok(merged.attackScore > candidateMaximum);
});

test("확장 요청 레코드는 식별자와 operation을 저장하고 민감 헤더를 보존하지 않는다", () => {
  const session = store.recordRequest("extended-record", "127.0.0.44", {
    method: "post",
    url: "/api/Users/123?detail=true",
    status: 401,
    headers: {
      authorization: "Bearer raw-token",
      cookie: "token=raw-token; dcid=raw-client-cookie",
      "x-experiment-run-id": "codex-run-001",
      "user-agent": "curl/8.0",
    },
    authGroupId: "auth:test",
    payloadFingerprint: "payload-hmac",
    hasAuthorization: true,
    experimentRunId: "codex-run-001",
    requestContentType: "application/json",
    requestContentLength: 17,
    requestBodyBytes: 17,
    responseContentType: "application/json; charset=utf-8",
    responseContentLength: 42,
    responseBodyBytes: 42,
    tags: [],
    requestId: "request:trace-example",
    policyDecision: { basis: "prior-completed-requests", source: "confirmed-resolved-actor",
      automationScore: 0.2, attackScore: 0.85, confirmedAttackScore: 0.85,
      riskScore: 0.85, strategies: ["rate_limit_strict", "decoy_maze"] },
    defenseSignal: "rate_limited",
  });

  const request = session.requests[0];
  assert.equal(request.sessionId, "extended-record");
  assert.equal(request.actorId, session.actorId);
  assert.equal(request.authGroupId, "auth:test");
  assert.equal(request.normalizedPath, "/api/Users/:id");
  assert.equal(request.operation, "POST /api/Users/:id");
  assert.equal(request.payloadFingerprint, "payload-hmac");
  assert.equal(request.hasAuthorization, true);
  assert.equal(request.experimentRunId, "codex-run-001");
  assert.equal(request.requestContentType, "application/json");
  assert.equal(request.requestContentLength, 17);
  assert.equal(request.requestBodyBytes, 17);
  assert.equal(request.requestId, "request:trace-example");
  assert.deepEqual(request.policyDecision.strategies, ["rate_limit_strict", "decoy_maze"]);
  assert.equal(request.defenseSignal, "rate_limited");
  store.attachDetectionResult(request, { source: "confirmed-resolved-actor", attackScore: 0.87 });
  assert.equal(store.getActor(session.actorId).requests.at(-1).detectionResult.attackScore, 0.87);
  assert.equal(request.responseContentType, "application/json; charset=utf-8");
  assert.equal(request.responseContentLength, 42);
  assert.equal(request.responseBodyBytes, 42);
  assert.equal(JSON.stringify(session.headerSample).includes("raw-token"), false);
  assert.equal(session.headerSample.cookie, undefined);
  assert.equal(session.headerSample["x-experiment-run-id"], undefined);
});

test("50개가 넘는 정상 요청 뒤에도 lifecycle Attack Feature와 누적 이력이 유지된다", () => {
  const sessionId = "crs-history-survives-window";
  const ip = "127.0.0.77";
  const detectedAt = 1_700_000_000_000;
  const attackDetection = {
    available: true,
    engine: "owasp-modsecurity",
    crsVersion: "4.25.1",
    anomalyScore: 10,
    ruleHitCount: 2,
    categories: ["sqli"],
    hits: [{ ruleId: "942100" }, { ruleId: "942190" }],
  };

  const session = store.recordRequest(sessionId, ip, {
    method: "GET",
    url: "/search?q=attack",
    status: 200,
    headers: cliHeaders,
    tags: ["sqli"],
    authGroupId: "auth:crs-history-test",
    attackDetection,
    ts: detectedAt,
  });
  for (let index = 0; index < 55; index++) {
    record(sessionId, ip, `/clean/${index}`, cliHeaders);
  }

  const features = extractFeatures(session);
  assert.equal(features.attack.sampleSize, 56);
  assert.equal(features.attack.crsRuleHits, 2);
  assert.equal(features.attack.payloadSignatureHits, 1);
  assert.deepEqual(session.attackHistory, {
    hasAttackHistory: true,
    maxAttackScore: 0,
    maxCrsAnomalyScore: 10,
    cumulativeRuleHits: 2,
    matchedRuleIds: ["942100", "942190"],
    attackCategories: ["sqli"],
    firstAttackAt: detectedAt,
    lastAttackAt: detectedAt,
  });

  store.updateAttackScoreHistory({
    sessionId,
    actorId: session.actorId,
    authGroupId: "auth:crs-history-test",
    scores: { session: 0.7, actor: 0.8, authGroup: 0.6 },
  });
  store.updateAttackScoreHistory({
    sessionId,
    actorId: session.actorId,
    authGroupId: "auth:crs-history-test",
    scores: { session: 0.1, actor: 0.2, authGroup: 0.1 },
  });
  assert.equal(session.attackHistory.maxAttackScore, 0.7);
  assert.equal(store.getActor(session.actorId).attackHistory.maxAttackScore, 0.8);
  assert.equal(store.getActor(session.actorId).attackHistory.cumulativeRuleHits, 2);
  assert.equal(store.getAuthGroup("auth:crs-history-test").attackHistory.maxAttackScore, 0.6);
  assert.equal(store.getAuthGroup("auth:crs-history-test").attackHistory.cumulativeRuleHits, 2);
});
