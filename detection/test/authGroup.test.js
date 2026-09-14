const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");

const { deriveAuthGroupId } = require("../lib/authGroup");
const { classify } = require("../lib/classifier");
const { extractAuthGroupFeatures } = require("../lib/featureExtractor");
const store = require("../lib/sessionStore");

test("Bearer token은 전체 SHA-256 hash Auth Group ID로 변환된다", () => {
  const token = "header.payload.signature";
  const expected = `auth:${crypto.createHash("sha256").update(token).digest("hex")}`;

  assert.equal(deriveAuthGroupId(`Bearer ${token}`), expected);
  assert.equal(deriveAuthGroupId(`bearer ${token}`), expected);
  assert.equal(deriveAuthGroupId(undefined), null);
  assert.equal(deriveAuthGroupId("Basic abc"), null);
  assert.equal(deriveAuthGroupId("Bearer"), null);
});

test("같은 token은 여러 session에서 한 Auth Group으로 집계된다", () => {
  const token = "same-token-for-independent-sessions";
  const authGroupId = deriveAuthGroupId(`Bearer ${token}`);

  for (const sessionId of ["test-session-a", "test-session-b", "test-session-c"]) {
    store.recordRequest(sessionId, "127.0.0.1", {
      method: "GET",
      url: "/api/Users/",
      status: 200,
      headers: { authorization: `Bearer ${token}`, "user-agent": "test" },
      tags: [],
      authGroupId,
    });
  }

  const group = store.getAuthGroup(authGroupId);
  assert.equal(group.totalRequests, 3);
  assert.deepEqual([...group.sessionIds], [
    "test-session-a",
    "test-session-b",
    "test-session-c",
  ]);
  assert.equal(group.requests.length, 3);
  assert.ok(group.requests.every((request) => request.authGroupId === authGroupId));
});

test("다른 token은 분리되고 Authorization 없는 요청은 그룹에 추가되지 않는다", () => {
  const authGroupA = deriveAuthGroupId("Bearer token-a");
  const authGroupB = deriveAuthGroupId("Bearer token-b");
  assert.notEqual(authGroupA, authGroupB);

  store.recordRequest("mixed-session", "127.0.0.2", {
    method: "GET",
    url: "/a",
    status: 200,
    headers: { authorization: "Bearer token-a", "user-agent": "test" },
    tags: [],
    authGroupId: authGroupA,
  });
  store.recordRequest("mixed-session", "127.0.0.2", {
    method: "GET",
    url: "/b",
    status: 200,
    headers: { authorization: "Bearer token-b", "user-agent": "test" },
    tags: [],
    authGroupId: authGroupB,
  });
  store.recordRequest("anonymous-session", "127.0.0.2", {
    method: "GET",
    url: "/anonymous",
    status: 200,
    headers: { "user-agent": "test" },
    tags: [],
    authGroupId: null,
  });

  assert.equal(store.getAuthGroup(authGroupA).totalRequests, 1);
  assert.equal(store.getAuthGroup(authGroupB).totalRequests, 1);
  assert.equal(store.getSession("anonymous-session").requests[0].authGroupId, null);
});

test("raw Authorization 값은 저장 데이터에 남지 않는다", () => {
  const rawToken = "raw-token-must-not-be-stored";
  const authGroupId = deriveAuthGroupId(`Bearer ${rawToken}`);
  store.recordRequest("redaction-session", "127.0.0.3", {
    method: "GET",
    url: "/private",
    status: 200,
    headers: {
      authorization: `Bearer ${rawToken}`,
      "proxy-authorization": `Bearer ${rawToken}`,
      "user-agent": "test",
    },
    tags: [],
    authGroupId,
  });

  const serialized = JSON.stringify({
    session: store.getSession("redaction-session"),
    authGroup: store.getAuthGroup(authGroupId),
  });
  assert.equal(serialized.includes(rawToken), false);
  assert.equal(serialized.includes("authorization"), false);
});

test("Auth Group 전체 요청으로 score와 feature를 계산한다", () => {
  const token = "auth-group-scoring-token";
  const authGroupId = deriveAuthGroupId(`Bearer ${token}`);

  for (let i = 0; i < 4; i++) {
    store.recordRequest(`scoring-session-${i % 2}`, "127.0.0.4", {
      method: "GET",
      url: `/rest/products/search?q=' OR ${i}=1--`,
      status: i === 3 ? 404 : 200,
      headers: { "user-agent": "curl/8.0" },
      tags: ["sqli"],
      authGroupId,
    });
  }

  const group = store.getAuthGroup(authGroupId);
  const features = extractAuthGroupFeatures(group, store.getSession);
  const verdict = classify(features);

  assert.equal(features.totalRequests, 4);
  assert.equal(features.client.sessionChurn, 2);
  assert.equal(features.attack.payloadSignatureHits, 4);
  assert.deepEqual(features.attack.payloadCategories, ["sqli"]);
  assert.ok(verdict.attackScore > 0);
  assert.equal(verdict.label, undefined);
  assert.equal(verdict.score, undefined);
});
