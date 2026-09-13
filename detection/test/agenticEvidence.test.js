const assert = require("node:assert/strict");
const test = require("node:test");

const {
  computeAgenticEvidence,
  computePartitionedAgenticEvidence,
} = require("../lib/agenticEvidence");

function request({
  ts,
  path,
  method = "POST",
  status,
  payload = null,
  auth = false,
  actorId = "actor:a",
  sessionId = "session:a",
}) {
  return {
    ts,
    method,
    normalizedPath: path,
    operation: `${method} ${path}`,
    status,
    payloadFingerprint: payload,
    hasAuthorization: auth,
    actorId,
    sessionId,
  };
}

test("인접 요청과 동일 경로 조건에 따라 Agentic Evidence 관찰값을 계산한다", () => {
  const evidence = computeAgenticEvidence([
    request({ ts: 0, path: "/login", status: 401, payload: "a", auth: false }),
    request({ ts: 1_000, path: "/login", status: 500, payload: "b", auth: true }),
    request({ ts: 2_000, path: "/login", method: "GET", status: 200, payload: "b", auth: true }),
    request({ ts: 3_000, path: "/missing", method: "GET", status: 404 }),
    request({ ts: 4_000, path: "/other", method: "GET", status: 200 }),
  ]);

  assert.deepEqual(evidence, {
    errorToEndpointChangeCount: 1,
    errorToMethodChangeCount: 1,
    retryWithPayloadChangeCount: 1,
    authAddedAfter401Count: 1,
    failureChangeSuccessCount: 1,
  });
});

test("5분을 초과한 전이와 서로 다른 Actor 사이의 전이를 연결하지 않는다", () => {
  const tooLate = computeAgenticEvidence([
    request({ ts: 0, path: "/login", status: 401 }),
    request({ ts: 300_001, path: "/other", status: 200 }),
  ]);
  assert.equal(tooLate.errorToEndpointChangeCount, 0);

  const partitioned = computePartitionedAgenticEvidence([
    request({ ts: 0, path: "/login", status: 401, actorId: "actor:a" }),
    request({ ts: 1_000, path: "/login", status: 200, actorId: "actor:b" }),
  ]);
  assert.equal(partitioned.failureChangeSuccessCount, 0);
  assert.equal(partitioned.authAddedAfter401Count, 0);
});

test("actorId가 없으면 sessionId를 fallback partition으로 사용한다", () => {
  const partitioned = computePartitionedAgenticEvidence([
    request({ ts: 0, path: "/login", status: 401, actorId: null, sessionId: "session:a" }),
    request({ ts: 1_000, path: "/login", status: 200, payload: "changed", actorId: null, sessionId: "session:a" }),
    request({ ts: 1_500, path: "/login", status: 200, actorId: null, sessionId: "session:b" }),
  ]);
  assert.equal(partitioned.failureChangeSuccessCount, 1);
});

test("Socket.IO background traffic은 Agentic Evidence 전이를 끊거나 만들지 않는다", () => {
  const evidence = computeAgenticEvidence([
    request({ ts: 0, path: "/login", status: 401, payload: "old" }),
    {
      ...request({ ts: 500, path: "/socket.io/", method: "GET", status: 200 }),
      backgroundTraffic: { isBackground: true, category: "socket_io_polling" },
    },
    request({ ts: 1_000, path: "/login", status: 200, payload: "new" }),
  ]);

  assert.equal(evidence.retryWithPayloadChangeCount, 1);
  assert.equal(evidence.failureChangeSuccessCount, 1);
  assert.equal(evidence.errorToEndpointChangeCount, 0);
});
