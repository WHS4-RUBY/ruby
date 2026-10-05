const test = require("node:test");
const assert = require("node:assert/strict");
const { XssCandidateStore } = require("../lib/xssCandidateStore");

test("XSS candidates obey entry, byte and idle time bounds", () => {
  let now = 1000;
  const store = new XssCandidateStore({ ttlMs: 1000, maxEntries: 2, maxBytes: 1400,
    now: () => now });
  for (let index = 0; index < 20; index++) {
    store.observe([{ value: `<script>${index}</script>`, parameter: "comment", source: "json" }],
      "/reviews", { requestId: `request:${index}` });
    assert.ok(store.size() <= 2);
    assert.ok(store.bytes <= 1400);
  }
  assert.equal(store.size(), 2);
  now += 1001;
  assert.equal(store.size(), 0);
  assert.equal(store.bytes, 0);
});

test("current in-memory XSS candidate store loses unconfirmed evidence on restart", () => {
  const firstProcess = new XssCandidateStore();
  firstProcess.observe([{ value: "<script>alert(1)</script>", parameter: "comment", source: "json" }],
    "/reviews", { requestId: "request:writer" });
  assert.equal(firstProcess.size(), 1);
  const afterRestart = new XssCandidateStore();
  assert.equal(afterRestart.size(), 0);
});

test("confirmed XSS request history is also lost when the in-memory session store restarts", () => {
  const modulePath = require.resolve("../lib/sessionStore");
  const firstProcess = require(modulePath);
  const sessionId = "xss-retention-restart";
  firstProcess.recordRequest(sessionId, "127.0.0.1", {
    method: "POST", url: "/reviews", status: 200,
    headers: { "user-agent": "XssRetentionTest" },
    requestId: "xss-confirmed-before-restart",
    xssTags: ["xss:stored-critical"], xssMaxRisk: 1,
  });
  assert.equal(firstProcess.getSession(sessionId).requests[0].xssTags[0], "xss:stored-critical");
  delete require.cache[modulePath];
  const afterRestart = require(modulePath);
  assert.equal(afterRestart.getSession(sessionId), undefined);
});
