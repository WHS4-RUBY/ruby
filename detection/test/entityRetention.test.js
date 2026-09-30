const assert = require("node:assert/strict");
const test = require("node:test");

function withStore(overrides, run) {
  const settings = {
    MAX_SESSIONS: "5", MAX_ACTORS: "5", MAX_AUTH_GROUPS: "5", MAX_IP_ENTRIES: "5",
    DETECTION_ENTITY_TTL_MS: "100", RISKY_ENTITY_TTL_MS: "1000", DETECTION_ENTITY_SWEEP_MS: "10",
    ...overrides,
  };
  const previous = Object.fromEntries(Object.keys(settings).map((key) => [key, process.env[key]]));
  const originalNow = Date.now;
  let now = 1_000_000;
  Date.now = () => now;
  Object.assign(process.env, settings);
  delete require.cache[require.resolve("../lib/sessionStore")];
  try {
    run(require("../lib/sessionStore"), (delta) => { now += delta; });
  } finally {
    Date.now = originalNow;
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
}

const request = (extra = {}) => ({
  method: "GET", url: "/safe", status: 200,
  headers: { "user-agent": "retention-test/1.0" }, ...extra,
});

test("telemetry admissions obey the session cap and keep the current session", () => {
  withStore({}, (store) => {
    for (let i = 0; i < 12; i++) store.recordTelemetry(`telemetry-${i}`, "192.0.2.1", {});
    assert.ok(store.getAllSessions().length <= 5);
    assert.ok(store.getSession("telemetry-11"));
  });
});

test("eviction removes session references from actors, auth groups, IP entries and flows", () => {
  withStore({}, (store) => {
    let last;
    for (let i = 0; i < 12; i++) {
      last = store.recordRequest(`session-${i}`, "192.0.2.1", request({ authGroupId: "auth-test" }));
    }
    const retained = new Set(store.getAllSessions().map((session) => session.id));
    for (const entity of [store.getActor(last.actorId), store.getAuthGroup("auth-test"), store.getIpEntry("192.0.2.1")]) {
      assert.deepEqual(new Set(entity.sessionIds), retained);
    }
    assert.deepEqual(new Set(store.getClientFlowState(last.clientFlowId).sessionIds), retained);
  });
});

test("ordinary and risky entities have separate idle TTLs", () => {
  withStore({}, (store, advance) => {
    store.recordRequest("ordinary", "192.0.2.1", request());
    const risky = store.recordRequest("risky", "192.0.2.2", request());
    store.updateAttackScoreHistory({ sessionId: risky.id, actorId: risky.actorId, scores: { session: 0.3, actor: 0.3 } });
    advance(101);
    store.recordTelemetry("trigger", "192.0.2.3", {});
    assert.equal(store.getSession("ordinary"), undefined);
    assert.ok(store.getSession("risky"));
    advance(901);
    store.recordTelemetry("trigger", "192.0.2.3", {});
    assert.equal(store.getSession("risky"), undefined);
  });
});

test("risk-aware eviction protects the request currently being scored even at cap one", () => {
  withStore({ MAX_SESSIONS: "1", MAX_ACTORS: "1", MAX_AUTH_GROUPS: "1", MAX_IP_ENTRIES: "1" }, (store) => {
    const old = store.recordRequest("old", "192.0.2.1", request({ authGroupId: "old-auth" }));
    store.updateAttackScoreHistory({ sessionId: old.id, actorId: old.actorId, scores: { session: 0.3, actor: 0.3 } });
    const current = store.recordRequest("current", "192.0.2.2", request({ authGroupId: "new-auth" }));
    assert.equal(store.getAllSessions().length, 1);
    assert.equal(store.getSession(current.id), current);
    assert.ok(store.getActor(current.actorId));
    assert.ok(store.getAuthGroup("new-auth"));
  });
});

test("the periodic sweep expires a quiet session without another admission", async () => {
  const keys = ["DETECTION_ENTITY_TTL_MS", "DETECTION_ENTITY_SWEEP_MS"];
  const previous = keys.map((key) => process.env[key]);
  process.env.DETECTION_ENTITY_TTL_MS = "5";
  process.env.DETECTION_ENTITY_SWEEP_MS = "10";
  delete require.cache[require.resolve("../lib/sessionStore")];
  const store = require("../lib/sessionStore");
  try {
    store.recordTelemetry("quiet", "192.0.2.9", {});
    await new Promise((resolve) => setTimeout(resolve, 30));
    assert.equal(store.getSession("quiet"), undefined);
  } finally {
    keys.forEach((key, index) => {
      if (previous[index] === undefined) delete process.env[key]; else process.env[key] = previous[index];
    });
  }
});
