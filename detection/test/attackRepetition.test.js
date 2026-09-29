const assert = require("node:assert/strict");
const test = require("node:test");

const { ClientFlowStore } = require("../lib/clientFlowStore");
const { isQualifyingAttackRequest, repetitionBonusPoints } = require("../lib/attackRepetition");

test("첫 공격은 가산하지 않고 반복할수록 최대 50점까지 더한다", () => {
  assert.deepEqual([1, 2, 4, 8, 16, 32, 64].map(repetitionBonusPoints), [0, 10, 20, 30, 40, 50, 50]);
});

test("Origin 부재만 있는 CLI 요청은 제외하고 독립 공격 근거는 유지한다", () => {
  const missingOrigin = { csrfTags: ["csrf:missing-origin"] };
  assert.equal(isQualifyingAttackRequest(missingOrigin), false);
  for (const evidence of [
    { tags: ["sqli"] },
    { blTags: ["mass-assignment:role"] },
    { csrfTags: ["csrf:missing-origin", "csrf:origin-mismatch"] },
    { csrfTags: ["csrf:referer-mismatch"] },
    { attackDetection: { available: true, anomalyScore: 5 } },
    { deceptionEvents: [{ signal: "watermark_reuse" }] },
  ]) {
    assert.equal(isQualifyingAttackRequest({ ...missingOrigin, ...evidence }), true);
  }
  assert.equal(isQualifyingAttackRequest({
    ...missingOrigin, attackDetection: { available: true, anomalyScore: 4 },
  }), false);
});

test("공격 태그만 60분 동안 누적하고 정상·백그라운드 요청은 제외한다", () => {
  const start = 1_700_000_000_000;
  const store = new ClientFlowStore({ ttlMs: 60 * 60_000 });
  const group = store.create("actor:a", { observedAt: start }, "session:a", null, start);
  store.recordAttackRequest(group.id, { requestId: "normal", ts: start, status: 404 });
  store.recordAttackRequest(group.id, {
    requestId: "background", ts: start, tags: ["sqli"], backgroundTraffic: { isBackground: true },
  });
  assert.equal(store.attackRepetition(group.id, start).bonusPoints, 0);
  for (let index = 0; index < 16; index++) {
    store.recordAttackRequest(group.id, { requestId: `attack:${index}`, ts: start + index * 1000, tags: ["sqli"] });
  }
  assert.equal(store.attackRepetition(group.id, start + 16_000).qualifyingRequests, 16);
  assert.equal(store.attackRepetition(group.id, start + 16_000).bonusPoints, 40);
  assert.equal(store.attackRepetition(group.id, start + 61 * 60_000).bonusPoints, 0);
});
