const assert = require("node:assert/strict");
const test = require("node:test");

const {
  assessDetection,
  normalizeDetectionLevel,
  DETECTION_THRESHOLDS,
} = require("../lib/riskPolicy");

test("판정 기준은 LOW 30, MEDIUM 50, HIGH 70점이다", () => {
  assert.deepEqual(DETECTION_THRESHOLDS, { low: 0.3, medium: 0.5, high: 0.7 });
  assert.equal(normalizeDetectionLevel("LOW"), "low");
  assert.equal(normalizeDetectionLevel("unexpected"), "medium");
});

test("Automation은 현재 점수를 선택 기준과 비교한다", () => {
  assert.equal(assessDetection({ automationScore: 0.299 }, { level: "low" }).automationDetected, false);
  assert.equal(assessDetection({ automationScore: 0.3 }, { level: "low" }).automationDetected, true);
  assert.equal(assessDetection({ automationScore: 0.5 }, { level: "medium" }).automationDetected, true);
  assert.equal(assessDetection({ automationScore: 0.699 }, { level: "high" }).automationDetected, false);
  assert.equal(assessDetection({ automationScore: 0.7 }, { level: "high" }).automationDetected, true);
});

test("동일한 45점은 LOW에서만 Automation 접근으로 식별한다", () => {
  const score = { automationScore: 0.45 };
  assert.equal(assessDetection(score, { level: "low" }).automationDetected, true);
  assert.equal(assessDetection(score, { level: "medium" }).automationDetected, false);
  assert.equal(assessDetection(score, { level: "high" }).automationDetected, false);
});

test("Attack은 현재값이 내려가도 과거 최고 점수로 판정한다", () => {
  const score = { attackScore: 0.05, maxAttackScore: 0.6 };
  const low = assessDetection(score, { level: "low" });
  const medium = assessDetection(score, { level: "medium" });
  const high = assessDetection(score, { level: "high" });
  assert.equal(low.attackDetected, true);
  assert.equal(medium.attackDetected, true);
  assert.equal(high.attackDetected, false);
  assert.equal(medium.currentAttackScore, 0.05);
  assert.equal(medium.effectiveAttackScore, 0.6);
  assert.equal(medium.attackScoreBasis, "historical-max");
});

test("최고 Attack 값이 아직 갱신되지 않았어도 현재값을 잃지 않는다", () => {
  const result = assessDetection(
    { attackScore: 0.72, maxAttackScore: 0.4 },
    { level: "high" }
  );
  assert.equal(result.effectiveAttackScore, 0.72);
  assert.equal(result.attackDetected, true);
});
