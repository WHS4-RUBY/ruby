const assert = require("node:assert/strict");
const test = require("node:test");

const { selectEffectiveDetection } = require("../lib/detectionPolicy");

function analysis(automationScore, attackScore, totalRequests = 1, maxAttackScore = attackScore) {
  return {
    automationScore,
    attackScore,
    detection: { effectiveAttackScore: maxAttackScore },
    features: { totalRequests },
  };
}

test("CONFIRMED 요청이 없는 Resolved Actor는 Candidate 탐지 이력을 가리지 않는다", () => {
  const [source, selected] = selectEffectiveDetection({
    session: analysis(0.1, 0),
    candidate: analysis(0.7, 0.2, 8),
    authGroup: null,
    resolved: analysis(0, 0, 0),
  });
  assert.equal(source, "actor-candidate-fallback");
  assert.equal(selected.automationScore, 0.7);
});

test("CONFIRMED Resolved Actor와 Auth Group은 독립된 탐지 출처로 비교한다", () => {
  const [source] = selectEffectiveDetection({
    session: analysis(0.1, 0),
    candidate: analysis(0.2, 0.1),
    authGroup: analysis(0.3, 0.8),
    resolved: analysis(0.7, 0.4, 5),
  });
  assert.equal(source, "auth-group");
});

test("현재 점수가 낮아도 과거 최고 Attack 점수가 높은 출처를 우선한다", () => {
  const [source] = selectEffectiveDetection({
    session: analysis(0.525, 0, 8, 0),
    candidate: analysis(0, 0.05, 2, 0.6),
    authGroup: null,
    resolved: null,
  });
  assert.equal(source, "actor-candidate-fallback");
});
