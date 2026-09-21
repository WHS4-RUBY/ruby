const assert = require("node:assert/strict");
const test = require("node:test");

const { selectClientId, selectEffectiveDetection } = require("../lib/detectionPolicy");

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

test("Fingerprint Client Flow 점수가 가장 높으면 자동 탐지 출처로 사용한다", () => {
  const [source] = selectEffectiveDetection({
    session: analysis(0.1, 0.1),
    candidate: analysis(0.2, 0.2),
    authGroup: null,
    clientFlow: analysis(0.8, 0.9, 12),
    resolved: null,
  });
  assert.equal(source, "fingerprint-client-flow");
});

// 하위 계층은 X-Client-Id를 방어 상태(rate limit 카운터 등)의 키로 쓴다.
// 점수 출처는 요청마다 바뀔 수 있으므로 식별자 선택은 점수와 분리되어야 한다.
test("Client Flow가 성립하면 Candidate 점수가 더 높아도 식별자는 Flow를 유지한다", () => {
  const analyses = {
    session: analysis(0.9, 0.9),
    candidate: analysis(0.9, 0.9),
    authGroup: null,
    clientFlow: analysis(0.2, 0.2, 12),
    resolved: null,
  };
  const [source] = selectEffectiveDetection(analyses);
  assert.notEqual(source, "fingerprint-client-flow");
  assert.equal(
    selectClientId(analyses, {
      actorId: "actor:aaa",
      resolvedActorId: null,
      clientFlowId: "client-flow:bbb",
    }),
    "client-flow:bbb"
  );
});

test("확정된 Resolved Actor가 있으면 Client Flow보다 우선한다", () => {
  assert.equal(
    selectClientId(
      { resolved: analysis(0.1, 0.1, 5), clientFlow: analysis(0.9, 0.9, 12) },
      {
        actorId: "actor:aaa",
        resolvedActorId: "resolved:ccc",
        clientFlowId: "client-flow:bbb",
      }
    ),
    "resolved:ccc"
  );
});

test("근거가 없으면 Candidate 식별자로 떨어진다", () => {
  assert.equal(
    selectClientId({}, { actorId: "actor:aaa", resolvedActorId: null, clientFlowId: null }),
    "actor:aaa"
  );
});
