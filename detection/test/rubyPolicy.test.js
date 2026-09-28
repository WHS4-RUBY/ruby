const test = require("node:test");
const assert = require("node:assert/strict");

const {
  stripDetectionHeaders,
  buildPolicyDecision,
} = require("../lib/rubyPolicy");

test("Automation과 누적 Attack 중 큰 값을 RUBY risk score로 선택한다", () => {
  const decision = buildPolicyDecision({
    source: "auth-group",
    clientId: "actor:123",
    analysis: {
      automationScore: 0.42,
      attackScore: 0.31,
      detection: { effectiveAttackScore: 0.81 },
    },
  });

  assert.deepEqual(decision, {
    source: "auth-group",
    clientId: "actor:123",
    riskScore: 0.81,
  });
});

test("관찰 이력이 없으면 안전한 기본값 0을 사용한다", () => {
  assert.equal(buildPolicyDecision().riskScore, 0);
});

test("외부에서 주입한 탐지 헤더를 제거한다", () => {
  const headers = new Map([
    ["x-client-id", "spoofed-client"],
    ["x-risk-score", "1"],
    ["x-classification", "spoofed"],
    ["x-defense-plan", '[{"name":"delay"}]'],
    ["content-type", "application/json"],
  ]);
  const proxyReq = {
    removeHeader(name) {
      headers.delete(name.toLowerCase());
    },
  };

  stripDetectionHeaders(proxyReq);
  
  assert.equal(headers.has("x-client-id"), false);
  assert.equal(headers.has("x-risk-score"), false);
  assert.equal(headers.has("x-classification"), false);
  assert.equal(headers.has("x-defense-plan"), false);

  // 관련 없는 헤더는 유지되어야 한다.
  assert.equal(headers.get("content-type"), "application/json")
});
