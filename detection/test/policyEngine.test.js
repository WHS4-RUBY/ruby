const test = require("node:test");
const assert = require("node:assert/strict");

const {
  applyDefensePlan,
  loadPolicyRules,
  selectStrategies,
} = require("../lib/policyEngine");

test("위험도 구간의 첫 번째 일치 규칙으로 Defense 전략을 선택한다", () => {
  const rules = loadPolicyRules();

  assert.deepEqual(selectStrategies(0.19, rules), []);
  assert.deepEqual(selectStrategies(0.2, rules), [{ name: "delay", params: { delay_ms: 200 } }]);
  assert.deepEqual(selectStrategies(0.8, rules), [{ name: "delay", params: { delay_ms: 500 } }]);
  assert.deepEqual(selectStrategies(1, rules), [{ name: "delay", params: { delay_ms: 500 } }]);
});

test("클라이언트의 Defense plan을 제거하고 서버 정책 결과로 교체한다", () => {
  const headers = new Map([["x-defense-plan", '[{"name":"bypass"}]']]);
  const proxyReq = {
    removeHeader(name) {
      headers.delete(name.toLowerCase());
    },
    setHeader(name, value) {
      headers.set(name.toLowerCase(), value);
    },
  };

  applyDefensePlan(proxyReq, {
    riskScore: 0.6,
    rules: loadPolicyRules(),
  });

  assert.equal(
    headers.get("x-defense-plan"),
    '[{"name":"delay","params":{"delay_ms":300}}]'
  );
  assert.equal(headers.get("accept-encoding"), "identity");
});
