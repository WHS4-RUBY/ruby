const assert = require("node:assert/strict");
const test = require("node:test");

const {
  MASS_ASSIGNMENT_WHITELIST,
  detectMassAssignment,
} = require("../lib/businessLogicSignatures");
const { IDENTITY_ROUTE_RULES } = require("../lib/identityMismatch");

// 같은 라우트를 두 번 적던 자리들. 한쪽만 고치면 조용히 어긋나므로 정본을 하나로
// 모았고, 이 테스트가 다시 늘어나는 것을 막는다.

test("화이트리스트에 뒤 슬래시 변종을 따로 나열하지 않는다", () => {
  for (const key of MASS_ASSIGNMENT_WHITELIST.keys()) {
    assert.equal(key.endsWith("/"), false, key);
  }
  // 같은 값을 두 키에 적어 둔 항목이 없어야 한다.
  const seen = new Map();
  for (const [key, fields] of MASS_ASSIGNMENT_WHITELIST) {
    const signature = [...fields].sort().join(",");
    const previous = seen.get(signature);
    assert.equal(previous, undefined,
      `${key} 와 ${previous} 가 같은 필드 집합을 중복 선언한다`);
    seen.set(signature, key);
  }
});

test("뒤 슬래시가 붙어도 같은 라우트로 판정한다", () => {
  const body = { email: "a@b.c", role: "admin" };
  for (const path of ["/api/Users", "/api/Feedbacks"]) {
    const bare = detectMassAssignment("POST", path, body);
    const slashed = detectMassAssignment("POST", `${path}/`, body);
    assert.deepEqual(slashed.extraFields, bare.extraFields, path);
    assert.deepEqual(slashed.suspiciousFields, bare.suspiciousFields, path);
  }
});

test("신원 규칙은 라우트를 한 번만 적고 추출 정규식을 거기서 만든다", () => {
  assert.ok(IDENTITY_ROUTE_RULES.length > 0);
  for (const rule of IDENTITY_ROUTE_RULES) {
    assert.equal(typeof rule.normalizedPath, "string");
    assert.ok(rule.normalizedPath.includes(":id"), rule.normalizedPath);
    // 템플릿에서 만든 추출기가 그 템플릿의 경로에서 숫자를 꺼낸다.
    const concrete = rule.normalizedPath.replace(":id", "42");
    assert.equal(rule.extractRequestedId(concrete), 42, rule.normalizedPath);
    assert.equal(rule.extractRequestedId(`${concrete}?from=list`), 42, rule.normalizedPath);
    assert.equal(rule.extractRequestedId(rule.normalizedPath.replace(":id", "abc")), null);
    assert.equal(rule.extractRequestedId(""), null);
    assert.equal(rule.extractRequestedId(null), null);
    // test() 와 추출기가 같은 템플릿을 본다.
    assert.equal(rule.test("GET", rule.normalizedPath), true);
    assert.equal(rule.test("GET", `${rule.normalizedPath}/extra`), false);
  }
});
