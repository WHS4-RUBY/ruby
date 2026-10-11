const assert = require("node:assert/strict");
const { test } = require("node:test");

const { extractLoginAttemptEmail } = require("../lib/loginBruteForce");

/**
 * loginBruteForce.js 의 특성화(characterization) 테스트.
 *
 * 사이트 프로파일로 바꾸기 **전에** 현재 동작을 고정한다. CI 가 Juice Shop 로직을
 * 전혀 검증하지 않으므로(integration-check 는 정적 index.html 하나를 쓴다) 이 단계를
 * 건너뛰면 리팩토링이 무엇을 바꿨는지 알 방법이 없다.
 *
 * 여기 적힌 것은 "좋은 동작" 이 아니라 "지금 동작" 이다. 고쳐야 할 것처럼 보이는
 * 항목도 그대로 고정한다 — 고치는 것은 별도의 동작 변경 커밋이다.
 */

const JUICE_LOGIN = { method: "POST", normalizedPath: "/rest/user/login" };

test("특성화: 로그인 라우트의 email 을 소문자로 정규화해 돌려준다", () => {
  assert.equal(
    extractLoginAttemptEmail({ ...JUICE_LOGIN, body: { email: "admin@juice-sh.op" } }),
    "admin@juice-sh.op"
  );
  // 앞뒤 공백을 떼고 소문자로 바꾼다.
  assert.equal(
    extractLoginAttemptEmail({ ...JUICE_LOGIN, body: { email: "  ADMIN@Juice-SH.op  " } }),
    "admin@juice-sh.op"
  );
  // 메서드 대소문자는 무관하다.
  assert.equal(
    extractLoginAttemptEmail({ method: "post", normalizedPath: "/rest/user/login", body: { email: "a@b" } }),
    "a@b"
  );
});

test("특성화: 본문이 JSON 문자열이어도 파싱한다", () => {
  assert.equal(
    extractLoginAttemptEmail({ ...JUICE_LOGIN, body: '{"email":"A@B"}' }),
    "a@b"
  );
  // 깨진 JSON 은 null 이다 — 던지지 않는다.
  assert.equal(extractLoginAttemptEmail({ ...JUICE_LOGIN, body: "{not json" }), null);
});

test("특성화: 라우트가 정확히 일치하지 않으면 null 이다", () => {
  for (const [method, path] of [
    ["GET", "/rest/user/login"],
    ["PUT", "/rest/user/login"],
    ["POST", "/rest/user/logout"],
    ["POST", "/api/auth/login"],
    ["POST", "/"],
  ]) {
    assert.equal(
      extractLoginAttemptEmail({ method, normalizedPath: path, body: { email: "a@b" } }),
      null,
      `${method} ${path} 가 로그인으로 잡혔다`
    );
  }
});

// 지금 게이트는 뒤 슬래시를 허용하지 않는다(loginBruteForce.js 의 === 비교).
// identityMismatch 의 routeMatches 는 뒤 슬래시를 떼고 비교하므로 두 모듈이 다르다.
// 고치면 동작 변경이므로 여기서는 **지금 동작을 고정만** 한다.
test("특성화: 뒤 슬래시가 붙은 로그인 경로는 잡지 않는다", () => {
  assert.equal(
    extractLoginAttemptEmail({ method: "POST", normalizedPath: "/rest/user/login/", body: { email: "a@b" } }),
    null
  );
});

test("특성화: email 필드가 쓸 수 없는 값이면 null 이다", () => {
  const cases = [
    { email: "" },
    { email: "   " },
    { email: 42 },
    { email: null },
    { email: { nested: "a@b" } },
    { email: ["a@b"] },
    { username: "a@b" },
    {},
  ];
  for (const body of cases) {
    assert.equal(extractLoginAttemptEmail({ ...JUICE_LOGIN, body }), null,
      `${JSON.stringify(body)} 가 이메일로 잡혔다`);
  }
});

test("특성화: 본문이 객체가 아니면 null 이다", () => {
  for (const body of [null, undefined, 42, true, ["a"], ""]) {
    assert.equal(extractLoginAttemptEmail({ ...JUICE_LOGIN, body }), null,
      `본문 ${JSON.stringify(body)} 가 통과했다`);
  }
});

test("특성화: method 와 normalizedPath 가 없어도 던지지 않는다", () => {
  assert.equal(extractLoginAttemptEmail({ body: { email: "a@b" } }), null);
  assert.equal(extractLoginAttemptEmail({ method: null, normalizedPath: null, body: { email: "a@b" } }), null);
});
