const assert = require("node:assert/strict");
const { after, test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const schemaDir = fs.mkdtempSync(path.join(os.tmpdir(), "schema-learning-test-"));
process.env.SCHEMA_LEARNING_FILE = path.join(schemaDir, "schema-learning.json");

const {
  analyzeBusinessLogic,
  detectMassAssignment,
  detectNumericAbuse,
  detectNoSqlOperatorInjection,
} = require("../lib/businessLogicSignatures");
const { checkIdentityMismatch } = require("../lib/identityMismatch");
const { checkRoleGatedAccess } = require("../lib/roleGatedAccess");
const { checkCsrf, buildAllowedOrigins } = require("../lib/csrfDetection");
const { extractLoginAttemptEmail } = require("../lib/loginBruteForce");
const {
  extractResetPasswordEmail,
  extractSecurityQuestionEmail,
} = require("../lib/passwordResetAbuse");
const { detectPriceTampering } = require("../lib/priceTampering");
const {
  checkPriceDelta,
  ingestProductResponseBody,
  resetPriceCache,
} = require("../lib/priceIntegrity");
const schemaLearning = require("../lib/schemaLearning");

after(() => fs.rmSync(schemaDir, { recursive: true, force: true }));

function token(payload) {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "none", typ: "JWT" })}.${encode(payload)}.`;
}

test("mass assignment, 숫자 남용, NoSQL 연산자와 comment-only SQLi를 구분한다", () => {
  const mass = detectMassAssignment("POST", "/api/Users", {
    email: "new@example.test",
    password: "safe-value",
    passwordRepeat: "safe-value",
    securityQuestion: { id: 1 },
    securityAnswer: "answer",
    nested: { role: "admin" },
  });
  assert.equal(mass.hit, true);
  assert.ok(mass.extraFields.includes("nested"));
  assert.ok(mass.suspiciousFields.includes("role"));

  assert.equal(detectNumericAbuse({ quantity: -1 }).hit, true);
  assert.equal(detectNoSqlOperatorInjection({ id: { $ne: -1 } }).hit, true);
  assert.ok(
    analyzeBusinessLogic({
      method: "POST",
      normalizedPath: "/rest/user/login",
      body: { email: "admin@example.test'--", password: "x" },
      rawQueryOrBody: "/rest/user/login",
    }).some((hit) => hit.tag === "sqli-comment-only")
  );
});

test("JWT claimed basket ownership 불일치와 관리자 엔드포인트 무단 접근을 태깅한다", () => {
  const userToken = token({ data: { id: 7, role: "customer" }, bid: 12 });
  const matching = checkIdentityMismatch({
    method: "GET",
    normalizedPath: "/rest/basket/:id",
    url: "/rest/basket/12",
    authorizationHeader: `Bearer ${userToken}`,
  });
  const mismatching = checkIdentityMismatch({
    method: "GET",
    normalizedPath: "/rest/basket/:id",
    url: "/rest/basket/99",
    authorizationHeader: `Bearer ${userToken}`,
  });
  assert.deepEqual(matching, []);
  assert.equal(mismatching[0].tag, "identity-mismatch:basket");

  const denied = checkRoleGatedAccess({
    method: "GET",
    normalizedPath: "/rest/admin/application-configuration",
    authorizationHeader: `Bearer ${userToken}`,
  });
  assert.equal(denied[0].tag, "role-gated:admin-config");
  const adminToken = token({ data: { id: 1, role: "admin" }, bid: 1 });
  assert.deepEqual(
    checkRoleGatedAccess({
      method: "GET",
      normalizedPath: "/rest/admin/application-configuration",
      authorizationHeader: `Bearer ${adminToken}`,
    }),
    []
  );
});

test("CSRF는 상태 변경 요청의 Origin/Referer만 검사한다", () => {
  const allowed = buildAllowedOrigins(["http://localhost:8080"]);
  assert.deepEqual(checkCsrf({ method: "GET", normalizedPath: "/api/Users" }, allowed), []);
  assert.deepEqual(
    checkCsrf({
      method: "POST",
      normalizedPath: "/api/Users",
      originHeader: "http://localhost:8080",
    }, allowed),
    []
  );
  assert.equal(
    checkCsrf({
      method: "POST",
      normalizedPath: "/api/Users",
      originHeader: "https://attacker.invalid",
    }, allowed)[0].tag,
    "csrf:origin-mismatch"
  );
  assert.equal(
    checkCsrf({ method: "POST", normalizedPath: "/api/Users" }, allowed)[0].tag,
    "csrf:missing-origin"
  );
});

test("로그인·비밀번호 재설정·보안질문에서 이메일 집계 키를 추출한다", () => {
  assert.equal(
    extractLoginAttemptEmail({
      method: "POST",
      normalizedPath: "/rest/user/login",
      body: { email: " User@Example.Test " },
    }),
    "user@example.test"
  );
  assert.equal(
    extractResetPasswordEmail({
      method: "POST",
      normalizedPath: "/rest/user/reset-password",
      body: { email: " User@Example.Test " },
    }),
    "user@example.test"
  );
  assert.equal(
    extractSecurityQuestionEmail({
      method: "GET",
      normalizedPath: "/rest/user/security-question",
      url: "/rest/user/security-question?email=User%40Example.Test",
    }),
    "user@example.test"
  );
});

test("요청 내부 총액 불일치와 관찰 가격 대비 급락을 탐지한다", () => {
  assert.equal(detectPriceTampering({ quantity: 2, price: 10, total: 20 }).hit, false);
  assert.equal(detectPriceTampering({ quantity: 2, price: 10, total: 1 }).hit, true);

  resetPriceCache();
  assert.equal(checkPriceDelta(1, 20).hit, false);
  ingestProductResponseBody({ data: [{ id: 1, price: 100 }] });
  assert.equal(checkPriceDelta(1, 60).hit, false);
  assert.equal(checkPriceDelta(1, 50).hit, true);
});

test("스키마 학습은 제안 후 명시적 승인 전까지 탐지 규칙에 사용하지 않는다", () => {
  schemaLearning.resetAll();
  for (let index = 0; index < 3; index++) {
    schemaLearning.observeMassAssignment({
      method: "POST",
      normalizedPath: "/api/Custom",
      bodyObj: { name: "normal", count: 1 },
      statusCode: 201,
      hasHardcodedWhitelist: false,
    });
  }
  const candidate = schemaLearning.listCandidates().massAssignment.find(
    (entry) => entry.key === "POST /api/Custom"
  );
  assert.equal(candidate.ready, true);
  assert.equal(schemaLearning.getApprovedMassAssignmentWhitelist("POST", "/api/Custom"), null);
  assert.equal(schemaLearning.approveMassAssignment(candidate.key), true);
  assert.deepEqual(
    [...schemaLearning.getApprovedMassAssignmentWhitelist("POST", "/api/Custom")].sort(),
    ["count", "name"]
  );
});
