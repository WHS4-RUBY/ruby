const assert = require("node:assert/strict");
const { after, test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const schemaDir = fs.mkdtempSync(path.join(os.tmpdir(), "schema-learning-test-"));
// 학습 상태는 Detection 통합 DB 에 들어간다. 테스트마다 별도 파일을 쓴다.
process.env.DETECTION_STORE_DB = path.join(schemaDir, "detection.sqlite3");

const {
  analyzeBusinessLogic,
  detectMassAssignment,
  detectNumericAbuse,
  detectNoSqlOperatorInjection,
} = require("../lib/businessLogicSignatures");
const { checkIdentityMismatch, extractToken } = require("../lib/identityMismatch");
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
const { loadSiteProfile } = require("../lib/siteProfile");

// 라우트·필드명은 이제 프로파일에서 온다. 이 파일의 단정은 juice-shop 대상이므로
// juice-shop 프로파일을 넘긴다.
const JUICE_PROFILE = loadSiteProfile(
  path.join(__dirname, "..", "config", "site-profiles", "juice-shop.json")
);

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
      profile: JUICE_PROFILE,
    }),
    "user@example.test"
  );
  assert.equal(
    extractResetPasswordEmail({
      method: "POST",
      normalizedPath: "/rest/user/reset-password",
      body: { email: " User@Example.Test " },
      profile: JUICE_PROFILE,
    }),
    "user@example.test"
  );
  assert.equal(
    extractSecurityQuestionEmail({
      method: "GET",
      normalizedPath: "/rest/user/security-question",
      url: "/rest/user/security-question?email=User%40Example.Test",
      profile: JUICE_PROFILE,
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

// 형제 함수들(extractQueryValue, xssReflection.decode, server.js 의 쿠키 파서)은 모두
// decodeURIComponent 를 try/catch 로 감싸는데 extractToken 만 빠져 있었다. 이 미들웨어는
// app.use 에서 래퍼 없이 호출되므로(server.js) 던지면 Express 가 500 을 낸다.
// 실패 시 raw 로 되돌리는 쪽을 택했다 — null 로 두면 공격자가 쿠키 끝에 % 하나를 붙여
// Detection 의 신원 판정을 통째로 눈감게 만들 수 있다.
test("쿠키의 깨진 퍼센트 인코딩이 500 을 만들지 않고 신원 판정도 눈감지 않는다", () => {
  const userToken = token({ data: { id: 7, role: "customer" }, bid: 12 });

  assert.doesNotThrow(() => extractToken(undefined, "token=%"));
  assert.equal(extractToken(undefined, "token=%"), "%");

  // 디코딩 가능한 값은 그대로 디코딩한다(기존 동작).
  assert.equal(extractToken(undefined, `token=${encodeURIComponent(userToken)}`), userToken);

  // 깨진 인코딩이 뒤에 붙어도 토큰을 버리지 않는다 — 그러지 않으면 % 한 글자로 회피된다.
  for (const cookie of [`token=${userToken}%`, `token=%${userToken}`]) {
    const hits = checkIdentityMismatch({
      method: "GET",
      normalizedPath: "/rest/basket/:id",
      url: "/rest/basket/99",
      cookieHeader: cookie,
    });
    assert.equal(hits.length, 1, `${cookie} 에서 신원 불일치를 놓쳤다`);
    assert.equal(hits[0].tag, "identity-mismatch:basket");
  }

  // 역할 게이트도 같은 경로를 쓴다(extractToken 재export).
  assert.doesNotThrow(() =>
    checkRoleGatedAccess({
      method: "GET",
      normalizedPath: "/rest/admin/application-configuration",
      cookieHeader: "token=%",
    })
  );
});
