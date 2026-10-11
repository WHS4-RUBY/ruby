const assert = require("node:assert/strict");
const { after, test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

// schemaLearning 은 import 시점에 저장소를 열고 모듈 전역 상태를 만든다 — require 보다
// 먼저 DB 경로를 잡아야 한다(businessDetection.test.js 와 같은 전처리).
const schemaDir = fs.mkdtempSync(path.join(os.tmpdir(), "characterize-bl-"));
process.env.DETECTION_STORE_DB = path.join(schemaDir, "detection.sqlite3");

const {
  analyzeBusinessLogic: analyze,
  detectMassAssignment: detectMass,
  hasHardcodedMassAssignmentWhitelist: hasWhitelist,
  detectNumericAbuse: detectNumeric,
  detectNoSqlOperatorInjection,
  detectCommentOnlySqli,
} = require("../lib/businessLogicSignatures");
const schemaLearning = require("../lib/schemaLearning");
const { loadSiteProfile } = require("../lib/siteProfile");

const profileAt = (id) =>
  loadSiteProfile(path.join(__dirname, "..", "config", "site-profiles", `${id}.json`));

// juice-shop 프로파일을 주입하면 아래 단정은 한 글자도 바뀌지 않고 통과해야 한다.
const JUICE_PROFILE = profileAt("juice-shop");
const analyzeBusinessLogic = (args) => analyze({ ...args, profile: JUICE_PROFILE });
const detectMassAssignment = (method, route, body) => detectMass(method, route, body, JUICE_PROFILE);
const hasHardcodedMassAssignmentWhitelist = (method, route) =>
  hasWhitelist(method, route, JUICE_PROFILE);
const detectNumericAbuse = (body) => detectNumeric(body, JUICE_PROFILE);

after(() => fs.rmSync(schemaDir, { recursive: true, force: true }));

/**
 * businessLogicSignatures.js 의 특성화 테스트.
 *
 * 이 모듈은 네 가지 판정을 한 진입점에 묶고 있고, 그중 **라우트에 묶인 것은
 * mass-assignment 의 화이트리스트 하나뿐**이다. 숫자 범위·의심 필드명·NoSQL 연산자·
 * comment-only SQLi 는 모두 라우트와 무관하게 모든 본문에서 돌고 있다. 그래서
 * 프로파일화 뒤에도 그 셋은 generic 프로파일에 들어가야 동작이 보존된다.
 *
 * NoSQL 연산자와 comment-only SQLi 는 **설정을 받지 않는다** — 사이트와 무관한
 * 구문 판정이므로 프로파일로 옮기지 않는다.
 */

test("특성화: 화이트리스트가 있는 라우트에서 허용 밖 최상위 필드를 잡는다", () => {
  const result = detectMassAssignment("POST", "/api/Users", {
    email: "a@b", password: "x", passwordRepeat: "x",
    securityQuestion: { id: 1 }, securityAnswer: "y",
    nested: { role: "admin" },
  });
  assert.equal(result.hit, true);
  // extraFields 는 **최상위만** 본다. 중첩 객체는 그 키 이름 하나로 센다.
  assert.deepEqual(result.extraFields, ["nested"]);
  // 의심 필드명은 중첩 안까지 훑는다.
  assert.deepEqual(result.suspiciousFields, ["role"]);
});

test("특성화: 다섯 개 화이트리스트 라우트가 모두 등록돼 있다", () => {
  const routes = [
    ["POST", "/api/Users", ["email", "password", "passwordRepeat", "securityQuestion", "securityAnswer"]],
    ["POST", "/api/Feedbacks", ["comment", "rating", "captchaId", "captcha"]],
    ["PUT", "/rest/products/:id/reviews", ["message"]],
    ["PATCH", "/rest/products/reviews", ["id", "message"]],
    ["PUT", "/api/Products/:id",
      ["name", "description", "price", "deluxePrice", "image", "category", "CategoryId"]],
  ];
  for (const [method, route, allowed] of routes) {
    assert.equal(hasHardcodedMassAssignmentWhitelist(method, route), true,
      `${method} ${route} 에 화이트리스트가 없다`);
    // 허용 필드만 보내면 extraFields 가 비어 있다.
    const body = Object.fromEntries(allowed.map((f) => [f, "x"]));
    assert.deepEqual(detectMassAssignment(method, route, body).extraFields, [],
      `${method} ${route} 의 허용 필드가 extraFields 로 잡혔다`);
    // 허용 밖 필드 하나를 더하면 그것만 잡힌다.
    assert.deepEqual(
      detectMassAssignment(method, route, { ...body, zzzExtra: "x" }).extraFields,
      ["zzzExtra"]
    );
  }
});

test("특성화: 화이트리스트 조회는 뒤 슬래시를 같은 라우트로 본다", () => {
  assert.equal(hasHardcodedMassAssignmentWhitelist("POST", "/api/Users/"), true);
  assert.equal(hasHardcodedMassAssignmentWhitelist("post", "/api/Users"), true);
  assert.deepEqual(detectMassAssignment("POST", "/api/Users/", { email: "a@b" }).extraFields, []);
  // 루트는 슬래시를 떼지 않는다.
  assert.equal(hasHardcodedMassAssignmentWhitelist("POST", "/"), false);
});

test("특성화: 화이트리스트가 없는 라우트는 extraFields 와 suspiciousValues 를 비워 둔다", () => {
  const result = detectMassAssignment("POST", "/no/such/route", {
    anything: "x", role: "admin",
  });
  assert.deepEqual(result.extraFields, [], "화이트리스트가 없으면 판단하지 않는다");
  assert.deepEqual(result.suspiciousValues, [], "값 검사는 화이트리스트가 있을 때만");
  // 의심 필드명은 라우트와 무관하게 항상 본다.
  assert.deepEqual(result.suspiciousFields, ["role"]);
  assert.equal(result.hit, true);
});

test("특성화: 의심 필드명 21개를 대소문자 무관으로, 중첩·배열까지 훑는다", () => {
  const names = [
    "role", "isadmin", "is_admin", "admin", "permissions", "scope",
    "accesslevel", "is_staff", "is_superuser", "usertype",
    "roles", "authority", "authorities", "grants", "privilege", "privileges",
    "acl", "superuser", "root", "roleid", "role_id",
  ];
  for (const name of names) {
    assert.deepEqual(
      detectMassAssignment("POST", "/x", { [name.toUpperCase()]: "x" }).suspiciousFields,
      [name.toUpperCase()],
      `${name} 을 의심 필드명으로 잡지 않았다`
    );
  }
  // 중첩 객체와 배열 안까지.
  assert.deepEqual(
    detectMassAssignment("POST", "/x", { data: { inner: [{ role: "x" }] } }).suspiciousFields,
    ["role"]
  );
  // 같은 이름이 여러 번 나와도 중복 제거한다.
  assert.deepEqual(
    detectMassAssignment("POST", "/x", { role: "a", b: { role: "c" } }).suspiciousFields,
    ["role"]
  );
});

// 값 검사의 핵심 예외: 최상위이면서 화이트리스트에 있는 필드는 값을 보지 않는다 —
// 사용자가 실제로 비밀번호를 "admin" 으로 정한 정상 케이스를 오탐하지 않으려는 것이다.
test("특성화: 화이트리스트 최상위 필드의 값은 검사에서 제외된다", () => {
  const exempt = detectMassAssignment("POST", "/api/Users", { password: "admin" });
  assert.deepEqual(exempt.suspiciousValues, [], "화이트리스트 최상위 필드는 값 검사 제외");
  assert.equal(exempt.hit, false);

  // 같은 필드라도 **중첩된 안쪽** 값은 검사한다.
  const nested = detectMassAssignment("POST", "/api/Users", { securityQuestion: { x: "admin" } });
  assert.deepEqual(nested.suspiciousValues, ["x"]);
  assert.equal(nested.hit, true);

  // 화이트리스트 밖 최상위 필드의 값은 검사한다.
  const outside = detectMassAssignment("POST", "/api/Users", { nickname: "administrator" });
  assert.deepEqual(outside.suspiciousValues, ["nickname"]);
});

test("특성화: 의심 역할 값 7개를 공백·대소문자 무관으로 본다", () => {
  for (const value of ["admin", "administrator", "root", "superadmin",
                       "super_admin", "sysadmin", "owner"]) {
    assert.deepEqual(
      detectMassAssignment("POST", "/api/Users", { nickname: `  ${value.toUpperCase()}  ` }).suspiciousValues,
      ["nickname"],
      `역할 값 ${value} 를 잡지 않았다`
    );
  }
});

test("특성화: 숫자 범위 규칙 네 개와 그 경계값", () => {
  // price >= 0.01
  assert.equal(detectNumericAbuse({ price: 0.01 }).hit, false);
  assert.equal(detectNumericAbuse({ price: 0 }).hit, true);
  assert.equal(detectNumericAbuse({ price: -1 }).hit, true);
  // deluxeprice >= 0 (price 와 다르다)
  assert.equal(detectNumericAbuse({ deluxePrice: 0 }).hit, false);
  assert.equal(detectNumericAbuse({ deluxePrice: -0.01 }).hit, true);
  // quantity 1..100
  assert.equal(detectNumericAbuse({ quantity: 1 }).hit, false);
  assert.equal(detectNumericAbuse({ quantity: 100 }).hit, false);
  assert.equal(detectNumericAbuse({ quantity: 0 }).hit, true);
  assert.equal(detectNumericAbuse({ quantity: 101 }).hit, true);
  // rating 1..5 — 최소값은 0 이 아니라 1 이다
  assert.equal(detectNumericAbuse({ rating: 1 }).hit, false);
  assert.equal(detectNumericAbuse({ rating: 5 }).hit, false);
  assert.equal(detectNumericAbuse({ rating: 0 }).hit, true);
  assert.equal(detectNumericAbuse({ rating: 6 }).hit, true);
});

test("특성화: 숫자 규칙은 최상위만 보고, 키는 소문자로 조회하되 보고는 원본 표기다", () => {
  // 규칙 조회는 소문자. 보고되는 field 는 원본 대소문자를 유지한다.
  const result = detectNumericAbuse({ PRICE: 0 });
  assert.equal(result.hit, true);
  assert.equal(result.violations[0].field, "PRICE");
  assert.deepEqual(result.violations[0].rule, { min: 0.01 });

  // 중첩은 보지 않는다 — 최상위 Object.entries 만 훑는다.
  assert.equal(detectNumericAbuse({ item: { price: 0 } }).hit, false);
  // 배열 본문은 아예 보지 않는다.
  assert.equal(detectNumericAbuse([{ price: 0 }]).hit, false);
});

// Infinity 는 `typeof === 'number' && !Number.isNaN` 가드를 통과하므로 max 를 위반한다.
// NaN 은 통과하지 못한다. 둘을 구별해 고정한다.
test("특성화: Infinity 는 상한을 위반하고 NaN 은 무시된다", () => {
  assert.equal(detectNumericAbuse({ quantity: Number.POSITIVE_INFINITY }).hit, true);
  assert.equal(detectNumericAbuse({ quantity: Number.NEGATIVE_INFINITY }).hit, true);
  assert.equal(detectNumericAbuse({ quantity: Number.NaN }).hit, false);
  assert.equal(detectNumericAbuse({ quantity: "0" }).hit, false, "문자열은 보지 않는다");
});

test("특성화: NoSQL 연산자와 comment-only SQLi 는 설정 없이 동작한다", () => {
  const nosql = detectNoSqlOperatorInjection({ id: { $ne: -1 } });
  assert.equal(nosql.hit, true);
  assert.deepEqual(nosql.paths, ["id.$ne"]);
  assert.deepEqual(detectNoSqlOperatorInjection({ a: [{ $gt: 1 }] }).paths, ["a[0].$gt"]);
  assert.equal(detectNoSqlOperatorInjection({ a: 1 }).hit, false);

  assert.equal(detectCommentOnlySqli("' --"), true);
  assert.equal(detectCommentOnlySqli("'#"), true);
  assert.equal(detectCommentOnlySqli("'/*"), true);
  assert.equal(detectCommentOnlySqli("1=1"), false);
  assert.equal(detectCommentOnlySqli(null), false);
  assert.equal(detectCommentOnlySqli(42), false);
});

test("특성화: 통합 진입점이 네 태그를 모아 돌려준다", () => {
  const tags = analyzeBusinessLogic({
    method: "POST",
    normalizedPath: "/api/Users",
    body: { email: "a@b", role: "admin", rating: 99, id: { $ne: -1 } },
    rawQueryOrBody: "/api/Users?q=' --",
  });
  assert.deepEqual(tags.map((t) => t.tag).sort(), [
    "mass-assignment", "nosql-injection-generalized", "numeric-abuse", "sqli-comment-only",
  ]);

  // 본문이 JSON 문자열이어도 파싱한다. 깨지면 null 로 보고 넘어간다.
  assert.equal(
    analyzeBusinessLogic({ method: "POST", normalizedPath: "/x", body: '{"role":"admin"}' })
      .some((t) => t.tag === "mass-assignment"),
    true
  );
  assert.deepEqual(
    analyzeBusinessLogic({ method: "POST", normalizedPath: "/x", body: "{not json" }),
    []
  );
});

// comment-only SQLi 는 rawQueryOrBody 와 **직렬화한 본문** 양쪽을 본다.
test("특성화: comment-only SQLi 는 본문을 직렬화해서도 본다", () => {
  assert.equal(
    analyzeBusinessLogic({ method: "POST", normalizedPath: "/x", body: { q: "' --" } })
      .some((t) => t.tag === "sqli-comment-only"),
    true
  );
});

// schemaLearning 의 승인 화이트리스트는 **하드코딩이 없을 때만** 쓰인다.
test("특성화: 학습 화이트리스트는 하드코딩이 없는 라우트에만 적용된다", () => {
  schemaLearning.resetAll();
  const learnedRoute = "/api/Learned";

  // 승인 전에는 아무 판단도 하지 않는다.
  assert.deepEqual(detectMassAssignment("POST", learnedRoute, { a: 1, b: 2 }).extraFields, []);

  for (let i = 0; i < 3; i += 1) {
    schemaLearning.observeMassAssignment({
      method: "POST",
      normalizedPath: learnedRoute,
      bodyObj: { a: 1 },
      statusCode: 200,
      hasHardcodedWhitelist: false,
    });
  }
  assert.equal(schemaLearning.approveMassAssignment(`POST ${learnedRoute}`), true);
  assert.deepEqual(detectMassAssignment("POST", learnedRoute, { a: 1, b: 2 }).extraFields, ["b"]);

  // 하드코딩이 있는 라우트는 학습이 끼어들지 않는다.
  assert.equal(hasHardcodedMassAssignmentWhitelist("POST", "/api/Users"), true);
  assert.deepEqual(
    detectMassAssignment("POST", "/api/Users", { email: "a@b", zzz: 1 }).extraFields,
    ["zzz"]
  );
  schemaLearning.resetAll();
});

test("특성화: 본문이 객체가 아니면 아무것도 판정하지 않는다", () => {
  for (const body of [null, undefined, 42, "x", ["a"]]) {
    const result = detectMassAssignment("POST", "/api/Users", body);
    assert.deepEqual(result,
      { hit: false, extraFields: [], suspiciousFields: [], suspiciousValues: [] },
      `본문 ${JSON.stringify(body)} 가 통과했다`);
  }
});

// ---------------------------------------------------------------------------
// 프로파일화 이후
// ---------------------------------------------------------------------------

const GENERIC_PROFILE = profileAt("generic");
const RUBY_PROFILE = profileAt("ruby-shop");

// D3-R: 라우트 무관한 세 판정은 generic·ruby-shop 에도 같은 값으로 들어간다.
// 빠지면 프로파일 없는 대상(legacy/alternate)의 동작이 바뀐다.
test("라우트 무관 판정은 세 프로파일에서 모두 같다", () => {
  for (const profile of [GENERIC_PROFILE, RUBY_PROFILE]) {
    // 의심 필드명 — 라우트와 무관하다.
    assert.deepEqual(
      detectMass("POST", "/anything", { role: "admin" }, profile).suspiciousFields,
      detectMass("POST", "/anything", { role: "admin" }, JUICE_PROFILE).suspiciousFields,
      `${profile.profileId} 의 의심 필드명 판정이 juice-shop 과 다르다`
    );
    // 숫자 범위 — 라우트와 무관하다.
    assert.deepEqual(
      detectNumeric({ quantity: -1 }, profile),
      detectNumeric({ quantity: -1 }, JUICE_PROFILE)
    );
    assert.deepEqual(detectNumeric({ rating: 0 }, profile), detectNumeric({ rating: 0 }, JUICE_PROFILE));
    // 비활성으로 보고되어서는 안 된다.
    for (const feature of ["businessLogic.alwaysSuspiciousFields",
                           "businessLogic.suspiciousRoleValues",
                           "businessLogic.numericFieldRules"]) {
      assert.ok(!profile.disabledFeatures.includes(feature),
        `${profile.profileId} 가 ${feature} 를 비활성으로 선언했다 — 동작이 바뀐다`);
    }
  }
});

// 반대로 라우트별 화이트리스트는 사이트 종속이므로 generic·ruby-shop 에 없다.
test("라우트별 화이트리스트는 generic·ruby-shop 에서 비활성이고 그 사실이 드러난다", () => {
  for (const profile of [GENERIC_PROFILE, RUBY_PROFILE]) {
    assert.equal(hasWhitelist("POST", "/api/Users", profile), false);
    const result = detectMass("POST", "/api/Users", { email: "a@b", zzz: 1 }, profile);
    assert.deepEqual(result.extraFields, [], "화이트리스트가 없으면 판단하지 않는다");
    assert.deepEqual(result.suspiciousValues, [], "값 검사도 화이트리스트가 있을 때만");
    assert.ok(profile.disabledFeatures.includes("businessLogic.massAssignmentWhitelist"),
      `${profile.profileId} 가 massAssignmentWhitelist 비활성을 선언하지 않았다`);
  }
});

test("다른 사이트의 라우트·필드·범위로도 같은 판정이 나온다", () => {
  const otherSite = {
    ...GENERIC_PROFILE,
    businessLogic: {
      massAssignmentWhitelist: [
        { route: "POST /api/auth/register", fields: ["email", "password"] },
      ],
      alwaysSuspiciousFields: ["is_seller", "tier"],
      suspiciousRoleValues: ["seller", "staff"],
      numericFieldRules: [{ field: "amount", min: 1, max: 10 }],
    },
  };

  assert.equal(hasWhitelist("POST", "/api/auth/register", otherSite), true);
  const mass = detectMass("POST", "/api/auth/register",
    { email: "a@b", password: "x", is_seller: true }, otherSite);
  assert.deepEqual(mass.extraFields, ["is_seller"]);
  assert.deepEqual(mass.suspiciousFields, ["is_seller"]);

  // juice-shop 의 의심 필드명·범위는 이 프로파일에서 잡히지 않는다.
  assert.deepEqual(detectMass("POST", "/x", { role: "admin" }, otherSite).suspiciousFields, []);
  assert.equal(detectNumeric({ quantity: -1 }, otherSite).hit, false);
  assert.equal(detectNumeric({ amount: 0 }, otherSite).hit, true);
  assert.equal(detectNumeric({ amount: 11 }, otherSite).hit, true);
  assert.equal(detectNumeric({ amount: 5 }, otherSite).hit, false);
  // 값 검사도 이 사이트의 어휘를 쓴다.
  assert.deepEqual(
    detectMass("POST", "/api/auth/register", { nickname: "SELLER" }, otherSite).suspiciousValues,
    ["nickname"]
  );
});

// NoSQL 연산자와 comment-only SQLi 는 설정을 받지 않으므로 프로파일이 없어도 돈다 —
// 비활성 보고 대상이 아니다.
test("구문 판정 둘은 프로파일과 무관하게 계속 돈다", () => {
  for (const profile of [GENERIC_PROFILE, RUBY_PROFILE, null, undefined, {}]) {
    const tags = analyze({
      method: "POST",
      normalizedPath: "/anything",
      body: { id: { $ne: -1 }, q: "' --" },
      profile,
    }).map((t) => t.tag);
    assert.ok(tags.includes("nosql-injection-generalized"),
      "NoSQL 연산자 판정은 프로파일과 무관해야 한다");
    assert.ok(tags.includes("sqli-comment-only"),
      "comment-only SQLi 판정은 프로파일과 무관해야 한다");
  }
});

test("프로파일에 businessLogic 블록이 아예 없으면 네 판정 중 둘만 돈다", () => {
  const noBlock = { profileId: "x", label: "x", schemaVersion: 1 };
  assert.deepEqual(detectMass("POST", "/api/Users", { role: "admin" }, noBlock),
    { hit: false, extraFields: [], suspiciousFields: [], suspiciousValues: [] });
  assert.deepEqual(detectNumeric({ quantity: -1 }, noBlock), { hit: false, violations: [] });
  assert.equal(hasWhitelist("POST", "/api/Users", noBlock), false);
});
