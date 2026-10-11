const assert = require("node:assert/strict");
const { after, test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const schemaDir = fs.mkdtempSync(path.join(os.tmpdir(), "cross-site-"));
process.env.DETECTION_STORE_DB = path.join(schemaDir, "detection.sqlite3");

const { analyzeBusinessLogic } = require("../lib/businessLogicSignatures");
const { checkIdentityMismatch } = require("../lib/identityMismatch");
const { checkRoleGatedAccess } = require("../lib/roleGatedAccess");
const { extractLoginAttemptEmail } = require("../lib/loginBruteForce");
const { extractResetPasswordEmail } = require("../lib/passwordResetAbuse");
const { detectPriceTampering } = require("../lib/priceTampering");
const {
  checkPriceDelta, ingestProductResponseBody, resetPriceCache,
} = require("../lib/priceIntegrity");
const { loadSiteProfile, validateSiteProfile } = require("../lib/siteProfile");

after(() => fs.rmSync(schemaDir, { recursive: true, force: true }));

/**
 * 프로파일 계약 테스트 — "프로파일만 갈아끼우면 같은 공격이 잡힌다" 를 증명한다.
 *
 * 같은 **공격 의도**를 두 사이트의 어휘로 각각 표현하고, 두 프로파일에서 나오는
 * 태그 집합이 같은지 본다. 라우트·필드명·쿠키명·JWT 클레임·응답 엔벌로프가 전부
 * 다른데도 결과가 같아야 한다.
 *
 * 왜 출하된 ruby-shop 프로파일을 쓰지 않는가: 그 프로파일은 저장소에 근거가 없는
 * 블록을 **일부러 비워 두었다**(JWT 클레임 맵, 역할 이름, 응답 엔벌로프 등). 그래서
 * 교차 증명에는 쓸 수 없다. 대신 같은 기능을 전부 다른 어휘로 선언한 합성 프로파일을
 * 만들어 쓴다 — 이것이 "새 사이트를 붙이면 어떻게 되는가" 의 정확한 모사다.
 *
 * 컨테이너가 필요 없어 `npm test` 안에서 돈다. 한계: 실제 앱의 응답 본문 세이프는
 * 검증하지 않는다(그건 대상 앱이 있어야 한다).
 */

const JUICE = loadSiteProfile(
  path.join(__dirname, "..", "config", "site-profiles", "juice-shop.json")
);

// 같은 기능을 전부 다른 어휘로 선언한 두 번째 사이트. 라우트 접두어, 본문 필드명,
// 쿠키 이름, JWT 래퍼·클레임 키, 응답 엔벌로프, 역할 이름이 모두 juice-shop 과 다르다.
const OTHER = validateSiteProfile({
  schemaVersion: 1,
  profileId: "other-shop",
  label: "Other Shop",
  _note: "교차 증명용 합성 프로파일. 출하되지 않는다.",
  _needsConfirmation: [],
  deception: {
    loginPath: "/v2/session",
    apiPathPrefixes: ["/v2/"],
    plaintextBaitPaths: ["/robots.txt"],
    frontendFlavor: "fetch",
  },
  loginBruteForce: {
    route: { method: "POST", normalizedPath: "/v2/session" },
    emailField: "login_id",
  },
  passwordResetAbuse: {
    resetRoute: { method: "POST", normalizedPath: "/v2/session/recover" },
    resetEmailField: "login_id",
  },
  priceTampering: {
    quantityFields: ["count"],
    unitPriceFields: ["unit_cost"],
    totalFields: ["line_sum"],
    amountTolerance: 0.01,
  },
  priceIntegrity: {
    listRoute: "/v2/catalog",
    itemRoute: "/v2/catalog/:id",
    priceDropRatio: 0.5,
    idField: "sku",
    priceField: "unit_cost",
    responseEnvelope: { itemsKey: "items", bareObjectHasField: "sku" },
  },
  businessLogic: {
    // 두 프로파일의 **커버리지가 같아야** 교차 증명이 코드를 재는 테스트가 된다.
    // 처음에는 리뷰 라우트의 화이트리스트를 빼먹었는데, juice-shop 에는 있어서
    // "리뷰 본문에 타인 소유자 ID" 시나리오가 한쪽에서만 mass-assignment 를 냈다 —
    // 테스트가 프로파일 커버리지 비대칭을 잡아낸 것이다.
    massAssignmentWhitelist: [
      { route: "POST /v2/members", fields: ["login_id", "secret"] },
      { route: "POST /v2/reviews", fields: ["body"] },
    ],
    alwaysSuspiciousFields: JUICE.businessLogic.alwaysSuspiciousFields,
    suspiciousRoleValues: ["operator"],
    numericFieldRules: [{ field: "unit_cost", min: 0.01 }],
  },
  identity: {
    tokenSources: { bearer: false, cookieNames: ["os_session"] },
    claimMap: {
      wrapperKey: "",
      id: "sub",
      email: "mail",
      role: "scope",
      basketId: { at: "root", key: "cart" },
    },
    learnedFallback: true,
    routeRules: [
      { tag: "identity-mismatch:basket", normalizedPath: "/v2/cart/:id", claimField: "bid" },
      { tag: "identity-mismatch:user", normalizedPath: "/v2/members/:id", claimField: "id" },
    ],
    bodyRules: [
      { tag: "identity-mismatch:feedback-userid", method: "POST",
        normalizedPath: "/v2/reviews", field: "owner_id", claimField: "id" },
    ],
    queryRules: [
      { tag: "identity-mismatch:baskets-query", method: "GET",
        normalizedPath: "/v2/carts", field: "owner_id", claimField: "id" },
    ],
  },
  roleGated: {
    sensitiveRoutes: [
      { tag: "role-gated:admin-config", method: "GET",
        normalizedPath: "/v2/ops/settings", requiredRoles: ["operator"] },
      { tag: "role-gated:user-list", method: "GET",
        normalizedPath: "/v2/members", requiredRoles: ["operator"] },
      { tag: "role-gated:product-write", method: "PUT",
        normalizedPath: "/v2/catalog/:id", requiredRoles: ["operator"] },
    ],
  },
}, { source: "other-shop (synthetic)" });

/** 두 사이트의 같은 개념을 짝지은 어휘표. */
const VOCABULARY = {
  "juice-shop": {
    profile: JUICE,
    login: "/rest/user/login",
    reset: "/rest/user/reset-password",
    emailField: "email",
    basket: "/rest/basket/:id",
    user: "/api/Users/:id",
    reviewPost: "/api/Feedbacks",
    cartQuery: "/api/Baskets",
    ownerField: "UserId",
    adminConfig: "/rest/admin/application-configuration",
    userList: "/api/Users",
    productItem: "/api/Products/:id",
    productList: "/api/Products",
    memberCreate: "/api/Users",
    memberFields: { email: "a@b", password: "x" },
    priceField: "price",
    role: "admin",
    cookie: "token",
    claim: (id, bid, role) => ({ data: { id, email: "a@b", role }, bid }),
    envelope: (sku, price) => ({ status: "success", data: [{ id: sku, price }] }),
    quantityBody: { quantity: 2, price: 10, total: 5 },
  },
  "other-shop": {
    profile: OTHER,
    login: "/v2/session",
    reset: "/v2/session/recover",
    emailField: "login_id",
    basket: "/v2/cart/:id",
    user: "/v2/members/:id",
    reviewPost: "/v2/reviews",
    cartQuery: "/v2/carts",
    ownerField: "owner_id",
    adminConfig: "/v2/ops/settings",
    userList: "/v2/members",
    productItem: "/v2/catalog/:id",
    productList: "/v2/catalog",
    memberCreate: "/v2/members",
    memberFields: { login_id: "a@b", secret: "x" },
    priceField: "unit_cost",
    role: "operator",
    cookie: "os_session",
    claim: (id, cart, scope) => ({ sub: id, mail: "a@b", scope, cart }),
    envelope: (sku, price) => ({ items: [{ sku, unit_cost: price }] }),
    quantityBody: { count: 2, unit_cost: 10, line_sum: 5 },
  },
};

const SITES = Object.keys(VOCABULARY);

function jwt(payload) {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "none", typ: "JWT" })}.${encode(payload)}.`;
}

/** server.js 의 computeBusinessLogicTags 와 같은 순서로 태그를 모은다. */
function tagsFor(site, request) {
  const v = VOCABULARY[site];
  const { profile } = v;
  const hits = [
    ...analyzeBusinessLogic({
      method: request.method,
      normalizedPath: request.normalizedPath,
      body: request.body,
      rawQueryOrBody: request.url,
      profile,
    }),
    ...checkIdentityMismatch({
      method: request.method,
      normalizedPath: request.normalizedPath,
      url: request.url,
      body: request.body,
      cookieHeader: request.cookieHeader,
      profile,
    }),
    ...checkRoleGatedAccess({
      method: request.method,
      normalizedPath: request.normalizedPath,
      cookieHeader: request.cookieHeader,
      profile,
    }),
  ].map((hit) => hit.tag);
  if (detectPriceTampering(request.body, profile).hit) hits.push("price-tampering:total-mismatch");
  return [...new Set(hits)].sort();
}

/** 각 사이트 어휘로 같은 공격 의도를 표현하는 시나리오. */
const SCENARIOS = {
  "타인 바스켓 열람 (IDOR)": (v) => ({
    method: "GET",
    normalizedPath: v.basket,
    url: v.basket.replace(":id", "99"),
    cookieHeader: `${v.cookie}=${jwt(v.claim(7, 12, "customer"))}`,
  }),
  "타인 계정 열람 (IDOR)": (v) => ({
    method: "GET",
    normalizedPath: v.user,
    url: v.user.replace(":id", "99"),
    cookieHeader: `${v.cookie}=${jwt(v.claim(7, 12, "customer"))}`,
  }),
  "리뷰 본문에 타인 소유자 ID": (v) => ({
    method: "POST",
    normalizedPath: v.reviewPost,
    url: v.reviewPost,
    body: { [v.ownerField]: 99 },
    cookieHeader: `${v.cookie}=${jwt(v.claim(7, 12, "customer"))}`,
  }),
  "쿼리로 타인 바스켓 목록": (v) => ({
    method: "GET",
    normalizedPath: v.cartQuery,
    url: `${v.cartQuery}?${v.ownerField}=99`,
    cookieHeader: `${v.cookie}=${jwt(v.claim(7, 12, "customer"))}`,
  }),
  "비관리자의 관리 설정 열람": (v) => ({
    method: "GET",
    normalizedPath: v.adminConfig,
    url: v.adminConfig,
    cookieHeader: `${v.cookie}=${jwt(v.claim(7, 12, "customer"))}`,
  }),
  "비관리자의 사용자 목록 열람": (v) => ({
    method: "GET",
    normalizedPath: v.userList,
    url: v.userList,
    cookieHeader: `${v.cookie}=${jwt(v.claim(7, 12, "customer"))}`,
  }),
  "토큰 없이 관리 설정 열람": (v) => ({
    method: "GET",
    normalizedPath: v.adminConfig,
    url: v.adminConfig,
  }),
  "회원가입에 권한 필드 끼워넣기": (v) => ({
    method: "POST",
    normalizedPath: v.memberCreate,
    url: v.memberCreate,
    body: { ...v.memberFields, role: "admin" },
  }),
  "가격을 범위 밖으로": (v) => ({
    method: "PUT",
    normalizedPath: v.productItem,
    url: v.productItem.replace(":id", "1"),
    body: { [v.priceField]: 0 },
    cookieHeader: `${v.cookie}=${jwt(v.claim(1, 1, v.role))}`,
  }),
  "요청 내부 총액 불일치": (v) => ({
    method: "POST",
    normalizedPath: "/anything",
    url: "/anything",
    body: v.quantityBody,
  }),
  "NoSQL 연산자 주입 (사이트 무관)": (v) => ({
    method: "PATCH",
    normalizedPath: "/anything",
    url: "/anything",
    body: { id: { $ne: -1 } },
  }),
  "정상 요청 (본인 바스켓)": (v) => ({
    method: "GET",
    normalizedPath: v.basket,
    url: v.basket.replace(":id", "12"),
    cookieHeader: `${v.cookie}=${jwt(v.claim(7, 12, "customer"))}`,
  }),
};

// ---------------------------------------------------------------------------

test("합성 두 번째 사이트 프로파일이 스키마 검증을 통과한다", () => {
  assert.equal(OTHER.profileId, "other-shop");
  assert.deepEqual(OTHER.disabledFeatures, [],
    "교차 증명에는 모든 기능이 설정된 프로파일이 필요하다");
  // 두 프로파일의 어휘가 실제로 겹치지 않는지 — 겹치면 교차 증명이 의미가 없다.
  assert.notEqual(OTHER.deception.loginPath, JUICE.deception.loginPath);
  assert.notEqual(OTHER.loginBruteForce.emailField, JUICE.loginBruteForce.emailField);
  assert.notDeepEqual(OTHER.identity.tokenSources.cookieNames,
    JUICE.identity.tokenSources.cookieNames);
  assert.notEqual(OTHER.identity.claimMap.id, JUICE.identity.claimMap.id);
  assert.notEqual(OTHER.priceIntegrity.responseEnvelope.itemsKey,
    JUICE.priceIntegrity.responseEnvelope.itemsKey);
  assert.notEqual(OTHER.roleGated.sensitiveRoutes[0].requiredRoles[0],
    JUICE.roleGated.sensitiveRoutes[0].requiredRoles[0]);
});

test("같은 공격 의도가 두 사이트에서 같은 태그 집합으로 잡힌다", () => {
  for (const [name, build] of Object.entries(SCENARIOS)) {
    const perSite = SITES.map((site) => tagsFor(site, build(VOCABULARY[site])));
    assert.deepEqual(perSite[1], perSite[0],
      `"${name}" 의 태그가 두 사이트에서 다르다: ` +
      `${SITES[0]}=[${perSite[0]}] vs ${SITES[1]}=[${perSite[1]}]`);
  }
});

// 위 테스트는 "둘 다 빈 집합" 으로도 통과할 수 있다. 공격 시나리오가 실제로 뭔가를
// 잡고 정상 시나리오는 잡지 않는지 따로 단정한다 — 그래야 교차 증명이 비어 있지 않다.
test("공격 시나리오는 태그를 내고 정상 요청은 내지 않는다", () => {
  for (const site of SITES) {
    for (const [name, build] of Object.entries(SCENARIOS)) {
      const tags = tagsFor(site, build(VOCABULARY[site]));
      if (name.startsWith("정상 요청")) {
        assert.deepEqual(tags, [], `${site}: "${name}" 이 태그를 냈다`);
      } else {
        assert.ok(tags.length > 0, `${site}: "${name}" 이 아무 태그도 내지 않았다`);
      }
    }
  }
});

test("로그인·비밀번호 재설정 이메일 추출이 두 사이트에서 같다", () => {
  for (const site of SITES) {
    const v = VOCABULARY[site];
    assert.equal(
      extractLoginAttemptEmail({
        method: "POST", normalizedPath: v.login,
        body: { [v.emailField]: "  Victim@Example.Test " }, profile: v.profile,
      }),
      "victim@example.test", `${site} 로그인 이메일`);
    assert.equal(
      extractResetPasswordEmail({
        method: "POST", normalizedPath: v.reset,
        body: { [v.emailField]: "  Victim@Example.Test " }, profile: v.profile,
      }),
      "victim@example.test", `${site} 재설정 이메일`);
    // 다른 사이트의 라우트·필드명으로는 잡히지 않는다.
    const other = VOCABULARY[SITES.find((s) => s !== site)];
    assert.equal(
      extractLoginAttemptEmail({
        method: "POST", normalizedPath: other.login,
        body: { [other.emailField]: "x@y" }, profile: v.profile,
      }),
      null, `${site} 가 다른 사이트의 로그인 경로를 잡았다`);
  }
});

test("가격 급락 탐지가 두 사이트에서 같다", () => {
  for (const site of SITES) {
    const v = VOCABULARY[site];
    resetPriceCache();
    // 각 사이트의 응답 엔벌로프로 관찰가를 심는다.
    ingestProductResponseBody(v.envelope(1, 100), v.profile, site);
    assert.deepEqual(
      checkPriceDelta(1, 20, v.profile, site),
      { hit: true, observed: 100, submitted: 20, dropRatio: 0.2 },
      `${site} 가격 급락`);
    assert.equal(checkPriceDelta(1, 90, v.profile, site).hit, false, `${site} 정상 할인`);
    // 다른 사이트의 엔벌로프로는 관찰가가 심기지 않는다.
    const other = VOCABULARY[SITES.find((s) => s !== site)];
    resetPriceCache();
    ingestProductResponseBody(other.envelope(1, 100), v.profile, site);
    assert.deepEqual(checkPriceDelta(1, 20, v.profile, site), { hit: false },
      `${site} 가 다른 사이트의 엔벌로프를 읽었다`);
  }
});

// 위 테스트들은 모듈을 직접 부른다. server.js 가 실제로 프로파일을 모든 모듈에
// 넘기는지는 소스에서 확인한다 — 배선이 빠지면 교차 증명이 통과하는데 운영은
// 프로파일 없이 도는 상태가 된다.
test("server.js 가 일곱 모듈 전부에 프로파일을 넘긴다", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "server.js"), "utf8");
  const wiring = [
    [/analyzeBusinessLogic\(\{[^}]*profile: req\.siteProfile/s, "analyzeBusinessLogic"],
    [/checkIdentityMismatch\(\{[^}]*profile: req\.siteProfile/s, "checkIdentityMismatch"],
    [/checkRoleGatedAccess\(\{[^}]*profile: req\.siteProfile/s, "checkRoleGatedAccess"],
    [/extractLoginAttemptEmail\(\{[^}]*profile: req\.siteProfile/s, "extractLoginAttemptEmail"],
    [/extractResetPasswordEmail\(\{[^}]*profile: req\.siteProfile/s, "extractResetPasswordEmail"],
    [/extractSecurityQuestionEmail\(\{[^}]*profile: req\.siteProfile/s, "extractSecurityQuestionEmail"],
    [/detectPriceTampering\(req\.body, req\.siteProfile\)/, "detectPriceTampering"],
    [/checkPriceDelta\([^)]*req\.siteProfile/s, "checkPriceDelta"],
    [/ingestProductResponseBody\([^;]*req\.siteProfile/s, "ingestProductResponseBody"],
    [/hasHardcodedMassAssignmentWhitelist\([^)]*req\.siteProfile/s, "hasHardcodedMassAssignmentWhitelist"],
    [/isHardcodedSensitiveRoute\([^)]*req\.siteProfile/s, "isHardcodedSensitiveRoute"],
    [/inspectRequest\(\{[^}]*profile: req\.siteProfile/s, "deceptionEngine.inspectRequest"],
    [/matchTrap\(\{[^}]*profile: req\.siteProfile/s, "deceptionEngine.matchTrap"],
    [/injectSignalsJs\([^;]*req\.siteProfile/s, "deceptionEngine.injectSignalsJs"],
  ];
  for (const [pattern, name] of wiring) {
    assert.match(source, pattern, `server.js 가 ${name} 에 프로파일을 넘기지 않는다`);
  }
  // 프로파일은 활성 대상이 정해진 직후에 붙어야 한다.
  assert.match(source, /req\.activeTarget = targetSelection\.read\(\);[\s\S]{0,400}?req\.siteProfile =/);
});
