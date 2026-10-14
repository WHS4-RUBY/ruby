const assert = require("node:assert/strict");
const { after, test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const schemaDir = fs.mkdtempSync(path.join(os.tmpdir(), "characterize-rolegated-"));
process.env.DETECTION_STORE_DB = path.join(schemaDir, "detection.sqlite3");

const {
  checkRoleGatedAccess: checkRoleGated,
  isHardcodedSensitiveRoute: isHardcodedRoute,
} = require("../lib/roleGatedAccess");
const schemaLearning = require("../lib/schemaLearning");
const { loadSiteProfile } = require("../lib/siteProfile");

const profileAt = (id) =>
  loadSiteProfile(path.join(__dirname, "..", "config", "site-profiles", `${id}.json`));

// juice-shop 프로파일을 주입하면 아래 단정은 한 글자도 바뀌지 않고 통과해야 한다.
const JUICE_PROFILE = profileAt("juice-shop");
const checkRoleGatedAccess = (args) => checkRoleGated({ ...args, profile: JUICE_PROFILE });
const isHardcodedSensitiveRoute = (method, route) => isHardcodedRoute(method, route, JUICE_PROFILE);

after(() => fs.rmSync(schemaDir, { recursive: true, force: true }));

/**
 * roleGatedAccess.js 의 특성화 테스트.
 *
 * 이 모듈은 identityMismatch 의 decodeClaimedIdentity/extractToken 을 재export 해서
 * 쓰므로 그 모듈의 JWT 셰이프에 간접 결합돼 있다 — 두 모듈을 연속한 커밋으로 푼다.
 */

function token(payload) {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "none", typ: "JWT" })}.${encode(payload)}.`;
}

const SEVEN_ROUTES = [
  ["role-gated:admin-config", "GET", "/rest/admin/application-configuration"],
  ["role-gated:admin-version", "GET", "/rest/admin/application-version"],
  ["role-gated:metrics", "GET", "/metrics"],
  ["role-gated:user-list", "GET", "/api/Users"],
  ["role-gated:product-write", "PUT", "/api/Products/:id"],
  ["role-gated:product-create", "POST", "/api/Products"],
  ["role-gated:product-delete", "DELETE", "/api/Products/:id"],
];

test("특성화: 민감 라우트 일곱 개가 등록돼 있고 admin 만 통과한다", () => {
  const adminAuth = `Bearer ${token({ data: { id: 1, role: "admin" } })}`;
  const customerAuth = `Bearer ${token({ data: { id: 7, role: "customer" } })}`;

  for (const [tag, method, normalizedPath] of SEVEN_ROUTES) {
    assert.equal(isHardcodedSensitiveRoute(method, normalizedPath), true,
      `${method} ${normalizedPath} 가 민감 라우트에 없다`);

    // admin 은 통과한다.
    assert.deepEqual(
      checkRoleGatedAccess({ method, normalizedPath, authorizationHeader: adminAuth }),
      [], `${tag} 에서 admin 이 막혔다`);

    // 다른 역할은 막힌다.
    const denied = checkRoleGatedAccess({ method, normalizedPath, authorizationHeader: customerAuth });
    assert.equal(denied.length, 1, tag);
    assert.equal(denied[0].tag, tag);
    assert.deepEqual(denied[0].detail,
      { requiredRoles: ["admin"], claimedRole: "customer", hasToken: true });
  }
});

test("특성화: 토큰이 없으면 hasToken:false 로 막힌다", () => {
  const hits = checkRoleGatedAccess({ method: "GET", normalizedPath: "/metrics" });
  assert.equal(hits.length, 1);
  assert.deepEqual(hits[0].detail,
    { requiredRoles: ["admin"], claimedRole: null, hasToken: false });

  // 토큰이 있지만 해독되지 않으면 hasToken:true, claimedRole:null 이다.
  const undecodable = checkRoleGatedAccess({
    method: "GET", normalizedPath: "/metrics", authorizationHeader: "Bearer notajwt",
  });
  assert.deepEqual(undecodable[0].detail,
    { requiredRoles: ["admin"], claimedRole: null, hasToken: true });
});

// 역할 비교는 소문자로 하지만 **trim 을 하지 않는다** — "ADMIN" 은 통과하고
// "Admin " 은 막힌다. 고쳐야 할 것처럼 보이지만 지금 동작이다.
test("특성화: 역할은 소문자로 비교하되 공백은 떼지 않는다", () => {
  const route = { method: "GET", normalizedPath: "/metrics" };
  for (const role of ["admin", "ADMIN", "Admin"]) {
    assert.deepEqual(
      checkRoleGatedAccess({ ...route, authorizationHeader: `Bearer ${token({ data: { role } })}` }),
      [], `역할 ${JSON.stringify(role)} 이 막혔다`);
  }
  for (const role of ["Admin ", " admin", "admin\t"]) {
    assert.equal(
      checkRoleGatedAccess({ ...route,
        authorizationHeader: `Bearer ${token({ data: { role } })}` }).length,
      1, `역할 ${JSON.stringify(role)} 이 통과했다`);
  }
});

// 빈 문자열 역할은 falsy 라 claimedRole 이 null 이 된다(`claimed.role ? ... : null`).
test("특성화: 빈 문자열 역할은 역할 없음으로 취급된다", () => {
  const hits = checkRoleGatedAccess({
    method: "GET", normalizedPath: "/metrics",
    authorizationHeader: `Bearer ${token({ data: { role: "" } })}`,
  });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].detail.claimedRole, null);
  assert.equal(hits[0].detail.hasToken, true);
});

test("특성화: 민감 라우트가 아니면 아무것도 보지 않는다", () => {
  const customerAuth = `Bearer ${token({ data: { role: "customer" } })}`;
  for (const [method, normalizedPath] of [
    ["GET", "/rest/admin/application-configuration/"],  // 뒤 슬래시는 엄격 비교로 불일치
    ["POST", "/metrics"],
    ["GET", "/api/Products"],                            // POST 만 민감하다
    ["GET", "/api/Products/:id"],                        // PUT/DELETE 만 민감하다
    ["GET", "/"],
  ]) {
    assert.deepEqual(
      checkRoleGatedAccess({ method, normalizedPath, authorizationHeader: customerAuth }),
      [], `${method} ${normalizedPath} 가 민감 라우트로 잡혔다`);
    assert.equal(isHardcodedSensitiveRoute(method, normalizedPath), false,
      `${method} ${normalizedPath} 가 하드코딩 라우트로 잡혔다`);
  }
});

test("특성화: 메서드 대소문자는 무관하다", () => {
  const customerAuth = `Bearer ${token({ data: { role: "customer" } })}`;
  assert.equal(
    checkRoleGatedAccess({ method: "get", normalizedPath: "/metrics",
                           authorizationHeader: customerAuth }).length,
    1
  );
  assert.equal(isHardcodedSensitiveRoute("get", "/metrics"), true);
});

test("특성화: 쿠키로 들어온 토큰도 같은 판정을 받는다", () => {
  assert.deepEqual(
    checkRoleGatedAccess({ method: "GET", normalizedPath: "/metrics",
                           cookieHeader: `token=${token({ data: { role: "admin" } })}` }),
    []
  );
});

// 학습된 민감 라우트는 하드코딩 매치가 **하나도 없을 때만** 확인한다.
test("특성화: 학습 민감 라우트는 하드코딩 매치가 없을 때만 본다", () => {
  schemaLearning.resetAll();
  const customerAuth = `Bearer ${token({ data: { role: "customer" } })}`;
  const learned = "/api/Reports";

  assert.deepEqual(
    checkRoleGatedAccess({ method: "GET", normalizedPath: learned,
                           authorizationHeader: customerAuth }),
    [], "승인 전에는 아무것도 하지 않는다"
  );

  for (let i = 0; i < 3; i += 1) {
    schemaLearning.observeRoleAccess({
      method: "GET", normalizedPath: learned, role: "admin", statusCode: 200,
      hasHardcodedRule: false,
    });
  }
  schemaLearning.observeRoleAccess({
    method: "GET", normalizedPath: learned, role: "customer", statusCode: 403,
    hasHardcodedRule: false,
  });
  assert.equal(schemaLearning.approveRoleGated(`GET ${learned}`), true);

  const hits = checkRoleGatedAccess({ method: "GET", normalizedPath: learned,
                                      authorizationHeader: customerAuth });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].tag, "role-gated:learned");
  assert.equal(hits[0].detail.source, "schemaLearning");
  // 승인 시 역할을 명시하지 않으면 기본이 ['admin'] 이다(schemaLearning.js).
  assert.deepEqual(hits[0].detail.requiredRoles, ["admin"]);

  // 하드코딩 라우트에서는 학습 태그가 나오지 않는다.
  const hardcoded = checkRoleGatedAccess({ method: "GET", normalizedPath: "/metrics",
                                           authorizationHeader: customerAuth });
  assert.deepEqual(hardcoded.map((h) => h.tag), ["role-gated:metrics"]);
  schemaLearning.resetAll();
});

// ---------------------------------------------------------------------------
// 프로파일화 이후
// ---------------------------------------------------------------------------

const GENERIC_PROFILE = profileAt("generic");
const RUBY_PROFILE = profileAt("ruby-shop");

test("다른 사이트의 민감 라우트와 역할 이름으로도 같은 판정이 나온다", () => {
  const otherSite = {
    ...GENERIC_PROFILE,
    roleGated: {
      sensitiveRoutes: [
        { tag: "role-gated:admin-users", method: "GET", normalizedPath: "/api/admin/users",
          requiredRoles: ["administrator"] },
        { tag: "role-gated:role-change", method: "PUT",
          normalizedPath: "/api/admin/users/:id/role", requiredRoles: ["administrator", "owner"] },
      ],
    },
  };

  const call = (method, normalizedPath, role) => checkRoleGated({
    method, normalizedPath, profile: otherSite,
    authorizationHeader: `Bearer ${token({ data: { role } })}`,
  });

  assert.deepEqual(call("GET", "/api/admin/users", "administrator"), []);
  const denied = call("GET", "/api/admin/users", "admin");
  assert.equal(denied.length, 1, "juice-shop 의 admin 은 이 사이트에서 통과하지 않는다");
  assert.deepEqual(denied[0].detail.requiredRoles, ["administrator"]);

  // 여러 역할을 허용하는 라우트.
  for (const role of ["administrator", "owner"]) {
    assert.deepEqual(call("PUT", "/api/admin/users/:id/role", role), [], role);
  }
  assert.equal(call("PUT", "/api/admin/users/:id/role", "seller").length, 1);

  // juice-shop 의 민감 라우트는 이 프로파일에서 민감하지 않다.
  assert.deepEqual(call("GET", "/metrics", "seller"), []);
  assert.equal(isHardcodedRoute("GET", "/metrics", otherSite), false);
  assert.equal(isHardcodedRoute("GET", "/api/admin/users", otherSite), true);
});

// ruby-shop 은 main.py 에서 근거를 찾은 민감 라우트와 역할 이름(admin, support_staff,
// seller_staff)을 선언한다. 단, 실제 세션 토큰이 JWT 가 아니라서 이 선언이 운영에서
// 판정까지 이어지는지는 별개다(ruby-shop.json 의 _note 참고) — 여기서는 선언 자체만 고정한다.
test("ruby-shop 의 민감 라우트는 선언돼 있고 juice-shop 라우트는 섞이지 않는다", () => {
  assert.ok(!RUBY_PROFILE.disabledFeatures.includes("roleGated"),
    "ruby-shop 이 roleGated 를 비활성으로 선언했다");

  const routes = RUBY_PROFILE.roleGated.sensitiveRoutes;
  assert.ok(routes.length > 0);
  for (const { method, normalizedPath } of routes) {
    assert.equal(isHardcodedRoute(method, normalizedPath, RUBY_PROFILE), true,
      `${method} ${normalizedPath} 가 민감 라우트로 인식되지 않는다`);
  }

  // 역할 이름은 소문자로 선언돼야 한다(비교가 소문자 기준이다).
  for (const { requiredRoles } of routes) {
    for (const role of requiredRoles) assert.equal(role, role.toLowerCase());
  }

  // juice-shop 의 일곱 라우트는 RUBY 에서 민감하지 않다.
  const customerAuth = `Bearer ${token({ data: { role: "customer" } })}`;
  for (const [, method, normalizedPath] of SEVEN_ROUTES) {
    assert.equal(isHardcodedRoute(method, normalizedPath, RUBY_PROFILE), false,
      `${method} ${normalizedPath} 가 RUBY 에서 민감 라우트로 잡혔다`);
    assert.deepEqual(
      checkRoleGated({ method, normalizedPath, authorizationHeader: customerAuth,
                       profile: RUBY_PROFILE }),
      [], `ruby-shop 의 ${method} ${normalizedPath} 에서 태그가 나왔다`);
  }
});

// 규칙 3: generic 은 사이트별 역할 이름(admin? ADMIN? administrator?)을 알 수 없어
// 이 블록을 비워 둔다. 역할 이름을 틀리면 모든 관리자 요청을 오탐하거나 모든 침입을
// 미탐한다.
test("프로파일에 설정이 없으면 비활성이고 학습 폴백만 남는다", () => {
  const customerAuth = `Bearer ${token({ data: { role: "customer" } })}`;
  for (const profile of [GENERIC_PROFILE]) {
    for (const [, method, normalizedPath] of SEVEN_ROUTES) {
      assert.deepEqual(
        checkRoleGated({ method, normalizedPath, authorizationHeader: customerAuth, profile }),
        [], `${profile.profileId} 의 ${method} ${normalizedPath} 에서 태그가 나왔다`);
      assert.equal(isHardcodedRoute(method, normalizedPath, profile), false);
    }
    assert.ok(profile.disabledFeatures.includes("roleGated"),
      `${profile.profileId} 가 roleGated 비활성을 선언하지 않았다`);
  }
});

// identity 설정이 없으면 역할을 알 수 없으므로 이 검사 자체가 성립하지 않는다.
test("identity 설정이 없으면 민감 라우트가 있어도 판정하지 않는다", () => {
  const noIdentity = {
    profileId: "x", label: "x", schemaVersion: 1,
    roleGated: { sensitiveRoutes: [
      { tag: "role-gated:x", method: "GET", normalizedPath: "/metrics", requiredRoles: ["admin"] },
    ] },
  };
  assert.deepEqual(
    checkRoleGated({ method: "GET", normalizedPath: "/metrics", profile: noIdentity }),
    []
  );
});

test("프로파일이 아예 없으면 던지지 않고 비어 있다", () => {
  for (const profile of [null, undefined, {}, { roleGated: null }]) {
    assert.deepEqual(
      checkRoleGated({ method: "GET", normalizedPath: "/metrics", profile }), []);
    assert.equal(isHardcodedRoute("GET", "/metrics", profile), false);
  }
});