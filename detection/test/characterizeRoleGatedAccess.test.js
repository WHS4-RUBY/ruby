const assert = require("node:assert/strict");
const { after, test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const schemaDir = fs.mkdtempSync(path.join(os.tmpdir(), "characterize-rolegated-"));
process.env.DETECTION_STORE_DB = path.join(schemaDir, "detection.sqlite3");

const {
  checkRoleGatedAccess: checkRoleGated,
  isHardcodedSensitiveRoute,
} = require("../lib/roleGatedAccess");
const schemaLearning = require("../lib/schemaLearning");
const { loadSiteProfile } = require("../lib/siteProfile");

const profileAt = (id) =>
  loadSiteProfile(path.join(__dirname, "..", "config", "site-profiles", `${id}.json`));

// juice-shop 프로파일을 주입하면 아래 단정은 한 글자도 바뀌지 않고 통과해야 한다.
const JUICE_PROFILE = profileAt("juice-shop");
const checkRoleGatedAccess = (args) => checkRoleGated({ ...args, profile: JUICE_PROFILE });

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
