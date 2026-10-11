const assert = require("node:assert/strict");
const test = require("node:test");

const fs = require("node:fs");
const nodePath = require("node:path");

const { detectMassAssignment } = require("../lib/businessLogicSignatures");
const { checkIdentityMismatch } = require("../lib/identityMismatch");
const { loadSiteProfile } = require("../lib/siteProfile");

// 같은 라우트를 두 번 적던 자리들. 한쪽만 고치면 조용히 어긋나므로 정본을 하나로
// 모았고, 이 테스트가 다시 늘어나는 것을 막는다.
//
// 화이트리스트가 모듈 상수에서 사이트 프로파일로 옮겨갔으므로, 한 상수가 아니라
// **출하된 프로파일 전부**를 돈다 — 새 프로파일이 중복을 들여오는 것도 막힌다.
const PROFILES_DIR = nodePath.join(__dirname, "..", "config", "site-profiles");
const PROFILES = fs.readdirSync(PROFILES_DIR)
  .filter((name) => name.endsWith(".json"))
  .map((name) => loadSiteProfile(nodePath.join(PROFILES_DIR, name)));

test("어느 프로파일도 화이트리스트에 뒤 슬래시 변종을 따로 나열하지 않는다", () => {
  let checked = 0;
  for (const profile of PROFILES) {
    const whitelist = profile.businessLogic?.massAssignmentWhitelist;
    if (!whitelist) continue;
    checked += 1;
    for (const entry of whitelist) {
      assert.equal(entry.route.endsWith("/"), false, `${profile.profileId}: ${entry.route}`);
    }
    // 같은 라우트를 두 번 적어 둔 항목이 없어야 한다(siteProfile.js 검증기도 막는다).
    const routes = whitelist.map((entry) => entry.route);
    assert.equal(new Set(routes).size, routes.length, `${profile.profileId} 에 중복 라우트가 있다`);
    // 같은 필드 집합을 두 라우트에 적어 둔 항목이 없어야 한다.
    const seen = new Map();
    for (const entry of whitelist) {
      const signature = [...entry.fields].sort().join(",");
      const previous = seen.get(signature);
      assert.equal(previous, undefined,
        `${profile.profileId}: ${entry.route} 와 ${previous} 가 같은 필드 집합을 중복 선언한다`);
      seen.set(signature, entry.route);
    }
  }
  assert.ok(checked > 0, "화이트리스트를 가진 프로파일이 하나도 없다 — 테스트가 비었다");
});

test("뒤 슬래시가 붙어도 같은 라우트로 판정한다", () => {
  const juice = PROFILES.find((profile) => profile.profileId === "juice-shop");
  const body = { email: "a@b.c", role: "admin" };
  for (const route of juice.businessLogic.massAssignmentWhitelist.map((e) => e.route)) {
    const [method, path] = route.split(" ");
    const bare = detectMassAssignment(method, path, body, juice);
    const slashed = detectMassAssignment(method, `${path}/`, body, juice);
    assert.deepEqual(slashed.extraFields, bare.extraFields, route);
    assert.deepEqual(slashed.suspiciousFields, bare.suspiciousFields, route);
    assert.deepEqual(slashed.suspiciousValues, bare.suspiciousValues, route);
  }
});

test("신원 규칙은 라우트를 한 번만 적고 추출 정규식을 거기서 만든다", () => {
  // 규칙이 프로파일 선언으로 옮겨갔다. 선언한 템플릿 하나에서 추출 정규식이 만들어지는지
  // 실제 판정으로 확인한다 — 두 번 적을 자리가 구조적으로 없어졌다.
  const juice = PROFILES.find((profile) => profile.profileId === "juice-shop");
  const rules = juice.identity.routeRules;
  assert.ok(rules.length > 0);

  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  for (const rule of rules) {
    assert.ok(rule.normalizedPath.includes(":id"), rule.normalizedPath);
    // 템플릿의 :id 자리에 42 를 넣은 URL 에서, 클레임이 42 면 통과하고 다르면 잡힌다.
    const concrete = rule.normalizedPath.replace(":id", "42");
    const claimFor = (value) => {
      const payload = rule.claimField === "bid"
        ? { data: { id: 1 }, bid: value }
        : { data: { id: value } };
      return `Bearer ${encode({ alg: "none", typ: "JWT" })}.${encode(payload)}.`;
    };
    const call = (url, claimValue) => checkIdentityMismatch({
      method: "GET", normalizedPath: rule.normalizedPath, url,
      authorizationHeader: claimFor(claimValue), profile: juice,
    });
    assert.deepEqual(call(concrete, 42), [], `${rule.normalizedPath} 에서 본인 요청이 잡혔다`);
    assert.equal(call(concrete, 99).length, 1, `${rule.normalizedPath} 에서 타인 요청을 놓쳤다`);
    // 쿼리스트링이 붙어도 같은 추출이 된다.
    assert.equal(call(`${concrete}?from=list`, 99).length, 1, rule.normalizedPath);
    // 숫자가 아니면 추출하지 않는다.
    assert.deepEqual(call(rule.normalizedPath.replace(":id", "abc"), 99), []);
  }
});
