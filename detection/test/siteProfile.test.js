const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  FEATURE_PATHS,
  PROFILE_ID,
  SiteProfileError,
  loadSiteProfile,
  validateSiteProfile,
} = require("../lib/siteProfile");
const { SiteProfileRegistry, FALLBACK_PROFILE_ID } = require("../lib/siteProfiles");

const PROFILES_DIR = path.join(__dirname, "..", "config", "site-profiles");
const SHIPPED = ["juice-shop", "generic", "ruby-shop"];

function load(id) {
  return loadSiteProfile(path.join(PROFILES_DIR, `${id}.json`));
}

/** 임시 디렉터리에 프로파일 묶음을 깔고 콜백에 경로를 준다. */
function withProfiles(docs, run) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "site-profiles-test-"));
  try {
    for (const [name, doc] of Object.entries(docs)) {
      fs.writeFileSync(path.join(dir, `${name}.json`), JSON.stringify(doc));
    }
    return run(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function genericDoc(overrides = {}) {
  return { ...JSON.parse(fs.readFileSync(path.join(PROFILES_DIR, "generic.json"), "utf8")), ...overrides };
}

// ---------------------------------------------------------------------------
// 1. 동작 보존의 증거 — juice-shop 프로파일이 살아 있는 모듈 상수와 같은가
// ---------------------------------------------------------------------------

// 아직 어떤 모듈도 프로파일을 읽지 않는다. 상수를 갈아치우기 **전에** 전사(轉寫)가
// 정확한지 증명해 두는 것이 규칙 1 에 대해 얻을 수 있는 가장 강한 보장이다.
test("juice-shop 프로파일은 지금 살아 있는 모듈 상수와 정확히 같다", () => {
  const juice = load("juice-shop");

  // loginBruteForce 는 이미 프로파일을 읽으므로 비교할 상수가 없다. 그 보장은
  // characterizeLoginBruteForce.test.js 가 이어받는다 — 상수 비교보다 동작 비교가 강하다.

  // passwordResetAbuse 도 프로파일을 읽는다 — 보장은 characterizePasswordResetAbuse 로.

  // priceTampering 도 프로파일을 읽는다 — 보장은 characterizePriceTampering 으로.

  // priceIntegrity 도 프로파일을 읽는다 — 보장은 characterizePriceIntegrity 로.

  const bl = require("../lib/businessLogicSignatures");
  assert.deepEqual(
    juice.businessLogic.massAssignmentWhitelist.map((entry) => [entry.route, entry.fields]),
    [...bl.MASS_ASSIGNMENT_WHITELIST].map(([route, fields]) => [route, [...fields]])
  );
  assert.deepEqual(juice.businessLogic.alwaysSuspiciousFields, [...bl.ALWAYS_SUSPICIOUS_FIELDS]);
  assert.deepEqual(juice.businessLogic.suspiciousRoleValues, [...bl.SUSPICIOUS_ROLE_VALUES]);
  assert.deepEqual(
    juice.businessLogic.numericFieldRules,
    [...bl.NUMERIC_FIELD_RULES].map(([field, rule]) => ({ field, ...rule }))
  );

  const { SENSITIVE_ROUTES } = require("../lib/roleGatedAccess");
  assert.deepEqual(
    juice.roleGated.sensitiveRoutes,
    SENSITIVE_ROUTES.map((route) => ({
      tag: route.tag,
      method: route.method,
      normalizedPath: route.normalizedPath,
      requiredRoles: [...route.requiredRoles],
    }))
  );

  const im = require("../lib/identityMismatch");
  assert.deepEqual(
    juice.identity.routeRules,
    im.IDENTITY_ROUTE_RULES.map((rule) => ({
      tag: rule.tag, normalizedPath: rule.normalizedPath, claimField: rule.claimField,
    }))
  );
  // 본문·쿼리 규칙은 method/path 를 test 클로저 안에 숨기고 있어 직접 비교할 수 없다.
  // 태그·필드·클레임만 맞추고, 클로저가 프로파일이 적은 라우트를 실제로 받는지 확인한다.
  for (const [rules, declared] of [
    [im.IDENTITY_BODY_RULES, juice.identity.bodyRules],
    [im.IDENTITY_QUERY_RULES, juice.identity.queryRules],
  ]) {
    assert.equal(rules.length, declared.length);
    rules.forEach((rule, index) => {
      assert.equal(rule.tag, declared[index].tag);
      assert.equal(rule.field, declared[index].field);
      assert.equal(rule.claimField, declared[index].claimField);
      assert.equal(rule.test(declared[index].method, declared[index].normalizedPath), true,
        `${rule.tag} 의 test 가 프로파일이 선언한 라우트를 받지 않는다`);
    });
  }

  const de = require("../lib/deceptionEngine");
  assert.deepEqual(juice.deception.apiPathPrefixes, ["/rest/", "/api/"]);
  assert.equal(de.INTERNAL_PREFIX, "/rest/internal", "미끼 네임스페이스는 프로파일이 아니라 카탈로그 소관이다");

  assert.deepEqual(juice.disabledFeatures, [], "juice-shop 은 모든 기능이 설정돼 있어야 한다");
});

// ---------------------------------------------------------------------------
// 2. 출하된 세 프로파일
// ---------------------------------------------------------------------------

test("출하된 프로파일 셋이 모두 로드되고 파일명과 profileId 가 같다", () => {
  const onDisk = fs.readdirSync(PROFILES_DIR).filter((n) => n.endsWith(".json")).sort();
  assert.deepEqual(onDisk, SHIPPED.map((id) => `${id}.json`).sort());
  for (const id of SHIPPED) {
    const profile = load(id);
    assert.equal(profile.profileId, id);
    assert.ok(PROFILE_ID.test(profile.profileId));
    assert.equal(profile.schemaVersion, 1);
  }
});

// D3-R: 기능 블록은 지금 코드 경로가 라우트 무관일 때에만 generic 에 들어간다.
// 이 테스트가 그 원칙의 기계적 집행이다 — generic 에 라우트 묶인 기능이 들어오면 실패한다.
test("generic 은 라우트 무관 기능만 담고 라우트에 묶인 기능은 비활성으로 보고한다", () => {
  const generic = load("generic");

  // 지금 모든 대상에서 라우트 게이트 없이 도는 것들 — 빠지면 legacy 대상의 동작이 바뀐다.
  for (const feature of [
    "priceTampering",
    "businessLogic.alwaysSuspiciousFields",
    "businessLogic.suspiciousRoleValues",
    "businessLogic.numericFieldRules",
    "identity.tokenSources",
    "identity.claimMap",
    "deception.apiPathPrefixes",
    "deception.plaintextBaitPaths",
    "deception.frontendFlavor",
  ]) {
    assert.ok(!generic.disabledFeatures.includes(feature),
      `${feature} 는 지금 모든 대상에서 도는 기능이라 generic 에 있어야 한다`);
  }

  // 라우트 게이트가 있어 다른 사이트에서 이미 부동인 것들 — 생략해도 byte-identical.
  assert.deepEqual([...generic.disabledFeatures].sort(), [
    "businessLogic.massAssignmentWhitelist",
    "deception.loginPath",
    "identity.bodyRules",
    "identity.queryRules",
    "identity.routeRules",
    "loginBruteForce",
    "passwordResetAbuse",
    "priceIntegrity",
    "roleGated",
  ]);
});

test("generic 의 라우트 무관 값은 juice-shop 과 완전히 같다", () => {
  const juice = load("juice-shop");
  const generic = load("generic");
  assert.deepEqual(generic.priceTampering, juice.priceTampering);
  assert.deepEqual(generic.identity.tokenSources, juice.identity.tokenSources);
  assert.deepEqual(generic.identity.claimMap, juice.identity.claimMap);
  assert.equal(generic.identity.learnedFallback, juice.identity.learnedFallback);
  assert.deepEqual(generic.deception.apiPathPrefixes, juice.deception.apiPathPrefixes);
  assert.deepEqual(generic.deception.plaintextBaitPaths, juice.deception.plaintextBaitPaths);
  assert.equal(generic.deception.frontendFlavor, juice.deception.frontendFlavor);
  for (const key of ["alwaysSuspiciousFields", "suspiciousRoleValues", "numericFieldRules"]) {
    assert.deepEqual(generic.businessLogic[key], juice.businessLogic[key]);
  }
});

test("ruby-shop 은 근거가 있는 값만 담고 나머지는 확인 필요로 선언한다", () => {
  const ruby = load("ruby-shop");
  // 저장소 안에 근거가 있는 것 (site-ruby-shop.toml, ruby-shop-routes.json, INTEGRATION.md)
  assert.equal(ruby.deception.loginPath, "/api/auth/login");
  assert.deepEqual(ruby.deception.apiPathPrefixes, ["/api/"]);
  assert.equal(ruby.deception.frontendFlavor, "fetch");
  // 근거가 없어 비워 둔 것 — 추측해서 채우지 않았다.
  assert.deepEqual([...ruby.disabledFeatures].sort(), [
    "businessLogic.massAssignmentWhitelist",
    "identity.bodyRules",
    "identity.queryRules",
    "identity.routeRules",
    "loginBruteForce",
    "passwordResetAbuse",
    "priceIntegrity",
    "roleGated",
  ]);
  // generic 에서 가져왔을 뿐 RUBY 에서 검증되지 않은 것.
  assert.ok(ruby.genericDefaultFeatures.includes("identity.claimMap"));
  assert.ok(ruby.genericDefaultFeatures.includes("priceTampering"));
});

// ---------------------------------------------------------------------------
// 3. 검증기 — 로드 시점에 던진다
// ---------------------------------------------------------------------------

test("검증기는 모르는 키를 거부한다", () => {
  assert.throws(() => validateSiteProfile({ ...genericDoc(), loginBrutForce: {} }),
    /unknown key .loginBrutForce/);
  assert.throws(() => validateSiteProfile(genericDoc({ deception: { typo: 1 } })),
    /unknown key deception.typo/);
});

test("검증기는 profileId 와 schemaVersion 과 label 을 강제한다", () => {
  for (const bad of ["Juice-Shop", "1shop", "", "a".repeat(33), "has_underscore"]) {
    assert.throws(() => validateSiteProfile(genericDoc({ profileId: bad })), SiteProfileError,
      `profileId ${JSON.stringify(bad)} 가 통과했다`);
  }
  assert.throws(() => validateSiteProfile(genericDoc({ schemaVersion: 2 })), /schemaVersion must be 1/);
  assert.throws(() => validateSiteProfile(genericDoc({ label: " " })), /label must be/);
  assert.throws(() => validateSiteProfile(genericDoc({ label: "a\nb" })), /label must be/);
});

test("파일명과 profileId 가 다르면 던진다", () => {
  withProfiles({ generic: genericDoc(), "ruby-shop": genericDoc({ profileId: "generic" }) }, (dir) => {
    assert.throws(() => loadSiteProfile(path.join(dir, "ruby-shop.json")),
      /does not match the file name ruby-shop/);
  });
});

// Defense site_profile.py 규칙 1 과 같은 경로 규칙이어야 한다. 양쪽이 같은 입력을
// 거부하는지는 defense/tests/test_site_profile_contract.py 가 교차 확인한다.
test("검증기는 비정규 경로를 거부한다", () => {
  for (const bad of ["rest/user/login", "//rest/user/login", "/rest\\user", "/rest/user\nlogin",
                     "/rest/user/login?a=1", "/rest/user/login#x", ""]) {
    assert.throws(
      () => validateSiteProfile(genericDoc({ deception: { ...genericDoc().deception, loginPath: bad } })),
      SiteProfileError, `경로 ${JSON.stringify(bad)} 가 통과했다`
    );
  }
});

test("검증기는 모르는 자리표시자와 :id 두 개를 거부한다", () => {
  const withPath = (p) => genericDoc({
    identity: { ...genericDoc().identity, routeRules: [
      { tag: "identity-mismatch:x", normalizedPath: p, claimField: "id" },
    ] },
    _needsConfirmation: genericDoc()._needsConfirmation.filter((f) => f !== "identity.routeRules"),
  });
  assert.throws(() => validateSiteProfile(withPath("/a/:slug")), /unknown placeholder :slug/);
  // numericIdFrom() 은 첫 :id 만 치환하므로 두 개면 조용히 깨진 정규식이 된다.
  assert.throws(() => validateSiteProfile(withPath("/a/:id/b/:id")), /at most one :id/);
  assert.doesNotThrow(() => validateSiteProfile(withPath("/a/:id/reviews")));
});

test("검증기는 쿠키·필드 이름을 단순 토큰으로 제한한다", () => {
  // identityMismatch 가 쿠키 이름을 RegExp 에 보간하므로 이 제한이 정규식 주입을 막는다.
  for (const bad of ["tok(en", "tok|en", "tok.*", "", "tok en"]) {
    assert.throws(
      () => validateSiteProfile(genericDoc({
        identity: { ...genericDoc().identity, tokenSources: { bearer: false, cookieNames: [bad] } },
      })),
      SiteProfileError, `쿠키 이름 ${JSON.stringify(bad)} 가 통과했다`
    );
  }
});

test("검증기는 숫자 범위와 역할 대소문자를 강제한다", () => {
  const base = genericDoc();
  assert.throws(() => validateSiteProfile(genericDoc({
    priceTampering: { ...base.priceTampering, amountTolerance: 0 },
  })), /amountTolerance must be greater than 0/);
  assert.throws(() => validateSiteProfile(genericDoc({
    businessLogic: { ...base.businessLogic, numericFieldRules: [{ field: "a", min: 5, max: 1 }] },
  })), /min must be <= max/);
  assert.throws(() => validateSiteProfile(genericDoc({
    businessLogic: { ...base.businessLogic, numericFieldRules: [{ field: "a" }] },
  })), /must declare min or max/);
  // roleGatedAccess.js 가 claimed.role 을 소문자로 비교한다 — 선언이 대문자면 영구 미스매치다.
  assert.throws(() => validateSiteProfile(genericDoc({
    roleGated: { sensitiveRoutes: [
      { tag: "role-gated:x", method: "GET", normalizedPath: "/a", requiredRoles: ["Admin"] },
    ] },
    _needsConfirmation: base._needsConfirmation.filter((f) => f !== "roleGated"),
  })), /requiredRoles must be lower case/);
});

test("검증기는 중복 선언을 거부한다", () => {
  const base = genericDoc();
  assert.throws(() => validateSiteProfile(genericDoc({
    businessLogic: { ...base.businessLogic, massAssignmentWhitelist: [
      { route: "POST /a", fields: ["x"] }, { route: "POST /a", fields: ["y"] },
    ] },
    _needsConfirmation: base._needsConfirmation.filter((f) => f !== "businessLogic.massAssignmentWhitelist"),
  })), /declared twice/);
  // whitelistKey() 가 뒤 슬래시를 떼고 조회하므로 원본에 슬래시가 남으면 영구 미스다.
  assert.throws(() => validateSiteProfile(genericDoc({
    businessLogic: { ...base.businessLogic, massAssignmentWhitelist: [{ route: "POST /a/", fields: [] }] },
    _needsConfirmation: base._needsConfirmation.filter((f) => f !== "businessLogic.massAssignmentWhitelist"),
  })), /must not end with a slash/);
});

// 조용한 무력화 금지(규칙 3)의 값싼 불변식: 오타난 블록 이름이 "일부러 끈 것" 으로
// 위장하지 못한다. 이름을 틀리면 그 기능은 미설정이 되는데, 목록에 없으니 던진다.
test("없는 기능은 _needsConfirmation 에 적혀 있어야 하고 적힌 것은 실제 기능이어야 한다", () => {
  const base = genericDoc();
  const { priceTampering, ...withoutPriceTampering } = base;
  assert.throws(() => validateSiteProfile(withoutPriceTampering),
    /priceTampering is absent but not listed in _needsConfirmation/);
  assert.throws(() => validateSiteProfile(genericDoc({
    _needsConfirmation: [...base._needsConfirmation, "priceTamperring"],
  })), /unknown feature: priceTamperring/);
  assert.throws(() => validateSiteProfile(genericDoc({
    _needsConfirmation: [...base._needsConfirmation, "priceTampering"],
  })), /lists priceTampering but the profile declares it/);
  assert.throws(() => validateSiteProfile(genericDoc({ _genericDefaults: ["roleGated"] })),
    /lists roleGated but the profile does not declare it/);
});

test("FEATURE_PATHS 는 실제 섹션 구조와 맞는다", () => {
  const juice = load("juice-shop");
  for (const feature of FEATURE_PATHS) {
    const value = feature.split(".").reduce((node, key) => (node || {})[key], juice);
    assert.notEqual(value, undefined, `${feature} 가 juice-shop 에 없다 — FEATURE_PATHS 와 어긋난다`);
  }
});

test("깨진 JSON 과 읽을 수 없는 파일은 파일 이름과 함께 던진다", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "site-profiles-bad-"));
  try {
    fs.writeFileSync(path.join(dir, "generic.json"), "{ not json");
    assert.throws(() => loadSiteProfile(path.join(dir, "generic.json")),
      /site profile generic\.json: is not valid JSON/);
    assert.throws(() => loadSiteProfile(path.join(dir, "missing.json")),
      /site profile missing\.json: cannot be read/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// 4. 레지스트리 — 해결 순서와 경고
// ---------------------------------------------------------------------------

test("레지스트리는 대상 ID → 기본 프로파일 → generic 순으로 해결한다", () => {
  const registry = new SiteProfileRegistry({ dir: PROFILES_DIR, warn: () => {} });

  const juice = registry.forTarget("juice-shop");
  assert.equal(juice.profileId, "juice-shop");
  assert.equal(juice.source, "target-id");

  // 매핑 없는 대상 → generic. 라우트 무관 기능은 그대로 살아 있어 동작이 보존된다.
  for (const unmapped of ["legacy", "alternate", null, undefined, 42]) {
    const resolved = registry.forTarget(unmapped);
    assert.equal(resolved.profileId, FALLBACK_PROFILE_ID);
    assert.equal(resolved.source, "generic-fallback");
    assert.ok(resolved.profile.priceTampering, "generic 폴백에서도 priceTampering 은 살아 있어야 한다");
  }

  const pinned = new SiteProfileRegistry({
    dir: PROFILES_DIR, defaultProfileId: "juice-shop", warn: () => {},
  });
  const fallback = pinned.forTarget("legacy");
  assert.equal(fallback.profileId, "juice-shop");
  assert.equal(fallback.source, "default-env");
});

test("모르는 기본 프로파일 ID 는 기동 시 던진다", () => {
  assert.throws(
    () => new SiteProfileRegistry({ dir: PROFILES_DIR, defaultProfileId: "nope", warn: () => {} }),
    /unknown DETECTION_DEFAULT_SITE_PROFILE: nope/
  );
  // 빈 값은 generic 을 뜻한다.
  assert.equal(
    new SiteProfileRegistry({ dir: PROFILES_DIR, defaultProfileId: "  ", warn: () => {} }).defaultProfileId,
    FALLBACK_PROFILE_ID
  );
});

test("generic.json 이 없는 디렉터리는 기동 시 던진다", () => {
  withProfiles({ "juice-shop": genericDoc({ profileId: "juice-shop" }) }, (dir) => {
    assert.throws(() => new SiteProfileRegistry({ dir, warn: () => {} }), /has no generic\.json/);
  });
  withProfiles({}, (dir) => {
    assert.throws(() => new SiteProfileRegistry({ dir, warn: () => {} }), /has no profile/);
  });
  assert.throws(() => new SiteProfileRegistry({ dir: path.join(os.tmpdir(), "nope-not-here"), warn: () => {} }),
    /cannot be read/);
});

test("비활성 기능은 기동 시 대상·기능·사유와 함께 한 번 경고된다", () => {
  const lines = [];
  new SiteProfileRegistry({ dir: PROFILES_DIR, warn: (line) => lines.push(line) });

  const disabled = lines.filter((line) => line.includes("-> disabled (no profile)"));
  assert.ok(disabled.length >= 9, "generic 의 비활성 기능이 경고되지 않았다");
  assert.ok(disabled.some((l) => l.includes("profile=generic") && l.includes("feature=roleGated")));
  assert.ok(disabled.some((l) => l.includes("profile=ruby-shop") && l.includes("feature=loginBruteForce")));
  // juice-shop 은 전부 설정돼 있으므로 비활성 경고가 없어야 한다.
  assert.equal(disabled.filter((l) => l.includes("profile=juice-shop")).length, 0);
  // generic 기본값을 쓰는 것은 별도로 알린다.
  assert.ok(lines.some((l) => l.includes("profile=ruby-shop") && l.includes("generic default")));
  // 기동 시 한 번뿐 — 요청마다 찍으면 로그가 범람한다.
  assert.equal(new Set(lines).size, lines.length, "같은 경고가 두 번 나왔다");
});

test("프로파일 없는 대상 경고는 대상당 한 번만 나오고 상한이 있다", () => {
  const lines = [];
  const registry = new SiteProfileRegistry({ dir: PROFILES_DIR, warn: (line) => lines.push(line) });
  lines.length = 0;

  for (let i = 0; i < 5; i += 1) registry.forTarget("legacy");
  registry.forTarget("alternate");
  const unmapped = lines.filter((line) => line.includes("has no profile"));
  assert.equal(unmapped.length, 2, "대상당 한 번만 경고해야 한다");
  assert.ok(unmapped[0].includes("target=legacy"));
  assert.ok(unmapped[0].includes("features disabled (no profile)"));

  // 프로파일이 있는 대상은 경고하지 않는다.
  lines.length = 0;
  registry.forTarget("juice-shop");
  assert.deepEqual(lines, []);

  // 상한. 대상 ID 는 TARGET_CHOICES 에서 오지만 Set 이 무한히 자라지 않게 한다.
  for (let i = 0; i < 200; i += 1) registry.forTarget(`t${i}`);
  assert.ok(registry.warnedTargets.size <= 64, `중복 억제 Set 이 ${registry.warnedTargets.size} 까지 자랐다`);
});

test("status() 는 활성 대상과 비활성 기능을 관리 API 모양으로 돌려준다", () => {
  const registry = new SiteProfileRegistry({ dir: PROFILES_DIR, warn: () => {} });
  const status = registry.status("ruby-shop");

  assert.equal(status.defaultProfileId, FALLBACK_PROFILE_ID);
  assert.deepEqual(status.active,
    { targetId: "ruby-shop", profileId: "ruby-shop", source: "target-id", label: "RUBY Market" });
  assert.deepEqual(status.profiles.map((p) => p.profileId).sort(), [...SHIPPED].sort());

  const ruby = status.profiles.find((p) => p.profileId === "ruby-shop");
  assert.ok(ruby.disabledFeatures.includes("roleGated"));
  assert.ok(ruby.genericDefaultFeatures.includes("priceTampering"));
  assert.deepEqual(status.profiles.find((p) => p.profileId === "juice-shop").disabledFeatures, []);

  // 매핑 없는 대상은 목록에 남아 대시보드가 보여줄 수 있다.
  registry.forTarget("legacy");
  assert.ok(registry.status().unmappedTargets.includes("legacy"));
});

// ---------------------------------------------------------------------------
// 5. 점수 격리 — 규칙 1 의 기계적 집행
// ---------------------------------------------------------------------------

// blTags 는 점수에 직접 들어간다: featureExtractor.js:244,348 이 그 개수와 종류를
// businessLogicHits / distinctBusinessLogicCategories 로 만들고, classifier.js:179,287 의
// scoreBusinessLogicViolation 이 가중치 0.12 로 반영한다. 거기에 "프로파일 비활성" 같은
// 태그를 하나 더하면 서브스코어가 0 에서 0.7 이상으로 뛴다. 그래서 프로파일 상태는
// 전용 채널(관리 API + 대시보드)로만 흐르고 요청 특징에는 한 글자도 넣지 않는다.
test("프로파일 상태는 요청 특징에 새지 않는다", () => {
  const { extractStreamFeatures } = require("../lib/featureExtractor");
  const registry = new SiteProfileRegistry({ dir: PROFILES_DIR, warn: () => {} });
  const resolution = registry.forTarget("legacy");
  assert.ok(resolution.profile.disabledFeatures.length, "이 테스트는 비활성 기능이 있어야 의미가 있다");

  const request = {
    ts: 1_000,
    method: "GET",
    url: "/",
    operation: "GET /",
    status: 200,
    tags: [],
    blTags: [],
    experimentRunId: null,
    // 요청 객체에 프로파일이 붙어 있어도(server.js 가 붙인다) 특징에는 나오지 않아야 한다.
    siteProfile: resolution.profile,
    siteProfileResolution: resolution,
  };
  const stream = (requests) => extractStreamFeatures({
    requests,
    headerSample: { "user-agent": "curl/8.0" },
    fingerprint: "test",
    userAgent: "curl/8.0",
    telemetry: null,
    firstSeen: 0,
    lastSeen: 2_000,
    sessionChurn: 1,
  });
  const features = stream([request]);
  const serialized = JSON.stringify(features);

  assert.doesNotMatch(serialized, /siteProfile/i, "특징에 프로파일 상태가 섞였다");
  assert.doesNotMatch(serialized, /disabledFeatures/i);
  assert.doesNotMatch(serialized, /no profile/i);
  assert.equal(features.attack.businessLogicHits, 0);
  assert.equal(features.attack.distinctBusinessLogicCategories, 0);
  assert.deepEqual(features.attack.businessLogicCategories, []);

  // 프로파일을 붙이지 않은 같은 요청과 특징이 완전히 같아야 한다.
  const { siteProfile, siteProfileResolution, ...bare } = request;
  assert.deepEqual(features, stream([bare]));
});
