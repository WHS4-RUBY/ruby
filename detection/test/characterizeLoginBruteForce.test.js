const assert = require("node:assert/strict");
const { test } = require("node:test");

const path = require("node:path");

const { extractLoginAttemptEmail: extract } = require("../lib/loginBruteForce");
const { loadSiteProfile } = require("../lib/siteProfile");

// 리팩토링 뒤에는 라우트와 필드명이 프로파일에서 온다. juice-shop 프로파일을 주입하면
// 아래 단정은 **한 글자도 바뀌지 않고** 그대로 통과해야 한다 — 그게 동작 보존의 증거다.
const JUICE_PROFILE = loadSiteProfile(
  path.join(__dirname, "..", "config", "site-profiles", "juice-shop.json")
);
const extractLoginAttemptEmail = (args) => extract({ ...args, profile: JUICE_PROFILE });

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

// ---------------------------------------------------------------------------
// 프로파일화 이후: 다른 사이트와 비활성 상태
// ---------------------------------------------------------------------------

const GENERIC_PROFILE = loadSiteProfile(
  path.join(__dirname, "..", "config", "site-profiles", "generic.json")
);
const RUBY_PROFILE = loadSiteProfile(
  path.join(__dirname, "..", "config", "site-profiles", "ruby-shop.json")
);

test("다른 사이트의 로그인 경로와 필드명으로도 같은 신호가 나온다", () => {
  // RUBY 의 로그인 경로에 가상의 필드명(username)을 붙인 합성 프로파일.
  // ruby-shop.json 은 실제 필드명 email 을 쓴다 — 아래 별도 테스트가 고정한다.
  const otherSite = {
    ...GENERIC_PROFILE,
    loginBruteForce: {
      route: { method: "POST", normalizedPath: "/api/auth/login" },
      emailField: "username",
    },
  };

  assert.equal(
    extract({ method: "POST", normalizedPath: "/api/auth/login",
              body: { username: "  ADMIN@Example.Test " }, profile: otherSite }),
    "admin@example.test",
    "프로파일만 갈아끼우면 다른 사이트에서도 같은 정규화가 나와야 한다"
  );
  // Juice Shop 의 경로·필드명은 이제 이 프로파일에서 잡히지 않는다.
  assert.equal(
    extract({ method: "POST", normalizedPath: "/rest/user/login",
              body: { email: "a@b" }, profile: otherSite }),
    null
  );
  assert.equal(
    extract({ method: "POST", normalizedPath: "/api/auth/login",
              body: { email: "a@b" }, profile: otherSite }),
    null,
    "필드명이 다르면 잡지 않는다"
  );
});

// 규칙 3: 프로파일에 설정이 없으면 기능은 꺼지지만 조용히 꺼지지는 않는다.
// 비활성 사실은 프로파일의 disabledFeatures 에 있고, siteProfiles.js 가 기동 시
// 경고하며 /__detection/api/site-profile-status 가 노출한다.
test("ruby-shop 은 자기 로그인 경로와 email 필드로 활성이다", () => {
  assert.ok(!RUBY_PROFILE.disabledFeatures.includes("loginBruteForce"),
    "ruby-shop 이 loginBruteForce 를 비활성으로 선언했다");
  assert.equal(
    extract({ method: "POST", normalizedPath: "/api/auth/login",
              body: { email: "  ADMIN@Example.Test " }, profile: RUBY_PROFILE }),
    "admin@example.test"
  );
  // juice-shop 의 로그인 경로는 RUBY 에서 잡히지 않는다.
  assert.equal(
    extract({ method: "POST", normalizedPath: "/rest/user/login",
              body: { email: "a@b" }, profile: RUBY_PROFILE }),
    null
  );
  // email 필드가 아니면 잡지 않는다.
  assert.equal(
    extract({ method: "POST", normalizedPath: "/api/auth/login",
              body: { username: "a@b" }, profile: RUBY_PROFILE }),
    null
  );
});

test("프로파일에 설정이 없으면 비활성이고 그 사실이 드러난다", () => {
  for (const profile of [GENERIC_PROFILE]) {
    assert.equal(
      extract({ method: "POST", normalizedPath: "/rest/user/login",
                body: { email: "a@b" }, profile }),
      null,
      `${profile.profileId} 에서 null 이어야 한다`
    );
    assert.equal(
      extract({ method: "POST", normalizedPath: "/api/auth/login",
                body: { email: "a@b" }, profile }),
      null
    );
    // 에러 없이 0점을 돌려주는 동작은 허용하지 않는다 — 비활성이 선언돼 있어야 한다.
    assert.ok(
      profile.disabledFeatures.includes("loginBruteForce"),
      `${profile.profileId} 가 loginBruteForce 비활성을 선언하지 않았다`
    );
  }
});

test("프로파일이 아예 없으면 던지지 않고 null 이다", () => {
  for (const profile of [null, undefined, {}, { loginBruteForce: null }]) {
    assert.equal(
      extract({ method: "POST", normalizedPath: "/rest/user/login",
                body: { email: "a@b" }, profile }),
      null
    );
  }
});