const assert = require("node:assert/strict");
const { test } = require("node:test");

const path = require("node:path");

const {
  extractResetPasswordEmail: extractReset,
  extractSecurityQuestionEmail: extractQuestion,
} = require("../lib/passwordResetAbuse");
const { loadSiteProfile } = require("../lib/siteProfile");

const profileAt = (id) =>
  loadSiteProfile(path.join(__dirname, "..", "config", "site-profiles", `${id}.json`));

// juice-shop 프로파일을 주입하면 아래 단정은 한 글자도 바뀌지 않고 통과해야 한다.
const JUICE_PROFILE = profileAt("juice-shop");
const extractResetPasswordEmail = (args) => extractReset({ ...args, profile: JUICE_PROFILE });
const extractSecurityQuestionEmail = (args) => extractQuestion({ ...args, profile: JUICE_PROFILE });

/**
 * passwordResetAbuse.js 의 특성화 테스트. 사이트 프로파일로 바꾸기 전에 현재 동작을
 * 고정한다. 여기 적힌 것은 "좋은 동작" 이 아니라 "지금 동작" 이다.
 *
 * 이 모듈은 독립된 두 반쪽이다: 비밀번호 재설정(POST, 본문)과 보안질문 조회(GET,
 * 쿼리스트링). RUBY Market 에는 보안질문 라우트가 아예 없으므로 프로파일에서도
 * 두 반쪽이 따로 켜지고 꺼져야 한다.
 */

const RESET = { method: "POST", normalizedPath: "/rest/user/reset-password" };
const QUESTION = { method: "GET", normalizedPath: "/rest/user/security-question" };

test("특성화: 재설정 라우트의 본문 email 을 소문자로 정규화한다", () => {
  assert.equal(extractResetPasswordEmail({ ...RESET, body: { email: "Bender@Juice-SH.op" } }),
    "bender@juice-sh.op");
  assert.equal(extractResetPasswordEmail({ ...RESET, body: { email: "  A@B  " } }), "a@b");
  assert.equal(extractResetPasswordEmail({ method: "post", normalizedPath: RESET.normalizedPath, body: { email: "a@b" } }),
    "a@b");
  // JSON 문자열 본문도 파싱하고, 깨진 JSON 은 null 이다.
  assert.equal(extractResetPasswordEmail({ ...RESET, body: '{"email":"A@B"}' }), "a@b");
  assert.equal(extractResetPasswordEmail({ ...RESET, body: "{not json" }), null);
});

test("특성화: 재설정 라우트가 아니거나 email 이 쓸 수 없으면 null 이다", () => {
  for (const [method, routePath] of [
    ["GET", "/rest/user/reset-password"],
    ["POST", "/rest/user/reset-password/"],
    ["POST", "/rest/user/security-question"],
    ["POST", "/api/auth/password-reset/confirm"],
  ]) {
    assert.equal(extractResetPasswordEmail({ method, normalizedPath: routePath, body: { email: "a@b" } }), null,
      `${method} ${routePath} 가 재설정으로 잡혔다`);
  }
  for (const body of [{ email: "" }, { email: "  " }, { email: 7 }, { email: null }, {}, null, 42, ["a"]]) {
    assert.equal(extractResetPasswordEmail({ ...RESET, body }), null,
      `본문 ${JSON.stringify(body)} 가 통과했다`);
  }
});

test("특성화: 보안질문 라우트는 본문이 아니라 쿼리스트링에서 email 을 읽는다", () => {
  assert.equal(
    extractSecurityQuestionEmail({ ...QUESTION, url: "/rest/user/security-question?email=Bender%40Juice-SH.op" }),
    "bender@juice-sh.op"
  );
  assert.equal(
    extractSecurityQuestionEmail({ ...QUESTION, url: "/rest/user/security-question?email=%20A%40B%20" }),
    "a@b"
  );
  // 상대 URL 을 받으므로 더미 origin 을 붙여 파싱한다.
  assert.equal(
    extractSecurityQuestionEmail({ ...QUESTION, url: "?email=a@b" }),
    "a@b"
  );
  // 본문에 email 이 있어도 보지 않는다.
  assert.equal(
    extractSecurityQuestionEmail({ ...QUESTION, url: "/rest/user/security-question", body: { email: "a@b" } }),
    null
  );
});

// 지금 보안질문 쪽은 쿼리 파라미터 이름을 **대소문자 구분**해서 찾는다
// (searchParams.get('email')). identityMismatch 의 extractQueryValue 는 일부러
// 대소문자 무관으로 찾는다. 두 모듈이 다르다 — 고치면 동작 변경이므로 고정만 한다.
test("특성화: 보안질문의 쿼리 파라미터 이름은 대소문자를 구분한다", () => {
  assert.equal(extractSecurityQuestionEmail({ ...QUESTION, url: "?email=a@b" }), "a@b");
  assert.equal(extractSecurityQuestionEmail({ ...QUESTION, url: "?Email=a@b" }), null);
  assert.equal(extractSecurityQuestionEmail({ ...QUESTION, url: "?EMAIL=a@b" }), null);
});

test("특성화: 보안질문 라우트가 아니거나 email 이 없으면 null 이다", () => {
  for (const [method, routePath] of [
    ["POST", "/rest/user/security-question"],
    ["GET", "/rest/user/security-question/"],
    ["GET", "/rest/user/reset-password"],
  ]) {
    assert.equal(extractSecurityQuestionEmail({ method, normalizedPath: routePath, url: "?email=a@b" }), null,
      `${method} ${routePath} 가 보안질문으로 잡혔다`);
  }
  for (const url of ["", "/rest/user/security-question", "?email=", "?email=%20%20", "?user=a@b", undefined]) {
    assert.equal(extractSecurityQuestionEmail({ ...QUESTION, url }), null,
      `URL ${JSON.stringify(url)} 가 통과했다`);
  }
});

test("특성화: 두 추출기 모두 method/path 부재에 던지지 않는다", () => {
  assert.equal(extractResetPasswordEmail({ body: { email: "a@b" } }), null);
  assert.equal(extractSecurityQuestionEmail({ url: "?email=a@b" }), null);
});

// ---------------------------------------------------------------------------
// 프로파일화 이후: 두 반쪽의 독립, 다른 사이트, 비활성 상태
// ---------------------------------------------------------------------------

const GENERIC_PROFILE = profileAt("generic");
const RUBY_PROFILE = profileAt("ruby-shop");

test("다른 사이트의 재설정 라우트와 필드명으로도 같은 신호가 나온다", () => {
  const otherSite = {
    ...GENERIC_PROFILE,
    passwordResetAbuse: {
      resetRoute: { method: "POST", normalizedPath: "/api/auth/password-reset/request" },
      resetEmailField: "account",
      securityQuestionRoute: { method: "GET", normalizedPath: "/api/auth/recovery-hint" },
      securityQuestionEmailField: "account",
    },
  };

  assert.equal(
    extractReset({ method: "POST", normalizedPath: "/api/auth/password-reset/request",
                   body: { account: "  Bender@Example.Test " }, profile: otherSite }),
    "bender@example.test"
  );
  assert.equal(
    extractQuestion({ method: "GET", normalizedPath: "/api/auth/recovery-hint",
                      url: "?account=Bender%40Example.Test", profile: otherSite }),
    "bender@example.test"
  );
  // Juice Shop 의 경로·필드명은 이 프로파일에서 잡히지 않는다.
  assert.equal(
    extractReset({ ...RESET, body: { email: "a@b" }, profile: otherSite }),
    null
  );
  assert.equal(
    extractQuestion({ ...QUESTION, url: "?email=a@b", profile: otherSite }),
    null
  );
});

// RUBY 에는 재설정 라우트는 있고 보안질문 라우트는 없다. 한쪽만 선언한 프로파일에서
// 그 반쪽만 돌고 나머지는 꺼져야 한다 — 블록 전체가 함께 꺼지면 안 된다.
test("두 반쪽은 독립이다 — 한쪽만 선언하면 그쪽만 돈다", () => {
  const resetOnly = {
    ...GENERIC_PROFILE,
    passwordResetAbuse: {
      resetRoute: { method: "POST", normalizedPath: "/api/auth/password-reset/request" },
      resetEmailField: "email",
    },
  };
  assert.equal(
    extractReset({ method: "POST", normalizedPath: "/api/auth/password-reset/request",
                   body: { email: "a@b" }, profile: resetOnly }),
    "a@b",
    "재설정 반쪽은 돌아야 한다"
  );
  assert.equal(
    extractQuestion({ method: "GET", normalizedPath: "/api/auth/recovery-hint",
                      url: "?email=a@b", profile: resetOnly }),
    null,
    "보안질문 반쪽은 선언이 없으므로 꺼져야 한다"
  );

  const questionOnly = {
    ...GENERIC_PROFILE,
    passwordResetAbuse: {
      securityQuestionRoute: { method: "GET", normalizedPath: "/api/auth/recovery-hint" },
      securityQuestionEmailField: "email",
    },
  };
  assert.equal(
    extractQuestion({ method: "GET", normalizedPath: "/api/auth/recovery-hint",
                      url: "?email=a@b", profile: questionOnly }),
    "a@b"
  );
  assert.equal(
    extractReset({ method: "POST", normalizedPath: "/api/auth/password-reset/request",
                   body: { email: "a@b" }, profile: questionOnly }),
    null
  );
});

test("프로파일에 설정이 없으면 양쪽 모두 비활성이고 그 사실이 드러난다", () => {
  for (const profile of [GENERIC_PROFILE, RUBY_PROFILE, null, undefined, {}]) {
    assert.equal(extractReset({ ...RESET, body: { email: "a@b" }, profile }), null);
    assert.equal(extractQuestion({ ...QUESTION, url: "?email=a@b", profile }), null);
  }
  for (const profile of [GENERIC_PROFILE]) {
    assert.ok(profile.disabledFeatures.includes("passwordResetAbuse"),
      `${profile.profileId} 가 passwordResetAbuse 비활성을 선언하지 않았다`);
  }
});

// RUBY 는 재설정 라우트만 선언한다(보안질문 라우트는 앱에 없다).
test("ruby-shop 은 재설정 반쪽만 활성이고 보안질문 반쪽은 꺼져 있다", () => {
  assert.ok(!RUBY_PROFILE.disabledFeatures.includes("passwordResetAbuse"),
    "ruby-shop 이 passwordResetAbuse 를 비활성으로 선언했다");
  assert.equal(
    extractReset({ method: "POST", normalizedPath: "/api/auth/password-reset/request",
                   body: { email: "  Bender@Example.Test " }, profile: RUBY_PROFILE }),
    "bender@example.test"
  );
  // 확정 단계(confirm)는 이메일을 받지 않으므로 잡지 않는다.
  assert.equal(
    extractReset({ method: "POST", normalizedPath: "/api/auth/password-reset/confirm",
                   body: { email: "a@b" }, profile: RUBY_PROFILE }),
    null
  );
  assert.equal(
    extractQuestion({ method: "GET", normalizedPath: "/api/auth/password-reset/request",
                      url: "?email=a@b", profile: RUBY_PROFILE }),
    null
  );
});