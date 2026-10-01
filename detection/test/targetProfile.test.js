const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
  loadTargetProfile, parseTargetProfile, matchProfileTrap, injectProfileBait,
} = require("../lib/targetProfile");
const { extractLoginAttemptEmail } = require("../lib/loginBruteForce");
const { checkRoleGatedAccess } = require("../lib/roleGatedAccess");

const fixture = {
  version: 1,
  routes: { login: { method: "POST", path: "/api/session", accountField: "username", failureStatuses: [401, 403] } },
  permissions: [{ method: "GET", path: "/api/admin/reports", requiredRoles: ["admin"] }],
  bait: {
    traps: [{ method: "GET", path: "/__ruby_bait/reports", status: 404,
      contentType: "text/plain", body: "Not found" }],
    htmlPaths: ["/"], plaintextPaths: [],
  },
};

test("custom target profile changes login, role and bait paths without Juice rules", () => {
  const profile = parseTargetProfile(fixture);
  assert.equal(extractLoginAttemptEmail({ method: "POST", normalizedPath: "/api/session",
    body: { username: "Me@Example.Test" }, route: profile.routes.login }), "me@example.test");
  assert.equal(extractLoginAttemptEmail({ method: "POST", normalizedPath: "/rest/user/login",
    body: { email: "juice@example.test" }, route: profile.routes.login }), null);
  assert.equal(checkRoleGatedAccess({ method: "GET", normalizedPath: "/api/admin/reports" },
    { routes: profile.permissions, allowLearned: false })[0].tag, "role-gated:target-profile");
  assert.deepEqual(checkRoleGatedAccess({ method: "GET", normalizedPath: "/api/Users" },
    { routes: profile.permissions, allowLearned: false }), []);
  assert.equal(matchProfileTrap(profile, "GET", "/__ruby_bait/reports").status, 404);
  assert.match(injectProfileBait(profile, "<body>Hello</body>", "/", "text/html"),
    /href="\/__ruby_bait\/reports"/);
  assert.equal(injectProfileBait(profile, "<body>Hello</body>", "/other", "text/html"),
    "<body>Hello</body>");
});

test("profile file loads and rejects paths that could intercept management APIs", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "target-profile-"));
  try {
    const file = path.join(dir, "target.json");
    fs.writeFileSync(file, JSON.stringify(fixture));
    assert.equal(loadTargetProfile(file).routes.login.path, "/api/session");
    assert.throws(() => parseTargetProfile({ ...fixture, bait: {
      traps: [{ method: "GET", path: "/__detection/api/export", status: 200,
        contentType: "text/plain", body: "bad" }],
    } }), /invalid method, path/);
    assert.throws(() => parseTargetProfile({ ...fixture, unexpected: true }), /not supported/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
