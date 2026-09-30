const assert = require("node:assert/strict");
const test = require("node:test");
const cookieParser = require("cookie-parser");
const express = require("express");

const {
  DashboardAuthManager,
  InvalidCredentialsError,
  LoginRateLimitedError,
  installDashboardRoutes,
} = require("../lib/dashboardAuth");

test("관리자 인증은 로그인 실패를 제한하고 만료 세션을 제거한다", () => {
  let timestamp = 1000;
  const manager = new DashboardAuthManager({
    password: "secret",
    sessionTtlMs: 60_000,
    maxAttempts: 2,
    attemptWindowMs: 30_000,
    now: () => timestamp,
    randomBytes: () => Buffer.alloc(32, 1),
  });

  assert.throws(() => manager.login("wrong", "client-a"), InvalidCredentialsError);
  assert.throws(() => manager.login("wrong", "client-a"), InvalidCredentialsError);
  assert.throws(() => manager.login("secret", "client-a"), LoginRateLimitedError);

  const token = manager.login("secret", "client-b");
  assert.equal(manager.isAuthenticated(token), true);
  timestamp += 60_001;
  assert.equal(manager.isAuthenticated(token), false);
  assert.equal(manager.sessions.size, 0);
});

test("관리자 세션 수를 설정값 이하로 유지한다", () => {
  let counter = 0;
  const manager = new DashboardAuthManager({
    password: "secret",
    maxSessions: 2,
    randomBytes: () => Buffer.alloc(32, ++counter),
  });
  const tokens = [0, 1, 2].map((index) => manager.login("secret", `client-${index}`));

  assert.equal(manager.sessions.size, 2);
  assert.equal(manager.isAuthenticated(tokens[0]), false);
  assert.equal(manager.isAuthenticated(tokens[2]), true);
});

test("로그인 실패 클라이언트 추적도 설정된 상한을 넘지 않는다", () => {
  const manager = new DashboardAuthManager({ password: "secret", maxFailureClients: 2 });
  for (let index = 0; index < 4; index += 1) {
    assert.throws(() => manager.login("wrong", `client-${index}`), InvalidCredentialsError);
  }
  assert.equal(manager.failures.size, 2);
});

test("탐지 대시보드와 관리 API는 로그인 세션 전후로 접근을 구분한다", async (context) => {
  const app = express();
  app.use(cookieParser());
  app.use(express.json());
  installDashboardRoutes({
    app,
    authManager: new DashboardAuthManager({ password: "secret" }),
  });
  app.get("/__detection/api/sessions", (_req, res) => res.json([]));

  const server = app.listen(0, "127.0.0.1");
  context.after(() => server.close());
  await new Promise((resolve) => server.once("listening", resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  const dashboard = await fetch(`${baseUrl}/__detection/dashboard`, { redirect: "manual" });
  assert.equal(dashboard.status, 302);
  assert.equal(dashboard.headers.get("location"), "/__detection/login");
  assert.equal((await fetch(`${baseUrl}/__detection/api/sessions`)).status, 401);

  const login = await fetch(`${baseUrl}/__detection/api/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ password: "secret" }),
  });
  assert.equal(login.status, 204);
  const cookie = login.headers.get("set-cookie").split(";", 1)[0];
  assert.equal(
    (await fetch(`${baseUrl}/__detection/api/sessions`, { headers: { cookie } })).status,
    200
  );
  assert.equal(
    (await fetch(`${baseUrl}/__detection/dashboard`, { headers: { cookie } })).status,
    200
  );
});
