const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const cookieParser = require("cookie-parser");
const express = require("express");

const {
  TargetSelectionStore,
  checkTargetReachable,
  parsePublicOrigin,
  parseTargetChoices,
} = require("../lib/targetSelection");
const { installTargetSelectionRoutes } = require("../lib/targetSelectionRoutes");
const { DashboardAuthManager, installDashboardRoutes } = require("../lib/dashboardAuth");

test("only configured target IDs can be selected and the selection survives a restart", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ruby-target-test-"));
  try {
    const filePath = path.join(directory, "selection.json");
    const choices = parseTargetChoices(
      "legacy=http://127.0.0.1:3000,juice-shop=http://127.0.0.1:3010",
      "http://127.0.0.1:3000"
    );
    const first = new TargetSelectionStore({ choices, defaultId: "legacy", filePath });
    const initial = first.read();
    assert.equal(initial.targetId, "legacy");
    const selected = first.select("juice-shop");
    assert.equal(selected.targetId, "juice-shop");
    assert.notEqual(selected.runId, initial.runId);
    const restarted = new TargetSelectionStore({ choices, defaultId: "legacy", filePath });
    assert.deepEqual(restarted.read(), selected);
    assert.throws(() => restarted.select("attacker-url"), /unknown target ID/);
    assert.deepEqual(restarted.read(), selected);
    fs.writeFileSync(filePath, '{"targetId":"attacker-url","runId":"x","changedAt":"2026-10-07"}');
    assert.throws(() => restarted.read(), /invalid target selection state/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("target catalog rejects arbitrary schemes, credentials, and duplicate IDs", () => {
  for (const raw of [
    "unsafe=file:///etc/passwd",
    "unsafe=http://user:pass@example.com",
    "a=http://localhost:3000,a=http://localhost:3001",
  ]) {
    assert.throws(() => parseTargetChoices(raw, "http://localhost:3000"));
  }
});

test("protected link only accepts a configured HTTP origin", () => {
  assert.equal(parsePublicOrigin("http://158.247.253.127"), "http://158.247.253.127");
  assert.throws(() => parsePublicOrigin("http://example.com/path"));
  assert.throws(() => parsePublicOrigin("https://user:pass@example.com"));
  assert.throws(() => parsePublicOrigin("file:///etc/passwd"));
});

test("reachability probe checks the configured target before changing state", async () => {
  const server = net.createServer((socket) => socket.end());
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const target = { url: `http://127.0.0.1:${server.address().port}` };
    await checkTargetReachable(target);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("global target switch requires a dashboard session and same-origin write", async (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ruby-target-api-"));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const choices = parseTargetChoices(
    "legacy=http://127.0.0.1:3000,juice-shop=http://127.0.0.1:3010",
    "http://127.0.0.1:3000"
  );
  const selection = new TargetSelectionStore({
    choices, defaultId: "legacy", filePath: path.join(directory, "active.json"),
  });
  const app = express();
  app.use(cookieParser());
  app.use(express.json());
  installDashboardRoutes({ app, authManager: new DashboardAuthManager({ password: "secret" }) });
  installTargetSelectionRoutes({ app, targetSelection: selection, probe: async () => {} });
  const server = app.listen(0, "127.0.0.1");
  context.after(() => server.close());
  await new Promise((resolve) => server.once("listening", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const endpoint = `${base}/__detection/api/target-selection`;
  const body = JSON.stringify({ targetId: "juice-shop" });
  const write = (cookie, origin, controlHeader = "1") => fetch(endpoint, {
    method: "POST",
    headers: {
      cookie, origin, "content-type": "application/json",
      "x-ruby-target-selection": controlHeader,
    },
    body,
  });

  assert.equal((await fetch(endpoint)).status, 401);
  assert.equal((await write("", base)).status, 401);
  const login = await fetch(`${base}/__detection/api/login`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ password: "secret" }),
  });
  assert.equal(login.status, 204);
  const cookie = login.headers.get("set-cookie").split(";", 1)[0];
  assert.equal((await write(cookie, "http://evil.example")).status, 403);
  assert.equal((await write(cookie, base, "")).status, 403);
  assert.equal(selection.read().targetId, "legacy");
  const selected = await write(cookie, base);
  assert.equal(selected.status, 200);
  assert.equal((await selected.json()).active.targetId, "juice-shop");
  assert.equal(selection.read().targetId, "juice-shop");
});

test("선택 상태 파일은 통일된 경계값으로 검증한다", () => {
  // 경계값의 정본은 shared/target-selection.json 이고, 그 선언과 이 파일의 리터럴이
  // 같은지는 defense/tests/test_target_selection_contract.py 가 강제한다. 여기서는
  // 런타임 동작만 본다 — shared/ 는 Detection 이미지에 없으므로 읽지 않는다.
  const MAX_SELECTION_BYTES = 8192;
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "target-bounds-"));
  try {
    const filePath = path.join(directory, "selection.json");
    const choices = parseTargetChoices("legacy=http://127.0.0.1:3000", "http://127.0.0.1:3000");
    const store = new TargetSelectionStore({ choices, defaultId: "legacy", filePath });
    const valid = store.read();
    assert.match(valid.runId, UUID, "writer 는 canonical UUID 만 쓴다");

    // runId 가 UUID 가 아니면 거부한다 (예전에는 [a-zA-Z0-9:-]{1,100} 이면 통과했다).
    for (const runId of ["run-001", valid.runId.toUpperCase(), "", "x".repeat(36)]) {
      fs.writeFileSync(filePath, JSON.stringify({
        targetId: "legacy", runId, changedAt: valid.changedAt }));
      assert.throws(() => store.read(), /invalid target selection state/, runId);
    }

    // changedAt 은 파싱 가능해야 한다.
    for (const changedAt of ["now", "", "yesterday"]) {
      fs.writeFileSync(filePath, JSON.stringify({
        targetId: "legacy", runId: valid.runId, changedAt }));
      assert.throws(() => store.read(), /invalid target selection state/, changedAt);
    }

    // 크기 상한 — 예전에는 상한이 없어 공유 볼륨의 거대한 파일을 그대로 파싱했다.
    const padded = JSON.stringify({
      targetId: "legacy", runId: valid.runId, changedAt: valid.changedAt,
      padding: "p".repeat(MAX_SELECTION_BYTES) });
    assert.ok(Buffer.byteLength(padded) > MAX_SELECTION_BYTES);
    fs.writeFileSync(filePath, padded);
    assert.throws(() => store.read(), /invalid target selection state/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
