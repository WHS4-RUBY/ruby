const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const { spawn } = require("node:child_process");
const path = require("node:path");

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
}

function request(port, method, route, { headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method, path: route, headers }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers,
        body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    if (body !== null) req.write(body);
    req.end();
  });
}

async function startDetection(t, targetPort) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ruby-cookieless-run-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const dashboardPassword = crypto.randomBytes(24).toString("hex");
  const reservation = http.createServer();
  await listen(reservation);
  const port = reservation.address().port;
  await new Promise((resolve) => reservation.close(resolve));
  const detection = spawn(process.execPath, [path.join(__dirname, "..", "server.js")], {
    cwd: path.join(__dirname, ".."),
    env: { ...process.env, NODE_ENV: "test", PORT: String(port),
      TARGET_URL: `http://127.0.0.1:${targetPort}`,
      TARGET_CHOICES: `legacy=http://127.0.0.1:${targetPort},alternate=http://127.0.0.1:${targetPort}`,
      TARGET_DEFAULT_ID: "legacy",
      TARGET_SELECTION_FILE: path.join(directory, "selection.json"),
      CRS_ENABLED: "false", DECEPTION_ENABLED: "false",
      DETECTION_DASHBOARD_PASSWORD: dashboardPassword,
      DCID_HMAC_SECRET: crypto.randomBytes(32).toString("hex"),
      ACCOUNT_ID_HASH_KEY: crypto.randomBytes(32).toString("hex"),
      PAYLOAD_FINGERPRINT_KEY: crypto.randomBytes(32).toString("hex") },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let startupError = "";
  detection.stderr.on("data", (chunk) => { startupError += chunk.toString().slice(0, 2000); });
  t.after(() => detection.kill());
  await new Promise((resolve, reject) => {
    let output = "";
    const onExit = (code) => reject(new Error(`Detection exited ${code}: ${startupError}`));
    const onData = (chunk) => {
      output += chunk.toString();
      if (!output.includes(`[detection-proxy] listening on :${port} ->`)) return;
      detection.stdout.off("data", onData);
      detection.off("exit", onExit);
      resolve();
    };
    detection.stdout.on("data", onData);
    detection.once("exit", onExit);
  });
  return { port, dashboardPassword };
}

function cookiesFrom(response) {
  return (response.headers["set-cookie"] || []).map((value) => value.split(";", 1)[0]).join("; ");
}

test("세션만 바꿔 보내는 공격은 같은 후보 이력으로 미끼 단계까지 방어하고, 쿠키 유무만으로는 방어하지 않는다", { timeout: 30000 }, async (t) => {
  const seen = [];
  const defenseStub = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      seen.push({
        clientId: req.headers["x-client-id"],
        candidateId: req.headers["x-ruby-candidate-id"],
        source: req.headers["x-ruby-policy-source"],
        tier: req.headers["x-ruby-defense-tier"],
        targetId: req.headers["x-ruby-target-id"],
        runId: req.headers["x-ruby-run-id"],
        riskScore: Number(req.headers["x-ruby-risk-score"]),
        plan: JSON.parse(req.headers["x-defense-plan"] || "[]").map((step) => step.name),
      });
      // pipelineTrace와 같은 취약한 대상: 입력값을 그대로 반사한다.
      let payload = "";
      try { payload = JSON.parse(Buffer.concat(chunks).toString()).payload || ""; } catch {}
      res.writeHead(404, { "Content-Type": "text/html" });
      res.end(`<html><body>${payload}</body></html>`);
    });
  });
  await listen(defenseStub);
  t.after(() => defenseStub.close());
  const { port, dashboardPassword } = await startDetection(t, defenseStub.address().port);

  // 쿠키 없이 깨끗한 요청만 반복하는 클라이언트: 쿠키가 없다는 이유만으로 방어하지 않는다.
  const quiet = [];
  for (let index = 0; index < 8; index++) {
    await request(port, "GET", `/products/${index}`, { headers: { "User-Agent": "quiet-client/1.0" } });
    quiet.push(seen.at(-1));
  }
  assert.ok(quiet.every((item) => item.plan.length === 0 && !item.tier));
  assert.ok(quiet.every((item) => item.riskScore < 0.8));
  assert.equal(new Set(quiet.map((item) => item.clientId)).size, 1, "cookie-less requests keep one policy key");

  // 매 요청 쿠키를 버리고(=새 dlsid·dcid) 같은 공격을 반복한다.
  const attackBody = JSON.stringify({ payload: "union select <script>alert(1)</script>" });
  const attacker = [];
  for (let index = 0; index < 80; index++) {
    await request(port, "POST", `/api/orders/${index}`, {
      headers: { "User-Agent": "session-rotating-agent/1.0", "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(attackBody) },
      body: attackBody,
    });
    attacker.push(seen.at(-1));
  }
  const firstDefended = attacker.findIndex((item) => item.plan.length > 0);
  assert.ok(firstDefended > 0, "the very first request has no completed history yet");
  assert.equal(attacker[0].plan.length, 0);
  for (const item of attacker.slice(firstDefended)) {
    assert.deepEqual(item.plan, ["decoy_maze"], "once suspected, every later rotated session stays defended");
    assert.equal(item.tier, "suspected");
  }
  assert.ok(attacker.every((item) => !item.plan.includes("rate_limit_strict")),
    "cookie-less evidence never reaches the confirmed (429) tier");
  assert.equal(new Set(attacker.map((item) => item.candidateId)).size, 1);
  assert.equal(new Set(attacker.slice(1).map((item) => item.clientId)).size, 1,
    "rotated sessions share one defense state key");
  assert.notEqual(attacker.at(-1).clientId, quiet.at(-1).clientId);

  // 같은 IP의 다른 지문(다른 클라이언트)은 공격자 이력을 물려받지 않는다.
  await request(port, "GET", "/", { headers: { "User-Agent": "other-browser/2.0" } });
  assert.deepEqual(seen.at(-1).plan, []);

  // 공격자와 같은 IP·지문이라도 서명 dcid를 돌려주는 클라이언트는 자기 이력만 본다.
  const first = await request(port, "GET", "/", { headers: { "User-Agent": "session-rotating-agent/1.0" } });
  assert.deepEqual(seen.at(-1).plan, ["decoy_maze"], "its first cookie-less request is the accepted NAT trade-off");
  for (let index = 0; index < 3; index++) {
    await request(port, "GET", "/", {
      headers: { "User-Agent": "session-rotating-agent/1.0", Cookie: cookiesFrom(first) },
    });
    assert.deepEqual(seen.at(-1).plan, [], "a returning signed client does not inherit the candidate score");
    assert.match(seen.at(-1).clientId, /^dcid:/);
  }

  // 관리자가 대상을 바꾸면 새 실행은 이전 Candidate 점수를 물려받지 않는다.
  const loginBody = JSON.stringify({ password: dashboardPassword });
  const login = await request(port, "POST", "/__detection/api/login", {
    headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(loginBody) },
    body: loginBody,
  });
  assert.equal(login.status, 204);
  const adminCookie = cookiesFrom(login);
  const selectionBody = JSON.stringify({ targetId: "alternate" });
  const selected = await request(port, "POST", "/__detection/api/target-selection", {
    headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(selectionBody),
      Cookie: adminCookie, Origin: `http://127.0.0.1:${port}`,
      "X-Ruby-Target-Selection": "1" },
    body: selectionBody,
  });
  assert.equal(selected.status, 200);
  const previousRunId = attacker.at(-1).runId;
  await request(port, "GET", "/", { headers: { "User-Agent": "session-rotating-agent/1.0" } });
  assert.equal(seen.at(-1).targetId, "alternate");
  assert.notEqual(seen.at(-1).runId, previousRunId);
  assert.deepEqual(seen.at(-1).plan, [], "new target run starts without the prior candidate's decoy");
  assert.ok(!seen.at(-1).tier);

  const secondRun = [];
  for (let index = 0; index < 80; index++) {
    await request(port, "POST", `/api/orders/${index}`, {
      headers: { "User-Agent": "session-rotating-agent/1.0", "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(attackBody) },
      body: attackBody,
    });
    secondRun.push(seen.at(-1));
  }
  assert.deepEqual(secondRun[0].plan, []);
  assert.ok(secondRun.some((item) => item.tier === "suspected" &&
    item.plan.length === 1 && item.plan[0] === "decoy_maze"),
  "new run eventually responds to its own repeated attack evidence");
});
