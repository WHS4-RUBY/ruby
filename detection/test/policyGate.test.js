const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");

const KEY = "local-trap-policy-gate-0123456789abcdef0123456789abcdef";
const STAGE4 = [
  { name: "decoy_maze", params: {} },
  { name: "delay", params: { delay_ms: 700 } },
  { name: "rate_limit_strict", params: { max_rps: 1 } },
  { name: "account_overlay_high", params: {} },
];

function signGateResponse(res, requestBody, { status = 200, tier = null,
  delay = null, signal = null } = {}) {
  const fields = ["ruby:policy-gate-response:v1",
    crypto.createHash("sha256").update(requestBody).digest("hex"),
    String(status), tier || "", delay || "", signal || ""];
  const signature = crypto.createHmac("sha256", KEY)
    .update(fields.join("\n")).digest("hex");
  res.setHeader("X-Defense-Policy-Response-Signature", signature);
  if (delay) res.setHeader("X-Defense-Delay-Ms", delay);
  if (signal) res.setHeader("X-Defense-Signal", signal);
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
}

function request(port, method, route, { body = "", headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const sent = Buffer.from(body);
    const started = Date.now();
    const req = http.request({ host: "127.0.0.1", port, method, path: route,
      headers: { ...headers, "Content-Length": sent.length } }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers,
        body: Buffer.concat(chunks).toString("utf8"), elapsed: Date.now() - started }));
    });
    req.on("error", reject);
    req.end(sent);
  });
}

async function startDetection(t, targetPort, { forceStage4 = false, gateEnabled = true } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ruby-policy-gate-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  let policyPath;
  if (forceStage4) {
    policyPath = path.join(directory, "policy.json");
    fs.writeFileSync(policyPath, JSON.stringify({ defense: { rules: [{
      tier: "stage4", min_score: 0, max_score: 1.01,
      min_confirmed_attack_score: 0, max_confirmed_attack_score: 1.01,
      strategies: STAGE4,
    }] } }));
  }
  const reservation = http.createServer();
  await listen(reservation);
  const port = reservation.address().port;
  await new Promise((resolve) => reservation.close(resolve));
  const dashboardPassword = crypto.randomBytes(24).toString("hex");
  const child = spawn(process.execPath, [path.join(__dirname, "..", "server.js")], {
    cwd: path.join(__dirname, ".."),
    env: { ...process.env, NODE_ENV: "test", PORT: String(port),
      TARGET_URL: `http://127.0.0.1:${targetPort}`,
      TARGET_CHOICES: `juice-shop=http://127.0.0.1:${targetPort}`,
      TARGET_DEFAULT_ID: "juice-shop",
      TARGET_SELECTION_FILE: path.join(directory, "selection.json"),
      ...(policyPath ? { POLICY_CONFIG_PATH: policyPath } : {}),
      DETECTION_POLICY_GATE_ENABLED: gateEnabled ? "true" : "false",
      OVERLAY_DETECTOR_KEY: KEY,
      CRS_ENABLED: "false", DECEPTION_ENABLED: "true", XSS_STORE: "memory",
      DETECTION_EXPOSE_REQUEST_ID: "true",
      DETECTION_DASHBOARD_PASSWORD: dashboardPassword,
      DCID_HMAC_SECRET: crypto.randomBytes(32).toString("hex"),
      ACCOUNT_ID_HASH_KEY: crypto.randomBytes(32).toString("hex"),
      PAYLOAD_FINGERPRINT_KEY: crypto.randomBytes(32).toString("hex"),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  t.after(() => child.kill());
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk.toString().slice(0, 2000); });
  await new Promise((resolve, reject) => {
    let stdout = "";
    const onExit = (code) => reject(new Error(`Detection exited ${code}: ${stderr}`));
    const onData = (chunk) => {
      stdout += chunk.toString();
      if (!stdout.includes(`[detection-proxy] listening on :${port} ->`)) return;
      child.stdout.off("data", onData);
      child.off("exit", onExit);
      resolve();
    };
    child.stdout.on("data", onData);
    child.once("exit", onExit);
  });
  return { port, dashboardPassword };
}

async function recordedRequest(port, dashboardPassword, requestId) {
  const login = await request(port, "POST", "/__detection/api/login", {
    body: JSON.stringify({ password: dashboardPassword }),
    headers: { "Content-Type": "application/json" },
  });
  assert.equal(login.status, 204);
  const cookie = (login.headers["set-cookie"] || [])
    .find((value) => value.startsWith("detection_dashboard_session="))?.split(";", 1)[0];
  assert.ok(cookie);
  const exported = await request(port, "GET", "/__detection/api/export", {
    headers: { Cookie: cookie },
  });
  assert.equal(exported.status, 200);
  return JSON.parse(exported.body).flatMap((session) => session.requests)
    .find((entry) => entry.requestId === requestId);
}

test("local traps send only signed policy metadata and keep credentials off upstream", {
  timeout: 20000,
}, async (t) => {
  const seen = [];
  let sticky = false;
  let gateError = false;
  let forgedResponse = false;
  const target = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      seen.push({ path: req.url, body: body.toString("utf8"), headers: req.headers });
      if (req.url === "/__defense/policy-gate") {
        const expected = crypto.createHmac("sha256", KEY).update(body).digest("hex");
        assert.equal(req.headers["x-defense-policy-signature"], expected);
        if (gateError) {
          res.writeHead(503).end();
          return;
        }
        if (forgedResponse) {
          res.setHeader("X-Defense-Policy-Response-Signature", "0".repeat(64));
        } else {
          signGateResponse(res, body, { tier: sticky ? "medium" : null });
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ tier: sticky ? "medium" : null }));
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json",
        "X-Ruby-Overlay-Active": "1" });
      res.end('{"from":"overlay"}');
    });
  });
  await listen(target);
  t.after(() => target.close());
  const { port, dashboardPassword } = await startDetection(t, target.address().port);

  const secret = "SECRET_NEVER_FORWARD_TO_GATE_OR_TARGET";
  const write = await request(port, "PUT", "/rest/internal/ops/service-backup.conf", {
    body: secret, headers: { "Content-Type": "text/plain" },
  });
  assert.equal(write.status, 200);
  assert.equal(write.body, "OK");
  const loginBody = JSON.stringify({ email: "LLM_Admin", password: "password123" });
  const localLogin = await request(port, "POST", "/rest/user/login", {
    body: loginBody, headers: { "Content-Type": "application/json" },
  });
  assert.equal(localLogin.status, 423);
  assert.ok(seen.every((entry) => entry.path === "/__defense/policy-gate"));
  for (const entry of seen) {
    assert.doesNotMatch(entry.body, /SECRET_NEVER_FORWARD|LLM_Admin|password123|rest\/user\/login/);
    const policy = JSON.parse(entry.body);
    assert.equal(policy.targetId, "juice-shop");
    assert.deepEqual(policy.plan, [{ name: "decoy_maze", params: {} }]);
    assert.equal(policy.confirmedAttackScore, 0);
    assert.match(policy.requestId, /^request:[0-9a-f-]+$/);
  }
  const record = await recordedRequest(port, dashboardPassword,
    localLogin.headers["x-ruby-request-id"]);
  assert.equal(record.status, 423);

  gateError = true;
  const failedLogin = await request(port, "POST", "/rest/user/login", {
    body: loginBody, headers: { "Content-Type": "application/json" },
  });
  assert.equal(failedLogin.status, 503);
  assert.equal(seen.at(-1).path, "/__defense/policy-gate");
  assert.doesNotMatch(seen.at(-1).body, /LLM_Admin|password123/);

  gateError = false;
  forgedResponse = true;
  sticky = true;
  const forgedLogin = await request(port, "POST", "/rest/user/login", {
    body: loginBody, headers: { "Content-Type": "application/json" },
  });
  assert.equal(forgedLogin.status, 503);
  assert.equal(seen.at(-1).path, "/__defense/policy-gate");
  forgedResponse = false;
  sticky = true;
  const forwarded = await request(port, "POST", "/rest/user/login", {
    body: loginBody, headers: { "Content-Type": "application/json" },
  });
  assert.equal(forwarded.status, 200);
  assert.equal(seen.at(-1).path, "/rest/user/login");
  assert.equal(seen.at(-1).body, loginBody);
});

test("rate and failed gates stop local traps; selected overlay login bypasses gate", {
  timeout: 20000,
}, async (t) => {
  const seen = [];
  let gateMode = "rate";
  const target = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      seen.push({ path: req.url, body, headers: req.headers });
      if (req.url === "/__defense/policy-gate") {
        const policy = JSON.parse(body);
        assert.deepEqual(policy.plan, STAGE4);
        if (gateMode === "rate") {
          signGateResponse(res, Buffer.from(body), {
            status: 429, delay: "700", signal: "rate_limited",
          });
          res.writeHead(429);
          res.end('{"error":"rate_limited"}');
        } else if (gateMode === "forged-rate") {
          res.writeHead(429, { "X-Defense-Signal": "rate_limited",
            "X-Defense-Delay-Ms": "700",
            "X-Defense-Policy-Response-Signature": "0".repeat(64) });
          res.end('{"error":"rate_limited"}');
        } else {
          res.writeHead(503).end();
        }
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json",
        "X-Ruby-Overlay-Active": "1" });
      res.end('{"from":"overlay"}');
    });
  });
  await listen(target);
  t.after(() => target.close());
  const { port, dashboardPassword } = await startDetection(t, target.address().port,
    { forceStage4: true });

  const blocked = await request(port, "GET", "/rest/internal/ops/alarm.sh");
  assert.equal(blocked.status, 429);
  // 적용된 지연과 속도 제한 신호는 내부 상태다. 단계를 알려 주는 지연값과 "방어가
  // 발동했다"는 신호 모두 공개 응답에 실리지 않고 기록으로만 남는다.
  assert.equal(blocked.headers["x-defense-signal"], undefined);
  assert.equal(blocked.headers["x-defense-delay-ms"], undefined);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].path, "/__defense/policy-gate");
  const record = await recordedRequest(port, dashboardPassword,
    blocked.headers["x-ruby-request-id"]);
  assert.equal(record.defenseSignal, "rate_limited");

  gateMode = "forged-rate";
  const forgedRate = await request(port, "GET", "/rest/internal/ops/alarm.sh");
  assert.equal(forgedRate.status, 503);
  assert.equal(forgedRate.headers["x-defense-signal"], undefined);

  gateMode = "error";
  const unavailable = await request(port, "GET", "/rest/internal/ops/alarm.sh");
  assert.equal(unavailable.status, 503);
  assert.equal(seen.at(-1).path, "/__defense/policy-gate");

  const credentials = JSON.stringify({ email: "LLM_Admin", password: "password123" });
  const login = await request(port, "POST", "/rest/user/login", {
    body: credentials, headers: { "Content-Type": "application/json" },
  });
  assert.equal(login.status, 200);
  assert.equal(seen.at(-1).path, "/rest/user/login");
  assert.equal(seen.at(-1).body, credentials);
});

test("standalone direct target serves local deception without a Defense gate", {
  timeout: 20000,
}, async (t) => {
  const seen = [];
  const target = http.createServer((req, res) => {
    seen.push(req.url);
    res.writeHead(404).end();
  });
  await listen(target);
  t.after(() => target.close());
  const { port } = await startDetection(t, target.address().port, { gateEnabled: false });
  const response = await request(port, "GET", "/rest/internal/ops/alarm.sh");
  assert.equal(response.status, 200);
  assert.match(response.body, /alarm/);
  assert.deepEqual(seen, []);
});
