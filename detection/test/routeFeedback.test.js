const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");

const FEEDBACK_KEY = "route-feedback-key-0123456789abcdef0123456789abcdef";

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
}

function get(port, route, userAgent, cookie = "") {
  return new Promise((resolve, reject) => {
    http.get({ host: "127.0.0.1", port, path: route,
      headers: { "User-Agent": userAgent, ...(cookie ? { Cookie: cookie } : {}) } }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => { response.body = Buffer.concat(chunks).toString(); resolve(response); });
    }).on("error", reject);
  });
}

function post(port, route, userAgent, payload) {
  const body = Buffer.from(JSON.stringify(payload));
  return new Promise((resolve, reject) => {
    const request = http.request({ host: "127.0.0.1", port, path: route, method: "POST",
      headers: { "User-Agent": userAgent, "Content-Type": "application/json",
        "Content-Length": body.length } }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => { response.body = Buffer.concat(chunks).toString(); resolve(response); });
    });
    request.on("error", reject);
    request.end(body);
  });
}

async function startDetection(t, targetPort) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ruby-route-feedback-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const reservation = http.createServer();
  await listen(reservation);
  const port = reservation.address().port;
  await new Promise((resolve) => reservation.close(resolve));
  const dashboardPassword = crypto.randomBytes(24).toString("hex");
  const detection = spawn(process.execPath, [path.join(__dirname, "..", "server.js")], {
    cwd: path.join(__dirname, ".."),
    env: { ...process.env, NODE_ENV: "test", PORT: String(port),
      TARGET_URL: `http://127.0.0.1:${targetPort}`,
      // These requests use Juice Shop routes and must run with its PR #50 site profile.
      TARGET_CHOICES: `juice-shop=http://127.0.0.1:${targetPort}`,
      TARGET_DEFAULT_ID: "juice-shop",
      TARGET_SELECTION_FILE: path.join(directory, "selection.json"),
      CRS_ENABLED: "false", DECEPTION_ENABLED: "true",
      DETECTION_DASHBOARD_PASSWORD: dashboardPassword,
      DCID_HMAC_SECRET: crypto.randomBytes(32).toString("hex"),
      ACCOUNT_ID_HASH_KEY: crypto.randomBytes(32).toString("hex"),
      PAYLOAD_FINGERPRINT_KEY: crypto.randomBytes(32).toString("hex"),
      OVERLAY_DETECTOR_KEY: FEEDBACK_KEY },
    stdio: ["ignore", "pipe", "pipe"],
  });
  t.after(() => detection.kill());
  let stderr = "";
  detection.stderr.on("data", (chunk) => { stderr += chunk.toString().slice(0, 2000); });
  await new Promise((resolve, reject) => {
    let stdout = "";
    const onExit = (code) => reject(new Error(`Detection exited ${code}: ${stderr}`));
    const onData = (chunk) => {
      stdout += chunk.toString();
      if (!stdout.includes(`[detection-proxy] listening on :${port} ->`)) return;
      detection.stdout.off("data", onData);
      detection.off("exit", onExit);
      resolve();
    };
    detection.stdout.on("data", onData);
    detection.once("exit", onExit);
  });
  return { port, dashboardPassword };
}

test("signed restored routes score on the next request, while bad feedback is ignored and hidden", {
  timeout: 30000,
}, async (t) => {
  const observed = [];
  const target = http.createServer((req, res) => {
    observed.push({ path: req.url, attackScore: Number(req.headers["x-ruby-attack-score"]),
      automationScore: Number(req.headers["x-ruby-automation-score"]) });
    const idor = /^\/(signed|tampered|unsigned|badid|external)-(\d+)$/.exec(req.url);
    const login = /^\/login-(signed|tampered)$/.exec(req.url);
    const coverage = /^\/coverage-(signed|tampered)$/.exec(req.url);
    if (idor || login || coverage) {
      const kind = idor ? idor[1] : login ? login[1] : coverage[1];
      const restored = kind === "external" ? `https://other.example/api/Users/${idor[2]}`
        : idor ? `/api/Users/${idor[2]}` : login ? "/rest/user/login" : "/api/Products";
      if (kind !== "unsigned") {
        const message = ["ruby:route-feedback:v1",
          kind === "badid" ? "request:wrong" : req.headers["x-ruby-request-id"],
          req.method, req.headers["x-ruby-target-id"], req.headers["x-ruby-run-id"] || "",
          restored].join("\n");
        const key = kind === "signed" ? FEEDBACK_KEY : "wrong-feedback-key";
        const signature = crypto.createHmac("sha256", key).update(message).digest("hex");
        res.setHeader("X-Ruby-Resolved-Url", restored);
        res.setHeader("X-Ruby-Resolved-Url-Sig", signature);
      }
    }
    res.writeHead(login ? 401 : 200, { "Content-Type": "application/json" });
    res.end("{}");
  });
  await listen(target);
  t.after(() => target.close());
  const { port } = await startDetection(t, target.address().port);

  async function scoreAfter(kind) {
    const userAgent = `route-feedback-${kind}/1.0`;
    for (let id = 1; id <= 4; id++) {
      const response = await get(port, `/${kind}-${id}`, userAgent);
      assert.equal(response.statusCode, 200);
      assert.equal(response.headers["x-ruby-resolved-url"], undefined);
      assert.equal(response.headers["x-ruby-resolved-url-sig"], undefined);
    }
    await get(port, "/probe", userAgent);
    return observed.at(-1).attackScore;
  }

  const signed = await scoreAfter("signed");
  const tampered = await scoreAfter("tampered");
  const unsigned = await scoreAfter("unsigned");
  const badid = await scoreAfter("badid");
  const external = await scoreAfter("external");
  assert.ok(signed > 0.1, `signed route should restore IDOR scoring, got ${signed}`);
  assert.equal(tampered, 0);
  assert.equal(unsigned, 0);
  assert.equal(badid, 0);
  assert.equal(external, 0);

  async function loginScoreAfter(kind) {
    const userAgent = `route-login-${kind}/1.0`;
    for (let index = 0; index < 10; index++) {
      const response = await post(port, `/login-${kind}`, userAgent,
        { email: `person${index}@example.test`, password: "wrong" });
      assert.equal(response.statusCode, 401);
    }
    await get(port, "/probe", userAgent);
    return observed.at(-1).attackScore;
  }
  const signedLogin = await loginScoreAfter("signed");
  const tamperedLogin = await loginScoreAfter("tampered");
  assert.ok(signedLogin - tamperedLogin >= 0.07,
    `signed route should restore login brute-force scoring: ${signedLogin} vs ${tamperedLogin}`);

  async function automationScoreAfter(kind) {
    const userAgent = `route-coverage-${kind}/1.0`;
    let cookie = "";
    for (let index = 0; index < 3; index++) {
      const response = await get(port, `/coverage-${kind}`, userAgent, cookie);
      assert.equal(response.statusCode, 200);
      if (!cookie) cookie = (response.headers["set-cookie"] || [])
        .map((value) => value.split(";", 1)[0]).join("; ");
    }
    await get(port, "/probe", userAgent, cookie);
    return observed.at(-1).automationScore;
  }
  const signedAutomation = await automationScoreAfter("signed");
  const tamperedAutomation = await automationScoreAfter("tampered");
  assert.ok(signedAutomation - tamperedAutomation >= 0.06,
    `signed API route should restore no-asset signal: ${signedAutomation} vs ${tamperedAutomation}`);
});

test("signed stage1 alias login reuses the credential trap after Defense responds", {
  timeout: 30000,
}, async (t) => {
  const seenTiers = [];
  const restored = "/rest/user/login";
  const target = http.createServer((req, res) => {
    seenTiers.push(req.headers["x-ruby-defense-tier"]);
    const kind = /^\/login-(signed|invalid|overlay|stream|rate)$/.exec(req.url)?.[1];
    assert.ok(kind);
    const message = ["ruby:route-feedback:v1", req.headers["x-ruby-request-id"],
      req.method, req.headers["x-ruby-target-id"], req.headers["x-ruby-run-id"] || "",
      restored].join("\n");
    const key = kind === "invalid" ? "wrong-feedback-key" : FEEDBACK_KEY;
    res.setHeader("X-Ruby-Resolved-Url", restored);
    res.setHeader("X-Ruby-Resolved-Url-Sig",
      crypto.createHmac("sha256", key).update(message).digest("hex"));
    if (kind === "overlay") res.setHeader("X-Ruby-Overlay-Active", "1");
    if (kind === "rate") res.setHeader("X-Defense-Signal", "rate_limited");
    res.writeHead(kind === "rate" ? 429 : 401, {
      "Content-Type": kind === "stream" ? "text/event-stream" : "application/json",
      "WWW-Authenticate": 'Basic realm="origin"',
    });
    res.end(kind === "stream" ? "data: invalid\n\n" : '{"error":"invalid"}');
  });
  await listen(target);
  t.after(() => target.close());
  const { port, dashboardPassword } = await startDetection(t, target.address().port);
  const responses = new Map();
  for (const kind of ["signed", "invalid", "overlay", "stream", "rate"]) {
    const response = await post(port, `/login-${kind}`, `alias-login-${kind}/1.0`,
      { email: "LLM_Admin", password: "password123" });
    responses.set(kind, response);
    assert.equal(response.headers["x-ruby-resolved-url"], undefined);
    assert.equal(response.headers["x-ruby-resolved-url-sig"], undefined);
    assert.equal(response.headers["x-ruby-overlay-active"], undefined);
  }
  assert.deepEqual(seenTiers, ["stage1", "stage1", "stage1", "stage1", "stage1"]);
  const trapped = responses.get("signed");
  assert.equal(trapped.statusCode, 423);
  assert.equal(trapped.statusMessage, "Locked");
  assert.match(trapped.headers["content-type"], /^application\/json/);
  assert.equal(Number(trapped.headers["content-length"]), Buffer.byteLength(trapped.body));
  assert.equal(trapped.headers["www-authenticate"], undefined);
  assert.match(trapped.body, /temporarily locked/);
  for (const kind of ["invalid", "overlay", "stream"]) {
    assert.equal(responses.get(kind).statusCode, 401, kind);
    assert.equal(responses.get(kind).headers["www-authenticate"], 'Basic realm="origin"');
  }
  assert.equal(responses.get("rate").statusCode, 429);

  const login = await post(port, "/__detection/api/login", "dashboard-test/1.0",
    { password: dashboardPassword });
  assert.equal(login.statusCode, 204);
  const cookie = (login.headers["set-cookie"] || [])
    .find((value) => value.startsWith("detection_dashboard_session="))?.split(";", 1)[0];
  assert.ok(cookie);
  const exportResponse = await get(port, "/__detection/api/export", "dashboard-test/1.0", cookie);
  assert.equal(exportResponse.statusCode, 200);
  const records = JSON.parse(exportResponse.body).flatMap((session) => session.requests);
  for (const [kind, response] of responses) {
    const record = records.find((entry) => entry.requestId === response.headers["x-ruby-request-id"]);
    assert.ok(record, kind);
    assert.equal(record.status, response.statusCode, kind);
    assert.equal(record.url, kind === "invalid" ? `/login-${kind}` : restored);
    assert.equal(record.observedUrl, kind === "invalid" ? null : `/login-${kind}`);
  }
});
