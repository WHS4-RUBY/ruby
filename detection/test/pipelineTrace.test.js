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

function upgrade(port, route, headers = {}) {
  return new Promise((resolve, reject) => {
    const key = crypto.randomBytes(16).toString("base64");
    const req = http.request({ host: "127.0.0.1", port, path: route, headers: {
      Connection: "Upgrade", Upgrade: "websocket", "Sec-WebSocket-Version": "13",
      "Sec-WebSocket-Key": key, ...headers,
    } });
    req.setTimeout(3000, () => req.destroy(new Error("WebSocket upgrade timed out")));
    req.on("upgrade", (response, socket) => {
      socket.destroy();
      resolve({ status: response.statusCode, headers: response.headers });
    });
    req.on("response", (response) => {
      response.resume();
      reject(new Error(`WebSocket upgrade returned HTTP ${response.statusCode}`));
    });
    req.on("error", reject);
    req.end();
  });
}

function expectedStrictStrategies(confirmedAttackScore) {
  return confirmedAttackScore >= 0.95
    ? ["rate_limit_strict", "account_overlay_high"]
    : ["rate_limit_strict", "decoy_maze"];
}

test("HTTP request trace and signed versus unsigned WebSocket upgrade policies", { timeout: 20000 }, async (t) => {
  const selectionDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "ruby-pipeline-run-"));
  t.after(() => fs.rmSync(selectionDirectory, { recursive: true, force: true }));
  const seen = [];
  const seenUpgrades = [];
  const upgradeSockets = new Set();
  const strictLastSeen = new Map();
  const defenseStub = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const plan = JSON.parse(req.headers["x-defense-plan"] || "[]");
      const strict = plan.some((step) => step.name === "rate_limit_strict");
      const clientId = req.headers["x-client-id"];
      // Use logical milliseconds so the stub's quota does not depend on test speed.
      const now = seen.length;
      const blocked = strict && strictLastSeen.has(clientId) &&
        now - strictLastSeen.get(clientId) < 1000;
      if (strict) strictLastSeen.set(clientId, now);
      seen.push({ requestId: req.headers["x-ruby-request-id"],
        forwardedFor: req.headers["x-forwarded-for"],
        forwardedProto: req.headers["x-forwarded-proto"],
        attackScore: Number(req.headers["x-ruby-attack-score"]),
        confirmedAttackScore: Number(req.headers["x-ruby-confirmed-attack-score"]),
        riskScore: Number(req.headers["x-ruby-risk-score"]),
        forgedDefenseControl: req.headers["x-defense-overlay-level"],
        forgedRubyControl: req.headers["x-ruby-unknown-control"],
        source: req.headers["x-ruby-policy-source"], plan, clientId, blocked,
        tier: req.headers["x-ruby-defense-tier"],
        candidateId: req.headers["x-ruby-candidate-id"],
        clientFlowId: req.headers["x-ruby-client-flow-id"] });
      if (blocked) {
        res.writeHead(429, { "Content-Type": "application/json",
          "X-Defense-Signal": "rate_limited" });
        res.end('{"error":"rate_limited"}');
        return;
      }
      if (req.method === "GET" && req.url === "/") {
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end("ok");
        return;
      }
      let payload = "";
      try { payload = JSON.parse(Buffer.concat(chunks).toString()).payload || ""; } catch {}
      res.writeHead(404, { "Content-Type": "text/html" });
      res.end(`<html><body>${payload}</body></html>`);
    });
  });
  defenseStub.on("upgrade", (req, socket) => {
    upgradeSockets.add(socket);
    socket.on("close", () => upgradeSockets.delete(socket));
    seenUpgrades.push({
      requestId: req.headers["x-ruby-request-id"],
      forwardedFor: req.headers["x-forwarded-for"],
      attackScore: Number(req.headers["x-ruby-attack-score"]),
      confirmedAttackScore: Number(req.headers["x-ruby-confirmed-attack-score"]),
      riskScore: Number(req.headers["x-ruby-risk-score"]),
      forgedDefenseControl: req.headers["x-defense-overlay-level"],
      forgedRubyControl: req.headers["x-ruby-unknown-control"],
      source: req.headers["x-ruby-policy-source"],
      plan: JSON.parse(req.headers["x-defense-plan"] || "[]"),
      clientId: req.headers["x-client-id"],
    });
    const accept = crypto.createHash("sha1")
      .update(`${req.headers["sec-websocket-key"]}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest("base64");
    socket.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n" +
      `Connection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
  });
  await listen(defenseStub);
  t.after(() => {
    for (const socket of upgradeSockets) socket.destroy();
    defenseStub.close();
  });

  const reservation = http.createServer();
  await listen(reservation);
  const detectionPort = reservation.address().port;
  await new Promise((resolve) => reservation.close(resolve));
  const dashboardPassword = crypto.randomBytes(24).toString("hex");
  const detection = spawn(process.execPath, [path.join(__dirname, "..", "server.js")], {
    cwd: path.join(__dirname, ".."),
    env: { ...process.env, NODE_ENV: "test", PORT: String(detectionPort),
      TARGET_URL: `http://127.0.0.1:${defenseStub.address().port}`,
      TARGET_CHOICES: `legacy=http://127.0.0.1:${defenseStub.address().port},alternate=http://127.0.0.1:${defenseStub.address().port}`,
      TARGET_DEFAULT_ID: "legacy",
      TARGET_SELECTION_FILE: path.join(selectionDirectory, "selection.json"),
      CRS_ENABLED: "false", DECEPTION_ENABLED: "false",
      TRUST_PROXY: "true",
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
      if (output.includes(`[detection-proxy] listening on :${detectionPort} ->`)) {
        detection.stdout.off("data", onData);
        detection.off("exit", onExit);
        detection.off("error", reject);
        resolve();
      }
    };
    detection.stdout.on("data", onData);
    detection.once("error", reject);
    detection.once("exit", onExit);
  });
  const health = await request(detectionPort, "GET", "/healthz");
  assert.equal(health.status, 200);

  const cookies = new Map();
  const attackBody = JSON.stringify({ payload: "union select <script>alert(1)</script>" });
  let blockedResponse = null;
  for (let index = 1; index <= 66; index++) {
    const cookie = [...cookies.values()].join("; ");
    const response = await request(detectionPort, "POST", `/api/orders/${index}`, {
      headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(attackBody),
        "X-Forwarded-For": "203.0.113.9", "X-Forwarded-Proto": "https",
        "User-Agent": "curl/8.0", ...(cookie ? { Cookie: cookie } : {}) },
      body: attackBody,
    });
    for (const value of response.headers["set-cookie"] || []) {
      const pair = value.split(";", 1)[0];
      cookies.set(pair.split("=", 1)[0], pair);
    }
    if (response.status === 429) { blockedResponse = response; break; }
  }
  assert.ok(blockedResponse, "repeated confirmed attack never reached strict policy");
  assert.equal(blockedResponse.headers["x-defense-signal"], "rate_limited");
  const last = seen.at(-1);
  assert.equal(last.blocked, true);
  assert.equal(last.requestId, blockedResponse.headers["x-ruby-request-id"]);
  assert.ok(last.attackScore >= 0.8);
  assert.ok(last.confirmedAttackScore >= 0.8);
  assert.ok(last.riskScore >= 0.8);
  assert.deepEqual(last.plan.map((step) => step.name),
    expectedStrictStrategies(last.confirmedAttackScore));
  assert.ok(seen.every((item) => item.forwardedFor === undefined));
  assert.ok(seen.every((item) => item.forwardedProto === "https"));
  assert.match(last.candidateId, /^actor:/);
  assert.ok(seen.every((item) => item.candidateId === last.candidateId),
    "same IP and fingerprint keep one observation candidate for the defense dashboard");

  assert.ok(cookies.has("dlsid") && cookies.has("dcid"), "high-risk client has both session and signed client cookies");
  const anonymousUpgrade = await upgrade(detectionPort, "/socket", {
    "User-Agent": "curl/8.0", "X-Forwarded-For": "203.0.113.9",
    "X-Ruby-Confirmed-Attack-Score": "1", "X-Defense-Overlay-Level": "high",
    "X-Ruby-Unknown-Control": "forged",
  });
  assert.equal(anonymousUpgrade.status, 101);
  const anonymousPolicy = seenUpgrades.at(-1);
  assert.deepEqual(anonymousPolicy.plan, [], "cookie-less upgrade must not inherit attack rate limit or decoy");
  assert.equal(anonymousPolicy.attackScore, 0);
  assert.equal(anonymousPolicy.confirmedAttackScore, 0);
  assert.equal(anonymousPolicy.riskScore, 0);
  assert.equal(anonymousPolicy.forgedDefenseControl, undefined);
  assert.equal(anonymousPolicy.forgedRubyControl, undefined);
  assert.match(anonymousPolicy.clientId, /^websocket:/);
  assert.notEqual(anonymousPolicy.clientId, last.clientId);
  assert.ok(anonymousPolicy.requestId);

  const secondAnonymousUpgrade = await upgrade(detectionPort, "/socket", { "User-Agent": "curl/8.0" });
  assert.equal(secondAnonymousUpgrade.status, 101);
  assert.notEqual(seenUpgrades.at(-1).clientId, anonymousPolicy.clientId,
    "each unsigned upgrade receives an independent client ID");

  const signedUpgrade = await upgrade(detectionPort, "/socket", {
    "User-Agent": "curl/8.0", Cookie: [...cookies.values()].join("; "),
    "X-Forwarded-For": "198.51.100.9",
  });
  assert.equal(signedUpgrade.status, 101);
  const signedPolicy = seenUpgrades.at(-1);
  assert.equal(signedPolicy.clientId, last.clientId);
  assert.ok(signedPolicy.attackScore >= 0.8);
  assert.ok(signedPolicy.confirmedAttackScore >= 0.8);
  assert.ok(signedPolicy.riskScore >= 0.8);
  assert.deepEqual(signedPolicy.plan.map((step) => step.name),
    expectedStrictStrategies(signedPolicy.confirmedAttackScore));
  assert.ok(!signedPolicy.plan.some((step) => step.name === "delay"));
  assert.notEqual(signedPolicy.requestId, last.requestId);
  assert.ok(seenUpgrades.every((item) => item.forwardedFor === undefined));

  const loginBody = JSON.stringify({ password: dashboardPassword });
  const login = await request(detectionPort, "POST", "/__detection/api/login", {
    headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(loginBody) },
    body: loginBody,
  });
  assert.equal(login.status, 204);
  const sessionCookie = (login.headers["set-cookie"] || []).find((value) =>
    value.startsWith("detection_dashboard_session="))?.split(";", 1)[0];
  assert.ok(sessionCookie);
  const exportResponse = await request(detectionPort, "GET", "/__detection/api/export", {
    headers: { Cookie: sessionCookie },
  });
  assert.equal(exportResponse.status, 200);
  const recordedRequests = JSON.parse(exportResponse.body).flatMap((session) => session.requests);
  assert.ok(recordedRequests.some((item) => item.tags?.includes("sqli")));
  assert.ok(recordedRequests.some((item) => item.xssTags?.includes("xss:reflected-critical")));
  const record = recordedRequests
    .find((item) => item.requestId === last.requestId);
  assert.ok(record);
  assert.match(record.ip, /^(::ffff:)?127\.0\.0\.1$/);
  assert.equal(record.status, 429);
  assert.equal(record.policyDecision.basis, "prior-completed-requests");
  assert.ok(record.policyDecision.strategies.includes("rate_limit_strict"));
  assert.equal(record.defenseSignal, "rate_limited");
  assert.ok(record.detectionResult.effectiveAttackScore >= 0.8);

  const normal = await request(detectionPort, "GET", "/", {
    headers: { "User-Agent": "curl/8.0", "X-Ruby-Confirmed-Attack-Score": "1",
      "X-Defense-Overlay-Level": "high", "X-Ruby-Unknown-Control": "forged" },
  });
  assert.equal(normal.status, 200);
  assert.equal(normal.body, "ok");
  // 쿠키를 돌려주지 않는 요청은 같은 IP·지문 Candidate 이력으로 판단한다. 같은 NAT의
  // 다른 사용자일 수도 있으므로 확정 단계(429)가 아닌 미끼만 붙고, 서명 클라이언트의
  // 방어 카운터도 공유하지 않는다.
  assert.equal(seen.at(-1).candidateId, last.candidateId);
  assert.deepEqual(seen.at(-1).plan.map((step) => step.name), ["decoy_maze"]);
  assert.equal(seen.at(-1).tier, "suspected");
  assert.equal(seen.at(-1).source, "actor-candidate-fallback");
  assert.equal(seen.at(-1).clientId, last.candidateId);
  assert.equal(seen.at(-1).confirmedAttackScore, 0);
  assert.equal(seen.at(-1).forgedDefenseControl, undefined);
  assert.equal(seen.at(-1).forgedRubyControl, undefined);
  assert.notEqual(seen.at(-1).clientId, last.clientId);

  const firstOtherAttack = await request(detectionPort, "POST", "/api/orders/99", {
    headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(attackBody),
      "User-Agent": "curl/8.0" },
    body: attackBody,
  });
  assert.equal(firstOtherAttack.status, 404);
  assert.ok(!seen.at(-1).plan.some((step) => step.name === "rate_limit_strict"),
    "cookie-less requests never reach the confirmed tier");
  assert.notEqual(seen.at(-1).clientId, last.clientId);
  const anonymousSeen = [];
  for (let index = 0; index < 3; index++) {
    await request(detectionPort, "GET", "/", {
      headers: { "User-Agent": "curl/8.0", "X-Ruby-Client-Flow-Id": "client-flow:spoofed",
        "X-Ruby-Candidate-Id": "actor:spoofed" },
    });
    anonymousSeen.push(seen.at(-1));
  }
  assert.ok(anonymousSeen.every((item) => item.candidateId === anonymousSeen[0].candidateId &&
    item.candidateId !== "actor:spoofed"));
  assert.equal(new Set(anonymousSeen.map((item) => item.clientId)).size, 1,
    "cookie-less requests share one policy key instead of a fresh DCID each time");
  assert.match(anonymousSeen.at(-1).clientFlowId, /^client-flow:[0-9a-f]{24}$/,
    "cookie-less requests from one candidate are reported as one linked flow");
  const finalExport = await request(detectionPort, "GET", "/__detection/api/export", {
    headers: { Cookie: sessionCookie },
  });
  const finalRequests = JSON.parse(finalExport.body).flatMap((session) => session.requests);
  const normalRecord = finalRequests.find((item) =>
    item.requestId === normal.headers["x-ruby-request-id"]);
  const otherAttackRecord = finalRequests.find((item) =>
    item.requestId === firstOtherAttack.headers["x-ruby-request-id"]);
  assert.equal(normalRecord.detectionResult.source, "provisional-client-observation");
  assert.equal(normalRecord.detectionResult.effectiveAttackScore, 0);
  assert.equal(otherAttackRecord.detectionResult.source, "provisional-client-observation");
  assert.ok(otherAttackRecord.detectionResult.effectiveAttackScore < last.attackScore);

  // 동일 signed dcid도 새 대상 실행에서는 이전 실행의 확정 공격 점수를 승계하지 않는다.
  const selectionBody = JSON.stringify({ targetId: "alternate" });
  const selected = await request(detectionPort, "POST", "/__detection/api/target-selection", {
    headers: { Cookie: sessionCookie, Origin: `http://127.0.0.1:${detectionPort}`,
      "X-Ruby-Target-Selection": "1", "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(selectionBody) },
    body: selectionBody,
  });
  assert.equal(selected.status, 200);
  const newRunSigned = await request(detectionPort, "GET", "/", {
    headers: { "User-Agent": "curl/8.0", Cookie: [...cookies.values()].join("; ") },
  });
  assert.equal(newRunSigned.status, 200);
  assert.deepEqual(seen.at(-1).plan, []);
  assert.equal(seen.at(-1).confirmedAttackScore, 0);
  assert.equal(seen.at(-1).riskScore, 0);
});
