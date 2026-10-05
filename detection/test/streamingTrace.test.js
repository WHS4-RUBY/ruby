const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const crypto = require("node:crypto");
const path = require("node:path");
const { spawn } = require("node:child_process");

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
}

function request(port, route, { method = "GET", headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: route, method, headers }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers,
        body: Buffer.concat(chunks).toString("utf8") }));
      res.on("error", reject);
    });
    req.on("error", reject);
    if (body !== null) req.write(body);
    req.end();
  });
}

test("Detection traces complete streams and partial upstream errors by request ID", { timeout: 20000 }, async (t) => {
  let upstreamEventsEnded = false;
  const backend = http.createServer((req, res) => {
    if (req.url === "/events") {
      res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" });
      res.write("data: first\n\n");
      setTimeout(() => {
        upstreamEventsEnded = true;
        res.end("data: second\n\n");
      }, 350);
      return;
    }
    if (req.url === "/broken") {
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      res.write("data: partial\n\n");
      setTimeout(() => res.destroy(), 35);
      return;
    }
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<html><body>hello</body></html>");
  });
  await listen(backend);
  t.after(() => backend.close());

  const reservation = http.createServer();
  await listen(reservation);
  const port = reservation.address().port;
  await new Promise((resolve) => reservation.close(resolve));
  const password = crypto.randomBytes(24).toString("hex");
  const detection = spawn(process.execPath, [path.join(__dirname, "..", "server.js")], {
    cwd: path.join(__dirname, ".."),
    env: { ...process.env, NODE_ENV: "test", PORT: String(port),
      TARGET_URL: `http://127.0.0.1:${backend.address().port}`,
      TARGET_PROFILE_FILE: "", CRS_ENABLED: "false", DECEPTION_ENABLED: "false",
      DETECTION_DASHBOARD_PASSWORD: password,
      DCID_HMAC_SECRET: crypto.randomBytes(32).toString("hex"),
      ACCOUNT_ID_HASH_KEY: crypto.randomBytes(32).toString("hex"),
      PAYLOAD_FINGERPRINT_KEY: crypto.randomBytes(32).toString("hex") },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let startupError = "";
  detection.stderr.on("data", (chunk) => { startupError += chunk.toString().slice(0, 2000); });
  t.after(() => detection.kill());
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      if ((await request(port, "/healthz")).status === 200) { ready = true; break; }
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.equal(ready, true, `Detection did not start: ${startupError}`);

  const streamed = await new Promise((resolve, reject) => {
    http.get({ host: "127.0.0.1", port, path: "/events" }, (res) => {
      const chunks = [];
      let firstArrivedBeforeEnd = false;
      res.on("data", (chunk) => {
        if (chunks.length === 0) firstArrivedBeforeEnd = !upstreamEventsEnded;
        chunks.push(chunk);
      });
      res.on("end", () => resolve({ headers: res.headers,
        body: Buffer.concat(chunks).toString(), firstArrivedBeforeEnd }));
      res.on("error", reject);
    }).on("error", reject);
  });
  assert.equal(streamed.firstArrivedBeforeEnd, true, "SSE first event must be delivered before upstream ends");
  assert.equal(streamed.body, "data: first\n\ndata: second\n\n");

  const partial = await new Promise((resolve, reject) => {
    const req = http.get({ host: "127.0.0.1", port, path: "/broken" }, (res) => {
      let settled = false;
      const finish = () => {
        if (!settled) { settled = true; resolve({ headers: res.headers }); }
      };
      res.resume();
      res.on("aborted", finish);
      res.on("error", finish);
      res.on("end", finish);
    });
    req.on("error", reject);
  });
  assert.ok(partial.headers["x-ruby-request-id"]);

  const small = await request(port, "/small");
  assert.match(small.body, /__detection\/static\/telemetry\.js/);
  const loginBody = JSON.stringify({ password });
  const login = await request(port, "/__detection/api/login", {
    method: "POST", headers: { "Content-Type": "application/json",
      "Content-Length": Buffer.byteLength(loginBody) }, body: loginBody,
  });
  assert.equal(login.status, 204);
  const sessionCookie = (login.headers["set-cookie"] || []).find((value) =>
    value.startsWith("detection_dashboard_session="))?.split(";", 1)[0];
  assert.ok(sessionCookie);

  let records = [];
  for (let attempt = 0; attempt < 30; attempt++) {
    const exported = await request(port, "/__detection/api/export", {
      headers: { Cookie: sessionCookie },
    });
    records = JSON.parse(exported.body).flatMap((session) => session.requests);
    if (records.some((record) => record.requestId === partial.headers["x-ruby-request-id"])) break;
    await new Promise((resolve) => setTimeout(resolve, 30));
  }
  const streamedRecord = records.find((record) =>
    record.requestId === streamed.headers["x-ruby-request-id"]);
  const partialRecords = records.filter((record) =>
    record.requestId === partial.headers["x-ruby-request-id"]);
  const smallRecord = records.find((record) =>
    record.requestId === small.headers["x-ruby-request-id"]);
  assert.ok(streamedRecord);
  assert.equal(streamedRecord.responseTransportOutcome, "complete");
  assert.equal(streamedRecord.responseBodyInspected, false);
  assert.equal(streamedRecord.responseBodyBytes, Buffer.byteLength(streamed.body));
  assert.equal(partialRecords.length, 1, "partial response has exactly one Detection record");
  assert.equal(partialRecords[0].responseTransportOutcome, "error");
  assert.equal(partialRecords[0].responseBodyInspected, false);
  assert.ok(partialRecords[0].responseBodyBytes > 0);
  assert.ok(partialRecords[0].policyDecision);
  assert.equal(smallRecord.responseTransportOutcome, "complete");
  assert.equal(smallRecord.responseBodyInspected, true);
});
