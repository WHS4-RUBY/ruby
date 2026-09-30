const assert = require("node:assert/strict");
const test = require("node:test");
const http = require("node:http");
const { spawn } = require("node:child_process");
const path = require("node:path");
const { once } = require("node:events");

test("server wiring credits stored evidence to the writer once, and preserves normal traffic", async (context) => {
  const target = http.createServer((req, res) => {
    req.resume();
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ status: "ok" }));
  });
  target.listen(0, "127.0.0.1");
  await once(target, "listening");
  const reservation = http.createServer();
  reservation.listen(0, "127.0.0.1");
  await once(reservation, "listening");
  const port = reservation.address().port;
  await new Promise((resolve) => reservation.close(resolve));

  // Inject synthetic detector evidence at the module boundary. All HTTP bodies are harmless JSON.
  const runner = `
    const reflection = require('./lib/xssReflection');
    const original = reflection.analyzeExchange;
    reflection.analyzeExchange = (req, body, headers, candidates) => {
      const entry = candidates.all()[0];
      if (req.url === '/reader' && entry) {
        candidates.delete(entry.candidateKey);
        return { reflected: { tags: [], maxRisk: 0 }, findings: [{
          vulnerabilityType: 'stored', severity: 'critical', riskScore: 100, origin: entry.origin,
        }] };
      }
      return original(req, body, headers, candidates);
    };
    require('./server');
  `;
  const child = spawn(process.execPath, ["-e", runner], {
    cwd: path.resolve(__dirname, ".."),
    env: {
      ...process.env, NODE_ENV: "test", PORT: String(port), TARGET_URL: `http://127.0.0.1:${target.address().port}`,
      CRS_ENABLED: "false", DECEPTION_ENABLED: "false", DETECTION_DASHBOARD_PASSWORD: "",
      TRUST_PROXY: "false", SCHEMA_LEARNING_FILE: "", MAX_SESSIONS: "50",
      PAYLOAD_FINGERPRINT_KEY: "integration-payload", DCID_HMAC_SECRET: "integration-dcid",
      ACCOUNT_ID_HASH_KEY: "integration-account", DETECTION_ENTITY_TTL_MS: "1800000",
      CSRF_ALLOWED_ORIGINS: `http://127.0.0.1:${port}`,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (data) => { output += data; });
  child.stderr.on("data", (data) => { output += data; });
  context.after(async () => {
    if (child.exitCode === null) {
      const exited = once(child, "exit");
      child.kill();
      await exited;
    }
    target.closeAllConnections();
    await new Promise((resolve) => target.close(resolve));
  });

  const base = `http://127.0.0.1:${port}`;
  let ready = false;
  for (let i = 0; i < 100; i++) {
    try { ready = (await fetch(`${base}/healthz`)).ok; } catch {}
    if (ready) break;
    if (child.exitCode !== null) break;
    await new Promise((resolve) => setTimeout(resolve, 30));
  }
  assert.ok(ready, output);
  const headers = { "content-type": "application/json", "user-agent": "Mozilla/5.0 ReviewBrowser/1.0", origin: base };
  const write = await fetch(`${base}/comments`, { method: "POST", headers, body: JSON.stringify({ name: "O'Reilly" }) });
  assert.equal(write.status, 200);
  await write.text();
  const writerCookie = write.headers.getSetCookie().find((cookie) => cookie.startsWith("dlsid=")).split(";", 1)[0];
  const writerId = writerCookie.slice("dlsid=".length);
  const read = await fetch(`${base}/reader`, { headers: { "user-agent": "Mozilla/5.0 OtherBrowser/2.0" } });
  assert.equal(read.status, 200);
  await read.text();
  const readerCookie = read.headers.getSetCookie().find((cookie) => cookie.startsWith("dlsid=")).split(";", 1)[0];
  const readerId = readerCookie.slice("dlsid=".length);
  const detail = async (id) => (await fetch(`${base}/__detection/api/sessions/${id}`)).json();
  const writer = await detail(writerId);
  const reader = await detail(readerId);
  assert.equal(writer.attackScore, 0.15);
  assert.equal(writer.attackHistory.maxAttackScore, 0.15);
  assert.deepEqual(writer.requests[0].xssTags, ["xss:stored-critical"]);
  assert.equal(reader.attackScore, 0);
  assert.deepEqual(reader.requests[0].xssTags, []);
  await (await fetch(`${base}/reader`, { headers: { cookie: readerCookie } })).text();
  assert.equal((await detail(writerId)).attackScore, 0.15);
  assert.equal((await detail(readerId)).attackScore, 0);
  const normal = await fetch(`${base}/normal?name=O%27Reilly`, { headers: { cookie: writerCookie } });
  assert.equal(normal.status, 200);
  await normal.text();
});
