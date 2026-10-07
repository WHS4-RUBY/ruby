const assert = require("node:assert/strict");
const test = require("node:test");

const {
  createProxyCore,
  applyForwardedHeaders,
  runRequestHooks,
  runResponseHooks,
} = require("../lib/proxyCore");

test("request hook은 등록 순서대로 같은 context를 공유한다", () => {
  const context = { trace: [] };
  runRequestHooks([
    { onRequest(ctx) { ctx.trace.push("first"); } },
    { onRequest(ctx) { ctx.trace.push("second"); } },
  ], context);

  assert.deepEqual(context.trace, ["first", "second"]);
});

test("response hook의 반환 body를 다음 hook으로 전달한다", async () => {
  const result = await runResponseHooks([
    { onResponse: async ({ responseBuffer }) => Buffer.concat([responseBuffer, Buffer.from("-a")]) },
    { onResponse: async ({ responseBuffer }) => `${responseBuffer.toString()}-b` },
  ], { responseBuffer: Buffer.from("body") });

  assert.equal(result.toString(), "body-a-b");
});


const http = require("node:http");
const express = require("express");

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return `http://127.0.0.1:${server.address().port}`;
}

async function close(server) {
  server.closeAllConnections();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

function request(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { headers }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers,
        body: Buffer.concat(chunks).toString("utf8") }));
      res.on("error", reject);
    });
    req.on("error", reject);
  });
}

for (const scenario of [
  { name: "local and upstream cookies", local: ["dlsid=session; Path=/", "dcid=client; Path=/"],
    upstream: ["first=1; Path=/", "second=2; Path=/", "__ruby_tg=token; Path=/; HttpOnly"] },
  { name: "local cookies only", local: ["dlsid=session; Path=/", "dcid=client; Path=/"], upstream: [] },
  { name: "upstream cookies only", local: [], upstream: ["__ruby_tg=token; Path=/; HttpOnly"] },
  { name: "no cookies", local: [], upstream: [] },
  { name: "single string local cookie", local: "dcid=client; Path=/", upstream: ["app=1; Path=/"] },
]) {
  test(`proxy preserves ${scenario.name} and forwards request headers`, async (t) => {
    let received;
    let seenByResponseHook;
    const backend = http.createServer((req, res) => {
      received = req.headers;
      if (scenario.upstream.length) res.setHeader("Set-Cookie", scenario.upstream);
      res.setHeader("Content-Type", "application/json");
      res.setHeader("X-App", "unchanged");
      res.end('{"ok":true}');
    });
    const target = await listen(backend);
    t.after(() => close(backend));
    const app = express();
    app.use((_req, res, next) => {
      if (scenario.local.length) res.setHeader("Set-Cookie", scenario.local);
      next();
    });
    app.use(createProxyCore({ target, hooks: [{
      onResponse({ res, responseBuffer }) {
        seenByResponseHook = res.getHeader("set-cookie");
        return responseBuffer;
      },
    }] }));
    const proxy = http.createServer(app);
    const baseUrl = await listen(proxy);
    t.after(() => close(proxy));
    const headers = { Accept: "text/html", "Sec-Fetch-Dest": "document",
      "Sec-Fetch-Mode": "navigate", Cookie: "__ruby_tg=existing; app=1" };
    const result = await request(baseUrl + "/api", headers);
    const local = Array.isArray(scenario.local) ? scenario.local : [scenario.local];
    const expected = [...local, ...scenario.upstream];
    assert.deepEqual(result.headers["set-cookie"] || [], expected);
    assert.deepEqual(seenByResponseHook === undefined ? []
      : Array.isArray(seenByResponseHook) ? seenByResponseHook : [seenByResponseHook], expected);
    assert.equal(result.status, 200);
    assert.equal(result.body, '{"ok":true}');
    assert.equal(result.headers["x-app"], "unchanged");
    for (const [name, value] of Object.entries(headers)) assert.equal(received[name.toLowerCase()], value);
  });
}

test("concurrent proxy responses keep cookie snapshots isolated and preserve body hooks", async (t) => {
  const backend = http.createServer((req, res) => {
    const client = req.url.slice(1);
    res.setHeader("Set-Cookie", [`__ruby_tg=${client}; Path=/`]);
    setTimeout(() => res.end(client), client === "one" ? 20 : 0);
  });
  const target = await listen(backend);
  t.after(() => close(backend));
  const app = express();
  app.use((req, res, next) => {
    res.setHeader("Set-Cookie", [`dcid=${req.url.slice(1)}; Path=/`]);
    next();
  });
  app.use(createProxyCore({ target, hooks: [{
    onRequest({ req, res }) { res.append("Set-Cookie", `dlsid=${req.url.slice(1)}; Path=/`); },
    onResponse({ responseBuffer }) { return Buffer.concat([responseBuffer, Buffer.from("-hook")]); },
  }] }));
  const proxy = http.createServer(app);
  const baseUrl = await listen(proxy);
  t.after(() => close(proxy));
  const results = await Promise.all(["one", "two"].map((client) => request(`${baseUrl}/${client}`)));
  for (const [index, client] of ["one", "two"].entries()) {
    assert.deepEqual(results[index].headers["set-cookie"], [
      `dcid=${client}; Path=/`, `dlsid=${client}; Path=/`, `__ruby_tg=${client}; Path=/`,
    ]);
    assert.equal(results[index].body, `${client}-hook`);
  }
});

test("외부 Forwarded 헤더를 제거하고 Express가 검증한 연결 정보로 교체한다", () => {
  const headers = new Map([
    ["forwarded", "for=attacker"],
    ["x-forwarded-for", "attacker"],
  ]);
  const proxyReq = {
    removeHeader: (name) => headers.delete(name.toLowerCase()),
    setHeader: (name, value) => headers.set(name.toLowerCase(), value),
  };
  const req = {
    ip: "203.0.113.10",
    protocol: "https",
    headers: { host: "ruby.example.com" },
    get: (name) => (name === "host" ? "ruby.example.com" : undefined),
  };

  applyForwardedHeaders(proxyReq, req);

  assert.equal(headers.has("forwarded"), false);
  assert.equal(headers.get("x-forwarded-for"), "203.0.113.10");
  assert.equal(headers.get("x-forwarded-host"), "ruby.example.com");
  assert.equal(headers.get("x-forwarded-proto"), "https");
});
