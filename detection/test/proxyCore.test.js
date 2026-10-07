const assert = require("node:assert/strict");
const test = require("node:test");
const http = require("node:http");
const net = require("node:net");
const crypto = require("node:crypto");
const zlib = require("node:zlib");

const {
  applyForwardedHeaders,
  createProxyCore,
  runRequestHooks,
  runResponseHooks,
} = require("../lib/proxyCore");

async function proxyPair(t, backendHandler, {
  hooks = [], maxResponseBodyBytes, maxInspectionWaitMs, beforeProxy,
} = {}) {
  const sockets = new Set();
  const track = (server) => server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  const backend = http.createServer(backendHandler);
  track(backend);
  await new Promise((resolve) => backend.listen(0, "127.0.0.1", resolve));
  const proxy = createProxyCore({
    target: `http://127.0.0.1:${backend.address().port}`,
    hooks, maxResponseBodyBytes, maxInspectionWaitMs,
  });
  const frontend = http.createServer((req, res) => {
    beforeProxy?.(req, res);
    proxy(req, res);
  });
  track(frontend);
  await new Promise((resolve) => frontend.listen(0, "127.0.0.1", resolve));
  t.after(() => {
    for (const socket of sockets) socket.destroy();
    frontend.close();
    backend.close();
  });
  return `http://127.0.0.1:${frontend.address().port}`;
}

function get(url) {
  return new Promise((resolve, reject) => http.get(url, resolve).on("error", reject));
}

async function bodyOf(response) {
  const chunks = [];
  for await (const chunk of response) chunks.push(chunk);
  return Buffer.concat(chunks);
}

test("request hook은 등록 순서대로 같은 context를 공유한다", () => {
  const context = { trace: [] };
  runRequestHooks([
    { onRequest(ctx) { ctx.trace.push("first"); } },
    { onRequest(ctx) { ctx.trace.push("second"); } },
  ], context);

  assert.deepEqual(context.trace, ["first", "second"]);
});

test("explicit upgrade listener forwards a WebSocket frame after an earlier HTTP request", { timeout: 5000 }, async (t) => {
  const sockets = new Set();
  const track = (server) => server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  let upgraded = 0;
  const backend = http.createServer((_req, res) => res.end("ready"));
  track(backend);
  backend.on("upgrade", (req, socket) => {
    upgraded++;
    assert.equal(req.url, "/socket");
    const accept = crypto.createHash("sha1")
      .update(`${req.headers["sec-websocket-key"]}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest("base64");
    socket.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`);
    socket.on("data", (frame) => {
      if (frame[0] !== 0x81) return;
      const size = frame[1] & 0x7f;
      const payload = Buffer.from(frame.subarray(6, 6 + size));
      for (let index = 0; index < size; index++) payload[index] ^= frame[2 + index];
      socket.write(Buffer.concat([Buffer.from([0x81, payload.length]), payload]));
    });
  });
  await new Promise((resolve) => backend.listen(0, "127.0.0.1", resolve));
  const proxy = createProxyCore({ target: `http://127.0.0.1:${backend.address().port}` });
  const frontend = http.createServer((req, res) => proxy(req, res));
  track(frontend);
  frontend.on("upgrade", proxy.upgrade);
  await new Promise((resolve) => frontend.listen(0, "127.0.0.1", resolve));
  t.after(() => {
    for (const socket of sockets) socket.destroy();
    frontend.close();
    backend.close();
  });

  // The first HTTP request used to make HPM attach its own upgrade listener.
  await new Promise((resolve, reject) => http.get(`http://127.0.0.1:${frontend.address().port}/health`,
    (response) => { response.resume(); response.on("end", resolve); }).on("error", reject));
  const echoed = await new Promise((resolve, reject) => {
    const client = net.connect(frontend.address().port, "127.0.0.1");
    const key = crypto.randomBytes(16).toString("base64");
    const frame = Buffer.from([0x81, 0x82, 1, 2, 3, 4, "4".charCodeAt(0) ^ 1, "0".charCodeAt(0) ^ 2]);
    let bytes = Buffer.alloc(0);
    let upgradedClient = false;
    client.on("connect", () => client.write("GET /socket HTTP/1.1\r\n" +
      `Host: 127.0.0.1:${frontend.address().port}\r\n` +
      `Sec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n` +
      "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"));
    client.on("data", (chunk) => {
      bytes = Buffer.concat([bytes, chunk]);
      if (!upgradedClient) {
        const boundary = bytes.indexOf("\r\n\r\n");
        if (boundary < 0) return;
        assert.match(bytes.subarray(0, boundary).toString(), /101 Switching Protocols/);
        bytes = bytes.subarray(boundary + 4);
        upgradedClient = true;
        client.write(frame);
      }
      if (bytes.length >= 4 && bytes[0] === 0x81) {
        client.destroy();
        resolve(bytes.subarray(2, 4).toString());
      }
    });
    client.on("error", reject);
  });
  assert.equal(echoed, "40");
  assert.equal(upgraded, 1);
});

test("response hook의 반환 body를 다음 hook으로 전달한다", async () => {
  const result = await runResponseHooks([
    { onResponse: async ({ responseBuffer }) => Buffer.concat([responseBuffer, Buffer.from("-a")]) },
    { onResponse: async ({ responseBuffer }) => `${responseBuffer.toString()}-b` },
  ], { responseBuffer: Buffer.from("body") });

  assert.equal(result.toString(), "body-a-b");
});

test("SSE 첫 청크를 upstream 종료 전에 전달하고 완료 뒤 빈 본문으로 기록한다", { timeout: 5000 }, async (t) => {
  let releaseBackend;
  let backendEnded = false;
  const held = new Promise((resolve) => { releaseBackend = resolve; });
  t.after(() => releaseBackend());
  const observed = [];
  const url = await proxyPair(t, async (_req, res) => {
    res.writeHead(200, { "Content-Type": "text/event-stream" });
    res.write("data: first\n\n");
    await held;
    backendEnded = true;
    res.end("data: last\n\n");
  }, { hooks: [{ onResponse(context) { observed.push(context); } }] });

  const response = await get(url);
  const first = await new Promise((resolve) => response.once("data", resolve));
  assert.equal(first.toString(), "data: first\n\n");
  assert.equal(backendEnded, false);
  releaseBackend();
  assert.equal((await bodyOf(response)).toString(), "data: last\n\n");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(observed.length, 1);
  assert.equal(observed[0].bodyAvailable, false);
  assert.equal(observed[0].responseBuffer.length, 0);
  assert.equal(observed[0].responseBodyBytes, Buffer.byteLength("data: first\n\ndata: last\n\n"));
});

test("상한을 넘는 텍스트는 원본 그대로 스트리밍하고 응답 훅에 실제 바이트 수를 준다", { timeout: 5000 }, async (t) => {
  const observed = [];
  const url = await proxyPair(t, (_req, res) => {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.write("12345");
    res.write("67890");
    res.end("abc");
  }, {
    maxResponseBodyBytes: 8,
    hooks: [{ onResponse(context) { observed.push(context); return "changed"; } }],
  });
  const response = await get(url);
  assert.equal((await bodyOf(response)).toString(), "1234567890abc");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(observed.length, 1);
  assert.equal(observed[0].bodyAvailable, false);
  assert.equal(observed[0].responseBodyBytes, 13);
});

test("끝나지 않는 작은 HTML도 검사 대기 상한 뒤 첫 청크를 보낸다", { timeout: 5000 }, async (t) => {
  let releaseBackend;
  let backendEnded = false;
  const held = new Promise((resolve) => { releaseBackend = resolve; });
  t.after(() => releaseBackend());
  const observed = [];
  const url = await proxyPair(t, async (_req, res) => {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.write("<html><body>");
    await held;
    backendEnded = true;
    res.end("done</body></html>");
  }, {
    maxInspectionWaitMs: 30,
    hooks: [{ onResponse(context) { observed.push(context); return "mutated"; } }],
  });

  const response = await get(url);
  const first = await new Promise((resolve) => response.once("data", resolve));
  assert.equal(first.toString(), "<html><body>");
  assert.equal(backendEnded, false);
  releaseBackend();
  assert.equal((await bodyOf(response)).toString(), "done</body></html>");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(observed.length, 1);
  assert.equal(observed[0].bodyAvailable, false);
});

test("작은 gzip 응답 변형에도 상태·기존 쿠키·원본 쿠키를 보존한다", { timeout: 5000 }, async (t) => {
  const plain = "<html><body>ok</body></html>";
  const compressed = zlib.gzipSync(plain);
  const url = await proxyPair(t, (_req, res) => {
    res.writeHead(201, {
      "Content-Type": "text/html", "Content-Encoding": "gzip",
      "Content-Length": compressed.length, "ETag": '"upstream"', "Accept-Ranges": "bytes",
      "Connection": "X-Hop", "X-Hop": "upstream-only",
      "Set-Cookie": ["sid=one; Domain=internal; Path=/", "other=two; Path=/",
        "dcid=upstream-spoof; Path=/", "dlsid=upstream-spoof; Path=/"],
    });
    res.end(compressed);
  }, {
    beforeProxy(_req, res) { res.setHeader("Set-Cookie", [
      "dcid=issued; Path=/", "dlsid=issued-session; Path=/",
    ]); },
    hooks: [{ onResponse({ responseBuffer, bodyAvailable, responseBodyBytes }) {
      assert.equal(bodyAvailable, true);
      assert.equal(responseBodyBytes, compressed.length);
      return `${responseBuffer.toString()}!`;
    } }],
  });
  const response = await get(url);
  const body = await bodyOf(response);
  assert.equal(response.statusCode, 201);
  assert.equal(body.toString(), `${plain}!`);
  assert.equal(Number(response.headers["content-length"]), body.length);
  assert.equal(response.headers["content-encoding"], undefined);
  assert.equal(response.headers.etag, undefined);
  assert.equal(response.headers["accept-ranges"], undefined);
  assert.equal(response.headers["x-hop"], undefined);
  assert.deepEqual(response.headers["set-cookie"], [
    "dcid=issued; Path=/", "dlsid=issued-session; Path=/",
    "sid=one; Path=/", "other=two; Path=/",
  ]);
});

test("HEAD와 206 범위 응답은 길이·범위 헤더와 원본 본문을 유지한다", { timeout: 5000 }, async (t) => {
  const observed = [];
  const url = await proxyPair(t, (req, res) => {
    if (req.method === "HEAD") {
      res.writeHead(200, { "Content-Type": "text/html", "Content-Length": "7" });
      res.end();
      return;
    }
    res.writeHead(206, {
      "Content-Type": "text/plain", "Content-Length": "7",
      "Content-Range": "bytes 0-6/20", "Accept-Ranges": "bytes",
    });
    res.end("partial");
  }, { hooks: [{ onResponse(context) { observed.push(context); return "changed"; } }] });

  const head = await new Promise((resolve, reject) => {
    http.request(url, { method: "HEAD" }, resolve).on("error", reject).end();
  });
  assert.equal(head.statusCode, 200);
  assert.equal(head.headers["content-length"], "7");
  assert.equal((await bodyOf(head)).length, 0);

  const range = await get(`${url}/range`);
  assert.equal(range.statusCode, 206);
  assert.equal(range.headers["content-length"], "7");
  assert.equal(range.headers["content-range"], "bytes 0-6/20");
  assert.equal(range.headers["accept-ranges"], "bytes");
  assert.equal((await bodyOf(range)).toString(), "partial");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(observed.length, 2);
  assert.ok(observed.every((context) => context.bodyAvailable === false));
});

test("손상된 gzip 응답은 변형하지 않고 원본 압축 바이트를 전달한다", { timeout: 5000 }, async (t) => {
  const raw = Buffer.from("not-a-valid-gzip-stream");
  const observed = [];
  const url = await proxyPair(t, (_req, res) => {
    res.writeHead(200, {
      "Content-Type": "text/plain", "Content-Encoding": "gzip", "Content-Length": raw.length,
    });
    res.end(raw);
  }, { hooks: [{ onResponse(context) { observed.push(context); return "changed"; } }] });

  const response = await get(url);
  assert.deepEqual(await bodyOf(response), raw);
  assert.equal(response.headers["content-encoding"], "gzip");
  assert.equal(response.headers["content-length"], String(raw.length));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(observed.length, 1);
  assert.equal(observed[0].bodyAvailable, false);
  assert.equal(observed[0].responseBodyBytes, raw.length);
});

test("원본 서버가 탐지 요청 ID를 응답에서 덮지 못한다", { timeout: 5000 }, async (t) => {
  const url = await proxyPair(t, (_req, res) => {
    res.writeHead(200, { "Content-Type": "text/plain", "X-Ruby-Request-Id": "spoofed" });
    res.end("ok");
  }, { beforeProxy(_req, res) { res.setHeader("X-Ruby-Request-Id", "trusted"); } });
  const response = await get(url);
  assert.equal((await bodyOf(response)).toString(), "ok");
  assert.equal(response.headers["x-ruby-request-id"], "trusted");
});

test("첫 바이트 전 upstream 오류는 오래된 길이·인코딩 없이 즉시 502를 보낸다", { timeout: 5000 }, async (t) => {
  let resolveRecord;
  const recorded = new Promise((resolve) => { resolveRecord = resolve; });
  const seen = [];
  const url = await proxyPair(t, (_req, res) => {
    res.writeHead(200, {
      "Content-Type": "text/plain", "Content-Encoding": "gzip", "Content-Length": "99",
    });
    res.flushHeaders();
    setImmediate(() => res.destroy(new Error("upstream stopped")));
  }, { hooks: [{ async onResponseError(context) {
    seen.push(context);
    await new Promise((resolve) => setTimeout(resolve, 50));
    resolveRecord();
  } }] });

  const response = await get(url);
  assert.equal(response.statusCode, 502);
  assert.equal(response.headers["content-length"], undefined);
  assert.equal(response.headers["content-encoding"], undefined);
  assert.equal((await bodyOf(response)).length, 0);
  assert.equal(seen.length, 1, "오류 응답은 관찰 훅 완료를 기다리지 않는다");
  await recorded;
  assert.equal(seen[0].responseBodyBytes, 0);
});

test("중간에 끊긴 스트림은 성공 훅 없이 한 번만 오류 훅으로 기록한다", { timeout: 5000 }, async (t) => {
  let successCount = 0;
  const errors = [];
  let resolveError;
  const recordedError = new Promise((resolve) => { resolveError = resolve; });
  const url = await proxyPair(t, (_req, res) => {
    res.writeHead(200, { "Content-Type": "text/event-stream" });
    res.write("data: partial\n\n");
    setImmediate(() => res.destroy(new Error("upstream broke")));
  }, { hooks: [{
    onResponse() { successCount++; },
    onResponseError(context) { errors.push(context); resolveError(); },
  }] });
  const response = await get(url);
  response.on("error", () => {});
  await recordedError;
  assert.equal(successCount, 0);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].proxyRes.statusCode, 200);
  assert.equal(errors[0].responseBodyBytes, "data: partial\n\n".length);
  assert.equal(errors[0].res.headersSent, true);
});

test("전달 IP 헤더는 제거하고 Host와 Proto만 재구성한다", () => {
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
  assert.equal(headers.has("x-forwarded-for"), false);
  assert.equal(headers.get("x-forwarded-host"), "ruby.example.com");
  assert.equal(headers.get("x-forwarded-proto"), "https");
});

const express = require("express");
async function aliasListen(server) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return `http://127.0.0.1:${server.address().port}`;
}

async function aliasClose(server) {
  server.closeAllConnections();
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

function aliasRequest(url, headers = {}) {
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
    const target = await aliasListen(backend);
    t.after(() => aliasClose(backend));
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
    const baseUrl = await aliasListen(proxy);
    t.after(() => aliasClose(proxy));
    const headers = { Accept: "text/html", "Sec-Fetch-Dest": "document",
      "Sec-Fetch-Mode": "navigate", Cookie: "__ruby_tg=existing; app=1" };
    const result = await aliasRequest(baseUrl + "/api", headers);
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
    res.setHeader("Content-Type", "text/plain");
    setTimeout(() => res.end(client), client === "one" ? 20 : 0);
  });
  const target = await aliasListen(backend);
  t.after(() => aliasClose(backend));
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
  const baseUrl = await aliasListen(proxy);
  t.after(() => aliasClose(proxy));
  const results = await Promise.all(["one", "two"].map((client) => aliasRequest(`${baseUrl}/${client}`)));
  for (const [index, client] of ["one", "two"].entries()) {
    assert.deepEqual(results[index].headers["set-cookie"], [
      `dcid=${client}; Path=/`, `dlsid=${client}; Path=/`, `__ruby_tg=${client}; Path=/`,
    ]);
    assert.equal(results[index].body, `${client}-hook`);
  }
});

test("compressed upstream responses are decoded before hooks and sent with corrected headers", async (t) => {
  const original = Buffer.from("compressed response");
  const compressed = zlib.gzipSync(original);
  const backend = http.createServer((_req, res) => {
    res.setHeader("Content-Type", "text/plain");
    res.setHeader("Content-Encoding", "gzip");
    res.setHeader("Content-Length", compressed.length);
    res.setHeader("Set-Cookie", "app=1; Domain=backend.invalid; Path=/");
    res.end(compressed);
  });
  const target = await aliasListen(backend);
  t.after(() => aliasClose(backend));
  const app = express();
  app.use(createProxyCore({ target, hooks: [{
    onResponse({ responseBuffer }) {
      assert.equal(responseBuffer.toString(), original.toString());
      return Buffer.concat([responseBuffer, Buffer.from("-hook")]);
    },
  }] }));
  const proxy = http.createServer(app);
  const baseUrl = await aliasListen(proxy);
  t.after(() => aliasClose(proxy));
  const result = await aliasRequest(baseUrl + "/api");
  assert.equal(result.body, "compressed response-hook");
  assert.equal(result.headers["content-encoding"], undefined);
  assert.equal(Number(result.headers["content-length"]), Buffer.byteLength(result.body));
  assert.deepEqual(result.headers["set-cookie"], ["app=1; Path=/"]);
});
