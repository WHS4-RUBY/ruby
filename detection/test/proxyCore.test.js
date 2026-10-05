const assert = require("node:assert/strict");
const test = require("node:test");
const http = require("node:http");
const net = require("node:net");
const crypto = require("node:crypto");

const {
  applyForwardedHeaders,
  createProxyCore,
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
