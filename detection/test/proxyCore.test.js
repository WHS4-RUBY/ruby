const assert = require("node:assert/strict");
const test = require("node:test");

const {
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
