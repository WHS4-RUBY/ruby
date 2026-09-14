const test = require("node:test");
const assert = require("node:assert/strict");

const {
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
