const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { PassThrough } = require("node:stream");
const test = require("node:test");

const {
  CrsScanner,
  normalizeHeaderValues,
  requestBodyBuffer,
} = require("../lib/crsScanner");

function fakeScannerProcess(onRequest) {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.stdin = new PassThrough();
  let buffered = "";
  child.stdin.on("data", (chunk) => {
    buffered += String(chunk);
    const lines = buffered.split("\n");
    buffered = lines.pop();
    for (const line of lines) {
      if (!line) continue;
      const request = JSON.parse(line);
      const result = onRequest(request);
      child.stdout.write(`${JSON.stringify({ id: request.id, ...result })}\n`);
    }
  });
  return child;
}

test("CRS scanner는 헤더와 제한된 원문 body를 JSONL helper에 전달한다", async () => {
  let observed;
  const scanner = new CrsScanner({
    maximumBodyBytes: 4,
    spawnProcess: () => fakeScannerProcess((request) => {
      observed = request;
      return {
        available: true,
        crsVersion: "test",
        anomalyScore: 5,
        ruleHitCount: 1,
        categories: ["sqli"],
        hits: [{ ruleId: "942100" }],
      };
    }),
  });

  const result = await scanner.scan({
    method: "POST",
    originalUrl: "/login?q=1",
    httpVersion: "1.1",
    headers: {
      accept: ["text/html", "application/json"],
      authorization: "Bearer must-not-leave-node",
      cookie: "token=must-not-leave-node",
      empty: null,
    },
    detectionRequestBodyBuffer: Buffer.from("abcdef"),
  }, "192.0.2.10");

  assert.equal(result.available, true);
  assert.equal(result.ruleHitCount, 1);
  assert.equal(observed.headers.accept, "text/html, application/json");
  assert.equal(observed.headers.empty, undefined);
  assert.equal(observed.headers.authorization, undefined);
  assert.equal(observed.headers.cookie, undefined);
  assert.equal(Buffer.from(observed.bodyBase64, "base64").toString(), "abcd");
  assert.equal(observed.bodyTruncated, true);
});

test("CRS 비활성화 시 helper를 실행하지 않고 unavailable 관찰값을 반환한다", async () => {
  let spawned = false;
  const scanner = new CrsScanner({
    enabled: false,
    spawnProcess: () => {
      spawned = true;
      return fakeScannerProcess(() => ({}));
    },
  });
  const result = await scanner.scan({ method: "GET", headers: {} }, "127.0.0.1");
  assert.equal(spawned, false);
  assert.equal(result.available, false);
  assert.match(result.error, /disabled/);
});

test("헤더 정규화와 body 길이 제한 helper가 입력을 변형하지 않는다", () => {
  assert.deepEqual(normalizeHeaderValues({ a: 1, b: undefined }), { a: "1" });
  const source = Buffer.from("123456");
  assert.equal(requestBodyBuffer({ detectionRequestBodyBuffer: source }, 3).toString(), "123");
  assert.equal(source.toString(), "123456");
});
