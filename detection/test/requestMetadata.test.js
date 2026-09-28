const assert = require("node:assert/strict");
const test = require("node:test");

const {
  normalizePath,
  canonicalPayload,
  createPayloadFingerprint,
  sanitizeExperimentRunId,
  sanitizeMetadataHeaderValue,
  parseContentLength,
} = require("../lib/requestMetadata");

test("numeric ID, UUID, query를 보수적으로 normalizedPath로 변환한다", () => {
  assert.equal(normalizePath("/api/Users/123?detail=true"), "/api/Users/:id");
  assert.equal(normalizePath("/rest/basket/12"), "/rest/basket/:id");
  assert.equal(
    normalizePath("/users/550e8400-e29b-41d4-a716-446655440000"),
    "/users/:uuid"
  );
  assert.equal(normalizePath("/search?q=test"), "/search");
  assert.equal(normalizePath("/products/abc123"), "/products/abc123");
});

test("JSON과 form payload는 key 순서와 무관하게 같은 HMAC fingerprint를 만든다", () => {
  const key = "unit-test-hmac-key";
  const first = createPayloadFingerprint(
    { b: 2, a: { y: 2, x: 1 } },
    "application/json",
    key
  );
  const second = createPayloadFingerprint(
    { a: { x: 1, y: 2 }, b: 2 },
    "application/json",
    key
  );
  assert.equal(first, second);
  assert.notEqual(first, createPayloadFingerprint({ a: 2, b: 2 }, "application/json", key));
  assert.equal(
    createPayloadFingerprint("b=2&a=1", "application/x-www-form-urlencoded", key),
    createPayloadFingerprint("a=1&b=2", "application/x-www-form-urlencoded", key)
  );
  assert.equal(createPayloadFingerprint({}, "application/json", key), null);
  assert.equal(canonicalPayload([2, 1], "application/json"), "[2,1]");
});

test("experimentRunId는 제한된 실험 식별자만 허용한다", () => {
  assert.equal(sanitizeExperimentRunId("codex-run-001"), "codex-run-001");
  assert.equal(sanitizeExperimentRunId(" human_curl_001 "), "human_curl_001");
  assert.equal(sanitizeExperimentRunId("bad value"), null);
  assert.equal(sanitizeExperimentRunId("x".repeat(65)), null);
});

test("로깅용 헤더 값과 Content-Length를 보수적으로 정규화한다", () => {
  assert.equal(sanitizeMetadataHeaderValue("application/json; charset=utf-8"), "application/json; charset=utf-8");
  assert.equal(sanitizeMetadataHeaderValue(["text/plain", "ignored"]), "text/plain");
  assert.equal(sanitizeMetadataHeaderValue(undefined), null);
  assert.equal(sanitizeMetadataHeaderValue("x".repeat(300)).length, 256);
  assert.equal(parseContentLength("123"), 123);
  assert.equal(parseContentLength(" 0 "), 0);
  assert.equal(parseContentLength("12.5"), null);
  assert.equal(parseContentLength("-1"), null);
  assert.equal(parseContentLength(undefined), null);
});
