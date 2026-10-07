const test = require("node:test");
const assert = require("node:assert/strict");
const { listenerBoundary } = require("../lib/listenerBoundary");

function allowed(port, method, path) {
  const middleware = listenerBoundary({ publicPort: 8081, adminPort: 8080 });
  let passed = false;
  let rejected = false;
  middleware(
    { socket: { localPort: port }, method, path },
    { status(code) { assert.equal(code, 404); rejected = true; return this; }, end() {} },
    () => { passed = true; }
  );
  assert.notEqual(passed, rejected);
  return passed;
}

test("public listener serves target traffic and telemetry but no management routes", () => {
  assert.equal(allowed(8081, "GET", "/"), true);
  assert.equal(allowed(8081, "GET", "/healthz"), true);
  assert.equal(allowed(8081, "GET", "/__detection/static/telemetry.js"), true);
  assert.equal(allowed(8081, "POST", "/__detection/telemetry"), true);
  assert.equal(allowed(8081, "GET", "/__detection/dashboard"), false);
  assert.equal(allowed(8081, "POST", "/__detection/api/target-selection"), false);
  assert.equal(allowed(8081, "GET", "/__defense/dashboard"), false);
});

test("admin listener never serves target content", () => {
  assert.equal(allowed(8080, "GET", "/"), false);
  assert.equal(allowed(8080, "GET", "/rest/products"), false);
  assert.equal(allowed(8080, "GET", "/__detection/dashboard"), true);
  assert.equal(allowed(8080, "POST", "/__detection/api/target-selection"), true);
  assert.equal(allowed(8080, "GET", "/__defense/dashboard"), true);
  assert.equal(allowed(8080, "POST", "/__detection/telemetry"), false);
  assert.equal(allowed(12345, "GET", "/__detection/dashboard"), false);
});
