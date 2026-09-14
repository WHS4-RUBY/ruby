const assert = require("node:assert/strict");
const { existsSync } = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const SCANNER_PATH = process.env.MODSECURITY_SCANNER_PATH || "/app/bin/modsecurity-scanner";
const RULES_PATH = process.env.MODSECURITY_RULES_FILE
  || path.join(__dirname, "..", "scanner", "modsecurity.conf");

function scannerRequest(id, contentType, body) {
  const bodyBuffer = Buffer.from(body);
  return {
    id,
    method: "POST",
    uri: "/rest/user/login",
    protocol: "1.1",
    clientIp: "127.0.0.1",
    headers: {
      "content-type": contentType,
      "content-length": String(bodyBuffer.length),
    },
    bodyBase64: bodyBuffer.toString("base64"),
  };
}

function runScanner(requests) {
  const input = `${requests.map((request) => JSON.stringify(request)).join("\n")}\n`;
  const result = spawnSync(SCANNER_PATH, [RULES_PATH], {
    input,
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim().split("\n").map((line) => JSON.parse(line));
}

test("실제 CRS 바이너리가 JSON·+json·URL-encoded SQLi를 탐지하고 정상 JSON은 통과시킨다", {
  skip: !existsSync(SCANNER_PATH) || !existsSync(RULES_PATH),
}, () => {
  const exactBody = JSON.stringify({
    email: "' or '1' = '1' #--",
    password: "123123",
  });
  const requests = [
    scannerRequest("json-exact", "application/json", exactBody),
    scannerRequest(
      "json-charset",
      "application/json; charset=utf-8",
      JSON.stringify({ email: "' OR 1=1--", password: "x" })
    ),
    scannerRequest(
      "problem-json",
      "application/problem+json",
      JSON.stringify({ email: "' UNION SELECT 1,2,3--", password: "x" })
    ),
    scannerRequest(
      "json-xss",
      "application/json",
      JSON.stringify({ value: "<script>alert(1)</script>" })
    ),
    scannerRequest(
      "urlencoded",
      "application/x-www-form-urlencoded",
      "email=%27+OR+1%3D1--&password=x"
    ),
    scannerRequest(
      "clean-json",
      "application/json",
      JSON.stringify({ email: "normal@example.com", password: "ordinary-value" })
    ),
  ];

  const results = Object.fromEntries(runScanner(requests).map((result) => [result.id, result]));
  for (const id of ["json-exact", "json-charset", "problem-json", "urlencoded"]) {
    assert.equal(results[id].available, true);
    assert.ok(results[id].anomalyScore >= 5, `${id} anomaly score was ${results[id].anomalyScore}`);
    assert.ok(results[id].categories.includes("sqli"), `${id} did not include the sqli category`);
    assert.ok(results[id].hits.some((hit) => hit.ruleId === "942100"));
  }

  assert.ok(results["json-xss"].anomalyScore >= 5);
  assert.ok(results["json-xss"].categories.includes("xss"));
  assert.ok(results["json-xss"].hits.some((hit) => hit.ruleId === "941100"));

  assert.equal(results["clean-json"].available, true);
  assert.equal(results["clean-json"].anomalyScore, 0);
  assert.deepEqual(results["clean-json"].hits, []);
});
