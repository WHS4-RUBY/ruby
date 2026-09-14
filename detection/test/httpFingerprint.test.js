const assert = require("node:assert/strict");
const test = require("node:test");

const {
  buildHttpFingerprint,
  headerNamesInOrder,
  userAgentProduct,
} = require("../lib/httpFingerprint");

const baseHeaders = {
  "user-agent": "Mozilla/5.0 Chrome/140.0.0.0 Safari/537.36",
  "accept-language": "ko-KR,ko;q=0.9,en;q=0.8",
  "accept-encoding": "gzip, deflate, br",
  "sec-ch-ua-platform": '"Windows"',
};

test("resource-specific Accept changes request fingerprint but not client fingerprint", () => {
  const document = buildHttpFingerprint({
    headers: { ...baseHeaders, accept: "text/html,application/xhtml+xml" },
    rawHeaders: ["User-Agent", baseHeaders["user-agent"], "Accept", "text/html"],
    httpVersion: "1.1",
    method: "GET",
  });
  const api = buildHttpFingerprint({
    headers: { ...baseHeaders, accept: "application/json" },
    rawHeaders: ["Accept", "application/json", "User-Agent", baseHeaders["user-agent"]],
    httpVersion: "1.1",
    method: "GET",
  });

  assert.equal(document.clientFingerprint, api.clientFingerprint);
  assert.notEqual(document.requestFingerprint, api.requestFingerprint);
  assert.notEqual(document.headerOrderFingerprint, api.headerOrderFingerprint);
});

test("client attributes change the client fingerprint", () => {
  const chrome = buildHttpFingerprint({ headers: baseHeaders });
  const curl = buildHttpFingerprint({
    headers: { "user-agent": "curl/8.10.1", accept: "*/*" },
  });
  assert.notEqual(chrome.clientFingerprint, curl.clientFingerprint);
  assert.deepEqual(userAgentProduct("curl/8.10.1"), { family: "curl", major: "8" });
});

test("ground-truth and credential headers never enter the order fingerprint", () => {
  const names = headerNamesInOrder([
    "Host", "localhost",
    "X-Attacker-ID", "agent-a",
    "X-Experiment-Run-ID", "run-a",
    "Authorization", "Bearer secret",
    "Cookie", "dcid=secret",
    "Accept", "*/*",
  ], {});
  assert.deepEqual(names, ["host", "accept"]);
});
