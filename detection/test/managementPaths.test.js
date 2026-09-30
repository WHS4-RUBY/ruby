const test = require("node:test");
const assert = require("node:assert/strict");

const {
  applyDefenseManagementHeaders,
  isDefenseManagementPath,
} = require("../lib/managementPaths");

test("Defense 관리 경로만 탐지 훅 우회 대상으로 판정한다", () => {
  assert.equal(isDefenseManagementPath("/__defense"), true);
  assert.equal(isDefenseManagementPath("/__defense/dashboard"), true);
  assert.equal(isDefenseManagementPath("/__defense/api/summary"), true);
  assert.equal(isDefenseManagementPath("/__detection/dashboard"), false);
  assert.equal(isDefenseManagementPath("/api/__defense"), false);
});

test("Defense 관리 클라이언트 헤더는 외부 값을 제거하고 실제 요청 IP로 교체한다", () => {
  const headers = new Map([["x-defense-management-client", "spoofed"]]);
  const proxyReq = {
    removeHeader(name) {
      headers.delete(name.toLowerCase());
    },
    setHeader(name, value) {
      headers.set(name.toLowerCase(), value);
    },
  };

  applyDefenseManagementHeaders(proxyReq, { ip: "203.0.113.7" });

  assert.equal(headers.get("x-defense-management-client"), "203.0.113.7");
});
