const assert = require("node:assert/strict");
const test = require("node:test");

const {
  classifyBackgroundTraffic,
  isBehaviorAnalyzable,
} = require("../lib/backgroundTraffic");

test("Socket.IO polling을 background traffic으로 분류하고 sid는 hash만 보존한다", () => {
  const classified = classifyBackgroundTraffic(
    "/socket.io/?EIO=4&transport=polling&t=Q248YoN&sid=nJwViKweS4Nf4m1AAAAO"
  );

  assert.deepEqual(
    {
      isBackground: classified.isBackground,
      category: classified.category,
      label: classified.label,
      transport: classified.transport,
      connectionPhase: classified.connectionPhase,
    },
    {
      isBackground: true,
      category: "socket_io_polling",
      label: "background:socket_io",
      transport: "polling",
      connectionPhase: "established",
    }
  );
  assert.match(classified.connectionId, /^socket:[a-f0-9]{16}$/);
  assert.equal(JSON.stringify(classified).includes("nJwViKweS4Nf4m1AAAAO"), false);
  assert.equal(isBehaviorAnalyzable({ backgroundTraffic: classified }), false);
});

test("Socket.IO handshake와 일반 요청을 구분한다", () => {
  const handshake = classifyBackgroundTraffic("/socket.io?EIO=4&transport=polling&t=one");
  assert.equal(handshake.connectionPhase, "handshake");
  assert.equal(handshake.connectionId, null);
  assert.equal(classifyBackgroundTraffic("/api/Products/?transport=polling"), null);
  assert.equal(isBehaviorAnalyzable({ normalizedPath: "/api/Products/" }), true);
});
