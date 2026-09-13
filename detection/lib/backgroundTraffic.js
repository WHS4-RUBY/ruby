const crypto = require("crypto");

const SOCKET_IO_PATH = "/socket.io/";

function hashConnectionId(value) {
  if (!value) return null;
  return `socket:${crypto.createHash("sha256").update(String(value)).digest("hex").slice(0, 16)}`;
}

function classifyBackgroundTraffic(url) {
  let parsed;
  try {
    parsed = new URL(String(url || "/"), "http://detector.local");
  } catch (_) {
    return null;
  }

  const pathname = parsed.pathname.endsWith("/") ? parsed.pathname : `${parsed.pathname}/`;
  if (pathname !== SOCKET_IO_PATH) return null;

  const transport = parsed.searchParams.get("transport") || "unknown";
  const socketSessionId = parsed.searchParams.get("sid");
  return {
    isBackground: true,
    category: transport === "polling" ? "socket_io_polling" : "socket_io",
    label: "background:socket_io",
    transport,
    connectionId: hashConnectionId(socketSessionId),
    connectionPhase: socketSessionId ? "established" : "handshake",
  };
}

function isBehaviorAnalyzable(request) {
  return request?.backgroundTraffic?.isBackground !== true;
}

module.exports = {
  SOCKET_IO_PATH,
  classifyBackgroundTraffic,
  isBehaviorAnalyzable,
};
