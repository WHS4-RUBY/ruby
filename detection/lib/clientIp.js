function parseTrustProxy(value = process.env.TRUST_PROXY) {
  if (value === undefined || value === null || value === "" || value === "false") return false;
  if (value === "true") return true;
  if (/^\d+$/.test(String(value))) return Number(value);
  return String(value).split(",").map((item) => item.trim()).filter(Boolean);
}

function getClientIp(req) {
  return req.ip || req.socket?.remoteAddress || "unknown";
}

module.exports = { parseTrustProxy, getClientIp };
