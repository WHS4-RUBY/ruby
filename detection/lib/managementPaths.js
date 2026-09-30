function isDefenseManagementPath(pathname) {
  const value = String(pathname || "");
  return value === "/__defense" || value.startsWith("/__defense/");
}

function applyDefenseManagementHeaders(proxyReq, req) {
  proxyReq.removeHeader("x-defense-management-client");
  proxyReq.setHeader("X-Defense-Management-Client", req.ip || "unknown");
}

module.exports = { applyDefenseManagementHeaders, isDefenseManagementPath };
