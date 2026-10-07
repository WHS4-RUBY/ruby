"use strict";

function isDetectionPath(pathname) {
  return pathname === "/__detection" || pathname.startsWith("/__detection/");
}

function isDefensePath(pathname) {
  return pathname === "/__defense" || pathname.startsWith("/__defense/");
}

function isPublicTelemetry(req) {
  return (req.method === "GET" && req.path === "/__detection/static/telemetry.js") ||
    (req.method === "POST" && req.path === "/__detection/telemetry");
}

function listenerBoundary({ publicPort, adminPort }) {
  if (adminPort === null || adminPort === undefined) return (_req, _res, next) => next();
  if (!Number.isInteger(publicPort) || publicPort < 1 || publicPort > 65535 ||
      !Number.isInteger(adminPort) || adminPort < 1 || adminPort > 65535 ||
      publicPort === adminPort) {
    throw new Error("public and admin listener ports must be distinct");
  }
  return (req, res, next) => {
    const port = req.socket.localPort;
    const managementPath = isDetectionPath(req.path) || isDefensePath(req.path);
    if (port === publicPort) {
      if (!managementPath || isPublicTelemetry(req)) return next();
    } else if (port === adminPort) {
      if (req.path === "/healthz" || (managementPath && !isPublicTelemetry(req))) return next();
    }
    return res.status(404).end();
  };
}

module.exports = { listenerBoundary };
