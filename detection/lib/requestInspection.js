// The proxy must not be created/dispatched until inspection has finished.
// Scores here are the helper's attack-rule subtotal, not CRS's full native score.
const { unavailableResult } = require("./crsScanner");

function loadInspectionConfig(env = process.env) {
  const mode = String(env.CRS_MODE || "observe").trim().toLowerCase();
  if (!["off", "observe", "enforce"].includes(mode)) {
    throw new Error("CRS_MODE must be off, observe or enforce");
  }
  const threshold = Number(env.CRS_BLOCK_THRESHOLD ?? 5);
  if (!Number.isFinite(threshold) || threshold <= 0) {
    throw new Error("CRS_BLOCK_THRESHOLD must be a positive number");
  }
  if (mode === "enforce" && env.CRS_ENABLED === "false") {
    throw new Error("CRS enforce requires CRS_ENABLED=true");
  }
  return { mode, threshold };
}

function bodyInspectionIssue(req, maximumBytes) {
  const raw = req.detectionRequestBodyBuffer;
  const contentLength = Number(req.headers["content-length"] || 0);
  if (contentLength > maximumBytes || (Buffer.isBuffer(raw) && raw.length > maximumBytes)) {
    return "body_too_large";
  }
  const hasBody = contentLength > 0 || Boolean(req.headers["transfer-encoding"])
    || (Buffer.isBuffer(raw) && raw.length > 0);
  if (!hasBody) return null;
  const encoding = String(req.headers["content-encoding"] || "identity").trim().toLowerCase();
  if (encoding !== "identity") return "unsupported_body_encoding";
  const charset = /;\s*charset\s*=\s*"?([^;"\s]+)/i.exec(req.headers["content-type"] || "")?.[1];
  if (charset && !/^utf-?8$/i.test(charset)) return "unsupported_body_encoding";
  const type = String(req.headers["content-type"] || "").split(";", 1)[0].trim().toLowerCase();
  if (!Buffer.isBuffer(raw) || !(type === "application/x-www-form-urlencoded" || type === "text/plain"
      || /^application\/(?:[a-z0-9._-]+\+)?json$/.test(type))) {
    return "unsupported_body_type";
  }
  return null;
}

function decideInspection(result, { mode, threshold }) {
  if (mode === "off") return { action: "off", status: null, reason: "disabled" };
  let reason = result.inspectionIssue;
  if (!reason && result.bodyTruncated) reason = "body_too_large";
  if (!reason && (result.available !== true || !Number.isFinite(result.anomalyScore)
      || result.anomalyScore < 0)) reason = "scanner_unavailable";
  if (!reason && result.inspectionComplete !== true) reason = "incomplete_scan";
  if (reason) {
    const status = reason === "body_too_large" ? 413
      : reason.startsWith("unsupported_body_") ? 415 : 503;
    return { action: mode === "enforce" ? "reject" : "observe_incomplete", status, reason };
  }
  if (result.anomalyScore >= threshold) {
    return { action: mode === "enforce" ? "block" : "would_block", status: 403, reason: "attack_rules" };
  }
  return { action: "allow", status: null, reason: "below_threshold" };
}

function createRequestInspection({ scanner, config = loadInspectionConfig(),
  getClientIp = () => "127.0.0.1", onRejected = () => {}, onDecision = () => {} }) {
  return (req, res, next) => {
    const inspect = async () => {
      let result;
      const issue = bodyInspectionIssue(req, scanner.maximumBodyBytes);
      if (config.mode === "off") {
        result = unavailableResult("CRS inspection disabled");
      } else if (issue) {
        result = { ...unavailableResult(issue), inspectionIssue: issue, inspectionComplete: false };
      } else {
        try {
          result = await scanner.scan(req, getClientIp(req));
          if (!result || typeof result !== "object") result = unavailableResult("Invalid scanner result");
        } catch {
          result = unavailableResult("CRS scan failed");
        }
      }
      req.attackDetection = result;
      const decision = decideInspection(result, config);
      req.inspectionDecision = decision;
      onDecision(req, decision, result);
      if (req.aborted || res.destroyed) return;
      if (decision.action === "block" || decision.action === "reject") {
        const body = Buffer.from(JSON.stringify({ error: decision.action === "block"
          ? "request_blocked" : "request_inspection_incomplete" }));
        onRejected(req, { status: decision.status, responseContentType: "application/json",
          responseBodyBytes: body.length, attackDetection: result, upstreamReached: false });
        res.setHeader("X-Defense-Applied", "crs");
        res.setHeader("Cache-Control", "no-store");
        res.status(decision.status).type("application/json").send(body);
        return;
      }
      next();
    };
    inspect().catch(next);
  };
}

// Replay exactly the bytes that were inspected, including structured +json types.
function replayInspectedBody(proxyReq, req) {
  const raw = req.detectionRequestBodyBuffer;
  if (!Buffer.isBuffer(raw)) return false;
  proxyReq.removeHeader("transfer-encoding");
  proxyReq.removeHeader("content-encoding");
  proxyReq.setHeader("content-length", String(raw.length));
  if (raw.length) proxyReq.write(raw);
  return true;
}

module.exports = { loadInspectionConfig, bodyInspectionIssue, decideInspection,
  createRequestInspection, replayInspectedBody };
