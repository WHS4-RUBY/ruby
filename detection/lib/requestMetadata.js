const crypto = require("crypto");

const UUID_SEGMENT = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NUMERIC_SEGMENT = /^\d+$/;
const EXPERIMENT_RUN_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_METADATA_HEADER_CHARS = 256;

function sanitizeMetadataHeaderValue(value) {
  if (Array.isArray(value)) value = value[0];
  if (typeof value !== "string") return null;
  return value.slice(0, MAX_METADATA_HEADER_CHARS);
}

function parseContentLength(value) {
  if (Array.isArray(value)) value = value[0];
  if (typeof value !== "string" || !/^\d+$/.test(value.trim())) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}

function normalizePath(rawUrl) {
  let pathname = "/";
  try {
    pathname = new URL(rawUrl || "/", "http://detection.local").pathname || "/";
  } catch {
    pathname = String(rawUrl || "/").split("?", 1)[0] || "/";
  }

  const normalized = pathname
    .split("/")
    .map((segment) => {
      if (UUID_SEGMENT.test(segment)) return ":uuid";
      if (NUMERIC_SEGMENT.test(segment)) return ":id";
      return segment;
    })
    .join("/");

  return normalized || "/";
}

function canonicalize(value) {
  if (value === null) return null;
  if (Buffer.isBuffer(value)) return { $buffer: value.toString("base64") };
  if (Array.isArray(value)) return value.map(canonicalize);
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])])
    );
  }
  if (["string", "number", "boolean"].includes(typeof value)) return value;
  return String(value);
}

function canonicalPayload(body, contentType = "") {
  if (body === undefined || body === null) return null;
  if (typeof body === "object" && !Buffer.isBuffer(body) && Object.keys(body).length === 0) {
    return null;
  }
  if (typeof body === "string" && body.length === 0) return null;

  if (typeof body === "string" && contentType.includes("application/x-www-form-urlencoded")) {
    const entries = Array.from(new URLSearchParams(body).entries()).sort(([ak, av], [bk, bv]) => {
      const byKey = ak.localeCompare(bk);
      return byKey || av.localeCompare(bv);
    });
    return JSON.stringify(entries);
  }

  return JSON.stringify(canonicalize(body));
}

function createPayloadFingerprint(body, contentType, hmacKey) {
  const canonical = canonicalPayload(body, contentType);
  if (canonical === null) return null;
  if (!hmacKey) throw new Error("payload fingerprint HMAC key is required");
  return crypto.createHmac("sha256", hmacKey).update(canonical, "utf8").digest("hex");
}

function sanitizeExperimentRunId(value) {
  if (Array.isArray(value)) value = value[0];
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return EXPERIMENT_RUN_ID_PATTERN.test(trimmed) ? trimmed : null;
}

module.exports = {
  normalizePath,
  canonicalPayload,
  createPayloadFingerprint,
  sanitizeExperimentRunId,
  sanitizeMetadataHeaderValue,
  parseContentLength,
};
