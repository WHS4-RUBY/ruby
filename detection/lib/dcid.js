const crypto = require("crypto");

const DEFAULT_TTL_MS = 30 * 24 * 60 * 60_000;
const DEFAULT_VERSION = 1;
const CLIENT_ID_BYTES = 24;

function positiveNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left));
  const b = Buffer.from(String(right));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

class DcidManager {
  constructor({
    secret = process.env.DCID_HMAC_SECRET,
    ttlMs = positiveNumber(process.env.DCID_TTL_MS, DEFAULT_TTL_MS),
    version = positiveNumber(process.env.DCID_VERSION, DEFAULT_VERSION),
    now = () => Date.now(),
    randomBytes = crypto.randomBytes,
    logger = console,
    secureCookie = process.env.DCID_COOKIE_SECURE === "true",
  } = {}) {
    this.usingFallbackSecret = !secret;
    this.secret = secret ? Buffer.from(secret, "utf8") : randomBytes(32);
    this.ttlMs = positiveNumber(ttlMs, DEFAULT_TTL_MS);
    this.version = positiveNumber(version, DEFAULT_VERSION);
    this.now = now;
    this.randomBytes = randomBytes;
    this.secureCookie = Boolean(secureCookie);
    if (this.usingFallbackSecret) {
      logger.warn(
        "[detection-proxy] DCID_HMAC_SECRET is not configured; using a process-local development key. " +
        "All dcid cookies become invalid after restart."
      );
    }
  }

  sign(encodedPayload) {
    return crypto.createHmac("sha256", this.secret).update(encodedPayload).digest("base64url");
  }

  clientKey(clientId) {
    const digest = crypto.createHash("sha256").update(String(clientId)).digest("hex").slice(0, 32);
    return `dcid:${digest}`;
  }

  issue() {
    const issuedAt = this.now();
    const payload = {
      clientId: this.randomBytes(CLIENT_ID_BYTES).toString("base64url"),
      issuedAt,
      expiresAt: issuedAt + this.ttlMs,
      version: this.version,
    };
    const encodedPayload = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
    const value = `${encodedPayload}.${this.sign(encodedPayload)}`;
    return {
      value,
      identity: {
        valid: true,
        continuityVerified: false,
        clientId: this.clientKey(payload.clientId),
        issuedAt: payload.issuedAt,
        expiresAt: payload.expiresAt,
        version: payload.version,
        source: "issued",
      },
    };
  }

  verify(value) {
    if (typeof value !== "string" || !value) return { valid: false, reason: "missing" };
    const parts = value.split(".");
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      return { valid: false, reason: "malformed" };
    }
    const [encodedPayload, signature] = parts;
    if (!safeEqual(signature, this.sign(encodedPayload))) {
      return { valid: false, reason: "invalid_signature" };
    }

    let payload;
    try {
      payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8"));
    } catch (_) {
      return { valid: false, reason: "invalid_payload" };
    }

    const validClientId = typeof payload.clientId === "string" && /^[A-Za-z0-9_-]{32}$/.test(payload.clientId);
    const validTimes = Number.isSafeInteger(payload.issuedAt) && Number.isSafeInteger(payload.expiresAt);
    if (!validClientId || !validTimes || payload.version !== this.version) {
      return { valid: false, reason: "invalid_claims" };
    }
    const now = this.now();
    if (payload.issuedAt > now + 60_000) return { valid: false, reason: "issued_in_future" };
    if (payload.expiresAt <= now) return { valid: false, reason: "expired" };
    if (payload.expiresAt - payload.issuedAt > this.ttlMs + 60_000) {
      return { valid: false, reason: "invalid_lifetime" };
    }

    return {
      valid: true,
      continuityVerified: true,
      clientId: this.clientKey(payload.clientId),
      issuedAt: payload.issuedAt,
      expiresAt: payload.expiresAt,
      version: payload.version,
      source: "verified",
    };
  }

  cookieOptions(identity) {
    return {
      httpOnly: true,
      sameSite: "lax",
      secure: this.secureCookie,
      path: "/",
      maxAge: Math.max(0, identity.expiresAt - this.now()),
    };
  }

  status() {
    return {
      cookieName: "dcid",
      version: this.version,
      ttlMs: this.ttlMs,
      secureCookie: this.secureCookie,
      keySource: this.usingFallbackSecret ? "process-local-development-fallback" : "environment",
    };
  }
}

module.exports = { DcidManager, DEFAULT_TTL_MS, DEFAULT_VERSION };
