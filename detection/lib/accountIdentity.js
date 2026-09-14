const crypto = require("crypto");
const fs = require("fs");
const { extractBearerToken } = require("./authGroup");

function decodeJsonPart(part) {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

function getClaim(payload) {
  const candidates = [
    ["sub", payload?.sub],
    ["data.id", payload?.data?.id],
    ["id", payload?.id],
    ["data.email", payload?.data?.email],
    ["email", payload?.email],
  ];
  for (const [path, value] of candidates) {
    if ((typeof value === "string" && value) || Number.isSafeInteger(value)) {
      return { path, value: String(value) };
    }
  }
  return null;
}

function loadPublicKey({ publicKey, publicKeyFile, logger }) {
  if (publicKey) return String(publicKey).replace(/\\n/g, "\n");
  if (!publicKeyFile) return null;
  try {
    return fs.readFileSync(publicKeyFile, "utf8");
  } catch (error) {
    logger.warn(`[detection-proxy] unable to read ACCOUNT_JWT_PUBLIC_KEY_FILE: ${error.message}`);
    return null;
  }
}

class AccountIdentityResolver {
  constructor({
    publicKey = process.env.ACCOUNT_JWT_PUBLIC_KEY,
    publicKeyFile = process.env.ACCOUNT_JWT_PUBLIC_KEY_FILE,
    hashKey = process.env.ACCOUNT_ID_HASH_KEY || process.env.DCID_HMAC_SECRET,
    issuer = process.env.ACCOUNT_JWT_ISSUER,
    audience = process.env.ACCOUNT_JWT_AUDIENCE,
    now = () => Date.now(),
    randomBytes = crypto.randomBytes,
    logger = console,
  } = {}) {
    this.publicKey = loadPublicKey({ publicKey, publicKeyFile, logger });
    this.hashKey = Buffer.from(hashKey || randomBytes(32));
    this.issuer = issuer || null;
    this.audience = audience || null;
    this.now = now;
    this.logger = logger;
    if (!this.publicKey) {
      logger.warn(
        "[detection-proxy] Account JWT public key is not configured; JWT account claims are observation-only and unverified."
      );
    }
  }

  accountKey(claim) {
    const digest = crypto
      .createHmac("sha256", this.hashKey)
      .update(`${claim.path}\u0000${claim.value}`)
      .digest("hex")
      .slice(0, 32);
    return `account:${digest}`;
  }

  inspectAuthorization(authorizationHeader) {
    const token = extractBearerToken(authorizationHeader);
    if (!token) return null;
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    let header;
    let payload;
    try {
      header = decodeJsonPart(parts[0]);
      payload = decodeJsonPart(parts[1]);
    } catch (_) {
      return null;
    }
    const claim = getClaim(payload);
    if (!claim) return null;

    let verified = false;
    let verification = "public_key_unavailable";
    if (this.publicKey) {
      if (header?.alg !== "RS256") {
        verification = "unsupported_algorithm";
      } else {
        try {
          const signatureValid = crypto.verify(
            "RSA-SHA256",
            Buffer.from(`${parts[0]}.${parts[1]}`),
            this.publicKey,
            Buffer.from(parts[2], "base64url")
          );
          const nowSeconds = Math.floor(this.now() / 1000);
          const timeValid =
            (!Number.isFinite(payload.exp) || payload.exp > nowSeconds) &&
            (!Number.isFinite(payload.nbf) || payload.nbf <= nowSeconds);
          const issuerValid = !this.issuer || payload.iss === this.issuer;
          const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
          const audienceValid = !this.audience || audiences.includes(this.audience);
          verified = signatureValid && timeValid && issuerValid && audienceValid;
          verification = verified
            ? "verified_rs256"
            : !signatureValid
              ? "invalid_signature"
              : !timeValid
                ? "invalid_time"
                : !issuerValid
                  ? "invalid_issuer"
                  : "invalid_audience";
        } catch (_) {
          verification = "verification_error";
        }
      }
    }

    return {
      accountId: this.accountKey(claim),
      verified,
      verification,
      claim: claim.path,
    };
  }

  status() {
    return {
      verificationAvailable: Boolean(this.publicKey),
      algorithm: this.publicKey ? "RS256" : null,
      issuerRequired: Boolean(this.issuer),
      audienceRequired: Boolean(this.audience),
      rawClaimsStored: false,
    };
  }
}

module.exports = { AccountIdentityResolver, getClaim };
