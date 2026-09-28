const crypto = require("crypto");

const BEARER_TOKEN_PATTERN = /^\s*Bearer[ \t]+([A-Za-z0-9\-._~+/]+={0,})\s*$/i;

/**
 * Authorization: Bearer <token> 값을 raw token 저장 없이 Auth Group ID로 변환한다.
 */
function extractBearerToken(authorizationHeader) {
  if (typeof authorizationHeader !== "string") return null;

  const match = authorizationHeader.match(BEARER_TOKEN_PATTERN);
  if (!match) return null;
  return match[1];
}

function deriveAuthGroupId(authorizationHeader) {
  const token = extractBearerToken(authorizationHeader);
  if (!token) return null;
  const tokenHash = crypto.createHash("sha256").update(token, "utf8").digest("hex");
  return `auth:${tokenHash}`;
}

module.exports = { deriveAuthGroupId, extractBearerToken };
