const crypto = require("crypto");

const SIMILARITY_VERSION = "fingerprint-similarity-v1";
const DEFAULT_WEIGHTS = Object.freeze({
  ip: 30,
  userAgentFamily: 25,
  userAgentVersion: 15,
  primaryLanguage: 10,
  acceptEncodings: 10,
  clientHints: 7,
  headerOrder: 3,
});

function clean(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeIp(value) {
  return clean(value).replace(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/, "$1") || "unknown";
}

function uniqueStrings(values) {
  return [...new Set((values || []).map(clean).filter(Boolean))];
}

function baseLanguage(value) {
  return clean(value).split("-")[0];
}

function jaccard(left, right) {
  const a = new Set(uniqueStrings(left));
  const b = new Set(uniqueStrings(right));
  if (!a.size && !b.size) return null;
  const intersection = [...a].filter((value) => b.has(value)).length;
  const union = new Set([...a, ...b]).size;
  return union ? intersection / union : null;
}

function orderedSimilarity(left, right) {
  const a = uniqueStrings(left);
  const b = uniqueStrings(right);
  if (!a.length && !b.length) return null;
  if (a.join("\u0000") === b.join("\u0000")) return 1;
  // 헤더 순서는 약한 관찰값이다. 공통 위치가 유지된 비율과 집합 유사도의 평균만 사용한다.
  const samePosition = Math.min(a.length, b.length)
    ? a.filter((value, index) => b[index] === value).length / Math.max(a.length, b.length)
    : 0;
  return (samePosition + (jaccard(a, b) || 0)) / 2;
}

function parseVersion(value) {
  const match = String(value || "").match(/\b(?:curl|wget|python-requests|python-urllib|chrome|crios|firefox|fxios|version|edg)\/([0-9]+(?:\.[0-9]+)*)/i);
  return match?.[1] || "";
}

function buildClientObservation({ ip, httpFingerprint, ts = Date.now() } = {}) {
  const client = httpFingerprint?.clientComponents || {};
  const request = httpFingerprint?.requestComponents || {};
  return {
    schemaVersion: 3,
    observedAt: ts,
    network: { ip: normalizeIp(ip) },
    clientProfile: {
      userAgent: {
        raw: String(client.userAgentRaw || client.userAgent || ""),
        normalized: clean(client.userAgent),
        family: clean(client.userAgentFamily) || "unknown",
        major: clean(client.userAgentMajor) || "0",
        version: clean(client.userAgentVersion) || parseVersion(client.userAgent),
      },
      language: {
        raw: String(client.acceptLanguageRaw || ""),
        primary: clean(client.primaryLanguage) || "unknown",
      },
      acceptEncoding: {
        raw: String(client.acceptEncodingRaw || ""),
        tokens: uniqueStrings(client.acceptEncodings).sort(),
      },
      clientHints: {
        brands: clean(client.clientHints?.brands),
        mobile: clean(client.clientHints?.mobile),
        platform: clean(client.clientHints?.platform),
      },
    },
    requestProfile: {
      httpVersion: clean(request.httpVersion) || "unknown",
      headerNames: uniqueStrings(request.headerNames),
    },
    fingerprints: {
      client: httpFingerprint?.clientFingerprint || null,
      request: httpFingerprint?.requestFingerprint || null,
      headerOrder: httpFingerprint?.headerOrderFingerprint || null,
    },
  };
}

function versionSimilarity(left, right) {
  const a = clean(left.version);
  const b = clean(right.version);
  if (a && b) {
    if (a === b) return 1;
    if (a.split(".")[0] === b.split(".")[0]) return 0.7;
    return 0;
  }
  return clean(left.major) === clean(right.major) ? 1 : 0;
}

function hintsSimilarity(left, right) {
  const fields = ["brands", "mobile", "platform"];
  const comparable = fields.filter((field) => left[field] || right[field]);
  // 둘 다 Client Hints를 보내지 않는 패턴도 관찰 가능한 약한 일치로 취급한다.
  // 가중치는 7점으로 제한되어 UA/IP 앵커를 대신하지 못한다.
  if (!comparable.length) return 1;
  return comparable.filter((field) => clean(left[field]) === clean(right[field])).length / comparable.length;
}

function compareClientObservations(left, right, { weights = DEFAULT_WEIGHTS } = {}) {
  const a = left || {};
  const b = right || {};
  const aUa = a.clientProfile?.userAgent || {};
  const bUa = b.clientProfile?.userAgent || {};
  const aLanguage = a.clientProfile?.language?.primary;
  const bLanguage = b.clientProfile?.language?.primary;
  const languageScore = clean(aLanguage) === clean(bLanguage)
    ? 1
    : baseLanguage(aLanguage) && baseLanguage(aLanguage) === baseLanguage(bLanguage)
      ? 0.6
      : 0;
  const comparisons = {
    ip: normalizeIp(a.network?.ip) === normalizeIp(b.network?.ip) ? 1 : 0,
    userAgentFamily: clean(aUa.family) === clean(bUa.family) ? 1 : 0,
    userAgentVersion: versionSimilarity(aUa, bUa),
    primaryLanguage: languageScore,
    acceptEncodings: jaccard(
      a.clientProfile?.acceptEncoding?.tokens,
      b.clientProfile?.acceptEncoding?.tokens
    ),
    clientHints: hintsSimilarity(
      a.clientProfile?.clientHints || {},
      b.clientProfile?.clientHints || {}
    ),
    headerOrder: orderedSimilarity(
      a.requestProfile?.headerNames,
      b.requestProfile?.headerNames
    ),
  };

  let earned = 0;
  let available = 0;
  const fieldScores = {};
  const matchedFields = [];
  const changedFields = [];
  const ignoredFields = [];
  for (const [field, ratio] of Object.entries(comparisons)) {
    const weight = Number(weights[field]) || 0;
    if (ratio === null || ratio === undefined) {
      ignoredFields.push(field);
      continue;
    }
    const normalized = Math.max(0, Math.min(1, Number(ratio) || 0));
    available += weight;
    earned += weight * normalized;
    fieldScores[field] = {
      weight,
      similarity: Number(normalized.toFixed(3)),
      points: Number((weight * normalized).toFixed(1)),
    };
    if (normalized === 1) matchedFields.push(field);
    else changedFields.push(field);
  }
  const sameUserAgentRaw = clean(aUa.raw) === clean(bUa.raw);
  (sameUserAgentRaw ? matchedFields : changedFields).push("userAgentRaw");
  const score = available ? Number(((earned / available) * 100).toFixed(1)) : 0;
  const profileAvailable = available - (comparisons.ip === null ? 0 : weights.ip);
  const profileEarned = earned - (comparisons.ip === null ? 0 : weights.ip * comparisons.ip);
  const profileScore = profileAvailable
    ? Number(((profileEarned / profileAvailable) * 100).toFixed(1))
    : 0;
  const decision = score === 100 && sameUserAgentRaw
    ? "EXACT"
    : score >= 70
      ? "RELATED"
      : score >= 50
        ? "POSSIBLE"
        : "SEPARATE";

  return {
    version: SIMILARITY_VERSION,
    score,
    profileScore,
    decision,
    sameIp: comparisons.ip === 1,
    matchedFields,
    changedFields,
    ignoredFields,
    fieldScores,
  };
}

function canAutoAggregate(comparison, left, right, { windowMs = 30 * 60_000 } = {}) {
  const timeGapMs = Math.abs(Number(left?.observedAt || 0) - Number(right?.observedAt || 0));
  const uaLeft = left?.clientProfile?.userAgent || {};
  const uaRight = right?.clientProfile?.userAgent || {};
  const sameFamily = clean(uaLeft.family) === clean(uaRight.family);
  const sameMajor = clean(uaLeft.major) === clean(uaRight.major);
  if (!sameFamily || !sameMajor || timeGapMs > windowMs) {
    return { eligible: false, reason: timeGapMs > windowMs ? "outside_similarity_window" : "ua_anchor_mismatch" };
  }
  if (comparison.sameIp) {
    return {
      eligible: comparison.score >= 85,
      reason: comparison.score >= 85 ? "same_ip_high_similarity" : "same_ip_below_threshold",
    };
  }
  const sameRawUa = clean(uaLeft.raw) && clean(uaLeft.raw) === clean(uaRight.raw);
  const sameLanguage = clean(left?.clientProfile?.language?.primary) === clean(right?.clientProfile?.language?.primary);
  const encodingScore = comparison.fieldScores.acceptEncodings?.similarity;
  const encodingCompatible = encodingScore === undefined || encodingScore >= 0.8;
  const eligible = comparison.score >= 70 && comparison.profileScore >= 95 && sameRawUa && sameLanguage && encodingCompatible;
  return {
    eligible,
    reason: eligible ? "ip_rotated_profile_match" : "ip_rotated_profile_insufficient",
  };
}

function clientFlowId(candidateId) {
  return `client-flow:${crypto.createHash("sha256").update(String(candidateId)).digest("hex").slice(0, 24)}`;
}

module.exports = {
  DEFAULT_WEIGHTS,
  SIMILARITY_VERSION,
  buildClientObservation,
  canAutoAggregate,
  compareClientObservations,
  clientFlowId,
  jaccard,
};
