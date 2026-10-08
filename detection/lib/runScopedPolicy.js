// Policy decisions must not borrow attack evidence from a previous target run.
// Dashboard analysis remains global; only this helper filters completed requests.
const { extractStreamFeatures } = require("./featureExtractor");
const { classify } = require("./classifier");
const { assessDetection } = require("./riskPolicy");
const {
  computeAgenticEvidence,
  computePartitionedAgenticEvidence,
} = require("./agenticEvidence");

const SOURCES = new Set(["session", "candidate", "authGroup", "clientFlow", "resolved"]);
const DEFAULT_MAX_ENTRIES = 5000;
const DEFAULT_IDLE_TTL_MS = 24 * 60 * 60_000;

function matchesRun(request, targetId, runId) {
  return request?.targetId === targetId && (request.targetRunId ?? null) === runId;
}

function runDeceptionHistory(requests) {
  const counts = {};
  for (const request of requests) {
    for (const event of request.deceptionEvents || []) {
      if (typeof event?.signal !== "string" || !event.signal) continue;
      counts[event.signal] = (counts[event.signal] || 0) + 1;
    }
  }
  return { distinctSignals: Object.keys(counts), signalCounts: counts };
}

function metadataForSource(requests, source) {
  // Entity/Session headerSample is captured once and can belong to an older
  // run. Request fingerprints retain the header evidence of the current run.
  const fingerprint = [...requests].reverse()
    .find((request) => request.httpFingerprint?.clientComponents)?.httpFingerprint;
  if (!fingerprint) return { headerSample: null, fingerprint: null, userAgent: "" };
  const client = fingerprint.clientComponents;
  const headerNames = new Set(fingerprint.requestComponents?.headerNames || []);
  const headerSample = {};
  if (client.userAgentRaw) headerSample["user-agent"] = client.userAgentRaw;
  if (client.acceptLanguageRaw) headerSample["accept-language"] = client.acceptLanguageRaw;
  if (client.acceptEncodingRaw) headerSample["accept-encoding"] = client.acceptEncodingRaw;
  for (const name of ["sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"]) {
    if (headerNames.has(name)) headerSample[name] = "present";
  }
  return {
    headerSample,
    fingerprint: source === "resolved" || source === "clientFlow"
      ? null : fingerprint.clientFingerprint || null,
    userAgent: client.userAgentRaw || "",
  };
}

/**
 * Create one process-local analyzer. Call analyze() before forwarding and again
 * after recording a completed request, so a peak survives ring-buffer eviction.
 * Cached maxima are scoped to source, entity, target and run, with bounded LRU
 * retention. Neither global entity.attackHistory nor stored detectionResult is used.
 */
function createRunScopedPolicyAnalyzer({
  level,
  maxEntries = DEFAULT_MAX_ENTRIES,
  idleTtlMs = DEFAULT_IDLE_TTL_MS,
  now = Date.now,
} = {}) {
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 1 ||
      !Number.isFinite(idleTtlMs) || idleTtlMs <= 0 || typeof now !== "function") {
    throw new TypeError("invalid run-scoped policy cache configuration");
  }
  const maxima = new Map();

  function prune(at = now()) {
    for (const [key, entry] of maxima) {
      if (at - entry.touchedAt < idleTtlMs) break;
      maxima.delete(key);
    }
    while (maxima.size > maxEntries) maxima.delete(maxima.keys().next().value);
  }

  function analyze({ source, entity, targetId, runId } = {}) {
    if (!SOURCES.has(source)) throw new TypeError("invalid run-scoped policy source");
    if (typeof targetId !== "string" || !targetId ||
        !(runId === null || typeof runId === "string" && runId)) {
      throw new TypeError("targetId and runId are required for run-scoped policy");
    }
    if (!entity) return null;
    if (typeof entity.id !== "string" || !Array.isArray(entity.requests)) {
      throw new TypeError("run-scoped policy entity needs an id and requests");
    }

    const requests = entity.requests.filter((request) => matchesRun(request, targetId, runId));
    if (!requests.length) return null;
    const metadata = metadataForSource(requests, source);
    const timestamps = requests.map((request) => request.ts).filter(Number.isFinite);
    const sessionIds = new Set(requests.map((request) => request.sessionId).filter(Boolean));
    const features = extractStreamFeatures({
      requests,
      ...metadata,
      // Telemetry totals on Session/Actor are global and have no run marker.
      // Excluding them prevents another run's browser activity affecting policy.
      telemetry: null,
      firstSeen: timestamps.length ? Math.min(...timestamps) : 0,
      lastSeen: timestamps.length ? Math.max(...timestamps) : 0,
      sessionChurn: Math.max(1, sessionIds.size),
      deceptionHistory: runDeceptionHistory(requests),
    });
    const analysis = classify(features);
    const key = JSON.stringify([source, entity.id, targetId, runId]);
    const at = now();
    prune(at);
    const previous = maxima.get(key);
    const maxAttackScore = Math.max(previous?.score || 0, analysis.attackScore);
    maxima.delete(key);
    maxima.set(key, { score: maxAttackScore, touchedAt: at });
    prune(at);

    return {
      ...analysis,
      detection: assessDetection({ ...analysis, maxAttackScore }, { level }),
      features,
      agenticEvidence: source === "authGroup"
        ? computePartitionedAgenticEvidence(requests)
        : computeAgenticEvidence(requests),
      observedIps: [...new Set(requests.map((request) => request.ip).filter(Boolean))],
    };
  }

  return {
    analyze,
    prune,
    clear: () => maxima.clear(),
    cacheSize: () => maxima.size,
  };
}

module.exports = {
  createRunScopedPolicyAnalyzer,
  matchesRun,
};
