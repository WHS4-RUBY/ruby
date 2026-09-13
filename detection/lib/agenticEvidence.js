const { FEATURE_WINDOWS } = require("./featureWindows");
const { isBehaviorAnalyzable } = require("./backgroundTraffic");

function emptyAgenticEvidence() {
  return {
    errorToEndpointChangeCount: 0,
    errorToMethodChangeCount: 0,
    retryWithPayloadChangeCount: 0,
    authAddedAfter401Count: 0,
    failureChangeSuccessCount: 0,
  };
}

function mergeAgenticEvidence(target, source) {
  for (const key of Object.keys(target)) target[key] += source[key] || 0;
  return target;
}

function computeAgenticEvidence(requests = []) {
  const evidence = emptyAgenticEvidence();
  const recent = [...requests]
    .filter(isBehaviorAnalyzable)
    .sort((a, b) => a.ts - b.ts)
    .slice(-FEATURE_WINDOWS.agenticRequests);

  for (let index = 1; index < recent.length; index++) {
    const previous = recent[index - 1];
    const next = recent[index];
    const gap = next.ts - previous.ts;
    if (gap < 0 || gap > FEATURE_WINDOWS.agenticMaxGapMs) continue;

    const failure = previous.status >= 400;
    if (!failure) continue;

    const samePath = previous.normalizedPath === next.normalizedPath;
    const sameOperation = previous.operation === next.operation;
    const methodChanged = previous.method !== next.method;
    const payloadChanged = previous.payloadFingerprint !== next.payloadFingerprint;
    const authChanged = Boolean(previous.hasAuthorization) !== Boolean(next.hasAuthorization);

    if (!samePath) evidence.errorToEndpointChangeCount++;
    if (samePath && methodChanged) evidence.errorToMethodChangeCount++;
    if (sameOperation && payloadChanged) evidence.retryWithPayloadChangeCount++;
    if (
      previous.status === 401 &&
      samePath &&
      !previous.hasAuthorization &&
      next.hasAuthorization
    ) {
      evidence.authAddedAfter401Count++;
    }

    const success = next.status >= 200 && next.status < 400;
    if (samePath && success && (methodChanged || payloadChanged || authChanged)) {
      evidence.failureChangeSuccessCount++;
    }
  }

  return evidence;
}

function computePartitionedAgenticEvidence(requests = []) {
  const partitions = new Map();
  for (const request of requests) {
    const key = request.actorId || (request.sessionId ? `session:${request.sessionId}` : null);
    if (!key) continue;
    if (!partitions.has(key)) partitions.set(key, []);
    partitions.get(key).push(request);
  }

  const total = emptyAgenticEvidence();
  for (const partitionRequests of partitions.values()) {
    mergeAgenticEvidence(total, computeAgenticEvidence(partitionRequests));
  }
  return total;
}

module.exports = {
  computeAgenticEvidence,
  computePartitionedAgenticEvidence,
  emptyAgenticEvidence,
};
