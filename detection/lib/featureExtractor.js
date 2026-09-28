const { isAutomationUA, missingBrowserHeaders } = require("./uaSignatures");
const { FEATURE_WINDOWS } = require("./featureWindows");
const { isBehaviorAnalyzable } = require("./backgroundTraffic");

function mean(arr) {
  if (!arr.length) return 0;
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function stdev(arr) {
  if (arr.length < 2) return 0;
  const m = mean(arr);
  return Math.sqrt(mean(arr.map((value) => (value - m) ** 2)));
}

function recent(requests, count) {
  return requests.slice(Math.max(0, requests.length - count));
}

function maxRequestsInWindow(timestamps, windowMs) {
  if (!timestamps.length) return 0;
  let maximum = 1;
  let left = 0;
  for (let right = 0; right < timestamps.length; right++) {
    while (timestamps[right] - timestamps[left] > windowMs) left++;
    maximum = Math.max(maximum, right - left + 1);
  }
  return maximum;
}

const maxBurst = maxRequestsInWindow;

const IDOR_RESOURCE_ID_PATTERN =
  /\/(users?|orders?|accounts?|baskets?|address(?:es)?|cards?|wallets?|deliver(?:y|ies)?)\/(\d+)/i;

function extractIdorWalkSignal(attackRequests) {
  const idsByResource = new Map();
  for (const request of attackRequests) {
    const match = String(request.url || "").match(IDOR_RESOURCE_ID_PATTERN);
    if (!match) continue;
    const resource = match[1].toLowerCase();
    if (!idsByResource.has(resource)) idsByResource.set(resource, new Set());
    idsByResource.get(resource).add(Number(match[2]));
  }

  return {
    maxDistinctIdsPerResource: Math.max(0, ...Array.from(idsByResource.values(), (ids) => ids.size)),
  };
}

const LOGIN_ROUTE_METHOD = "POST";
const LOGIN_ROUTE_PATH = "/rest/user/login";
const RESET_PASSWORD_ROUTE_METHOD = "POST";
const RESET_PASSWORD_ROUTE_PATH = "/rest/user/reset-password";
const SECURITY_QUESTION_ROUTE_METHOD = "GET";
const SECURITY_QUESTION_ROUTE_PATH = "/rest/user/security-question";

function extractLoginBruteForceSignal(attackRequests) {
  const failedLogins = attackRequests.filter(
    (request) =>
      request.method === LOGIN_ROUTE_METHOD &&
      request.normalizedPath === LOGIN_ROUTE_PATH &&
      request.status === 401 &&
      request.loginAttemptEmail
  );
  const resetPasswordAttempts = attackRequests.filter(
    (request) =>
      request.method === RESET_PASSWORD_ROUTE_METHOD &&
      request.normalizedPath === RESET_PASSWORD_ROUTE_PATH &&
      request.resetPasswordEmail
  );
  const securityQuestionProbes = attackRequests.filter(
    (request) =>
      request.method === SECURITY_QUESTION_ROUTE_METHOD &&
      request.normalizedPath === SECURITY_QUESTION_ROUTE_PATH &&
      request.securityQuestionEmail
  );

  const attemptsByEmail = new Map();
  const tally = (email) => attemptsByEmail.set(email, (attemptsByEmail.get(email) || 0) + 1);
  failedLogins.forEach((request) => tally(request.loginAttemptEmail));
  resetPasswordAttempts.forEach((request) => tally(request.resetPasswordEmail));
  securityQuestionProbes.forEach((request) => tally(request.securityQuestionEmail));

  return {
    failedLoginCount: failedLogins.length,
    resetPasswordAttemptCount: resetPasswordAttempts.length,
    securityQuestionProbeCount: securityQuestionProbes.length,
    distinctEmailsAttempted: attemptsByEmail.size,
    maxAttemptsPerEmail: Math.max(0, ...attemptsByEmail.values()),
  };
}

function maxConsecutiveRepeats(operations) {
  if (!operations.length) return 0;
  let maximum = 1;
  let current = 1;
  for (let index = 1; index < operations.length; index++) {
    current = operations[index] === operations[index - 1] ? current + 1 : 1;
    maximum = Math.max(maximum, current);
  }
  return maximum;
}

function emptyTelemetry() {
  return {
    mouseMoveCount: 0,
    scrollCount: 0,
    routeChangeCount: 0,
    domEventTypes: new Set(),
    pageLoads: 0,
    currentUrl: null,
    lastTelemetryAt: null,
  };
}

function aggregateTelemetry(memberSessions) {
  return memberSessions.reduce((result, session) => {
    result.mouseMoveCount += session.telemetry.mouseMoveCount;
    result.scrollCount += session.telemetry.scrollCount;
    result.routeChangeCount += session.telemetry.routeChangeCount;
    session.telemetry.domEventTypes.forEach((eventType) => result.domEventTypes.add(eventType));
    result.pageLoads += session.telemetry.pageLoads;
    if (session.telemetry.lastTelemetryAt !== null) {
      if (result.lastTelemetryAt === null || session.telemetry.lastTelemetryAt >= result.lastTelemetryAt) {
        result.currentUrl = session.telemetry.currentUrl;
      }
      result.lastTelemetryAt = Math.max(result.lastTelemetryAt || 0, session.telemetry.lastTelemetryAt);
    }
    return result;
  }, emptyTelemetry());
}

function extractStreamFeatures({
  requests,
  headerSample,
  fingerprint,
  userAgent,
  telemetry,
  firstSeen,
  lastSeen,
  sessionChurn,
  deceptionHistory = null,
}) {
  const ordered = [...requests].sort((a, b) => a.ts - b.ts);
  const behaviorRequests = ordered.filter(isBehaviorAnalyzable);
  const backgroundRequests = ordered.filter((request) => !isBehaviorAnalyzable(request));
  const backgroundByCategory = {};
  for (const request of backgroundRequests) {
    const category = request.backgroundTraffic?.category || "background";
    backgroundByCategory[category] = (backgroundByCategory[category] || 0) + 1;
  }

  const timingRequests = recent(behaviorRequests, FEATURE_WINDOWS.timingRequests);
  const timestamps = timingRequests.map((request) => request.ts);
  const intervals = [];
  for (let index = 1; index < timestamps.length; index++) {
    intervals.push(timestamps[index] - timestamps[index - 1]);
  }
  const avgIntervalMs = mean(intervals);
  const intervalStdevMs = stdev(intervals);
  const intervalCV = avgIntervalMs > 0 ? intervalStdevMs / avgIntervalMs : 0;
  const maxRequests2s = maxRequestsInWindow(timestamps, FEATURE_WINDOWS.intensityShortMs);
  const latestTimestamp = timestamps.at(-1);
  const requests10s = latestTimestamp === undefined
    ? 0
    : timestamps.filter((timestamp) => latestTimestamp - timestamp <= FEATURE_WINDOWS.intensityLongMs).length;

  const sequenceRequests = recent(behaviorRequests, FEATURE_WINDOWS.sequenceRequests);
  const repeatedRequests = recent(behaviorRequests, FEATURE_WINDOWS.repeatedRequests);
  const repeatedOperations = repeatedRequests.map((request) => request.operation);
  const operationCounts = new Map();
  for (const operation of repeatedOperations) {
    operationCounts.set(operation, (operationCounts.get(operation) || 0) + 1);
  }
  const mostRepeatedCount = operationCounts.size ? Math.max(...operationCounts.values()) : 0;

  const diversityRequests = recent(behaviorRequests, FEATURE_WINDOWS.diversityRequests);
  const uniquePaths = new Set(diversityRequests.map((request) => request.normalizedPath));
  const uniqueApiPaths = new Set(
    diversityRequests
      .filter((request) => /^\/(?:api|rest)\//.test(request.normalizedPath || ""))
      .map((request) => request.normalizedPath)
  );

  const errorRequests = recent(behaviorRequests, FEATURE_WINDOWS.errorRequests);
  const notFoundCount = errorRequests.filter((request) => request.status === 404).length;
  const accessDeniedCount = errorRequests.filter(
    (request) => request.status === 401 || request.status === 403
  ).length;
  const statusCounts = {};
  for (const request of errorRequests) {
    statusCounts[request.status] = (statusCounts[request.status] || 0) + 1;
  }

  const headers = headerSample || null;
  const ua = userAgent || "";
  const headerObservationAvailable = headers !== null;
  const automationUA = headerObservationAvailable ? isAutomationUA(ua) : false;
  const missingHeaders = headerObservationAvailable ? missingBrowserHeaders(headers) : [];
  const interaction = telemetry || emptyTelemetry();
  const deceptionSignals = Array.from(
    new Set(deceptionHistory?.distinctSignals || [])
  );
  const deceptionSignalCounts = { ...(deceptionHistory?.signalCounts || {}) };

  // 공격 증거는 최근 50건 창에서 제거하지 않고, 보관 중인 entity lifecycle 전체로 집계한다.
  // Session 저장소의 메모리 상한과 과거 최고 Attack Score는 별도로 유지된다.
  const attackRequests = ordered;
  const allTags = attackRequests.flatMap((request) => request.tags || []);
  const attackCategories = Array.from(new Set(allTags));
  const idorWalk = extractIdorWalkSignal(attackRequests);
  const loginBruteForce = extractLoginBruteForceSignal(attackRequests);
  const allBlTags = attackRequests.flatMap((request) => request.blTags || []);
  const businessLogicCategories = Array.from(new Set(allBlTags));
  const allCsrfTags = attackRequests.flatMap((request) => request.csrfTags || []);
  const csrfCategories = Array.from(new Set(allCsrfTags));
  const crsResults = attackRequests
    .map((request) => request.attackDetection)
    .filter((result) => result?.available);
  const crsRuleHits = crsResults.reduce(
    (sum, result) => sum + (Number(result.ruleHitCount) || 0),
    0
  );
  const matchedRuleIds = Array.from(
    new Set(crsResults.flatMap((result) => (result.hits || []).map((hit) => hit.ruleId)))
  );
  const experimentRunIds = Array.from(
    new Set(ordered.map((request) => request.experimentRunId).filter(Boolean))
  );

  return {
    totalRequests: ordered.length,
    behaviorAnalyzedRequests: behaviorRequests.length,
    backgroundRequests: backgroundRequests.length,
    requestAccounting: {
      totalRequests: ordered.length,
      behaviorAnalyzedRequests: behaviorRequests.length,
      backgroundRequests: backgroundRequests.length,
      backgroundByCategory,
    },
    sessionDurationMs: Math.max(0, (lastSeen || 0) - (firstSeen || 0)),
    fingerprint: fingerprint || null,
    userAgent: ua,
    experimentRunIds,
    windows: FEATURE_WINDOWS,
    temporal: {
      timingSampleSize: timingRequests.length,
      avgIntervalMs,
      intervalStdevMs,
      intervalCV,
      maxRequests2s,
      requests10s,
    },
    behavior: {
      recentSequence: sequenceRequests.map((request) => request.operation),
      repeatSampleSize: repeatedRequests.length,
      repeatRatio: repeatedRequests.length ? mostRepeatedCount / repeatedRequests.length : 0,
      maxConsecutiveRepeats: maxConsecutiveRepeats(repeatedOperations),
      diversitySampleSize: diversityRequests.length,
      uniqueNormalizedPaths: uniquePaths.size,
      pathDiversity: diversityRequests.length ? uniquePaths.size / diversityRequests.length : 0,
    },
    exploration: {
      sampleSize: errorRequests.length,
      notFoundCount,
      notFoundRatio: errorRequests.length ? notFoundCount / errorRequests.length : 0,
      accessDeniedCount,
      accessDeniedRatio: errorRequests.length ? accessDeniedCount / errorRequests.length : 0,
      statusCounts,
    },
    client: {
      sessionChurn,
      headerObservationAvailable,
      automationUA,
      missingHeaderCount: missingHeaders.length,
      missingHeaders,
      browserInteraction: {
        mouseMoveCount: interaction.mouseMoveCount,
        scrollCount: interaction.scrollCount,
        routeChangeCount: interaction.routeChangeCount,
        domEventDiversity: interaction.domEventTypes.size,
        pageLoads: interaction.pageLoads,
        currentUrl: interaction.currentUrl,
        hasTelemetry: interaction.lastTelemetryAt !== null,
      },
    },
    deception: {
      distinctSignals: deceptionSignals,
      signalCounts: deceptionSignalCounts,
      recentUniqueApiPaths: uniqueApiPaths.size,
      coverageEligible:
        deceptionSignals.includes("no_asset_loading") ||
        automationUA ||
        interaction.lastTelemetryAt === null,
    },
    attack: {
      sampleSize: attackRequests.length,
      payloadSignatureHits: allTags.length,
      distinctPayloadCategories: attackCategories.length,
      payloadCategories: attackCategories,
      crsSampleSize: crsResults.length,
      crsUnavailableCount: attackRequests.length - crsResults.length,
      crsRuleHits,
      maxCrsAnomalyScore: crsResults.length
        ? Math.max(...crsResults.map((result) => Number(result.anomalyScore) || 0))
        : 0,
      matchedRuleIds,
      idorWalk,
      loginBruteForce,
      businessLogicHits: allBlTags.length,
      distinctBusinessLogicCategories: businessLogicCategories.length,
      businessLogicCategories,
      csrfHits: allCsrfTags.length,
      distinctCsrfCategories: csrfCategories.length,
      csrfCategories,
    },
  };
}

function extractFeatures(session) {
  return extractStreamFeatures({
    requests: session.requests,
    headerSample: session.headerSample,
    fingerprint: session.fingerprint,
    userAgent: session.userAgent,
    telemetry: session.telemetry,
    firstSeen: session.firstSeen,
    lastSeen: session.lastSeen,
    sessionChurn: 1,
    deceptionHistory: session.deceptionHistory,
  });
}

function extractActorFeatures(actor, getSession) {
  const memberSessions = Array.from(actor.sessionIds, (id) => getSession(id)).filter(Boolean);
  return extractStreamFeatures({
    requests: actor.requests,
    headerSample: actor.headerSample,
    fingerprint: actor.fingerprint,
    userAgent: actor.userAgent,
    telemetry: aggregateTelemetry(memberSessions),
    firstSeen: actor.firstSeen,
    lastSeen: actor.lastSeen,
    sessionChurn: actor.sessionIds.size,
    deceptionHistory: actor.deceptionHistory,
  });
}

function extractAuthGroupFeatures(group, getSession) {
  const memberSessions = Array.from(group.sessionIds, (id) => getSession(id)).filter(Boolean);
  const representative = memberSessions.find((session) => session.headerSample) || memberSessions[0];
  return extractStreamFeatures({
    requests: group.requests,
    headerSample: representative ? representative.headerSample : null,
    fingerprint: representative ? representative.fingerprint : null,
    userAgent: representative ? representative.userAgent : "",
    telemetry: aggregateTelemetry(memberSessions),
    firstSeen: group.firstSeen,
    lastSeen: group.lastSeen,
    sessionChurn: group.sessionIds.size,
    deceptionHistory: group.deceptionHistory,
  });
}

function extractResolvedActorFeatures(aggregate) {
  const memberSessions = aggregate.memberSessions || [];
  const representative = [...memberSessions]
    .sort((a, b) => b.lastSeen - a.lastSeen)
    .find((session) => session.headerSample) || memberSessions[0];
  return extractStreamFeatures({
    requests: aggregate.requests || [],
    // Resolved Actor는 여러 header fingerprint를 포함할 수 있으므로 가장 최근
    // CONFIRMED Session의 클라이언트 관찰값만 대표값으로 사용한다.
    headerSample: representative ? representative.headerSample : null,
    fingerprint: null,
    userAgent: representative ? representative.userAgent : "",
    telemetry: aggregateTelemetry(memberSessions),
    firstSeen: aggregate.firstSeen,
    lastSeen: aggregate.lastSeen,
    sessionChurn: aggregate.sessionIds.length,
    deceptionHistory: aggregate.deceptionHistory,
  });
}

function extractIpFeatures(ipEntry, getSession) {
  const memberSessions = Array.from(ipEntry.sessionIds, (id) => getSession(id)).filter(Boolean);
  return extractStreamFeatures({
    requests: ipEntry.requests,
    headerSample: null,
    fingerprint: null,
    userAgent: "",
    telemetry: aggregateTelemetry(memberSessions),
    firstSeen: ipEntry.firstSeen,
    lastSeen: ipEntry.lastSeen,
    sessionChurn: ipEntry.sessionIds.size,
  });
}

module.exports = {
  extractFeatures,
  extractActorFeatures,
  extractAuthGroupFeatures,
  extractResolvedActorFeatures,
  extractIpFeatures,
  extractStreamFeatures,
  aggregateTelemetry,
  mean,
  stdev,
  maxBurst,
  maxRequestsInWindow,
  extractIdorWalkSignal,
  extractLoginBruteForceSignal,
};
