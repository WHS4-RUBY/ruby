// 모든 결과는 실험 전 heuristic score(0~1)이며 확률이 아니다.
const clamp = (value, low = 0, high = 1) => Math.min(high, Math.max(low, value));

const AUTOMATION_WEIGHTS = Object.freeze({
  timingRegularity: 0.05,
  requestIntensity: 0.05,
  repeatedOperation: 0.1,
  sessionChurn: 0.1,
  headerAnomaly: 0.15,
  browserInteraction: 0.2,
  automationHoney: 0.35,
});

const ATTACK_WEIGHTS = Object.freeze({
  payloadSignature: 0.3,
  notFoundExploration: 0.06,
  accessDeniedExploration: 0.06,
  idorWalk: 0.07,
  loginBruteForce: 0.08,
  businessLogicViolation: 0.12,
  csrf: 0.09,
  attackHoney: 0.22,
});

const AUTOMATION_HONEY_MAX_POINTS = 35;
const ATTACK_HONEY_MAX_POINTS = 35;
const AUTOMATION_HONEY_POINTS = Object.freeze({
  trap_trigger: 20,
  no_asset_loading: 8,
});
const ATTACK_HONEY_POINTS = Object.freeze({
  watermark_reuse: 20,
  writable_file_write: 20,
  ssh_cred_reuse: 12,
  password_list_reuse: 12,
  writable_file_found: 8,
  script_hint_access: 5,
});

// Ground truth 실험 후 교체할 임시 정규화 기준이다.
const NORMALIZATION = Object.freeze({
  fastIntervalMs: 800,
  regularityCv: 0.6,
  burstBaseline2s: 3,
  burstRange2s: 12,
  volumeBaseline10s: 10,
  volumeRange10s: 40,
  repeatRatioBaseline: 0.4,
  consecutiveBaseline: 2,
  consecutiveRange: 8,
  errorRatioHigh: 0.4,
  idorWalkRange: 5,
  loginBruteForceRange: 9,
});

function scoreTimingRegularity(features) {
  const temporal = features.temporal;
  if (temporal.timingSampleSize < 3) return 0;
  const fast = clamp(1 - temporal.avgIntervalMs / NORMALIZATION.fastIntervalMs);
  const regular = clamp(1 - temporal.intervalCV / NORMALIZATION.regularityCv);
  return clamp(0.6 * fast + 0.4 * regular);
}

function scoreRequestIntensity(features) {
  const temporal = features.temporal;
  if (temporal.timingSampleSize < 3) return 0;
  const shortWindow = clamp(
    (temporal.maxRequests2s - NORMALIZATION.burstBaseline2s) / NORMALIZATION.burstRange2s
  );
  const longWindow = clamp(
    (temporal.requests10s - NORMALIZATION.volumeBaseline10s) / NORMALIZATION.volumeRange10s
  );
  return clamp(0.6 * shortWindow + 0.4 * longWindow);
}

function scoreRepeatedOperation(features) {
  const behavior = features.behavior;
  if (behavior.repeatSampleSize < 3) return 0;
  const ratio = clamp(
    (behavior.repeatRatio - NORMALIZATION.repeatRatioBaseline) /
      (1 - NORMALIZATION.repeatRatioBaseline)
  );
  const consecutive = clamp(
    (behavior.maxConsecutiveRepeats - NORMALIZATION.consecutiveBaseline) /
      NORMALIZATION.consecutiveRange
  );
  return clamp(0.6 * ratio + 0.4 * consecutive);
}

function scoreSessionChurn(features) {
  return clamp((features.client.sessionChurn - 1) / 9);
}

function scoreHeaderAnomaly(features) {
  const client = features.client;
  if (!client.headerObservationAvailable) return 0;
  let score = client.automationUA ? 0.6 : 0;
  score += clamp(client.missingHeaderCount / 4) * 0.4;
  return clamp(score);
}

function scoreBrowserInteraction(features) {
  const interaction = features.client.browserInteraction;
  const analyzedRequests = Number.isFinite(features.behaviorAnalyzedRequests)
    ? features.behaviorAnalyzedRequests
    : features.totalRequests;
  if (!interaction.hasTelemetry) return analyzedRequests >= 3 ? 0.9 : 0.5;
  if (analyzedRequests < 5) return 0;
  const mouse = interaction.mouseMoveCount === 0 ? 1 : clamp(1 - interaction.mouseMoveCount / 30);
  const scroll = interaction.scrollCount === 0 ? 1 : clamp(1 - interaction.scrollCount / 10);
  const dom = clamp(1 - interaction.domEventDiversity / 5);
  return clamp(0.5 * mouse + 0.2 * scroll + 0.3 * dom);
}

function scorePayloadSignature(features) {
  const attack = features.attack;
  if (!attack.payloadSignatureHits) return 0;
  const variety = clamp((attack.distinctPayloadCategories - 1) / 3) * 0.3;
  return clamp(0.7 + variety);
}

function scoreNotFoundExploration(features) {
  return clamp(features.exploration.notFoundRatio / NORMALIZATION.errorRatioHigh);
}

function scoreAccessDeniedExploration(features) {
  return clamp(features.exploration.accessDeniedRatio / NORMALIZATION.errorRatioHigh);
}

function scoreIdorWalk(features) {
  const signal = features.attack.idorWalk;
  if (!signal || signal.maxDistinctIdsPerResource < 1) return 0;
  return clamp((signal.maxDistinctIdsPerResource - 1) / NORMALIZATION.idorWalkRange);
}

function scoreLoginBruteForce(features) {
  const signal = features.attack.loginBruteForce;
  if (!signal || signal.distinctEmailsAttempted < 1) return 0;
  const repeated = clamp(
    (signal.maxAttemptsPerEmail - 1) / NORMALIZATION.loginBruteForceRange
  );
  const stuffing = clamp(
    (signal.distinctEmailsAttempted - 1) / NORMALIZATION.loginBruteForceRange
  );
  return Math.max(repeated, stuffing);
}

function scoreBusinessLogicViolation(features) {
  const attack = features.attack;
  if (!attack.businessLogicHits) return 0;
  return clamp(0.7 + clamp((attack.distinctBusinessLogicCategories - 1) / 3) * 0.3);
}

function scoreCsrf(features) {
  const attack = features.attack;
  if (!attack.csrfHits) return 0;
  return clamp(0.7 + clamp((attack.distinctCsrfCategories - 1) / 2) * 0.3);
}

function hasDeceptionSignal(features, signal) {
  return (features.deception?.distinctSignals || []).includes(signal);
}

function coverageHoneyPoints(features) {
  if (!features.deception?.coverageEligible) return 0;
  const count = Number(features.deception.recentUniqueApiPaths) || 0;
  if (count >= 20) return 7;
  if (count >= 15) return 5;
  if (count >= 10) return 3;
  return 0;
}

function honeyScore(features, pointMap, maximumPoints, extraPoints = {}) {
  const contributions = {};
  for (const [signal, points] of Object.entries(pointMap)) {
    contributions[signal] = hasDeceptionSignal(features, signal) ? points : 0;
  }
  Object.assign(contributions, extraPoints);
  const rawPoints = Object.values(contributions).reduce((sum, points) => sum + points, 0);
  const totalPoints = Math.min(maximumPoints, rawPoints);
  return {
    score: totalPoints / maximumPoints,
    totalPoints,
    rawPoints,
    maximumPoints,
    contributions,
  };
}

function scoreAutomationHoney(features) {
  return honeyScore(features, AUTOMATION_HONEY_POINTS, AUTOMATION_HONEY_MAX_POINTS, {
    coverage: coverageHoneyPoints(features),
  });
}

function scoreAttackHoney(features) {
  return honeyScore(features, ATTACK_HONEY_POINTS, ATTACK_HONEY_MAX_POINTS);
}

function weightedScore(breakdown, weights) {
  return Number(
    Object.entries(weights)
      .reduce((score, [name, weight]) => score + breakdown[name] * weight, 0)
      .toFixed(3)
  );
}

function classify(features) {
  const automationHoney = scoreAutomationHoney(features);
  const attackHoney = scoreAttackHoney(features);
  const automationBreakdown = {
    timingRegularity: scoreTimingRegularity(features),
    requestIntensity: scoreRequestIntensity(features),
    repeatedOperation: scoreRepeatedOperation(features),
    sessionChurn: scoreSessionChurn(features),
    headerAnomaly: scoreHeaderAnomaly(features),
    browserInteraction: scoreBrowserInteraction(features),
    automationHoney: automationHoney.score,
  };
  const attackBreakdown = {
    payloadSignature: scorePayloadSignature(features),
    notFoundExploration: scoreNotFoundExploration(features),
    accessDeniedExploration: scoreAccessDeniedExploration(features),
    idorWalk: scoreIdorWalk(features),
    loginBruteForce: scoreLoginBruteForce(features),
    businessLogicViolation: scoreBusinessLogicViolation(features),
    csrf: scoreCsrf(features),
    attackHoney: attackHoney.score,
  };

  return {
    scoreType: "heuristic-not-probability",
    automationScore: weightedScore(automationBreakdown, AUTOMATION_WEIGHTS),
    attackScore: weightedScore(attackBreakdown, ATTACK_WEIGHTS),
    automationBreakdown,
    attackBreakdown,
    honeyBreakdown: {
      automation: automationHoney,
      attack: attackHoney,
    },
  };
}

module.exports = {
  classify,
  AUTOMATION_WEIGHTS,
  ATTACK_WEIGHTS,
  AUTOMATION_HONEY_POINTS,
  ATTACK_HONEY_POINTS,
  scoreAutomationHoney,
  scoreAttackHoney,
  NORMALIZATION,
};
