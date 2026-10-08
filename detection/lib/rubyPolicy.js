const { severity } = require("./detectionPolicy");
const { clampScore } = require("./policyEngine");

const DETECTION_RESULT_HEADERS = Object.freeze([
  "x-client-id",
  "x-risk-score",
  "x-classification",
  "x-defense-plan",
  "x-ruby-request-id",
  "x-ruby-automation-score",
  "x-ruby-attack-score",
  "x-ruby-confirmed-attack-score",
  "x-ruby-risk-score",
  "x-ruby-policy-source",
  "x-ruby-target-id",
  "x-ruby-run-id",
  "x-ruby-candidate-id",
  "x-ruby-client-flow-id",
  "x-ruby-defense-tier",
  "x-defense-signal",
]);

/**
 * 탐지기의 두 축 중 더 강한 값(현재 Automation 또는 누적 최고 Attack)을
 * 0~1 risk score로 만든다. 정책 선택에 사용하고, 공식 Defense의 관측용으로
 * X-Ruby-Risk-Score를 전달한다.
 */
function buildPolicyDecision({ source = "none", analysis = null, clientId = "unknown", confirmedAttackScore = 0 } = {}) {
  return {
    source,
    clientId: String(clientId || "unknown"),
    riskScore: clampScore(analysis ? severity(analysis) : 0),
    automationScore: clampScore(analysis?.automationScore),
    attackScore: clampScore(analysis?.detection?.effectiveAttackScore ?? analysis?.attackScore),
    confirmedAttackScore: clampScore(confirmedAttackScore),
  };
}

function stripDetectionHeaders(proxyReq) {
  for (const header of DETECTION_RESULT_HEADERS) proxyReq.removeHeader(header);
  // The Detection/Defense namespaces are internal contracts. Strip unknown
  // variants too, so a client cannot introduce a new control header before
  // the proxies know how to interpret it.
  for (const header of proxyReq.getHeaderNames?.() || []) {
    if (header.toLowerCase().startsWith("x-defense-") || header.toLowerCase().startsWith("x-ruby-")) {
      proxyReq.removeHeader(header);
    }
  }
}

module.exports = {
  DETECTION_RESULT_HEADERS,
  stripDetectionHeaders,
  buildPolicyDecision,
  clampScore,
};
