const { severity } = require("./detectionPolicy");
const { clampScore } = require("./policyEngine");

const DETECTION_RESULT_HEADERS = Object.freeze([
  "x-client-id",
  "x-risk-score",
  "x-classification",
  "x-defense-plan",
]);

/**
 * 탐지기의 두 축 중 더 강한 값(현재 Automation 또는 누적 최고 Attack)을
 * 0~1 risk score로 만든다. 이 값은 이 프록시 안에서 정책을 고르는 입력으로만
 * 쓰이고, 다음 계층으로는 전달되지 않는다.
 */
function buildPolicyDecision({ source = "none", analysis = null, clientId = "unknown" } = {}) {
  return {
    source,
    clientId: String(clientId || "unknown"),
    riskScore: clampScore(analysis ? severity(analysis) : 0),
  };
}

function stripDetectionHeaders(proxyReq) {
  for (const header of DETECTION_RESULT_HEADERS) proxyReq.removeHeader(header);
}

module.exports = {
  DETECTION_RESULT_HEADERS,
  stripDetectionHeaders,
  buildPolicyDecision,
  clampScore,
};
