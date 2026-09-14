const { severity } = require("./detectionPolicy");

const DETECTION_RESULT_HEADERS = Object.freeze([
  "x-client-id",
  "x-risk-score",
  "x-classification",
]);

function clampScore(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  return Math.max(0, Math.min(1, numeric));
}

/**
 * RUBY Policy는 0~1의 단일 X-Risk-Score를 입력으로 받는다.
 * 탐지기의 두 축 중 더 강한 값(현재 Automation 또는 누적 최고 Attack)을
 * 선택해 기존 Policy 계약으로 변환한다.
 */
function buildPolicyDecision({ source = "none", analysis = null, clientId = "unknown" } = {}) {
  return {
    source,
    clientId: String(clientId || "unknown"),
    riskScore: clampScore(analysis ? severity(analysis) : 0),
  };
}

/**
 * 클라이언트가 탐지 결과 헤더를 위조하지 못하게 제거한 뒤, 서버가 계산한
 * 값만 Policy 요청에 싣는다.
 */
function applyPolicyHeaders(proxyReq, decision) {
  for (const header of DETECTION_RESULT_HEADERS) proxyReq.removeHeader(header);
  proxyReq.setHeader("X-Client-Id", decision.clientId);
  proxyReq.setHeader("X-Risk-Score", String(clampScore(decision.riskScore)));
}

module.exports = {
  DETECTION_RESULT_HEADERS,
  applyPolicyHeaders,
  buildPolicyDecision,
  clampScore,
};
