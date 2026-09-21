function severity(analysis) {
  if (!analysis) return -1;
  return Math.max(
    Number(analysis.detection?.effectiveAttackScore ?? analysis.attackScore) || 0,
    Number(analysis.automationScore) || 0
  );
}

// Identity resolution과 탐지 continuity는 서로 다른 문제다. CONFIRMED 요청이
// 없는 Resolved Actor가 기존 Candidate/Auth Group 이력을 가리지 않도록, 현재
// log-only 판단에는 독립 집계 중 가장 강한 관찰값과 그 출처를 사용한다.
function selectEffectiveDetection({ session, candidate, authGroup, clientFlow, resolved }) {
  const sources = [
    ["session", session],
    ["actor-candidate-fallback", candidate],
    ["auth-group", authGroup],
  ];
  if (Number(clientFlow?.features?.totalRequests) > 0) {
    sources.push(["fingerprint-client-flow", clientFlow]);
  }
  if (Number(resolved?.features?.totalRequests) > 0) {
    sources.push(["confirmed-resolved-actor", resolved]);
  }
  return sources
    .filter(([, analysis]) => analysis)
    .reduce((selected, current) => severity(current[1]) > severity(selected[1]) ? current : selected);
}

/**
 * 하위 계층(Policy/Defense)은 X-Client-Id를 방어 상태(rate limit 카운터 등)의 키로
 * 쓴다. 따라서 이 값은 "이번 요청에서 어떤 근거가 가장 높은 점수를 냈는지"와 무관하게
 * 지금까지 확인된 가장 넓은 묶음을 안정적으로 가리켜야 한다. selectEffectiveDetection의
 * 출처를 그대로 쓰면 Candidate 점수가 Flow 점수를 잠깐 앞지르는 순간 식별자가
 * client-flow:* -> actor:* 로 되돌아가, 공격자가 방어 카운터를 새로 받게 된다.
 */
function selectClientId(analyses = {}, { actorId, resolvedActorId, clientFlowId } = {}) {
  if (resolvedActorId && Number(analyses.resolved?.features?.totalRequests) > 0) {
    return resolvedActorId;
  }
  if (clientFlowId && Number(analyses.clientFlow?.features?.totalRequests) > 0) {
    return clientFlowId;
  }
  return actorId;
}

module.exports = { selectClientId, selectEffectiveDetection, severity };
