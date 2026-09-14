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
function selectEffectiveDetection({ session, candidate, authGroup, resolved }) {
  const sources = [
    ["session", session],
    ["actor-candidate-fallback", candidate],
    ["auth-group", authGroup],
  ];
  if (Number(resolved?.features?.totalRequests) > 0) {
    sources.push(["confirmed-resolved-actor", resolved]);
  }
  return sources
    .filter(([, analysis]) => analysis)
    .reduce((selected, current) => severity(current[1]) > severity(selected[1]) ? current : selected);
}

module.exports = { selectEffectiveDetection, severity };
