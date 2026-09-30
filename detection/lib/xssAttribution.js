const { findingSummary } = require("./xssReflection");

// Stored evidence belongs to the retained write request, never to its reader.
function attributeStoredFindings(findings, { attachFinding, refreshOrigin }) {
  const groups = new Map();
  for (const finding of findings || []) {
    if (finding.vulnerabilityType !== "stored" || !finding.origin?.requestId) continue;
    const key = finding.origin.requestId;
    if (!groups.has(key)) groups.set(key, { origin: finding.origin, findings: [] });
    groups.get(key).findings.push(finding);
  }
  let updated = 0;
  for (const { origin, findings: evidence } of groups.values()) {
    const { tags, maxRisk } = findingSummary(evidence);
    if (!attachFinding(origin, tags, maxRisk)) continue;
    refreshOrigin(origin);
    updated++;
  }
  return updated;
}

module.exports = { attributeStoredFindings };
