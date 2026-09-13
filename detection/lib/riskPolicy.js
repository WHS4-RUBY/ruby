const DETECTION_THRESHOLDS = Object.freeze({
  low: 0.3,
  medium: 0.5,
  high: 0.7,
});

const DEFAULT_DETECTION_LEVEL = "medium";

function normalizeDetectionLevel(value) {
  const normalized = String(value || "").trim().toLowerCase();
  return Object.hasOwn(DETECTION_THRESHOLDS, normalized)
    ? normalized
    : DEFAULT_DETECTION_LEVEL;
}

function assessDetection(
  { automationScore = 0, attackScore = 0, maxAttackScore = 0 } = {},
  { level } = {}
) {
  const selectedLevel = normalizeDetectionLevel(level);
  const threshold = DETECTION_THRESHOLDS[selectedLevel];
  const currentAutomationScore = Math.max(0, Math.min(1, Number(automationScore) || 0));
  const currentAttackScore = Math.max(0, Math.min(1, Number(attackScore) || 0));
  const effectiveAttackScore = Math.max(
    currentAttackScore,
    Math.max(0, Math.min(1, Number(maxAttackScore) || 0))
  );

  return {
    level: selectedLevel,
    threshold,
    automationScoreBasis: "current",
    attackScoreBasis: "historical-max",
    currentAutomationScore,
    currentAttackScore,
    effectiveAttackScore,
    automationDetected: currentAutomationScore >= threshold,
    attackDetected: effectiveAttackScore >= threshold,
  };
}

module.exports = {
  assessDetection,
  normalizeDetectionLevel,
  DEFAULT_DETECTION_LEVEL,
  DETECTION_THRESHOLDS,
};
