const { DECEPTION_SIGNAL_CATALOG } = require("./deceptionEngine");

const ATTACK_WINDOW_MS = 60 * 60_000;
const ATTACK_BUCKET_MS = 60_000;

function isQualifyingAttackRequest(request) {
  if (!request || request.backgroundTraffic?.isBackground) return false;
  if ((request.tags || []).length || (request.blTags || []).length || (request.csrfTags || []).length) {
    return true;
  }
  if (request.attackDetection?.available && Number(request.attackDetection.anomalyScore) >= 5) {
    return true;
  }
  return (request.deceptionEvents || []).some((event) => {
    const signal = DECEPTION_SIGNAL_CATALOG[event.signal];
    return signal?.scored && signal.scoreTarget === "attack";
  });
}

function repetitionBonusPoints(qualifyingRequests) {
  const count = Math.max(0, Number(qualifyingRequests) || 0);
  return count < 2 ? 0 : Math.min(50, Math.round(10 * Math.log2(count) * 10) / 10);
}

function attackBucket(ts) {
  return Math.floor(ts / ATTACK_BUCKET_MS) * ATTACK_BUCKET_MS;
}

module.exports = {
  ATTACK_BUCKET_MS,
  ATTACK_WINDOW_MS,
  attackBucket,
  isQualifyingAttackRequest,
  repetitionBonusPoints,
};
