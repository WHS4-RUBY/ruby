// 실험 전 기본값이다. Ground truth 비교 후 한 곳에서 조정할 수 있도록 모아 둔다.
const FEATURE_WINDOWS = Object.freeze({
  timingRequests: 50,
  intensityShortMs: 2_000,
  intensityLongMs: 10_000,
  sequenceRequests: 10,
  repeatedRequests: 20,
  diversityRequests: 50,
  errorRequests: 50,
  attackRequests: 50,
  agenticRequests: 50,
  agenticMaxGapMs: 5 * 60_000,
});

module.exports = { FEATURE_WINDOWS };
