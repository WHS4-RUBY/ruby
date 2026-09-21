const { ActorResolver } = require("../lib/actorResolver");
const { buildHttpFingerprint } = require("../lib/httpFingerprint");
const {
  buildClientObservation,
  canAutoAggregate,
  compareClientObservations,
} = require("../lib/fingerprintSimilarity");

const TS = 1_700_000_000_000;
const baseHeaders = {
  "user-agent": "curl/8.10.1",
  "accept-language": "ko-KR,ko;q=0.9",
  "accept-encoding": "gzip, deflate, br",
  accept: "*/*",
};
const headerPairs = [
  ["Host", "example.test"],
  ["User-Agent", baseHeaders["user-agent"]],
  ["Accept", baseHeaders.accept],
  ["Accept-Language", baseHeaders["accept-language"]],
  ["Accept-Encoding", baseHeaders["accept-encoding"]],
];

function flatten(pairs) {
  return pairs.flatMap(([name, value]) => [name, value]);
}

function sample({ ip = "203.0.113.10", headers = baseHeaders, pairs = headerPairs, ts = TS } = {}) {
  const fingerprint = buildHttpFingerprint({
    headers,
    rawHeaders: flatten(pairs),
    method: "GET",
    httpVersion: "1.1",
  });
  return {
    ip,
    fingerprint,
    observation: buildClientObservation({ ip, httpFingerprint: fingerprint, ts }),
  };
}

function compareCase(number, name, baseline, current, note = null) {
  const comparison = compareClientObservations(baseline.observation, current.observation);
  // 이 실험은 기본 정책(IP 로테이션 연결 허용) 기준 표를 재현한다.
  // 환경변수와 무관하게 결정적이어야 하므로 값을 고정한다.
  const eligibility = canAutoAggregate(comparison, baseline.observation, current.observation, {
    allowIpRotation: true,
  });
  const sameCandidate = baseline.ip === current.ip && baseline.fingerprint.clientFingerprint === current.fingerprint.clientFingerprint;
  return {
    number,
    name,
    score: comparison.score,
    profileScore: comparison.profileScore,
    decision: comparison.decision,
    sameCandidate,
    autoAggregate: !sameCandidate && eligibility.eligible,
    matchedFields: comparison.matchedFields,
    changedFields: comparison.changedFields,
    ignoredFields: comparison.ignoredFields,
    note,
  };
}

const baseline = sample();
const rows = [
  compareCase(1, "모든 값 동일", baseline, sample()),
  compareCase(2, "IP만 변경", baseline, sample({ ip: "198.51.100.20" })),
  compareCase(3, "curl 버전만 변경", baseline, sample({
    headers: { ...baseHeaders, "user-agent": "curl/8.11.0" },
  })),
  compareCase(4, "언어만 변경", baseline, sample({
    headers: { ...baseHeaders, "accept-language": "en-US,en;q=0.9" },
  })),
  compareCase(5, "Accept-Encoding만 변경", baseline, sample({
    headers: { ...baseHeaders, "accept-encoding": "gzip, br" },
  })),
  compareCase(6, "헤더 순서만 변경", baseline, sample({ pairs: [...headerPairs].reverse() })),
  compareCase(7, "IP 동일 + 일부 헤더 변경", baseline, sample({
    headers: {
      ...baseHeaders,
      "user-agent": "curl/8.11.0",
      "accept-language": "ko",
      "accept-encoding": "gzip, br",
    },
  })),
  compareCase(8, "IP 다름 + 나머지 동일", baseline, sample({ ip: "192.0.2.30" })),
  compareCase(
    9,
    "같은 IP에서 Claude와 Codex 실행",
    sample({ headers: { ...baseHeaders, "x-experiment-run-id": "claude-run" } }),
    sample({ headers: { ...baseHeaders, "x-experiment-run-id": "codex-run" } }),
    "실험 라벨은 입력에서 제외된다. 전송 헤더가 같으면 모델 종류는 구분할 수 없다."
  ),
];

const resolver = new ActorResolver();
const clientIdentity = {
  valid: true,
  continuityVerified: true,
  source: "verified",
  clientId: "dcid:experiment-client",
  version: 1,
};
const first = resolver.observe({
  sessionId: "dcid-session-a",
  candidateId: "actor:dcid-a",
  ip: "203.0.113.10",
  clientIdentity,
  fingerprint: baseline.fingerprint.clientFingerprint,
  operation: "GET /one",
  ts: TS,
});
const second = resolver.observe({
  sessionId: "dcid-session-b",
  candidateId: "actor:dcid-b",
  ip: "198.51.100.20",
  clientIdentity,
  fingerprint: baseline.fingerprint.clientFingerprint,
  operation: "GET /two",
  ts: TS + 1_000,
});
rows.push({
  number: 10,
  name: "유효 DCID 유지 + 세션 초기화",
  decision: first.resolvedActorId === second.resolvedActorId ? "CONFIRMED" : "CONFLICT",
  sameResolvedActor: first.resolvedActorId === second.resolvedActorId,
  sessionChanged: true,
  note: "Fingerprint 점수보다 signed DCID 연속성이 우선한다.",
});

console.log(JSON.stringify({
  experiment: "fingerprint-single-variable-v1",
  similarityIsProbability: false,
  allowIpRotation: true,
  rows,
}, null, 2));
