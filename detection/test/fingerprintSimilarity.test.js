const assert = require("node:assert/strict");
const test = require("node:test");

const { buildHttpFingerprint } = require("../lib/httpFingerprint");
const {
  buildClientObservation,
  canAutoAggregate,
  compareClientObservations,
} = require("../lib/fingerprintSimilarity");
const { ClientFlowStore } = require("../lib/clientFlowStore");

const baseHeaders = {
  "user-agent": "curl/8.10.1",
  "accept-language": "ko-KR,ko;q=0.9",
  "accept-encoding": "gzip, deflate, br",
  accept: "*/*",
};
const baseOrder = [
  "Host", "example.test",
  "User-Agent", baseHeaders["user-agent"],
  "Accept", "*/*",
  "Accept-Language", baseHeaders["accept-language"],
  "Accept-Encoding", baseHeaders["accept-encoding"],
];

function observation({ ip = "203.0.113.10", headers = baseHeaders, rawHeaders = baseOrder, ts = 1_700_000_000_000 } = {}) {
  return buildClientObservation({
    ip,
    ts,
    httpFingerprint: buildHttpFingerprint({ headers, rawHeaders, method: "GET", httpVersion: "1.1" }),
  });
}

test("필수 Fingerprint 단일 변수 실험은 필드별 변경 근거를 반환한다", () => {
  const baseline = observation();
  const cases = [
    ["all-same", observation(), "EXACT", []],
    ["ip-only", observation({ ip: "198.51.100.20" }), "RELATED", ["ip"]],
    ["curl-version", observation({ headers: { ...baseHeaders, "user-agent": "curl/8.11.0" } }), "RELATED", ["userAgentVersion"]],
    ["language", observation({ headers: { ...baseHeaders, "accept-language": "en-US,en;q=0.9" } }), "RELATED", ["primaryLanguage"]],
    ["encoding", observation({ headers: { ...baseHeaders, "accept-encoding": "gzip, br" } }), "RELATED", ["acceptEncodings"]],
    ["header-order", observation({ rawHeaders: [...baseOrder].reverse() }), "RELATED", ["headerOrder"]],
  ];
  for (const [name, current, expectedDecision, expectedChanged] of cases) {
    const result = compareClientObservations(baseline, current);
    assert.equal(result.decision, expectedDecision, name);
    for (const field of expectedChanged) assert.ok(result.changedFields.includes(field), `${name}:${field}`);
  }
});

test("IP 동일 일부 변경과 IP 변경 나머지 동일은 자동 잠정 집계 대상이다", () => {
  const baseline = observation();
  const sameIpChangedEncoding = observation({
    headers: { ...baseHeaders, "accept-encoding": "gzip, br" },
  });
  const rotatedIp = observation({ ip: "198.51.100.20" });
  const sameIpResult = compareClientObservations(baseline, sameIpChangedEncoding);
  const rotatedResult = compareClientObservations(baseline, rotatedIp);
  assert.equal(canAutoAggregate(sameIpResult, baseline, sameIpChangedEncoding).eligible, true);
  assert.equal(canAutoAggregate(rotatedResult, baseline, rotatedIp).eligible, true);
});

test("선택한 원본 헤더를 보존하고 IPv4-mapped 주소는 같은 IP로 정규화한다", () => {
  const mapped = observation({ ip: "::ffff:203.0.113.10" });
  const plain = observation({ ip: "203.0.113.10" });
  assert.equal(mapped.clientProfile.userAgent.raw, "curl/8.10.1");
  assert.equal(mapped.clientProfile.language.raw, "ko-KR,ko;q=0.9");
  assert.equal(mapped.clientProfile.acceptEncoding.raw, "gzip, deflate, br");
  assert.equal(compareClientObservations(mapped, plain).fieldScores.ip.similarity, 1);
});

test("IP와 UA 계열이 모두 다르면 별도 후보로 유지한다", () => {
  const baseline = observation();
  const different = observation({
    ip: "198.51.100.20",
    headers: {
      "user-agent": "Mozilla/5.0 Firefox/142.0",
      "accept-language": "en-US",
      "accept-encoding": "identity",
      accept: "text/html",
    },
  });
  const result = compareClientObservations(baseline, different);
  assert.equal(result.decision, "SEPARATE");
  assert.equal(canAutoAggregate(result, baseline, different).eligible, false);
});

test("Client Flow는 고유사도 Candidate를 연결하되 서로 다른 verified DCID를 신원 병합하지 않는다", () => {
  const store = new ClientFlowStore({ ttlMs: 60_000, maxCandidates: 3 });
  const first = store.observe({
    candidateId: "actor:a",
    observation: observation(),
    sessionId: "session:a",
    ts: 1_700_000_000_000,
  });
  const second = store.observe({
    candidateId: "actor:b",
    observation: observation({ ip: "198.51.100.20", ts: 1_700_000_001_000 }),
    sessionId: "session:b",
    ts: 1_700_000_001_000,
  });
  assert.equal(first.id, second.id);
  assert.equal(second.aggregationEnabled, true);
  assert.equal(second.links[0].reason, "ip_rotated_profile_match");

  const verifiedA = {
    valid: true, continuityVerified: true, source: "verified", clientId: "dcid:a",
  };
  const verifiedB = {
    valid: true, continuityVerified: true, source: "verified", clientId: "dcid:b",
  };
  const isolated = new ClientFlowStore({ ttlMs: 60_000 });
  const dcidA = isolated.observe({
    candidateId: "actor:dcid-a", observation: observation(), clientIdentity: verifiedA,
    ts: 1_700_000_000_000,
  });
  const dcidB = isolated.observe({
    candidateId: "actor:dcid-b", observation: observation({ ip: "198.51.100.20" }), clientIdentity: verifiedB,
    ts: 1_700_000_001_000,
  });
  assert.equal(dcidA.id, dcidB.id);
  assert.equal(dcidB.verifiedClientIds.size, 2);
  assert.equal(dcidB.conflicts.length, 0);
});

test("같은 Candidate에서 서로 다른 verified DCID가 확인돼도 Client Flow는 유지한다", () => {
  const store = new ClientFlowStore();
  store.observe({
    candidateId: "actor:shared", observation: observation(),
    clientIdentity: { continuityVerified: true, clientId: "dcid:a" },
  });
  const conflicted = store.observe({
    candidateId: "actor:shared", observation: observation(),
    clientIdentity: { continuityVerified: true, clientId: "dcid:b" },
  });
  assert.equal(conflicted.aggregationEnabled, false);
  assert.equal(conflicted.verifiedClientIds.size, 2);
  assert.deepEqual(conflicted.conflicts, []);
});

test("UA가 달라도 같은 세션의 Candidate는 하나의 Client Flow로 연결한다", () => {
  const store = new ClientFlowStore({ ttlMs: 60_000, maxCandidates: 1 });
  const first = store.observe({
    candidateId: "actor:curl", observation: observation(), sessionId: "session:shared",
    clientIdentity: { continuityVerified: true, clientId: "dcid:curl" }, ts: 1_700_000_000_000,
  });
  const second = store.observe({
    candidateId: "actor:python",
    observation: observation({
      headers: { ...baseHeaders, "user-agent": "python-requests/2.31.0" },
      ts: 1_700_000_001_000,
    }),
    sessionId: "session:shared",
    clientIdentity: { continuityVerified: true, clientId: "dcid:python" }, ts: 1_700_000_001_000,
  });
  assert.equal(second.id, first.id);
  assert.deepEqual([...second.candidateIds], ["actor:curl", "actor:python"]);
  assert.equal(second.aggregationEnabled, true);
  assert.equal(second.links[0].reason, "shared_session_continuity");
  assert.equal(second.verifiedClientIds.size, 2);
});

test("이미 분리된 Flow도 나중에 세션이 겹치면 연결하고 이전 ID를 조회할 수 있다", () => {
  const store = new ClientFlowStore({ ttlMs: 60_000 });
  const first = store.observe({
    candidateId: "actor:curl", observation: observation(), sessionId: "session:a",
    ts: 1_700_000_000_000,
  });
  const second = store.observe({
    candidateId: "actor:python",
    observation: observation({
      ip: "198.51.100.20",
      headers: { ...baseHeaders, "user-agent": "python-requests/2.31.0" },
      ts: 1_700_000_001_000,
    }),
    sessionId: "session:b", ts: 1_700_000_001_000,
  });
  assert.notEqual(first.id, second.id);
  const merged = store.observe({
    candidateId: "actor:python", observation: observation(), sessionId: "session:a",
    ts: 1_700_000_002_000,
  });
  assert.equal(store.getAll().length, 1);
  assert.equal(store.get(first.id), merged);
  assert.equal(store.get(second.id), merged);
  assert.equal(store.getByCandidate("actor:python"), merged);
  assert.deepEqual([...merged.sessionIds].sort(), ["session:a", "session:b"]);
  assert.ok(merged.links.some((link) => link.reason === "shared_session_continuity"));
});

test("IP와 시간만 같고 세션이 다르면 UA가 다른 Flow를 합치지 않는다", () => {
  const store = new ClientFlowStore({ ttlMs: 60_000 });
  const first = store.observe({
    candidateId: "actor:curl", observation: observation(), sessionId: "session:a",
    ts: 1_700_000_000_000,
  });
  const second = store.observe({
    candidateId: "actor:python",
    observation: observation({
      headers: { ...baseHeaders, "user-agent": "python-requests/2.31.0" },
      ts: 1_700_000_001_000,
    }),
    sessionId: "session:b", ts: 1_700_000_001_000,
  });
  assert.notEqual(first.id, second.id);
});
