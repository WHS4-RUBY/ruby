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

test("59/60 공통 세션은 UA가 다른 네 Flow를 연결하고 이전 ID도 조회된다", () => {
  const start = 1_700_000_000_000;
  const store = new ClientFlowStore({ ttlMs: 60 * 60_000, similarityWindowMs: 30 * 60_000 });
  const headers = [
    baseHeaders,
    { ...baseHeaders, "user-agent": "Mozilla/5.0 Firefox/142.0" },
    { ...baseHeaders, "user-agent": "python-requests/2.31.0" },
    { ...baseHeaders, "user-agent": "wget/1.21.4" },
  ];
  const ids = [];
  for (let client = 0; client < headers.length; client++) {
    for (let session = 0; session < (client === 0 ? 60 : 59); session++) {
      const ts = start + client * 100_000 + session * 100;
      const group = store.observe({
        candidateId: `actor:${client}`,
        observation: observation({ headers: headers[client], ts }),
        sessionId: `session:${session}`,
        ts,
      });
      if (session === 0) ids.push(group.id);
    }
  }
  const groups = store.getAll();
  assert.equal(groups.length, 1);
  assert.equal(groups[0].candidateIds.size, 4);
  assert.equal(groups[0].sessionIds.size, 60);
  assert.equal(groups[0].candidateSessionIds.get("actor:1").size, 59);
  assert.equal([...groups[0].candidateSessionIds.get("actor:1")]
    .filter((sessionId) => groups[0].coreSessionIds.has(sessionId)).length, 59);
  for (const id of ids) assert.equal(store.get(id)?.id, groups[0].id);
});

test("공통 세션 하나와 UA 변경만으로는 Flow를 합치지 않는다", () => {
  const store = new ClientFlowStore({ ttlMs: 60_000 });
  const start = 1_700_000_000_000;
  for (let client = 0; client < 2; client++) {
    store.observe({
      candidateId: `actor:${client}`,
      observation: observation({
        headers: client ? { ...baseHeaders, "user-agent": "Mozilla/5.0 Firefox/142.0" } : baseHeaders,
        ts: start + client * 100,
      }),
      sessionId: "session:shared",
      ts: start + client * 100,
    });
  }
  assert.equal(store.getAll().length, 2);
});

test("중간 Flow와만 80% 겹치는 세 번째 Flow는 연쇄 병합하지 않는다", () => {
  const start = 1_700_000_000_000;
  const store = new ClientFlowStore({ ttlMs: 60_000 });
  const agents = ["curl/8.10.1", "Mozilla/5.0 Firefox/142.0", "python-requests/2.31.0"];
  const sessionRanges = [[0, 10], [2, 12], [4, 14]];
  for (let client = 0; client < agents.length; client++) {
    const [first, end] = sessionRanges[client];
    for (let session = first; session < end; session++) {
      const ts = start + client * 1000 + session;
      store.observe({
        candidateId: `actor:${client}`,
        observation: observation({ headers: { ...baseHeaders, "user-agent": agents[client] }, ts }),
        sessionId: `session:${session}`,
        ts,
      });
    }
  }
  assert.equal(store.getAll().length, 2);
  assert.equal(store.getByCandidate("actor:0")?.id, store.getByCandidate("actor:1")?.id);
  assert.notEqual(store.getByCandidate("actor:0")?.id, store.getByCandidate("actor:2")?.id);
});

for (const newCandidate of [false, true]) {
  test(`이미 알려진 세션을 ${newCandidate ? "새 지문 연결 Candidate" : "기존 핵심 Candidate"}가 사용해도 병합을 재검사한다`, () => {
    const start = 1_700_000_000_000;
    const store = new ClientFlowStore();
    const agents = ["curl/8.10.1", "Mozilla/5.0 Firefox/142.0", "python-requests/2.31.0", "curl/8.10.1", "curl/8.10.1"];
    let ts = start;
    function observe(client, session) {
      ts++;
      return store.observe({
        candidateId: `actor:${client}`,
        observation: observation({
          ip: client >= 3 ? `198.51.100.${client}` : "203.0.113.10",
          headers: { ...baseHeaders, "user-agent": agents[client] }, ts,
        }),
        sessionId: `session:${session}`,
        ts,
      });
    }
    for (let session = 0; session < 10; session++) observe(0, session);
    for (let session = 2; session < 12; session++) observe(1, session);
    for (const session of [12, 13, 10, 11, 2, 3, 4, 5, 6, 7, 8, 9]) observe(2, session);
    const oldThirdId = store.getByCandidate("actor:2").id;
    assert.equal(store.getAll().length, 2);
    // 병합으로 들어온 Candidate의 새 세션은 핵심 세션을 확장하지 않는다.
    observe(1, 12);
    observe(1, 13);
    assert.equal(store.getByCandidate("actor:0").coreSessionIds.size, 10);
    assert.equal(store.getAll().length, 2);
    observe(newCandidate ? 3 : 0, 10);
    assert.equal(store.getAll().length, 2);
    observe(newCandidate ? 4 : 0, 11);
    // 새로운 지문 Candidate를 사용하는 경우 같은 앵커 프로필을 유지한다.
    assert.equal(store.getAll().length, 1);
    const merged = store.getByCandidate("actor:0");
    assert.equal(store.getByCandidate("actor:2").id, merged.id);
    assert.equal(store.get(oldThirdId).id, merged.id);
    assert.ok(merged.links.some((link) => link.reason === "shared_session_continuity"
      && link.sharedSessionCount === 10
      && link.sourceCoverage >= 0.8 && link.targetCoverage >= 0.8));
  });
}

test("Candidate 128개가 한 Flow로 연결되며 설정된 옛 3개 상한은 분리에 쓰이지 않는다", () => {
  const store = new ClientFlowStore({ ttlMs: 60_000, maxCandidates: 3 });
  const start = 1_700_000_000_000;
  for (let index = 0; index < 128; index++) {
    store.observe({
      candidateId: `actor:${index}`,
      observation: observation({ ts: start + index }),
      sessionId: `session:${index}`,
      ts: start + index,
    });
  }
  assert.equal(store.getAll().length, 1);
  assert.equal(store.getAll()[0].candidateIds.size, 128);
});

test("마지막 요청 이후 60분이 지나면 동일 Candidate의 Flow 이력이 새로 시작된다", () => {
  const start = 1_700_000_000_000;
  const store = new ClientFlowStore({ ttlMs: 60 * 60_000 });
  store.observe({ candidateId: "actor:a", observation: observation({ ts: start }), sessionId: "session:old", ts: start });
  store.observe({
    candidateId: "actor:a", observation: observation({ ts: start + 59 * 60_000 }),
    sessionId: "session:still-active", ts: start + 59 * 60_000,
  });
  assert.equal(store.getByCandidate("actor:a")?.sessionIds.size, 2);
  store.observe({
    candidateId: "actor:a", observation: observation({ ts: start + 120 * 60_000 }),
    sessionId: "session:new", ts: start + 120 * 60_000,
  });
  assert.deepEqual([...store.getByCandidate("actor:a").sessionIds], ["session:new"]);
  assert.equal(store.getByCandidate("actor:a")?.firstSeen, start + 120 * 60_000);
});
