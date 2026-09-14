const assert = require("node:assert/strict");
const test = require("node:test");

const store = require("../lib/sessionStore");
const { extractResolvedActorFeatures } = require("../lib/featureExtractor");
const { ActorResolver } = require("../lib/actorResolver");

const baseHeaders = {
  "user-agent": "curl/8.0",
  accept: "*/*",
};

function client(name) {
  return {
    valid: true,
    continuityVerified: true,
    source: "verified",
    clientId: `dcid:${name}`,
    version: 1,
  };
}

function issuedClient(name) {
  return {
    valid: true,
    continuityVerified: false,
    source: "issued",
    clientId: `dcid:${name}`,
    version: 1,
  };
}

function account(name, verified = true) {
  return {
    accountId: `account:${name}`,
    verified,
    verification: verified ? "verified_rs256" : "public_key_unavailable",
    claim: "data.id",
  };
}

function record({
  sessionId,
  ip,
  headers = baseHeaders,
  url = "/api/test",
  method = "GET",
  clientIdentity,
  accountIdentity = null,
  authGroupId = null,
  ts = Date.now(),
}) {
  return store.recordRequest(sessionId, ip, {
    method,
    url,
    status: 200,
    headers,
    tags: [],
    clientIdentity,
    accountIdentity,
    authGroupId,
    ts,
  });
}

function latest(session) {
  return session.requests.at(-1);
}

test("Case 1: IP만 변경하면 Candidate는 바뀌어도 signed dcid 기반 Resolved Actor는 유지된다", () => {
  const sid = "resolved-case-1";
  const identity = client("case-1");
  const first = latest(record({ sessionId: sid, ip: "1.1.1.1", clientIdentity: identity }));
  const second = latest(record({ sessionId: sid, ip: "8.8.8.8", clientIdentity: identity }));
  assert.notEqual(first.actorId, second.actorId);
  assert.equal(first.resolvedActorId, second.resolvedActorId);
});

test("같은 verified dcid는 Resolver 재생성 후에도 동일 Resolved Actor ID를 만든다", () => {
  const identity = client("restart-stable");
  const observe = (resolver, sessionId) => resolver.observe({
    sessionId,
    candidateId: "actor:restart",
    ip: "10.0.1.9",
    clientIdentity: identity,
    fingerprint: "hfp2:restart",
    operation: "GET /",
    ts: 1_700_000_000_000,
  });
  const first = observe(new ActorResolver(), "restart-a");
  const second = observe(new ActorResolver(), "restart-b");
  assert.equal(first.resolvedActorId, second.resolvedActorId);
});

test("Case 2: User-Agent만 변경해도 signed dcid가 같으면 Resolved Actor는 유지된다", () => {
  const identity = client("case-2");
  const first = latest(record({ sessionId: "case-2-a", ip: "10.0.2.1", clientIdentity: identity }));
  const second = latest(record({
    sessionId: "case-2-b",
    ip: "10.0.2.1",
    headers: { ...baseHeaders, "user-agent": "Mozilla/5.0" },
    clientIdentity: identity,
  }));
  assert.notEqual(first.actorId, second.actorId);
  assert.equal(first.resolvedActorId, second.resolvedActorId);
});

test("Case 3: IP와 User-Agent가 함께 변경돼도 signed dcid가 같으면 유지된다", () => {
  const identity = client("case-3");
  const first = latest(record({ sessionId: "case-3-a", ip: "10.0.3.1", clientIdentity: identity }));
  const second = latest(record({
    sessionId: "case-3-b",
    ip: "10.0.3.2",
    headers: { ...baseHeaders, "user-agent": "Agent/3" },
    clientIdentity: identity,
  }));
  assert.notEqual(first.actorId, second.actorId);
  assert.equal(first.resolvedActorId, second.resolvedActorId);
});

test("Case 4: dlsid가 달라도 signed dcid가 같으면 새 Session이 동일 Resolved Actor에 연결된다", () => {
  const identity = client("case-4");
  const first = latest(record({ sessionId: "case-4-a", ip: "10.0.4.1", clientIdentity: identity }));
  const second = latest(record({ sessionId: "case-4-b", ip: "10.0.4.1", clientIdentity: identity }));
  assert.notEqual(first.sessionId, second.sessionId);
  assert.equal(first.resolvedActorId, second.resolvedActorId);
  assert.equal(store.getResolvedActorAggregate(first.resolvedActorId).sessionIds.length, 2);
});

test("Case 5: Bearer Token이 갱신돼 Auth Group이 달라도 dcid가 같으면 Resolved Actor는 유지된다", () => {
  const identity = client("case-5");
  const first = latest(record({
    sessionId: "case-5-a", ip: "10.0.5.1", clientIdentity: identity, authGroupId: "auth:old",
  }));
  const second = latest(record({
    sessionId: "case-5-b", ip: "10.0.5.2", clientIdentity: identity, authGroupId: "auth:new",
  }));
  const aggregate = store.getResolvedActorAggregate(first.resolvedActorId);
  assert.equal(first.resolvedActorId, second.resolvedActorId);
  assert.deepEqual(new Set(aggregate.authGroupIds), new Set(["auth:old", "auth:new"]));
});

test("Case 6: 동일 dcid에서 Account가 바뀌면 Client는 유지하고 account_changed를 기록한다", () => {
  const identity = client("case-6");
  const first = latest(record({
    sessionId: "case-6-a", ip: "10.0.6.1", clientIdentity: identity, accountIdentity: account("user1"),
  }));
  const second = latest(record({
    sessionId: "case-6-b", ip: "10.0.6.1", clientIdentity: identity, accountIdentity: account("user2"),
  }));
  const aggregate = store.getResolvedActorAggregate(first.resolvedActorId);
  assert.equal(first.resolvedActorId, second.resolvedActorId);
  assert.deepEqual(
    new Set(aggregate.accountAffiliations.map((entry) => entry.accountId)),
    new Set(["account:user1", "account:user2"])
  );
  assert.ok(aggregate.evidence.some((item) => item.code === "account_changed"));
});

test("Case 7: 동일 Account라도 서로 다른 dcid는 자동 Confirmed Merge하지 않는다", () => {
  const first = latest(record({
    sessionId: "case-7-a", ip: "10.0.7.1", clientIdentity: client("case-7-a"), accountIdentity: account("shared"),
  }));
  const second = latest(record({
    sessionId: "case-7-b", ip: "10.0.7.2", clientIdentity: client("case-7-b"), accountIdentity: account("shared"),
  }));
  assert.notEqual(first.resolvedActorId, second.resolvedActorId);
  const firstAggregate = store.getResolvedActorAggregate(first.resolvedActorId);
  assert.deepEqual(firstAggregate.sessionIds, ["case-7-a"]);
  assert.ok(
    firstAggregate.memberships.some(
      (membership) => membership.sessionId === "case-7-b" && membership.status === "PROVISIONAL"
    )
  );
});

test("Case 8: 동일 NAT와 동일 Header Candidate라도 서로 다른 dcid는 별도 Resolved Actor다", () => {
  const first = latest(record({
    sessionId: "case-8-a", ip: "10.0.8.1", clientIdentity: client("case-8-a"),
  }));
  const second = latest(record({
    sessionId: "case-8-b", ip: "10.0.8.1", clientIdentity: client("case-8-b"),
  }));
  assert.equal(first.actorId, second.actorId);
  assert.notEqual(first.resolvedActorId, second.resolvedActorId);
});

test("Case 9: Header와 operation만 같으면 SUGGESTED 관계만 만들고 Feature에는 합치지 않는다", () => {
  const now = Date.now();
  const first = latest(record({
    sessionId: "case-9-a", ip: "10.0.9.1", clientIdentity: client("case-9-a"), url: "/api/items/1", ts: now,
  }));
  record({
    sessionId: "case-9-b", ip: "10.0.9.2", clientIdentity: client("case-9-b"), url: "/api/items/2", ts: now + 1_000,
  });
  const aggregate = store.getResolvedActorAggregate(first.resolvedActorId);
  assert.ok(aggregate.memberships.some((membership) => membership.status === "SUGGESTED"));
  assert.deepEqual(aggregate.sessionIds, ["case-9-a"]);
  assert.equal(aggregate.totalRequests, 1);
});

test("Case 10: IP가 반복 변경돼도 dcid가 같으면 IP history만 증가하고 Feature는 연속 집계된다", () => {
  const identity = client("case-10");
  const ips = ["1.1.1.1", "8.8.8.8", "3.3.3.3"];
  let resolvedActorId;
  ips.forEach((ip, index) => {
    const request = latest(record({
      sessionId: `case-10-${index}`,
      ip,
      clientIdentity: identity,
      url: `/api/sequence/${index}`,
      ts: Date.now() + index,
    }));
    resolvedActorId = resolvedActorId || request.resolvedActorId;
    assert.equal(request.resolvedActorId, resolvedActorId);
  });
  const aggregate = store.getResolvedActorAggregate(resolvedActorId);
  const features = extractResolvedActorFeatures(aggregate);
  assert.deepEqual(aggregate.observedIps, ips);
  assert.equal(aggregate.ipChangeCount, 2);
  assert.equal(features.totalRequests, 3);
  assert.equal(features.behavior.recentSequence.length, 3);
});

test("같은 Session에서 signed dcid가 충돌하면 기존 Confirmed Membership을 유지하고 CONFLICT를 기록한다", () => {
  const first = latest(record({
    sessionId: "case-conflict", ip: "10.0.11.1", clientIdentity: client("conflict-a"),
  }));
  const second = latest(record({
    sessionId: "case-conflict", ip: "10.0.11.1", clientIdentity: client("conflict-b"),
  }));
  assert.equal(first.resolvedActorId, second.resolvedActorId);
  const aggregate = store.getResolvedActorAggregate(first.resolvedActorId);
  assert.ok(aggregate.conflicts.some((item) => item.code === "signed_dcid_changed_within_session"));
  assert.ok(aggregate.memberships[0].conflicts.includes("signed_dcid_changed_within_session"));
});

test("Resolved Actor 요청은 Session 참조로 구성하고 requestId 기준 중복 제거한다", () => {
  const identity = client("dedup");
  const request = latest(record({ sessionId: "case-dedup", ip: "10.0.12.1", clientIdentity: identity }));
  const aggregate = store.getResolvedActorAggregate(request.resolvedActorId);
  assert.equal(aggregate.totalRequests, new Set(aggregate.requests.map((item) => item.requestId)).size);
  assert.equal(Object.prototype.hasOwnProperty.call(store.getResolvedActorAggregate(request.resolvedActorId), "requests"), true);
});

test("Membership을 비활성화하면 Resolved Feature에서 제외되지만 원본 Session은 보존된다", () => {
  const request = latest(record({
    sessionId: "case-revoke",
    ip: "10.0.13.1",
    clientIdentity: client("revoke"),
  }));
  const before = store.getResolvedActorAggregate(request.resolvedActorId);
  const membershipId = before.confirmedMemberships[0].membershipId;
  assert.equal(store.deactivateResolutionMembership(membershipId, "manual_test_revoke"), true);

  const after = store.getResolvedActorAggregate(request.resolvedActorId);
  assert.equal(after.totalRequests, 0);
  assert.deepEqual(after.sessionIds, []);
  assert.equal(after.memberships[0].active, false);
  assert.equal(store.getSession("case-revoke").requests.length, 1);
});

test("새로 발급했지만 반환되지 않은 dcid는 CONFIRMED 근거가 아니다", () => {
  const request = latest(record({
    sessionId: "case-issued-pending",
    ip: "10.0.14.1",
    headers: { ...baseHeaders, "user-agent": "issued-pending-agent" },
    clientIdentity: issuedClient("pending-return"),
  }));
  const aggregate = store.getResolvedActorAggregate(request.resolvedActorId);
  assert.equal(aggregate.status, "PROVISIONAL");
  assert.equal(aggregate.continuityConfirmed, false);
  assert.equal(aggregate.totalRequests, 0);
  assert.equal(aggregate.observedTotalRequests, 1);
  assert.deepEqual(aggregate.observedSessionIds, ["case-issued-pending"]);
  assert.deepEqual(aggregate.sessionIds, []);
  assert.ok(aggregate.memberships[0].reasonCodes.includes("dcid_issued_not_returned"));
});

test("발급한 dcid가 반환되면 최초 PROVISIONAL Session까지 CONFIRMED로 소급 승격한다", () => {
  const clientId = "promoted-return";
  const first = latest(record({
    sessionId: "case-promote-a",
    ip: "10.0.15.1",
    headers: { ...baseHeaders, "user-agent": "promote-agent" },
    clientIdentity: issuedClient(clientId),
  }));
  const second = latest(record({
    sessionId: "case-promote-b",
    ip: "10.0.15.2",
    headers: { ...baseHeaders, "user-agent": "promote-agent-v2" },
    clientIdentity: client(clientId),
  }));
  assert.equal(first.resolvedActorId, second.resolvedActorId);
  const aggregate = store.getResolvedActorAggregate(first.resolvedActorId);
  assert.equal(aggregate.continuityConfirmed, true);
  assert.equal(aggregate.totalRequests, 2);
  assert.deepEqual(new Set(aggregate.sessionIds), new Set(["case-promote-a", "case-promote-b"]));
  assert.equal(aggregate.confirmedMemberships.length, 2);
  assert.ok(
    aggregate.confirmedMemberships
      .find(membership => membership.sessionId === "case-promote-a")
      .reasonCodes.includes("signed_dcid_returned")
  );
});

test("쿠키를 반환하지 않는 독립 요청은 Candidate 탐지를 유지하되 동일 Client로 확정하지 않는다", () => {
  const headers = { ...baseHeaders, "user-agent": "stateless-natural-agent" };
  const requests = [0, 1, 2].map(index => latest(record({
    sessionId: `case-stateless-${index}`,
    ip: "10.0.16.1",
    headers,
    url: `/natural/${index}`,
    clientIdentity: issuedClient(`stateless-${index}`),
  })));
  assert.equal(new Set(requests.map(request => request.actorId)).size, 1);
  assert.equal(new Set(requests.map(request => request.resolvedActorId)).size, 3);
  assert.equal(store.getActor(requests[0].actorId).totalRequests, 3);
  for (const request of requests) {
    assert.equal(store.getResolvedActorAggregate(request.resolvedActorId).continuityConfirmed, false);
  }
});
