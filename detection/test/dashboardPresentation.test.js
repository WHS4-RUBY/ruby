const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function loadPresentation(fetchImpl = async () => ({ status: 200 })) {
  const dashboardPath = path.join(__dirname, "../public/dashboard.html");
  const html = fs.readFileSync(dashboardPath, "utf8");
  const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
  assert.ok(script, "탐지 대시보드의 inline script가 있어야 한다");
  const bootstrap = "document.getElementById('closeButton').addEventListener('click', closeModal);";
  const bootstrapAt = script.indexOf(bootstrap);
  assert.ok(bootstrapAt > 0, "이벤트 등록 전의 표시 함수를 분리할 수 있어야 한다");

  const elements = new Map();
  const document = {
    activeElement: null,
    getElementById(id) {
      if (!elements.has(id)) {
        elements.set(id, {
          innerHTML: "",
          textContent: "",
          scrollTop: 0,
          querySelectorAll: () => [],
          addEventListener: () => {},
        });
      }
      return elements.get(id);
    },
  };
  const context = vm.createContext({
    document,
    window: { fetch: fetchImpl },
    localStorage: { getItem: () => null },
  });
  context.fetch = (...args) => context.window.fetch(...args);
  vm.runInContext(
    `${script.slice(0, bootstrapAt)}\nglobalThis.presentation = { state, scoreNumber, detectionFor, buildUserRows, filterAndSortUsers, renderEvidenceOverview, renderUserList, renderUserDetail, selectUser, loadUserDetail, buildSessionNodes, renderRelation, renderConnectionDetails, renderTimeline };`,
    context,
    { filename: dashboardPath }
  );
  return { ...context.presentation, elements, document, context };
}

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

function confirmedActor(id, candidateId, attackScore = 0.1) {
  return {
    resolvedActorId: id,
    continuityConfirmed: true,
    status: "CONFIRMED",
    confidence: "HIGH",
    candidateIds: [candidateId],
    sessionIds: [`session:${id}`],
    observedIps: ["203.0.113.10"],
    confirmedMembershipCount: 1,
    totalRequests: 2,
    sessionCount: 1,
    automationScore: 0.1,
    attackScore,
    attackHistory: { maxAttackScore: attackScore },
    firstSeen: 1000,
    lastSeen: 2000,
  };
}

function candidate(id, resolvedId, attackScore = 0.1) {
  return {
    actorId: id,
    resolvedActorIds: [resolvedId],
    ip: "203.0.113.10",
    totalRequests: 2,
    sessionCount: 1,
    automationScore: 0.1,
    attackScore,
    attackHistory: { maxAttackScore: attackScore },
    firstSeen: 1000,
    lastSeen: 2000,
  };
}

test("서로 다른 서명 ID가 한 Client Flow에 있어도 동일 클라이언트로 확정하지 않는다", () => {
  const ui = loadPresentation();
  const actors = [confirmedActor("resolved:a", "actor:a", 0.8), confirmedActor("resolved:b", "actor:b", 0.1)];
  const candidates = [candidate("actor:a", "resolved:a", 0.8), candidate("actor:b", "resolved:b", 0.1)];
  const flow = {
    clientFlowId: "client-flow:linked",
    status: "FLOW_LINKED",
    confidence: "MEDIUM",
    flowLinked: true,
    candidateIds: ["actor:a", "actor:b"],
    resolvedActorIds: ["resolved:a", "resolved:b"],
    observedIps: ["203.0.113.10", "198.51.100.20"],
    verifiedClientCount: 2,
    links: [{ matchedFields: ["userAgentFamily"], changedFields: ["ip"] }],
    totalRequests: 4,
    sessionCount: 2,
    candidateCount: 2,
    automationScore: 0.1,
    attackScore: 0.8,
    attackHistory: { maxAttackScore: 0.8 },
    firstSeen: 1000,
    lastSeen: 2000,
  };

  const rows = ui.buildUserRows(actors, candidates, [flow]);
  assert.equal(rows.length, 3);
  const flowRow = rows.find(row => row.kind === "client-flows");
  assert.equal(flowRow.identity, "heuristic");
  assert.equal(flowRow.verifiedClientCount, 2);
  assert.equal(rows.filter(row => row.identity === "confirmed").length, 2);
  ui.state.identityFilter = "confirmed";
  assert.equal(ui.filterAndSortUsers(rows).length, 2, "각 서명 ID 흐름은 확인 필터에서 찾을 수 있다");
  ui.state.identityFilter = "all";
  assert.equal(actors[1].attackScore, 0.1, "다른 서명 ID의 점수는 변경되지 않는다");

  ui.state.users = rows;
  ui.renderUserList();
  const listHtml = ui.elements.get("userList").innerHTML;
  assert.match(listHtml, /서명 ID 2개는 별도/);
  assert.match(listHtml, /동일 클라이언트 미확정/);
  assert.match(listHtml, /서명 ID 확인/);

  const overview = ui.renderEvidenceOverview(flow, "client-flows", []);
  assert.match(overview, /서명 ID 2개는 별도/);
  assert.match(overview, /동일인 확률이 아닙니다/);
  assert.doesNotMatch(overview, /서명 ID 근거/);
});

test("후보 흐름의 합산 공격 점수는 개별 서명 ID의 공격 식별로 표시하지 않는다", () => {
  const ui = loadPresentation();
  const actors = [confirmedActor("resolved:a", "actor:a", 0.4), confirmedActor("resolved:b", "actor:b", 0)];
  const candidates = [candidate("actor:a", "resolved:a", 0.4), candidate("actor:b", "resolved:b", 0)];
  const flow = {
    clientFlowId: "client-flow:linked",
    status: "FLOW_LINKED",
    confidence: "MEDIUM",
    flowLinked: true,
    candidateIds: ["actor:a", "actor:b"],
    resolvedActorIds: ["resolved:a", "resolved:b"],
    observedIps: ["203.0.113.10"],
    verifiedClientCount: 2,
    links: [{ matchedFields: ["userAgentFamily"], changedFields: ["ip"] }],
    totalRequests: 4,
    sessionCount: 2,
    candidateCount: 2,
    automationScore: 0.1,
    attackScore: 0.5,
    attackHistory: { maxAttackScore: 0.5 },
    firstSeen: 1000,
    lastSeen: 2000,
  };

  const rows = ui.buildUserRows(actors, candidates, [flow]);
  assert.equal(rows.length, 3);
  assert.equal(rows.filter(row => row.identity === "confirmed").length, 2);
  ui.state.users = rows;
  ui.renderUserList();
  const listHtml = ui.elements.get("userList").innerHTML;
  const cardFor = id => {
    const card = listHtml.match(new RegExp(`<button[^>]*data-user-id="${id}"[^>]*>[\\s\\S]*?<\\/button>`));
    assert.ok(card, `${id} 카드가 보여야 한다`);
    return card[0];
  };
  const flowCard = cardFor("client-flow:linked");
  const firstClientCard = cardFor("resolved:a");
  const secondClientCard = cardFor("resolved:b");

  assert.match(flowCard, /<span class="mini-value">50<\/span>/);
  assert.match(flowCard, /후보 흐름 공격 신호/);
  assert.doesNotMatch(flowCard, />공격 식별<\/span>/);
  assert.match(firstClientCard, /<span class="mini-value">40<\/span>/);
  for (const card of [firstClientCard, secondClientCard]) {
    assert.doesNotMatch(card, /후보 흐름 공격 신호|>공격 식별<\/span>|<span class="mini-value">50<\/span>/);
  }

  ui.state.riskFilter = "attack-detected";
  assert.equal(ui.filterAndSortUsers(rows).map(row => row.id).join(), "client-flow:linked");
});

test("확정 흐름과 미확정 요청이 섞인 후보를 목록에서 숨기지 않는다", () => {
  const ui = loadPresentation();
  const resolved = confirmedActor("resolved:a", "actor:a");
  const mixed = {
    ...candidate("actor:a", "resolved:a"),
    totalRequests: 3,
    unresolvedRequestCount: 1,
  };
  const rows = ui.buildUserRows([resolved], [mixed], []);
  assert.equal(rows.length, 2);
  const mixedRow = rows.find(row => row.kind === "actors");
  assert.equal(mixedRow.identity, "heuristic");
  assert.equal(mixedRow.totalRequests, 3);
  assert.match(mixedRow.note, /미확정 흐름/);
  assert.equal(rows.filter(row => row.identity === "confirmed").length, 1);
});

test("타임라인에 요청이 없는 잠정 세션은 필터 버튼으로 표시하지 않는다", () => {
  const ui = loadPresentation();
  const detail = {
    resolvedActorId: "resolved:a",
    candidateIds: ["actor:a"],
    requests: [{ sessionId: "session:confirmed", ts: 1000, method: "GET", url: "/", status: 200 }],
    memberships: [
      { sessionId: "session:confirmed", status: "CONFIRMED", candidateId: "actor:a" },
      { sessionId: "session:provisional", status: "PROVISIONAL", candidateId: "actor:a", requestCount: 3, createdAt: 1100, updatedAt: 1200 },
    ],
  };
  const nodes = ui.buildSessionNodes(detail, "resolved-actors");
  assert.equal(nodes.find(node => node.sessionId === "session:provisional").timelineAvailable, false);
  const relation = ui.renderRelation(detail, "resolved-actors", nodes);
  assert.match(relation, /타임라인 없음/);
  assert.doesNotMatch(relation, /data-session-filter="session:provisional"/);
  const timeline = ui.renderTimeline(detail, nodes);
  assert.doesNotMatch(timeline, /<option value="session:provisional"/);
});

test("첫 요청의 잠정 행위자 연결을 서명 ID 확인이나 확정 흐름으로 표시하지 않는다", () => {
  const ui = loadPresentation();
  const pending = {
    ...confirmedActor("resolved:pending", "actor:pending"),
    continuityConfirmed: false,
    status: "PROVISIONAL",
    clientIds: ["issued-but-not-returned"],
    confirmedMembershipCount: 0,
    provisionalMembershipCount: 1,
  };
  const observed = {
    ...candidate("actor:pending", "resolved:pending"),
    sessionIds: ["session:pending"],
    requests: [{
      sessionId: "session:pending",
      resolvedActorId: "resolved:pending",
      ts: 1000,
      method: "GET",
      url: "/",
      status: 200,
    }],
  };
  const rows = ui.buildUserRows([pending], [observed]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].identity, "heuristic");
  assert.match(rows[0].note, /서명 ID 확인 전/);

  const overview = ui.renderEvidenceOverview(observed, "actors", []);
  assert.match(overview, /연결된 행위자 기록 1개/);
  assert.match(overview, /첫 요청의 잠정 연결도 포함/);
  assert.doesNotMatch(overview, /연결된 서명 ID 흐름|서명 ID 근거/);

  const sessionNodes = ui.buildSessionNodes(observed, "actors");
  const relation = ui.renderRelation(observed, "actors", sessionNodes);
  assert.match(relation, /연결된 행위자 기록/);
  assert.doesNotMatch(relation, /연결된 확정 흐름/);

  const flowDetail = {
    clientFlowId: "client-flow:pending",
    candidateIds: ["actor:pending"],
    requests: observed.requests,
  };
  const connection = ui.renderConnectionDetails(flowDetail, "client-flows", sessionNodes);
  assert.match(connection, /연결 기록 1/);
  assert.doesNotMatch(connection, /확정 흐름 1/);

  ui.state.selected = { kind: "resolved-actors", id: pending.resolvedActorId };
  ui.state.userDetail = { ...pending, requests: observed.requests, memberships: [{ sessionId: "session:pending", status: "PROVISIONAL" }] };
  ui.renderUserDetail();
  const pendingHtml = ui.elements.get("userDetail").innerHTML;
  assert.match(pendingHtml, /연속성 미확인/);
  assert.match(pendingHtml, /잠정 연결 세션 1개/);
  assert.doesNotMatch(pendingHtml, /<span class="badge confirmed"[^>]*>서명 ID 확인<\/span>|서명 ID 근거|확정 연결 세션/);
});

test("확인된 연속성과 잠정·관찰 근거를 별도 수준으로 표시한다", () => {
  const ui = loadPresentation();
  const resolved = {
    ...confirmedActor("resolved:a", "actor:a"),
    clientIds: ["dcid:a"],
    confirmedMembershipCount: 1,
    provisionalMembershipCount: 2,
    accountAffiliations: [{ verified: true }],
  };
  const confirmedHtml = ui.renderEvidenceOverview(resolved, "resolved-actors", []);
  assert.match(confirmedHtml, /서명 ID 근거/);
  assert.match(confirmedHtml, /확정 연결 세션 1개/);
  assert.match(confirmedHtml, /evidence-point observed">잠정 연결 세션 2개/);
  assert.match(confirmedHtml, /실제 사람의 동일성까지 확인된 것은 아닙니다/);

  const observedHtml = ui.renderEvidenceOverview({
    observedIps: ["203.0.113.10"],
    resolvedActorIds: ["resolved:a", "resolved:b"],
  }, "actors", [{}, {}]);
  assert.match(observedHtml, /관찰 단서/);
  assert.match(observedHtml, /연결된 행위자 기록 2개는 별도/);
  assert.match(observedHtml, /IP와 헤더 정보만으로 같은 클라이언트나 사람이라고 확정할 수 없습니다/);
});

test("단서와 목록 텍스트를 HTML로 해석하지 않는다", () => {
  const ui = loadPresentation();
  const injection = '<img src=x onerror="alert(1)">';
  const overview = ui.renderEvidenceOverview({
    status: "FLOW_LINKED",
    candidateIds: ["actor:a", "actor:b"],
    links: [{ matchedFields: [injection] }],
  }, "client-flows", []);
  assert.doesNotMatch(overview, /<img/);
  assert.match(overview, /&lt;img/);

  const row = ui.buildUserRows([confirmedActor("resolved:a", "actor:a")], [], [])[0];
  row.id = injection;
  row.note = injection;
  ui.state.users = [row];
  ui.renderUserList();
  const listHtml = ui.elements.get("userList").innerHTML;
  assert.doesNotMatch(listHtml, /<img/);
  assert.match(listHtml, /&lt;img/);
});

test("확인 상태·위험 필터와 원본 점수는 표시 변경 후에도 분리된다", () => {
  const ui = loadPresentation();
  const confirmed = ui.buildUserRows([confirmedActor("resolved:low", "actor:low", 0.1)], [], [])[0];
  const heuristic = ui.buildUserRows([], [candidate("actor:high", null, 0.8)], [])[0];
  ui.state.users = [confirmed, heuristic];
  ui.state.identityFilter = "confirmed";
  assert.equal(ui.filterAndSortUsers(ui.state.users).map(row => row.id).join(), "resolved:low");
  ui.state.identityFilter = "heuristic";
  assert.equal(ui.filterAndSortUsers(ui.state.users).map(row => row.id).join(), "actor:high");
  ui.state.identityFilter = "all";
  ui.state.riskFilter = "attack-detected";
  assert.equal(ui.filterAndSortUsers(ui.state.users).map(row => row.id).join(), "actor:high");
  assert.equal(confirmed.attackScore, 0.1);
  assert.equal(heuristic.attackScore, 0.8);
});

test("표시 점수가 임계값 아래의 원점수를 반올림해 넘기지 않는다", () => {
  const ui = loadPresentation();
  ui.state.detectionLevel = "high";
  assert.equal(ui.scoreNumber(0.6999), 69.99);
  assert.equal(ui.detectionFor({ attackScore: 0.6999 }).attackDetected, false);
  assert.equal(ui.detectionFor({ attackScore: 0.7 }).attackDetected, true);
  assert.equal(ui.scoreNumber(0.796), 79.6);
});

test("요청 ID 검색 결과에서는 백그라운드 요청을 접지 않는다", () => {
  const ui = loadPresentation();
  const detail = { requests: [{
    requestId: "request:polling", sessionId: "session:one", ts: 1700000000000,
    method: "GET", url: "/socket.io/?EIO=4", status: 200,
    backgroundTraffic: { isBackground: true, category: "socket_io_polling" },
  }] };
  const nodes = [{ sessionId: "session:one", timelineAvailable: true, index: 1, color: "#123456", requestCount: 1 }];
  assert.match(ui.renderTimeline(detail, nodes), /Socket\.IO polling 1건/);
  ui.state.timelineQuery = "request:polling";
  const result = ui.renderTimeline(detail, nodes);
  assert.match(result, /요청 ID <code>request:polling<\/code>/);
  assert.doesNotMatch(result, /Socket\.IO polling 1건/);
});

test("부분 응답 오류와 스트리밍 본문 미검사를 성공 응답과 구별한다", () => {
  const ui = loadPresentation();
  const nodes = [{ sessionId: "session:one", timelineAvailable: true, index: 1,
    color: "#123456", requestCount: 2 }];
  const detail = { requests: [
    { requestId: "request:partial", sessionId: "session:one", ts: 1000,
      method: "GET", url: "/broken", status: 200, responseTransportOutcome: "error",
      responseBodyInspected: false },
    { requestId: "request:events", sessionId: "session:one", ts: 2000,
      method: "GET", url: "/events", status: 200, responseTransportOutcome: "complete",
      responseBodyInspected: false },
  ] };
  const html = ui.renderTimeline(detail, nodes);
  assert.match(html, /200 · 전송 오류/);
  assert.match(html, /응답 전달 중 오류\(본문 불완전\)/);
  assert.match(html, /응답 본문 검사 생략\(스트리밍·크기 제한\)/);
  ui.state.timelineFlaggedOnly = true;
  const flagged = ui.renderTimeline(detail, nodes);
  assert.match(flagged, /request:partial/);
  assert.doesNotMatch(flagged, /request:events/);
});

test("A 상세 응답이 B 선택 뒤 늦게 도착해도 B 상세를 덮지 않는다", async () => {
  const aResponse = deferred();
  const requested = [];
  const ui = loadPresentation((url) => {
    requested.push(url);
    return url.endsWith("resolved%3Aa") ? aResponse.promise : Promise.resolve({
      status: 200,
      ok: true,
      json: async () => ({ resolvedActorId: "resolved:b" }),
    });
  });
  // 이 테스트는 비동기 상세 선택의 상태 경쟁만 확인한다.
  vm.runInContext("renderUserDetail = () => {};", ui.context);
  ui.state.users = [
    ui.buildUserRows([confirmedActor("resolved:a", "actor:a")], [], [])[0],
    ui.buildUserRows([confirmedActor("resolved:b", "actor:b")], [], [])[0],
  ];

  const selectingA = ui.selectUser("resolved-actors", "resolved:a");
  const selectingB = ui.selectUser("resolved-actors", "resolved:b");
  await selectingB;
  assert.equal(ui.state.userDetail.resolvedActorId, "resolved:b");
  aResponse.resolve({ status: 200, ok: true, json: async () => ({ resolvedActorId: "resolved:a" }) });
  await selectingA;
  assert.equal(ui.state.userDetail.resolvedActorId, "resolved:b");
  assert.deepEqual(requested, [
    "/__detection/api/resolved-actors/resolved%3Aa",
    "/__detection/api/resolved-actors/resolved%3Ab",
  ]);
});

test("자동 목록 재렌더는 선택 카드의 키보드 포커스와 스크롤 위치를 유지한다", () => {
  const ui = loadPresentation();
  ui.state.users = [
    ui.buildUserRows([confirmedActor("resolved:a", "actor:a")], [], [])[0],
    ui.buildUserRows([confirmedActor("resolved:b", "actor:b")], [], [])[0],
  ];
  const list = ui.document.getElementById("userList");
  list.scrollTop = 120;
  const oldFocused = {
    dataset: { userKind: "resolved-actors", userId: "resolved:b" },
    closest(selector) { return selector === ".user-card" ? this : null; },
  };
  const otherCard = {
    dataset: { userKind: "resolved-actors", userId: "resolved:a" },
    addEventListener() {},
    focus() { throw new Error("다른 카드로 포커스가 이동하면 안 된다"); },
  };
  const replacement = {
    dataset: { userKind: "resolved-actors", userId: "resolved:b" },
    addEventListener() {},
    focus(options) { ui.document.activeElement = this; this.focusOptions = options; },
  };
  ui.document.activeElement = oldFocused;
  list.querySelectorAll = () => [otherCard, replacement];

  ui.renderUserList();
  assert.equal(ui.document.activeElement, replacement);
  assert.equal(replacement.focusOptions.preventScroll, true);
  assert.equal(list.scrollTop, 120);
});
