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
    `${script.slice(0, bootstrapAt)}\nglobalThis.presentation = { state, scoreNumber, detectionFor, buildUserRows, filterAndSortUsers, renderEvidenceOverview, renderUserList, renderUserDetail, selectUser, loadUserDetail, buildSessionNodes, renderRelation, renderConnectionDetails, renderTimeline, renderRequests, renderLogDetail, renderModalDetail, parseLogQuery, matchesLogQuery, buildLogEntries, highlightText, highlightJson, toggleLogQueryToken, requestSeverity };`,
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
    aggregationEnabled: true,
    anchorCandidateId: "actor:a",
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
  assert.equal(rows.length, 1, "서명 ID는 요청 흐름 목록에 중복 행으로 표시하지 않는다");
  const flowRow = rows.find(row => row.kind === "client-flows");
  assert.equal(flowRow.identity, "heuristic");
  assert.equal(flowRow.verifiedClientCount, 2);
  assert.equal(flowRow.relatedIds.includes("resolved:a"), true);
  assert.equal(flowRow.relatedIds.includes("resolved:b"), true);
  assert.equal(actors[1].attackScore, 0.1, "다른 서명 ID의 점수는 변경되지 않는다");

  ui.state.users = rows;
  ui.renderUserList();
  const listHtml = ui.elements.get("userList").innerHTML;
  assert.match(listHtml, /서명 ID 2개는 별도/);
  assert.match(listHtml, /동일 클라이언트 미확정/);
  assert.doesNotMatch(listHtml, /data-user-kind="resolved-actors"/);

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
    aggregationEnabled: true,
    anchorCandidateId: "actor:a",
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
  assert.equal(rows.length, 1);
  ui.state.users = rows;
  ui.renderUserList();
  const listHtml = ui.elements.get("userList").innerHTML;
  const cardFor = id => {
    const card = listHtml.match(new RegExp(`<button[^>]*data-user-id="${id}"[^>]*>[\\s\\S]*?<\\/button>`));
    assert.ok(card, `${id} 카드가 보여야 한다`);
    return card[0];
  };
  const flowCard = cardFor("client-flow:linked");

  assert.match(flowCard, /<span class="mini-value">50<\/span>/);
  assert.match(flowCard, /후보 흐름 공격 신호/);
  assert.doesNotMatch(flowCard, />공격 식별<\/span>/);
  assert.doesNotMatch(listHtml, /data-user-id="resolved:/);
  assert.equal(actors[0].attackScore, 0.4);
  assert.equal(actors[1].attackScore, 0);

  ui.state.riskFilter = "attack-detected";
  assert.equal(ui.filterAndSortUsers(rows).map(row => row.id).join(), "client-flow:linked");
});

test("서명 ID 확인 여부와 관계없이 연결되지 않은 후보의 요청은 주 목록에 남는다", () => {
  const ui = loadPresentation();
  const resolved = confirmedActor("resolved:a", "actor:a");
  const mixed = {
    ...candidate("actor:a", "resolved:a"),
    totalRequests: 3,
    unresolvedRequestCount: 1,
  };
  const rows = ui.buildUserRows([resolved], [mixed], []);
  assert.equal(rows.length, 1);
  const mixedRow = rows.find(row => row.kind === "actors");
  assert.equal(mixedRow.identity, "heuristic");
  assert.equal(mixedRow.totalRequests, 3);
  assert.match(mixedRow.note, /연결된 Client Flow 없음/);
  assert.equal(mixedRow.relatedIds.includes("resolved:a"), true);
});

test("연결된 흐름 64건과 단독 관찰 3건을 한 번씩 주 목록에서 열 수 있다", () => {
  const ui = loadPresentation();
  const candidates = [
    { ...candidate("actor:main", "resolved:main"), totalRequests: 64, sessionCount: 25 },
    ...[1, 2, 3].map(n => ({ ...candidate(`actor:single-${n}`, `resolved:single-${n}`), totalRequests: 1 })),
  ];
  const flow = {
    clientFlowId: "client-flow:main", flowLinked: true, status: "FLOW_LINKED",
    anchorCandidateId: "actor:main", candidateIds: ["actor:main"],
    totalRequests: 64, sessionCount: 25, candidateCount: 1,
    observedIps: ["203.0.113.10"], lastSeen: 1000,
  };
  const rows = ui.buildUserRows([], candidates, [flow]);
  assert.equal(rows.length, 4);
  assert.equal(rows.reduce((sum, row) => sum + row.totalRequests, 0), 67);
  assert.equal(rows.filter(row => row.flowType === "standalone").length, 3);
  assert.equal(ui.filterAndSortUsers(rows)[0].id, "client-flow:main", "Client Flow를 먼저 보여 준다");
  assert.equal(rows.some(row => row.id === "actor:main"), false, "Flow에 완전히 포함된 Candidate는 중복하지 않는다");
});

test("연결 Flow가 없어도 요청 86건을 단독 관찰 흐름에서 열 수 있다", () => {
  const ui = loadPresentation();
  const rows = ui.buildUserRows([], [{ ...candidate("actor:only", "resolved:only"), totalRequests: 86 }], []);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].kind, "actors");
  assert.equal(rows[0].flowType, "standalone");
  assert.equal(rows[0].totalRequests, 86);
});

test("Flow 집계가 일부 요청만 포함하면 후보 행을 보존해 요청 누락을 피한다", () => {
  const ui = loadPresentation();
  const candidates = [candidate("actor:a", "resolved:a"), candidate("actor:b", "resolved:b")];
  const flow = {
    clientFlowId: "client-flow:partial", flowLinked: true, aggregationEnabled: true,
    status: "FLOW_LINKED", candidateIds: ["actor:a", "actor:b"], totalRequests: 3,
  };
  const rows = ui.buildUserRows([], candidates, [flow]);
  assert.equal(rows.length, 3);
  assert.equal(rows.filter(row => row.flowType === "standalone").length, 2);
  assert.match(rows[0].note, /누락 방지를 위해 후보 요청도 표시/);
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
  assert.match(rows[0].note, /서명 ID 기록 1개는 별도 보기/);

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

  const row = ui.buildUserRows([], [candidate("actor:a", "resolved:a")], [])[0];
  row.id = injection;
  row.note = injection;
  ui.state.users = [row];
  ui.renderUserList();
  const listHtml = ui.elements.get("userList").innerHTML;
  assert.doesNotMatch(listHtml, /<img/);
  assert.match(listHtml, /&lt;img/);
});

test("연결 상태·위험 필터와 원본 점수는 표시 변경 후에도 분리된다", () => {
  const ui = loadPresentation();
  const standalone = ui.buildUserRows([], [candidate("actor:high", null, 0.8)], [])[0];
  const linked = ui.buildUserRows([], [], [{
    clientFlowId: "client-flow:low", flowLinked: true, status: "FLOW_LINKED",
    totalRequests: 2, attackScore: 0.1, automationScore: 0.1,
  }])[0];
  ui.state.users = [standalone, linked];
  ui.state.flowFilter = "linked";
  assert.equal(ui.filterAndSortUsers(ui.state.users).map(row => row.id).join(), "client-flow:low");
  ui.state.flowFilter = "standalone";
  assert.equal(ui.filterAndSortUsers(ui.state.users).map(row => row.id).join(), "actor:high");
  ui.state.flowFilter = "all";
  ui.state.riskFilter = "attack-detected";
  assert.equal(ui.filterAndSortUsers(ui.state.users).map(row => row.id).join(), "actor:high");
  assert.equal(linked.attackScore, 0.1);
  assert.equal(standalone.attackScore, 0.8);
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
  assert.match(result, /class="log-entry[^"]*expanded"[^>]*data-log-key="request:polling"/, "요청 ID를 그대로 검색하면 해당 행을 펼친다");
  assert.match(result, /<dt>요청 ID<\/dt><dd><code>request:polling<\/code>/);
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
  const rowFor = id => html.match(new RegExp(`<div class="log-entry[^"]*" data-log-key="${id}">[\\s\\S]*?</button>`))?.[0] || "";
  assert.match(rowFor("request:partial"), /log-entry sev-error/, "전송 오류는 성공 응답과 다른 심각도로 표시한다");
  assert.match(rowFor("request:partial"), />200<\/span>[\s\S]*>전송 오류<\/span>/);
  assert.match(rowFor("request:events"), />본문 미검사<\/span>/);
  assert.doesNotMatch(rowFor("request:events"), /전송 오류/);
  assert.match(ui.renderLogDetail(detail.requests[0]), /200<\/span> <span class="kv-warn">응답 전달 중 오류\(본문 불완전\)/);
  assert.match(ui.renderLogDetail(detail.requests[1]), /응답 본문 검사 생략\(스트리밍·크기 제한\)/);
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
    return url.endsWith("actor%3Aa") ? aResponse.promise : Promise.resolve({
      status: 200,
      ok: true,
      json: async () => ({ actorId: "actor:b" }),
    });
  });
  // 이 테스트는 비동기 상세 선택의 상태 경쟁만 확인한다.
  vm.runInContext("renderUserDetail = () => {};", ui.context);
  ui.state.users = [
    ui.buildUserRows([], [candidate("actor:a", "resolved:a")], [])[0],
    ui.buildUserRows([], [candidate("actor:b", "resolved:b")], [])[0],
  ];

  const selectingA = ui.selectUser("actors", "actor:a");
  const selectingB = ui.selectUser("actors", "actor:b");
  await selectingB;
  assert.equal(ui.state.userDetail.actorId, "actor:b");
  aResponse.resolve({ status: 200, ok: true, json: async () => ({ actorId: "actor:a" }) });
  await selectingA;
  assert.equal(ui.state.userDetail.actorId, "actor:b");
  assert.deepEqual(requested, [
    "/__detection/api/actors/actor%3Aa",
    "/__detection/api/actors/actor%3Ab",
  ]);
});

test("자동 목록 재렌더는 선택 카드의 키보드 포커스와 스크롤 위치를 유지한다", () => {
  const ui = loadPresentation();
  ui.state.users = [
    ui.buildUserRows([], [candidate("actor:a", "resolved:a")], [])[0],
    ui.buildUserRows([], [candidate("actor:b", "resolved:b")], [])[0],
  ];
  const list = ui.document.getElementById("userList");
  list.scrollTop = 120;
  const oldFocused = {
    dataset: { userKind: "actors", userId: "actor:b" },
    closest(selector) { return selector === ".user-card" ? this : null; },
  };
  const otherCard = {
    dataset: { userKind: "actors", userId: "actor:a" },
    addEventListener() {},
    focus() { throw new Error("다른 카드로 포커스가 이동하면 안 된다"); },
  };
  const replacement = {
    dataset: { userKind: "actors", userId: "actor:b" },
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

function logKeysInOrder(html) {
  return [...html.matchAll(/data-log-key="([^"]+)"/g)].map(match => match[1]);
}

test("요청 로그와 상세 모달 타임라인은 최신 요청을 맨 위에 둔다", () => {
  const ui = loadPresentation();
  const nodes = [{ sessionId: "session:one", timelineAvailable: true, index: 1, color: "#123456", requestCount: 3 }];
  const requests = [
    { requestId: "request:old", sessionId: "session:one", ts: 1000, method: "GET", url: "/a", status: 200 },
    { requestId: "request:new", sessionId: "session:one", ts: 3000, method: "GET", url: "/c", status: 200 },
    { requestId: "request:mid", sessionId: "session:one", ts: 2000, method: "GET", url: "/b", status: 200 },
  ];
  assert.deepEqual(logKeysInOrder(ui.renderTimeline({ requests }, nodes)), ["request:new", "request:mid", "request:old"]);
  assert.deepEqual(logKeysInOrder(ui.renderRequests(requests)), ["request:new", "request:mid", "request:old"]);
  assert.equal(requests[0].requestId, "request:old", "원본 요청 배열 순서는 바꾸지 않는다");
});

test("접힌 백그라운드 묶음의 시간 범위는 최신순에서도 오래된 시각부터 표시한다", () => {
  const ui = loadPresentation();
  const poll = (id, ts) => ({ requestId: id, sessionId: "session:one", ts, method: "GET", url: "/socket.io/?EIO=4", status: 200,
    backgroundTraffic: { isBackground: true, category: "socket_io_polling" } });
  const entries = ui.buildLogEntries([poll("b", 2000), poll("a", 1000)]);
  assert.equal(entries.length, 1);
  assert.equal(entries[0].requests.length, 2);
  const nodes = [{ sessionId: "session:one", timelineAvailable: true, index: 1, color: "#123456", requestCount: 2 }];
  const html = ui.renderTimeline({ requests: [poll("a", 1000), poll("b", 2000)] }, nodes);
  const first = new Date(1000).toLocaleTimeString();
  const last = new Date(2000).toLocaleTimeString();
  assert.ok(html.includes(`${first}–${last}`), "시간 범위가 거꾸로 표시되면 안 된다");
});

test("검색은 field:value 필터와 일반 검색어를 함께 해석한다", () => {
  const ui = loadPresentation();
  const login = { requestId: "request:1", method: "POST", url: "/rest/user/login", status: 401, tags: [] };
  const honey = { requestId: "request:2", method: "GET", url: "/api/admin", status: 200,
    deceptionEvents: [{ signal: "admin-probe" }] };
  const poll = { requestId: "request:3", method: "GET", url: "/socket.io/?EIO=4", status: 200,
    backgroundTraffic: { isBackground: true } };
  const match = (text, request) => ui.matchesLogQuery(request, ui.parseLogQuery(text));
  assert.equal(match("status:4xx method:post", login), true);
  assert.equal(match("status:4xx", honey), false);
  assert.equal(match("status:401", login), true);
  assert.equal(match("tag:honey", honey), true);
  assert.equal(match("tag:background", poll), true);
  assert.equal(match("-path:/socket.io", poll), false);
  assert.equal(match("-path:/socket.io", login), true);
  assert.equal(match("rest login", login), true, "일반 검색어는 모두 포함해야 한다");
  assert.equal(match("rest admin", login), false);
  assert.equal(match("request:1", login), true, "요청 ID의 콜론은 필터로 해석하지 않는다");
  assert.equal(ui.parseLogQuery("request:1").fields.length, 0);
});

test("패싯은 검색어 토큰을 켜고 끄며 대소문자를 구분하지 않는다", () => {
  const ui = loadPresentation();
  ui.state.timelineQuery = "login";
  ui.toggleLogQueryToken("status:4xx");
  assert.equal(ui.state.timelineQuery, "login status:4xx");
  ui.toggleLogQueryToken("STATUS:4XX");
  assert.equal(ui.state.timelineQuery, "login");
});

test("중복 접기는 신호 없는 연속 동일 요청만 ×N으로 묶는다", () => {
  const ui = loadPresentation();
  const same = ts => ({ sessionId: "s", ts, method: "GET", url: "/rest/products", status: 200 });
  const attacked = { sessionId: "s", ts: 4, method: "GET", url: "/rest/products", status: 200, tags: ["sqli"] };
  const entries = ui.buildLogEntries([same(3), same(2), attacked, same(1)], { dedupe: true });
  assert.equal(entries.map(entry => entry.repeats.length).join(), "1,0,0");
  assert.equal(ui.buildLogEntries([same(3), same(2)], { dedupe: false }).length, 2);

  ui.state.timelineDedup = true;
  const nodes = [{ sessionId: "s", timelineAvailable: true, index: 1, color: "#123456", requestCount: 3 }];
  const html = ui.renderTimeline({ requests: [same(1000), same(2000), same(3000)] }, nodes);
  assert.match(html, />×3<\/span>/);
});

test("심각도는 공격 신호 > 5xx·전송 오류 > 4xx 순으로 정한다", () => {
  const ui = loadPresentation();
  assert.equal(ui.requestSeverity({ status: 404, tags: ["sqli"] }), "critical");
  assert.equal(ui.requestSeverity({ status: 200, attackDetection: { anomalyScore: 5 } }), "critical");
  assert.equal(ui.requestSeverity({ status: 503 }), "error");
  assert.equal(ui.requestSeverity({ status: 200, responseTransportOutcome: "error" }), "error");
  assert.equal(ui.requestSeverity({ status: 403 }), "warn");
  assert.equal(ui.requestSeverity({ status: 200 }), "info");
});

test("로그 행·검색 강조·원본 JSON은 요청 값을 HTML로 해석하지 않는다", () => {
  const ui = loadPresentation();
  const injection = '<img src=x onerror="alert(1)">';
  assert.equal(ui.highlightText(`/a${injection}`, ["img"]), "/a&lt;<mark>img</mark> src=x onerror=&quot;alert(1)&quot;&gt;");
  const request = { requestId: injection, sessionId: injection, ts: 1000, method: injection, url: injection,
    status: 200, operation: injection, tags: [injection], body: injection };
  ui.state.timelineQuery = "img";
  const nodes = [{ sessionId: injection, timelineAvailable: true, index: 1, color: "#123456", requestCount: 1 }];
  const html = ui.renderTimeline({ requests: [request] }, nodes) + ui.renderLogDetail(request) + ui.highlightJson(request);
  assert.doesNotMatch(html, /<img/);
  assert.match(ui.highlightJson({ a: '"<b>"', n: 1, ok: true }), /<span class="j-key">&quot;a&quot;<\/span>: <span class="j-str">&quot;\\&quot;&lt;b&gt;\\&quot;&quot;<\/span>/);
});

test("히스토그램 구간을 고르면 그 시간대 요청만 표시한다", () => {
  const ui = loadPresentation();
  const nodes = [{ sessionId: "s", timelineAvailable: true, index: 1, color: "#123456", requestCount: 3 }];
  const requests = [1000, 5000, 9000].map(ts => ({ requestId: `request:${ts}`, sessionId: "s", ts, method: "GET", url: "/", status: 200 }));
  const all = ui.renderTimeline({ requests }, nodes);
  assert.match(all, /data-hist-from="1000"/);
  ui.state.timelineRange = { from: 4000, to: 6000 };
  const ranged = ui.renderTimeline({ requests }, nodes);
  assert.deepEqual(logKeysInOrder(ranged), ["request:5000"]);
  assert.match(ranged, /id="timelineRangeClear"/);
});

test("로그 필터와 연결 근거의 펼침 상태는 상세 재렌더 뒤에도 유지된다", () => {
  const ui = loadPresentation();
  ui.state.selected = { kind: "resolved-actors", id: "resolved:one" };
  ui.state.userDetail = { requests: [], observedIps: [] };
  const handlers = new Map();
  for (const id of ["logOptionsDisclosure", "evidenceDisclosure"]) {
    ui.document.getElementById(id).addEventListener = (name, handler) => {
      if (name === "toggle") handlers.set(id, handler);
    };
  }
  const disclosure = id => ui.elements.get("userDetail").innerHTML
    .match(new RegExp(`<details[^>]*id="${id}"[^>]*>`))?.[0];
  ui.renderUserDetail();
  assert.equal(handlers.size, 2, "두 펼침 영역 모두 상태 변경을 구독해야 한다");
  for (const id of handlers.keys()) assert.doesNotMatch(disclosure(id), /\bopen\b/);
  for (const handler of handlers.values()) handler({ currentTarget: { open: true } });
  ui.renderUserDetail();
  for (const id of handlers.keys()) assert.match(disclosure(id), /\bopen\b/);
  for (const handler of handlers.values()) handler({ currentTarget: { open: false } });
  ui.renderUserDetail();
  for (const id of handlers.keys()) assert.doesNotMatch(disclosure(id), /\bopen\b/);
});

test("접힌 상세 필터도 선택한 세션·중복·시간 범위를 그대로 적용한다", () => {
  const ui = loadPresentation();
  const request = (id, sessionId, ts) => ({ requestId: id, sessionId, ts, method: "GET", url: "/", status: 200 });
  const requests = [request("old", "s1", 1000), request("a", "s1", 2000),
    request("b", "s1", 3000), request("other", "s2", 3000)];
  const nodes = ["s1", "s2"].map((sessionId, index) =>
    ({ sessionId, index, timelineAvailable: true, requestCount: 2, color: "#123456" }));
  ui.state.timelineSession = "s1";
  ui.state.timelineDedup = true;
  ui.state.timelineRange = { from: 2000, to: 3000 };
  const collapsed = ui.renderTimeline({ requests }, nodes);
  ui.state.logOptionsExpanded = true;
  const expanded = ui.renderTimeline({ requests }, nodes);
  assert.deepEqual(logKeysInOrder(collapsed), ["b"]);
  assert.deepEqual(logKeysInOrder(expanded), ["b"]);
});

test("상세 재렌더는 펼침 버튼의 키보드 포커스와 화면 위치를 유지한다", () => {
  const ui = loadPresentation();
  ui.state.selected = { kind: "resolved-actors", id: "resolved:one" };
  ui.state.userDetail = { requests: [], observedIps: [] };
  for (const id of ["logOptionsSummary", "evidenceSummary"]) {
    ui.document.activeElement = { id };
    let options;
    ui.document.getElementById(id).focus = value => { options = value; };
    ui.renderUserDetail();
    assert.ok(ui.elements.get("userDetail").innerHTML.includes(`<summary id="${id}">`),
      "포커스 복원 대상이 새 DOM에도 있어야 한다");
    assert.equal(options?.preventScroll, true);
  }
});

test("상세 모달은 요청을 먼저 표시하고 모든 계산·이력·연결·특성을 접어서 보존한다", () => {
  const ui = loadPresentation();
  const data = {
    continuityConfirmed: true, totalRequests: 2, automationScore: 0.2, attackScore: 0.1,
    automationBreakdown: { timingRegularity: 0.123 }, attackBreakdown: { csrf: 0.456 },
    honeyBreakdown: { automation: { contributions: { "honey-marker": 7 } } },
    attackHistory: { attackCategories: ["attack-marker"] },
    deceptionHistory: { distinctSignals: ["deception-marker"] },
    memberships: [{ sessionId: "session:member", reasonCodes: ["connection-marker"] }],
    features: { temporal: { avgIntervalMs: 111 }, behavior: { recentSequence: ["sequence-marker"] },
      exploration: { marker: "exploration-marker" }, client: { marker: "client-marker" },
      deception: { marker: "honey-feature-marker" }, attack: { marker: "attack-feature-marker" } },
    agenticEvidence: { marker: "agentic-marker" },
    requests: [{ requestId: "request:one", sessionId: "session:member", ts: 1000, method: "GET", url: "/", status: 200 }],
  };
  const html = ui.renderModalDetail(data, "resolved-actors", "resolved:one");
  const disclosures = [...html.matchAll(/<details class="modal-disclosure"[^>]*>/g)].map(match => match[0]);
  assert.equal(disclosures.length, 4);
  for (const disclosure of disclosures) assert.doesNotMatch(disclosure, /\bopen\b/);
  assert.ok(html.indexOf('data-log-key="request:one"') < html.indexOf('id="modalScores"'));
  for (const marker of ["honey-marker", "attack-marker", "deception-marker", "connection-marker",
    "sequence-marker", "exploration-marker", "client-marker", "honey-feature-marker",
    "attack-feature-marker", "agentic-marker"]) assert.ok(html.includes(marker), marker);
  assert.match(html, /0\.12/);
  assert.match(html, /0\.46/);
  assert.match(html, /111\.00/);
  assert.match(html, /id="modalJsonButton"/);
});

test("모달 요약은 현재 점수와 과거 최고를 구분하며 IP에는 점수를 넣지 않는다", () => {
  const ui = loadPresentation();
  const data = { totalRequests: 19, automationScore: 0.4, attackScore: 0.1,
    attackHistory: { maxAttackScore: 0.9 }, sessionCount: 3, actorCandidateCount: 2, requests: [] };
  const actorHtml = ui.renderModalDetail(data, "resolved-actors", "resolved:one");
  const summary = actorHtml.split('id="modalRequests"')[0];
  const values = [...summary.matchAll(/<dd><b>([\d.]+)/g)].map(match => Number(match[1]));
  assert.deepEqual(values, [19, 0, 40, 10], "현재 공격 점수 자리에 과거 최고 점수를 넣지 않는다");
  assert.match(summary, /class="badge danger"/, "과거 고점의 신호는 별도 표시한다");
  const ipHtml = ui.renderModalDetail(data, "ip-entries", "127.0.0.1");
  assert.doesNotMatch(ipHtml, /id="modalScores"|id="modalHistory"|modal-findings|score-grid/);
  const ipValues = [...ipHtml.split('id="modalRequests"')[0].matchAll(/<dd><b>([\d.]+)/g)].map(match => Number(match[1]));
  assert.deepEqual(ipValues, [19, 0, 3, 2]);
});

test("후보 흐름의 지문 연결과 모달 입력값은 누락하거나 HTML로 해석하지 않는다", () => {
  const ui = loadPresentation();
  const unsafe = '<img src=x onerror="alert(1)">';
  const data = { clientFlow: { links: [{ score: 74, decision: unsafe, reason: "fingerprint-marker",
    fromCandidateId: "actor:from", toCandidateId: "actor:to" }] },
    features: { behavior: { recentSequence: [unsafe] } }, requests: [] };
  for (const kind of ["actors", "client-flows", "sessions", "auth-groups", "ip-entries"]) {
    const html = ui.renderModalDetail(data, kind, unsafe);
    assert.match(html, /id="modalConnections"/);
    assert.match(html, /fingerprint-marker/);
    assert.doesNotMatch(html, /<img/);
    assert.match(html, /&lt;img/);
  }
});

test("모달 키보드 순환은 닫힌 details의 컨트롤을 제외하고 summary는 유지한다", () => {
  const ui = loadPresentation();
  const dashboard = fs.readFileSync(path.join(__dirname, "../public/dashboard.html"), "utf8");
  const script = dashboard.match(/<script>([\s\S]*?)<\/script>/)[1];
  let keydown;
  ui.document.addEventListener = (name, handler) => { if (name === "keydown") keydown = handler; };
  vm.runInContext(script.slice(script.indexOf("document.addEventListener('keydown', event => {"),
    script.indexOf("document.getElementById('themeToggle').addEventListener")), ui.context);
  assert.equal(typeof keydown, "function");
  ui.state.modalOpen = true;
  const modal = { id: "modal" };
  const details = { tagName: "DETAILS", open: false, parentElement: modal };
  const close = { parentElement: modal };
  const summary = { parentElement: details };
  const json = { parentElement: details };
  details.firstElementChild = summary;
  for (const control of [close, summary, json]) {
    // Chrome can report a rectangle for a control in closed details, even though it cannot receive focus.
    control.getClientRects = () => [{}];
    control.focus = () => { ui.document.activeElement = control; };
  }
  ui.document.getElementById("modal").querySelectorAll = () => [close, summary, json];
  for (const open of [false, true]) {
    details.open = open;
    ui.document.activeElement = close;
    let prevented = false;
    keydown({ key: "Tab", shiftKey: true, preventDefault: () => { prevented = true; } });
    assert.equal(prevented, true);
    assert.equal(ui.document.activeElement, open ? json : summary);
    keydown({ key: "Tab", shiftKey: false, preventDefault: () => {} });
    assert.equal(ui.document.activeElement, close);
  }
});

test("해시 화면 전환을 요청 사이에 시간순으로 끼워 넣고 요청과 구분해 표시한다", () => {
  const ui = loadPresentation();
  const nodes = [{ sessionId: "session:one", timelineAvailable: true, index: 1,
    color: "#123456", requestCount: 2 }];
  const detail = {
    requests: [
      { requestId: "request:first", sessionId: "session:one", ts: 1000,
        method: "GET", url: "/", status: 200 },
      { requestId: "request:last", sessionId: "session:one", ts: 3000,
        method: "GET", url: "/rest/products", status: 200 },
    ],
    features: { client: { browserInteraction: { routeHistory: [
      { url: "/#/administration", at: 2000, sessionId: "session:one", reported: true },
    ] } } },
  };

  const html = ui.renderTimeline(detail, nodes);
  assert.match(html, /화면 이동/);
  assert.match(html, /#\/administration/);
  assert.match(html, /tag route"[^>]*title="[^"]*위조[^"]*"/, "클라이언트 보고값이라는 설명은 태그 툴팁에 남긴다");
  // 최신순이므로 3000 → 2000 → 1000 순서로 놓인다.
  assert.ok(
    html.indexOf("request:last") < html.indexOf("#/administration")
      && html.indexOf("#/administration") < html.indexOf("request:first"),
    "화면 이동이 두 요청 사이 시각에 놓인다"
  );

  ui.state.timelineFlaggedOnly = true;
  assert.doesNotMatch(ui.renderTimeline(detail, nodes), /#\/administration/,
    "신호 있는 요청만 보기에서는 화면 이동을 섞지 않는다");
  ui.state.timelineFlaggedOnly = false;

  ui.state.timelineSession = "session:other";
  assert.doesNotMatch(ui.renderTimeline(detail, nodes), /#\/administration/,
    "다른 세션을 고르면 그 세션이 보고한 이동만 남는다");
  ui.state.timelineSession = "all";
});

test("화면 이동 기록의 주소는 HTML로 해석하지 않는다", () => {
  const ui = loadPresentation();
  const nodes = [{ sessionId: "session:one", timelineAvailable: true, index: 1,
    color: "#123456", requestCount: 1 }];
  const detail = {
    requests: [{ requestId: "request:one", sessionId: "session:one", ts: 1000,
      method: "GET", url: "/", status: 200 }],
    features: { client: { browserInteraction: { routeHistory: [
      { url: "/#/<img src=x onerror=alert(1)>", at: 1500, sessionId: "session:one" },
    ] } } },
  };
  const html = ui.renderTimeline(detail, nodes);
  assert.doesNotMatch(html, /<img src=x/);
  assert.match(html, /&lt;img src=x/);
});
