const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function loadDashboard(fetchImpl = async () => ({ ok: true, json: async () => ({}) })) {
  const html = fs.readFileSync(path.join(__dirname, "../app/public/dashboard.html"), "utf8");
  const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
  assert.ok(script);
  const bootstrapAt = script.indexOf("document.getElementById('themeToggle').addEventListener");
  assert.ok(bootstrapAt > 0);
  const elements = new Map();
  const document = {
    activeElement: null,
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, {
        value: "",
        innerHTML: "",
        textContent: "",
        contains: () => false,
        querySelectorAll: () => [],
      });
      return elements.get(id);
    },
  };
  const context = vm.createContext({ document, window: {}, navigator: {}, fetch: fetchImpl });
  vm.runInContext(
    `${script.slice(0, bootstrapAt)}\nglobalThis.dashboard = { state, formatScore, hasClientId, indexRequests, groupRequests, renderRequestRow, renderRequests };`,
    context
  );
  return { ...context.dashboard, elements, document };
}

test("유효한 정책 키만 묶고 unknown 기록은 백엔드 기록 ID별로 분리한다", () => {
  const ui = loadDashboard();
  const events = [
    { id: "event-a", clientId: "unknown", requestId: "request-a", timestamp: 4 },
    { id: "event-b", clientId: "unknown", requestId: "request-b", timestamp: 3 },
    { id: "event-c", clientId: "resolved:one", requestId: "request-c", timestamp: 2 },
    { id: "event-d", clientId: "resolved:one", requestId: "request-d", timestamp: 1 },
  ];
  const groups = ui.groupRequests(ui.indexRequests(events));
  assert.equal(groups.length, 3);
  assert.equal(groups.filter(group => group.missingClientId).length, 2);
  assert.equal(groups.find(group => !group.missingClientId).events.length, 2);
  assert.notEqual(groups[0].key, groups[1].key);

  ui.state.requests = events;
  ui.state.selectedKey = groups[1].key;
  ui.renderRequests();
  assert.match(ui.elements.get("requestMeta").textContent, /정책 키 없음 2건/);
  ui.state.requests.unshift({ id: "event-new", clientId: "unknown", requestId: "request-new", timestamp: 5 });
  ui.renderRequests();
  assert.equal(ui.state.selectedKey, groups[1].key, "새 기록이 앞에 와도 선택한 정책 클라이언트를 유지한다");
});

test("탐지 기준(연결된 흐름 · 단독 관찰)으로 묶고, 흐름 연결 전 요청과 합쳐진 흐름도 한 그룹에 둔다", () => {
  const ui = loadDashboard();
  // 최신순. c1은 첫 요청 때 흐름 연결 전이었고, f-old는 이후 f-new로 합쳐졌다.
  const events = [
    { id: "4", clientId: "dcid:4", candidateId: "actor:c2", clientFlowId: "client-flow:new", timestamp: 4 },
    { id: "3", clientId: "dcid:3", candidateId: "actor:c1", clientFlowId: "client-flow:new", timestamp: 3 },
    { id: "2", clientId: "dcid:2", candidateId: "actor:c1", clientFlowId: "client-flow:old", timestamp: 2 },
    { id: "1", clientId: "dcid:1", candidateId: "actor:c1", timestamp: 1 },
    { id: "5", clientId: "dcid:5", candidateId: "actor:alone", timestamp: 5 },
    { id: "6", clientId: "resolved:legacy", timestamp: 6 },
  ];
  const groups = ui.groupRequests(ui.indexRequests(events));
  assert.deepEqual(Array.from(groups, group => [group.flowType, group.label, group.events.length]), [
    ["linked", "client-flow:new", 4],
    ["standalone", "actor:alone", 1],
    ["unlinked", "resolved:legacy", 1],
  ]);

  ui.state.requests = events;
  ui.renderRequests();
  assert.equal(ui.state.selectedKey, JSON.stringify(["flow", "client-flow:new"]));
  const meta = ui.elements.get("requestMeta").textContent;
  assert.match(meta, /연결된 흐름 1개 · 단독 관찰 1개 · 흐름 정보 없음 1개 · 정책 키 6개/);
  const list = ui.elements.get("requestGroups").innerHTML;
  assert.match(list, /<span class="badge flow"[^>]*>연결된 흐름<\/span>/);
  assert.match(list, /후보 2개 · <span class="split-warn">정책 키 4개로 나뉨<\/span>/);
  assert.match(list, /<span class="badge neutral"[^>]*>단독 관찰<\/span>/);
  const detail = ui.elements.get("groupDetail").innerHTML;
  assert.match(detail, /정책 키 4개로 나뉘었습니다/, "같은 흐름의 방어 상태가 나뉜 것을 상세에서 알린다");
  assert.match(detail, /data-copy="actor:c1"/);
  assert.match(detail, /data-copy="dcid:4"/);
});

test("흐름 필터는 종류별 건수를 보여 주고, 가려진 요청을 ID로 검색하면 필터를 푼다", () => {
  const ui = loadDashboard();
  ui.state.requests = [
    { id: "a", clientId: "dcid:a", candidateId: "actor:a", clientFlowId: "client-flow:a", requestId: "req-a", timestamp: 2 },
    { id: "b", clientId: "dcid:b", candidateId: "actor:b", requestId: "req-b", timestamp: 1 },
  ];
  ui.state.flowFilter = "standalone";
  ui.renderRequests();
  assert.equal(ui.state.selectedKey, JSON.stringify(["candidate", "actor:b"]));
  const chips = ui.elements.get("flowFilters").innerHTML;
  assert.match(chips, /data-flow-filter="linked" aria-pressed="false">연결된 흐름 <span class="chip-count">1<\/span>/);
  assert.match(chips, /data-flow-filter="standalone" aria-pressed="true">단독 관찰 <span class="chip-count">1<\/span>/);
  assert.doesNotMatch(chips, /흐름 정보 없음/, "후보 정보가 없는 기록이 없으면 칩을 숨긴다");
  assert.doesNotMatch(ui.elements.get("requestGroups").innerHTML, /client-flow:a/);

  ui.document.getElementById("requestSearch").value = "req-a";
  ui.renderRequests();
  assert.equal(ui.state.flowFilter, "all");
  assert.equal(ui.state.selectedKey, JSON.stringify(["flow", "client-flow:a"]));
  assert.ok(ui.state.expanded.has("event:a"));
});

test("정책 키가 없는 중복 요청 ID도 서로 다른 기록으로 표시한다", () => {
  const ui = loadDashboard();
  const events = [
    { clientId: "", requestId: "same" },
    { clientId: null, requestId: "same" },
    { clientId: " ", requestId: null },
  ];
  assert.equal(ui.groupRequests(ui.indexRequests(events)).length, 3);
});

test("흐름 정보가 없는 기록은 정책 키로 묶고, 선택한 그룹의 요청만 상세에 표시한다", () => {
  const ui = loadDashboard();
  ui.state.requests = [
    { id: "a1", clientId: "client:a", requestId: "req-a1", path: "/a", method: "GET", status: 200, outcome: "forwarded", timestamp: 3 },
    { id: "b1", clientId: "client:b", requestId: "req-b1", path: "/b", method: "GET", status: 200, outcome: "forwarded", timestamp: 2 },
  ];
  ui.renderRequests();
  const firstKey = ui.state.selectedKey;
  assert.equal(firstKey, JSON.stringify(["client", "client:a"]));
  let detail = ui.elements.get("groupDetail").innerHTML;
  assert.match(detail, /data-row-key="event:a1"/);
  assert.doesNotMatch(detail, /data-row-key="event:b1"/);

  ui.state.selectedKey = JSON.stringify(["client", "client:b"]);
  ui.renderRequests();
  detail = ui.elements.get("groupDetail").innerHTML;
  assert.match(detail, /data-row-key="event:b1"/);
  assert.match(ui.elements.get("requestGroups").innerHTML, /class="user-card selected" data-group-key="\[&quot;client&quot;,&quot;client:b&quot;\]"/);

  ui.state.requests = ui.state.requests.slice(0, 1);
  ui.renderRequests();
  assert.equal(ui.state.selectedKey, firstKey);
});

test("결과 필터는 방어 적용·차단·오류 요청만 남기고 건수를 칩에 표시한다", () => {
  const ui = loadDashboard();
  ui.state.requests = [
    { id: "1", clientId: "c", outcome: "forwarded", strategies: [] },
    { id: "2", clientId: "c", outcome: "forwarded", strategies: ["delay"] },
    { id: "3", clientId: "c", outcome: "blocked", strategies: ["rate_limit_strict"] },
    { id: "4", clientId: "c", outcome: "error", strategies: [] },
  ];
  ui.state.outcomeFilter = "defended";
  ui.renderRequests();
  assert.match(ui.elements.get("requestMeta").textContent, /최근 4건 중 2건/);
  assert.match(ui.elements.get("outcomeFilters").innerHTML, /data-outcome-filter="defended" aria-pressed="true">방어 적용 <span class="chip-count">2<\/span>/);
  ui.state.outcomeFilter = "blocked";
  ui.renderRequests();
  assert.match(ui.elements.get("requestMeta").textContent, /최근 4건 중 2건/);
  assert.doesNotMatch(ui.elements.get("groupDetail").innerHTML, /data-row-key="event:1"/);
});

test("요청 ID를 그대로 검색하면(?q=) 해당 그룹을 고르고 요청을 한 번 펼친다", () => {
  const ui = loadDashboard();
  ui.state.requests = [
    { id: "a1", clientId: "client:a", requestId: "req-a1", path: "/a", outcome: "forwarded", timestamp: 3 },
    { id: "b1", clientId: "client:b", requestId: "REQ-B1", path: "/b", outcome: "forwarded", timestamp: 2 },
  ];
  const search = ui.document.getElementById("requestSearch");
  search.value = "req-b1";
  ui.renderRequests();
  assert.equal(ui.state.selectedKey, JSON.stringify(["client", "client:b"]));
  assert.ok(ui.state.expanded.has("event:b1"));
  assert.match(ui.elements.get("groupDetail").innerHTML, /class="log-entry sev-forwarded highlight expanded"/);

  ui.state.expanded.delete("event:b1");
  ui.renderRequests();
  assert.ok(!ui.state.expanded.has("event:b1"), "사용자가 접은 행을 갱신마다 다시 펼치지 않는다");
});

test("요청 경로와 식별자, 전략 이름을 HTML로 해석하지 않는다", () => {
  const ui = loadDashboard();
  const injection = '<img src=x onerror="alert(1)">';
  const event = {
    id: injection,
    requestId: injection,
    path: injection,
    method: injection,
    status: injection,
    strategies: [injection],
    policySource: injection,
    defenseSignal: injection,
    targetId: injection,
    runId: injection,
    decoyAction: injection,
    outcome: "forwarded",
  };
  for (const row of [ui.renderRequestRow(event), ui.renderRequestRow(event, { key: injection, query: "img", expanded: true })]) {
    assert.doesNotMatch(row, /<img/);
    assert.match(row, /&lt;img/);
  }
  ui.state.requests = [{ ...event, clientId: injection, candidateId: injection, clientFlowId: injection }];
  ui.renderRequests();
  assert.doesNotMatch(ui.elements.get("requestGroups").innerHTML, /<img/);
  assert.doesNotMatch(ui.elements.get("groupDetail").innerHTML, /<img/);
  ui.state.expanded.add(ui.indexRequests(ui.state.requests)[0].rowKey);
  ui.renderRequests();
  assert.doesNotMatch(ui.elements.get("groupDetail").innerHTML, /<img/);
  assert.match(ui.elements.get("groupDetail").innerHTML, /요청 당시 흐름/);
});

test("WebSocket 업그레이드와 연결 결과를 HTTP 응답으로 표시하지 않는다", () => {
  const ui = loadDashboard();
  const cases = [
    [{ method: "WEBSOCKET", status: 403, outcome: "blocked" }, "WS 업그레이드 차단"],
    [{ method: "WEBSOCKET", status: 502, outcome: "error" }, "WS 업그레이드 오류"],
    [{ method: "WEBSOCKET", status: 101, outcome: "forwarded" }, "WS 연결 종료"],
    [{ method: "WEBSOCKET", status: 101, outcome: "error" }, "WS 연결 중 오류"],
  ];
  for (const [event, label] of cases) {
    const row = ui.renderRequestRow(event, { expanded: true });
    assert.match(row, new RegExp(`<span class="tag muted">${label}</span>`));
    assert.match(row, new RegExp(`<span class="status-code">${event.status}</span>`), "WebSocket 결과에는 HTTP 상태 색을 붙이지 않는다");
    assert.doesNotMatch(row, /HTTP \d+/);
  }
  assert.match(ui.renderRequestRow({ method: "GET", status: 502, outcome: "error" }, { expanded: true }), /HTTP 502/);
});

test("정책 점수를 올림 표시해 방어 경계값을 잘못 암시하지 않는다", () => {
  const ui = loadDashboard();
  assert.equal(ui.formatScore(0.796), "79.6");
  assert.equal(ui.formatScore(0.799999), "79.99");
  assert.equal(ui.formatScore(0.8), "80");
});

test("요청 행은 결과별 막대·글자 태그와 메서드·상태 색을 붙이고 검색한 요청 ID를 강조한다", () => {
  const ui = loadDashboard();
  const blocked = ui.renderRequestRow({ requestId: "request:a", method: "POST", path: "/login", status: 429, outcome: "blocked", strategies: ["rate_limit_strict"] });
  assert.match(blocked, /class="log-entry sev-blocked"/);
  assert.match(blocked, /class="method-badge m-post">POST</);
  assert.match(blocked, /class="status-code s-4xx">429</);
  assert.match(blocked, /<span class="tag">차단<\/span>/, "색만이 아니라 글자로도 결과를 알린다");
  assert.match(blocked, /<span class="tag action"[^>]*>엄격 속도 제한<\/span>/);
  const defended = ui.renderRequestRow({ requestId: "request:b", method: "GET", status: 200, outcome: "forwarded", strategies: ["delay"] }, { query: "request:b" });
  assert.match(defended, /class="log-entry sev-defended highlight"/);
  const plain = ui.renderRequestRow({ requestId: "request:c", method: "GET", status: 200, outcome: "forwarded", strategies: [] }, { query: "request:b" });
  assert.match(plain, /class="log-entry sev-forwarded"/);
});
