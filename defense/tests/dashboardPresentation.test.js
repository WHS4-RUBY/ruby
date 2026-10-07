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
    `${script.slice(0, bootstrapAt)}\nglobalThis.dashboard = { state, formatScore, hasClientId, indexRequests, groupRequests, renderRequestCard, renderRequests };`,
    context
  );
  return { ...context.dashboard, elements };
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
  ui.state.groupOpen.set(groups[1].key, true);
  ui.renderRequests();
  assert.match(ui.elements.get("requestMeta").textContent, /정책 키 없음 2건/);
  ui.state.requests.unshift({ id: "event-new", clientId: "unknown", requestId: "request-new", timestamp: 5 });
  ui.renderRequests();
  assert.equal(ui.state.groupOpen.get(groups[1].key), true, "새 기록이 앞에 와도 기존 펼침 키를 유지한다");
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

test("요청 경로와 식별자, 전략 이름을 HTML로 해석하지 않는다", () => {
  const ui = loadDashboard();
  const injection = '<img src=x onerror="alert(1)">';
  const card = ui.renderRequestCard({
    requestId: injection,
    path: injection,
    method: "GET",
    status: 200,
    strategies: [injection],
    policySource: injection,
    targetId: injection,
    runId: injection,
    decoyAction: injection,
    outcome: "forwarded",
  });
  assert.doesNotMatch(card, /<img/);
  assert.match(card, /&lt;img/);
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
    const card = ui.renderRequestCard(event);
    assert.match(card, new RegExp(`<span class="badge mono">${label}</span>`), "WebSocket 결과에는 HTTP 상태 색을 붙이지 않는다");
    assert.doesNotMatch(card, /HTTP \d+/);
  }
  assert.match(ui.renderRequestCard({ method: "GET", status: 502, outcome: "error" }), /HTTP 502/);
});

test("정책 점수를 올림 표시해 방어 경계값을 잘못 암시하지 않는다", () => {
  const ui = loadDashboard();
  assert.equal(ui.formatScore(0.796), "79.6");
  assert.equal(ui.formatScore(0.799999), "79.99");
  assert.equal(ui.formatScore(0.8), "80");
});

test("요청 행은 결과별 색 막대와 메서드·상태 색을 붙이고 검색한 요청 ID를 강조한다", () => {
  const ui = loadDashboard();
  const blocked = ui.renderRequestCard({ requestId: "request:a", method: "POST", path: "/login", status: 429, outcome: "blocked", strategies: ["rate_limit_strict"] });
  assert.match(blocked, /class="request-card sev-blocked"/);
  assert.match(blocked, /class="method-badge m-post">POST</);
  assert.match(blocked, /class="badge mono s-4xx">HTTP 429</);
  const defended = ui.renderRequestCard({ requestId: "request:b", method: "GET", status: 200, outcome: "forwarded", strategies: ["delay"] }, "request:b");
  assert.match(defended, /class="request-card sev-defended highlight"/);
  const plain = ui.renderRequestCard({ requestId: "request:c", method: "GET", status: 200, outcome: "forwarded", strategies: [] }, "request:b");
  assert.match(plain, /class="request-card sev-forwarded"/);
});
