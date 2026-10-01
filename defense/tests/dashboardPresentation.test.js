const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function loadDashboard(fetchImpl = async () => ({ ok: true, json: async () => ({ publicPath: "/juice-shop/" }) })) {
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
    `${script.slice(0, bootstrapAt)}\nglobalThis.dashboard = { state, formatScore, loadTarget, hasClientId, indexRequests, groupRequests, renderRequestCard, renderRequests };`,
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
    outcome: "forwarded",
  });
  assert.doesNotMatch(card, /<img/);
  assert.match(card, /&lt;img/);
});

test("정책 점수를 올림 표시해 방어 경계값을 잘못 암시하지 않는다", () => {
  const ui = loadDashboard();
  assert.equal(ui.formatScore(0.796), "79.6");
  assert.equal(ui.formatScore(0.799999), "79.99");
  assert.equal(ui.formatScore(0.8), "80");
});

test("열린 방어 화면에서 대상 전환 시 공개 경로 링크를 바꾼다", async () => {
  let publicPath = "/juice-shop/";
  const ui = loadDashboard(async () => ({ ok: true, json: async () => ({ publicPath }) }));
  await ui.loadTarget();
  assert.equal(ui.elements.get("targetLink").href, "/juice-shop/");
  publicPath = "/ruby-market/";
  await ui.loadTarget();
  assert.equal(ui.elements.get("targetLink").href, "/ruby-market/");
  publicPath = "/__defense/";
  await ui.loadTarget();
  assert.equal(ui.elements.get("targetLink").hidden, true);
  assert.equal(ui.elements.get("targetUnavailable").textContent, "경로 확인 불가");
});
