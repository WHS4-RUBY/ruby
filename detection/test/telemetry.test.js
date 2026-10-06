const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const { extractFeatures } = require("../lib/featureExtractor");
const store = require("../lib/sessionStore");

const telemetrySource = fs.readFileSync(
  path.join(__dirname, "..", "public", "telemetry.js"),
  "utf8"
);

function createEventTarget() {
  const listeners = new Map();
  return {
    addEventListener(type, listener, options) {
      listeners.set(type, { listener, options });
    },
    dispatch(type) {
      const entry = listeners.get(type);
      if (entry) entry.listener({ type });
    },
    listener(type) {
      return listeners.get(type);
    },
  };
}

function runTelemetry() {
  const windowEvents = createEventTarget();
  const documentEvents = createEventTarget();
  const beacons = [];
  let intervalCallback;

  const location = { pathname: "/", search: "", hash: "#/" };
  const history = {
    pushState(_state, _title, url) {
      location.hash = url.startsWith("#") ? url : "";
      location.pathname = url.startsWith("#") ? location.pathname : url;
    },
    replaceState(_state, _title, url) {
      this.pushState(_state, _title, url);
    },
  };
  const window = {
    ...windowEvents,
    location,
    history,
  };
  const document = { ...documentEvents };
  const navigator = {
    sendBeacon(url, body) {
      beacons.push({ url, body });
      return true;
    },
  };

  vm.runInNewContext(telemetrySource, {
    Blob,
    document,
    fetch: async () => {},
    navigator,
    setInterval(callback) {
      intervalCallback = callback;
    },
    window,
  });

  return { beacons, document, interval: () => intervalCallback(), window };
}

async function payloadAt(beacons, index) {
  return JSON.parse(await beacons[index].body.text());
}

test("pageLoad는 최초 전송에만 포함되고 내부 요소 scroll을 집계한다", async () => {
  const runtime = runTelemetry();
  const scrollListener = runtime.document.listener("scroll");
  assert.equal(scrollListener.options.passive, true);
  assert.equal(scrollListener.options.capture, true);

  runtime.document.dispatch("scroll");
  runtime.interval();
  runtime.interval();

  const first = await payloadAt(runtime.beacons, 0);
  assert.deepEqual({ ...first, routes: undefined }, {
    mouseMoveCount: 0,
    scrollCount: 1,
    routeChangeCount: 0,
    domEventTypes: [],
    pageLoad: true,
    url: "/#/",
    routes: undefined,
  });
  // 최초 전송에는 문서가 열린 화면 하나만 담기고, 다음 구간에서는 비워진다.
  assert.deepEqual(first.routes.map((entry) => entry.url), ["/#/"]);
  const second = await payloadAt(runtime.beacons, 1);
  assert.equal(second.pageLoad, false);
  assert.deepEqual(second.routes, []);
});

test("hash, History API, 뒤로 가기 전환을 URL 중복 없이 집계한다", async () => {
  const runtime = runTelemetry();

  runtime.window.location.hash = "#/login";
  runtime.window.dispatch("hashchange");
  runtime.window.dispatch("popstate");
  runtime.window.history.pushState({}, "", "#/basket");
  runtime.interval();

  const payload = await payloadAt(runtime.beacons, 0);
  assert.equal(payload.routeChangeCount, 2);
  assert.equal(payload.url, "/#/basket");
  // 전송 주기 안에서 거쳐 간 화면이 순서대로 남는다. 마지막 주소만 보면 /#/login을 놓친다.
  assert.deepEqual(payload.routes.map((entry) => entry.url), ["/#/", "/#/login", "/#/basket"]);
});

test("서버가 page load와 SPA route change를 분리해 Feature로 노출한다", () => {
  const sessionId = `telemetry-test-${Date.now()}`;
  store.recordTelemetry(sessionId, "127.0.0.1", {
    mouseMoveCount: 3,
    scrollCount: 2,
    routeChangeCount: 1,
    domEventTypes: ["click"],
    pageLoad: true,
    url: "/#/login",
    routes: [{ url: "/#/", at: 1 }, { url: "/#/login", at: 2 }],
  });
  store.recordTelemetry(sessionId, "127.0.0.1", {
    routeChangeCount: 2,
    pageLoad: false,
    url: "/#/basket",
    routes: [{ url: "/#/administration", at: 3 }, { url: "/#/basket", at: 4 }],
  });

  const interaction = extractFeatures(store.getSession(sessionId)).client.browserInteraction;
  assert.equal(interaction.pageLoads, 1);
  assert.equal(interaction.routeChangeCount, 3);
  assert.equal(interaction.currentUrl, "/#/basket");
  assert.equal(interaction.scrollCount, 2);
  // 서버가 본 요청 경로에는 남지 않는 해시 화면까지 순서대로 보인다.
  assert.deepEqual(interaction.routeHistory.map((entry) => entry.url), [
    "/#/", "/#/login", "/#/administration", "/#/basket",
  ]);
});
