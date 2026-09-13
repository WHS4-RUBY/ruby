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

  assert.deepEqual(await payloadAt(runtime.beacons, 0), {
    mouseMoveCount: 0,
    scrollCount: 1,
    routeChangeCount: 0,
    domEventTypes: [],
    pageLoad: true,
    url: "/#/",
  });
  assert.equal((await payloadAt(runtime.beacons, 1)).pageLoad, false);
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
  });
  store.recordTelemetry(sessionId, "127.0.0.1", {
    routeChangeCount: 2,
    pageLoad: false,
    url: "/#/basket",
  });

  const interaction = extractFeatures(store.getSession(sessionId)).client.browserInteraction;
  assert.equal(interaction.pageLoads, 1);
  assert.equal(interaction.routeChangeCount, 3);
  assert.equal(interaction.currentUrl, "/#/basket");
  assert.equal(interaction.scrollCount, 2);
});
