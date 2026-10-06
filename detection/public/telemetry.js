(function () {
  var mouseMoveCount = 0;
  var scrollCount = 0;
  var routeChangeCount = 0;
  var domEventTypes = new Set();
  var pageLoadPending = true;
  var currentUrl = getCurrentUrl();
  // 전송 주기(5초) 안에 여러 번 이동하면 마지막 주소만 남으므로, 거쳐 간 화면을
  // 따로 모아 보낸다. 한 전송에 담을 수 있는 수를 제한해 길이를 묶는다.
  var MAX_ROUTES_PER_BATCH = 50;
  var routes = [{ url: currentUrl, at: Date.now() }];
  var TRACKED_EVENTS = [
    "click",
    "keydown",
    "keyup",
    "focus",
    "blur",
    "touchstart",
    "submit",
    "input",
  ];

  window.addEventListener("mousemove", function () {
    mouseMoveCount++;
  }, { passive: true });

  // scroll 이벤트는 버블링되지 않으므로 capture 단계에서 내부 스크롤 요소까지 관찰한다.
  document.addEventListener("scroll", function () {
    scrollCount++;
  }, { passive: true, capture: true });

  TRACKED_EVENTS.forEach(function (evt) {
    window.addEventListener(evt, function () {
      domEventTypes.add(evt);
    }, { passive: true, capture: true });
  });

  function getCurrentUrl() {
    return window.location.pathname + window.location.search + window.location.hash;
  }

  function handleRouteChange() {
    var nextUrl = getCurrentUrl();
    // hashchange와 popstate가 같은 이동에서 함께 발생해도 한 번만 센다.
    if (nextUrl === currentUrl) return;
    currentUrl = nextUrl;
    routeChangeCount++;
    if (routes.length < MAX_ROUTES_PER_BATCH) routes.push({ url: nextUrl, at: Date.now() });
  }

  function instrumentHistoryMethod(methodName) {
    var original = window.history && window.history[methodName];
    if (typeof original !== "function") return;
    window.history[methodName] = function () {
      var result = original.apply(this, arguments);
      handleRouteChange();
      return result;
    };
  }

  instrumentHistoryMethod("pushState");
  instrumentHistoryMethod("replaceState");
  window.addEventListener("popstate", handleRouteChange);
  window.addEventListener("hashchange", handleRouteChange);

  function send(isFinal) {
    var payload = {
      mouseMoveCount: mouseMoveCount,
      scrollCount: scrollCount,
      routeChangeCount: routeChangeCount,
      domEventTypes: Array.from(domEventTypes),
      // 실제 문서가 로드되어 이 스크립트가 실행된 최초 구간에만 true다.
      pageLoad: pageLoadPending,
      url: currentUrl,
      routes: routes,
    };
    // 누적치는 리셋하고 다음 구간을 다시 센다 (서버에서 합산)
    mouseMoveCount = 0;
    scrollCount = 0;
    routeChangeCount = 0;
    domEventTypes = new Set();
    pageLoadPending = false;
    routes = [];

    var body = JSON.stringify(payload);
    if (navigator.sendBeacon) {
      navigator.sendBeacon(
        "/__detection/telemetry",
        new Blob([body], { type: "application/json" })
      );
    } else {
      fetch("/__detection/telemetry", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: body,
        keepalive: true,
      }).catch(function () {});
    }
  }

  // 5초마다 주기적으로 전송 + 페이지 이탈 시 마지막 전송
  setInterval(function () { send(false); }, 5000);
  window.addEventListener("beforeunload", function () { send(true); });
})();
