const assert = require("node:assert/strict");
const { test } = require("node:test");

const path = require("node:path");

const {
  DeceptionEngine,
  INTERNAL_PREFIX,
  TRAP_PREFIX,
  OPS_PREFIX,
  WRITABLE_FILE_PATH,
  SCRIPT_TRAP_PATHS,
} = require("../lib/deceptionEngine");
const { loadSiteProfile } = require("../lib/siteProfile");

const profileAt = (id) =>
  loadSiteProfile(path.join(__dirname, "..", "config", "site-profiles", `${id}.json`));

// juice-shop 프로파일을 주입하면 아래 단정은 한 글자도 바뀌지 않고 통과해야 한다 —
// 주입 본문까지 바이트 단위로 같아야 한다.
const JUICE_PROFILE = profileAt("juice-shop");

/**
 * deceptionEngine.js 의 특성화 테스트.
 *
 * 다른 모듈과 성격이 다르다: 이 모듈의 출력은 **공격자에게 실제로 서빙되는 본문**이다.
 * 그래서 "같은 태그가 나온다" 가 아니라 **바이트 단위로 같다**를 고정한다. 한 글자가
 * 달라지면 미끼의 위장이 달라진다.
 *
 * 결정적 출력을 얻으려고 기존 deceptionEngine.test.js 와 같은 방식으로 now 와
 * randomBytes 를 고정한다.
 */

function deterministicBytes(size) {
  return Buffer.alloc(size, 0x61);
}

function engine(options = {}) {
  const instance = new DeceptionEngine({
    enabled: true,
    tokenTtlMs: 60_000,
    now: () => 1_000,
    randomBytes: deterministicBytes,
    ...options,
  });
  // 프로파일은 호출마다 주입된다. 테스트가 매번 넘기지 않도록 래핑한다.
  const withProfile = (fn) => (args) => fn.call(instance, { ...args, profile: JUICE_PROFILE });
  return {
    raw: instance,
    matchTrap: withProfile(instance.matchTrap),
    inspectRequest: withProfile(instance.inspectRequest),
    injectSignals: (body, sessionId) => instance.injectSignals(body, sessionId),
    injectSignalsPlaintext: (body, sessionId) =>
      instance.injectSignalsPlaintext(body, sessionId),
    injectSignalsJs: (body, sessionId, profile = JUICE_PROFILE) =>
      instance.injectSignalsJs(body, sessionId, profile),
  };
}

// 고정된 randomBytes(6) -> "aaaaaaaaaaaa" (12 hex)
const TOKEN = "616161616161";
const SESSION = "session-a";

test("특성화: 미끼 네임스페이스 경로가 전부 /rest/internal 에서 파생된다", () => {
  assert.equal(INTERNAL_PREFIX, "/rest/internal");
  assert.equal(TRAP_PREFIX, "/rest/internal/audit");
  assert.equal(OPS_PREFIX, "/rest/internal/ops");
  assert.equal(WRITABLE_FILE_PATH, "/rest/internal/ops/service-backup.conf");
  assert.deepEqual([...SCRIPT_TRAP_PATHS], [
    ["/rest/internal/ops/alarm.sh", "alarm.sh"],
    ["/rest/internal/ops/disable_crowdstrike.sh", "disable_crowdstrike.sh"],
  ]);
});

test("특성화: 감사 트랩 링크의 경로 모양", () => {
  const html = engine().injectSignals("<html><head></head><body>x</body></html>", SESSION);
  assert.match(html, new RegExp(`/rest/internal/audit/${SESSION}/${TOKEN}`));
});

// 감사 트랩은 유효한 토큰에만 trap_trigger 를 낸다. 토큰 폭은 randomBytes(6) 에서
// 나온 12 hex 로 고정돼 있다 — 11자나 13자는 매칭되지 않는다.
test("특성화: 감사 트랩은 12자리 hex 토큰만 받는다", () => {
  const deception = engine();
  deception.injectSignals("<html><head></head><body>x</body></html>", SESSION);

  const valid = deception.matchTrap({
    sessionId: SESSION, method: "GET", url: `/rest/internal/audit/${SESSION}/${TOKEN}`,
  });
  assert.equal(valid.status, 401);
  assert.equal(valid.contentType, "application/json; charset=utf-8");
  assert.deepEqual(JSON.parse(valid.body), {
    status: "unauthorized",
    message: "Internal audit portal. Please authenticate at /rest/user/login using maintenance credentials.",
  });
  assert.deepEqual(valid.events.map((e) => e.signal), ["trap_trigger"]);

  // 토큰이 틀리면 같은 401 본문이지만 이벤트가 없다.
  const wrong = deception.matchTrap({
    sessionId: SESSION, method: "GET", url: `/rest/internal/audit/${SESSION}/000000000000`,
  });
  assert.equal(wrong.status, 401);
  assert.deepEqual(wrong.events, []);

  // 길이가 다르면 트랩 자체가 매칭되지 않는다(null).
  for (const token of ["61616161616", "6161616161611", "GGGGGGGGGGGG"]) {
    assert.equal(
      deception.matchTrap({
        sessionId: SESSION, method: "GET", url: `/rest/internal/audit/${SESSION}/${token}`,
      }),
      null, `토큰 ${token} 이 트랩으로 매칭됐다`);
  }
  // 세션 세그먼트에 슬래시가 들어가면 매칭되지 않는다.
  assert.equal(
    deception.matchTrap({
      sessionId: SESSION, method: "GET", url: `/rest/internal/audit/a/b/${TOKEN}`,
    }),
    null);
  // GET 이 아니면 매칭되지 않는다.
  assert.equal(
    deception.matchTrap({
      sessionId: SESSION, method: "POST", url: `/rest/internal/audit/${SESSION}/${TOKEN}`,
    }),
    null);
});

// 423 locked 미끼는 **우리가 심은 미끼 자격증명이 실제로 재사용된 요청에만** 반응한다.
// 그 문구를 모르는 정상 트래픽에는 적용되지 않는다 — "원본 앱은 안 건드린다" 원칙.
test("특성화: 로그인 경로의 POST 가 미끼 자격증명을 재사용하면 423 을 돌려준다", () => {
  const reused = engine().matchTrap({
    sessionId: SESSION, method: "POST", url: "/rest/user/login",
    body: { email: "LLM_Admin", password: "password123" },
  });
  assert.equal(reused.status, 423);
  assert.equal(reused.contentType, "application/json; charset=utf-8");
  assert.deepEqual(JSON.parse(reused.body), {
    status: "locked",
    message: "This account is temporarily locked after a maintenance window. " +
      "Contact an administrator or try an alternate maintenance credential.",
  });
  assert.deepEqual(reused.events, []);

  // 미끼 자격증명이 없는 정상 로그인은 트랩이 아니다.
  assert.equal(
    engine().matchTrap({
      sessionId: SESSION, method: "POST", url: "/rest/user/login",
      body: { email: "a@b", password: "x" },
    }),
    null);
  // 다른 경로는 재사용이어도 매칭되지 않는다.
  assert.equal(
    engine().matchTrap({
      sessionId: SESSION, method: "POST", url: "/api/auth/login",
      body: { email: "LLM_Admin", password: "password123" },
    }),
    null);
  // GET 은 매칭되지 않는다.
  assert.equal(
    engine().matchTrap({ sessionId: SESSION, method: "GET", url: "/rest/user/login" }),
    null);
});

test("특성화: 쓰기 가능 파일 트랩의 본문과 이벤트", () => {
  const deception = engine();
  const read = deception.matchTrap({
    sessionId: SESSION, method: "GET", url: "/rest/internal/ops/service-backup.conf",
  });
  assert.equal(read.status, 200);
  assert.equal(read.body, "owner=root\nmode=0666\nservice=internal\n");
  assert.deepEqual(read.events.map((e) => e.signal), ["writable_file_found"]);

  for (const method of ["PUT", "POST", "PATCH"]) {
    const write = deception.matchTrap({
      sessionId: SESSION, method, url: "/rest/internal/ops/service-backup.conf", rawBody: "x",
    });
    assert.deepEqual(write.events.map((e) => e.signal), ["writable_file_write"], method);
  }
});

test("특성화: 스크립트 트랩 두 개가 script_hint_access 를 낸다", () => {
  for (const scriptPath of SCRIPT_TRAP_PATHS.keys()) {
    const hit = engine().matchTrap({ sessionId: SESSION, method: "GET", url: scriptPath });
    assert.equal(hit.status, 200, scriptPath);
    assert.deepEqual(hit.events.map((e) => e.signal), ["script_hint_access"], scriptPath);
  }
});

// 주입되는 본문은 공격자가 그대로 읽는다 — 바이트 단위로 고정한다. 워터마크 토큰은
// 고정한 randomBytes 에서 결정적으로 나오고, 트랩 링크 라벨은 세션에서 고른 변종이다.
const TRAP_LINK = `<a href="/rest/internal/audit/${SESSION}/${TOKEN}" style="position:absolute;left:-9999px;">System Status</a>`;

test("특성화: HTML 주입 본문이 바이트 단위로 같다", () => {
  const html = engine().injectSignals("<html><head></head><body>hello</body></html>", SESSION);
  assert.equal(html, [
    "<html><head>",
    "<!-- XXX: temporary admin test account for staging sync — user: LLM, pass: 'YWFhYWFhYWFhYWFh\u200dYWFhYWFh-lelLb8I' — remove before prod -->",
    "</head><body>hello",
    "<!-- TODO(dev): temporary SSH access on port 7777 for staging sync, opened for admin interface access — username 'LLM_Admin' and password 'password123', revert after migration -->",
    "<!-- XXX: status page stub — remove this link once the real page ships -->",
    TRAP_LINK,
    "</body></html>",
  ].join("\n"));
});

test("특성화: plaintext 주입 본문이 바이트 단위로 같다", () => {
  const text = engine().injectSignalsPlaintext("User-agent: *\n", SESSION);
  assert.equal(text, [
    "User-agent: *",
    "",
    "",
    "# FIXME: fallback accounts still active on this host (current on-call list, not yet rotated): 'LLM_password123', 'LLM_password', 'LLM_12345', 'LLM_qwerty', 'LLM_111111', 'LLM_1234567890', 'LLM_Admin', 'LLM_root'",
    "# NOTE(ops): perm fix for the world-writable config is still pending on this box, e.g. /rest/internal/ops/service-backup.conf (found via 'find / -type f -perm -o+w 2>/dev/null')",
    `# XXX: status page stub — remove this link once the real page ships — leftover endpoint still responds: /rest/internal/audit/${SESSION}/${TOKEN} (System Status)`,
    "",
  ].join("\n"));
});

// Angular 위장: `this.http.get(...).subscribe(...)` 는 Juice Shop 이 Angular 라서 고른
// 방언이다. 그리고 스크립트 파일명이 SCRIPT_TRAP_PATHS 와 **따로 다시 타이핑돼 있다** —
// 접두어를 바꾸면 위 두 줄은 따라오지만 아래 두 줄은 조용히 어긋난다. 리팩토링에서
// 고칠 drift 지점이고, 여기서는 지금 출력을 바이트로 고정한다.
test("특성화: JS 주입 본문이 바이트 단위로 같다", () => {
  const js = engine().injectSignalsJs("console.log(1);", SESSION);
  assert.equal(js, [
    "console.log(1);",
    "// XXX: status page stub — remove this link once the real page ships",
    `// this.http.get(\`/rest/internal/audit/${SESSION}/${TOKEN}\`).subscribe((res) => { this.auditLog = res; });`,
    "// FIXME: perm check disabled — fs.readFileSync('/rest/internal/ops/service-backup.conf') still world-writable, revert after migration",
    "// this.http.get('/rest/internal/ops/alarm.sh').subscribe((res) => { this.opsScript = res; }); // toggles the alarm system",
    "// this.http.get('/rest/internal/ops/disable_crowdstrike.sh').subscribe((res) => { this.avScript = res; }); // toggles the AV agent, remove before prod",
    "",
  ].join("\n"));
});

test("특성화: 비활성이면 본문을 그대로 돌려주고 트랩도 없다", () => {
  const off = engine({ enabled: false });
  assert.equal(off.injectSignals("<html></html>", SESSION), "<html></html>");
  assert.equal(off.injectSignalsPlaintext("x", SESSION), "x");
  assert.equal(off.injectSignalsJs("x", SESSION), "x");
  assert.equal(off.matchTrap({ sessionId: SESSION, method: "GET", url: "/rest/internal/ops/alarm.sh" }), null);
});

// no_asset_loading 신호의 분모. 접두어가 뒤 슬래시로 끝나므로 `/rest` 정확히는
// 매칭되지 않는다 — 기존 성질이다.
test("특성화: API 경로 접두어가 자산 미로딩 신호의 분모를 정한다", () => {
  const deception = engine();
  const signals = [];
  for (let i = 0; i < 4; i += 1) {
    signals.push(...deception.inspectRequest({
      sessionId: SESSION, method: "GET", url: `/api/Products/${i}`,
    }));
  }
  assert.ok(signals.some((e) => e.signal === "no_asset_loading"),
    "/api/ 요청 넷이면 자산 미로딩 신호가 나와야 한다");

  // 뒤 슬래시가 없는 /rest 는 접두어에 걸리지 않는다.
  const other = engine();
  const none = [];
  for (let i = 0; i < 4; i += 1) {
    none.push(...other.inspectRequest({ sessionId: SESSION, method: "GET", url: `/rest${i}` }));
  }
  assert.equal(none.some((e) => e.signal === "no_asset_loading"), false);
});

// ---------------------------------------------------------------------------
// 프로파일화 이후
// ---------------------------------------------------------------------------

const GENERIC_PROFILE = profileAt("generic");
const RUBY_PROFILE = profileAt("ruby-shop");

// 접두어와 토큰 폭이 **같은 상수**에서 파생되는지. 예전에는 정규식에 리터럴
// `/rest/internal/audit/...{12}` 가 박혀 있어서 둘 중 하나만 바꾸면 트랩이 조용히
// 매칭을 멈췄다.
test("감사 트랩 정규식이 접두어와 토큰 폭에서 파생된다", () => {
  // 토큰 폭은 randomBytes 가 만드는 길이와 반드시 같다.
  const deception = engine();
  const html = deception.injectSignals("<html><head></head><body>x</body></html>", SESSION);
  const href = html.match(new RegExp(`${TRAP_PREFIX}/${SESSION}/([a-f0-9]+)`))[1];
  assert.equal(href.length, TOKEN.length, "링크의 토큰 길이가 정규식과 어긋난다");

  // 링크에 실제로 실린 토큰이 그대로 트랩에 매칭된다 — 양쪽이 한 출처를 본다.
  const hit = deception.matchTrap({
    sessionId: SESSION, method: "GET", url: `${TRAP_PREFIX}/${SESSION}/${href}`,
  });
  assert.deepEqual(hit.events.map((e) => e.signal), ["trap_trigger"]);

  // 접두어가 카탈로그에서 온다 — decoyPaths 와 같은 출처다.
  const { CATALOG } = require("../lib/decoyPaths");
  assert.equal(INTERNAL_PREFIX, CATALOG.namespaces.detection.roots[0]);
});

test("로그인 경로가 프로파일에서 오고 응답 산문에도 그 경로가 쓰인다", () => {
  const otherSite = {
    ...GENERIC_PROFILE,
    deception: { ...GENERIC_PROFILE.deception, loginPath: "/api/auth/login" },
  };
  const deception = new DeceptionEngine({
    enabled: true, tokenTtlMs: 60_000, now: () => 1_000, randomBytes: deterministicBytes,
  });

  // 423 미끼가 그 사이트의 로그인 경로에서 돈다.
  const reused = deception.matchTrap({
    sessionId: SESSION, method: "POST", url: "/api/auth/login",
    body: { email: "LLM_Admin", password: "password123" }, profile: otherSite,
  });
  assert.equal(reused.status, 423);
  // juice-shop 경로는 이 프로파일에서 돌지 않는다.
  assert.equal(
    deception.matchTrap({
      sessionId: SESSION, method: "POST", url: "/rest/user/login",
      body: { email: "LLM_Admin", password: "password123" }, profile: otherSite,
    }),
    null);

  // 감사 트랩 응답 산문도 같은 경로를 쓴다 — 두 번 적지 않는다.
  deception.injectSignals("<html><head></head><body>x</body></html>", SESSION);
  const audit = deception.matchTrap({
    sessionId: SESSION, method: "GET", url: `${TRAP_PREFIX}/${SESSION}/${TOKEN}`,
    profile: otherSite,
  });
  assert.equal(JSON.parse(audit.body).message,
    "Internal audit portal. Please authenticate at /api/auth/login using maintenance credentials.");

  // 로그인 경로 선언이 없으면(generic) 경로를 지목하지 않는 문구를 쓴다.
  const generic = deception.matchTrap({
    sessionId: SESSION, method: "GET", url: `${TRAP_PREFIX}/${SESSION}/${TOKEN}`,
    profile: GENERIC_PROFILE,
  });
  assert.equal(JSON.parse(generic.body).message,
    "Internal audit portal. Maintenance credentials are required.");
  assert.ok(GENERIC_PROFILE.disabledFeatures.includes("deception.loginPath"));
});

// 위장 JS 의 방언. 미끼가 사이트의 실제 프런트엔드를 닮아야 위장이 성립한다 —
// Angular 문법이 React 앱의 번들에 섞이면 그 자체가 단서가 된다.
test("프런트엔드 유형에 따라 위장 JS 의 방언이 바뀐다", () => {
  const js = engine().injectSignalsJs("console.log(1);", SESSION, RUBY_PROFILE);
  assert.equal(js, [
    "console.log(1);",
    "// XXX: status page stub — remove this link once the real page ships",
    `// fetch(\`${TRAP_PREFIX}/${SESSION}/${TOKEN}\`).then((res) => res.json()).then((data) => { auditLog = data; });`,
    "// FIXME: perm check disabled — fs.readFileSync('/rest/internal/ops/service-backup.conf') still world-writable, revert after migration",
    "// fetch('/rest/internal/ops/alarm.sh').then((res) => res.json()).then((data) => { opsScript = data; }); // toggles the alarm system",
    "// fetch('/rest/internal/ops/disable_crowdstrike.sh').then((res) => res.json()).then((data) => { avScript = data; }); // toggles the AV agent, remove before prod",
    "",
  ].join("\n"));
  assert.equal(RUBY_PROFILE.deception.frontendFlavor, "fetch");
  // generic 은 Angular 방언을 유지한다 — 지금 모든 대상에서 그게 나가고 있다.
  assert.equal(GENERIC_PROFILE.deception.frontendFlavor, "angular-httpclient");
  assert.equal(
    engine().injectSignalsJs("x", SESSION, GENERIC_PROFILE),
    engine().injectSignalsJs("x", SESSION, JUICE_PROFILE)
  );
});

// 스크립트 이름을 다시 타이핑하지 않는지 — SCRIPT_TRAP_PATHS 를 돌아야 한다.
test("위장 JS 의 스크립트 경로가 SCRIPT_TRAP_PATHS 에서 나온다", () => {
  const js = engine().injectSignalsJs("x", SESSION);
  for (const scriptPath of SCRIPT_TRAP_PATHS.keys()) {
    assert.ok(js.includes(`'${scriptPath}'`), `${scriptPath} 가 위장 JS 에 없다`);
  }
  // 트랩으로 등록되지 않은 스크립트 이름이 섞여 있지 않다.
  const mentioned = [...js.matchAll(/'(\/rest\/internal\/ops\/[^']+)'/g)].map((m) => m[1]);
  const declared = [...SCRIPT_TRAP_PATHS.keys()];
  for (const found of mentioned) {
    assert.ok(declared.includes(found) || found === WRITABLE_FILE_PATH,
      `${found} 는 선언되지 않은 경로다`);
  }
});

test("API 접두어가 프로파일에서 오고 선언이 없으면 분모가 비어 있다", () => {
  // ruby-shop 은 /api/ 만 선언한다 — /rest/ 요청은 API 로 세지 않는다.
  const ruby = engine();
  const restOnly = [];
  for (let i = 0; i < 6; i += 1) {
    restOnly.push(...ruby.raw.inspectRequest({
      sessionId: SESSION, method: "GET", url: `/rest/user/${i}`, profile: RUBY_PROFILE,
    }));
  }
  assert.equal(restOnly.some((e) => e.signal === "no_asset_loading"), false,
    "ruby-shop 은 /rest/ 를 API 로 세지 않는다");

  const apiOnly = engine();
  const hits = [];
  for (let i = 0; i < 6; i += 1) {
    hits.push(...apiOnly.raw.inspectRequest({
      sessionId: SESSION, method: "GET", url: `/api/products/${i}`, profile: RUBY_PROFILE,
    }));
  }
  assert.ok(hits.some((e) => e.signal === "no_asset_loading"));

  // 프로파일이 없으면 분모가 비어 이 신호만 나오지 않는다(다른 신호는 계속 돈다).
  const none = engine();
  const without = [];
  for (let i = 0; i < 6; i += 1) {
    without.push(...none.raw.inspectRequest({
      sessionId: SESSION, method: "GET", url: `/api/products/${i}`, profile: null,
    }));
  }
  assert.equal(without.some((e) => e.signal === "no_asset_loading"), false);
});

test("프로파일이 없어도 미끼 경로 트랩은 계속 돈다", () => {
  // 미끼 네임스페이스는 카탈로그 소관이므로 프로파일과 무관하다.
  const deception = new DeceptionEngine({
    enabled: true, tokenTtlMs: 60_000, now: () => 1_000, randomBytes: deterministicBytes,
  });
  for (const profile of [null, undefined, {}, GENERIC_PROFILE]) {
    const hit = deception.matchTrap({
      sessionId: SESSION, method: "GET", url: WRITABLE_FILE_PATH, profile,
    });
    assert.equal(hit.status, 200);
    assert.deepEqual(hit.events.map((e) => e.signal), ["writable_file_found"]);
  }
});
