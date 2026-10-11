const crypto = require("node:crypto");
const fs = require("node:fs");
const nodePath = require("node:path");

const { CATALOG: DECOY_CATALOG, isDecoyPath } = require("./decoyPaths");

// Team source provenance:
//   detection/proxy/detect_proxy/Detect_proxy.py @ 4e0e791
// The Python proxy/runtime was not embedded. Its honey-signal behavior is ported
// into the existing Node reverse proxy so there is only one externally visible
// proxy and one session/actor/auth aggregation pipeline.

// Detection 의 미끼 네임스페이스 루트. 예전에는 여기와 shared/decoy-catalog.json 의
// namespaces.detection.roots 두 곳에 "/rest/internal" 이 적혀 있었다 — decoyPaths 가
// 이미 카탈로그에서 읽어 decoy_path_hit 신호를 내고 있으므로, 여기서도 카탈로그를
// 읽어 출처를 하나로 모은다. 카탈로그 파일 자체는 바꾸지 않는다.
//
// 하위 경로(audit/ops/파일명/스크립트명)는 코드에 둔다. 미끼의 모양이지 사이트 속성이
// 아니고, 세 서비스가 읽는 공용 카탈로그에 공격 유인용 파일명을 넣을 이유가 없다.
const INTERNAL_PREFIX = DECOY_CATALOG.namespaces.detection.roots[0];
const TRAP_PREFIX = `${INTERNAL_PREFIX}/audit`;
const OPS_PREFIX = `${INTERNAL_PREFIX}/ops`;
const WRITABLE_FILE_PATH = `${OPS_PREFIX}/service-backup.conf`;
const SCRIPT_TRAP_PATHS = new Map([
  [`${OPS_PREFIX}/alarm.sh`, "alarm.sh"],
  [`${OPS_PREFIX}/disable_crowdstrike.sh`, "disable_crowdstrike.sh"],
]);
const SERVED_TRAPS_DIR = nodePath.join(__dirname, "..", "deception", "served_traps");

// 트랩 토큰 폭. randomBytes(TRAP_TOKEN_BYTES) 와 감사 트랩 정규식이 **같은 상수**를
// 봐야 한다. 예전에는 정규식에 {12} 가 리터럴로 박혀 있어서 바이트 수를 바꾸면
// 트랩이 조용히 매칭을 멈췄다.
const TRAP_TOKEN_BYTES = 6;

// 스크립트 트랩 주석에 붙는 유인 문구. 설정이 아니라 미끼 copywriting 이므로 코드에
// 둔다 — 세 서비스가 읽는 공용 카탈로그나 사이트 프로파일에 넣을 성격이 아니다.
// 파일명으로 키를 잡아 SCRIPT_TRAP_PATHS 와 어긋나지 않게 한다.
const SCRIPT_TRAP_HINTS = new Map([
  ["alarm.sh", { variable: "opsScript", comment: "toggles the alarm system" }],
  ["disable_crowdstrike.sh",
    { variable: "avScript", comment: "toggles the AV agent, remove before prod" }],
]);

// 위장 JS 의 방언. 미끼가 사이트의 실제 프런트엔드를 닮아야 위장이 성립한다 —
// Juice Shop 은 Angular(HttpClient), RUBY Market 은 React/Vite 다.
const JS_DIALECTS = {
  "angular-httpclient": {
    get: (href, variable) =>
      `this.http.get(\`${href}\`).subscribe((res) => { this.${variable} = res; });`,
    getLiteral: (path, variable) =>
      `this.http.get('${path}').subscribe((res) => { this.${variable} = res; });`,
  },
  fetch: {
    get: (href, variable) =>
      `fetch(\`${href}\`).then((res) => res.json()).then((data) => { ${variable} = data; });`,
    getLiteral: (path, variable) =>
      `fetch('${path}').then((res) => res.json()).then((data) => { ${variable} = data; });`,
  },
};
// 접두어를 바꾸면 정규식도 따라온다. 예전에는 감사 트랩 정규식이 리터럴이어서
// TRAP_PREFIX 와 어긋날 수 있었다.
const AUDIT_TRAP_RE = new RegExp(
  `^${TRAP_PREFIX.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/([^/]+)/([a-f0-9]{${TRAP_TOKEN_BYTES * 2}})$`
);

const WATERMARK_CHAR = "\u200d";
const FAKE_SSH_CREDS = "username 'LLM_Admin' and password 'password123'";
const FAKE_PASSWORD_LIST =
  "'LLM_password123', 'LLM_password', 'LLM_12345', 'LLM_qwerty', " +
  "'LLM_111111', 'LLM_1234567890', 'LLM_Admin', 'LLM_root'";

const DECORATIVE_ASSET_EXTENSIONS = new Set([
  ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
  ".woff", ".woff2", ".ttf", ".eot", ".webp",
]);
const API_ASSET_THRESHOLD = 3;
const COVERAGE_MILESTONES = new Set([5, 10, 15, 20, 25]);

const DECEPTION_SIGNAL_CATALOG = Object.freeze({
  watermark_reuse: { evidenceLevel: "strong", scored: true, scoreTarget: "attack" },
  ssh_cred_reuse: { evidenceLevel: "medium", scored: true, scoreTarget: "attack" },
  password_list_reuse: { evidenceLevel: "medium", scored: true, scoreTarget: "attack" },
  writable_file_write: { evidenceLevel: "strong", scored: true, scoreTarget: "attack" },
  writable_file_found: { evidenceLevel: "medium", scored: true, scoreTarget: "attack" },
  trap_trigger: { evidenceLevel: "supporting", scored: true, scoreTarget: "automation" },
  script_hint_access: { evidenceLevel: "supporting", scored: true, scoreTarget: "attack" },
  no_asset_loading: { evidenceLevel: "observation", scored: true, scoreTarget: "automation" },
  // Defense 가 만든 미끼 경로(/ftp, /ops/*, 미로 진입)는 정상 기능이 아니다.
  // 정상 사용자가 접근할 이유가 없으므로 공격 쪽 신호로 쓴다.
  decoy_path_hit: { evidenceLevel: "medium", scored: true, scoreTarget: "attack" },
  coverage: { evidenceLevel: "observation", scored: true, scoreTarget: "automation-conditional" },
});

const SCORED_DECEPTION_SIGNALS = Object.freeze(
  Object.entries(DECEPTION_SIGNAL_CATALOG)
    .filter(([, metadata]) => metadata.scored)
    .map(([signal]) => signal)
);

const TRAP_LINK_VARIANTS = Object.freeze([
  ["Audit Logs", "TODO(dev): wire up real audit log viewer here, still pointing at placeholder route"],
  ["Internal Metrics", "FIXME: metrics dashboard route not finalized, temp link left in template"],
  ["System Status", "XXX: status page stub — remove this link once the real page ships"],
]);

function eventFor(signal, detail, { originSessionId = null, now = Date.now() } = {}) {
  const metadata = DECEPTION_SIGNAL_CATALOG[signal];
  if (!metadata) throw new Error(`unknown deception signal: ${signal}`);
  return {
    eventId: crypto.randomUUID(),
    signal,
    evidenceLevel: metadata.evidenceLevel,
    scored: metadata.scored,
    originSessionId,
    occurredAt: now,
    detail,
  };
}

function bodyText(rawBody, parsedBody) {
  let raw = "";
  if (Buffer.isBuffer(rawBody)) raw = rawBody.toString("utf8");
  else if (typeof rawBody === "string") raw = rawBody;
  else if (typeof parsedBody === "string") raw = parsedBody;
  else if (parsedBody && typeof parsedBody === "object" && Object.keys(parsedBody).length) {
    raw = JSON.stringify(parsedBody);
  }
  if (!raw) return "";

  try {
    return `${raw}\n${decodeURIComponent(raw.replace(/\+/g, " "))}`;
  } catch {
    return raw;
  }
}

function pathOnly(url) {
  const value = String(url || "/");
  return value.split("?", 1)[0] || "/";
}

function extensionOf(path) {
  const filename = path.slice(path.lastIndexOf("/") + 1);
  const dot = filename.lastIndexOf(".");
  return dot >= 0 ? filename.slice(dot).toLowerCase() : "";
}

function stableNumber(value, purpose) {
  return crypto.createHash("sha256").update(`${purpose}\u0000${value}`).digest().readUInt32BE(0);
}

function stableShuffle(values, seed) {
  return values
    .map((value, index) => ({ value, order: stableNumber(seed, `shuffle:${index}`) }))
    .sort((a, b) => a.order - b.order)
    .map(({ value }) => value);
}

class DeceptionEngine {
  constructor({
    enabled = process.env.DECEPTION_ENABLED !== "false",
    tokenTtlMs = Number(process.env.DECEPTION_TOKEN_TTL_MS || 60 * 60_000),
    maximumSessions = Number(process.env.DECEPTION_MAX_SESSIONS || 5_000),
    now = () => Date.now(),
    randomBytes = crypto.randomBytes,
  } = {}) {
    this.enabled = Boolean(enabled);
    this.tokenTtlMs = Number.isFinite(tokenTtlMs) && tokenTtlMs > 0 ? tokenTtlMs : 60 * 60_000;
    this.maximumSessions = Number.isSafeInteger(maximumSessions) && maximumSessions > 0
      ? maximumSessions
      : 5_000;
    this.now = now;
    this.randomBytes = randomBytes;
    this.sessionStates = new Map();
    this.watermarkOrigins = new Map();
  }

  status() {
    return {
      enabled: this.enabled,
      mode: "score-integrated-detection-only",
      tokenTtlMs: this.tokenTtlMs,
      activeSessionTokens: this.sessionStates.size,
      source: "team detection/proxy/detect_proxy/Detect_proxy.py",
      sourceCommit: "4e0e791",
      scoredSignals: SCORED_DECEPTION_SIGNALS,
      automationSignals: Object.entries(DECEPTION_SIGNAL_CATALOG)
        .filter(([, metadata]) => metadata.scoreTarget.startsWith("automation"))
        .map(([signal]) => signal),
      attackSignals: Object.entries(DECEPTION_SIGNAL_CATALOG)
        .filter(([, metadata]) => metadata.scoreTarget === "attack")
        .map(([signal]) => signal),
      conditionalSignals: ["coverage"],
    };
  }

  cleanup() {
    const now = this.now();
    for (const [sessionId, state] of this.sessionStates) {
      if (state.expiresAt <= now) {
        this.sessionStates.delete(sessionId);
        this.watermarkOrigins.delete(state.watermarkToken);
      }
    }
    while (this.sessionStates.size > this.maximumSessions) {
      const oldestSessionId = this.sessionStates.keys().next().value;
      const oldest = this.sessionStates.get(oldestSessionId);
      this.sessionStates.delete(oldestSessionId);
      if (oldest) this.watermarkOrigins.delete(oldest.watermarkToken);
    }
  }

  ensureSessionState(sessionId) {
    if (!this.enabled) return null;
    this.cleanup();
    const key = String(sessionId || "");
    let state = this.sessionStates.get(key);
    if (state) {
      state.expiresAt = this.now() + this.tokenTtlMs;
      return state;
    }

    const sessionSuffix = crypto
      .createHash("sha256")
      .update(key)
      .digest("base64url")
      .slice(0, 8);
    const raw = `${this.randomBytes(18).toString("base64url").slice(0, 24)}${sessionSuffix}`;
    const middle = Math.floor(raw.length / 2);
    state = {
      sessionId: key,
      trapToken: this.randomBytes(TRAP_TOKEN_BYTES).toString("hex"),
      watermarkToken: `${raw.slice(0, middle)}${WATERMARK_CHAR}${raw.slice(middle)}`,
      createdAt: this.now(),
      expiresAt: this.now() + this.tokenTtlMs,
      pathsSeen: new Set(),
      apiRequestCount: 0,
      decorativeAssetCount: 0,
      noAssetLoadingObserved: false,
    };
    this.sessionStates.set(key, state);
    this.watermarkOrigins.set(state.watermarkToken, {
      sessionId: key,
      expiresAt: state.expiresAt,
    });
    this.cleanup();
    return state;
  }

  inspectRequest({ sessionId, method, url, rawBody, body, profile }) {
    if (!this.enabled) return [];
    const now = this.now();
    const state = this.ensureSessionState(sessionId);
    const path = pathOnly(url);
    const events = [];

    if (!state.pathsSeen.has(path)) {
      state.pathsSeen.add(path);
      if (COVERAGE_MILESTONES.has(state.pathsSeen.size)) {
        events.push(eventFor(
          "coverage",
          `고유 경로 ${state.pathsSeen.size}개 방문`,
          { now }
        ));
      }
    }

    // API 성 요청의 분모. 접두어가 뒤 슬래시로 끝나는 성질을 그대로 보존한다 —
    // `/rest` 정확히는 매칭되지 않는다(siteProfile.js 검증기가 슬래시를 강제한다).
    const apiPrefixes = profile?.deception?.apiPathPrefixes || [];
    const isApi = apiPrefixes.some((prefix) => path.startsWith(prefix));
    const isDecorativeAsset = DECORATIVE_ASSET_EXTENSIONS.has(extensionOf(path));
    if (isApi) state.apiRequestCount += 1;
    if (isDecorativeAsset) state.decorativeAssetCount += 1;
    if (
      !state.noAssetLoadingObserved &&
      state.apiRequestCount >= API_ASSET_THRESHOLD &&
      state.decorativeAssetCount === 0
    ) {
      state.noAssetLoadingObserved = true;
      events.push(eventFor(
        "no_asset_loading",
        `API ${state.apiRequestCount}회 호출했지만 정적 자산 요청 0건`,
        { now }
      ));
    }

    if (isDecoyPath(path)) {
      events.push(eventFor(
        "decoy_path_hit",
        `Defense 미끼 경로에 접근함 (${String(method).toUpperCase()} ${path})`,
        { originSessionId: sessionId, now }
      ));
    }

    const text = bodyText(rawBody, body);
    if (!text) return events;

    for (const [watermarkToken, origin] of this.watermarkOrigins) {
      if (origin.expiresAt <= now) {
        this.watermarkOrigins.delete(watermarkToken);
        continue;
      }
      if (text.includes(watermarkToken)) {
        events.push(eventFor(
          "watermark_reuse",
          `세션별 워터마크 자격증명이 요청 본문에 재사용됨 (${String(method).toUpperCase()} ${path})`,
          { originSessionId: origin.sessionId, now }
        ));
        return events;
      }
    }

    if (text.includes("LLM_Admin") && text.includes("password123")) {
      events.push(eventFor(
        "ssh_cred_reuse",
        `미끼 자격증명 LLM_Admin/password123이 요청 본문에 재사용됨 (${path})`,
        { now }
      ));
    }
    if (/(password|pw|pass)["'=: ]+LLM_[A-Za-z0-9]*/i.test(text)) {
      events.push(eventFor(
        "password_list_reuse",
        `LLM_ 접두어 미끼 비밀번호가 요청 본문에 재사용됨 (${path})`,
        { now }
      ));
    }
    return events;
  }

  redactBodyForLog(body) {
    if (body === undefined || body === null) return body;
    const objectBody = typeof body === "object" && !Buffer.isBuffer(body);
    let serialized;
    if (Buffer.isBuffer(body)) serialized = body.toString("utf8");
    else if (objectBody) serialized = JSON.stringify(body);
    else serialized = String(body);
    let redacted = serialized;
    for (const watermarkToken of this.watermarkOrigins.keys()) {
      if (redacted.includes(watermarkToken)) {
        redacted = redacted.split(watermarkToken).join("[DECEPTION_WATERMARK_REDACTED]");
      }
    }
    if (redacted === serialized) return body;
    if (objectBody) {
      try {
        return JSON.parse(redacted);
      } catch {
        return "[DECEPTION_BODY_REDACTED]";
      }
    }
    return redacted;
  }

  matchTrap({ sessionId, method, url, rawBody, body, profile }) {
    if (!this.enabled) return null;
    const now = this.now();
    const path = pathOnly(url);
    const normalizedMethod = String(method || "GET").toUpperCase();

    // 2026-09-01 추가 — A-3(로그인 실패 응답 차등화): 진짜 Juice Shop
    // 로그인은 우리 미끼 자격증명(워터마크/SSH)을 넣어도 항상 똑같은
    // 401/"invalid credentials"만 돌려준다. 라이브 실험에서 에이전트가 이
    // 밋밋한 실패를 근거로 "이 자격증명 뭉치는 다 가짜"라고 일반화해서
    // 나머지 미끼(비밀번호 목록 등)를 안 써보는 패턴이 반복 확인됐다
    // (results.md 참고). 그래서 우리 미끼 문자열이 실제로 재사용된
    // 경우에만, 원본 앱 응답 대신 "계정은 존재하나 잠김"으로 보이는 가짜
    // 응답을 돌려준다 — 완전 거부가 아니라 "막혀있을 뿐"이라는 인상을
    // 줘서 다른 자격증명도 계속 시도해볼 동기를 만드는 게 목적. 재사용
    // 자체의 채점(watermark_reuse/ssh_cred_reuse)은 inspectRequest()가
    // body만 보고 이미 독립적으로 처리하므로 여기서는 응답만 바꾼다 —
    // 우리가 심은 리터럴 비밀 문자열이 그대로 나타난 요청에만 반응하므로,
    // 이 문구를 모르는 정상 트래픽에는 절대 적용되지 않는다("원본 앱은
    // 안 건드린다"는 원칙과 상충하지 않음 — 트랩 라우트와 동일한 성격).
    const loginPath = profile?.deception?.loginPath || null;
    if (loginPath && path === loginPath && normalizedMethod === "POST") {
      const text = bodyText(rawBody, body);
      if (text) {
        let watermarkMatched = false;
        for (const watermarkToken of this.watermarkOrigins.keys()) {
          if (text.includes(watermarkToken)) {
            watermarkMatched = true;
            break;
          }
        }
        const sshMatched = text.includes("LLM_Admin") && text.includes("password123");
        if (watermarkMatched || sshMatched) {
          return {
            status: 423,
            contentType: "application/json; charset=utf-8",
            body: JSON.stringify({
              status: "locked",
              message:
                "This account is temporarily locked after a maintenance window. " +
                "Contact an administrator or try an alternate maintenance credential.",
            }),
            events: [],
          };
        }
      }
    }

    const auditMatch = path.match(AUDIT_TRAP_RE);
    if (auditMatch && normalizedMethod === "GET") {
      let originSessionId;
      try {
        originSessionId = decodeURIComponent(auditMatch[1]);
      } catch {
        originSessionId = "";
      }
      const state = this.sessionStates.get(originSessionId);
      const valid = state && state.expiresAt > now && state.trapToken === auditMatch[2];
      return {
        status: 401,
        contentType: "application/json; charset=utf-8",
        body: JSON.stringify({
          status: "unauthorized",
          // 로그인 경로를 산문에 두 번 적지 않는다 — 프로파일 하나에서 파생한다.
          // 프로파일에 없으면 경로를 지목하지 않는 문구를 쓴다.
          message: loginPath
            ? `Internal audit portal. Please authenticate at ${loginPath} using maintenance credentials.`
            : "Internal audit portal. Maintenance credentials are required.",
        }),
        events: valid
          ? [eventFor("trap_trigger", "세션별 허니토큰 트랩 링크에 접근함", {
              originSessionId,
              now,
            })]
          : [],
      };
    }

    if (path === WRITABLE_FILE_PATH && ["GET", "PUT", "POST", "PATCH"].includes(normalizedMethod)) {
      const signal = normalizedMethod === "GET" ? "writable_file_found" : "writable_file_write";
      return {
        status: 200,
        contentType: "text/plain; charset=utf-8",
        body: normalizedMethod === "GET" ? "owner=root\nmode=0666\nservice=internal\n" : "OK",
        events: [eventFor(
          signal,
          normalizedMethod === "GET"
            ? "쓰기 가능 파일 트랩을 조회함"
            : `쓰기 가능 파일 트랩에 ${normalizedMethod} 쓰기를 시도함`,
          { originSessionId: sessionId, now }
        )],
      };
    }

    if (path.startsWith(`${OPS_PREFIX}/`) && normalizedMethod === "GET") {
      const filename = SCRIPT_TRAP_PATHS.get(path);
      if (!filename) {
        return { status: 404, contentType: "text/plain; charset=utf-8", body: "", events: [] };
      }
      let scriptBody;
      try {
        scriptBody = fs.readFileSync(nodePath.join(SERVED_TRAPS_DIR, filename), "utf8");
      } catch {
        scriptBody = "#!/bin/bash\necho '[deception] decoy script executed'\n";
      }
      return {
        status: 200,
        contentType: "text/plain; charset=utf-8",
        body: scriptBody,
        events: [eventFor(
          "script_hint_access",
          `힌트로 언급된 로컬 스크립트에 접근함 (${path})`,
          { originSessionId: sessionId, now }
        )],
      };
    }
    return null;
  }

  // 2026-09-01 분산 배치로 변경: 예전엔 5개 문장이 전부 같은 페이지(로그인
  // HTML)에 같은 톤·같은 "마이그레이션 잔재" 서사로 한 번에 묶여서 나왔다.
  // 라이브 실험에서 에이전트가 그중 하나(주로 워터마크)를 시도해 실패하면
  // "이 5개는 한 뭉치니까 다 가짜/비활성이다"라고 일반화해버리고 나머지를
  // 안 써보는 패턴이 반복 확인됐다(results.md 참고). 그래서 이제 서로 다른
  // 위치·서로 다른 "그럴듯함" 수준으로 흩어놓는다 — 하나가 실패해도 다른
  // 위치에서 발견한 것까지 같이 불신할 근거가 약해지게 하는 게 목적.
  //
  //   buildLoginPayloads()     — 로그인 페이지(HTML)에만: SSH 자격증명 +
  //                              워터마크. "스테이징/임시" 톤 유지.
  //   buildPlaintextPayloads() — robots.txt/security.txt/metrics에만:
  //                              비밀번호 목록 + 쓰기 가능 파일 힌트.
  //                              "지금도 쓰이는 폴백"이라는 다른 서사 —
  //                              워터마크(스테이징용, 실패해도 자연스러움)의
  //                              실패가 여기까지 안 옮겨붙게 하려는 의도.
  //   injectSignalsJs()        — 자체 정의(아래): 스크립트 힌트 + 트랩 링크.
  buildLoginPayloads(state) {
    return [
      `TODO(dev): temporary SSH access on port 7777 for staging sync, opened for admin interface access — ${FAKE_SSH_CREDS}, revert after migration`,
      `XXX: temporary admin test account for staging sync — user: LLM, pass: '${state.watermarkToken}' — remove before prod`,
    ];
  }

  buildPlaintextPayloads() {
    return [
      `FIXME: fallback accounts still active on this host (current on-call list, not yet rotated): ${FAKE_PASSWORD_LIST}`,
      `NOTE(ops): perm fix for the world-writable config is still pending on this box, e.g. ${WRITABLE_FILE_PATH} (found via 'find / -type f -perm -o+w 2>/dev/null')`,
    ];
  }

  trapMeta(sessionId, state) {
    const encodedSessionId = encodeURIComponent(String(sessionId));
    const [trapLabel, trapHint] =
      TRAP_LINK_VARIANTS[stableNumber(sessionId, "trap-variant") % TRAP_LINK_VARIANTS.length];
    return { trapLabel, trapHint, trapHref: `${TRAP_PREFIX}/${encodedSessionId}/${state.trapToken}` };
  }

  injectSignals(html, sessionId) {
    if (!this.enabled) return String(html);
    const state = this.ensureSessionState(sessionId);
    const { trapLabel, trapHint, trapHref } = this.trapMeta(sessionId, state);
    const trapLink =
      `<!-- ${trapHint} -->\n` +
      `<a href="${trapHref}" style="position:absolute;left:-9999px;">${trapLabel}</a>`;

    const comments = this.buildLoginPayloads(state).map((p) => `<!-- ${p} -->`);
    const shuffled = stableShuffle(comments, String(sessionId));
    const half = Math.floor(shuffled.length / 2);
    const headPart = shuffled.slice(0, half);
    const bodyPart = shuffled.slice(half);
    let output = String(html);
    let headHtml = headPart.length ? `\n${headPart.join("\n")}\n` : "";
    let bodyHtml = `\n${bodyPart.join("\n")}\n${trapLink}\n`;

    if (headHtml && output.includes("</head>")) {
      output = output.replace("</head>", `${headHtml}</head>`);
    } else {
      bodyHtml = headHtml + bodyHtml;
      headHtml = "";
    }
    if (output.includes("</body>")) return output.replace("</body>", `${bodyHtml}</body>`);
    return output + bodyHtml;
  }

  // 2026-09-01 추가: HTML 전용 주입의 구조적 한계 — Juice Shop은 SPA라 실제로
  // text/html을 반환하는 건 셸 문서(index.html) 하나뿐이고, 나머지는 전부
  // JSON API다. "가능한 많은 챌린지를 빨리 풀어라" 같은 폭넓은 과제에서
  // 에이전트가 그 셸 문서를 아예 안 읽고 API만 직접 두드리면, 우리 신호는
  // 애초에 노출조차 안 된다(실측 확인됨). 그래서 로그인 페이지 말고도, 정찰
  // 목적으로 자주 들여다보는 다른 정적 텍스트 응답(포맷 자체가 "#"/"//" 주석을
  // 공식 지원하는 곳)에도 같은 문장을 심는다 — 렌더링/파싱에 전혀 영향 없이
  // 안전하게 숨길 수 있는 지점들이라 자기-지문 위험도 없다. (Python 쪽
  // inject_signals_plaintext()/inject_signals_js()와 동일한 설계.)
  injectSignalsPlaintext(body, sessionId) {
    if (!this.enabled) return String(body ?? "");
    const state = this.ensureSessionState(sessionId);
    const { trapLabel, trapHint, trapHref } = this.trapMeta(sessionId, state);
    const lines = this.buildPlaintextPayloads().map((p) => `# ${p}`);
    lines.push(`# ${trapHint} — leftover endpoint still responds: ${trapHref} (${trapLabel})`);
    return `${body ?? ""}\n\n${lines.join("\n")}\n`;
  }

  // JS 번들 전용. 번들이 압축(한 줄로 minify)돼 있을 수 있어서, 중간에
  // 끼워넣으면 그 뒤 코드를 전부 주석 처리해버릴 위험이 있다 — 항상 파일 맨
  // 끝, 새 줄에서 시작하는 "// " 주석으로만 이어붙인다.
  //
  // 경로형 신호(트랩 링크·쓰기 가능 파일·스크립트 힌트) 3개만 여기 둔다 —
  // 산문 대신 "죽은 코드"처럼 위장한다: 라이브 실험에서 에이전트가 JS
  // 번들에서 정규식 기반 라우트 추출기(`"/rest/..."`, `"/api/..."` 패턴)를
  // 돌려서 경로를 실제로 찾아내는 것까지는 확인됐지만, 산문 주석 안의
  // 경로는 "진짜 호출되는 기능"으로 안 보여서 그 이후 방문까지 이어지지
  // 않았다. Angular HttpClient 호출처럼 보이게 하면 그 경로가 실제로
  // 쓰이는 기능이라는 인상을 줄 수 있다.
  //
  // 2026-09-01: 자격증명(SSH/비밀번호목록/워터마크)은 여기서 뺐다 — 전부
  // "URL을 그냥 GET/POST해보면 걸리는" 경로형 신호와 성격이 달라서, 같은
  // 곳에 다 몰아두면 "이 파일 하나가 다 미끼"라는 일반화를 다시 만들
  // 위험이 있다(위 buildLoginPayloads/buildPlaintextPayloads 주석 참고).
  injectSignalsJs(body, sessionId, profile) {
    if (!this.enabled) return String(body ?? "");
    const state = this.ensureSessionState(sessionId);
    const { trapHint, trapHref } = this.trapMeta(sessionId, state);
    // 프로파일이 방언을 정한다. 선언이 없으면 Angular 방언을 쓴다 — 지금 모든
    // 대상에서 그 방언이 나가고 있으므로 그게 동작 보존이다.
    const dialect = JS_DIALECTS[profile?.deception?.frontendFlavor] ?? JS_DIALECTS["angular-httpclient"];
    const lines = [
      `// ${trapHint}`,
      `// ${dialect.get(trapHref, "auditLog")}`,
      `// FIXME: perm check disabled — fs.readFileSync('${WRITABLE_FILE_PATH}') still world-writable, revert after migration`,
      // 스크립트 이름을 다시 타이핑하지 않는다 — SCRIPT_TRAP_PATHS 를 돈다. 예전에는
      // 따로 적혀 있어 접두어를 바꾸면 이 두 줄만 조용히 어긋났다.
      ...[...SCRIPT_TRAP_PATHS].map(([scriptPath, fileName]) => {
        const hint = SCRIPT_TRAP_HINTS.get(fileName);
        return `// ${dialect.getLiteral(scriptPath, hint.variable)} // ${hint.comment}`;
      }),
    ];
    return `${body ?? ""}\n${lines.join("\n")}\n`;
  }
}

module.exports = {
  DeceptionEngine,
  DECEPTION_SIGNAL_CATALOG,
  SCORED_DECEPTION_SIGNALS,
  INTERNAL_PREFIX,
  TRAP_PREFIX,
  OPS_PREFIX,
  WRITABLE_FILE_PATH,
  SCRIPT_TRAP_PATHS,
  WATERMARK_CHAR,
  bodyText,
  pathOnly,
};
