const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const { fixRequestBody } = require("http-proxy-middleware");

const store = require("./lib/sessionStore");
const { deriveAuthGroupId } = require("./lib/authGroup");
const { DcidManager } = require("./lib/dcid");
const { AccountIdentityResolver } = require("./lib/accountIdentity");
const { parseTrustProxy, getClientIp } = require("./lib/clientIp");
const { buildHttpFingerprint } = require("./lib/httpFingerprint");
const {
  extractFeatures,
  extractActorFeatures,
  extractAuthGroupFeatures,
  extractResolvedActorFeatures,
  extractIpFeatures,
} = require("./lib/featureExtractor");
const { classify } = require("./lib/classifier");
const { selectClientId, selectEffectiveDetection, confirmedAttackScore } = require("./lib/detectionPolicy");
const {
  assessDetection,
  normalizeDetectionLevel,
  DETECTION_THRESHOLDS,
} = require("./lib/riskPolicy");
const { tagPayload } = require("./lib/payloadSignatures");
const {
  createPayloadFingerprint,
  sanitizeExperimentRunId,
  sanitizeMetadataHeaderValue,
  parseContentLength,
  normalizePath,
} = require("./lib/requestMetadata");
const {
  computeAgenticEvidence,
  computePartitionedAgenticEvidence,
} = require("./lib/agenticEvidence");
const { CrsScanner } = require("./lib/crsScanner");
const { DeceptionEngine } = require("./lib/deceptionEngine");
const { classifyBackgroundTraffic } = require("./lib/backgroundTraffic");
const {
  analyzeBusinessLogic,
  hasHardcodedMassAssignmentWhitelist,
} = require("./lib/businessLogicSignatures");
const { checkIdentityMismatch, decodeClaimedIdentity, extractToken } = require("./lib/identityMismatch");
const { checkRoleGatedAccess, isHardcodedSensitiveRoute } = require("./lib/roleGatedAccess");
const { checkCsrf, buildAllowedOrigins } = require("./lib/csrfDetection");
const { analyzeExchange: analyzeXssExchange, extractCandidates: extractXssCandidates } = require("./lib/xssReflection");
const { XssCandidateStore } = require("./lib/xssCandidateStore");
const { attributeStoredFindings } = require("./lib/xssAttribution");
const { XssEvidenceStore } = require("./lib/xssEvidenceStore");
const { extractLoginAttemptEmail } = require("./lib/loginBruteForce");
const {
  extractResetPasswordEmail,
  extractSecurityQuestionEmail,
} = require("./lib/passwordResetAbuse");
const { detectPriceTampering } = require("./lib/priceTampering");
const {
  ingestProductResponseBody,
  extractTrailingNumericId,
  checkPriceDelta,
  PRODUCTS_LIST_PATH,
  PRODUCTS_ITEM_PATH,
} = require("./lib/priceIntegrity");
const schemaLearning = require("./lib/schemaLearning");
const { stripDetectionHeaders, buildPolicyDecision } = require("./lib/rubyPolicy");
const { applyDefensePlan, loadPolicyRules } = require("./lib/policyEngine");
const { createProxyCore } = require("./lib/proxyCore");
const {
  DashboardAuthManager,
  installDashboardRoutes,
} = require("./lib/dashboardAuth");
const {
  applyDefenseManagementHeaders,
  isDefenseManagementPath,
} = require("./lib/managementPaths");
const {
  TargetSelectionStore,
  parseTargetChoices,
} = require("./lib/targetSelection");
const { installTargetSelectionRoutes } = require("./lib/targetSelectionRoutes");
const { listenerBoundary } = require("./lib/listenerBoundary");

const PORT = Number(process.env.PORT || 8080);
const ADMIN_PORT = process.env.ADMIN_PORT ? Number(process.env.ADMIN_PORT) : null;
if (process.env.NODE_ENV === "production" && ADMIN_PORT === null) {
  throw new Error("production requires an isolated ADMIN_PORT listener");
}
const TARGET = process.env.TARGET_URL || "http://localhost:3000";
// 2026-09-01 추가: HTML(index.html) 하나만 보는 정찰 대신, 자주 조회되는
// 정적 텍스트 응답에도 기만 신호를 심는다 — deceptionEngine.injectSignalsPlaintext 참고.
const PLAINTEXT_BAIT_PATHS = new Set([
  "/robots.txt",
  "/security.txt",
  "/.well-known/security.txt",
  "/metrics",
]);
const BLOCK_MODE = process.env.BLOCK_MODE === "true";
const DETECTION_LEVEL = normalizeDetectionLevel(process.env.DETECTION_LEVEL);
const ENABLE_EXPERIMENT_RUN_ID = process.env.ENABLE_EXPERIMENT_RUN_ID === "true";
const EXPERIMENT_RUN_HEADER = "x-experiment-run-id";
const configuredPayloadFingerprintKey = process.env.PAYLOAD_FINGERPRINT_KEY;
const PAYLOAD_FINGERPRINT_KEY = configuredPayloadFingerprintKey || crypto.randomBytes(32);
const DETECTION_DASHBOARD_SESSION_COOKIE = "detection_dashboard_session";
const DETECTION_DASHBOARD_SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const DETECTION_DASHBOARD_COOKIE_SECURE =
  process.env.DETECTION_DASHBOARD_COOKIE_SECURE === "true";
const DETECTION_DASHBOARD_REQUIRE_HTTPS =
  process.env.DETECTION_DASHBOARD_REQUIRE_HTTPS === "true";
const ALLOW_INSECURE_DASHBOARD_HTTP =
  process.env.ALLOW_INSECURE_DASHBOARD_HTTP === "true";
if (process.env.NODE_ENV === "production") {
  const missing = [
    "PAYLOAD_FINGERPRINT_KEY",
    "DCID_HMAC_SECRET",
    "ACCOUNT_ID_HASH_KEY",
    "DETECTION_DASHBOARD_PASSWORD",
  ].filter((name) => !process.env[name]);
  if (missing.length) throw new Error(`missing production secrets: ${missing.join(", ")}`);
  if (ALLOW_INSECURE_DASHBOARD_HTTP &&
      (DETECTION_DASHBOARD_COOKIE_SECURE || DETECTION_DASHBOARD_REQUIRE_HTTPS)) {
    throw new Error("HTTP dashboard mode requires HTTPS enforcement and Secure cookies to be disabled");
  }
  if (!ALLOW_INSECURE_DASHBOARD_HTTP &&
      (!DETECTION_DASHBOARD_COOKIE_SECURE || !DETECTION_DASHBOARD_REQUIRE_HTTPS)) {
    throw new Error("production dashboard authentication requires HTTPS and Secure cookies");
  }
}
const CSRF_ALLOWED_ORIGINS = buildAllowedOrigins(
  (process.env.CSRF_ALLOWED_ORIGINS || `http://localhost:${PORT},http://127.0.0.1:${PORT}`)
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean)
);

const SESSION_COOKIE = "dlsid";
const DCID_COOKIE = "dcid";
const crsScanner = new CrsScanner();
const deceptionEngine = new DeceptionEngine({ enabled: process.env.DECEPTION_ENABLED !== "false" });
const dcidManager = new DcidManager();
const accountIdentityResolver = new AccountIdentityResolver();
const policyRules = loadPolicyRules();

function positiveInt(name, fallback) {
  const value = Number.parseInt(process.env[name] || "", 10);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

const dashboardAuth = new DashboardAuthManager({
  password: process.env.DETECTION_DASHBOARD_PASSWORD || "",
  sessionTtlMs: DETECTION_DASHBOARD_SESSION_TTL_MS,
  maxSessions: positiveInt("DETECTION_DASHBOARD_MAX_SESSIONS", 1000),
  maxAttempts: positiveInt("DETECTION_DASHBOARD_LOGIN_ATTEMPTS", 5),
  attemptWindowMs: positiveInt("DETECTION_DASHBOARD_LOGIN_WINDOW_SECONDS", 300) * 1000,
});
const targetSelection = new TargetSelectionStore({
  choices: parseTargetChoices(
    process.env.TARGET_CHOICES,
    process.env.LEGACY_TARGET_URL || "http://host.docker.internal:3000"
  ),
  defaultId: process.env.TARGET_DEFAULT_ID || "legacy",
  filePath: process.env.TARGET_SELECTION_FILE,
  publicOrigin: process.env.PUBLIC_TARGET_ORIGIN,
});

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", parseTrustProxy());
app.use(listenerBoundary({ publicPort: PORT, adminPort: ADMIN_PORT }));
app.use(cookieParser());
app.use((req, res, next) => {
  delete req.headers["x-forwarded-for"];
  if (req.path === "/__detection" || req.path.startsWith("/__detection/")) {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
  }
  next();
});

// Docker Compose와 운영 오케스트레이터가 Detection 자체의 준비 상태를
// downstream 애플리케이션과 독립적으로 확인할 수 있는 엔드포인트다.
app.get("/healthz", (_req, res) => {
  res.json({ status: "ok", service: "detection" });
});

// Defense 운영 화면은 보호 대상 트래픽이 아니다. 일반 탐지 훅을 통과시키면
// 대시보드의 주기적 폴링이 자동화 점수와 요청 통계를 오염시키므로 그대로 전달한다.
const defenseManagementProxy = createProxyCore({
  target: TARGET,
  hooks: [{ onRequest: ({ proxyReq, req }) => applyDefenseManagementHeaders(proxyReq, req) }],
});
app.use((req, res, next) => {
  if (isDefenseManagementPath(req.path)) {
    return defenseManagementProxy(req, res, next);
  }
  return next();
});

function analyzeSession(session) {
  const features = extractFeatures(session);
  const analysis = classify(features);
  return {
    ...analysis,
    detection: assessDetection(
      { ...analysis, maxAttackScore: session.attackHistory?.maxAttackScore },
      { level: DETECTION_LEVEL }
    ),
    features,
    agenticEvidence: computeAgenticEvidence(session.requests),
  };
}

function analyzeActor(actor) {
  const features = extractActorFeatures(actor, store.getSession);
  const analysis = classify(features);
  return {
    ...analysis,
    detection: assessDetection(
      { ...analysis, maxAttackScore: actor.attackHistory?.maxAttackScore },
      { level: DETECTION_LEVEL }
    ),
    features,
    agenticEvidence: computeAgenticEvidence(actor.requests),
  };
}

function analyzeAuthGroup(group) {
  const features = extractAuthGroupFeatures(group, store.getSession);
  const analysis = classify(features);
  return {
    ...analysis,
    detection: assessDetection(
      { ...analysis, maxAttackScore: group.attackHistory?.maxAttackScore },
      { level: DETECTION_LEVEL }
    ),
    features,
    // 동일 token을 공유하는 서로 다른 Actor의 transition은 연결하지 않는다.
    agenticEvidence: computePartitionedAgenticEvidence(group.requests),
  };
}

function analyzeResolvedActor(aggregate) {
  const features = extractResolvedActorFeatures(aggregate);
  const analysis = classify(features);
  return {
    ...analysis,
    detection: assessDetection(
      { ...analysis, maxAttackScore: aggregate.attackHistory?.maxAttackScore },
      { level: DETECTION_LEVEL }
    ),
    features,
    agenticEvidence: computeAgenticEvidence(aggregate.requests),
  };
}

function analyzeClientFlow(aggregate) {
  const features = extractResolvedActorFeatures(aggregate);
  const analysis = classify(features);
  return {
    ...analysis,
    detection: assessDetection(
      { ...analysis, maxAttackScore: aggregate.attackHistory?.maxAttackScore },
      { level: DETECTION_LEVEL }
    ),
    features,
    agenticEvidence: computeAgenticEvidence(aggregate.requests),
  };
}

// Client Flow는 동일 클라이언트 확정 객체가 아니라 Session/Candidate 요청을
// 시간순으로 이어 보는 휴리스틱 집계다.

/**
 * Policy는 요청을 전달하기 전에 위험도 헤더가 필요하지만, 이 탐지기의 일부
 * 신호(CRS 결과, 응답 상태)는 upstream 응답이 끝난 뒤 확정된다. 따라서 현재
 * 요청에는 같은 Session/Candidate/Auth Group에서 직전까지 완료된 관찰 이력의
 * 가장 강한 점수를 적용한다. 방금 요청의 결과는 다음 요청부터 반영된다.
 */
function buildPriorPolicyDecision(req) {
  // An upgrade cannot receive the signed dcid cookie that the HTTP middleware
  // issues on a first request. Do not borrow a NAT/fingerprint neighbor's
  // Candidate or Client Flow history for a cookie-less WebSocket connection.
  if (req.isWebSocketUpgrade && !req.clientIdentity?.valid) {
    return buildPolicyDecision({ clientId: req.websocketClientId });
  }
  const ip = getClientIp(req);
  const fingerprint = buildHttpFingerprint({
    headers: req.headers,
    rawHeaders: req.rawHeaders,
    httpVersion: req.httpVersion,
    method: req.method,
  }).clientFingerprint;
  const actorId = store.deriveActorId(ip, fingerprint);

  const session = store.getSession(req.detectionSessionId);
  const actor = store.getActor(actorId);
  const authGroup = req.authGroupId ? store.getAuthGroup(req.authGroupId) : null;
  const verifiedClientId = req.clientIdentity?.valid && req.clientIdentity?.continuityVerified
    ? req.clientIdentity.clientId : null;
  const resolvedActor = verifiedClientId
    ? store.getResolvedActorByClientId(verifiedClientId) : null;
  // 전체 집계는 멤버 세션의 요청을 모두 훑고 정렬하므로 요청 수에 대해 제곱으로
  // 커진다. 실제로 Flow가 병합된 경우에만 계산하고, 그 외에는 O(1) 상태만 본다.
  const clientFlowState = store.getClientFlowState(actorId);
  const clientFlow = clientFlowState?.aggregationEnabled
    ? store.getClientFlowAggregate(actorId)
    : null;

  // dlsid는 서명되지 않았으므로 다른 signed dcid와 함께 오면 그 세션 이력을
  // 현재 클라이언트의 확정 근거로 사용하지 않는다.
  const sessionOwned = verifiedClientId && session &&
    session.requests.at(-1)?.clientId === verifiedClientId;
  const analyses = {
    session: sessionOwned ? analyzeSession(session) : null,
    candidate: actor && clientFlowState?.status !== "CONFLICT" ? analyzeActor(actor) : null,
    authGroup: authGroup ? analyzeAuthGroup(authGroup) : null,
    clientFlow: clientFlow ? analyzeClientFlow(clientFlow) : null,
    resolved: resolvedActor ? analyzeResolvedActor(resolvedActor) : null,
  };
  // Every HTTP request receives a fresh signed DCID when one is absent. A
  // different client's shared curl/NAT fingerprint must not become this
  // client's policy score, including a 500ms delay on a normal request.
  const policyAnalyses = req.clientIdentity?.valid
    ? { session: analyses.session, resolved: analyses.resolved }
    : analyses;
  if (!Object.values(policyAnalyses).some(Boolean)) {
    return buildPolicyDecision({ clientId: req.clientIdentity?.valid ? req.clientIdentity.clientId : actorId });
  }

  const [source, analysis] = selectEffectiveDetection(policyAnalyses);
  const clientId = (req.clientIdentity?.valid && req.clientIdentity.clientId) || selectClientId(analyses, {
    actorId,
    resolvedActorId: resolvedActor?.id,
    clientFlowId: clientFlowState?.id,
  });
  // Candidate/Flow fingerprint와 Bearer 값의 hash는 신원 검증이 아니다.
  // 자동 429에는 같은 signed dcid로 묶인 확정 Resolved Actor만 사용한다.
  return buildPolicyDecision({ source, analysis, clientId,
    confirmedAttackScore: confirmedAttackScore(analyses) });
}

function computeBusinessLogicTags(req) {
  const normalizedPath = normalizePath(req.originalUrl);
  const businessLogicHits = analyzeBusinessLogic({
    method: req.method,
    normalizedPath,
    body: req.body,
    rawQueryOrBody: req.originalUrl,
  });
  const identityHits = checkIdentityMismatch({
    method: req.method,
    normalizedPath,
    url: req.originalUrl,
    body: req.body,
    authorizationHeader: req.headers.authorization,
    cookieHeader: req.headers.cookie,
  });
  const roleGateHits = checkRoleGatedAccess({
    method: req.method,
    normalizedPath,
    authorizationHeader: req.headers.authorization,
    cookieHeader: req.headers.cookie,
  });
  const priceResult = detectPriceTampering(req.body);
  const tags = [
    ...businessLogicHits.map((hit) => hit.tag),
    ...identityHits.map((hit) => hit.tag),
    ...roleGateHits.map((hit) => hit.tag),
  ];
  if (priceResult.hit) tags.push("price-tampering:total-mismatch");

  if (String(req.method).toUpperCase() === "PUT" && normalizedPath === PRODUCTS_ITEM_PATH) {
    const productId = extractTrailingNumericId(req.originalUrl);
    const submittedPrice = req.body && typeof req.body === "object" ? req.body.price : undefined;
    if (checkPriceDelta(productId, submittedPrice).hit) tags.push("price-tampering:delta");
  }
  return [...new Set(tags)];
}

function computeCsrfTags(req) {
  return checkCsrf(
    {
      method: req.method,
      normalizedPath: normalizePath(req.originalUrl),
      originHeader: req.headers.origin,
      refererHeader: req.headers.referer,
    },
    CSRF_ALLOWED_ORIGINS
  ).map((hit) => hit.tag);
}

function observeSchemaLearning(req, statusCode, normalizedPath) {
  let bodyObj = req.body;
  if (typeof bodyObj === "string") {
    try {
      bodyObj = JSON.parse(bodyObj);
    } catch {
      bodyObj = null;
    }
  }

  schemaLearning.observeMassAssignment({
    method: req.method,
    normalizedPath,
    bodyObj,
    statusCode,
    hasHardcodedWhitelist: hasHardcodedMassAssignmentWhitelist(req.method, normalizedPath),
  });

  const token = extractToken(req.headers.authorization, req.headers.cookie);
  const claimed = token ? decodeClaimedIdentity(token) : null;
  const role = claimed?.role ? String(claimed.role).toLowerCase() : null;
  schemaLearning.observeRoleAccess({
    method: req.method,
    normalizedPath,
    statusCode,
    role,
    hasHardcodedRule: isHardcodedSensitiveRoute(req.method, normalizedPath),
  });

  const requestedId = extractTrailingNumericId(req.originalUrl);
  const claimedIds = claimed
    ? [claimed.id, claimed.bid].filter((value) => value !== null && value !== undefined)
    : [];
  schemaLearning.observeIdentityAccess({
    method: req.method,
    normalizedPath,
    statusCode,
    requestedId,
    claimedIds,
  });
}

function prepareRequestObservation(req) {
  if (req._detectionPrepared) return;
  req._detectionPrepared = true;
  req.activeTarget = targetSelection.read();
  req._detectionStart = Date.now();
  req.experimentRunId = ENABLE_EXPERIMENT_RUN_ID
    ? sanitizeExperimentRunId(req.headers[EXPERIMENT_RUN_HEADER])
    : null;
  req.authGroupId = deriveAuthGroupId(req.headers.authorization);
  req.accountIdentity = accountIdentityResolver.inspectAuthorization(req.headers.authorization);
  req.hasAuthorization = typeof req.headers.authorization === "string";
  req.detectionHeaders = store.withoutSensitiveHeaders(req.headers);
  req.payloadFingerprint = createPayloadFingerprint(
    req.body,
    req.headers["content-type"] || "",
    PAYLOAD_FINGERPRINT_KEY
  );
  req.deceptionEvents = deceptionEngine.inspectRequest({
    sessionId: req.detectionSessionId,
    method: req.method,
    url: req.originalUrl,
    rawBody: req.detectionRequestBodyBuffer,
    body: req.body,
  });
  req.backgroundTraffic = classifyBackgroundTraffic(req.originalUrl);
  const normalizedPath = normalizePath(req.originalUrl);
  req.blTags = computeBusinessLogicTags(req);
  req.csrfTags = computeCsrfTags(req);
  req.loginAttemptEmail = extractLoginAttemptEmail({
    method: req.method,
    normalizedPath,
    body: req.body,
  });
  req.resetPasswordEmail = extractResetPasswordEmail({
    method: req.method,
    normalizedPath,
    body: req.body,
  });
  req.securityQuestionEmail = extractSecurityQuestionEmail({
    method: req.method,
    normalizedPath,
    url: req.originalUrl,
  });
}

// Stored XSS 대조용 저장소: 쓰기 요청에서 관찰한 값을 나중 응답과 대조한다.
// 기본은 SQLite(파일) 저장 → 재시작해도 후보 텍스트가 보존된다(/app/data 영속 볼륨).
// node:sqlite 미지원(예: node20) 또는 오류 시 자동으로 인메모리로 폴백(서버는 항상 기동).
// 환경변수: XSS_STORE=memory 로 인메모리 강제, XSS_DB_PATH 로 DB 경로 지정.
const xssStoreOpts = {
  ttlMs: process.env.XSS_CANDIDATE_TTL_MS,
  maxEntries: process.env.XSS_MAX_CANDIDATES,
  maxBytes: process.env.XSS_MAX_CANDIDATE_BYTES,
  maxValueBytes: process.env.XSS_MAX_VALUE_BYTES,
};
let xssCandidateStore;
if (String(process.env.XSS_STORE || "sqlite").toLowerCase() === "memory") {
  xssCandidateStore = new XssCandidateStore(xssStoreOpts);
  console.log("[detection] XSS candidate store: in-memory (XSS_STORE=memory)");
} else {
  try {
    const fsMod = require("fs");
    const pathMod = require("path");
    const dbPath = process.env.XSS_DB_PATH || pathMod.join(__dirname, "data", "xss-candidates.db");
    fsMod.mkdirSync(pathMod.dirname(dbPath), { recursive: true });
    const { XssCandidateStoreSqlite } = require("./lib/xssCandidateStoreSqlite");
    xssCandidateStore = new XssCandidateStoreSqlite({ ...xssStoreOpts, dbPath });
    console.log("[detection] XSS candidate store: SQLite(file) -> " + dbPath);
  } catch (e) {
    xssCandidateStore = new XssCandidateStore(xssStoreOpts);
    console.warn("[detection] SQLite 사용 불가 → 인메모리 폴백:", e && e.message);
  }
}

// XSS 증거(확정 stored / reflected) 영속 저장소 — 각각 별도 DB 파일.
// 후보(candidate)는 detect-once로 제거되므로, 실제 탐지된 증거는 여기 별도 보존(재시작에도 유지).
let xssEvidenceStore;
{
  const evOpts = {
    maxConfirmed: Number(process.env.XSS_MAX_CONFIRMED) || 1000,
    maxReflected: Number(process.env.XSS_MAX_REFLECTED) || 1000,
  };
  if (String(process.env.XSS_STORE || "sqlite").toLowerCase() === "memory") {
    xssEvidenceStore = new XssEvidenceStore(evOpts);
    console.log("[detection] XSS evidence store: in-memory (XSS_STORE=memory)");
  } else {
    try {
      const fsMod = require("fs");
      const pathMod = require("path");
      const confirmedDbPath = process.env.XSS_CONFIRMED_DB_PATH || pathMod.join(__dirname, "data", "xss-confirmed.db");
      const reflectedDbPath = process.env.XSS_REFLECTED_DB_PATH || pathMod.join(__dirname, "data", "xss-reflected.db");
      fsMod.mkdirSync(pathMod.dirname(confirmedDbPath), { recursive: true });
      fsMod.mkdirSync(pathMod.dirname(reflectedDbPath), { recursive: true });
      xssEvidenceStore = new XssEvidenceStore({ ...evOpts, confirmedDbPath, reflectedDbPath });
      console.log("[detection] XSS evidence store: SQLite -> 확정:" + confirmedDbPath + " · reflected:" + reflectedDbPath
        + (xssEvidenceStore.persistent ? "" : " (인메모리 폴백)"));
    } catch (e) {
      xssEvidenceStore = new XssEvidenceStore(evOpts);
      console.warn("[detection] XSS 증거 저장소 SQLite 불가 → 인메모리 폴백:", e && e.message);
    }
  }
}
// payload 원문은 그대로 노출하지 않고 짧게 잘라 미리보기만.
const xssPreview = (v) => { const s = String(v || ""); return s.length > 120 ? s.slice(0, 120) + "…" : s; };
// XSS 반영 검사에 넘길 응답 본문 최대 크기(과대 응답은 body 검사 생략, 헤더 검사만).
const configuredXssBodyBytes = Number(process.env.XSS_MAX_BODY_BYTES);
const XSS_MAX_BODY_BYTES = Number.isSafeInteger(configuredXssBodyBytes) && configuredXssBodyBytes > 0
  ? configuredXssBodyBytes : 2_000_000;
const XSS_WRITE_METHODS = new Set(["POST", "PUT", "PATCH"]);

// Reflected/Stored XSS: 요청 값이 이 응답에 이스케이프 없이 반영됐는지 검사한다.
function computeXssDetection(req, responseBuffer, responseHeaders) {
  try {
    const method = String(req.method || "").toUpperCase();
    const xssReq = {
      method,
      url: req.originalUrl,
      body: req.body,
      contentType: req.headers["content-type"],
      responseContentType: responseHeaders && responseHeaders["content-type"],
    };
    const body =
      Buffer.isBuffer(responseBuffer) && responseBuffer.length <= XSS_MAX_BODY_BYTES
        ? responseBuffer.toString("utf8")
        : "";
    const result = analyzeXssExchange(xssReq, body, responseHeaders || {}, xssCandidateStore);
    attributeStoredFindings(result.findings, {
      attachFinding: store.attachStoredXssFinding,
      refreshOrigin: refreshXssOriginScores,
    });
    // 탐지된 증거를 영속 저장소에 기록(확정 stored = 심은 자, reflected = 보낸 요청).
    for (const f of result.findings || []) {
      if (f.vulnerabilityType === "stored") xssEvidenceStore.recordConfirmed(f);
      else if (f.vulnerabilityType === "reflected") {
        xssEvidenceStore.recordReflected(f, { endpoint: normalizePath(req.originalUrl) });
      }
    }
    return result.reflected;
  } catch {
    return { tags: [], maxRisk: 0 };
  }
}

function refreshXssOriginScores(origin) {
  const session = store.getSession(origin.sessionId);
  const actor = store.getActor(origin.actorId);
  const authGroup = store.getAuthGroup(origin.authGroupId);
  const flow = store.getClientFlowAggregate(origin.clientFlowId);
  const resolved = origin.resolvedActorId
    ? store.getResolvedActorAggregate(origin.resolvedActorId) : null;
  const sessionAnalysis = session ? analyzeSession(session) : null;
  const resolvedAnalysis = resolved?.totalRequests ? analyzeResolvedActor(resolved) : null;
  store.updateAttackScoreHistory({
    ...origin,
    scores: {
      session: sessionAnalysis?.attackScore,
      actor: actor ? analyzeActor(actor).attackScore : undefined,
      resolved: resolvedAnalysis?.attackScore,
      authGroup: authGroup ? analyzeAuthGroup(authGroup).attackScore : undefined,
      clientFlow: flow?.aggregationEnabled ? analyzeClientFlow(flow).attackScore : undefined,
    },
  });
  if (sessionAnalysis) store.attachDetectionResult(origin, {
    source: "stored-xss-writer",
    automationScore: sessionAnalysis.automationScore,
    attackScore: sessionAnalysis.attackScore,
    effectiveAttackScore: sessionAnalysis.detection?.effectiveAttackScore || 0,
    automationDetected: Boolean(sessionAnalysis.detection?.automationDetected),
    attackDetected: Boolean(sessionAnalysis.detection?.attackDetected),
  });
}

function observeXssWrite(req, session, status) {
  if (!XSS_WRITE_METHODS.has(String(req.method).toUpperCase()) || status < 200 || status >= 400) return;
  const origin = session.requests.at(-1);
  if (!origin) return;
  xssCandidateStore.observe(extractXssCandidates({
    url: req.originalUrl,
    body: req.body,
    contentType: req.headers["content-type"],
  }), normalizePath(req.originalUrl), origin);
}

function recordCompletedRequest(req, {
  status,
  responseContentType = null,
  responseContentLength = null,
  responseBodyBytes = null,
  responseTransportOutcome = null,
  responseBodyInspected = null,
  attackDetection,
}) {
  const ip = getClientIp(req);
  const detection = attackDetection || {
    available: false,
    error: "scan was not started",
    categories: [],
    hits: [],
  };
  const tags = detection.available ? detection.categories : tagPayload(req.originalUrl, req.body);
  const normalizedPath = normalizePath(req.originalUrl);
  // A partial upstream response must not teach the schema learner that a
  // write succeeded just because its HTTP headers contained a 2xx status.
  if (responseTransportOutcome !== "error") observeSchemaLearning(req, status, normalizedPath);
  const session = store.recordRequest(req.detectionSessionId, ip, {
    method: req.method,
    url: req.originalUrl,
    status,
    headers: req.detectionHeaders,
    rawHeaders: req.rawHeaders,
    httpVersion: req.httpVersion,
    body: deceptionEngine.redactBodyForLog(req.body),
    tags,
    blTags: req.blTags,
    csrfTags: req.csrfTags,
    xssTags: req.xssTags,
    xssMaxRisk: Number.isFinite(req.xssMaxRisk) ? req.xssMaxRisk : 0,
    loginAttemptEmail: req.loginAttemptEmail,
    resetPasswordEmail: req.resetPasswordEmail,
    securityQuestionEmail: req.securityQuestionEmail,
    authGroupId: req.authGroupId,
    payloadFingerprint: req.payloadFingerprint,
    hasAuthorization: req.hasAuthorization,
    experimentRunId: req.experimentRunId,
    targetId: req.activeTarget?.targetId || null,
    targetRunId: req.activeTarget?.runId || null,
    requestContentType: sanitizeMetadataHeaderValue(req.headers["content-type"]),
    requestContentLength: parseContentLength(req.headers["content-length"]),
    requestBodyBytes: Number.isSafeInteger(req.detectionRequestBodyBytes)
      ? req.detectionRequestBodyBytes
      : null,
    responseContentType: sanitizeMetadataHeaderValue(responseContentType),
    responseContentLength: Number.isSafeInteger(responseContentLength)
      ? responseContentLength
      : parseContentLength(responseContentLength),
    responseBodyBytes,
    responseTransportOutcome,
    responseBodyInspected,
    attackDetection: detection,
    backgroundTraffic: req.backgroundTraffic,
    deceptionEvents: req.deceptionEvents,
    requestId: req.rubyRequestId || null,
    policyDecision: req.rubyPolicyDecision ? {
      basis: "prior-completed-requests",
      source: req.rubyPolicyDecision.source,
      automationScore: req.rubyPolicyDecision.automationScore,
      attackScore: req.rubyPolicyDecision.attackScore,
      confirmedAttackScore: req.rubyPolicyDecision.confirmedAttackScore,
      riskScore: req.rubyPolicyDecision.riskScore,
      strategies: (req.rubyPolicyDecision.plan || []).map((step) => step.name),
    } : null,
    defenseSignal: req.defenseSignal || null,
    clientIdentity: req.clientIdentity,
    accountIdentity: req.accountIdentity,
  });

  const sessionAnalysis = analyzeSession(session);
  const actorId = session.requests.at(-1)?.actorId;
  const actor = actorId ? store.getActor(actorId) : null;
  const actorAnalysis = actor ? analyzeActor(actor) : sessionAnalysis;
  const authGroup = req.authGroupId ? store.getAuthGroup(req.authGroupId) : null;
  const authGroupAnalysis = authGroup ? analyzeAuthGroup(authGroup) : null;
  const resolvedActorId = session.requests.at(-1)?.resolvedActorId;
  const resolvedActor = resolvedActorId
    ? store.getResolvedActorAggregate(resolvedActorId)
    : null;
  const resolvedActorAnalysis = resolvedActor ? analyzeResolvedActor(resolvedActor) : null;
  const clientFlowId = session.requests.at(-1)?.clientFlowId;
  const clientFlowState = clientFlowId ? store.getClientFlowState(clientFlowId) : null;
  const clientFlowAnalysis = clientFlowState?.aggregationEnabled
    ? analyzeClientFlow(store.getClientFlowAggregate(clientFlowId))
    : null;
  // The per-request result must describe this client's own evidence. Candidate,
  // Flow and Auth Group are useful observations, but can contain another user
  // with the same NAT/fingerprint or an unverified Bearer value. Include this
  // request's provisional actor so its first response is also attributed only
  // to the DCID issued for that request.
  const requestRecord = session.requests.at(-1);
  const requestActor = resolvedActorId
    ? store.getResolvedActorAggregate(resolvedActorId, { includeProvisional: true })
    : null;
  const requestActorAnalysis = requestActor?.requests.length
    ? analyzeResolvedActor(requestActor) : null;
  const effectiveDetectionSource = requestActorAnalysis
    ? requestRecord.clientContinuityVerified
      ? "confirmed-resolved-actor" : "provisional-client-observation"
    : "session";
  const effectiveDetectionAnalysis = requestActorAnalysis || sessionAnalysis;
  store.updateAttackScoreHistory({
    sessionId: session.id,
    actorId,
    resolvedActorId,
    authGroupId: req.authGroupId,
    clientFlowId,
    scores: {
      session: sessionAnalysis.attackScore,
      actor: actorAnalysis.attackScore,
      resolved: resolvedActorAnalysis?.attackScore,
      authGroup: authGroupAnalysis?.attackScore,
      clientFlow: clientFlowAnalysis?.attackScore,
    },
  });
  store.attachDetectionResult(session.requests.at(-1), {
    source: effectiveDetectionSource,
    automationScore: effectiveDetectionAnalysis.automationScore,
    attackScore: effectiveDetectionAnalysis.attackScore,
    effectiveAttackScore: effectiveDetectionAnalysis.detection?.effectiveAttackScore || 0,
    automationDetected: Boolean(effectiveDetectionAnalysis.detection?.automationDetected),
    attackDetected: Boolean(effectiveDetectionAnalysis.detection?.attackDetected),
  });
  return {
    session,
    sessionAnalysis,
    actorAnalysis,
    authGroupAnalysis,
    clientFlowAnalysis,
    resolvedActorAnalysis,
    effectiveDetectionSource,
    effectiveDetectionAnalysis,
  };
}

// 세션 쿠키 부여 (없으면 새로 발급)
app.use((req, res, next) => {
  let sid = req.cookies[SESSION_COOKIE];
  if (!sid) {
    sid = crypto.randomUUID();
    res.cookie(SESSION_COOKIE, sid, { httpOnly: false, sameSite: "lax" });
  }
  req.detectionSessionId = sid;
  next();
});

// dlsid와 별도로 서명된 지속 Client ID를 검증한다. 잘못된 값은 연결 근거로
// 사용하지 않고 즉시 새 dcid를 발급한다. HMAC secret 자체는 클라이언트에 노출되지 않는다.
app.use((req, res, next) => {
  const verification = dcidManager.verify(req.cookies[DCID_COOKIE]);
  if (verification.valid) {
    req.clientIdentity = verification;
    return next();
  }
  const issued = dcidManager.issue();
  req.clientIdentity = {
    ...issued.identity,
    replacedReason: verification.reason,
  };
  res.cookie(DCID_COOKIE, issued.value, dcidManager.cookieOptions(issued.identity));
  next();
});

app.use((req, res, next) => {
  req.rubyRequestId = `request:${crypto.randomUUID()}`;
  res.setHeader("X-Ruby-Request-Id", req.rubyRequestId);
  next();
});

function captureParsedBodyBytes(req, _res, buffer) {
  req.detectionRequestBodyBytes = buffer.length;
  req.detectionRequestBodyBuffer = Buffer.from(buffer);
}

// JSON / urlencoded body만 파싱 (multipart, 바이너리 등은 그대로 통과되어 스트림이 안 깨짐).
// 파싱된 body는 onProxyReq에서 fixRequestBody()로 다시 스트림에 실어 upstream으로 전달한다.
app.use(express.json({ limit: "5mb", verify: captureParsedBodyBytes }));
app.use(express.urlencoded({ extended: true, limit: "5mb", verify: captureParsedBodyBytes }));

// 대상 페이지에 삽입되는 telemetry만 공개하고, 운영 UI/API는 별도 세션으로 보호한다.
installDashboardRoutes({
  app,
  authManager: dashboardAuth,
  cookieName: DETECTION_DASHBOARD_SESSION_COOKIE,
  sessionTtlMs: DETECTION_DASHBOARD_SESSION_TTL_MS,
  secureCookie: DETECTION_DASHBOARD_COOKIE_SECURE,
  requireHttps: DETECTION_DASHBOARD_REQUIRE_HTTPS,
});

installTargetSelectionRoutes({ app, targetSelection });

// 팀원 Python 프록시의 미끼 라우트를 현재 Express 프록시 안에서 직접 처리한다.
// 이 요청도 일반 요청과 동일하게 CRS, Session, Actor, Auth Group과 타임라인에 기록한다.
app.use((req, res, next) => {
  const trap = deceptionEngine.matchTrap({
    sessionId: req.detectionSessionId,
    method: req.method,
    url: req.originalUrl,
    rawBody: req.detectionRequestBodyBuffer,
    body: req.body,
  });
  if (!trap) return next();

  prepareRequestObservation(req);
  req.deceptionEvents.push(...trap.events);
  const responseBuffer = Buffer.from(trap.body, "utf8");
  crsScanner.scan(req, getClientIp(req)).then((attackDetection) => {
    recordCompletedRequest(req, {
      status: trap.status,
      responseContentType: trap.contentType,
      responseContentLength: responseBuffer.length,
      responseBodyBytes: responseBuffer.length,
      attackDetection,
    });
    res.status(trap.status).type(trap.contentType).send(responseBuffer);
  }).catch(next);
});

app.post("/__detection/telemetry", (req, res) => {
  const ip = getClientIp(req);
  store.recordTelemetry(req.detectionSessionId, ip, req.body || {});
  res.status(204).end();
});

// 탐지 담당자용: XSS 후보/확정/reflected 조회 + 관리자 삭제·상태.
app.get("/__detection/api/xss/candidates", (_req, res) => {
  let items = [];
  try {
    items = (xssCandidateStore.all() || []).map((c) => ({
      value: c.value, payloadPreview: xssPreview(c.value), parameter: c.parameter,
      endpoint: c.endpoint, originSession: c.origin && c.origin.sessionId,
      firstSeenAt: c.firstSeen ? new Date(c.firstSeen).toISOString() : null,
      lastSeenAt: c.lastSeen ? new Date(c.lastSeen).toISOString() : null, timesSeen: c.timesSeen,
    }));
  } catch (_) {}
  res.json({ count: items.length, items });
});
app.get("/__detection/api/xss/confirmed", (_req, res) => {
  const items = xssEvidenceStore.confirmedList().map((c) => ({
    value: c.value, payloadPreview: xssPreview(c.value), parameter: c.parameter,
    severity: c.severity, riskScore: c.riskScore, originSession: c.originSession,
    endpoint: c.endpoint, status: c.status || "open", note: c.note || "",
    firstAt: c.firstAt ? new Date(c.firstAt).toISOString() : null,
    lastAt: c.lastAt ? new Date(c.lastAt).toISOString() : null, times: c.times,
  }));
  res.json({ count: items.length, persistent: xssEvidenceStore.persistent, items });
});
app.get("/__detection/api/xss/reflected", (_req, res) => {
  const items = xssEvidenceStore.reflectedList().map((c) => ({
    value: c.value, payloadPreview: xssPreview(c.value), parameter: c.parameter,
    severity: c.severity, riskScore: c.riskScore, originSession: c.originSession,
    endpoint: c.endpoint,
    firstAt: c.firstAt ? new Date(c.firstAt).toISOString() : null,
    lastAt: c.lastAt ? new Date(c.lastAt).toISOString() : null, times: c.times,
  }));
  res.json({ count: items.length, items });
});
app.post("/__detection/api/xss/confirmed/update", express.json({ limit: "256kb" }), (req, res) => {
  const { value, status, note } = req.body || {};
  if (!value) return res.status(400).json({ ok: false, error: "value required" });
  const allowed = new Set(["open", "investigating", "resolved", "false_positive"]);
  const patch = {};
  if (status !== undefined) patch.status = allowed.has(status) ? status : "open";
  if (note !== undefined) patch.note = String(note).slice(0, 2000);
  res.json({ ok: xssEvidenceStore.updateConfirmed(value, patch) });
});
app.post("/__detection/api/xss/confirmed/delete", express.json({ limit: "256kb" }), (req, res) => {
  const { value } = req.body || {};
  if (!value) return res.status(400).json({ ok: false, error: "value required" });
  res.json({ ok: xssEvidenceStore.removeConfirmed(value) });
});
app.post("/__detection/api/xss/reflected/delete", express.json({ limit: "256kb" }), (req, res) => {
  const { value } = req.body || {};
  if (!value) return res.status(400).json({ ok: false, error: "value required" });
  res.json({ ok: xssEvidenceStore.removeReflected(value) });
});

app.get("/__detection/api/sessions", (req, res) => {
  const result = store.getAllSessions().map((s) => {
    return {
      sessionId: s.id,
      actorId: s.actorId,
      resolvedActorId: s.resolvedActorId,
      clientFlowId: s.clientFlowId,
      ip: s.ip,
      ...analyzeSession(s),
      attackHistory: s.attackHistory,
      deceptionHistory: s.deceptionHistory,
      firstSeen: s.firstSeen,
      lastSeen: s.lastSeen,
    };
  });
  res.json(result);
});

app.get("/__detection/api/sessions/:id", (req, res) => {
  const s = store.getSession(req.params.id);
  if (!s) return res.status(404).json({ error: "not found" });
  res.json({
    sessionId: s.id,
    actorId: s.actorId,
    actorIds: Array.from(s.actorIds),
    resolvedActorId: s.resolvedActorId,
    resolutionMembershipId: s.resolutionMembershipId,
    clientFlowId: s.clientFlowId,
    ip: s.ip,
    ...analyzeSession(s),
    attackHistory: s.attackHistory,
    deceptionHistory: s.deceptionHistory,
    firstSeen: s.firstSeen,
    lastSeen: s.lastSeen,
    requests: s.requests,
  });
});

// 세션의 공격 경로 = 시간순 요청 타임라인 (url, method, status, body, 시그니처 태그)
app.get("/__detection/api/sessions/:id/path", (req, res) => {
  const s = store.getSession(req.params.id);
  if (!s) return res.status(404).json({ error: "not found" });
  res.json({
    sessionId: s.id,
    ip: s.ip,
    userAgent: s.userAgent,
    requests: s.requests, // 이미 시간순으로 push 됨
  });
});

function resolvedActorJson(aggregate, { includeRequests = false, includeMemberships = false } = {}) {
  const analysis = analyzeResolvedActor(aggregate);
  const result = {
    resolvedActorId: aggregate.id,
    status: aggregate.status,
    confidence: aggregate.confidence,
    firstSeen: aggregate.firstSeen,
    lastSeen: aggregate.lastSeen,
    sessionIds: aggregate.sessionIds,
    observedSessionIds: aggregate.observedSessionIds,
    candidateIds: aggregate.candidateIds,
    sessionCount: aggregate.sessionIds.length,
    observedSessionCount: aggregate.observedSessionIds.length,
    candidateCount: aggregate.candidateIds.length,
    confirmedMembershipCount: aggregate.confirmedMemberships.length,
    provisionalMembershipCount: aggregate.provisionalMemberships.length,
    observedIps: aggregate.observedIps,
    ipFirstSeen: aggregate.ipFirstSeen,
    ipLastSeen: aggregate.ipLastSeen,
    ipChangeCount: aggregate.ipChangeCount,
    clientIds: aggregate.clientIds,
    accountAffiliations: aggregate.accountAffiliations,
    authGroupIds: aggregate.authGroupIds,
    evidence: aggregate.evidence,
    conflicts: aggregate.conflicts,
    continuityConfirmed: aggregate.continuityConfirmed,
    observedTotalRequests: aggregate.observedTotalRequests,
    totalRequests: aggregate.totalRequests,
    aggregationPolicy: aggregate.aggregationPolicy,
    attackHistory: aggregate.attackHistory,
    deceptionHistory: aggregate.deceptionHistory,
    ...analysis,
  };
  if (includeMemberships) result.memberships = aggregate.memberships;
  if (includeRequests) result.requests = aggregate.requests;
  return result;
}

app.get("/__detection/api/resolved-actors", (req, res) => {
  res.json(store.getAllResolvedActorAggregates().map((aggregate) => resolvedActorJson(aggregate)));
});

app.get("/__detection/api/resolved-actors/:id", (req, res) => {
  const aggregate = store.getResolvedActorAggregate(req.params.id);
  if (!aggregate) return res.status(404).json({ error: "not found" });
  res.json(resolvedActorJson(aggregate, { includeRequests: true, includeMemberships: true }));
});

app.get("/__detection/api/resolved-actors/:id/path", (req, res) => {
  const aggregate = store.getResolvedActorAggregate(req.params.id);
  if (!aggregate) return res.status(404).json({ error: "not found" });
  res.json({
    resolvedActorId: aggregate.id,
    aggregationPolicy: aggregate.aggregationPolicy,
    sessionIds: aggregate.sessionIds,
    candidateIds: aggregate.candidateIds,
    requests: aggregate.requests,
  });
});

app.get("/__detection/api/resolved-actors/:id/memberships", (req, res) => {
  const memberships = store.getResolutionMemberships(req.params.id);
  if (!memberships) return res.status(404).json({ error: "not found" });
  res.json({ resolvedActorId: req.params.id, memberships });
});

function clientFlowJson(aggregate, { includeRequests = false } = {}) {
  const analysis = analyzeClientFlow(aggregate);
  const candidates = aggregate.candidateIds.map((candidateId) => store.getActor(candidateId)).filter(Boolean);
  const candidateAnalyses = candidates.map(analyzeActor);
  const result = {
    clientFlowId: aggregate.id,
    status: aggregate.status,
    confidence: aggregate.confidence,
    similarityVersion: aggregate.similarityVersion,
    aggregationPolicy: aggregate.aggregationPolicy,
    aggregationEnabled: aggregate.aggregationEnabled,
    flowLinked: aggregate.flowLinked,
    verifiedClientCount: aggregate.verifiedClientCount,
    scoringApplied: aggregate.aggregationEnabled,
    anchorCandidateId: aggregate.anchorCandidateId,
    candidateIds: aggregate.candidateIds,
    candidateCount: aggregate.candidateCount,
    sessionIds: aggregate.sessionIds,
    sessionCount: aggregate.sessionCount,
    resolvedActorIds: [...new Set(aggregate.requests.map((request) => request.resolvedActorId).filter(Boolean))],
    observedIps: aggregate.observedIps,
    links: aggregate.links,
    conflicts: aggregate.conflicts,
    clientObservation: aggregate.clientObservation,
    firstSeen: aggregate.firstSeen,
    lastSeen: aggregate.lastSeen,
    totalRequests: aggregate.totalRequests,
    preMergeAutomationScore: Math.max(0, ...candidateAnalyses.map((item) => item.automationScore || 0)),
    preMergeAttackScore: Math.max(0, ...candidateAnalyses.map((item) => item.attackScore || 0)),
    attackHistory: aggregate.attackHistory,
    deceptionHistory: aggregate.deceptionHistory,
    ...analysis,
  };
  if (includeRequests) result.requests = aggregate.requests;
  return result;
}

app.get("/__detection/api/client-flows", (_req, res) => {
  res.json(store.getAllClientFlowAggregates().map((aggregate) => clientFlowJson(aggregate)));
});

app.get("/__detection/api/client-flows/:id", (req, res) => {
  const aggregate = store.getClientFlowAggregate(req.params.id);
  if (!aggregate) return res.status(404).json({ error: "not found" });
  res.json(clientFlowJson(aggregate, { includeRequests: true }));
});

app.get("/__detection/api/client-flows/:id/path", (req, res) => {
  const aggregate = store.getClientFlowAggregate(req.params.id);
  if (!aggregate) return res.status(404).json({ error: "not found" });
  res.json({
    clientFlowId: aggregate.id,
    aggregationPolicy: aggregate.aggregationPolicy,
    candidateIds: aggregate.candidateIds,
    sessionIds: aggregate.sessionIds,
    links: aggregate.links,
    requests: aggregate.requests,
  });
});

app.get("/__detection/api/actors", (req, res) => {
  const result = store.getAllActors().map((actor) => {
    const flow = store.getClientFlowState(actor.id);
    return {
      actorId: actor.id,
      resolvedActorIds: [...new Set(actor.requests.map((request) => request.resolvedActorId).filter(Boolean))],
      unresolvedRequestCount: actor.requests.filter((request) => !request.resolvedActorId).length,
      ip: actor.ip,
      fingerprint: actor.fingerprint,
      clientObservation: actor.clientObservation,
      clientFlow: flow && flow.flowLinked ? {
        clientFlowId: flow.id,
        status: flow.status,
        aggregationEnabled: flow.aggregationEnabled,
        candidateCount: flow.candidateCount,
        sessionCount: flow.sessionCount,
        links: flow.links,
      } : null,
      ...analyzeActor(actor),
      attackHistory: actor.attackHistory,
      deceptionHistory: actor.deceptionHistory,
      totalRequests: actor.totalRequests,
      sessionCount: actor.sessionIds.size,
      firstSeen: actor.firstSeen,
      lastSeen: actor.lastSeen,
    };
  });
  res.json(result);
});

app.get("/__detection/api/actors/:id", (req, res) => {
  const actor = store.getActor(req.params.id);
  if (!actor) return res.status(404).json({ error: "not found" });
  const flow = store.getClientFlowState(actor.id);
  res.json({
    actorId: actor.id,
    resolvedActorIds: [...new Set(actor.requests.map((request) => request.resolvedActorId).filter(Boolean))],
    unresolvedRequestCount: actor.requests.filter((request) => !request.resolvedActorId).length,
    ip: actor.ip,
    fingerprint: actor.fingerprint,
    clientObservation: actor.clientObservation,
    clientFlow: flow && flow.flowLinked ? {
      clientFlowId: flow.id,
      status: flow.status,
      aggregationEnabled: flow.aggregationEnabled,
      candidateIds: flow.candidateIds,
      sessionIds: flow.sessionIds,
      links: flow.links,
      conflicts: flow.conflicts,
    } : null,
    ...analyzeActor(actor),
    attackHistory: actor.attackHistory,
    deceptionHistory: actor.deceptionHistory,
    firstSeen: actor.firstSeen,
    lastSeen: actor.lastSeen,
    totalRequests: actor.totalRequests,
    sessionCount: actor.sessionIds.size,
    sessionIds: Array.from(actor.sessionIds),
    requests: [...actor.requests].sort((a, b) => a.ts - b.ts),
  });
});

app.get("/__detection/api/actors/:id/path", (req, res) => {
  const actor = store.getActor(req.params.id);
  if (!actor) return res.status(404).json({ error: "not found" });
  res.json({
    actorId: actor.id,
    ip: actor.ip,
    fingerprint: actor.fingerprint,
    sessionCount: actor.sessionIds.size,
    sessionIds: Array.from(actor.sessionIds),
    requests: [...actor.requests].sort((a, b) => a.ts - b.ts),
  });
});

app.get("/__detection/api/auth-groups", (req, res) => {
  const result = store.getAllAuthGroups().map((group) => {
    return {
      authGroupId: group.id,
      resolvedActorIds: [...new Set(group.requests.map((request) => request.resolvedActorId).filter(Boolean))],
      ...analyzeAuthGroup(group),
      attackHistory: group.attackHistory,
      deceptionHistory: group.deceptionHistory,
      totalRequests: group.totalRequests,
      sessionCount: group.sessionIds.size,
      actorCount: group.actorIds.size,
      firstSeen: group.firstSeen,
      lastSeen: group.lastSeen,
    };
  });
  res.json(result);
});

app.get("/__detection/api/auth-groups/:id", (req, res) => {
  const group = store.getAuthGroup(req.params.id);
  if (!group) return res.status(404).json({ error: "not found" });
  res.json({
    authGroupId: group.id,
    resolvedActorIds: [...new Set(group.requests.map((request) => request.resolvedActorId).filter(Boolean))],
    ...analyzeAuthGroup(group),
    attackHistory: group.attackHistory,
    deceptionHistory: group.deceptionHistory,
    firstSeen: group.firstSeen,
    lastSeen: group.lastSeen,
    totalRequests: group.totalRequests,
    sessionCount: group.sessionIds.size,
    sessionIds: Array.from(group.sessionIds),
    actorCount: group.actorIds.size,
    actorIds: Array.from(group.actorIds),
    requests: [...group.requests].sort((a, b) => a.ts - b.ts),
  });
});

// IP Entry는 NAT/Docker 혼합 가능성이 있어 관찰 Feature만 제공하며 점수/차단에 사용하지 않는다.
app.get("/__detection/api/ip-entries", (req, res) => {
  res.json(
    store.getAllIpEntries().map((entry) => ({
      ip: entry.ip,
      totalRequests: entry.totalRequests,
      sessionCount: entry.sessionIds.size,
      actorCandidateCount: entry.actorIds.size,
      firstSeen: entry.firstSeen,
      lastSeen: entry.lastSeen,
      features: extractIpFeatures(entry, store.getSession),
    }))
  );
});

app.get("/__detection/api/ip-entries/:ip", (req, res) => {
  const entry = store.getIpEntry(req.params.ip);
  if (!entry) return res.status(404).json({ error: "not found" });
  res.json({
    ip: entry.ip,
    observationOnly: true,
    totalRequests: entry.totalRequests,
    sessionCount: entry.sessionIds.size,
    sessionIds: Array.from(entry.sessionIds),
    actorCandidateCount: entry.actorIds.size,
    actorIds: Array.from(entry.actorIds),
    firstSeen: entry.firstSeen,
    lastSeen: entry.lastSeen,
    features: extractIpFeatures(entry, store.getSession),
    requests: [...entry.requests].sort((a, b) => a.ts - b.ts),
  });
});

app.get("/__detection/api/crs-status", (req, res) => {
  res.json({
    mode: "detection-only",
    ...crsScanner.status(),
  });
});

app.get("/__detection/api/deception-status", (req, res) => {
  res.json(deceptionEngine.status());
});

app.get("/__detection/api/resolution-status", (req, res) => {
  res.json({
    ...store.getResolutionStatus(),
    dcid: dcidManager.status(),
    accountIdentity: accountIdentityResolver.status(),
    trustProxy: app.get("trust proxy"),
  });
});

// Auth Group의 공격 경로 = 동일 Bearer token을 쓴 모든 세션의 시간순 요청 타임라인
app.get("/__detection/api/auth-groups/:id/path", (req, res) => {
  const group = store.getAuthGroup(req.params.id);
  if (!group) return res.status(404).json({ error: "not found" });
  res.json({
    authGroupId: group.id,
    sessionCount: group.sessionIds.size,
    sessionIds: Array.from(group.sessionIds),
    requests: [...group.requests].sort((a, b) => a.ts - b.ts),
  });
});

// 리포트용 전체 export (세션 1개 또는 전체)
app.get("/__detection/api/export", (req, res) => {
  const result = store.getAllSessions().map((s) => {
    return {
      sessionId: s.id,
      actorId: s.actorId,
      resolvedActorId: s.resolvedActorId,
      clientFlowId: s.clientFlowId,
      ip: s.ip,
      userAgent: s.userAgent,
      firstSeen: s.firstSeen,
      lastSeen: s.lastSeen,
      analysis: analyzeSession(s),
      attackHistory: s.attackHistory,
      deceptionHistory: s.deceptionHistory,
      requests: s.requests,
    };
  });
  res.setHeader("Content-Disposition", "attachment; filename=detection-log-export.json");
  res.json(result);
});

app.get("/__detection/api/schema-learning/candidates", (req, res) => {
  res.json(schemaLearning.listCandidates());
});

app.post("/__detection/api/schema-learning/mass-assignment/approve", (req, res) => {
  const { key, fields } = req.body || {};
  if (!key) return res.status(400).json({ error: "key required" });
  if (!schemaLearning.approveMassAssignment(key, fields)) {
    return res.status(404).json({ error: "candidate not found" });
  }
  res.json({ approved: true, key });
});

app.post("/__detection/api/schema-learning/mass-assignment/reject", (req, res) => {
  const { key } = req.body || {};
  if (!key) return res.status(400).json({ error: "key required" });
  if (!schemaLearning.rejectMassAssignment(key)) {
    return res.status(404).json({ error: "candidate not found" });
  }
  res.json({ rejected: true, key });
});

app.post("/__detection/api/schema-learning/role-gated/approve", (req, res) => {
  const { key, requiredRoles } = req.body || {};
  if (!key) return res.status(400).json({ error: "key required" });
  if (!schemaLearning.approveRoleGated(key, requiredRoles)) {
    return res.status(404).json({ error: "candidate not found" });
  }
  res.json({ approved: true, key });
});

app.post("/__detection/api/schema-learning/role-gated/reject", (req, res) => {
  const { key } = req.body || {};
  if (!key) return res.status(400).json({ error: "key required" });
  if (!schemaLearning.rejectRoleGated(key)) {
    return res.status(404).json({ error: "candidate not found" });
  }
  res.json({ rejected: true, key });
});

app.post("/__detection/api/schema-learning/identity/approve", (req, res) => {
  const { key } = req.body || {};
  if (!key) return res.status(400).json({ error: "key required" });
  if (!schemaLearning.approveIdentityCandidate(key)) {
    return res.status(404).json({ error: "candidate not found" });
  }
  res.json({ approved: true, key });
});

app.post("/__detection/api/schema-learning/identity/reject", (req, res) => {
  const { key } = req.body || {};
  if (!key) return res.status(400).json({ error: "key required" });
  if (!schemaLearning.rejectIdentityCandidate(key)) {
    return res.status(404).json({ error: "candidate not found" });
  }
  res.json({ rejected: true, key });
});

app.post("/__detection/api/schema-learning/reset", (_req, res) => {
  schemaLearning.resetAll();
  res.json({ reset: true });
});

// 등록되지 않은 탐지 내부 경로가 RUBY Policy로 흘러가 탐지 요청으로
// 기록되지 않도록 네임스페이스 전체를 여기서 종료한다.
app.use("/__detection", (req, res) => {
  res.status(404).json({ error: "detection endpoint not found" });
});

function forwardPolicyDecision(proxyReq, req) {
  req.rubyRequestId ||= `request:${crypto.randomUUID()}`;
  req.activeTarget ||= targetSelection.read();
  req.rubyPolicyDecision = buildPriorPolicyDecision(req);
  stripDetectionHeaders(proxyReq);
  const plan = applyDefensePlan(proxyReq, {
    riskScore: req.rubyPolicyDecision.riskScore,
    confirmedAttackScore: req.rubyPolicyDecision.confirmedAttackScore,
    rules: policyRules,
  });
  req.rubyPolicyDecision.plan = plan;
  proxyReq.setHeader("X-Client-Id", req.rubyPolicyDecision.clientId);
  proxyReq.setHeader("X-Ruby-Request-Id", req.rubyRequestId);
  proxyReq.setHeader("X-Ruby-Automation-Score", String(req.rubyPolicyDecision.automationScore));
  proxyReq.setHeader("X-Ruby-Attack-Score", String(req.rubyPolicyDecision.attackScore));
  proxyReq.setHeader("X-Ruby-Risk-Score", String(req.rubyPolicyDecision.riskScore));
  proxyReq.setHeader("X-Ruby-Policy-Source", req.rubyPolicyDecision.source);
  proxyReq.setHeader("X-Ruby-Target-Id", req.activeTarget.targetId);
  proxyReq.setHeader("X-Ruby-Run-Id", req.activeTarget.runId);
}

function upgradeCookie(req, name) {
  for (const part of String(req.headers.cookie || "").split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0 || part.slice(0, separator).trim() !== name) continue;
    try { return decodeURIComponent(part.slice(separator + 1).trim()); } catch { return null; }
  }
  return null;
}

const detectionHook = {
  name: "behavior-and-attack-detection",

  onWebSocketRequest({ proxyReq, req }) {
    req.originalUrl ||= req.url;
    req.isWebSocketUpgrade = true;
    req.detectionSessionId = upgradeCookie(req, SESSION_COOKIE);
    req.clientIdentity = dcidManager.verify(upgradeCookie(req, DCID_COOKIE));
    if (!req.clientIdentity.valid) req.websocketClientId = `websocket:${crypto.randomUUID()}`;
    req.authGroupId = deriveAuthGroupId(req.headers.authorization);
    forwardPolicyDecision(proxyReq, req);
  },

  onRequest({ proxyReq, req }) {
    prepareRequestObservation(req);
    // RUBY Policy 계약: 외부 입력을 제거하고, 완료된 탐지 이력에서 계산한
    // 0~1 risk score와 가명 client id만 내부 헤더로 전달한다.
    forwardPolicyDecision(proxyReq, req);
    // Ground truth용 헤더는 탐지 프록시에서 소비하고 RUBY Policy에는 전달하지 않는다.
    proxyReq.removeHeader(EXPERIMENT_RUN_HEADER);
    // ModSecurity/CRS 검사는 응답을 차단하지 않으며 결과만 비동기로 기록한다.
    req.crsScanPromise = crsScanner.scan(req, getClientIp(req));
    // express.json()/urlencoded()가 body를 이미 읽어버렸다면 upstream으로 다시 실어준다.
    // (안 해주면 로그인/주문 등 POST 요청 body가 Policy에 도달하지 않는다)
    fixRequestBody(proxyReq, req);
  },

  async onResponse({ responseBuffer, proxyRes, req, bodyAvailable = true, responseBodyBytes }) {
    if (req.rubyResponseRecorded) return responseBuffer;
    req.defenseSignal = proxyRes.headers["x-defense-signal"] === "rate_limited"
      ? "rate_limited" : null;
    const attackDetection = req.crsScanPromise
      ? await req.crsScanPromise
      : { available: false, error: "scan was not started", categories: [], hits: [] };
    const xssDetection = computeXssDetection(
      req, bodyAvailable ? responseBuffer : Buffer.alloc(0), proxyRes.headers
    );
    req.xssTags = xssDetection.tags;
    req.xssMaxRisk = xssDetection.maxRisk;
    const {
      session,
      effectiveDetectionSource,
      effectiveDetectionAnalysis,
    } = recordCompletedRequest(req, {
      status: proxyRes.statusCode,
      responseContentType: proxyRes.headers["content-type"],
      responseContentLength: proxyRes.headers["content-length"],
      responseBodyBytes: Number.isSafeInteger(responseBodyBytes)
        ? responseBodyBytes : responseBuffer.length,
      responseTransportOutcome: "complete",
      responseBodyInspected: bodyAvailable && responseBuffer.length <= XSS_MAX_BODY_BYTES,
      attackDetection,
    });
    req.rubyResponseRecorded = true;
    observeXssWrite(req, session, proxyRes.statusCode);

    // 실험 검증 전에는 BLOCK_MODE도 log-only다. 응답 상태나 body를 변경하지 않는다.
    if (BLOCK_MODE) {
      if (
        effectiveDetectionAnalysis.detection?.automationDetected ||
        effectiveDetectionAnalysis.detection?.attackDetected
      ) {
        console.warn(
          `[detection-proxy][log-only] ${effectiveDetectionSource} ` +
          `level=${DETECTION_LEVEL} ` +
          `threshold=${DETECTION_THRESHOLDS[DETECTION_LEVEL]} ` +
          `automationDetected=${effectiveDetectionAnalysis.detection.automationDetected} ` +
          `attackDetected=${effectiveDetectionAnalysis.detection.attackDetected} ` +
          `automation=${effectiveDetectionAnalysis.automationScore} ` +
          `attackCurrent=${effectiveDetectionAnalysis.attackScore} ` +
          `attackMax=${effectiveDetectionAnalysis.detection.effectiveAttackScore}`
        );
      }
    }

    // Streaming and large responses are forwarded as original bytes. Their
    // request/CRS/header evidence is recorded, but no response body claim or
    // injection is made without a complete, bounded body.
    if (!bodyAvailable) return responseBuffer;

    // HTML 응답이면 telemetry.js 를 </body> 직전에 주입
    const contentType = proxyRes.headers["content-type"] || "";
    if (contentType.includes("text/html")) {
      const htmlWithDeception = deceptionEngine.injectSignals(
        responseBuffer.toString("utf8"),
        session.id
      );
      const injected = htmlWithDeception.includes("</body>")
        ? htmlWithDeception.replace(
            "</body>",
            '<script src="/__detection/static/telemetry.js"></script></body>'
          )
        : htmlWithDeception + '<script src="/__detection/static/telemetry.js"></script>';
      return injected;
    }

    const normalizedPath = normalizePath(req.originalUrl);
    if (
      String(req.method).toUpperCase() === "GET" &&
      (normalizedPath === PRODUCTS_LIST_PATH || normalizedPath === PRODUCTS_ITEM_PATH) &&
      contentType.includes("application/json")
    ) {
      try {
        ingestProductResponseBody(JSON.parse(responseBuffer.toString("utf8")));
      } catch {
        // 가격 기준 캐시는 관찰 가능한 정상 JSON 응답만 best-effort로 반영한다.
      }
    }

    // 2026-09-01 추가: HTML(index.html) 하나만 보는 게 아니라, 정찰 목적으로
    // 자주 조회되는 다른 정적 텍스트 응답(포맷 자체가 "#"/"//" 주석을
    // 지원하는 곳)에도 같은 신호를 심는다 — deceptionEngine.injectSignals*
    // 참고 주석.
    if (PLAINTEXT_BAIT_PATHS.has(req.path)) {
      return deceptionEngine.injectSignalsPlaintext(responseBuffer.toString("utf8"), session.id);
    }
    if (req.path.endsWith(".js") || contentType.includes("javascript")) {
      return deceptionEngine.injectSignalsJs(responseBuffer.toString("utf8"), session.id);
    }

    return responseBuffer;
  },

  async onResponseError({ req, proxyRes, responseBodyBytes }) {
    if (req.rubyResponseRecorded || !req._detectionPrepared) return;
    req.defenseSignal = proxyRes?.headers?.["x-defense-signal"] === "rate_limited"
      ? "rate_limited" : null;
    const attackDetection = req.crsScanPromise
      ? await req.crsScanPromise
      : { available: false, error: "scan was not started", categories: [], hits: [] };
    // Keep the observed status but mark the transport as incomplete; 502 is
    // used only when upstream never sent headers. Never log raw error text.
    recordCompletedRequest(req, {
      status: proxyRes?.statusCode || 502,
      responseContentType: proxyRes?.headers?.["content-type"],
      responseContentLength: proxyRes?.headers?.["content-length"],
      responseBodyBytes: Number.isSafeInteger(responseBodyBytes) ? responseBodyBytes : 0,
      responseTransportOutcome: "error",
      responseBodyInspected: false,
      attackDetection,
    });
    req.rubyResponseRecorded = true;
  },
};

// 공통 Express 프록시 코어에 탐지와 정책 훅을 함께 장착한다. TARGET_URL은
// Defense 또는 보호할 애플리케이션을 직접 가리키며, 별도 Policy 프록시는 없다.
const mainProxy = createProxyCore({ target: TARGET, hooks: [detectionHook] });
app.use("/", mainProxy);

const server = app.listen(PORT, () => {
  console.log(`[detection-proxy] listening on :${PORT} -> proxying ${TARGET}`);
  console.log(`[detection-proxy] dashboard: http://localhost:${ADMIN_PORT || PORT}/__detection/dashboard`);
  console.log(
    `[detection-proxy] BLOCK_MODE=${BLOCK_MODE} (log-only) ` +
    `level=${DETECTION_LEVEL} threshold=${DETECTION_THRESHOLDS[DETECTION_LEVEL]}`
  );
  console.log(`[detection-proxy] experiment run header enabled=${ENABLE_EXPERIMENT_RUN_ID}`);
  console.log(`[detection-proxy] trust proxy=${JSON.stringify(app.get("trust proxy"))}`);
  console.log(`[detection-proxy] DCID status=${JSON.stringify(dcidManager.status())}`);
  console.log(`[detection-proxy] Account identity status=${JSON.stringify(accountIdentityResolver.status())}`);
  console.log(`[detection-proxy] Resolution status=${JSON.stringify(store.getResolutionStatus())}`);
  console.log(`[detection-proxy] CRS status=${JSON.stringify(crsScanner.status())}`);
  console.log(`[detection-proxy] Deception status=${JSON.stringify(deceptionEngine.status())}`);
  if (!configuredPayloadFingerprintKey) {
    console.warn(
      "[detection-proxy] PAYLOAD_FINGERPRINT_KEY is unset; using an ephemeral key (fingerprints change after restart)"
    );
  }
});
if (ADMIN_PORT) {
  app.listen(ADMIN_PORT, () => {
    console.log(`[detection-proxy] management listening on :${ADMIN_PORT}`);
  });
}
server.on("upgrade", (req, socket, head) => {
  const path = String(req.url || "").split("?", 1)[0];
  if (path === "/__detection" || path.startsWith("/__detection/") ||
      path === "/__defense" || path.startsWith("/__defense/")) {
    socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    return;
  }
  mainProxy.upgrade(req, socket, head);
});
