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
const { selectClientId, selectEffectiveDetection } = require("./lib/detectionPolicy");
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

const PORT = process.env.PORT || 8080;
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
const CSRF_ALLOWED_ORIGINS = buildAllowedOrigins(
  (process.env.CSRF_ALLOWED_ORIGINS || `http://localhost:${PORT},http://127.0.0.1:${PORT}`)
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean)
);

const SESSION_COOKIE = "dlsid";
const DCID_COOKIE = "dcid";
const crsScanner = new CrsScanner();
const deceptionEngine = new DeceptionEngine();
const dcidManager = new DcidManager();
const accountIdentityResolver = new AccountIdentityResolver();
const policyRules = loadPolicyRules();

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", parseTrustProxy());
app.use(cookieParser());

// Docker Compose와 운영 오케스트레이터가 Detection 자체의 준비 상태를
// downstream 애플리케이션과 독립적으로 확인할 수 있는 엔드포인트다.
app.get("/healthz", (_req, res) => {
  res.json({ status: "ok", service: "detection" });
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
  const baseAnalysis = classify(features);
  const repetitionBonusPoints = Number(aggregate.attackRepetition?.bonusPoints) || 0;
  const analysis = {
    ...baseAnalysis,
    baseAttackScore: baseAnalysis.attackScore,
    attackScore: Math.min(1, Number((baseAnalysis.attackScore + repetitionBonusPoints / 100).toFixed(3))),
    attackRepetition: aggregate.attackRepetition,
  };
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
  const resolvedActor = session?.resolvedActorId
    ? store.getResolvedActorAggregate(session.resolvedActorId)
    : null;
  // 전체 집계는 요청을 훑으므로 병합 또는 반복 공격 근거가 있을 때만 계산한다.
  const clientFlowState = store.getClientFlowPolicyState(actorId);
  const clientFlow = clientFlowState?.aggregationEnabled || clientFlowState?.attackRepetition?.bonusPoints > 0
    ? store.getClientFlowAggregate(actorId)
    : null;

  const analyses = {
    session: session ? analyzeSession(session) : null,
    candidate: actor && clientFlowState?.status !== "CONFLICT" ? analyzeActor(actor) : null,
    authGroup: authGroup ? analyzeAuthGroup(authGroup) : null,
    clientFlow: clientFlow ? analyzeClientFlow(clientFlow) : null,
    resolved: resolvedActor ? analyzeResolvedActor(resolvedActor) : null,
  };
  if (!Object.values(analyses).some(Boolean)) {
    return buildPolicyDecision({ clientId: actorId });
  }

  const [source, analysis] = selectEffectiveDetection(analyses);
  const clientId = selectClientId(analyses, {
    actorId,
    resolvedActorId: resolvedActor?.id,
    clientFlowId: clientFlowState?.id,
  });
  return buildPolicyDecision({ source, analysis, clientId });
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

function recordCompletedRequest(req, {
  status,
  responseContentType = null,
  responseContentLength = null,
  responseBodyBytes = null,
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
  observeSchemaLearning(req, status, normalizedPath);
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
    loginAttemptEmail: req.loginAttemptEmail,
    resetPasswordEmail: req.resetPasswordEmail,
    securityQuestionEmail: req.securityQuestionEmail,
    authGroupId: req.authGroupId,
    payloadFingerprint: req.payloadFingerprint,
    hasAuthorization: req.hasAuthorization,
    experimentRunId: req.experimentRunId,
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
    attackDetection: detection,
    backgroundTraffic: req.backgroundTraffic,
    deceptionEvents: req.deceptionEvents,
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
  const clientFlowState = clientFlowId ? store.getClientFlowPolicyState(clientFlowId) : null;
  const clientFlowAnalysis = clientFlowState?.aggregationEnabled || clientFlowState?.attackRepetition?.bonusPoints > 0
    ? analyzeClientFlow(store.getClientFlowAggregate(clientFlowId))
    : null;
  const [effectiveDetectionSource, effectiveDetectionAnalysis] = selectEffectiveDetection({
    session: sessionAnalysis,
    candidate: clientFlowState?.status === "CONFLICT" ? null : actorAnalysis,
    authGroup: authGroupAnalysis,
    clientFlow: clientFlowAnalysis,
    resolved: resolvedActorAnalysis,
  });
  store.updateAttackScoreHistory({
    sessionId: session.id,
    actorId,
    authGroupId: req.authGroupId,
    clientFlowId,
    scores: {
      session: sessionAnalysis.attackScore,
      actor: actorAnalysis.attackScore,
      authGroup: authGroupAnalysis?.attackScore,
      clientFlow: clientFlowAnalysis?.attackScore,
    },
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

// --- 탐지 레이어 자체 엔드포인트들 (프록시보다 먼저 매칭) ---
app.use("/__detection/static", express.static(require("path").join(__dirname, "public")));

app.get("/__detection/dashboard", (req, res) => {
  res.sendFile(require("path").join(__dirname, "public", "dashboard.html"));
});

function captureParsedBodyBytes(req, _res, buffer) {
  req.detectionRequestBodyBytes = buffer.length;
  req.detectionRequestBodyBuffer = Buffer.from(buffer);
}

// JSON / urlencoded body만 파싱 (multipart, 바이너리 등은 그대로 통과되어 스트림이 안 깨짐).
// 파싱된 body는 onProxyReq에서 fixRequestBody()로 다시 스트림에 실어 upstream으로 전달한다.
app.use(express.json({ limit: "5mb", verify: captureParsedBodyBytes }));
app.use(express.urlencoded({ extended: true, limit: "5mb", verify: captureParsedBodyBytes }));

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
    scoringApplied: aggregate.aggregationEnabled || aggregate.attackRepetition?.bonusPoints > 0,
    anchorCandidateId: aggregate.anchorCandidateId,
    candidateIds: aggregate.candidateIds,
    candidateCount: aggregate.candidateCount,
    sharedSessionLinks: aggregate.sharedSessionLinks,
    maxSharedSessionCount: aggregate.maxSharedSessionCount,
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
  store.pruneExpiredClientFlows();
  res.json(store.getAllClientFlowAggregates().map((aggregate) => clientFlowJson(aggregate)));
});

app.get("/__detection/api/client-flows/:id", (req, res) => {
  store.pruneExpiredClientFlows();
  const aggregate = store.getClientFlowAggregate(req.params.id);
  if (!aggregate) return res.status(404).json({ error: "not found" });
  res.json(clientFlowJson(aggregate, { includeRequests: true }));
});

app.get("/__detection/api/client-flows/:id/path", (req, res) => {
  store.pruneExpiredClientFlows();
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

const detectionHook = {
  name: "behavior-and-attack-detection",

  onRequest({ proxyReq, req }) {
    prepareRequestObservation(req);
    // RUBY Policy 계약: 외부 입력을 제거하고, 완료된 탐지 이력에서 계산한
    // 0~1 risk score와 가명 client id만 내부 헤더로 전달한다.
    req.rubyPolicyDecision = buildPriorPolicyDecision(req);
    stripDetectionHeaders(proxyReq);
    applyDefensePlan(proxyReq, {
      riskScore: req.rubyPolicyDecision.riskScore,
      rules: policyRules,
    });
    proxyReq.setHeader("X-Client-Id", req.rubyPolicyDecision.clientId);
    // Ground truth용 헤더는 탐지 프록시에서 소비하고 RUBY Policy에는 전달하지 않는다.
    proxyReq.removeHeader(EXPERIMENT_RUN_HEADER);
    // ModSecurity/CRS 검사는 응답을 차단하지 않으며 결과만 비동기로 기록한다.
    req.crsScanPromise = crsScanner.scan(req, getClientIp(req));
    // express.json()/urlencoded()가 body를 이미 읽어버렸다면 upstream으로 다시 실어준다.
    // (안 해주면 로그인/주문 등 POST 요청 body가 Policy에 도달하지 않는다)
    fixRequestBody(proxyReq, req);
  },

  async onResponse({ responseBuffer, proxyRes, req }) {
    const attackDetection = req.crsScanPromise
      ? await req.crsScanPromise
      : { available: false, error: "scan was not started", categories: [], hits: [] };
    const {
      session,
      effectiveDetectionSource,
      effectiveDetectionAnalysis,
    } = recordCompletedRequest(req, {
      status: proxyRes.statusCode,
      responseContentType: proxyRes.headers["content-type"],
      responseContentLength: proxyRes.headers["content-length"],
      responseBodyBytes: responseBuffer.length,
      attackDetection,
    });

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
};

// 공통 Express 프록시 코어에 탐지와 정책 훅을 함께 장착한다. TARGET_URL은
// Defense 또는 보호할 애플리케이션을 직접 가리키며, 별도 Policy 프록시는 없다.
app.use("/", createProxyCore({ target: TARGET, hooks: [detectionHook] }));

app.listen(PORT, () => {
  console.log(`[detection-proxy] listening on :${PORT} -> proxying ${TARGET}`);
  console.log(`[detection-proxy] dashboard: http://localhost:${PORT}/__detection/dashboard`);
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
