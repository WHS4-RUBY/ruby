const crypto = require("crypto");
const { normalizePath } = require("./requestMetadata");
const { DECEPTION_SIGNAL_CATALOG } = require("./deceptionEngine");
const { ActorResolver, MEMBERSHIP_STATUS } = require("./actorResolver");
const { buildHttpFingerprint } = require("./httpFingerprint");

// 세션 단위 데이터: 요청 로그 + 클라이언트 텔레메트리
const sessions = new Map();
// IP + HTTP 헤더 fingerprint 단위 행위자 그룹.
// Docker/NAT 환경에서 IP만으로 서로 다른 브라우저와 CLI를 합치지 않도록 분리한다.
const actors = new Map();
// 동일 Authorization Bearer Token의 SHA-256 hash 단위 요청 그룹
const authGroups = new Map();
// 동일 IP 전체 트래픽 관찰용. NAT/Docker에서 여러 클라이언트가 섞일 수 있어 점수/차단에 쓰지 않는다.
const ipEntries = new Map();
// Session 단위 Resolution Assignment를 관리하며 원본 요청은 복사하지 않는다.
const actorResolver = new ActorResolver();

const MAX_REQUESTS_PER_SESSION = 500; // 메모리 보호용 링버퍼 상한
const MAX_REQUESTS_PER_AUTH_GROUP = MAX_REQUESTS_PER_SESSION * 2;
const MAX_REQUESTS_PER_IP_ENTRY = MAX_REQUESTS_PER_SESSION * 2;
const MAX_REQUESTS_PER_RESOLVED_ACTOR = MAX_REQUESTS_PER_SESSION * 2;

const SENSITIVE_DETECTION_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "x-experiment-run-id",
]);

function emptyAttackHistory() {
  return {
    hasAttackHistory: false,
    maxAttackScore: 0,
    maxCrsAnomalyScore: 0,
    cumulativeRuleHits: 0,
    matchedRuleIds: [],
    attackCategories: [],
    firstAttackAt: null,
    lastAttackAt: null,
  };
}

function emptyDeceptionHistory() {
  return {
    hasEvidence: false,
    totalEvents: 0,
    distinctSignals: [],
    distinctScoredSignals: [],
    signalCounts: {},
    strongestEvidenceLevel: null,
    firstEventAt: null,
    lastEventAt: null,
    recentEvents: [],
  };
}

const EVIDENCE_LEVEL_ORDER = Object.freeze({
  observation: 0,
  supporting: 1,
  medium: 2,
  strong: 3,
});
const MAX_DECEPTION_EVENTS_PER_ENTITY = 100;

function recordDeceptionHistory(entity, events, timestamp) {
  if (!entity || !Array.isArray(events) || !events.length) return false;
  const history = entity.deceptionHistory || (entity.deceptionHistory = emptyDeceptionHistory());
  for (const source of events) {
    const metadata = DECEPTION_SIGNAL_CATALOG[source?.signal];
    if (!metadata) continue;
    const occurredAt = Number.isFinite(source.occurredAt) ? source.occurredAt : timestamp;
    const event = {
      eventId: String(source.eventId || crypto.randomUUID()),
      signal: source.signal,
      evidenceLevel: metadata.evidenceLevel,
      scored: metadata.scored,
      originSessionId: source.originSessionId ? String(source.originSessionId) : null,
      occurredAt,
      detail: String(source.detail || "").slice(0, 500),
    };
    history.hasEvidence = true;
    history.totalEvents += 1;
    history.signalCounts[event.signal] = (history.signalCounts[event.signal] || 0) + 1;
    addUnique(history.distinctSignals, [event.signal]);
    if (metadata.scored) addUnique(history.distinctScoredSignals, [event.signal]);
    if (
      history.strongestEvidenceLevel === null ||
      EVIDENCE_LEVEL_ORDER[event.evidenceLevel] >
        EVIDENCE_LEVEL_ORDER[history.strongestEvidenceLevel]
    ) {
      history.strongestEvidenceLevel = event.evidenceLevel;
    }
    if (history.firstEventAt === null || occurredAt < history.firstEventAt) {
      history.firstEventAt = occurredAt;
    }
    if (history.lastEventAt === null || occurredAt > history.lastEventAt) {
      history.lastEventAt = occurredAt;
    }
    history.recentEvents.push(event);
    if (history.recentEvents.length > MAX_DECEPTION_EVENTS_PER_ENTITY) {
      history.recentEvents.shift();
    }
  }
  return true;
}

function addUnique(target, values) {
  const existing = new Set(target);
  for (const value of values || []) {
    if (value === undefined || value === null || value === "") continue;
    existing.add(String(value));
  }
  target.splice(0, target.length, ...existing);
}

function recordCrsAttackHistory(entity, attackDetection, timestamp) {
  if (!entity || !attackDetection?.available || !attackDetection.ruleHitCount) return false;
  const history = entity.attackHistory || (entity.attackHistory = emptyAttackHistory());
  history.hasAttackHistory = true;
  history.cumulativeRuleHits += Number(attackDetection.ruleHitCount) || 0;
  history.maxCrsAnomalyScore = Math.max(
    history.maxCrsAnomalyScore,
    Number(attackDetection.anomalyScore) || 0
  );
  addUnique(history.matchedRuleIds, (attackDetection.hits || []).map((hit) => hit.ruleId));
  addUnique(history.attackCategories, attackDetection.categories);
  if (history.firstAttackAt === null) history.firstAttackAt = timestamp;
  history.lastAttackAt = timestamp;
  return true;
}

function updateMaxAttackScore(entity, score) {
  if (!entity || !Number.isFinite(score)) return;
  const history = entity.attackHistory || (entity.attackHistory = emptyAttackHistory());
  history.maxAttackScore = Math.max(history.maxAttackScore, score);
}

function withoutSensitiveHeaders(headers = {}) {
  return Object.fromEntries(
    Object.entries(headers).filter(
      ([name]) => !SENSITIVE_DETECTION_HEADERS.has(name.toLowerCase())
    )
  );
}

const withoutAuthorizationHeaders = withoutSensitiveHeaders;

function headerFingerprint(headers) {
  const relevant = [
    headers["user-agent"] || "",
    headers["accept"] || "",
    headers["accept-language"] || "",
    headers["accept-encoding"] || "",
  ].join("|");
  return crypto.createHash("sha1").update(relevant).digest("hex").slice(0, 12);
}

function deriveActorId(ip, fingerprint) {
  const digest = crypto
    .createHash("sha256")
    .update(`${ip}\u0000${fingerprint}`)
    .digest("hex")
    .slice(0, 24);
  return `actor:${digest}`;
}

function getOrCreateSession(sessionId, ip) {
  if (!sessions.has(sessionId)) {
    sessions.set(sessionId, {
      id: sessionId,
      ip,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      requests: [], // { ts, method, url, status }
      headerSample: null,
      fingerprint: null,
      actorId: null,
      actorIds: new Set(),
      resolvedActorId: null,
      resolutionMembershipId: null,
      userAgent: null,
      attackHistory: emptyAttackHistory(),
      deceptionHistory: emptyDeceptionHistory(),
      telemetry: {
        mouseMoveCount: 0,
        scrollCount: 0,
        routeChangeCount: 0,
        domEventTypes: new Set(),
        pageLoads: 0,
        currentUrl: null,
        lastTelemetryAt: null,
      },
    });
  }
  const s = sessions.get(sessionId);
  s.lastSeen = Date.now();
  return s;
}

const MAX_BODY_LOG_CHARS = 2000; // 요청 로그에 남기는 body 최대 길이 (메모리 보호)

function truncateBody(body) {
  if (body === undefined || body === null) return undefined;
  // body-parser는 body가 없는 요청(GET 등)에도 기본값 {}를 넣어주므로 빈 객체는 제외
  if (typeof body === "object" && Object.keys(body).length === 0) return undefined;
  const str = typeof body === "string" ? body : JSON.stringify(body);
  if (!str) return undefined;
  return str.length > MAX_BODY_LOG_CHARS ? str.slice(0, MAX_BODY_LOG_CHARS) + "…(truncated)" : str;
}

function recordRequest(
  sessionId,
  ip,
  {
    method,
    url,
    status,
    headers = {},
    rawHeaders = [],
    httpVersion = null,
    body,
    tags,
    blTags,
    csrfTags,
    loginAttemptEmail,
    resetPasswordEmail,
    securityQuestionEmail,
    authGroupId,
    normalizedPath: suppliedNormalizedPath,
    payloadFingerprint = null,
    hasAuthorization,
    experimentRunId = null,
    requestContentType = null,
    requestContentLength = null,
    requestBodyBytes = null,
    responseContentType = null,
    responseContentLength = null,
    responseBodyBytes = null,
    attackDetection = null,
    backgroundTraffic = null,
    deceptionEvents = [],
    clientIdentity = null,
    accountIdentity = null,
    ts,
  }
) {
  const s = getOrCreateSession(sessionId, ip);
  const now = Number.isFinite(ts) ? ts : Date.now();
  const legacyFingerprint = headerFingerprint(headers);
  const legacyActorId = deriveActorId(ip, legacyFingerprint);
  const httpFingerprint = buildHttpFingerprint({
    headers,
    rawHeaders,
    httpVersion,
    method,
  });
  // V2 안정 Client Profile을 실제 Candidate 그룹 키로 사용한다. Accept처럼 요청
  // 종류마다 달라지는 값은 requestFingerprint에만 남겨 동일 브라우저 분할을 막는다.
  const fingerprint = httpFingerprint.clientFingerprint;
  const actorId = deriveActorId(ip, fingerprint);
  const actorV2Id = actorId;
  const normalizedPath = suppliedNormalizedPath || normalizePath(url);
  const normalizedMethod = String(method || "GET").toUpperCase();
  const operation = `${normalizedMethod} ${normalizedPath}`;
  const requestHasAuthorization =
    typeof hasAuthorization === "boolean" ? hasAuthorization : Boolean(headers.authorization);

  if (!s.headerSample) {
    // 분류에 필요한 헤더 특성은 유지하되 자격 증명은 저장하지 않는다.
    s.headerSample = withoutSensitiveHeaders(headers);
    s.fingerprint = fingerprint;
    s.actorId = actorId;
    s.userAgent = headers["user-agent"] || "";
  }
  s.actorIds.add(actorId);
  s.lastSeen = now;

  const requestRecord = {
    requestId: `request:${crypto.randomUUID()}`,
    ts: now,
    method: normalizedMethod,
    url,
    normalizedPath,
    operation,
    status,
    ip,
    sessionId,
    actorId,
    legacyActorId,
    legacyFingerprint,
    actorV2Id,
    httpFingerprint,
    authGroupId: authGroupId || null,
    resolvedActorId: null,
    resolutionMembershipId: null,
    clientId: clientIdentity?.valid ? clientIdentity.clientId : null,
    clientContinuityVerified: Boolean(
      clientIdentity?.continuityVerified === true || clientIdentity?.source === "verified"
    ),
    clientIdentitySource: clientIdentity?.source || null,
    accountId: accountIdentity?.accountId || null,
    accountVerified: Boolean(accountIdentity?.verified),
    payloadFingerprint,
    hasAuthorization: requestHasAuthorization,
    experimentRunId: experimentRunId || null,
    requestContentType,
    requestContentLength,
    requestBodyBytes,
    responseContentType,
    responseContentLength,
    responseBodyBytes,
    attackDetection,
    backgroundTraffic: backgroundTraffic?.isBackground
      ? {
          isBackground: true,
          category: backgroundTraffic.category,
          label: backgroundTraffic.label,
          transport: backgroundTraffic.transport,
          connectionId: backgroundTraffic.connectionId,
          connectionPhase: backgroundTraffic.connectionPhase,
        }
      : null,
    deceptionEvents: Array.isArray(deceptionEvents)
      ? deceptionEvents.map((event) => ({
          eventId: event.eventId,
          signal: event.signal,
          evidenceLevel: event.evidenceLevel,
          scored: event.scored,
          originSessionId: event.originSessionId || null,
          occurredAt: event.occurredAt,
          detail: String(event.detail || "").slice(0, 500),
        }))
      : [],
    body: truncateBody(body),
    blTags: blTags || [],
    csrfTags: csrfTags || [],
    loginAttemptEmail: loginAttemptEmail || null,
    resetPasswordEmail: resetPasswordEmail || null,
    securityQuestionEmail: securityQuestionEmail || null,
    tags: tags || [],
  };
  s.requests.push(requestRecord);
  if (s.requests.length > MAX_REQUESTS_PER_SESSION) {
    s.requests.shift();
  }

  const resolution = actorResolver.observe({
    sessionId,
    candidateId: actorId,
    ip,
    clientIdentity,
    authGroupId,
    accountIdentity,
    fingerprint,
    operation,
    ts: now,
  });
  requestRecord.resolvedActorId = resolution.resolvedActorId;
  requestRecord.resolutionMembershipId = resolution.membershipId;
  s.resolvedActorId = resolution.resolvedActorId;
  s.resolutionMembershipId = resolution.membershipId;

  if (authGroupId) {
    if (!authGroups.has(authGroupId)) {
      authGroups.set(authGroupId, {
        id: authGroupId,
        firstSeen: now,
        lastSeen: now,
        totalRequests: 0,
        sessionIds: new Set(),
        actorIds: new Set(),
        requests: [],
        attackHistory: emptyAttackHistory(),
        deceptionHistory: emptyDeceptionHistory(),
      });
    }
    const authGroup = authGroups.get(authGroupId);
    authGroup.lastSeen = now;
    authGroup.totalRequests++;
    authGroup.sessionIds.add(sessionId);
    authGroup.actorIds.add(actorId);
    authGroup.requests.push({ ...requestRecord });
    if (authGroup.requests.length > MAX_REQUESTS_PER_AUTH_GROUP) {
      authGroup.requests.shift();
    }
  }

  // 같은 IP에서도 브라우저/CLI fingerprint가 다르면 별도 Actor로 취급한다.
  // 동일 fingerprint가 dlsid를 계속 바꾸는 경우에만 요청과 churn을 합산한다.
  if (!actors.has(actorId)) {
    actors.set(actorId, {
      id: actorId,
      ip,
      fingerprint,
      clientFingerprintV2: httpFingerprint.clientFingerprint,
      headerSample: withoutSensitiveHeaders(headers),
      userAgent: headers["user-agent"] || "",
      firstSeen: now,
      lastSeen: now,
      totalRequests: 0,
      sessionIds: new Set(),
      requests: [],
      attackHistory: emptyAttackHistory(),
      deceptionHistory: emptyDeceptionHistory(),
    });
  }
  const actor = actors.get(actorId);
  actor.clientFingerprintV2 = httpFingerprint.clientFingerprint;
  actor.lastSeen = now;
  actor.totalRequests++;
  actor.sessionIds.add(sessionId);
  actor.requests.push({ ...requestRecord });
  if (actor.requests.length > MAX_REQUESTS_PER_SESSION * 2) {
    actor.requests.shift();
  }

  if (!ipEntries.has(ip)) {
    ipEntries.set(ip, {
      ip,
      firstSeen: now,
      lastSeen: now,
      totalRequests: 0,
      sessionIds: new Set(),
      actorIds: new Set(),
      requests: [],
    });
  }
  const ipEntry = ipEntries.get(ip);
  ipEntry.lastSeen = now;
  ipEntry.totalRequests++;
  ipEntry.sessionIds.add(sessionId);
  ipEntry.actorIds.add(actorId);
  ipEntry.requests.push({ ...requestRecord });
  if (ipEntry.requests.length > MAX_REQUESTS_PER_IP_ENTRY) ipEntry.requests.shift();

  // 최근 요청 링버퍼와 별도로 CRS가 확인한 공격 규칙 이력을 누적한다.
  // legacy 정규식 fallback은 CRS 결과와 섞이지 않도록 누적 이력에서 제외한다.
  recordCrsAttackHistory(s, attackDetection, now);
  recordCrsAttackHistory(actor, attackDetection, now);
  if (authGroupId) recordCrsAttackHistory(authGroups.get(authGroupId), attackDetection, now);
  // 점수에는 고유 신호만 사용하고 여기서는 반복 횟수와 근거 이력을 함께 보존한다.
  recordDeceptionHistory(s, deceptionEvents, now);
  recordDeceptionHistory(actor, deceptionEvents, now);
  if (authGroupId) recordDeceptionHistory(authGroups.get(authGroupId), deceptionEvents, now);

  return s;
}

function updateAttackScoreHistory({ sessionId, actorId, authGroupId, scores = {} }) {
  updateMaxAttackScore(sessions.get(sessionId), scores.session);
  updateMaxAttackScore(actors.get(actorId), scores.actor);
  if (authGroupId) updateMaxAttackScore(authGroups.get(authGroupId), scores.authGroup);
}

function recordTelemetry(sessionId, ip, payload) {
  const s = getOrCreateSession(sessionId, ip);
  const t = s.telemetry;
  t.mouseMoveCount += payload.mouseMoveCount || 0;
  t.scrollCount += payload.scrollCount || 0;
  t.routeChangeCount += payload.routeChangeCount || 0;
  (payload.domEventTypes || []).forEach((ev) => t.domEventTypes.add(ev));
  t.pageLoads += payload.pageLoad ? 1 : 0;
  if (typeof payload.url === "string") t.currentUrl = payload.url.slice(0, 2048);
  t.lastTelemetryAt = Date.now();
  return s;
}

function getSession(sessionId) {
  return sessions.get(sessionId);
}

function getAllSessions() {
  return Array.from(sessions.values());
}

function getAllActors() {
  return Array.from(actors.values());
}

function getActor(actorId) {
  return actors.get(actorId);
}

function getAllAuthGroups() {
  return Array.from(authGroups.values());
}

function getAuthGroup(authGroupId) {
  return authGroups.get(authGroupId);
}

function getAllIpEntries() {
  return Array.from(ipEntries.values());
}

function getIpEntry(ip) {
  return ipEntries.get(ip);
}

function serializeMembership(membership) {
  return {
    membershipId: membership.membershipId,
    resolvedActorId: membership.resolvedActorId,
    sessionId: membership.sessionId,
    candidateId: membership.candidateId,
    candidateIds: [...membership.candidateIds],
    status: membership.status,
    confidence: membership.confidence,
    reasonCodes: [...membership.reasonCodes],
    conflicts: [...membership.conflicts],
    createdAt: membership.createdAt,
    updatedAt: membership.updatedAt,
    lastConfirmedAt: membership.lastConfirmedAt,
    active: membership.active,
    resolverVersion: membership.resolverVersion,
    requestCount: membership.requestCount,
  };
}

function aggregateAttackHistory(memberSessions) {
  const histories = memberSessions.map((session) => session.attackHistory || emptyAttackHistory());
  const firstTimes = histories.map((history) => history.firstAttackAt).filter(Number.isFinite);
  const lastTimes = histories.map((history) => history.lastAttackAt).filter(Number.isFinite);
  return {
    hasAttackHistory: histories.some((history) => history.hasAttackHistory),
    maxAttackScore: Math.max(0, ...histories.map((history) => Number(history.maxAttackScore) || 0)),
    maxCrsAnomalyScore: Math.max(0, ...histories.map((history) => Number(history.maxCrsAnomalyScore) || 0)),
    cumulativeRuleHits: histories.reduce(
      (sum, history) => sum + (Number(history.cumulativeRuleHits) || 0),
      0
    ),
    matchedRuleIds: [...new Set(histories.flatMap((history) => history.matchedRuleIds || []))],
    attackCategories: [...new Set(histories.flatMap((history) => history.attackCategories || []))],
    firstAttackAt: firstTimes.length ? Math.min(...firstTimes) : null,
    lastAttackAt: lastTimes.length ? Math.max(...lastTimes) : null,
  };
}

function aggregateDeceptionHistory(memberSessions) {
  const histories = memberSessions.map((session) => session.deceptionHistory || emptyDeceptionHistory());
  const recentEvents = histories
    .flatMap((history) => history.recentEvents || [])
    .filter((event, index, all) => all.findIndex((item) => item.eventId === event.eventId) === index)
    .sort((a, b) => a.occurredAt - b.occurredAt)
    .slice(-MAX_DECEPTION_EVENTS_PER_ENTITY);
  const signalCounts = {};
  for (const history of histories) {
    for (const [signal, count] of Object.entries(history.signalCounts || {})) {
      signalCounts[signal] = (signalCounts[signal] || 0) + Number(count || 0);
    }
  }
  const levels = histories.map((history) => history.strongestEvidenceLevel).filter(Boolean);
  const firstTimes = histories.map((history) => history.firstEventAt).filter(Number.isFinite);
  const lastTimes = histories.map((history) => history.lastEventAt).filter(Number.isFinite);
  return {
    hasEvidence: histories.some((history) => history.hasEvidence),
    totalEvents: histories.reduce((sum, history) => sum + Number(history.totalEvents || 0), 0),
    distinctSignals: [...new Set(histories.flatMap((history) => history.distinctSignals || []))],
    distinctScoredSignals: [
      ...new Set(histories.flatMap((history) => history.distinctScoredSignals || [])),
    ],
    signalCounts,
    strongestEvidenceLevel: levels.sort(
      (a, b) => EVIDENCE_LEVEL_ORDER[b] - EVIDENCE_LEVEL_ORDER[a]
    )[0] || null,
    firstEventAt: firstTimes.length ? Math.min(...firstTimes) : null,
    lastEventAt: lastTimes.length ? Math.max(...lastTimes) : null,
    recentEvents,
  };
}

function getResolvedActorAggregate(resolvedActorId, { includeProvisional = false } = {}) {
  const actor = actorResolver.getActor(resolvedActorId);
  if (!actor) return null;
  const memberships = actorResolver.getMembershipsForActor(resolvedActorId);
  const includedStatuses = new Set([MEMBERSHIP_STATUS.CONFIRMED]);
  if (includeProvisional) includedStatuses.add(MEMBERSHIP_STATUS.PROVISIONAL);
  const includedMemberships = memberships.filter(
    (membership) => membership.active && includedStatuses.has(membership.status)
  );
  const sessionIds = [...new Set(includedMemberships.map((membership) => membership.sessionId))];
  const memberSessions = sessionIds.map((id) => sessions.get(id)).filter(Boolean);
  const requestIds = new Set();
  const requests = [];
  for (const session of memberSessions) {
    for (const request of session.requests) {
      const key = request.requestId || `${request.sessionId}\u0000${request.ts}\u0000${request.operation}`;
      if (requestIds.has(key)) continue;
      requestIds.add(key);
      requests.push(request);
    }
  }
  requests.sort((a, b) => a.ts - b.ts);
  if (requests.length > MAX_REQUESTS_PER_RESOLVED_ACTOR) {
    requests.splice(0, requests.length - MAX_REQUESTS_PER_RESOLVED_ACTOR);
  }

  const candidateIds = [...actor.candidateIds];
  const observedIps = [...actor.observedIps.keys()];
  const statuses = memberships.filter((membership) => membership.active).map((membership) => membership.status);
  const observedMemberships = memberships.filter((membership) => membership.active);
  const observedSessionIds = [...new Set(observedMemberships.map((membership) => membership.sessionId))];
  const status = !statuses.length
    ? "INACTIVE"
    : statuses.includes(MEMBERSHIP_STATUS.CONFIRMED)
      ? MEMBERSHIP_STATUS.CONFIRMED
      : statuses.includes(MEMBERSHIP_STATUS.PROVISIONAL)
        ? MEMBERSHIP_STATUS.PROVISIONAL
        : statuses.includes(MEMBERSHIP_STATUS.SUGGESTED)
          ? MEMBERSHIP_STATUS.SUGGESTED
          : MEMBERSHIP_STATUS.CONFLICT;
  const confidence = status === MEMBERSHIP_STATUS.CONFIRMED
    ? "HIGH"
    : status === MEMBERSHIP_STATUS.PROVISIONAL
      ? "MEDIUM"
      : status === MEMBERSHIP_STATUS.SUGGESTED
        ? "LOW"
        : "NONE";

  return {
    id: actor.id,
    firstSeen: actor.firstSeen,
    lastSeen: actor.lastSeen,
    status,
    confidence,
    sessionIds,
    observedSessionIds,
    candidateIds,
    confirmedMemberships: memberships.filter(
      (membership) => membership.active && membership.status === MEMBERSHIP_STATUS.CONFIRMED
    ).map(serializeMembership),
    provisionalMemberships: memberships.filter(
      (membership) => membership.active && membership.status === MEMBERSHIP_STATUS.PROVISIONAL
    ).map(serializeMembership),
    memberships: memberships.map(serializeMembership),
    observedIps,
    ipFirstSeen: Object.fromEntries(
      observedIps.map((ip) => [ip, actor.observedIps.get(ip)?.firstSeen || null])
    ),
    ipLastSeen: Object.fromEntries(
      observedIps.map((ip) => [ip, actor.observedIps.get(ip)?.lastSeen || null])
    ),
    ipChangeCount: actor.ipChangeCount,
    clientIds: [...actor.clientIds.keys()],
    accountAffiliations: Array.from(actor.accountAffiliations.values(), (entry) => ({
      accountId: entry.accountId,
      verified: entry.verified,
      verification: entry.verification,
      claim: entry.claim,
      firstSeen: entry.firstSeen,
      lastSeen: entry.lastSeen,
      authGroupIds: [...entry.authGroupIds],
    })),
    authGroupIds: [...actor.authGroupIds.keys()],
    evidence: actor.evidence.map((item) => ({ ...item })),
    conflicts: actor.conflicts.map((item) => ({ ...item })),
    continuityConfirmed: includedMemberships.some(
      (membership) => membership.status === MEMBERSHIP_STATUS.CONFIRMED
    ),
    observedTotalRequests: observedMemberships.reduce(
      (sum, membership) => sum + Number(membership.requestCount || 0),
      0
    ),
    totalRequests: includedMemberships.reduce(
      (sum, membership) => sum + Number(membership.requestCount || 0),
      0
    ),
    requests,
    memberSessions,
    attackHistory: aggregateAttackHistory(memberSessions),
    deceptionHistory: aggregateDeceptionHistory(memberSessions),
    aggregationPolicy: includeProvisional ? "CONFIRMED_AND_PROVISIONAL" : "CONFIRMED_ONLY",
  };
}

function getAllResolvedActorAggregates(options) {
  return actorResolver.getAllActors().map((actor) => getResolvedActorAggregate(actor.id, options));
}

function getResolutionMemberships(resolvedActorId) {
  if (!actorResolver.getActor(resolvedActorId)) return null;
  return actorResolver.getMembershipsForActor(resolvedActorId).map(serializeMembership);
}

function deactivateResolutionMembership(membershipId, reason) {
  return actorResolver.deactivateMembership(membershipId, reason);
}

function getResolutionStatus() {
  return actorResolver.status();
}

module.exports = {
  getOrCreateSession,
  recordRequest,
  recordTelemetry,
  getSession,
  getAllSessions,
  getAllActors,
  getActor,
  getAllAuthGroups,
  getAuthGroup,
  getAllIpEntries,
  getIpEntry,
  getResolvedActorAggregate,
  getAllResolvedActorAggregates,
  getResolutionMemberships,
  deactivateResolutionMembership,
  getResolutionStatus,
  updateAttackScoreHistory,
  emptyAttackHistory,
  emptyDeceptionHistory,
  recordDeceptionHistory,
  headerFingerprint,
  deriveActorId,
  withoutSensitiveHeaders,
  withoutAuthorizationHeaders,
};
