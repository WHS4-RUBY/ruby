const crypto = require("crypto");
const { normalizePath } = require("./requestMetadata");
const { DECEPTION_SIGNAL_CATALOG } = require("./deceptionEngine");
const { ActorResolver, MEMBERSHIP_STATUS } = require("./actorResolver");
const { buildHttpFingerprint } = require("./httpFingerprint");
const { buildClientObservation } = require("./fingerprintSimilarity");
const { ClientFlowStore } = require("./clientFlowStore");

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
// Fingerprint 유사도 기반 Client Flow 집계. DCID 기반 Resolved Actor는 신원 경계로
// 그대로 보존하고, Session/Candidate 사이의 휴리스틱 요청 흐름만 연결한다.
const clientFlowStore = new ClientFlowStore();

const MAX_REQUESTS_PER_SESSION = 500; // 메모리 보호용 링버퍼 상한
const MAX_REQUESTS_PER_AUTH_GROUP = MAX_REQUESTS_PER_SESSION * 2;
const MAX_REQUESTS_PER_IP_ENTRY = MAX_REQUESTS_PER_SESSION * 2;
const MAX_REQUESTS_PER_RESOLVED_ACTOR = MAX_REQUESTS_PER_SESSION * 2;

// 엔티티 "개수" 상한 + idle TTL.
// 위의 MAX_REQUESTS_*는 엔티티 하나가 쥔 요청 이력(링버퍼)만 제한할 뿐,
// sessions/actors/authGroups/ipEntries Map 자체의 크기(고유 접속자 수)는 제한하지 않는다.
// 그래서 고유 세션/지문이 계속 늘면(세션 회전 공격·장기 운영) 메모리가 무제한 증가한다.
// actorResolver가 이미 쓰는 cleanup(TTL)+enforceLimits(LRU) 패턴을 동일하게 적용한다.
function positiveInt(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}
const ENTITY_IDLE_TTL_MS = positiveInt(process.env.DETECTION_ENTITY_TTL_MS, 30 * 60_000); // 평범한 신원: 30분 미활동 시 제거
const RISKY_ENTITY_TTL_MS = positiveInt(process.env.RISKY_ENTITY_TTL_MS, 24 * 60 * 60_000); // 위험 신원: 훨씬 오래 보존(기본 24시간)
const MAX_SESSIONS = positiveInt(process.env.MAX_SESSIONS, 50_000);
const MAX_ACTORS = positiveInt(process.env.MAX_ACTORS, 50_000);
const MAX_AUTH_GROUPS = positiveInt(process.env.MAX_AUTH_GROUPS, 50_000);
const MAX_IP_ENTRIES = positiveInt(process.env.MAX_IP_ENTRIES, 50_000);
const ENTITY_SWEEP_INTERVAL_MS = positiveInt(process.env.DETECTION_ENTITY_SWEEP_MS, 60_000);
let lastEntitySweepAt = 0;

// 위험 신원 판정: CRS 공격 이력 또는 기만(Honey) 증거가 하나라도 있으면 위험으로 본다.
// 이미 엔티티에 쌓여 있는 attackHistory/deceptionHistory를 그대로 사용한다.
function isRiskyEntity(entity) {
  const a = entity.attackHistory;
  const d = entity.deceptionHistory;
  return Boolean(
    (a &&
      (a.hasAttackHistory ||
        (Number(a.maxAttackScore) || 0) > 0 ||
        (Number(a.maxCrsAnomalyScore) || 0) > 0)) ||
    (d && d.hasEvidence)
  );
}

// 상한 초과 시 제거 우선순위: (1) 위험하지 않은 것 먼저, (2) 그중 lastSeen 오래된 것 먼저.
// → 위험 신원은 조용해도 마지막까지 남고, 평범한 신원만 밀려난다.
// 단 위험 신원만 남아 상한을 넘으면 그때는 가장 오래된 위험 신원부터 제거(메모리는 끝까지 유계).
// 배치로 목표치(상한의 90%)까지 비워 매 삽입마다 정렬하지 않는다.
function evictOverCap(map, max) {
  if (map.size <= max) return;
  const target = Math.floor(max * 0.9);
  const pairs = [...map.entries()].sort((a, b) => {
    const ra = isRiskyEntity(a[1]) ? 1 : 0;
    const rb = isRiskyEntity(b[1]) ? 1 : 0;
    if (ra !== rb) return ra - rb; // 평범한 것(0)을 먼저 제거
    return (a[1].lastSeen || 0) - (b[1].lastSeen || 0); // 그다음 오래된 것부터
  });
  const removeCount = map.size - target;
  for (let i = 0; i < removeCount && i < pairs.length; i++) map.delete(pairs[i][0]);
}

// 오래 활동이 없는 엔티티를 주기적으로 청소(요청마다 전체 스캔하지 않도록 간격 제한).
// 위험 신원은 훨씬 긴 TTL을 적용해, 한탕 하고 잠수 타도 이력이 바로 지워지지 않는다.
function sweepIdleEntities(now) {
  if (now - lastEntitySweepAt < ENTITY_SWEEP_INTERVAL_MS) return;
  lastEntitySweepAt = now;
  for (const map of [sessions, actors, authGroups, ipEntries]) {
    for (const [key, value] of map) {
      const ttl = isRiskyEntity(value) ? RISKY_ENTITY_TTL_MS : ENTITY_IDLE_TTL_MS;
      if (now - (value.lastSeen || 0) > ttl) map.delete(key);
    }
  }
}

function enforceEntityLimits(now) {
  sweepIdleEntities(now);
  evictOverCap(sessions, MAX_SESSIONS);
  evictOverCap(actors, MAX_ACTORS);
  evictOverCap(authGroups, MAX_AUTH_GROUPS);
  evictOverCap(ipEntries, MAX_IP_ENTRIES);
}


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
      clientFlowId: null,
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
    xssTags,
    xssMaxRisk,
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
    clientFlowId: null,
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
    xssTags: xssTags || [],
    xssMaxRisk: Number.isFinite(xssMaxRisk) ? xssMaxRisk : 0,
    loginAttemptEmail: loginAttemptEmail || null,
    resetPasswordEmail: resetPasswordEmail || null,
    securityQuestionEmail: securityQuestionEmail || null,
    tags: tags || [],
  };
  const clientObservation = buildClientObservation({ ip, httpFingerprint, ts: now });
  const clientFlow = clientFlowStore.observe({
    candidateId: actorId,
    observation: clientObservation,
    sessionId,
    clientIdentity,
    ts: now,
  });
  // 관찰값은 Actor와 Client Flow에만 보관한다. 요청마다 복사하면 세션당 최대 500벌이
  // 중복 적재되는데 읽는 쪽이 없다.
  requestRecord.clientFlowId = clientFlow.id;
  s.clientFlowId = clientFlow.id;
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
      clientObservation,
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
  actor.clientObservation = clientObservation;
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

  // 엔티티 목록이 무제한으로 커지지 않도록 개수 상한 + idle TTL 적용(위험 신원 우선 보존).
  enforceEntityLimits(now);

  return s;
}

function updateAttackScoreHistory({ sessionId, actorId, authGroupId, clientFlowId, scores = {} }) {
  updateMaxAttackScore(sessions.get(sessionId), scores.session);
  updateMaxAttackScore(actors.get(actorId), scores.actor);
  if (authGroupId) updateMaxAttackScore(authGroups.get(authGroupId), scores.authGroup);
  if (clientFlowId) clientFlowStore.updateAttackScore(clientFlowId, scores.clientFlow);
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
  return {
    ...actorResolver.status(),
    fingerprintSimilarity: clientFlowStore.status(),
  };
}

function summarizeClientFlowGroup(group) {
  const flowLinked =
    group.sessionIds.size > 1 || group.candidateIds.size > 1 || group.verifiedClientIds.size > 1;
  return {
    id: group.id,
    status: group.conflicts.length ? "CONFLICT" : flowLinked ? "FLOW_LINKED" : "OBSERVED",
    confidence: flowLinked ? "MEDIUM" : "LOW",
    similarityVersion: group.similarityVersion,
    aggregationPolicy: group.aggregationEnabled
      ? "FINGERPRINT_CLIENT_FLOW_AUTO"
      : "CANDIDATE_CLIENT_FLOW",
    aggregationEnabled: group.aggregationEnabled,
    flowLinked,
    verifiedClientCount: group.verifiedClientIds.size,
    anchorCandidateId: group.anchorCandidateId,
    candidateIds: [...group.candidateIds],
    candidateCount: group.candidateIds.size,
    sessionIds: [...group.sessionIds],
    sessionCount: group.sessionIds.size,
    links: group.links.map((link) => ({ ...link })),
    conflicts: [...group.conflicts],
    firstSeen: group.firstSeen,
    lastSeen: group.lastSeen,
  };
}

/**
 * 프록시 핫패스에서 매 요청 호출되는 O(1) 조회.
 * 전체 집계(getClientFlowAggregate)는 멤버 세션의 요청을 전부 훑고 정렬하므로
 * 실제로 Flow가 병합된 경우에만 호출한다.
 */
function getClientFlowState(idOrCandidateId) {
  const group = clientFlowStore.get(idOrCandidateId) || clientFlowStore.getByCandidate(idOrCandidateId);
  return group ? summarizeClientFlowGroup(group) : null;
}

function getClientFlowAggregate(idOrCandidateId) {
  const group = clientFlowStore.get(idOrCandidateId) || clientFlowStore.getByCandidate(idOrCandidateId);
  if (!group) return null;
  const summary = summarizeClientFlowGroup(group);
  const memberSessions = [...group.sessionIds].map((id) => sessions.get(id)).filter(Boolean);
  const requestIds = new Set();
  const requests = [];
  for (const session of memberSessions) {
    for (const request of session.requests) {
      if (!group.candidateIds.has(request.actorId)) continue;
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
  const includedRequests = group.aggregationEnabled
    ? requests
    : requests.filter((request) => request.actorId === group.anchorCandidateId);
  const includedSessionIds = new Set(includedRequests.map((request) => request.sessionId));
  const includedSessions = memberSessions.filter((session) => includedSessionIds.has(session.id));
  const attackHistory = aggregateAttackHistory(includedSessions);
  if (group.aggregationEnabled) {
    attackHistory.maxAttackScore = Math.max(attackHistory.maxAttackScore, group.maxAttackScore || 0);
  }
  return {
    ...summary,
    sessionIds: [...includedSessionIds],
    sessionCount: includedSessionIds.size,
    observedIps: [...new Set(requests.map((request) => request.ip).filter(Boolean))],
    clientObservation: group.anchorObservation,
    totalRequests: includedRequests.length,
    requests: includedRequests,
    memberSessions: includedSessions,
    attackHistory,
    deceptionHistory: aggregateDeceptionHistory(includedSessions),
  };
}

function getAllClientFlowAggregates() {
  return clientFlowStore
    .getAll()
    .filter((group) =>
      group.sessionIds.size > 1 ||
      group.candidateIds.size > 1 ||
      group.verifiedClientIds.size > 1 ||
      group.conflicts.length > 0
    )
    .map((group) => getClientFlowAggregate(group.id));
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
  getClientFlowAggregate,
  getAllClientFlowAggregates,
  getClientFlowState,
  updateAttackScoreHistory,
  emptyAttackHistory,
  emptyDeceptionHistory,
  recordDeceptionHistory,
  headerFingerprint,
  deriveActorId,
  withoutSensitiveHeaders,
  withoutAuthorizationHeaders,
};
