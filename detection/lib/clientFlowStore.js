const {
  SIMILARITY_VERSION,
  canAutoAggregate,
  clientFlowId,
  compareClientObservations,
} = require("./fingerprintSimilarity");
const {
  ATTACK_BUCKET_MS,
  ATTACK_WINDOW_MS,
  attackBucket,
  isQualifyingAttackRequest,
  repetitionBonusPoints,
} = require("./attackRepetition");

function positiveNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function booleanFlag(value, fallback) {
  if (value === undefined || value === "") return fallback;
  return !["0", "false", "no", "off"].includes(String(value).trim().toLowerCase());
}

class ClientFlowStore {
  constructor({
    ttlMs = positiveNumber(process.env.CLIENT_FLOW_IDLE_TTL_MS, 60 * 60_000),
    similarityWindowMs = positiveNumber(process.env.FINGERPRINT_SIMILARITY_TTL_MS, 30 * 60_000),
    maxGroups = positiveNumber(process.env.MAX_CLIENT_FLOWS, 5_000),
    cleanupIntervalMs = positiveNumber(process.env.FINGERPRINT_CLEANUP_INTERVAL_MS, 60_000),
    allowIpRotation = booleanFlag(process.env.FINGERPRINT_IP_ROTATION_ENABLED, true),
  } = {}) {
    this.ttlMs = ttlMs;
    this.similarityWindowMs = similarityWindowMs;
    this.maxGroups = maxGroups;
    this.cleanupIntervalMs = cleanupIntervalMs;
    this.allowIpRotation = allowIpRotation;
    this.lastCleanupAt = 0;
    this.groups = new Map();
    this.candidateIndex = new Map();
    this.sessionIndex = new Map();
    this.aliases = new Map();
  }

  addSession(group, sessionId, candidateId) {
    if (!sessionId) return false;
    const coreSessionAdded = group.coreCandidateIds.has(candidateId) && !group.coreSessionIds.has(sessionId);
    group.sessionIds.add(sessionId);
    if (group.coreCandidateIds.has(candidateId)) group.coreSessionIds.add(sessionId);
    if (!group.candidateSessionIds.has(candidateId)) group.candidateSessionIds.set(candidateId, new Set());
    group.candidateSessionIds.get(candidateId).add(sessionId);
    if (!this.sessionIndex.has(sessionId)) this.sessionIndex.set(sessionId, new Set());
    this.sessionIndex.get(sessionId).add(group.id);
    return coreSessionAdded;
  }

  overlap(left, right) {
    const leftSessions = left.coreSessionIds;
    const rightSessions = right.coreSessionIds;
    if (!leftSessions.size || !rightSessions.size) return null;
    const smaller = leftSessions.size <= rightSessions.size ? leftSessions : rightSessions;
    const larger = smaller === leftSessions ? rightSessions : leftSessions;
    let shared = 0;
    for (const sessionId of smaller) if (larger.has(sessionId)) shared++;
    const leftCoverage = shared / leftSessions.size;
    const rightCoverage = shared / rightSessions.size;
    if (shared < 5 || leftCoverage < 0.8 || rightCoverage < 0.8) return null;
    return { shared, leftCoverage, rightCoverage };
  }

  merge(left, right, overlap) {
    const [target, source] = left.firstSeen < right.firstSeen ||
      (left.firstSeen === right.firstSeen && left.id < right.id)
      ? [left, right] : [right, left];
    const targetCoverage = overlap.shared / target.coreSessionIds.size;
    const sourceCoverage = overlap.shared / source.coreSessionIds.size;
    for (const candidateId of source.candidateIds) {
      target.candidateIds.add(candidateId);
      this.candidateIndex.set(candidateId, target.id);
    }
    for (const [candidateId, sessionIds] of source.candidateSessionIds) {
      target.candidateSessionIds.set(candidateId, sessionIds);
    }
    for (const sessionId of source.sessionIds) {
      target.sessionIds.add(sessionId);
      const owners = this.sessionIndex.get(sessionId);
      if (owners) {
        owners.delete(source.id);
        owners.add(target.id);
      }
    }
    for (const clientId of source.verifiedClientIds) target.verifiedClientIds.add(clientId);
    for (const [bucket, count] of source.attackBuckets) {
      target.attackBuckets.set(bucket, (target.attackBuckets.get(bucket) || 0) + count);
    }
    const link = {
      fromCandidateId: target.anchorCandidateId,
      toCandidateId: source.anchorCandidateId,
      sourceCandidateIds: [...source.candidateIds],
      reason: "shared_session_continuity",
      sharedSessionCount: overlap.shared,
      sourceCoverage,
      targetCoverage,
      observedAt: Math.max(left.lastSeen, right.lastSeen),
    };
    target.links = target.links.concat(source.links, link).slice(-2_000);
    target.sharedSessionLinks += source.sharedSessionLinks + 1;
    target.maxSharedSessionCount = Math.max(target.maxSharedSessionCount, source.maxSharedSessionCount, overlap.shared);
    target.conflicts.push(...source.conflicts);
    target.firstSeen = Math.min(left.firstSeen, right.firstSeen);
    target.lastSeen = Math.max(left.lastSeen, right.lastSeen);
    target.totalRequests += source.totalRequests;
    target.maxAttackScore = Math.max(left.maxAttackScore, right.maxAttackScore);
    target.aggregationEnabled = target.conflicts.length === 0 && target.candidateIds.size > 1;
    this.groups.delete(source.id);
    this.aliases.set(source.id, target.id);
    return target;
  }

  mergeOverlaps(group, ts, sessionId) {
    let current = group;
    let merged = true;
    let inspectAllSessions = false;
    while (merged) {
      merged = false;
      const peerIds = new Set();
      const relevantSessions = inspectAllSessions ? current.sessionIds : sessionId ? [sessionId] : [];
      for (const relevantSessionId of relevantSessions) {
        for (const id of this.sessionIndex.get(relevantSessionId) || []) peerIds.add(id);
      }
      for (const id of peerIds) {
        const peer = this.groups.get(id);
        if (!peer || peer === current || ts - peer.lastSeen > this.ttlMs) continue;
        const overlap = this.overlap(current, peer);
        if (!overlap) continue;
        current = this.merge(current, peer, overlap);
        merged = true;
        inspectAllSessions = true;
        break;
      }
    }
    return current;
  }

  pruneAttackBuckets(group, now) {
    for (const bucket of group.attackBuckets.keys()) {
      if (bucket + ATTACK_BUCKET_MS <= now - ATTACK_WINDOW_MS) group.attackBuckets.delete(bucket);
    }
  }

  recordAttackRequest(groupId, request) {
    const group = this.get(groupId);
    if (!group || !isQualifyingAttackRequest(request)) return;
    const ts = Number(request.ts);
    if (!Number.isFinite(ts)) return;
    this.pruneAttackBuckets(group, ts);
    const bucket = attackBucket(ts);
    group.attackBuckets.set(bucket, (group.attackBuckets.get(bucket) || 0) + 1);
  }

  attackRepetition(groupId, now = Date.now()) {
    const group = this.get(groupId);
    if (!group) return { qualifyingRequests: 0, bonusPoints: 0, windowMs: ATTACK_WINDOW_MS };
    this.pruneAttackBuckets(group, now);
    const qualifyingRequests = [...group.attackBuckets.values()].reduce((sum, count) => sum + count, 0);
    return { qualifyingRequests, bonusPoints: repetitionBonusPoints(qualifyingRequests), windowMs: ATTACK_WINDOW_MS };
  }

  create(candidateId, observation, sessionId, clientIdentity, now) {
    const id = clientFlowId(candidateId);
    const verifiedClientIds = new Set();
    if (clientIdentity?.continuityVerified && clientIdentity.clientId) {
      verifiedClientIds.add(clientIdentity.clientId);
    }
    const group = {
      id,
      status: "PROVISIONAL",
      confidence: "MEDIUM",
      similarityVersion: SIMILARITY_VERSION,
      anchorCandidateId: candidateId,
      anchorObservation: observation,
      candidateIds: new Set([candidateId]),
      coreCandidateIds: new Set([candidateId]),
      coreSessionIds: new Set(),
      candidateSessionIds: new Map(),
      sessionIds: new Set(),
      verifiedClientIds,
      links: [],
      sharedSessionLinks: 0,
      maxSharedSessionCount: 0,
      // Client Flow는 신원 병합이 아니라 요청 흐름 연결이다. 서로 다른 verified
      // DCID는 별도 Resolved Actor 경계로 보존하되 Flow 연결을 끊는 충돌로 보지 않는다.
      conflicts: [],
      firstSeen: now,
      lastSeen: now,
      totalRequests: 1,
      aggregationEnabled: false,
      maxAttackScore: 0,
      attackBuckets: new Map(),
    };
    this.groups.set(id, group);
    this.candidateIndex.set(candidateId, id);
    this.addSession(group, sessionId, candidateId);
    this.enforceLimits();
    return group;
  }

  observe({ candidateId, observation, sessionId, clientIdentity = null, ts = Date.now() }) {
    // cleanup은 전체 그룹을 순회하므로 요청마다 돌리면 프록시 핫패스가 O(그룹 수)가
    // 된다. 주기적으로만 실행하고, 조회한 그룹의 만료 여부는 여기서 직접 확인한다.
    this.cleanupIfDue(ts);
    let indexed = this.getByCandidate(candidateId);
    if (indexed && ts - indexed.lastSeen > this.ttlMs) {
      this.remove(indexed.id);
      indexed = null;
    }
    if (indexed) {
      indexed.lastSeen = ts;
      indexed.totalRequests++;
      if (indexed.anchorCandidateId === candidateId) indexed.anchorObservation = observation;
      const coreSessionAdded = this.addSession(indexed, sessionId, candidateId);
      if (clientIdentity?.continuityVerified && clientIdentity.clientId) {
        indexed.verifiedClientIds.add(clientIdentity.clientId);
      }
      return coreSessionAdded ? this.mergeOverlaps(indexed, ts, sessionId) : indexed;
    }

    let best = null;
    for (const group of this.groups.values()) {
      if (ts - group.lastSeen > this.ttlMs) continue;
      const comparison = compareClientObservations(group.anchorObservation, observation);
      const eligibility = canAutoAggregate(comparison, group.anchorObservation, observation, {
        windowMs: this.similarityWindowMs,
        allowIpRotation: this.allowIpRotation,
      });
      if (!eligibility.eligible) continue;
      if (!best || comparison.score > best.comparison.score) {
        best = { group, comparison, eligibility };
      }
    }

    if (!best) return this.mergeOverlaps(this.create(candidateId, observation, sessionId, clientIdentity, ts), ts, sessionId);

    const { group, comparison, eligibility } = best;
    group.candidateIds.add(candidateId);
    group.coreCandidateIds.add(candidateId);
    const coreSessionAdded = this.addSession(group, sessionId, candidateId);
    if (clientIdentity?.continuityVerified && clientIdentity.clientId) {
      group.verifiedClientIds.add(clientIdentity.clientId);
    }
    group.links.push({
      fromCandidateId: group.anchorCandidateId,
      toCandidateId: candidateId,
      score: comparison.score,
      profileScore: comparison.profileScore,
      decision: comparison.decision,
      matchedFields: comparison.matchedFields,
      changedFields: comparison.changedFields,
      ignoredFields: comparison.ignoredFields,
      fieldScores: comparison.fieldScores,
      reason: eligibility.reason,
      observedAt: ts,
    });
    if (group.links.length > 2_000) group.links.shift();
    group.lastSeen = ts;
    group.totalRequests++;
    group.aggregationEnabled = group.conflicts.length === 0 && group.candidateIds.size > 1;
    this.candidateIndex.set(candidateId, group.id);
    return coreSessionAdded ? this.mergeOverlaps(group, ts, sessionId) : group;
  }

  updateAttackScore(groupId, score) {
    const group = this.get(groupId);
    if (group && Number.isFinite(score)) group.maxAttackScore = Math.max(group.maxAttackScore, score);
  }

  get(id) {
    let canonicalId = id;
    while (this.aliases.has(canonicalId)) canonicalId = this.aliases.get(canonicalId);
    return this.groups.get(canonicalId);
  }

  getByCandidate(candidateId) {
    const id = this.candidateIndex.get(candidateId);
    return id ? this.get(id) : null;
  }

  getAll() {
    return [...this.groups.values()];
  }

  cleanupIfDue(now = Date.now()) {
    if (now - this.lastCleanupAt < this.cleanupIntervalMs) return;
    this.cleanup(now);
  }

  cleanup(now = Date.now()) {
    this.lastCleanupAt = now;
    for (const [id, group] of this.groups) {
      if (now - group.lastSeen <= this.ttlMs) continue;
      this.remove(id);
    }
  }

  remove(id) {
    const group = this.get(id);
    if (!group) return;
    const aliases = [...this.aliases.keys()].filter((alias) => this.get(alias)?.id === group.id);
    for (const candidateId of group.candidateIds) this.candidateIndex.delete(candidateId);
    for (const sessionId of group.sessionIds) {
      const owners = this.sessionIndex.get(sessionId);
      if (!owners) continue;
      owners.delete(group.id);
      if (!owners.size) this.sessionIndex.delete(sessionId);
    }
    this.groups.delete(group.id);
    for (const alias of aliases) this.aliases.delete(alias);
  }

  enforceLimits() {
    if (this.groups.size <= this.maxGroups) return;
    // 축출할 때마다 전체를 다시 정렬하면 O(n^2 log n)이 된다. 한 번만 정렬한다.
    const byOldest = [...this.groups.values()].sort((a, b) => a.lastSeen - b.lastSeen);
    for (const group of byOldest) {
      if (this.groups.size <= this.maxGroups) break;
      this.remove(group.id);
    }
  }

  status() {
    return {
      similarityVersion: SIMILARITY_VERSION,
      ttlMs: this.ttlMs,
      similarityWindowMs: this.similarityWindowMs,
      candidateLimit: null,
      maxGroups: this.maxGroups,
      allowIpRotation: this.allowIpRotation,
      groups: this.groups.size,
      aggregatingGroups: [...this.groups.values()].filter((group) => group.aggregationEnabled).length,
    };
  }
}

module.exports = { ClientFlowStore };
