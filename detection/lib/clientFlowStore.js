const {
  SIMILARITY_VERSION,
  canAutoAggregate,
  clientFlowId,
  compareClientObservations,
} = require("./fingerprintSimilarity");

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
    ttlMs = positiveNumber(process.env.FINGERPRINT_SIMILARITY_TTL_MS, 30 * 60_000),
    maxCandidates = positiveNumber(process.env.FINGERPRINT_MAX_FLOW_CANDIDATES, 3),
    maxGroups = positiveNumber(process.env.MAX_CLIENT_FLOWS, 5_000),
    cleanupIntervalMs = positiveNumber(process.env.FINGERPRINT_CLEANUP_INTERVAL_MS, 60_000),
    allowIpRotation = booleanFlag(process.env.FINGERPRINT_IP_ROTATION_ENABLED, true),
  } = {}) {
    this.ttlMs = ttlMs;
    this.maxCandidates = maxCandidates;
    this.maxGroups = maxGroups;
    this.cleanupIntervalMs = cleanupIntervalMs;
    this.allowIpRotation = allowIpRotation;
    this.lastCleanupAt = 0;
    this.groups = new Map();
    this.candidateIndex = new Map();
    this.sessionIndex = new Map();
    this.aliases = new Map();
    this.aliasVersion = 0;
  }

  addSession(group, sessionId) {
    if (!sessionId) return false;
    const added = !group.sessionIds.has(sessionId);
    group.sessionIds.add(sessionId);
    if (!this.sessionIndex.has(sessionId)) this.sessionIndex.set(sessionId, new Set());
    this.sessionIndex.get(sessionId).add(group.id);
    return added;
  }

  merge(left, right, sharedSessionId, now) {
    const [target, source] = left.firstSeen < right.firstSeen ||
      (left.firstSeen === right.firstSeen && left.id < right.id)
      ? [left, right] : [right, left];
    const sharedSessionCount = [...source.sessionIds].filter((id) => target.sessionIds.has(id)).length;
    const sourceCoverage = sharedSessionCount / source.sessionIds.size;
    const targetCoverage = sharedSessionCount / target.sessionIds.size;
    for (const candidateId of source.candidateIds) {
      target.candidateIds.add(candidateId);
      this.candidateIndex.set(candidateId, target.id);
    }
    for (const [candidateId, observation] of source.observations) {
      target.observations.set(candidateId, observation);
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
    target.links.push(...source.links, {
      fromCandidateId: target.anchorCandidateId,
      toCandidateId: source.anchorCandidateId,
      reason: "shared_session_continuity",
      sharedSessionCount,
      sourceCoverage,
      targetCoverage,
      sharedSessionId,
      observedAt: now,
    });
    target.firstSeen = Math.min(target.firstSeen, source.firstSeen);
    target.lastSeen = Math.max(target.lastSeen, source.lastSeen, now);
    target.maxAttackScore = Math.max(target.maxAttackScore, source.maxAttackScore);
    target.conflicts.push(...source.conflicts);
    target.aggregationEnabled = target.conflicts.length === 0 && target.candidateIds.size > 1;
    this.groups.delete(source.id);
    this.aliases.set(source.id, target.id);
    this.aliasVersion++;
    return target;
  }

  mergeSessionOverlaps(group, sessionId, now) {
    if (!sessionId) return group;
    let current = group;
    let pending = [sessionId];
    while (pending.length) {
      const sharedSessionId = pending.pop();
      const owners = [...(this.sessionIndex.get(sharedSessionId) || [])];
      let merged = false;
      for (const id of owners) {
        const peer = this.groups.get(id);
        if (!peer || peer === current || now - peer.lastSeen > this.ttlMs) continue;
        current = this.merge(current, peer, sharedSessionId, now);
        merged = true;
        break;
      }
      if (merged) pending = [...current.sessionIds];
    }
    return current;
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
      sessionIds: new Set(),
      verifiedClientIds,
      observations: new Map([[candidateId, observation]]),
      links: [],
      // Client Flow는 신원 병합이 아니라 요청 흐름 연결이다. 서로 다른 verified
      // DCID는 별도 Resolved Actor 경계로 보존하되 Flow 연결을 끊는 충돌로 보지 않는다.
      conflicts: [],
      firstSeen: now,
      lastSeen: now,
      aggregationEnabled: false,
      maxAttackScore: 0,
    };
    this.groups.set(id, group);
    this.candidateIndex.set(candidateId, id);
    this.addSession(group, sessionId);
    const linked = this.mergeSessionOverlaps(group, sessionId, now);
    this.enforceLimits();
    return linked;
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
      indexed.observations.set(candidateId, observation);
      if (indexed.anchorCandidateId === candidateId) indexed.anchorObservation = observation;
      this.addSession(indexed, sessionId);
      if (clientIdentity?.continuityVerified && clientIdentity.clientId) {
        indexed.verifiedClientIds.add(clientIdentity.clientId);
        while (indexed.verifiedClientIds.size > 100) indexed.verifiedClientIds.delete(indexed.verifiedClientIds.values().next().value);
      }
      return this.mergeSessionOverlaps(indexed, sessionId, ts);
    }

    let best = null;
    for (const group of this.groups.values()) {
      if (ts - group.lastSeen > this.ttlMs) continue;
      if (sessionId && group.sessionIds.has(sessionId)) {
        best = { group, comparison: compareClientObservations(group.anchorObservation, observation),
          eligibility: { eligible: true, reason: "shared_session_continuity" } };
        break;
      }
      if (group.candidateIds.size >= this.maxCandidates) continue;
      const comparison = compareClientObservations(group.anchorObservation, observation);
      const eligibility = canAutoAggregate(comparison, group.anchorObservation, observation, {
        windowMs: this.ttlMs,
        allowIpRotation: this.allowIpRotation,
      });
      if (!eligibility.eligible) continue;
      if (!best || comparison.score > best.comparison.score) {
        best = { group, comparison, eligibility };
      }
    }

    if (!best) return this.create(candidateId, observation, sessionId, clientIdentity, ts);

    const { group, comparison, eligibility } = best;
    group.candidateIds.add(candidateId);
    group.observations.set(candidateId, observation);
    this.addSession(group, sessionId);
    if (clientIdentity?.continuityVerified && clientIdentity.clientId) {
      group.verifiedClientIds.add(clientIdentity.clientId);
      while (group.verifiedClientIds.size > 100) group.verifiedClientIds.delete(group.verifiedClientIds.values().next().value);
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
    group.lastSeen = ts;
    group.aggregationEnabled = group.conflicts.length === 0 && group.candidateIds.size > 1;
    this.candidateIndex.set(candidateId, group.id);
    return this.mergeSessionOverlaps(group, sessionId, ts);
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
    return id ? this.groups.get(id) : null;
  }

  getAll() {
    return [...this.groups.values()];
  }

  pruneSessions(isRetained) {
    for (const group of this.groups.values()) {
      for (const id of group.sessionIds) {
        if (isRetained(id)) continue;
        group.sessionIds.delete(id);
        const owners = this.sessionIndex.get(id);
        if (owners) {
          owners.delete(group.id);
          if (!owners.size) this.sessionIndex.delete(id);
        }
      }
    }
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
    for (const alias of aliases) this.aliases.delete(alias);
    for (const candidateId of group.candidateIds) this.candidateIndex.delete(candidateId);
    for (const sessionId of group.sessionIds) {
      const owners = this.sessionIndex.get(sessionId);
      if (!owners) continue;
      owners.delete(group.id);
      if (!owners.size) this.sessionIndex.delete(sessionId);
    }
    this.groups.delete(group.id);
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
      maxCandidates: this.maxCandidates,
      maxGroups: this.maxGroups,
      allowIpRotation: this.allowIpRotation,
      groups: this.groups.size,
      aggregatingGroups: [...this.groups.values()].filter((group) => group.aggregationEnabled).length,
    };
  }
}

module.exports = { ClientFlowStore };
