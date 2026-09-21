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

class ClientFlowStore {
  constructor({
    ttlMs = positiveNumber(process.env.FINGERPRINT_SIMILARITY_TTL_MS, 30 * 60_000),
    maxCandidates = positiveNumber(process.env.FINGERPRINT_MAX_FLOW_CANDIDATES, 3),
    maxGroups = positiveNumber(process.env.MAX_CLIENT_FLOWS, 5_000),
  } = {}) {
    this.ttlMs = ttlMs;
    this.maxCandidates = maxCandidates;
    this.maxGroups = maxGroups;
    this.groups = new Map();
    this.candidateIndex = new Map();
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
      sessionIds: new Set(sessionId ? [sessionId] : []),
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
    this.enforceLimits();
    return group;
  }

  observe({ candidateId, observation, sessionId, clientIdentity = null, ts = Date.now() }) {
    this.cleanup(ts);
    const indexed = this.getByCandidate(candidateId);
    if (indexed) {
      indexed.lastSeen = ts;
      indexed.observations.set(candidateId, observation);
      if (indexed.anchorCandidateId === candidateId) indexed.anchorObservation = observation;
      if (sessionId) indexed.sessionIds.add(sessionId);
      if (clientIdentity?.continuityVerified && clientIdentity.clientId) {
        indexed.verifiedClientIds.add(clientIdentity.clientId);
      }
      return indexed;
    }

    let best = null;
    for (const group of this.groups.values()) {
      if (ts - group.lastSeen > this.ttlMs || group.candidateIds.size >= this.maxCandidates) continue;
      const comparison = compareClientObservations(group.anchorObservation, observation);
      const eligibility = canAutoAggregate(comparison, group.anchorObservation, observation, {
        windowMs: this.ttlMs,
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
    if (sessionId) group.sessionIds.add(sessionId);
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
    group.lastSeen = ts;
    group.aggregationEnabled = group.conflicts.length === 0 && group.candidateIds.size > 1;
    this.candidateIndex.set(candidateId, group.id);
    return group;
  }

  updateAttackScore(groupId, score) {
    const group = this.groups.get(groupId);
    if (group && Number.isFinite(score)) group.maxAttackScore = Math.max(group.maxAttackScore, score);
  }

  get(id) {
    return this.groups.get(id);
  }

  getByCandidate(candidateId) {
    const id = this.candidateIndex.get(candidateId);
    return id ? this.groups.get(id) : null;
  }

  getAll() {
    return [...this.groups.values()];
  }

  cleanup(now = Date.now()) {
    for (const [id, group] of this.groups) {
      if (now - group.lastSeen <= this.ttlMs) continue;
      for (const candidateId of group.candidateIds) this.candidateIndex.delete(candidateId);
      this.groups.delete(id);
    }
  }

  remove(id) {
    const group = this.groups.get(id);
    if (!group) return;
    for (const candidateId of group.candidateIds) this.candidateIndex.delete(candidateId);
    this.groups.delete(id);
  }

  enforceLimits() {
    while (this.groups.size > this.maxGroups) {
      const oldest = [...this.groups.values()].sort((a, b) => a.lastSeen - b.lastSeen)[0];
      if (!oldest) break;
      this.remove(oldest.id);
    }
  }

  status() {
    return {
      similarityVersion: SIMILARITY_VERSION,
      ttlMs: this.ttlMs,
      maxCandidates: this.maxCandidates,
      maxGroups: this.maxGroups,
      groups: this.groups.size,
      aggregatingGroups: [...this.groups.values()].filter((group) => group.aggregationEnabled).length,
    };
  }
}

module.exports = { ClientFlowStore };
