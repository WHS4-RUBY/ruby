const crypto = require("crypto");

const RESOLVER_VERSION = "session-resolution-v3";
const MEMBERSHIP_STATUS = Object.freeze({
  CONFIRMED: "CONFIRMED",
  PROVISIONAL: "PROVISIONAL",
  SUGGESTED: "SUGGESTED",
  CONFLICT: "CONFLICT",
});
const CONFIDENCE = Object.freeze({
  HIGH: "HIGH",
  MEDIUM: "MEDIUM",
  LOW: "LOW",
  NONE: "NONE",
});

function positiveNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function addBoundedUnique(array, value, maximum) {
  if (value === undefined || value === null || value === "") return;
  const normalized = String(value);
  const index = array.indexOf(normalized);
  if (index >= 0) array.splice(index, 1);
  array.push(normalized);
  while (array.length > maximum) array.shift();
}

function hasClientIdentity(clientIdentity) {
  return Boolean(clientIdentity?.valid && clientIdentity.clientId);
}

function hasVerifiedContinuity(clientIdentity) {
  return Boolean(
    hasClientIdentity(clientIdentity) &&
    (clientIdentity.continuityVerified === true || clientIdentity.source === "verified")
  );
}

class ActorResolver {
  constructor({
    now = () => Date.now(),
    ttlMs = positiveNumber(process.env.RESOLVED_ACTOR_TTL_MS, 7 * 24 * 60 * 60_000),
    maxActors = positiveNumber(process.env.MAX_RESOLVED_ACTORS, 5_000),
    maxMemberships = positiveNumber(process.env.MAX_RESOLUTION_MEMBERSHIPS, 20_000),
    maxHistory = positiveNumber(process.env.MAX_RESOLUTION_HISTORY, 100),
    maxObservedIps = positiveNumber(process.env.MAX_RESOLVED_ACTOR_IPS, 50),
    maxRelatedLinks = positiveNumber(process.env.MAX_RESOLUTION_RELATED_LINKS, 5),
    suggestionWindowMs = positiveNumber(process.env.RESOLUTION_SUGGESTION_WINDOW_MS, 5 * 60_000),
  } = {}) {
    this.now = now;
    this.ttlMs = ttlMs;
    this.maxActors = maxActors;
    this.maxMemberships = maxMemberships;
    this.maxHistory = maxHistory;
    this.maxObservedIps = maxObservedIps;
    this.maxRelatedLinks = maxRelatedLinks;
    this.suggestionWindowMs = suggestionWindowMs;
    this.actors = new Map();
    this.memberships = new Map();
    this.sessionMembershipIds = new Map();
    this.sessionPrimaryMembership = new Map();
    this.clientIndex = new Map();
    this.authIndex = new Map();
    this.accountIndex = new Map();
    this.fingerprintIndex = new Map();
  }

  createActor(now, preferredId = null) {
    const actor = {
      id: preferredId || `resolved:${crypto.randomUUID()}`,
      firstSeen: now,
      lastSeen: now,
      membershipIds: new Set(),
      observedIps: new Map(),
      clientIds: new Map(),
      accountAffiliations: new Map(),
      authGroupIds: new Map(),
      candidateIds: new Set(),
      evidence: [],
      conflicts: [],
      fingerprints: new Map(),
      recentOperations: [],
      totalRequests: 0,
      ipChangeCount: 0,
      lastObservedIp: null,
    };
    this.actors.set(actor.id, actor);
    return actor;
  }

  indexAdd(index, key, actorId) {
    if (!key) return;
    if (!index.has(key)) index.set(key, new Set());
    index.get(key).add(actorId);
  }

  capMap(actor, map, index = null) {
    while (map.size > this.maxHistory) {
      const oldestKey = map.keys().next().value;
      map.delete(oldestKey);
      if (index) {
        index.get(oldestKey)?.delete(actor.id);
        if (index.get(oldestKey)?.size === 0) index.delete(oldestKey);
      }
    }
  }

  capSet(set) {
    while (set.size > this.maxHistory) set.delete(set.values().next().value);
  }

  recordEvidence(actor, code, now, relatedActorId = null) {
    const existing = actor.evidence.find(
      (item) => item.code === code && item.relatedActorId === relatedActorId
    );
    if (existing) {
      existing.count++;
      existing.lastSeen = now;
      return;
    }
    actor.evidence.push({ code, relatedActorId, count: 1, firstSeen: now, lastSeen: now });
    while (actor.evidence.length > this.maxHistory) actor.evidence.shift();
  }

  recordConflict(actor, code, now, detail = null) {
    const existing = actor.conflicts.find((item) => item.code === code && item.detail === detail);
    if (existing) {
      existing.count++;
      existing.lastSeen = now;
      return;
    }
    actor.conflicts.push({ code, detail, count: 1, firstSeen: now, lastSeen: now });
    while (actor.conflicts.length > this.maxHistory) actor.conflicts.shift();
  }

  createMembership({
    actor,
    sessionId,
    candidateId,
    status,
    confidence,
    reasonCodes = [],
    conflicts = [],
    clientId = null,
    now,
  }) {
    const existing = Array.from(actor.membershipIds, (id) => this.memberships.get(id)).find(
      (membership) =>
        membership && membership.active && membership.sessionId === sessionId && membership.status === status
    );
    if (existing) {
      addBoundedUnique(existing.candidateIds, candidateId, this.maxHistory);
      for (const reason of reasonCodes) addBoundedUnique(existing.reasonCodes, reason, this.maxHistory);
      for (const conflict of conflicts) addBoundedUnique(existing.conflicts, conflict, this.maxHistory);
      existing.updatedAt = now;
      existing.lastConfirmedAt = status === MEMBERSHIP_STATUS.CONFIRMED ? now : existing.lastConfirmedAt;
      return existing;
    }

    const membership = {
      membershipId: `membership:${crypto.randomUUID()}`,
      resolvedActorId: actor.id,
      sessionId,
      candidateId,
      candidateIds: candidateId ? [candidateId] : [],
      status,
      confidence,
      reasonCodes: [...new Set(reasonCodes)],
      conflicts: [...new Set(conflicts)],
      createdAt: now,
      updatedAt: now,
      lastConfirmedAt: status === MEMBERSHIP_STATUS.CONFIRMED ? now : null,
      active: true,
      resolverVersion: RESOLVER_VERSION,
      clientId,
      requestCount: 0,
    };
    this.memberships.set(membership.membershipId, membership);
    actor.membershipIds.add(membership.membershipId);
    if (!this.sessionMembershipIds.has(sessionId)) this.sessionMembershipIds.set(sessionId, new Set());
    this.sessionMembershipIds.get(sessionId).add(membership.membershipId);
    return membership;
  }

  findOrCreateClientActor(clientId, now) {
    const indexed = this.clientIndex.get(clientId);
    if (indexed && this.actors.has(indexed)) return this.actors.get(indexed);
    // clientId는 원본 dcid가 아니라 이미 가명화된 값이다. 같은 signed dcid가
    // 검증되면 인메모리 저장소가 재시작돼도 동일한 Resolved Actor ID를 재생성한다.
    const stableId = `resolved:${crypto
      .createHash("sha256")
      .update(`verified-dcid\u0000${clientId}`)
      .digest("hex")
      .slice(0, 32)}`;
    const actor = this.actors.get(stableId) || this.createActor(now, stableId);
    this.clientIndex.set(clientId, actor.id);
    return actor;
  }

  promoteReturnedClient(actor, clientId, now) {
    if (!actor || !clientId || this.clientIndex.get(clientId) !== actor.id) return;
    for (const membershipId of actor.membershipIds) {
      const membership = this.memberships.get(membershipId);
      if (
        !membership?.active ||
        membership.clientId !== clientId ||
        membership.status !== MEMBERSHIP_STATUS.PROVISIONAL ||
        !membership.reasonCodes.includes("dcid_issued_not_returned")
      ) {
        continue;
      }
      membership.status = MEMBERSHIP_STATUS.CONFIRMED;
      membership.confidence = CONFIDENCE.HIGH;
      membership.updatedAt = now;
      membership.lastConfirmedAt = now;
      addBoundedUnique(membership.reasonCodes, "signed_dcid_returned", this.maxHistory);
    }
    this.recordEvidence(actor, "signed_dcid_returned", now);
  }

  observeActor(actor, observation, membership) {
    const {
      now,
      ip,
      candidateId,
      clientIdentity,
      authGroupId,
      accountIdentity,
      fingerprint,
      operation,
    } = observation;
    actor.lastSeen = now;
    actor.totalRequests++;
    membership.requestCount++;
    if (candidateId) {
      if (membership.candidateIds.length && !membership.candidateIds.includes(String(candidateId))) {
        this.recordEvidence(actor, "candidate_changed", now);
        addBoundedUnique(membership.reasonCodes, "candidate_changed", this.maxHistory);
      }
      actor.candidateIds.add(candidateId);
      this.capSet(actor.candidateIds);
    }
    addBoundedUnique(membership.candidateIds, candidateId, this.maxHistory);
    membership.updatedAt = now;
    if (membership.status === MEMBERSHIP_STATUS.CONFIRMED) membership.lastConfirmedAt = now;

    if (ip) {
      if (actor.lastObservedIp !== null && actor.lastObservedIp !== ip) {
        actor.ipChangeCount++;
        this.recordEvidence(actor, "ip_changed", now);
        addBoundedUnique(membership.reasonCodes, "ip_changed", this.maxHistory);
      }
      actor.lastObservedIp = ip;
      const entry = actor.observedIps.get(ip) || { ip, firstSeen: now, lastSeen: now, count: 0 };
      entry.lastSeen = now;
      entry.count++;
      actor.observedIps.delete(ip);
      actor.observedIps.set(ip, entry);
      while (actor.observedIps.size > this.maxObservedIps) {
        actor.observedIps.delete(actor.observedIps.keys().next().value);
      }
    }

    if (
      hasClientIdentity(clientIdentity) &&
      clientIdentity.clientId &&
      (!membership.clientId || membership.clientId === clientIdentity.clientId)
    ) {
      const clientId = clientIdentity.clientId;
      membership.clientId = membership.clientId || clientId;
      const entry = actor.clientIds.get(clientId) || {
        clientId,
        firstSeen: now,
        lastSeen: now,
        version: clientIdentity.version,
      };
      entry.lastSeen = now;
      actor.clientIds.set(clientId, entry);
      this.clientIndex.set(clientId, actor.id);
      this.capMap(actor, actor.clientIds, this.clientIndex);
      const continuityReason = hasVerifiedContinuity(clientIdentity)
        ? membership.reasonCodes.includes("same_signed_dcid")
          ? "same_signed_dcid"
          : "valid_signed_dcid"
        : "dcid_issued_not_returned";
      this.recordEvidence(actor, continuityReason, now);
    }

    if (accountIdentity?.accountId) {
      const existingVerified = Array.from(actor.accountAffiliations.values()).filter(
        (entry) => entry.verified && entry.accountId !== accountIdentity.accountId
      );
      if (accountIdentity.verified && existingVerified.length) {
        this.recordEvidence(actor, "account_changed", now);
        addBoundedUnique(membership.reasonCodes, "account_changed", this.maxHistory);
      }
      const entry = actor.accountAffiliations.get(accountIdentity.accountId) || {
        accountId: accountIdentity.accountId,
        verified: Boolean(accountIdentity.verified),
        verification: accountIdentity.verification,
        claim: accountIdentity.claim,
        firstSeen: now,
        lastSeen: now,
        authGroupIds: new Set(),
      };
      entry.verified = entry.verified || Boolean(accountIdentity.verified);
      entry.verification = accountIdentity.verification;
      entry.lastSeen = now;
      if (authGroupId) entry.authGroupIds.add(authGroupId);
      this.capSet(entry.authGroupIds);
      actor.accountAffiliations.set(accountIdentity.accountId, entry);
      this.capMap(actor, actor.accountAffiliations, this.accountIndex);
    }

    if (authGroupId) {
      if (actor.authGroupIds.has(authGroupId)) {
        this.recordEvidence(actor, "auth_continuity", now);
        addBoundedUnique(membership.reasonCodes, "auth_continuity", this.maxHistory);
      } else if (actor.authGroupIds.size > 0) {
        this.recordEvidence(actor, "auth_group_changed", now);
        addBoundedUnique(membership.reasonCodes, "auth_group_changed", this.maxHistory);
      }
      const entry = actor.authGroupIds.get(authGroupId) || {
        authGroupId,
        firstSeen: now,
        lastSeen: now,
        count: 0,
      };
      entry.lastSeen = now;
      entry.count++;
      actor.authGroupIds.set(authGroupId, entry);
      this.capMap(actor, actor.authGroupIds, this.authIndex);
    }
    if (fingerprint) {
      actor.fingerprints.delete(fingerprint);
      actor.fingerprints.set(fingerprint, now);
      this.capMap(actor, actor.fingerprints, this.fingerprintIndex);
    }
    if (operation) addBoundedUnique(actor.recentOperations, operation, 10);
  }

  crossLink(observation, primaryActor, primaryMembership) {
    const {
      sessionId,
      candidateId,
      clientIdentity,
      authGroupId,
      accountIdentity,
      fingerprint,
      operation,
      now,
    } = observation;
    const related = new Map();

    if (authGroupId) {
      for (const actorId of this.authIndex.get(authGroupId) || []) {
        if (actorId === primaryActor.id || !this.actors.has(actorId)) continue;
        const actor = this.actors.get(actorId);
        const hasSupportingContinuity =
          (fingerprint && actor.fingerprints.has(fingerprint)) ||
          (accountIdentity?.verified && actor.accountAffiliations.get(accountIdentity.accountId)?.verified);
        related.set(actorId, {
          status: hasSupportingContinuity ? MEMBERSHIP_STATUS.PROVISIONAL : MEMBERSHIP_STATUS.SUGGESTED,
          confidence: hasSupportingContinuity ? CONFIDENCE.MEDIUM : CONFIDENCE.LOW,
          reasons: hasSupportingContinuity
            ? ["auth_continuity", fingerprint && actor.fingerprints.has(fingerprint) ? "same_header_fingerprint" : "verified_account_continuity"].filter(Boolean)
            : ["same_auth_credential_observed"],
        });
      }
    }

    if (accountIdentity?.verified) {
      for (const actorId of this.accountIndex.get(accountIdentity.accountId) || []) {
        if (actorId === primaryActor.id || !this.actors.has(actorId)) continue;
        related.set(actorId, {
          status: MEMBERSHIP_STATUS.PROVISIONAL,
          confidence: CONFIDENCE.MEDIUM,
          reasons: ["verified_account_continuity", "client_continuity_unconfirmed"],
        });
      }
    }

    if (fingerprint && operation) {
      for (const actorId of this.fingerprintIndex.get(fingerprint) || []) {
        if (actorId === primaryActor.id || !this.actors.has(actorId) || related.has(actorId)) continue;
        const actor = this.actors.get(actorId);
        if (now - actor.lastSeen > this.suggestionWindowMs) continue;
        if (!actor.recentOperations.includes(operation)) continue;
        related.set(actorId, {
          status: MEMBERSHIP_STATUS.SUGGESTED,
          confidence: CONFIDENCE.LOW,
          reasons: ["same_header_fingerprint", "similar_operation_flow"],
        });
      }
    }

    const selectedLinks = [...related.entries()]
      .sort((left, right) => this.actors.get(right[0]).lastSeen - this.actors.get(left[0]).lastSeen)
      .slice(0, this.maxRelatedLinks);
    for (const [actorId, link] of selectedLinks) {
      const target = this.actors.get(actorId);
      const differentClient =
        hasVerifiedContinuity(clientIdentity) &&
        target.clientIds.size > 0 &&
        !target.clientIds.has(clientIdentity.clientId);
      const conflicts = differentClient ? ["different_signed_dcid"] : [];
      this.createMembership({
        actor: target,
        sessionId,
        candidateId,
        status: link.status,
        confidence: link.confidence,
        reasonCodes: link.reasons,
        conflicts,
        clientId: clientIdentity?.clientId || null,
        now,
      });
      this.recordEvidence(target, link.reasons[0], now, primaryActor.id);
      this.recordEvidence(primaryActor, link.reasons[0], now, target.id);
    }

    this.indexAdd(this.authIndex, authGroupId, primaryActor.id);
    if (accountIdentity?.verified) {
      this.indexAdd(this.accountIndex, accountIdentity.accountId, primaryActor.id);
    }
    this.indexAdd(this.fingerprintIndex, fingerprint, primaryActor.id);
    return primaryMembership;
  }

  observe({
    sessionId,
    candidateId,
    ip,
    clientIdentity = null,
    authGroupId = null,
    accountIdentity = null,
    fingerprint = null,
    operation = null,
    ts,
  }) {
    const now = Number.isFinite(ts) ? ts : this.now();
    this.cleanup(now);
    let primaryMembership = this.memberships.get(this.sessionPrimaryMembership.get(sessionId));
    let actor = primaryMembership ? this.actors.get(primaryMembership.resolvedActorId) : null;
    let clientConflict = false;

    if (!actor || !primaryMembership?.active) {
      const hasClient = hasClientIdentity(clientIdentity);
      const continuityVerified = hasVerifiedContinuity(clientIdentity);
      actor = hasClient
        ? this.findOrCreateClientActor(clientIdentity.clientId, now)
        : this.createActor(now);
      const existingClientActor = hasClient && actor.membershipIds.size > 0;
      primaryMembership = this.createMembership({
        actor,
        sessionId,
        candidateId,
        status: continuityVerified ? MEMBERSHIP_STATUS.CONFIRMED : MEMBERSHIP_STATUS.PROVISIONAL,
        confidence: continuityVerified ? CONFIDENCE.HIGH : CONFIDENCE.MEDIUM,
        reasonCodes: continuityVerified
          ? [existingClientActor ? "same_signed_dcid" : "valid_signed_dcid"]
          : hasClient
            ? ["dcid_issued_not_returned"]
          : ["client_continuity_unavailable"],
        clientId: hasClient ? clientIdentity.clientId : null,
        now,
      });
      this.sessionPrimaryMembership.set(sessionId, primaryMembership.membershipId);
      if (continuityVerified) this.promoteReturnedClient(actor, clientIdentity.clientId, now);
    } else if (
      hasVerifiedContinuity(clientIdentity) &&
      primaryMembership.clientId === clientIdentity.clientId
    ) {
      this.promoteReturnedClient(actor, clientIdentity.clientId, now);
    } else if (
      hasVerifiedContinuity(clientIdentity) &&
      primaryMembership.clientId &&
      primaryMembership.clientId !== clientIdentity.clientId
    ) {
      clientConflict = true;
      const code = "signed_dcid_changed_within_session";
      this.recordConflict(actor, code, now, clientIdentity.clientId);
      addBoundedUnique(primaryMembership.conflicts, code, this.maxHistory);
      const conflictingActor = this.findOrCreateClientActor(clientIdentity.clientId, now);
      this.createMembership({
        actor: conflictingActor,
        sessionId,
        candidateId,
        status: MEMBERSHIP_STATUS.CONFLICT,
        confidence: CONFIDENCE.NONE,
        reasonCodes: [],
        conflicts: [code],
        clientId: clientIdentity.clientId,
        now,
      });
    }

    const observation = {
      sessionId,
      candidateId,
      ip,
      clientIdentity: clientConflict ? null : clientIdentity,
      authGroupId,
      accountIdentity,
      fingerprint,
      operation,
      now,
    };
    this.observeActor(actor, observation, primaryMembership);
    this.crossLink(observation, actor, primaryMembership);
    this.enforceLimits(now);
    return {
      resolvedActorId: actor.id,
      membershipId: primaryMembership.membershipId,
      status: primaryMembership.status,
      confidence: primaryMembership.confidence,
    };
  }

  deactivateMembership(membershipId, reason = "revoked") {
    const membership = this.memberships.get(membershipId);
    if (!membership || !membership.active) return false;
    membership.active = false;
    membership.updatedAt = this.now();
    addBoundedUnique(membership.conflicts, reason, this.maxHistory);
    if (this.sessionPrimaryMembership.get(membership.sessionId) === membershipId) {
      this.sessionPrimaryMembership.delete(membership.sessionId);
    }
    return true;
  }

  getActor(id) {
    return this.actors.get(id);
  }

  getAllActors() {
    return Array.from(this.actors.values());
  }

  getMembership(id) {
    return this.memberships.get(id);
  }

  getMembershipsForActor(actorId) {
    const actor = this.actors.get(actorId);
    if (!actor) return [];
    return Array.from(actor.membershipIds, (id) => this.memberships.get(id)).filter(Boolean);
  }

  getMembershipsForSession(sessionId) {
    return Array.from(this.sessionMembershipIds.get(sessionId) || [], (id) => this.memberships.get(id)).filter(Boolean);
  }

  getPrimaryResolution(sessionId) {
    const membership = this.memberships.get(this.sessionPrimaryMembership.get(sessionId));
    if (!membership?.active) return null;
    return {
      resolvedActorId: membership.resolvedActorId,
      membershipId: membership.membershipId,
      status: membership.status,
      confidence: membership.confidence,
    };
  }

  removeActor(actorId) {
    const actor = this.actors.get(actorId);
    if (!actor) return;
    for (const membershipId of actor.membershipIds) {
      const membership = this.memberships.get(membershipId);
      if (membership) {
        this.sessionMembershipIds.get(membership.sessionId)?.delete(membershipId);
        if (this.sessionPrimaryMembership.get(membership.sessionId) === membershipId) {
          this.sessionPrimaryMembership.delete(membership.sessionId);
        }
      }
      this.memberships.delete(membershipId);
    }
    for (const [key, value] of this.clientIndex) if (value === actorId) this.clientIndex.delete(key);
    for (const index of [this.authIndex, this.accountIndex, this.fingerprintIndex]) {
      for (const [key, ids] of index) {
        ids.delete(actorId);
        if (!ids.size) index.delete(key);
      }
    }
    this.actors.delete(actorId);
  }

  cleanup(now = this.now()) {
    for (const actor of this.actors.values()) {
      if (now - actor.lastSeen > this.ttlMs) this.removeActor(actor.id);
    }
  }

  enforceLimits() {
    while (this.actors.size > this.maxActors || this.memberships.size > this.maxMemberships) {
      const oldest = [...this.actors.values()].sort((a, b) => a.lastSeen - b.lastSeen)[0];
      if (!oldest) break;
      this.removeActor(oldest.id);
    }
  }

  status() {
    return {
      resolverVersion: RESOLVER_VERSION,
      resolvedActors: this.actors.size,
      memberships: this.memberships.size,
      ttlMs: this.ttlMs,
      maxActors: this.maxActors,
      maxMemberships: this.maxMemberships,
      maxRelatedLinks: this.maxRelatedLinks,
      confirmedOnlyForDetection: true,
    };
  }
}

module.exports = { ActorResolver, MEMBERSHIP_STATUS, CONFIDENCE, RESOLVER_VERSION };
