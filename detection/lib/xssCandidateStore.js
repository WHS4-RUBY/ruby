'use strict';

/**
 * xssCandidateStore.js
 *
 * Stored XSS 대조용 인메모리 후보 저장소. 쓰기 요청(리뷰/댓글/프로필 등록 등)에서 관찰한
 * "나중에 다른 응답으로 새어 나올 수 있는 값"을 작성 요청과 값 기준으로 보관하고,
 * xssReflection.analyze()가 나중 응답과 대조할 수 있게 한다.
 *
 * 우리 파이썬 CandidateStore를 이식한 것. Map은 삽입 순서를 보존하므로 그걸로 LRU를 구현.
 * TTL 만료 + 최대 개수 초과 시 가장 오래된 것부터 제거.
 */

const DEFAULT_TTL_MS = 60 * 60 * 1000; // 1시간
const DEFAULT_MAX_ENTRIES = 2000;
const DEFAULT_MAX_BYTES = 4 * 1024 * 1024;
const DEFAULT_MAX_VALUE_BYTES = 4096;

function positiveInt(value, fallback) {
  return Number.isSafeInteger(Number(value)) && Number(value) > 0 ? Number(value) : fallback;
}

const META_CHARS = new Set(['<', '>', '"', "'", '(', ')', ';', '`']);
function hasMetaChars(value) {
  for (const ch of value) if (META_CHARS.has(ch)) return true;
  return false;
}

class XssCandidateStore {
  constructor({ ttlMs = DEFAULT_TTL_MS, maxEntries = DEFAULT_MAX_ENTRIES,
    maxBytes = DEFAULT_MAX_BYTES, maxValueBytes = DEFAULT_MAX_VALUE_BYTES, now = Date.now } = {}) {
    this.ttlMs = positiveInt(ttlMs, DEFAULT_TTL_MS);
    this.maxEntries = positiveInt(maxEntries, DEFAULT_MAX_ENTRIES);
    this.maxBytes = positiveInt(maxBytes, DEFAULT_MAX_BYTES);
    this.maxValueBytes = positiveInt(maxValueBytes, DEFAULT_MAX_VALUE_BYTES);
    this.bytes = 0;
    this._now = now;
    this._map = new Map(); // (write request, value) -> candidate with bounded origin metadata
  }

  /**
   * 후보 값들을 관찰해 저장한다(메타문자 없는 값은 XSS가 될 수 없어 무시).
   * @returns {number} 이번 호출로 새로 추가된 작성 요청/값의 개수
   */
  observe(candidates, endpoint, origin = null) {
    this._evictExpired();
    let added = 0;
    const now = this._now();
    for (const c of candidates || []) {
      if (!c || typeof c.value !== 'string' || !hasMetaChars(c.value)) continue;
      // Preserve writer provenance; equal values from independent writes are not one identity.
      if (Buffer.byteLength(c.value, 'utf8') > this.maxValueBytes) continue;
      const candidateKey = JSON.stringify([origin?.requestId || null, c.value]);
      const existing = this._map.get(candidateKey);
      if (existing) {
        existing.lastSeen = now;
        existing.timesSeen += 1;
        const { byteSize, ...serialized } = existing;
        existing.byteSize = Buffer.byteLength(JSON.stringify(serialized), 'utf8');
        this.bytes += existing.byteSize - byteSize;
        this._map.delete(candidateKey);
        this._map.set(candidateKey, existing); // 최근 사용으로 이동(LRU)
      } else {
        const entry = {
          candidateKey,
          value: c.value,
          parameter: String(c.parameter || '').slice(0, 128),
          source: String(c.source || '').slice(0, 32),
          endpoint: endpoint ? String(endpoint).slice(0, 2048) : null,
          origin: origin ? Object.fromEntries(
            ['requestId', 'sessionId', 'actorId', 'resolvedActorId', 'authGroupId', 'clientFlowId', 'ip']
              .map((name) => [name, typeof origin[name] === 'string' ? origin[name].slice(0, 256) : null])
          ) : null,
          firstSeen: now,
          lastSeen: now,
          timesSeen: 1,
        };
        entry.byteSize = Buffer.byteLength(JSON.stringify(entry), 'utf8');
        if (entry.byteSize > this.maxBytes) continue;
        this._map.set(candidateKey, entry);
        this.bytes += entry.byteSize;
        added += 1;
      }
    }
    this._evictOverflow();
    return added;
  }

  /** 만료되지 않은 모든 후보를 배열로 반환. */
  all() {
    this._evictExpired();
    return [...this._map.values()];
  }

  size() {
    this._evictExpired();
    return this._map.size;
  }

  clear() {
    this._map.clear();
    this.bytes = 0;
  }

  /** 특정 작성 요청의 후보만 제거한다(stored XSS detect-once). */
  delete(candidateKey) {
    const entry = this._map.get(candidateKey);
    if (!entry) return false;
    this.bytes -= entry.byteSize;
    return this._map.delete(candidateKey);
  }

  _evictExpired() {
    const cutoff = this._now() - this.ttlMs;
    for (const [key, entry] of this._map) {
      if (entry.lastSeen < cutoff) this.delete(key);
    }
  }

  _evictOverflow() {
    while (this._map.size > this.maxEntries || this.bytes > this.maxBytes) {
      const oldest = this._map.keys().next().value; // 삽입/사용 순 가장 오래된 것
      this.delete(oldest);
    }
  }
}

module.exports = { XssCandidateStore, DEFAULT_TTL_MS, DEFAULT_MAX_ENTRIES };
