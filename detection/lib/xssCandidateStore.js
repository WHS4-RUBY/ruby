'use strict';

/**
 * xssCandidateStore.js
 *
 * Stored XSS 대조용 인메모리 후보 저장소. 쓰기 요청(리뷰/댓글/프로필 등록 등)에서 관찰한
 * "나중에 다른 응답으로 새어 나올 수 있는 값"을 값 기준으로 중복 제거해 쌓아두고,
 * xssReflection.analyze()가 나중 응답과 대조할 수 있게 한다.
 *
 * 우리 파이썬 CandidateStore를 이식한 것. Map은 삽입 순서를 보존하므로 그걸로 LRU를 구현.
 * TTL 만료 + 최대 개수 초과 시 가장 오래된 것부터 제거.
 */

const DEFAULT_TTL_MS = 60 * 60 * 1000; // 1시간
const DEFAULT_MAX_ENTRIES = 2000;

const META_CHARS = new Set(['<', '>', '"', "'", '(', ')', ';', '`']);
function hasMetaChars(value) {
  for (const ch of value) if (META_CHARS.has(ch)) return true;
  return false;
}

class XssCandidateStore {
  constructor({ ttlMs = DEFAULT_TTL_MS, maxEntries = DEFAULT_MAX_ENTRIES, now = Date.now } = {}) {
    this.ttlMs = ttlMs > 0 ? ttlMs : DEFAULT_TTL_MS;
    this.maxEntries = maxEntries > 0 ? maxEntries : DEFAULT_MAX_ENTRIES;
    this._now = now;
    this._map = new Map(); // value -> { value, parameter, source, endpoint, firstSeen, lastSeen, timesSeen }
  }

  /**
   * 후보 값들을 관찰해 저장한다(메타문자 없는 값은 XSS가 될 수 없어 무시).
   * @returns {number} 이번 호출로 새로 추가된(처음 보는) 값의 개수
   */
  observe(candidates, endpoint) {
    this._evictExpired();
    let added = 0;
    const now = this._now();
    for (const c of candidates || []) {
      if (!c || typeof c.value !== 'string' || !hasMetaChars(c.value)) continue;
      const existing = this._map.get(c.value);
      if (existing) {
        existing.lastSeen = now;
        existing.timesSeen += 1;
        this._map.delete(c.value);
        this._map.set(c.value, existing); // 최근 사용으로 이동(LRU)
      } else {
        this._map.set(c.value, {
          value: c.value,
          parameter: c.parameter,
          source: c.source,
          endpoint: endpoint || null,
          firstSeen: now,
          lastSeen: now,
          timesSeen: 1,
        });
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
  }

  /** 특정 값 후보를 제거한다(stored XSS로 탐지되면 더 이상 비교하지 않기 위해). */
  delete(value) {
    return this._map.delete(value);
  }

  _evictExpired() {
    const cutoff = this._now() - this.ttlMs;
    for (const [value, entry] of this._map) {
      if (entry.lastSeen < cutoff) this._map.delete(value);
    }
  }

  _evictOverflow() {
    while (this._map.size > this.maxEntries) {
      const oldest = this._map.keys().next().value; // 삽입/사용 순 가장 오래된 것
      this._map.delete(oldest);
    }
  }
}

module.exports = { XssCandidateStore, DEFAULT_TTL_MS, DEFAULT_MAX_ENTRIES };
