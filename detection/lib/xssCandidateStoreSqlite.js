'use strict';

/**
 * xssCandidateStoreSqlite.js
 *
 * XssCandidateStore와 "완전히 동일한 인터페이스"를 SQLite(파일/메모리)로 구현한 드롭인 저장소.
 * Node 내장 node:sqlite 사용 → 서버·npm 불필요. 파일 모드면 재시작해도 후보 텍스트가 보존된다.
 *
 * 인메모리 버전과 동일하게 동작한다:
 *   - 키: candidateKey = JSON.stringify([origin?.requestId || null, value])  (작성요청+값 기준)
 *   - 메타문자 없는 값·maxValueBytes 초과 값은 무시
 *   - origin은 7개 필드(requestId/sessionId/actorId/resolvedActorId/authGroupId/clientFlowId/ip)만 보존
 *   - TTL 만료 + (maxEntries / maxBytes) 초과 시 가장 오래된 것부터 제거(LRU)
 *   - all() 반환 엔트리 모양은 인메모리와 동일 → xssReflection/xssAttribution 그대로 호환
 *
 * 성능: 쓰기 fsync 부담을 줄이려 WAL+synchronous=NORMAL. TTL/상한 정리는 읽기 경로가 아니라
 *       주기적 sweep(기본 60초)에서 수행 → all()은 순수 SELECT.
 */

const { DatabaseSync } = require('node:sqlite');

const DEFAULT_TTL_MS = 60 * 60 * 1000;            // 1시간
const DEFAULT_MAX_ENTRIES = 2000;
const DEFAULT_MAX_BYTES = 4 * 1024 * 1024;
const DEFAULT_MAX_VALUE_BYTES = 4096;
const SWEEP_INTERVAL_MS = 60 * 1000;              // TTL/상한 정리 최소 간격

const ORIGIN_FIELDS = ['requestId', 'sessionId', 'actorId', 'resolvedActorId', 'authGroupId', 'clientFlowId', 'ip'];

function positiveInt(value, fallback) {
  return Number.isSafeInteger(Number(value)) && Number(value) > 0 ? Number(value) : fallback;
}

const META_CHARS = new Set(['<', '>', '"', "'", '(', ')', ';', '`']);
function hasMetaChars(value) {
  for (const ch of value) if (META_CHARS.has(ch)) return true;
  return false;
}

function normalizeOrigin(origin) {
  if (!origin) return null;
  return Object.fromEntries(
    ORIGIN_FIELDS.map((name) => [name, typeof origin[name] === 'string' ? origin[name].slice(0, 256) : null])
  );
}

// 인메모리 버전과 동일한 방식으로 byteSize 계산(byteSize 필드 자신은 제외한 엔트리 직렬화 크기).
function entryByteSize(entry) {
  const { byteSize, ...rest } = entry;
  return Buffer.byteLength(JSON.stringify(rest), 'utf8');
}

class XssCandidateStoreSqlite {
  constructor({ ttlMs = DEFAULT_TTL_MS, maxEntries = DEFAULT_MAX_ENTRIES,
    maxBytes = DEFAULT_MAX_BYTES, maxValueBytes = DEFAULT_MAX_VALUE_BYTES,
    dbPath = ':memory:', now = Date.now } = {}) {
    this.ttlMs = positiveInt(ttlMs, DEFAULT_TTL_MS);
    this.maxEntries = positiveInt(maxEntries, DEFAULT_MAX_ENTRIES);
    this.maxBytes = positiveInt(maxBytes, DEFAULT_MAX_BYTES);
    this.maxValueBytes = positiveInt(maxValueBytes, DEFAULT_MAX_VALUE_BYTES);
    this._now = now;
    this._lastSweep = 0;

    this.db = new DatabaseSync(dbPath);
    if (dbPath !== ':memory:') {
      try { this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;'); } catch (_) {}
    }
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS cand(
        key TEXT PRIMARY KEY,
        value TEXT,
        parameter TEXT,
        source TEXT,
        endpoint TEXT,
        origin TEXT,
        first_seen INTEGER,
        last_seen INTEGER,
        times_seen INTEGER,
        byte_size INTEGER);
      CREATE INDEX IF NOT EXISTS idx_cand_last ON cand(last_seen);`);

    this._get = this.db.prepare('SELECT key,value,parameter,source,endpoint,origin,first_seen,last_seen,times_seen,byte_size FROM cand WHERE key=?');
    this._ins = this.db.prepare(`INSERT INTO cand(key,value,parameter,source,endpoint,origin,first_seen,last_seen,times_seen,byte_size)
      VALUES(?,?,?,?,?,?,?,?,1,?)`);
    this._touch = this.db.prepare('UPDATE cand SET last_seen=?, times_seen=times_seen+1, byte_size=? WHERE key=?');
    this._selAll = this.db.prepare(`SELECT key,value,parameter,source,endpoint,origin,first_seen,last_seen,times_seen,byte_size
      FROM cand WHERE last_seen>=? ORDER BY last_seen`);
    this._count = this.db.prepare('SELECT COUNT(*) AS c, COALESCE(SUM(byte_size),0) AS b FROM cand');
    this._del = this.db.prepare('DELETE FROM cand WHERE key=?');
    this._delExpired = this.db.prepare('DELETE FROM cand WHERE last_seen < ?');
    this._oldest = this.db.prepare('SELECT key FROM cand ORDER BY last_seen LIMIT ?');
  }

  observe(candidates, endpoint, origin = null) {
    const now = this._now();
    this._maybeSweep(now);
    const normOrigin = normalizeOrigin(origin);
    const originJson = normOrigin ? JSON.stringify(normOrigin) : null;
    const reqId = (origin && typeof origin.requestId === 'string') ? origin.requestId : null;
    const ep = endpoint ? String(endpoint).slice(0, 2048) : null;
    let added = 0;
    for (const c of candidates || []) {
      if (!c || typeof c.value !== 'string' || !hasMetaChars(c.value)) continue;
      if (Buffer.byteLength(c.value, 'utf8') > this.maxValueBytes) continue;
      const candidateKey = JSON.stringify([reqId, c.value]);
      const existing = this._get.get(candidateKey);
      if (existing) {
        // 인메모리와 동일: lastSeen/timesSeen 갱신 + byteSize 재계산
        const entry = this._rowToEntry(existing);
        entry.lastSeen = now;
        entry.timesSeen += 1;
        entry.byteSize = entryByteSize(entry);
        this._touch.run(now, entry.byteSize, candidateKey);
      } else {
        const entry = {
          candidateKey,
          value: c.value,
          parameter: String(c.parameter || '').slice(0, 128),
          source: String(c.source || '').slice(0, 32),
          endpoint: ep,
          origin: normOrigin,
          firstSeen: now,
          lastSeen: now,
          timesSeen: 1,
        };
        entry.byteSize = entryByteSize(entry);
        if (entry.byteSize > this.maxBytes) continue;
        this._ins.run(candidateKey, entry.value, entry.parameter, entry.source, ep, originJson, now, now, entry.byteSize);
        added += 1;
      }
    }
    this._evictOverflow();
    return added;
  }

  all() {
    const now = this._now();
    return this._selAll.all(now - this.ttlMs).map((r) => this._rowToEntry(r));
  }

  size() {
    return this._count.get().c;
  }

  clear() {
    this.db.exec('DELETE FROM cand');
  }

  /** 특정 작성 요청의 후보만 제거한다(stored XSS detect-once). */
  delete(candidateKey) {
    return this._del.run(candidateKey).changes > 0;
  }

  _rowToEntry(r) {
    return {
      candidateKey: r.key,
      value: r.value,
      parameter: r.parameter,
      source: r.source,
      endpoint: r.endpoint,
      origin: r.origin ? JSON.parse(r.origin) : null,
      firstSeen: r.first_seen,
      lastSeen: r.last_seen,
      timesSeen: r.times_seen,
      byteSize: r.byte_size,
    };
  }

  _maybeSweep(now) {
    if (now - this._lastSweep < SWEEP_INTERVAL_MS) return;
    this._lastSweep = now;
    this._delExpired.run(now - this.ttlMs);
    this._evictOverflow();
  }

  _evictOverflow() {
    const { c, b } = this._count.get();
    if (c <= this.maxEntries && b <= this.maxBytes) return;
    // 개수 초과분 + (바이트 초과 시 넉넉히) 오래된 것부터 제거
    let overBy = Math.max(0, c - this.maxEntries);
    if (b > this.maxBytes && overBy === 0) overBy = 1;
    while (true) {
      const stat = this._count.get();
      if (stat.c <= this.maxEntries && stat.b <= this.maxBytes) break;
      if (stat.c === 0) break;
      const batch = Math.max(1, overBy || 1);
      const keys = this._oldest.all(batch).map((row) => row.key);
      if (!keys.length) break;
      for (const k of keys) this._del.run(k);
      overBy = 0; // 이후엔 1개씩
    }
  }
}

module.exports = { XssCandidateStoreSqlite, DEFAULT_TTL_MS, DEFAULT_MAX_ENTRIES };
