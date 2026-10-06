'use strict';

/**
 * xssEvidenceStore.js
 *
 * XSS "증거" 영속 저장소. 후보(candidate)는 detect-once로 제거되므로, 실제 탐지된
 * 증거(확정 stored / reflected)는 여기 별도로 남겨 재시작·재배포에도 보존한다.
 *
 * - 확정(stored): 심은 자(origin) 기준. detect-once로 후보에서 빠져도 증거는 영구 보존.
 * - reflected: 보낸 요청 기준의 탐지 기록(확정 개념 없음).
 * - 확정/reflected는 각각 "별도 DB 파일"로 분리 보관(confirmedDbPath / reflectedDbPath).
 *
 * node:sqlite 미지원(예: node20) 또는 오류 시 자동으로 인메모리로 폴백한다(서버는 항상 기동).
 * xssRetention.test.js가 지적한 "재시작 시 확정 기록 소실" 문제를 해소한다.
 */

let DatabaseSync = null;
try { ({ DatabaseSync } = require('node:sqlite')); } catch (_) { /* 미지원 → 인메모리 폴백 */ }

const DEFAULT_MAX = 1000;

function positiveInt(v, fallback) {
  return Number.isSafeInteger(Number(v)) && Number(v) > 0 ? Number(v) : fallback;
}

function originSessionId(origin) {
  return origin && typeof origin.sessionId === 'string' ? origin.sessionId : null;
}
function originRequestId(origin) {
  return origin && typeof origin.requestId === 'string' ? origin.requestId : null;
}

// ── SQLite 백엔드(파일 하나 = 한 종류) ───────────────────────────────────────
class SqliteBackend {
  constructor(dbPath) {
    this.db = new DatabaseSync(dbPath);
    if (dbPath !== ':memory:') { try { this.db.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;'); } catch (_) {} }
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS evidence(
        value TEXT PRIMARY KEY, parameter TEXT, severity TEXT, risk_score INTEGER,
        origin_session TEXT, origin_request TEXT, endpoint TEXT,
        first_at INTEGER, last_at INTEGER, times INTEGER,
        status TEXT, note TEXT);`);
    this._get = this.db.prepare('SELECT * FROM evidence WHERE value=?');
    this._ins = this.db.prepare(`INSERT INTO evidence(value,parameter,severity,risk_score,origin_session,origin_request,endpoint,first_at,last_at,times,status,note)
      VALUES(?,?,?,?,?,?,?,?,?,1,?,?)`);
    this._bump = this.db.prepare(`UPDATE evidence SET last_at=?, times=times+1,
      risk_score=MAX(risk_score,?), severity=CASE WHEN ?>risk_score THEN ? ELSE severity END WHERE value=?`);
    this._list = this.db.prepare('SELECT * FROM evidence ORDER BY last_at DESC');
    this._count = this.db.prepare('SELECT COUNT(*) AS c FROM evidence');
    this._del = this.db.prepare('DELETE FROM evidence WHERE value=?');
    this._updMeta = this.db.prepare('UPDATE evidence SET status=COALESCE(?,status), note=COALESCE(?,note) WHERE value=?');
    this._overflow = this.db.prepare('DELETE FROM evidence WHERE value IN (SELECT value FROM evidence ORDER BY last_at LIMIT ?)');
  }
  has(value) { return !!this._get.get(value); }
  record(row, max) {
    if (this._get.get(row.value)) {
      this._bump.run(row.lastAt, row.riskScore, row.riskScore, row.severity, row.value);
      return false;
    }
    this._ins.run(row.value, row.parameter, row.severity, row.riskScore, row.originSession,
      row.originRequest, row.endpoint, row.firstAt, row.lastAt, row.status, row.note);
    const n = this._count.get().c;
    if (n > max) this._overflow.run(n - max);
    return true;
  }
  list() {
    return this._list.all().map((r) => ({
      value: r.value, parameter: r.parameter, severity: r.severity, riskScore: r.risk_score,
      originSession: r.origin_session, originRequest: r.origin_request, endpoint: r.endpoint,
      firstAt: r.first_at, lastAt: r.last_at, times: r.times, status: r.status, note: r.note,
    }));
  }
  size() { return this._count.get().c; }
  remove(value) { return this._del.run(value).changes > 0; }
  update(value, patch) { return this._updMeta.run(patch.status ?? null, patch.note ?? null, value).changes > 0; }
}

// ── 인메모리 백엔드(폴백) ────────────────────────────────────────────────────
class MapBackend {
  constructor() { this._m = new Map(); }
  has(value) { return this._m.has(value); }
  record(row, max) {
    const e = this._m.get(row.value);
    if (e) {
      e.lastAt = row.lastAt; e.times += 1;
      if (row.riskScore > e.riskScore) { e.riskScore = row.riskScore; e.severity = row.severity; }
      return false;
    }
    this._m.set(row.value, { ...row, times: 1 });
    while (this._m.size > max) this._m.delete(this._m.keys().next().value);
    return true;
  }
  list() { return [...this._m.values()].sort((a, b) => b.lastAt - a.lastAt); }
  size() { return this._m.size; }
  remove(value) { return this._m.delete(value); }
  update(value, patch) {
    const e = this._m.get(value); if (!e) return false;
    if (patch.status != null) e.status = patch.status;
    if (patch.note != null) e.note = patch.note;
    return true;
  }
}

function openBackend(dbPath) {
  if (dbPath && DatabaseSync) {
    try { return new SqliteBackend(dbPath); } catch (_) { /* 폴백 */ }
  }
  return new MapBackend();
}

class XssEvidenceStore {
  constructor({ confirmedDbPath = null, reflectedDbPath = null,
    maxConfirmed = DEFAULT_MAX, maxReflected = DEFAULT_MAX, now = Date.now } = {}) {
    this._now = now;
    this.maxConfirmed = positiveInt(maxConfirmed, DEFAULT_MAX);
    this.maxReflected = positiveInt(maxReflected, DEFAULT_MAX);
    this._confirmed = openBackend(confirmedDbPath);
    this._reflected = openBackend(reflectedDbPath);
    this.persistent = this._confirmed instanceof SqliteBackend && this._reflected instanceof SqliteBackend;
  }

  // 확정(stored): 심은 자(finding.origin) 기준.
  recordConfirmed(finding) {
    if (!finding || typeof finding.value !== 'string' || !finding.value) return false;
    const now = this._now();
    return this._confirmed.record({
      value: finding.value,
      parameter: finding.parameter || null,
      severity: finding.severity || null,
      riskScore: Number(finding.riskScore) || 0,
      originSession: originSessionId(finding.origin),
      originRequest: originRequestId(finding.origin),
      endpoint: finding.storedFromEndpoint || finding.endpoint || null,
      firstAt: now, lastAt: now, status: 'open', note: null,
    }, this.maxConfirmed);
  }
  isConfirmed(value) { return this._confirmed.has(value); }
  confirmedList() { return this._confirmed.list(); }
  confirmedSize() { return this._confirmed.size(); }
  removeConfirmed(value) { return this._confirmed.remove(value); }
  updateConfirmed(value, patch = {}) { return this._confirmed.update(value, patch); }

  // reflected: 보낸 요청 기준의 탐지 기록(확정 개념 없음).
  recordReflected(finding, ctx = {}) {
    if (!finding || typeof finding.value !== 'string' || !finding.value) return false;
    const now = this._now();
    return this._reflected.record({
      value: finding.value,
      parameter: finding.parameter || null,
      severity: finding.severity || null,
      riskScore: Number(finding.riskScore) || 0,
      originSession: originSessionId(ctx.origin),
      originRequest: originRequestId(ctx.origin),
      endpoint: ctx.endpoint || finding.endpoint || null,
      firstAt: now, lastAt: now, status: 'open', note: null,
    }, this.maxReflected);
  }
  reflectedList() { return this._reflected.list(); }
  reflectedSize() { return this._reflected.size(); }
  removeReflected(value) { return this._reflected.remove(value); }
}

module.exports = { XssEvidenceStore };
