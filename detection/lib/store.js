// Detection 의 SQLite 접근·마이그레이션 계층.
//
// 이전에는 세 저장소가 각각 자기 파일을 열고 CREATE TABLE IF NOT EXISTS 를 돌렸다
// (xss-candidates.db / xss-confirmed.db / xss-reflected.db). 두 증거 저장소는 테이블
// 이름이 둘 다 evidence 라서 한 파일에 담을 수 없었고, 무엇이 적용됐는지 기록하는
// 곳이 없었다.
//
// 마이그레이션은 컴포넌트 단위다. 한 파일이 여러 컴포넌트를 담고 각자 독립적으로
// 버전을 올릴 수 있어야 저장소를 하나로 합칠 수 있다. Python 쪽 shared/py/store.py
// 와 같은 schema_migrations(component, version, applied_at) 스키마를 쓴다.

let DatabaseSync = null;
try { ({ DatabaseSync } = require("node:sqlite")); } catch (_) { /* 미지원 → 호출자가 폴백 */ }

const MIGRATIONS_TABLE = "schema_migrations";
const MIGRATIONS_DDL = `CREATE TABLE IF NOT EXISTS ${MIGRATIONS_TABLE}(
  component TEXT NOT NULL, version INTEGER NOT NULL, applied_at REAL NOT NULL,
  PRIMARY KEY(component, version))`;

class StoreError extends Error {}

function available() {
  return DatabaseSync !== null;
}

/** 파일 저장소는 WAL + synchronous=NORMAL. 인메모리(':memory:')는 PRAGMA 를 건너뛴다. */
function open(dbPath, { timeoutMs = 10_000 } = {}) {
  if (!available()) throw new StoreError("node:sqlite is unavailable");
  const db = new DatabaseSync(dbPath);
  if (dbPath !== ":memory:") {
    try {
      db.exec(`PRAGMA busy_timeout=${Number(timeoutMs) || 10_000};`
        + " PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;");
    } catch (_) { /* 파일시스템이 WAL 을 못 쓰면 기본 저널로 계속한다 */ }
  }
  db.exec(MIGRATIONS_DDL);
  return db;
}

function appliedVersions(db, component) {
  db.exec(MIGRATIONS_DDL);
  const rows = db.prepare(`SELECT version FROM ${MIGRATIONS_TABLE} WHERE component=?`).all(component);
  return new Set(rows.map((row) => Number(row.version)));
}

/**
 * 아직 기록되지 않은 버전만 순서대로 적용한다. 버전 하나의 DDL 과 기록 행은 같은
 * 트랜잭션에서 커밋하므로 중간에 죽어도 반쯤 적용된 버전이 완료로 남지 않는다.
 * 재실행은 무해하다. migrations = [[version, [sql, ...]], ...]
 */
function applyMigrations(db, component, migrations) {
  const ordered = [...migrations].sort((a, b) => a[0] - b[0]);
  const versions = ordered.map(([version]) => version);
  if (new Set(versions).size !== versions.length) {
    throw new StoreError(`duplicate migration version for ${component}`);
  }
  if (versions.some((version) => !Number.isSafeInteger(version) || version < 1)) {
    throw new StoreError(`migration versions for ${component} must be integers from 1`);
  }
  const done = appliedVersions(db, component);
  const record = db.prepare(
    `INSERT INTO ${MIGRATIONS_TABLE}(component,version,applied_at) VALUES(?,?,?)`);
  const newly = [];
  for (const [version, statements] of ordered) {
    if (done.has(version)) continue;
    db.exec("BEGIN IMMEDIATE");
    try {
      for (const statement of statements) db.exec(statement);
      record.run(component, version, Date.now() / 1000);
      db.exec("COMMIT");
    } catch (error) {
      try { db.exec("ROLLBACK"); } catch (_) { /* 이미 롤백됨 */ }
      throw new StoreError(`migration ${component} v${version} failed: ${error.message}`);
    }
    newly.push(version);
  }
  return newly;
}

/**
 * schema_migrations 가 없는 기존 파일을 버전으로 환산해 기록만 남긴다(DDL 미실행).
 * 이 기록이 없으면 이미 존재하는 테이블에 v1 의 DDL 이 다시 돌아간다.
 */
function adoptExisting(db, component, versions) {
  if (appliedVersions(db, component).size) return [];
  const record = db.prepare(
    `INSERT INTO ${MIGRATIONS_TABLE}(component,version,applied_at) VALUES(?,?,?)`);
  db.exec("BEGIN IMMEDIATE");
  try {
    for (const version of versions) record.run(component, version, Date.now() / 1000);
    db.exec("COMMIT");
  } catch (error) {
    try { db.exec("ROLLBACK"); } catch (_) { /* 이미 롤백됨 */ }
    throw new StoreError(`adopting ${component} failed: ${error.message}`);
  }
  return [...versions];
}

function tableExists(db, name) {
  return db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(name) !== undefined;
}

module.exports = {
  MIGRATIONS_TABLE,
  StoreError,
  adoptExisting,
  appliedVersions,
  applyMigrations,
  available,
  open,
  tableExists,
};
