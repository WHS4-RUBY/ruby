#!/usr/bin/env node
// 구 Detection 저장소 파일을 통합 DB 하나로 옮긴다.
//
//   xss-candidates.db  (cand)      -> detection.sqlite3 (cand)
//   xss-confirmed.db   (evidence)  -> detection.sqlite3 (evidence_confirmed)
//   xss-reflected.db   (evidence)  -> detection.sqlite3 (evidence_reflected)
//
// 구 파일이 없어도 정상 종료한다(새로 시작하는 배포). 옮긴 구 파일은 <이름>.migrated
// 로 바꿔 두므로 다시 실행해도 안전하다. 멱등하다.
//
//   node scripts/migrate-stores.js [--db <통합 경로>] [--data-dir <구 파일 디렉터리>]
//   node scripts/migrate-stores.js --dry-run

const fs = require("node:fs");
const path = require("node:path");

const store = require("../lib/store");
const { COMPONENT: CANDIDATE_COMPONENT, MIGRATIONS: CANDIDATE_MIGRATIONS } =
  require("../lib/xssCandidateStoreSqlite");
const { CONFIRMED_TABLE, REFLECTED_TABLE, evidenceMigrations } =
  require("../lib/xssEvidenceStore");

const SOURCES = [
  { file: "xss-candidates.db", from: "cand", to: "cand",
    component: CANDIDATE_COMPONENT, migrations: CANDIDATE_MIGRATIONS },
  { file: "xss-confirmed.db", from: "evidence", to: CONFIRMED_TABLE,
    component: "xss_evidence_confirmed", migrations: evidenceMigrations(CONFIRMED_TABLE) },
  { file: "xss-reflected.db", from: "evidence", to: REFLECTED_TABLE,
    component: "xss_evidence_reflected", migrations: evidenceMigrations(REFLECTED_TABLE) },
];

function parseArgs(argv) {
  const options = { dryRun: false, db: null, dataDir: null };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--dry-run") options.dryRun = true;
    else if (arg === "--db") options.db = argv[++index];
    else if (arg === "--data-dir") options.dataDir = argv[++index];
    else throw new Error(`알 수 없는 인자: ${arg}`);
  }
  return options;
}

function copyRows(target, source, spec) {
  if (!store.tableExists(source, spec.from)) return 0;
  const rows = source.prepare(`SELECT * FROM ${spec.from}`).all();
  if (!rows.length) return 0;
  const columns = Object.keys(rows[0]);
  const placeholders = columns.map(() => "?").join(",");
  // OR IGNORE: 같은 키가 이미 통합 DB 에 있으면(재실행·부분 이전) 기존 행을 남긴다.
  const insert = target.prepare(
    `INSERT OR IGNORE INTO ${spec.to}(${columns.join(",")}) VALUES(${placeholders})`);
  let moved = 0;
  target.exec("BEGIN IMMEDIATE");
  try {
    for (const row of rows) moved += insert.run(...columns.map((name) => row[name])).changes;
    target.exec("COMMIT");
  } catch (error) {
    try { target.exec("ROLLBACK"); } catch (_) { /* 이미 롤백됨 */ }
    throw error;
  }
  return moved;
}

function retire(filePath) {
  for (const suffix of ["", "-wal", "-shm"]) {
    const candidate = filePath + suffix;
    if (fs.existsSync(candidate)) fs.renameSync(candidate, `${candidate}.migrated`);
  }
}

function main(argv) {
  const options = parseArgs(argv);
  if (!store.available()) {
    console.error("node:sqlite 를 쓸 수 없다 (node --experimental-sqlite 로 실행할 것)");
    return 1;
  }
  const dataDir = options.dataDir || path.join(__dirname, "..", "data");
  const dbPath = options.db || process.env.DETECTION_STORE_DB
    || path.join(dataDir, "detection.sqlite3");

  const pending = SOURCES.filter((spec) => fs.existsSync(path.join(dataDir, spec.file)));
  if (!pending.length) {
    console.log(`옮길 구 저장소가 없다 (${dataDir}). 통합 DB 는 ${dbPath} 에서 새로 시작한다.`);
    return 0;
  }
  if (options.dryRun) {
    for (const spec of pending) {
      console.log(`[dry-run] ${spec.file} (${spec.from}) -> ${path.basename(dbPath)} (${spec.to})`);
    }
    return 0;
  }

  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const target = store.open(dbPath);
  try {
    for (const spec of pending) {
      store.applyMigrations(target, spec.component, spec.migrations);
      const sourcePath = path.join(dataDir, spec.file);
      const source = store.open(sourcePath);
      try {
        const moved = copyRows(target, source, spec);
        console.log(`${spec.file} (${spec.from}) -> ${spec.to}: ${moved}행`);
      } finally {
        source.close();
      }
      retire(sourcePath);
    }
  } finally {
    target.close();
  }
  console.log(`완료. 구 파일은 .migrated 로 바꿔 두었다. 통합 DB: ${dbPath}`);
  return 0;
}

if (require.main === module) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (error) {
    console.error("마이그레이션 실패:", error.message);
    process.exitCode = 1;
  }
}

module.exports = { main, SOURCES };
