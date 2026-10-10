const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const store = require("../lib/store");
const { XssCandidateStoreSqlite } = require("../lib/xssCandidateStoreSqlite");
const { XssEvidenceStore, CONFIRMED_TABLE, REFLECTED_TABLE } = require("../lib/xssEvidenceStore");
const { main: migrate } = require("../scripts/migrate-stores");

function workDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "detection-store-"));
}

// 구 코드가 만들던 파일 모양을 그대로 세운다 — 파일 하나에 테이블 하나.
function seedLegacyCandidates(file, keys) {
  const db = store.open(file);
  db.exec(`CREATE TABLE cand(key TEXT PRIMARY KEY, value TEXT, parameter TEXT, source TEXT,
    endpoint TEXT, origin TEXT, first_seen INTEGER, last_seen INTEGER,
    times_seen INTEGER, byte_size INTEGER)`);
  const insert = db.prepare(`INSERT INTO cand(key,value,parameter,source,endpoint,origin,
    first_seen,last_seen,times_seen,byte_size) VALUES(?,?,?,?,?,?,?,?,1,10)`);
  for (const key of keys) insert.run(key, `<i>${key}</i>`, "q", "body", "/x", null, 1, 2);
  db.close();
}

function seedLegacyEvidence(file, values) {
  const db = store.open(file);
  db.exec(`CREATE TABLE evidence(value TEXT PRIMARY KEY, parameter TEXT, severity TEXT,
    risk_score INTEGER, origin_session TEXT, origin_request TEXT, endpoint TEXT,
    first_at INTEGER, last_at INTEGER, times INTEGER, status TEXT, note TEXT)`);
  const insert = db.prepare(`INSERT INTO evidence(value,parameter,severity,risk_score,
    origin_session,origin_request,endpoint,first_at,last_at,times,status,note)
    VALUES(?,?,?,?,?,?,?,?,?,1,?,?)`);
  for (const value of values) {
    insert.run(value, "p", "high", 9, "s1", "r1", "/y", 1, 2, "open", null);
  }
  db.close();
}

function counts(dbPath) {
  const db = store.open(dbPath);
  try {
    const of = (table) => (store.tableExists(db, table)
      ? db.prepare(`SELECT COUNT(*) AS c FROM ${table}`).get().c : null);
    return { cand: of("cand"), confirmed: of(CONFIRMED_TABLE), reflected: of(REFLECTED_TABLE) };
  } finally {
    db.close();
  }
}

test("세 저장소가 한 DB 파일의 서로 다른 테이블을 쓴다", () => {
  const db = store.open(":memory:");
  const candidates = new XssCandidateStoreSqlite({ db });
  const evidence = new XssEvidenceStore({ db });
  candidates.observe([{ value: "<script>1</script>", parameter: "q", source: "body" }], "/a");
  evidence.recordConfirmed({ value: "<script>1</script>", riskScore: 9, severity: "high" });
  evidence.recordReflected({ value: "<img onerror=1>", riskScore: 5, severity: "medium" }, {});

  assert.equal(candidates.size(), 1);
  assert.equal(evidence.confirmedSize(), 1);
  assert.equal(evidence.reflectedSize(), 1);
  assert.equal(evidence.persistent, true);

  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    .all().map((row) => row.name);
  assert.deepEqual(tables, ["cand", CONFIRMED_TABLE, REFLECTED_TABLE, store.MIGRATIONS_TABLE]);

  const components = db.prepare(`SELECT component FROM ${store.MIGRATIONS_TABLE} ORDER BY component`)
    .all().map((row) => row.component);
  assert.deepEqual(components,
    ["xss_candidates", "xss_evidence_confirmed", "xss_evidence_reflected"]);
});

test("구 파일이 없으면 마이그레이션은 아무것도 하지 않고 성공한다", () => {
  const dir = workDir();
  assert.equal(migrate(["--data-dir", dir, "--db", path.join(dir, "detection.sqlite3")]), 0);
  assert.equal(fs.existsSync(path.join(dir, "detection.sqlite3")), false,
    "옮길 것이 없으면 통합 DB 도 만들지 않는다");
});

test("구 파일 세 개의 행을 통합 DB 로 옮기고 구 파일을 .migrated 로 치운다", () => {
  const dir = workDir();
  const unified = path.join(dir, "detection.sqlite3");
  seedLegacyCandidates(path.join(dir, "xss-candidates.db"), ["k1", "k2", "k3"]);
  seedLegacyEvidence(path.join(dir, "xss-confirmed.db"), ["<c1>", "<c2>"]);
  seedLegacyEvidence(path.join(dir, "xss-reflected.db"), ["<r1>"]);

  assert.equal(migrate(["--data-dir", dir, "--db", unified]), 0);
  assert.deepEqual(counts(unified), { cand: 3, confirmed: 2, reflected: 1 });
  for (const name of ["xss-candidates.db", "xss-confirmed.db", "xss-reflected.db"]) {
    assert.equal(fs.existsSync(path.join(dir, name)), false, name);
    assert.equal(fs.existsSync(path.join(dir, `${name}.migrated`)), true, name);
  }
});

test("마이그레이션을 다시 실행해도 안전하다", () => {
  const dir = workDir();
  const unified = path.join(dir, "detection.sqlite3");
  seedLegacyCandidates(path.join(dir, "xss-candidates.db"), ["k1", "k2"]);
  seedLegacyEvidence(path.join(dir, "xss-confirmed.db"), ["<c1>"]);

  assert.equal(migrate(["--data-dir", dir, "--db", unified]), 0);
  const first = counts(unified);
  assert.equal(migrate(["--data-dir", dir, "--db", unified]), 0);
  assert.deepEqual(counts(unified), first, "두 번째 실행이 행을 늘리거나 지우지 않는다");
});

test("이미 통합 DB 를 쓰던 상태에서 구 파일이 다시 나타나도 기존 행을 덮지 않는다", () => {
  const dir = workDir();
  const unified = path.join(dir, "detection.sqlite3");
  const db = store.open(unified);
  const evidence = new XssEvidenceStore({ db });
  evidence.recordConfirmed({ value: "<c1>", riskScore: 9, severity: "high", parameter: "new" });
  db.close();

  seedLegacyEvidence(path.join(dir, "xss-confirmed.db"), ["<c1>", "<c2>"]);
  assert.equal(migrate(["--data-dir", dir, "--db", unified]), 0);

  const after = store.open(unified);
  try {
    const row = after.prepare(`SELECT parameter FROM ${CONFIRMED_TABLE} WHERE value=?`).get("<c1>");
    assert.equal(row.parameter, "new", "통합 DB 의 기존 행이 구 파일 행으로 덮이지 않는다");
    assert.equal(after.prepare(`SELECT COUNT(*) AS c FROM ${CONFIRMED_TABLE}`).get().c, 2);
  } finally {
    after.close();
  }
});

test("dry-run 은 파일을 건드리지 않는다", () => {
  const dir = workDir();
  seedLegacyCandidates(path.join(dir, "xss-candidates.db"), ["k1"]);
  assert.equal(migrate(["--data-dir", dir, "--dry-run"]), 0);
  assert.equal(fs.existsSync(path.join(dir, "xss-candidates.db")), true);
  assert.equal(fs.existsSync(path.join(dir, "detection.sqlite3")), false);
});

test("schema-learning.json 의 세 맵이 schema_learning 테이블로 옮겨진다", () => {
  const dir = workDir();
  const unified = path.join(dir, "detection.sqlite3");
  fs.writeFileSync(path.join(dir, "schema-learning.json"), JSON.stringify({
    version: 1,
    massAssignment: {
      "POST /api/Users": { fields: { email: { count: 3, firstSeen: 1 } }, totalObservations: 3,
        status: "approved", approvedFields: ["email"] },
    },
    roleGated: { "GET /metrics": { roleStats: {}, status: "learning", approvedRequiredRoles: null } },
    identityCandidates: { "GET /api/Baskets": { sampleSize: 12, matches: 12, status: "learning" } },
  }, null, 2));

  assert.equal(migrate(["--data-dir", dir, "--db", unified]), 0);
  assert.equal(fs.existsSync(path.join(dir, "schema-learning.json")), false);
  assert.equal(fs.existsSync(path.join(dir, "schema-learning.json.migrated")), true);

  const db = store.open(unified);
  try {
    const rows = db.prepare("SELECT kind,route FROM schema_learning ORDER BY kind,route").all();
    assert.deepEqual(rows.map((row) => `${row.kind} ${row.route}`), [
      "identityCandidates GET /api/Baskets",
      "massAssignment POST /api/Users",
      "roleGated GET /metrics",
    ]);
    const payload = JSON.parse(db.prepare(
      "SELECT payload FROM schema_learning WHERE kind=? AND route=?")
      .get("massAssignment", "POST /api/Users").payload);
    assert.deepEqual(payload.approvedFields, ["email"]);
  } finally {
    db.close();
  }

  // 멱등
  assert.equal(migrate(["--data-dir", dir, "--db", unified]), 0);
});

test("손상된 schema-learning.json 은 건너뛰고 나머지 이전을 막지 않는다", () => {
  const dir = workDir();
  const unified = path.join(dir, "detection.sqlite3");
  seedLegacyCandidates(path.join(dir, "xss-candidates.db"), ["k1"]);
  fs.writeFileSync(path.join(dir, "schema-learning.json"), "{ not json");

  assert.equal(migrate(["--data-dir", dir, "--db", unified]), 0);
  assert.equal(counts(unified).cand, 1, "후보 이전은 그대로 진행된다");
  assert.equal(fs.existsSync(path.join(dir, "schema-learning.json")), true,
    "읽지 못한 파일은 사람이 보도록 그대로 남긴다");
});

test("학습 상태가 프로세스 재시작을 넘어 남는다", () => {
  const dir = workDir();
  const dbPath = path.join(dir, "detection.sqlite3");
  const previous = process.env.DETECTION_STORE_DB;
  process.env.DETECTION_STORE_DB = dbPath;
  try {
    delete require.cache[require.resolve("../lib/schemaLearning")];
    const first = require("../lib/schemaLearning");
    first.resetAll();
    for (let n = 0; n < 3; n += 1) {
      first.observeRoleAccess({ method: "GET", normalizedPath: "/metrics", statusCode: 200,
        role: "admin", hasHardcodedRule: false });
    }
    first.observeRoleAccess({ method: "GET", normalizedPath: "/metrics", statusCode: 403,
      role: "customer", hasHardcodedRule: false });
    first.flush();                  // 2초 디바운스를 기다리지 않고 즉시 저장

    delete require.cache[require.resolve("../lib/schemaLearning")];
    const reloaded = require("../lib/schemaLearning");
    const candidate = reloaded.listCandidates().roleGated
      .find((item) => item.key === "GET /metrics");
    assert.ok(candidate, "재로드 후에도 학습 후보가 남아 있다");
    assert.deepEqual(candidate.roleStats.admin, { success: 3, denied: 0 });
    assert.deepEqual(candidate.roleStats.customer, { success: 0, denied: 1 });
  } finally {
    delete require.cache[require.resolve("../lib/schemaLearning")];
    if (previous === undefined) delete process.env.DETECTION_STORE_DB;
    else process.env.DETECTION_STORE_DB = previous;
  }
});
