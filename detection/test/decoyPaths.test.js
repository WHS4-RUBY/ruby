const assert = require("node:assert/strict");
const test = require("node:test");

const {
  CATALOG,
  decoyNamespaceOf,
  isDecoyPath,
  normalizeDecoyPath,
} = require("../lib/decoyPaths");

// 이 테스트는 detection/config 사본만 본다. 원본(shared/)은 Detection 이미지에
// 없으므로 npm test 안에서 참조하면 컨테이너에서 실패한다. 원본과 사본의 동일성은
// defense/tests/test_decoy_catalog_contract.py 가 저장소 루트에서 검증한다.

test("카탈로그는 Detection 이 채점할 네임스페이스를 선언한다", () => {
  const scored = Object.entries(CATALOG.namespaces)
    .filter(([, spec]) => spec.detectionSignal)
    .map(([name]) => name)
    .sort();
  assert.deepEqual(scored, ["cheat", "overlay"]);
  // Detection 자신의 트랩은 trap_trigger·script_hint_access 로 이미 채점된다.
  assert.equal(CATALOG.namespaces.detection.detectionSignal, false);
});

test("오버레이 미끼 네임스페이스는 세그먼트 경계로 판정한다", () => {
  for (const root of CATALOG.namespaces.overlay.roots) {
    assert.equal(isDecoyPath(root), true, root);
    assert.equal(isDecoyPath(`${root}/deeper`), true, root);
    assert.equal(isDecoyPath(`${root}x`), false, root);
  }
  for (const entry of CATALOG.overlayEntries) {
    assert.equal(decoyNamespaceOf(entry), "overlay", entry);
  }
});

test("CHeaT 는 진입 경로만 정확 일치로 본다", () => {
  const { entryPath } = CATALOG.namespaces.cheat;
  assert.equal(decoyNamespaceOf(entryPath), "cheat");
  // 미로 루트(/internal, /backup, /admin ...)는 사이트의 정상 경로와 겹칠 수 있어
  // 접두어로 쓰지 않는다.
  assert.equal(isDecoyPath("/internal/other"), false);
  assert.equal(isDecoyPath("/admin"), false);
  assert.equal(isDecoyPath("/config/app.yml"), false);
});

test("미끼가 스스로 주입하는 자산은 공격 신호가 아니다", () => {
  for (const asset of CATALOG.namespaces.overlay.assets) {
    assert.equal(isDecoyPath(asset), false, asset);
  }
});

test("대소문자·이중 슬래시·뒤 슬래시·퍼센트 인코딩으로 회피할 수 없다", () => {
  for (const evasion of ["/OPS/x", "//ops/x", "/ops/x/", "/ops%2frecovery", "/Ftp"]) {
    assert.equal(isDecoyPath(evasion), true, evasion);
  }
  assert.equal(normalizeDecoyPath("//OPS/x/?q=1#f"), "/ops/x");
  assert.equal(normalizeDecoyPath(""), "/");
});

test("정상 경로와 Detection 자체 트랩은 신호를 만들지 않는다", () => {
  for (const ordinary of ["/", "/api/Products", "/rest/user/login", "/assets/main.js",
    "/rest/internal/audit/session/0123456789ab"]) {
    assert.equal(isDecoyPath(ordinary), false, ordinary);
  }
});
