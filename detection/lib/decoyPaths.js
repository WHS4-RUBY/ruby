const fs = require("fs");
const path = require("path");

// Defense 쪽 미끼 경로를 Detection 에서도 알아보기 위한 공용 판별.
// 원본은 shared/decoy-catalog.json 이고 이 사본은 scripts/sync-decoy-catalog.sh 가 만든다.
const DEFAULT_CATALOG_PATH = path.join(__dirname, "..", "config", "decoy-catalog.json");

function loadDecoyCatalog(catalogPath = process.env.DECOY_CATALOG_PATH || DEFAULT_CATALOG_PATH) {
  const resolvedPath = path.resolve(catalogPath);
  const catalog = JSON.parse(fs.readFileSync(resolvedPath, "utf8"));
  const namespaces = catalog?.namespaces;
  if (!namespaces || typeof namespaces !== "object") {
    throw new Error(`decoy catalog at ${resolvedPath} must contain namespaces`);
  }
  const scored = [];
  for (const [name, spec] of Object.entries(namespaces)) {
    if (!spec?.detectionSignal) continue;
    // 접두어(세그먼트 경계)와 정확 일치 진입 경로를 구분해 담는다. CHeaT 미로 루트
    // (/internal, /backup, /admin ...)는 사이트의 정상 경로와 겹칠 수 있어 접두어로
    // 쓰지 않고, 진입 경로 하나만 정확 일치로 본다.
    const roots = Array.isArray(spec.roots) ? spec.roots : [];
    const exact = typeof spec.entryPath === "string" ? [spec.entryPath] : [];
    if (!roots.length && !exact.length) continue;
    scored.push({ name, roots, exact });
  }
  if (!scored.length) {
    throw new Error(`decoy catalog at ${resolvedPath} marks no namespace for detection`);
  }
  // 미끼 자신이 주입해 브라우저가 자동으로 받아오는 자산은 공격 신호가 아니다.
  const assets = new Set(
    Object.values(namespaces).flatMap((spec) => (Array.isArray(spec?.assets) ? spec.assets : []))
  );
  return { catalog, scored, assets };
}

const { catalog: CATALOG, scored: SCORED_NAMESPACES, assets: DECOY_ASSETS } = loadDecoyCatalog();

// 대소문자·이중 슬래시·뒤 슬래시·한 번의 퍼센트 인코딩으로 회피하지 못하게 한다.
// (Detection 은 Defense 와 달리 경로를 미리 정규화하는 게이트가 없다.)
function normalizeDecoyPath(value) {
  const bare = String(value || "/").split("?", 1)[0].split("#", 1)[0];
  let decoded = bare;
  try {
    decoded = decodeURIComponent(bare);
  } catch {
    decoded = bare;
  }
  const collapsed = decoded.replace(/\/{2,}/g, "/").toLowerCase();
  return collapsed.length > 1 ? collapsed.replace(/\/+$/, "") || "/" : collapsed;
}

function withinRoot(normalized, root) {
  const lowered = root.toLowerCase();
  return normalized === lowered || normalized.startsWith(`${lowered}/`);
}

function decoyNamespaceOf(url) {
  const normalized = normalizeDecoyPath(url);
  if (DECOY_ASSETS.has(normalized)) return null;
  for (const { name, roots, exact } of SCORED_NAMESPACES) {
    if (exact.some((entry) => normalized === entry.toLowerCase())) return name;
    if (roots.some((root) => withinRoot(normalized, root))) return name;
  }
  return null;
}

function isDecoyPath(url) {
  return decoyNamespaceOf(url) !== null;
}

module.exports = {
  CATALOG,
  DEFAULT_CATALOG_PATH,
  decoyNamespaceOf,
  isDecoyPath,
  loadDecoyCatalog,
  normalizeDecoyPath,
};
