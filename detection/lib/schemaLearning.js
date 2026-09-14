'use strict';

/**
 * schemaLearning.js
 *
 * "이 프로젝트를 다른 웹사이트에 붙이려면 화이트리스트/민감 라우트 목록을 그 사이트에 맞춰
 * 전부 다시 손으로 짜야 한다"는 한계(architecture-design.md 3.1.1절, businessLogicSignatures.js/
 * roleGatedAccess.js 상단 주석에 이미 명시돼 있던 것)에 대한 첫 대응. "정상 트래픽을 관찰해서
 * 화이트리스트를 자동으로 학습"하는 아이디어를 그대로 구현하되, 완전 자동 적용은 하지 않는다.
 *
 * 왜 완전 자동이 아닌가(가장 중요한 설계 판단): 학습 기간에 공격 트래픽이 섞이면 그 공격이 쓴
 * 필드/패턴을 "정상"으로 학습해버리는 오염(poisoning) 위험이 있다. 그래서 이 모듈은
 * **관찰(observe) → 제안(propose) → 사람이 승인(approve)** 3단계로만 동작한다. 승인 전까지는
 * 아무리 많이 관찰해도 실제 탐지 판정에 전혀 영향을 주지 않는다 — 이 프로젝트가 지금까지
 * 일관되게 지켜온 "오탐보다 미탐을 택한다" 원칙과 같은 이유다.
 *
 * 세 가지를 학습한다(성숙도 차이가 커서 마지막 하나는 자동 적용 경로 자체가 없다):
 *   1) Mass Assignment 필드 화이트리스트 — 하드코딩된 라우트가 없는 곳에서, 2xx 성공 응답을 받은
 *      요청의 필드를 관찰해 화이트리스트 후보를 만든다. 승인되면 businessLogicSignatures.js의
 *      하드코딩 화이트리스트와 완전히 동일하게 mass-assignment 판정에 쓰인다.
 *   2) Role-Gated 민감 라우트 — 하드코딩된 SENSITIVE_ROUTES에 없는 라우트에서, role별
 *      성공(2xx)/거부(401·403) 횟수를 관찰한다. admin만 성공하고 non-admin은 거부당한 라우트가
 *      보이면 "이것도 admin 전용일 가능성이 높다"는 후보로 제안한다. 승인되면 roleGatedAccess.js의
 *      SENSITIVE_ROUTES와 동일하게 쓰인다.
 *   3) Identity 후보(제안만, 자동 적용 경로 없음) — URL 안의 숫자 ID가 요청자 본인의 JWT
 *      claim(id/bid)과 얼마나 자주 일치하는지 관찰한다. 거의 항상 일치하면 "이 라우트는 본인
 *      소유 자원만 접근하는 패턴일 가능성이 높다"는 신호지만, 어떤 URL 세그먼트가 ID인지·어떤
 *      claim과 비교해야 하는지는 라우트마다 형태가 달라 안전하게 일반화하기 어렵다. 그래서 이건
 *      대시보드에 통계로만 보여주고, 실제 identityMismatch.js 규칙 추가는 여전히 사람이 코드로
 *      작성해야 한다 — 정직하게 자동화 범위를 좁혀둔 부분.
 *
 * 영속화: 프로세스 재시작(컨테이너 재빌드 포함)에도 학습 내용이 남아있어야 의미가 있어서 디스크에
 * JSON 파일로 저장한다. 요청마다 디스크에 쓰면 트래픽이 몰릴 때 I/O 병목이 될 수 있어 2초
 * 디바운스로 묶어서 쓴다. 파일이 없거나 손상됐으면 빈 상태로 조용히 시작한다(죽지 않는다) —
 * 이 프로젝트의 다른 모듈들과 같은 방어적 원칙.
 *
 * 초기화(리셋): DATA_FILE은 평범한 JSON 파일이라 서버를 끄고 파일/폴더를 직접 지워도 되고,
 * 서버를 켜둔 채로는 resetAll()을 호출하는 API(server.js의 POST /__detection/api/schema-learning/reset
 * 참고)로 메모리와 디스크를 한 번에 비울 수 있다.
 */

const fs = require('fs');
const path = require('path');

const DATA_FILE = process.env.SCHEMA_LEARNING_FILE || path.join(__dirname, '..', 'data', 'schema-learning.json');
const SAVE_DEBOUNCE_MS = 2000;

// 후보를 "제안"으로 승격시키는 데 필요한 최소 근거
const ROLE_MIN_SUCCESS = 3;       // admin(또는 특정 role)이 최소 이만큼 성공해야
const ROLE_MIN_DENIALS = 1;       // 다른 role이 최소 이만큼 거부당해야
const IDENTITY_MIN_SAMPLE = 10;
const IDENTITY_MATCH_THRESHOLD = 0.9;

function emptyState() {
  return { version: 1, massAssignment: {}, roleGated: {}, identityCandidates: {} };
}

let state = emptyState();
let saveTimer = null;

function routeKey(method, normalizedPath) {
  return `${String(method || '').toUpperCase()} ${normalizedPath || ''}`;
}

function load() {
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') {
      state = { ...emptyState(), ...parsed };
    }
  } catch {
    // 파일이 없거나(첫 실행) 손상됐으면 빈 상태로 시작 — 정상 동작
    state = emptyState();
  }
}

function writeNow() {
  try {
    fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
    fs.writeFileSync(DATA_FILE, JSON.stringify(state, null, 2));
  } catch (err) {
    console.warn('[schemaLearning] 디스크 저장 실패(계속 진행, 다음 기회에 재시도):', err.message);
  }
}

function scheduleSave() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    writeNow();
  }, SAVE_DEBOUNCE_MS);
  if (typeof saveTimer.unref === 'function') saveTimer.unref(); // 이 타이머 때문에 프로세스 종료가 막히지 않도록
}

load();

// ---------------------------------------------------------------------------
// 1. Mass Assignment 필드 학습
// ---------------------------------------------------------------------------

function observeMassAssignment({ method, normalizedPath, bodyObj, statusCode, hasHardcodedWhitelist }) {
  if (hasHardcodedWhitelist) return; // 이미 하드코딩된 라우트는 학습 대상이 아니다
  if (!bodyObj || typeof bodyObj !== 'object' || Array.isArray(bodyObj)) return;
  if (!['POST', 'PUT', 'PATCH'].includes(String(method || '').toUpperCase())) return;
  if (Object.keys(bodyObj).length === 0) return;
  if (!(statusCode >= 200 && statusCode < 300)) return; // 성공한 요청만 "정상 스키마"로 취급

  const key = routeKey(method, normalizedPath);
  const entry = state.massAssignment[key] || {
    fields: {}, totalObservations: 0, status: 'learning', approvedFields: null,
  };
  entry.totalObservations += 1;
  const now = new Date().toISOString();
  for (const field of Object.keys(bodyObj)) {
    const f = entry.fields[field] || { count: 0, firstSeen: now };
    f.count += 1;
    f.lastSeen = now;
    entry.fields[field] = f;
  }
  state.massAssignment[key] = entry;
  scheduleSave();
}

function getApprovedMassAssignmentWhitelist(method, normalizedPath) {
  const entry = state.massAssignment[routeKey(method, normalizedPath)];
  if (!entry || entry.status !== 'approved' || !Array.isArray(entry.approvedFields)) return null;
  return new Set(entry.approvedFields);
}

function approveMassAssignment(key, fields) {
  const entry = state.massAssignment[key];
  if (!entry) return false;
  entry.status = 'approved';
  entry.approvedFields = Array.isArray(fields) ? fields : Object.keys(entry.fields);
  writeNow(); // 승인은 바로 반영
  return true;
}

function rejectMassAssignment(key) {
  if (!state.massAssignment[key]) return false;
  delete state.massAssignment[key];
  writeNow();
  return true;
}

// ---------------------------------------------------------------------------
// 2. Role-Gated 민감 라우트 학습
// ---------------------------------------------------------------------------

function observeRoleAccess({ method, normalizedPath, statusCode, role, hasHardcodedRule }) {
  if (hasHardcodedRule) return;
  if (!(statusCode >= 200 && statusCode < 300) && statusCode !== 401 && statusCode !== 403) return;

  const key = routeKey(method, normalizedPath);
  const entry = state.roleGated[key] || { roleStats: {}, status: 'learning', approvedRequiredRoles: null };
  const roleName = role || '(무인증/role없음)';
  const stat = entry.roleStats[roleName] || { success: 0, denied: 0 };
  if (statusCode >= 200 && statusCode < 300) stat.success += 1;
  else stat.denied += 1;
  entry.roleStats[roleName] = stat;
  state.roleGated[key] = entry;
  scheduleSave();
}

function getApprovedSensitiveRoute(method, normalizedPath) {
  const entry = state.roleGated[routeKey(method, normalizedPath)];
  if (!entry || entry.status !== 'approved' || !Array.isArray(entry.approvedRequiredRoles)) return null;
  return new Set(entry.approvedRequiredRoles);
}

function approveRoleGated(key, requiredRoles) {
  const entry = state.roleGated[key];
  if (!entry) return false;
  entry.status = 'approved';
  entry.approvedRequiredRoles = Array.isArray(requiredRoles) ? requiredRoles : ['admin'];
  writeNow();
  return true;
}

function rejectRoleGated(key) {
  if (!state.roleGated[key]) return false;
  delete state.roleGated[key];
  writeNow();
  return true;
}

// ---------------------------------------------------------------------------
// 3. Identity 후보 관찰 — 제안만, 자동 적용 경로 없음
// ---------------------------------------------------------------------------

function observeIdentityAccess({ method, normalizedPath, statusCode, requestedId, claimedIds }) {
  if (requestedId === null || requestedId === undefined) return;
  if (!Array.isArray(claimedIds) || claimedIds.length === 0) return;
  if (!(statusCode >= 200 && statusCode < 300)) return;

  const key = routeKey(method, normalizedPath);
  const entry = state.identityCandidates[key] || { sampleSize: 0, matches: 0, status: 'learning' };
  entry.sampleSize += 1;
  if (claimedIds.some((c) => String(c) === String(requestedId))) entry.matches += 1;
  state.identityCandidates[key] = entry;
  scheduleSave();
}

// mass-assignment/role-gated와 동일한 승인 개념을 identity 후보에도 추가한다(15차 확장). 원래는
// "제안만, 자동 적용 경로 없음"으로 일부러 좁혀뒀던 부분 — 어떤 URL 세그먼트가 ID인지 라우트마다
// 다르다는 문제는 여전하지만, extractTrailingNumericId()(priceIntegrity.js, URL 마지막 숫자
// 세그먼트)로 이미 일반화해서 관찰하고 있었고, 승인이라는 사람 개입 단계가 있는 한 mass-assignment/
// role-gated와 위험 성격이 다르지 않다고 판단해 승인 경로를 열었다. identityMismatch.js가 이
// 함수를 써서 "하드코딩된 규칙이 없는 라우트에서, URL 끝 숫자 ID가 승인됐다면 claimed id/bid와
// 다를 때 탐지"하는 fallback을 수행한다.
function getApprovedIdentityRule(method, normalizedPath) {
  const entry = state.identityCandidates[routeKey(method, normalizedPath)];
  return !!(entry && entry.status === 'approved');
}

function approveIdentityCandidate(key) {
  const entry = state.identityCandidates[key];
  if (!entry) return false;
  entry.status = 'approved';
  writeNow();
  return true;
}

function rejectIdentityCandidate(key) {
  if (!state.identityCandidates[key]) return false;
  delete state.identityCandidates[key];
  writeNow();
  return true;
}

// ---------------------------------------------------------------------------
// 조회 / 리셋
// ---------------------------------------------------------------------------

function listCandidates() {
  const massAssignment = Object.entries(state.massAssignment).map(([key, e]) => ({
    key,
    status: e.status,
    totalObservations: e.totalObservations,
    fields: Object.entries(e.fields)
      .map(([name, f]) => ({ name, count: f.count, lastSeen: f.lastSeen }))
      .sort((a, b) => b.count - a.count),
    approvedFields: e.approvedFields,
    ready: e.status === 'learning' && e.totalObservations >= 3,
  }));

  const roleGated = Object.entries(state.roleGated).map(([key, e]) => {
    const roles = Object.entries(e.roleStats);
    const adminLike = roles.filter(([name]) => name !== '(무인증/role없음)');
    const totalDenied = roles.reduce((sum, [, s]) => sum + s.denied, 0);
    const dominantRole = adminLike.sort((a, b) => b[1].success - a[1].success)[0];
    const suggestion = dominantRole && dominantRole[1].success >= ROLE_MIN_SUCCESS && totalDenied >= ROLE_MIN_DENIALS
      ? [dominantRole[0]]
      : null;
    return {
      key,
      status: e.status,
      roleStats: e.roleStats,
      approvedRequiredRoles: e.approvedRequiredRoles,
      suggestedRoles: suggestion,
      ready: e.status === 'learning' && !!suggestion,
    };
  });

  const identityCandidates = Object.entries(state.identityCandidates)
    .map(([key, e]) => {
      const matchRatio = e.sampleSize > 0 ? e.matches / e.sampleSize : 0;
      const meetsThreshold = e.sampleSize >= IDENTITY_MIN_SAMPLE && matchRatio >= IDENTITY_MATCH_THRESHOLD;
      return {
        key,
        status: e.status,
        sampleSize: e.sampleSize,
        matchRatio,
        ready: e.status === 'learning' && meetsThreshold,
      };
    })
    // 임계값을 넘어 제안 상태인 것과, 이미 승인된 것(재관찰로 표본이 줄어들 일은 없지만 승인
    // 후에도 계속 관찰되므로 계속 노출해 대시보드에서 거부/재검토할 수 있게 한다)만 보여준다.
    .filter((c) => c.ready || c.status === 'approved');

  return { massAssignment, roleGated, identityCandidates };
}

function resetAll() {
  state = emptyState();
  if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
  writeNow();
}

module.exports = {
  DATA_FILE,
  observeMassAssignment,
  getApprovedMassAssignmentWhitelist,
  approveMassAssignment,
  rejectMassAssignment,
  observeRoleAccess,
  getApprovedSensitiveRoute,
  approveRoleGated,
  rejectRoleGated,
  observeIdentityAccess,
  getApprovedIdentityRule,
  approveIdentityCandidate,
  rejectIdentityCandidate,
  listCandidates,
  resetAll,
  routeKey,
  // 테스트 전용
  _load: load,
};
