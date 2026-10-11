'use strict';

const schemaLearning = require('./schemaLearning');

/**
 * businessLogicSignatures.js
 *
 * payloadSignatures.js가 놓치는 "문법적으로는 완전히 정상인 공격"을 잡기 위한 모듈.
 * 4차례 실측 공격 테스트(attack-claude-01 / attack-codex-sqli-01 / detection-test-001 3차·4차)에서
 * 실제로 뚫렸던 패턴만 근거로 만들었다:
 *
 *   - Mass Assignment      : 회원가입에 role:"admin" 주입 → 관리자 계정 즉시 생성 (3차, 4차 재현)
 *   - Numeric abuse        : 상품 가격을 0으로, 장바구니 수량을 음수로 (3차: price, 4차: quantity)
 *   - NoSQL 연산자 주입     : 리뷰 수정에 {"id":{"$ne":-1}} 로 전체 리뷰 일괄 변조 (3차)
 *   - SQLi comment-only    : 비교식 없는 `'--` 만으로 로그인 우회 (3차에서 3건 미탐)
 *
 * Juice Shop 엔드포인트에 맞춰 화이트리스트/범위를 하드코딩했다. 다른 사이트에 재사용하려면
 * WHITELIST/RULES 두 상수만 그 사이트 스키마로 갈아끼우면 된다 — 이거 하나만으로는 여전히
 * 수작업이 필요하지만, 하드코딩이 없는 라우트는 이제 schemaLearning.js가 관찰→제안→승인
 * 3단계로 자동 학습한다(2026-09-02 15차, 아래 detectMassAssignment 참고). 승인된 학습
 * 화이트리스트는 여기 하드코딩된 것과 완전히 동일한 방식으로 mass-assignment 판정에 쓰인다.
 *
 * server.js 연동: onProxyReq/트랩 핸들러에서 tagPayload와 나란히 호출해 태그를 합친다.
 * 반환 태그는 tagPayload와 분리된 별도 필드(blTags)로 기록되고, featureExtractor.js가
 * features.attack.businessLogic* 필드로 집계하며, classifier.js의 scoreBusinessLogicViolation이
 * 별도 가중 서브스코어(ATTACK_WEIGHTS.businessLogicViolation)로 반영한다 — 정규식 매칭과
 * 필드 화이트리스트 위반은 신뢰도 성격이 달라 같은 서브스코어에 섞지 않는다.
 */

// ---------------------------------------------------------------------------
// 1. Mass Assignment — 엔드포인트별 "클라이언트가 채워도 되는 필드" 화이트리스트
// ---------------------------------------------------------------------------

// 라우트별 허용 필드·의심 필드명·의심 역할 값·숫자 범위는 프로파일의 `businessLogic`
// 블록에서 온다. 이 중 **라우트에 묶인 것은 massAssignmentWhitelist 하나뿐**이고
// 나머지 셋은 라우트와 무관하게 모든 본문에서 돈다 — 그래서 generic 프로파일에도
// 같은 값으로 들어가고, 프로파일이 없는 대상의 동작이 보존된다.
//
// NoSQL 연산자와 comment-only SQLi 는 사이트와 무관한 구문 판정이므로 프로파일로
// 옮기지 않는다. 설정이 없으니 비활성 보고 대상도 아니다.
//
// 화이트리스트 키는 뒤 슬래시를 뗀 형태로만 적는다 — whitelistKey() 가 조회할 때
// 정규화하고, siteProfile.js 의 검증기가 슬래시로 끝나는 라우트를 거부한다.

// 요청마다 배열을 Map/Set 으로 다시 만들지 않도록 프로파일 객체당 한 번만 만들어
// 둔다. 프로파일은 frozen 이라 속성을 붙일 수 없어 WeakMap 을 쓴다 — 프로파일이
// 교체되면 항목도 함께 수거된다.
const lookupCache = new WeakMap();

function lookupsFor(profile) {
  const config = profile?.businessLogic;
  if (!config) return null;
  const cached = lookupCache.get(profile);
  if (cached) return cached;

  const built = {
    whitelist: new Map(
      (config.massAssignmentWhitelist || []).map((entry) => [entry.route, new Set(entry.fields)])
    ),
    suspiciousFields: new Set(
      (config.alwaysSuspiciousFields || []).map((field) => field.toLowerCase())
    ),
    suspiciousValues: new Set(
      (config.suspiciousRoleValues || []).map((value) => value.toLowerCase())
    ),
    numericRules: new Map(
      (config.numericFieldRules || []).map(({ field, ...rule }) => [field.toLowerCase(), rule])
    ),
  };
  lookupCache.set(profile, built);
  return built;
}

function routeKey(method, normalizedPath) {
  return `${String(method || '').toUpperCase()} ${normalizedPath || ''}`;
}

/** 화이트리스트 조회용 키. 뒤 슬래시가 붙은 같은 라우트를 같은 키로 본다. */
function whitelistKey(method, normalizedPath) {
  const path = String(normalizedPath || '');
  return routeKey(method, path.length > 1 && path.endsWith('/') ? path.slice(0, -1) : path);
}

/**
 * @returns {{hit:boolean, extraFields:string[], suspiciousFields:string[], suspiciousValues:string[]}}
 */
// ALWAYS_SUSPICIOUS_FIELDS는 최상위 필드뿐 아니라 중첩된 객체/배열 안에도 숨겨질 수 있어
// (예: {"data":{"role":"admin"}}) 재귀적으로 훑는다 — detectNoSqlOperatorInjection과 같은 패턴.
function findSuspiciousFieldsDeep(node, suspiciousFields, acc = []) {
  if (!node || typeof node !== 'object') return acc;
  if (Array.isArray(node)) {
    for (const item of node) findSuspiciousFieldsDeep(item, suspiciousFields, acc);
    return acc;
  }
  for (const [key, value] of Object.entries(node)) {
    if (suspiciousFields.has(key.toLowerCase())) acc.push(key);
    if (value && typeof value === 'object') findSuspiciousFieldsDeep(value, suspiciousFields, acc);
  }
  return acc;
}

// 최상위 필드 중 화이트리스트에 있는 것(password/comment 등 자유 텍스트)은 값 검사에서
// 제외한다 — 안 그러면 사용자가 실제로 비밀번호를 "admin"으로 정한 정상 케이스까지
// 공격으로 오탐한다. 화이트리스트 밖 최상위 필드와, 어떤 필드든 그 안에 중첩된 값은 검사한다.
function findSuspiciousValuesDeep(node, whitelist, suspiciousValues, acc = [], isTopLevel = true) {
  if (!node || typeof node !== 'object') return acc;
  if (Array.isArray(node)) {
    for (const item of node) findSuspiciousValuesDeep(item, whitelist, suspiciousValues, acc, false);
    return acc;
  }
  for (const [key, value] of Object.entries(node)) {
    const skipValueCheck = isTopLevel && whitelist && whitelist.has(key);
    if (!skipValueCheck && typeof value === 'string' && suspiciousValues.has(value.trim().toLowerCase())) {
      acc.push(key);
    }
    if (value && typeof value === 'object') {
      findSuspiciousValuesDeep(value, whitelist, suspiciousValues, acc, false);
    }
  }
  return acc;
}

// 하드코딩된 화이트리스트가 있는 라우트인지 — server.js가 schemaLearning 관찰 시점에
// "이미 하드코딩돼 있으니 학습 대상 아님"을 판단할 때 재사용한다.
function hasHardcodedMassAssignmentWhitelist(method, normalizedPath, profile) {
  const lookups = lookupsFor(profile);
  if (!lookups) return false;
  return lookups.whitelist.has(whitelistKey(method, normalizedPath));
}

function detectMassAssignment(method, normalizedPath, bodyObj, profile) {
  const result = { hit: false, extraFields: [], suspiciousFields: [], suspiciousValues: [] };
  const lookups = lookupsFor(profile);
  if (!lookups) return result;
  if (!bodyObj || typeof bodyObj !== 'object' || Array.isArray(bodyObj)) return result;

  const fields = Object.keys(bodyObj);

  // 화이트리스트가 정의된 라우트면 최상위 필드만 정확 매치(라우트별 스키마 기준이라
  // 중첩까지 화이트리스트로 관리하면 너무 엄격해져 오탐이 늘어난다). 하드코딩이 없으면
  // schemaLearning.js가 승인해둔 학습 화이트리스트를 대신 쓴다 — 둘 다 없으면 여전히
  // checked:false 취급(아무 판단 안 함, 오탐 방지 원칙 유지).
  const whitelist = lookups.whitelist.get(whitelistKey(method, normalizedPath))
    || schemaLearning.getApprovedMassAssignmentWhitelist(method, normalizedPath)
    || null;
  if (whitelist) {
    result.extraFields = fields.filter((f) => !whitelist.has(f));
  }

  // 화이트리스트 유무와 무관하게 권한 관련 필드명은 항상 의심 — 중첩된 객체 안까지 훑는다
  result.suspiciousFields =
    Array.from(new Set(findSuspiciousFieldsDeep(bodyObj, lookups.suspiciousFields)));

  // 값 기반 검사는 화이트리스트가 정의된 라우트(스키마가 명확한 폼)에서만 수행한다 —
  // 스키마가 없는 라우트까지 값을 훑으면 일반 텍스트(상품 설명, 코멘트 등)에서 오탐이 늘어난다.
  result.suspiciousValues = whitelist
    ? Array.from(new Set(findSuspiciousValuesDeep(bodyObj, whitelist, lookups.suspiciousValues)))
    : [];

  result.hit = result.extraFields.length > 0 || result.suspiciousFields.length > 0 || result.suspiciousValues.length > 0;
  return result;
}

// ---------------------------------------------------------------------------
// 2. 숫자 필드 도메인 범위 이상탐지 — 가격을 0으로, 수량을 음수로 등
// ---------------------------------------------------------------------------

/**
 * @returns {{hit:boolean, violations:Array<{field:string, value:number, rule:object}>}}
 */
function detectNumericAbuse(bodyObj, profile) {
  const violations = [];
  const lookups = lookupsFor(profile);
  if (!lookups) return { hit: false, violations };
  if (!bodyObj || typeof bodyObj !== 'object' || Array.isArray(bodyObj)) return { hit: false, violations };

  for (const [key, value] of Object.entries(bodyObj)) {
    const rule = lookups.numericRules.get(key.toLowerCase());
    if (!rule || typeof value !== 'number' || Number.isNaN(value)) continue;
    const tooLow = rule.min !== undefined && value < rule.min;
    const tooHigh = rule.max !== undefined && value > rule.max;
    if (tooLow || tooHigh) violations.push({ field: key, value, rule });
  }
  return { hit: violations.length > 0, violations };
}

// ---------------------------------------------------------------------------
// 3. NoSQL 연산자 주입 — 특정 엔드포인트가 아니라 바디 전체를 재귀적으로 훑는다
// ---------------------------------------------------------------------------

const MONGO_OPERATOR_RE = /^\$/;

/**
 * @returns {{hit:boolean, paths:string[]}}
 */
function detectNoSqlOperatorInjection(bodyObj, _path = '', _acc = []) {
  if (bodyObj && typeof bodyObj === 'object') {
    if (!Array.isArray(bodyObj)) {
      for (const [key, value] of Object.entries(bodyObj)) {
        if (MONGO_OPERATOR_RE.test(key)) {
          _acc.push(`${_path}${_path ? '.' : ''}${key}`);
        } else if (value && typeof value === 'object') {
          detectNoSqlOperatorInjection(value, `${_path}${_path ? '.' : ''}${key}`, _acc);
        }
      }
    } else {
      bodyObj.forEach((item, i) => detectNoSqlOperatorInjection(item, `${_path}[${i}]`, _acc));
    }
  }
  return { hit: _acc.length > 0, paths: _acc };
}

// ---------------------------------------------------------------------------
// 4. SQLi — 비교식 없는 순수 comment-injection ('-- 만으로 나머지를 주석 처리)
//    기존 payloadSignatures.js의 SQLi 정규식은 "비교식(1=1 등)"을 요구하기 때문에
//    이 좁은 패턴을 보완용으로 별도 태그(sqli-comment-only)로 둔다.
// ---------------------------------------------------------------------------

const SQLI_COMMENT_ONLY_RE = /'\s*(--|#|\/\*)/;

function detectCommentOnlySqli(rawString) {
  if (!rawString || typeof rawString !== 'string') return false;
  return SQLI_COMMENT_ONLY_RE.test(rawString);
}

// ---------------------------------------------------------------------------
// 통합 진입점
// ---------------------------------------------------------------------------

/**
 * @param {object} req
 * @param {string} req.method
 * @param {string} req.normalizedPath
 * @param {object|null} req.body      - 이미 JSON.parse된 객체 (문자열이면 내부에서 파싱 시도)
 * @param {string} [req.rawQueryOrBody] - comment-only SQLi 검사용 원본 문자열(URL 쿼리 등)
 * @returns {Array<{tag:string, detail:object}>}
 */
function analyzeBusinessLogic({ method, normalizedPath, body, rawQueryOrBody, profile }) {
  const tags = [];

  let bodyObj = body;
  if (typeof bodyObj === 'string') {
    try { bodyObj = JSON.parse(bodyObj); } catch { bodyObj = null; }
  }

  const mass = detectMassAssignment(method, normalizedPath, bodyObj, profile);
  if (mass.hit) tags.push({ tag: 'mass-assignment', detail: mass });

  const numeric = detectNumericAbuse(bodyObj, profile);
  if (numeric.hit) tags.push({ tag: 'numeric-abuse', detail: numeric });

  const nosql = detectNoSqlOperatorInjection(bodyObj);
  if (nosql.hit) tags.push({ tag: 'nosql-injection-generalized', detail: nosql });

  const commentSqli = detectCommentOnlySqli(rawQueryOrBody) || detectCommentOnlySqli(JSON.stringify(bodyObj || ''));
  if (commentSqli) tags.push({ tag: 'sqli-comment-only', detail: {} });

  return tags;
}

module.exports = {
  analyzeBusinessLogic,
  detectMassAssignment,
  hasHardcodedMassAssignmentWhitelist,
  detectNumericAbuse,
  detectNoSqlOperatorInjection,
  detectCommentOnlySqli,
};
