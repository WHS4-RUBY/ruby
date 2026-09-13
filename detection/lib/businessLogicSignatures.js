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

const MASS_ASSIGNMENT_WHITELIST = new Map([
  ['POST /api/Users', new Set(['email', 'password', 'passwordRepeat', 'securityQuestion', 'securityAnswer'])],
  ['POST /api/Users/', new Set(['email', 'password', 'passwordRepeat', 'securityQuestion', 'securityAnswer'])],
  ['POST /api/Feedbacks', new Set(['comment', 'rating', 'captchaId', 'captcha'])],
  ['POST /api/Feedbacks/', new Set(['comment', 'rating', 'captchaId', 'captcha'])],
  ['PUT /rest/products/:id/reviews', new Set(['message'])], // author는 세션에서 나와야지 클라이언트가 지정하면 안 됨
  ['PATCH /rest/products/reviews', new Set(['id', 'message'])],
  // 1차 실전 공격 테스트 미탐: PUT /api/Products/:id (상품 변조)는 role-gated:product-write로만
  // 커버되고 있었는데, 관리자 상품 편집 폼이 절대 보내지 않는 필드를 끼워넣는 시도는 잡지
  // 못했다. review 변조를 mass-assignment로 잡던 것과 같은 원리를 여기에도 적용한다.
  ['PUT /api/Products/:id', new Set(['name', 'description', 'price', 'deluxePrice', 'image', 'category', 'CategoryId'])],
]);

// 값(형태)과 무관하게, 어떤 엔드포인트에서도 나타나면 안 되는 "권한 관련 필드 이름"
const ALWAYS_SUSPICIOUS_FIELDS = new Set([
  'role', 'isadmin', 'is_admin', 'admin', 'permissions', 'scope',
  'accesslevel', 'is_staff', 'is_superuser', 'usertype',
  // 1차 실전 공격 테스트: 회원가입 role:"admin" 주입이 한 번 잡힌 뒤 바로 다음 유사 시도가
  // 미탐이었다 — 동의어(roles/authority/grants 등)로 바꾸거나 값을 객체 안에 중첩시키면
  // 빠져나갔을 가능성이 커서, 동의어를 늘리고 아래에서 중첩 객체까지 재귀적으로 훑도록 고쳤다.
  'roles', 'authority', 'authorities', 'grants', 'privilege', 'privileges',
  'acl', 'superuser', 'root', 'roleid', 'role_id',
]);

// 필드 "이름"이 아니라 "값"이 권한 상승을 노리는 경우 — 화이트리스트에 있는 필드라도
// (예: securityQuestion을 문자열 대신 객체로 보내면서 그 안에 admin류 값을 숨김) 값 자체가
// admin류 리터럴이면 의심스럽다. 2차 실전 공격 테스트에서 재현된 "회원가입 재시도 2차
// 시도"가 필드명 동의어/중첩 확장(9차)으로도 안 잡힌 것에 대한 방어적 보강 — 다만 그 요청의
// 원본 페이로드를 직접 확인하지 못했으므로 정확히 같은 패턴인지는 확신할 수 없고, 타입
// 혼동(type confusion)을 통한 값 주입 경로를 넓게 커버하는 목적이 크다.
const SUSPICIOUS_ROLE_VALUES = new Set([
  'admin', 'administrator', 'root', 'superadmin', 'super_admin', 'sysadmin', 'owner',
]);

function routeKey(method, normalizedPath) {
  return `${String(method || '').toUpperCase()} ${normalizedPath || ''}`;
}

/**
 * @returns {{hit:boolean, extraFields:string[], suspiciousFields:string[], suspiciousValues:string[]}}
 */
// ALWAYS_SUSPICIOUS_FIELDS는 최상위 필드뿐 아니라 중첩된 객체/배열 안에도 숨겨질 수 있어
// (예: {"data":{"role":"admin"}}) 재귀적으로 훑는다 — detectNoSqlOperatorInjection과 같은 패턴.
function findSuspiciousFieldsDeep(node, acc = []) {
  if (!node || typeof node !== 'object') return acc;
  if (Array.isArray(node)) {
    for (const item of node) findSuspiciousFieldsDeep(item, acc);
    return acc;
  }
  for (const [key, value] of Object.entries(node)) {
    if (ALWAYS_SUSPICIOUS_FIELDS.has(key.toLowerCase())) acc.push(key);
    if (value && typeof value === 'object') findSuspiciousFieldsDeep(value, acc);
  }
  return acc;
}

// 최상위 필드 중 화이트리스트에 있는 것(password/comment 등 자유 텍스트)은 값 검사에서
// 제외한다 — 안 그러면 사용자가 실제로 비밀번호를 "admin"으로 정한 정상 케이스까지
// 공격으로 오탐한다. 화이트리스트 밖 최상위 필드와, 어떤 필드든 그 안에 중첩된 값은 검사한다.
function findSuspiciousValuesDeep(node, whitelist, acc = [], isTopLevel = true) {
  if (!node || typeof node !== 'object') return acc;
  if (Array.isArray(node)) {
    for (const item of node) findSuspiciousValuesDeep(item, whitelist, acc, false);
    return acc;
  }
  for (const [key, value] of Object.entries(node)) {
    const skipValueCheck = isTopLevel && whitelist && whitelist.has(key);
    if (!skipValueCheck && typeof value === 'string' && SUSPICIOUS_ROLE_VALUES.has(value.trim().toLowerCase())) {
      acc.push(key);
    }
    if (value && typeof value === 'object') findSuspiciousValuesDeep(value, whitelist, acc, false);
  }
  return acc;
}

// 하드코딩된 화이트리스트가 있는 라우트인지 — server.js가 schemaLearning 관찰 시점에
// "이미 하드코딩돼 있으니 학습 대상 아님"을 판단할 때 재사용한다.
function hasHardcodedMassAssignmentWhitelist(method, normalizedPath) {
  return MASS_ASSIGNMENT_WHITELIST.has(routeKey(method, normalizedPath));
}

function detectMassAssignment(method, normalizedPath, bodyObj) {
  const result = { hit: false, extraFields: [], suspiciousFields: [], suspiciousValues: [] };
  if (!bodyObj || typeof bodyObj !== 'object' || Array.isArray(bodyObj)) return result;

  const fields = Object.keys(bodyObj);

  // 화이트리스트가 정의된 라우트면 최상위 필드만 정확 매치(라우트별 스키마 기준이라
  // 중첩까지 화이트리스트로 관리하면 너무 엄격해져 오탐이 늘어난다). 하드코딩이 없으면
  // schemaLearning.js가 승인해둔 학습 화이트리스트를 대신 쓴다 — 둘 다 없으면 여전히
  // checked:false 취급(아무 판단 안 함, 오탐 방지 원칙 유지).
  const whitelist = MASS_ASSIGNMENT_WHITELIST.get(routeKey(method, normalizedPath))
    || schemaLearning.getApprovedMassAssignmentWhitelist(method, normalizedPath)
    || null;
  if (whitelist) {
    result.extraFields = fields.filter((f) => !whitelist.has(f));
  }

  // 화이트리스트 유무와 무관하게 권한 관련 필드명은 항상 의심 — 중첩된 객체 안까지 훑는다
  result.suspiciousFields = Array.from(new Set(findSuspiciousFieldsDeep(bodyObj)));

  // 값 기반 검사는 화이트리스트가 정의된 라우트(스키마가 명확한 폼)에서만 수행한다 —
  // 스키마가 없는 라우트까지 값을 훑으면 일반 텍스트(상품 설명, 코멘트 등)에서 오탐이 늘어난다.
  result.suspiciousValues = whitelist
    ? Array.from(new Set(findSuspiciousValuesDeep(bodyObj, whitelist)))
    : [];

  result.hit = result.extraFields.length > 0 || result.suspiciousFields.length > 0 || result.suspiciousValues.length > 0;
  return result;
}

// ---------------------------------------------------------------------------
// 2. 숫자 필드 도메인 범위 이상탐지 — 가격을 0으로, 수량을 음수로 등
// ---------------------------------------------------------------------------

const NUMERIC_FIELD_RULES = new Map([
  ['price', { min: 0.01 }],
  ['deluxeprice', { min: 0 }],
  ['quantity', { min: 1, max: 100 }],
  ['rating', { min: 1, max: 5 }], // Juice Shop "Zero Stars" 챌린지: UI는 1~5점만 허용하지만 API는 0점도 받아줌 — min을 1로 둬야 실제 정상 범위와 일치한다
]);

/**
 * @returns {{hit:boolean, violations:Array<{field:string, value:number, rule:object}>}}
 */
function detectNumericAbuse(bodyObj) {
  const violations = [];
  if (!bodyObj || typeof bodyObj !== 'object' || Array.isArray(bodyObj)) return { hit: false, violations };

  for (const [key, value] of Object.entries(bodyObj)) {
    const rule = NUMERIC_FIELD_RULES.get(key.toLowerCase());
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
function analyzeBusinessLogic({ method, normalizedPath, body, rawQueryOrBody }) {
  const tags = [];

  let bodyObj = body;
  if (typeof bodyObj === 'string') {
    try { bodyObj = JSON.parse(bodyObj); } catch { bodyObj = null; }
  }

  const mass = detectMassAssignment(method, normalizedPath, bodyObj);
  if (mass.hit) tags.push({ tag: 'mass-assignment', detail: mass });

  const numeric = detectNumericAbuse(bodyObj);
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
  MASS_ASSIGNMENT_WHITELIST,
  ALWAYS_SUSPICIOUS_FIELDS,
  SUSPICIOUS_ROLE_VALUES,
  NUMERIC_FIELD_RULES,
};
