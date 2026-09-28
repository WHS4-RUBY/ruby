'use strict';

const { extractTrailingNumericId } = require('./priceIntegrity');
const schemaLearning = require('./schemaLearning');

/**
 * identityMismatch.js
 *
 * IDOR을 "그 경로에 접근했다"가 아니라 "내 토큰이 주장하는 신원과 실제로 접근한
 * 리소스 소유자가 다르다"로 잡는 모듈. payloadSignatures.js의 idor-probe 정규식과
 * featureExtractor.js의 idorWalk 신호는 경로 패턴/순차 열람만 보기 때문에 내 바구니를
 * 정상 조회하는 것과 남의 바구니를 훔쳐보는 것을 구분하지 못한다 — 이 모듈이 그 둘을 구분한다.
 *
 * 핵심 아이디어: Juice Shop의 JWT는 서명 검증 없이도(base64url decode만으로) 다음을 담고 있다.
 *   { "data": { "id": <userId>, "email": ..., "role": ... }, "bid": <basketId>, "iat": ... }
 * (attack-claude-01 라운드에서 위조한 alg:none 토큰 페이로드로 실측 확인된 구조.)
 * payloadSignatures.js가 이미 JWT alg:none 검사를 위해 같은 방식(서명 검증 없이 base64url
 * 디코딩)으로 header segment를 읽고 있으니, 같은 방식으로 payload segment도 읽어서
 * "이 요청을 보낸 사람이 누구라고 주장하는지"를 얻는다. 서명을 검증하지 않으므로 이 값
 * 자체는 위조된 값일 수 있지만, 오히려 그게 좋다 — 위조한 값과 실제 접근 대상이 다르면
 * (예: alg:none으로 admin을 사칭했는데 실제 자기 바구니 bid는 다른 값) 그 자체가 강한 신호다.
 *
 * 한계: 리뷰 수정(PATCH /rest/products/reviews)처럼 리소스 소유자가 JWT 클레임이 아니라
 * DB에만 있는 경우(Mongo review _id -> 그 리뷰를 처음 쓴 사람)는 이 방식으로 못 잡는다 —
 * 응답 바디를 보고 소유자를 학습해두는 별도의 상태 추적이 필요하고, 지금은 범위 밖으로 남겼다.
 *
 * 2026-09-02 11차 추가: 쿼리파라미터형 IDOR — `GET /api/Baskets?UserId=18`처럼 대상 리소스를
 * URL 경로(`/rest/basket/:id`)가 아니라 **쿼리스트링**으로 지정하는 라우트는 기존
 * IDENTITY_ROUTE_RULES(경로 세그먼트만 정규식으로 추출)로 못 잡았다. payloadSignatures.js의
 * `idor-probe`도 경로만 보는 정규식이라 마찬가지로 못 잡는 사각지대였다. 이 모듈이 이미
 * "JWT 클레임 vs 실제 접근 대상"을 비교하는 인프라(디코딩·정규화)를 갖추고 있어서, 대상 ID를
 * 쿼리스트링에서 뽑는 IDENTITY_QUERY_RULES만 추가하면 됐다 — 판단 로직/신뢰도 성격이 완전히
 * 같아 새 태그 카테고리(identity-mismatch:*)만 하나 늘리고 별도 모듈/서브스코어는 안 만들었다.
 */

// ---------------------------------------------------------------------------
// JWT 디코딩 (서명 검증 없음 — 의도적)
// ---------------------------------------------------------------------------

function base64UrlDecode(segment) {
  try {
    const padded = segment.replace(/-/g, '+').replace(/_/g, '/').padEnd(segment.length + ((4 - (segment.length % 4)) % 4), '=');
    return Buffer.from(padded, 'base64').toString('utf8');
  } catch {
    return null;
  }
}

/**
 * @returns {{id:number|string|null, email:string|null, role:string|null, bid:number|string|null}|null}
 */
function decodeClaimedIdentity(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length < 2) return null;

  const payloadRaw = base64UrlDecode(parts[1]);
  if (!payloadRaw) return null;

  let payload;
  try { payload = JSON.parse(payloadRaw); } catch { return null; }

  const data = payload.data || payload; // 혹시 다른 사이트에서 data 래핑이 없을 경우 대비
  return {
    id: data.id ?? null,
    email: data.email ?? null,
    role: data.role ?? null,
    bid: payload.bid ?? null,
  };
}

function extractToken(authorizationHeader, cookieHeader) {
  if (authorizationHeader && /^Bearer\s+/i.test(authorizationHeader)) {
    return authorizationHeader.replace(/^Bearer\s+/i, '').trim();
  }
  // CSRF 라운드(3차)에서 관측된 패턴: Authorization 헤더 대신 Cookie: token=<JWT> 로 세팅
  if (cookieHeader) {
    const m = /(?:^|;\s*)token=([^;]+)/.exec(cookieHeader);
    if (m) return decodeURIComponent(m[1]);
  }
  return null;
}

// ---------------------------------------------------------------------------
// 라우트별 "요청 대상 리소스가 내 것이어야 한다" 규칙
// ---------------------------------------------------------------------------

const IDENTITY_ROUTE_RULES = [
  {
    tag: 'identity-mismatch:basket',
    test: (method, normalizedPath) => normalizedPath === '/rest/basket/:id',
    extractRequestedId: (url) => {
      const m = /\/rest\/basket\/(\d+)/.exec(url);
      return m ? Number(m[1]) : null;
    },
    claimField: 'bid',
  },
  {
    tag: 'identity-mismatch:user',
    test: (method, normalizedPath) => normalizedPath === '/api/Users/:id',
    extractRequestedId: (url) => {
      const m = /\/api\/Users\/(\d+)/.exec(url);
      return m ? Number(m[1]) : null;
    },
    claimField: 'id',
  },
];

/**
 * 요청 바디 안에서 "본인 UserId여야 하는데 남의 것을 넣었다"를 잡는 규칙.
 */
const IDENTITY_BODY_RULES = [
  {
    tag: 'identity-mismatch:feedback-userid',
    test: (method, normalizedPath) =>
      routeMatches(method, normalizedPath, 'POST', '/api/Feedbacks') ||
      routeMatches(method, normalizedPath, 'POST', '/api/Feedbacks/'),
    field: 'UserId',
    claimField: 'id',
  },
];

function routeMatches(method, normalizedPath, expectedMethod, expectedPath) {
  return String(method).toUpperCase() === expectedMethod && normalizedPath === expectedPath;
}

/**
 * 요청 URL의 쿼리스트링 안에서 "본인 UserId여야 하는데 남의 것을 넣었다"를 잡는 규칙.
 * IDENTITY_ROUTE_RULES(경로 세그먼트)/IDENTITY_BODY_RULES(요청 바디)와 대상은 같지만
 * 값이 실려오는 위치만 다르다 — `GET /api/Baskets?UserId=18`처럼 필터링용 쿼리파라미터로
 * 대상 리소스 소유자를 지정하는 라우트용.
 */
const IDENTITY_QUERY_RULES = [
  {
    tag: 'identity-mismatch:baskets-query',
    test: (method, normalizedPath) => routeMatches(method, normalizedPath, 'GET', '/api/Baskets'),
    field: 'UserId',
    claimField: 'id',
  },
];

// URLSearchParams는 키 대소문자를 구분하므로, 쿼리파라미터 이름 표기가 흔들려도
// (UserId/userId/userid) 놓치지 않도록 대소문자 무관 비교로 값을 찾는다.
function extractQueryValue(url, field) {
  try {
    const parsed = new URL(url || '', 'http://detection.local');
    const lowerField = field.toLowerCase();
    for (const [key, value] of parsed.searchParams.entries()) {
      if (key.toLowerCase() === lowerField) return value;
    }
    return null;
  } catch {
    return null;
  }
}

// 세 규칙(경로/바디/쿼리) 중 하나라도 이 method+normalizedPath에 매칭되면 하드코딩된 규칙이
// 있는 라우트다 — schemaLearning 학습 fallback은 이런 라우트에는 적용하지 않는다(하드코딩이
// 우선, businessLogicSignatures.js/roleGatedAccess.js와 같은 원칙).
function isHardcodedIdentityRoute(method, normalizedPath) {
  return (
    IDENTITY_ROUTE_RULES.some((rule) => rule.test(method, normalizedPath)) ||
    IDENTITY_BODY_RULES.some((rule) => rule.test(method, normalizedPath)) ||
    IDENTITY_QUERY_RULES.some((rule) => rule.test(method, normalizedPath))
  );
}

// schemaLearning.js가 승인한 identity 후보 fallback(15차 확장). 하드코딩 규칙과 달리 어떤
// 필드(id vs bid)와 비교해야 하는지 라우트마다 다르다는 문제를 피하려고, URL 끝 숫자
// 세그먼트(extractTrailingNumericId — priceIntegrity.js와 동일한 일반화된 추출기)가 claimed.id/
// claimed.bid 둘 중 아무거나와도 안 맞으면 탐지하는 넓은 규칙 하나만 쓴다.
function checkLearnedIdentityMismatch(method, normalizedPath, url, claimed) {
  if (isHardcodedIdentityRoute(method, normalizedPath)) return null; // 하드코딩이 우선
  if (!schemaLearning.getApprovedIdentityRule(method, normalizedPath)) return null;

  const requestedId = extractTrailingNumericId(url);
  if (requestedId === null) return null;

  const claimedIds = [claimed.id, claimed.bid].filter((v) => v !== null && v !== undefined);
  if (claimedIds.length === 0) return null;
  if (claimedIds.some((c) => String(c) === String(requestedId))) return null;

  return {
    tag: 'identity-mismatch:learned',
    detail: { requestedId, claimedIdentity: claimed, source: 'schemaLearning' },
  };
}

// ---------------------------------------------------------------------------
// 통합 진입점
// ---------------------------------------------------------------------------

/**
 * @returns {Array<{tag:string, detail:object}>}
 */
function checkIdentityMismatch({ method, normalizedPath, url, body, authorizationHeader, cookieHeader }) {
  const results = [];
  const token = extractToken(authorizationHeader, cookieHeader);
  if (!token) return results; // 비인증 요청은 이 검사 대상이 아님(다른 IDOR 신호가 커버)

  const claimed = decodeClaimedIdentity(token);
  if (!claimed) return results; // JWT처럼 안 생겼으면 조용히 패스

  for (const rule of IDENTITY_ROUTE_RULES) {
    if (!rule.test(method, normalizedPath)) continue;
    const requestedId = rule.extractRequestedId(url);
    const claimedValue = claimed[rule.claimField];
    if (requestedId !== null && claimedValue !== null && String(requestedId) !== String(claimedValue)) {
      results.push({
        tag: rule.tag,
        detail: { requestedId, claimedValue, claimField: rule.claimField, claimedIdentity: claimed },
      });
    }
  }

  let bodyObj = body;
  if (typeof bodyObj === 'string') {
    try { bodyObj = JSON.parse(bodyObj); } catch { bodyObj = null; }
  }
  if (bodyObj && typeof bodyObj === 'object') {
    for (const rule of IDENTITY_BODY_RULES) {
      if (!rule.test(method, normalizedPath)) continue;
      const bodyValue = bodyObj[rule.field];
      const claimedValue = claimed[rule.claimField];
      if (bodyValue !== undefined && claimedValue !== null && String(bodyValue) !== String(claimedValue)) {
        results.push({
          tag: rule.tag,
          detail: { field: rule.field, bodyValue, claimedValue, claimedIdentity: claimed },
        });
      }
    }
  }

  for (const rule of IDENTITY_QUERY_RULES) {
    if (!rule.test(method, normalizedPath)) continue;
    const queryValue = extractQueryValue(url, rule.field);
    const claimedValue = claimed[rule.claimField];
    if (queryValue !== null && claimedValue !== null && String(queryValue) !== String(claimedValue)) {
      results.push({
        tag: rule.tag,
        detail: { field: rule.field, queryValue, claimedValue, claimedIdentity: claimed },
      });
    }
  }

  const learnedHit = checkLearnedIdentityMismatch(method, normalizedPath, url, claimed);
  if (learnedHit) results.push(learnedHit);

  return results;
}

module.exports = {
  checkIdentityMismatch,
  decodeClaimedIdentity,
  extractToken,
  isHardcodedIdentityRoute,
  IDENTITY_ROUTE_RULES,
  IDENTITY_BODY_RULES,
  IDENTITY_QUERY_RULES,
};
