'use strict';

/**
 * roleGatedAccess.js
 *
 * mass-assignment/identity-mismatch와는 잡는 지점이 다르다: 이건 "body에 이상한 필드가
 * 있는가"도 "리소스 소유자가 맞는가"도 아니라, **"이 엔드포인트 자체를 이 role로 써도
 * 되는가"** 를 본다 — 인가(Authorization) 그 자체를 흉내 낸 관찰이다.
 *
 * 4차 라운드 로그에 `GET /rest/admin/application-configuration`이 200으로 통과한 실제
 * 사례가 있었는데, 그 요청을 보낸 토큰의 role이 admin이었는지는 지금까지 아무 코드도
 * 확인하지 않고 있었다. Juice Shop 공식 챌린지 중 Exposed Metrics(`GET /metrics`)와
 * Product Tampering(관리자 전용 상품 API)도 같은 종류다.
 *
 * JWT 디코딩(서명 검증 없음)은 identityMismatch.js에 이미 있는 decodeClaimedIdentity()/
 * extractToken()을 그대로 재사용한다 — 새로 만든 코드는 "민감 엔드포인트 목록"뿐이다.
 *
 * 주의(정직하게): 이건 화이트리스트 기반 근사치다. 진짜 인가 체계를 재구현하는 게 아니라,
 * "이 경로는 보통 admin만 써야 한다"는 걸 사람이 미리 나열해둔 것 — Juice Shop이 실제로
 * 서버 단에서 role을 어떻게 검증하는지와 무관하게, 탐지 프록시 입장에서 의심 신호로만 쓴다
 * (log-only, 다른 신규 피처들과 동일).
 *
 * server.js 연동: businessLogicSignatures.js/identityMismatch.js와 나란히 호출해 같은
 * blTags 배열에 합친다 — 이것도 "정규식으로는 안 걸리는, 문법적으로 정상인 요청"이라는
 * businessLogicViolation 서브스코어의 정의에 들어맞기 때문에 별도 가중치를 새로 만들지
 * 않고 기존 파이프라인(blTags → businessLogicHits → scoreBusinessLogicViolation)에 얹었다.
 * 나중에 데이터가 쌓여서 인가 위반만 따로 추적하고 싶어지면, 그때 별도 서브스코어로
 * 분리하면 된다(태그 이름을 role-gated:*로 미리 구분해둔 이유이기도 하다).
 */

const { decodeClaimedIdentity, extractToken } = require('./identityMismatch');
const schemaLearning = require('./schemaLearning');

/**
 * 민감 라우트 목록과 요구 역할은 프로파일의 `roleGated.sensitiveRoutes` 에서 온다.
 * normalizedPath 는 requestMetadata.normalizePath() 결과와 동일한 형식(숫자 세그먼트는
 * :id 로 치환됨)이라고 가정한다.
 *
 * 역할 이름은 소문자로만 선언할 수 있다 — 이 모듈이 claimed.role 을 소문자로 비교하므로
 * 대문자로 선언하면 영구 미스매치가 된다. siteProfile.js 의 검증기가 막는다.
 *
 * 요청마다 Set 을 다시 만들지 않도록 프로파일당 한 번만 만들어 WeakMap 에 담는다.
 */
const routeCache = new WeakMap();

function sensitiveRoutesFor(profile) {
  const declared = profile?.roleGated?.sensitiveRoutes;
  if (!declared) return null;
  const cached = routeCache.get(profile);
  if (cached) return cached;
  const built = declared.map((route) => ({
    tag: route.tag,
    method: route.method,
    normalizedPath: route.normalizedPath,
    requiredRoles: new Set(route.requiredRoles),
  }));
  routeCache.set(profile, built);
  return built;
}

// 프로파일이 선언한 민감 라우트에 이 라우트가 있는지 — server.js가 schemaLearning 관찰
// 시점에 "이미 선언돼 있으니 학습 대상 아님"을 판단할 때 재사용한다.
function isHardcodedSensitiveRoute(method, normalizedPath, profile) {
  const routes = sensitiveRoutesFor(profile);
  if (!routes) return false;
  const upperMethod = String(method || '').toUpperCase();
  return routes.some((route) => route.method === upperMethod && route.normalizedPath === normalizedPath);
}

/**
 * @returns {Array<{tag:string, detail:object}>}
 */
function checkRoleGatedAccess({
  method, normalizedPath, authorizationHeader, cookieHeader, profile,
}) {
  const results = [];
  const identity = profile?.identity;
  // 토큰 추출과 클레임 해독은 identityMismatch 가 프로파일에서 읽는다 — 그 설정이
  // 없으면 역할을 알 수 없으므로 이 검사도 성립하지 않는다.
  if (!identity?.tokenSources || !identity?.claimMap) return results;

  const upperMethod = String(method || '').toUpperCase();
  const declared = sensitiveRoutesFor(profile);
  const matches = (declared || []).filter(
    (route) => route.method === upperMethod && route.normalizedPath === normalizedPath
  );

  const token = extractToken(authorizationHeader, cookieHeader, identity.tokenSources);
  const claimed = token ? decodeClaimedIdentity(token, identity.claimMap) : null;
  const claimedRole = claimed && claimed.role ? String(claimed.role).toLowerCase() : null;

  for (const route of matches) {
    const allowed = claimedRole !== null && route.requiredRoles.has(claimedRole);
    if (!allowed) {
      results.push({
        tag: route.tag,
        detail: {
          requiredRoles: Array.from(route.requiredRoles),
          claimedRole: claimedRole || null,
          hasToken: Boolean(token),
        },
      });
    }
  }

  // 선언된 매치가 하나도 없을 때만 학습된(승인된) 민감 라우트를 확인한다 — 선언이
  // 우선이고, schemaLearning은 선언이 없는 빈틈만 메운다(15차, 2026-09-02).
  // 프로파일에 roleGated 블록이 아예 없으면 학습 폴백만 남는다 — 리팩토링 이전에도
  // 다른 사이트에서는 그 상태였다(7개 라우트가 전부 Juice Shop 전용이었으므로).
  if (!matches.length) {
    const learnedRoles = schemaLearning.getApprovedSensitiveRoute(method, normalizedPath);
    if (learnedRoles) {
      const allowed = claimedRole !== null && learnedRoles.has(claimedRole);
      if (!allowed) {
        results.push({
          tag: 'role-gated:learned',
          detail: {
            requiredRoles: Array.from(learnedRoles),
            claimedRole: claimedRole || null,
            hasToken: Boolean(token),
            source: 'schemaLearning',
          },
        });
      }
    }
  }

  return results;
}

module.exports = { checkRoleGatedAccess, isHardcodedSensitiveRoute };
