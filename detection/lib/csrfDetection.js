'use strict';

/**
 * csrfDetection.js
 *
 * CSRF(Cross-Site Request Forgery)를 Origin/Referer 헤더 검증으로 잡는 모듈.
 *
 * businessLogicSignatures.js/identityMismatch.js/roleGatedAccess.js는 전부 JWT 클레임이나
 * 요청 바디를 근거로 삼지만, 이 모듈은 그 둘을 전혀 보지 않고 오직 Origin/Referer 헤더만
 * 본다 — 근거(evidence source)가 근본적으로 달라서 businessLogicViolation 서브스코어에
 * 얹지 않고 별도 서브스코어(csrf, ATTACK_WEIGHTS.csrf)로 분리했다(2026-09-01, 사용자 확인).
 *
 * 판정 대상: 상태를 바꾸는 메서드(POST/PUT/PATCH/DELETE)만 본다 — GET/HEAD 등 안전한
 * 메서드는 CSRF 위협모델 밖이라 애초에 검사하지 않는다.
 *
 * 판정 로직 (OWASP CSRF Cheat Sheet의 "Verifying Origin with Standard Headers" 절 기준):
 *   1. Origin 헤더가 있으면 그 값이 이 프록시의 허용 origin 목록에 있는지만 본다
 *      (Origin이 있는데 불일치 -> csrf:origin-mismatch. 있고 일치하면 통과).
 *   2. Origin이 없고 Referer 헤더가 있으면 Referer의 origin으로 같은 방식 검사
 *      (csrf:referer-mismatch).
 *   3. 둘 다 없으면 csrf:missing-origin — 최신 브라우저는 fetch/XHR/form 제출 시 same-origin
 *      POST에도 Origin을 자동으로 붙이므로, 상태 변경 요청에 둘 다 없다는 건 브라우저를
 *      거치지 않은 직접 HTTP 호출(curl, requests, 자동화 스크립트 등)일 가능성을 시사한다.
 *      이건 고전적 CSRF라기보다 "브라우저 컨텍스트 부재" 신호에 가깝지만, 이 프로젝트의
 *      목적(AI 에이전트 자동화 공격 탐지)에는 오히려 더 유용한 신호라 같은 태그 계열로 묶었다.
 *
 * server.js 연동 지점 (computeBusinessLogicTags 옆에 별도 호출):
 *
 *   const { checkCsrf, buildAllowedOrigins } = require('./lib/csrfDetection');
 *   const ALLOWED_CSRF_ORIGINS = buildAllowedOrigins(['http://localhost:8080', ...]);
 *   const csrfTags = checkCsrf({
 *     method, normalizedPath,
 *     originHeader: req.headers.origin,
 *     refererHeader: req.headers.referer,
 *   }, ALLOWED_CSRF_ORIGINS).map(h => h.tag);
 *
 * 한계: 이 프록시가 자기 자신의 "정상 origin"이 무엇인지 환경변수/기본값으로만 알 수 있다.
 * 리버스 프록시 앞에 또 다른 프록시나 CDN이 있어서 브라우저가 보는 origin이 달라지는
 * 배포 환경이라면 CSRF_ALLOWED_ORIGINS 환경변수로 맞춰줘야 한다(README에 기록 권장).
 */

const STATE_CHANGING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function parseOrigin(value) {
  if (!value || typeof value !== 'string') return null;
  try {
    const u = new URL(value);
    return `${u.protocol}//${u.host}`;
  } catch {
    return null;
  }
}

/**
 * 문자열 배열(예: 환경변수를 콤마로 split한 것)을 정규화된 origin Set으로 만든다.
 * 이미 Set이 들어오면 그대로 통과시킨다(매 요청마다 다시 빌드하지 않도록 server.js에서
 * 시작 시 한 번만 호출해서 재사용하는 걸 권장).
 */
function buildAllowedOrigins(rawList) {
  if (rawList instanceof Set) return rawList;
  const set = new Set();
  for (const raw of rawList || []) {
    const origin = parseOrigin(raw) || (typeof raw === 'string' && raw ? raw.replace(/\/+$/, '') : null);
    if (origin) set.add(origin);
  }
  return set;
}

/**
 * @param {object} req
 * @param {string} req.method
 * @param {string} req.normalizedPath
 * @param {string} [req.originHeader]
 * @param {string} [req.refererHeader]
 * @param {Set<string>|string[]} allowedOrigins - 이 프록시가 정상으로 취급할 origin 목록
 * @returns {Array<{tag:string, detail:object}>}
 */
function checkCsrf({ method, normalizedPath, originHeader, refererHeader }, allowedOrigins) {
  const results = [];
  const upperMethod = String(method || '').toUpperCase();
  if (!STATE_CHANGING_METHODS.has(upperMethod)) return results;

  const allowed = buildAllowedOrigins(allowedOrigins);

  if (originHeader) {
    const origin = parseOrigin(originHeader);
    if (!origin || !allowed.has(origin)) {
      results.push({
        tag: 'csrf:origin-mismatch',
        detail: { normalizedPath, origin: originHeader, allowed: Array.from(allowed) },
      });
    }
    return results; // Origin이 있으면 그걸로 판정 끝 — Referer는 보조 신호라 중복 태깅 안 함
  }

  if (refererHeader) {
    const refererOrigin = parseOrigin(refererHeader);
    if (!refererOrigin || !allowed.has(refererOrigin)) {
      results.push({
        tag: 'csrf:referer-mismatch',
        detail: { normalizedPath, referer: refererHeader, allowed: Array.from(allowed) },
      });
    }
    return results;
  }

  results.push({ tag: 'csrf:missing-origin', detail: { normalizedPath } });
  return results;
}

module.exports = {
  checkCsrf,
  buildAllowedOrigins,
  parseOrigin,
  STATE_CHANGING_METHODS,
};
