'use strict';

/**
 * passwordResetAbuse.js
 *
 * 비밀번호 재설정(Forgot Password) 플로우 남용 탐지 — loginBruteForce.js와 완전히 같은
 * 이유로 별도 모듈로 분리했다: 요청 하나만 보고는 절대 판단할 수 없고, **같은 세션/Actor
 * 안에서 여러 계정을 대상으로 반복된 패턴**을 봐야만 안다. 그래서 이 모듈도 "판정"이 아니라
 * "요청 하나에서 집계에 필요한 최소한의 정보(email)만 뽑아내는" 역할만 하고, 반복 패턴 집계는
 * featureExtractor.js가, 점수화는 classifier.js가 한다.
 *
 * 1차 실전 공격 테스트 재검증 라운드에서 발견된 미탐: 공격자가 (1) `GET
 * /rest/user/security-question?email=...`로 여러 계정의 보안 질문을 순회 정찰한 뒤,
 * (2) `POST /rest/user/reset-password`로 각 계정의 비밀번호 재설정을 연속 시도 —
 * Juice Shop의 "Reset Bender's Password" 류 챌린지가 정확히 이 패턴이다. 로그인 무차별
 * 대입과 위협 모델이 사실상 동일(계정을 대상으로 반복 시도해 접근권을 얻으려는 시도)하고
 * 계산 방식(이메일별 시간창 내 반복 집계)도 loginBruteForce와 완전히 같은 형태라, 새
 * 서브스코어를 만들지 않고 featureExtractor.js에서 loginBruteForce 신호와 같은
 * attemptsByEmail 집계에 합류시킨다(classifier.js의 scoreLoginBruteForce를 그대로 재사용) —
 * role-gated를 businessLogicViolation에 접었던 것과 같은 판단 기준.
 *
 * server.js 연동 지점 (트랩 핸들러 + onProxyRes 양쪽):
 *
 *   const { extractResetPasswordEmail, extractSecurityQuestionEmail } = require('./lib/passwordResetAbuse');
 *   const resetPasswordEmail = extractResetPasswordEmail({ method, normalizedPath, body });
 *   const securityQuestionEmail = extractSecurityQuestionEmail({ method, normalizedPath, url });
 *   // recordRequest()에 각각 전달 -> requestRecord.resetPasswordEmail / .securityQuestionEmail
 *   // -> featureExtractor.extractLoginBruteForceSignal()이 loginAttemptEmail과 합쳐 이메일별로 집계
 *
 * security-question 조회는 로그인 실패와 달리 "실패"라는 상태가 없다(그냥 질문을 보여줄 뿐) —
 * 그래서 status 필터링 없이 라우트/이메일 존재만으로 집계 대상에 넣는다. 본인 계정 비밀번호를
 * 잊어 자기 보안질문을 한 번 조회하는 정상 사용자는 count=1이라 기존 scoreLoginBruteForce
 * 공식(1회는 거의 0점)에서 자연스럽게 정상 범위로 처리된다 — 여러 타인 계정을 순회할 때만
 * distinctEmailsAttempted가 쌓여 점수가 오른다.
 */

/**
 * 재설정·보안질문 라우트와 계정 식별 필드명은 사이트마다 다르고, **한쪽만 있는
 * 사이트도 있다** — RUBY Market 에는 `/api/auth/password-reset/{request,confirm}` 이
 * 있지만 보안질문 라우트가 아예 없다. 그래서 프로파일의 두 반쪽
 * (`passwordResetAbuse.resetRoute`/`.resetEmailField`,
 *  `.securityQuestionRoute`/`.securityQuestionEmailField`)을 **따로** 본다.
 *
 * 한쪽이 없으면 그 반쪽만 꺼지고 나머지는 계속 돈다. 꺼진 사실은 siteProfiles.js 의
 * 기동 경고와 /__detection/api/site-profile-status 로 드러난다.
 */

function normalizeEmail(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim().toLowerCase();
  return trimmed || null;
}

/**
 * @param {object} req
 * @param {string} req.method
 * @param {string} req.normalizedPath
 * @param {object|string|null} req.body
 * @param {object|null} req.profile 활성 사이트 프로파일(`req.siteProfile`)
 * @returns {string|null} 소문자로 정규화된 email, 재설정 라우트가 아니거나 email 필드가
 *   없거나 프로파일에 설정이 없으면 null
 */
function extractResetPasswordEmail({ method, normalizedPath, body, profile }) {
  const route = profile?.passwordResetAbuse?.resetRoute;
  if (!route) return null;

  const upperMethod = String(method || '').toUpperCase();
  if (upperMethod !== route.method || normalizedPath !== route.normalizedPath) {
    return null;
  }

  let bodyObj = body;
  if (typeof bodyObj === 'string') {
    try { bodyObj = JSON.parse(bodyObj); } catch { return null; }
  }
  if (!bodyObj || typeof bodyObj !== 'object') return null;

  return normalizeEmail(bodyObj[profile.passwordResetAbuse.resetEmailField]);
}

/**
 * security-question 조회는 body가 아니라 쿼리스트링(`?email=...`)으로 대상 계정을 지정한다 —
 * loginAttemptEmail/resetPasswordEmail과 달리 body가 아니라 url을 받는 이유.
 *
 * @param {object} req
 * @param {string} req.method
 * @param {string} req.normalizedPath
 * @param {string} req.url
 * @param {object|null} req.profile 활성 사이트 프로파일(`req.siteProfile`)
 * @returns {string|null}
 */
function extractSecurityQuestionEmail({ method, normalizedPath, url, profile }) {
  const route = profile?.passwordResetAbuse?.securityQuestionRoute;
  if (!route) return null;

  const upperMethod = String(method || '').toUpperCase();
  if (upperMethod !== route.method || normalizedPath !== route.normalizedPath) {
    return null;
  }

  try {
    const parsed = new URL(url || '', 'http://detection.local');
    // 대소문자를 구분해서 찾는다(기존 동작). identityMismatch 의 extractQueryValue 는
    // 일부러 대소문자 무관인데, 두 모듈의 이 차이는 이번 범위에서 바꾸지 않는다.
    return normalizeEmail(
      parsed.searchParams.get(profile.passwordResetAbuse.securityQuestionEmailField)
    );
  } catch {
    return null;
  }
}

module.exports = {
  extractResetPasswordEmail,
  extractSecurityQuestionEmail,
};
