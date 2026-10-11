'use strict';

/**
 * loginBruteForce.js
 *
 * 로그인 무차별 대입(Brute Force)/Credential Stuffing 탐지 — Juice Shop의 "Password Strength"
 * 챌린지(약한 계정 비밀번호를 계속 시도해 뚫는 것) 대응.
 *
 * 지금까지 만든 businessLogicSignatures.js/identityMismatch.js/roleGatedAccess.js/csrfDetection.js는
 * 전부 "요청 하나만 보고 즉시 판정 가능한" 순수 함수였다. 이 모듈은 다르다 — 무차별 대입은 한 번의
 * 요청만으로는 절대 판단할 수 없고, **같은 세션/Actor 안에서 반복된 로그인 실패 패턴**을 봐야만 안다.
 * 그래서 이 모듈은 "판정"이 아니라 "요청 하나에서 집계에 필요한 최소한의 정보(email)만 뽑아내는"
 * 역할만 하고, 실제 반복 패턴 집계는 featureExtractor.js(extractLoginBruteForceSignal, IDOR Walk와
 * 동일한 패턴)에서, 점수화는 classifier.js(scoreLoginBruteForce)에서 한다 — 3단 분리.
 *
 * server.js 연동 지점 (onProxyRes):
 *
 *   const { extractLoginAttemptEmail } = require('./lib/loginBruteForce');
 *   const loginAttemptEmail = extractLoginAttemptEmail({
 *     method: req.method, normalizedPath, body: req.body, profile: req.siteProfile,
 *   });
 *   // recordRequest()에 loginAttemptEmail로 전달 -> requestRecord.loginAttemptEmail
 *   // -> featureExtractor가 status===401인 것만 골라 이메일별로 집계
 *
 * 왜 이메일을 태그가 아니라 별도 필드로 두는가: tags/blTags/csrfTags는 전부 "이 요청이 어떤 종류의
 * 위반인가"를 나타내는 라벨이고, 이건 그 자체로 위반 여부를 말하지 않는 원자료(raw datum) —
 * 로그인 성공이든 실패든 이메일 자체는 무해하고, 실패가 여러 번 반복될 때만 의미가 생기기 때문에
 * featureExtractor 단계에서 status와 결합해서 판단해야 한다.
 */

/**
 * 로그인 라우트와 본문 필드명은 사이트마다 다르다 — Juice Shop 은
 * `POST /rest/user/login` 의 `email`, RUBY Market 은 `POST /api/auth/login` 이다.
 * 그래서 프로파일(`loginBruteForce.route`, `loginBruteForce.emailField`)에서 읽는다.
 *
 * 프로파일에 블록이 없으면 이 기능은 꺼진다. 조용히 꺼지지는 않는다 —
 * siteProfiles.js 가 기동 시 프로파일·기능·사유를 경고하고,
 * /__detection/api/site-profile-status 와 대시보드가 "비활성(프로파일 없음)" 으로
 * 표시한다. 리팩토링 전에는 라우트가 다른 사이트에서 이 함수가 아무 신호 없이
 * 영구히 null 을 돌려줬다.
 *
 * 프로파일을 모듈 전역으로 받지 않고 호출마다 받는 이유는 siteProfiles.js 주석 참고 —
 * 한 프로세스가 여러 대상을 서비스하고 활성 대상이 런타임에 전환된다.
 *
 * @param {object} req
 * @param {string} req.method
 * @param {string} req.normalizedPath
 * @param {object|string|null} req.body
 * @param {object|null} req.profile 활성 사이트 프로파일(`req.siteProfile`)
 * @returns {string|null} 소문자로 정규화된 email, 로그인 라우트가 아니거나 email 필드가
 *   없거나 프로파일에 설정이 없으면 null
 */
function extractLoginAttemptEmail({ method, normalizedPath, body, profile }) {
  const config = profile?.loginBruteForce;
  if (!config) return null;

  const upperMethod = String(method || '').toUpperCase();
  if (upperMethod !== config.route.method || normalizedPath !== config.route.normalizedPath) {
    return null;
  }

  let bodyObj = body;
  if (typeof bodyObj === 'string') {
    try { bodyObj = JSON.parse(bodyObj); } catch { return null; }
  }
  if (!bodyObj || typeof bodyObj !== 'object') return null;

  const email = bodyObj[config.emailField];
  if (typeof email !== 'string' || !email.trim()) return null;

  return email.trim().toLowerCase();
}

module.exports = {
  extractLoginAttemptEmail,
};
