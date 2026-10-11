"use strict";

const fs = require("fs");
const nodePath = require("path");

/**
 * 사이트 프로파일 — 대상 웹 애플리케이션의 라우트·필드명·JWT 클레임·쿠키 이름을
 * 코드 밖으로 뺀 선언. `detection/config/site-profiles/<profileId>.json` 하나가
 * 한 사이트를 설명한다.
 *
 * 왜 JSON Schema 라이브러리를 쓰지 않는가: Detection 은 devDependencies 가 0개이고
 * Dockerfile 이 `npm ci --omit=dev` 로 설치하므로, 검증기를 쓰려면 운영 의존성이
 * 되어야 한다(런타임 공격 표면과 `audit-ci --moderate` 표면이 함께 늘어난다).
 * 그리고 참조로 삼은 Defense 의 `site_profile.py` 자체가 JSON Schema 가 아니라
 * `__post_init__` 안의 손으로 쓴 규칙 6개다. 이 저장소의 모든 설정 로더
 * (`policyEngine.js`, `decoyPaths.js`, `targetSelection.js`, `requestInspection.js`)가
 * 같은 방식이다. 그래서 FEATURE_PATHS 표를 선언으로 두고 검사기가 그 표를 돈다 —
 * 스키마처럼 읽히면서 의존성이 없다.
 *
 * 검증은 로드 시점에 throw 한다. 잘못된 프로파일로 절반만 동작하는 탐지보다
 * 기동 실패가 낫다.
 */

// 프로파일이 켜거나 끌 수 있는 기능 경로의 정본 목록. 여기 없는 키는 거부되고,
// 여기 있는데 프로파일에 없으면 그 기능만 비활성 + 경고가 된다.
const FEATURE_PATHS = Object.freeze([
  "loginBruteForce",
  "passwordResetAbuse",
  "priceTampering",
  "priceIntegrity",
  "businessLogic.massAssignmentWhitelist",
  "businessLogic.alwaysSuspiciousFields",
  "businessLogic.suspiciousRoleValues",
  "businessLogic.numericFieldRules",
  "identity.tokenSources",
  "identity.claimMap",
  "identity.routeRules",
  "identity.bodyRules",
  "identity.queryRules",
  "roleGated",
  "deception.loginPath",
  "deception.apiPathPrefixes",
  "deception.plaintextBaitPaths",
  "deception.frontendFlavor",
]);

const TOP_LEVEL_KEYS = Object.freeze([
  "schemaVersion", "profileId", "label",
  "_needsConfirmation", "_genericDefaults", "_note",
  "deception", "loginBruteForce", "passwordResetAbuse", "priceTampering",
  "priceIntegrity", "businessLogic", "identity", "roleGated",
]);

const SECTION_KEYS = Object.freeze({
  deception: ["loginPath", "apiPathPrefixes", "plaintextBaitPaths", "frontendFlavor"],
  loginBruteForce: ["route", "emailField"],
  passwordResetAbuse: [
    "resetRoute", "resetEmailField", "securityQuestionRoute", "securityQuestionEmailField",
  ],
  priceTampering: ["quantityFields", "unitPriceFields", "totalFields", "amountTolerance"],
  priceIntegrity: [
    "listRoute", "itemRoute", "priceDropRatio", "idField", "priceField", "responseEnvelope",
  ],
  businessLogic: [
    "massAssignmentWhitelist", "alwaysSuspiciousFields",
    "suspiciousRoleValues", "numericFieldRules",
  ],
  identity: [
    "tokenSources", "claimMap", "learnedFallback", "routeRules", "bodyRules", "queryRules",
  ],
  roleGated: ["sensitiveRoutes"],
});

// targetSelection.js 의 TARGET_ID 와 같은 모양이어야 한다 — 대상 ID 가 곧 프로파일
// 파일명이기 때문이다. 일치는 defense/tests/test_site_profile_contract.py 가 강제한다.
const PROFILE_ID = /^[a-z][a-z0-9-]{0,31}$/;
// Defense site_profile.py 규칙 3 과 같은 토큰 규칙. 쿠키 이름이 RegExp 에 보간되므로
// (identityMismatch 의 쿠키 추출) 이 제한이 정규식 주입을 구조적으로 막는다.
const SIMPLE_TOKEN = /^[A-Za-z0-9._-]+$/;
// 탐지 태그는 blTags 에 실려 대시보드까지 간다. 콜론은 네임스페이스 구분자로 쓰이고
// (featureExtractor.js:104 이 "role-gated:" 접두어를 의미 있게 본다) 그 이상은 막는다.
const TAG = /^[a-z][a-z0-9-]*(?::[a-z0-9][a-z0-9-]*)+$/;
const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
const FRONTEND_FLAVORS = new Set(["angular-httpclient", "fetch"]);

class SiteProfileError extends Error {}

function fail(source, message) {
  throw new SiteProfileError(`site profile ${source}: ${message}`);
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function get(profile, featurePath) {
  return featurePath.split(".").reduce((node, key) => (isPlainObject(node) ? node[key] : undefined), profile);
}

/** Defense site_profile.py 규칙 1 과 같은 경로 규칙. */
function checkPath(source, where, value) {
  if (typeof value !== "string" || !value) fail(source, `${where} must be a non-empty string`);
  if (!value.startsWith("/")) fail(source, `${where} must be absolute: ${value}`);
  if (value.includes("//") || value.includes("\\") || /[\r\n]/.test(value)) {
    fail(source, `${where} must be canonical (no //, \\, CR or LF): ${value}`);
  }
  if (value.includes("?") || value.includes("#")) {
    fail(source, `${where} must not carry a query or fragment: ${value}`);
  }
  // requestMetadata.js 의 정규화 결과와 같은 자리표시자만 허용한다.
  const placeholders = value.match(/:[a-z]+/g) || [];
  for (const placeholder of placeholders) {
    if (placeholder !== ":id" && placeholder !== ":uuid") {
      fail(source, `${where} uses an unknown placeholder ${placeholder}: ${value}`);
    }
  }
  // numericIdFrom() 은 String.replace(':id', ...) 로 첫 항목만 치환한다 — 두 개면
  // 조용히 깨진 정규식이 만들어진다.
  if ((value.match(/:id/g) || []).length > 1) {
    fail(source, `${where} may carry at most one :id placeholder: ${value}`);
  }
}

function checkTag(source, where, value) {
  if (typeof value !== "string" || !TAG.test(value)) {
    fail(source, `${where} must look like "family:name": ${JSON.stringify(value)}`);
  }
}

function checkToken(source, where, value) {
  if (typeof value !== "string" || !SIMPLE_TOKEN.test(value)) {
    fail(source, `${where} must be a simple token [A-Za-z0-9._-]: ${JSON.stringify(value)}`);
  }
}

function checkTokenList(source, where, value, { allowEmpty = false } = {}) {
  if (!Array.isArray(value)) fail(source, `${where} must be an array`);
  if (!allowEmpty && !value.length) fail(source, `${where} must not be empty`);
  value.forEach((item, index) => checkToken(source, `${where}[${index}]`, item));
  const folded = value.map((item) => item.toLowerCase());
  if (new Set(folded).size !== folded.length) {
    fail(source, `${where} has duplicates after case folding`);
  }
}

function checkRoute(source, where, value) {
  if (!isPlainObject(value)) fail(source, `${where} must be an object`);
  checkKeys(source, where, value, ["method", "normalizedPath"]);
  if (!METHODS.has(value.method)) {
    fail(source, `${where}.method must be one of ${[...METHODS].join(", ")}: ${value.method}`);
  }
  checkPath(source, `${where}.normalizedPath`, value.normalizedPath);
}

function checkKeys(source, where, value, allowed) {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      fail(source, `unknown key ${where}.${key} (allowed: ${allowed.join(", ")})`);
    }
  }
}

function checkNumber(source, where, value, { min, max, exclusiveMin } = {}) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    fail(source, `${where} must be a finite number: ${JSON.stringify(value)}`);
  }
  if (exclusiveMin !== undefined && value <= exclusiveMin) {
    fail(source, `${where} must be greater than ${exclusiveMin}: ${value}`);
  }
  if (min !== undefined && value < min) fail(source, `${where} must be >= ${min}: ${value}`);
  if (max !== undefined && value > max) fail(source, `${where} must be <= ${max}: ${value}`);
}

const SECTION_VALIDATORS = {
  deception(source, section) {
    if (section.loginPath !== undefined) checkPath(source, "deception.loginPath", section.loginPath);
    if (section.apiPathPrefixes !== undefined) {
      if (!Array.isArray(section.apiPathPrefixes) || !section.apiPathPrefixes.length) {
        fail(source, "deception.apiPathPrefixes must be a non-empty array");
      }
      section.apiPathPrefixes.forEach((prefix, index) => {
        checkPath(source, `deception.apiPathPrefixes[${index}]`, prefix);
        // startsWith 로 비교하므로 세그먼트 경계를 뒤 슬래시가 만든다.
        if (!prefix.endsWith("/")) {
          fail(source, `deception.apiPathPrefixes[${index}] must end with /: ${prefix}`);
        }
      });
    }
    if (section.plaintextBaitPaths !== undefined) {
      if (!Array.isArray(section.plaintextBaitPaths)) {
        fail(source, "deception.plaintextBaitPaths must be an array");
      }
      section.plaintextBaitPaths.forEach((p, i) =>
        checkPath(source, `deception.plaintextBaitPaths[${i}]`, p));
    }
    if (section.frontendFlavor !== undefined && !FRONTEND_FLAVORS.has(section.frontendFlavor)) {
      fail(source, `deception.frontendFlavor must be one of ${[...FRONTEND_FLAVORS].join(", ")}: ${section.frontendFlavor}`);
    }
  },

  loginBruteForce(source, section) {
    checkRoute(source, "loginBruteForce.route", section.route);
    checkToken(source, "loginBruteForce.emailField", section.emailField);
  },

  passwordResetAbuse(source, section) {
    // 두 반쪽이 독립이다 — RUBY 에는 보안질문 라우트가 아예 없다.
    if (!section.resetRoute && !section.securityQuestionRoute) {
      fail(source, "passwordResetAbuse must declare resetRoute or securityQuestionRoute");
    }
    if (section.resetRoute !== undefined) {
      checkRoute(source, "passwordResetAbuse.resetRoute", section.resetRoute);
      checkToken(source, "passwordResetAbuse.resetEmailField", section.resetEmailField);
    }
    if (section.securityQuestionRoute !== undefined) {
      checkRoute(source, "passwordResetAbuse.securityQuestionRoute", section.securityQuestionRoute);
      checkToken(source, "passwordResetAbuse.securityQuestionEmailField",
        section.securityQuestionEmailField);
    }
  },

  priceTampering(source, section) {
    checkKeys(source, "priceTampering", section, SECTION_KEYS.priceTampering);
    for (const key of ["quantityFields", "unitPriceFields", "totalFields"]) {
      checkTokenList(source, `priceTampering.${key}`, section[key]);
    }
    checkNumber(source, "priceTampering.amountTolerance", section.amountTolerance,
      { exclusiveMin: 0 });
  },

  priceIntegrity(source, section) {
    checkKeys(source, "priceIntegrity", section, SECTION_KEYS.priceIntegrity);
    checkPath(source, "priceIntegrity.listRoute", section.listRoute);
    checkPath(source, "priceIntegrity.itemRoute", section.itemRoute);
    checkNumber(source, "priceIntegrity.priceDropRatio", section.priceDropRatio,
      { exclusiveMin: 0, max: 1 });
    checkToken(source, "priceIntegrity.idField", section.idField);
    checkToken(source, "priceIntegrity.priceField", section.priceField);
    const envelope = section.responseEnvelope;
    if (!isPlainObject(envelope)) fail(source, "priceIntegrity.responseEnvelope must be an object");
    checkKeys(source, "priceIntegrity.responseEnvelope", envelope,
      ["itemsKey", "bareObjectHasField"]);
    // "" 는 "본문 자체가 배열/객체" 를 뜻한다.
    if (typeof envelope.itemsKey !== "string") {
      fail(source, "priceIntegrity.responseEnvelope.itemsKey must be a string");
    }
    if (envelope.itemsKey) checkToken(source, "priceIntegrity.responseEnvelope.itemsKey", envelope.itemsKey);
    checkToken(source, "priceIntegrity.responseEnvelope.bareObjectHasField",
      envelope.bareObjectHasField);
  },

  businessLogic(source, section) {
    checkKeys(source, "businessLogic", section, SECTION_KEYS.businessLogic);
    if (section.massAssignmentWhitelist !== undefined) {
      const list = section.massAssignmentWhitelist;
      if (!Array.isArray(list)) fail(source, "businessLogic.massAssignmentWhitelist must be an array");
      const seen = new Set();
      list.forEach((entry, index) => {
        const where = `businessLogic.massAssignmentWhitelist[${index}]`;
        if (!isPlainObject(entry)) fail(source, `${where} must be an object`);
        checkKeys(source, where, entry, ["route", "fields"]);
        if (typeof entry.route !== "string") fail(source, `${where}.route must be a string`);
        const parts = entry.route.split(" ");
        if (parts.length !== 2) fail(source, `${where}.route must look like "METHOD /path": ${entry.route}`);
        if (!METHODS.has(parts[0])) fail(source, `${where}.route has an unknown method: ${parts[0]}`);
        checkPath(source, `${where}.route path`, parts[1]);
        // whitelistKey() 가 뒤 슬래시를 떼고 조회하므로 원본도 떼어 둬야 키가 맞는다.
        if (parts[1].length > 1 && parts[1].endsWith("/")) {
          fail(source, `${where}.route must not end with a slash: ${entry.route}`);
        }
        if (seen.has(entry.route)) fail(source, `${where}.route is declared twice: ${entry.route}`);
        seen.add(entry.route);
        checkTokenList(source, `${where}.fields`, entry.fields, { allowEmpty: true });
      });
    }
    if (section.alwaysSuspiciousFields !== undefined) {
      checkTokenList(source, "businessLogic.alwaysSuspiciousFields", section.alwaysSuspiciousFields);
    }
    if (section.suspiciousRoleValues !== undefined) {
      checkTokenList(source, "businessLogic.suspiciousRoleValues", section.suspiciousRoleValues);
    }
    if (section.numericFieldRules !== undefined) {
      const rules = section.numericFieldRules;
      if (!Array.isArray(rules)) fail(source, "businessLogic.numericFieldRules must be an array");
      rules.forEach((rule, index) => {
        const where = `businessLogic.numericFieldRules[${index}]`;
        if (!isPlainObject(rule)) fail(source, `${where} must be an object`);
        checkKeys(source, where, rule, ["field", "min", "max"]);
        checkToken(source, `${where}.field`, rule.field);
        if (rule.min === undefined && rule.max === undefined) {
          fail(source, `${where} must declare min or max`);
        }
        if (rule.min !== undefined) checkNumber(source, `${where}.min`, rule.min);
        if (rule.max !== undefined) checkNumber(source, `${where}.max`, rule.max);
        if (rule.min !== undefined && rule.max !== undefined && rule.min > rule.max) {
          fail(source, `${where}.min must be <= max`);
        }
      });
    }
  },

  identity(source, section) {
    checkKeys(source, "identity", section, SECTION_KEYS.identity);
    if (section.tokenSources !== undefined) {
      const sources = section.tokenSources;
      if (!isPlainObject(sources)) fail(source, "identity.tokenSources must be an object");
      checkKeys(source, "identity.tokenSources", sources, ["bearer", "cookieNames"]);
      if (typeof sources.bearer !== "boolean") {
        fail(source, "identity.tokenSources.bearer must be a boolean");
      }
      checkTokenList(source, "identity.tokenSources.cookieNames", sources.cookieNames,
        { allowEmpty: true });
      if (!sources.bearer && !sources.cookieNames.length) {
        fail(source, "identity.tokenSources must declare bearer or at least one cookie");
      }
    }
    if (section.claimMap !== undefined) {
      const claims = section.claimMap;
      if (!isPlainObject(claims)) fail(source, "identity.claimMap must be an object");
      checkKeys(source, "identity.claimMap", claims,
        ["wrapperKey", "id", "email", "role", "basketId"]);
      // "" 는 "래퍼 없음" 을 뜻한다.
      if (typeof claims.wrapperKey !== "string") {
        fail(source, "identity.claimMap.wrapperKey must be a string");
      }
      if (claims.wrapperKey) checkToken(source, "identity.claimMap.wrapperKey", claims.wrapperKey);
      for (const key of ["id", "email", "role"]) {
        checkToken(source, `identity.claimMap.${key}`, claims[key]);
      }
      if (claims.basketId !== undefined) {
        if (!isPlainObject(claims.basketId)) fail(source, "identity.claimMap.basketId must be an object");
        checkKeys(source, "identity.claimMap.basketId", claims.basketId, ["at", "key"]);
        if (!["root", "wrapper"].includes(claims.basketId.at)) {
          fail(source, `identity.claimMap.basketId.at must be root or wrapper: ${claims.basketId.at}`);
        }
        checkToken(source, "identity.claimMap.basketId.key", claims.basketId.key);
      }
    }
    if (section.learnedFallback !== undefined && typeof section.learnedFallback !== "boolean") {
      fail(source, "identity.learnedFallback must be a boolean");
    }
    if (section.routeRules !== undefined) {
      checkRuleList(source, "identity.routeRules", section.routeRules,
        ["tag", "normalizedPath", "claimField"]);
    }
    for (const key of ["bodyRules", "queryRules"]) {
      if (section[key] !== undefined) {
        checkRuleList(source, `identity.${key}`, section[key],
          ["tag", "method", "normalizedPath", "field", "claimField"]);
      }
    }
  },

  roleGated(source, section) {
    checkKeys(source, "roleGated", section, SECTION_KEYS.roleGated);
    const routes = section.sensitiveRoutes;
    if (!Array.isArray(routes) || !routes.length) {
      fail(source, "roleGated.sensitiveRoutes must be a non-empty array");
    }
    const tags = new Set();
    routes.forEach((entry, index) => {
      const where = `roleGated.sensitiveRoutes[${index}]`;
      if (!isPlainObject(entry)) fail(source, `${where} must be an object`);
      checkKeys(source, where, entry, ["tag", "method", "normalizedPath", "requiredRoles"]);
      checkTag(source, `${where}.tag`, entry.tag);
      if (tags.has(entry.tag)) fail(source, `${where}.tag is declared twice: ${entry.tag}`);
      tags.add(entry.tag);
      checkRoute(source, where, { method: entry.method, normalizedPath: entry.normalizedPath });
      checkTokenList(source, `${where}.requiredRoles`, entry.requiredRoles);
      // roleGatedAccess.js 가 claimed.role 을 소문자로 비교하므로 선언도 소문자여야 한다.
      for (const role of entry.requiredRoles) {
        if (role !== role.toLowerCase()) {
          fail(source, `${where}.requiredRoles must be lower case: ${role}`);
        }
      }
    });
  },
};

function checkRuleList(source, where, value, allowed) {
  if (!Array.isArray(value)) fail(source, `${where} must be an array`);
  const tags = new Set();
  value.forEach((rule, index) => {
    const at = `${where}[${index}]`;
    if (!isPlainObject(rule)) fail(source, `${at} must be an object`);
    checkKeys(source, at, rule, allowed);
    for (const key of allowed) {
      if (rule[key] === undefined) fail(source, `${at}.${key} is required`);
    }
    checkTag(source, `${at}.tag`, rule.tag);
    if (tags.has(rule.tag)) fail(source, `${at}.tag is declared twice: ${rule.tag}`);
    tags.add(rule.tag);
    checkPath(source, `${at}.normalizedPath`, rule.normalizedPath);
    if (rule.method !== undefined && !METHODS.has(rule.method)) {
      fail(source, `${at}.method must be a known method: ${rule.method}`);
    }
    if (rule.field !== undefined) checkToken(source, `${at}.field`, rule.field);
    checkToken(source, `${at}.claimField`, rule.claimField);
  });
}

/**
 * 프로파일 문서 하나를 검증한다. 실패하면 SiteProfileError 를 던진다.
 * `source` 는 오류 메시지에 들어가는 파일 이름이다.
 */
function validateSiteProfile(data, { source = "<inline>", expectedProfileId = null } = {}) {
  if (!isPlainObject(data)) fail(source, "must be a JSON object");
  checkKeys(source, "", data, TOP_LEVEL_KEYS);

  if (data.schemaVersion !== 1) fail(source, `schemaVersion must be 1: ${data.schemaVersion}`);
  if (typeof data.profileId !== "string" || !PROFILE_ID.test(data.profileId)) {
    fail(source, `profileId must match ${PROFILE_ID}: ${JSON.stringify(data.profileId)}`);
  }
  if (expectedProfileId && data.profileId !== expectedProfileId) {
    fail(source, `profileId ${data.profileId} does not match the file name ${expectedProfileId}`);
  }
  if (typeof data.label !== "string" || !data.label.trim() || /[\r\n]/.test(data.label)) {
    fail(source, "label must be a non-empty single-line string");
  }

  for (const [name, validate] of Object.entries(SECTION_VALIDATORS)) {
    if (data[name] === undefined) continue;
    if (!isPlainObject(data[name])) fail(source, `${name} must be an object`);
    checkKeys(source, name, data[name], SECTION_KEYS[name]);
    validate(source, data[name]);
  }

  // 없는 기능은 전부 _needsConfirmation 에 적혀 있어야 하고, 적힌 것은 전부 실제
  // 기능 경로여야 한다. "일부러 미설정" 과 "빠뜨림" 을 구별하는 값싼 불변식이고,
  // 비활성 보고의 reason 이 여기서 나온다.
  const declared = new Set(data._needsConfirmation || []);
  const genericDefaults = new Set(data._genericDefaults || []);
  for (const path of [...declared, ...genericDefaults]) {
    if (!FEATURE_PATHS.includes(path)) {
      fail(source, `_needsConfirmation/_genericDefaults names an unknown feature: ${path}`);
    }
  }
  const absent = FEATURE_PATHS.filter((path) => get(data, path) === undefined);
  for (const path of absent) {
    if (!declared.has(path)) {
      fail(source, `${path} is absent but not listed in _needsConfirmation`);
    }
  }
  for (const path of declared) {
    if (get(data, path) !== undefined) {
      fail(source, `_needsConfirmation lists ${path} but the profile declares it`);
    }
  }
  for (const path of genericDefaults) {
    if (get(data, path) === undefined) {
      fail(source, `_genericDefaults lists ${path} but the profile does not declare it`);
    }
  }

  return Object.freeze({
    ...data,
    disabledFeatures: Object.freeze(absent),
    genericDefaultFeatures: Object.freeze([...genericDefaults]),
  });
}

/** 파일 하나를 읽어 검증한다. JSON 구문 오류도 파일 이름과 함께 던진다. */
function loadSiteProfile(filePath) {
  const resolved = nodePath.resolve(filePath);
  const name = nodePath.basename(resolved);
  let raw;
  try {
    raw = fs.readFileSync(resolved, "utf8");
  } catch (error) {
    throw new SiteProfileError(`site profile ${name}: cannot be read (${error.code || error.message})`);
  }
  let data;
  try {
    data = JSON.parse(raw);
  } catch (error) {
    throw new SiteProfileError(`site profile ${name}: is not valid JSON (${error.message})`);
  }
  return validateSiteProfile(data, { source: name, expectedProfileId: name.replace(/\.json$/, "") });
}

module.exports = {
  FEATURE_PATHS,
  PROFILE_ID,
  SiteProfileError,
  loadSiteProfile,
  validateSiteProfile,
};
