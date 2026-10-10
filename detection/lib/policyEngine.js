const fs = require("fs");
const path = require("path");

const DEFAULT_CONFIG_PATH = path.join(__dirname, "..", "config", "policy.json");
// 단계 이름은 내부 헤더(X-Ruby-Defense-Tier)로 넘어가므로 짧은 식별자만 허용한다.
const TIER_PATTERN = /^[a-z][a-z0-9_-]{0,31}$/;

function clampScore(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  return Math.max(0, Math.min(1, numeric));
}

function loadPolicyRules(configPath = process.env.POLICY_CONFIG_PATH || DEFAULT_CONFIG_PATH) {
  const resolvedPath = path.resolve(configPath);
  const config = JSON.parse(fs.readFileSync(resolvedPath, "utf8"));
  const rules = config?.defense?.rules;
  if (!Array.isArray(rules)) {
    throw new Error(`policy config at ${resolvedPath} must contain defense.rules`);
  }

  return rules.map((rule, index) => {
    const minScore = Number(rule?.min_score);
    const maxScore = Number(rule?.max_score);
    if (!Number.isFinite(minScore) || !Number.isFinite(maxScore) || minScore > maxScore) {
      throw new Error(`policy rule ${index} has an invalid score range`);
    }
    if (!Array.isArray(rule.strategies)) {
      throw new Error(`policy rule ${index} must contain a strategies array`);
    }
    const minConfirmedAttackScore = rule.min_confirmed_attack_score === undefined
      ? 0 : Number(rule.min_confirmed_attack_score);
    if (!Number.isFinite(minConfirmedAttackScore) || minConfirmedAttackScore < 0 || minConfirmedAttackScore > 1) {
      throw new Error(`policy rule ${index} has an invalid confirmed attack threshold`);
    }
    const maxConfirmedAttackScore = rule.max_confirmed_attack_score === undefined
      ? 1.01 : Number(rule.max_confirmed_attack_score);
    if (!Number.isFinite(maxConfirmedAttackScore) || maxConfirmedAttackScore <= minConfirmedAttackScore ||
        maxConfirmedAttackScore > 1.01) {
      throw new Error(`policy rule ${index} has an invalid confirmed attack ceiling`);
    }
    if (rule.tier !== undefined && (typeof rule.tier !== "string" || !TIER_PATTERN.test(rule.tier))) {
      throw new Error(`policy rule ${index} has an invalid tier name`);
    }
    return { tier: rule.tier || null, minScore, maxScore,
      minConfirmedAttackScore, maxConfirmedAttackScore,
      strategies: rule.strategies };
  });
}

function readPointTable(table, label, knownSignals) {
  if (table === undefined) return undefined;
  if (table === null || typeof table !== "object" || Array.isArray(table)) {
    throw new Error(`deception ${label} points must be an object`);
  }
  for (const [signal, points] of Object.entries(table)) {
    if (knownSignals && !knownSignals.has(signal)) {
      throw new Error(`deception ${label} points name an unknown signal: ${signal}`);
    }
    const numeric = Number(points);
    if (!Number.isFinite(numeric) || numeric < 0) {
      throw new Error(`deception ${label} points for ${signal} must be a nonnegative number`);
    }
  }
  return table;
}

function readMaximum(value, label) {
  if (value === undefined) return undefined;
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    throw new Error(`deception ${label} maximum must be a positive number`);
  }
  return numeric;
}

/**
 * 미끼 신호 배점 덮어쓰기. policy.json 에 detection.deception.points 가 없으면
 * 빈 객체를 돌려주고 classifier 는 코드 기본값을 그대로 쓴다. knownSignals 를 주면
 * 오타를 조용히 무시하지 않고 거부한다.
 */
function loadDeceptionPoints(
  configPath = process.env.POLICY_CONFIG_PATH || DEFAULT_CONFIG_PATH,
  { knownSignals } = {}
) {
  const resolvedPath = path.resolve(configPath);
  const config = JSON.parse(fs.readFileSync(resolvedPath, "utf8"));
  const points = config?.detection?.deception?.points;
  if (points === undefined) return {};
  if (points === null || typeof points !== "object" || Array.isArray(points)) {
    throw new Error(`detection.deception.points at ${resolvedPath} must be an object`);
  }
  const known = knownSignals ? new Set(knownSignals) : null;
  const override = {
    automationPoints: readPointTable(points.automation, "automation", known),
    attackPoints: readPointTable(points.attack, "attack", known),
    automationMaxPoints: readMaximum(points.automationMax, "automation"),
    attackMaxPoints: readMaximum(points.attackMax, "attack"),
  };
  return Object.fromEntries(
    Object.entries(override).filter(([, value]) => value !== undefined)
  );
}

/**
 * 규칙은 위에서부터 처음 맞는 하나만 고른다. 단계(tier)는 "얼마나 확실한 근거인가"를
 * 나타내고, 각 단계에 어떤 전략을 붙일지는 policy.json에서만 정한다. 새 방어 전략은
 * 점수 코드를 바꾸지 않고 해당 단계의 strategies에 추가하면 된다.
 */
function selectRule(riskScore, rules, { confirmedAttackScore = 0 } = {}) {
  const score = clampScore(riskScore);
  const confirmed = clampScore(confirmedAttackScore);
  return rules.find(({ minScore, maxScore, minConfirmedAttackScore = 0,
    maxConfirmedAttackScore = 1.01 }) =>
    minScore <= score && score < maxScore &&
    minConfirmedAttackScore <= confirmed && confirmed < maxConfirmedAttackScore) || null;
}

function selectStrategies(riskScore, rules, options) {
  return selectRule(riskScore, rules, options)?.strategies || [];
}

function applyDefenseRule(proxyReq, { riskScore, confirmedAttackScore = 0, rules }) {
  proxyReq.removeHeader("x-defense-plan");
  proxyReq.removeHeader("x-ruby-defense-tier");
  const rule = selectRule(riskScore, rules, { confirmedAttackScore });
  const plan = rule?.strategies || [];
  proxyReq.setHeader("X-Defense-Plan", JSON.stringify(plan));
  if (rule?.tier) proxyReq.setHeader("X-Ruby-Defense-Tier", rule.tier);
  // The response interceptor operates on uncompressed response bodies.
  proxyReq.setHeader("Accept-Encoding", "identity");
  return { plan, tier: rule?.tier || null };
}

function applyDefensePlan(proxyReq, options) {
  return applyDefenseRule(proxyReq, options).plan;
}

module.exports = {
  DEFAULT_CONFIG_PATH,
  applyDefensePlan,
  applyDefenseRule,
  clampScore,
  loadDeceptionPoints,
  loadPolicyRules,
  selectRule,
  selectStrategies,
};
