const fs = require("fs");
const path = require("path");

const DEFAULT_CONFIG_PATH = path.join(__dirname, "..", "config", "policy.json");

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
    return { minScore, maxScore, minConfirmedAttackScore, strategies: rule.strategies };
  });
}

function selectStrategies(riskScore, rules, { confirmedAttackScore = 0 } = {}) {
  const score = clampScore(riskScore);
  const confirmed = clampScore(confirmedAttackScore);
  const rule = rules.find(({ minScore, maxScore, minConfirmedAttackScore = 0 }) =>
    minScore <= score && score < maxScore && confirmed >= minConfirmedAttackScore);
  return rule ? rule.strategies : [];
}

function applyDefensePlan(proxyReq, { riskScore, confirmedAttackScore = 0, rules }) {
  proxyReq.removeHeader("x-defense-plan");
  const plan = selectStrategies(riskScore, rules, { confirmedAttackScore });
  proxyReq.setHeader("X-Defense-Plan", JSON.stringify(plan));
  // The response interceptor operates on uncompressed response bodies.
  proxyReq.setHeader("Accept-Encoding", "identity");
  return plan;
}

module.exports = {
  DEFAULT_CONFIG_PATH,
  applyDefensePlan,
  clampScore,
  loadPolicyRules,
  selectStrategies,
};
