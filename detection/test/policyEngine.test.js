const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  DEFAULT_CONFIG_PATH,
  applyDefensePlan,
  clampScore,
  loadPolicyRules,
  selectStrategies,
} = require("../lib/policyEngine");

const EPS = 1e-9;

// ---------------------------------------------------------------------------
// policy.json을 엔진과 별개로 직접 읽어서 기대값(oracle)을 만든다.
// (엔진의 loadPolicyRules 결과로 기대값을 만들면 동어반복이 되므로 raw JSON 사용)
// ---------------------------------------------------------------------------
const CONFIG_PATH = path.resolve(process.env.POLICY_CONFIG_PATH || DEFAULT_CONFIG_PATH);
const rawRules = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8")).defense.rules;

// 규칙 구간은 [min_score, max_score) 반개구간, 겹치면 먼저 나온 규칙이 우선
function expectedStrategies(score, confirmedAttackScore = 0) {
  const rule = rawRules.find((r) => r.min_score <= score && score < r.max_score &&
    confirmedAttackScore >= (r.min_confirmed_attack_score || 0));
  return rule ? rule.strategies : [];
}

// 각 규칙의 경계값 주변 + 중간값 + 0/0.5/1 을 샘플링
function samplePoints(ruleList) {
  const points = new Set([0, 0.5, 1]);
  for (const { min_score, max_score } of ruleList) {
    const mid = min_score + (max_score - min_score) / 2;
    [min_score - EPS, min_score, mid, max_score - EPS, max_score].forEach((p) => points.add(p));
  }
  return [...points]
    .filter((p) => Number.isFinite(p) && p >= 0 && p <= 1)
    .sort((a, b) => a - b);
}

function createProxyReq(initialHeaders = {}) {
  const headers = new Map(
    Object.entries(initialHeaders).map(([k, v]) => [k.toLowerCase(), v])
  );
  return {
    headers,
    removeHeader(name) {
      headers.delete(name.toLowerCase());
    },
    setHeader(name, value) {
      headers.set(name.toLowerCase(), value);
    },
  };
}

// ---------------------------------------------------------------------------
// loadPolicyRules: policy.json 내용이 그대로 로드되는지
// ---------------------------------------------------------------------------
test("loadPolicyRules는 policy.json의 모든 규칙을 순서대로 로드한다", () => {
  const rules = loadPolicyRules(CONFIG_PATH);

  assert.equal(rules.length, rawRules.length);
  rules.forEach((rule, i) => {
    assert.equal(rule.minScore, rawRules[i].min_score, `rule ${i} minScore`);
    assert.equal(rule.maxScore, rawRules[i].max_score, `rule ${i} maxScore`);
    assert.equal(rule.minConfirmedAttackScore, rawRules[i].min_confirmed_attack_score || 0);
    assert.deepEqual(rule.strategies, rawRules[i].strategies, `rule ${i} strategies`);
  });
});

// ---------------------------------------------------------------------------
// selectStrategies: 규칙마다 테스트를 동적으로 생성
// ---------------------------------------------------------------------------
const rules = loadPolicyRules(CONFIG_PATH);

rawRules.forEach((rule, i) => {
  const { min_score: min, max_score: max } = rule;
  const label = `rule ${i} [${min}, ${max})`;

  test(`${label}: 하한은 포함하고 상한은 제외한다`, () => {
    if (min >= 0 && min <= 1) {
      assert.deepEqual(selectStrategies(min, rules), expectedStrategies(min), `score=${min}`);
    }
    if (max >= 0 && max <= 1) {
      assert.deepEqual(selectStrategies(max, rules), expectedStrategies(max), `score=${max}`);
    }
    const belowMax = max - EPS;
    if (belowMax >= 0 && belowMax <= 1) {
      assert.deepEqual(
        selectStrategies(belowMax, rules),
        expectedStrategies(belowMax),
        `score=${belowMax}`
      );
    }
  });

  test(`${label}: 구간 중간값은 해당 규칙의 전략을 반환한다`, () => {
    const mid = min + (max - min) / 2;
    if (mid < 0 || mid > 1) return;
    assert.deepEqual(selectStrategies(mid, rules), expectedStrategies(mid), `score=${mid}`);
  });
});

test("모든 샘플 점수에서 policy.json 기준 기대값과 일치한다 (규칙 공백·겹침 포함)", () => {
  for (const score of samplePoints(rawRules)) {
    assert.deepEqual(selectStrategies(score, rules), expectedStrategies(score), `score=${score}`);
  }
});

test("어느 규칙에도 속하지 않는 점수는 빈 배열을 반환한다", () => {
  const uncovered = samplePoints(rawRules).filter(
    (p) => !rawRules.some((r) => r.min_score <= p && p < r.max_score)
  );
  for (const score of uncovered) {
    assert.deepEqual(selectStrategies(score, rules), [], `score=${score}`);
  }
});

test("점수는 0~1 범위로 보정된 뒤 규칙에 적용된다", () => {
  assert.equal(clampScore(-5), 0);
  assert.equal(clampScore(5), 1);
  assert.equal(clampScore("abc"), 0);
  assert.equal(clampScore(NaN), 0);

  assert.deepEqual(selectStrategies(-5, rules), expectedStrategies(0));
  assert.deepEqual(selectStrategies(5, rules), expectedStrategies(1));
  assert.deepEqual(selectStrategies(NaN, rules), expectedStrategies(0));
});

// ---------------------------------------------------------------------------
// applyDefensePlan: 헤더가 정책 결과로 교체되는지
// ---------------------------------------------------------------------------
test("클라이언트의 Defense plan을 제거하고 policy.json 결과로 교체한다", () => {
  for (const riskScore of samplePoints(rawRules)) {
    const proxyReq = createProxyReq({ "x-defense-plan": '[{"name":"bypass"}]' });

    applyDefensePlan(proxyReq, { riskScore, rules });

    assert.equal(
      proxyReq.headers.get("x-defense-plan"),
      JSON.stringify(expectedStrategies(riskScore)),
      `riskScore=${riskScore}`
    );
    assert.equal(proxyReq.headers.get("accept-encoding"), "identity");
  }
});

test("확정 공격 점수와 위험 점수가 모두 0.8 이상일 때만 제한과 범용 미끼를 적용하며 기본 지연은 없다", () => {
  const names = (riskScore, confirmedAttackScore = 0) => selectStrategies(
    riskScore, rules, { confirmedAttackScore }
  ).map((step) => step.name);

  assert.deepEqual(names(0.9), []);
  assert.deepEqual(names(0.9, 0.799), []);
  assert.deepEqual(names(0.799, 0.9), []);
  for (const riskScore of [0, 0.2, 0.5, 0.8, 1]) {
    assert.deepEqual(names(riskScore, 0.799), [], `riskScore=${riskScore}`);
  }
  assert.deepEqual(names(0.8, 0.8), ["rate_limit_strict", "decoy_maze"]);
  assert.deepEqual(names(1, 1), ["rate_limit_strict", "decoy_maze"]);
  assert.deepEqual(names(0.4, 0.9), []);
  assert.deepEqual(names(0.1, 0.9), []);
});

test("확정된 고위험 플랜은 요청 제한과 미끼만 전달한다", () => {
  const proxyReq = createProxyReq({ "x-defense-plan": '[{"name":"bypass"}]' });
  const plan = applyDefensePlan(proxyReq, {
    riskScore: 0.8,
    confirmedAttackScore: 0.8,
    rules,
  });

  assert.deepEqual(plan, [
    { name: "rate_limit_strict", params: { max_rps: 1 } },
    { name: "decoy_maze", params: {} },
  ]);
  assert.equal(proxyReq.headers.get("x-defense-plan"), JSON.stringify(plan));
});

// ---------------------------------------------------------------------------
// loadPolicyRules: 잘못된 설정 검증 (임시 설정 파일 사용)
// ---------------------------------------------------------------------------
function withTempConfig(content, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "policy-test-"));
  const file = path.join(dir, "policy.json");
  fs.writeFileSync(file, JSON.stringify(content));
  try {
    return fn(file);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test("defense.rules가 없으면 로드에 실패한다", () => {
  withTempConfig({ defense: {} }, (file) => {
    assert.throws(() => loadPolicyRules(file), /must contain defense\.rules/);
  });
});

test("min_score가 max_score보다 크면 로드에 실패한다", () => {
  withTempConfig(
    { defense: { rules: [{ min_score: 0.8, max_score: 0.2, strategies: [] }] } },
    (file) => {
      assert.throws(() => loadPolicyRules(file), /invalid score range/);
    }
  );
});

test("strategies가 배열이 아니면 로드에 실패한다", () => {
  withTempConfig(
    { defense: { rules: [{ min_score: 0, max_score: 1, strategies: "x" }] } },
    (file) => {
      assert.throws(() => loadPolicyRules(file), /strategies array/);
    }
  );
});
