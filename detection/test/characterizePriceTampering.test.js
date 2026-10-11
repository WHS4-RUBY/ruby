const assert = require("node:assert/strict");
const { test } = require("node:test");

const path = require("node:path");

const {
  detectPriceTampering: detect,
  findAmountMismatches: findMismatches,
} = require("../lib/priceTampering");
const { loadSiteProfile } = require("../lib/siteProfile");

const profileAt = (id) =>
  loadSiteProfile(path.join(__dirname, "..", "config", "site-profiles", `${id}.json`));

// juice-shop 프로파일을 주입하면 아래 단정은 한 글자도 바뀌지 않고 통과해야 한다.
const JUICE_PROFILE = profileAt("juice-shop");
const detectPriceTampering = (body) => detect(body, JUICE_PROFILE);
const findAmountMismatches = (node, pathPrefix, acc) =>
  findMismatches(node, JUICE_PROFILE.priceTampering, pathPrefix, acc);

/**
 * priceTampering.js 의 특성화 테스트.
 *
 * **이 모듈에는 라우트 게이트가 없다.** server.js:392 가 `detectPriceTampering(req.body)`
 * 를 모든 요청 본문에 무조건 호출하므로 모든 대상에서 상시 동작한다. 모듈 주석은
 * 이 프로젝트 실측 트래픽에서 발동한 사례가 아직 없다고 적고 있다 — 즉 도달 가능하지만
 * 한 번도 맞은 적 없는 코드다. 그래서 회귀를 실측으로 잡을 수 없고 합성 입력에
 * 의존한다. 경계값을 촘촘히 고정하는 이유다.
 *
 * 프로파일화 뒤에도 **라우트 게이트를 추가하지 않는다** — 추가하면 동작 변경이다.
 * 필드명·허용 오차만 프로파일에서 읽는다. 그리고 지금 모든 대상에서 도는 기능이므로
 * generic 프로파일에도 같은 값이 들어간다(그래서 매핑 없는 대상의 동작이 보존된다).
 */

test("특성화: 같은 객체 레벨에 세 필드가 다 있을 때만 총액을 검산한다", () => {
  // 맞으면 hit 없음.
  assert.deepEqual(detectPriceTampering({ quantity: 2, price: 10, total: 20 }),
    { hit: false, mismatches: [] });

  // 틀리면 hit. 경로는 루트에서 "(root)" 다.
  const bad = detectPriceTampering({ quantity: 2, price: 10, total: 5 });
  assert.equal(bad.hit, true);
  assert.deepEqual(bad.mismatches, [
    { path: "(root)", quantity: 2, price: 10, total: 5, expected: 20 },
  ]);

  // 세 필드 중 하나라도 없으면 검산하지 않는다.
  for (const body of [
    { quantity: 2, price: 10 },
    { quantity: 2, total: 5 },
    { price: 10, total: 5 },
    { quantity: 2 },
    {},
  ]) {
    assert.equal(detectPriceTampering(body).hit, false, `${JSON.stringify(body)} 가 잡혔다`);
  }
});

test("특성화: 필드명 별칭을 전부 인정한다", () => {
  // quantity / qty
  assert.equal(detectPriceTampering({ qty: 2, price: 10, total: 5 }).hit, true);
  // price / unitprice / itemprice
  for (const key of ["price", "unitPrice", "itemPrice"]) {
    assert.equal(detectPriceTampering({ quantity: 2, [key]: 10, total: 5 }).hit, true,
      `단가 별칭 ${key} 를 인정하지 않았다`);
  }
  // totalprice / total / amount / ordertotal / linetotal
  for (const key of ["totalPrice", "total", "amount", "orderTotal", "lineTotal"]) {
    assert.equal(detectPriceTampering({ quantity: 2, price: 10, [key]: 5 }).hit, true,
      `총액 별칭 ${key} 를 인정하지 않았다`);
  }
  // 별칭 비교는 소문자로 한다 — 원본 대소문자는 무관하다.
  assert.equal(detectPriceTampering({ QUANTITY: 2, PRICE: 10, TOTAL: 5 }).hit, true);
});

// findKey 는 Object.keys 순서로 **첫 번째** 일치 키를 고른다. 같은 역할의 키가 둘
// 있으면 선언 순서가 결과를 정한다.
test("특성화: 같은 역할의 키가 둘이면 선언 순서상 첫 번째를 쓴다", () => {
  const result = detectPriceTampering({ Quantity: 3, qty: 99, price: 10, total: 30 });
  assert.equal(result.hit, false, "Quantity(3) 를 썼다면 3*10=30 으로 맞는다");

  const flipped = detectPriceTampering({ qty: 99, Quantity: 3, price: 10, total: 30 });
  assert.equal(flipped.hit, true, "qty(99) 를 썼다면 99*10 != 30 이다");
});

// 1센트 허용 오차. 경계값은 **포함되지 않는다**(Math.abs(...) > 0.01 이므로 정확히
// 0.01 차이는 hit 이 아니다).
test("특성화: 허용 오차 경계값은 hit 이 아니다", () => {
  assert.equal(detectPriceTampering({ quantity: 1, price: 10, total: 10.01 }).hit, false);
  assert.equal(detectPriceTampering({ quantity: 1, price: 10, total: 9.99 }).hit, false);
  assert.equal(detectPriceTampering({ quantity: 1, price: 10, total: 10.011 }).hit, true);
  assert.equal(detectPriceTampering({ quantity: 1, price: 10, total: 9.989 }).hit, true);
});

test("특성화: 숫자가 아니거나 유한수가 아니면 검산하지 않는다", () => {
  for (const body of [
    { quantity: "2", price: 10, total: 5 },
    { quantity: 2, price: "10", total: 5 },
    { quantity: 2, price: 10, total: "5" },
    { quantity: Number.NaN, price: 10, total: 5 },
    { quantity: Number.POSITIVE_INFINITY, price: 10, total: 5 },
    { quantity: 2, price: 10, total: Number.NaN },
    { quantity: null, price: 10, total: 5 },
  ]) {
    assert.equal(detectPriceTampering(body).hit, false, `${JSON.stringify(body)} 가 잡혔다`);
  }
});

test("특성화: 중첩 객체와 배열을 재귀로 훑고 경로를 적는다", () => {
  const nested = detectPriceTampering({
    order: { items: [{ quantity: 2, price: 10, total: 5 }] },
  });
  assert.equal(nested.hit, true);
  assert.equal(nested.mismatches[0].path, "order.items[0]");

  const topArray = detectPriceTampering([{ quantity: 2, price: 10, total: 5 }]);
  assert.equal(topArray.hit, true);
  assert.equal(topArray.mismatches[0].path, "[0]");

  // 여러 건이면 전부 모은다.
  const many = detectPriceTampering({
    a: { quantity: 2, price: 10, total: 5 },
    b: { quantity: 3, price: 10, total: 7 },
  });
  assert.equal(many.mismatches.length, 2);
  assert.deepEqual(many.mismatches.map((m) => m.path), ["a", "b"]);
});

// 어떤 객체가 스스로 hit 이면서 자식으로도 내려간다 — 같은 노드가 두 번 방문되는
// 것은 아니지만, 부모와 자식이 각각 따로 잡힐 수 있다.
test("특성화: 부모와 자식이 각각 따로 잡힌다", () => {
  const result = detectPriceTampering({
    quantity: 2, price: 10, total: 5,
    line: { quantity: 3, price: 10, total: 7 },
  });
  assert.equal(result.mismatches.length, 2);
  assert.deepEqual(result.mismatches.map((m) => m.path), ["(root)", "line"]);
});

test("특성화: 본문이 JSON 문자열이어도 파싱하고 깨진 JSON 은 hit 없음이다", () => {
  assert.equal(detectPriceTampering('{"quantity":2,"price":10,"total":5}').hit, true);
  assert.deepEqual(detectPriceTampering("{not json"), { hit: false, mismatches: [] });
  for (const body of [null, undefined, 42, true, ""]) {
    assert.deepEqual(detectPriceTampering(body), { hit: false, mismatches: [] },
      `본문 ${JSON.stringify(body)} 가 통과했다`);
  }
});

test("특성화: findAmountMismatches 는 누적기를 직접 받을 수 있다", () => {
  const acc = [];
  const returned = findAmountMismatches({ quantity: 2, price: 10, total: 5 }, "", acc);
  assert.equal(returned, acc, "같은 배열을 돌려줘야 한다");
  assert.equal(acc.length, 1);
});

// ---------------------------------------------------------------------------
// 프로파일화 이후
// ---------------------------------------------------------------------------

const GENERIC_PROFILE = profileAt("generic");
const RUBY_PROFILE = profileAt("ruby-shop");

// D3-R 의 핵심: 이 기능은 지금 모든 대상에서 라우트 게이트 없이 도므로 generic 과
// ruby-shop 프로파일에도 같은 값으로 들어간다. 그래서 프로파일이 없는 대상
// (legacy/alternate)의 동작이 바뀌지 않는다 — 비활성이 아니라 그대로 활성이다.
test("generic·ruby-shop 프로파일에서도 juice-shop 과 똑같이 동작한다", () => {
  for (const profile of [GENERIC_PROFILE, RUBY_PROFILE]) {
    assert.deepEqual(
      detect({ quantity: 2, price: 10, total: 5 }, profile),
      detect({ quantity: 2, price: 10, total: 5 }, JUICE_PROFILE),
      `${profile.profileId} 의 판정이 juice-shop 과 다르다`
    );
    assert.equal(detect({ quantity: 2, price: 10, total: 20 }, profile).hit, false);
    // 비활성으로 보고되어서는 안 된다 — 지금 도는 기능이기 때문이다.
    assert.ok(!profile.disabledFeatures.includes("priceTampering"),
      `${profile.profileId} 가 priceTampering 을 비활성으로 선언했다 — 동작이 바뀐다`);
  }
});

test("다른 사이트의 필드명과 허용 오차로도 같은 검산이 나온다", () => {
  const otherSite = {
    ...GENERIC_PROFILE,
    priceTampering: {
      quantityFields: ["count"],
      unitPriceFields: ["unit_cost"],
      totalFields: ["grand_total"],
      amountTolerance: 1,
    },
  };
  assert.equal(detect({ count: 2, unit_cost: 10, grand_total: 5 }, otherSite).hit, true);
  assert.equal(detect({ count: 2, unit_cost: 10, grand_total: 20 }, otherSite).hit, false);
  // 허용 오차가 1 이므로 0.5 차이는 넘어간다.
  assert.equal(detect({ count: 1, unit_cost: 10, grand_total: 10.5 }, otherSite).hit, false);
  assert.equal(detect({ count: 1, unit_cost: 10, grand_total: 12 }, otherSite).hit, true);
  // juice-shop 의 필드명은 이 프로파일에서 잡히지 않는다.
  assert.equal(detect({ quantity: 2, price: 10, total: 5 }, otherSite).hit, false);
});

test("프로파일에 설정이 없으면 던지지 않고 hit 없음이다", () => {
  for (const profile of [null, undefined, {}, { priceTampering: null }]) {
    assert.deepEqual(detect({ quantity: 2, price: 10, total: 5 }, profile),
      { hit: false, mismatches: [] });
  }
  // findAmountMismatches 도 설정 없이 호출되면 빈 누적기를 돌려준다.
  assert.deepEqual(findMismatches({ quantity: 2, price: 10, total: 5 }, null), []);
});
