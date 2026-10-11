const assert = require("node:assert/strict");
const { beforeEach, test } = require("node:test");

const path = require("node:path");

const {
  recordObservedPrice: record,
  ingestProductResponseBody: ingestFor,
  extractTrailingNumericId,
  checkPriceDelta: checkDeltaFor,
  resetPriceCache,
} = require("../lib/priceIntegrity");
const { loadSiteProfile } = require("../lib/siteProfile");

const profileAt = (id) =>
  loadSiteProfile(path.join(__dirname, "..", "config", "site-profiles", `${id}.json`));

// juice-shop 프로파일을 주입하면 아래 단정은 한 글자도 바뀌지 않고 통과해야 한다.
const JUICE_PROFILE = profileAt("juice-shop");
// 가격 캐시는 대상별로 분리된다. 이 파일의 단정은 한 대상 안에서의 동작이므로
// 고정된 대상 ID 하나를 쓴다.
const TARGET = "juice-shop";
const recordObservedPrice = (id, price) => record(TARGET, id, price);
const ingest = (body, profile) => ingestFor(body, profile, TARGET);
const checkDelta = (id, price, profile) => checkDeltaFor(id, price, profile, TARGET);
const ingestProductResponseBody = (body) => ingest(body, JUICE_PROFILE);
const checkPriceDelta = (id, price) => checkDelta(id, price, JUICE_PROFILE);

/**
 * priceIntegrity.js 의 특성화 테스트.
 *
 * 이 모듈은 상태를 갖는다 — 모듈 전역 priceCache 에 관찰된 가격을 모으고, 나중의
 * 쓰기 요청이 제출한 가격과 비교한다. node --test 는 파일 단위로만 격리하므로
 * 매 테스트 앞에서 resetPriceCache() 로 비운다(기존 테스트와 같은 방식).
 */

beforeEach(() => resetPriceCache());

// 상수였던 값이 프로파일로 옮겨갔다. 같은 값인지 여기서 고정한다 — 이것이
// 리팩토링 전 모듈 상수와 juice-shop 프로파일이 같다는 증거다.
test("특성화: 라우트와 임계 비율이 리팩토링 전 상수와 같다", () => {
  assert.equal(JUICE_PROFILE.priceIntegrity.listRoute, "/api/Products");
  assert.equal(JUICE_PROFILE.priceIntegrity.itemRoute, "/api/Products/:id");
  assert.equal(JUICE_PROFILE.priceIntegrity.priceDropRatio, 0.5);
  assert.equal(JUICE_PROFILE.priceIntegrity.idField, "id");
  assert.equal(JUICE_PROFILE.priceIntegrity.priceField, "price");
  assert.deepEqual(JUICE_PROFILE.priceIntegrity.responseEnvelope,
    { itemsKey: "data", bareObjectHasField: "id" });
});

test("특성화: 쓸 수 있는 가격만 캐시에 들어간다", () => {
  recordObservedPrice(1, 100);
  assert.equal(checkPriceDelta(1, 10).hit, true);

  // id 가 없으면 기록하지 않는다.
  for (const id of [undefined, null]) {
    recordObservedPrice(id, 100);
  }
  // 가격이 숫자가 아니거나 0 이하면 기록하지 않는다.
  for (const price of [0, -1, "100", null, Number.NaN, Number.POSITIVE_INFINITY, undefined]) {
    recordObservedPrice(2, price);
    assert.deepEqual(checkPriceDelta(2, 1), { hit: false },
      `가격 ${JSON.stringify(price)} 가 기록됐다`);
  }
});

// 캐시 키는 String(productId) 다 — 숫자 1 과 문자열 "1" 이 같은 키다.
test("특성화: 캐시 키는 문자열로 강제 변환된다", () => {
  recordObservedPrice(1, 100);
  assert.equal(checkPriceDelta("1", 10).hit, true);
  recordObservedPrice("7", 100);
  assert.equal(checkPriceDelta(7, 10).hit, true);
});

test("특성화: 세 가지 응답 엔벌로프를 모두 받아들인다", () => {
  // 1) 목록: {data: [...]}
  ingestProductResponseBody({ status: "success", data: [{ id: 1, price: 100 }, { id: 2, price: 50 }] });
  assert.equal(checkPriceDelta(1, 10).hit, true);
  assert.equal(checkPriceDelta(2, 5).hit, true);

  // 2) 단일: {data: {...}}
  resetPriceCache();
  ingestProductResponseBody({ status: "success", data: { id: 3, price: 100 } });
  assert.equal(checkPriceDelta(3, 10).hit, true);

  // 3) 맨몸 객체: {id, price, ...} — data 가 없고 id 가 있을 때만
  resetPriceCache();
  ingestProductResponseBody({ id: 4, price: 100 });
  assert.equal(checkPriceDelta(4, 10).hit, true);
});

test("특성화: 엔벌로프가 맞지 않으면 아무것도 기록하지 않는다", () => {
  for (const body of [
    null, undefined, 42, "x", [],
    { data: 42 },
    { data: "x" },
    { price: 100 },               // id 가 없다
    { data: [{ price: 100 }] },   // 항목에 id 가 없다
    { items: [{ id: 1, price: 100 }] }, // data 가 아니다
  ]) {
    resetPriceCache();
    ingestProductResponseBody(body);
    assert.deepEqual(checkPriceDelta(1, 1), { hit: false },
      `${JSON.stringify(body)} 에서 뭔가 기록됐다`);
  }
});

// data 가 배열이 아닌 객체면 그 **하나만** 본다. data 가 빈 배열이면 아무것도 없다.
test("특성화: data 가 빈 배열이면 아무것도 기록하지 않는다", () => {
  ingestProductResponseBody({ data: [] });
  assert.deepEqual(checkPriceDelta(1, 1), { hit: false });
});

// 반환 모양이 두 가지다: 기준값이 없으면 {hit:false} 만, 있으면 observed/submitted/
// dropRatio 까지 함께 온다. 둘 다 고정한다.
test("특성화: 기준값 유무에 따라 반환 모양이 다르다", () => {
  assert.deepEqual(checkPriceDelta(1, 10), { hit: false }, "기준값 없으면 키가 하나다");

  recordObservedPrice(1, 100);
  assert.deepEqual(checkPriceDelta(1, 10),
    { hit: true, observed: 100, submitted: 10, dropRatio: 0.1 });
  assert.deepEqual(checkPriceDelta(1, 90),
    { hit: false, observed: 100, submitted: 90, dropRatio: 0.9 });
});

// 경계값: dropRatio 가 정확히 0.5 면 **hit 이다**(`<=` 비교).
test("특성화: 하락 비율 경계값 0.5 는 hit 이다", () => {
  recordObservedPrice(1, 100);
  assert.equal(checkPriceDelta(1, 50).hit, true, "정확히 절반은 hit");
  assert.equal(checkPriceDelta(1, 50.01).hit, false);
  assert.equal(checkPriceDelta(1, 49.99).hit, true);
  // 올린 가격은 hit 이 아니다.
  assert.equal(checkPriceDelta(1, 200).hit, false);
  assert.equal(checkPriceDelta(1, 100).hit, false);
});

test("특성화: id 나 제출 가격이 쓸 수 없으면 판단을 보류한다", () => {
  recordObservedPrice(1, 100);
  for (const id of [undefined, null]) {
    assert.deepEqual(checkPriceDelta(id, 10), { hit: false });
  }
  for (const price of ["10", null, undefined, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.deepEqual(checkPriceDelta(1, price), { hit: false },
      `제출 가격 ${JSON.stringify(price)} 가 통과했다`);
  }
});

test("특성화: URL 마지막 세그먼트가 숫자일 때만 id 로 뽑는다", () => {
  assert.equal(extractTrailingNumericId("/api/Products/12"), "12");
  assert.equal(extractTrailingNumericId("/api/Products/12?x=1"), "12");
  assert.equal(extractTrailingNumericId("/api/Products/12/"), "12");
  assert.equal(extractTrailingNumericId("/api/Products/abc"), null);
  assert.equal(extractTrailingNumericId("/api/Products"), null);
  assert.equal(extractTrailingNumericId("/api/Products/12a"), null);
  assert.equal(extractTrailingNumericId(""), null);
  assert.equal(extractTrailingNumericId(undefined), null);
});

test("특성화: 같은 상품의 관찰가는 마지막 값으로 갱신된다", () => {
  recordObservedPrice(1, 100);
  recordObservedPrice(1, 40);
  // 기준이 40 이 되었으므로 10 은 25% — hit.
  assert.equal(checkPriceDelta(1, 10).hit, true);
  // 30 은 75% — hit 아님.
  assert.equal(checkPriceDelta(1, 30).hit, false);
});

// ---------------------------------------------------------------------------
// 프로파일화 이후
// ---------------------------------------------------------------------------

const GENERIC_PROFILE = profileAt("generic");
const RUBY_PROFILE = profileAt("ruby-shop");

test("다른 사이트의 엔벌로프·필드명·임계 비율로도 같은 판정이 나온다", () => {
  const otherSite = {
    ...GENERIC_PROFILE,
    priceIntegrity: {
      listRoute: "/api/products",
      itemRoute: "/api/products/:id",
      priceDropRatio: 0.8,
      idField: "product_id",
      priceField: "unit_price",
      responseEnvelope: { itemsKey: "items", bareObjectHasField: "product_id" },
    },
  };

  // 목록: {items: [...]}
  ingest({ items: [{ product_id: 9, unit_price: 100 }] }, otherSite);
  assert.equal(checkDelta(9, 70, otherSite).hit, true, "70% 는 임계 0.8 이하라 hit");
  assert.equal(checkDelta(9, 90, otherSite).hit, false);

  // 맨몸: {product_id, unit_price}
  resetPriceCache();
  ingest({ product_id: 10, unit_price: 100 }, otherSite);
  assert.equal(checkDelta(10, 50, otherSite).hit, true);

  // juice-shop 의 엔벌로프·필드명은 이 프로파일에서 잡히지 않는다.
  resetPriceCache();
  ingest({ data: [{ id: 11, price: 100 }] }, otherSite);
  assert.deepEqual(checkDelta(11, 10, otherSite), { hit: false });
});

// itemsKey 가 빈 문자열이면 본문 자체가 컨테이너다 — 응답이 맨 배열인 API 를 위해.
test("itemsKey 가 빈 문자열이면 본문 자체를 컨테이너로 본다", () => {
  const bareArray = {
    ...GENERIC_PROFILE,
    priceIntegrity: {
      listRoute: "/api/products",
      itemRoute: "/api/products/:id",
      priceDropRatio: 0.5,
      idField: "id",
      priceField: "price",
      responseEnvelope: { itemsKey: "", bareObjectHasField: "id" },
    },
  };
  ingest([{ id: 1, price: 100 }, { id: 2, price: 200 }], bareArray);
  assert.equal(checkDelta(1, 10, bareArray).hit, true);
  assert.equal(checkDelta(2, 20, bareArray).hit, true);

  resetPriceCache();
  ingest({ id: 3, price: 100 }, bareArray);
  assert.equal(checkDelta(3, 10, bareArray).hit, true);
});

// 규칙 3: ruby-shop 은 라우트(/api/products, /api/products/{product_id})를 알면서도
// 이 블록을 비워 둔다. 엔벌로프와 필드명 근거가 없는데 반쯤 채우면 캐시가 영원히
// 비어 checkPriceDelta 가 항상 {hit:false} 를 돌려주는 **조용한 무력화**가 된다.
test("프로파일에 설정이 없으면 비활성이고 그 사실이 드러난다", () => {
  for (const profile of [GENERIC_PROFILE, RUBY_PROFILE, null, undefined, {}]) {
    resetPriceCache();
    ingest({ data: [{ id: 1, price: 100 }] }, profile);
    assert.deepEqual(checkDelta(1, 10, profile), { hit: false });
  }
  for (const profile of [GENERIC_PROFILE, RUBY_PROFILE]) {
    assert.ok(profile.disabledFeatures.includes("priceIntegrity"),
      `${profile.profileId} 가 priceIntegrity 비활성을 선언하지 않았다`);
  }
});

// ---------------------------------------------------------------------------
// 대상별 캐시 격리 (동작 변경)
// ---------------------------------------------------------------------------

// Detection 은 한 프로세스가 여러 대상을 서비스하고 활성 대상이 런타임에 전환된다.
// 예전에는 캐시 키가 productId 하나여서, 두 사이트가 모두 상품 라우트를 가지면
// 대상을 바꾼 뒤 **다른 사이트의 가격**을 기준값으로 썼다.
test("가격 캐시는 대상별로 분리된다", () => {
  const siteA = { ...JUICE_PROFILE, profileId: "site-a" };
  const siteB = {
    ...JUICE_PROFILE,
    profileId: "site-b",
    priceIntegrity: { ...JUICE_PROFILE.priceIntegrity },
  };

  // 같은 상품 id 1 이 두 대상에서 전혀 다른 가격을 갖는다.
  ingestFor({ data: [{ id: 1, price: 100 }] }, siteA, "target-a");
  ingestFor({ data: [{ id: 1, price: 10 }] }, siteB, "target-b");

  // target-a 기준 100 -> 20 은 20% 로 hit.
  assert.deepEqual(checkDeltaFor(1, 20, siteA, "target-a"),
    { hit: true, observed: 100, submitted: 20, dropRatio: 0.2 });
  // target-b 기준 10 -> 20 은 가격 인상이므로 hit 아님. 대상이 섞였다면
  // observed 가 100 으로 보여 hit 이 되었을 것이다.
  assert.deepEqual(checkDeltaFor(1, 20, siteB, "target-b"),
    { hit: false, observed: 10, submitted: 20, dropRatio: 2 });

  // 한 대상에서만 관찰된 상품은 다른 대상에서 기준값이 없다.
  ingestFor({ data: [{ id: 2, price: 100 }] }, siteA, "target-a");
  assert.deepEqual(checkDeltaFor(2, 10, siteB, "target-b"), { hit: false },
    "다른 대상의 관찰값을 기준으로 쓰면 안 된다");
  assert.equal(checkDeltaFor(2, 10, siteA, "target-a").hit, true);
});

test("대상 ID 가 없어도 한 묶음으로 동작한다", () => {
  record(null, 1, 100);
  assert.equal(checkDeltaFor(1, 10, JUICE_PROFILE, null).hit, true);
  assert.equal(checkDeltaFor(1, 10, JUICE_PROFILE, undefined).hit, true,
    "null 과 undefined 는 같은 묶음이다");
  assert.deepEqual(checkDeltaFor(1, 10, JUICE_PROFILE, "other"), { hit: false });
});
