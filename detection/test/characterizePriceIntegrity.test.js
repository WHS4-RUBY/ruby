const assert = require("node:assert/strict");
const { beforeEach, test } = require("node:test");

const {
  recordObservedPrice,
  ingestProductResponseBody,
  extractTrailingNumericId,
  checkPriceDelta,
  resetPriceCache,
  PRODUCTS_LIST_PATH,
  PRODUCTS_ITEM_PATH,
  PRICE_DROP_RATIO,
} = require("../lib/priceIntegrity");

/**
 * priceIntegrity.js 의 특성화 테스트.
 *
 * 이 모듈은 상태를 갖는다 — 모듈 전역 priceCache 에 관찰된 가격을 모으고, 나중의
 * 쓰기 요청이 제출한 가격과 비교한다. node --test 는 파일 단위로만 격리하므로
 * 매 테스트 앞에서 resetPriceCache() 로 비운다(기존 테스트와 같은 방식).
 */

beforeEach(() => resetPriceCache());

test("특성화: 라우트 상수와 임계 비율", () => {
  assert.equal(PRODUCTS_LIST_PATH, "/api/Products");
  assert.equal(PRODUCTS_ITEM_PATH, "/api/Products/:id");
  assert.equal(PRICE_DROP_RATIO, 0.5);
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
