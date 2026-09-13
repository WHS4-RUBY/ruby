'use strict';

/**
 * priceTampering.js
 *
 * "결제/주문 금액 위변조" 탐지 — Juice Shop의 "Payback Time" 챌린지(장바구니/체크아웃 총액을
 * 조작해서 오히려 돈을 돌려받는 것) 대응 후보로 제안했던 기능.
 *
 * 원래 계획은 "상품 ID별 정가 테이블을 하드코딩해서 실제 제출된 price와 대조"하는 것이었는데,
 * 이 프로젝트에서 실측된 유일한 가격 조작 공격(detection-test-001, `PUT /api/Products/1
 * {"price":0}`)은 이미 numeric-abuse(price min:0.01)와 role-gated:product-write(관리자 전용
 * 엔드포인트) 두 가지로 이중 커버되고 있다는 걸 뒤늦게 확인했다 — 그래서 외부 정가 테이블은
 * 만들지 않기로 하고(잘못된 값을 하드코딩하면 정상 주문까지 오탐될 위험), 대신 **같은 요청
 * 안에서 수량×단가와 제출된 총액이 서로 맞는지 자체 일관성만 검사**하는 방식으로 다시 설계했다.
 *
 * 이건 외부 참조 데이터가 전혀 필요 없다는 게 핵심 — quantity/price/total 세 필드가 같은
 * 객체 안에 함께 있을 때만 산술적으로 맞는지 보고, 하나라도 없으면 아무 판단도 안 한다.
 * 그래서 오탐 위험이 구조적으로 낮다(있는 데이터로 산수만 확인하는 것뿐이라).
 *
 * 다른 businessLogicSignatures.js 계열(mass-assignment/numeric-abuse 등)과 마찬가지로 요청
 * 본문(body)만 보는 stateless 검사라 businessLogicViolation 서브스코어에 그대로 접는다(role-gated와
 * 동일한 판단 — 같은 데이터 소스/같은 계산 성격이면 기존 서브스코어에 합류, 다른 데이터
 * 소스(csrf의 헤더)나 다른 계산 성격(loginBruteForce의 시간창 반복 집계)일 때만 분리).
 *
 * server.js 연동 지점: computeBusinessLogicTags() 안에 checkRoleGatedAccess()와 나란히 호출.
 *
 * 한계: 이 프로젝트에서 실제로 캡처된 트래픽 중 quantity+price+total이 한 요청에 같이 들어있는
 * 사례는 아직 확인된 바 없다(Juice Shop의 실제 장바구니/체크아웃 API는 가격을 서버가 DB에서
 * 조회해 쓰지, 클라이언트가 price/total을 함께 제출하도록 설계되어 있지 않은 것으로 보임) —
 * 그래서 지금은 "그런 필드 조합이 나타나면" 방어적으로 잡아두는 성격이 강하고, 이 프로젝트
 * 실측 트래픽에서 실제로 발동한 사례는 아직 없다. 정직하게 남겨둔다.
 */

const QUANTITY_FIELDS = new Set(['quantity', 'qty']);
const UNIT_PRICE_FIELDS = new Set(['price', 'unitprice', 'itemprice']);
const TOTAL_FIELDS = new Set(['totalprice', 'total', 'amount', 'ordertotal', 'linetotal']);

// 부동소수점/통화 반올림 오차 허용치 (1센트)
const AMOUNT_TOLERANCE = 0.01;

function findKey(keys, fieldSet) {
  return keys.find((k) => fieldSet.has(k.toLowerCase()));
}

/**
 * body를 재귀적으로 훑어(NoSQL 연산자 탐지와 동일한 순회 방식), 같은 객체 레벨에 quantity/
 * unit-price/total 세 필드가 전부 있으면 total ≈ quantity × price인지 확인한다.
 *
 * @returns {Array<{path:string, quantity:number, price:number, total:number, expected:number}>}
 */
function findAmountMismatches(node, path = '', acc = []) {
  if (!node || typeof node !== 'object') return acc;

  if (Array.isArray(node)) {
    node.forEach((item, i) => findAmountMismatches(item, `${path}[${i}]`, acc));
    return acc;
  }

  const keys = Object.keys(node);
  const quantityKey = findKey(keys, QUANTITY_FIELDS);
  const priceKey = findKey(keys, UNIT_PRICE_FIELDS);
  const totalKey = findKey(keys, TOTAL_FIELDS);

  if (quantityKey && priceKey && totalKey) {
    const quantity = node[quantityKey];
    const price = node[priceKey];
    const total = node[totalKey];
    if (
      typeof quantity === 'number' && Number.isFinite(quantity) &&
      typeof price === 'number' && Number.isFinite(price) &&
      typeof total === 'number' && Number.isFinite(total)
    ) {
      const expected = quantity * price;
      if (Math.abs(expected - total) > AMOUNT_TOLERANCE) {
        acc.push({ path: path || '(root)', quantity, price, total, expected });
      }
    }
  }

  for (const [key, value] of Object.entries(node)) {
    if (value && typeof value === 'object') {
      findAmountMismatches(value, `${path}${path ? '.' : ''}${key}`, acc);
    }
  }

  return acc;
}

/**
 * @param {object|string|null} body
 * @returns {{hit:boolean, mismatches:Array}}
 */
function detectPriceTampering(body) {
  let bodyObj = body;
  if (typeof bodyObj === 'string') {
    try { bodyObj = JSON.parse(bodyObj); } catch { return { hit: false, mismatches: [] }; }
  }
  if (!bodyObj || typeof bodyObj !== 'object') return { hit: false, mismatches: [] };

  const mismatches = findAmountMismatches(bodyObj);
  return { hit: mismatches.length > 0, mismatches };
}

module.exports = {
  detectPriceTampering,
  findAmountMismatches,
  QUANTITY_FIELDS,
  UNIT_PRICE_FIELDS,
  TOTAL_FIELDS,
  AMOUNT_TOLERANCE,
};
