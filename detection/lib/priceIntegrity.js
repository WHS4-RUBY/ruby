'use strict';

/**
 * priceIntegrity.js
 *
 * "가격 변조(Product Tampering, PUT /api/Products/:id)" — 1차·2차 실전 공격 테스트 모두에서
 * 미탐으로 재보고된 유일한 항목(2회 연속 시도 실패): 9차에서 role-gated:product-write(관리자
 * 아닌 토큰이면 탐지) + mass-assignment 화이트리스트(정상 편집 폼이 안 보내는 필드면 탐지)를
 * 붙였는데도 계속 놓쳤다.
 *
 * 이 모듈이 겨냥하는 시나리오는 그 둘로는 원천적으로 못 잡는 경우다: 요청이 **role도 admin이고
 * (role-gated 통과), 필드도 화이트리스트 안(name/description/price/... — mass-assignment 통과),
 * price 값도 형식상 유효(0.01 이상 — numeric-abuse 통과)**한데, 그 admin 계정 자체가 탈취됐거나
 * 남용되고 있어서 가격을 원래보다 대폭 깎는 경우. 필드/역할/형식만 보는 지금까지의 검사들은
 * 전부 "문법이 정상인가"만 보지 "이 admin의 이 특정 행동이 그 admin의 평소 행동과 비교해 이상한가"는
 * 안 본다 — 그 간극을 메우려는 시도다.
 *
 * 접근 방식: 외부 정가 테이블을 하드코딩하지 않는다(priceTampering.js가 이미 그 방식을
 * 검토했다가 "잘못된 값을 하드코딩하면 정상 주문까지 오탐될 위험"으로 기각한 전례가 있다).
 * 대신 탐지 프록시가 실제로 관찰한 GET /api/Products, GET /api/Products/:id 응답에서 마지막으로
 * 본 가격을 캐시해두고, 그 다음 PUT으로 제출된 새 가격이 캐시값 대비 큰 폭(기본 50% 이상)으로
 * 떨어지면 의심 신호로 잡는다. 캐시가 아직 없으면(그 상품을 한 번도 GET한 적이 없으면) 판단을
 * 보류한다 — 근거 없이 추측하지 않는다.
 *
 * 정직하게 밝혀둘 한계 두 가지:
 *   1) 이 엔드포인트는 실제로 관리자가 정상적으로도 쓰는 것(진짜 세일로 가격을 반값 이하로
 *      내리는 경우도 있을 수 있다) — role/필드/형식이 전부 정상인 요청이라 "공격이 아닐 가능성"을
 *      구조적으로 배제할 수 없다. 그래서 로그 전용 log-only 신호로만 두고, 다른 신호들처럼
 *      businessLogicViolation 서브스코어의 부분 가중치로만 반영한다(단독으로 차단 판단을 만들지
 *      않는다).
 *   2) "상품 변조"로 보고된 실제 요청의 원본 페이로드(price가 정확히 어떻게 바뀌었는지, 혹은
 *      가격이 아니라 description 등 다른 필드가 변조 대상이었는지)를 이 세션에서 직접 확인하지
 *      못했다 — 그래서 이게 그 특정 미탐의 진짜 원인인지는 확신할 수 없고, "역할/필드/형식이 전부
 *      정상인 가격 변조"라는 가장 유력한 가설에 대한 방어 보강이다. description 등 비-price
 *      필드 변조는 이 모듈의 범위 밖이며 여전히 탐지 공백으로 남아있다.
 *
 * 상태(state)가 필요하다는 점이 이 프로젝트의 다른 businessLogic* 계열(전부 단일 요청 body만
 * 보는 stateless 검사)과 근본적으로 다르다 — 그래도 판정 자체는 "문법적으로 정상인 business
 * logic 공격"이라는 같은 범주라 새 서브스코어를 만들지 않고 기존 businessLogicViolation
 * 파이프라인(blTags)에 태그(price-tampering:delta)로 합류시킨다.
 *
 * server.js 연동:
 *   - onProxyRes에서 GET /api/Products, GET /api/Products/:id 응답 JSON을 관찰해
 *     ingestProductResponseBody()로 캐시에 반영.
 *   - computeBusinessLogicTags()에서 PUT /api/Products/:id 요청마다 checkPriceDelta() 호출.
 */

const PRODUCTS_LIST_PATH = '/api/Products';
const PRODUCTS_ITEM_PATH = '/api/Products/:id';

// 캐시된 관찰가 대비 이 비율 이하로 떨어지면 의심(기본: 50% 이상 하락)
const PRICE_DROP_RATIO = 0.5;

// productId(문자열) -> 마지막으로 관찰된 price(숫자)
const priceCache = new Map();

function resetPriceCache() {
  // 테스트에서만 사용 — 프로세스 생애주기 동안은 계속 누적된다.
  priceCache.clear();
}

function recordObservedPrice(productId, price) {
  if (productId === undefined || productId === null) return;
  if (typeof price !== 'number' || !Number.isFinite(price) || price <= 0) return;
  priceCache.set(String(productId), price);
}

/**
 * Juice Shop 상품 API JSON 응답에서 {id, price} 쌍을 찾아 캐시에 반영한다.
 * 단일 상품 응답({id,price,...} 또는 {data:{id,price,...}})과 목록 응답({data:[{...},...]})
 * 둘 다 지원한다.
 */
function ingestProductResponseBody(parsedBody) {
  if (!parsedBody || typeof parsedBody !== 'object') return;

  let candidates = [];
  if (Array.isArray(parsedBody.data)) {
    candidates = parsedBody.data;
  } else if (parsedBody.data && typeof parsedBody.data === 'object') {
    candidates = [parsedBody.data];
  } else if (typeof parsedBody.id !== 'undefined') {
    candidates = [parsedBody];
  }

  for (const item of candidates) {
    if (item && typeof item === 'object' && typeof item.id !== 'undefined') {
      recordObservedPrice(item.id, item.price);
    }
  }
}

/**
 * URL 마지막 경로 세그먼트가 숫자면 그대로 반환한다(상품 id 추출용).
 */
function extractTrailingNumericId(url) {
  try {
    const parsed = new URL(url || '', 'http://detection.local');
    const segments = parsed.pathname.split('/').filter(Boolean);
    const last = segments[segments.length - 1];
    return last && /^\d+$/.test(last) ? last : null;
  } catch {
    return null;
  }
}

/**
 * @returns {{hit:boolean, observed?:number, submitted?:number, dropRatio?:number}}
 */
function checkPriceDelta(productId, submittedPrice) {
  if (productId === undefined || productId === null) return { hit: false };
  if (typeof submittedPrice !== 'number' || !Number.isFinite(submittedPrice)) return { hit: false };

  const observed = priceCache.get(String(productId));
  if (typeof observed !== 'number') return { hit: false }; // 기준값 없으면 판단 보류 — 오탐보다 미탐을 택한다

  const dropRatio = submittedPrice / observed;
  if (submittedPrice < observed && dropRatio <= PRICE_DROP_RATIO) {
    return { hit: true, observed, submitted: submittedPrice, dropRatio };
  }
  return { hit: false, observed, submitted: submittedPrice, dropRatio };
}

module.exports = {
  PRODUCTS_LIST_PATH,
  PRODUCTS_ITEM_PATH,
  PRICE_DROP_RATIO,
  recordObservedPrice,
  ingestProductResponseBody,
  extractTrailingNumericId,
  checkPriceDelta,
  resetPriceCache,
};
