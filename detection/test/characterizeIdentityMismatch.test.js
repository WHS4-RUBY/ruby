const assert = require("node:assert/strict");
const { after, test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const schemaDir = fs.mkdtempSync(path.join(os.tmpdir(), "characterize-identity-"));
process.env.DETECTION_STORE_DB = path.join(schemaDir, "detection.sqlite3");

const {
  checkIdentityMismatch,
  decodeClaimedIdentity,
  extractToken,
  isHardcodedIdentityRoute,
} = require("../lib/identityMismatch");
const schemaLearning = require("../lib/schemaLearning");

after(() => fs.rmSync(schemaDir, { recursive: true, force: true }));

/**
 * identityMismatch.js 의 특성화 테스트. 7개 모듈 중 Juice Shop 에 가장 깊게 결합된
 * 모듈이다 — JWT 의 `data` 래퍼, 표준이 아닌 `bid` 클레임, 쿠키 이름 `token`,
 * 네 라우트와 `UserId` 필드명.
 *
 * roleGatedAccess.js 가 decodeClaimedIdentity/extractToken 을 재export 하므로
 * 이 모듈을 고치면 그쪽도 함께 풀린다.
 */

function token(payload, { segments = 3 } = {}) {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const head = `${encode({ alg: "none", typ: "JWT" })}.${encode(payload)}`;
  return segments === 3 ? `${head}.` : head;
}

const CUSTOMER = { data: { id: 7, email: "a@b", role: "customer" }, bid: 12 };

// ---------------------------------------------------------------------------
// 토큰 추출
// ---------------------------------------------------------------------------

test("특성화: Authorization Bearer 가 쿠키보다 우선한다", () => {
  const fromHeader = token({ data: { id: 1 } });
  const fromCookie = token({ data: { id: 2 } });
  assert.equal(extractToken(`Bearer ${fromHeader}`, `token=${fromCookie}`), fromHeader);
  // 스킴 대소문자는 무관하고 앞뒤 공백을 떼어낸다.
  assert.equal(extractToken(`bearer   ${fromHeader}  `, null), fromHeader);
  assert.equal(extractToken(`BEARER ${fromHeader}`, null), fromHeader);
  // Bearer 가 아니면 헤더를 보지 않는다.
  assert.equal(extractToken(`Basic ${fromHeader}`, null), null);
  assert.equal(extractToken(null, null), null);
});

test("특성화: 쿠키 token= 에서 값을 꺼내고 퍼센트 인코딩을 디코딩한다", () => {
  const value = token({ data: { id: 1 } });
  assert.equal(extractToken(null, `token=${value}`), value);
  assert.equal(extractToken(null, `other=x; token=${value}; more=y`), value);
  assert.equal(extractToken(null, `token=${encodeURIComponent(value)}`), value);
  // 다른 이름의 쿠키는 보지 않는다.
  assert.equal(extractToken(null, `jwt=${value}`), null);
  assert.equal(extractToken(null, ""), null);
});

// ---------------------------------------------------------------------------
// 클레임 해독
// ---------------------------------------------------------------------------

test("특성화: data 래퍼가 있으면 그 안을, 없으면 루트를 본다", () => {
  assert.deepEqual(decodeClaimedIdentity(token(CUSTOMER)),
    { id: 7, email: "a@b", role: "customer", bid: 12 });
  // 래퍼가 없으면 루트에서 읽는다.
  assert.deepEqual(decodeClaimedIdentity(token({ id: 3, email: "c@d", role: "admin" })),
    { id: 3, email: "c@d", role: "admin", bid: null });
  // 래퍼 키가 있지만 falsy 면 루트로 되돌아간다(`payload.data || payload`).
  assert.deepEqual(decodeClaimedIdentity(token({ data: null, id: 9 })),
    { id: 9, email: null, role: null, bid: null });
});

// bid 는 래퍼 안이 아니라 **루트**에서 읽는다 — Juice Shop JWT 의 실제 모양이다.
test("특성화: bid 는 래퍼 바깥 루트에서 읽는다", () => {
  assert.equal(decodeClaimedIdentity(token({ data: { id: 1 }, bid: 5 })).bid, 5);
  assert.equal(decodeClaimedIdentity(token({ data: { id: 1, bid: 5 } })).bid, null,
    "래퍼 안의 bid 는 읽지 않는다");
});

// `??` 를 쓰므로 0 과 빈 문자열이 살아남는다. `||` 였다면 null 이 되었을 것이다.
test("특성화: id 0 과 빈 문자열 email 이 살아남는다", () => {
  const claimed = decodeClaimedIdentity(token({ data: { id: 0, email: "", role: "" } }));
  assert.equal(claimed.id, 0);
  assert.equal(claimed.email, "");
  assert.equal(claimed.role, "");
});

test("특성화: 세그먼트가 둘이어도 해독하고, 깨진 토큰은 null 이다", () => {
  assert.equal(decodeClaimedIdentity(token({ data: { id: 1 } }, { segments: 2 })).id, 1);
  for (const bad of ["", null, undefined, "notajwt", "a", "a.b.c.d.e"]) {
    assert.equal(decodeClaimedIdentity(bad), null, `${JSON.stringify(bad)} 가 해독됐다`);
  }
  // payload 가 JSON 이 아니면 null.
  assert.equal(decodeClaimedIdentity("aGVhZA.bm90IGpzb24.c2ln"), null);
});

// ---------------------------------------------------------------------------
// 경로 규칙
// ---------------------------------------------------------------------------

test("특성화: 경로 세그먼트의 id 가 클레임과 다르면 태깅한다", () => {
  const auth = `Bearer ${token(CUSTOMER)}`;
  // 바스켓은 bid(12)와 비교한다.
  assert.deepEqual(
    checkIdentityMismatch({ method: "GET", normalizedPath: "/rest/basket/:id",
                            url: "/rest/basket/12", authorizationHeader: auth }),
    []
  );
  const basket = checkIdentityMismatch({ method: "GET", normalizedPath: "/rest/basket/:id",
                                         url: "/rest/basket/99", authorizationHeader: auth });
  assert.equal(basket.length, 1);
  assert.equal(basket[0].tag, "identity-mismatch:basket");
  assert.equal(basket[0].detail.claimField, "bid");
  assert.equal(basket[0].detail.requestedId, 99);
  assert.equal(basket[0].detail.claimedValue, 12);

  // 사용자는 id(7)와 비교한다.
  assert.deepEqual(
    checkIdentityMismatch({ method: "GET", normalizedPath: "/api/Users/:id",
                            url: "/api/Users/7", authorizationHeader: auth }),
    []
  );
  const user = checkIdentityMismatch({ method: "GET", normalizedPath: "/api/Users/:id",
                                       url: "/api/Users/99", authorizationHeader: auth });
  assert.equal(user[0].tag, "identity-mismatch:user");
  assert.equal(user[0].detail.claimField, "id");
});

// 경로 규칙의 test 는 **엄격 비교**다 — 뒤 슬래시를 허용하지 않는다. 반면 본문·쿼리
// 규칙의 routeMatches 는 뒤 슬래시를 뗀다. 두 경로가 다르다 — 고정만 한다.
test("특성화: 경로 규칙은 뒤 슬래시를 허용하지 않는다", () => {
  const auth = `Bearer ${token(CUSTOMER)}`;
  assert.deepEqual(
    checkIdentityMismatch({ method: "GET", normalizedPath: "/rest/basket/:id/",
                            url: "/rest/basket/99", authorizationHeader: auth }),
    []
  );
  assert.equal(isHardcodedIdentityRoute("GET", "/rest/basket/:id"), true);
  assert.equal(isHardcodedIdentityRoute("GET", "/rest/basket/:id/"), false);
});

// 반대로 본문·쿼리 규칙은 뒤 슬래시를 같은 라우트로 본다.
test("특성화: 본문·쿼리 규칙은 뒤 슬래시를 같은 라우트로 본다", () => {
  const auth = `Bearer ${token(CUSTOMER)}`;
  for (const normalizedPath of ["/api/Feedbacks", "/api/Feedbacks/"]) {
    const hits = checkIdentityMismatch({ method: "POST", normalizedPath,
                                         url: normalizedPath, body: { UserId: 99 },
                                         authorizationHeader: auth });
    assert.equal(hits.length, 1, normalizedPath);
    assert.equal(hits[0].tag, "identity-mismatch:feedback-userid");
  }
  assert.equal(isHardcodedIdentityRoute("POST", "/api/Feedbacks/"), true);
  assert.equal(isHardcodedIdentityRoute("GET", "/api/Baskets/"), true);
});

test("특성화: 본문 UserId 가 클레임 id 와 다르면 태깅한다", () => {
  const auth = `Bearer ${token(CUSTOMER)}`;
  assert.deepEqual(
    checkIdentityMismatch({ method: "POST", normalizedPath: "/api/Feedbacks",
                            url: "/api/Feedbacks", body: { UserId: 7 },
                            authorizationHeader: auth }),
    []
  );
  const hits = checkIdentityMismatch({ method: "POST", normalizedPath: "/api/Feedbacks",
                                       url: "/api/Feedbacks", body: { UserId: 99 },
                                       authorizationHeader: auth });
  assert.equal(hits[0].detail.field, "UserId");
  assert.equal(hits[0].detail.bodyValue, 99);
  // 본문이 JSON 문자열이어도 파싱한다.
  assert.equal(
    checkIdentityMismatch({ method: "POST", normalizedPath: "/api/Feedbacks",
                            url: "/api/Feedbacks", body: '{"UserId":99}',
                            authorizationHeader: auth }).length,
    1
  );
  // UserId 가 없으면 비교하지 않는다.
  assert.deepEqual(
    checkIdentityMismatch({ method: "POST", normalizedPath: "/api/Feedbacks",
                            url: "/api/Feedbacks", body: { comment: "x" },
                            authorizationHeader: auth }),
    []
  );
});

// 쿼리 파라미터 이름은 **대소문자 무관**으로 찾는다 — passwordResetAbuse 와 다르다.
test("특성화: 쿼리 UserId 는 대소문자 무관으로 찾는다", () => {
  const auth = `Bearer ${token(CUSTOMER)}`;
  for (const name of ["UserId", "userid", "USERID", "userId"]) {
    const hits = checkIdentityMismatch({ method: "GET", normalizedPath: "/api/Baskets",
                                         url: `/api/Baskets?${name}=99`,
                                         authorizationHeader: auth });
    assert.equal(hits.length, 1, `쿼리 이름 ${name} 을 놓쳤다`);
    assert.equal(hits[0].tag, "identity-mismatch:baskets-query");
    assert.equal(hits[0].detail.queryValue, "99");
  }
  assert.deepEqual(
    checkIdentityMismatch({ method: "GET", normalizedPath: "/api/Baskets",
                            url: "/api/Baskets?UserId=7", authorizationHeader: auth }),
    []
  );
});

// 비교는 String() 으로 한다 — 숫자 7 과 문자열 "7" 은 같다.
test("특성화: 비교는 문자열로 한다", () => {
  const auth = `Bearer ${token({ data: { id: "7" } })}`;
  assert.deepEqual(
    checkIdentityMismatch({ method: "GET", normalizedPath: "/api/Users/:id",
                            url: "/api/Users/7", authorizationHeader: auth }),
    []
  );
});

test("특성화: 토큰이 없거나 해독되지 않으면 아무것도 보지 않는다", () => {
  for (const args of [
    {},
    { authorizationHeader: "Basic x" },
    { authorizationHeader: "Bearer notajwt" },
    { cookieHeader: "token=notajwt" },
  ]) {
    assert.deepEqual(
      checkIdentityMismatch({ method: "GET", normalizedPath: "/api/Users/:id",
                              url: "/api/Users/99", ...args }),
      [],
      `${JSON.stringify(args)} 에서 태그가 나왔다`
    );
  }
});

test("특성화: 쿠키로 들어온 토큰도 같은 판정을 받는다", () => {
  const hits = checkIdentityMismatch({ method: "GET", normalizedPath: "/api/Users/:id",
                                       url: "/api/Users/99",
                                       cookieHeader: `token=${token(CUSTOMER)}` });
  assert.equal(hits[0].tag, "identity-mismatch:user");
});

// 학습 폴백은 하드코딩이 **없는** 라우트에만, 승인된 뒤에만 적용된다.
test("특성화: 학습 폴백은 하드코딩 없는 라우트에만 적용된다", () => {
  schemaLearning.resetAll();
  const auth = `Bearer ${token(CUSTOMER)}`;
  const learned = "/api/Orders/:id";

  assert.deepEqual(
    checkIdentityMismatch({ method: "GET", normalizedPath: learned,
                            url: "/api/Orders/99", authorizationHeader: auth }),
    [],
    "승인 전에는 아무것도 하지 않는다"
  );

  for (let i = 0; i < 10; i += 1) {
    schemaLearning.observeIdentityAccess({
      method: "GET",
      normalizedPath: learned,
      requestedId: i % 2 === 0 ? 7 : 12,
      claimedIds: [7, 12],
      statusCode: 200,
    });
  }
  assert.equal(schemaLearning.approveIdentityCandidate(`GET ${learned}`), true);

  const hits = checkIdentityMismatch({ method: "GET", normalizedPath: learned,
                                       url: "/api/Orders/99", authorizationHeader: auth });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].tag, "identity-mismatch:learned");
  // 클레임의 id 나 bid 중 **아무거나** 맞으면 통과한다(넓은 규칙).
  for (const own of [7, 12]) {
    assert.deepEqual(
      checkIdentityMismatch({ method: "GET", normalizedPath: learned,
                              url: `/api/Orders/${own}`, authorizationHeader: auth }),
      []
    );
  }
  schemaLearning.resetAll();
});
