const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");

const { DcidManager } = require("../lib/dcid");
const { AccountIdentityResolver } = require("../lib/accountIdentity");
const { getClientIp, parseTrustProxy } = require("../lib/clientIp");

function silentLogger() {
  return { warn() {} };
}

function signJwt(privateKey, payload) {
  const header = Buffer.from(JSON.stringify({ typ: "JWT", alg: "RS256" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto.sign("RSA-SHA256", Buffer.from(`${header}.${body}`), privateKey);
  return `${header}.${body}.${signature.toString("base64url")}`;
}

test("dcid는 HMAC 서명, 발급/만료 시각과 버전을 검증하고 원문 client ID를 노출하지 않는다", () => {
  let now = 1_700_000_000_000;
  const manager = new DcidManager({
    secret: "test-only-secret-at-least-32-bytes-long",
    ttlMs: 60_000,
    now: () => now,
    randomBytes: (size) => Buffer.alloc(size, 0xab),
    logger: silentLogger(),
  });
  const issued = manager.issue();
  const verified = manager.verify(issued.value);

  assert.equal(issued.identity.continuityVerified, false);
  assert.equal(issued.identity.source, "issued");
  assert.equal(verified.valid, true);
  assert.equal(verified.continuityVerified, true);
  assert.equal(verified.source, "verified");
  assert.match(verified.clientId, /^dcid:[a-f0-9]{32}$/);
  assert.equal(JSON.stringify(verified).includes(Buffer.alloc(24, 0xab).toString("base64url")), false);

  const tampered = `${issued.value.slice(0, -1)}x`;
  assert.equal(manager.verify(tampered).reason, "invalid_signature");
  now += 60_001;
  assert.equal(manager.verify(issued.value).reason, "expired");
});

test("검증된 RS256 JWT만 verified Account affiliation을 생성한다", () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const resolver = new AccountIdentityResolver({
    publicKey: publicKey.export({ type: "spki", format: "pem" }),
    hashKey: "account-hash-key-for-tests",
    now: () => 1_700_000_000_000,
    logger: silentLogger(),
  });
  const token = signJwt(privateKey, { data: { id: 7, email: "user@example.test" }, exp: 1_800_000_000 });
  const identity = resolver.inspectAuthorization(`Bearer ${token}`);

  assert.equal(identity.verified, true);
  assert.equal(identity.claim, "data.id");
  assert.match(identity.accountId, /^account:[a-f0-9]{32}$/);
  assert.equal(JSON.stringify(identity).includes("user@example.test"), false);

  const [header, body] = token.split(".");
  const badToken = `${header}.${body}.${Buffer.from("invalid").toString("base64url")}`;
  assert.equal(resolver.inspectAuthorization(`Bearer ${badToken}`).verified, false);
});

test("공개키가 없으면 JWT claim은 unverified 관찰값으로만 반환한다", () => {
  const resolver = new AccountIdentityResolver({
    publicKey: null,
    publicKeyFile: null,
    hashKey: "account-hash-key-for-tests",
    logger: silentLogger(),
  });
  const header = Buffer.from(JSON.stringify({ alg: "RS256" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({ data: { id: 8 } })).toString("base64url");
  const identity = resolver.inspectAuthorization(`Bearer ${header}.${payload}.fake`);
  assert.equal(identity.verified, false);
  assert.equal(identity.verification, "public_key_unavailable");
});

test("IP는 Express trust proxy 결과(req.ip)만 사용하고 raw X-Forwarded-For를 직접 신뢰하지 않는다", () => {
  assert.equal(
    getClientIp({ ip: "10.0.0.5", headers: { "x-forwarded-for": "203.0.113.9" }, socket: {} }),
    "10.0.0.5"
  );
  assert.equal(parseTrustProxy("false"), false);
  assert.equal(parseTrustProxy("1"), 1);
  assert.deepEqual(parseTrustProxy("loopback, linklocal, uniquelocal"), [
    "loopback",
    "linklocal",
    "uniquelocal",
  ]);
});
