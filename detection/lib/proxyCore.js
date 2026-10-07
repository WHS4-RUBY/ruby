const httpProxy = require("http-proxy");
const querystring = require("node:querystring");
const zlib = require("node:zlib");

function normalizedHooks(hooks) {
  return Array.isArray(hooks) ? hooks.filter(Boolean) : [];
}

function runRequestHooks(hooks, context) {
  for (const hook of normalizedHooks(hooks)) {
    if (typeof hook.onRequest === "function") hook.onRequest(context);
  }
}

function runWebSocketHooks(hooks, context) {
  for (const hook of normalizedHooks(hooks)) {
    if (typeof hook.onWebSocketRequest === "function") hook.onWebSocketRequest(context);
  }
}

function applyForwardedHeaders(proxyReq, req) {
  proxyReq.removeHeader("forwarded");
  proxyReq.removeHeader("x-forwarded-for");
  proxyReq.removeHeader("x-forwarded-host");
  proxyReq.removeHeader("x-forwarded-proto");
  proxyReq.setHeader("X-Forwarded-For", req.ip || req.socket?.remoteAddress || "unknown");
  proxyReq.setHeader("X-Forwarded-Host", req.get?.("host") || req.headers?.host || "");
  proxyReq.setHeader("X-Forwarded-Proto", req.protocol || "http");
}

async function runResponseHooks(hooks, context) {
  let responseBuffer = context.responseBuffer;
  for (const hook of normalizedHooks(hooks)) {
    if (typeof hook.onResponse !== "function") continue;
    const nextBody = await hook.onResponse({ ...context, responseBuffer });
    if (nextBody !== undefined && nextBody !== null) {
      responseBuffer = Buffer.isBuffer(nextBody) ? nextBody : Buffer.from(String(nextBody));
    }
  }
  return responseBuffer;
}

function fixRequestBody(proxyReq, req) {
  if (req.readableLength !== 0 || !req.body) return;
  const contentType = String(proxyReq.getHeader("content-type") || "");
  let body;
  if (contentType.includes("application/json")) body = JSON.stringify(req.body);
  else if (contentType.includes("application/x-www-form-urlencoded")) {
    body = querystring.stringify(req.body);
  }
  if (body === undefined) return;
  proxyReq.setHeader("content-length", Buffer.byteLength(body));
  proxyReq.write(body);
}

function decodedResponse(proxyRes) {
  switch (proxyRes.headers["content-encoding"]) {
    case "gzip": return proxyRes.pipe(zlib.createGunzip());
    case "deflate": return proxyRes.pipe(zlib.createInflate());
    case "br": return proxyRes.pipe(zlib.createBrotliDecompress());
    default: return proxyRes;
  }
}

async function handleResponse(proxyRes, req, res, hooks, target) {
  const chunks = [];
  for await (const chunk of decodedResponse(proxyRes)) chunks.push(chunk);
  if (res.destroyed) return;
  const responseBuffer = Buffer.concat(chunks);
  const localCookies = res.getHeader("set-cookie");
  const preservedCookies = localCookies === undefined ? [] :
    Array.isArray(localCookies) ? [...localCookies] : [String(localCookies)];
  res.statusCode = proxyRes.statusCode || 502;
  res.statusMessage = proxyRes.statusMessage || res.statusMessage;
  for (const [name, value] of Object.entries(proxyRes.headers)) {
    if (["content-encoding", "transfer-encoding", "content-length", "set-cookie"].includes(name) ||
        value === undefined) continue;
    res.setHeader(name, value);
  }
  const upstreamCookies = proxyRes.headers["set-cookie"];
  const cookies = upstreamCookies === undefined ? [] :
    (Array.isArray(upstreamCookies) ? upstreamCookies : [upstreamCookies]).map(cookie =>
      String(cookie).replace(/;\s*Domain=[^;]*/gi, ""));
  if (preservedCookies.length || cookies.length)
    res.setHeader("set-cookie", [...preservedCookies, ...cookies]);
  const body = await runResponseHooks(hooks, { responseBuffer, proxyRes, req, res, target });
  if (res.destroyed || res.writableEnded) return;
  res.setHeader("content-length", body.length);
  res.end(body);
}

/**
 * RUBY의 기존 Python ProxyHook 생명주기를 Express용으로 옮긴 공통 프록시 코어.
 *
 * Hook contract:
 *   onRequest({ proxyReq, req, res, target })
 *   onResponse({ responseBuffer, proxyRes, req, res, target }) -> Buffer|string|undefined
 *
 * 요청 훅은 http-proxy가 upstream 요청을 보내기 직전에 동기 실행된다. 응답 훅은
 * 순서대로 비동기 실행되며, 각 훅이 반환한 body가 다음 훅의 입력이 된다.
 */
function createProxyCore({ target, hooks = [], changeOrigin = true }) {
  if (!target) throw new Error("proxy target is required");
  const hookList = normalizedHooks(hooks);
  const proxy = httpProxy.createProxyServer({ target, changeOrigin, ws: true,
    selfHandleResponse: true });
  proxy.on("proxyReq", (proxyReq, req, res) => {
    applyForwardedHeaders(proxyReq, req);
    runRequestHooks(hookList, { proxyReq, req, res, target });
  });
  proxy.on("proxyReqWs", (proxyReq, req, socket) => {
    applyForwardedHeaders(proxyReq, req);
    runWebSocketHooks(hookList, { proxyReq, req, res: socket, target });
  });
  proxy.on("proxyRes", (proxyRes, req, res) => {
    handleResponse(proxyRes, req, res, hookList, target).catch(error => {
      if (res.destroyed) return;
      if (!res.headersSent) res.statusCode = 502;
      res.end();
      console.error("proxy response failed:", error);
    });
  });
  const middleware = (req, res) => proxy.web(req, res, { target }, error => {
    if (!res.headersSent) res.statusCode = 502;
    res.end();
    console.error("proxy request failed:", error);
  });
  middleware.upgrade = (req, socket, head) => proxy.ws(req, socket, head, { target }, error => {
    socket.destroy();
    console.error("proxy websocket failed:", error);
  });
  return middleware;
}

module.exports = {
  applyForwardedHeaders,
  createProxyCore,
  fixRequestBody,
  runRequestHooks,
  runResponseHooks,
  runWebSocketHooks,
};
