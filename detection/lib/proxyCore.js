const {
  createProxyMiddleware,
  responseInterceptor,
} = require("http-proxy-middleware");

function normalizedHooks(hooks) {
  return Array.isArray(hooks) ? hooks.filter(Boolean) : [];
}

function runRequestHooks(hooks, context) {
  for (const hook of normalizedHooks(hooks)) {
    if (typeof hook.onRequest === "function") hook.onRequest(context);
  }
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

  return createProxyMiddleware({
    target,
    changeOrigin,
    selfHandleResponse: true,
    onProxyReq(proxyReq, req, res) {
      runRequestHooks(hookList, { proxyReq, req, res, target });
    },
    onProxyRes(proxyRes, req, res) {
      // responseInterceptor copies upstream headers before running its callback.
      // Snapshot this hop's cookies now, before that copy can replace them.
      const currentCookies = res.getHeader("set-cookie");
      const localCookies = currentCookies === undefined
        ? []
        : Array.isArray(currentCookies) ? [...currentCookies] : [String(currentCookies)];

      return responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
        if (localCookies.length && proxyRes.headers["set-cookie"] !== undefined) {
          // Read the copied cookies to preserve the interceptor's domain rewriting.
          const copiedCookies = res.getHeader("set-cookie");
          const upstreamCookies = Array.isArray(copiedCookies)
            ? copiedCookies : copiedCookies === undefined ? [] : [String(copiedCookies)];
          res.setHeader("set-cookie", [...localCookies, ...upstreamCookies]);
        }
        return runResponseHooks(hookList, {
          responseBuffer,
          proxyRes,
          req,
          res,
          target,
        });
      })(proxyRes, req, res);
    },
  });
}

module.exports = {
  createProxyCore,
  runRequestHooks,
  runResponseHooks,
};
