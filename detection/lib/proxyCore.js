const zlib = require("node:zlib");
const httpProxy = require("http-proxy");
const querystring = require("node:querystring");

const DEFAULT_MAX_RESPONSE_BODY_BYTES = 4 * 1024 * 1024;
const DETECTION_COOKIE_NAMES = new Set(["dlsid", "dcid"]);
const HOP_BY_HOP_RESPONSE_HEADERS = new Set([
  "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
  "te", "trailer", "transfer-encoding", "upgrade",
]);

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
  proxyReq.setHeader("X-Forwarded-Host", req.get?.("host") || req.headers?.host || "");
  proxyReq.setHeader("X-Forwarded-Proto", req.protocol || "http");
}

async function runResponseHooks(hooks, context) {
  let responseBuffer = context.responseBuffer;
  for (const hook of normalizedHooks(hooks)) {
    if (typeof hook.onResponse !== "function") continue;
    const nextBody = await hook.onResponse({ ...context, responseBuffer });
    // A streamed response has already reached the client; its body cannot be
    // changed by a hook running after completion.
    if (context.bodyAvailable === false) continue;
    if (nextBody !== undefined && nextBody !== null) {
      responseBuffer = Buffer.isBuffer(nextBody) ? nextBody : Buffer.from(String(nextBody));
    }
  }
  return responseBuffer;
}

async function runResponseErrorHooks(hooks, context) {
  for (const hook of normalizedHooks(hooks)) {
    if (typeof hook.onResponseError === "function") await hook.onResponseError(context);
  }
}

function responseLimit(value) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError("maxResponseBodyBytes must be a positive safe integer");
  }
  return value;
}

function inspectionWait(value) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError("maxInspectionWaitMs must be a positive safe integer");
  }
  return value;
}

function contentLength(headers) {
  const raw = String(headers["content-length"] || "").trim();
  return /^\d+$/.test(raw) ? Number(raw) : null;
}

function contentEncoding(headers) {
  return String(headers["content-encoding"] || "identity").trim().toLowerCase();
}

function shouldInspectBody(proxyRes, req, maxResponseBodyBytes) {
  const status = Number(proxyRes.statusCode);
  if (String(req.method).toUpperCase() === "HEAD" || status < 200 ||
      [204, 205, 206, 304].includes(status) || proxyRes.headers["content-range"]) return false;
  const mime = String(proxyRes.headers["content-type"] || "").split(";", 1)[0].trim().toLowerCase();
  if (mime === "text/event-stream" || /(?:^|;)\s*attachment\b/i.test(
    String(proxyRes.headers["content-disposition"] || ""))) return false;
  if (!["identity", "gzip", "br", "deflate"].includes(contentEncoding(proxyRes.headers))) return false;
  const length = contentLength(proxyRes.headers);
  if (length !== null && length > maxResponseBodyBytes) return false;
  if (mime.startsWith("text/") || mime === "image/svg+xml" ||
      /^(?:application\/)(?:json|javascript|x-javascript|xml|xhtml\+xml|[^;]+\+(?:json|xml))$/.test(mime)) return true;
  // Some text assets are served without a MIME type by existing targets.
  const path = String(req.originalUrl || req.url || "").split("?", 1)[0];
  return !mime && /\.(?:html?|[cm]?js|css|json|txt|xml|svg)$/i.test(path);
}

function decodeBody(raw, encoding, maxResponseBodyBytes) {
  if (encoding === "identity") return raw;
  const options = { maxOutputLength: maxResponseBodyBytes };
  try {
    if (encoding === "gzip") return zlib.gunzipSync(raw, options);
    if (encoding === "br") return zlib.brotliDecompressSync(raw, options);
    return zlib.inflateSync(raw, options);
  } catch (_) {
    // An oversized or malformed compressed response is safer to relay as its
    // original bytes and encoding than to replace with a proxy-generated body.
    return null;
  }
}

function cookies(value) {
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

function copyResponseHeaders(proxyRes, res, { rawBody, dropContentLength = false, bodyChanged = false }) {
  res.statusCode = proxyRes.statusCode;
  if (proxyRes.statusMessage) res.statusMessage = proxyRes.statusMessage;
  const nominatedHopHeaders = new Set(String(proxyRes.headers.connection || "")
    .split(",").map((name) => name.trim().toLowerCase()).filter(Boolean));
  for (const [key, value] of Object.entries(proxyRes.headers)) {
    // The Detection middleware minted this correlation ID before the proxy
    // request. A target response must not replace it.
    if (key === "x-ruby-request-id" && res.hasHeader(key)) continue;
    if (HOP_BY_HOP_RESPONSE_HEADERS.has(key) || nominatedHopHeaders.has(key) ||
        (key === "content-length" && (!rawBody || dropContentLength)) ||
        (key === "content-encoding" && !rawBody) ||
        (bodyChanged && ["etag", "content-md5", "digest", "accept-ranges"].includes(key))) continue;
    if (key === "set-cookie") {
      // Detection may already have set dlsid/dcid. Keep both sets, as the
      // previous interceptor also removed upstream Domain attributes.
      // The Detection session/identity cookie names are reserved on this
      // origin. A target cookie with either name would overwrite the issued
      // value in the browser and break policy continuity.
      const upstream = cookies(value)
        .filter((cookie) => !DETECTION_COOKIE_NAMES.has(String(cookie).split("=", 1)[0].trim().toLowerCase()))
        .map((cookie) => cookie.replace(/;\s*Domain=[^;]*/ig, ""));
      res.setHeader(key, [...cookies(res.getHeader(key)), ...upstream]);
    } else if (value !== undefined) {
      res.setHeader(key, value);
    }
  }
  if (!rawBody) {
    res.removeHeader("content-length");
    res.removeHeader("content-encoding");
  } else if (dropContentLength) {
    res.removeHeader("content-length");
  }
}

function writeWithBackpressure(res, chunk) {
  if (res.destroyed) return Promise.reject(new Error("downstream connection closed"));
  if (res.write(chunk)) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      res.off("drain", onDrain);
      res.off("close", onClose);
      res.off("error", onError);
    };
    const onDrain = () => { cleanup(); resolve(); };
    const onClose = () => { cleanup(); reject(new Error("downstream connection closed")); };
    const onError = (error) => { cleanup(); reject(error); };
    res.once("drain", onDrain);
    res.once("close", onClose);
    res.once("error", onError);
  });
}

function closeFailedResponse(res) {
  if (!res || res.destroyed || res.writableEnded) return;
  if (typeof res.writeHead !== "function") {
    res.destroy?.();
  } else if (res.headersSent) {
    res.destroy();
  } else {
    for (const header of ["content-length", "content-encoding", "transfer-encoding",
      "content-range", "content-type", "etag", "content-md5", "digest", "accept-ranges"]) {
      res.removeHeader(header);
    }
    res.writeHead(502);
    res.end();
  }
}

/**
 * Small inspectable responses may be transformed. SSE, binary, ranges and
 * oversized responses stream unchanged. Streamed onResponse hooks receive
 * bodyAvailable=false and an empty buffer; onResponseError receives the bytes
 * observed before failure. Both paths preserve request/response correlation.
 */
function createProxyCore({
  target, hooks = [], changeOrigin = true,
  maxResponseBodyBytes = DEFAULT_MAX_RESPONSE_BODY_BYTES,
  maxInspectionWaitMs = 250,
}) {
  if (!target) throw new Error("proxy target is required");
  const hookList = normalizedHooks(hooks);
  const maxBytes = responseLimit(maxResponseBodyBytes);
  const maxWaitMs = inspectionWait(maxInspectionWaitMs);
  const requestStates = new WeakMap();
  const stateFor = (req) => {
    if (!requestStates.has(req)) requestStates.set(req, { terminal: null, responseBodyBytes: 0, proxyRes: null });
    return requestStates.get(req);
  };

  async function reportError(req, res, error) {
    const state = stateFor(req);
    if (state.terminal) return;
    state.terminal = "error";
    // A slow monitoring hook must not hold an error response open.
    closeFailedResponse(res);
    try {
      await runResponseErrorHooks(hookList, {
        req, proxyRes: state.proxyRes, res, error,
        responseBodyBytes: state.responseBodyBytes, target,
      });
    } catch (_) {
      // A monitoring hook must not leave the client response open.
    }
  }

  async function handleProxyResponse(proxyRes, req, res) {
    const state = stateFor(req);
    state.proxyRes = proxyRes;
    let streaming = !shouldInspectBody(proxyRes, req, maxBytes);
    let responseHeadersCopied = false;
    let buffered = [];
    let timerFlush = null;
    const startStreaming = (dropContentLength = false) => {
      if (responseHeadersCopied) return;
      copyResponseHeaders(proxyRes, res, { rawBody: true, dropContentLength });
      responseHeadersCopied = true;
    };
    const switchToStreaming = async (dropContentLength = false) => {
      if (streaming) return;
      streaming = true;
      startStreaming(dropContentLength);
      const held = buffered;
      buffered = [];
      for (const chunk of held) await writeWithBackpressure(res, chunk);
    };
    const inspectionTimer = streaming ? null : setTimeout(() => {
      if (!streaming) {
        timerFlush = switchToStreaming();
        timerFlush.catch((error) => proxyRes.destroy(error));
      }
    }, maxWaitMs);
    const abortOnClientClose = () => {
      if (!res.writableEnded) proxyRes.destroy(new Error("downstream connection closed"));
    };
    res.once("close", abortOnClientClose);
    try {
      for await (const part of proxyRes) {
        if (timerFlush) await timerFlush;
        const chunk = Buffer.isBuffer(part) ? part : Buffer.from(part);
        state.responseBodyBytes += chunk.length;
        if (!streaming && state.responseBodyBytes > maxBytes) {
          await switchToStreaming(true);
        }
        if (streaming) {
          startStreaming();
          await writeWithBackpressure(res, chunk);
        }
        else buffered.push(chunk);
      }
      if (inspectionTimer) clearTimeout(inspectionTimer);
      if (timerFlush) await timerFlush;

      if (!streaming) {
        const raw = Buffer.concat(buffered, state.responseBodyBytes);
        const decoded = decodeBody(raw, contentEncoding(proxyRes.headers), maxBytes);
        if (decoded === null) {
          streaming = true;
          startStreaming();
          await writeWithBackpressure(res, raw);
        } else {
          copyResponseHeaders(proxyRes, res, { rawBody: false });
          const responseBuffer = await runResponseHooks(hookList, {
            responseBuffer: decoded, bodyAvailable: true,
            responseBodyBytes: state.responseBodyBytes, proxyRes, req, res, target,
          });
          if (!decoded.equals(responseBuffer) || contentEncoding(proxyRes.headers) !== "identity") {
            for (const name of ["etag", "content-md5", "digest", "accept-ranges"]) res.removeHeader(name);
          }
          res.setHeader("content-length", responseBuffer.length);
          res.end(responseBuffer);
          state.terminal = "success";
        }
      }
      if (streaming) {
        startStreaming();
        await runResponseHooks(hookList, {
          responseBuffer: Buffer.alloc(0), bodyAvailable: false,
          responseBodyBytes: state.responseBodyBytes, proxyRes, req, res, target,
        });
        if (!res.writableEnded) res.end();
        state.terminal = "success";
      }
    } catch (error) {
      await reportError(req, res, error);
    } finally {
      if (inspectionTimer) clearTimeout(inspectionTimer);
      res.off("close", abortOnClientClose);
    }
  }

  const proxy = httpProxy.createProxyServer({ target, changeOrigin, selfHandleResponse: true });
  proxy.on("proxyReq", (proxyReq, req, res) => {
    applyForwardedHeaders(proxyReq, req);
    runRequestHooks(hookList, { proxyReq, req, res, target });
  });
  proxy.on("proxyReqWs", (proxyReq, req, socket) => {
    applyForwardedHeaders(proxyReq, req);
    runWebSocketHooks(hookList, { proxyReq, req, res: socket, target });
  });
  proxy.on("proxyRes", (proxyRes, req, res) => {
    void handleProxyResponse(proxyRes, req, res);
  });
  const middleware = (req, res) => proxy.web(req, res, { target }, error => {
    void reportError(req, res, error);
  });
  middleware.upgrade = (req, socket, head) => proxy.ws(req, socket, head, { target }, error => {
    void reportError(req, socket, error);
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
