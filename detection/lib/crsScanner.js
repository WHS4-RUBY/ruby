const { spawn } = require("node:child_process");
const { randomUUID } = require("node:crypto");
const readline = require("node:readline");
const { TextDecoder } = require("node:util");

const EMPTY_RESULT = Object.freeze({
  available: false,
  inspectionComplete: false,
  engine: "owasp-modsecurity",
  crsVersion: null,
  anomalyScore: 0,
  ruleHitCount: 0,
  categories: [],
  hits: [],
});

// CRS 규칙 평가에 필요하지 않은 자격 증명 원문은 helper 프로세스로 넘기지 않는다.
const SENSITIVE_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-experiment-run-id",
]);

function unavailableResult(error) {
  return {
    ...EMPTY_RESULT,
    error: error instanceof Error ? error.message : String(error || "scanner unavailable"),
  };
}

function normalizeHeaderValues(headers = {}) {
  return Object.fromEntries(
    Object.entries(headers).flatMap(([name, value]) => {
      if (SENSITIVE_HEADERS.has(String(name).toLowerCase())) return [];
      if (Array.isArray(value)) value = value.join(", ");
      if (value === undefined || value === null) return [];
      return [[String(name), String(value)]];
    })
  );
}

function requestBodyBuffer(req, maximumBytes) {
  const raw = req.detectionRequestBodyBuffer;
  if (!Buffer.isBuffer(raw) || raw.length === 0) return null;
  return raw.subarray(0, maximumBytes);
}

class CrsScanner {
  constructor({
    enabled = process.env.CRS_ENABLED !== "false",
    executable = process.env.MODSECURITY_SCANNER_PATH || "/app/bin/modsecurity-scanner",
    rulesFile = process.env.MODSECURITY_RULES_FILE || "/app/scanner/modsecurity.conf",
    timeoutMs = Number(process.env.CRS_SCAN_TIMEOUT_MS || 2000),
    maximumBodyBytes = Number(process.env.CRS_MAX_BODY_BYTES || 1_048_576),
    spawnProcess = spawn,
  } = {}) {
    this.enabled = enabled;
    this.executable = executable;
    this.rulesFile = rulesFile;
    this.timeoutMs = Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : 2000;
    this.maximumBodyBytes = Number.isSafeInteger(maximumBodyBytes) && maximumBodyBytes > 0
      ? Math.min(maximumBodyBytes, 1_048_576) // native scanner's configured hard limit
      : 1_048_576;
    this.spawnProcess = spawnProcess;
    this.pending = new Map();
    this.child = null;
    this.startError = null;
    if (this.enabled) this.start();
  }

  start() {
    if (this.child) return;
    try {
      const child = this.spawnProcess(this.executable, [this.rulesFile], {
        stdio: ["pipe", "pipe", "pipe"],
      });
      this.child = child;
      const output = readline.createInterface({ input: child.stdout });
      output.on("line", (line) => this.handleLine(line));
      child.stderr.on("data", (chunk) => {
        const message = String(chunk).trim();
        if (message) this.startError = message.slice(0, 500);
      });
      child.on("error", (error) => {
        if (this.child === child) this.child = null;
        this.failAll(error);
      });
      child.on("exit", (code, signal) => {
        if (this.child === child) this.child = null;
        this.failAll(new Error(`ModSecurity scanner exited code=${code} signal=${signal || "none"}`));
      });
    } catch (error) {
      this.startError = error.message;
      this.child = null;
    }
  }

  failAll(error) {
    this.startError = error.message;
    for (const { resolve, timer } of this.pending.values()) {
      clearTimeout(timer);
      resolve(unavailableResult(error));
    }
    this.pending.clear();
  }

  handleLine(line) {
    let result;
    try {
      result = JSON.parse(line);
    } catch {
      return;
    }
    const pending = this.pending.get(result.id);
    if (!pending) return;
    clearTimeout(pending.timer);
    this.pending.delete(result.id);
    pending.resolve({ ...EMPTY_RESULT, ...result,
      bodyTruncated: pending.bodyTruncated,
      inspectionBodyMode: pending.inspectionBodyMode,
      inspectionComplete: result.available === true && !pending.bodyTruncated
        && result.inspectionComplete === true,
    });
  }

  scan(req, clientIp) {
    if (!this.enabled) return Promise.resolve(unavailableResult("CRS disabled"));
    if (!this.child || !this.child.stdin.writable) {
      if (!this.child) this.start();
      if (!this.child || !this.child.stdin.writable) {
        return Promise.resolve(unavailableResult(this.startError || "scanner not running"));
      }
    }

    const id = randomUUID();
    let body = req.detectionRequestBodyBuffer;
    const headers = normalizeHeaderValues(req.headers);
    const type = String(req.headers["content-type"] || "").split(";", 1)[0].trim().toLowerCase();
    let inspectionBodyMode = "native";
    if (type === "text/plain" && Buffer.isBuffer(body) && body.length) {
      // CRS inspects ARGS; plain text otherwise has no body processor. Inspect
      // the entire UTF-8 text as a JSON string, but forward the original bytes.
      // This is content inspection, not an Engine.IO/Socket.IO protocol parser.
      try {
        body = Buffer.from(JSON.stringify({ ruby_raw_body: new TextDecoder("utf-8", { fatal: true }).decode(body) }));
      } catch {
        return Promise.resolve({ ...unavailableResult("Invalid UTF-8 body"), inspectionIssue: "unsupported_body_encoding" });
      }
      headers["content-type"] = "application/json";
      headers["content-length"] = String(body.length);
      inspectionBodyMode = "text_as_json_string";
    }
    const bodyTruncated = Buffer.isBuffer(body) && body.length > this.maximumBodyBytes;
    const payload = {
      id,
      method: req.method,
      uri: req.originalUrl || req.url || "/",
      protocol: req.httpVersion || "1.1",
      clientIp: clientIp || "127.0.0.1",
      headers,
      bodyBase64: Buffer.isBuffer(body) ? body.subarray(0, this.maximumBodyBytes).toString("base64") : "",
      bodyTruncated,
    };

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        resolve(unavailableResult(`CRS scan timed out after ${this.timeoutMs}ms`));
      }, this.timeoutMs);
      this.pending.set(id, { resolve, timer, bodyTruncated, inspectionBodyMode });
      this.child.stdin.write(`${JSON.stringify(payload)}\n`, (error) => {
        if (!error) return;
        clearTimeout(timer);
        this.pending.delete(id);
        resolve(unavailableResult(error));
      });
    });
  }

  status() {
    return {
      enabled: this.enabled,
      running: Boolean(this.child),
      error: this.startError,
    };
  }
}

module.exports = {
  CrsScanner,
  EMPTY_RESULT,
  unavailableResult,
  normalizeHeaderValues,
  requestBodyBuffer,
};
