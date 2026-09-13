const { spawn } = require("node:child_process");
const { randomUUID } = require("node:crypto");
const readline = require("node:readline");

const EMPTY_RESULT = Object.freeze({
  available: false,
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
      ? maximumBodyBytes
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
    pending.resolve({ ...EMPTY_RESULT, ...result });
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
    const body = requestBodyBuffer(req, this.maximumBodyBytes);
    const payload = {
      id,
      method: req.method,
      uri: req.originalUrl || req.url || "/",
      protocol: req.httpVersion || "1.1",
      clientIp: clientIp || "127.0.0.1",
      headers: normalizeHeaderValues(req.headers),
      bodyBase64: body ? body.toString("base64") : "",
      bodyTruncated: Buffer.isBuffer(req.detectionRequestBodyBuffer)
        ? req.detectionRequestBodyBuffer.length > this.maximumBodyBytes
        : false,
    };

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        resolve(unavailableResult(`CRS scan timed out after ${this.timeoutMs}ms`));
      }, this.timeoutMs);
      this.pending.set(id, { resolve, timer });
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
  normalizeHeaderValues,
  requestBodyBuffer,
};
