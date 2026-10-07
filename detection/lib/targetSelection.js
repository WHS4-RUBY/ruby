"use strict";

const crypto = require("crypto");
const fs = require("fs");
const net = require("net");
const os = require("os");
const path = require("path");

const TARGET_ID = /^[a-z][a-z0-9-]{0,31}$/;
const LABELS = {
  legacy: "기본 대상",
  "ruby-shop": "RUBY Market",
  "juice-shop": "OWASP Juice Shop",
};

function parseTargetChoices(raw, fallbackUrl) {
  const entries = raw
    ? String(raw).split(",").map((part) => part.trim()).filter(Boolean)
    : [`legacy=${fallbackUrl}`];
  const choices = new Map();
  for (const entry of entries) {
    const separator = entry.indexOf("=");
    const id = entry.slice(0, separator);
    const rawUrl = entry.slice(separator + 1);
    if (separator < 1 || !TARGET_ID.test(id) || choices.has(id)) {
      throw new Error(`invalid or duplicate target ID: ${id}`);
    }
    let url;
    try { url = new URL(rawUrl); } catch { throw new Error(`invalid target URL for ${id}`); }
    if (!["http:", "https:"].includes(url.protocol) || !url.hostname ||
        url.username || url.password || url.search || url.hash) {
      throw new Error(`invalid target URL for ${id}`);
    }
    choices.set(id, {
      id,
      label: LABELS[id] || id,
      url: url.toString().replace(/\/$/, ""),
    });
  }
  if (!choices.size) throw new Error("at least one target is required");
  return choices;
}

function validateSelection(value, choices) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      !choices.has(value.targetId) ||
      typeof value.runId !== "string" || !/^[a-zA-Z0-9:-]{1,100}$/.test(value.runId) ||
      typeof value.changedAt !== "string" || !Number.isFinite(Date.parse(value.changedAt))) {
    throw new Error("invalid target selection state");
  }
  return {
    targetId: value.targetId,
    runId: value.runId,
    changedAt: value.changedAt,
  };
}

function parsePublicOrigin(value) {
  if (!value) return null;
  let url;
  try { url = new URL(value); } catch { throw new Error("invalid public target origin"); }
  if (!["http:", "https:"].includes(url.protocol) || !url.hostname ||
      url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    throw new Error("invalid public target origin");
  }
  return url.origin;
}

class TargetSelectionStore {
  constructor({ choices, defaultId, filePath, publicOrigin = null }) {
    if (!choices.has(defaultId)) throw new Error(`unknown default target: ${defaultId}`);
    this.choices = choices;
    this.defaultId = defaultId;
    this.filePath = filePath || path.join(os.tmpdir(), `ruby-target-selection-${process.pid}.json`);
    this.publicOrigin = parsePublicOrigin(publicOrigin);
    if (!fs.existsSync(this.filePath)) {
      this._write({ targetId: defaultId, runId: crypto.randomUUID(), changedAt: new Date().toISOString() });
    }
    this.read();
  }

  read() {
    return validateSelection(JSON.parse(fs.readFileSync(this.filePath, "utf8")), this.choices);
  }

  _write(selection) {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const temporary = `${this.filePath}.${process.pid}.${crypto.randomUUID()}.tmp`;
    try {
      fs.writeFileSync(temporary, `${JSON.stringify(selection)}\n`, { mode: 0o600, flag: "wx" });
      fs.renameSync(temporary, this.filePath);
    } finally {
      try { fs.unlinkSync(temporary); } catch (error) { if (error.code !== "ENOENT") throw error; }
    }
  }

  select(targetId) {
    if (!this.choices.has(targetId)) throw new Error("unknown target ID");
    const selection = { targetId, runId: crypto.randomUUID(), changedAt: new Date().toISOString() };
    this._write(selection);
    return selection;
  }

  publicStatus() {
    return {
      active: this.read(),
      targets: [...this.choices.values()].map(({ id, label }) => ({ id, label })),
      protectedUrl: this.publicOrigin ? `${this.publicOrigin}/` : "/",
    };
  }
}

function checkTargetReachable(target, timeoutMs = 2000) {
  const url = new URL(target.url);
  const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: url.hostname, port });
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => { socket.destroy(); resolve(); });
    socket.once("timeout", () => { socket.destroy(); reject(new Error("target connection timed out")); });
    socket.once("error", (error) => { socket.destroy(); reject(error); });
  });
}

module.exports = { TargetSelectionStore, checkTargetReachable, parsePublicOrigin, parseTargetChoices, validateSelection };
