const fs = require("node:fs");
const crypto = require("node:crypto");

const PATH_RE = /^\/(?!__detection(?:\/|$)|__defense(?:\/|$))[A-Za-z0-9/_:.-]*$/;
const METHOD_RE = /^(GET|POST|PUT|PATCH|DELETE|HEAD)$/;
const FIELD_RE = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;
const MAX_PROFILE_BYTES = 64 * 1024;

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function keysOnly(value, allowed, label) {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw new Error(`${label}.${key} is not supported`);
  }
}

function route(value, label, { account = false, permission = false } = {}) {
  if (!plainObject(value)) throw new Error(`${label} must be an object`);
  keysOnly(value, account ? ["method", "path", "accountField", "failureStatuses"]
    : permission ? ["method", "path", "requiredRoles"] : ["method", "path"], label);
  if (!METHOD_RE.test(value.method) || !PATH_RE.test(value.path) || value.path.length > 256) {
    throw new Error(`${label} must contain a valid method and path`);
  }
  if (account) {
    if (!FIELD_RE.test(value.accountField)) throw new Error(`${label}.accountField is invalid`);
    if (value.failureStatuses !== undefined && (
      !Array.isArray(value.failureStatuses) || !value.failureStatuses.length ||
      value.failureStatuses.some((status) => !Number.isInteger(status) || status < 400 || status > 499)
    )) throw new Error(`${label}.failureStatuses must be HTTP 4xx codes`);
  }
  return value;
}

function pathList(value, label) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 32 ||
      value.some((path) => typeof path !== "string" || path.length > 256 || !PATH_RE.test(path))) {
    throw new Error(`${label} must be a list of at most 32 paths`);
  }
  return [...new Set(value)];
}

function parseTargetProfile(value) {
  if (!plainObject(value)) throw new Error("target profile must be an object");
  keysOnly(value, ["version", "routes", "permissions", "bait"], "target profile");
  if (value.version !== 1) throw new Error("target profile version must be 1");
  const routes = value.routes ?? {};
  if (!plainObject(routes)) throw new Error("routes must be an object");
  keysOnly(routes, ["login", "passwordReset", "securityQuestion"], "routes");
  const parsedRoutes = {};
  for (const [name, definition] of Object.entries(routes)) {
    parsedRoutes[name] = route(definition, `routes.${name}`, { account: true });
  }

  const permissions = value.permissions ?? [];
  if (!Array.isArray(permissions) || permissions.length > 64) {
    throw new Error("permissions must be a list of at most 64 routes");
  }
  const parsedPermissions = permissions.map((definition, index) => {
    const label = `permissions[${index}]`;
    route(definition, label, { permission: true });
    if (!Array.isArray(definition.requiredRoles) || !definition.requiredRoles.length ||
        definition.requiredRoles.length > 16 ||
        definition.requiredRoles.some((role) => !FIELD_RE.test(role))) {
      throw new Error(`${label}.requiredRoles must be a nonempty role list`);
    }
    return {
      method: definition.method,
      normalizedPath: definition.path,
      tag: "role-gated:target-profile",
      requiredRoles: new Set(definition.requiredRoles.map((role) => role.toLowerCase())),
    };
  });

  const bait = value.bait ?? {};
  if (!plainObject(bait)) throw new Error("bait must be an object");
  keysOnly(bait, ["traps", "htmlPaths", "plaintextPaths"], "bait");
  const traps = bait.traps ?? [];
  if (!Array.isArray(traps) || traps.length > 32) throw new Error("bait.traps must be a list of at most 32 routes");
  const parsedTraps = traps.map((definition, index) => {
    const label = `bait.traps[${index}]`;
    if (!plainObject(definition)) throw new Error(`${label} must be an object`);
    keysOnly(definition, ["method", "path", "status", "contentType", "body"], label);
    if (!METHOD_RE.test(definition.method) || !PATH_RE.test(definition.path) || definition.path.length > 256 ||
        !Number.isInteger(definition.status) || definition.status < 200 || definition.status > 599 ||
        typeof definition.body !== "string" || Buffer.byteLength(definition.body) > 2048 ||
        !["text/plain", "application/json"].includes(definition.contentType)) {
      throw new Error(`${label} has an invalid method, path, status, content type or body`);
    }
    return definition;
  });
  const routeKeys = new Set();
  for (const trap of parsedTraps) {
    const key = `${trap.method} ${trap.path}`;
    if (routeKeys.has(key)) throw new Error(`duplicate bait trap ${key}`);
    routeKeys.add(key);
  }

  return {
    version: 1,
    routes: parsedRoutes,
    permissions: parsedPermissions,
    bait: {
      traps: parsedTraps,
      htmlPaths: pathList(bait.htmlPaths, "bait.htmlPaths"),
      plaintextPaths: pathList(bait.plaintextPaths, "bait.plaintextPaths"),
    },
  };
}

function loadTargetProfile(file = process.env.TARGET_PROFILE_FILE) {
  if (!file) return null;
  const stats = fs.statSync(file);
  if (stats.size > MAX_PROFILE_BYTES) throw new Error("target profile exceeds 64 KiB");
  return parseTargetProfile(JSON.parse(fs.readFileSync(file, "utf8")));
}

function matchProfileTrap(profile, method, path) {
  return profile?.bait.traps.find((trap) => trap.method === method && trap.path === path) || null;
}

function injectProfileBait(profile, body, path, contentType) {
  if (!profile) return body;
  const html = String(contentType || "").includes("text/html") && profile.bait.htmlPaths.includes(path);
  const plaintext = String(contentType || "").includes("text/plain") && profile.bait.plaintextPaths.includes(path);
  if (!html && !plaintext) return body;
  const links = profile.bait.traps.filter((trap) => trap.method === "GET").map((trap) => trap.path);
  if (!links.length) return body;
  const source = String(body);
  if (html) {
    const hints = links.map((link) => `<a href="${link}" hidden rel="nofollow">System status</a>`).join("\n");
    return source.includes("</body>") ? source.replace("</body>", `${hints}</body>`) : `${source}\n${hints}`;
  }
  return `${source}\n${links.map((link) => `# System status: ${link}`).join("\n")}\n`;
}

function profileTrapEvent(sessionId, now = Date.now()) {
  return {
    eventId: crypto.randomUUID(), signal: "trap_trigger", evidenceLevel: "supporting",
    scored: true, originSessionId: sessionId, occurredAt: now,
    detail: "설정된 대상 미끼 경로 접근",
  };
}

module.exports = { loadTargetProfile, parseTargetProfile, matchProfileTrap, injectProfileBait, profileTrapEvent };
