const crypto = require("crypto");
const path = require("path");

class InvalidCredentialsError extends Error {}

class LoginRateLimitedError extends Error {
  constructor(retryAfterSeconds) {
    super("too many login attempts");
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

class DashboardAuthManager {
  constructor({
    password = "",
    sessionTtlMs = 12 * 60 * 60 * 1000,
    maxSessions = 1000,
    maxAttempts = 5,
    attemptWindowMs = 5 * 60 * 1000,
    maxFailureClients = maxSessions * 2,
    now = Date.now,
    randomBytes = crypto.randomBytes,
  } = {}) {
    this.passwordDigest = crypto.createHash("sha256").update(String(password)).digest();
    this.enabled = Boolean(password);
    this.sessionTtlMs = Math.max(60_000, sessionTtlMs);
    this.maxSessions = Math.max(1, maxSessions);
    this.maxAttempts = Math.max(1, maxAttempts);
    this.attemptWindowMs = Math.max(1000, attemptWindowMs);
    this.maxFailureClients = Math.max(1, maxFailureClients);
    this.now = now;
    this.randomBytes = randomBytes;
    this.sessions = new Map();
    this.failures = new Map();
  }

  cleanup(timestamp = this.now()) {
    for (const [token, expiresAt] of this.sessions) {
      if (expiresAt <= timestamp) this.sessions.delete(token);
    }

    const cutoff = timestamp - this.attemptWindowMs;
    for (const [clientKey, attempts] of this.failures) {
      const active = attempts.filter((attemptedAt) => attemptedAt > cutoff);
      if (active.length) this.failures.set(clientKey, active);
      else this.failures.delete(clientKey);
    }
  }

  isAuthenticated(token) {
    if (!this.enabled) return true;
    const timestamp = this.now();
    this.cleanup(timestamp);
    return Boolean(token && (this.sessions.get(token) || 0) > timestamp);
  }

  login(password, clientKey = "unknown") {
    if (!this.enabled) return null;
    const timestamp = this.now();
    this.cleanup(timestamp);
    const key = clientKey || "unknown";
    const attempts = this.failures.get(key) || [];
    if (attempts.length >= this.maxAttempts) {
      const retryAfterSeconds = Math.max(
        1,
        Math.ceil((attempts[0] + this.attemptWindowMs - timestamp) / 1000)
      );
      throw new LoginRateLimitedError(retryAfterSeconds);
    }

    const candidate = crypto.createHash("sha256").update(String(password || "")).digest();
    if (!crypto.timingSafeEqual(candidate, this.passwordDigest)) {
      while (!this.failures.has(key) && this.failures.size >= this.maxFailureClients) {
        this.failures.delete(this.failures.keys().next().value);
      }
      attempts.push(timestamp);
      this.failures.set(key, attempts);
      throw new InvalidCredentialsError("invalid password");
    }

    this.failures.delete(key);
    while (this.sessions.size >= this.maxSessions) {
      const oldest = [...this.sessions.entries()].sort((left, right) => left[1] - right[1])[0];
      this.sessions.delete(oldest[0]);
    }
    const token = this.randomBytes(32).toString("base64url");
    this.sessions.set(token, timestamp + this.sessionTtlMs);
    return token;
  }

  logout(token) {
    if (token) this.sessions.delete(token);
  }
}

function installDashboardRoutes({
  app,
  authManager,
  cookieName = "detection_dashboard_session",
  sessionTtlMs = 12 * 60 * 60 * 1000,
  secureCookie = false,
  requireHttps = false,
  publicDirectory = path.join(__dirname, "..", "public"),
}) {
  const sessionToken = (req) => req.cookies[cookieName] || "";
  const requireAuth = (req, res, next) => {
    if (authManager.isAuthenticated(sessionToken(req))) return next();
    return res.status(401).json({ error: "dashboard authentication required" });
  };

  app.get("/__detection/static/telemetry.js", (_req, res) => {
    res.sendFile(path.join(publicDirectory, "telemetry.js"));
  });

  app.get("/__detection/api/auth/status", (req, res) => {
    res.json({
      enabled: authManager.enabled,
      authenticated: authManager.isAuthenticated(sessionToken(req)),
      httpsRequired: requireHttps,
    });
  });

  app.post("/__detection/api/login", (req, res) => {
    if (requireHttps && !req.secure) {
      return res.status(426).json({ error: "dashboard login requires HTTPS" });
    }
    try {
      const token = authManager.login(req.body?.password, req.ip || "unknown");
      if (token) {
        res.cookie(cookieName, token, {
          httpOnly: true,
          sameSite: "strict",
          secure: secureCookie,
          maxAge: sessionTtlMs,
          path: "/__detection",
        });
      }
      return res.status(204).end();
    } catch (error) {
      if (error instanceof LoginRateLimitedError) {
        res.setHeader("Retry-After", String(error.retryAfterSeconds));
        return res.status(429).json({ error: "too many login attempts" });
      }
      if (error instanceof InvalidCredentialsError) {
        return res.status(401).json({ error: "invalid password" });
      }
      throw error;
    }
  });

  app.post("/__detection/api/logout", (req, res) => {
    authManager.logout(sessionToken(req));
    res.clearCookie(cookieName, { path: "/__detection" });
    res.status(204).end();
  });

  app.use("/__detection/api", requireAuth);

  app.get("/__detection/login", (req, res) => {
    if (authManager.isAuthenticated(sessionToken(req))) {
      return res.redirect(302, "/__detection/dashboard");
    }
    return res.sendFile(path.join(publicDirectory, "login.html"));
  });

  app.get("/__detection/dashboard", (req, res) => {
    if (!authManager.isAuthenticated(sessionToken(req))) {
      return res.redirect(302, "/__detection/login");
    }
    return res.sendFile(path.join(publicDirectory, "dashboard.html"));
  });
}

module.exports = {
  DashboardAuthManager,
  InvalidCredentialsError,
  LoginRateLimitedError,
  installDashboardRoutes,
};
