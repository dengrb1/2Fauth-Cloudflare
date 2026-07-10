import assert from "node:assert/strict";
import { pbkdf2Sync } from "node:crypto";
import test from "node:test";

import worker from "../src/worker.js";
import { CLIENT_SCRIPT } from "../src/ui/client.js";

const TEST_ENV = {
  ENCRYPTION_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  SESSION_PEPPER: "test-pepper",
  CORS_ALLOWED_ORIGINS: "chrome-extension://abc123",
};

function envWithDb(db) {
  return { ...TEST_ENV, DB: db };
}

function ctx() {
  return { waitUntil() {} };
}

function emptyDb() {
  return {
    prepare() {
      throw new Error("DB should not be queried");
    },
  };
}

function apiSessionDb(state = {}) {
  return {
    prepare(sql) {
      const statement = {
        bind(...args) {
          state.binds = state.binds || [];
          state.binds.push({ sql, args });
          return statement;
        },
        async first() {
          if (sql.includes("FROM api_sessions")) {
            return {
              session_id: 7,
              client_type: "android",
              last_used_at: state.lastUsedAt,
              id: 3,
              username: "alice",
              role: "user",
            };
          }
          return null;
        },
        async run() {
          state.runs = state.runs || [];
          state.runs.push(sql);
          return { meta: { changes: 1 } };
        },
        async all() {
          return { results: [] };
        },
      };
      return statement;
    },
  };
}

function webAppDataDb(state = {}) {
  return {
    prepare(sql) {
      const statement = {
        bind(...args) {
          state.binds = state.binds || [];
          state.binds.push({ sql, args });
          return statement;
        },
        async first() {
          if (sql.includes("FROM login_risk_control")) return null;
          if (sql.includes("FROM sessions")) {
            return { id: 1, username: "admin", role: "admin" };
          }
          return null;
        },
        async run() {
          state.runs = state.runs || [];
          state.runs.push(sql);
          return { meta: { changes: 1 } };
        },
        async all() {
          if (sql.includes("FROM totp_entries")) {
            return {
              results: [
                {
                  id: 11,
                  user_id: 1,
                  username: "admin",
                  label: "Email",
                  issuer: "Example",
                  digits: 6,
                  period: 30,
                  algorithm: "SHA-256",
                  otp_type: "totp",
                  hotp_counter: 0,
                  enabled: 1,
                  group_id: null,
                  group_name: null,
                  group_color: null,
                  created_at: "2026-01-01T00:00:00.000Z",
                },
              ],
            };
          }
          if (sql.includes("FROM groups")) {
            return {
              results: [
                {
                  id: 5,
                  user_id: 1,
                  username: "admin",
                  name: "Work",
                  color: "#0f766e",
                  created_at: "2026-01-01T00:00:00.000Z",
                },
              ],
            };
          }
          return { results: [] };
        },
      };
      return statement;
    },
  };
}

function loginRiskDb(state = {}) {
  return {
    prepare(sql) {
      const statement = {
        bind(...args) {
          state.binds = state.binds || [];
          state.binds.push({ sql, args });
          return statement;
        },
        async first() {
          if (sql.includes("FROM login_risk_control")) return null;
          throw new Error(`Unexpected first() query: ${sql}`);
        },
        async run() {
          state.runs = state.runs || [];
          state.runs.push(sql);
          return { meta: { changes: 1 } };
        },
        async all() {
          if (sql.includes("FROM app_settings")) return { results: [] };
          throw new Error(`Unexpected all() query: ${sql}`);
        },
      };
      return statement;
    },
  };
}

function passwordHash(password, saltB64, iterations = 100_000) {
  return pbkdf2Sync(password, Buffer.from(saltB64, "base64"), iterations, 32, "sha256").toString("base64");
}

function legacyWebLoginDb(state = {}, userOverrides = {}) {
  const saltB64 = "AQIDBAUGBwgJCgsMDQ4PEA==";
  const user = {
    id: 1,
    username: "admin",
    role: "admin",
    password_salt: saltB64,
    password_hash: passwordHash("correct horse battery", saltB64),
    ...userOverrides,
  };
  return {
    prepare(sql) {
      const statement = {
        args: [],
        bind(...args) {
          statement.args = args;
          state.binds = state.binds || [];
          state.binds.push({ sql, args });
          return statement;
        },
        async first() {
          if (sql.includes("FROM login_risk_control")) throw new Error("no such table: login_risk_control");
          if (sql.includes("FROM users WHERE username = ?")) return user;
          if (sql.includes("SELECT id FROM sessions WHERE token_hash = ?")) return { id: 10 };
          return null;
        },
        async run() {
          state.runs = state.runs || [];
          state.runs.push(sql);
          if (sql.includes("api_sessions")) throw new Error("no such table: api_sessions");
          if (sql.includes("INSERT INTO sessions") && sql.includes("client_type")) {
            throw new Error("table sessions has no column named client_type");
          }
          return { meta: { changes: 1, last_row_id: sql.includes("INSERT INTO sessions") ? 10 : undefined } };
        },
        async all() {
          if (sql.includes("FROM app_settings")) throw new Error("no such table: app_settings");
          return { results: [] };
        },
      };
      return statement;
    },
  };
}

function refreshDb(clientType, changes = 1) {
  return {
    prepare(sql) {
      const statement = {
        bind() {
          return statement;
        },
        async first() {
          if (sql.includes("FROM api_sessions")) {
            return {
              id: 9,
              client_type: clientType,
              user_id: 3,
              username: "alice",
              role: "user",
            };
          }
          return null;
        },
        async run() {
          return { meta: { changes } };
        },
      };
      return statement;
    },
  };
}

function loginRateLimitPassThroughDb(user, state = {}) {
  return {
    prepare(sql) {
      const statement = {
        bind(...args) {
          state.binds = state.binds || [];
          state.binds.push({ sql, args });
          return statement;
        },
        async first() {
          if (sql.includes("FROM login_risk_control")) return null;
          if (sql.includes("FROM users WHERE username = ?")) return user;
          if (sql.includes("SELECT id FROM api_sessions WHERE token_hash = ?")) return { id: 42 };
          if (sql.includes("SELECT id FROM sessions WHERE token_hash = ?")) return { id: 10 };
          return null;
        },
        async run() {
          state.runs = state.runs || [];
          state.runs.push(sql);
          return { meta: { changes: 1, last_row_id: sql.includes("INSERT INTO sessions") ? 10 : undefined } };
        },
        async all() {
          if (sql.includes("FROM app_settings")) return { results: [] };
          return { results: [] };
        },
      };
      return statement;
    },
  };
}

function adminSessionDb(handler = {}) {
  const state = { inserts: 0, updates: 0, deletes: 0 };
  const saltB64 = "AQIDBAUGBwgJCgsMDQ4PEA==";
  const adminPassword = "correct horse battery";
  const adminPasswordHash = passwordHash(adminPassword, saltB64);
  const db = {
    state,
    prepare(sql) {
      const statement = {
        args: [],
        bind(...args) {
          statement.args = args;
          return statement;
        },
        async first() {
          if (sql.includes("FROM api_sessions")) {
            return {
              session_id: 7,
              client_type: state.apiClientType || "android",
              id: 1,
              username: "admin",
              role: "admin",
            };
          }
          if (sql.includes("FROM sessions")) {
            return {
              session_id: 10,
              step_up_at: state.stepUpAt || null,
              id: 1,
              username: "admin",
              role: "admin",
            };
          }
          if (sql.includes("SELECT password_hash, password_salt FROM users WHERE id = ?")) {
            return { password_hash: adminPasswordHash, password_salt: saltB64 };
          }
          return handler.first ? handler.first(sql, statement.args, state) : null;
        },
        async run() {
          state.runs = state.runs || [];
          state.runs.push(sql);
          if (sql.startsWith("INSERT")) state.inserts += 1;
          if (sql.startsWith("UPDATE")) state.updates += 1;
          if (sql.startsWith("DELETE")) state.deletes += 1;
          if (sql.includes("UPDATE sessions SET step_up_at")) state.stepUpAt = statement.args[0];
          return handler.run ? handler.run(sql, statement.args, state) : { meta: { changes: 1 } };
        },
        async all() {
          return handler.all ? handler.all(sql, statement.args, state) : { results: [] };
        },
      };
      return statement;
    },
  };
  return db;
}

function entryCaptureDb(handler = {}) {
  return adminSessionDb({
    first(sql, args, state) {
      if (sql.includes("SELECT id FROM users WHERE id = ?")) return { id: args[0] };
      return handler.first ? handler.first(sql, args, state) : null;
    },
    run(sql, args, state) {
      if (sql.includes("INSERT INTO totp_entries")) {
        state.entryInserts = state.entryInserts || [];
        state.entryInserts.push(args);
        return { meta: { changes: 1, last_row_id: state.entryInserts.length } };
      }
      if (sql.includes("UPDATE totp_entries")) {
        state.entryUpdates = state.entryUpdates || [];
        state.entryUpdates.push(args);
      }
      return handler.run ? handler.run(sql, args, state) : { meta: { changes: 1 } };
    },
    all: handler.all,
  });
}

test("allows configured extension origin preflight", async () => {
  const request = new Request("https://example.com/api/v1/me", {
    method: "OPTIONS",
    headers: {
      Origin: "chrome-extension://abc123",
      "Access-Control-Request-Method": "GET",
    },
  });

  const response = await worker.fetch(request, envWithDb(emptyDb()), ctx());

  assert.equal(response.status, 204);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), "chrome-extension://abc123");
  assert.match(response.headers.get("Access-Control-Allow-Headers"), /Authorization/);
});

test("v1 capabilities exposes client contract metadata", async () => {
  const request = new Request("https://example.com/api/v1/capabilities", {
    headers: {
      Origin: "chrome-extension://abc123",
    },
  });

  const response = await worker.fetch(
    request,
    { ...envWithDb(emptyDb()), TURNSTILE_SECRET_KEY: "turnstile-secret" },
    ctx()
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.apiVersion, "v1");
  assert.deepEqual(body.compatibleClients, ["android", "browser_extension"]);
  assert.equal(body.auth.scheme, "Bearer");
  assert.equal(body.auth.turnstileRequired, true);
  assert.equal(body.auth.accessTokenExpiresIn, 604800);
  assert.equal(body.auth.refreshTokenRotation, true);
  assert.equal(body.endpoints.login, "/api/v1/auth/login");
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), "chrome-extension://abc123");
});

test("web UI responses include HTML security headers", async () => {
  const request = new Request("https://example.com/");

  const response = await worker.fetch(request, envWithDb(emptyDb()), ctx());

  assert.equal(response.status, 200);
  assert.match(response.headers.get("Content-Security-Policy"), /frame-ancestors 'none'/);
  assert.doesNotMatch(response.headers.get("Content-Security-Policy"), /unsafe-inline/);
  assert.match(response.headers.get("Content-Security-Policy"), /'nonce-[0-9a-f]{32}'/);
  assert.equal(response.headers.get("X-Frame-Options"), "DENY");
  assert.equal(response.headers.get("X-Content-Type-Options"), "nosniff");
  const html = await response.text();
  assert.match(html, /<title>2FAuth 验证器<\/title>/);
  assert.match(html, /<h1>2FAuth 验证器<\/h1>/);
  assert.doesNotMatch(html, /\?\/(?:title|h1)>/);
});

test("web UI renders the modern workspace shell and accessible dialogs", async () => {
  const response = await worker.fetch(new Request("https://example.com/"), envWithDb(emptyDb()), ctx());
  const html = await response.text();

  assert.match(html, /class="auth-card"/);
  assert.match(html, /class="sidebar"/);
  assert.match(html, /data-workspace="codes"/);
  assert.match(html, /data-workspace="groups"/);
  assert.match(html, /data-workspace="transfer"/);
  assert.match(html, /data-workspace="settings"/);
  assert.match(html, /id="adminNav" class="nav-item hidden"/);
  assert.match(html, /id="entryDialog"/);
  assert.match(html, /id="actionDialog"/);
  assert.match(html, /id="toastRegion"[^>]*aria-live="polite"/);
  assert.match(html, /prefers-reduced-motion/);
});

test("web UI includes Chinese and English copy without native business dialogs", async () => {
  const response = await worker.fetch(new Request("https://example.com/"), envWithDb(emptyDb()), ctx());
  const html = await response.text();

  assert.match(html, /安全验证码工作台/);
  assert.match(html, /Secure authenticator workspace/);
  assert.match(html, /Encrypted backup recommended/);
  assert.doesNotMatch(html, /\b(?:alert|confirm|prompt)\s*\(/);
});

test("web UI applies the generated nonce to inline style and script", async () => {
  const response = await worker.fetch(new Request("https://example.com/"), envWithDb(emptyDb()), ctx());
  const policy = response.headers.get("Content-Security-Policy");
  const nonce = policy.match(/'nonce-([0-9a-f]{32})'/)?.[1];
  const html = await response.text();

  assert.ok(nonce);
  assert.match(html, new RegExp(`<style nonce="${nonce}">`));
  assert.match(html, new RegExp(`<script nonce="${nonce}">`));
});

test("web UI client keeps authentication and form submission recovery paths", () => {
  assert.doesNotThrow(() => new Function("TURNSTILE_SITE_KEY", "PLAINTEXT_EXPORT_ENABLED", CLIENT_SCRIPT));
  assert.match(CLIENT_SCRIPT, /window\.turnstile\.reset\(turnstileWidgetId\)/);
  assert.match(CLIENT_SCRIPT, /turnstileToken = "";\s+throw error;/);
  assert.match(CLIENT_SCRIPT, /bootstrapForm: "bootstrap"/);
  assert.match(CLIENT_SCRIPT, /loginForm: "login"/);
  assert.match(CLIENT_SCRIPT, /entryForm: "save-entry"/);
  assert.match(CLIENT_SCRIPT, /groupForm: "create-group"/);
  assert.match(CLIENT_SCRIPT, /riskForm: "save-login-policy"/);
});

test("web UI camera scanner falls back when BarcodeDetector yields no code", () => {
  assert.match(CLIENT_SCRIPT, /if \(!raw\) \{\s+await ensureJsQrLoaded\(\);\s+detector = null;/);
  assert.match(CLIENT_SCRIPT, /setMessage\("scanMsg", t\("scanFallback"\)\);\s+raw = detectQrFromVideo\(video\);/);
});

test("wildcard CORS allowlist is ignored when credentials are enabled", async () => {
  const request = new Request("https://example.com/api/v1/me", {
    method: "OPTIONS",
    headers: {
      Origin: "https://evil.example",
      "Access-Control-Request-Method": "GET",
    },
  });

  const response = await worker.fetch(request, { ...envWithDb(emptyDb()), CORS_ALLOWED_ORIGINS: "*" }, ctx());

  assert.equal(response.status, 403);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), null);
});

test("rejects unconfigured extension origin preflight", async () => {
  const request = new Request("https://example.com/api/v1/me", {
    method: "OPTIONS",
    headers: {
      Origin: "chrome-extension://not-allowed",
      "Access-Control-Request-Method": "GET",
    },
  });

  const response = await worker.fetch(request, envWithDb(emptyDb()), ctx());

  assert.equal(response.status, 403);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), null);
});

test("invalid JSON body returns 400 instead of falling through", async () => {
  const request = new Request("https://example.com/api/v1/auth/login", {
    method: "POST",
    headers: {
      Origin: "chrome-extension://abc123",
      "Content-Type": "application/json",
    },
    body: "{",
  });

  const response = await worker.fetch(request, envWithDb(emptyDb()), ctx());
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.equal(body.error, "Invalid JSON body");
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), "chrome-extension://abc123");
});

test("oversized JSON body returns 413 before route handling", async () => {
  const request = new Request("https://example.com/api/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Length": "1048577",
    },
    body: "{}",
  });

  const response = await worker.fetch(request, envWithDb(emptyDb()), ctx());
  const body = await response.json();

  assert.equal(response.status, 413);
  assert.match(body.error, /JSON body too large/);
});

test("TURNSTILE_KEY also enforces login verification", async () => {
  const request = new Request("https://example.com/api/v1/auth/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username: "alice", password: "correct horse battery" }),
  });

  const response = await worker.fetch(
    request,
    { ...envWithDb(loginRiskDb()), TURNSTILE_KEY: "legacy-secret-name" },
    ctx()
  );
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.equal(body.error, "Turnstile verification failed");
});

test("web login remains compatible with pre-api-session D1 schema", async () => {
  const state = {};
  const request = new Request("https://example.com/api/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username: "admin", password: "correct horse battery" }),
  });

  const response = await worker.fetch(request, envWithDb(legacyWebLoginDb(state)), ctx());
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.user.username, "admin");
  assert.match(response.headers.get("set-cookie"), /__Host-session=/);
  assert.ok(state.runs.some((sql) => sql === "INSERT INTO sessions (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)"));
  assert.ok(state.runs.some((sql) => sql === "UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?"));
});

test("web login ignores android clientType and only returns a web session", async () => {
  const saltB64 = "AQIDBAUGBwgJCgsMDQ4PEA==";
  const user = {
    id: 1,
    username: "admin",
    role: "admin",
    password_salt: saltB64,
    password_hash: passwordHash("correct horse battery", saltB64),
  };
  const request = new Request("https://example.com/api/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username: "admin", password: "correct horse battery", clientType: "android" }),
  });

  const response = await worker.fetch(request, envWithDb(loginRateLimitPassThroughDb(user)), ctx());
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.accessToken, undefined);
  assert.equal(body.refreshToken, undefined);
  assert.match(response.headers.get("set-cookie"), /__Host-session=/);
});

test("malformed stored password hashes fail login without a 500", async () => {
  const state = {};
  const request = new Request("https://example.com/api/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username: "admin", password: "correct horse battery" }),
  });

  const response = await worker.fetch(
    request,
    envWithDb(legacyWebLoginDb(state, { password_hash: "not valid base64!" })),
    ctx()
  );
  const body = await response.json();

  assert.equal(response.status, 401);
  assert.equal(body.error, "Invalid credentials");
  assert.equal((state.runs || []).some((sql) => sql.includes("INSERT INTO sessions")), false);
});

test("v1 me accepts API bearer sessions", async () => {
  const state = {};
  const request = new Request("https://example.com/api/v1/me", {
    headers: {
      Authorization: "Bearer access-token",
    },
  });

  const response = await worker.fetch(request, envWithDb(apiSessionDb(state)), ctx());
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(body.user, { id: 3, username: "alice", role: "user" });
  assert.ok(state.runs.some((sql) => sql.includes("UPDATE api_sessions SET last_used_at")));
});

test("fresh API bearer sessions skip last_used_at writes", async () => {
  const state = { lastUsedAt: new Date().toISOString() };
  const request = new Request("https://example.com/api/v1/me", {
    headers: {
      Authorization: "Bearer access-token",
    },
  });

  const response = await worker.fetch(request, envWithDb(apiSessionDb(state)), ctx());
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(body.user, { id: 3, username: "alice", role: "user" });
  assert.equal((state.runs || []).some((sql) => sql.includes("UPDATE api_sessions SET last_used_at")), false);
});

test("web app data returns entries and groups in one request", async () => {
  const state = {};
  const request = new Request("https://example.com/api/app-data", {
    headers: {
      Cookie: "__Host-session=web-token",
    },
  });

  const response = await worker.fetch(request, envWithDb(webAppDataDb(state)), ctx());
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.entries.length, 1);
  assert.equal(body.entries[0].label, "Email");
  assert.equal(body.groups.length, 1);
  assert.equal(body.groups[0].name, "Work");
});

test("generic API rate limit rejects excessive authenticated requests", async () => {
  const nowSec = Math.floor(Date.now() / 1000);
  const db = {
    prepare(sql) {
      const statement = {
        bind() {
          return statement;
        },
        async first() {
          if (sql.includes("FROM login_risk_control")) {
            return { key: "api-key", window_start: nowSec, request_count: 10, lock_until: 0 };
          }
          throw new Error(`Unexpected first() query: ${sql}`);
        },
        async run() {
          return { meta: { changes: 1 } };
        },
      };
      return statement;
    },
  };
  const request = new Request("https://example.com/api/v1/me", {
    headers: {
      Authorization: "Bearer access-token",
    },
  });

  const response = await worker.fetch(
    request,
    { ...envWithDb(db), API_RATE_MAX_REQUESTS_PER_MINUTE: "10" },
    ctx()
  );
  const body = await response.json();

  assert.equal(response.status, 429);
  assert.equal(body.error, "Too many API requests. Temporarily locked.");
  assert.equal(response.headers.get("Retry-After") !== null, true);
});

test("generic API rate limit fails closed on DB errors", async () => {
  const db = {
    prepare(sql) {
      const statement = {
        bind() {
          return statement;
        },
        async first() {
          if (sql.includes("FROM login_risk_control")) throw new Error("database is locked");
          return null;
        },
      };
      return statement;
    },
  };
  const request = new Request("https://example.com/api/v1/me", {
    headers: {
      Authorization: "Bearer access-token",
    },
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 503);
  assert.equal(body.error, "API rate limiter unavailable");
});

test("v1 logout deletes the authenticated API session", async () => {
  const state = {};
  const request = new Request("https://example.com/api/v1/auth/logout", {
    method: "POST",
    headers: {
      Authorization: "Bearer access-token",
    },
  });

  const response = await worker.fetch(request, envWithDb(apiSessionDb(state)), ctx());
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.ok(state.runs.some((sql) => sql.includes("DELETE FROM api_sessions WHERE id = ?")));
});

test("v1 refresh accepts browser extension client type aliases", async () => {
  const request = new Request("https://example.com/api/v1/auth/refresh", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ refreshToken: "refresh-token", clientType: "browser_extension" }),
  });

  const response = await worker.fetch(request, envWithDb(refreshDb("edge_extension:edge:1.0.0")), ctx());
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.user.username, "alice");
  assert.equal(typeof body.accessToken, "string");
  assert.equal(typeof body.refreshToken, "string");
  assert.equal(body.refreshExpiresIn, 7776000);
});

test("v1 refresh rejects already-rotated refresh tokens", async () => {
  const request = new Request("https://example.com/api/v1/auth/refresh", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ refreshToken: "refresh-token", clientType: "android" }),
  });

  const response = await worker.fetch(request, envWithDb(refreshDb("android", 0)), ctx());
  const body = await response.json();

  assert.equal(response.status, 409);
  assert.equal(body.error, "Refresh token already used");
});

test("admin cannot bind an entry to another user's group", async () => {
  const db = adminSessionDb({
    first(sql) {
      if (sql.includes("SELECT id FROM users WHERE id = ?")) return { id: 10 };
      if (sql.includes("SELECT id, user_id FROM groups WHERE id = ?")) {
        return { id: 99, user_id: 11 };
      }
      return null;
    },
  });
  const request = new Request("https://example.com/api/v1/entries", {
    method: "POST",
    headers: {
      Authorization: "Bearer access-token",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      userId: 10,
      groupId: 99,
      label: "Email",
      secret: "JBSWY3DPEHPK3PXP",
    }),
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.equal(body.error, "groupId must belong to entry user");
  assert.equal(db.state.runs.some((sql) => sql.includes("INSERT INTO totp_entries")), false);
});

test("bearer token cannot access legacy users API", async () => {
  const db = adminSessionDb({});
  const request = new Request("https://example.com/api/users", {
    headers: { Authorization: "Bearer access-token" },
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 403);
  assert.equal(body.error, "Web session required");
});

test("bearer token cannot access encrypted export", async () => {
  const db = adminSessionDb({});
  const request = new Request("https://example.com/api/export/encrypted", {
    method: "POST",
    headers: { Authorization: "Bearer extension-token", "Content-Type": "application/json" },
    body: JSON.stringify({ passphrase: "Backup-Passphrase-123" }),
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 403);
  assert.equal(body.error, "Web session required");
});

test("encrypted export requires current password step-up", async () => {
  const db = adminSessionDb({});
  const request = new Request("https://example.com/api/export/encrypted", {
    method: "POST",
    headers: { Cookie: "__Host-session=web-token", "Content-Type": "application/json" },
    body: JSON.stringify({ passphrase: "Backup-Passphrase-123" }),
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 401);
  assert.equal(body.error, "Current password confirmation required");
});

test("encrypted export step-up opens recent authentication window", async () => {
  const db = adminSessionDb({});
  const first = new Request("https://example.com/api/export/encrypted", {
    method: "POST",
    headers: { Cookie: "__Host-session=web-token", "Content-Type": "application/json" },
    body: JSON.stringify({
      passphrase: "Backup-Passphrase-123",
      confirmPassword: "correct horse battery",
    }),
  });

  const firstResponse = await worker.fetch(first, envWithDb(db), ctx());
  const firstBody = await firstResponse.json();

  assert.equal(firstResponse.status, 200);
  assert.equal(firstBody.ok, true);
  assert.ok(db.state.stepUpAt);

  const second = new Request("https://example.com/api/export/encrypted", {
    method: "POST",
    headers: { Cookie: "__Host-session=web-token", "Content-Type": "application/json" },
    body: JSON.stringify({ passphrase: "Backup-Passphrase-123" }),
  });

  const secondResponse = await worker.fetch(second, envWithDb(db), ctx());
  const secondBody = await secondResponse.json();

  assert.equal(secondResponse.status, 200);
  assert.equal(secondBody.ok, true);
});

test("extension bearer cannot reset another user's password", async () => {
  const db = adminSessionDb({});
  db.state.apiClientType = "edge_extension:edge:1.0.0";
  const request = new Request("https://example.com/api/users/2/password", {
    method: "PATCH",
    headers: { Authorization: "Bearer extension-token", "Content-Type": "application/json" },
    body: JSON.stringify({ newPassword: "NewSecure-Pass123", confirmPassword: "correct horse battery" }),
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 403);
  assert.equal(body.error, "Web session required");
  assert.equal((db.state.runs || []).some((sql) => sql.includes("UPDATE users SET password_hash")), false);
});

test("successful unknown-IP login clears the same risk buckets it created", async () => {
  const saltB64 = "AQIDBAUGBwgJCgsMDQ4PEA==";
  const user = {
    id: 1,
    username: "admin",
    role: "admin",
    password_salt: saltB64,
    password_hash: passwordHash("correct horse battery", saltB64),
  };
  const state = {};
  const request = new Request("https://example.com/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "admin", password: "correct horse battery" }),
  });

  const response = await worker.fetch(request, envWithDb(loginRateLimitPassThroughDb(user, state)), ctx());
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  const riskInserts = state.binds.filter((bind) => bind.sql.includes("INSERT INTO login_risk_control"));
  const clearDelete = state.binds.find((bind) => bind.sql.includes("DELETE FROM login_risk_control WHERE key IN"));
  assert.equal(riskInserts.length, 2);
  assert.ok(clearDelete);
  assert.equal(clearDelete.args[0], riskInserts[0].args[0]);
  assert.equal(clearDelete.args[1], riskInserts[1].args[0]);
});

test("bootstrap requires configured initialization token", async () => {
  const request = new Request("https://example.com/api/bootstrap", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "admin", password: "Admin-Pass123!" }),
  });

  const response = await worker.fetch(request, envWithDb(emptyDb()), ctx());
  const body = await response.json();

  assert.equal(response.status, 403);
  assert.equal(body.error, "Bootstrap token is required");
});

test("bootstrap atomic insert closes concurrent initialization race", async () => {
  const state = { bootstrapCompleted: false };
  const db = {
    prepare(sql) {
      const statement = {
        args: [],
        bind(...args) {
          statement.args = args;
          return statement;
        },
        async first() {
          if (sql.includes("SELECT id FROM users LIMIT 1")) return null;
          if (sql.includes("SELECT value FROM app_settings")) return null;
          return null;
        },
        async run() {
          if (sql.includes("INSERT INTO users")) return { meta: { changes: 0 } };
          if (sql.includes("INSERT INTO app_settings")) {
            state.bootstrapCompleted = true;
            return { meta: { changes: 1 } };
          }
          return { meta: { changes: 1 } };
        },
      };
      return statement;
    },
  };
  const request = new Request("https://example.com/api/bootstrap", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "admin", password: "Admin-Pass123!", bootstrapToken: "init-token" }),
  });

  const response = await worker.fetch(request, { ...envWithDb(db), BOOTSTRAP_TOKEN: "init-token" }, ctx());
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.equal(body.error, "Already initialized");
  assert.equal(state.bootstrapCompleted, true);
});

test("plaintext export is disabled unless explicitly enabled", async () => {
  const db = adminSessionDb({});
  const request = new Request("https://example.com/api/export?confirm=plaintext", {
    headers: {
      Cookie: "__Host-session=web-token",
      "x-plaintext-export-confirm": "true",
    },
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 403);
  assert.equal(body.error, "Plaintext export is disabled. Use /api/export/encrypted.");
});

test("encrypted import rejects downgraded PBKDF2 iterations", async () => {
  const db = adminSessionDb({});
  const request = new Request("https://example.com/api/import/encrypted", {
    method: "POST",
    headers: {
      Cookie: "__Host-session=web-token",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      passphrase: "correct horse",
      encrypted: {
        format: "worker-2fauth-encrypted-v1",
        kdf: "PBKDF2-SHA-256",
        iterations: 1,
        salt: "AQIDBAUGBwgJCgsMDQ4PEA==",
        iv: "AQIDBAUGBwgJCgsM",
        ciphertext: "AQID",
      },
    }),
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.equal(body.error, "failed to decrypt payload (wrong passphrase or payload corrupted)");
});

test("creating entries accepts explicit SHA-1 OTP algorithms", async () => {
  const db = entryCaptureDb();
  const request = new Request("https://example.com/api/v1/entries", {
    method: "POST",
    headers: {
      Authorization: "Bearer access-token",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      label: "Email",
      secret: "JBSWY3DPEHPK3PXP",
      algorithm: "SHA-1",
    }),
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 201);
  assert.equal(body.ok, true);
  assert.equal(db.state.entryInserts.length, 1);
  assert.equal(db.state.entryInserts[0][6], "SHA-1");
});

test("creating an entry from otpauth URI defaults omitted algorithm to SHA-1", async () => {
  const db = entryCaptureDb();
  const request = new Request("https://example.com/api/v1/entries", {
    method: "POST",
    headers: {
      Authorization: "Bearer access-token",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      otpauthUri: "otpauth://totp/NVIDIA:alice%40example.com?secret=jbsw-y3dp-ehpk3pxp&issuer=NVIDIA",
    }),
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 201);
  assert.equal(body.ok, true);
  assert.equal(db.state.entryInserts.length, 1);
  assert.equal(db.state.entryInserts[0][1], "alice@example.com");
  assert.equal(db.state.entryInserts[0][2], "NVIDIA");
  assert.equal(db.state.entryInserts[0][4], 6);
  assert.equal(db.state.entryInserts[0][5], 30);
  assert.equal(db.state.entryInserts[0][6], "SHA-1");
});

test("creating an entry from otpauth URI accepts algorithm=SHA1", async () => {
  const db = entryCaptureDb();
  const request = new Request("https://example.com/api/v1/entries", {
    method: "POST",
    headers: {
      Authorization: "Bearer access-token",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      otpauthUri: "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1",
    }),
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 201);
  assert.equal(body.ok, true);
  assert.equal(db.state.entryInserts.length, 1);
  assert.equal(db.state.entryInserts[0][6], "SHA-1");
});

test("creating an entry from a raw secret without algorithm defaults to SHA-1", async () => {
  const db = entryCaptureDb();
  const request = new Request("https://example.com/api/v1/entries", {
    method: "POST",
    headers: {
      Authorization: "Bearer access-token",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      label: "Email",
      secret: "jbsw y3dp-ehpk3pxp==",
    }),
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 201);
  assert.equal(body.ok, true);
  assert.equal(db.state.entryInserts.length, 1);
  assert.equal(db.state.entryInserts[0][6], "SHA-1");
});

test("creating an entry rejects conflicting secret and otpauthUri inputs", async () => {
  const db = entryCaptureDb();
  const request = new Request("https://example.com/api/v1/entries", {
    method: "POST",
    headers: {
      Authorization: "Bearer access-token",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      label: "Conflict",
      secret: "JBSWY3DPEHPK3PXP",
      otpauthUri: "otpauth://totp/Conflict?secret=AAAAAAAA",
    }),
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.equal(body.error, "secret and otpauthUri conflict");
  assert.equal(db.state.entryInserts || undefined, undefined);
});

test("otpauth import accepts omitted and SHA1 algorithms", async () => {
  const db = entryCaptureDb();
  const text = [
    "otpauth://totp/NVIDIA:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=NVIDIA",
    "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1",
  ].join("\n");
  const request = new Request("https://example.com/api/import/otpauth", {
    method: "POST",
    headers: {
      Cookie: "__Host-session=web-token",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ text }),
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(
    { found: body.found, imported: body.imported, failed: body.failed },
    { found: 2, imported: 2, failed: 0 }
  );
  assert.equal(db.state.entryInserts.length, 2);
  assert.deepEqual(db.state.entryInserts.map((args) => args[6]), ["SHA-1", "SHA-1"]);
});

test("captured NVIDIA otpauth sample imports after sanitization", { todo: true }, () => {});

test("updating entries accepts SHA-1 OTP algorithms", async () => {
  const db = adminSessionDb({
    first(sql) {
      if (sql.includes("SELECT * FROM totp_entries WHERE id = ?")) {
        return {
          id: 5,
          user_id: 1,
          label: "Email",
          issuer: "",
          secret_enc: "iv:cipher",
          digits: 6,
          period: 30,
          algorithm: "SHA-256",
          otp_type: "totp",
          hotp_counter: 0,
          group_id: null,
        };
      }
      return null;
    },
    run(sql, args, state) {
      if (sql.includes("UPDATE totp_entries")) {
        state.entryUpdates = state.entryUpdates || [];
        state.entryUpdates.push(args);
      }
      return { meta: { changes: 1 } };
    },
  });
  const request = new Request("https://example.com/api/v1/entries/5", {
    method: "PATCH",
    headers: {
      Authorization: "Bearer access-token",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ algorithm: "SHA-1" }),
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(db.state.entryUpdates.length, 1);
  assert.equal(db.state.entryUpdates[0][5], "SHA-1");
});

test("bootstrap rejects weak passwords before hashing", async () => {
  const db = {
    prepare(sql) {
      const statement = {
        bind() {
          return statement;
        },
        async first() {
          if (sql.includes("SELECT id FROM users LIMIT 1")) return null;
          throw new Error(`Unexpected first() query: ${sql}`);
        },
        async run() {
          throw new Error(`Unexpected run() query: ${sql}`);
        },
      };
      return statement;
    },
  };
  const request = new Request("https://example.com/api/bootstrap", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username: "admin", password: "longpassword" }),
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.equal(body.error, "Invalid username or password");
});

test("cannot demote the last admin", async () => {
  const db = adminSessionDb({
    first(sql) {
      if (sql.includes("SELECT id, role FROM users WHERE id = ?")) {
        return { id: 2, role: "admin" };
      }
      if (sql.includes("COUNT(*) AS count")) return { count: 1 };
      return null;
    },
  });
  const request = new Request("https://example.com/api/users/2/role", {
    method: "PATCH",
    headers: {
      Cookie: "__Host-session=web-token",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ role: "user", confirmPassword: "correct horse battery" }),
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.equal(body.error, "Cannot remove the last admin");
});

test("cannot delete the last admin", async () => {
  const db = adminSessionDb({
    first(sql) {
      if (sql.includes("SELECT id, username, role FROM users WHERE id = ?")) {
        return { id: 2, username: "root", role: "admin" };
      }
      if (sql.includes("COUNT(*) AS count")) return { count: 1 };
      return null;
    },
  });
  const request = new Request("https://example.com/api/users/2", {
    method: "DELETE",
    headers: {
      Cookie: "__Host-session=web-token",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ confirmPassword: "correct horse battery" }),
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.equal(body.error, "Cannot delete the last admin");
  assert.equal(db.state.runs.some((sql) => sql.includes("DELETE FROM users WHERE id = ?")), false);
});

test("change own password requires currentPassword and newPassword validation", async () => {
  const db = adminSessionDb({
    first(sql) {
      if (sql.includes("FROM users WHERE id = ?")) {
        return { id: 1, username: "admin", password_hash: "hash", password_salt: "salt" };
      }
      if (sql.includes("COUNT") && sql.includes("admin")) return { count: 1 };
      return null;
    },
  });

  const request = new Request("https://example.com/api/v1/me/password", {
    method: "PATCH",
    headers: { Authorization: "Bearer access-token", "Content-Type": "application/json" },
    body: JSON.stringify({ currentPassword: "short" }),
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.equal(body.error, "currentPassword and newPassword are required");
});

test("change own password rejects weak new password", async () => {
  const db = adminSessionDb({
    first(sql) {
      if (sql.includes("FROM users WHERE id = ?")) {
        return { id: 1, username: "admin", password_hash: "hash", password_salt: "salt" };
      }
      if (sql.includes("COUNT") && sql.includes("admin")) return { count: 1 };
      return null;
    },
  });

  const request = new Request("https://example.com/api/v1/me/password", {
    method: "PATCH",
    headers: { Authorization: "Bearer access-token", "Content-Type": "application/json" },
    body: JSON.stringify({ currentPassword: "some-old-password", newPassword: "weak" }),
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.equal(body.error, "Invalid new password");
});

test("admin can reset any user password", async () => {
  const db = adminSessionDb({
    first(sql) {
      if (sql.includes("SELECT id, username FROM users WHERE id = ?")) {
        return { id: 2, username: "alice" };
      }
      if (sql.includes("COUNT") && sql.includes("admin")) return { count: 1 };
      return null;
    },
  });

  const request = new Request("https://example.com/api/users/2/password", {
    method: "PATCH",
    headers: { Cookie: "__Host-session=web-token", "Content-Type": "application/json" },
    body: JSON.stringify({ newPassword: "NewSecure-Pass123", confirmPassword: "correct horse battery" }),
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.ok(db.state.runs.some((sql) => sql.includes("UPDATE users SET password_hash = ?")));
});

test("admin cannot reset own password via user endpoint", async () => {
  const db = adminSessionDb({
    first(sql) {
      if (sql.includes("COUNT") && sql.includes("admin")) return { count: 1 };
      return null;
    },
  });

  const request = new Request("https://example.com/api/users/1/password", {
    method: "PATCH",
    headers: { Cookie: "__Host-session=web-token", "Content-Type": "application/json" },
    body: JSON.stringify({ newPassword: "NewSecure-Pass123" }),
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.equal(body.error, "Use /api/me/password to change your own password");
});
