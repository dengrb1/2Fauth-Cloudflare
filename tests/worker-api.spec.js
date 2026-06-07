import assert from "node:assert/strict";
import test from "node:test";

import worker from "../src/worker.js";

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

function adminSessionDb(handler) {
  const state = { inserts: 0, updates: 0, deletes: 0 };
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
              client_type: "android",
              id: 1,
              username: "admin",
              role: "admin",
            };
          }
          return handler.first ? handler.first(sql, statement.args, state) : null;
        },
        async run() {
          state.runs = state.runs || [];
          state.runs.push(sql);
          if (sql.startsWith("INSERT")) state.inserts += 1;
          if (sql.startsWith("UPDATE")) state.updates += 1;
          if (sql.startsWith("DELETE")) state.deletes += 1;
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
  assert.equal(body.error, "Too many API requests");
  assert.equal(response.headers.get("Retry-After") !== null, true);
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

test("plaintext export is disabled unless explicitly enabled", async () => {
  const db = adminSessionDb({});
  const request = new Request("https://example.com/api/export?confirm=plaintext", {
    headers: {
      Authorization: "Bearer access-token",
      "x-plaintext-export-confirm": "true",
    },
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 403);
  assert.equal(body.error, "Plaintext export is disabled. Use /api/export/encrypted.");
});

test("creating entries rejects SHA-1 OTP algorithms", async () => {
  const db = adminSessionDb({});
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

  assert.equal(response.status, 400);
  assert.equal(body.error, "algorithm must be SHA-256 or SHA-512");
  assert.equal(db.state.runs.some((sql) => sql.includes("INSERT INTO totp_entries")), false);
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
  assert.match(body.error, /uppercase, lowercase, number, and symbol/);
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
      Authorization: "Bearer access-token",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ role: "user" }),
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
      Authorization: "Bearer access-token",
    },
  });

  const response = await worker.fetch(request, envWithDb(db), ctx());
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.equal(body.error, "Cannot delete the last admin");
  assert.equal(db.state.runs.some((sql) => sql.includes("DELETE FROM users WHERE id = ?")), false);
});
