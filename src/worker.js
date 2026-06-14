const SESSION_COOKIE = "__Host-session";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days
const API_ACCESS_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days
const API_REFRESH_TTL_SECONDS = 60 * 60 * 24 * 90; // 90 days
const CLOSE_LOGOUT_GRACE_SECONDS = 12;
const CLOSE_SOON_HEADER = "x-session-close";
const CLOSE_SOON_HEADER_VALUE = "web-beforeunload";
// Keep hashing strong while avoiding CPU limit spikes on Cloudflare Workers.
const PBKDF2_ITERATIONS = 100_000;
const MIN_PASSWORD_PBKDF2_ITERATIONS = 10_000;
const MAX_PASSWORD_PBKDF2_ITERATIONS = 1_000_000;
const PBKDF2_HASH = "SHA-256";
const PASSWORD_POLICY_DESCRIPTION = "at least 12 chars with uppercase, lowercase, number, and symbol";
const PASSPHRASE_PBKDF2_ITERATIONS = 180_000;
const MAX_PASSPHRASE_PBKDF2_ITERATIONS = 1_000_000;
const ENCRYPTED_BACKUP_PASSPHRASE_MIN_LENGTH = 12;
const DEFAULT_JSON_BODY_MAX_BYTES = 1_048_576;
const DEFAULT_RISK_MAX_REQUESTS_PER_MINUTE = 10;
const DEFAULT_RISK_LOCK_MINUTES = 15;
const DEFAULT_API_RATE_MAX_REQUESTS_PER_MINUTE = 120;
const DEFAULT_TOTP_VERIFY_MAX_REQUESTS_PER_MINUTE = 10;
const DEFAULT_TOTP_VERIFY_LOCK_MINUTES = 5;
const DEFAULT_HOTP_CONSUME_MAX_REQUESTS_PER_MINUTE = 5;
const DEFAULT_HOTP_CONSUME_LOCK_MINUTES = 5;
const ENCRYPTION_KEY_CACHE_TTL_MS = 5 * 60 * 1000;
const ENTRY_LABEL_MAX_LENGTH = 200;
const ENTRY_ISSUER_MAX_LENGTH = 100;
const GROUP_NAME_MAX_LENGTH = 60;
const DEFAULT_API_RATE_LOCK_MINUTES = 15;
const TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const ANDROID_CLIENT_TYPE = "android";
const EXTENSION_CLIENT_TYPE = "edge_extension";
const EXTENSION_BATCH_MAX_IDS = 100;
const DB_ID_PATH_PATTERN = "[1-9]\\d{0,15}";
const EXTENSION_CORS_PROTOCOLS = new Set(["chrome-extension:", "moz-extension:", "safari-web-extension:"]);

// N-01 fix: dummy salt/hash for constant-time PBKDF2 on missing user
const FAKE_PASSWORD_SALT = "AAAAAAAAAAAAAAAAAAAAAA";
const FAKE_PASSWORD_HASH = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const CORS_ALLOWED_HEADERS = "Content-Type, Authorization, X-Client-Type";
const CORS_ALLOWED_METHODS = "GET, POST, PATCH, DELETE, OPTIONS";

const API_ROUTES = [
  ["GET", "/api/status", handleStatus],
  ["POST", "/api/bootstrap", handleBootstrap],
  ["POST", "/api/login", handleLogin],
  ["POST", "/api/mobile/login", handleMobileLogin],
  ["POST", "/api/mobile/refresh", handleMobileRefresh],
  ["POST", "/api/mobile/logout", handleMobileLogout],
  ["POST", "/api/extension/login", handleExtensionLogin],
  ["POST", "/api/extension/refresh", handleExtensionRefresh],
  ["POST", "/api/extension/logout", handleExtensionLogout],
  ["GET", "/api/extension/entries", handleExtensionEntries],
  ["POST", "/api/extension/codes/batch", handleExtensionCodesBatch],
  ["GET", "/api/v1/capabilities", handleApiCapabilities],
  ["POST", "/api/v1/auth/login", handleApiClientLogin],
  ["POST", "/api/v1/auth/refresh", handleApiClientRefresh],
  ["POST", "/api/v1/auth/logout", handleApiClientLogout],
  ["GET", "/api/v1/me", handleMe],
  ["PATCH", "/api/v1/me/password", handleChangeMyPassword],
  ...entryRoutes("/api/v1"),
  ...groupRoutes("/api/v1"),
  ["POST", "/api/v1/codes/batch", handleApiCodesBatch],
  ["POST", "/api/logout", handleLogout],
  ["POST", "/api/session/close-soon", handleCloseSoon],
  ["GET", "/api/me", handleMe],
  ["PATCH", "/api/me/password", handleChangeMyPassword],
  ...entryRoutes("/api"),
  ...groupRoutes("/api"),
  ["POST", "/api/export", handleExportData],
  ["POST", "/api/export/otpauth", handleExportOtpAuth],
  ["POST", "/api/export/encrypted", handleExportDataEncrypted],
  ["POST", "/api/import", handleImportData],
  ["POST", "/api/import/otpauth", handleImportOtpAuth],
  ["POST", "/api/import/encrypted", handleImportDataEncrypted],
  ["GET", "/api/users", handleListUsers],
  ["POST", "/api/users", handleCreateUser],
  ["PATCH", routePattern("/api", `/users/${DB_ID_PATH_PATTERN}/role`), handleUpdateUserRole],
  ["PATCH", routePattern("/api", `/users/${DB_ID_PATH_PATTERN}/password`), handleResetUserPassword],
  ["DELETE", routePattern("/api", `/users/${DB_ID_PATH_PATTERN}`), handleDeleteUser],
  ["GET", "/api/security/login-policy", handleGetLoginPolicy],
  ["PATCH", "/api/security/login-policy", handleUpdateLoginPolicy],
];

function entryRoutes(prefix) {
  return [
    ["GET", `${prefix}/entries`, handleListEntries],
    ["POST", `${prefix}/entries`, handleCreateEntry],
    ["PATCH", routePattern(prefix, `/entries/${DB_ID_PATH_PATTERN}`), handleUpdateEntry],
    ["GET", routePattern(prefix, `/entries/${DB_ID_PATH_PATTERN}/code`), handleEntryCode],
    ["POST", routePattern(prefix, `/entries/${DB_ID_PATH_PATTERN}/verify`), handleVerifyTotp],
    ["POST", routePattern(prefix, `/entries/${DB_ID_PATH_PATTERN}/hotp`), handleConsumeHotp],
    ["DELETE", routePattern(prefix, `/entries/${DB_ID_PATH_PATTERN}`), handleDeleteEntry],
  ];
}

function groupRoutes(prefix) {
  return [
    ["GET", `${prefix}/groups`, handleListGroups],
    ["POST", `${prefix}/groups`, handleCreateGroup],
    ["DELETE", routePattern(prefix, `/groups/${DB_ID_PATH_PATTERN}`), handleDeleteGroup],
  ];
}

function routePattern(prefix, suffixPattern) {
  return new RegExp(`^${escapeRegExp(prefix)}${suffixPattern}$`);
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export default {
  async fetch(request, env, ctx) {
    try {
      if (!env.DB) {
        return json({ error: "D1 binding DB is required" }, 500);
      }
      if (!env.ENCRYPTION_KEY || !env.SESSION_PEPPER) {
        return json({ error: "ENCRYPTION_KEY and SESSION_PEPPER are required" }, 500);
      }

      ctx.waitUntil(Promise.all([cleanExpiredSessions(env), cleanExpiredLoginRisk(env)]).catch(() => {}));

      const url = new URL(request.url);
      const method = request.method.toUpperCase();
      const path = url.pathname;

      if (method === "OPTIONS") {
        return corsPreflight(request, env);
      }

      if (method === "GET" && path === "/") {
        const nonce = randomHex(16);
        return html(appShellHtml(env, nonce), nonce);
      }

      const route = findApiRoute(method, path);
      if (route) {
        const limited = await applyApiRateLimit(request, env, route);
        if (limited) return withCors(request, limited, env);
        return withCors(request, await route.handler(request, env), env);
      }
      if (method === "GET" && path === "/favicon.ico") {
        return new Response(null, { status: 204 });
      }
      if (method === "GET" && !path.startsWith("/api/")) {
        const nonce = randomHex(16);
        return html(appShellHtml(env, nonce), nonce);
      }

      return withCors(request, json({ error: "Not found" }, 404), env);
    } catch (err) {
      if (err instanceof ApiError) {
        return withCors(request, json({ error: err.message }, err.status), env);
      }
      const payload = { error: "Internal Server Error" };
      if (canExposeErrorDetail(request, env)) {
        payload.detail = err instanceof Error ? err.message : "Internal error";
      }
      return withCors(request, json(payload, 500), env);
    }
  },
};

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function findApiRoute(method, path) {
  for (const [routeMethod, matcher, handler] of API_ROUTES) {
    if (routeMethod !== method) continue;
    if (typeof matcher === "string" && matcher === path) return { method: routeMethod, matcher, handler };
    if (matcher instanceof RegExp && matcher.test(path)) return { method: routeMethod, matcher, handler };
  }
  return null;
}

async function handleStatus(request, env) {
  const initialized = await hasAnyUser(env);
  return json({ initialized });
}

async function handleBootstrap(request, env) {
  const body = await parseJson(request);
  const username = normalizeUsername(body.username);
  const password = String(body.password || "");
    if (!username || !validPassword(password)) {
      // F-04: vague error 鈥?do not disclose password policy details.
      return json({ error: "Invalid username or password" }, 400);
  }

  const initialized = await hasAnyUser(env);
  if (initialized) return json({ error: "Already initialized" }, 400);

  const { hashB64, saltB64 } = await hashPassword(password);
  const now = nowIso();
  const result = await env.DB.prepare(
    "INSERT INTO users (username, password_hash, password_salt, role, created_at) VALUES (?, ?, ?, 'admin', ?)"
  )
    .bind(username, encodePasswordHash(hashB64), saltB64, now)
    .run();

  let userId = normalizeDbId(result.meta?.last_row_id);
  if (!userId) {
    const row = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
    userId = normalizeDbId(row?.id);
  }
  if (!userId) return json({ error: "Failed to create user id" }, 500);
  const { cookie } = await regenerateWebSession(request, env, userId);
  return json(
    { ok: true, user: { id: userId, username, role: "admin" } },
    201,
    { "set-cookie": cookie }
  );
}

async function handleLogin(request, env) {
  const body = await parseJson(request);
  const username = normalizeUsername(body.username);
  const password = String(body.password || "");
  const turnstileToken = String(body.turnstileToken || "");
  const risk = await applyLoginRiskControl(request, env, username);
  if (risk.blocked) {
    return json(
      {
        error: "Too many login attempts. Temporarily locked.",
        retryAfterSeconds: risk.retryAfterSeconds,
      },
      429
    );
  }
  if (!username || !password) return json({ error: "Username and password are required" }, 400);
  if (hasTurnstileSecret(env)) {
    const ts = await verifyTurnstileToken(turnstileToken, clientIp(request), env);
    if (!ts.ok) {
      return json({ error: "Turnstile verification failed" }, 400);
    }
  }

  const row = await env.DB.prepare(
    "SELECT id, username, role, password_hash, password_salt FROM users WHERE username = ?"
  )
    .bind(username)
    .first();
  if (!row) {
    // N-01 fix: run dummy PBKDF2 to eliminate timing side-channel
    await verifyPasswordDetailed(password, FAKE_PASSWORD_SALT, FAKE_PASSWORD_HASH);
    return json({ error: "Invalid credentials" }, 401);
  }

  const passwordCheck = await verifyPasswordDetailed(password, row.password_salt, row.password_hash);
  if (!passwordCheck.ok) return json({ error: "Invalid credentials" }, 401);
  if (passwordCheck.needsRehash) {
    await upgradePasswordHash(env, row.id, password).catch(() => {});
  }
  await clearLoginRiskControl(request, env, username).catch(() => {});
  await revokePresentedWebSession(request, env);
  // F-05: session fixation prevention 鈥?old session revoked, new random token generated below.

  const { cookie } = await createSession(env, row.id);
  return json(
    { ok: true, user: { id: row.id, username: row.username, role: row.role } },
    200,
    { "set-cookie": cookie }
  );
}

async function handleMobileLogin(request, env) {
  return loginForApiClient(request, env, ANDROID_CLIENT_TYPE);
}

async function handleMobileRefresh(request, env) {
  return rotateApiSessionTokens(request, env, ANDROID_CLIENT_TYPE, { includeRefreshExpiresIn: true });
}

async function handleMobileLogout(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  if (auth.sessionKind !== "api" || auth.apiClientType !== ANDROID_CLIENT_TYPE) {
    return json({ error: "Mobile bearer token required" }, 400);
  }
  await env.DB.prepare("DELETE FROM api_sessions WHERE id = ?").bind(auth.sessionId).run();
  return json({ ok: true });
}

async function handleApiCapabilities(request, env) {
  const corsOrigins = normalizedAllowedCorsOrigins(env);
  return json({
    apiVersion: "v1",
    compatibleClients: [ANDROID_CLIENT_TYPE, "browser_extension"],
    auth: {
      scheme: "Bearer",
      accessTokenExpiresIn: API_ACCESS_TTL_SECONDS,
      refreshTokenExpiresIn: API_REFRESH_TTL_SECONDS,
      refreshTokenRotation: true,
      turnstileRequired: hasTurnstileSecret(env),
    },
    limits: {
      extensionBatchMaxIds: EXTENSION_BATCH_MAX_IDS,
    },
    cors: {
      exactOriginAllowlist: true,
      configured: corsOrigins.length > 0,
      credentials: corsCredentialsEnabled(env),
    },
    endpoints: {
      login: "/api/v1/auth/login",
      refresh: "/api/v1/auth/refresh",
      logout: "/api/v1/auth/logout",
      me: "/api/v1/me",
      entries: "/api/v1/entries",
      groups: "/api/v1/groups",
      codesBatch: "/api/v1/codes/batch",
    },
  });
}

async function handleApiClientLogin(request, env) {
  const body = await parseJson(request);
  const clientType = normalizeApiClientType(body.clientType || ANDROID_CLIENT_TYPE);
  if (!clientType) return json({ error: "clientType must be android or browser_extension" }, 400);

  if (clientType === "browser_extension") {
    body.clientType = EXTENSION_CLIENT_TYPE;
    return handleExtensionLogin(withJsonBody(request, body), env);
  }

  return loginForApiClient(withJsonBody(request, body), env, ANDROID_CLIENT_TYPE);
}

async function loginForApiClient(request, env, clientType) {
  const body = await parseJson(request);
  const username = normalizeUsername(body.username);
  const password = String(body.password || "");
  const turnstileToken = String(body.turnstileToken || "");
  const risk = await applyLoginRiskControl(request, env, username);
  if (risk.blocked) {
    return json(
      {
        error: "Too many login attempts. Temporarily locked.",
        retryAfterSeconds: risk.retryAfterSeconds,
      },
      429
    );
  }
  if (!username || !password) return json({ error: "Username and password are required" }, 400);
  if (hasTurnstileSecret(env)) {
    const ts = await verifyTurnstileToken(turnstileToken, clientIp(request), env);
    if (!ts.ok) {
      return json({ error: "Turnstile verification failed" }, 400);
    }
  }

  const row = await env.DB.prepare(
    "SELECT id, username, role, password_hash, password_salt FROM users WHERE username = ?"
  )
    .bind(username)
    .first();
  if (!row) {
    await verifyPasswordDetailed(password, FAKE_PASSWORD_SALT, FAKE_PASSWORD_HASH);
    return json({ error: "Invalid credentials" }, 401);
  }

  const passwordCheck = await verifyPasswordDetailed(password, row.password_salt, row.password_hash);
  if (!passwordCheck.ok) return json({ error: "Invalid credentials" }, 401);
  if (passwordCheck.needsRehash) {
    await upgradePasswordHash(env, row.id, password).catch(() => {});
  }
  await clearLoginRiskControl(request, env, username).catch(() => {});
  await revokePresentedWebSession(request, env);

  const apiSession = await createApiSession(env, row.id, clientType);
  return json({
    ok: true,
    user: { id: row.id, username: row.username, role: row.role },
    accessToken: apiSession.accessToken,
    refreshToken: apiSession.refreshToken,
    expiresIn: apiSession.expiresIn,
    refreshExpiresIn: API_REFRESH_TTL_SECONDS,
    sessionId: apiSession.sessionId,
  });
}

async function handleApiClientRefresh(request, env) {
  const body = await parseJson(request);
  const clientType = normalizeApiClientType(body.clientType || ANDROID_CLIENT_TYPE);
  if (!clientType) return json({ error: "clientType must be android or browser_extension" }, 400);
  const expected = clientType === "browser_extension" ? EXTENSION_CLIENT_TYPE : ANDROID_CLIENT_TYPE;
  return rotateApiSessionTokens(withJsonBody(request, body), env, expected, { includeRefreshExpiresIn: true });
}

async function handleApiClientLogout(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  if (auth.sessionKind !== "api") return json({ error: "API bearer token required" }, 400);
  await env.DB.prepare("DELETE FROM api_sessions WHERE id = ?").bind(auth.sessionId).run();
  return json({ ok: true });
}

async function handleExtensionLogin(request, env) {
  const body = await parseJson(request);
  const username = normalizeUsername(body.username);
  const password = String(body.password || "");
  const risk = await applyLoginRiskControl(request, env, username);
  if (risk.blocked) {
    return json(
      {
        error: "Too many login attempts. Temporarily locked.",
        retryAfterSeconds: risk.retryAfterSeconds,
      },
      429
    );
  }
  if (!username || !password) return json({ error: "Username and password are required" }, 400);

  // F-01 fix: Turnstile verification was missing, allowing CAPTCHA bypass via extension login
  const turnstileToken = String(body.turnstileToken || "");
  if (hasTurnstileSecret(env)) {
    const ts = await verifyTurnstileToken(turnstileToken, clientIp(request), env);
    if (!ts.ok) {
      return json({ error: "Turnstile verification failed" }, 400);
    }
  }

  const row = await env.DB.prepare(
    "SELECT id, username, role, password_hash, password_salt FROM users WHERE username = ?"
  )
    .bind(username)
    .first();
  if (!row) {
    // N-01 fix: run dummy PBKDF2 to eliminate timing side-channel
    await verifyPasswordDetailed(password, FAKE_PASSWORD_SALT, FAKE_PASSWORD_HASH);
    return json({ error: "Invalid credentials" }, 401);
  }

  const passwordCheck = await verifyPasswordDetailed(password, row.password_salt, row.password_hash);
  if (!passwordCheck.ok) return json({ error: "Invalid credentials" }, 401);
  if (passwordCheck.needsRehash) {
    await upgradePasswordHash(env, row.id, password).catch(() => {});
  }
  await clearLoginRiskControl(request, env, username).catch(() => {});
  await revokePresentedWebSession(request, env);

  const deviceName = normalizeClientMetadata(body.deviceName, 120, "edge");
  const clientVersion = normalizeClientMetadata(body.clientVersion, 64, "unknown");
  const clientType = `${EXTENSION_CLIENT_TYPE}:${deviceName}:${clientVersion}`;
  const apiSession = await createApiSession(env, row.id, clientType);

  return json({
    ok: true,
    user: { id: row.id, username: row.username, role: row.role },
    accessToken: apiSession.accessToken,
    refreshToken: apiSession.refreshToken,
    expiresIn: apiSession.expiresIn,
    refreshExpiresIn: API_REFRESH_TTL_SECONDS,
    sessionId: apiSession.sessionId,
  });
}

async function handleExtensionRefresh(request, env) {
  return rotateApiSessionTokens(request, env, EXTENSION_CLIENT_TYPE, { includeRefreshExpiresIn: true });
}

async function handleExtensionLogout(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  if (!isExtensionClientType(auth.apiClientType)) {
    return json({ error: "Extension bearer token required" }, 400);
  }
  await env.DB.prepare("DELETE FROM api_sessions WHERE id = ?").bind(auth.sessionId).run();
  return json({ ok: true });
}

async function handleExtensionEntries(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  if (!isExtensionClientType(auth.apiClientType)) {
    return json({ error: "Extension bearer token required" }, 400);
  }
  return handleListEntries(request, env);
}

async function handleExtensionCodesBatch(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  if (!isExtensionClientType(auth.apiClientType)) {
    return json({ error: "Extension bearer token required" }, 400);
  }
  return handleCodesBatchForAuth(request, env, auth);
}

async function handleApiCodesBatch(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  if (auth.sessionKind !== "api") return json({ error: "API bearer token required" }, 400);
  return handleCodesBatchForAuth(request, env, auth);
}

async function handleCodesBatchForAuth(request, env, auth) {
  const body = await parseJson(request);
  if (!Array.isArray(body.entryIds)) return json({ error: "entryIds must be an array" }, 400);

  const normalizedIds = [];
  const unique = new Set();
  for (const rawId of body.entryIds) {
    const id = Number(rawId);
    if (!Number.isFinite(id) || id <= 0 || !Number.isInteger(id)) {
      return json({ error: "entryIds must contain positive integer ids" }, 400);
    }
    if (unique.has(id)) continue;
    unique.add(id);
    normalizedIds.push(id);
  }
  if (normalizedIds.length === 0) return json({ error: "entryIds cannot be empty" }, 400);
  if (normalizedIds.length > EXTENSION_BATCH_MAX_IDS) {
    return json({ error: `entryIds cannot exceed ${EXTENSION_BATCH_MAX_IDS}` }, 400);
  }

  // F-01: safe IN-clause query builder 鈥?no string interpolation of SQL.
  // Every element was already validated as a positive integer above.
  const { placeholders, params: inParams } = buildInClause(normalizedIds);
  let query = `SELECT id, user_id, secret_enc, digits, period, algorithm, otp_type, hotp_counter FROM totp_entries WHERE id IN (${placeholders})`;
  const baseParams = [...inParams];
  if (auth.user.role !== "admin") {
    query += " AND user_id = ?";
    baseParams.push(auth.user.id);
  }
  const rows = await env.DB.prepare(query).bind(...baseParams).all();
  const rowMap = new Map((rows.results || []).map((row) => [Number(row.id), row]));

  const nowSec = Math.floor(Date.now() / 1000);
  const items = [];
  for (const id of normalizedIds) {
    const row = rowMap.get(id);
    if (!row) {
      items.push({ id, error: "Entry not found or forbidden" });
      continue;
    }

    const otpType = row.otp_type || "totp";
    if (otpType === "hotp") {
      items.push({
        id,
        otpType: "hotp",
        counter: Number(row.hotp_counter || 0),
        error: "Use HOTP endpoint",
      });
      continue;
    }

    try {
      const period = normalizeTotpPeriod(row.period);
      const digits = normalizeOtpDigits(row.digits);
      const algorithm = normalizeAlgorithm(row.algorithm || "SHA-1");
      if (!algorithm) {
        items.push({ id, otpType: "totp", error: "Unsupported OTP algorithm" });
        continue;
      }
      const secret = await decryptText(row.secret_enc, env);
      const step = Math.floor(nowSec / period);
      const code = await generateTotp(secret, period, digits, algorithm, step);
      const expiresIn = period - (nowSec % period);
      items.push({
        id,
        otpType: "totp",
        code,
        expiresIn,
      });
    } catch {
      items.push({ id, otpType: "totp", error: "Failed to generate code" });
    }
  }

  return json({
    serverTime: nowSec,
    items,
  });
}

async function handleLogout(request, env) {
  const origin = request.headers.get("Origin");
  if (origin) {
    const url = new URL(request.url);
    const expectedOrigin = `${url.protocol}//${url.host}`;
    if (origin !== expectedOrigin) return json({ error: "Invalid origin" }, 403);
  }
  const token = readCookie(request, SESSION_COOKIE);
  if (token) {
    const tokenHash = await hashSessionToken(token, env);
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
  }
  return json({ ok: true }, 200, { "set-cookie": clearSessionCookie() });
}

async function handleCloseSoon(request, env) {
  const token = readCookie(request, SESSION_COOKIE);
  if (!token) return json({ ok: true });
  if (!isAllowedCloseSoonRequest(request)) return json({ ok: true });
  const tokenHash = await hashSessionToken(token, env);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + CLOSE_LOGOUT_GRACE_SECONDS * 1000).toISOString();
  await updateWebSessionExpiry(env, tokenHash, expiresAt);
  return json({ ok: true });
}

function isAllowedCloseSoonRequest(request) {
  const closeHeader = String(request.headers.get(CLOSE_SOON_HEADER) || "").trim().toLowerCase();
  if (closeHeader === CLOSE_SOON_HEADER_VALUE) return true;

  const fetchMode = String(request.headers.get("sec-fetch-mode") || "").trim().toLowerCase();
  const fetchDest = String(request.headers.get("sec-fetch-dest") || "").trim().toLowerCase();
  return fetchMode === "navigate" && fetchDest === "document";
}

async function handleMe(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  if (auth.sessionKind === "web") {
    await refreshSessionTtl(request, env).catch(() => {});
  }
  return json({ user: auth.user });
}

async function handleListEntries(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;

  if (auth.user.role === "admin") {
    const rows = await env.DB.prepare(
      "SELECT e.id, e.user_id, u.username, e.label, e.issuer, e.digits, e.period, e.algorithm, e.otp_type, e.hotp_counter, e.group_id, g.name AS group_name, g.color AS group_color, e.created_at FROM totp_entries e JOIN users u ON u.id = e.user_id LEFT JOIN groups g ON g.id = e.group_id ORDER BY e.id DESC"
    ).all();
    return json({ entries: rows.results || [] });
  }

  const rows = await env.DB.prepare(
    "SELECT e.id, e.user_id, e.label, e.issuer, e.digits, e.period, e.algorithm, e.otp_type, e.hotp_counter, e.group_id, g.name AS group_name, g.color AS group_color, e.created_at FROM totp_entries e LEFT JOIN groups g ON g.id = e.group_id WHERE e.user_id = ? ORDER BY e.id DESC"
  )
    .bind(auth.user.id)
    .all();
  return json({ entries: rows.results || [] });
}

async function handleCreateEntry(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;

  const body = await parseJson(request);
  let payload = { ...body };
  if (payload.otpauthUri && !payload.secret) {
    const parsed = parseOtpAuthUri(String(payload.otpauthUri));
    if (!parsed.ok) return json({ error: parsed.error }, 400);
    payload = { ...payload, ...parsed.data };
  }

  const label = String(payload.label || "").trim();
  const issuer = payload.issuer ? String(payload.issuer).trim() : "";
  if (label.length > ENTRY_LABEL_MAX_LENGTH) return json({ error: `label must be at most ${ENTRY_LABEL_MAX_LENGTH} characters` }, 400);
  if (issuer.length > ENTRY_ISSUER_MAX_LENGTH) return json({ error: `issuer must be at most ${ENTRY_ISSUER_MAX_LENGTH} characters` }, 400);
  const secret = String(payload.secret || "").trim();
  const digits = Number(payload.digits || 6);
  const period = Number(payload.period || 30);
  const algorithm = normalizeAlgorithm(payload.algorithm || "SHA-256");
  const otpType = payload.otpType === "hotp" ? "hotp" : "totp";
  const hotpCounter = Number(payload.hotpCounter || 0);
  const groupId = parseOptionalPositiveId(payload.groupId);
  const requestedUserId = Number(payload.userId !== undefined ? payload.userId : auth.user.id);
  const userId = auth.user.role === "admin" ? requestedUserId : auth.user.id;

  if (!label || !secret) return json({ error: "label and secret are required" }, 400);
  if (!Number.isInteger(userId) || userId <= 0) return json({ error: "userId must be a positive integer" }, 400);
  if (groupId === false) return json({ error: "groupId must be a positive integer or null" }, 400);
  if (![6, 7, 8].includes(digits)) return json({ error: "digits must be 6/7/8" }, 400);
  if (otpType === "totp" && (!Number.isFinite(period) || period < 15 || period > 120)) return json({ error: "period must be between 15 and 120" }, 400);
  if (!algorithm) return json({ error: "algorithm must be SHA-256 or SHA-512" }, 400);
  if (algorithm === "SHA-1") return json({ error: "algorithm must be SHA-256 or SHA-512" }, 400);
  if (otpType === "hotp" && (!Number.isInteger(hotpCounter) || hotpCounter < 0)) return json({ error: "hotpCounter must be >= 0" }, 400);

  try {
    const bytes = base32Decode(secret);
    if (!bytes.length) throw new Error("empty");
  } catch {
    return json({ error: "secret is not valid base32" }, 400);
  }

  if (auth.user.role === "admin") {
    const exists = await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(userId).first();
    if (!exists) return json({ error: "userId does not exist" }, 400);
  }
  if (groupId) {
    const group = await env.DB.prepare("SELECT id, user_id FROM groups WHERE id = ?").bind(groupId).first();
    if (!group) return json({ error: "groupId does not exist" }, 400);
    if (Number(group.user_id) !== Number(userId)) return json({ error: "groupId must belong to entry user" }, 400);
  }

  const secretEnc = await encryptText(secret, env);
  const now = nowIso();
  const result = await env.DB.prepare(
    "INSERT INTO totp_entries (user_id, label, issuer, secret_enc, digits, period, algorithm, otp_type, hotp_counter, group_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
  )
    .bind(userId, label, issuer, secretEnc, digits, period, algorithm, otpType, hotpCounter, groupId, now)
    .run();

  return json({ ok: true, id: normalizeDbId(result.meta?.last_row_id) }, 201);
}

async function handleUpdateEntry(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  const id = pathResourceId(request, "entries");
  if (!Number.isFinite(id)) return json({ error: "Invalid id" }, 400);

  const existing = await env.DB.prepare("SELECT * FROM totp_entries WHERE id = ?").bind(id).first();
  if (!existing) return json({ error: "Entry not found" }, 404);
  if (auth.user.role !== "admin" && existing.user_id !== auth.user.id) return json({ error: "Forbidden" }, 403);

  const body = await parseJson(request);
  const label = body.label !== undefined ? String(body.label).trim() : existing.label;
  const issuer = body.issuer !== undefined ? String(body.issuer).trim() : existing.issuer;
  if (label.length > ENTRY_LABEL_MAX_LENGTH) return json({ error: `label must be at most ${ENTRY_LABEL_MAX_LENGTH} characters` }, 400);
  if (issuer.length > ENTRY_ISSUER_MAX_LENGTH) return json({ error: `issuer must be at most ${ENTRY_ISSUER_MAX_LENGTH} characters` }, 400);
  const digits = body.digits !== undefined ? Number(body.digits) : existing.digits;
  const period = body.period !== undefined ? Number(body.period) : existing.period;
  const algorithm = body.algorithm !== undefined ? normalizeAlgorithm(body.algorithm) : normalizeAlgorithm(existing.algorithm || "SHA-1");
  const otpType = body.otpType ? (body.otpType === "hotp" ? "hotp" : "totp") : (existing.otp_type || "totp");
  const hotpCounter = body.hotpCounter !== undefined ? Number(body.hotpCounter) : (existing.hotp_counter || 0);
  const groupId = body.groupId !== undefined ? parseOptionalPositiveId(body.groupId) : existing.group_id;

  if (!label) return json({ error: "label is required" }, 400);
  if (groupId === false) return json({ error: "groupId must be a positive integer or null" }, 400);
  if (![6, 7, 8].includes(digits)) return json({ error: "digits must be 6/7/8" }, 400);
  if (otpType === "totp" && (!Number.isFinite(period) || period < 15 || period > 120)) return json({ error: "period must be between 15 and 120" }, 400);
  if (!algorithm) return json({ error: "algorithm must be SHA-256 or SHA-512" }, 400);
  if (body.algorithm !== undefined && algorithm === "SHA-1") return json({ error: "algorithm must be SHA-256 or SHA-512" }, 400);
  if (otpType === "hotp" && (!Number.isInteger(hotpCounter) || hotpCounter < 0)) return json({ error: "hotpCounter must be >= 0" }, 400);

  let secretEnc = existing.secret_enc;
  if (body.secret !== undefined) {
    const secret = String(body.secret || "").trim();
    if (!secret) return json({ error: "secret cannot be empty" }, 400);
    try {
      const bytes = base32Decode(secret);
      if (!bytes.length) throw new Error("empty");
    } catch {
      return json({ error: "secret is not valid base32" }, 400);
    }
    secretEnc = await encryptText(secret, env);
  }

  if (groupId) {
    const group = await env.DB.prepare("SELECT id, user_id FROM groups WHERE id = ?").bind(groupId).first();
    if (!group) return json({ error: "groupId does not exist" }, 400);
    if (Number(group.user_id) !== Number(existing.user_id)) return json({ error: "groupId must belong to entry user" }, 400);
  }

  await env.DB.prepare(
    "UPDATE totp_entries SET label = ?, issuer = ?, secret_enc = ?, digits = ?, period = ?, algorithm = ?, otp_type = ?, hotp_counter = ?, group_id = ? WHERE id = ?"
  )
    .bind(label, issuer, secretEnc, digits, period, algorithm, otpType, hotpCounter, groupId, id)
    .run();
  return json({ ok: true });
}

async function handleEntryCode(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  const id = pathResourceId(request, "entries");
  if (!Number.isFinite(id)) return json({ error: "Invalid id" }, 400);

  const row = await env.DB.prepare("SELECT * FROM totp_entries WHERE id = ?").bind(id).first();
  if (!row) return json({ error: "Entry not found" }, 404);
  if (auth.user.role !== "admin" && row.user_id !== auth.user.id) return json({ error: "Forbidden" }, 403);

  const secret = await decryptText(row.secret_enc, env);
  const otpType = row.otp_type || "totp";
  if (otpType === "hotp") {
    return json({ error: "Use /api/entries/:id/hotp to generate HOTP code" }, 400);
  }
  const nowSec = Math.floor(Date.now() / 1000);
  const period = normalizeTotpPeriod(row.period);
  const digits = normalizeOtpDigits(row.digits);
  const step = Math.floor(nowSec / period);
  const algorithm = normalizeAlgorithm(row.algorithm || "SHA-1");
  if (!algorithm) return json({ error: "Unsupported OTP algorithm" }, 400);
  const code = await generateTotp(secret, period, digits, algorithm, step);
  const expiresIn = period - (nowSec % period);
  return json({ code, expiresIn, now: nowSec, otpType: "totp" });
}

async function handleVerifyTotp(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  const id = pathResourceId(request, "entries");
  if (!Number.isFinite(id)) return json({ error: "Invalid id" }, 400);

  const body = await parseJson(request);
  const submittedCode = String(body.code || "").replace(/\s+/g, "");
  if (!/^\d{6,8}$/.test(submittedCode)) return json({ error: "code must be 6 to 8 digits" }, 400);
  const verifyLimit = await applyTotpVerifyRateLimit(request, env, id);
  if (verifyLimit) return verifyLimit;

  const row = await env.DB.prepare("SELECT * FROM totp_entries WHERE id = ?").bind(id).first();
  if (!row) return json({ error: "Entry not found" }, 404);
  if (auth.user.role !== "admin" && row.user_id !== auth.user.id) return json({ error: "Forbidden" }, 403);
  if ((row.otp_type || "totp") === "hotp") return json({ error: "Use /api/entries/:id/hotp for HOTP codes" }, 400);

  const algorithm = normalizeAlgorithm(row.algorithm || "SHA-1");
  if (!algorithm) return json({ error: "Unsupported OTP algorithm" }, 400);
  const secret = await decryptText(row.secret_enc, env);
  const nowSec = Math.floor(Date.now() / 1000);
  const period = normalizeTotpPeriod(row.period);
  const digits = normalizeOtpDigits(row.digits);
  const currentStep = Math.floor(nowSec / period);
  for (const windowOffset of [-1, 0, 1]) {
    const expected = await generateTotp(secret, period, digits, algorithm, currentStep + windowOffset);
    if (constantTimeEqual(enc(submittedCode), enc(expected))) {
      return json({ ok: true, valid: true, window: windowOffset });
    }
  }
  return json({ ok: true, valid: false });
}

async function handleConsumeHotp(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  const id = pathResourceId(request, "entries");
  if (!Number.isFinite(id)) return json({ error: "Invalid id" }, 400);

  const row = await env.DB.prepare("SELECT * FROM totp_entries WHERE id = ?").bind(id).first();
  if (!row) return json({ error: "Entry not found" }, 404);
  if (auth.user.role !== "admin" && row.user_id !== auth.user.id) return json({ error: "Forbidden" }, 403);
  if ((row.otp_type || "totp") !== "hotp") return json({ error: "This entry is not HOTP" }, 400);

  const hotpLimit = await applyHotpConsumeRateLimit(request, env, id);
  if (hotpLimit) return hotpLimit;

  const secret = await decryptText(row.secret_enc, env);
  const counter = Number(row.hotp_counter || 0);
  const digits = normalizeOtpDigits(row.digits);
  const algorithm = normalizeAlgorithm(row.algorithm || "SHA-1");
  if (!algorithm) return json({ error: "Unsupported OTP algorithm" }, 400);

  // F-06 fix: single atomic UPDATE ... RETURNING to prevent TOCTOU race.
  // D1 serialises writes per DO, so RETURNING + increment is naturally atomic.
  const result = await env.DB.prepare(
    "UPDATE totp_entries SET hotp_counter = hotp_counter + 1 WHERE id = ? AND otp_type = 'hotp' RETURNING hotp_counter - 1 AS old_counter, hotp_counter AS new_counter"
  ).bind(id).first();

  if (!result || result.old_counter === undefined) {
    return json({ error: "HOTP code already consumed, please retry" }, 409);
  }

  const usedCounter = Number(result.old_counter);
  const nextCounter = Number(result.new_counter);
  const code = await generateHotp(secret, digits, algorithm, usedCounter);
  return json({ code, counter: usedCounter, nextCounter, otpType: "hotp" });
}

async function handleListGroups(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  if (auth.user.role === "admin") {
    const rows = await env.DB.prepare(
      "SELECT g.id, g.user_id, u.username, g.name, g.color, g.created_at FROM groups g JOIN users u ON u.id = g.user_id ORDER BY g.id DESC"
    ).all();
    return json({ groups: rows.results || [] });
  }
  const rows = await env.DB.prepare(
    "SELECT id, user_id, name, color, created_at FROM groups WHERE user_id = ? ORDER BY id DESC"
  )
    .bind(auth.user.id)
    .all();
  return json({ groups: rows.results || [] });
}

async function handleCreateGroup(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;

  const body = await parseJson(request);
  const name = String(body.name || "").trim();
  const color = validHexColor(body.color) ? body.color : "#0f766e";
  if (!name) return json({ error: "name is required" }, 400);
  if (name.length > GROUP_NAME_MAX_LENGTH) return json({ error: `name must be at most ${GROUP_NAME_MAX_LENGTH} characters` }, 400);
  const requestedUserId = Number(body.userId !== undefined ? body.userId : auth.user.id);
  const userId = auth.user.role === "admin" ? requestedUserId : auth.user.id;
  if (!Number.isInteger(userId) || userId <= 0) return json({ error: "userId must be a positive integer" }, 400);
  if (auth.user.role === "admin") {
    const exists = await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(userId).first();
    if (!exists) return json({ error: "userId does not exist" }, 400);
  }

  try {
    const result = await env.DB.prepare(
      "INSERT INTO groups (user_id, name, color, created_at) VALUES (?, ?, ?, ?)"
    )
      .bind(userId, name, color, nowIso())
      .run();
    return json({ ok: true, id: normalizeDbId(result.meta?.last_row_id) }, 201);
  } catch {
    return json({ error: "Group name already exists for this user" }, 409);
  }
}

async function handleDeleteGroup(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  const id = pathResourceId(request, "groups");
  if (!Number.isFinite(id)) return json({ error: "Invalid id" }, 400);

  const row = await env.DB.prepare("SELECT id, user_id FROM groups WHERE id = ?").bind(id).first();
  if (!row) return json({ error: "Group not found" }, 404);
  if (auth.user.role !== "admin" && row.user_id !== auth.user.id) return json({ error: "Forbidden" }, 403);

  await env.DB.prepare("UPDATE totp_entries SET group_id = NULL WHERE group_id = ?").bind(id).run();
  await env.DB.prepare("DELETE FROM groups WHERE id = ?").bind(id).run();
  return json({ ok: true });
}

async function handleExportData(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  const confirmation = await requirePlaintextExportConfirmation(request, env, auth);
  if (confirmation) return confirmation;
  return json(await getExportPayload(auth, env));
}

async function handleImportData(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;

  const body = await parseJson(request);
  return importPayload(body, auth, env);
}

async function handleExportOtpAuth(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  const confirmation = await requirePlaintextExportConfirmation(request, env, auth);
  if (confirmation) return confirmation;

  const entriesQuery =
    auth.user.role === "admin"
      ? env.DB.prepare("SELECT id, user_id, label, issuer, secret_enc, digits, period, algorithm, otp_type, hotp_counter FROM totp_entries ORDER BY id ASC")
      : env.DB.prepare("SELECT id, user_id, label, issuer, secret_enc, digits, period, algorithm, otp_type, hotp_counter FROM totp_entries WHERE user_id = ? ORDER BY id ASC").bind(auth.user.id);
  const entriesRes = await entriesQuery.all();
  const lines = [];
  for (const e of entriesRes.results || []) {
    const secret = await decryptText(e.secret_enc, env);
    lines.push(buildOtpAuthUri({ ...e, secret }));
  }
  const text = lines.join("\n");
  return new Response(text, {
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
      "content-disposition": `attachment; filename="otpauth-export-${Date.now()}.txt"`,
    },
  });
}

async function handleImportOtpAuth(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  const body = await parseJson(request);
  const text = String(body.text || "");
  if (!text.trim()) return json({ error: "text is required" }, 400);

  // N-07 fix: reject oversized payloads to prevent CPU/memory spikes
  if (text.length > 200_000) return json({ error: "otpauth text too large (max 200KB)" }, 413);

  // Non-admin users can ONLY import to their own account (security fix)
  const requestedUserId = Number(body.userId !== undefined ? body.userId : auth.user.id);
  if (auth.user.role !== "admin" && requestedUserId !== auth.user.id) {
    return json({ error: "Forbidden: cannot import data to another user's account" }, 403);
  }
  const userId = auth.user.role === "admin" ? requestedUserId : auth.user.id;
  if (!Number.isInteger(userId) || userId <= 0) return json({ error: "userId must be a positive integer" }, 400);
  if (auth.user.role === "admin") {
    const exists = await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(userId).first();
    if (!exists) return json({ error: "userId does not exist" }, 400);
  }

  const uris = extractOtpAuthUris(text);
  if (!uris.length) return json({ error: "No otpauth URI found in text" }, 400);
  // F-10 fix: limit otpauth import size
  if (uris.length > 500) {
    return json({ error: "Too many otpauth URIs (max 500)" }, 400);
  }

  let imported = 0;
  const errors = [];
  for (const uri of uris) {
    const parsed = parseOtpAuthUri(uri);
    if (!parsed.ok) {
      errors.push(parsed.error);
      continue;
    }
    const data = parsed.data;
    const secret = String(data.secret || "").trim();
    const label = String(data.label || "").trim();
    if (!secret || !label) {
      errors.push("Missing secret/label");
      continue;
    }
    if (label.length > ENTRY_LABEL_MAX_LENGTH) { errors.push("Label too long"); continue; }
    const issuer = String(data.issuer || "").trim();
    if (issuer.length > ENTRY_ISSUER_MAX_LENGTH) { errors.push("Issuer too long"); continue; }
    try {
      const secretBytes = base32Decode(secret);
      if (!secretBytes.length) throw new Error("invalid");
      const digits = normalizeOtpDigits(data.digits);
      const period = normalizeTotpPeriod(data.period);
      const algorithm = normalizeAlgorithm(data.algorithm || "SHA-1");
      if (!algorithm) {
        errors.push("Unsupported OTP algorithm");
        continue;
      }
      const otpType = data.otpType === "hotp" ? "hotp" : "totp";
      const hotpCounter = normalizeHotpCounter(data.hotpCounter);
      const secretEnc = await encryptText(secret, env);
      await env.DB.prepare(
        "INSERT INTO totp_entries (user_id, label, issuer, secret_enc, digits, period, algorithm, otp_type, hotp_counter, group_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)"
      )
        .bind(userId, label, issuer, secretEnc, digits, period, algorithm, otpType, hotpCounter, nowIso())
        .run();
      imported += 1;
    } catch (e) {
      errors.push(String(e && e.message ? e.message : "failed"));
    }
  }

  return json({
    ok: true,
    found: uris.length,
    imported,
    failed: uris.length - imported,
    errors: errors.slice(0, 5),
  });
}

async function requirePlaintextExportConfirmation(request, env, auth) {
  if (String(env.ALLOW_PLAINTEXT_EXPORT || "").toLowerCase() !== "true") {
    return json({ error: "Plaintext export is disabled. Use /api/export/encrypted." }, 403);
  }
  // Read password from request body for re-verification
  let password;
  try {
    const body = await parseJson(request.clone());
    password = String(body.confirmPassword || "");
  } catch {
    return json({ error: "Password confirmation required for plaintext export." }, 400);
  }
  if (!password) {
    return json({ error: "Password confirmation required for plaintext export." }, 400);
  }
  // Retrieve user's current password hash for verification
  const userRow = await env.DB.prepare(
    "SELECT password_hash, password_salt FROM users WHERE id = ?"
  ).bind(auth.user.id).first();
  if (!userRow) return json({ error: "User not found" }, 401);
  const passwordCheck = await verifyPassword(password, userRow.password_salt, userRow.password_hash);
  if (!passwordCheck) {
    return json({ error: "Invalid password confirmation" }, 401);
  }
  return null;
}

async function getExportPayload(auth, env) {
  const groupsQuery =
    auth.user.role === "admin"
      ? env.DB.prepare("SELECT id, user_id, name, color, created_at FROM groups ORDER BY id ASC")
      : env.DB.prepare("SELECT id, user_id, name, color, created_at FROM groups WHERE user_id = ? ORDER BY id ASC").bind(auth.user.id);
  const entriesQuery =
    auth.user.role === "admin"
      ? env.DB.prepare("SELECT id, user_id, label, issuer, secret_enc, digits, period, algorithm, otp_type, hotp_counter, group_id, created_at FROM totp_entries ORDER BY id ASC")
      : env.DB.prepare("SELECT id, user_id, label, issuer, secret_enc, digits, period, algorithm, otp_type, hotp_counter, group_id, created_at FROM totp_entries WHERE user_id = ? ORDER BY id ASC").bind(auth.user.id);

  const [groupsRes, entriesRes] = await Promise.all([groupsQuery.all(), entriesQuery.all()]);
  const entries = [];
  for (const e of entriesRes.results || []) {
    entries.push({
      ...e,
      secret: await decryptText(e.secret_enc, env),
      secret_enc: undefined,
    });
  }
  return {
    format: "worker-2fauth-export-v1",
    exportedAt: nowIso(),
    by: auth.user.username,
    groups: groupsRes.results || [],
    entries,
  };
}

async function importPayload(body, auth, env) {
  const groups = Array.isArray(body.groups) ? body.groups : [];
  const entries = Array.isArray(body.entries) ? body.entries : [];

  // F-10 fix: limit import size to prevent DoS
  const MAX_IMPORT_ENTRIES = 500;
  const MAX_IMPORT_GROUPS = 100;
  if (groups.length > MAX_IMPORT_GROUPS) {
    return json({ error: `groups cannot exceed ${MAX_IMPORT_GROUPS}` }, 400);
  }
  if (entries.length > MAX_IMPORT_ENTRIES) {
    return json({ error: `entries cannot exceed ${MAX_IMPORT_ENTRIES}` }, 400);
  }
  const imported = { groups: 0, entries: 0 };

  // Admin can only import to their own account unless explicitly managing another user
  // Non-admin users can ONLY import to their own account (security fix)
  const requestedUserId = Number(body.userId !== undefined ? body.userId : auth.user.id);
  if (auth.user.role !== "admin" && requestedUserId !== auth.user.id) {
    return json({ error: "Forbidden: cannot import data to another user's account" }, 403);
  }
  const userId = auth.user.role === "admin" ? requestedUserId : auth.user.id;
  if (!Number.isInteger(userId) || userId <= 0) return json({ error: "userId must be a positive integer" }, 400);
  if (auth.user.role === "admin") {
    const exists = await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(userId).first();
    if (!exists) return json({ error: "userId does not exist" }, 400);
  }

  const groupMap = new Map();
  for (const g of groups) {
    const name = String(g.name || "").trim();
    if (!name) continue;
    if (name.length > GROUP_NAME_MAX_LENGTH) continue;
    const color = validHexColor(g.color) ? g.color : "#0f766e";
    try {
      const res = await env.DB.prepare(
        "INSERT INTO groups (user_id, name, color, created_at) VALUES (?, ?, ?, ?)"
      )
        .bind(userId, name, color, nowIso())
        .run();
      const newId = normalizeDbId(res.meta?.last_row_id);
      groupMap.set(String(g.id), newId);
      imported.groups += 1;
    } catch {
      const exists = await env.DB.prepare("SELECT id FROM groups WHERE user_id = ? AND name = ?").bind(userId, name).first();
      if (exists) groupMap.set(String(g.id), normalizeDbId(exists.id));
    }
  }

  for (const e of entries) {
    const secret = String(e.secret || "").trim();
    const label = String(e.label || "").trim();
    const issuer = String(e.issuer || "").trim();
    if (!secret || !label) continue;
    if (label.length > ENTRY_LABEL_MAX_LENGTH) continue;
    if (issuer.length > ENTRY_ISSUER_MAX_LENGTH) continue;
    try {
      const secretBytes = base32Decode(secret);
      if (!secretBytes.length) continue;
    } catch {
      continue;
    }
    const groupId = e.group_id !== undefined && e.group_id !== null ? groupMap.get(String(e.group_id)) || null : null;
    const otpType = e.otp_type === "hotp" ? "hotp" : "totp";
    const algorithm = normalizeAlgorithm(e.algorithm || "SHA-1");
    if (!algorithm) continue;
    const digits = normalizeOtpDigits(e.digits);
    const period = normalizeTotpPeriod(e.period);
    const hotpCounter = normalizeHotpCounter(e.hotp_counter);
    const secretEnc = await encryptText(secret, env);

    await env.DB.prepare(
      "INSERT INTO totp_entries (user_id, label, issuer, secret_enc, digits, period, algorithm, otp_type, hotp_counter, group_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
      .bind(userId, label, issuer, secretEnc, digits, period, algorithm, otpType, hotpCounter, groupId, nowIso())
      .run();
    imported.entries += 1;
  }

  return json({ ok: true, imported });
}

async function handleExportDataEncrypted(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  const body = await parseJson(request);
  const passphrase = String(body.passphrase || "");
  if (passphrase.length < ENCRYPTED_BACKUP_PASSPHRASE_MIN_LENGTH) {
    return json({ error: `passphrase must be at least ${ENCRYPTED_BACKUP_PASSPHRASE_MIN_LENGTH} chars` }, 400);
  }

  const plainData = await getExportPayload(auth, env);
  const encrypted = await encryptWithPassphrase(plainData, passphrase);
  return json({ ok: true, encrypted });
}

async function handleImportDataEncrypted(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;

  const body = await parseJson(request);
  const passphrase = String(body.passphrase || "");
  const encrypted = body.encrypted;
  if (passphrase.length < ENCRYPTED_BACKUP_PASSPHRASE_MIN_LENGTH) return json({ error: `passphrase must be at least ${ENCRYPTED_BACKUP_PASSPHRASE_MIN_LENGTH} chars` }, 400);
  if (!encrypted || typeof encrypted !== "object") return json({ error: "encrypted payload is required" }, 400);

  let data;
  try {
    data = await decryptWithPassphrase(encrypted, passphrase);
  } catch {
    return json({ error: "failed to decrypt payload (wrong passphrase or payload corrupted)" }, 400);
  }

  return importPayload(data, auth, env);
}

async function handleDeleteEntry(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  const id = pathResourceId(request, "entries");
  if (!Number.isFinite(id)) return json({ error: "Invalid id" }, 400);

  const row = await env.DB.prepare("SELECT id, user_id FROM totp_entries WHERE id = ?").bind(id).first();
  if (!row) return json({ error: "Entry not found" }, 404);
  if (auth.user.role !== "admin" && row.user_id !== auth.user.id) return json({ error: "Forbidden" }, 403);

  await env.DB.prepare("DELETE FROM totp_entries WHERE id = ?").bind(id).run();
  return json({ ok: true });
}

async function handleListUsers(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  if (auth.user.role !== "admin") return json({ error: "Forbidden" }, 403);

  const rows = await env.DB.prepare("SELECT id, username, role, created_at FROM users ORDER BY id ASC").all();
  return json({ users: rows.results || [] });
}

async function handleCreateUser(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  if (auth.user.role !== "admin") return json({ error: "Forbidden" }, 403);

  const body = await parseJson(request);
  const username = normalizeUsername(body.username);
  const password = String(body.password || "");
  const role = body.role === "admin" ? "admin" : "user";
    if (!username || !validPassword(password)) {
      return json({ error: "Invalid username or password" }, 400);
  }

  const { hashB64, saltB64 } = await hashPassword(password);
  const now = nowIso();
  try {
    const result = await env.DB.prepare(
      "INSERT INTO users (username, password_hash, password_salt, role, created_at) VALUES (?, ?, ?, ?, ?)"
    )
      .bind(username, encodePasswordHash(hashB64), saltB64, role, now)
      .run();
    return json({ ok: true, id: normalizeDbId(result.meta?.last_row_id) }, 201);
  } catch {
    return json({ error: "Username already exists" }, 409);
  }
}

async function handleChangeMyPassword(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;

  const body = await parseJson(request);
  const currentPassword = String(body.currentPassword || body.oldPassword || "");
  const newPassword = String(body.newPassword || body.password || "");
  if (!currentPassword || !newPassword) {
    return json({ error: "currentPassword and newPassword are required" }, 400);
  }
    if (!validPassword(newPassword)) {
      return json({ error: "Invalid new password" }, 400);
  }

  const target = await env.DB.prepare("SELECT id, username, password_hash, password_salt FROM users WHERE id = ?")
    .bind(auth.user.id)
    .first();
  if (!target) return json({ error: "User not found" }, 404);

  const passwordCheck = await verifyPasswordDetailed(currentPassword, target.password_salt, target.password_hash);
  if (!passwordCheck.ok) return json({ error: "Invalid current password" }, 401);

  await upgradePasswordHash(env, auth.user.id, newPassword);
  await deleteUserSessions(env, auth.user.id);
  await clearLoginRiskForUsername(env, target.username);

  const headers = auth.sessionKind === "web" ? { "set-cookie": clearSessionCookie() } : {};
  return json({ ok: true }, 200, headers);
}

async function handleResetUserPassword(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  if (auth.user.role !== "admin") return json({ error: "Forbidden" }, 403);

  const id = pathResourceId(request, "users");
  if (!Number.isFinite(id)) return json({ error: "Invalid id" }, 400);
  if (id === auth.user.id) {
    return json({ error: "Use /api/me/password to change your own password" }, 400);
  }

  const body = await parseJson(request);
  const newPassword = String(body.newPassword || body.password || "");
  if (!validPassword(newPassword)) {
    return json({ error: "Invalid new password" }, 400);
  }

  const target = await env.DB.prepare("SELECT id, username FROM users WHERE id = ?").bind(id).first();
  if (!target) return json({ error: "User not found" }, 404);

  await upgradePasswordHash(env, id, newPassword);
  await deleteUserSessions(env, id);
  await clearLoginRiskForUsername(env, target.username);

  return json({ ok: true });
}

async function handleUpdateUserRole(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  if (auth.user.role !== "admin") return json({ error: "Forbidden" }, 403);

  const id = pathResourceId(request, "users");
  if (!Number.isFinite(id)) return json({ error: "Invalid id" }, 400);
  const body = await parseJson(request);
  const role = body.role === "admin" ? "admin" : body.role === "user" ? "user" : null;
  if (!role) return json({ error: "role must be admin or user" }, 400);
  if (id === auth.user.id && role !== "admin") {
    return json({ error: "Cannot demote yourself" }, 400);
  }
  const target = await env.DB.prepare("SELECT id, role FROM users WHERE id = ?").bind(id).first();
  if (!target) return json({ error: "User not found" }, 404);
  if (target.role === "admin" && role !== "admin" && (await countAdmins(env)) <= 1) {
    return json({ error: "Cannot remove the last admin" }, 400);
  }

  await env.DB.prepare("UPDATE users SET role = ? WHERE id = ?").bind(role, id).run();
  return json({ ok: true });
}

async function handleDeleteUser(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  if (auth.user.role !== "admin") return json({ error: "Forbidden" }, 403);

  const id = pathResourceId(request, "users");
  if (!Number.isFinite(id)) return json({ error: "Invalid id" }, 400);
  if (id === auth.user.id) return json({ error: "Cannot delete yourself" }, 400);

  const target = await env.DB.prepare("SELECT id, username, role FROM users WHERE id = ?").bind(id).first();
  if (!target) return json({ error: "User not found" }, 404);
  if (target.role === "admin" && (await countAdmins(env)) <= 1) {
    return json({ error: "Cannot delete the last admin" }, 400);
  }

  // Cascade delete: remove all related data before deleting user
  // This prevents orphaned records and ensures data consistency
  await env.DB.prepare("DELETE FROM totp_entries WHERE user_id = ?").bind(id).run();
  await env.DB.prepare("DELETE FROM groups WHERE user_id = ?").bind(id).run();
  await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(id).run();
  await env.DB.prepare("DELETE FROM api_sessions WHERE user_id = ?").bind(id).run();
  await env.DB.prepare("DELETE FROM login_risk_control WHERE username = ?").bind(target.username).run();
  await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
  return json({ ok: true });
}

async function handleGetLoginPolicy(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  if (auth.user.role !== "admin") return json({ error: "Forbidden" }, 403);
  return json(await getLoginPolicy(env));
}

async function handleUpdateLoginPolicy(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  if (auth.user.role !== "admin") return json({ error: "Forbidden" }, 403);

  const body = await parseJson(request);
  const maxRequestsPerMinute = Number(body.maxRequestsPerMinute);
  const lockMinutes = Number(body.lockMinutes);
  if (!Number.isFinite(maxRequestsPerMinute) || maxRequestsPerMinute < 3 || maxRequestsPerMinute > 100) {
    return json({ error: "maxRequestsPerMinute must be between 3 and 100" }, 400);
  }
  if (!Number.isFinite(lockMinutes) || lockMinutes < 1 || lockMinutes > 1440) {
    return json({ error: "lockMinutes must be between 1 and 1440" }, 400);
  }

  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(
    "INSERT INTO app_settings (key, value, updated_at) VALUES ('risk_max_requests_per_minute', ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at"
  )
    .bind(String(Math.floor(maxRequestsPerMinute)), now)
    .run();
  await env.DB.prepare(
    "INSERT INTO app_settings (key, value, updated_at) VALUES ('risk_lock_minutes', ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at"
  )
    .bind(String(Math.floor(lockMinutes)), now)
    .run();

  return json({ ok: true, ...(await getLoginPolicy(env)) });
}

async function hasAnyUser(env) {
  const row = await env.DB.prepare("SELECT id FROM users LIMIT 1").first();
  return !!row;
}

async function countAdmins(env) {
  const row = await env.DB.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'").first();
  return Number(row?.count || 0);
}

async function getUsernameById(env, userId) {
  const row = await env.DB.prepare("SELECT username FROM users WHERE id = ?").bind(userId).first();
  return row ? row.username : null;
}

async function getLoginPolicy(env) {
  let rows;
  try {
    rows = await env.DB.prepare(
      "SELECT key, value FROM app_settings WHERE key IN ('risk_max_requests_per_minute', 'risk_lock_minutes')"
    ).all();
  } catch (err) {
    if (isMissingTableError(err, "app_settings")) return defaultLoginPolicy();
    throw err;
  }
  const map = new Map((rows.results || []).map((r) => [r.key, r.value]));
  const maxRequestsPerMinute = Number(map.get("risk_max_requests_per_minute") || DEFAULT_RISK_MAX_REQUESTS_PER_MINUTE);
  const lockMinutes = Number(map.get("risk_lock_minutes") || DEFAULT_RISK_LOCK_MINUTES);
  return {
    maxRequestsPerMinute: Number.isFinite(maxRequestsPerMinute) ? maxRequestsPerMinute : DEFAULT_RISK_MAX_REQUESTS_PER_MINUTE,
    lockMinutes: Number.isFinite(lockMinutes) ? lockMinutes : DEFAULT_RISK_LOCK_MINUTES,
  };
}

function defaultLoginPolicy() {
  return {
    maxRequestsPerMinute: DEFAULT_RISK_MAX_REQUESTS_PER_MINUTE,
    lockMinutes: DEFAULT_RISK_LOCK_MINUTES,
  };
}

async function applyLoginRiskControl(request, env, username) {
  const nowSec = Math.floor(Date.now() / 1000);
  const policy = await getLoginPolicy(env);
  const ip = clientIp(request);
  const usernameKey = await sha256Base64(`login|user-ip|${username || "__empty__"}|${ip}`);
  // P1 fix: use global bucket for unknown IP to prevent cross-user lockout
  const ipKey = ip === "unknown" ? await sha256Base64("login|ip|unknown-global") : await sha256Base64(`login|ip|${ip}`);
  const ipPolicy = { ...policy, maxRequestsPerMinute: policy.maxRequestsPerMinute * 2 };
  let userRisk;
  let ipRisk;
  try {
    [userRisk, ipRisk] = await Promise.all([
      updateLoginRiskBucket(env, usernameKey, username || "__empty__", ip, nowSec, policy),
      updateLoginRiskBucket(env, ipKey, "__any__", ip, nowSec, ipPolicy),
    ]);
  } catch (err) {
    if (isMissingTableError(err, "login_risk_control")) throw new ApiError(503, "Service temporarily unavailable");
    throw err;
  }

  if (userRisk.blocked && ipRisk.blocked) {
    return userRisk.retryAfterSeconds >= ipRisk.retryAfterSeconds ? userRisk : ipRisk;
  }
  if (userRisk.blocked) return userRisk;
  if (ipRisk.blocked) return ipRisk;
  return { blocked: false };
}

async function updateLoginRiskBucket(env, riskKey, username, ip, nowSec, policy) {
  let row;
  row = await env.DB.prepare(
    "SELECT key, window_start, request_count, lock_until FROM login_risk_control WHERE key = ?"
  )
    .bind(riskKey)
    .first();

  if (row && Number(row.lock_until) > nowSec) {
    return {
      blocked: true,
      retryAfterSeconds: Number(row.lock_until) - nowSec,
      lockUntil: Number(row.lock_until),
    };
  }

  let windowStart = nowSec;
  let lockUntil = 0;
  let requestCount = 1;
  if (row && nowSec - Number(row.window_start) < 60) {
    windowStart = Number(row.window_start);
    requestCount = Number(row.request_count) + 1;
  }
  if (requestCount >= policy.maxRequestsPerMinute) {
    lockUntil = nowSec + policy.lockMinutes * 60;
  }

  await env.DB.prepare(
    "INSERT INTO login_risk_control (key, username, ip, window_start, request_count, lock_until, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET username = excluded.username, ip = excluded.ip, window_start = excluded.window_start, request_count = excluded.request_count, lock_until = excluded.lock_until, updated_at = excluded.updated_at"
  )
    .bind(riskKey, username || "__empty__", ip, windowStart, requestCount, lockUntil, nowSec)
    .run();

  if (lockUntil > nowSec) {
    return { blocked: true, retryAfterSeconds: lockUntil - nowSec, lockUntil };
  }
  return { blocked: false };
}

async function clearLoginRiskControl(request, env, username) {
  const ip = clientIp(request);
  const usernameKey = await sha256Base64(`login|user-ip|${username || "__empty__"}|${ip}`);
  const ipKey = await sha256Base64(`login|ip|${ip}`);
  await env.DB.prepare("DELETE FROM login_risk_control WHERE key IN (?, ?)")
    .bind(usernameKey, ipKey)
    .run();
}

async function clearLoginRiskForUsername(env, username) {
  const normalized = String(username || "").trim();
  if (!normalized) return;
  await env.DB.prepare("DELETE FROM login_risk_control WHERE username = ?").bind(normalized).run();
}

async function deleteUserSessions(env, userId) {
  await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(userId).run().catch((err) => {
    if (isMissingTableError(err, "sessions")) return;
    throw err;
  });
  await env.DB.prepare("DELETE FROM api_sessions WHERE user_id = ?").bind(userId).run().catch((err) => {
    if (isMissingTableError(err, "api_sessions")) return;
    throw err;
  });
}

async function applyApiRateLimit(request, env, route) {
  if (!shouldRateLimitRoute(request, route)) return null;

  const nowSec = Math.floor(Date.now() / 1000);
  const maxRequests = normalizeRateLimit(env.API_RATE_MAX_REQUESTS_PER_MINUTE, DEFAULT_API_RATE_MAX_REQUESTS_PER_MINUTE);
  const subject = await apiRateLimitSubject(request, env);
  const rateKey = await sha256Base64(`api|${subject}`);
  let row;
  try {
    row = await env.DB.prepare(
      "SELECT key, window_start, request_count, lock_until FROM login_risk_control WHERE key = ?"
    )
      .bind(rateKey)
      .first();
  } catch (err) {
    return json({ error: "API rate limiter unavailable" }, 503);
  }

  if (row && Number(row.lock_until) > nowSec) {
    return json(
      { error: "Too many API requests. Temporarily locked.", retryAfterSeconds: Number(row.lock_until) - nowSec },
      429,
      { "Retry-After": String(Number(row.lock_until) - nowSec) }
    );
  }

  let windowStart = nowSec;
  let lockUntil = 0;
  let requestCount = 1;
  if (row && nowSec - Number(row.window_start) < 60) {
    windowStart = Number(row.window_start);
    requestCount = Number(row.request_count) + 1;
  }
  if (requestCount > maxRequests) {
    const lockMinutes = normalizeRateLimit(env.API_RATE_LOCK_MINUTES, DEFAULT_API_RATE_LOCK_MINUTES);
    lockUntil = nowSec + lockMinutes * 60;
  }

  try {
    await env.DB.prepare(
      "INSERT INTO login_risk_control (key, username, ip, window_start, request_count, lock_until, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET username = excluded.username, ip = excluded.ip, window_start = excluded.window_start, request_count = excluded.request_count, lock_until = excluded.lock_until, updated_at = excluded.updated_at"
    )
      .bind(rateKey, "__api__", clientIp(request), windowStart, requestCount, lockUntil, nowSec)
      .run();
  } catch (err) {
    return json({ error: "API rate limiter unavailable" }, 503);
  }

  if (requestCount > maxRequests) {
    return json(
      { error: "Too many API requests. Temporarily locked.", retryAfterSeconds: lockUntil - nowSec },
      429,
      { "Retry-After": String(lockUntil - nowSec) }
    );
  }
  return null;
}

async function applyTotpVerifyRateLimit(request, env, entryId) {
  const nowSec = Math.floor(Date.now() / 1000);
  const subject = await apiRateLimitSubject(request, env);
  const rateKey = await sha256Base64(`totp-verify|${entryId}|${subject}`);
  const policy = {
    maxRequestsPerMinute: normalizeRateLimit(
      env.TOTP_VERIFY_MAX_REQUESTS_PER_MINUTE,
      DEFAULT_TOTP_VERIFY_MAX_REQUESTS_PER_MINUTE
    ),
    lockMinutes: normalizeRateLimit(env.TOTP_VERIFY_LOCK_MINUTES, DEFAULT_TOTP_VERIFY_LOCK_MINUTES),
  };

  let result;
  try {
    result = await updateLoginRiskBucket(env, rateKey, "__totp_verify__", clientIp(request), nowSec, policy);
  } catch (err) {
    return json({ error: "TOTP verification rate limiter unavailable" }, 503);
  }

  if (result.blocked) {
    return json(
      { error: "Too many TOTP verification attempts. Temporarily locked.", retryAfterSeconds: result.retryAfterSeconds },
      429,
      { "Retry-After": String(result.retryAfterSeconds) }
    );
  }
  return null;
}

async function applyHotpConsumeRateLimit(request, env, entryId) {
  const nowSec = Math.floor(Date.now() / 1000);
  const subject = await apiRateLimitSubject(request, env);
  const rateKey = await sha256Base64(`hotp-consume|${entryId}|${subject}`);
  const policy = {
    maxRequestsPerMinute: Number(env.HOTP_CONSUME_MAX_REQUESTS_PER_MINUTE) || DEFAULT_HOTP_CONSUME_MAX_REQUESTS_PER_MINUTE,
    lockMinutes: Number(env.HOTP_CONSUME_LOCK_MINUTES) || DEFAULT_HOTP_CONSUME_LOCK_MINUTES,
  };

  let result;
  try {
    result = await updateLoginRiskBucket(env, rateKey, "__hotp_consume__", clientIp(request), nowSec, policy);
  } catch (err) {
    return json({ error: "HOTP rate limiter unavailable" }, 503);
  }

  if (result.blocked) {
    return json(
      { error: "Too many HOTP requests. Temporarily locked.", retryAfterSeconds: result.retryAfterSeconds },
      429,
      { "Retry-After": String(result.retryAfterSeconds) }
    );
  }
  return null;
}

function shouldRateLimitRoute(request, route) {
  if (request.method.toUpperCase() === "OPTIONS") return false;
  const path = new URL(request.url).pathname;
  if (path === "/api/status" || path === "/api/v1/capabilities") return false;
  if (
    [
      "/api/login",
      "/api/mobile/login",
      "/api/extension/login",
      "/api/v1/auth/login",
      "/api/bootstrap",
    ].includes(path)
  ) {
    return false;
  }
  return !!route;
}

async function apiRateLimitSubject(request, env) {
  const bearerToken = readBearerToken(request);
  if (bearerToken) return `bearer:${await hashSessionToken(bearerToken, env)}`;
  const sessionToken = readCookie(request, SESSION_COOKIE);
  if (sessionToken) return `cookie:${await hashSessionToken(sessionToken, env)}`;
  const ip = clientIp(request);
  // P1 fix: avoid shared rate-limit bucket when IP is unknown (non-CF environments)
  return ip === "unknown" ? `ip:${crypto.randomUUID()}` : `ip:${ip}`;
}

function normalizeRateLimit(value, fallback) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 10 && n <= 5000 ? Math.floor(n) : fallback;
}

function isMissingTableError(err, tableName) {
  return dbErrorMessage(err).includes(`no such table: ${String(tableName).toLowerCase()}`);
}

function isMissingColumnError(err, columnName) {
  const msg = dbErrorMessage(err);
  const column = String(columnName).toLowerCase();
  return msg.includes(`no such column: ${column}`) || msg.includes(`has no column named ${column}`);
}

function dbErrorMessage(err) {
  return String(err?.message || err || "").toLowerCase();
}

function clientIp(request) {
  // Only trust cf-connecting-ip (set by Cloudflare edge, not spoofable by client).
  // x-forwarded-for / x-real-ip are client-controlled and must not be used.
  const value = String(request.headers.get("cf-connecting-ip") || "")
    .split(",")[0]
    .trim();
  return value || "unknown";
}

async function verifyTurnstileToken(token, remoteip, env) {
  const secretKey = String(env.TURNSTILE_SECRET_KEY || env.TURNSTILE_KEY || "");
  if (!secretKey) return { ok: false };
  if (!token) return { ok: false };
  const body = new URLSearchParams();
  body.set("secret", secretKey);
  body.set("response", token);
  if (remoteip) body.set("remoteip", remoteip);
  const resp = await fetch(TURNSTILE_VERIFY_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  if (!resp.ok) return { ok: false };
  const data = await resp.json().catch(() => ({}));
  return { ok: !!data.success };
}

async function requireAuth(request, env) {
  const current = await getCurrentUser(request, env);
  if (!current) return { ok: false, response: json({ error: "Unauthorized" }, 401) };
  return { ok: true, ...current };
}

async function getCurrentUser(request, env) {
  const bearerToken = readBearerToken(request);
  if (bearerToken) {
    const tokenHash = await hashSessionToken(bearerToken, env);
    const now = nowIso();
    let row = null;
    try {
      row = await env.DB.prepare(
        "SELECT s.id AS session_id, s.client_type, u.id, u.username, u.role FROM api_sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?"
      )
        .bind(tokenHash, now)
        .first();
    } catch (err) {
      if (!isMissingTableError(err, "api_sessions")) throw err;
    }
    if (row) {
      await env.DB.prepare("UPDATE api_sessions SET last_used_at = ? WHERE id = ?").bind(now, row.session_id).run();
      return {
        user: { id: row.id, username: row.username, role: row.role },
        sessionKind: "api",
        sessionId: row.session_id,
        apiClientType: String(row.client_type || ANDROID_CLIENT_TYPE),
      };
    }
  }

  const token = readCookie(request, SESSION_COOKIE);
  if (!token) return null;
  const tokenHash = await hashSessionToken(token, env);
  const now = nowIso();
  const row = await env.DB.prepare(
    "SELECT u.id, u.username, u.role FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ?"
  )
    .bind(tokenHash, now)
    .first();
  if (!row) return null;
  return { user: row, sessionKind: "web" };
}

async function createSession(env, userId) {
  const token = randomHex(32);
  const tokenHash = await hashSessionToken(token, env);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_TTL_SECONDS * 1000).toISOString();
  const result = await insertWebSession(env, userId, tokenHash, expiresAt, now.toISOString());
  let sessionId = normalizeDbId(result.meta?.last_row_id);
  if (!sessionId) {
    const row = await env.DB.prepare("SELECT id FROM sessions WHERE token_hash = ? AND user_id = ?")
      .bind(tokenHash, userId)
      .first();
    sessionId = normalizeDbId(row?.id);
  }
  if (sessionId) {
    await env.DB.prepare("DELETE FROM sessions WHERE user_id = ? AND id <> ?").bind(userId, sessionId).run();
  }
  await deleteApiSessionsForUser(env, userId);

  return { cookie: sessionCookie(token, SESSION_TTL_SECONDS) };
}

async function regenerateWebSession(request, env, userId) {
  await revokePresentedWebSession(request, env);
  return createSession(env, userId);
}

async function revokePresentedWebSession(request, env) {
  const token = readCookie(request, SESSION_COOKIE);
  if (!token) return;
  const tokenHash = await hashSessionToken(token, env);
  await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
}

async function refreshSessionTtl(request, env) {
  const token = readCookie(request, SESSION_COOKIE);
  if (!token) return;
  const tokenHash = await hashSessionToken(token, env);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_TTL_SECONDS * 1000).toISOString();
  await env.DB.prepare("UPDATE sessions SET expires_at = ? WHERE token_hash = ?").bind(expiresAt, tokenHash).run();
}

async function cleanExpiredSessions(env) {
  const now = nowIso();
  await env.DB.prepare("DELETE FROM sessions WHERE expires_at <= ?").bind(now).run();
  try {
    await env.DB.prepare("DELETE FROM api_sessions WHERE refresh_expires_at <= ?").bind(now).run();
  } catch (err) {
    if (!isMissingTableError(err, "api_sessions")) throw err;
  }
}

async function insertWebSession(env, userId, tokenHash, expiresAt, createdAt) {
  try {
    return await env.DB.prepare(
      "INSERT INTO sessions (user_id, token_hash, client_type, expires_at, created_at) VALUES (?, ?, 'web', ?, ?)"
    )
      .bind(userId, tokenHash, expiresAt, createdAt)
      .run();
  } catch (err) {
    if (!isMissingColumnError(err, "client_type")) throw err;
    return env.DB.prepare(
      "INSERT INTO sessions (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)"
    )
      .bind(userId, tokenHash, expiresAt, createdAt)
      .run();
  }
}

async function updateWebSessionExpiry(env, tokenHash, expiresAt) {
  try {
    await env.DB.prepare("UPDATE sessions SET expires_at = ? WHERE token_hash = ? AND client_type = 'web'")
      .bind(expiresAt, tokenHash)
      .run();
  } catch (err) {
    if (!isMissingColumnError(err, "client_type")) throw err;
    await env.DB.prepare("UPDATE sessions SET expires_at = ? WHERE token_hash = ?")
      .bind(expiresAt, tokenHash)
      .run();
  }
}

async function deleteApiSessionsForUser(env, userId) {
  try {
    await env.DB.prepare("DELETE FROM api_sessions WHERE user_id = ?").bind(userId).run();
  } catch (err) {
    if (!isMissingTableError(err, "api_sessions")) throw err;
  }
}

async function createApiSession(env, userId, clientType) {
  const accessToken = randomHex(32);
  const refreshToken = randomHex(32);
  const tokenHash = await hashSessionToken(accessToken, env);
  const refreshHash = await hashSessionToken(refreshToken, env);
  const now = new Date();
  const createdAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + API_ACCESS_TTL_SECONDS * 1000).toISOString();
  const refreshExpiresAt = new Date(now.getTime() + API_REFRESH_TTL_SECONDS * 1000).toISOString();

  await env.DB.prepare(
    "INSERT INTO api_sessions (user_id, token_hash, refresh_hash, expires_at, refresh_expires_at, created_at, last_used_at, client_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  )
    .bind(userId, tokenHash, refreshHash, expiresAt, refreshExpiresAt, createdAt, createdAt, clientType)
    .run();

  const sessionId = normalizeDbId(
    (
      await env.DB.prepare(
        "SELECT id FROM api_sessions WHERE token_hash = ? AND user_id = ?"
      ).bind(tokenHash, userId).first()
    )?.id
  );
  if (sessionId) {
    await env.DB.prepare("DELETE FROM api_sessions WHERE user_id = ? AND id <> ?")
      .bind(userId, sessionId)
      .run();
  }
  await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(userId).run();
  return { accessToken, refreshToken, expiresIn: API_ACCESS_TTL_SECONDS, sessionId };
}

function hasTurnstileSecret(env) {
  return !!String(env.TURNSTILE_SECRET_KEY || env.TURNSTILE_KEY || "");
}

async function rotateApiSessionTokens(request, env, expectedClientType, options = {}) {
  const body = await parseJson(request);
  const refreshToken = String(body.refreshToken || "").trim();
  if (!refreshToken) return json({ error: "refreshToken is required" }, 400);

  const refreshHash = await hashSessionToken(refreshToken, env);
  const now = nowIso();
  const row = await env.DB.prepare(
    "SELECT s.id, s.client_type, s.user_id, u.username, u.role FROM api_sessions s JOIN users u ON u.id = s.user_id WHERE s.refresh_hash = ? AND s.refresh_expires_at > ?"
  )
    .bind(refreshHash, now)
    .first();
  if (!row) return json({ error: "Invalid refresh token" }, 401);

  if (expectedClientType === ANDROID_CLIENT_TYPE && String(row.client_type || "") !== ANDROID_CLIENT_TYPE) {
    return json({ error: "Invalid refresh token" }, 401);
  }
  if (expectedClientType === EXTENSION_CLIENT_TYPE && !isExtensionClientType(String(row.client_type || ""))) {
    return json({ error: "Invalid refresh token" }, 401);
  }

  const accessToken = randomHex(32);
  const newRefreshToken = randomHex(32);
  const accessHash = await hashSessionToken(accessToken, env);
  const newRefreshHash = await hashSessionToken(newRefreshToken, env);
  const nowDate = new Date();
  const expiresAt = new Date(nowDate.getTime() + API_ACCESS_TTL_SECONDS * 1000).toISOString();
  const refreshExpiresAt = new Date(nowDate.getTime() + API_REFRESH_TTL_SECONDS * 1000).toISOString();

  const result = await env.DB.prepare(
    "UPDATE api_sessions SET token_hash = ?, refresh_hash = ?, expires_at = ?, refresh_expires_at = ?, last_used_at = ? WHERE id = ? AND refresh_hash = ?"
  )
    .bind(accessHash, newRefreshHash, expiresAt, refreshExpiresAt, nowDate.toISOString(), row.id, refreshHash)
    .run();
  if (result.meta?.changes === 0) {
    return json({ error: "Refresh token already used" }, 409);
  }

  const payload = {
    ok: true,
    user: { id: row.user_id, username: row.username, role: row.role },
    accessToken,
    refreshToken: newRefreshToken,
    expiresIn: API_ACCESS_TTL_SECONDS,
  };
  if (options.includeRefreshExpiresIn) {
    payload.refreshExpiresIn = API_REFRESH_TTL_SECONDS;
  }
  return json(payload);
}

function isExtensionClientType(clientType) {
  return String(clientType || "") === EXTENSION_CLIENT_TYPE || String(clientType || "").startsWith(`${EXTENSION_CLIENT_TYPE}:`);
}

function normalizeApiClientType(value) {
  const v = String(value || "").trim().toLowerCase();
  if (v === ANDROID_CLIENT_TYPE) return ANDROID_CLIENT_TYPE;
  if (["browser_extension", "extension", "edge_extension", "chrome_extension", "safari-web-extension"].includes(v)) {
    return "browser_extension";
  }
  return "";
}

function normalizeClientMetadata(value, maxLen, fallback) {
  const normalized = String(value || "").trim().replace(/[^\w.\- ]+/g, "");
  if (!normalized) return fallback;
  return normalized.slice(0, maxLen);
}

async function cleanExpiredLoginRisk(env) {
  const nowSec = Math.floor(Date.now() / 1000);
  // Keep recent rows, remove old/unlocked rows.
  await env.DB.prepare(
    "DELETE FROM login_risk_control WHERE lock_until <= ? AND updated_at < ?"
  )
    .bind(nowSec, nowSec - 24 * 60 * 60)
    .run();
}

async function hashSessionToken(token, env) {
  return sha256Base64(`${token}:${env.SESSION_PEPPER}`);
}

async function hashPassword(password, saltB64, iterations = PBKDF2_ITERATIONS) {
  const salt = saltB64 ? b64ToBytes(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc(String(password)), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: PBKDF2_HASH, iterations, salt },
    key,
    256
  );
  return { hashB64: bytesToB64(new Uint8Array(bits)), saltB64: bytesToB64(salt) };
}

function encodePasswordHash(hashB64, iterations = PBKDF2_ITERATIONS) {
  return `pbkdf2-${PBKDF2_HASH.toLowerCase()}:i=${iterations}:${hashB64}`;
}

function parsePasswordHash(storedHashB64) {
  const text = String(storedHashB64 || "");
  const match = text.match(/^pbkdf2-sha-256:i=([1-9]\d{0,9}):([A-Za-z0-9+/]+={0,2})$/);
  if (!match) return { hashB64: text, iterations: PBKDF2_ITERATIONS, legacy: true };
  const iterations = Number(match[1]);
  if (
    !Number.isSafeInteger(iterations) ||
    iterations < MIN_PASSWORD_PBKDF2_ITERATIONS ||
    iterations > MAX_PASSWORD_PBKDF2_ITERATIONS
  ) {
    throw new Error("invalid password hash iterations");
  }
  return { hashB64: match[2], iterations, legacy: false };
}

async function verifyPassword(password, saltB64, expectedHashB64) {
  return (await verifyPasswordDetailed(password, saltB64, expectedHashB64)).ok;
}

async function verifyPasswordDetailed(password, saltB64, expectedHashB64) {
  try {
    const parsed = parsePasswordHash(expectedHashB64);
    const expected = b64ToBytes(parsed.hashB64);
    const current = await hashPassword(password, saltB64, parsed.iterations);
    if (constantTimeEqual(b64ToBytes(current.hashB64), expected)) {
      return { ok: true, needsRehash: parsed.legacy || parsed.iterations < PBKDF2_ITERATIONS };
    }
  } catch {
    return { ok: false, needsRehash: false };
  }
  return { ok: false, needsRehash: false };
}

async function upgradePasswordHash(env, userId, password) {
  const { hashB64, saltB64 } = await hashPassword(password);
  await env.DB.prepare("UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?")
    .bind(encodePasswordHash(hashB64), saltB64, userId)
    .run();
}

const encryptionKeyCache = new Map();

async function getEncryptionKey(env) {
  // F-02 fix: hash secrets instead of storing plaintext secrets in Map key
  const raw = `${env.ENVIRONMENT || env.NODE_ENV || "default"}|${env.ENCRYPTION_KEY}|${env.SESSION_PEPPER}`;
  const cacheKey = await sha256Base64(raw);
  const now = Date.now();
  for (const [key, entry] of encryptionKeyCache) {
    if (entry.expiresAt <= now) encryptionKeyCache.delete(key);
  }
  const cached = encryptionKeyCache.get(cacheKey);
  if (!cached) {
    if (encryptionKeyCache.size >= 8) encryptionKeyCache.clear();
    const keyPromise = crypto.subtle.importKey(
      "raw",
      b64ToBytes(env.ENCRYPTION_KEY),
      "AES-GCM",
      false,
      ["encrypt", "decrypt"]
    );
    encryptionKeyCache.set(cacheKey, { keyPromise, expiresAt: now + ENCRYPTION_KEY_CACHE_TTL_MS });
    return keyPromise;
  }
  return cached.keyPromise;
}

async function encryptText(plain, env) {
  const key = await getEncryptionKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc(plain));
  return `${bytesToB64(iv)}:${bytesToB64(new Uint8Array(cipher))}`;
}

async function decryptText(payload, env) {
  const [ivB64, ctB64] = String(payload || "").split(":");
  if (!ivB64 || !ctB64) throw new Error("Bad encrypted payload");
  const key = await getEncryptionKey(env);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64ToBytes(ivB64) },
    key,
    b64ToBytes(ctB64)
  );
  return dec(new Uint8Array(plain));
}

async function encryptWithPassphrase(data, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await derivePassphraseKey(passphrase, salt);
  const plaintext = enc(JSON.stringify(data));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return {
    format: "worker-2fauth-encrypted-v1",
    kdf: "PBKDF2-SHA-256",
    iterations: PASSPHRASE_PBKDF2_ITERATIONS,
    salt: bytesToB64(salt),
    iv: bytesToB64(iv),
    ciphertext: bytesToB64(new Uint8Array(cipher)),
  };
}

async function decryptWithPassphrase(payload, passphrase) {
  if (payload.format !== "worker-2fauth-encrypted-v1") throw new Error("unsupported format");
  const iterations = normalizePassphraseIterations(payload.iterations);
  const salt = b64ToBytes(String(payload.salt || ""));
  const iv = b64ToBytes(String(payload.iv || ""));
  const ciphertext = b64ToBytes(String(payload.ciphertext || ""));
  const key = await derivePassphraseKey(passphrase, salt, iterations);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return JSON.parse(dec(new Uint8Array(plain)));
}

async function derivePassphraseKey(passphrase, salt, iterations = PASSPHRASE_PBKDF2_ITERATIONS) {
  const baseKey = await crypto.subtle.importKey("raw", enc(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function normalizePassphraseIterations(value) {
  const iterations = value === undefined || value === null ? PASSPHRASE_PBKDF2_ITERATIONS : Number(value);
  if (
    !Number.isSafeInteger(iterations) ||
    iterations < PASSPHRASE_PBKDF2_ITERATIONS ||
    iterations > MAX_PASSPHRASE_PBKDF2_ITERATIONS
  ) {
    throw new Error("invalid PBKDF2 iterations");
  }
  return iterations;
}

function parseOtpAuthUri(uri) {
  try {
    // F-07: limit input length to prevent ReDoS via URL parser.
    if (typeof uri !== "string" || uri.length > 1024) {
      return { ok: false, error: "otpauth URI too long" };
    }
    const url = new URL(uri);
    if (url.protocol !== "otpauth:" || !["totp", "hotp"].includes(url.hostname)) {
      return { ok: false, error: "Only otpauth://totp or otpauth://hotp URI is supported" };
    }
    const otpType = url.hostname;
    const secret = String(url.searchParams.get("secret") || "").trim();
    if (!secret) return { ok: false, error: "otpauth URI missing secret" };
    const issuerQ = String(url.searchParams.get("issuer") || "").trim();
    // F-07: use substring instead of regex to avoid any backtracking risk.
    const labelRaw = decodeURIComponent(url.pathname.startsWith("/") ? url.pathname.slice(1) : url.pathname);
    let issuer = issuerQ;
    let label = labelRaw;
    if (labelRaw.includes(":")) {
      const [issuerInLabel, account] = labelRaw.split(":");
      if (!issuer) issuer = issuerInLabel.trim();
      label = account.trim();
    }
    const digits = Number(url.searchParams.get("digits") || 6);
    const period = Number(url.searchParams.get("period") || 30);
    const hotpCounter = Number(url.searchParams.get("counter") || 0);
    const algorithm = normalizeAlgorithm(url.searchParams.get("algorithm") || "SHA-1");
    if (!algorithm) return { ok: false, error: "otpauth URI algorithm must be SHA-1, SHA-256, or SHA-512" };
    return {
      ok: true,
      data: { secret, issuer, label: label || issuer || "OTP", digits, period, algorithm, otpType, hotpCounter },
    };
  } catch {
    return { ok: false, error: "Invalid otpauth URI" };
  }
}

function extractOtpAuthUris(text) {
  // F-07: limit input length to prevent DoS via regex on large payloads.
  if (typeof text !== "string" || text.length > 65536) return [];
  const out = [];
  const re = /otpauth:\/\/[^\s"'<>]+/gi;
  let m;
  while ((m = re.exec(String(text || ""))) !== null) out.push(m[0]);
  return [...new Set(out)];
}

function buildOtpAuthUri(entry) {
  const otpType = entry.otp_type === "hotp" ? "hotp" : "totp";
  const label = encodeURIComponent(String(entry.label || "OTP"));
  const params = new URLSearchParams();
  params.set("secret", String(entry.secret || ""));
  if (entry.issuer) params.set("issuer", String(entry.issuer));
  params.set("algorithm", String(normalizeAlgorithm(entry.algorithm || "SHA-1") || "SHA-1").replace("-", ""));
  params.set("digits", String(Number(entry.digits || 6)));
  if (otpType === "hotp") {
    params.set("counter", String(Number(entry.hotp_counter || 0)));
  } else {
    params.set("period", String(Number(entry.period || 30)));
  }
  return `otpauth://${otpType}/${label}?${params.toString()}`;
}

async function generateTotp(secretBase32, period, digits, algorithm, counter) {
  const secretBytes = base32Decode(secretBase32);
  const algo = normalizeAlgorithm(algorithm);
  if (!algo) throw new Error("Unsupported OTP algorithm");
  const key = await crypto.subtle.importKey("raw", secretBytes, { name: "HMAC", hash: { name: algo } }, false, [
    "sign",
  ]);
  const data = new ArrayBuffer(8);
  const view = new DataView(data);
  const high = Math.floor(counter / 2 ** 32);
  const low = counter >>> 0;
  view.setUint32(0, high);
  view.setUint32(4, low);
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const mod = 10 ** digits;
  return String(binCode % mod).padStart(digits, "0");
}

async function generateHotp(secretBase32, digits, algorithm, counter) {
  return generateTotp(secretBase32, 30, digits, algorithm, counter);
}

function base32Decode(input) {
  const clean = String(input).toUpperCase().replace(/[\s=-]/g, "");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) throw new Error("invalid base32");
    bits += idx.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

function normalizeAlgorithm(value) {
  const v = String(value || "").toUpperCase();
  if (v === "SHA1" || v === "SHA-1") return "SHA-1";
  if (v === "SHA256" || v === "SHA-256") return "SHA-256";
  if (v === "SHA512" || v === "SHA-512") return "SHA-512";
  return null;
}

function normalizeOtpDigits(value) {
  const digits = Number(value);
  return [6, 7, 8].includes(digits) ? digits : 6;
}

function normalizeTotpPeriod(value) {
  const period = Number(value);
  return Number.isInteger(period) && period >= 15 && period <= 120 ? period : 30;
}

function normalizeHotpCounter(value) {
  const counter = Number(value);
  return Number.isInteger(counter) && counter >= 0 ? counter : 0;
}

function normalizeUsername(v) {
  const out = String(v || "").trim().toLowerCase();
  return /^[a-z0-9_.-]{3,40}$/.test(out) ? out : "";
}

function validPassword(p) {
  return (
    typeof p === "string" &&
    p.length >= 12 &&
    /[a-z]/.test(p) &&
    /[A-Z]/.test(p) &&
    /[0-9]/.test(p) &&
    /[^A-Za-z0-9]/.test(p)
  );
}

function validHexColor(v) {
  return typeof v === "string" && /^#[0-9a-fA-F]{6}$/.test(v);
}

function parseCookies(request) {
  const raw = request.headers.get("cookie") || "";
  const map = {};
  for (const part of raw.split(";")) {
    const idx = part.indexOf("=");
    if (idx < 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    map[k] = decodeURIComponent(v);
  }
  return map;
}

function readCookie(request, key) {
  return parseCookies(request)[key] || null;
}

function readBearerToken(request) {
  const authHeader = String(request.headers.get("authorization") || "");
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  return match[1].trim() || null;
}

function withJsonBody(request, data) {
  const headers = new Headers(request.headers);
  headers.set("content-type", "application/json");
  headers.delete("content-length");
  return new Request(request.url, {
    method: request.method,
    headers,
    body: JSON.stringify(data),
  });
}

function sessionCookie(token, ttlSeconds) {
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${ttlSeconds}`;
}

function clearSessionCookie() {
  return `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`;
}

function nowIso() {
  return new Date().toISOString();
}

function normalizeDbId(value) {
  if (typeof value === "bigint") return Number(value);
  if (typeof value === "string") return Number(value);
  if (typeof value === "number") return value;
  return null;
}

// F-01: safe IN-clause builder. Returns only "?" placeholders 鈥?never interpolates user values into SQL.
function buildInClause(values) {
  // values must be pre-validated (e.g. positive integers) by the caller.
  const placeholders = Array(values.length).fill("?").join(", ");
  return { placeholders, params: [...values] };
}

function pathResourceId(request, resource) {
  const parts = new URL(request.url).pathname.split("/").filter(Boolean);
  const idx = parts.indexOf(resource);
  if (idx < 0 || idx + 1 >= parts.length) return NaN;
  return parsePathId(parts[idx + 1]);
}

function parsePathId(value) {
  const text = String(value || "");
  if (!/^[1-9]\d{0,15}$/.test(text)) return NaN;
  const id = Number(text);
  return Number.isSafeInteger(id) && id > 0 ? id : NaN;
}

function parseOptionalPositiveId(value) {
  if (value === undefined || value === null || value === "") return null;
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) return false;
  return id;
}

function randomHex(byteLen) {
  const arr = crypto.getRandomValues(new Uint8Array(byteLen));
  return [...arr].map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function parseJson(request) {
  const text = await readRequestTextLimited(request, DEFAULT_JSON_BODY_MAX_BYTES);
  if (!text.trim()) return {};
  try {
    return JSON.parse(text);
  } catch {
    throw new ApiError(400, "Invalid JSON body");
  }
}

async function readRequestTextLimited(request, maxBytes) {
  const contentLength = Number(request.headers.get("content-length") || 0);
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    throw new ApiError(413, `JSON body too large (max ${maxBytes} bytes)`);
  }
  if (!request.body) return "";

  const reader = request.body.getReader();
  const decoder = new TextDecoder();
  let total = 0;
  let text = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new ApiError(413, `JSON body too large (max ${maxBytes} bytes)`);
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
    return text;
  } finally {
    reader.releaseLock();
  }
}

async function sha256Base64(input) {
  const digest = await crypto.subtle.digest("SHA-256", enc(String(input)));
  return bytesToB64(new Uint8Array(digest));
}

function constantTimeEqual(a, b) {
  const maxLen = Math.max(a.length, b.length);
  let out = a.length ^ b.length;
  for (let i = 0; i < maxLen; i++) out |= (a[i] || 0) ^ (b[i] || 0);
  return out === 0;
}

function enc(s) {
  return new TextEncoder().encode(s);
}

function dec(bytes) {
  return new TextDecoder().decode(bytes);
}

function bytesToB64(bytes) {
  let str = "";
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str);
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function corsPreflight(request, env) {
  const origin = allowedCorsOrigin(request, env);
  if (!origin) return new Response(null, { status: 403 });
  const headers = corsHeaders(origin, env);
  headers.set("Access-Control-Max-Age", "86400");
  headers.set("Vary", "Origin");
  return new Response(null, { status: 204, headers });
}

function withCors(request, response, env) {
  const origin = allowedCorsOrigin(request, env);
  if (!origin) return response;
  const next = new Response(response.body, response);
  const headers = corsHeaders(origin, env);
  for (const [key, value] of headers) next.headers.set(key, value);
  next.headers.set("Vary", appendVary(next.headers.get("Vary"), "Origin"));
  return next;
}

function corsHeaders(origin, env) {
  const headers = new Headers({
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": CORS_ALLOWED_METHODS,
    "Access-Control-Allow-Headers": CORS_ALLOWED_HEADERS,
  });
  // F-03: never allow credentials in CORS responses.
  return headers;
}

function allowedCorsOrigin(request, env) {
  const origin = String(request.headers.get("origin") || "").trim();
  if (!origin) return "";
  if (!isSafeCorsOrigin(origin)) return "";
  const allowed = normalizedAllowedCorsOrigins(env);
  return allowed.includes(origin) ? origin : "";
}

function normalizedAllowedCorsOrigins(env) {
  return String(env.CORS_ALLOWED_ORIGINS || "")
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item && item !== "*" && item !== "null" && isSafeCorsOrigin(item));
}

function corsCredentialsEnabled(env) {
  // F-03: credentials are never allowed.
  return false;
}

function isSafeCorsOrigin(origin) {
  // F-11 fix: no longer automatically trust all browser extensions.
  // Extensions must be explicitly listed in CORS_ALLOWED_ORIGINS.
  try {
    const url = new URL(origin);
    if (["https:", "http:"].includes(url.protocol)) return origin === url.origin;
    if (EXTENSION_CORS_PROTOCOLS.has(url.protocol)) {
      const normalized = `${url.protocol}//${url.host}`;
      return origin === normalized && !!url.host;
    }
    return false;
  } catch {
    return false;
  }
}

function appendVary(current, value) {
  const parts = String(current || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  if (!parts.some((item) => item.toLowerCase() === value.toLowerCase())) parts.push(value);
  return parts.join(", ");
}

function commonSecurityHeaders() {
  return {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
  };
}

function debugErrorsEnabled(env) {
  const enabled = String(env.DEBUG_ERRORS || "").toLowerCase() === "true";
  const environment = String(env.ENVIRONMENT || env.NODE_ENV || "").toLowerCase();
  // F-06: only expose details in explicit development/staging with opt-in flag.
  const isNonProd = environment === "development" || environment === "staging";
  return enabled && isNonProd;
}

function canExposeErrorDetail(request, env) {
  if (!debugErrorsEnabled(env)) return false;
  // F-06: only expose to same-origin requests, never via API or curl.
  const origin = String(request.headers.get("origin") || "").trim();
  if (!origin) return false;
  try {
    return origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

function json(data, status = 200, headers = {}) {
  const securityHeaders = commonSecurityHeaders();
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...securityHeaders,
      ...headers,
    },
  });
}

function html(markup, nonce) {
  // F-08 fix: jsQR has SRI integrity; cdn.jsdelivr.net still needed for fetch. Inlining jsQR would eliminate this risk.
  // N-06 / F-08: narrow CSP to the exact jsQR path with SRI; drop the broad jsdelivr domain.
  const scriptSrc = ["'self'", `'nonce-${nonce}'`, "https://challenges.cloudflare.com", "https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js"];
  const styleSrc = ["'self'", `'nonce-${nonce}'`];
  return new Response(markup, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "Content-Security-Policy": [
        "default-src 'self'",
        `script-src ${scriptSrc.join(" ")}`,
        `style-src ${styleSrc.join(" ")}`,
        "img-src 'self' data: blob:",
        "connect-src 'self' https://challenges.cloudflare.com",
        "frame-src https://challenges.cloudflare.com",
        "base-uri 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
      ].join("; "),
      ...commonSecurityHeaders(),
    },
  });
}

function appShellHtml(env, nonce) {
  const turnstileSiteKey = String((env && env.TURNSTILE_SITE_KEY) || "");
  const turnstileScript = turnstileSiteKey
    ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
    : "";
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>2FAuth 验证器</title>
  ${turnstileScript}
  <style nonce="${nonce}">
    :root {
      --bg: #f4f7f8;
      --ink: #122426;
      --muted: #607174;
      --card: #ffffff;
      --line: #d8e2e4;
      --primary: #0f766e;
      --danger: #b42318;
      --soft: #edf5f4;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      color: var(--ink);
      font-family: "Segoe UI", Arial, sans-serif;
      background: linear-gradient(155deg, #f8fbfb, var(--bg));
    }
    .page { max-width: 1120px; margin: 0 auto; padding: 24px 16px 40px; }
    .top { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 14px; }
    h1 { margin: 0; font-size: 26px; }
    h2, h3 { margin: 0; }
    .sub, .muted { color: var(--muted); font-size: 13px; }
    .panel {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      margin-bottom: 12px;
      box-shadow: 0 12px 28px rgba(18, 36, 38, 0.07);
    }
    .grid { display: grid; grid-template-columns: 330px 1fr; gap: 12px; align-items: start; }
    .stack { display: grid; gap: 10px; }
    .row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    .hidden { display: none; }
    input, select, button, textarea {
      min-height: 38px;
      border-radius: 8px;
      border: 1px solid var(--line);
      padding: 8px 10px;
      font-size: 14px;
    }
    input, select, textarea { background: #fff; color: var(--ink); }
    textarea { width: 100%; min-height: 74px; resize: vertical; }
    button { border: 0; cursor: pointer; background: var(--primary); color: #fff; }
    button.secondary { background: var(--soft); color: var(--ink); border: 1px solid var(--line); }
    button.danger { background: var(--danger); }
    button:disabled { cursor: not-allowed; opacity: 0.6; }
    .entries { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 10px; }
    .entry { border: 1px solid var(--line); border-radius: 8px; padding: 12px; background: #fff; }
    .entry-title { font-weight: 700; margin-bottom: 3px; }
    .code { font-size: 28px; font-weight: 800; letter-spacing: 2px; margin: 8px 0 4px; }
    .bar { height: 6px; background: #edf2f2; border-radius: 99px; overflow: hidden; }
    .bar i { display: block; height: 100%; width: 0; background: var(--primary); transition: width 0.2s; }
    .error { color: var(--danger); font-size: 13px; }
    .pill { display: inline-flex; padding: 2px 8px; border-radius: 99px; background: var(--soft); font-size: 12px; }
    @media (max-width: 820px) {
      .top { align-items: flex-start; flex-direction: column; }
      .grid { grid-template-columns: 1fr; }
      .row > input, .row > select, .row > button { width: 100%; }
      .page { padding: 14px 10px 28px; }
    }
  </style>
</head>
<body>
  <main class="page">
    <header class="top">
      <div>
        <h1>2FAuth 验证器</h1>
        <div id="state" class="sub">加载中...</div>
      </div>
      <div class="row">
        <span id="whoami" class="sub"></span>
        <button id="refreshBtn" type="button" class="secondary hidden">刷新</button>
        <button id="logoutBtn" type="button" class="danger hidden">退出登录</button>
      </div>
    </header>

    <section id="bootstrap" class="panel stack hidden">
      <h2>初始化管理员</h2>
      <div class="row">
        <input id="bsUser" autocomplete="username" placeholder="用户名" />
        <input id="bsPass" type="password" autocomplete="new-password" placeholder="强密码" />
        <button id="bootstrapBtn" type="button">创建管理员</button>
      </div>
      <div id="bsMsg" class="muted"></div>
    </section>

    <section id="login" class="panel stack hidden">
      <h2>登录</h2>
      <div class="row">
        <input id="loginUser" autocomplete="username" placeholder="???" />
        <input id="loginPass" type="password" autocomplete="current-password" placeholder="密码" />
        <button id="loginBtn" type="button">登录</button>
      </div>
      <div id="turnstileBox" class="hidden"></div>
      <div id="loginMsg" class="muted"></div>
    </section>

    <section id="app" class="hidden">
      <div class="grid">
        <div class="stack">
          <section class="panel stack">
            <h3>添加令牌</h3>
            <input id="eLabel" placeholder="名称，例如 GitHub" />
            <input id="eIssuer" placeholder="发行方" />
            <input id="eSecret" placeholder="Base32 密钥" />
            <textarea id="eUri" placeholder="或粘贴 otpauth:// 链接"></textarea>
            <div class="row">
              <select id="eOtpType"><option value="totp">TOTP</option><option value="hotp">HOTP</option></select>
              <select id="eAlgo"><option>SHA-256</option><option>SHA-512</option></select>
              <input id="eDigits" value="6" inputmode="numeric" placeholder="位数" />
              <input id="ePeriod" value="30" inputmode="numeric" placeholder="周期" />
              <input id="eCounter" value="0" inputmode="numeric" placeholder="计数器" />
            </div>
            <select id="eGroup"><option value="">无分组</option></select>
            <button id="createEntryBtn" type="button">保存令牌</button>
            <div id="entryMsg" class="muted"></div>
          </section>

          <section class="panel stack">
            <h3>分组</h3>
            <div class="row">
              <input id="gName" placeholder="分组名称" />
              <input id="gColor" value="#0f766e" placeholder="#0f766e" />
              <button id="createGroupBtn" type="button">添加分组</button>
            </div>
            <div id="groupsList" class="stack"></div>
          </section>
        </div>

        <section class="panel stack">
          <div class="row">
            <h3>验证码</h3>
            <input id="search" placeholder="搜索令牌" />
            <select id="groupFilter"><option value="">全部分组</option></select>
          </div>
          <div id="entries" class="entries"></div>
        </section>
      </div>
    </section>
  </main>

  <script nonce="${nonce}">
    const TURNSTILE_SITE_KEY = ${JSON.stringify(turnstileSiteKey)};
    let currentUser = null;
    let entries = [];
    let groups = [];
    let codeState = {};
    let turnstileWidgetId = null;
    let turnstileToken = "";

    function byId(id) {
      return document.getElementById(id);
    }

    function value(id) {
      return byId(id).value.trim();
    }

    function show(id, visible) {
      byId(id).classList.toggle("hidden", !visible);
    }

    function text(id, content, error) {
      const el = byId(id);
      el.textContent = content || "";
      el.className = error ? "error" : "muted";
    }

    function esc(input) {
      return String(input || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
    }

    async function api(path, opts) {
      const init = opts || {};
      const res = await fetch(path, {
        ...init,
        credentials: "include",
        headers: { "content-type": "application/json", ...(init.headers || {}) }
      });
      const data = await res.json().catch(function() { return {}; });
      if (!res.ok) throw new Error(data.detail ? data.error + ": " + data.detail : (data.error || "HTTP " + res.status));
      return data;
    }

    function renderTurnstile() {
      if (!TURNSTILE_SITE_KEY) return;
      const box = byId("turnstileBox");
      box.classList.remove("hidden");
      let tries = 0;
      const tick = function() {
        if (turnstileWidgetId !== null) return;
        if (window.turnstile && typeof window.turnstile.render === "function") {
          turnstileWidgetId = window.turnstile.render("#turnstileBox", {
            sitekey: TURNSTILE_SITE_KEY,
            callback: function(token) { turnstileToken = token || ""; },
            "expired-callback": function() { turnstileToken = ""; },
            "error-callback": function() { turnstileToken = ""; }
          });
          return;
        }
        tries += 1;
        if (tries < 40) setTimeout(tick, 100);
      };
      tick();
    }

    async function init() {
      try {
        byId("state").textContent = "加载中...";
        const status = await api("/api/status");
        if (!status.initialized) {
          byId("state").textContent = "系统尚未初始化。";
          show("bootstrap", true);
          return;
        }
        const me = await api("/api/me").catch(function() { return null; });
        if (!me) {
          byId("state").textContent = "请先登录。";
          show("login", true);
          renderTurnstile();
          return;
        }
        currentUser = me.user;
        byId("state").textContent = "已就绪";
        byId("whoami").textContent = currentUser.username + " (" + currentUser.role + ")";
        show("logoutBtn", true);
        show("refreshBtn", true);
        show("app", true);
        await refreshAll();
      } catch (err) {
        byId("state").textContent = err.message || String(err);
      }
    }

    async function bootstrap() {
      try {
        await api("/api/bootstrap", {
          method: "POST",
          body: JSON.stringify({ username: value("bsUser"), password: value("bsPass") })
        });
        location.reload();
      } catch (err) {
        text("bsMsg", err.message, true);
      }
    }

    async function login() {
      try {
        if (TURNSTILE_SITE_KEY && !turnstileToken) {
          text("loginMsg", "请先完成 Turnstile 验证。", true);
          return;
        }
        await api("/api/login", {
          method: "POST",
          body: JSON.stringify({ username: value("loginUser"), password: value("loginPass"), turnstileToken: turnstileToken })
        });
        location.reload();
      } catch (err) {
        text("loginMsg", err.message, true);
        if (window.turnstile && turnstileWidgetId !== null) {
          try { window.turnstile.reset(turnstileWidgetId); } catch (_) {}
          turnstileToken = "";
        }
      }
    }

    async function logout() {
      await api("/api/logout", { method: "POST", body: "{}" });
      location.reload();
    }

    async function refreshAll() {
      const data = await Promise.all([api("/api/entries"), api("/api/groups")]);
      entries = data[0].entries || [];
      groups = data[1].groups || [];
      hydrateGroups();
      renderGroups();
      renderEntries();
      await refreshVisibleCodes();
    }

    function hydrateGroups() {
      const entryOptions = ['<option value="">无分组</option>'];
      const filterOptions = ['<option value="">全部分组</option>'];
      groups.forEach(function(group) {
        const option = '<option value="' + esc(group.id) + '">' + esc(group.name) + '</option>';
        entryOptions.push(option);
        filterOptions.push(option);
      });
      byId("eGroup").innerHTML = entryOptions.join("");
      byId("groupFilter").innerHTML = filterOptions.join("");
    }

    function renderGroups() {
      const box = byId("groupsList");
      if (!groups.length) {
        box.innerHTML = '<div class="muted">暂无分组。</div>';
        return;
      }
      box.innerHTML = groups.map(function(group) {
        return '<div class="row"><span class="pill">&nbsp;</span><span>' +
          esc(group.name) + '</span></div>';
      }).join("");
    }

    function filteredEntries() {
      const q = value("search").toLowerCase();
      const groupId = value("groupFilter");
      return entries.filter(function(entry) {
        const haystack = String((entry.label || "") + " " + (entry.issuer || "") + " " + (entry.username || "")).toLowerCase();
        return (!q || haystack.indexOf(q) !== -1) && (!groupId || String(entry.group_id || "") === groupId);
      });
    }

    function renderEntries() {
      const box = byId("entries");
      const list = filteredEntries();
      if (!list.length) {
        box.innerHTML = '<div class="muted">当前筛选条件下无匹配令牌。</div>';
        return;
      }
      box.innerHTML = list.map(function(entry) {
        const state = codeState[entry.id] || {};
        const isHotp = (entry.otp_type || "totp") === "hotp";
        const code = state.code || (isHotp ? "点击生成" : "------");
        const progress = state.expiresIn && entry.period ? Math.max(0, Math.min(100, state.expiresIn / entry.period * 100)) : 0;
        return '<article class="entry" data-entry-id="' + esc(entry.id) + '">' +
          '<div class="entry-title">' + esc(entry.label) + '</div>' +
          '<div class="muted">' + esc(entry.issuer || "无发行方") + (entry.group_name ? " - " + esc(entry.group_name) : "") + '</div>' +
          '<div class="code">' + esc(code) + '</div>' +
          (isHotp ? '<button type="button" data-action="hotp" data-id="' + esc(entry.id) + '">生成 HOTP</button>' : '<div class="bar"><i data-progress="' + esc(progress) + '"></i></div><div class="muted">' + esc(state.expiresIn || "") + '秒后过期</div>') +
          '</article>';
      }).join("");
      document.querySelectorAll(".bar i[data-progress]").forEach(function(bar) {
        const progress = Math.max(0, Math.min(100, Number(bar.getAttribute("data-progress") || 0)));
        bar.style.width = progress + "%";
      });
    }

    async function refreshVisibleCodes() {
      await Promise.all(filteredEntries().map(async function(entry) {
        if ((entry.otp_type || "totp") === "hotp") return;
        try {
          codeState[entry.id] = await api("/api/entries/" + entry.id + "/code");
        } catch (err) {
          codeState[entry.id] = { code: "错误", expiresIn: 0 };
        }
      }));
      renderEntries();
    }

    async function createEntry() {
      try {
        const otpauthUri = value("eUri");
        const payload = otpauthUri ? { otpauthUri: otpauthUri } : {
          label: value("eLabel"),
          issuer: value("eIssuer"),
          secret: value("eSecret"),
          otpType: value("eOtpType"),
          algorithm: value("eAlgo"),
          digits: Number(value("eDigits") || 6),
          period: Number(value("ePeriod") || 30),
          hotpCounter: Number(value("eCounter") || 0),
          groupId: value("eGroup") || null
        };
        await api("/api/entries", { method: "POST", body: JSON.stringify(payload) });
        ["eLabel", "eIssuer", "eSecret", "eUri"].forEach(function(id) { byId(id).value = ""; });
        text("entryMsg", "已保存");
        await refreshAll();
      } catch (err) {
        text("entryMsg", err.message, true);
      }
    }

    async function createGroup() {
      try {
        await api("/api/groups", {
          method: "POST",
          body: JSON.stringify({ name: value("gName"), color: value("gColor") || "#0f766e" })
        });
        byId("gName").value = "";
        await refreshAll();
      } catch (err) {
        alert(err.message || String(err));
      }
    }

    async function generateHotp(id) {
      const data = await api("/api/entries/" + id + "/hotp", { method: "POST", body: "{}" });
      codeState[id] = data;
      renderEntries();
    }

    function bindEvents() {
      byId("bootstrapBtn").addEventListener("click", bootstrap);
      byId("loginBtn").addEventListener("click", login);
      byId("logoutBtn").addEventListener("click", logout);
      byId("refreshBtn").addEventListener("click", refreshAll);
      byId("createEntryBtn").addEventListener("click", createEntry);
      byId("createGroupBtn").addEventListener("click", createGroup);
      byId("search").addEventListener("input", renderEntries);
      byId("groupFilter").addEventListener("change", renderEntries);
      document.addEventListener("click", function(event) {
        const button = event.target.closest("[data-action='hotp']");
        if (button) generateHotp(button.dataset.id).catch(function(err) { alert(err.message || String(err)); });
      });
    }

    bindEvents();
    init();
    setInterval(refreshVisibleCodes, 5000);
  </script>
</body>
</html>`;
}

function appHtml(env, nonce) {
  const turnstileSiteKey = String((env && env.TURNSTILE_SITE_KEY) || "");
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>2FAuth 楠岃瘉鍣?/title>
  <style nonce="${nonce}">
    :root {
      --bg: #f3f7f6;
      --ink: #102a2c;
      --muted: #5c7173;
      --card: #ffffff;
      --line: #d8e4e1;
      --ok: #0f766e;
      --warn: #b42318;
      --chip: #e5f2ef;
      --shadow: 0 14px 36px rgba(16, 42, 44, 0.08);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", Arial, sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at 20% 0%, #d9ede8 0, transparent 40%),
        linear-gradient(160deg, #f7faf9, #eef5f3 45%, #e8f2f0);
      min-height: 100vh;
    }
    .page { max-width: 1180px; margin: 28px auto; padding: 0 16px 32px; }
    .top {
      display: flex; justify-content: space-between; align-items: center; gap: 12px;
      margin-bottom: 14px;
    }
    h1 { margin: 0; font-size: 24px; }
    .sub { color: var(--muted); font-size: 13px; }
    .panel {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 14px;
      box-shadow: var(--shadow);
      padding: 14px;
      margin-bottom: 12px;
    }
    .grid { display: grid; grid-template-columns: 320px 1fr; gap: 12px; align-items: start; }
    .row { display: flex; flex-wrap: wrap; gap: 8px; }
    .flush { margin: 0; }
    .hidden { display: none; }
    .visible { display: block !important; }
    .top-actions { justify-content: space-between; align-items: center; }
    .narrow-74 { width: 74px; }
    .narrow-86 { width: 86px; }
    .narrow-110 { width: 110px; }
    .mt-8 { margin-top: 8px; }
    .group-row {
      justify-content: space-between;
      align-items: center;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 7px;
    }
    .swatch {
      display: inline-block;
      width: 8px;
      height: 8px;
      border-radius: 999px;
      background: #0f766e;
    }
    .stack { display: grid; gap: 8px; }
    input, select, button, textarea {
      border-radius: 10px;
      border: 1px solid var(--line);
      padding: 9px 11px;
      font-size: 14px;
      min-height: 38px;
    }
    textarea { min-height: 90px; resize: vertical; width: 100%; }
    input, select { background: #fff; color: var(--ink); }
    button { border: 0; cursor: pointer; background: var(--ok); color: #fff; }
    button.ghost { background: #eff5f3; color: var(--ink); border: 1px solid var(--line); }
    button.warn { background: var(--warn); }
    .muted { color: var(--muted); font-size: 12px; }
    .error { color: var(--warn); font-size: 12px; }
    video { width: 100%; border-radius: 10px; border: 1px solid var(--line); background: #dfe9e6; }
    .entry-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
      gap: 10px;
      align-content: start;
      grid-auto-rows: max-content;
    }
    .entry {
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 12px;
      background: #fff;
      height: auto;
    }
    .entry .title { font-weight: 600; margin-bottom: 4px; }
    .entry .meta { color: var(--muted); font-size: 12px; margin-bottom: 6px; }
    .chip {
      display: inline-flex; align-items: center; gap: 5px;
      padding: 3px 9px; border-radius: 999px; background: var(--chip);
      font-size: 12px;
    }
    .code { font-size: 28px; letter-spacing: 2px; font-weight: 700; margin: 8px 0 3px; }
    .bar { height: 6px; background: #ecf2f0; border-radius: 99px; overflow: hidden; }
    .bar > i { display: block; height: 100%; background: var(--ok); width: 0%; transition: width .3s; }
    table { width: 100%; border-collapse: collapse; }
    th, td { border-bottom: 1px solid var(--line); padding: 7px 4px; text-align: left; font-size: 13px; }
    #bootstrap, #login, #app { display: none; }
    @media (max-width: 980px) {
      .grid { grid-template-columns: 1fr; }
      .top { flex-direction: column; align-items: flex-start; }
    }
    @media (max-width: 768px) {
      .page { margin: 12px auto; padding: 0 10px 20px; }
      .panel { padding: 12px; border-radius: 12px; }
      .row { gap: 6px; }
      .row > input,
      .row > select,
      .row > button {
        width: 100%;
      }
      input, select, button, textarea {
        min-height: 42px;
        font-size: 15px;
      }
      .entry-grid {
        grid-template-columns: 1fr;
      }
      .code {
        font-size: 24px;
      }
      #langSelect, #autoLogoutSelect {
        width: 100%;
      }
      table {
        font-size: 12px;
      }
      th, td {
        padding: 6px 3px;
        word-break: break-word;
      }
    }
  </style>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head>
<body>
  <div class="page">
    <div class="top">
      <div>
        <h1 id="appTitle">2FAuth 楠岃瘉鍣?/h1>
        <div id="state" class="sub">鍔犺浇涓?..</div>
      </div>
      <div class="row">
        <select id="langSelect">
          <option value="zh-CN">绠€浣撲腑鏂?/option>
          <option value="en-US">English</option>
        </select>
        <select id="autoLogoutSelect">
          <option value="15">15鍒嗛挓鑷姩閫€鍑?/option>
          <option value="30">30鍒嗛挓鑷姩閫€鍑?/option>
          <option value="60">60鍒嗛挓鑷姩閫€鍑?/option>
          <option value="120">120鍒嗛挓鑷姩閫€鍑?/option>
          <option value="0">涓嶈嚜鍔ㄩ€€鍑?/option>
        </select>
        <div id="whoami" class="sub"></div>
      </div>
    </div>

    <section id="bootstrap" class="panel stack">
      <h3 class="flush">鍒濆鍖栫鐞嗗憳</h3>
      <div class="row">
        <input id="bsUser" placeholder="绠＄悊鍛樼敤鎴峰悕" />
        <input id="bsPass" type="password" placeholder="瀵嗙爜锛堣嚦灏?2浣嶏紝鍚ぇ灏忓啓/鏁板瓧/绗﹀彿锛? />
        <button type="button" data-action="bootstrap">鍒濆鍖?/button>
      </div>
      <div id="bsMsg" class="muted"></div>
    </section>

    <section id="login" class="panel stack">
      <h3 class="flush">鐧诲綍</h3>
      <div class="row">
        <input id="loginUser" placeholder="鐢ㄦ埛鍚? />
        <input id="loginPass" type="password" placeholder="瀵嗙爜" />
        <button type="button" data-action="login">鐧诲綍</button>
      </div>
      <div id="turnstileBox" class="row hidden"></div>
      <div id="loginMsg" class="muted"></div>
    </section>

    <section id="app">
      <div class="panel row top-actions">
        <div class="row">
          <input id="search" placeholder="鎼滅储鏍囩/鍙戣鏂?.." />
          <select id="groupFilter"><option value="">鍏ㄩ儴鍒嗙粍</option></select>
          <button class="ghost" data-action="refresh-all">鍒锋柊</button>
        </div>
        <div class="row">
          <button class="ghost" data-action="export-data">瀵煎嚭</button>
          <button class="ghost" data-action="export-otpauth">瀵煎嚭 otpauth 鏂囨湰</button>
          <button class="ghost" data-action="export-encrypted">鍔犲瘑瀵煎嚭</button>
          <button class="ghost" data-action="toggle-import">瀵煎叆</button>
          <button class="ghost" data-action="change-my-password">淇敼瀵嗙爜</button>
          <button type="button" class="warn" data-action="logout">閫€鍑虹櫥褰?/button>
        </div>
      </div>

      <div id="importPanel" class="panel stack hidden">
        <h3 class="flush">瀵煎叆澶囦唤 JSON</h3>
        <textarea id="importText" placeholder='绮樿创 /api/export 鐨?JSON'></textarea>
        <div class="row">
          <input id="importFile" type="file" accept=".json,.txt,text/plain,application/json" />
          <input id="importPassphrase" type="password" placeholder="鍙ｄ护锛堢敤浜庡姞瀵嗗浠斤級" />
          <button data-action="import-data">鎵ц瀵煎叆</button>
          <button class="ghost" data-action="import-otpauth">瀵煎叆 otpauth 鏂囨湰</button>
          <button class="ghost" data-action="import-encrypted">鎵ц鍔犲瘑瀵煎叆</button>
        </div>
        <div id="importMsg" class="muted"></div>
      </div>

      <div class="grid">
        <div class="stack">
          <div class="panel stack">
            <h3 class="flush">鏂板缓鏉＄洰</h3>
            <input id="eLabel" placeholder="鏍囩锛堝 GitHub锛? />
            <input id="eIssuer" placeholder="鍙戣鏂癸紙鍙€夛級" />
            <input id="eSecret" placeholder="Base32 瀵嗛挜" />
            <input id="eUri" placeholder="鎴?otpauth://totp/... / otpauth://hotp/..." />
            <div class="row">
              <button class="ghost" data-action="start-scan">鎽勫儚澶存壂鐮?/button>
              <button class="ghost" data-action="stop-scan">鍋滄鎵爜</button>
              <input id="qrImageFile" type="file" accept="image/*" />
            </div>
            <video id="scanVideo" autoplay playsinline class="hidden"></video>
            <div id="scanMsg" class="muted"></div>
            <div class="row">
              <select id="eOtpType"><option value="totp">TOTP</option><option value="hotp">HOTP</option></select>
              <select id="eAlgo"><option>SHA-256</option><option>SHA-512</option></select>
              <input id="eDigits" value="6" class="narrow-74" />
              <input id="ePeriod" value="30" class="narrow-74" />
              <input id="eCounter" value="0" class="narrow-86" />
            </div>
            <select id="eGroup"><option value="">涓嶅垎缁?/option></select>
            <button data-action="create-entry">淇濆瓨鏉＄洰</button>
            <div id="entryMsg" class="muted"></div>
          </div>

          <div class="panel stack">
            <h3 class="flush">鍒嗙粍</h3>
            <div class="row">
              <input id="gName" placeholder="鍒嗙粍鍚嶇О" />
              <input id="gColor" value="#0f766e" class="narrow-110" />
              <button data-action="create-group">鏂板</button>
            </div>
            <div id="groupsList" class="stack"></div>
          </div>

          <div id="adminPanel" class="panel stack hidden">
            <h3 class="flush">鐢ㄦ埛绠＄悊锛堢鐞嗗憳锛?/h3>
            <div class="row">
              <input id="uName" placeholder="鐢ㄦ埛鍚? />
              <input id="uPass" type="password" placeholder="瀵嗙爜 >=12 浣嶏紝鍚ぇ灏忓啓/鏁板瓧/绗﹀彿" />
              <select id="uRole"><option value="user">user</option><option value="admin">admin</option></select>
              <button data-action="create-user">鍒涘缓</button>
            </div>
            <div id="userMsg" class="muted"></div>
            <table id="usersTable"></table>
            <div class="panel stack mt-8">
              <h4 class="flush">鐧诲綍椋庢帶璁剧疆</h4>
              <div class="row">
                <input id="riskMaxReq" type="number" min="3" max="100" placeholder="姣忓垎閽熻姹傞槇鍊硷紙榛樿10锛? />
                <input id="riskLockMin" type="number" min="1" max="1440" placeholder="閿佸畾鍒嗛挓鏁帮紙榛樿15锛? />
                <button data-action="save-login-policy">淇濆瓨椋庢帶璁剧疆</button>
              </div>
              <div id="riskMsg" class="muted"></div>
            </div>
          </div>
        </div>

        <div class="panel stack">
          <h3 class="flush">鎴戠殑楠岃瘉鐮?/h3>
          <div id="entries" class="entry-grid"></div>
        </div>
      </div>
    </section>
  </div>

  <script nonce="${nonce}">
    const TURNSTILE_SITE_KEY = ${JSON.stringify(turnstileSiteKey)};
    const PLAINTEXT_EXPORT_ENABLED = ${JSON.stringify(String((env && env.ALLOW_PLAINTEXT_EXPORT) || "").toLowerCase() === "true")};
    let currentUser = null;
    let entries = [];
    let groups = [];
    let codeState = {};
    let scanStream = null;
    let scanTimer = null;
    let jsQrReady = false;
    let inactivityTimer = null;
    let activityBound = false;
    let turnstileWidgetId = null;
    let turnstileToken = "";
    const I18N = {
      "zh-CN": {
        loading: "鍔犺浇涓?..",
        systemNotInitialized: "绯荤粺灏氭湭鍒濆鍖栵紝璇峰厛鍒涘缓绠＄悊鍛樸€?,
        pleaseLogin: "璇峰厛鐧诲綍銆?,
        ready: "宸插氨缁?,
        logoutTimeout: "浼氳瘽鍥犻暱鏃堕棿鏃犳搷浣滃凡鑷姩閫€鍑恒€?,
        noGroup: "涓嶅垎缁?,
        allGroups: "鍏ㄩ儴鍒嗙粍",
        noGroupsYet: "鏆傛棤鍒嗙粍銆?,
        noEntriesMatched: "褰撳墠绛涢€変笅娌℃湁鏉＄洰銆?,
        noIssuer: "鏃犲彂琛屾柟",
        clickGenerate: "鐐瑰嚮鐢熸垚",
        secLeft: "绉掑悗杩囨湡",
        copyCode: "澶嶅埗楠岃瘉鐮?,
        codeCopied: "楠岃瘉鐮佸凡澶嶅埗",
        copyFailed: "澶嶅埗澶辫触锛岃鎵嬪姩澶嶅埗",
        setGroup: "璁句负鍒嗙粍",
        removeGroup: "绉诲嚭鍒嗙粍",
        groupUpdated: "鍒嗙粍宸叉洿鏂?,
        generateHotp: "鐢熸垚 HOTP",
        edit: "缂栬緫",
        delete: "鍒犻櫎",
        deleteEntryConfirm: "纭鍒犻櫎璇ユ潯鐩紵",
        deleteGroupConfirm: "纭鍒犻櫎鍒嗙粍锛熷垎缁勪笅鏉＄洰灏嗗彉涓轰笉鍒嗙粍銆?,
        deleteUserConfirm: "纭鍒犻櫎鐢ㄦ埛锛?,
        backupCopied: "澶囦唤 JSON 宸插鍒跺埌鍓创鏉裤€?,
        encryptedBackupCopied: "鍔犲瘑澶囦唤 JSON 宸插鍒跺埌鍓创鏉裤€?,
        plaintextExportConfirm: "鏄庢枃瀵煎嚭浼氬寘鍚墍鏈?OTP 瀵嗛挜銆傜‘璁ょ户缁紵",
        plaintextExportDisabled: "褰撳墠閮ㄧ讲鏈紑鍚槑鏂囧鍑猴紝璇蜂娇鐢ㄢ€滃姞瀵嗗鍑衡€濄€?,
        setBackupPassphrase: "璁剧疆澶囦唤鍙ｄ护锛堣嚦灏?0浣嶏級",
        copyExportJson: "澶嶅埗瀵煎嚭 JSON",
        copyEncryptedExportJson: "澶嶅埗鍔犲瘑瀵煎嚭 JSON",
        importedDone: "瀵煎叆瀹屾垚",
        encryptedImportedDone: "鍔犲瘑瀵煎叆瀹屾垚",
        cameraNotSupported: "褰撳墠娴忚鍣ㄤ笉鏀寔 BarcodeDetector銆?,
        cameraFallback: "宸插惎鐢ㄥ吋瀹规壂鐮佹ā寮忥紙jsQR锛夈€?,
        cameraStarted: "鎽勫儚澶存壂鐮佸凡鍚姩...",
        qrDetected: "宸茶瘑鍒簩缁寸爜锛孶RI 宸插～鍏ヨ〃鍗曘€?,
        qrReadyToSave: "浜岀淮鐮佸凡璇嗗埆锛岀偣鍑烩€滀繚瀛樻潯鐩€濆嵆鍙坊鍔犮€?,
        cameraDenied: "鏃犳硶璁块棶鎽勫儚澶达細",
        noQrFound: "鍥剧墖涓湭璇嗗埆鍒颁簩缁寸爜銆?,
        qrFromImage: "鍥剧墖浜岀淮鐮佽瘑鍒垚鍔熴€?,
        scanImageFailed: "鍥剧墖鎵爜澶辫触锛?,
        saved: "宸蹭繚瀛?,
        userCreated: "鐢ㄦ埛宸插垱寤?,
        changePassword: "淇敼瀵嗙爜",
        resetPassword: "閲嶇疆瀵嗙爜",
        currentPassword: "褰撳墠瀵嗙爜",
        newPassword: "鏂板瘑鐮?,
        passwordChanged: "瀵嗙爜宸蹭慨鏀癸紝璇烽噸鏂扮櫥褰曘€?,
        passwordReset: "瀵嗙爜宸查噸缃?,
        passwordResetConfirm: "纭閲嶇疆璇ョ敤鎴风殑瀵嗙爜锛?,
        labelPrompt: "鏍囩",
        issuerPrompt: "鍙戣鏂?,
        groupIdPrompt: "鍒嗙粍 ID锛堢暀绌轰唬琛ㄤ笉鍒嗙粍锛?,
        usersThId: "ID",
        usersThName: "鐢ㄦ埛鍚?,
        usersThRole: "瑙掕壊",
        usersThAction: "鎿嶄綔",
        setRole: "璁剧疆涓?,
        riskPolicySaved: "椋庢帶璁剧疆宸蹭繚瀛?,
        riskPolicyLoaded: "褰撳墠椋庢帶锛氭瘡鍒嗛挓",
        times: "娆?,
        lockFor: "锛岄攣瀹?,
        minutes: "鍒嗛挓",
        otpauthExportDone: "otpauth 鏂囨湰宸蹭笅杞姐€?,
        otpauthImportDone: "otpauth 瀵煎叆瀹屾垚",
        importFileLoaded: "鏂囦欢鍐呭宸插姞杞藉埌瀵煎叆妗嗐€?,
        turnstileRequired: "璇峰厛瀹屾垚 Cloudflare Turnstile 楠岃瘉銆?,
      },
      "en-US": {
        loading: "Loading...",
        systemNotInitialized: "System not initialized yet.",
        pleaseLogin: "Please login.",
        ready: "Ready",
        logoutTimeout: "Logged out due to inactivity.",
        noGroup: "No group",
        allGroups: "All groups",
        noGroupsYet: "No groups yet.",
        noEntriesMatched: "No entries match current filters.",
        noIssuer: "No issuer",
        clickGenerate: "Click Generate",
        secLeft: "s left",
        copyCode: "Copy Code",
        codeCopied: "Code copied",
        copyFailed: "Copy failed, please copy manually",
        setGroup: "Set Group",
        removeGroup: "Remove Group",
        groupUpdated: "Group updated",
        generateHotp: "Generate HOTP",
        edit: "Edit",
        delete: "Delete",
        deleteEntryConfirm: "Delete this entry?",
        deleteGroupConfirm: "Delete group? Entries will be ungrouped.",
        deleteUserConfirm: "Delete user?",
        backupCopied: "Backup JSON copied to clipboard.",
        encryptedBackupCopied: "Encrypted backup JSON copied to clipboard.",
        plaintextExportConfirm: "Plaintext export includes all OTP secrets. Continue?",
        plaintextExportDisabled: "Plaintext export is disabled in this deployment. Use encrypted export instead.",
        setBackupPassphrase: "Set backup passphrase (>=12 chars):",
        copyExportJson: "Copy export JSON:",
        copyEncryptedExportJson: "Copy encrypted export JSON:",
        importedDone: "Import completed",
        encryptedImportedDone: "Encrypted import completed",
        cameraNotSupported: "BarcodeDetector is not supported by this browser.",
        cameraFallback: "Using compatible scanner mode (jsQR).",
        cameraStarted: "Camera scanning started...",
        qrDetected: "QR detected. URI filled in form.",
        qrReadyToSave: "QR parsed. Click 'Save Entry' to add it.",
        cameraDenied: "Camera access denied or unavailable: ",
        noQrFound: "No QR code found in image.",
        qrFromImage: "QR detected from image.",
        scanImageFailed: "Failed to scan image: ",
        saved: "Saved",
        userCreated: "User created",
        changePassword: "Change Password",
        resetPassword: "Reset Password",
        currentPassword: "Current password",
        newPassword: "New password",
        passwordChanged: "Password changed. Please login again.",
        passwordReset: "Password reset",
        passwordResetConfirm: "Confirm reset this user's password?",
        labelPrompt: "Label",
        issuerPrompt: "Issuer",
        groupIdPrompt: "Group ID (empty for none)",
        usersThId: "ID",
        usersThName: "Username",
        usersThRole: "Role",
        usersThAction: "Action",
        setRole: "Set",
        riskPolicySaved: "Risk policy saved",
        riskPolicyLoaded: "Current policy:",
        times: "times/min",
        lockFor: ", lock for ",
        minutes: "minutes",
        otpauthExportDone: "otpauth text downloaded.",
        otpauthImportDone: "otpauth import completed",
        importFileLoaded: "File content loaded into import box.",
        turnstileRequired: "Please complete Cloudflare Turnstile verification first.",
      }
    };
    let currentLang = localStorage.getItem("ui_lang") || "zh-CN";
    let autoLogoutMinutes = Number(localStorage.getItem("auto_logout_minutes") || "30");

    function t(key) {
      const pack = I18N[currentLang] || I18N["zh-CN"];
      return pack[key] || key;
    }

    function changeLang(lang) {
      currentLang = I18N[lang] ? lang : "zh-CN";
      localStorage.setItem("ui_lang", currentLang);
      applyLanguage();
      renderGroups();
      renderEntries();
      if (currentUser && currentUser.role === "admin") refreshUsers();
    }

    function changeAutoLogout(minutes) {
      autoLogoutMinutes = Number(minutes || 0);
      localStorage.setItem("auto_logout_minutes", String(autoLogoutMinutes));
      scheduleAutoLogout();
    }

    function applyLanguage() {
      document.documentElement.lang = currentLang;
      document.getElementById("langSelect").value = currentLang;
      document.getElementById("autoLogoutSelect").value = String(autoLogoutMinutes);
      syncPlaintextExportUi();
      if (!currentUser) {
        document.getElementById("state").textContent = t("loading");
      }
    }

    function syncPlaintextExportUi() {
      const buttons = document.querySelectorAll('[data-action="export-data"], [data-action="export-otpauth"]');
      buttons.forEach(function(button) {
        button.disabled = !PLAINTEXT_EXPORT_ENABLED;
        button.title = PLAINTEXT_EXPORT_ENABLED ? "" : t("plaintextExportDisabled");
      });
    }

    async function timeoutLogout() {
      try {
        await api("/api/logout", { method: "POST", body: "{}" });
      } finally {
        alert(t("logoutTimeout"));
        location.reload();
      }
    }

    function scheduleAutoLogout() {
      if (inactivityTimer) clearTimeout(inactivityTimer);
      if (!currentUser) return;
      if (!Number.isFinite(autoLogoutMinutes) || autoLogoutMinutes <= 0) return;
      inactivityTimer = setTimeout(timeoutLogout, autoLogoutMinutes * 60 * 1000);
    }

    function onActivity() {
      scheduleAutoLogout();
    }

    function bindActivityEvents() {
      if (activityBound) return;
      activityBound = true;
      ["click", "keydown", "mousemove", "touchstart", "scroll"].forEach(function(evt) {
        window.addEventListener(evt, onActivity, { passive: true });
      });
      window.addEventListener("pagehide", closeSoonOnLeave);
      window.addEventListener("beforeunload", closeSoonOnLeave);
    }

    function closeSoonOnLeave() {
      if (!currentUser) return;
      try {
        const blob = new Blob(['{}'], { type: "application/json" });
        // N-06 fix: use sendBeacon as primary; only fall back to fetch on failure
        const ok = navigator.sendBeacon("/api/session/close-soon", blob);
        if (!ok) {
          fetch("/api/session/close-soon", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-Session-Close": "web-beforeunload" },
            body: "{}",
            keepalive: true,
            credentials: "same-origin"
          }).catch(function() {});
        }
      } catch {}
    }

    function initTurnstile() {
      if (!TURNSTILE_SITE_KEY) return;
      const box = document.getElementById("turnstileBox");
      if (!box) return;
      box.classList.remove("hidden");

      let tries = 0;
      const tryRender = function() {
        if (turnstileWidgetId !== null) return;
        if (window.turnstile && typeof window.turnstile.render === "function") {
          turnstileWidgetId = window.turnstile.render("#turnstileBox", {
            sitekey: TURNSTILE_SITE_KEY,
            callback: function(token) { turnstileToken = token || ""; },
            "expired-callback": function() { turnstileToken = ""; },
            "error-callback": function() { turnstileToken = ""; }
          });
          return;
        }
        tries += 1;
        if (tries < 40) setTimeout(tryRender, 100);
      };
      tryRender();
    }

    async function api(path, opts = {}) {
      const res = await fetch(path, {
        ...opts,
        headers: { "content-type": "application/json", ...(opts.headers || {}) },
        credentials: "include"
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail ? data.error + ": " + data.detail : (data.error || ("HTTP " + res.status)));
      return data;
    }

    function msg(id, text, err) {
      const el = document.getElementById(id);
      el.textContent = text || "";
      el.className = err ? "error" : "muted";
    }

    async function init() {
      applyLanguage();
      try {
        const status = await api("/api/status");
        if (!status.initialized) {
          document.getElementById("state").textContent = t("systemNotInitialized");
          document.getElementById("bootstrap").classList.add("visible");
          return;
        }
        const me = await api("/api/me").catch(() => null);
        if (!me) {
          document.getElementById("state").textContent = t("pleaseLogin");
          document.getElementById("login").classList.add("visible");
          initTurnstile();
          return;
        }
        currentUser = me.user;
        document.getElementById("state").textContent = t("ready");
        document.getElementById("whoami").textContent = me.user.username + " (" + me.user.role + ")";
        document.getElementById("app").classList.add("visible");
        bindActivityEvents();
        scheduleAutoLogout();
        if (me.user.role === "admin") document.getElementById("adminPanel").classList.remove("hidden");
        await refreshAll();
        if (me.user.role === "admin") {
          await refreshUsers();
          await loadLoginPolicy();
        }
      } catch (e) {
        document.getElementById("state").textContent = e.message;
      }
    }

    async function bootstrap(evt) {
      if (evt && typeof evt.preventDefault === "function") evt.preventDefault();
      try {
        await api("/api/bootstrap", {
          method: "POST",
          body: JSON.stringify({ username: v("bsUser"), password: v("bsPass") })
        });
        window.location.replace("/");
      } catch (e) { msg("bsMsg", e.message, true); }
    }

    async function login(evt) {
      if (evt && typeof evt.preventDefault === "function") evt.preventDefault();
      try {
        if (TURNSTILE_SITE_KEY && !turnstileToken) {
          msg("loginMsg", t("turnstileRequired"), true);
          return;
        }
        await api("/api/login", {
          method: "POST",
          body: JSON.stringify({ username: v("loginUser"), password: v("loginPass"), turnstileToken: turnstileToken })
        });
        window.location.replace("/");
      } catch (e) {
        msg("loginMsg", e.message, true);
        if (window.turnstile && turnstileWidgetId !== null) {
          try { window.turnstile.reset(turnstileWidgetId); } catch {}
          turnstileToken = "";
        }
      }
    }

    async function logout(evt) {
      if (evt && typeof evt.preventDefault === "function") evt.preventDefault();
      if (inactivityTimer) clearTimeout(inactivityTimer);
      await api("/api/logout", { method: "POST", body: "{}" });
      window.location.replace("/");
    }

    function v(id) { return document.getElementById(id).value; }

    async function refreshAll() {
      const [e, g] = await Promise.all([api("/api/entries"), api("/api/groups")]);
      entries = e.entries || [];
      groups = g.groups || [];
      hydrateGroupSelects();
      renderGroups();
      renderEntries();
      await refreshVisibleCodes();
    }

    function hydrateGroupSelects() {
      const opts = ['<option value="">' + esc(t("noGroup")) + '</option>'];
      const filter = ['<option value="">' + esc(t("allGroups")) + '</option>'];
      groups.forEach(function(g) {
        opts.push('<option value="' + g.id + '">' + esc(g.name) + '</option>');
        filter.push('<option value="' + g.id + '">' + esc(g.name) + '</option>');
      });
      document.getElementById("eGroup").innerHTML = opts.join("");
      document.getElementById("groupFilter").innerHTML = filter.join("");
    }

    function renderGroups() {
      const box = document.getElementById("groupsList");
      if (!groups.length) { box.innerHTML = '<div class="muted">' + esc(t("noGroupsYet")) + '</div>'; return; }
      box.innerHTML = groups.map(function(g) {
        const id = esc(g.id);
        return '<div class="row group-row">'
          + '<span class="chip"><i class="swatch" data-color="' + esc(g.color || "#0f766e") + '"></i>' + esc(g.name) + '</span>'
          + '<button class="warn" data-action="delete-group" data-id="' + id + '">' + esc(t("delete")) + '</button>'
          + '</div>';
      }).join("");
      applyDynamicStyles();
    }

    function groupOptionsHtml(selectedGroupId) {
      const selected = selectedGroupId === null || selectedGroupId === undefined ? "" : String(selectedGroupId);
      const opts = ['<option value="">' + esc(t("noGroup")) + '</option>'];
      groups.forEach(function(g) {
        const val = String(g.id);
        const isSelected = val === selected ? " selected" : "";
        opts.push('<option value="' + esc(val) + '"' + isSelected + '>' + esc(g.name) + '</option>');
      });
      return opts.join("");
    }

    function renderEntries() {
      const q = v("search").trim().toLowerCase();
      const gf = v("groupFilter");
      const list = entries.filter(function(e) {
        const text = (e.label + " " + (e.issuer || "")).toLowerCase();
        if (q && !text.includes(q)) return false;
        if (gf && String(e.group_id || "") !== gf) return false;
        return true;
      });
      const out = document.getElementById("entries");
      if (!list.length) { out.innerHTML = '<div class="muted">' + esc(t("noEntriesMatched")) + '</div>'; return; }
      out.innerHTML = list.map(function(e) {
        const id = esc(e.id);
        const state = codeState[e.id] || {};
        const code = state.code || "------";
        const ex = state.expiresIn || "";
        const progress = state.progress || 0;
        const group = e.group_name ? '<span class="chip"><i class="swatch" data-color="' + esc(e.group_color || "#0f766e") + '"></i>' + esc(e.group_name) + '</span>' : '';
        const otpTag = '<span class="chip">' + esc((e.otp_type || "totp").toUpperCase()) + '</span>';
        const counter = (e.otp_type === "hotp") ? ('<span class="chip">counter ' + Number(e.hotp_counter || 0) + '</span>') : '';
        return '<article class="entry">'
          + '<div class="title">' + esc(e.label) + '</div>'
          + '<div class="meta">' + esc(e.issuer || t("noIssuer")) + '</div>'
          + '<div class="row">' + otpTag + group + counter + '</div>'
          + '<div class="code" id="c-' + id + '">' + esc(code) + '</div>'
          + '<div class="muted" id="x-' + id + '">' + (ex ? (ex + t("secLeft")) : (e.otp_type === "hotp" ? t("clickGenerate") : "")) + '</div>'
          + '<div class="bar"><i id="p-' + id + '" data-progress="' + esc(progress) + '"></i></div>'
          + '<div class="row mt-8">'
          + (e.otp_type === "hotp"
            ? '<button data-action="gen-hotp" data-id="' + id + '">' + esc(t("generateHotp")) + '</button>'
            : '<button class="ghost" data-action="copy-code" data-id="' + id + '">' + esc(t("copyCode")) + '</button>')
          + '<select id="entry-group-' + id + '">' + groupOptionsHtml(e.group_id) + '</select>'
          + '<button class="ghost" data-action="set-entry-group" data-id="' + id + '">' + esc(t("setGroup")) + '</button>'
          + '<button class="ghost" data-action="remove-entry-group" data-id="' + id + '">' + esc(t("removeGroup")) + '</button>'
          + '<button class="ghost" data-action="edit-entry" data-id="' + id + '">' + esc(t("edit")) + '</button>'
          + '<button class="warn" data-action="delete-entry" data-id="' + id + '">' + esc(t("delete")) + '</button>'
          + '</div></article>';
      }).join("");
      applyDynamicStyles();
    }

    async function refreshVisibleCodes() {
      const current = entries.filter(function(e) { return e.otp_type !== "hotp"; });
      await Promise.all(current.map(function(e) { return refreshCode(e.id, true); }));
    }

    async function refreshCode(id, silent) {
      try {
        const r = await api("/api/entries/" + id + "/code?_t=" + Date.now());
        const entry = entries.find(function(x){ return x.id === id; });
        const period = Math.max(1, Number((entry && entry.period) || 30));
        const progress = Math.max(0, Math.min(100, ((period - r.expiresIn) / period) * 100));
        codeState[id] = { code: r.code, expiresIn: r.expiresIn, progress: progress };
        const codeEl = document.getElementById("c-" + id);
        const exEl = document.getElementById("x-" + id);
        const pEl = document.getElementById("p-" + id);
        if (codeEl) codeEl.textContent = r.code;
        if (exEl) exEl.textContent = r.expiresIn + t("secLeft");
        if (pEl) pEl.style.width = progress + "%";
      } catch (e) {
        if (!silent) alert(e.message);
      }
    }

    async function copyCode(id) {
      const state = codeState[id] || {};
      const code = String(state.code || "").trim();
      if (!code || code === "------") {
        try {
          await refreshCode(id, true);
        } catch {}
      }
      const latest = String(((codeState[id] || {}).code) || "").trim();
      if (!latest || latest === "------") {
        alert(t("copyFailed"));
        return;
      }
      try {
        await navigator.clipboard.writeText(latest);
        alert(t("codeCopied"));
      } catch (e) {
        const ok = window.prompt(t("copyFailed"), latest);
        if (ok !== null) {
          alert(t("codeCopied"));
        }
      }
    }

    async function genHotp(id) {
      try {
        const r = await api("/api/entries/" + id + "/hotp", { method: "POST", body: "{}" });
        codeState[id] = { code: r.code, expiresIn: 0, progress: 100 };
        await refreshAll();
      } catch (e) { alert(e.message); }
    }

    async function createEntry() {
      try {
        await api("/api/entries", {
          method: "POST",
          body: JSON.stringify({
            label: v("eLabel"),
            issuer: v("eIssuer"),
            secret: v("eSecret"),
            otpauthUri: v("eUri"),
            otpType: v("eOtpType"),
            algorithm: v("eAlgo"),
            digits: Number(v("eDigits") || 6),
            period: Number(v("ePeriod") || 30),
            hotpCounter: Number(v("eCounter") || 0),
            groupId: v("eGroup") ? Number(v("eGroup")) : null
          })
        });
        msg("entryMsg", t("saved"));
        ["eLabel","eIssuer","eSecret","eUri"].forEach(function(id){ document.getElementById(id).value = ""; });
        await refreshAll();
      } catch (e) { msg("entryMsg", e.message, true); }
    }

    async function setEntryGroup(id) {
      const el = document.getElementById("entry-group-" + id);
      const groupId = el && el.value ? Number(el.value) : null;
      await api("/api/entries/" + id, {
        method: "PATCH",
        body: JSON.stringify({ groupId: groupId })
      });
      alert(t("groupUpdated"));
      await refreshAll();
    }

    async function removeEntryGroup(id) {
      await api("/api/entries/" + id, {
        method: "PATCH",
        body: JSON.stringify({ groupId: null })
      });
      alert(t("groupUpdated"));
      await refreshAll();
    }

    async function editEntry(id) {
      const e = entries.find(function(x){ return x.id === id; });
      if (!e) return;
      const label = prompt(t("labelPrompt"), e.label); if (label === null) return;
      const issuer = prompt(t("issuerPrompt"), e.issuer || ""); if (issuer === null) return;
      const groupIdRaw = prompt(t("groupIdPrompt"), e.group_id || "");
      const groupId = groupIdRaw ? Number(groupIdRaw) : null;
      await api("/api/entries/" + id, {
        method: "PATCH",
        body: JSON.stringify({ label: label, issuer: issuer, groupId: groupId })
      });
      await refreshAll();
    }

    async function deleteEntry(id) {
      if (!confirm(t("deleteEntryConfirm"))) return;
      await api("/api/entries/" + id, { method: "DELETE" });
      await refreshAll();
    }

    async function createGroup() {
      try {
        await api("/api/groups", {
          method: "POST",
          body: JSON.stringify({ name: v("gName"), color: v("gColor") })
        });
        document.getElementById("gName").value = "";
        await refreshAll();
      } catch (e) { alert(e.message); }
    }

    async function deleteGroup(id) {
      if (!confirm(t("deleteGroupConfirm"))) return;
      await api("/api/groups/" + id, { method: "DELETE" });
      await refreshAll();
    }

    async function createUser() {
      try {
        await api("/api/users", {
          method: "POST",
          body: JSON.stringify({ username: v("uName"), password: v("uPass"), role: v("uRole") })
        });
        msg("userMsg", t("userCreated"));
        await refreshUsers();
      } catch (e) { msg("userMsg", e.message, true); }
    }

    async function loadLoginPolicy() {
      try {
        const d = await api("/api/security/login-policy");
        document.getElementById("riskMaxReq").value = d.maxRequestsPerMinute;
        document.getElementById("riskLockMin").value = d.lockMinutes;
        msg(
          "riskMsg",
          t("riskPolicyLoaded") + " " + d.maxRequestsPerMinute + " " + t("times") + t("lockFor") + d.lockMinutes + " " + t("minutes")
        );
      } catch (e) {
        msg("riskMsg", e.message, true);
      }
    }

    async function saveLoginPolicy() {
      try {
        const maxRequestsPerMinute = Number(v("riskMaxReq") || 10);
        const lockMinutes = Number(v("riskLockMin") || 15);
        await api("/api/security/login-policy", {
          method: "PATCH",
          body: JSON.stringify({ maxRequestsPerMinute: maxRequestsPerMinute, lockMinutes: lockMinutes })
        });
        msg("riskMsg", t("riskPolicySaved"));
        await loadLoginPolicy();
      } catch (e) {
        msg("riskMsg", e.message, true);
      }
    }

    async function refreshUsers() {
      const d = await api("/api/users");
      const table = document.getElementById("usersTable");
      // F-03 fix: rebuild table with a single DOM write (no innerHTML += accumulation)
      const tbody = document.createElement("tbody");
      const headerRow = document.createElement("tr");
      [t("usersThId"), t("usersThName"), t("usersThRole"), t("usersThAction")].forEach(function(label) {
        const th = document.createElement("th");
        th.textContent = label;
        headerRow.appendChild(th);
      });
      tbody.appendChild(headerRow);
      (d.users || []).forEach(function(u) {
        const next = u.role === "admin" ? "user" : "admin";
        const tr = document.createElement("tr");
        const idCell = document.createElement("td");
        idCell.textContent = String(u.id || "");
        const usernameCell = document.createElement("td");
        usernameCell.textContent = String(u.username || "");
        const roleCell = document.createElement("td");
        roleCell.textContent = String(u.role || "");
        const actionCell = document.createElement("td");
        actionCell.appendChild(userActionButton("ghost", "switch-role", u.id, t("setRole") + " " + next, next));
        actionCell.appendChild(document.createTextNode(" "));
        actionCell.appendChild(userActionButton("ghost", "reset-password", u.id, t("resetPassword")));
        actionCell.appendChild(document.createTextNode(" "));
        actionCell.appendChild(userActionButton("warn", "delete-user", u.id, t("delete")));
        tr.appendChild(idCell);
        tr.appendChild(usernameCell);
        tr.appendChild(roleCell);
        tr.appendChild(actionCell);
        tbody.appendChild(tr);
      });
      table.replaceChildren(tbody);
    }

    function userActionButton(className, action, id, label, role) {
      const button = document.createElement("button");
      button.className = className;
      button.dataset.action = action;
      button.dataset.id = String(id || "");
      if (role) button.dataset.role = role;
      button.textContent = label;
      return button;
    }

    async function switchRole(id, role) {
      // F-03 fix: properly implemented switchRole body
      await api("/api/users/" + id + "/role", { method: "PATCH", body: JSON.stringify({ role: role }) });
      await refreshUsers();
    }

    async function changeMyPassword() {
      const currentPassword = prompt(t("currentPassword"));
      if (!currentPassword) return;
      const newPassword = prompt(t("newPassword"));
      if (!newPassword) return;
      try {
        await api("/api/me/password", {
          method: "PATCH",
          body: JSON.stringify({ currentPassword: currentPassword, newPassword: newPassword })
        });
        alert(t("passwordChanged"));
        location.reload();
      } catch (e) { alert(e.message); }
    }

    async function resetPassword(id) {
      if (!confirm(t("passwordResetConfirm"))) return;
      const newPassword = prompt(t("newPassword"));
      if (!newPassword) return;
      try {
        await api("/api/users/" + id + "/password", {
          method: "PATCH",
          body: JSON.stringify({ newPassword: newPassword })
        });
        alert(t("passwordReset"));
        await refreshUsers();
      } catch (e) { alert(e.message); }
    }

    async function deleteUser(id) {
      if (!confirm(t("deleteUserConfirm"))) return;
      await api("/api/users/" + id, { method: "DELETE" });
      await refreshUsers();
    }

    function toggleImport() {
      const el = document.getElementById("importPanel");
      el.classList.toggle("hidden");
    }

    async function exportData() {
      if (!PLAINTEXT_EXPORT_ENABLED) {
        alert(t("plaintextExportDisabled"));
        return;
      }
      if (!confirm(t("plaintextExportConfirm"))) return;
      const password = prompt(t("currentPassword"));
      if (!password) return;
      const d = await api("/api/export", {
        method: "POST",
        body: JSON.stringify({ confirmPassword: password })
      });
      const text = JSON.stringify(d, null, 2);
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        alert(t("backupCopied"));
      } else {
        prompt(t("copyExportJson"), text);
      }
    }

    async function exportOtpAuthTxt() {
      try {
        if (!PLAINTEXT_EXPORT_ENABLED) {
          alert(t("plaintextExportDisabled"));
          return;
        }
        if (!confirm(t("plaintextExportConfirm"))) return;
        const password = prompt(t("currentPassword"));
        if (!password) return;
        const resp = await fetch("/api/export/otpauth", {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ confirmPassword: password })
        });
        if (!resp.ok) {
          let err = "HTTP " + resp.status;
          try {
            const d = await resp.json();
            if (d && d.error) err = d.error;
          } catch {}
          throw new Error(err);
        }
        const text = await resp.text();
        downloadTextFile("otpauth-export.txt", text);
        alert(t("otpauthExportDone"));
      } catch (e) {
        msg("importMsg", e.message, true);
      }
    }

    async function exportDataEncrypted() {
      const passphrase = prompt(t("setBackupPassphrase"));
      if (!passphrase) return;
      const d = await api("/api/export/encrypted", {
        method: "POST",
        body: JSON.stringify({ passphrase: passphrase })
      });
      const text = JSON.stringify(d.encrypted, null, 2);
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
        alert(t("encryptedBackupCopied"));
      } else {
        prompt(t("copyEncryptedExportJson"), text);
      }
    }

    async function importData() {
      try {
        const payload = JSON.parse(v("importText") || "{}");
        const d = await api("/api/import", { method: "POST", body: JSON.stringify(payload) });
        msg("importMsg", t("importedDone") + ": groups=" + d.imported.groups + ", entries=" + d.imported.entries);
        await refreshAll();
      } catch (e) { msg("importMsg", e.message, true); }
    }

    async function importOtpAuthText() {
      try {
        const text = String(v("importText") || "");
        const d = await api("/api/import/otpauth", { method: "POST", body: JSON.stringify({ text: text }) });
        msg("importMsg", t("otpauthImportDone") + ": found=" + d.found + ", imported=" + d.imported + ", failed=" + d.failed);
        await refreshAll();
      } catch (e) { msg("importMsg", e.message, true); }
    }

    async function importDataEncrypted() {
      try {
        const encrypted = JSON.parse(v("importText") || "{}");
        const passphrase = v("importPassphrase");
        const d = await api("/api/import/encrypted", {
          method: "POST",
          body: JSON.stringify({ encrypted: encrypted, passphrase: passphrase })
        });
        msg("importMsg", t("encryptedImportedDone") + ": groups=" + d.imported.groups + ", entries=" + d.imported.entries);
        await refreshAll();
      } catch (e) { msg("importMsg", e.message, true); }
    }

    async function loadImportFile(ev) {
      try {
        const file = ev && ev.target && ev.target.files && ev.target.files[0];
        if (!file) return;
        const text = await file.text();
        document.getElementById("importText").value = text;
        msg("importMsg", t("importFileLoaded"));
      } catch (e) {
        msg("importMsg", e.message, true);
      }
    }

    async function startScan() {
      try {
        const video = document.getElementById("scanVideo");
        scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
        video.srcObject = scanStream;
        video.classList.remove("hidden");
        msg("scanMsg", t("cameraStarted"));
        const canUseBarcodeDetector = "BarcodeDetector" in window;
        let detector = null;
        if (canUseBarcodeDetector) {
          detector = new BarcodeDetector({ formats: ["qr_code"] });
        } else {
          await ensureJsQrLoaded();
          msg("scanMsg", t("cameraFallback"));
        }
        clearInterval(scanTimer);
        scanTimer = setInterval(async function() {
          try {
            let raw = "";
            if (detector) {
              const barcodes = await detector.detect(video);
              if (barcodes && barcodes.length) raw = String(barcodes[0].rawValue || "");
            } else {
              raw = await detectQrFromVideoByJsQr(video);
            }
            if (raw) {
              applyScannedOtpUri(raw);
              stopScan();
            } else if (canUseBarcodeDetector && !jsQrReady) {
              // BarcodeDetector may fail on some devices; fallback once to jsQR.
              await ensureJsQrLoaded();
              msg("scanMsg", t("cameraFallback"));
              detector = null;
            }
          } catch {}
        }, 600);
      } catch (e) {
        msg("scanMsg", t("cameraDenied") + e.message, true);
      }
    }

    function stopScan() {
      if (scanTimer) { clearInterval(scanTimer); scanTimer = null; }
      if (scanStream) {
        scanStream.getTracks().forEach(function(t) { t.stop(); });
        scanStream = null;
      }
      const video = document.getElementById("scanVideo");
      if (video) {
        video.srcObject = null;
        video.classList.add("hidden");
      }
    }

    async function scanImageFile(ev) {
      try {
        const file = ev && ev.target && ev.target.files && ev.target.files[0];
        if (!file) return;
        let raw = "";
        // F-02: use local-only QR detection 鈥?no third-party API.
          if ("BarcodeDetector" in window) {
            const bmp = await createImageBitmap(file);
            const detector = new BarcodeDetector({ formats: ["qr_code"] });
            const barcodes = await detector.detect(bmp);
            if (barcodes.length) raw = String(barcodes[0].rawValue || "");
          }
          if (!raw) {
            await ensureJsQrLoaded();
            raw = await detectQrFromImageFileByJsQr(file);
          }
        if (!raw) {
          msg("scanMsg", t("noQrFound"), true);
          return;
        }
        applyScannedOtpUri(raw);
        msg("scanMsg", t("qrFromImage"));
      } catch (e) {
        msg("scanMsg", t("scanImageFailed") + e.message, true);
      }
    }

    function applyScannedOtpUri(raw) {
      document.getElementById("eUri").value = String(raw || "").trim();
      msg("scanMsg", t("qrDetected") + " " + t("qrReadyToSave"));
    }

    async function ensureJsQrLoaded() {
      if (jsQrReady && typeof window.jsQR === "function") return;
      await new Promise(function(resolve, reject) {
        const exists = document.querySelector("script[data-jsqr='1']");
        if (exists) {
          exists.addEventListener("load", resolve, { once: true });
          exists.addEventListener("error", reject, { once: true });
          return;
        }
        const s = document.createElement("script");
        s.src = "https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js";
        s.integrity = "sha384-b5Ya4Bq3qCyz39m2ISh+4DxjAIljdeFwK/BsXLuj9gugaNwAcj/ia15fxNZL9Nlx";
        s.crossOrigin = "anonymous";
        s.async = true;
        s.dataset.jsqr = "1";
        s.onload = resolve;
        s.onerror = reject;
        document.head.appendChild(s);
      });
      jsQrReady = typeof window.jsQR === "function";
      if (!jsQrReady) throw new Error("jsQR unavailable");
    }

    async function detectQrFromVideoByJsQr(video) {
      if (!window.jsQR) return "";
      const w = video.videoWidth || 0;
      const h = video.videoHeight || 0;
      if (!w || !h) return "";
      const canvas = document.createElement("canvas");
      canvas.width = w;
      canvas.height = h;
      const ctx = canvas.getContext("2d", { willReadFrequently: true });
      ctx.drawImage(video, 0, 0, w, h);
      const img = ctx.getImageData(0, 0, w, h);
      const result = window.jsQR(img.data, w, h, { inversionAttempts: "attemptBoth" });
      return result && result.data ? String(result.data) : "";
    }

    async function detectQrFromImageFileByJsQr(file) {
      if (!window.jsQR) return "";
      const dataUrl = await fileToDataUrl(file);
      const img = await loadImage(dataUrl);
      const canvas = document.createElement("canvas");
      canvas.width = img.naturalWidth || img.width;
      canvas.height = img.naturalHeight || img.height;
      const ctx = canvas.getContext("2d", { willReadFrequently: true });
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const result = window.jsQR(imageData.data, canvas.width, canvas.height, { inversionAttempts: "attemptBoth" });
      return result && result.data ? String(result.data) : "";
    }

    function fileToDataUrl(file) {
      return new Promise(function(resolve, reject) {
        const fr = new FileReader();
        fr.onload = function() { resolve(String(fr.result || "")); };
        fr.onerror = reject;
        fr.readAsDataURL(file);
      });
    }

    function loadImage(src) {
      return new Promise(function(resolve, reject) {
        const img = new Image();
        img.onload = function() { resolve(img); };
        img.onerror = reject;
        img.src = src;
      });
    }

    function downloadTextFile(filename, content) {
      const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    }

    function esc(s) {
      return String(s || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/\"/g, "&quot;")
        .replace(/'/g, "&#39;");
    }

    function bindUiEvents() {
      document.addEventListener("click", function(evt) {
        const target = evt.target.closest("[data-action]");
        if (!target) return;
        const action = target.dataset.action;
        const id = Number(target.dataset.id || 0);
        const role = target.dataset.role || "";
        const run = {
          "bootstrap": function() { return bootstrap(evt); },
          "login": function() { return login(evt); },
          "logout": function() { return logout(evt); },
          "refresh-all": refreshAll,
          "export-data": exportData,
          "export-otpauth": exportOtpAuthTxt,
          "export-encrypted": exportDataEncrypted,
          "toggle-import": toggleImport,
          "import-data": importData,
          "import-otpauth": importOtpAuthText,
          "import-encrypted": importDataEncrypted,
          "start-scan": startScan,
          "stop-scan": stopScan,
          "create-entry": createEntry,
          "create-group": createGroup,
          "create-user": createUser,
          "save-login-policy": saveLoginPolicy,
          "delete-group": function() { return deleteGroup(id); },
          "gen-hotp": function() { return genHotp(id); },
          "copy-code": function() { return copyCode(id); },
          "set-entry-group": function() { return setEntryGroup(id); },
          "remove-entry-group": function() { return removeEntryGroup(id); },
          "edit-entry": function() { return editEntry(id); },
          "delete-entry": function() { return deleteEntry(id); },
          "switch-role": function() { return switchRole(id, role); },
          "change-my-password": changeMyPassword,
          "reset-password": function() { return resetPassword(id); },
          "delete-user": function() { return deleteUser(id); },
        }[action];
        if (!run) return;
        evt.preventDefault();
        Promise.resolve(run()).catch(function(e) { alert(e.message || String(e)); });
      });

      document.getElementById("langSelect").addEventListener("change", function(evt) {
        changeLang(evt.target.value);
      });
      document.getElementById("autoLogoutSelect").addEventListener("change", function(evt) {
        changeAutoLogout(evt.target.value);
      });
      document.getElementById("search").addEventListener("input", renderEntries);
      document.getElementById("groupFilter").addEventListener("change", renderEntries);
      document.getElementById("importFile").addEventListener("change", loadImportFile);
      document.getElementById("qrImageFile").addEventListener("change", scanImageFile);
    }

    function applyDynamicStyles() {
      document.querySelectorAll(".swatch[data-color]").forEach(function(el) {
        const color = el.getAttribute("data-color") || "#0f766e";
        if (/^#[0-9a-fA-F]{6}$/.test(color)) el.style.backgroundColor = color;
      });
      document.querySelectorAll(".bar > i[data-progress]").forEach(function(el) {
        const progress = Math.max(0, Math.min(100, Number(el.getAttribute("data-progress") || 0)));
        el.style.width = progress + "%";
      });
    }

    setInterval(function() {
      entries.forEach(function(e) {
        if (e.otp_type !== "hotp") refreshCode(e.id, true);
      });
    }, 5000);

    bindUiEvents();
    init();
  </script>
</body>
</html>`;
}

