const SESSION_COOKIE = "__Host-session";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days
const API_ACCESS_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days
const API_REFRESH_TTL_SECONDS = 60 * 60 * 24 * 90; // 90 days
const CLOSE_LOGOUT_GRACE_SECONDS = 12;
const CLOSE_SOON_HEADER = "x-session-close";
const CLOSE_SOON_HEADER_VALUE = "web-beforeunload";
// Keep hashing strong while avoiding CPU limit spikes on Cloudflare Workers.
const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_HASH = "SHA-256";
const PASSWORD_POLICY_DESCRIPTION = "at least 12 chars with uppercase, lowercase, number, and symbol";
const DEFAULT_RISK_MAX_REQUESTS_PER_MINUTE = 10;
const DEFAULT_RISK_LOCK_MINUTES = 15;
const DEFAULT_API_RATE_MAX_REQUESTS_PER_MINUTE = 120;
const TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const ANDROID_CLIENT_TYPE = "android";
const EXTENSION_CLIENT_TYPE = "edge_extension";
const EXTENSION_BATCH_MAX_IDS = 100;
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
  ["GET", "/api/export", handleExportData],
  ["GET", "/api/export/otpauth", handleExportOtpAuth],
  ["POST", "/api/export/encrypted", handleExportDataEncrypted],
  ["POST", "/api/import", handleImportData],
  ["POST", "/api/import/otpauth", handleImportOtpAuth],
  ["POST", "/api/import/encrypted", handleImportDataEncrypted],
  ["GET", "/api/users", handleListUsers],
  ["POST", "/api/users", handleCreateUser],
  ["PATCH", /^\/api\/users\/\d+\/role$/, handleUpdateUserRole],
  ["PATCH", /^\/api\/users\/\d+\/password$/, handleResetUserPassword],
  ["DELETE", /^\/api\/users\/\d+$/, handleDeleteUser],
  ["GET", "/api/security/login-policy", handleGetLoginPolicy],
  ["PATCH", "/api/security/login-policy", handleUpdateLoginPolicy],
];

function entryRoutes(prefix) {
  return [
    ["GET", `${prefix}/entries`, handleListEntries],
    ["POST", `${prefix}/entries`, handleCreateEntry],
    ["PATCH", routePattern(prefix, "/entries/\\d+"), handleUpdateEntry],
    ["GET", routePattern(prefix, "/entries/\\d+/code"), handleEntryCode],
    ["POST", routePattern(prefix, "/entries/\\d+/verify"), handleVerifyTotp],
    ["POST", routePattern(prefix, "/entries/\\d+/hotp"), handleConsumeHotp],
    ["DELETE", routePattern(prefix, "/entries/\\d+"), handleDeleteEntry],
  ];
}

function groupRoutes(prefix) {
  return [
    ["GET", `${prefix}/groups`, handleListGroups],
    ["POST", `${prefix}/groups`, handleCreateGroup],
    ["DELETE", routePattern(prefix, "/groups/\\d+"), handleDeleteGroup],
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
        return html(appHtml(env, nonce), nonce);
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
        return html(appHtml(env, nonce), nonce);
      }

      return withCors(request, json({ error: "Not found" }, 404), env);
    } catch (err) {
      if (err instanceof ApiError) {
        return withCors(request, json({ error: err.message }, err.status), env);
      }
      const payload = { error: "Internal Server Error" };
      if (debugErrorsEnabled(env)) {
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
  const initialized = await hasAnyUser(env);
  if (initialized) return json({ error: "Already initialized" }, 400);

  const body = await parseJson(request);
  const username = normalizeUsername(body.username);
  const password = String(body.password || "");
  if (!username || !validPassword(password)) {
    return json({ error: `Invalid username or password (${PASSWORD_POLICY_DESCRIPTION})` }, 400);
  }

  const { hashB64, saltB64 } = await hashPassword(password);
  const now = nowIso();
  const result = await env.DB.prepare(
    "INSERT INTO users (username, password_hash, password_salt, role, created_at) VALUES (?, ?, ?, 'admin', ?)"
  )
    .bind(username, hashB64, saltB64, now)
    .run();

  let userId = normalizeDbId(result.meta?.last_row_id);
  if (!userId) {
    const row = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
    userId = normalizeDbId(row?.id);
  }
  if (!userId) return json({ error: "Failed to create user id" }, 500);
  const { cookie } = await createSession(env, userId);
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
        lockedUntil: new Date(risk.lockUntil * 1000).toISOString(),
      },
      429
    );
  }
  if (!username || !password) return json({ error: "Username and password are required" }, 400);
  if (hasTurnstileSecret(env)) {
    const ip = String(request.headers.get("cf-connecting-ip") || "").split(",")[0].trim();
    const ts = await verifyTurnstileToken(turnstileToken, ip, env);
    if (!ts.ok) {
      return json({ error: "Turnstile verification failed" }, 400);
    }
  }

  const row = await env.DB.prepare(
    "SELECT id, username, role, password_hash, password_salt FROM users WHERE username = ?"
  )
    .bind(username)
    .first();
  if (!row) return json({ error: "Invalid credentials" }, 401);

  const passwordCheck = await verifyPasswordDetailed(password, row.password_salt, row.password_hash);
  if (!passwordCheck.ok) return json({ error: "Invalid credentials" }, 401);
  if (passwordCheck.needsRehash) {
    await upgradePasswordHash(env, row.id, password).catch(() => {});
  }
  await clearLoginRiskControl(request, env, username).catch(() => {});

  const clientType = String(body.clientType || "").trim().toLowerCase();
  if (clientType === ANDROID_CLIENT_TYPE) {
    const apiSession = await createApiSession(env, row.id, ANDROID_CLIENT_TYPE);
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

  const { cookie } = await createSession(env, row.id);
  return json(
    { ok: true, user: { id: row.id, username: row.username, role: row.role } },
    200,
    { "set-cookie": cookie }
  );
}

async function handleMobileLogin(request, env) {
  const body = await parseJson(request);
  body.clientType = ANDROID_CLIENT_TYPE;
  return handleLogin(withJsonBody(request, body), env);
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
  const clientType = normalizeApiClientType(body.clientType || request.headers.get("x-client-type") || ANDROID_CLIENT_TYPE);
  if (!clientType) return json({ error: "clientType must be android or browser_extension" }, 400);

  if (clientType === "browser_extension") {
    body.clientType = EXTENSION_CLIENT_TYPE;
    return handleExtensionLogin(withJsonBody(request, body), env);
  }

  body.clientType = ANDROID_CLIENT_TYPE;
  return handleLogin(withJsonBody(request, body), env);
}

async function handleApiClientRefresh(request, env) {
  const body = await parseJson(request);
  const clientType = normalizeApiClientType(body.clientType || request.headers.get("x-client-type") || ANDROID_CLIENT_TYPE);
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
        lockedUntil: new Date(risk.lockUntil * 1000).toISOString(),
      },
      429
    );
  }
  if (!username || !password) return json({ error: "Username and password are required" }, 400);

  const row = await env.DB.prepare(
    "SELECT id, username, role, password_hash, password_salt FROM users WHERE username = ?"
  )
    .bind(username)
    .first();
  if (!row) return json({ error: "Invalid credentials" }, 401);

  const passwordCheck = await verifyPasswordDetailed(password, row.password_salt, row.password_hash);
  if (!passwordCheck.ok) return json({ error: "Invalid credentials" }, 401);
  if (passwordCheck.needsRehash) {
    await upgradePasswordHash(env, row.id, password).catch(() => {});
  }
  await clearLoginRiskControl(request, env, username).catch(() => {});

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

  const placeholders = normalizedIds.map(() => "?").join(", ");
  const baseParams = [...normalizedIds];
  let query =
    `SELECT id, user_id, secret_enc, digits, period, algorithm, otp_type, hotp_counter FROM totp_entries WHERE id IN (${placeholders})`;
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
      const algorithm = normalizeAlgorithm(row.algorithm || "SHA-256");
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
  const digits = body.digits !== undefined ? Number(body.digits) : existing.digits;
  const period = body.period !== undefined ? Number(body.period) : existing.period;
  const algorithm = body.algorithm !== undefined ? normalizeAlgorithm(body.algorithm) : normalizeAlgorithm(existing.algorithm || "SHA-256");
  const otpType = body.otpType ? (body.otpType === "hotp" ? "hotp" : "totp") : (existing.otp_type || "totp");
  const hotpCounter = body.hotpCounter !== undefined ? Number(body.hotpCounter) : (existing.hotp_counter || 0);
  const groupId = body.groupId !== undefined ? parseOptionalPositiveId(body.groupId) : existing.group_id;

  if (!label) return json({ error: "label is required" }, 400);
  if (groupId === false) return json({ error: "groupId must be a positive integer or null" }, 400);
  if (![6, 7, 8].includes(digits)) return json({ error: "digits must be 6/7/8" }, 400);
  if (otpType === "totp" && (!Number.isFinite(period) || period < 15 || period > 120)) return json({ error: "period must be between 15 and 120" }, 400);
  if (!algorithm) return json({ error: "algorithm must be SHA-256 or SHA-512" }, 400);
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
  const algorithm = normalizeAlgorithm(row.algorithm || "SHA-256");
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

  const row = await env.DB.prepare("SELECT * FROM totp_entries WHERE id = ?").bind(id).first();
  if (!row) return json({ error: "Entry not found" }, 404);
  if (auth.user.role !== "admin" && row.user_id !== auth.user.id) return json({ error: "Forbidden" }, 403);
  if ((row.otp_type || "totp") === "hotp") return json({ error: "Use /api/entries/:id/hotp for HOTP codes" }, 400);

  const algorithm = normalizeAlgorithm(row.algorithm || "SHA-256");
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

  const secret = await decryptText(row.secret_enc, env);
  const counter = Number(row.hotp_counter || 0);
  const digits = normalizeOtpDigits(row.digits);
  const algorithm = normalizeAlgorithm(row.algorithm || "SHA-256");
  if (!algorithm) return json({ error: "Unsupported OTP algorithm" }, 400);
  const code = await generateHotp(secret, digits, algorithm, counter);
  
  // Use transactional update with counter verification to prevent race condition
  const nextCounter = counter + 1;
  const result = await env.DB.prepare(
    "UPDATE totp_entries SET hotp_counter = ? WHERE id = ? AND hotp_counter = ?"
  ).bind(nextCounter, id, counter).run();
  
  if (result.meta?.changes === 0) {
    // Counter was modified by another request, reject this attempt
    return json({ error: "HOTP code already consumed or counter mismatch" }, 409);
  }
  
  return json({ code, counter, nextCounter, otpType: "hotp" });
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
  const requestedUserId = Number(body.userId !== undefined ? body.userId : auth.user.id);
  const userId = auth.user.role === "admin" ? requestedUserId : auth.user.id;
  if (!name) return json({ error: "name is required" }, 400);
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

  await env.DB.prepare("DELETE FROM groups WHERE id = ?").bind(id).run();
  return json({ ok: true });
}

async function handleExportData(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  const confirmation = requirePlaintextExportConfirmation(request, env);
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
  const confirmation = requirePlaintextExportConfirmation(request, env);
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
    try {
      const secretBytes = base32Decode(secret);
      if (!secretBytes.length) throw new Error("invalid");
      const digits = normalizeOtpDigits(data.digits);
      const period = normalizeTotpPeriod(data.period);
      const algorithm = normalizeAlgorithm(data.algorithm || "SHA-256");
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
        .bind(userId, label, String(data.issuer || ""), secretEnc, digits, period, algorithm, otpType, hotpCounter, nowIso())
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

function requirePlaintextExportConfirmation(request, env) {
  if (String(env.ALLOW_PLAINTEXT_EXPORT || "").toLowerCase() !== "true") {
    return json({ error: "Plaintext export is disabled. Use /api/export/encrypted." }, 403);
  }
  const url = new URL(request.url);
  const confirmed =
    url.searchParams.get("confirm") === "plaintext" ||
    String(request.headers.get("x-plaintext-export-confirm") || "").toLowerCase() === "true";
  if (!confirmed) {
    return json({ error: "Plaintext export requires explicit confirmation." }, 400);
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
    if (!secret || !label) continue;
    try {
      const secretBytes = base32Decode(secret);
      if (!secretBytes.length) continue;
    } catch {
      continue;
    }
    const groupId = e.group_id !== undefined && e.group_id !== null ? groupMap.get(String(e.group_id)) || null : null;
    const otpType = e.otp_type === "hotp" ? "hotp" : "totp";
    const algorithm = normalizeAlgorithm(e.algorithm || "SHA-256");
    if (!algorithm) continue;
    const digits = normalizeOtpDigits(e.digits);
    const period = normalizeTotpPeriod(e.period);
    const hotpCounter = normalizeHotpCounter(e.hotp_counter);
    const secretEnc = await encryptText(secret, env);

    await env.DB.prepare(
      "INSERT INTO totp_entries (user_id, label, issuer, secret_enc, digits, period, algorithm, otp_type, hotp_counter, group_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
      .bind(userId, label, String(e.issuer || ""), secretEnc, digits, period, algorithm, otpType, hotpCounter, groupId, nowIso())
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
  if (passphrase.length < 10) {
    return json({ error: "passphrase must be at least 10 chars" }, 400);
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
  if (passphrase.length < 10) return json({ error: "passphrase must be at least 10 chars" }, 400);
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
    return json({ error: `Invalid username or password (${PASSWORD_POLICY_DESCRIPTION})` }, 400);
  }

  const { hashB64, saltB64 } = await hashPassword(password);
  const now = nowIso();
  try {
    const result = await env.DB.prepare(
      "INSERT INTO users (username, password_hash, password_salt, role, created_at) VALUES (?, ?, ?, ?, ?)"
    )
      .bind(username, hashB64, saltB64, role, now)
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
    return json({ error: `Invalid new password (${PASSWORD_POLICY_DESCRIPTION})` }, 400);
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
    return json({ error: `Invalid new password (${PASSWORD_POLICY_DESCRIPTION})` }, 400);
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
  const riskKey = await sha256Base64(`${username || "__empty__"}|${ip}`);
  let row;
  try {
    row = await env.DB.prepare(
      "SELECT key, window_start, request_count, lock_until FROM login_risk_control WHERE key = ?"
    )
      .bind(riskKey)
      .first();
  } catch (err) {
    if (isMissingTableError(err, "login_risk_control")) return { blocked: false };
    throw err;
  }

  if (row && Number(row.lock_until) > nowSec) {
    return {
      blocked: true,
      retryAfterSeconds: Number(row.lock_until) - nowSec,
      lockUntil: Number(row.lock_until),
    };
  }

  let windowStart = nowSec;
  let requestCount = 1;
  let lockUntil = 0;
  if (row && nowSec - Number(row.window_start) < 60) {
    windowStart = Number(row.window_start);
    requestCount = Number(row.request_count) + 1;
  }
  if (requestCount >= policy.maxRequestsPerMinute) {
    lockUntil = nowSec + policy.lockMinutes * 60;
  }

  try {
    await env.DB.prepare(
      "INSERT INTO login_risk_control (key, username, ip, window_start, request_count, lock_until, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(key) DO UPDATE SET username = excluded.username, ip = excluded.ip, window_start = excluded.window_start, request_count = excluded.request_count, lock_until = excluded.lock_until, updated_at = excluded.updated_at"
    )
      .bind(riskKey, username || "__empty__", ip, windowStart, requestCount, lockUntil, nowSec)
      .run();
  } catch (err) {
    if (isMissingTableError(err, "login_risk_control")) return { blocked: false };
    throw err;
  }

  if (lockUntil > nowSec) {
    return { blocked: true, retryAfterSeconds: lockUntil - nowSec, lockUntil };
  }
  return { blocked: false };
}

async function clearLoginRiskControl(request, env, username) {
  const ip = clientIp(request);
  const riskKey = await sha256Base64(`${username || "__empty__"}|${ip}`);
  await env.DB.prepare("DELETE FROM login_risk_control WHERE key = ?").bind(riskKey).run();
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
    if (isMissingTableError(err, "login_risk_control")) return null;
    throw err;
  }

  let windowStart = nowSec;
  let requestCount = 1;
  if (row && nowSec - Number(row.window_start) < 60) {
    windowStart = Number(row.window_start);
    requestCount = Number(row.request_count) + 1;
  }

  try {
    await env.DB.prepare(
      "INSERT INTO login_risk_control (key, username, ip, window_start, request_count, lock_until, updated_at) VALUES (?, ?, ?, ?, ?, 0, ?) ON CONFLICT(key) DO UPDATE SET username = excluded.username, ip = excluded.ip, window_start = excluded.window_start, request_count = excluded.request_count, lock_until = excluded.lock_until, updated_at = excluded.updated_at"
    )
      .bind(rateKey, "__api__", clientIp(request), windowStart, requestCount, nowSec)
      .run();
  } catch (err) {
    if (isMissingTableError(err, "login_risk_control")) return null;
    throw err;
  }

  if (requestCount > maxRequests) {
    return json(
      { error: "Too many API requests", retryAfterSeconds: Math.max(1, 60 - (nowSec - windowStart)) },
      429,
      { "Retry-After": String(Math.max(1, 60 - (nowSec - windowStart))) }
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
      "/api/bootstrap",
      "/api/login",
      "/api/mobile/login",
      "/api/extension/login",
      "/api/v1/auth/login",
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
  return `ip:${clientIp(request)}`;
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
  return String(request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || "unknown")
    .split(",")[0]
    .trim() || "unknown";
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
        "SELECT s.id AS session_id, s.client_type, u.id, u.username, u.role FROM api_sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ? AND s.refresh_expires_at > ?"
      )
        .bind(tokenHash, now, now)
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
  if (["browser_extension", "extension", "edge_extension", "chrome_extension"].includes(v)) {
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

async function verifyPassword(password, saltB64, expectedHashB64) {
  return (await verifyPasswordDetailed(password, saltB64, expectedHashB64)).ok;
}

async function verifyPasswordDetailed(password, saltB64, expectedHashB64) {
  try {
    const expected = b64ToBytes(expectedHashB64);
    const current = await hashPassword(password, saltB64, PBKDF2_ITERATIONS);
    if (constantTimeEqual(b64ToBytes(current.hashB64), expected)) {
      return { ok: true, needsRehash: false };
    }
  } catch {
    return { ok: false, needsRehash: false };
  }
  return { ok: false, needsRehash: false };
}

async function upgradePasswordHash(env, userId, password) {
  const { hashB64, saltB64 } = await hashPassword(password);
  await env.DB.prepare("UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?")
    .bind(hashB64, saltB64, userId)
    .run();
}

const encryptionKeyCache = new Map();

async function getEncryptionKey(env) {
  const cacheKey = `${env.ENVIRONMENT || env.NODE_ENV || "default"}|${env.ENCRYPTION_KEY}|${env.SESSION_PEPPER}`;
  if (!encryptionKeyCache.has(cacheKey)) {
    if (encryptionKeyCache.size >= 8) encryptionKeyCache.clear();
    encryptionKeyCache.set(cacheKey, crypto.subtle.importKey("raw", b64ToBytes(env.ENCRYPTION_KEY), "AES-GCM", false, [
      "encrypt",
      "decrypt",
    ]));
  }
  return encryptionKeyCache.get(cacheKey);
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
    iterations: 180000,
    salt: bytesToB64(salt),
    iv: bytesToB64(iv),
    ciphertext: bytesToB64(new Uint8Array(cipher)),
  };
}

async function decryptWithPassphrase(payload, passphrase) {
  if (payload.format !== "worker-2fauth-encrypted-v1") throw new Error("unsupported format");
  const iterations = Number(payload.iterations || 180000);
  const salt = b64ToBytes(String(payload.salt || ""));
  const iv = b64ToBytes(String(payload.iv || ""));
  const ciphertext = b64ToBytes(String(payload.ciphertext || ""));
  const key = await derivePassphraseKey(passphrase, salt, iterations);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return JSON.parse(dec(new Uint8Array(plain)));
}

async function derivePassphraseKey(passphrase, salt, iterations = 180000) {
  const baseKey = await crypto.subtle.importKey("raw", enc(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function parseOtpAuthUri(uri) {
  try {
    const url = new URL(uri);
    if (url.protocol !== "otpauth:" || !["totp", "hotp"].includes(url.hostname)) {
      return { ok: false, error: "Only otpauth://totp or otpauth://hotp URI is supported" };
    }
    const otpType = url.hostname;
    const secret = String(url.searchParams.get("secret") || "").trim();
    if (!secret) return { ok: false, error: "otpauth URI missing secret" };
    const issuerQ = String(url.searchParams.get("issuer") || "").trim();
    const labelRaw = decodeURIComponent(url.pathname.replace(/^\//, ""));
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
    const algorithm = normalizeAlgorithm(url.searchParams.get("algorithm") || "SHA-256");
    if (!algorithm) return { ok: false, error: "otpauth URI algorithm must be SHA-256 or SHA-512" };
    return {
      ok: true,
      data: { secret, issuer, label: label || issuer || "OTP", digits, period, algorithm, otpType, hotpCounter },
    };
  } catch {
    return { ok: false, error: "Invalid otpauth URI" };
  }
}

function extractOtpAuthUris(text) {
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
  params.set("algorithm", String(normalizeAlgorithm(entry.algorithm || "SHA-256") || "SHA-256").replace("-", ""));
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

function pathResourceId(request, resource) {
  const parts = new URL(request.url).pathname.split("/").filter(Boolean);
  const idx = parts.indexOf(resource);
  if (idx < 0 || idx + 1 >= parts.length) return NaN;
  return Number(parts[idx + 1]);
}

function parseOptionalPositiveId(value) {
  if (value === undefined || value === null || value === "") return null;
  const id = Number(value);
  if (!Number.isInteger(id) || id <= 0) return false;
  return id;
}

function randomHex(byteLen) {
  const arr = crypto.getRandomValues(new Uint8Array(byteLen));
  return [...arr].map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function parseJson(request) {
  const text = await request.text();
  if (!text.trim()) return {};
  try {
    return JSON.parse(text);
  } catch {
    throw new ApiError(400, "Invalid JSON body");
  }
}

async function sha256Base64(input) {
  const digest = await crypto.subtle.digest("SHA-256", enc(String(input)));
  return bytesToB64(new Uint8Array(digest));
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a[i] ^ b[i];
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
  const headers = corsHeaders(origin);
  headers.set("Access-Control-Max-Age", "86400");
  headers.set("Vary", "Origin");
  return new Response(null, { status: 204, headers });
}

function withCors(request, response, env) {
  const origin = allowedCorsOrigin(request, env);
  if (!origin) return response;
  const next = new Response(response.body, response);
  const headers = corsHeaders(origin);
  for (const [key, value] of headers) next.headers.set(key, value);
  next.headers.set("Vary", appendVary(next.headers.get("Vary"), "Origin"));
  return next;
}

function corsHeaders(origin) {
  return new Headers({
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": CORS_ALLOWED_METHODS,
    "Access-Control-Allow-Headers": CORS_ALLOWED_HEADERS,
    "Access-Control-Allow-Credentials": "true",
  });
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

function isSafeCorsOrigin(origin) {
  if (/^chrome-extension:\/\/[a-z0-9_-]{3,128}$/i.test(origin)) return true;
  if (/^moz-extension:\/\/[a-z0-9_-]{3,128}$/i.test(origin)) return true;
  try {
    const url = new URL(origin);
    return origin === url.origin && ["https:", "http:"].includes(url.protocol);
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
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
  };
}

function debugErrorsEnabled(env) {
  const enabled = String(env.DEBUG_ERRORS || "").toLowerCase() === "true";
  const environment = String(env.ENVIRONMENT || env.NODE_ENV || "").toLowerCase();
  return enabled && environment !== "production";
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
  const scriptSrc = ["'self'", `'nonce-${nonce}'`, "https://challenges.cloudflare.com", "https://cdn.jsdelivr.net"];
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
        "connect-src 'self' https://api.qrserver.com https://challenges.cloudflare.com",
        "frame-src https://challenges.cloudflare.com",
        "base-uri 'none'",
        "frame-ancestors 'none'",
        "form-action 'self'",
      ].join("; "),
      ...commonSecurityHeaders(),
    },
  });
}

function appHtml(env, nonce) {
  const turnstileSiteKey = String((env && env.TURNSTILE_SITE_KEY) || "");
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>2FAuth 验证器</title>
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
        <h1 id="appTitle">2FAuth 验证器</h1>
        <div id="state" class="sub">加载中...</div>
      </div>
      <div class="row">
        <select id="langSelect">
          <option value="zh-CN">简体中文</option>
          <option value="en-US">English</option>
        </select>
        <select id="autoLogoutSelect">
          <option value="15">15分钟自动退出</option>
          <option value="30">30分钟自动退出</option>
          <option value="60">60分钟自动退出</option>
          <option value="120">120分钟自动退出</option>
          <option value="0">不自动退出</option>
        </select>
        <div id="whoami" class="sub"></div>
      </div>
    </div>

    <section id="bootstrap" class="panel stack">
      <h3 class="flush">初始化管理员</h3>
      <div class="row">
        <input id="bsUser" placeholder="管理员用户名" />
        <input id="bsPass" type="password" placeholder="密码（至少12位，含大小写/数字/符号）" />
        <button type="button" data-action="bootstrap">初始化</button>
      </div>
      <div id="bsMsg" class="muted"></div>
    </section>

    <section id="login" class="panel stack">
      <h3 class="flush">登录</h3>
      <div class="row">
        <input id="loginUser" placeholder="用户名" />
        <input id="loginPass" type="password" placeholder="密码" />
        <button type="button" data-action="login">登录</button>
      </div>
      <div id="turnstileBox" class="row hidden"></div>
      <div id="loginMsg" class="muted"></div>
    </section>

    <section id="app">
      <div class="panel row top-actions">
        <div class="row">
          <input id="search" placeholder="搜索标签/发行方..." />
          <select id="groupFilter"><option value="">全部分组</option></select>
          <button class="ghost" data-action="refresh-all">刷新</button>
        </div>
        <div class="row">
          <button class="ghost" data-action="export-data">导出</button>
          <button class="ghost" data-action="export-otpauth">导出 otpauth 文本</button>
          <button class="ghost" data-action="export-encrypted">加密导出</button>
          <button class="ghost" data-action="toggle-import">导入</button>
          <button class="ghost" data-action="change-my-password">修改密码</button>
          <button type="button" class="warn" data-action="logout">退出登录</button>
        </div>
      </div>

      <div id="importPanel" class="panel stack hidden">
        <h3 class="flush">导入备份 JSON</h3>
        <textarea id="importText" placeholder='粘贴 /api/export 的 JSON'></textarea>
        <div class="row">
          <input id="importFile" type="file" accept=".json,.txt,text/plain,application/json" />
          <input id="importPassphrase" type="password" placeholder="口令（用于加密备份）" />
          <button data-action="import-data">执行导入</button>
          <button class="ghost" data-action="import-otpauth">导入 otpauth 文本</button>
          <button class="ghost" data-action="import-encrypted">执行加密导入</button>
        </div>
        <div id="importMsg" class="muted"></div>
      </div>

      <div class="grid">
        <div class="stack">
          <div class="panel stack">
            <h3 class="flush">新建条目</h3>
            <input id="eLabel" placeholder="标签（如 GitHub）" />
            <input id="eIssuer" placeholder="发行方（可选）" />
            <input id="eSecret" placeholder="Base32 密钥" />
            <input id="eUri" placeholder="或 otpauth://totp/... / otpauth://hotp/..." />
            <div class="row">
              <button class="ghost" data-action="start-scan">摄像头扫码</button>
              <button class="ghost" data-action="stop-scan">停止扫码</button>
              <button class="ghost" data-action="recognize-frame">API识别当前画面</button>
              <select id="scanMode">
                <option value="auto">自动（本地优先，失败走API）</option>
                <option value="local">仅本地识别</option>
                <option value="api">仅API识别</option>
              </select>
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
            <select id="eGroup"><option value="">不分组</option></select>
            <button data-action="create-entry">保存条目</button>
            <div id="entryMsg" class="muted"></div>
          </div>

          <div class="panel stack">
            <h3 class="flush">分组</h3>
            <div class="row">
              <input id="gName" placeholder="分组名称" />
              <input id="gColor" value="#0f766e" class="narrow-110" />
              <button data-action="create-group">新增</button>
            </div>
            <div id="groupsList" class="stack"></div>
          </div>

          <div id="adminPanel" class="panel stack hidden">
            <h3 class="flush">用户管理（管理员）</h3>
            <div class="row">
              <input id="uName" placeholder="用户名" />
              <input id="uPass" type="password" placeholder="密码 >=12 位，含大小写/数字/符号" />
              <select id="uRole"><option value="user">user</option><option value="admin">admin</option></select>
              <button data-action="create-user">创建</button>
            </div>
            <div id="userMsg" class="muted"></div>
            <table id="usersTable"></table>
            <div class="panel stack mt-8">
              <h4 class="flush">登录风控设置</h4>
              <div class="row">
                <input id="riskMaxReq" type="number" min="3" max="100" placeholder="每分钟请求阈值（默认10）" />
                <input id="riskLockMin" type="number" min="1" max="1440" placeholder="锁定分钟数（默认15）" />
                <button data-action="save-login-policy">保存风控设置</button>
              </div>
              <div id="riskMsg" class="muted"></div>
            </div>
          </div>
        </div>

        <div class="panel stack">
          <h3 class="flush">我的验证码</h3>
          <div id="entries" class="entry-grid"></div>
        </div>
      </div>
    </section>
  </div>

  <script nonce="${nonce}">
    const TURNSTILE_SITE_KEY = ${JSON.stringify(turnstileSiteKey)};
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
        loading: "加载中...",
        systemNotInitialized: "系统尚未初始化，请先创建管理员。",
        pleaseLogin: "请先登录。",
        ready: "已就绪",
        logoutTimeout: "会话因长时间无操作已自动退出。",
        noGroup: "不分组",
        allGroups: "全部分组",
        noGroupsYet: "暂无分组。",
        noEntriesMatched: "当前筛选下没有条目。",
        noIssuer: "无发行方",
        clickGenerate: "点击生成",
        secLeft: "秒后过期",
        copyCode: "复制验证码",
        codeCopied: "验证码已复制",
        copyFailed: "复制失败，请手动复制",
        setGroup: "设为分组",
        removeGroup: "移出分组",
        groupUpdated: "分组已更新",
        generateHotp: "生成 HOTP",
        edit: "编辑",
        delete: "删除",
        deleteEntryConfirm: "确认删除该条目？",
        deleteGroupConfirm: "确认删除分组？分组下条目将变为不分组。",
        deleteUserConfirm: "确认删除用户？",
        backupCopied: "备份 JSON 已复制到剪贴板。",
        encryptedBackupCopied: "加密备份 JSON 已复制到剪贴板。",
        plaintextExportConfirm: "明文导出会包含所有 OTP 密钥。确认继续？",
        setBackupPassphrase: "设置备份口令（至少10位）",
        copyExportJson: "复制导出 JSON",
        copyEncryptedExportJson: "复制加密导出 JSON",
        importedDone: "导入完成",
        encryptedImportedDone: "加密导入完成",
        cameraNotSupported: "当前浏览器不支持 BarcodeDetector。",
        cameraFallback: "已启用兼容扫码模式（jsQR）。",
        cameraStarted: "摄像头扫码已启动...",
        qrDetected: "已识别二维码，URI 已填入表单。",
        qrReadyToSave: "二维码已识别，点击“保存条目”即可添加。",
        cameraDenied: "无法访问摄像头：",
        noQrFound: "图片中未识别到二维码。",
        qrFromImage: "图片二维码识别成功。",
        qrFromApi: "第三方 API 识别成功。",
        apiDetecting: "正在调用第三方 API 识别...",
        apiUnavailable: "第三方 API 识别失败：",
        apiFrameNeedCamera: "请先启动摄像头扫码后再使用该功能。",
        apiNoData: "第三方 API 未识别到二维码内容。",
        scanImageFailed: "图片扫码失败：",
        saved: "已保存",
        userCreated: "用户已创建",
        changePassword: "修改密码",
        resetPassword: "重置密码",
        currentPassword: "当前密码",
        newPassword: "新密码",
        passwordChanged: "密码已修改，请重新登录。",
        passwordReset: "密码已重置",
        passwordResetConfirm: "确认重置该用户的密码？",
        labelPrompt: "标签",
        issuerPrompt: "发行方",
        groupIdPrompt: "分组 ID（留空代表不分组）",
        usersThId: "ID",
        usersThName: "用户名",
        usersThRole: "角色",
        usersThAction: "操作",
        setRole: "设置为",
        riskPolicySaved: "风控设置已保存",
        riskPolicyLoaded: "当前风控：每分钟",
        times: "次",
        lockFor: "，锁定",
        minutes: "分钟",
        otpauthExportDone: "otpauth 文本已下载。",
        otpauthImportDone: "otpauth 导入完成",
        importFileLoaded: "文件内容已加载到导入框。",
        turnstileRequired: "请先完成 Cloudflare Turnstile 验证。",
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
        setBackupPassphrase: "Set backup passphrase (>=10 chars):",
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
        qrFromApi: "Third-party API decoded QR successfully.",
        apiDetecting: "Calling third-party API...",
        apiUnavailable: "Third-party API failed: ",
        apiFrameNeedCamera: "Please start camera scanning first.",
        apiNoData: "Third-party API returned no QR payload.",
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
      if (!currentUser) {
        document.getElementById("state").textContent = t("loading");
      }
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
        navigator.sendBeacon("/api/session/close-soon", blob);
        fetch("/api/session/close-soon", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Session-Close": "web-beforeunload" },
          body: "{}",
          keepalive: true,
          credentials: "same-origin"
        }).catch(function() {});
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
        return '<div class="row group-row">'
          + '<span class="chip"><i class="swatch" data-color="' + esc(g.color || "#0f766e") + '"></i>' + esc(g.name) + '</span>'
          + '<button class="warn" data-action="delete-group" data-id="' + g.id + '">' + esc(t("delete")) + '</button>'
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
          + '<div class="code" id="c-' + e.id + '">' + esc(code) + '</div>'
          + '<div class="muted" id="x-' + e.id + '">' + (ex ? (ex + t("secLeft")) : (e.otp_type === "hotp" ? t("clickGenerate") : "")) + '</div>'
          + '<div class="bar"><i id="p-' + e.id + '" data-progress="' + progress + '"></i></div>'
          + '<div class="row mt-8">'
          + (e.otp_type === "hotp"
            ? '<button data-action="gen-hotp" data-id="' + e.id + '">' + esc(t("generateHotp")) + '</button>'
            : '<button class="ghost" data-action="copy-code" data-id="' + e.id + '">' + esc(t("copyCode")) + '</button>')
          + '<select id="entry-group-' + e.id + '">' + groupOptionsHtml(e.group_id) + '</select>'
          + '<button class="ghost" data-action="set-entry-group" data-id="' + e.id + '">' + esc(t("setGroup")) + '</button>'
          + '<button class="ghost" data-action="remove-entry-group" data-id="' + e.id + '">' + esc(t("removeGroup")) + '</button>'
          + '<button class="ghost" data-action="edit-entry" data-id="' + e.id + '">' + esc(t("edit")) + '</button>'
          + '<button class="warn" data-action="delete-entry" data-id="' + e.id + '">' + esc(t("delete")) + '</button>'
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
      table.innerHTML = "<tr><th>" + esc(t("usersThId")) + "</th><th>" + esc(t("usersThName")) + "</th><th>" + esc(t("usersThRole")) + "</th><th>" + esc(t("usersThAction")) + "</th></tr>";
      (d.users || []).forEach(function(u) {
        const next = u.role === "admin" ? "user" : "admin";
        table.innerHTML += "<tr><td>" + u.id + "</td><td>" + esc(u.username) + "</td><td>" + u.role + "</td><td><button class='ghost' data-action='switch-role' data-id='" + u.id + "' data-role='" + next + "'>" + esc(t("setRole")) + " " + next + "</button> <button class='warn' data-action='delete-user' data-id='" + u.id + "'>" + esc(t("delete")) + "</button></td></tr>";
        table.innerHTML += "<tr><td>" + u.id + "</td><td>" + esc(u.username) + "</td><td>" + u.role + "</td><td><button class='ghost' data-action='switch-role' data-id='" + u.id + "' data-role='" + next + "'>" + esc(t("setRole")) + " " + next + "</button> <button class='ghost' data-action='reset-password' data-id='" + u.id + "'>" + esc(t("resetPassword")) + "</button> <button class='warn' data-action='delete-user' data-id='" + u.id + "'>" + esc(t("delete")) + "</button></td></tr>";
      });
    }

    async function switchRole(id, role) {

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
      await api("/api/users/" + id + "/role", { method: "PATCH", body: JSON.stringify({ role: role }) });
      await refreshUsers();
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
      if (!confirm(t("plaintextExportConfirm"))) return;
      const d = await api("/api/export?confirm=plaintext", {
        headers: { "x-plaintext-export-confirm": "true" }
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
        if (!confirm(t("plaintextExportConfirm"))) return;
        const resp = await fetch("/api/export/otpauth?confirm=plaintext", {
          credentials: "include",
          headers: { "x-plaintext-export-confirm": "true" }
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
        const mode = getScanMode();
        let raw = "";
        if (mode !== "api") {
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
        }
        if (!raw && mode !== "local") {
          msg("scanMsg", t("apiDetecting"));
          raw = await detectQrByThirdPartyApiFromFile(file);
          if (raw) msg("scanMsg", t("qrFromApi"));
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

    function getScanMode() {
      const modeEl = document.getElementById("scanMode");
      const mode = modeEl ? String(modeEl.value || "auto") : "auto";
      return ["auto", "local", "api"].includes(mode) ? mode : "auto";
    }

    async function recognizeCurrentFrameByApi() {
      try {
        const video = document.getElementById("scanVideo");
        if (!video || !scanStream) {
          msg("scanMsg", t("apiFrameNeedCamera"), true);
          return;
        }
        msg("scanMsg", t("apiDetecting"));
        const raw = await detectQrByThirdPartyApiFromVideo(video);
        if (!raw) {
          msg("scanMsg", t("apiNoData"), true);
          return;
        }
        applyScannedOtpUri(raw);
        msg("scanMsg", t("qrFromApi"));
      } catch (e) {
        msg("scanMsg", t("apiUnavailable") + e.message, true);
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

    async function detectQrByThirdPartyApiFromFile(file) {
      const blob = file instanceof Blob ? file : new Blob([file], { type: "image/png" });
      return detectQrByThirdPartyApiFromBlob(blob);
    }

    async function detectQrByThirdPartyApiFromVideo(video) {
      const w = video.videoWidth || 0;
      const h = video.videoHeight || 0;
      if (!w || !h) return "";
      const canvas = document.createElement("canvas");
      canvas.width = w;
      canvas.height = h;
      const ctx = canvas.getContext("2d", { willReadFrequently: true });
      ctx.drawImage(video, 0, 0, w, h);
      const blob = await new Promise(function(resolve) {
        canvas.toBlob(function(b) { resolve(b); }, "image/jpeg", 0.92);
      });
      if (!blob) return "";
      return detectQrByThirdPartyApiFromBlob(blob);
    }

    async function detectQrByThirdPartyApiFromBlob(blob) {
      const form = new FormData();
      form.append("file", blob, "qr-image.jpg");
      const resp = await fetch("https://api.qrserver.com/v1/read-qr-code/", {
        method: "POST",
        body: form
      });
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      const data = await resp.json();
      const item = Array.isArray(data) && data[0] ? data[0] : null;
      const symbol = item && Array.isArray(item.symbol) && item.symbol[0] ? item.symbol[0] : null;
      const raw = symbol && typeof symbol.data === "string" ? symbol.data.trim() : "";
      return raw || "";
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
          "recognize-frame": recognizeCurrentFrameByApi,
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

