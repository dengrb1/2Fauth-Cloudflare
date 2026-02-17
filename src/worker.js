const SESSION_COOKIE = "__Host-session";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days
const MOBILE_ACCESS_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days
const MOBILE_REFRESH_TTL_SECONDS = 60 * 60 * 24 * 90; // 90 days
const CLOSE_LOGOUT_GRACE_SECONDS = 12;
// Keep hashing strong while avoiding CPU limit spikes on Workers.
const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_HASH = "SHA-256";
const DEFAULT_RISK_MAX_REQUESTS_PER_MINUTE = 10;
const DEFAULT_RISK_LOCK_MINUTES = 15;
const TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

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

      if (method === "GET" && path === "/") return html(appHtml(env));

      if (method === "GET" && path === "/api/status") {
        const initialized = await hasAnyUser(env);
        return json({ initialized });
      }

      if (method === "POST" && path === "/api/bootstrap") {
        return handleBootstrap(request, env);
      }
      if (method === "POST" && path === "/api/login") {
        return handleLogin(request, env);
      }
      if (method === "POST" && path === "/api/mobile/login") {
        return handleMobileLogin(request, env);
      }
      if (method === "POST" && path === "/api/mobile/refresh") {
        return handleMobileRefresh(request, env);
      }
      if (method === "POST" && path === "/api/mobile/logout") {
        return handleMobileLogout(request, env);
      }
      if (method === "POST" && path === "/api/logout") {
        return handleLogout(request, env);
      }
      if (method === "POST" && path === "/api/session/close-soon") {
        return handleCloseSoon(request, env);
      }
      if (method === "GET" && path === "/api/me") {
        return handleMe(request, env);
      }

      if (method === "GET" && path === "/api/entries") {
        return handleListEntries(request, env);
      }
      if (method === "POST" && path === "/api/entries") {
        return handleCreateEntry(request, env);
      }
      if (method === "PATCH" && path.match(/^\/api\/entries\/\d+$/)) {
        return handleUpdateEntry(request, env);
      }
      if (method === "GET" && path.match(/^\/api\/entries\/\d+\/code$/)) {
        return handleEntryCode(request, env);
      }
      if (method === "POST" && path.match(/^\/api\/entries\/\d+\/hotp$/)) {
        return handleConsumeHotp(request, env);
      }
      if (method === "DELETE" && path.match(/^\/api\/entries\/\d+$/)) {
        return handleDeleteEntry(request, env);
      }

      if (method === "GET" && path === "/api/groups") {
        return handleListGroups(request, env);
      }
      if (method === "POST" && path === "/api/groups") {
        return handleCreateGroup(request, env);
      }
      if (method === "DELETE" && path.match(/^\/api\/groups\/\d+$/)) {
        return handleDeleteGroup(request, env);
      }

      if (method === "GET" && path === "/api/export") {
        return handleExportData(request, env);
      }
      if (method === "GET" && path === "/api/export/otpauth") {
        return handleExportOtpAuth(request, env);
      }
      if (method === "POST" && path === "/api/export/encrypted") {
        return handleExportDataEncrypted(request, env);
      }
      if (method === "POST" && path === "/api/import") {
        return handleImportData(request, env);
      }
      if (method === "POST" && path === "/api/import/otpauth") {
        return handleImportOtpAuth(request, env);
      }
      if (method === "POST" && path === "/api/import/encrypted") {
        return handleImportDataEncrypted(request, env);
      }

      if (method === "GET" && path === "/api/users") {
        return handleListUsers(request, env);
      }
      if (method === "POST" && path === "/api/users") {
        return handleCreateUser(request, env);
      }
      if (method === "PATCH" && path.match(/^\/api\/users\/\d+\/role$/)) {
        return handleUpdateUserRole(request, env);
      }
      if (method === "DELETE" && path.match(/^\/api\/users\/\d+$/)) {
        return handleDeleteUser(request, env);
      }
      if (method === "GET" && path === "/api/security/login-policy") {
        return handleGetLoginPolicy(request, env);
      }
      if (method === "PATCH" && path === "/api/security/login-policy") {
        return handleUpdateLoginPolicy(request, env);
      }
      if (method === "GET" && path === "/favicon.ico") {
        return new Response(null, { status: 204 });
      }
      if (method === "GET" && !path.startsWith("/api/")) {
        return html(appHtml(env));
      }

      return json({ error: "Not found" }, 404);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Internal error";
      return json({ error: "Internal Server Error", detail: message }, 500);
    }
  },
};

async function handleBootstrap(request, env) {
  const initialized = await hasAnyUser(env);
  if (initialized) return json({ error: "Already initialized" }, 400);

  const body = await parseJson(request);
  const username = normalizeUsername(body.username);
  const password = String(body.password || "");
  if (!username || !validPassword(password)) {
    return json({ error: "Invalid username or password (min 10 chars)" }, 400);
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
  if (env.TURNSTILE_SECRET_KEY) {
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

  const ok = await verifyPassword(password, row.password_salt, row.password_hash);
  if (!ok) return json({ error: "Invalid credentials" }, 401);

  const clientType = String(body.clientType || "").trim().toLowerCase();
  if (clientType === "android") {
    const mobileSession = await createMobileSession(env, row.id, "android");
    return json({
      ok: true,
      user: { id: row.id, username: row.username, role: row.role },
      accessToken: mobileSession.accessToken,
      refreshToken: mobileSession.refreshToken,
      expiresIn: mobileSession.expiresIn,
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
  body.clientType = "android";
  return handleLogin(withJsonBody(request, body), env);
}

async function handleMobileRefresh(request, env) {
  const body = await parseJson(request);
  const refreshToken = String(body.refreshToken || "").trim();
  if (!refreshToken) return json({ error: "refreshToken is required" }, 400);

  const refreshHash = await hashSessionToken(refreshToken, env);
  const now = nowIso();
  const row = await env.DB.prepare(
    "SELECT s.id, s.user_id, u.username, u.role FROM api_sessions s JOIN users u ON u.id = s.user_id WHERE s.refresh_hash = ? AND s.refresh_expires_at > ?"
  )
    .bind(refreshHash, now)
    .first();
  if (!row) return json({ error: "Invalid refresh token" }, 401);

  const accessToken = randomHex(32);
  const newRefreshToken = randomHex(32);
  const accessHash = await hashSessionToken(accessToken, env);
  const newRefreshHash = await hashSessionToken(newRefreshToken, env);
  const nowDate = new Date();
  const expiresAt = new Date(nowDate.getTime() + MOBILE_ACCESS_TTL_SECONDS * 1000).toISOString();
  const refreshExpiresAt = new Date(nowDate.getTime() + MOBILE_REFRESH_TTL_SECONDS * 1000).toISOString();

  await env.DB.prepare(
    "UPDATE api_sessions SET token_hash = ?, refresh_hash = ?, expires_at = ?, refresh_expires_at = ?, last_used_at = ? WHERE id = ?"
  )
    .bind(accessHash, newRefreshHash, expiresAt, refreshExpiresAt, nowDate.toISOString(), row.id)
    .run();

  return json({
    ok: true,
    user: { id: row.user_id, username: row.username, role: row.role },
    accessToken,
    refreshToken: newRefreshToken,
    expiresIn: MOBILE_ACCESS_TTL_SECONDS,
  });
}

async function handleMobileLogout(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  if (auth.sessionKind !== "mobile") return json({ error: "Mobile bearer token required" }, 400);
  await env.DB.prepare("DELETE FROM api_sessions WHERE id = ?").bind(auth.sessionId).run();
  return json({ ok: true });
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
  const tokenHash = await hashSessionToken(token, env);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + CLOSE_LOGOUT_GRACE_SECONDS * 1000).toISOString();
  await env.DB.prepare("UPDATE sessions SET expires_at = ? WHERE token_hash = ?").bind(expiresAt, tokenHash).run();
  return json({ ok: true });
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
  const algorithm = normalizeAlgorithm(payload.algorithm || "SHA-1");
  const otpType = payload.otpType === "hotp" ? "hotp" : "totp";
  const hotpCounter = Number(payload.hotpCounter || 0);
  const groupId = payload.groupId ? Number(payload.groupId) : null;
  const requestedUserId = Number(payload.userId || auth.user.id);
  const userId = auth.user.role === "admin" ? requestedUserId : auth.user.id;

  if (!label || !secret) return json({ error: "label and secret are required" }, 400);
  if (![6, 7, 8].includes(digits)) return json({ error: "digits must be 6/7/8" }, 400);
  if (otpType === "totp" && (!Number.isFinite(period) || period < 15 || period > 120)) return json({ error: "period must be between 15 and 120" }, 400);
  if (!algorithm) return json({ error: "algorithm must be SHA-1/SHA-256/SHA-512" }, 400);
  if (otpType === "hotp" && (!Number.isFinite(hotpCounter) || hotpCounter < 0)) return json({ error: "hotpCounter must be >= 0" }, 400);

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
    if (auth.user.role !== "admin" && group.user_id !== auth.user.id) return json({ error: "Forbidden group" }, 403);
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
  const id = Number(new URL(request.url).pathname.split("/")[3]);
  if (!Number.isFinite(id)) return json({ error: "Invalid id" }, 400);

  const existing = await env.DB.prepare("SELECT * FROM totp_entries WHERE id = ?").bind(id).first();
  if (!existing) return json({ error: "Entry not found" }, 404);
  if (auth.user.role !== "admin" && existing.user_id !== auth.user.id) return json({ error: "Forbidden" }, 403);

  const body = await parseJson(request);
  const label = body.label !== undefined ? String(body.label).trim() : existing.label;
  const issuer = body.issuer !== undefined ? String(body.issuer).trim() : existing.issuer;
  const digits = body.digits !== undefined ? Number(body.digits) : existing.digits;
  const period = body.period !== undefined ? Number(body.period) : existing.period;
  const algorithm = body.algorithm ? normalizeAlgorithm(body.algorithm) : existing.algorithm;
  const otpType = body.otpType ? (body.otpType === "hotp" ? "hotp" : "totp") : (existing.otp_type || "totp");
  const hotpCounter = body.hotpCounter !== undefined ? Number(body.hotpCounter) : (existing.hotp_counter || 0);
  const groupId = body.groupId === null ? null : body.groupId !== undefined ? Number(body.groupId) : existing.group_id;

  if (!label) return json({ error: "label is required" }, 400);
  if (![6, 7, 8].includes(digits)) return json({ error: "digits must be 6/7/8" }, 400);
  if (otpType === "totp" && (!Number.isFinite(period) || period < 15 || period > 120)) return json({ error: "period must be between 15 and 120" }, 400);
  if (!algorithm) return json({ error: "algorithm must be SHA-1/SHA-256/SHA-512" }, 400);
  if (otpType === "hotp" && (!Number.isFinite(hotpCounter) || hotpCounter < 0)) return json({ error: "hotpCounter must be >= 0" }, 400);

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
    if (auth.user.role !== "admin" && group.user_id !== auth.user.id) return json({ error: "Forbidden group" }, 403);
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
  const id = Number(new URL(request.url).pathname.split("/")[3]);
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
  const step = Math.floor(nowSec / row.period);
  const code = await generateTotp(secret, row.period, row.digits, row.algorithm, step);
  const expiresIn = row.period - (nowSec % row.period);
  return json({ code, expiresIn, now: nowSec, otpType: "totp" });
}

async function handleConsumeHotp(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  const id = Number(new URL(request.url).pathname.split("/")[3]);
  if (!Number.isFinite(id)) return json({ error: "Invalid id" }, 400);

  const row = await env.DB.prepare("SELECT * FROM totp_entries WHERE id = ?").bind(id).first();
  if (!row) return json({ error: "Entry not found" }, 404);
  if (auth.user.role !== "admin" && row.user_id !== auth.user.id) return json({ error: "Forbidden" }, 403);
  if ((row.otp_type || "totp") !== "hotp") return json({ error: "This entry is not HOTP" }, 400);

  const secret = await decryptText(row.secret_enc, env);
  const counter = Number(row.hotp_counter || 0);
  const code = await generateHotp(secret, row.digits, row.algorithm, counter);
  await env.DB.prepare("UPDATE totp_entries SET hotp_counter = ? WHERE id = ?").bind(counter + 1, id).run();
  return json({ code, counter, nextCounter: counter + 1, otpType: "hotp" });
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
  const requestedUserId = Number(body.userId || auth.user.id);
  const userId = auth.user.role === "admin" ? requestedUserId : auth.user.id;
  if (!name) return json({ error: "name is required" }, 400);

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
  const id = Number(new URL(request.url).pathname.split("/")[3]);
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

  const requestedUserId = Number(body.userId || auth.user.id);
  const userId = auth.user.role === "admin" ? requestedUserId : auth.user.id;
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
      const digits = [6, 7, 8].includes(Number(data.digits)) ? Number(data.digits) : 6;
      const period = Number(data.period) > 0 ? Number(data.period) : 30;
      const algorithm = normalizeAlgorithm(data.algorithm || "SHA-1") || "SHA-1";
      const otpType = data.otpType === "hotp" ? "hotp" : "totp";
      const hotpCounter = Number(data.hotpCounter) >= 0 ? Number(data.hotpCounter) : 0;
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

  const groupMap = new Map();
  for (const g of groups) {
    const name = String(g.name || "").trim();
    if (!name) continue;
    const userId = auth.user.role === "admin" ? Number(g.user_id || auth.user.id) : auth.user.id;
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
    const userId = auth.user.role === "admin" ? Number(e.user_id || auth.user.id) : auth.user.id;
    const groupId = e.group_id !== undefined && e.group_id !== null ? groupMap.get(String(e.group_id)) || null : null;
    const otpType = e.otp_type === "hotp" ? "hotp" : "totp";
    const algorithm = normalizeAlgorithm(e.algorithm || "SHA-1") || "SHA-1";
    const digits = [6, 7, 8].includes(Number(e.digits)) ? Number(e.digits) : 6;
    const period = Number(e.period) > 0 ? Number(e.period) : 30;
    const hotpCounter = Number(e.hotp_counter) >= 0 ? Number(e.hotp_counter) : 0;
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
  const id = Number(new URL(request.url).pathname.split("/")[3]);
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
    return json({ error: "Invalid username or password (min 10 chars)" }, 400);
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

async function handleUpdateUserRole(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  if (auth.user.role !== "admin") return json({ error: "Forbidden" }, 403);

  const id = Number(new URL(request.url).pathname.split("/")[3]);
  if (!Number.isFinite(id)) return json({ error: "Invalid id" }, 400);
  const body = await parseJson(request);
  const role = body.role === "admin" ? "admin" : body.role === "user" ? "user" : null;
  if (!role) return json({ error: "role must be admin or user" }, 400);
  if (id === auth.user.id && role !== "admin") {
    return json({ error: "Cannot demote yourself" }, 400);
  }

  await env.DB.prepare("UPDATE users SET role = ? WHERE id = ?").bind(role, id).run();
  return json({ ok: true });
}

async function handleDeleteUser(request, env) {
  const auth = await requireAuth(request, env);
  if (!auth.ok) return auth.response;
  if (auth.user.role !== "admin") return json({ error: "Forbidden" }, 403);

  const id = Number(new URL(request.url).pathname.split("/")[3]);
  if (!Number.isFinite(id)) return json({ error: "Invalid id" }, 400);
  if (id === auth.user.id) return json({ error: "Cannot delete yourself" }, 400);

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

async function getLoginPolicy(env) {
  const rows = await env.DB.prepare(
    "SELECT key, value FROM app_settings WHERE key IN ('risk_max_requests_per_minute', 'risk_lock_minutes')"
  ).all();
  const map = new Map((rows.results || []).map((r) => [r.key, r.value]));
  const maxRequestsPerMinute = Number(map.get("risk_max_requests_per_minute") || DEFAULT_RISK_MAX_REQUESTS_PER_MINUTE);
  const lockMinutes = Number(map.get("risk_lock_minutes") || DEFAULT_RISK_LOCK_MINUTES);
  return {
    maxRequestsPerMinute: Number.isFinite(maxRequestsPerMinute) ? maxRequestsPerMinute : DEFAULT_RISK_MAX_REQUESTS_PER_MINUTE,
    lockMinutes: Number.isFinite(lockMinutes) ? lockMinutes : DEFAULT_RISK_LOCK_MINUTES,
  };
}

async function applyLoginRiskControl(request, env, username) {
  const nowSec = Math.floor(Date.now() / 1000);
  const policy = await getLoginPolicy(env);
  const ip = String(request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || "unknown")
    .split(",")[0]
    .trim();
  const riskKey = await sha256Base64(`${username || "__empty__"}|${ip}`);
  const row = await env.DB.prepare(
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
  let requestCount = 1;
  let lockUntil = 0;
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

async function verifyTurnstileToken(token, remoteip, env) {
  const secretKey = String(env.TURNSTILE_SECRET_KEY || env.TURNSTILE_KEY || "");
  if (!secretKey) return { ok: true };
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
    const row = await env.DB.prepare(
      "SELECT s.id AS session_id, u.id, u.username, u.role FROM api_sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ? AND s.refresh_expires_at > ?"
    )
      .bind(tokenHash, now, now)
      .first();
    if (row) {
      await env.DB.prepare("UPDATE api_sessions SET last_used_at = ? WHERE id = ?").bind(now, row.session_id).run();
      return {
        user: { id: row.id, username: row.username, role: row.role },
        sessionKind: "mobile",
        sessionId: row.session_id,
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
  await env.DB.prepare(
    "INSERT INTO sessions (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)"
  )
    .bind(userId, tokenHash, expiresAt, now.toISOString())
    .run();

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
  await env.DB.prepare("DELETE FROM api_sessions WHERE refresh_expires_at <= ?").bind(now).run();
}

async function createMobileSession(env, userId, clientType) {
  const accessToken = randomHex(32);
  const refreshToken = randomHex(32);
  const tokenHash = await hashSessionToken(accessToken, env);
  const refreshHash = await hashSessionToken(refreshToken, env);
  const now = new Date();
  const createdAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + MOBILE_ACCESS_TTL_SECONDS * 1000).toISOString();
  const refreshExpiresAt = new Date(now.getTime() + MOBILE_REFRESH_TTL_SECONDS * 1000).toISOString();

  await env.DB.prepare(
    "INSERT INTO api_sessions (user_id, token_hash, refresh_hash, expires_at, refresh_expires_at, created_at, last_used_at, client_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  )
    .bind(userId, tokenHash, refreshHash, expiresAt, refreshExpiresAt, createdAt, createdAt, clientType)
    .run();

  return { accessToken, refreshToken, expiresIn: MOBILE_ACCESS_TTL_SECONDS };
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

async function hashPassword(password, saltB64) {
  const salt = saltB64 ? b64ToBytes(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", enc(String(password)), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: PBKDF2_HASH, iterations: PBKDF2_ITERATIONS, salt },
    key,
    256
  );
  return { hashB64: bytesToB64(new Uint8Array(bits)), saltB64: bytesToB64(salt) };
}

async function verifyPassword(password, saltB64, expectedHashB64) {
  const { hashB64 } = await hashPassword(password, saltB64);
  return constantTimeEqual(b64ToBytes(hashB64), b64ToBytes(expectedHashB64));
}

let keyCacheRaw = null;
let keyCachePromise = null;

async function getEncryptionKey(env) {
  if (keyCacheRaw !== env.ENCRYPTION_KEY) {
    keyCacheRaw = env.ENCRYPTION_KEY;
    keyCachePromise = crypto.subtle.importKey("raw", b64ToBytes(env.ENCRYPTION_KEY), "AES-GCM", false, [
      "encrypt",
      "decrypt",
    ]);
  }
  return keyCachePromise;
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
    const algorithm = normalizeAlgorithm(url.searchParams.get("algorithm") || "SHA-1");
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
  params.set("algorithm", String(entry.algorithm || "SHA-1").replace("-", ""));
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
  const algo = normalizeAlgorithm(algorithm) || "SHA-1";
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

function normalizeUsername(v) {
  const out = String(v || "").trim().toLowerCase();
  return /^[a-z0-9_.-]{3,40}$/.test(out) ? out : "";
}

function validPassword(p) {
  return typeof p === "string" && p.length >= 10;
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
  return new Request(request.url, {
    method: request.method,
    headers: request.headers,
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

function randomHex(byteLen) {
  const arr = crypto.getRandomValues(new Uint8Array(byteLen));
  return [...arr].map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function parseJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
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

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...headers,
    },
  });
}

function html(markup) {
  return new Response(markup, {
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  });
}

function appHtml(env) {
  const turnstileSiteKey = String((env && env.TURNSTILE_SITE_KEY) || "");
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>2FAuth 验证器</title>
  <style>
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
        <select id="langSelect" onchange="changeLang(this.value)">
          <option value="zh-CN">简体中文</option>
          <option value="en-US">English</option>
        </select>
        <select id="autoLogoutSelect" onchange="changeAutoLogout(this.value)">
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
      <h3 style="margin:0;">初始化管理员</h3>
      <div class="row">
        <input id="bsUser" placeholder="管理员用户名" />
        <input id="bsPass" type="password" placeholder="密码（至少10位）" />
        <button type="button" onclick="bootstrap(event)">初始化</button>
      </div>
      <div id="bsMsg" class="muted"></div>
    </section>

    <section id="login" class="panel stack">
      <h3 style="margin:0;">登录</h3>
      <div class="row">
        <input id="loginUser" placeholder="用户名" />
        <input id="loginPass" type="password" placeholder="密码" />
        <button type="button" onclick="login(event)">登录</button>
      </div>
      <div id="turnstileBox" class="row" style="display:none;"></div>
      <div id="loginMsg" class="muted"></div>
    </section>

    <section id="app">
      <div class="panel row" style="justify-content:space-between;align-items:center;">
        <div class="row">
          <input id="search" placeholder="搜索标签/发行方..." oninput="renderEntries()" />
          <select id="groupFilter" onchange="renderEntries()"><option value="">全部分组</option></select>
          <button class="ghost" onclick="refreshAll()">刷新</button>
        </div>
        <div class="row">
          <button class="ghost" onclick="exportData()">导出</button>
          <button class="ghost" onclick="exportOtpAuthTxt()">导出 otpauth 文本</button>
          <button class="ghost" onclick="exportDataEncrypted()">加密导出</button>
          <button class="ghost" onclick="toggleImport()">导入</button>
          <button type="button" class="warn" onclick="logout(event)">退出登录</button>
        </div>
      </div>

      <div id="importPanel" class="panel stack" style="display:none;">
        <h3 style="margin:0;">导入备份 JSON</h3>
        <textarea id="importText" placeholder='粘贴 /api/export 的 JSON'></textarea>
        <div class="row">
          <input id="importFile" type="file" accept=".json,.txt,text/plain,application/json" onchange="loadImportFile(event)" />
          <input id="importPassphrase" type="password" placeholder="口令（用于加密备份）" />
          <button onclick="importData()">执行导入</button>
          <button class="ghost" onclick="importOtpAuthText()">导入 otpauth 文本</button>
          <button class="ghost" onclick="importDataEncrypted()">执行加密导入</button>
        </div>
        <div id="importMsg" class="muted"></div>
      </div>

      <div class="grid">
        <div class="stack">
          <div class="panel stack">
            <h3 style="margin:0;">新建条目</h3>
            <input id="eLabel" placeholder="标签（如 GitHub）" />
            <input id="eIssuer" placeholder="发行方（可选）" />
            <input id="eSecret" placeholder="Base32 密钥" />
            <input id="eUri" placeholder="或 otpauth://totp/... / otpauth://hotp/..." />
            <div class="row">
              <button class="ghost" onclick="startScan()">摄像头扫码</button>
              <button class="ghost" onclick="stopScan()">停止扫码</button>
              <button class="ghost" onclick="recognizeCurrentFrameByApi()">API识别当前画面</button>
              <select id="scanMode">
                <option value="auto">自动（本地优先，失败走API）</option>
                <option value="local">仅本地识别</option>
                <option value="api">仅API识别</option>
              </select>
              <input id="qrImageFile" type="file" accept="image/*" onchange="scanImageFile(event)" />
            </div>
            <video id="scanVideo" autoplay playsinline style="display:none;"></video>
            <div id="scanMsg" class="muted"></div>
            <div class="row">
              <select id="eOtpType"><option value="totp">TOTP</option><option value="hotp">HOTP</option></select>
              <select id="eAlgo"><option>SHA-1</option><option>SHA-256</option><option>SHA-512</option></select>
              <input id="eDigits" value="6" style="width:74px;" />
              <input id="ePeriod" value="30" style="width:74px;" />
              <input id="eCounter" value="0" style="width:86px;" />
            </div>
            <select id="eGroup"><option value="">不分组</option></select>
            <button onclick="createEntry()">保存条目</button>
            <div id="entryMsg" class="muted"></div>
          </div>

          <div class="panel stack">
            <h3 style="margin:0;">分组</h3>
            <div class="row">
              <input id="gName" placeholder="分组名称" />
              <input id="gColor" value="#0f766e" style="width:110px;" />
              <button onclick="createGroup()">新增</button>
            </div>
            <div id="groupsList" class="stack"></div>
          </div>

          <div id="adminPanel" class="panel stack" style="display:none;">
            <h3 style="margin:0;">用户管理（管理员）</h3>
            <div class="row">
              <input id="uName" placeholder="用户名" />
              <input id="uPass" type="password" placeholder="密码 >=10 位" />
              <select id="uRole"><option value="user">user</option><option value="admin">admin</option></select>
              <button onclick="createUser()">创建</button>
            </div>
            <div id="userMsg" class="muted"></div>
            <table id="usersTable"></table>
            <div class="panel stack" style="margin-top:8px;">
              <h4 style="margin:0;">登录风控设置</h4>
              <div class="row">
                <input id="riskMaxReq" type="number" min="3" max="100" placeholder="每分钟请求阈值（默认10）" />
                <input id="riskLockMin" type="number" min="1" max="1440" placeholder="锁定分钟数（默认15）" />
                <button onclick="saveLoginPolicy()">保存风控设置</button>
              </div>
              <div id="riskMsg" class="muted"></div>
            </div>
          </div>
        </div>

        <div class="panel stack">
          <h3 style="margin:0;">我的验证码</h3>
          <div id="entries" class="entry-grid"></div>
        </div>
      </div>
    </section>
  </div>

  <script>
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
        refreshCode: "刷新验证码",
        generateHotp: "生成 HOTP",
        edit: "编辑",
        delete: "删除",
        deleteEntryConfirm: "确认删除该条目？",
        deleteGroupConfirm: "确认删除分组？分组下条目将变为不分组。",
        deleteUserConfirm: "确认删除用户？",
        backupCopied: "备份 JSON 已复制到剪贴板。",
        encryptedBackupCopied: "加密备份 JSON 已复制到剪贴板。",
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
        manualRefreshed: "已手动刷新",
        maybeUnchanged: "（当前周期内验证码可能不变）"
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
        refreshCode: "Refresh Code",
        generateHotp: "Generate HOTP",
        edit: "Edit",
        delete: "Delete",
        deleteEntryConfirm: "Delete this entry?",
        deleteGroupConfirm: "Delete group? Entries will be ungrouped.",
        deleteUserConfirm: "Delete user?",
        backupCopied: "Backup JSON copied to clipboard.",
        encryptedBackupCopied: "Encrypted backup JSON copied to clipboard.",
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
        manualRefreshed: "Manually refreshed",
        maybeUnchanged: "(code may remain unchanged within current period)"
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
      } catch {}
    }

    function initTurnstile() {
      if (!TURNSTILE_SITE_KEY) return;
      const box = document.getElementById("turnstileBox");
      if (!box) return;
      box.style.display = "block";

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
          document.getElementById("bootstrap").style.display = "block";
          return;
        }
        const me = await api("/api/me").catch(() => null);
        if (!me) {
          document.getElementById("state").textContent = t("pleaseLogin");
          document.getElementById("login").style.display = "block";
          initTurnstile();
          return;
        }
        currentUser = me.user;
        document.getElementById("state").textContent = t("ready");
        document.getElementById("whoami").textContent = me.user.username + " (" + me.user.role + ")";
        document.getElementById("app").style.display = "block";
        bindActivityEvents();
        scheduleAutoLogout();
        if (me.user.role === "admin") document.getElementById("adminPanel").style.display = "block";
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
        return '<div class="row" style="justify-content:space-between;align-items:center;border:1px solid var(--line);border-radius:10px;padding:7px;">'
          + '<span class="chip"><i style="display:inline-block;width:8px;height:8px;border-radius:999px;background:' + esc(g.color || "#0f766e") + ';"></i>' + esc(g.name) + '</span>'
          + '<button class="warn" onclick="deleteGroup(' + g.id + ')">' + esc(t("delete")) + '</button>'
          + '</div>';
      }).join("");
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
        const group = e.group_name ? '<span class="chip"><i style="display:inline-block;width:8px;height:8px;border-radius:999px;background:' + esc(e.group_color || "#0f766e") + ';"></i>' + esc(e.group_name) + '</span>' : '';
        const otpTag = '<span class="chip">' + esc((e.otp_type || "totp").toUpperCase()) + '</span>';
        const counter = (e.otp_type === "hotp") ? ('<span class="chip">counter ' + Number(e.hotp_counter || 0) + '</span>') : '';
        return '<article class="entry">'
          + '<div class="title">' + esc(e.label) + '</div>'
          + '<div class="meta">' + esc(e.issuer || t("noIssuer")) + '</div>'
          + '<div class="row">' + otpTag + group + counter + '</div>'
          + '<div class="code" id="c-' + e.id + '">' + esc(code) + '</div>'
          + '<div class="muted" id="x-' + e.id + '">' + (ex ? (ex + t("secLeft")) : (e.otp_type === "hotp" ? t("clickGenerate") : "")) + '</div>'
          + '<div class="bar"><i id="p-' + e.id + '" style="width:' + progress + '%;"></i></div>'
          + '<div class="row" style="margin-top:8px;">'
          + (e.otp_type === "hotp"
            ? '<button onclick="genHotp(' + e.id + ')">' + esc(t("generateHotp")) + '</button>'
            : '<button class="ghost" onclick="refreshCode(' + e.id + ', false, true)">' + esc(t("refreshCode")) + '</button>')
          + '<button class="ghost" onclick="editEntry(' + e.id + ')">' + esc(t("edit")) + '</button>'
          + '<button class="warn" onclick="deleteEntry(' + e.id + ')">' + esc(t("delete")) + '</button>'
          + '</div></article>';
      }).join("");
    }

    async function refreshVisibleCodes() {
      const current = entries.filter(function(e) { return e.otp_type !== "hotp"; });
      await Promise.all(current.map(function(e) { return refreshCode(e.id, true); }));
    }

    async function refreshCode(id, silent, manual) {
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
        if (exEl) {
          if (manual) {
            exEl.textContent = t("manualRefreshed") + t("maybeUnchanged") + " " + r.expiresIn + t("secLeft");
          } else {
            exEl.textContent = r.expiresIn + t("secLeft");
          }
        }
        if (pEl) pEl.style.width = progress + "%";
      } catch (e) {
        if (!silent) alert(e.message);
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
        table.innerHTML += "<tr><td>" + u.id + "</td><td>" + esc(u.username) + "</td><td>" + u.role + "</td><td><button class='ghost' onclick='switchRole(" + u.id + ",\\\"" + next + "\\\")'>" + esc(t("setRole")) + " " + next + "</button> <button class='warn' onclick='deleteUser(" + u.id + ")'>" + esc(t("delete")) + "</button></td></tr>";
      });
    }

    async function switchRole(id, role) {
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
      el.style.display = el.style.display === "none" ? "block" : "none";
    }

    async function exportData() {
      const d = await api("/api/export");
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
        const resp = await fetch("/api/export/otpauth", { credentials: "include" });
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
        video.style.display = "block";
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
        video.style.display = "none";
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

    setInterval(function() {
      entries.forEach(function(e) {
        if (e.otp_type !== "hotp") refreshCode(e.id, true);
      });
    }, 5000);

    init();
  </script>
</body>
</html>`;
}



