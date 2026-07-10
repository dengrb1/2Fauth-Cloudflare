# API Contract

This Worker keeps the existing Web UI routes and exposes stable `/api/v1` bearer-token routes for native Android apps and browser extensions.

## Client Authentication

Requests must use exactly one authentication mechanism. Do not send the Web UI `__Host-session` cookie together with an `Authorization: Bearer ...` header; mixed authentication requests are rejected.

### `POST /api/bootstrap`

Creates the first admin account only when the database has no users.

Required header:

```http
X-Bootstrap-Token: <BOOTSTRAP_TOKEN>
```

`BOOTSTRAP_TOKEN` must be configured with `wrangler secret put BOOTSTRAP_TOKEN`. If the token is missing or incorrect, an empty deployment will not initialize.

### `GET /api/v1/capabilities`

Returns runtime API metadata for Android apps and browser extensions before login.

Response:

```json
{
  "apiVersion": "v1",
  "compatibleClients": ["android", "browser_extension"],
  "auth": {
    "scheme": "Bearer",
    "accessTokenExpiresIn": 604800,
    "refreshTokenExpiresIn": 7776000,
    "refreshTokenRotation": true,
    "turnstileRequired": false,
    "turnstileSiteKey": ""
  },
  "limits": {
    "extensionBatchMaxIds": 100
  },
  "cors": {
    "exactOriginAllowlist": true,
    "configured": true
  },
  "endpoints": {
    "login": "/api/v1/auth/login",
    "refresh": "/api/v1/auth/refresh",
    "logout": "/api/v1/auth/logout",
    "me": "/api/v1/me",
    "changePassword": "/api/v1/me/password",
    "entries": "/api/v1/entries",
    "groups": "/api/v1/groups",
    "codesBatch": "/api/v1/codes/batch",
    "importOtpAuth": "/api/v1/import/otpauth",
    "exportEncrypted": "/api/v1/export/encrypted",
    "importEncrypted": "/api/v1/import/encrypted"
  }
}
```

`auth.turnstileSiteKey` is sourced from `TURNSTILE_SITE_KEY`; it is an empty string when Turnstile is not configured.

### `POST /api/v1/auth/login`

Request:

```json
{
  "username": "alice",
  "password": "Long-password-123",
  "clientType": "android"
}
```

Passwords created through bootstrap or user management must be 12 to 256 characters and include uppercase, lowercase, number, and symbol.

For browser extensions, use `"clientType": "browser_extension"` and optionally include:

```json
{
  "deviceName": "edge",
  "clientVersion": "1.0.0"
}
```

Response:

```json
{
  "ok": true,
  "user": { "id": 1, "username": "alice", "role": "user" },
  "accessToken": "...",
  "refreshToken": "...",
  "expiresIn": 604800,
  "refreshExpiresIn": 7776000,
  "sessionId": 1
}
```

### `POST /api/v1/auth/refresh`

Request:

```json
{
  "refreshToken": "...",
  "clientType": "android"
}
```

`clientType` accepts `android` or `browser_extension`. Refresh tokens are rotated on every successful refresh.

### `POST /api/v1/auth/logout`

Requires `Authorization: Bearer <accessToken>`.

## Bearer Routes

All routes below require `Authorization: Bearer <accessToken>`.

- `GET /api/v1/me`
- `PATCH /api/v1/me/password`
- `GET /api/v1/entries`
- `POST /api/v1/entries`
- `PATCH /api/v1/entries/:id`
- `GET /api/v1/entries/:id/code`
- `POST /api/v1/entries/:id/verify`
- `POST /api/v1/entries/:id/hotp`
- `DELETE /api/v1/entries/:id`
- `GET /api/v1/groups`
- `POST /api/v1/groups`
- `PATCH /api/v1/groups/:id`
- `DELETE /api/v1/groups/:id`
- `POST /api/v1/codes/batch`
- `POST /api/v1/import/otpauth`
- `POST /api/v1/export/encrypted`
- `POST /api/v1/import/encrypted`

`PATCH /api/v1/groups/:id` accepts `name` and/or `color` only:

```json
{
  "name": "Work",
  "color": "#0f766e"
}
```

`name` is trimmed, must be non-empty, and must be at most 60 characters. `color` must be `#RRGGBB`. Non-admin users can update only their own groups; admins can update any group. Duplicate group names for the same user return `409`.

Batch code request:

```json
{
  "entryIds": [1, 2, 3]
}
```

Batch code response:

```json
{
  "serverTime": 1730000000,
  "items": [
    { "id": 1, "otpType": "totp", "code": "123456", "expiresIn": 21 }
  ]
}
```

HOTP entries are not consumed by the batch endpoint. Use `POST /api/v1/entries/:id/hotp` for HOTP so the counter can be advanced atomically.

New TOTP/HOTP entries accept `SHA-1`, `SHA-256`, or `SHA-512` (`SHA1`, `SHA256`, and `SHA512` aliases are normalized). Missing algorithms default to `SHA-1` for otpauth compatibility. `POST /api/v1/entries/:id/verify` validates a submitted TOTP code with a +/-1 time-step window:

```json
{
  "code": "123456"
}
```

Response:

```json
{
  "ok": true,
  "valid": true,
  "window": 0
}
```

## Export

Encrypted export is the default safe export path and requires a Web UI cookie session plus current-password step-up confirmation:

- `POST /api/export/encrypted` with `{ "passphrase": "<backup passphrase>", "confirmPassword": "<current password>" }`

A successful password confirmation opens a 5-minute recent-authentication window for sensitive Web UI actions. Bearer tokens cannot call legacy export endpoints.
- `POST /api/v1/export/encrypted`

Request:

```json
{
  "passphrase": "Long backup passphrase"
}
```

Response:

```json
{
  "ok": true,
  "encrypted": {
    "format": "worker-2fauth-encrypted-v1",
    "kdf": "PBKDF2-SHA-256",
    "iterations": 180000,
    "salt": "...",
    "iv": "...",
    "ciphertext": "..."
  }
}
```

Plaintext export is disabled by default. The plaintext export endpoints require `ALLOW_PLAINTEXT_EXPORT=true` and a password confirmation in the POST body:

- `POST /api/export` with `{ "confirmPassword": "<current password>" }`
- `POST /api/export/otpauth` with `{ "confirmPassword": "<current password>" }`

When the flag is disabled, both endpoints return `403`.

## Import

OTPAuth import:

- `POST /api/v1/import/otpauth`
- `POST /api/import/otpauth`

Request:

```json
{
  "text": "otpauth://totp/Example:alice?secret=...&algorithm=SHA256",
  "groupId": 1
}
```

`groupId` is optional and must belong to the target user. Missing groups return `404`; groups owned by a different target user return `403`.

Response:

```json
{
  "ok": true,
  "found": 1,
  "imported": 1,
  "importedIds": [42],
  "failed": 0,
  "errors": []
}
```

Imported OTPAuth URIs must explicitly declare `SHA-256` or `SHA-512`. URIs with no algorithm or `SHA-1` are rejected per item and counted in `failed`; existing stored SHA-1 entries remain readable for compatibility.

Encrypted import:

- `POST /api/v1/import/encrypted`
- `POST /api/import/encrypted`

Request:

```json
{
  "passphrase": "Long backup passphrase",
  "encrypted": {
    "format": "worker-2fauth-encrypted-v1",
    "kdf": "PBKDF2-SHA-256",
    "iterations": 180000,
    "salt": "...",
    "iv": "...",
    "ciphertext": "..."
  }
}
```

Encrypted import is separately rate limited. Defaults are `ENCRYPTED_IMPORT_MAX_REQUESTS_PER_MINUTE=5` and `ENCRYPTED_IMPORT_LOCK_MINUTES=15`.

Encrypted backup passphrases must be 12 to 256 characters.

Bootstrap token failures are separately rate limited. Defaults are `BOOTSTRAP_MAX_REQUESTS_PER_MINUTE=5` and `BOOTSTRAP_LOCK_MINUTES=15`.

Plain JSON backup import skips entries that do not explicitly declare `SHA-256` or `SHA-512`. Entries with missing `algorithm` or `SHA-1` are not imported.

## Web Cookie Writes

Cookie-authenticated Web UI write requests (`POST`, `PATCH`, and `DELETE`) must be same-origin JSON requests. Requests carrying `__Host-session` must send `Origin` equal to the Worker origin, must not send `Sec-Fetch-Site: cross-site`, and must use `Content-Type: application/json`.

Bearer-only API requests do not require these cookie write checks. Requests carrying both the Web session cookie and a Bearer token are rejected before route handling.

## Browser Extension CORS

Set `CORS_ALLOWED_ORIGINS` as a comma-separated list of exact extension or HTTPS origins, for example:

```text
chrome-extension://<extension-id>,moz-extension://<extension-id>,https://app.example.com
```

The Worker does not allow cross-origin API reads by default.
Wildcard origins and non-local `http://` origins are ignored. Use `http://localhost:<port>` only for local development.

## Legacy Routes

The existing `/api/mobile/*`, `/api/extension/*`, and Web UI cookie routes remain available for compatibility. Legacy `/api/*` Web UI and admin routes require the `__Host-session` cookie; `/api/v1/*` routes require bearer tokens and do not expose full user-management capabilities. Legacy Web API routes such as `/api/import/otpauth`, `/api/export/encrypted`, `/api/import/encrypted`, and `/api/groups/:id` remain available alongside the `/api/v1` contract.
