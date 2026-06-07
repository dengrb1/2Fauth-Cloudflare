# API Contract

This Worker keeps the existing Web UI routes and exposes stable `/api/v1` bearer-token routes for native Android apps and browser extensions.

## Client Authentication

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
    "turnstileRequired": false
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
    "entries": "/api/v1/entries",
    "groups": "/api/v1/groups",
    "codesBatch": "/api/v1/codes/batch"
  }
}
```

### `POST /api/v1/auth/login`

Request:

```json
{
  "username": "alice",
  "password": "long-password",
  "clientType": "android"
}
```

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
- `GET /api/v1/entries`
- `POST /api/v1/entries`
- `PATCH /api/v1/entries/:id`
- `GET /api/v1/entries/:id/code`
- `POST /api/v1/entries/:id/hotp`
- `DELETE /api/v1/entries/:id`
- `GET /api/v1/groups`
- `POST /api/v1/groups`
- `DELETE /api/v1/groups/:id`
- `POST /api/v1/codes/batch`

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

## Browser Extension CORS

Set `CORS_ALLOWED_ORIGINS` as a comma-separated list of exact extension origins, for example:

```text
chrome-extension://<extension-id>,moz-extension://<extension-id>
```

The Worker does not allow cross-origin API reads by default.

## Legacy Routes

The existing `/api/mobile/*`, `/api/extension/*`, and Web UI cookie routes remain available for compatibility.
