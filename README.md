# 2Fauth-Cloudflare

Cloudflare Worker + D1 based 2FA manager. It supports Web UI access, TOTP/HOTP entries, groups, user roles, import/export, encrypted backups, and bearer-token API access for Android apps and browser extensions.

## Features

- Web login with HttpOnly session cookie
- Login risk control and optional Cloudflare Turnstile verification
- Admin/user RBAC
- TOTP and HOTP entry management
- Group management
- JSON, otpauth URI, and encrypted backup import/export
- AES-GCM encrypted OTP secrets in D1
- `/api/v1` bearer-token API for Android and browser extensions
- Exact-origin CORS allowlist for browser extensions

## Requirements

- Node.js
- Wrangler CLI, installed through `npm install`
- Cloudflare D1 database

## Install

```bash
npm install
```

## Configuration

Create or update `wrangler.toml` with your Worker and D1 binding:

```toml
name = "worker-2fauth"
main = "src/worker.js"
compatibility_date = "2025-01-01"

[[d1_databases]]
binding = "DB"
database_name = "worker-2fauth-db"
database_id = "<your-d1-database-id>"
```

Set runtime secrets:

```bash
npx wrangler secret put ENCRYPTION_KEY
npx wrangler secret put SESSION_PEPPER
```

`ENCRYPTION_KEY` must be a 32-byte base64 value, for example:

```bash
openssl rand -base64 32
```

Optional settings:

- `TURNSTILE_SECRET_KEY` or `TURNSTILE_KEY`: enables Turnstile verification for web/android login.
- `TURNSTILE_SITE_KEY`: renders Turnstile in the Web UI.
- `CORS_ALLOWED_ORIGINS`: comma-separated exact origins for browser extensions, for example `chrome-extension://<id>,moz-extension://<id>`.
- `DEBUG_ERRORS`: when truthy, includes internal error details in JSON error responses.

## Database Migrations

Local:

```bash
npm run d1:migrate:local
```

Remote:

```bash
npm run d1:migrate:remote
```

The current migration chain includes API session storage and indexes for refresh cleanup and client-type queries.

## Development

```bash
npm run dev
```

Then open the local Worker URL. On first use, bootstrap the first admin account from the Web UI.

## Verification

```bash
npm test
node --check src/worker.js
```

The test suite covers API v1 CORS, JSON parsing, Turnstile config compatibility, bearer sessions, refresh rotation, HTML security headers, and key RBAC regressions.

## API

The stable client API is documented in [API.md](./API.md).

Useful entry points:

- `GET /api/v1/capabilities`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `GET /api/v1/me`
- `GET /api/v1/entries`
- `POST /api/v1/codes/batch`

Legacy Web UI, `/api/mobile/*`, and `/api/extension/*` routes remain available for compatibility.

## Security Notes

- Never commit real secrets or production `wrangler.toml` values.
- Treat export payloads as sensitive.
- Prefer encrypted export when sharing backups.
- Keep `SESSION_PEPPER` and `ENCRYPTION_KEY` stable unless you have a rotation plan.
- Configure `CORS_ALLOWED_ORIGINS` with exact browser-extension origins, not wildcards.
