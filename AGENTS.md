# Repository Guidelines

## Project Structure & Module Organization
This repository is a Cloudflare Worker application with D1 persistence.

- `src/worker.js`: Main Worker entrypoint (API routes, auth/RBAC, OTP logic, encryption helpers, and embedded UI).
- `migrations/`: Ordered D1 SQL migrations (for example `0001_init.sql`, `0002_groups_import_hotp.sql`).
- `wrangler.toml`: Worker config, D1 binding, runtime settings.
- `README.md`: Deployment and operational usage notes.
- `package.json`: Scripts for local dev, deploy, and migrations.

Add new runtime code under `src/` and schema changes as a new numbered file in `migrations/`.

## Build, Test, and Development Commands
- `npm install`: Install dependencies (Wrangler CLI).
- `npm run dev`: Run Worker locally.
- `npm run deploy`: Deploy to Cloudflare.
- `npm run d1:migrate:local`: Apply migrations to local D1.
- `npm run d1:migrate:remote`: Apply migrations to remote D1.
- `node --check src/worker.js`: Fast syntax check before deploy.

Typical flow:
1. `npm install`
2. `npm run d1:migrate:local`
3. `npm run dev`

## Coding Style & Naming Conventions
- Language: JavaScript (ES modules), 2-space indentation, semicolons required.
- Naming: `camelCase` for variables/functions (`handleImportDataEncrypted`), `UPPER_SNAKE_CASE` for constants (`SESSION_TTL_SECONDS`).
- Keep route handlers focused and move reusable logic into helper functions.
- Prefer concise comments only where behavior is non-obvious.
- No formatter/linter is currently enforced; keep style consistent with `src/worker.js`.

## Testing Guidelines
- No automated test framework is configured yet.
- Minimum validation before PR:
  - `node --check src/worker.js`
  - Manual checks for login/logout, TOTP/HOTP generation, import/export, encrypted backup, and group management.
- When adding tests, use `tests/` and `*.spec.js` naming (for example `tests/auth.spec.js`).

## Commit & Pull Request Guidelines
- Git history is not always available in this workspace; use Conventional Commits:
  - `feat: add encrypted import endpoint`
  - `fix: validate HOTP counter bounds`
- PRs should include:
  - clear summary and scope
  - migration impact (if any)
  - config/secrets changes
  - manual verification steps (and screenshots for UI changes)

## Security & Configuration Tips
- Never commit real secrets; store runtime secrets via Wrangler secrets.
- Treat export payloads as sensitive; prefer encrypted export in shared environments.
- For key rotation, plan a migration path for encrypted records before changing keys.
