# 2Fauth-Cloudflare

可部署在 Cloudflare Worker 的 2FA 管理器，支持：

- 用户登录与会话系统
- 登录风控：默认 1 分钟内 10 次请求触发风控并锁定 15 分钟（管理员可配置）
- 权限管理（`admin` / `user`）
- TOTP / HOTP 条目管理（保存、读取、编辑、删除）
- 分组管理（Group）
- 数据导入导出（JSON 备份）
- 加密备份导入导出（口令保护）
- 二维码扫码导入（浏览器原生 BarcodeDetector）
- 敏感信息加密（AES-GCM）
- 长久存储（Cloudflare D1）

## 1. 准备

1. 安装依赖
```bash
npm install
```

2. 登录 Cloudflare
```bash
npx wrangler login
```

3. 创建 D1 数据库
```bash
npx wrangler d1 create worker-2fauth-db
```

将输出中的 `database_id` 填入 `wrangler.toml` 的 `database_id`。

4. 配置密钥

在 `wrangler.toml` 中替换：

- `ENCRYPTION_KEY`：32 字节 base64（例如 `openssl rand -base64 32`）
- `SESSION_PEPPER`：一段足够长的随机字符串

## 2. 初始化数据库

本地：
```bash
npm run d1:migrate:local
```

线上：
```bash
npm run d1:migrate:remote
```

> 新版本包含 `0002_groups_import_hotp.sql`，升级时请务必执行迁移。

## 3. 本地运行

```bash
npm run dev
```

打开 Worker 地址后：

1. 首次访问先初始化管理员账号
2. 登录后添加 2FA 条目（支持 Base32 Secret 或 `otpauth://totp/...` URI）
3. 管理员可创建用户、调整角色、删除用户

## 4. 部署

```bash
npm run deploy
```

## 5. 绑定到你的 Cloudflare Worker（推荐步骤）

当前仓库已按以下值配置 `wrangler.toml`：

```toml
name = "worker-2fauth"
main = "src/worker.js"
compatibility_date = "2025-01-01"

[[d1_databases]]
binding = "DB"
database_name = "worker-2fauth-db"
database_id = "b388dc9b-021e-4184-a256-5599139acfa6"
```

如果后续你改了 D1 库或 Worker 名称，再同步修改该文件即可。

然后在项目目录执行：

```bash
npx wrangler login
npx wrangler whoami
npx wrangler d1 list
```

确保账号、Worker 与 D1 都在同一个 Cloudflare account 下，再执行：

```bash
npm run deploy
```

## 6. 开启自动构建 / 自动部署（GitHub Actions）

仓库新增了工作流：`.github/workflows/deploy-worker.yml`。

- 触发条件：`push` 到 `main`，或手动触发 `workflow_dispatch`
- 流程：安装依赖 → 语法检查 → 远程 D1 迁移 → 部署 Worker

你只需要在 GitHub 仓库里配置以下 Secrets：

- `CLOUDFLARE_API_TOKEN`（需包含 Workers Scripts Edit、D1 Edit 权限）
- `CLOUDFLARE_ACCOUNT_ID`（Cloudflare 账户 ID）

### 常见问题：构建命令 / 部署命令填什么？

如果你在某个 CI 平台里需要手动填写命令，可以直接用：

- 构建命令（Build）：`npm ci && node --check src/worker.js`
- 部署命令（Deploy）：`npm run d1:migrate:remote && npm run deploy`

> 本仓库的 GitHub Actions 已经内置了这两步（见 `.github/workflows/deploy-worker.yml`），一般不需要你再单独填写。

### 还需要填写哪些配置？

除了命令外，至少还要确认这些项：

1. `wrangler.toml` 已写入 Worker 与 D1 绑定（`name`、`main`、`compatibility_date`、`[[d1_databases]]`、`database_id`）。
2. GitHub Secrets 已设置：`CLOUDFLARE_API_TOKEN`、`CLOUDFLARE_ACCOUNT_ID`。
3. Cloudflare 运行时密钥已设置（不要放进 Git）：
   - `ENCRYPTION_KEY`
   - `SESSION_PEPPER`

设置 Wrangler Secret 示例：

```bash
npx wrangler secret put ENCRYPTION_KEY
npx wrangler secret put SESSION_PEPPER
```

配置完成后，每次合并到 `main` 都会自动执行部署。

## API 说明（简版）

- `GET /api/status`：检查是否已初始化
- `POST /api/bootstrap`：创建首个管理员
- `POST /api/login` / `POST /api/logout`
- `GET /api/me`
- `GET /api/entries` / `POST /api/entries`
- `PATCH /api/entries/:id`
- `GET /api/entries/:id/code`
- `POST /api/entries/:id/hotp`
- `DELETE /api/entries/:id`
- `GET /api/groups` / `POST /api/groups`
- `DELETE /api/groups/:id`
- `GET /api/export` / `POST /api/import`
- `POST /api/export/encrypted` / `POST /api/import/encrypted`
- `GET /api/users`（admin）
- `POST /api/users`（admin）
- `PATCH /api/users/:id/role`（admin）
- `DELETE /api/users/:id`（admin）
- `GET /api/security/login-policy`（admin）
- `PATCH /api/security/login-policy`（admin）

## 安全说明

- 用户密码使用 `PBKDF2(SHA-256, 210000 iterations)` + 随机盐哈希存储
- TOTP Secret 使用 `AES-GCM` 加密后写入 D1
- 会话令牌只存哈希值，浏览器使用 `HttpOnly + Secure + SameSite=Strict` Cookie

生产环境建议：

- 定期轮换 `SESSION_PEPPER` 和 `ENCRYPTION_KEY`（轮换加密密钥需要数据迁移）
- 将 Worker 绑定自定义域并启用访问策略（如 Cloudflare Access）
- 对登录接口增加限流（可加 KV/DO 计数）

扫码导入说明：

- 页面支持摄像头扫码和上传图片扫码。
- 依赖浏览器原生 `BarcodeDetector`（Chrome/Edge 新版支持较好）。
- 如果浏览器不支持，可手动粘贴 `otpauth://...` URI 导入。

## 注：本项目由GPT 5.3 Codex生成
