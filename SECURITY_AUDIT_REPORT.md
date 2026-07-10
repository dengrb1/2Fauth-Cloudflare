# 2Fauth-Cloudflare 安全审计报告

审计日期：2026-06-30  
审计范围：`src/worker.js`、`migrations/`、`wrangler.toml`、`wrangler.jsonc`、`package.json`、`package-lock.json`、`README.md`、`tests/worker-api.spec.js`

## 摘要

本项目整体安全基线较好：主要 SQL 查询使用参数绑定，Web UI 设置了 CSP 和基础安全响应头，Cookie 使用 `HttpOnly; Secure; SameSite=Strict`，OTP secret 使用 AES-GCM 加密存储，登录、API 和 OTP 操作已有一定限流与测试覆盖。

本次审计未发现明显 SQL 注入或直接的未认证数据读取漏洞。主要风险集中在首次初始化、Cookie 认证接口的 CSRF 边界、明文导出默认配置、导入策略绕过、资源消耗控制，以及本地开发依赖的供应链漏洞。

## 验证记录

已执行：

```powershell
node --check src/worker.js
npm test
npm audit --omit=dev
npm audit --registry=https://registry.npmjs.org
```

结果：

- `node --check src/worker.js`：通过
- `npm test`：41 项通过
- `npm audit --omit=dev`：未发现生产依赖漏洞
- `npm audit --registry=https://registry.npmjs.org`：发现 dev toolchain 依赖漏洞，详见 F-06

## 发现清单

| 编号 | 严重性 | 标题 | 状态 |
| --- | --- | --- | --- |
| F-01 | 高 | 初始化管理员存在公开抢占和并发竞态风险 | 未修复 |
| F-02 | 高 | Cookie 认证写接口缺少统一 CSRF/Origin 校验 | 未修复 |
| F-03 | 中高 | 明文导出默认开启 | 未修复 |
| F-04 | 中 | JSON 备份导入可绕过 SHA-1 禁用策略 | 未修复 |
| F-05 | 中 | OTP secret 缺少长度上限，可能造成资源消耗 | 未修复 |
| F-06 | 中 | Wrangler 本地开发依赖存在高危供应链告警 | 未修复 |
| F-07 | 低 | 加密导入可被认证用户用于 PBKDF2 CPU 消耗 | 未修复 |
| F-08 | 低 | 畸形 Cookie 值可能触发 500 错误 | 未修复 |

## F-01 初始化管理员存在公开抢占和并发竞态风险

严重性：高

### 证据

- `src/worker.js:197`：`handleBootstrap`
- `src/worker.js:206`：先调用 `hasAnyUser(env)`
- `src/worker.js:207`：如果已有用户才拒绝初始化
- `src/worker.js:211`：随后执行 `INSERT INTO users ... role='admin'`

当前流程是“先查询是否已有用户，再插入管理员”。在空库首次部署期间，任何可访问 Worker 的人都可以调用 `/api/bootstrap` 创建第一个管理员。如果存在并发初始化请求，也可能多个请求都在 `hasAnyUser()` 返回 false 后继续插入管理员。

### 影响

攻击者可在系统首次部署但管理员尚未初始化时抢占管理员账号，获得全部 OTP 条目、用户管理、导入导出等权限。

### 建议

- 增加一次性 `BOOTSTRAP_TOKEN`，要求 `/api/bootstrap` 请求必须携带该 token。
- 或通过 Cloudflare Access / IP allowlist 暂时保护初始化端点。
- 初始化写入应改为原子流程，例如使用初始化锁表或受唯一约束保护的 bootstrap state。
- 初始化完成后，可以通过环境变量显式禁用 bootstrap 端点。

## F-02 Cookie 认证写接口缺少统一 CSRF/Origin 校验

严重性：高

### 证据

- `src/worker.js:147`：匹配 API 路由后直接执行 handler
- `src/worker.js:150`：只做 API rate limit
- `src/worker.js:152`：未统一校验 `Origin` 或 CSRF token
- `src/worker.js:614`：只有 `/api/logout` 单独校验 `Origin`
- `src/worker.js:2465`：Session Cookie 使用 `SameSite=Strict`
- `src/worker.js:2516`：`parseJson()` 不要求 `Content-Type: application/json`

当前大多数 Cookie 认证写接口依赖 `SameSite=Strict` 防护跨站请求，但没有统一的服务端 CSRF 校验。`SameSite=Strict` 能阻止常见跨站点请求，但不能完整覆盖同站不同源场景，例如同一 eTLD+1 下的受控子域或未来部署形态变化。

同时，JSON 解析不要求 `Content-Type: application/json`，如果请求体刚好是合法 JSON，简单表单/文本请求也可能被服务端接受。

### 影响

在满足同站不同源、子域被接管、反向代理错误配置等条件时，攻击者可能诱导已登录用户触发状态变更操作，例如导入、删除、修改条目、生成 HOTP、用户管理等。

### 建议

- 对所有 Cookie 认证的非 `GET` / `HEAD` 请求统一校验 `Origin`，必须等于当前 Worker origin。
- 增加 `Sec-Fetch-Site` 检查，拒绝 `cross-site` 请求。
- 要求写接口 `Content-Type` 为 `application/json`。
- 如需更强保证，增加 CSRF token，并要求前端在自定义 header 中提交。
- Bearer token API 可与 Cookie Web API 分开处理，避免影响移动端/扩展端。

## F-03 明文导出默认开启

严重性：中高

### 证据

- `wrangler.toml:12`：`ALLOW_PLAINTEXT_EXPORT = "true"`
- `wrangler.jsonc:13`：`ALLOW_PLAINTEXT_EXPORT` 同样为 true
- `README.md:62`：文档说明仓库默认启用明文导出
- `src/worker.js:1145`：`requirePlaintextExportConfirmation`
- `src/worker.js:1187`：导出时将 `secret_enc` 解密为 `secret`

明文导出需要当前密码确认，这是有价值的保护。但配置默认启用会扩大误操作和配置漂移风险。管理员明文导出会包含所有用户的 OTP secret。

### 影响

一旦管理员会话、密码、浏览器剪贴板、下载目录或日志记录路径被攻破，明文导出会直接泄露所有 OTP seed，影响面比普通会话泄露更大。

### 建议

- 将 `wrangler.toml` 和 `wrangler.jsonc` 中默认值改为关闭或移除该变量。
- 生产环境默认只允许 `/api/export/encrypted`。
- 明文导出如确需使用，应临时开启、完成后关闭，并记录操作审计。
- 前端可继续保留按钮，但默认禁用并提示使用加密导出。

## F-04 JSON 备份导入可绕过 SHA-1 禁用策略

严重性：中

### 证据

- `src/worker.js:724`：新建 OTP 条目拒绝 SHA-1
- `src/worker.js:725`：明确返回 `algorithm must be SHA-256 or SHA-512`
- `src/worker.js:1116`：otpauth 导入拒绝缺失算法或 SHA-1
- `src/worker.js:1264`：JSON 备份导入只执行 `normalizeAlgorithm(e.algorithm || "SHA-1")`
- `README.md:122`：文档说明新 OTP 条目只接受 SHA-256 或 SHA-512

普通创建和 otpauth 导入都拒绝 SHA-1，但 JSON 导入路径没有拒绝 SHA-1。攻击者或误操作可通过 JSON 备份导入创建 SHA-1 条目。

### 影响

安全策略不一致，可能导致系统中重新出现被策略禁止的 SHA-1 OTP 条目。虽然 TOTP/HOTP 生态中 SHA-1 仍常见，但当前项目文档和新建逻辑已选择禁用 SHA-1，新旧路径应一致。

### 建议

- 在 `importPayload()` 中加入：

```js
if (algorithm === "SHA-1") continue;
```

- 或将导入失败原因返回给用户，而不是静默跳过。
- 如果要兼容旧备份，应在文档中明确“JSON 导入允许旧 SHA-1 条目”，并在 UI 上标注风险。

## F-05 OTP secret 缺少长度上限，可能造成资源消耗

严重性：中

### 证据

- `src/worker.js:708`：创建条目时读取 `secret`
- `src/worker.js:729`：仅检查 base32 可解码
- `src/worker.js:790`：更新条目时同样仅检查 base32 可解码
- `src/worker.js:1250`：JSON 导入读取 `secret`
- `src/worker.js:1257`：导入时仅检查 base32 可解码
- `src/worker.js:2355`：`base32Decode(input)`
- `src/worker.js:2358`：使用字符串累积 bit
- `src/worker.js:2362`：每个字符追加 5 bit 字符串

请求体总大小限制为 1MB，但单个 OTP secret 没有长度上限。`base32Decode()` 使用字符串拼接累积 bit，超长 secret 会放大 CPU 和内存开销，并进一步写入加密后的 D1 数据。

### 影响

认证用户可通过创建、更新或导入超长 secret 消耗 Worker CPU、内存和 D1 存储。批量导入最多 500 条，放大该影响。

### 建议

- 增加统一 secret 校验函数，例如限制 base32 secret 长度为 16 到 256 字符。
- 限制解码后字节数，例如 10 到 128 字节。
- 优化 `base32Decode()`，避免用字符串累积 bit。
- 对导入失败项返回原因，便于用户定位问题。

## F-06 Wrangler 本地开发依赖存在高危供应链告警

严重性：中

### 证据

- `package.json:14`：`wrangler` 使用 `^4.26.0`
- `package-lock.json:1424`：当前解析为 `wrangler 4.65.0`
- `package-lock.json:1267`：`miniflare 4.20260212.0`
- `package-lock.json:1381`：`undici 7.18.2`
- `package-lock.json:1459`：`ws 8.18.0`
- `package-lock.json:1200`：`esbuild 0.27.3`

使用官方 npm registry 执行 `npm audit` 发现 5 个漏洞，其中 4 个 high，主要涉及 `undici`、`ws`、`esbuild`，通过 `wrangler` / `miniflare` 引入。

这些依赖是 devDependency，通常不会进入 Cloudflare Worker 生产运行时，但会影响本地 `wrangler dev`、D1 本地模拟、CI 和部署环境。

### 建议

- 使用官方 registry 执行：

```powershell
npm audit fix --registry=https://registry.npmjs.org
```

- dry-run 显示修复路径会升级到 `wrangler 4.105.0`，并同步升级 `miniflare`、`esbuild`、`undici`、`ws` 等传递依赖。
- 升级后重新执行：

```powershell
node --check src/worker.js
npm test
npm audit --registry=https://registry.npmjs.org
```

## F-07 加密导入可被认证用户用于 PBKDF2 CPU 消耗

严重性：低

### 证据

- `src/worker.js:1298`：`handleImportDataEncrypted`
- `src/worker.js:1310`：解密前执行 passphrase KDF
- `src/worker.js:2231`：读取 payload 中的 `iterations`
- `src/worker.js:2255`：要求 iterations 不低于默认值
- `src/worker.js:2256`：允许最高 `MAX_PASSPHRASE_PBKDF2_ITERATIONS`

`MAX_PASSPHRASE_PBKDF2_ITERATIONS` 为 1,000,000。认证用户可以反复提交高迭代次数的加密导入请求触发 PBKDF2 计算。项目已有 API rate limit，但该接口单次计算成本仍偏高。

### 建议

- 对导入接口设置更低的专用 rate limit。
- 将导入 payload 的迭代次数固定为服务端策略，或降低最大允许值。
- 对失败解密次数增加短期锁定。

## F-08 畸形 Cookie 值可能触发 500 错误

严重性：低

### 证据

- `src/worker.js:2429`：`parseCookies`
- `src/worker.js:2437`：直接执行 `decodeURIComponent(v)`

如果 Cookie 值包含非法 percent encoding，`decodeURIComponent` 会抛出异常，最终返回 500。该问题通常不导致敏感信息泄露，因为生产错误详情默认不暴露，但会造成噪音和轻微可用性问题。

### 建议

- 对单个 Cookie 值解码加 `try/catch`。
- 解码失败时忽略该 Cookie 或保留原始值。

## 已确认的安全优点

- 多数 SQL 查询使用 D1 prepared statement 和 `.bind()`，未发现明显 SQL 注入。
- 批量 `IN` 查询通过 `buildInClause()` 生成占位符，且 ID 已验证。
- Web UI 设置 CSP、`X-Frame-Options: DENY`、`X-Content-Type-Options: nosniff` 等安全头。
- Session Cookie 使用 `HttpOnly; Secure; SameSite=Strict`。
- API CORS 使用精确 origin allowlist，且不允许 credentials。
- OTP secret 使用 AES-GCM 加密存储。
- 密码使用 PBKDF2-SHA-256，且包含旧 hash 自动升级逻辑。
- Refresh token 轮换使用 `WHERE id = ? AND refresh_hash = ?` 防重放。
- HOTP 消费使用 `UPDATE ... RETURNING` 原子递增 counter。
- 登录、API、TOTP verify、HOTP consume 均有一定限流。
- 测试覆盖了 CORS、Turnstile、Bearer session、refresh rotation、RBAC、明文导出关闭、SHA-1 拒绝等关键回归。

## 推荐修复优先级

1. 保护 `/api/bootstrap`，避免首次部署被抢占。
2. 为 Cookie 认证写接口增加统一 CSRF/Origin/Content-Type 防护。
3. 默认关闭明文导出。
4. 修复 JSON 导入 SHA-1 绕过。
5. 增加 OTP secret 长度和解码后字节数限制。
6. 升级 Wrangler dev toolchain 依赖。
7. 收紧加密导入 PBKDF2 迭代次数和失败限流。
8. 加固 Cookie 解析异常处理。

