# 2Fauth-Cloudflare 审计修复 Goal Plan

## 概述

本计划基于当前项目审计结果，目标是优先修复已确认的高风险问题，并补齐必要的测试与上线保护。

---

## Goal 1：立即封堵 Bearer Token 越权访问

**优先级：P0**

### 目标

将 Web UI / legacy `/api/*` / 管理接口 与 `/api/v1` Bearer Token 能力彻底隔离。

### 任务

- 新增明确的鉴权辅助函数：
  - `requireWebSession()`
  - `requireAdminWebSession()`
  - `requireApiSession()`
  - `requireExtensionSession()`
- 对以下接口强制改成 **仅允许 Web Session**：
  - `/api/export`
  - `/api/export/otpauth`
  - `/api/export/encrypted`
  - `/api/import`
  - `/api/import/otpauth`
  - `/api/import/encrypted`
  - `/api/users*`
  - `/api/security/login-policy`
- 对 `/api/v1/*` 保持 Bearer 访问，但只暴露文档声明的能力。

### 验收标准

- admin bearer 调 `/api/users` 返回 `403` 或 `400`
- extension bearer 调 `/api/export/encrypted` 返回 `403` 或 `400`
- 现有 `/api/v1` 客户端能力不回归

---

## Goal 2：为高敏感操作增加二次认证 / Step-up Auth

**优先级：P0**

### 目标

即使 session/token 泄露，也不能直接批量导出全部 OTP seed。

### 任务

- `POST /api/export/encrypted` 增加当前密码确认
- 对敏感接口增加“最近认证时间窗口”，例如 5 分钟内通过密码复核
- 对以下管理员敏感动作增加 step-up auth：
  - 重置密码
  - 修改角色
  - 删除用户
  - 修改登录风控策略

### 验收标准

- 无密码确认时，加密导出返回 `401` 或 `403`
- Bearer Token 无法单独完成全量 seed 导出

---

## Goal 3：修复 Unknown IP 风控 Key 不一致

**优先级：P1**

### 目标

让登录成功后的风控清理逻辑与建桶逻辑保持一致。

### 任务

- 统一 `unknown IP` 的 key 生成逻辑
- 将 `applyLoginRiskControl()` 与 `clearLoginRiskControl()` 依赖的 key builder 抽成同一实现

### 验收标准

- 新增测试覆盖 unknown IP 场景
- 成功登录后对应锁桶能被正确清除

---

## Goal 4：加固 Bootstrap 初始化流程

**优先级：P1**

### 目标

消除首次部署时的抢注/竞态风险。

### 任务

- 采用以下方案之一：
  1. 增加一次性 `BOOTSTRAP_TOKEN` / `INIT_SECRET`
  2. 增加初始化哨兵表 / 原子初始化记录
- 初始化完成后永久关闭 bootstrap
- 在 `README.md` 中补充首次部署安全说明，要求先受限访问再初始化

### 验收标准

- 未提供初始化密钥时，bootstrap 不可用
- 并发初始化只能成功一次

---

## Goal 5：补齐回归测试

**优先级：P0**

### 目标

为本次审计确认的问题建立长期回归保护。

### 必加测试

- bearer 访问 `/api/users` 被拒绝
- bearer 访问 `/api/export/encrypted` 被拒绝，或必须通过 step-up auth
- extension bearer 不能重置其他用户密码
- unknown IP 风控桶可正确清理
- bootstrap 并发 / 重复初始化保护

### 验收标准

- 新增测试全部通过
- 修复前测试失败，修复后测试通过

---

## 建议执行顺序

1. 先修 **Goal 1**
2. 再修 **Goal 2**
3. 同步补 **Goal 5** 中对应测试
4. 然后处理 **Goal 3**
5. 最后完成 **Goal 4**

---

## 预期产出

- 鉴权边界修复后的 `src/worker.js`
- 新增或更新的测试用例
- 更新后的 `README.md`
- 一套可验证的安全回归基线