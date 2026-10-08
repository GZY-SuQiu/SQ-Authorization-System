# SQ 授权系统：需求提取、现状差距与改造建议

> 分析日期：2026-10-06
> 分析范围：`SQ-Authorization-System-1.0.0`（core / server / admin / master / verification / tests / build）
> 方式：5 个只读子分析 + 跨模块关键词扫描；未修改任何代码，未运行测试。
> 结论状态：分析稿，待你确认取舍后再进入设计与开发。

---

## 0. 执行摘要

1. 现有系统是一个结构干净的单机授权核心：FastAPI + SQLite + PySide6 四端（本地服务器 / 管理端 / 验证端 / 主控端），已有完整的卡密生命周期、设备绑定、HMAC 请求签名 + Ed25519 响应验签、离线激活（LICREQ1 / LICACT1）、审计日志、备份恢复，以及一个能读写授权数据的 AI 助手。
2. 你的两组意见（A：邮箱账号 + 邮件告警；B：授权运营增强）共 17 项需求中：
   - **零实现**：邮箱字段与验证、找回密码、验证端邮箱登录、SMTP 邮件引擎、告警规则、风控触发、通知渠道、密钥模板、批量导入、功能旗标、订阅周期自动化、Web 管理后台、代理商分级、Webhook 事件总线、多语言 SDK。
   - **部分可复用**：批量导出（仅 CSV、无导入、无 Excel）、浮动席位（有绑定上限与心跳时间戳，无并发席位与在线口径）、离线激活增强（有 Ed25519 签名与硬件指纹绑定，无二维码 / 文件封装 / 离线宽限期）。
3. 最重要的架构判断：**验证端"邮箱+密码登录"不是给现有管理员登录换个字段，而是新增一个独立账号域**（门户账号 + 与许可证的绑定 + Token 作用域隔离）。管理端 Token 与验证端 Token 必须分开，否则存在越权风险。
4. 邮件与告警的正确形态是 **SQLite outbox + 后台 worker**（业务事务只入队，发送与重试异步化），不要在各请求里同步调用 SMTP，也不要为当前单机部署引入 Celery/Redis。
5. 建议的推进顺序：
   - **P0 底座**（1~2 周）：迁移版本化、私钥轮换、索引与读路径减写、outbox 基础设施、领域服务层收口写入。
   - **P1 你的主线**（4~6 周）：管理员邮箱绑定/验证/找回 → 验证端邮箱登录 → SMTP 邮件引擎 → 告警规则与风控 → 通知渠道（邮件优先）。
   - **P2 运营增强**（3~5 周）：密钥模板 → 批量导入导出 → 功能旗标 → 浮动席位 → 订阅周期自动化 → 离线激活增强。
   - **P3 平台化**（5~8 周+）：Web 管理后台 → 代理商分级 → Webhook/事件总线 → 多语言 SDK。
6. 必须先处理的既有隐患（不处理会直接影响新功能）：
   - 工作区 `server_config.json` 含明文 `secret_key` 与离线/响应签名私钥，若随包分发等于泄露签发能力，**建议立即轮换**。
   - 全局请求体上限 64KB 且全量缓冲，直接阻断"几万条导入"。
   - 每次列表/统计前都会执行 `sweep_expired()` 写操作，心跳一多就会放大写锁竞争。
   - 反代场景下不解析 `X-Forwarded-For`，告警与风控的 IP 会全部变成代理地址。
   - 客户端 `offline_last_seen_ts` 不在配置白名单里，重启后时钟回拨记忆丢失。

---

## 1. 需求提取（结构化）

### 1.1 主线 A：邮箱账号 + 邮件告警

| 编号 | 需求 | 关键点 | 验收标准（建议） |
|---|---|---|---|
| A1 | 管理员账号增加 email 字段与邮箱验证 | 主控端创建/编辑管理员时可填邮箱；发送验证邮件；未验证标记 | 管理员列表显示邮箱与验证状态；未验证邮箱不能用于找回密码 |
| A2 | 找回密码（邮箱） | 忘记密码页 → 邮件验证码/令牌 → 重置 → 旧的登录态失效 | 令牌一次性、有过期时间、有限流；重置后旧 Token 立即失效 |
| A3 | 验证端邮箱+密码登录（区别于激活码） | 新增门户账号体系，与许可证绑定；保留激活码入口 | 验证端可切换"账号登录 / 激活码激活"两种模式；账号登录仍需设备绑定 |
| A4 | 邮件发送引擎 | SMTP 配置、模板、重试、队列、投递记录 | 请求不阻塞；失败自动退避重试；可在界面查看投递状态与失败原因 |
| A5 | 告警规则（阈值触发） | 激活率、并发数、过期率等阈值；冷却与去重 | 规则可配置启停；触发后生成告警事件并通知；支持静默/确认 |
| A6 | 风控触发 | 异常 IP、虚拟机、并发超限等信号 | 记录风险事件；按等级告警或拦截；有审计与人工处置入口 |
| A7 | 通知渠道 | 邮件为主，可扩展 Webhook / 钉钉 / 企微 / 飞书 | 渠道统一抽象；新增渠道不改业务代码；凭据加密存储 |

### 1.2 主线 B：授权运营增强

| 编号 | 需求 | 关键点 |
|---|---|---|
| B1 | 密钥模板/预设 | 一键套用"专业版-年付-3设备-全模块"等组合，支持保存/另存/删除 |
| B2 | 批量导入导出 | CSV/Excel 双向；几万条；分块、进度、错误行回执 |
| B3 | 功能旗标 | 一个 Key 控制多个模块开关（feature_a=true / feature_b=false），随激活/校验/心跳下发 |
| B4 | 浮动/并发席位 | 池化管理，限制"同时在线数"，区别于"累计绑定设备数" |
| B5 | 订阅周期自动化 | 到期提醒、自动续费、宽限期、降级 |
| B6 | 离线激活增强 | 二维码分享、离线文件签名验证、硬件指纹绑定 |
| B7 | Web 管理后台 | 可视化仪表盘、实时在线、批量操作、报表导出 |
| B8 | 代理商/渠道分级 | 多级分销、激活码分发、核销统计、返佣 |
| B9 | Webhook/事件总线 | 激活/过期/吊销/心跳异常回调业务系统，带签名与重试 |
| B10 | SDK 多语言 | Python / Go / JS / .NET / Rust；自动心跳、离线重试 |

---

## 2. 现状基线（代码事实）

### 2.1 架构与规模

- 四端程序：`server`（FastAPI，默认 127.0.0.1:8765）、`admin`、`master`、`verification`（均为 PySide6）。
- 数据层：单文件 SQLite（`data/license.db`），WAL + `busy_timeout=5000`，单连接 + 进程内 `RLock`（P0 注意事项）。
- 关键模块规模：`core/pages.py` 约 79KB、`server/api.py` 约 56KB、`core/database.py` 约 52KB、`server/ai_gateway.py` 约 41KB、`server/ai_tools.py` 约 35KB。

### 2.2 已有能力（可直接复用）

- 卡密：批量生成、时长卡/激活次数卡、批次、吊销/恢复、冻结/解冻、续期、删除、解绑、CSV 导出（50k 上限）。
- 绑定：`licenses.max_devices` 累计绑定上限 + `activate_atomic` 原子占位；`activations.last_heartbeat_at / heartbeat_count` 已有心跳数据。
- 安全：PBKDF2-SHA256（60 万次）+ `auth_version` 使旧 Token 失效；管理端 HMAC Bearer Token；客户端 HMAC 请求签名 + nonce 防重放；服务端 Ed25519 响应签名；会话密钥 AES-GCM 落库加密。
- 离线：`LICREQ1` 请求码、`LICACT1` 签名激活码、Ed25519 验签、机器码强制匹配、管理端 30 天请求时效校验。
- 运维：审计日志（筛选/分页/导出/清理）、数据库备份恢复、日志自动刷新。
- AI：OpenAI 兼容网关，15 个工具，可查询和有权限地修改授权数据；但任务是内存队列（重启丢失）。

### 2.3 数据模型（当前仅 5 张表）

| 表 | 关键字段 | 与新需求的关系 |
|---|---|---|
| `admins` | username / password_hash / role / status / auth_version / must_change_password | 无 email，A1/A2 的改动对象 |
| `licenses` | key_code / edition / card_type / duration / activation_limit / max_devices / status / batch_no / expires_at | 模板、旗标、订阅、渠道归属的扩展对象 |
| `activations` | license_id / key_code / machine_code / status / last_heartbeat_at / session_secret | 并发席位与在线统计的基础 |
| `nonces` | nonce / key_code / created_at | 防重放，不是队列 |
| `audit_logs` | actor / action / target / detail / ip / created_at | 事件源，但不是结构化事件总线 |

迁移机制：`CREATE TABLE IF NOT EXISTS` + 每列一个 `ALTER TABLE ADD COLUMN`，**没有 schema 版本表、没有回滚、没有数据回填**。新增大量表之前应先升级迁移框架。

### 2.4 测试与打包

- 13 个测试文件、164 个测试函数，覆盖安全、事务并发、AI 工具、Qt 页面回归；**盲区**：邮件、告警、事件总线、Web 后台、容量/性能、打包产物。
- CI 只跑 `python -m unittest discover`，约 25 个 pytest 风格用例不会被发现；`pytest` 不在依赖中。
- 打包：PyInstaller onefile，四个 exe 约 52.5~57.3MB；依赖未锁版本。

---

## 3. 差距矩阵

判定口径：以"数据库结构 + 服务端行为 + 客户端 UI"三者是否可支撑为准。

| 编号 | 需求 | 判定 | 现有可复用 | 主要缺口 | 规模 | 建议阶段 |
|---|---|---|---|---|---|---|
| A1 | 管理员邮箱+验证 | 缺失 | PBKDF2、auth_version、主控管理员页 | admins 无 email；无验证令牌表；无发信能力 | M | P1 |
| A2 | 找回密码 | 缺失 | 改密接口、强制改密、登录限流 | 重置令牌、防枚举、SMTP、审计 | M | P1 |
| A3 | 验证端邮箱登录 | 缺失 | 设备绑定、HMAC 会话签名 | 独立账号域、Token scope 隔离、账号-许可证-设备模型、双模式 UI | L | P1 |
| A4 | 邮件引擎 | 缺失 | requests、现有配置写入与 ACL | SMTP 配置/模板/持久队列/退避重试/投递记录 | L | P1 |
| A5 | 告警阈值规则 | 缺失 | stats/批次/审计数据 | 规则表、评估器、告警事件、去重静默、时间序列 | M | P1 |
| A6 | 风控触发 | 部分 | IP/机器码/心跳/失败限流/审计 | VM 信号、持久化风险事件、IP 聚合封禁、并发执行、反代 IP | L | P1 |
| A7 | 通知渠道 | 缺失 | — | 渠道抽象 + outbox + 邮件/Webhook/钉钉/企微/飞书适配器 | M | P1 |
| B1 | 密钥模板 | 缺失 | 生成接口与生成页表单 | 模板表、CRUD API、套用/保存 UI | S | P2 |
| B2 | 批量导入导出 | 部分（仅 CSV 导出） | 导出、分页、进度对话框、公式注入净化 | 导入解析/校验/错误回执、Excel、异步任务、64KB 上限 | L | P2 |
| B3 | 功能旗标 | 缺失 | edition 字段、激活/校验/心跳响应 | features/license_features、响应下发、离线载荷兼容 | M | P2 |
| B4 | 浮动/并发席位 | 部分（绑定上限） | max_devices、activate_atomic、心跳时间 | 在线窗口、并发上限、租约/释放/抢占、在线看板 | M~L | P2 |
| B5 | 订阅周期自动化 | 缺失 | 到期时间、手动续期、prev_status | 订阅配置、幂等调度、提醒/续费/宽限/降级状态机 | L | P2 |
| B6 | 离线激活增强 | 部分（签名+指纹已有） | LICACT1 验签、机器码绑定 | 二维码、签名文件封装、离线宽限期、防篡改、指纹 v2 | M | P2 |
| B7 | Web 管理后台 | 缺失（仅桌面） | FastAPI、RBAC、Database、批量 API | 前端工程、聚合/时序接口、异步任务、CORS/refresh/错误模型 | L | P3 |
| B8 | 代理商/渠道分级 | 缺失 | created_by、batch_no | 多级关系、配额分发、核销、返佣、结算、权限隔离 | L | P3 |
| B9 | Webhook/事件总线 | 缺失 | audit_logs | 结构化事件、事务 outbox、订阅、HMAC 签名、重试死信 | L | P3 |
| B10 | 多语言 SDK | 部分（协议可文档化） | HMAC/Ed25519 算法与头规范 | 正式协议规范、错误码枚举、密钥轮换、测试向量、5 语言实现 | M（规范）/ L（SDK） | P3 |

---

## 4. 关键技术判断

### 4.1 验证端邮箱登录：新增"门户账号域"，禁止复用管理员 Token

- 现有 `current_admin` 只按 `uid` 查 `admins` 表；若验证端沿用同一 HMAC secret 签发无 `aud/typ` 的 Token，uid 一旦命中管理员即越权。
- 建议新表：`portal_accounts`（email 唯一、口令、状态、auth_version、邮箱验证时间、登录时间）、`portal_account_licenses`（账号-许可证-席位上限）、`portal_sessions`（refresh/revoke）。
- Token 必须带 `aud=portal` / `typ` 并单独校验；验证端登录后仍需完成设备绑定（复用 machine_code），`verify/heartbeat` 增加账号会话分支。
- 邮箱验证与找回密码共用 `email_verification_codes`（只存哈希、一次性、有限流、防枚举）。

### 4.2 邮件引擎：outbox + 单 worker，不引入重队列中间件

- 业务事务提交时只写 `notification_outbox`（或 `email_queue`），后台 worker 按 `next_attempt_at` 领取、发送、指数退避、记录失败、进死信。
- SMTP 用标准库 `smtplib/email` 即可，模板渲染可先用 `str.format`/`string.Template`，需要复杂模板再引入 Jinja2（注意打包 hidden-import）。
- SMTP 凭据必须只进服务端配置，并复用现有 AES-GCM 封装思路加密存储；绝不能下发到客户端角色。
- 请求线程绝不调用 SMTP；发送失败的告警本身也要防风暴。

### 4.3 告警引擎：指标 → 规则 → 事件 → 通知，四层分离

- 现有 `stats()` 是快照，缺时间序列；告警"激活率/过期率"需要按时间桶聚合（建议 `metric_samples` 或按需 SQL + 缓存）。
- 告警评估放 FastAPI lifespan 的后台任务（30~60 秒一轮），按 `rule_id + dedup_key` 去重，冷却窗口内不重复通知，支持确认/静默。
- 通知只写 outbox，不直接发；渠道通过统一接口（email/webhook/dingtalk/wecom/feishu）。
- 并发指标需要先补在线口径：`last_heartbeat_at >= now - 在线窗口`（建议窗口 = 2~3 个心跳周期）。

### 4.4 风控：服务端信号为主，虚拟机检测只作为风险分而非硬拦截

- 客户端上报的"是否虚拟机"不可信，建议服务端综合：心跳间隔异常、同一机器码多 Key、同一 IP 多 Key、激活/校验失败率、机器指纹分量变化、IP 归属与代理头。
- 已有信号：IP（注意解析 `X-Forwarded-For`）、机器码、设备名、心跳时间/次数、失败限流、签名失败与重放。
- 缺失信号：VM 检测、UA/代理、IP 封禁、持久化风险事件、并发超限执行。
- 建议 `risk_events` 表 + 分级动作（仅记录 → 告警 → 降速 → 冻结/封禁），避免误伤正常用户。

### 4.5 浮动席位：与"绑定设备数"并存的两套语义

- `max_devices` 是累计绑定上限，`activate_atomic` 已原子实现；浮动席位是"同时在线数"，需要新的 `concurrent_limit` 与在线窗口。
- 方案：基于 `last_heartbeat_at` 派生活跃集合，配合 `seat_leases`（租约、超时释放、可抢占/踢出）实现严格配额；对离线宽限要明确策略（离线设备是否占席位）。
- 建议先落"在线统计 + 超限告警"（M），再做"超限阻断/抢占"（L）。

### 4.6 批量导入：先解决 64KB 请求体与全量缓冲

- 当前全局 `max_request_bytes=65536` 且中间件把请求整体读入内存，几万条 JSON/CSV 在架构上先被阻断。
- 建议：专用分片/流式导入端点 + 后台导入任务（进度、取消、幂等键、错误行 CSV 回执、分块事务）；导出改游标分页或流式下载，避免 UI 线程拼全量列表。
- Excel 支持建议放服务端（openpyxl）或客户端按需引入，注意 PyInstaller 打包体积。

### 4.7 Web 后台：与桌面端并存，复用服务端能力

- 推荐 Vue 3 + TypeScript + Vite + Element Plus + ECharts；或 React + TS + Ant Design。
- 服务端要补：显式 CORS origin 与 `expose_headers`、refresh/logout 或单会话吊销、admin/list 与 license/detail 分页、统一错误码；响应签名中间件会缓冲响应体，SSE/流式需改造。
- 分工建议：桌面端保留服务启停、备份恢复、密钥生成、高风险删除/批量吊销、管理员管理；Web 端承担仪表盘、实时在线、批量导入导出、报表与配置类运营。
- 若近期不做 Web 工程，可先把 P1/P2 的新功能做进 PySide6，数据库与 API 保持一致，后续 Web 直接复用。

### 4.8 SDK：先出协议规范与测试向量，再写 5 门语言

- 可文档化：请求 HMAC-SHA256 规范串（`SQCLIENT-REQUEST-2`）、响应 Ed25519 规范串（`SQSERVER-RESPONSE-2`）、头字段、base64url/hex 规则、时间窗、查询串签名。
- 需要治理：协议版本协商、统一错误码枚举（当前 HTTP 200 + `code` 与 HTTP 4xx 混用）、响应公钥轮换与 `key_id`、跨语言测试向量、时间语义（建议 Unix 时间戳替代本地无时区字符串）。
- 文档缺陷：README 声称 activate 也需客户端签名，但实际激活时尚无会话密钥、服务端也不校验，第三方照文档实现会误判。

---

## 5. 数据模型与接口改造草案

### 5.1 新增/变更表（建议）

| 域 | 表 |
|---|---|
| 账号 | `admins` 加 email/email_verified_at；`admin_action_tokens`；`portal_accounts`；`portal_account_licenses`；`portal_sessions`；`email_verification_codes` |
| 邮件 | `email_templates`；`email_queue`（或统一 outbox）；`notification_channels`；`notification_outbox` |
| 模板/旗标 | `license_templates`；`features`；`license_features` |
| 席位/订阅 | `seat_leases`；`subscriptions`；`subscription_jobs` |
| 渠道 | `resellers`；`reseller_orders`；`commission_ledger`；`licenses.partner_id/order_id` |
| 事件 | `domain_events`；`webhook_subscriptions`；`webhook_deliveries`；`idempotency_keys` |
| 告警/风控 | `alert_rules`；`alert_events`；`metric_samples`；`risk_events` |
| 迁移 | `schema_migrations(version, applied_at)` |

### 5.2 新增接口（建议清单）

- 管理员/门户账号：`POST /api/admin/email/send_code|verify`、`POST /api/admin/password/forgot|reset`、`POST /api/portal/auth/register|login|logout|refresh`、`GET /api/portal/auth/me`、`POST /api/portal/auth/password/forgot|reset`。
- 告警/指标：`GET/POST /api/alerts/rules`、`PUT/DELETE /api/alerts/rules/{id}`、`GET /api/alerts/events`、`POST /api/alerts/events/{id}/ack`、`GET /api/metrics/overview|timeseries`。
- 在线/席位：`GET /api/online`、`POST /api/licenses/{key}/seats/{activation_id}/release|kick`。
- 风控：`GET /api/risk/events`、`GET/POST /api/risk/rules`、`GET/POST/DELETE /api/risk/blocklist`。
- 通知：`GET/POST /api/notification/channels`、`POST /api/notification/channels/{id}/test`、`GET /api/notification/deliveries`。
- Webhook：`GET/POST /api/webhooks`、`PUT/DELETE /api/webhooks/{id}`、`GET /api/webhooks/{id}/deliveries`。
- 模板/导入：`GET/POST /api/license/templates`、`POST /api/license/import`（分片/任务）、`GET /api/tasks/{id}`。
- SDK：`docs/protocol-v1.md` + `docs/sdk-test-vectors.json`（跨语言契约测试基线）。

### 5.3 代码结构建议（保持现有模块风格，先拆服务层）

```
server/
  services/          # 领域服务：许可证、账号、告警、订阅（API 与 AI 工具共用唯一写入口）
  jobs/              # lifespan 后台任务：outbox worker、告警评估、订阅调度、过期清理
  channels/          # email / webhook / dingtalk / wecom / feishu 适配器
  alerts/            # 规则引擎、指标聚合
  mailer.py          # SMTP 传输与模板渲染
core/
  portal_db.py       # 门户账号与许可证关系（避免 database.py 继续膨胀）
  migrations.py      # 版本化迁移
docs/
  protocol-v1.md     # 客户端/SDK 协议规范
```

---

## 6. 必须顺带修复的既有问题

| 优先级 | 问题 | 位置 | 建议 |
|---|---|---|---|
| 高 | 工作区 `server_config.json` 含明文私钥 | server_config.json | 立即轮换 secret_key 与两组 Ed25519 密钥；分发包不含私钥；把主密钥移出代码目录 |
| 高 | 64KB 请求体上限 + 全量缓冲 | `server/api.py` | 导入走流式/分片专用通道 |
| 高 | 读路径调用 `sweep_expired()` 写库 | `core/database.py` | 拆为后台定时任务，或先做候选行快速判断 |
| 高 | nonce 清理用客户端时间戳 | `server/api.py` | 改用服务端时间，消除超前时间戳导致 nonce 提前删除 |
| 高 | 反代下 IP 失真 | `server/api.py` | 可信代理配置下解析 `X-Forwarded-For`，否则风控告警无意义 |
| 高 | AI 任务未校验归属 | `server/ai_gateway.py` | 任务记录 operator_id，读取强校验；写入工具加确认 |
| 中 | 时钟回拨记忆重启丢失 | `core/config.py` / `verification/ui.py` | `offline_last_seen_ts` 入白名单并持久化，或改短期离线租约 |
| 中 | 离线回退无宽限期 | `verification/ui.py` | 离线码加"最近在线 + 宽限"或服务端短期租约 |
| 中 | 客户端公钥可被替换 | `verification_config.json` | 公钥指纹内置/双位置校验；配置机器绑定 HMAC |
| 中 | CI 漏跑 pytest 用例 | `.github/workflows` | 显式安装并运行 pytest |
| 低 | 依赖未锁版本、exe 体积偏大 | requirements.txt / build.py | 锁定版本；服务端专用依赖不进客户端 EXE |

---

## 7. 分阶段路线图（1 名熟悉本项目的工程师粗估）

| 阶段 | 内容 | 依赖 | 估时 |
|---|---|---|---|
| P0 底座与安全 | schema_migrations、私钥轮换、索引（含 last_heartbeat_at）、读路径减写、outbox 基座、领域服务层收口写操作、修复第 6 节高优先级问题 | — | 1~2 周 |
| P1 账号与邮件（你的主线） | A1~A4：管理员邮箱/验证/找回、门户账号与验证端邮箱登录、SMTP 模板/队列/重试、投递记录 UI | P0 | 4~6 周 |
| P2 告警与风控 | A5~A7：指标与在线口径、告警规则/事件/冷却、风控事件与分级动作、邮件优先 + Webhook/钉钉/企微/飞书 | P1（邮件/outbox） | 2~3 周 |
| P3 运营增强 | B1~B6：模板、批量导入导出、功能旗标、浮动席位、订阅自动化、离线增强 | P0；B5 依赖邮件 | 3~5 周 |
| P4 平台化 | B7~B10：Web 后台、代理商分级、公开事件总线/Webhook、多语言 SDK | P1~P3 的数据与接口稳定 | 5~8 周+ |

里程碑建议：
- M1：管理员可用邮箱找回密码，验证端可邮箱登录，邮件可查投递状态。
- M2：告警规则可配置，阈值/风控触发能发出邮件与 Webhook，并有告警事件列表。
- M3：运营侧完成模板、批量、旗标、席位、订阅、离线增强。
- M4：Web 后台 + 渠道 + SDK 对外可用。

---

## 8. 建议的最终产品形态

- **服务端**：单写者 FastAPI（SQLite + WAL），lifespan 内跑 outbox worker、告警评估、订阅调度；对外保留 `/api/...`，逐步补 `/v1` 与 OpenAPI 契约。
- **桌面端**：保留高权限、低频、本机操作（服务启停、备份恢复、密钥生成、管理员管理）。
- **Web 后台**：仪表盘、实时在线、批量导入导出、报表、配置类运营（模板/旗标/席位/订阅/告警/渠道/Webhook）。
- **验证端**：双模式（邮箱登录 / 激活码），离线交付支持文本 + 二维码 + 签名文件；离线租约与宽限期明确。
- **SDK**：以协议规范 + 测试向量为基线，先 Python/JS，再 Go/.NET/Rust。
- **AI 助手**：从"能直接改数据"演进为"查询默认开放、写入显式确认"，接入告警摘要与异常分析的结构化数据。

---

## 9. 待确认问题（影响方案与工作量）

1. 验证端邮箱登录后，"账号"与"许可证/激活码"是什么关系？一个邮箱可绑定多个 Key，还是一个账号一份订阅？老用户如何迁移？
2. 邮件告警的收件人是谁：超级管理员、普通管理员、终端用户，还是按规则分别配置？
3. 风控触发后是"只告警"还是"自动冻结/封禁"？虚拟机检测的误伤容忍度与合规边界是什么？
4. 部署形态：继续单机单进程 SQLite，还是准备上服务器（多用户/反向代理/HTTPS）？这决定 Web 后台、多 worker 与数据库选型。
5. Web 后台是替代桌面端还是并存？若是并存，谁是主操作面？
6. "自动续费"是指自动延期，还是要对接支付渠道？
7. 代理商返佣是否需要结算账务/对账/发票，还是只做统计展示？
8. 是否接受在 P0 先做底座重构（迁移框架、服务层、outbox）？跳过它会显著增加后续返工。

---

## 10. 关键证据索引

- 数据模型与迁移：`core/database.py`（SCHEMA 13-85、MIGRATIONS 88-108、`_migrate` 185-192、`activate_atomic` 876-1014、`stats` 1173-1201）
- 服务端接口与风控：`server/api.py`（路由 674-1355、登录 696-753、告警相关缺失、限流 33-115、客户端端点 1194-1355）
- 客户端协议与签名：`core/security.py`（请求签名 341-420、响应签名 423-452）、`core/api_client.py`（190-224、545-582）
- 验证端与离线：`verification/ui.py`（UI 175-198、离线 325-500、心跳 549-661）、`core/offline.py`（171-243）、`core/machine.py`（8-75）
- 管理端 UI：`master/ui.py`（管理员页 74-198、导航 248-272）、`core/pages.py`（生成页 404-528、表格/导出 135-250、批量 976-1147）
- 测试与打包：`tests/`、`.github/workflows/python-package-conda.yml`、`build.py`、`requirements.txt`
- AI 子系统：`server/ai_gateway.py`、`server/ai_tools.py`、`core/ai_page.py`

---

*本文档为分析稿，尚未做任何代码改动；确认优先级与第 9 节问题后，可据此拆分为可执行的迭代计划。*

---

## 11. 需求决策记录（第二轮确认，2026-10-06）

| 原问题 | 你的答复 | 设计含义 |
|---|---|---|
| 验证端邮箱与 Key 的关系 | 一个邮箱同一时间只绑定一个 Key；Key 失效后可选择续费或直接脱绑；订阅失效后可重新订阅 | 门户账号与许可证是 **1:1 当前绑定 + 历史绑定记录**；需要绑定/续费/脱绑/重绑四个状态流转，全部写审计 |
| 告警收件人 | 发件方是主控端/管理端；收件人是验证端绑定的邮箱；配置方式由系统设计 | 收件人按“触发规则所涉 Key 的绑定邮箱”解析；支持按规则附加 CC 管理员；SMTP 配置只在服务端 |
| 风控动作 | 检测到新硬件码或 IP 频繁跳动：直接封禁 + 告警；IP 跳动超过 2 次自动告警 | 风控策略引擎按事件类型配动作（freeze/revoke/alert）；默认策略：新硬件码 = 冻结+告警，IP 跳动 > 2 次 = 告警（可选降速） |
| 部署形态 | 先维持单机 SQLite，服务器部署未定 | 保持 workers=1、SQLite outbox + 单 worker；不引入 Redis/Celery/PostgreSQL，Web 后台方案推迟 |

### 11.1 邮箱 ↔ 许可证绑定状态机

- 表：`portal_accounts`（email 唯一）、`portal_account_licenses`（account_id ↔ license_id 当前绑定，UNIQUE(account_id)、UNIQUE(license_id)）、`portal_binding_history`（绑定/脱绑/续费/重绑审计）。
- 状态：`unbound`（账号未绑 Key）、`bound`（已绑定且有效）、`expired`（Key 失效待选择）、`unbound_by_user`、`unbound_by_admin`、`revoked`。
- 流转：
  - 绑定：邮箱的当前 Key 为空 + Key 可用 + 设备占用校验通过 → 建立绑定；否则拒绝并提示先脱绑/续费。
  - 续费：Key 过期/冻结 → 续费保持绑定（复用现有 `/api/license/renew` 的语义，但要带绑定关系校验）。
  - 脱绑：建议只允许对已过期/已吊销/次数用尽的 Key 自助脱绑；有效 Key 脱绑需管理员操作，防止绕过设备限制。
  - 重绑：脱绑后账号可绑定另一枚可用 Key；历史记录保留，便于风控与客服追溯。

### 11.2 告警收件人解析

- 发件：主控端/管理端配置的 SMTP（服务端保存，凭据加密）。
- 收件：`license_id → portal binding → portal_accounts.email`；若 Key 未绑定邮箱，则退化为配置中的管理员兜底收件人。
- 规则可覆盖：`alert_rules.channels_json` 指定渠道；`recipients_mode` 支持 `bound_user` / `admins` / `both`。
- 告警模板变量：Key（脱敏显示）、设备名、机器码前缀、IP、事件类型、时间、建议动作。

### 11.3 风控判定细节

- 新硬件码：现有 `activate_atomic` 在 `max_devices` 用尽时返回 `limit`；改造为发出 `machine_mismatch` 事件，按策略冻结许可证（保留一键解冻/换绑），并向绑定邮箱与管理员发告警。
  - 误杀提示：换网卡、重装系统、虚拟机迁移都会造成机器码变化。你的策略是直接封禁，实现上按此默认，但必须提供管理员解冻/人工换绑入口，并记录 `freeze_reason=machine_mismatch`。
- IP 跳动：在 `activations` 增加 `last_ip`，新增 `activation_ip_events` 记录 IP 变化；定义“跳动”为同一 Key 在时间窗内（建议 10 分钟）IP 的 /24 或 ASN 发生变化。
  - 计数：窗口内变化次数 > 2 → 自动告警；若启用，可叠加降速或冻结。
  - 反代环境必须先修 `X-Forwarded-For` 解析，否则所有 Key 的 IP 都是代理地址。
- 需要保住“误伤可申诉”：告警正文带事件 ID，管理员可在后台一键解冻并备注。

---

## 12. 新增需求 C1：EXE 与发布目录完整性自校验

### 12.1 目标与验收

- 四个 EXE（本地服务器/管理端/验证端/主控端）启动时校验自身与发布目录完整性。
- 判定对象：EXE 本体、发布目录受保护文件、关键资源；文件被修改、被截断、被追加、被替换、缺失或多出受保护文件都算不一致。
- 不一致的动作：本地弹窗（错误码 + 判定对象）→ 拒绝激活/校验/心跳等一切授权操作 → 写本地日志 → 尝试上报服务端 → 服务端记录并邮件告警。
- 目标不是“绝对防破解”，而是：挡住常规篡改、让脱壳改码成本显著升高、把最终裁决权放到服务端。

### 12.2 必须先知道的技术边界

1. 客户端文件一旦交到用户手里，就可以被复制、反汇编、修改；**不存在 100% 无法破解的本地程序**。
2. 当前是 PyInstaller `--onefile`：EXE 本质是自解压归档，现成的 pyinstxtractor 类工具可以提取，`.pyc` 可以反编译，Python 本地自检代码也可以被打补丁跳过。
3. 因此纯 Python 自检只能作为“第一道闸门”；真正的防线是：本地自检提高门槛 + 服务端 attestation 拒绝未知版本 + 关键逻辑与密钥不下发到客户端。
4. 自哈希有“自引用”问题：不能把最终 EXE 的哈希写进 EXE 自己。解决方式是外部签名清单或服务端登记哈希，而不是把哈希硬编码进被校验的文件。

### 12.3 分层方案

**第 1 层：构建期生成签名清单（C1a）**

- `build.py` 构建完成后生成 `release_manifest.json`：版本、构建时间、每个受保护文件的相对路径、大小、SHA-256；以及 EXE 本体的 SHA-256。
- 用独立的发布签名密钥（Ed25519，与现有离线签名/响应签名密钥分开）对清单生成 `release_manifest.sig`。
- 清单 + 签名随发布目录分发，同时把各版本 EXE 哈希写入服务端 `release_hashes` 表（支持多版本、灰度、回滚）。

**第 2 层：启动期本地自检（C1b/C1d）**

- 自身 EXE 哈希：计算当前运行 EXE 的 SHA-256，与已签名清单/服务端登记值比对。
- PE 结构检查：节表、节数量、入口点范围、overlay 大小、文件大小；用于发现追加数据、删减节、替换入口等。
- PyInstaller 归档自检：`build.py` 已在使用 `CArchiveReader`，可在客户端解析自身 CArchive 的目录项，与清单中的条目长度/哈希比对。
- 目录完整性：校验受保护文件集合的哈希 + 检测缺失 + 检测多出的受保护文件；`config/`、`data/`、`logs/`、`__pycache__/` 等运行时可变路径加入白名单，不参与“多出文件”判定。
- 代码签名：若购买 Authenticode 证书，用 WinVerifyTrust 校验并对发布者指纹做固定比对。
- 调试器/注入检查（IsDebuggerPresent、PEB 标志、硬件断点、时间异常）只作为风险信号上报，不建议单独作为拒绝理由，误报率较高。

**第 3 层：服务端 attestation（C1c，关键）**

- 新增 `POST /api/client/attest`：上报 `exe_hash + version + machine_code + nonce + 本地自检结果`。
- 服务端与 `release_hashes` 白名单比对，通过后签发短期 `attest_token`（例如 10 分钟）。
- `activate / verify / heartbeat` 必须携带有效 `attest_token`；不在白名单的客户端直接拒绝，并记录 `tamper_events` + 邮件告警。
- 这是最重要的一层：即使攻击者把本地自检 patch 成“永远通过”，只要他修改后的 EXE 哈希不在服务端白名单，授权操作仍然被拒绝。

**第 4 层：运行期抽查（C1d）**

- 启动时全量校验一次；运行期由后台线程每 10~30 分钟复核一次清单/overlay 关键部分，避免“启动后替换文件再重启”或“先通过再篡改”。
- 心跳携带 `attest_token` 刷新；token 过期前必须重新 attest。
- 55MB 的 EXE 全量 SHA-256 约百毫秒级，启动时可接受；运行期建议只做轻量抽查，不必每次心跳全量哈希。

### 12.4 不一致时的响应策略

| 场景 | 动作 |
|---|---|
| 本地 EXE/目录不一致 | 弹窗（错误码、哪个文件、期望/实际哈希前缀）→ 拒绝所有授权操作 → 写本地日志 → 上报服务端 |
| 服务端白名单不匹配 | 直接拒绝 attest/activate/verify/heartbeat → 写 `tamper_events` → 邮件告警 → 通知管理员 |
| 目录缺失文件 | 视为篡改；若缺失的是可再生成文件（缓存/临时），白名单放行 |
| 目录多出受保护文件 | 视为篡改；运行时生成目录不参与判定 |
| 校验通过后运行期再被替换 | 抽查发现后立即终止会话并要求重启验证 |

建议本地行为：直接退出程序（或停留在“完整性校验失败”页），不要只弹窗后继续运行。

### 12.5 防误杀清单

- 防护软件修改、系统更新、用户从压缩包解压、PyInstaller 临时目录差异，都可能触发误报。
- 只校验“受保护清单”；配置、数据库、日志、缓存目录必须白名单。
- 版本升级时先注册新哈希，再发布；支持灰度与回滚，避免旧版本突然被服务端全部拒绝。
- 失败提示带错误码与支持渠道提示，便于客服定位是篡改还是环境问题。

### 12.6 工程量与建议优先级

| 子项 | 内容 | 规模 |
|---|---|---|
| C1a | 构建清单 + Ed25519 发布签名 + 服务端版本哈希登记 | S（1~2 天） |
| C1b | 客户端启动自检（EXE + 目录）+ 弹窗 + 拒绝 + 上报 | M（2~4 天） |
| C1c | 服务端 attestation + 白名单 + tamper 告警 | M（2~3 天） |
| C1d | CArchive/PE/Authenticode/运行期抽查 | M（2~3 天） |
| C2 | 高级加固：Nuitka/PyArmor 编译、原生引导层、反调试 | L（1~2 周+，注意 PySide6 兼容与误报） |

建议顺序：先 C1a + C1b + C1c（覆盖“文件多了少了被改了 → 拒绝 + 弹窗 + 告警”的日常篡改），再 C1d，最后视破解压力决定是否上 C2。

### 12.7 与现有架构的结合点

- `build.py`：已有 `CArchiveReader` 检查，扩展为构建后生成清单与签名。
- `server/api.py`：新增 `/api/client/attest`；在 activate/verify/heartbeat 增加 attest 校验依赖。
- `core/security.py`：复用 Ed25519 验签能力；发布签名密钥与服务端离线私钥分开管理。
- `verification/ui.py` / 其他端启动入口：启动时先跑完整性检查，失败即拦截。
- `server/outbox` 与告警引擎：tamper 事件作为告警源，走邮件/Webhook 通知。

---

## 13. 路线图更新（加入 C1 与第二轮决策）

| 阶段 | 新增内容 |
|---|---|
| P0 底座 | schema_migrations、私钥轮换、索引与读路径减写、outbox 基座、服务层收口；纳入 C1a 与 C1c 的基础设施 |
| P1 账号与邮件 | 管理员邮箱/验证/找回、门户账号与验证端邮箱登录（1 邮箱 : 1 Key + 历史记录）、SMTP/outbox/投递记录；纳入 C1b |
| P2 告警风控 | 告警规则/事件/冷却、新硬件码冻结+告警、IP 跳动 > 2 次告警、邮件优先 + 四渠道；纳入 C1d 与 tamper 告警 |
| P3 运营增强 | B1~B6 不变 |
| P4 平台化 | B7~B10 不变；部署形态确定后再决定 Web 后台与多 worker 方案 |

*第二轮决策已记录。C1 的边界与分层方案见第 12 节；下一步可选择“先做 C1 自校验”或“先做 P0+P1 账号与邮件主线”。*

---

## 14. 实施状态：C1 Batch 1 已完成（2026-10-07）

| 子项 | 状态 | 落地内容 |
|---|---|---|
| C1a 构建清单 + 签名 | 已完成 | `build.py` 打包前固定 Ed25519 发布公钥；打包后生成 `dist/release_manifest.json` + `.sig` 与 `dist/releases/` 副本；私钥在 `release_keys/release_key.json`（已 gitignore，需离线备份）；`tools/release_manifest.py` 可单独重签 |
| C1b 客户端启动自检 | 已完成 | `core/integrity.py`：开发模式跳过；frozen 校验自身 exe 哈希与大小；server 角色校验全部 `required_apps`；其它角色自检 + 已存在的其它 app 一致性；顶层多余 `.exe/.dll` 检测；失败弹窗 + `integrity_tamper.log` + 尽力上报 + 退出；四个 `main.py` 已接入 |
| C1c 服务端 attest | 已完成 | `release_hashes` / `tamper_events` 两张表；`POST /api/client/attest`、`POST /api/client/integrity_report`；`activate/verify/heartbeat` 在 auto 模式（白名单非空）强制 `X-Attest-Token`，403 固定文案；`GET /api/release/list`、`POST /api/release/import`（master 验签）、`POST /api/release/status`、`GET /api/tamper/events`；服务器启动自动导入 `releases/` 清单 |

验证证据：

- 全量测试 `218 passed + 3 subtests`（原 164 基线无回归）。
- `python build.py` 重新打包四个 exe，并生成签名清单（公钥指纹 `24f5a721...`）。
- `python tools/verify_integrity_e2e.py` 通过：清单验签与四 exe 哈希核对、正常 frozen 服务器放行、缺清单/多出 exe/被篡改 exe 三类拒绝、真实沙箱服务器 attest 签发、无 token 403、有效 token 放行、未知哈希落库，退出码 0。

尚未包含：

- 邮件告警依赖 P1 邮件引擎；当前告警形态为本地弹窗 + `integrity_tamper.log` + 服务端 `tamper_events` + 审计日志。
- C1d（PE 节表/CArchive/Authenticode/运行期抽查）与 C2（Nuitka/PyArmor/原生引导）未做。

---

## 15. 实施状态：P1 已完成（2026-10-07）

| 需求 | 状态 | 落地内容 |
|---|---|---|
| A1 管理员邮箱 + 验证 | 已完成 | `admins.email/email_verified_at`、`action_codes` 验证码表；`/api/admin/email/set|verify`；主控端管理员管理新增邮箱/验证状态列与设置入口 |
| A2 邮箱找回密码 | 已完成 | `/api/admin/password/forgot|reset`；登录框"忘记密码"对话框；重置后 `auth_version+1` 使旧令牌失效 |
| A3 验证端邮箱登录 | 已完成 | `portal_accounts` / `portal_account_licenses` / `portal_binding_history`；注册/登录/me/绑定/脱绑/续费请求；验证端"邮箱登录 / 激活码"双模式 UI；**1 邮箱同一时间只绑定 1 个 Key**；有效 Key 禁止自助脱绑 |
| A4 邮件引擎 | 已完成 | `server/mailer.py` + `email_templates` / `email_outbox`；SMTP 配置界面；后台 worker（5 秒轮询）、指数退避重试（最多 5 次）、dead 终态；6 个内置中文模板 |
| A6 风控触发（核心） | 已完成 | 新硬件码抢占已满设备位 → 冻结 Key + 高等级告警；同一 Key 10 分钟内超过 2 个 IP 网段 → 告警；阈值在 `security.ip_jump_*` 配置 |
| A7 通知渠道（邮件） | 部分完成 | 邮件渠道已完整；收件人 = 绑定邮箱 + `smtp.alert_admin_emails` + 已验证管理员邮箱；Webhook/钉钉/企微/飞书适配器未做 |

验证证据：

- 全量测试 `290 passed + 3 subtests`（含新增邮件/账号/UI/风控用例）。
- `python tools/verify_mail_e2e.py`：内置假 SMTP，注册验证码 → 注册 → 管理员邮箱验证 → 忘记密码重置 → 门户绑定 → 有效期脱绑 409 → 续费邮件；队列统计 `sent=6, failed=0, dead=0`。
- `python tools/verify_integrity_e2e.py`：重新打包后完整性/attest 全链路仍通过，公钥指纹 `24f5a721...`。
- 重新打包四个 exe（服务器 57.4MB，其余 52.6MB）。

尚未包含：

- A5 可配置告警规则引擎与 A7 非邮件渠道适配器（当前为内置策略 + 邮件）。
- 邮件模板编辑 UI（模板已入库，暂需 SQL 修改）。
- SMTP 配置保存后需重启服务器生效。
- 续费未接支付：用户在验证端发"续费请求"，邮件通知用户与管理员，管理员手动续期。
- 管理员"设置邮箱"目前作用于当前登录账号；对其它管理员逐行设置需后端加 `admin_id` 参数。
- C1d 与 C2 加固仍待安排。

---

## 16. 实施状态：A5 + A7 已完成（2026-10-08）

| 需求 | 状态 | 落地内容 |
|---|---|---|
| A5 可配置告警规则 | 已完成 | `alert_rules` / `alert_events` 表；7 指标（激活率、在线并发、过期率、7 天内到期、激活失败、风控事件、完整性告警）；规则 CRUD API；`AlertEngine` 30 秒轮询、事件 firing/acked/resolved 生命周期、冷却防抖、指标恢复自动 resolved；`alert_rule` 邮件模板 |
| A5 告警中心 UI | 已完成 | `core/alert_center.py`：7 指标卡片 + 规则表格/编辑对话框 + 事件表格/确认/标记已处理 + 15 秒自动刷新；管理端与主控端导航注册 |
| A7 多渠道通知 | 已完成 | `notification_channels` / `channel_outbox` 表；Webhook / 钉钉 / 企微 / 飞书适配器；Webhook HMAC-SHA256 签名头、钉钉/飞书官方加签；`ChannelDispatcher` 5 秒轮询 + 指数退避 + dead 终态；渠道 CRUD/测试/投递记录 API |
| A7 渠道 UI | 已完成 | 告警中心新增"通知渠道"标签页（渠道 CRUD/测试/投递记录）；规则对话框支持邮件 + 多个 `channel:<id>` 多选 |
| 规则渠道派发 | 已完成 | 引擎按规则渠道派发：邮件入 `email_outbox`，其它渠道入 `channel_outbox`；任一入队成功即标记事件 notified |

验证证据：

- 全量测试 `344 passed + 9 subtests`。
- `python tools/verify_channels_e2e.py`：规则触发 → channel_outbox → 真实 HTTP 投递 → HMAC 签名一致 → 投递状态 sent → 事件 notified=1，全部通过。
- `python tools/verify_mail_e2e.py`：注册/登录/找回密码/绑定/续费 + A5 规则触发邮件，队列 `sent=8, failed=0, dead=0`。
- `python tools/verify_integrity_e2e.py`：最终打包产物完整性/attest 全链路通过，公钥指纹保持 `24f5a721...`。
- 四个 exe 已重打包（服务器 57.4MB，其余各 52.6MB）。

下一步（P2 运营增强）：B1 密钥模板、B2 批量导入导出、B3 功能旗标、B4 浮动/并发席位、B5 订阅周期自动化、B6 离线激活增强；C1d/C2 按需安排。

---

## 17. 缺陷修复批次完成（2026-10-08）

| 问题 | 状态 | 修复内容 |
|---|---|---|
| 1 验证端资料（头像/名称/邮箱） | 已修复 | `portal_accounts` 增加 `display_name/avatar_mime/avatar_data`；profile/avatar API；验证端登录后显示头像（失败回退首字母）、显示名、邮箱；"编辑资料"支持改名与上传/移除头像（≤256KB，png/jpg/webp） |
| 2 服务端卡顿 | 已修复 | 统计 `stats_cached` 5 秒缓存；`sweep_expired` 60 秒节流；补 4 个热点索引；邮件/渠道 worker 空队列预检不再抢写锁；nonce 清理节流；服务器界面刷新 3 秒→10 秒、日志 100→50 条 |
| 3 发布文件可被篡改利用 | 已修复 | 每次构建生成 `release_id` 并内嵌；清单携带 release_id 参与签名；attest 校验 release_id + manifest sha256，混用/替换清单判 `release_mismatch` 并写 tamper_events；启动导入与 API 导入统一写 `release_meta` |
| 4 验证端脱离文件运行 + 嵌入第三方 | 已修复 | 验证端缺两文件时进入 standalone（不弹窗不退出），文件存在但篡改仍失败；新增 Python SDK `sdk/sq_license_client.py`（激活/校验/心跳/离线码，不依赖配置与清单）+ 接入文档与示例；SDK 请求带 `X-Client-Kind: sdk`，默认豁免宿主 exe 白名单（HMAC/设备绑定/响应验签仍生效） |
| 5 管理端/主控端界面区分 | 已修复 | 窗口标题与角色徽标区分（管理端=密钥运营，主控端=系统管理）；导航确认管理端无"管理员管理/系统设置"，主控端有；侧栏分组与主色不同；新增测试断言导航差异 |
| 6 邮箱注册用户没有管理界面 | 已修复 | 新增用户管理：DB/API（列表/搜索/状态/强制脱绑）+ `core/user_admin.py` 页面，管理端与主控端导航都注册"用户管理" |

验证证据：

- 全量测试 `410 passed + 12 subtests`。
- 性能基准 `tools/bench_server.py`：500 许可证 + 200 设备下，`stats_cached` 平均 0.01ms（`stats` 0.19ms）、心跳 0.08ms、列表 0.41ms、日志 0.02ms，无 >100ms 抖动。
- `tools/verify_integrity_e2e.py`：清单 release_id 绑定、standalone、篡改拒绝、attest 全链路通过。
- `tools/verify_channels_e2e.py`、`tools/verify_mail_e2e.py`（sent=8 / failed=0 / dead=0）通过。
- 四个 exe 已重打包（服务器 57.4MB，其余 52.6MB），发布标识 `1d537332baff0add46aadc2e892807dd`。

已知取舍与遗留：

- SDK 嵌入第三方宿主程序时无法进入发布白名单，默认 `security.sdk_attest_exempt=true`；如要提高门槛可关闭该开关，并让宿主程序自行携带 attest token。
- 头像内嵌在 login/me 响应中传输（≤256KB 原图，base64 后约 342KB）；后续量大可改为独立头像端点。
- 窗口标题变更会让老用户首次启动丢失一次性窗口位置记忆（QSettings 键名变化），可接受。
- `build/smoke/*.png` 等推广截图仍是旧导航，需要时重跑 `tools/smoke_windows.py` / `tools/render_pages.py`。
- P2 运营增强（模板/批量/旗标/席位/订阅/离线增强）按用户要求暂缓，缺陷修复期间未推进。
