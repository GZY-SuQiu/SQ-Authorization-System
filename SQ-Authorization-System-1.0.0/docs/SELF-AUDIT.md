# 对抗性自查与修复记录（2026-10-08）

> 背景：用户要求"自己否定自己的项目"。本轮做了一次对抗审计（假设作者过于自信，
> 专门找崩溃、数据损坏和安全问题），并修复了其中可直接落地的项；延期项留了
> 明确的实施计划。

## 已修复

| 编号 | 问题 | 修复 | 证据 |
|---|---|---|---|
| P0-1 | 仓库与 dist 内带服务器私钥、HMAC 密钥、发布签名私钥，可伪造令牌/离线码/响应/发布清单 | 旧密钥与配置**整体移出**到 `backup_secrets_20261008/`（不入库，已 gitignore）；`python build.py` 会重新生成 secret_key、offline/response 密钥对与 release 密钥；发行包卫生检查禁止任何 config/db/私钥进入 | `tools/release_manifest.py` 的 `assemble_release_package/verify_release_package`；build 输出新指纹 |
| P0-2 | `dist/admin_config.json` 钉死的响应公钥与服务器不一致，管理端登录必失败 | 发行包不再携带任何 `*_config.json`，客户端首次运行生成空配置并在登录后固定服务端公钥；`ApiClient.set_base_url` 更换服务器时清空已固定公钥与会话 | `tests/test_hardening_guards.py::BaseUrlSwitchTests` |
| P0-3 | `dist/data/license.db`（含开发机 master 账号与 200 张卡密）被打包分发 | 发行包只包含 4 个 exe + 签名清单 + `releases/`；原 dist 数据移入备份目录；构建时卫生检查发现 `.db`/config 直接失败 | build.py 发布包步骤 |
| P1-4 | `X-Client-Kind: sdk` 一个头即可绕过完整性和白名单 | 默认关闭 `sdk_attest_exempt`；开启后仍必须配置 `sdk_shared_secret` 并携带 `X-SDK-Token = HMAC(secret, machine_code)`；豁免放行写审计日志 | `tests/test_sdk_attest_exempt.py`（3 例） |
| P1-5 | outbox 领取后崩溃，行永久卡在 `sending`，验证码/重置邮件丢失；"发送成功但落库失败"会被重试导致重复发送 | `email_outbox`/`channel_outbox` 增加 `claimed_at` 租约；领取条件回收超过 5 分钟的 `sending`；投递成功与状态落库拆分，落库失败不再触发重发 | `tests/test_outbox_recovery.py`（3 例） |
| P1-8 | worker `stop()` 超时后丢弃引用，`start()` 又清 stop 事件，导致双 worker 重复投递 | `AlertEngine`/`ChannelDispatcher` 每次 run 独立 stop 事件；只有线程真正退出才释放引用 | `tests/test_alert_channels.py::DispatcherLifecycleTests` |
| P1-12 | 头像只校验 MIME 与字节数，极小文件可声明巨大像素（解码炸弹） | 新增 `core/image_guard.py`：校验 PNG/JPEG/WebP 魔术字节与头部尺寸，拒绝 >4096×4096 或 >16MP | `tests/test_image_guard.py`（4 例） |
| P2-16 | 渠道 URL 可指向内网/元数据地址（SSRF） | 默认拒绝字面 IP 的 private/loopback/link-local/reserved 与 localhost/.local；内网 Webhook 需显式 `security.channel_allow_private_hosts=true`；域名不做同步解析（避免慢 DNS 阻塞） | `tests/test_hardening_guards.py::ChannelUrlGuardTests` |
| P2-17 | 审计日志可被换行/控制字符污染 | `Database.add_log` 统一剥离控制字符并限长（actor 64/action 64/target 128/detail 512/ip 64） | `tests/test_hardening_guards.py::AuditLogSanitizeTests` |
| P2-19 | SMTP 保存期不校验 SSL/STARTTLS 互斥与用户名/密码配对，坏配置进队列耗尽力重试 | 新增 `smtp_config_problem()`：保存时校验互斥、配对、发件人；同时修复 EHLO→AUTH 顺序、用户名缺省用发件邮箱、503/535/SSL 可读提示；**并修复 `socket.getfqdn()` 与本机反解析导致的每封邮件 12 秒阻塞**（显式 `local_hostname` + `make_msgid(domain=...)`） | `tests/test_mailer.py`（含 AUTH 假服务器与反向 DNS 禁用断言） |

其它修复：

- SMTP 配置改为**实时生效**：Mailer 保留配置字典引用，服务器界面保存后无需重启。
- 崩溃日志 `core/crashlog.py`：四个入口安装 excepthook/threading.excepthook/faulthandler/Qt 消息处理器，日志落 `crash_logs/`。
- 高频定时器护栏：服务器刷新、验证端心跳、日志页自动刷新异常只记日志不中断。

## 第二轮合题修复（2026-10-08，辩证审阅）

| 编号 | 状态 | 实现与证据 |
|---|---|---|
| P1-6 AI 写操作两阶段确认 | 已修复 | 9 个写工具默认返回 `pending_confirmation` + 120 秒 HMAC 确认令牌；`/api/ai/confirm|cancel`、operator 绑定、一次性消费、审计；客户端确认条。`tests/test_ai_confirmation.py`（18 例） |
| P1-7 AI 任务取消与有界退出 | 已修复 | 轮询 0.2 秒颗粒检查取消事件；`AIAssistantPage.shutdown()` + 窗口 Close 事件过滤器 + `aboutToQuit` 兜底；服务端 `_closing` + 有界退出。`tests/test_ai_cancel.py`（10 例） |
| P1-9 完整性修复通道 | 已修复 | `repair_manifest()` + 四个入口 `--repair-manifest <发布包目录>`：验签 + exe 哈希核对 + 原子写回 + 修复日志；哈希不符仍 fail closed。`tests/test_manifest_repair.py`（15 例） |
| P1-11 发布自动退役 | 已修复 | `release_auto_retire_old=true`：导入新清单时旧 `release_meta` 失效、旧 `release_hashes` 停用。`tests/test_maintenance.py` |
| P2-13 数据保留策略 | 已修复 | `run_maintenance()` 清理 7 类历史表；`MaintenanceWorker` 每 24 小时运行；`POST /api/maintenance/run`、`GET /api/maintenance/status`；保留天数可配置。`tests/test_maintenance.py`（15 例） |
| P2-14 日志检索与导出 | 部分修复 | `count_logs_cached`（30 秒、32 组筛选）降低 UI 周期开销；FTS5/keyset 导出留待日志过十万级再做 |
| P2-15 告警指标缓存 | 已修复 | `evaluate_once` 按 `window_seconds` 每周期只算一次指标，同窗口规则共享 |
| P2-18 批量操作重入 | 已修复 | 忙碌标志 + `ApplicationModal` 进度框 + 执行期禁用主要按钮 + `try/finally` 复位。`tests/test_batch_guard.py`（7 例） |
| P2-19 SMTP 保存期校验 | 已修复 | `smtp_config_problem()`：SSL/STARTTLS 互斥、用户名/密码配对、发件人必填；坏配置拒绝保存 |

仍延期（有明确原因）：

- **巨石文件拆分**（api.py/database.py 等服务层重构）：需要专属阶段与契约测试，混合改动会放大回归面。
- **FTS5/keyset 全量替换**：当前规模不需要，先观察保留策略后的数据增长。
- **渠道域名的内网解析拦截**：为避免慢 DNS 阻塞创建接口而妥协，需部署侧配合或异步校验。
- **支付、多语言 SDK、代理商**：属于产品与外部依赖决策，不在本轮工程修复范围。

## 运维必读

- **对外只分发 `dist/release_package/`**，绝不整目录分发 `dist/`。
- 旧密钥与旧数据已移到 `backup_secrets_20261008/`（保留排查能力，切勿随包分发）。
- 轮换后已发出的授权/离线码需要重新签发；旧部署的管理端/验证端配置需删除后重新固定新公钥。
- `sdk_attest_exempt` / `sdk_shared_secret` / `require_manifest_hash` / `channel_allow_private_hosts` 均可在 `server_config.json → security` 调整。
