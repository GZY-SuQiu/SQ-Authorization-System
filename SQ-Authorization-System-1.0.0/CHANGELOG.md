# 更新与修复记录（2026-10-08 整合版）

> 本目录是 SQ-Authorization-System 的**新版整合**；仓库根目录里的原始 v1.0.0
> 源码与构建产物原样保留，未做任何改动。
>
> 构建标识：`release_id = 35dff5c915f1ae057d38db75dce380eb`；
> 发布公钥指纹：`6d45f73838f78a4fb98b9b1e18636842`；
> 测试基线：**524 passed + 12 subtests passed**（Windows / Python 3.13 / PySide6 6.11）。

---

## 一、本轮界面缺陷修复（Windows 深色模式）

| 问题 | 根因 | 修复 | 证据 |
|---|---|---|---|
| 服务器设置面板、验证端页面、AI 助手聊天区滚动时出现**整条黑色横带** | 滚动区的内容层背景是透明的（抓图采样 `#000000 alpha=0`）。滚动时 Qt 只重绘“新露出的条带”，透明层不落任何像素，深色系统主题下就是一条纯黑带；深层还叠着 `windows11` 原生风格按系统深色主题绘制的子控件 | 滚动区、视口（`#qt_scrollarea_viewport`）与内容层全部改为不透明页面底色；启动强制浅色 `QPalette`；Windows 下统一切换 `Fusion` 样式（`SQ_KEEP_NATIVE_STYLE=1` 可回退原生风格）；标题栏/边框用 DWM 强制浅色 | `tests/test_theme_dark_mode.py`（3 例）、`tools/dark_mode_sweep.py`（四端所有页面与滚动位置扫描无黑带） |
| 服务器 exe 运行时会额外挂着一个黑色控制台窗口 | 本地服务器是唯一以控制台模式打包的 exe（headless 需要控制台输出），GUI 模式也带着它 | 双击运行时隐藏自带控制台；从 cmd / Windows Terminal 启动时**不隐藏终端窗口**（按 `GetConsoleProcessList` 判断控制台是否独占）；`--show-console` 可强制保留 | `tests/test_winconsole.py`（4 例） |
| Qt 事件过滤器偶发异常连锁：`SystemError: Error calling Python override of QObject::eventFilter()` | 应用级过滤器会收到正在销毁的对象/事件（C++ 侧已释放）；另有一处过滤器在属性赋值前注册，收到早期事件即报错 | 主题窗口过滤器、Toast、表格空态提示的 `eventFilter` 全部加就地兜底；调整注册顺序 | 上述用例与全量测试回归 |

## 二、相较旧版新增的功能

### 1. 邮箱账号与邮件告警（P1）

- 管理员账号支持**邮箱绑定 + 验证码验证**与**找回密码**。
- 验证端支持**邮箱 + 密码登录**（与激活码登录并列，顶部可切换）；邮箱可注册、登录、找回密码、绑定并激活、校验、请求续费、脱绑、退出。
- 绑定规则：**一个邮箱同一时间只能绑定一个 Key**；Key 仍有效时禁止自助脱绑（409），过期/吊销/次数用尽后可自助脱绑并释放设备；Key 失效后可续费或脱绑重订。
- SMTP 引擎：主机/端口/账号/密码/发件邮箱/STARTTLS/SSL/超时，配置**保存即生效**；「发送测试邮件」直接给出可读错误原因；保存时校验 SSL 与 STARTTLS 互斥、用户名/密码成对、发件人必填。
- 邮件队列：所有通知写 `email_outbox`，后台 worker 每 5 秒投递，失败按指数退避重试（最多 5 次进 dead），不阻塞请求；`GET /api/email/outbox` 可查投递记录。
- 收件人：触发 Key 的绑定邮箱 + `smtp.alert_admin_emails` 管理员邮箱 + 已绑定并验证邮箱的管理员账号。

### 2. 告警中心与多渠道通知（A5 / A7）

- 管理端 / 主控端新增「告警中心」：告警规则、告警事件、通知渠道、投递记录四个页签。
- 7 个内置指标：激活率、在线并发、过期率、7 天内到期、激活失败、风控事件、完整性告警；可配置运算符、阈值、统计窗口、级别、冷却时间、通知渠道与启停。
- 事件三态（触发中 / 已确认 / 已处理）+ 指标恢复自动 resolved，同一规则同时只保留一个活动事件，冷却期内不重复触发。
- 通知渠道：Webhook / 钉钉 / 企业微信 / 飞书，增删改查、测试发送与投递记录；Webhook 自动附带 `X-SQ-Signature: sha256=<hmac>`，钉钉/飞书支持官方加签。
- 风控内置规则：**检测到新硬件码抢占已满的设备位 → 冻结该 Key + 邮件告警**；**同一 Key 10 分钟内出现超过 2 个 IP 网段 → 告警**（阈值可配 `security.ip_jump_window_minutes` / `ip_jump_alert_threshold`）。

### 3. 发布完整性与自校验（C1）

- 每次构建生成新的 `release_id` 并写入 Ed25519 签名清单；exe 必须与 `release_manifest.json`、`release_manifest.sig` 同目录。
- 校验失败（哈希不符、缺文件、目录里多出未登记的 `.exe/.dll`、签名不对）→ **弹窗 + 写 `integrity_tamper.log` + 拒绝启动**并尽力上报。
- 服务器启动时自动验签并导入 `releases/` 清单到发行白名单；`activate` / `verify` / `heartbeat` 必须携带 `X-Attest-Token`，未知或篡改客户端返回 403 并记入 `tamper_events` 与审计日志。
- `--repair-manifest <发布包目录>` 修复通道（验签 + 哈希核对 + 原子写回）；新清单导入自动退役旧版本（`release_auto_retire_old`）。

### 4. 用户资料、用户管理与 Python SDK

- 验证端邮箱模式显示头像、显示名与邮箱；「编辑资料」支持改名称、上传/移除头像（png/jpg/webp ≤256KB）。
- 管理端 / 主控端新增「用户管理」：搜索邮箱注册用户、查看绑定与许可证状态、启用/禁用、强制脱绑。两端界面已区分：**管理端 = 密钥运营**，**主控端 = 系统管理**（含管理员管理与系统设置）。
- 验证端**可脱离发布文件独立运行**（standalone 模式）：缺少清单/签名时进入该模式；文件存在但被篡改仍拒绝启动。
- Python SDK `sdk/sq_license_client.py`：在自研软件内嵌授权校验（激活 / 校验 / 心跳 / 离线码），不读配置文件、不依赖清单；文档 `docs/SDK-PYTHON.md`，示例 `examples/embed_license_demo.py`。

### 5. 其它体验与运维能力

- 验证端与管理端/主控端登录框新增 **「记住账号」「记住密码（Windows DPAPI 加密保存）」**；首次引导弹窗新增 **「复制账号」「复制密码」** 独立按钮。
- AI 助手写操作两阶段确认（120 秒 HMAC 确认令牌，一次性消费 + 审计）、任务取消与有界退出。
- 批量操作防重入：忙碌标志 + 模态进度框 + 执行期禁用主要按钮 + `try/finally` 复位。
- 数据保留策略：`run_maintenance()` 清理 7 类历史表，后台每 24 小时执行，保留天数可配；`POST /api/maintenance/run`、`GET /api/maintenance/status`。
- 崩溃日志 `core/crashlog.py`：四个入口安装 excepthook / threading.excepthook / faulthandler / Qt 消息处理器，日志落 `crash_logs/`。

## 三、安全加固

- 服务器私钥、HMAC 密钥、发布签名私钥、开发数据库**整体移出**仓库与 dist（`backup_secrets_20261008/`，不入库）；构建重新生成密钥，发行包卫生检查禁止任何 config/db/私钥进入。
- 不再整目录分发 `dist/`：修复了旧包里 `dist/admin_config.json` 公钥与服务端不一致（管理端必然登录失败）与 `dist/data/license.db` 泄漏开发数据（含 master 账号）的问题。
- SDK 完整性豁免默认**关闭**；开启后仍需 `sdk_shared_secret` 且携带 `X-SDK-Token = HMAC(secret, machine_code)`，豁免放行写审计日志。
- 通知渠道 URL 增加 SSRF 防护：默认拒绝字面私网/回环/链路本地/保留地址与 localhost，内网 Webhook 需显式 `security.channel_allow_private_hosts=true`。
- 头像解码炸弹防护（`core/image_guard.py`）：校验 PNG/JPEG/WebP 魔术字节与头部尺寸，拒绝 >4096×4096 或 >16MP。
- 审计日志统一剥离控制字符并限长；登录具备账号级与来源 IP 级双重限流，未知账号同样执行完整口令哈希。
- 口令使用 `PBKDF2-SHA256` 600,000 次迭代（兼容旧库 120,000 次哈希）；配置与数据库写入后尽力收紧本机访问权限。
- 邮件/渠道 outbox 增加 `claimed_at` 租约：崩溃后卡在 `sending` 的行 5 分钟后可回收；投递成功与状态落库拆分，避免“发送成功但落库失败”导致重复发送；worker 生命周期修复，避免双 worker 重复投递。

## 四、性能与稳定性

- 统计结果 5 秒缓存、过期扫描 60 秒节流、补齐热点索引；日志计数缓存（30 秒、32 组筛选）。
- 邮件/渠道 worker 空队列不再抢占写锁；服务器界面刷新从 3 秒改为 10 秒且只预览 50 条日志。
- 修复 `socket.getfqdn()` 本机反解析导致**每封邮件卡 12 秒**的问题（显式 `local_hostname` + `make_msgid(domain=...)`）。
- 修复 `503 need EHLO and AUTH first`：发送状态机严格按 EHLO →（STARTTLS 后重新 EHLO）→ AUTH → MAIL FROM 执行。
- 修复服务器界面定时刷新在数据库关闭后仍触发导致的报错。

## 五、验收与验证命令

```powershell
python -m pytest -q                          # 524 passed + 12 subtests
python tools/verify_integrity_e2e.py         # 验签 / 篡改拒绝 / 修复通道 / attest 全链路
python tools/verify_channels_e2e.py          # 规则 → channel_outbox → 真实 HTTP 投递 + HMAC 校验
python tools/verify_mail_e2e.py              # 注册 / 验证 / 找回密码 / 绑定 / 续费 + A5 规则邮件链路
python tools/dark_mode_sweep.py              # 四个端所有页面与滚动位置的黑带扫描
```

## 六、发布与使用注意

- 对外**只分发** `dist/release_package/`（4 个 exe + `release_manifest.json` + `.sig` + `releases/`）。
- 替换或分发时**必须整套一起换**：只替换 exe 而保留旧清单会触发完整性门禁，启动被拒绝并写入 `integrity_tamper.log`。
- 远程部署需配置 HTTPS/受信证书，并将 `--print-public-key` 导出的响应公钥固定到客户端；远程明文 HTTP 会被客户端拒绝。
- 发布签名私钥 `release_keys/release_key.json` 必须离线备份，泄露等于泄露签名能力。
