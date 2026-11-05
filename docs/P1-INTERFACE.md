# P1 冻结接口契约（邮件账号 + 邮箱登录 + 告警基础）

> 本文件是 P1 并行实现的唯一接口依据。四个实现方按文件归属改代码，接口字段不得改名。

## 0. 文件归属（严格互斥）

- **Mailer**：`server/mailer.py`（新建）、`core/config.py`、`server/ui.py`、`tests/test_mailer.py`（新建）
- **Backend**：`core/database.py`、`core/security.py`、`server/api.py`、`tests/test_p1_backend.py`（新建）
- **ClientUI**：`core/api_client.py`、`verification/ui.py`、`tests/test_portal_client.py`（新建）
- **MasterUI**：`core/shell.py`、`master/ui.py`、`tests/test_admin_email_ui.py`（新建）

主流程负责：`server/alerting.py`、风险触发接线、集成测试、打包与端到端验收。

## 1. SMTP 配置（core/config.py，Mailer 负责）

`SERVER_DEFAULT_CONFIG` 增加顶层 `smtp`：

```json
{
  "enabled": false,
  "host": "",
  "port": 587,
  "username": "",
  "password": "",
  "from_email": "",
  "from_name": "密钥授权系统",
  "use_starttls": true,
  "use_ssl": false,
  "timeout": 15,
  "alert_admin_emails": []
}
```

密码只存在服务端配置文件中（该文件已做 ACL 收紧），不得下发到客户端角色。

## 2. 邮件引擎（server/mailer.py，Mailer 负责）

```python
DEFAULT_TEMPLATES: dict[str, dict]  # code -> {"subject": str, "body": str}

class Mailer:
    def __init__(self, db, smtp_config: dict, transport=None): ...
    def start(self) -> None
    def stop(self, timeout: float = 5.0) -> None
    def enqueue(self, to_email: str, template_code: str, variables: dict | None = None, dedupe_key: str = "") -> int | None
    def process_due(self, limit: int = 20) -> int
    def send_now(self, to_email: str, template_code: str, variables: dict | None = None) -> None
    def status(self) -> dict

def build_mailer(db, smtp_config: dict) -> Mailer
def send_test_email(db, smtp_config: dict, to_email: str) -> None
```

- 模板占位符：`{{变量名}}`，渲染时对变量值做 HTML 转义。
- 模板 code：`verify_email`、`reset_password`、`tamper_alert`、`risk_alert`、`renewal_request`、`test_email`。
- worker：后台线程每 5 秒调用 `process_due`；`start/stop` 幂等；`transport` 可注入用于测试，签名 `transport(config: dict, to_email: str, subject: str, body: str) -> None`。
- 重试：最多 5 次，退避 `60 * 2**(attempts-1)` 秒，上限 1 小时；超过进 `dead`。
- `status()` 返回：`{enabled, host, port, from_email, pending, sending, sent, failed, dead, last_error}`。
- 未启用 SMTP 时 `enqueue` 返回 `None` 且不写队列；`send_now` 抛 `RuntimeError("SMTP 未启用或未配置")`。

## 3. 邮件相关数据库方法（Backend 负责实现，Mailer 调用）

```python
def seed_email_templates(self, templates: dict) -> int            # 只补缺失的 code
def upsert_email_template(self, code, subject, body, locale="zh-CN") -> None
def get_email_template(self, code) -> dict | None
def enqueue_email(self, to_email, template_code, variables=None, dedupe_key="") -> int | None
def claim_due_emails(self, limit=20) -> list[dict]                # 原子领取 pending/failed 且到期 -> sending
def mark_email_sent(self, email_id) -> None
def mark_email_failed(self, email_id, error, next_retry_at, dead=False) -> None
def email_outbox_stats(self) -> dict
def list_email_outbox(self, status="", limit=200, offset=0) -> tuple[list[dict], int]
```

表结构（Backend 放进 SCHEMA）：

```sql
CREATE TABLE IF NOT EXISTS email_templates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE NOT NULL,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  locale TEXT NOT NULL DEFAULT 'zh-CN',
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS email_outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  to_email TEXT NOT NULL,
  template_code TEXT NOT NULL,
  variables_json TEXT NOT NULL DEFAULT '{}',
  subject TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',   -- pending/sending/sent/failed/dead
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  next_retry_at TEXT,
  last_error TEXT,
  dedupe_key TEXT UNIQUE,
  created_at TEXT NOT NULL,
  sent_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_email_outbox_due ON email_outbox(status, next_retry_at);
```

## 4. 账号相关数据库（Backend 负责）

### 4.1 admins 扩展

- `MIGRATIONS["admins"]` 增加：`email TEXT`、`email_verified_at TEXT`。
- SCHEMA 增加唯一索引：`CREATE UNIQUE INDEX IF NOT EXISTS idx_admins_email ON admins(email) WHERE email IS NOT NULL AND email <> ''`（email 一律小写存储）。
- `GET /api/admin/me` 响应增加 `email`、`email_verified`（bool）。

```python
def set_admin_email(self, admin_id, email) -> None
def get_admin_by_email(self, email) -> dict | None
def mark_admin_email_verified(self, admin_id) -> None
def list_verified_admin_emails(self) -> list[str]
```

### 4.2 验证码

```sql
CREATE TABLE IF NOT EXISTS action_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subject_type TEXT NOT NULL,      -- admin / portal
  subject_id INTEGER NOT NULL DEFAULT 0,
  email TEXT NOT NULL,
  purpose TEXT NOT NULL,           -- verify_email / reset_password / register
  code_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  used_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_action_codes_lookup ON action_codes(subject_type, email, purpose);
```

```python
def create_action_code(self, subject_type, subject_id, email, purpose, code_hash, expires_at) -> int
def consume_action_code(self, subject_type, email, purpose, code_hash) -> bool
def count_action_codes(self, email, purpose, since) -> int
```

- 验证码 6 位数字，有效期 10 分钟，最多尝试 5 次，一次性。
- 存储哈希：`core.security.hash_action_code(secret, code) -> str`（HMAC-SHA256，secret 为服务端 secret_key），`core.security.verify_action_code(secret, code, code_hash) -> bool`（恒定时间比较）。
- 发送频率：同一 email+purpose 60 秒内最多 1 条，10 分钟内最多 5 条。

### 4.3 门户账号（验证端邮箱登录）

```sql
CREATE TABLE IF NOT EXISTS portal_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  auth_version INTEGER NOT NULL DEFAULT 0,
  email_verified_at TEXT,
  created_at TEXT NOT NULL,
  last_login_at TEXT
);
CREATE TABLE IF NOT EXISTS portal_account_licenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL UNIQUE REFERENCES portal_accounts(id) ON DELETE CASCADE,
  license_id INTEGER NOT NULL UNIQUE REFERENCES licenses(id) ON DELETE CASCADE,
  key_code TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'bound',   -- bound / unbound
  bound_at TEXT NOT NULL,
  unbound_at TEXT,
  unbind_reason TEXT
);
CREATE TABLE IF NOT EXISTS portal_binding_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL,
  license_id INTEGER NOT NULL,
  key_code TEXT NOT NULL,
  action TEXT NOT NULL,                   -- bind / unbind / rebind
  reason TEXT NOT NULL DEFAULT '',
  actor TEXT NOT NULL DEFAULT 'user',
  created_at TEXT NOT NULL
);
```

规则：

- 一个邮箱同一时间只能绑定一个 Key；一个 Key 同一时间只能被一个邮箱绑定。
- 绑定成功 = 建立账号↔许可证关系 + 调用现有激活逻辑绑定设备（复用 `do_activate`，仍受 attest 门禁约束）。
- 自助脱绑只允许在 Key 已过期/吊销/次数用尽时；脱绑时将 `portal_account_licenses.status='unbound'`，并把该 Key 的 `activations.status` 全部置 `unbound`（释放设备），写历史。
- 有效 Key 脱绑返回 409，提示联系管理员。

```python
def create_portal_account(self, email, password_hash, salt) -> int
def get_portal_account(self, email) -> dict | None
def get_portal_account_by_id(self, account_id) -> dict | None
def touch_portal_login(self, account_id) -> None
def set_portal_password(self, account_id, password_hash, salt) -> None
def mark_portal_email_verified(self, account_id) -> None
def get_portal_binding(self, account_id) -> dict | None
def get_binding_by_license(self, license_id) -> dict | None
def bind_portal_license(self, account_id, license_id, key_code) -> bool
def unbind_portal_license(self, account_id, reason, actor="user") -> bool
def add_binding_history(self, account_id, license_id, key_code, action, reason, actor) -> None
def release_license_activations(self, license_id, reason="portal_unbind") -> int
```

### 4.4 续费请求与风险事件

```sql
CREATE TABLE IF NOT EXISTS renewal_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL,
  license_id INTEGER NOT NULL,
  key_code TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',   -- pending / done / rejected
  created_at TEXT NOT NULL,
  handled_at TEXT
);
CREATE TABLE IF NOT EXISTS risk_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,              -- machine_mismatch / ip_jump / tamper / other
  severity TEXT NOT NULL DEFAULT 'warning',
  key_code TEXT,
  machine_code TEXT,
  ip TEXT,
  detail TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_risk_events_created ON risk_events(created_at);
CREATE TABLE IF NOT EXISTS activation_ip_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  license_id INTEGER NOT NULL,
  key_code TEXT NOT NULL,
  machine_code TEXT NOT NULL,
  ip TEXT NOT NULL,
  subnet TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_activation_ip_key ON activation_ip_events(key_code, created_at);
```

```python
def create_renewal_request(self, account_id, license_id, key_code, note="") -> int
def list_renewal_requests(self, limit=200, offset=0) -> tuple[list[dict], int]
def add_risk_event(self, kind, severity, key_code, machine_code, ip, detail="") -> int
def list_risk_events(self, limit=200, offset=0) -> tuple[list[dict], int]
def add_activation_ip_event(self, license_id, key_code, machine_code, ip, subnet) -> int
def count_ip_changes(self, key_code, since) -> int
```

## 5. 门户令牌（core/security.py，Backend 负责）

```python
def create_portal_token(payload: dict, secret: str, ttl_seconds: int = 12 * 3600) -> str
def verify_portal_token(token: str, secret: str) -> dict | None
```

- payload 固定包含 `{"typ": "portal", "uid": account_id, "ver": auth_version}`。
- **`current_admin` 必须拒绝 `typ == "portal"` 的令牌**；`current_portal` 必须要求 `typ == "portal"`，否则 401。
- 验证端请求头沿用 `Authorization: Bearer <token>`。

## 6. API 契约（Backend 负责实现）

### 6.1 管理员邮箱与找回密码

- `POST /api/admin/email/set`（Bearer）`{"email"}` → 设置邮箱（未验证）并发验证码邮件；返回 `{"ok": true, "email": "...", "expires_in": 600}`；SMTP 未启用返回 400 `"SMTP 未启用或未配置"`。
- `POST /api/admin/email/verify`（Bearer）`{"code"}` → `{"ok": true}`。
- `POST /api/admin/password/forgot` `{"email"}` → 恒返回 `{"ok": true}`（防枚举）；邮箱存在且已验证时发重置码。
- `POST /api/admin/password/reset` `{"email", "code", "new_password"}` → 成功 `{"ok": true}`；重置后 `auth_version+1`（旧令牌全部失效）。
- `GET /api/admin/me` 增加 `email`、`email_verified`。

### 6.2 门户账号

- `POST /api/portal/email/send_code` `{"email", "purpose"}`（purpose: `register` | `reset`）→ 恒 `{"ok": true}`；register 时邮箱已注册返回 `{"ok": false, "code": "already_registered"}`。
- `POST /api/portal/register` `{"email", "code", "password"}` → 成功 `{"ok": true, "token": "...", "expires_in": 43200, "email": "..."}`。
- `POST /api/portal/login` `{"email", "password"}` → 成功 `{"ok": true, "token": "...", "expires_in": 43200, "email": "...", "binding": {...} | null}`；失败 `{"ok": false, "code": "invalid_credentials"}`（HTTP 200，按现有客户端端点风格）。
- `GET /api/portal/me`（门户 Bearer）→ `{"ok": true, "email": "...", "email_verified": true, "binding": {...}|null}`。
- `POST /api/portal/bind`（门户 Bearer）`{"key_code", "machine_code", "device_name"}` → 成功 `{"ok": true, "binding": {...}, "activation": {...}}`；已有绑定 409；Key 已被其它邮箱绑定 409；Key 不可用返回 `{"ok": false, "code": "invalid_license"}`。
- `POST /api/portal/unbind`（门户 Bearer）→ 成功 `{"ok": true}`；Key 仍有效 409 `"授权仍有效，不能自助脱绑，请联系管理员"`。
- `POST /api/portal/renew_request`（门户 Bearer）`{"note"}` → `{"ok": true, "request_id": n}`；同时写续费请求并触发邮件（主流程接线，Backend 只负责 create_renewal_request + 返回）。
- `POST /api/portal/password/reset` `{"email", "code", "new_password"}` → `{"ok": true}`；重置后 `auth_version+1`。

### 6.3 SMTP 与投递记录

- `GET /api/smtp/status`（Bearer）→ mailer.status()
- `POST /api/smtp/test`（master）`{"to_email"}` → `{"ok": true}`，同步调用 mailer.send_now
- `GET /api/email/outbox?status=&limit=&offset=`（Bearer）→ `{"items": [...], "total": n}`

## 7. Client 方法契约（core/api_client.py，ClientUI 负责）

```python
def portal_send_code(self, email: str, purpose: str) -> dict
def portal_register(self, email: str, code: str, password: str) -> dict
def portal_login(self, email: str, password: str) -> dict
def portal_me(self) -> dict
def portal_bind(self, key_code: str, machine_code: str, device_name: str = "") -> dict
def portal_unbind(self) -> dict
def portal_renew_request(self, note: str = "") -> dict
def portal_password_reset(self, email: str, code: str, new_password: str) -> dict
def admin_set_email(self, email: str) -> dict
def admin_verify_email(self, code: str) -> dict
def admin_password_forgot(self, email: str) -> dict
def admin_password_reset(self, email: str, code: str, new_password: str) -> dict
```

- 新增属性 `portal_token: str`；`_request(..., portal_auth: bool = False)` 为 True 时使用 `Authorization: Bearer {portal_token}`。
- `portal_login/register` 成功后保存 token；`portal_me` 返回 401 时清空 token。
- `portal_bind` 要先 `ensure_attest(...)` 并带 `X-Attest-Token`（沿用 C1 机制）。

## 8. UI 契约

### 8.1 验证端（ClientUI）

- 顶部增加模式切换：**邮箱登录** / **激活码**（默认邮箱登录，可配置回退）。
- 邮箱模式：
  - 未登录：邮箱、密码、登录、注册（邮箱+验证码+密码+发送验证码）、忘记密码（邮箱+验证码+新密码）。
  - 已登录：显示邮箱、绑定 Key 状态、到期时间；未绑定 → Key 输入 + "绑定并激活"；已绑定 → 校验、请求续费、脱绑（不满足条件时按钮禁用/提示）、退出登录。
  - 登录/绑定成功后复用现有心跳与状态展示；机器码取现有 `machine_code`。
- 激活码模式：保持现有 UI 与逻辑不变。
- 现有自动化测试与 `tools/smoke_windows.py` 必须仍能构造窗口。

### 8.2 主控端与登录（MasterUI）

- 管理端/主控端登录框增加"忘记密码"入口：邮箱 → 发送验证码 → 验证码 + 新密码 → 重置。
- 主控端管理员管理：创建管理员时可选填邮箱；列表显示邮箱与验证状态；操作增加"设置邮箱/重发验证"。
- 不改变现有创建/启停/重置密码行为。

### 8.3 服务器端 SMTP（Mailer）

- 服务器界面设置区增加 SMTP 分组：启用、主机、端口、用户名、密码、发件邮箱、发件人名称、STARTTLS、SSL、超时、管理员告警收件邮箱（逗号分隔）。
- 保存写入 `config.data["smtp"]` + `config.save()`；"发送测试邮件"在后台线程调用 `send_test_email`，结果用 toast 提示，不得卡 UI。

## 9. 主流程（不分配给子 agent）

- `server/alerting.py`：收件人解析（绑定邮箱 + 已验证管理员邮箱）、完整性/风控告警、续费请求通知。
- 风险接线：新硬件码 → 冻结 + 邮件告警；IP 跳动 > 2 次 → 邮件告警；tamper 事件 → 邮件告警。
- 集成、全量测试、SMTP 假服务器端到端验收、重新打包。
