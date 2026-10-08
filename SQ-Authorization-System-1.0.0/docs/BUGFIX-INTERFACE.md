# 缺陷修复冻结接口（2026-10-08）

> 三路并行；主流程负责构建侧 release_id、服务端 UI 性能、集成与打包。字段不得改名。

## 0. 文件归属

- **Backend(B)**：`core/database.py`、`server/api.py`、`tests/test_bugfix_backend.py`（新建）
- **UI(B)**：`core/api_client.py`、`verification/ui.py`、`core/user_admin.py`（新建）、`admin/ui.py`、`master/ui.py`、`core/shell.py`、`tests/test_profile_ui.py`（新建）、`tests/test_user_admin_ui.py`（新建）
- **SDK(B)**：`core/integrity.py`、`sdk/__init__.py`（新建）、`sdk/sq_license_client.py`（新建）、`docs/SDK-PYTHON.md`（新建）、`examples/embed_license_demo.py`（新建）、`tests/test_license_sdk.py`（新建）、`tests/test_integrity_standalone.py`（新建）
- **主流程**：`tools/release_manifest.py`、`build.py`、`.gitignore`、`server/ui.py`、`tools/bench_server.py`

## 1. 问题一：验证端用户资料（名称/头像/邮箱）

### DB（Backend）

`portal_accounts` 迁移新增：`display_name TEXT NOT NULL DEFAULT ''`、`avatar_mime TEXT NOT NULL DEFAULT ''`、`avatar_data BLOB`。

```python
def get_portal_profile(self, account_id) -> dict            # email/display_name/email_verified_at/avatar_mime/avatar_size
def set_portal_display_name(self, account_id, display_name) -> None
def set_portal_avatar(self, account_id, mime, data: bytes) -> None
def clear_portal_avatar(self, account_id) -> None
def get_portal_avatar(self, account_id) -> tuple[str, bytes] | None
```

### API（Backend）

- `GET /api/portal/profile`（门户 Bearer）→ `{"ok":true,"email":...,"display_name":...,"email_verified":bool,"avatar":{"mime":...,"data_base64":...}|null}`
- `PUT /api/portal/profile`（门户 Bearer）`{"display_name"}`（1..32 字符，去首尾空格）→ `{"ok":true}`
- `POST /api/portal/avatar`（门户 Bearer）`{"mime","data_base64"}`；mime ∈ image/png,image/jpeg,image/webp；原始数据 ≤256KB，base64 解码失败 400 → `{"ok":true}`
- `DELETE /api/portal/avatar`（门户 Bearer）→ `{"ok":true}`
- `POST /api/portal/login`、`GET /api/portal/me` 响应增加 `display_name` 与 `avatar`（结构同上，可为 null）。

### Client（UI）

```python
def portal_profile(self) -> dict
def portal_update_profile(self, display_name: str) -> dict
def portal_upload_avatar(self, mime: str, data_base64: str) -> dict
def portal_delete_avatar(self) -> dict
```

### 验证端 UI（UI）

- 登录后资料区显示头像（圆形/圆角 QLabel）、显示名（无则显示邮箱前缀）、邮箱。
- "编辑资料"对话框：名称输入；"选择头像"（QFileDialog 支持 png/jpg/webp，前端读取并 base64，≤256KB，超限提示）；"移除头像"；保存后立即刷新资料区。
- 头像加载失败时回退默认图标/首字母，不崩溃。

## 2. 问题二：服务端卡顿（Backend + 主流程）

### DB（Backend）

- SCHEMA 增加索引：`activations(license_id,status)`、`activations(last_heartbeat_at)`、`audit_logs(action,created_at)`、`licenses(created_at)`。
- `sweep_expired(force=False)`：用单调时钟节流，60 秒内只真正执行一次；写操作可传 force=True。
- 新增 `stats_cached(ttl=5)`：5 秒内复用 `stats()` 结果；`GET /api/license/stats` 改用 `stats_cached()`。
- `claim_due_emails` / `claim_due_channel_messages`：先做一次无锁 `SELECT 1 ... LIMIT 1`，无到期行直接返回 []，避免每 5 秒空 BEGIN IMMEDIATE 抢写锁。
- `prune_nonces`：节流（60 秒最多一次），调用方签名不变。

### Server UI（主流程）

- 3 秒全量刷新改为 10 秒；改用 `stats_cached()`；日志 limit 100→50；窗口不可见/最小化时跳过。

### 验收（主流程）

- `tools/bench_server.py`：200 次心跳 + 200 次列表 + 50 次统计的耗时；修复后总耗时目标显著下降（记录数值即可）。

## 3. 问题三：发布文件可被篡改利用（主流程 + Backend + SDK）

### 构建侧（主流程）

- 每次 `python build.py` 生成新的 `RELEASE_ID`（32 位 hex），写入 `core/release_identity.py`（`RELEASE_ID = "..."`，生成物，加入 .gitignore）。
- `release_manifest.json` 增加 `"release_id": "<RELEASE_ID>"` 字段（参与签名）。

### 客户端自检（SDK）

- `core/integrity.py` 读取 `core.release_identity.RELEASE_ID`；manifest 的 `release_id` 与内嵌值不一致 → 新增 issue code `release_mismatch`，判定失败。
- `run_self_check` 结果增加字段：`release_id`、`manifest_sha256`（manifest 文件原始字节的 sha256，缺失时为空串）。
- 开发模式/无 release_id（空串）时跳过 release 绑定校验。

### 服务端（Backend）

- 新增 `release_meta` 表：`id, release_id TEXT UNIQUE, manifest_sha256 TEXT, version TEXT, active INTEGER DEFAULT 1, created_at TEXT`；`release_hashes` 保持现状。
- `server/main.py` 与 `POST /api/release/import` 导入时：计算 manifest sha256、读取 release_id，写入/更新 release_meta（active=1）。
- `AttestBody` 增加可选 `release_id`（≤64）、`manifest_sha256`（空串或 64 hex）。
- `/api/client/attest`：当 release_meta 存在 active 记录时：
  - `release_id` 必须匹配某条 active 记录，否则写 tamper_events(`release_mismatch`) 并返回 `{"ok":false,"code":"release_mismatch"}`；
  - `manifest_sha256` 非空时必须与该记录一致，否则同上；
  - exe 哈希白名单校验保持原有逻辑。

## 4. 问题四：验证端可脱离文件运行 + 可嵌入第三方软件

### 独立运行（SDK）

- `run_startup_gate`/`run_self_check` 对 `role == "verification"`：
  - manifest 与签名文件**都不存在** → 进入 standalone：`ok=true, skipped=true, issues=[{"code":"standalone_mode",...}]`，不弹窗、不退出；
  - 文件存在但不一致 → 仍判定失败（防篡改不回退）。
- admin/master/server 角色行为不变（缺文件仍拒绝）。

### Python SDK（SDK）

`sdk/sq_license_client.py`：

```python
class LicenseClient:
    def __init__(self, server_url, response_public_key, response_key_id="",
                 timeout=8, allow_insecure_http=False): ...
    def machine_code(self) -> str
    def activate(self, key_code, machine_code=None, device_name="") -> dict
    def verify(self, key_code=None, machine_code=None) -> dict
    def heartbeat(self, key_code=None, machine_code=None) -> dict
    def is_valid(self, key_code=None, machine_code=None) -> bool
    def verify_offline(self, activation_code, machine_code=None) -> dict
    def reset_session(self) -> None
```

- 只依赖 `core.security` / `core.offline` / `core.machine` 与 requests；不读取任何配置文件、不依赖 manifest。
- 强制校验响应 Ed25519 签名；保存 session_secret 后 verify/heartbeat 使用 HMAC 请求签名。
- 允许把 server_url、response_public_key 直接写进调用方代码。

`docs/SDK-PYTHON.md` 给出接入示例；`examples/embed_license_demo.py` 是可运行的命令行示例。

## 5. 问题五：管理端/主控端界面区分

### UI（UI）

- AppShell 顶部显示角色徽标：管理端=“密钥运营”，主控端=“系统管理”；窗口标题分别为 `密钥授权系统 · 管理端（密钥运营）`、`密钥授权系统 · 主控端（系统管理）`。
- 管理端导航必须**不包含**“管理员管理”“系统设置”；主控端必须包含这两个。
- 管理端与主控端的主色/导航分组做可见区分（例如主控端侧栏标题与徽标样式不同），但保持现有控件风格。
- 测试：构造两个窗口，断言导航项集合差异与徽标文本。

## 6. 问题六：用户管理（邮箱注册用户）

### DB（Backend）

```python
def list_portal_accounts(self, keyword="", status="", limit=200, offset=0) -> tuple[list[dict], int]
# item: id,email,display_name,status,email_verified_at,created_at,last_login_at,
#       bound_key,binding_status,license_status,expires_at
def set_portal_account_status(self, account_id, status) -> bool   # active/disabled, auth_version+1
def admin_unbind_portal_account(self, account_id, reason, actor) -> bool  # 释放设备+写历史+解绑
```

### API（Backend）

- `GET /api/admin/portal_accounts?keyword=&status=&limit=&offset=`（Bearer）→ `{"items":[...],"total":n}`
- `POST /api/admin/portal_accounts/{id}/status`（Bearer）`{"status":"active"|"disabled"}` → `{"ok":true}`
- `POST /api/admin/portal_accounts/{id}/unbind`（Bearer）→ `{"ok":true}`

### UI（UI）

- 新增 `core/user_admin.py` 的 `UserAdminPage(client, notify)`：搜索框（邮箱/显示名）、状态筛选、表格（邮箱/名称/状态/绑定Key/许可证状态/到期/注册时间/最后登录）、按钮 刷新/启用/禁用/强制脱绑。
- 管理端与主控端导航都注册“用户管理”（放在“密钥管理”之后）。
- Client 方法：`portal_accounts(keyword="",status="",limit=200,offset=0)`、`set_portal_account_status(id,status)`、`admin_unbind_portal_account(id)`。
