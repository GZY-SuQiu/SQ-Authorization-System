# C1 完整性自校验：冻结接口契约（Batch 1）

> 本文件是并行实现的唯一接口依据。三个实现方都不得擅自改名/改字段；如需调整，先改本文件。

## 1. 发布清单格式（release_manifest.json）

- 文件：`release_manifest.json`（UTF-8，无 BOM，2 空格缩进）
- 签名：`release_manifest.sig`（对 manifest 原始字节做 Ed25519 签名，base64url 无填充，单行文本）
- `format` 必须为 `sq-release-manifest-v1`

```json
{
  "format": "sq-release-manifest-v1",
  "version": "1.0.0",
  "generated_at": "2026-10-07T12:00:00+08:00",
  "apps": {
    "server":       {"path": "本地服务器.exe", "sha256": "<64位小写hex>", "size": 123},
    "admin":        {"path": "管理端.exe",   "sha256": "<64位小写hex>", "size": 123},
    "master":       {"path": "主控端.exe",   "sha256": "<64位小写hex>", "size": 123},
    "verification": {"path": "验证端.exe",   "sha256": "<64位小写hex>", "size": 123}
  },
  "folder": {
    "guarded_extensions": [".exe", ".dll"],
    "exempt_files": ["release_manifest.json", "release_manifest.sig"],
    "required_apps": ["server", "admin", "master", "verification"]
  }
}
```

校验规则：

- `server` 角色：`required_apps` 中的全部条目必须存在且哈希/大小一致。
- 其它角色：只要求自己对应的 app 存在且一致；清单里其它 app 若文件存在，也必须一致（缺失不算错）。
- 额外文件：`app_dir` 顶层（不递归子目录）中，扩展名命中 `guarded_extensions`、且不在 `apps` 路径列表、也不在 `exempt_files` 的文件，记 `extra_file`。
- 缺少清单或签名（frozen 模式）记 `manifest_missing`；签名校验失败记 `signature_invalid`。
- 开发模式（`sys.frozen` 为假且未设置 `SQ_FORCE_INTEGRITY=1`）：整体跳过，`skipped=true`。

## 2. 发布公钥固定

- 文件：`core/release_pubkey.py`，内容仅：

```python
RELEASE_PUBLIC_KEY_HEX = ""
```

- `build.py` 在构建前用发布密钥对覆盖该文件；发布私钥保存在 `release_keys/release_key.json`（加入 `.gitignore`）。
- frozen 模式下公钥为空：记 `release_key_missing` 并判定失败。开发模式跳过。

## 3. core/integrity.py 导出 API

```python
MANIFEST_NAME = "release_manifest.json"
SIGNATURE_NAME = "release_manifest.sig"
MANIFEST_FORMAT = "sq-release-manifest-v1"

def sha256_file(path) -> str
def load_release_public_key() -> str
def verify_manifest_signature(manifest_bytes: bytes, signature_text: str, public_key_hex: str) -> bool
def read_and_verify_manifest(app_dir, public_key_hex=None) -> tuple[dict | None, list[dict]]
def run_self_check(role: str, app_dir=None, public_key_hex=None, force: bool = False) -> dict
def get_last_result() -> dict | None
def set_last_result(result: dict | None) -> None
def run_startup_gate(role: str, *, gui: bool | None = None) -> dict
```

`run_self_check` 返回（字段固定）：

```json
{
  "ok": true,
  "skipped": false,
  "role": "verification",
  "exe_name": "验证端.exe",
  "exe_path": "C:/.../验证端.exe",
  "exe_hash": "<hex>",
  "exe_size": 123,
  "version": "1.0.0",
  "manifest_verified": true,
  "checked_at": "2026-10-07 12:00:00",
  "issues": [{"code": "hash_mismatch", "file": "验证端.exe", "detail": "..."}]
}
```

issue.code 取值：`skip_dev_mode`、`manifest_missing`、`manifest_invalid`、`signature_invalid`、`release_key_missing`、`exe_missing`、`hash_mismatch`、`missing_file`、`extra_file`、`exe_hash_mismatch`。

`run_startup_gate` 行为：

- 开发模式：返回 skipped 结果，不弹窗、不退出。
- frozen 且失败：弹 QMessageBox（懒加载 PySide6；无 QApplication 时临时创建）→ 客户端角色（admin/master/verification）尽力调用 `ApiClient.report_integrity_failure()` → `raise SystemExit(1)`。
- 成功：`set_last_result` 后返回结果。

## 4. core/api_client.py 新增 API

```python
class ApiClient:
    attest_token: str
    attest_token_expires_at: int
    integrity_result: dict | None

    def set_integrity_result(self, result: dict | None) -> None: ...
    def attest(self, role: str = "verification", machine_code: str = "") -> dict: ...
    def ensure_attest(self, role: str = "verification", machine_code: str = "") -> str | None: ...
    def report_integrity_failure(self, reason: str, detail: dict | None = None) -> dict: ...
```

- `_request(...)` 增加关键字参数 `attest_token: str | None = None`，非空时加请求头 `X-Attest-Token`。
- `activate/verify/heartbeat` 先调用 `ensure_attest()`，把 token 带上；服务端返回 `code == "attest_required"` 时抛 `ApiError("客户端完整性校验未通过，已拒绝访问")`。
- `/api/client/attest` 请求体：`{role, exe_name, exe_hash, version, machine_code, local_check}`，`local_check` 为 `run_self_check` 结果。
- `/api/client/integrity_report` 请求体：`{role, exe_name, exe_hash, version, machine_code, reason, detail}`。
- `ApiClient.__init__` 自动读取 `integrity.get_last_result()`。

## 5. 服务端接口契约

### 5.1 客户端接口

`POST /api/client/attest`（无 Bearer，按 IP 限流）

请求：`{role, exe_name, exe_hash, version, machine_code, local_check}`
成功：`{"ok": true, "attest_token": "...", "expires_in": 600}`
失败：`{"ok": false, "code": "unknown_build" | "hash_mismatch" | "release_not_registered", "message": "..."}`

`POST /api/client/integrity_report`（无 Bearer，按 IP 限流）

请求：`{role, exe_name, exe_hash, version, machine_code, reason, detail}`
响应：`{"ok": true}`；同时写 `tamper_events` + 审计日志。

强制校验：

- 开关 `config.security["attest_mode"]`：`"off"` / `"auto"`（默认）/ `"strict"`。
- `auto`：`release_hashes` 中存在 active 记录时，activate/verify/heartbeat 必须携带有效 `X-Attest-Token`。
- `strict`：无论白名单是否为空都强制。
- 无效/缺失：HTTP 403，detail 固定为 `"客户端完整性校验未通过，已拒绝访问"`。
- token 必须绑定 machine_code；activate/verify/heartbeat 中 token 的 machine_code 与请求体一致。

### 5.2 管理接口（Bearer）

- `GET /api/release/list`：返回 `{"items": [...], "total": n}`
- `POST /api/release/import`（master）：`{"manifest": "<json文本>", "signature": "<sig文本>"}`，验签通过后 upsert，返回 `{"ok": true, "imported": n}`
- `POST /api/release/status`（master）：`{"file_name": "...", "sha256": "...", "active": true|false}`
- `GET /api/tamper/events?limit=200&offset=0`：返回 `{"items": [...], "total": n}`

## 6. core/security.py 新增 API

```python
def create_attest_token(secret: str, exe_hash: str, machine_code: str, role: str, ttl_seconds: int = 600) -> str
def verify_attest_token(secret: str, token: str, machine_code: str, role: str) -> tuple[bool, dict | None]
```

payload：`{"typ": "attest", "hash": "<lower>", "mc": "<UPPER>", "role": "..."}`，复用现有 `create_token/verify_token`。

## 7. core/database.py 新增表与方法

```sql
CREATE TABLE IF NOT EXISTS release_hashes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_name TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '',
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  UNIQUE(file_name, sha256)
);
CREATE INDEX IF NOT EXISTS idx_release_hashes_hash ON release_hashes(sha256, active);

CREATE TABLE IF NOT EXISTS tamper_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  role TEXT,
  exe_name TEXT,
  exe_hash TEXT,
  version TEXT,
  machine_code TEXT,
  ip TEXT,
  reason TEXT,
  detail TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tamper_events_created ON tamper_events(created_at);
```

方法：

```python
def upsert_release_hash(self, file_name, sha256, size=0, version="", active=1, note="") -> None
def list_release_hashes(self, limit=500) -> list[dict]
def count_active_release_hashes(self) -> int
def match_release_hash(self, sha256, file_name="") -> dict | None
def set_release_hash_active(self, file_name, sha256, active) -> bool
def add_tamper_event(self, role, exe_name, exe_hash, version, machine_code, ip, reason, detail="") -> int
def list_tamper_events(self, limit=200, offset=0) -> tuple[list[dict], int]
```

## 8. 配置新增（server.security）

```json
{
  "attest_mode": "auto",
  "attest_token_ttl_seconds": 600,
  "release_public_key": ""
}
```

`release_public_key` 为空时使用 `core.release_pubkey.RELEASE_PUBLIC_KEY_HEX`。

## 9. server/main.py 启动加载

- 启动时若存在 `APP_DIR/releases/release_manifest.json` 与 `.sig`，验签后把四个 app 的哈希 upsert 到 `release_hashes`（active=1）。
- 任何异常只记录日志，不得阻止服务器启动。
- 服务器自身启动前调用 `integrity.run_startup_gate("server", gui=not args.headless)`。

## 10. 文件归属（并行写入边界）

- A：`build.py`、`tools/release_manifest.py`、`core/release_pubkey.py`、`.gitignore`、`tests/test_release_manifest.py`
- B：`core/integrity.py`、`core/api_client.py`、`core/config.py`、`verification/main.py`、`admin/main.py`、`master/main.py`、`tests/test_integrity.py`、`tests/test_attest_client.py`
- C：`core/database.py`、`core/security.py`、`server/api.py`、`server/main.py`、`tests/test_attestation.py`

各自只改自己名下的文件；不得改别人的文件；需要跨文件改动时在结论里说明，由主流程统一处理。
