# A5 冻结接口契约（可配置告警规则引擎）

> 两个实现方按文件归属改代码；引擎与渠道由主流程实现。接口字段不得改名。

## 0. 文件归属

- **Backend(A5)**：`core/database.py`、`server/api.py`、`tests/test_alert_rules.py`（新建）
- **UI(A5)**：`core/alert_center.py`（新建）、`core/api_client.py`、`admin/ui.py`、`master/ui.py`、`tests/test_alert_center_ui.py`（新建）
- **主流程**：`server/alert_engine.py`（新建）、`server/mailer.py`（新增 alert_rule 模板）、集成与端到端验收

## 1. 指标定义（Backend 在 db.alert_metrics(window_seconds) 实现）

| metric | 含义 | 口径 |
|---|---|---|
| `activation_rate` | 激活率(%) | 窗口内创建的许可证中 `activated_at IS NOT NULL` 的占比；分母 0 时为 0 |
| `online_devices` | 在线并发(台) | `activations.status='active'` 且 `last_heartbeat_at >= now-window` |
| `expiration_rate` | 过期率(%) | `expires_at` 落在 [now-window, now] 的许可证中 `status='expired'` 的占比；分母 0 时为 0 |
| `expiring_soon` | 7 天内到期(个) | 有效许可证 `expires_at` 在 (now, now+7天] |
| `failed_activations` | 激活失败(次) | 窗口内 `audit_logs.action='激活失败'` |
| `risk_events` | 风控事件(次) | 窗口内 `risk_events` |
| `tamper_events` | 完整性告警(次) | 窗口内 `tamper_events` |

`db.alert_metrics(window_seconds)` 返回以上全部键（float/int）。

## 2. 规则与事件表（Backend 放进 SCHEMA）

```sql
CREATE TABLE IF NOT EXISTS alert_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  metric TEXT NOT NULL,
  operator TEXT NOT NULL,             -- gte/gt/lte/lt/eq
  threshold REAL NOT NULL,
  window_seconds INTEGER NOT NULL DEFAULT 600,
  severity TEXT NOT NULL DEFAULT 'warning',   -- info/warning/critical
  cooldown_seconds INTEGER NOT NULL DEFAULT 3600,
  channels_json TEXT NOT NULL DEFAULT '["email"]',
  enabled INTEGER NOT NULL DEFAULT 1,
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alert_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id INTEGER NOT NULL,
  rule_name TEXT NOT NULL DEFAULT '',
  metric TEXT NOT NULL,
  value REAL NOT NULL,
  threshold REAL NOT NULL,
  operator TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'warning',
  status TEXT NOT NULL DEFAULT 'firing',      -- firing/resolved/acked
  payload_json TEXT NOT NULL DEFAULT '{}',
  notified INTEGER NOT NULL DEFAULT 0,
  fired_at TEXT NOT NULL,
  resolved_at TEXT,
  acked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_alert_events_rule ON alert_events(rule_id, id);
CREATE INDEX IF NOT EXISTS idx_alert_events_status ON alert_events(status, id);
```

## 3. DB 方法（Backend 实现）

```python
def create_alert_rule(self, name, metric, operator, threshold, window_seconds=600,
                      severity="warning", cooldown_seconds=3600, channels=None,
                      enabled=True, note="") -> int
def list_alert_rules(self) -> list[dict]
def get_alert_rule(self, rule_id) -> dict | None
def update_alert_rule(self, rule_id, **fields) -> bool
def delete_alert_rule(self, rule_id) -> bool
def add_alert_event(self, rule_id, rule_name, metric, value, threshold, operator,
                    severity, payload=None) -> int
def list_alert_events(self, status="", limit=200, offset=0) -> tuple[list[dict], int]
def get_latest_alert_event(self, rule_id) -> dict | None
def resolve_alert_event(self, event_id) -> bool
def ack_alert_event(self, event_id) -> bool
def mark_alert_event_notified(self, event_id) -> None
def alert_metrics(self, window_seconds=600) -> dict
```

- channels 以 JSON 数组存储，仅接受 `email`（A5 阶段）；其他值由 API 校验拒绝（A7 再放开）。

## 4. API 契约（Backend 实现）

- `GET /api/alerts/rules`（Bearer）→ `{"items": [...]}` 
- `POST /api/alerts/rules`（Bearer）`{name, metric, operator, threshold, window_seconds, severity, cooldown_seconds, channels, enabled, note}` → `{"ok": true, "id": n}`
- `PUT /api/alerts/rules/{id}`（Bearer）同上字段（可部分）→ `{"ok": true}`
- `DELETE /api/alerts/rules/{id}`（master）→ `{"ok": true}`
- `GET /api/alerts/events?status=&limit=&offset=`（Bearer）→ `{"items": [...], "total": n}`
- `POST /api/alerts/events/{id}/ack`（Bearer）→ `{"ok": true}`
- `POST /api/alerts/events/{id}/resolve`（Bearer）→ `{"ok": true}`
- `GET /api/metrics/overview?window_seconds=600`（Bearer）→ `db.alert_metrics(...)`

校验：metric ∈ 第 1 节，operator ∈ {gte,gt,lte,lt,eq}，severity ∈ {info,warning,critical}；window_seconds 60..86400，cooldown_seconds 60..86400，threshold 有限浮点，name 长度 1..64，note ≤200。

## 5. 引擎接口（主流程实现，Backend 只负责接线）

```python
class AlertEngine:
    def __init__(self, db, mailer, config): ...
    def start(self) -> None      # 30 秒轮询，幂等
    def stop(self, timeout: float = 5.0) -> None
    def evaluate_once(self) -> list[dict]   # 返回本次触发的事件
```

create_app 增加可选参数 `alert_engine=None`（与 `mailer` 同一模式）；默认 `from .alert_engine import AlertEngine` 创建并挂到 `app.router.on_startup/on_shutdown`；模块缺失时用 `_NullAlertEngine` 兜底。

## 6. Client 方法契约（UI(A5) 实现）

```python
def alert_rules(self) -> dict
def create_alert_rule(self, **fields) -> dict
def update_alert_rule(self, rule_id: int, **fields) -> dict
def delete_alert_rule(self, rule_id: int) -> dict
def alert_events(self, status: str = "", limit: int = 200, offset: int = 0) -> dict
def ack_alert_event(self, event_id: int) -> dict
def resolve_alert_event(self, event_id: int) -> dict
def metrics_overview(self, window_seconds: int = 600) -> dict
```

## 7. UI 契约（UI(A5)）

- 新增 `core/alert_center.py` 的 `AlertCenterPage(client, notify)`，两个标签页：
  - **告警规则**：表格（名称/指标/条件/窗口/级别/冷却/状态/渠道）+ 新建/编辑/启用停用/删除（删除仅主控可用，按当前登录角色判断 `client.role` 或接口 403 提示）；新建/编辑对话框：名称、指标下拉（7 项中文标签）、运算符下拉、阈值、窗口秒、级别、冷却秒、渠道（A5 仅邮件复选框）、备注、启用。
  - **告警事件**：表格（时间/规则/指标值/阈值/级别/状态）+ 确认/标记已处理按钮 + 状态筛选 + 15 秒自动刷新。
- 页面顶部显示 `metrics_overview` 的 7 个指标卡片（不可用时显示“—”）。
- 在 `admin/ui.py` 与 `master/ui.py` 导航注册"告警中心"（AI 助手之后、生成密钥之前的位置即可）。
- 页面必须能被离屏构造（参考 core/pages.py 的 BasePage 与 core/widgets.py 控件风格）。

## 8. 通知（主流程）

- 邮件模板新增 `alert_rule`，变量：`rule_name`、`metric_label`、`value`、`operator`、`threshold`、`severity`、`window_text`、`time`。
- 收件人：`server.alerting.admin_alert_emails(db, smtp_config)`；无收件人时事件仍落库，notified=0。
- 事件通知成功后调用 `db.mark_alert_event_notified(event_id)`。
