# A7 冻结接口契约（Webhook / 钉钉 / 企微 / 飞书通知渠道）

> 两方实现；渠道适配器与投递器由主流程实现。接口字段不得改名。

## 0. 文件归属

- **Backend(A7)**：`core/database.py`、`server/api.py`、`tests/test_channels_api.py`（新建）
- **UI(A7)**：`core/alert_center.py`、`core/api_client.py`、`tests/test_alert_center_ui.py`（追加用例）
- **主流程**：`server/channels.py`（新建）、`server/alert_engine.py`（渠道派发）、集成与端到端

## 1. 表结构

```sql
CREATE TABLE IF NOT EXISTS notification_channels (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,                 -- webhook / dingtalk / wecom / feishu
  name TEXT NOT NULL UNIQUE,
  url TEXT NOT NULL,
  secret TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS channel_outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  channel_id INTEGER NOT NULL,
  subject TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'pending',   -- pending/sending/sent/failed/dead
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  next_retry_at TEXT,
  last_error TEXT,
  dedupe_key TEXT UNIQUE,
  created_at TEXT NOT NULL,
  sent_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_channel_outbox_due ON channel_outbox(status, next_retry_at);
```

## 2. DB 方法（Backend 实现）

```python
def create_notification_channel(self, kind, name, url, secret="", enabled=True) -> int
def list_notification_channels(self) -> list[dict]      # 含 id/kind/name/url/secret_set/enabled/created_at/updated_at
def get_notification_channel(self, channel_id) -> dict | None   # 含真实 secret，供投递器使用
def update_notification_channel(self, channel_id, **fields) -> bool   # secret 为空/None 表示保留
def delete_notification_channel(self, channel_id) -> bool
def enqueue_channel_message(self, channel_id, subject, body, payload=None, dedupe_key="") -> int | None
def claim_due_channel_messages(self, limit=20) -> list[dict]   # 原子领取，join 渠道 kind/url/secret/enabled
def mark_channel_message_sent(self, message_id) -> None
def mark_channel_message_failed(self, message_id, error, next_retry_at, dead=False) -> None
def channel_outbox_stats(self) -> dict
def list_channel_deliveries(self, status="", limit=200, offset=0) -> tuple[list[dict], int]
```

- `list_notification_channels` 绝不返回明文 secret，只给 `secret_set: bool`；`get_notification_channel` 返回明文供投递器/测试使用。
- 重试语义与 email_outbox 一致：attempts 记录已失败次数，退避 `60 * 2**(n-1)` 上限 1 小时，达 max_attempts 进 dead。

## 3. 渠道适配器（主流程实现，Backend 测试可 stub）

```python
CHANNEL_KINDS = ("webhook", "dingtalk", "wecom", "feishu")

class ChannelError(RuntimeError): ...

def send_channel_message(kind, url, secret="", subject="", body="",
                         payload=None, timeout=10.0) -> dict: ...

class ChannelDispatcher:
    def __init__(self, db, transport=send_channel_message, interval=5.0): ...
    def start(self) -> None
    def stop(self, timeout: float = 5.0) -> None
    def process_due(self, limit: int = 20) -> int
```

- webhook：POST JSON `{"event": subject, "text": body, "payload": payload}`；若 secret 非空加 `X-SQ-Signature: sha256=<hex hmac>`。
- 钉钉：POST `{"msgtype":"markdown","markdown":{"title":subject,"text":body}}`；secret 非空追加 `timestamp`/`sign`。
- 企微：POST `{"msgtype":"markdown","markdown":{"content":body}}`。
- 飞书：POST `{"msg_type":"text","content":{"text": subject + "\n" + body}}`；secret 非空追加 `timestamp`/`sign`。
- 非 2xx 或返回错误码（dingtalk/wecom errcode != 0、feishu code != 0）抛 ChannelError。

## 4. API 契约（Backend 实现）

- `GET /api/channels`（Bearer）→ `{"items": [...]}`
- `POST /api/channels`（master）`{kind,name,url,secret,enabled}` → `{"ok": true, "id": n}`
- `PUT /api/channels/{id}`（master）`{kind?,name?,url?,secret?,enabled?}` → `{"ok": true}`
- `DELETE /api/channels/{id}`（master）→ `{"ok": true}`
- `POST /api/channels/{id}/test`（master）→ 同步发送测试消息，成功 `{"ok": true}`，失败 400 `{"detail": "..."}`
- `GET /api/channels/deliveries?status=&limit=&offset=`（Bearer）→ `{"items": [...], "total": n}`

校验：kind ∈ CHANNEL_KINDS，url 必须 http(s) 且 ≤512，name 1..64 且唯一，secret ≤256。渠道不存在 404。

## 5. 规则渠道字段扩展（Backend + 引擎）

- `alert_rules.channels` 允许：`"email"` 或 `"channel:<id>"`。
- API 校验：每项必须是 `email` 或存在的 channel id；其余 400。
- 引擎（主流程）对 `"channel:<id>"`：读渠道 → enabled 时用 alert_rule 模板渲染 subject/body → `db.enqueue_channel_message(...)`；入队成功视为已通知。

## 6. Client 方法（UI 实现）

```python
def list_channels(self) -> dict
def create_channel(self, kind, name, url, secret="", enabled=True) -> dict
def update_channel(self, channel_id: int, **fields) -> dict
def delete_channel(self, channel_id: int) -> dict
def test_channel(self, channel_id: int) -> dict
def channel_deliveries(self, status: str = "", limit: int = 200, offset: int = 0) -> dict
```

## 7. UI 契约（UI 实现）

- `AlertCenterPage` 增加第三个标签页 **通知渠道**：
  - 渠道表格：名称/类型/地址/启用/状态；按钮 新建/编辑/删除/测试/刷新。
  - 渠道对话框：类型下拉（Webhook/钉钉/企微/飞书）、名称、地址、密钥（密码模式，编辑时留空表示不改）、启用。
  - 下方"投递记录"表格：时间/渠道/主题/状态/次数/错误；状态筛选 + 刷新。
- 规则对话框渠道区改为：邮件复选框 + 每个启用渠道一个复选框，值 `channel:<id>`。
- 渠道接口不可用时页面降级为提示，不得崩溃。
