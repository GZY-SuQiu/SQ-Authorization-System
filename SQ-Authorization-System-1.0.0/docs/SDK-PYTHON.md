# Python SDK 接入指南（第三方软件嵌入）

`sdk.LicenseClient` 是给第三方程序嵌入用的最小许可证客户端，接口冻结见
`docs/BUGFIX-INTERFACE.md` 第 4 节。它只依赖 `core.security`、`core.offline`、
`core.machine` 与 `requests`：

- **不读取任何配置文件**，服务器地址与响应公钥由调用方直接写在代码里；
- **不依赖发布清单**（`release_manifest.json` / `core.integrity`），可脱离本系统目录使用；
- **强制校验服务器响应的 Ed25519 签名**，验签失败一律抛异常，不返回数据；
- 激活成功后保存 `session_secret`，`verify` / `heartbeat` 自动附带 HMAC 请求签名。

## 运行环境

- Python 3.10+，`requests` 与 `cryptography`（离线码/响应验签用 Ed25519）。
- 把仓库的 `core/` 与 `sdk/` 两个目录一起随你的程序分发（或加入 `sys.path`），
  然后：

```python
from sdk import LicenseClient
```

## 初始化

`response_public_key` 必须显式传入（推荐从服务器 `/api/public_key` 获取一次后
写死到你的代码中，避免运行时被中间人替换）。

```python
SERVER_URL = "https://license.example.com"      # 内网 http 需 allow_insecure_http=True
RESPONSE_PUBLIC_KEY = "d1b70891158c349e60a98630a56fd632ead2a5f01cfea972304dd7a4f43efdbd"
RESPONSE_KEY_ID = "ed25519-d1b70891158c349e"    # 可留空，仅作展示/日志用途

from sdk import LicenseClient, LicenseError, LicenseSignatureError

client = LicenseClient(
    SERVER_URL,
    RESPONSE_PUBLIC_KEY,
    RESPONSE_KEY_ID,
    timeout=8,
)
```

本机机器码默认自动获取；如需自定义（例如固定设备号）可显式传入：

```python
machine = client.machine_code()          # 形如 8F3A1-0C4D9-...
```

## 激活

```python
result = client.activate("GSQ-XXXXX-XXXXX-XXXXX-XXXXX")   # 激活本机
# 或指定机器码/设备名：
# result = client.activate(key, machine_code="MACHINE-1", device_name="设计工作站")

if not result.get("ok"):
    # 服务器判定失败：密钥不存在 / 已吊销 / 已达设备上限 / 次数用尽……
    print(result.get("code"), result.get("message"))
```

`activate` 返回服务器原始响应（`ok`/`code`/`message`/`expires_at`/`remaining`/
`session_secret`…）。成功时 `session_secret` 会被自动保存。

## 校验与心跳

```python
verified = client.verify()            # 缺省复用最近一次激活的密钥与机器码
if verified.get("ok"):
    print("剩余：", verified.get("remaining"))

beat = client.heartbeat()
interval = beat.get("next_interval", 60)   # 建议按服务器返回的间隔发送心跳
```

也可以显式传入密钥/机器码：`client.verify(key_code=key, machine_code="MACHINE-1")`。

快速判断（失败时返回 `False`，不抛异常）：

```python
if client.is_valid():
    run_your_feature()
```

## 离线激活码

离线码由管理端生成（`POST /api/license/offline_code`），本机校验时不联网：

```python
# 纯离线环境：提前把服务器离线公钥固定到程序里
client.set_offline_public_key(OFFLINE_PUBLIC_KEY)

result = client.verify_offline(activation_code, machine_code="MACHINE-1")
if result["ok"]:
    print("离线授权有效，到期：", result["expires_at"] or "永久")
else:
    print(result["code"], result["message"])   # invalid_code / machine_mismatch / expired
```

离线公钥为空时会尝试联网从 `/api/public_key` 获取一次并缓存；联网失败只返回
`{"ok": false, "code": "offline_key_missing"}`，不会抛网络异常。

## 异常处理

网络、协议与验签问题都会抛出 `LicenseError` 的子类；业务失败（密钥错误、
已吊销等）按上面的 `result["ok"]` 判断，不算异常。

```python
from sdk import LicenseClient, LicenseError, LicenseSignatureError

try:
    client.activate(key)
except LicenseSignatureError as exc:
    # 服务器响应签名缺失/不匹配：连接可能被篡改，直接拒绝使用
    print("响应验签失败：", exc.code)
except LicenseError as exc:
    # exc.code: transport_error / no_session / no_key / http_error / insecure_http_blocked ...
    print("SDK 调用失败：", exc.code, exc)
```

常用错误码：

| code | 含义 |
| --- | --- |
| `response_key_missing` | 未提供响应公钥（构造时即抛） |
| `insecure_http_blocked` | 远程地址使用 http 且未显式放行 |
| `transport_error` | 连接失败/超时 |
| `signature_missing` / `response_key_mismatch` / `response_signature_invalid` | 响应验签失败 |
| `no_session` | 尚未激活（或 `reset_session()` 之后） |
| `no_key` | 未激活且没有显式传入密钥 |
| `http_error` | 服务器返回 4xx/5xx（`status_code` 保留原始状态） |
| `offline_key_missing` / `invalid_code` / `machine_mismatch` / `expired` | `verify_offline` 的结果码 |

## 生命周期

```python
client.reset_session()        # 退出登录/切换密钥：清空会话密钥与激活记忆
```

`session_secret` 只保存在内存中，进程退出即消失；需要持久化授权状态时，
请保存服务器返回的 `expires_at` 等业务字段，不要落盘 `session_secret`。

## 与服务端完整性门禁的关系

如果服务器开启了强制 attestation（`security.attest_mode = "strict"`，或已经导入
并启用发布清单），`activate/verify/heartbeat` 会要求请求头 `X-Attest-Token`。
SDK 不做完整性自检（不依赖 manifest），此时可以由宿主程序把已获得的 token 写入：

```python
client.attest_token = "..."    # 可选；为空则不发送该请求头
```

更常见的做法是：对 SDK 嵌入场景把服务端 `attest_mode` 保持 `auto` 且不导入
SDK 宿主程序的发布清单，由宿主程序自行完成完整性校验。

## 可运行示例

```powershell
python examples/embed_license_demo.py --server http://127.0.0.1:8765 --key GSQ-XXXXX-XXXXX-XXXXX-XXXXX
```

更多细节见 `examples/embed_license_demo.py` 源码与 `sdk/sq_license_client.py`。
