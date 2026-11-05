# 功能位授权（Feature Flags）

> 从"卖版本"到"卖功能"：一张卡密可携带任意功能位清单，激活/校验/心跳/离线码
> 全链下发，宿主软件用 `has_feature()` 按模块放行。

## 一、快速开始

**管理端**：生成密钥页 →「功能位」输入框（逗号分隔）→ 例如 `pro,cloud,export`。
留空则等价于旧行为（无功能位）。

**AI 助手**：`帮我生成 10 张 30 天、带 pro 和 cloud 功能的卡` —— 工具参数
`features=["pro","cloud"]`。

**API**（`POST /api/license/generate`）：

```json
{
  "count": 10, "duration_days": 30, "max_devices": 1,
  "features": ["pro", "cloud", "export"]
}
```

命名规则：小写字母 / 数字 / `._:-`，每项 ≤32 字符，最多 32 项（自动小写去重；
非法输入返回 400）。

## 二、下发链（宿主持卡即知功能）

| 通道 | 字段 | 说明 |
|---|---|---|
| `activate` / `verify` / `heartbeat` 响应 | `features: []` | 实时清单，落库为准 |
| `GET /api/license/detail` | `license.features` | 管理端查看（已转列表） |
| **离线激活码** | `feats: []` | 签名保护，离线场景同样可用 |
| 门户（邮箱账号） | 随许可证状态展示 | 同上 |

## 三、宿主软件（Python SDK）

```python
from sdk.sq_license_client import LicenseClient

client = LicenseClient("https://license.example.com", RESPONSE_PUBLIC_KEY)
client.activate("GSQ-XXXXX-XXXXX-XXXXX-XXXXX")

if client.has_feature("pro"):       # 大小写不敏感
    enable_pro_modules()

if client.has_feature("cloud"):
    enable_cloud_sync()

print(client.features())            # ['pro', 'cloud', 'export']
```

要点：`features()` / `has_feature()` 读的是**最近一次激活或校验响应**——建议
宿主启动时 `verify()` 一次并缓存；心跳周期内功能位变化会在下一次成功响应后生效。

## 四、其他语言接入（HTTP 层）

普通 HTTP 消费 `activate/verify/heartbeat` 响应的 `features` 数组即可；
离线场景解析 `LICACT1.` 载荷中的 `feats`（签名已覆盖该字段，不可篡改）。

## 五、兼容性与边界

- **老卡密**：`features` 为空 → 响应 `features: []`，行为与升级前完全一致。
- **老客户端**：对新增字段安全忽略（JSON 多余字段不影响解析）。
- **老离线码**：解析结果 `feats` 为空列表。
- **作用域**：功能位只做"能力声明"，不替代设备数/时长/次数约束——两者可叠加。
- **变更**：功能位目前跟随卡密本身；如需"升级功能位"（补差升级），下批次在
  卡密编辑链路实现（数据模型已就绪）。

## 六、验收记录（2026-11-06）

- 单元：规范化（去重/小写/字符串分隔/非法字符/超长/超量/roundtrip）8 例全过
- 集成（HTTP 全链）：生成→详情→激活→verify→心跳→离线码→SDK has_feature
  7 例全过；老卡兼容用例通过
- 全量回归：**410 passed**；端到端 62/62（43+19）全绿
