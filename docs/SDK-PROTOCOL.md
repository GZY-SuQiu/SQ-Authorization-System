# 授权协议规范（多语言 SDK 参考）

> 供 JS / Go / Java / C# / C++ 等宿主软件按此协议直连服务器；
> Python 宿主直接用 `sdk/sq_license_client.py`（本规范与之一致）。

## 一、接口总览

| 接口 | 方法 | 认证 | 说明 |
|---|---|---|---|
| `/api/client/activate` | POST | 无签名（可带 attest） | 激活，返回 `session_secret` |
| `/api/client/verify` | POST | **HMAC 请求签名** | 校验授权（含功能位/席位下发） |
| `/api/client/heartbeat` | POST | **HMAC 请求签名** | 心跳续期（浮动席位占位） |
| `/api/public_key` | GET | 无 | 获取响应公钥（用于固定） |

全部响应带 **Ed25519 响应签名**（`X-Server-Signature`），客户端必须验证。

## 二、请求签名（v2 协议）

**签名消息**（`\n` 连接，UTF-8）：

```
SQCLIENT-REQUEST-2
<METHOD>
<PATH>（不含查询串）
<TIMESTAMP>（Unix 秒）
<NONCE>（16 字节随机 hex）
<QUERY>（原始查询串，无 ?）
<BODY_SHA256>（原始请求体字节的 SHA-256 hex；空体为 ""
```

**签名值** = `HMAC-SHA256(secret=session_secret, message)` → 小写 hex。

**请求头**：`X-Client-Timestamp`、`X-Client-Nonce`、`X-Client-Signature`。
服务端校验：时间窗 ±300s、nonce 防重放、签名恒定时间比较。

### 测试向量（各语言实现对拍用）

```json
{
  "secret_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  "method": "POST",
  "path": "/api/client/verify",
  "timestamp": 1793900000,
  "nonce": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
  "query": "",
  "body_utf8": "{\"key_code\":\"GSQ-AAAAA-BBBBB-CCCCC-DDDDD\",\"machine_code\":\"XXXXX-YYYYY-ZZZZZ-WWWWW-VVVVV\"}",
  "canonical_message": "SQCLIENT-REQUEST-2\nPOST\n/api/client/verify\n1793900000\n0f1e2d3c4b5a69788796a5b4c3d2e1f0\n\n6c3e76fb987519c256a3b2531415721a2c7802a4485ee58172ea44222e674bc3",
  "signature_hex": "30424f6b1925907267c7a18bc70022922242425dfb252b10c31e5a6bfb3f2ee4"
}
```

对拍标准：用相同输入计算出相同 `canonical_message` 与 `signature_hex` 即为通过。

## 三、响应签名（必须验证）

响应头：`X-Server-Signature`（Ed25519，base64url 无填充）、
`X-Server-Key-Id`、`X-Server-Signed-At`。

**签名消息**（`\n` 连接）：

```
SQSERVER-RESPONSE-2
<METHOD>
<PATH>
<QUERY>
<请求的 X-Client-Timestamp>
<请求的 X-Client-Nonce>
<HTTP 状态码>
<X-Server-Key-Id>
<响应体字节的 SHA-256 hex>
```

验证：`Ed25519.verify(响应公钥, 消息字节, 签名)`；并要求 `X-Server-Key-Id` 等于
固定时的 `response_key_id`（防止换钥混淆）。**任何验证失败 → 视为连接被篡改，终止**。

## 四、接口字段（关键部分）

### activate 请求

```json
{
  "key_code": "GSQ-XXXXX-XXXXX-XXXXX-XXXXX",
  "machine_code": "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
  "device_name": "可选设备名",
  "machine_components": {"guid": "...", "vol": "...", "mac": "...", "cpu": "..."}
}
```
`machine_components` 可选（本机各硬件因子独立哈希），用于"同机硬件变更"容错。

### activate / verify / heartbeat 成功响应（节选）

```json
{
  "ok": true,
  "code": "activated",
  "session_secret": "64位hex（仅 activate 返回）",
  "expires_at": "2027-01-01 00:00:00",
  "remaining": "6天23小时",
  "features": ["pro", "cloud"],
  "seats": {"limit": 3, "in_use": 1, "left": 2, "lease_seconds": 90},
  "server_ts": 1793900000
}
```
`features`：功能位（宿主用 `has_feature` 逻辑放行）；`seats`：仅浮动席位卡返回。

### 错误码（`ok=false` 时的 `code`）

| code | 含义 | 客户端建议 |
|---|---|---|
| `not_found` / `revoked` / `expired` | 密钥状态问题 | 提示用户 |
| `limit` | 绑定设备数已满 | 提示联系管理员 |
| `seats_full` | 并发席位已满（浮动） | 稍后重试（下个心跳周期） |
| `trial_used` | 试用卡已领取过 | 提示已领取 |
| `frozen` | 冻结/长期锁定 | 展示 message |
| `exhausted` | 次数卡用尽 | 提示已用尽 |
| `unauthenticated` | 未激活/会话失效 | 重新 activate |
| `signature_invalid` / `replay` | 签名问题 | 检查实现（不应出现在正常客户端） |
## 五、多语言接入示例（激活 + 签名骨架）

> 各示例聚焦"签名字符串构造 + HMAC"这一核心；HTTP 库请用各语言标准方案。
> 所有语言都要遵循第二节的 canonical 格式（逐字节一致），用测试向量对拍。

### JavaScript（Node / 浏览器 + WebCrypto）

```javascript
import { createHmac, createHash } from "node:crypto";

function signRequest(secretHex, method, path, ts, nonce, bodyBuf, query = "") {
  const digest = createHash("sha256").update(bodyBuf).digest("hex");
  const message = ["SQCLIENT-REQUEST-2", method, path, String(ts), nonce, query, digest].join("\n");
  return createHmac("sha256", Buffer.from(secretHex, "hex")).update(message, "utf8").digest("hex");
}

const body = Buffer.from(JSON.stringify({ key_code, machine_code }));
const ts = Math.floor(Date.now() / 1000);
const nonce = crypto.randomBytes(16).toString("hex");
const sig = signRequest(sessionSecretHex, "POST", "/api/client/verify", ts, nonce, body);

await fetch(`${base}/api/client/verify`, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-Client-Timestamp": String(ts),
    "X-Client-Nonce": nonce,
    "X-Client-Signature": sig,
  },
  body,
});
```

### Go

```go
func signRequest(secretHex, method, path string, ts int64, nonce string, body []byte, query string) string {
	sum := sha256.Sum256(body)
	message := strings.Join([]string{
		"SQCLIENT-REQUEST-2", method, path, strconv.FormatInt(ts, 10),
		nonce, query, hex.EncodeToString(sum[:]),
	}, "\n")
	key, _ := hex.DecodeString(secretHex)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}
```

### Java

```java
static String signRequest(byte[] secret, String method, String path, long ts,
                          String nonce, byte[] body, String query) throws Exception {
    String digest = HexFormat.of().formatHex(
        MessageDigest.getInstance("SHA-256").digest(body));
    String message = String.join("\n", "SQCLIENT-REQUEST-2", method, path,
        Long.toString(ts), nonce, query, digest);
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(secret, "HmacSHA256"));
    return HexFormat.of().formatHex(mac.doFinal(message.getBytes(StandardCharsets.UTF_8)));
}
```

### C#（.NET）

```csharp
static string SignRequest(byte[] secret, string method, string path, long ts,
                          string nonce, byte[] body, string query = "") {
    using var sha = SHA256.Create();
    string digest = Convert.ToHexString(sha.ComputeHash(body)).ToLowerInvariant();
    string message = string.Join("\n", "SQCLIENT-REQUEST-2", method, path,
        ts.ToString(), nonce, query, digest);
    using var hmac = new HMACSHA256(secret);
    return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(message)))
        .ToLowerInvariant();
}
```

### C++（OpenSSL）

```cpp
std::string sign_request(const std::string& secret_hex, const std::string& method,
                         const std::string& path, long long ts, const std::string& nonce,
                         const std::string& body, const std::string& query = "") {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(body.data()), body.size(), digest);
    std::string digest_hex = to_hex(digest, SHA256_DIGEST_LENGTH);
    std::string message = "SQCLIENT-REQUEST-2\n" + method + "\n" + path + "\n" +
        std::to_string(ts) + "\n" + nonce + "\n" + query + "\n" + digest_hex;
    // HMAC-SHA256（secret 为 hex 解码后的字节）
    return hmac_sha256_hex(from_hex(secret_hex), message);
}
```

## 六、离线激活码（无网络环境）

- 格式：`LICACT1.<base64url(payload)>.<base64url(签名)>`。
- payload（JSON，规范化为紧凑格式+键排序）字段：
  `mc`（机器码）、`key`（卡密）、`ed`、`dur`、`exp`、`dev`、`note`、`feats`（功能位，可选）。
- 验证：`Ed25519.verify(离线公钥, payload_bytes, signature)` + 机器码匹配 + 未被
  时钟回拨保留过期（宿主应实现与验证端一致的"回拨保护"：记录最近见过的时间戳）。
- 注意：本机时间被回拨会让过期码"复活"——客户端务必持久化 `last_seen` 并拒绝回拨。

## 七、公钥固定流程

1. 首次联网：`GET /api/public_key` 获取
   `response_public_key` / `response_key_id` / `offline_key_fingerprint`；
2. **固定（pin）到宿主配置**，之后每响应都验证签名并核对 `key_id`；
3. 服务器轮换响应密钥后：`key_id` 变化 → 宿主应提示"服务器密钥已轮换，
   请更新固定公钥"（参考 `docs/KEY-ROTATION.md`）。

## 八、接入验收清单

- [ ] 测试向量对拍通过（canonical_message + signature_hex 完全一致）
- [ ] 激活 → 校验 → 心跳全链成功；响应签名验证开启
- [ ] `features`/`seats` 按业务逻辑消费（无该字段时为旧卡，不影响）
- [ ] 错误码表全部分支有处理（特别是 `seats_full` 重试与 `unauthenticated` 重激活）
- [ ] 离线码：验签 + 机器码 + 回拨保护
