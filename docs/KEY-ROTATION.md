# 密钥轮换操作手册（SOP）

> 触发场景：密钥材料流转到不可控位置（外发、多手传递、备份失守——例如完整包
> 带私钥分发给第三方审计）、怀疑泄露、人员变动、或按安全周期主动轮换。
>
> 本手册配合 `tools/rotate_keys.py` 使用；全部行为已在沙箱实测验证（见文末记录）。

## 一、轮换对象与影响面（先理解，再动手）

| 密钥 | 轮换影响 | 用户侧感知 |
|---|---|---|
| `server_config.secret_key` | 全部会话 token / attest / AI 确认令牌立即失效；库内加密会话密钥无法解密 | 客户端 **重新激活即恢复**（实测：老会话返回"未激活"，重激活成功） |
| `offline_private_key` | 所有已签发的离线激活码作废 | 离线用户需重新签发离线码 |
| `response_private_key` | 响应的 Ed25519 签名身份更换；客户端固定的旧公钥校验失败 | 必须发布**新客户端**（固定新公钥） |
| `release_key.json`（发布签名） | 旧 exe 无法通过新清单校验 | 配合版本升级与新清单分发（自动退役旧版） |
| `license.db` | **不轮换**（业务数据） | 无感知，激活记录全部保留 |

## 二、操作步骤（服务器 + 构建机）

```bash
# 0) 停止本地服务器（避免运行中回写配置），全量备份整个工作目录
#    保险：额外拷贝一份 data/license.db 单独存档

# 1) 预演（不修改任何东西，先看会做什么）
python tools/rotate_keys.py

# 2) 执行轮换（自动备份 release_key.json 与 server_config.json 到 key-rotation-backup/）
python tools/rotate_keys.py --apply

# 3) 重启本地服务器 —— 自动生成全新 secret_key / offline / response 密钥
python server/main.py --headless        # 或双击 本地服务器.exe

# 4) 导出新公钥（给客户端固定用）
python server/main.py --print-public-key

# 5) 重建发布包（build.py 自动生成新的发布密钥对，并把新公钥固定进四个程序）
python build.py
#    若使用加固链：python tools/build_nuitka.py all

# 6) 服务器导入新发布清单（本地服务器启动时自动导入 releases/ 下的清单；
#    或将 dist/release_package 放好后重启，旧版本自动退役）

# 7) 分发新客户端（验证端/管理端/主控端 + release_manifest.json + .sig 同目录）
#    旧客户端：能连但会被 attest 拒绝（若启用白名单）——按发布节奏灰度替换

# 8) 为用户重新签发离线激活码；已发出未使用的旧离线码作废处理
```

## 三、客户端侧配套动作

- 管理端 / 验证端 / 主控端：**删除旧配置文件**（*_config.json），重新连接服务器——
  客户端会在登录后重新固定新公钥（这是设计行为，见 `ApiClient.set_base_url`）。
- 若验证端提示"响应签名校验失败"，即需要执行上一条（旧公钥）。

## 四、验收检查单

- [ ] 服务器启动正常，`/api/health` 200
- [ ] 新 key 指纹与旧不同（`--print-public-key` 对比）
- [ ] 旧客户端连新服务器：被拒（例如响应验签失败 / attest 拒绝）——符合预期
- [ ] 新客户端全链：登录 → 激活 → verify → 心跳 → 离线码签发/导入
- [ ] 老用户客户端重新激活后正常（数据保留、无需管理员干预）
- [ ] `key-rotation-backup/` 已妥善归档（确认新链路稳定前不要删除）

## 五、回滚方案

轮换后发现问题需要回滚：

1. 停止服务器；
2. 从 `key-rotation-backup/` 恢复 `server_config.*.json` → 覆盖 `server_config.json`；
   恢复 `release_key.*.json` → 放回 `release_keys/release_key.json`；
3. 重启服务器。旧会话密钥恢复可解密，一切回到轮换前状态；
4. 注意：期间新产生的会话/离线码/清单将失效，按需重发。

## 六、沙箱实测记录（2026-11-06，随本 SOP 一并交付）

```
密钥指纹变化：
  secret_key            fc2b7fe21e -> deee92cf64   CHANGED
  offline_private_key   1c528a1718 -> 4459792601   CHANGED
  response_private_key  171763712d -> 8f8233d69a   CHANGED

行为验证：
  [6] 轮换前签发的会话 -> verify: code=unauthenticated（优雅失效，非报错崩溃）
  [7] 同一设备重新激活 -> ok=True（幂等 already）
  [8] 新会话 verify -> ok=True, remaining=4天23小时
  [9] license.db 数据完好：status=active、到期时间保留

结论：轮换不丢数据、不破坏业务；客户端侧唯一需要的就是"重新激活"这一动作。
```
