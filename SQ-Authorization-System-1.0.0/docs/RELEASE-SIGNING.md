# 发布清单签名（Ed25519）

本文说明 SQ 授权系统的发布签名密钥保管与构建流程。接口字段以
`docs/INTEGRITY-INTERFACE.md` 为准，不在本文重复定义。

## 产物与职责

| 文件 | 归属 | 说明 |
| --- | --- | --- |
| `release_keys/release_key.json` | 构建机（不入库） | 发布私钥（32 字节种子 hex）、公钥、创建时间。**绝不随包分发。** |
| `core/release_pubkey.py` | 生成物（不入库） | 构建前由公钥覆盖，随四个 exe 一起打包固定。 |
| `dist/release_manifest.json` | 发布产物 | 四个 exe 的相对路径、SHA-256、大小与目录校验规则。 |
| `dist/release_manifest.sig` | 发布产物 | 对清单**原始字节**的 Ed25519 签名，base64url 无填充，单行。 |
| `dist/releases/release_manifest.json(.sig)` | 发布产物 | 同一份清单与签名的副本，供服务端启动时加载。 |

## 私钥保管

- 发布私钥泄露等于**离线签发能力泄露**：拿到私钥的人可以伪造任意版本发布清单，
  让被篡改的客户端通过完整性校验并成功 attest。因此：

1. `release_keys/` 已被 `.gitignore` 排除，只允许保留在离线构建机或加密介质上，
   任何情况下都不得进入版本库、安装包、工单或聊天记录。
2. 工具会尽力收紧权限（`chmod 600`；Windows 上用 `icacls` 移除继承并只授权
   当前用户），但这只是兜底，不能替代离线保管。
3. 建议至少保留两份加密备份（例如离线硬盘 + 密码管理器内的加密副本），并记录
   公钥指纹（`core.offline.public_key_fingerprint`）用于日后核对。
4. 构建日志只需要打印公钥指纹，禁止打印私钥内容。

## 轮换注意事项

- 轮换会产生新的公钥，**旧版本 exe 内固定的是旧公钥**：轮换后旧客户端无法再校验
  新清单，必须重新打包并重新分发，同时通知服务端更新 `release_public_key` 配置。
- 轮换步骤：离线保存并移走 `release_keys/release_key.json` → 删除该文件 →
  重新构建（工具会生成新密钥对）→ 记录并公告新公钥指纹 → 重新导入发布清单。
- 怀疑私钥泄露时：立即停止使用旧密钥、按上述步骤轮换、把服务端
  `release_public_key` 换成新公钥，并回收所有由旧密钥签发的发布清单。
- 不要直接编辑 `core/release_pubkey.py`；它每次构建都会被覆盖，手改既无效也容易
  造成“以为换了公钥其实没换”的误判。

## 构建流程

```powershell
python build.py                 # 版本号默认 1.0.0
```

构建脚本按以下顺序执行，任一步失败都会打印明确错误并以非零码退出：

1. 检查 PyInstaller 与图标。
2. `tools.release_manifest.ensure_keypair("release_keys/release_key.json")`：
   密钥不存在时生成；存在但损坏或公私钥不匹配时**报错退出**，不会静默轮换。
3. `tools.release_manifest.write_pubkey_module(public_key)`：把公钥写进
   `core/release_pubkey.py`，再由 PyInstaller 打进四个 exe。
4. 依次打包 `本地服务器.exe`、`管理端.exe`、`验证端.exe`、`主控端.exe`，
   并保持原有 ICU 冲突检查。
5. `tools.release_manifest.write_signed_manifest(dist, version)`：生成清单与签名，
   写入 `dist/` 并在 `dist/releases/` 留副本。
6. 打印每个产物大小、清单路径、签名路径与公钥指纹。

签名对象是清单的原始字节（UTF-8 无 BOM、2 空格缩进），因此**任何手工改动
`release_manifest.json` 都会导致验签失败**。需要改清单时请重新运行构建或下方的
CLI，而不是编辑文件。

## 单独重新生成清单

只重新签名现有 `dist`（例如重新打包后补齐清单）而不跑完整 PyInstaller：

```powershell
python -m tools.release_manifest --dist dist --version 1.0.0
```

## 测试

```powershell
python -m unittest tests.test_release_manifest -v
```

测试在临时目录内构造假 exe 与独立密钥对，不会触碰仓库里的
`release_keys/` 或 `core/release_pubkey.py`。
