# 客户端加固：Nuitka 编译与混合打包

> 对应审计结论 P0-1："PyInstaller 裸包可一条命令解包（257 文件 + 507 模块），
> 协议全部可读、判定可改"。本方案把四个高价值模块编译为原生扩展（Nuitka C 后端），
> patch 面从"改文本级 pyc"升级为"逆向 C 代码"，配合 attest 白名单形成闭环。

## 一、加固目标（四模块）

| 模块 | 职责 | 加固后效果 |
|---|---|---|
| `core/offline` | 离线激活码签名/解析 | 伪造离线码需逆向原生代码 |
| `core/security` | 请求签名 / 令牌 / 口令哈希 | 协议核心不可读 |
| `core/integrity` | 发布完整性自检 | 门禁判定不可 patch |
| `core/api_client` | 客户端 HTTP/验签/attest 全链 | 假服务器 + patch 验签组合失效 |

## 二、用法

```bash
# 0) 前置（构建机）
pip install nuitka
#  Windows：安装 VS Build Tools（C 编译器），建议加装 ccache 加速
#  Linux/macOS：gcc + python3-dev

# 1) 编译四模块 → build_nuitka/compiled/
python tools/build_nuitka.py compile

# 2) 创建加固沙箱（复制项目 + 用编译产物替换 4 个模块）
python tools/build_nuitka.py sandbox

# 3) 一键完整流程（compile + sandbox + 在沙箱内执行 build.py 打包）
python tools/build_nuitka.py all
```

产物：`build_nuitka/sandbox/dist/` —— 与原生 build.py 完全一致的四个程序 + 发布清单 + 签名。

## 三、机制说明

- **为什么要在"沙箱"里打包**：扩展模块（`.pyd`/`.so`）在 import 时优先于同名 `.py`，
  但为避免 PyInstaller 静态分析倾向源码，沙箱内直接**删除 4 个同名 `.py`**、
  只留编译产物——PyInstaller 必然将其作为 binary 收集（已实测：
  `_internal/core/offline.so` 等正确入包）。
- **为什么只编译 4 个**：其余模块是业务 UI/数据层，加固收益低、编译成本高；
  四个模块覆盖"密钥、协议、门禁、客户端通信"全部攻击价值面。
- **开发不受影响**：仓库源码原样保留（.py 仍在），日常开发/测试一切照旧；
  加固只发生在打包链。

## 四、已完成的沙箱实测（2026-11-06）

| 验证项 | 结果 |
|---|---|
| `compile`：4 模块 Nuitka 编译 | ✅ 全部成功（约 4 分钟） |
| 编译产物作为 `core.*` 导入（含相对导入） | ✅ loader = nuitka_module_loader |
| 删除同名 .py 后系统完整运行 | ✅ 服务器全链 7/7（登录/发卡/激活/verify/心跳/离线码） |
| PyInstaller 收集编译模块 | ✅ `_internal/core/{offline,security,integrity,api_client}.so` |
| 冻结产物完整性门禁 | ✅ fail-closed 行为不变（缺清单拒绝启动） |

## 五、发布注意

1. 加固产物与普通产物**发布流程完全相同**（清单签名、attest 白名单、卫生检查全部照旧）。
2. 首次加固发布后，旧客户端与新客户端可共存——attest 按哈希白名单放行，新旧各自登记即可。
3. 如遇 Nuitka 兼容问题需回退：直接运行原生 `python build.py` 即可（源码未动）。
4. 每轮 Nuitka 升级后建议重跑一次全链测试（`python -m pytest tests/ -q`）。

## 六、进一步硬化（可选，后续批次）

- `--python-flag=no_docstrings` 去除文档字符串；
- 对字符串常量做加密插件（社区插件生态）；
- 关键判定进一步下沉到 native（如响应验签入口收进一个不可绕过的 C 校验函数）。
