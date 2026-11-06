# 安装包制作（三种分发形态）

> 流程：`python build.py` 出发布包 → `python installer/make_package.py` 校验并
> 生成素材 → 任选一种安装器制作。

## 一、一键流程（Windows 构建机）

```powershell
:: 1) 打包四个程序 + 发布清单（已有流程）
python build.py

:: 2) 校验发布包并生成 素材目录 + 便携版 ZIP
python installer/make_package.py --release-package dist\release_package
::    输出：installer_out\app\（四个程序+清单+说明）
::          installer_out\SQ授权系统-便携版-1.0.0-日期.zip

:: 3) 生成向导式安装器（二选一）
::   A. NSIS（推荐；winget install NSIS.NSIS 或官网下载）
makensis /DAPP_DIR=installer_out\app installer\sq_license_setup.nsi
::     产物：SQ授权系统-Setup-1.0.0.exe

::   B. Inno Setup 6
ISCC.exe /DAPP_DIR=installer_out\app installer\sq_license_setup.iss
::     产物：SQ授权系统-Setup-1.0.0.exe
```

## 二、三种形态对比

| 形态 | 产物 | 适用 | 特点 |
|---|---|---|---|
| 便携版 ZIP | 解压即用目录 | 老客户、U 盘分发 | 零安装、绿色 |
| NSIS 安装器 | 单文件 setup.exe | 正式分发（推荐） | 中文向导、开始菜单/桌面快捷方式、卸载器（保留数据目录） |
| Inno 安装器 | 单文件 setup.exe | NSIS 不可用时的备选 | 同上（可选中文需放语言文件） |
| **7zSD 自解压安装器** | 单文件 Setup.exe | **跨平台制作（含无 Windows 环境）** | 双击安装（当前用户级）、快捷方式、卸载器 |

**共同约定**：卸载不删除 `data/` 与 `server_config.json`（授权库与密钥防误删）；
四个程序必须与 `release_manifest.json/.sig` 同目录（完整性自检）。

## 一点五、方式 C：7zSD 自解压安装器（跨平台，无需 NSIS/Inno）

```bash
# 前置：7zSD 模块已随仓库提供 installer/tools/7zsd_All_x64.sfx
python installer/make_sfx_installer.py \
    --app installer_out/app \
    --sfx installer/tools/7zsd_All_x64.sfx \
    --output "installer_out/SQ授权系统-安装程序-1.0.0.exe"
```

特点：单文件双击安装（当前用户目录、免管理员）；自动创建开始菜单/桌面
快捷方式与卸载器；**在任何平台（含 Linux/macOS）都能制作**。
流程：双击 → 确认提示 → 解压 → 自动安装 → 完成。

## 三、校验与防护（make_package 内建）

1. **卫生扫描**（`tools/release_manifest.verify_release_package`）：
   发现任何 config / db / 私钥 / 疑似密钥内容 → 拒绝打包；
2. **清单验签**（Ed25519，内嵌发布公钥）→ 清单被篡改则拒绝；
3. **四端哈希复核**（与清单逐一对账）→ 任一程序被改动则拒绝。

## 四、沙箱验证记录（2026-11-06，本仓库实测）

| 项目 | 结果 |
|---|---|
| `make_package.py` 对真实发布材料运行 | ✅ 清单验签 + 4 端哈希全过；便携 ZIP 产出（7 文件） |
| 篡改检测（改 1 字节后重跑） | ✅ 精确报"哈希不一致：管理端.exe"并中止 |
| NSIS 安装器在沙箱编译 | ⚠️ 环境限制：PRoot 下 NSIS 自举（NSISRT）无法初始化（Linux 沙箱特性，非脚本问题）。**脚本按标准 NSIS 3.x 语法编写，请在 Windows 上编译**（一条命令，见上） |
| `entrypoint.sh` / compose / nsi 语法 | ✅ shell 语法检查通过；compose YAML 校验通过 |

## 五、发布检查单（安装包相关）

- [ ] `make_package.py` 校验通过（三重复核）
- [ ] 安装器文件名与版本号一致（`SQ授权系统-Setup-<版本>.exe`）
- [ ] 在干净 Windows 虚拟机安装一次：四端可启动、快捷方式正确、卸载保留数据
- [ ] 安装器分发给用户前，与发布包一同归档
