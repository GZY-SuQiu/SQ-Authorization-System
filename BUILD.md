# 构建指南（本仓库 = SQ 授权系统 · 安装包构建仓库）

## 方式一：GitHub 云端一键（推荐 · 零环境要求）
1. 打开仓库页 → **Actions** 标签；
2. 左侧选 **build-windows-installer** → 点 **Run workflow**（绿色按钮）；
3. 等待约 10~15 分钟；
4. 构建完成后，点开这次运行，页面底部 **Artifacts** 下载：
   - **SQ-Installer-1.0.0**（含 `SQ-Installer-1.0.0.exe` 安装包 + 便携版 ZIP）。

## 方式二：本地一键（Windows）
克隆/解压本仓库 → 双击 **一键构建.bat** → 全程自动（需要已装 Python 3.12）→
完成后自动打开 `installer_out\`（内含安装包与便携版）。

## 产物说明
- `SQ-Installer-1.0.0.exe`：单文件安装器，双击安装（当前用户级，免管理员），
  自动创建开始菜单/桌面快捷方式与卸载器。
- `SQ-Portable-1.0.0.zip`：便携版，解压即用。
