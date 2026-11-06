#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""制作 7zSD 自解压安装器（跨平台 · 无需 NSIS/Inno Setup）。

产物：单文件 Setup.exe —— 双击 → 提示确认 → 解压到临时目录 → 自动执行
install.bat（安装到当前用户目录 LocalAppData\\Programs，无需管理员权限，
自动创建开始菜单/桌面快捷方式与卸载器）。

前置：
  1. 7zSD 模块（7zsd_All_x64.sfx）：来自 7zsfxmm 项目
     https://github.com/chrislake/7zsfxmm/releases （7zsd_extra_*.7z 内）
  2. 7z 打包工具：Windows 用 7-Zip 自带 7z.exe；Linux 用 7zz（apk add 7zip）

用法::

    python installer/make_sfx_installer.py --app installer_out/app \\
        --sfx tools/7zsd_All_x64.sfx --output installer_out/SQ授权系统-安装程序-1.0.0.exe
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CONFIG_TEXT = """;!@Install@!UTF-8!
Title="SQ 授权系统 安装程序"
BeginPrompt="即将安装 SQ 授权系统（安装到当前用户目录，无需管理员权限）。\\n\\n是否继续？"
ExtractTitle="正在安装 SQ 授权系统..."
ExtractDialogText="正在解压安装文件，请稍候…"
ExtractCancelText="取消安装"
RunProgram="install.bat"
;!@InstallEnd@!
"""

INSTALL_BAT = """@echo off
setlocal EnableExtensions
set "TARGET=%LOCALAPPDATA%\\Programs\\SQ授权系统"
echo.
echo   SQ 授权系统 · 安装程序（当前用户安装，无需管理员）
echo   --------------------------------------------------
mkdir "%TARGET%" 2>nul
xcopy /E /I /Y "%~dp0app\\*" "%TARGET%\\" >nul
if errorlevel 1 (
  echo   [错误] 文件复制失败，请重试。
  pause
  exit /b 1
)
set "START=%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\SQ授权系统"
mkdir "%START%" 2>nul
powershell -NoProfile -ExecutionPolicy Bypass -Command "$w=New-Object -ComObject WScript.Shell; $p='%TARGET%'; $sm='%START%'; foreach($n in @('本地服务器','管理端','验证端','主控端')){ $s=$w.CreateShortcut($sm+'\\'+$n+'.lnk'); $s.TargetPath=$p+'\\'+$n+'.exe'; $s.WorkingDirectory=$p; $s.Save() }; $s=$w.CreateShortcut($sm+'\\卸载 SQ 授权系统.lnk'); $s.TargetPath=$p+'\\卸载.bat'; $s.WorkingDirectory=$p; $s.Save(); $d=[Environment]::GetFolderPath('Desktop'); $s=$w.CreateShortcut($d+'\\SQ 验证端.lnk'); $s.TargetPath=$p+'\\验证端.exe'; $s.WorkingDirectory=$p; $s.Save()"
echo.
echo   [完成] 已安装到：%TARGET%
echo   开始菜单 → SQ授权系统；桌面 → SQ 验证端。
echo   首次使用请先运行「本地服务器」。
echo.
pause
exit /b 0
"""

UNINSTALL_BAT = """@echo off
setlocal
set "TARGET=%LOCALAPPDATA%\\Programs\\SQ授权系统"
echo 正在卸载 SQ 授权系统（data 授权数据默认保留）…
choice /C YN /M "是否同时删除授权数据（data 目录与 server_config.json）"
if errorlevel 2 goto keep
rmdir /s /q "%TARGET%\\data" 2>nul
del "%TARGET%\\server_config.json" 2>nul
:keep
del "%USERPROFILE%\\Desktop\\SQ 验证端.lnk" 2>nul
rmdir /s /q "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\SQ授权系统" 2>nul
rmdir /s /q "%TARGET%\\assets" 2>nul
rmdir /s /q "%TARGET%\\releases" 2>nul
del "%TARGET%\\*.exe" 2>nul
del "%TARGET%\\release_manifest.*" 2>nul
del "%TARGET%\\安装说明.txt" 2>nul
del "%TARGET%\\卸载.bat" 2>nul
rmdir "%TARGET%" 2>nul
echo 卸载完成。
pause >nul
"""


def _find_sevenzip(explicit: str | None) -> str:
    if explicit:
        return explicit
    for name in ("7zz", "7z", "7za", "7z.exe"):
        found = shutil.which(name)
        if found:
            return found
    # Windows 常见安装位置（PATH 未加入时兜底）
    for candidate in (
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
        "/usr/bin/7zz",
    ):
        if Path(candidate).is_file():
            return candidate
    raise SystemExit("未找到 7z 打包工具（7zz / 7z）")


def build(app_dir: Path, sfx_path: Path, output: Path, sevenzip: str | None = None) -> Path:
    tool = _find_sevenzip(sevenzip)
    if not sfx_path.is_file():
        raise SystemExit(f"缺少 7zSD 模块：{sfx_path}")

    with tempfile.TemporaryDirectory(prefix="sq-sfx-") as tmp_name:
        tmp = Path(tmp_name)
        staging = tmp / "staging"
        (staging / "app").mkdir(parents=True)

        # 内容物
        for path in sorted(app_dir.rglob("*")):
            if path.is_file():
                relative = path.relative_to(app_dir)
                destination = staging / "app" / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, destination)
        # 中文批处理用 GBK 保存（Windows cmd 兼容）
        (staging / "install.bat").write_bytes(INSTALL_BAT.encode("gbk"))
        (staging / "app" / "卸载.bat").write_bytes(UNINSTALL_BAT.encode("gbk"))
        (tmp / "config.txt").write_text(CONFIG_TEXT, encoding="utf-8")

        archive = tmp / "setup.7z"
        result = subprocess.run(
            [tool, "a", "-t7z", "-m0=lzma2", "-mx=7", "-md=32m", "-mmt=on",
             str(archive), "."],
            cwd=str(staging),
        )
        if result.returncode != 0 or not archive.is_file():
            raise SystemExit("7z 打包失败")

        output.parent.mkdir(parents=True, exist_ok=True)
        with open(output, "wb") as out:
            out.write(sfx_path.read_bytes())
            out.write((tmp / "config.txt").read_bytes())
            out.write(archive.read_bytes())
    return output


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="制作 7zSD 自解压安装器")
    parser.add_argument("--app", required=True, help="安装素材目录（make_package.py 输出的 app/）")
    parser.add_argument("--sfx", required=True, help="7zsd_All_x64.sfx 路径")
    parser.add_argument("--output", required=True, help="输出 Setup.exe 路径")
    parser.add_argument("--sevenzip", default=None, help="7z 可执行文件（默认自动探测）")
    args = parser.parse_args(argv)

    app_dir = Path(args.app).expanduser().resolve()
    if not app_dir.is_dir():
        print(f"错误：素材目录不存在：{app_dir}", file=sys.stderr)
        return 2
    output = build(app_dir, Path(args.sfx).expanduser(), Path(args.output).expanduser(), args.sevenzip)
    size_mb = output.stat().st_size / 1024 / 1024
    print(f"[OK] 安装器已生成：{output}（{size_mb:.1f} MB）")
    print("提示：在 Windows 干净环境双击验证一遍：安装 → 快捷方式 → 四端启动 → 卸载。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
