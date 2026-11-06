@echo off
setlocal EnableExtensions
title SQ 授权系统 · 一键构建
cd /d "%~dp0"
echo.
echo   ================================================
echo    SQ 授权系统 · 一键构建（全自动生成安装包）
echo   ================================================
echo.

rem ---- 1/4 Python 检查（python 或 py 启动器） ----
set "PY=python"
where python >nul 2>nul
if errorlevel 1 (
  where py >nul 2>nul
  if errorlevel 1 (
    echo   [缺少] 未检测到 Python。
    echo   请安装 Python 3.12：https://www.python.org/downloads/
    echo   安装时务必勾选 "Add python.exe to PATH" 后重试。
    pause
    exit /b 1
  )
  set "PY=py -3"
)
%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" >nul 2>nul
if errorlevel 1 (
  echo   [提示] Python 版本过旧（需要 3.10 以上，建议 3.12），请升级后重试。
  pause
  exit /b 1
)

rem ---- 2/4 依赖 ----
echo   [1/4] 安装依赖（首次需要几分钟，请保持网络畅通）…
%PY% -m pip install --upgrade pip >nul 2>nul
%PY% -m pip install -r requirements.txt
if errorlevel 1 (
  echo.
  echo   [错误] 依赖安装失败（通常是网络问题）。重新运行本脚本可自动重试。
  pause
  exit /b 1
)

rem ---- 3/4 构建四端（PyInstaller，无需安装编译器） ----
echo.
echo   [2/4] 构建四个程序（约 5-10 分钟，请耐心等待）…
%PY% build.py
if errorlevel 1 (
  echo.
  echo   [错误] 构建失败。请把上方报错内容截图反馈。
  pause
  exit /b 1
)

rem ---- 4/4 发布包 + 安装器 ----
echo.
echo   [3/4] 生成发布包（完整性校验 + 便携版 ZIP）…
%PY% installer\make_package.py --release-package dist\release_package --output installer_out
if errorlevel 1 (
  echo   [错误] 发布包制作失败。
  pause
  exit /b 1
)

echo.
echo   [4/4] 制作安装器…
%PY% installer\make_sfx_installer.py --app installer_out\app --sfx installer\tools\7zsd_All_x64.sfx --output installer_out\SQ授权系统-安装包-1.0.0.exe
if errorlevel 1 (
  echo   [错误] 安装器制作失败。
  pause
  exit /b 1
)

echo.
echo   ================================================
echo    [完成] 安装包已生成：
echo      installer_out\SQ授权系统-安装包-1.0.0.exe
echo    （同目录还有便携版 ZIP）
echo   ================================================
start "" explorer "installer_out"
pause
