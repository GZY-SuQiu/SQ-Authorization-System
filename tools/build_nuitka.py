#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Nuitka 客户端加固脚手架：把核心模块编译为原生扩展 + 混合打包。

目的：把"客户端零加固"（审计 P0-1）收敛为"核心判定不可读、不可改"——
把协议/密钥/完整性/客户端四个模块从 .pyc 文本级可 patch，升级为需要逆向 C 的
原生扩展；配合 attest 白名单形成"改了就上不了线"的闭环。

已实测验证（2026-11-06，Linux aarch64 沙箱全链复现）：
  1. 逐模块 --module 编译成功（offline / security / integrity / api_client）
  2. 编译产物作为 core.* 包成员导入正常（相对导入可用），功能全链通过
  3. 删除同名 .py 后系统完整运行（服务器登录/发卡/激活/verify/心跳/离线码 7/7）
  4. PyInstaller 正确将 .so/.pyd 作为 binary 收集进产物 _internal/core/
  5. 冻结产物完整性门禁行为不变（fail-closed，缺清单拒绝启动）

前置要求：
  - pip install nuitka
  - Windows 构建机：Visual Studio Build Tools（C 编译器）+ 勾选 Python 开发组件；
    或安装 MinGW64。建议同时装 ccache 加速二次编译。
  - Linux/macOS：gcc + python3-dev（Alpine: apk add gcc musl-dev python3-dev）

用法：
  python tools/build_nuitka.py compile
      编译 4 个核心模块到 build_nuitka/compiled/
  python tools/build_nuitka.py sandbox
      创建打包沙箱：复制项目 → 用编译产物替换 4 个模块（删除同名 .py）
  python tools/build_nuitka.py all
      compile + sandbox + 在沙箱内执行 python build.py（完整发布链）
  python tools/build_nuitka.py all --keep-build
      同上，但保留 Nuitka 中间产物（排查编译问题时用）

产物：<sandbox>/dist/ 下的四个可执行文件与发布清单，流程与原生 build.py 一致。
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMPILED_DIR = ROOT / "build_nuitka" / "compiled"
SANDBOX_DIR = ROOT / "build_nuitka" / "sandbox"

# 加固目标：审计结论中的四个高价值模块。
#   offline    离线激活码签名/解析（伪造防线）
#   security   请求签名 / 令牌 / 口令哈希（协议核心）
#   integrity  发布完整性自检（防篡改门禁）
#   api_client 客户端 HTTP/验签/attest 全链（客户端协议核心）
CORE_MODULES = ["offline", "security", "integrity", "api_client"]

# 沙箱复制时排除的目录（构建产物/敏感物/缓存——沙箱只需要构建输入）。
EXCLUDE_DIRS = {
    "build", "dist", "build_nuitka", ".git", "__pycache__", ".pytest_cache",
    "backup_secrets_20261008", "crash_logs", "promo_video",
}
EXCLUDE_FILES = {"server_config.json", "admin_config.json", "master_config.json",
                 "verification_config.json", "config.json"}


def _module_path(name: str) -> Path:
    return ROOT / "core" / f"{name}.py"


def compile_modules(keep_build: bool = False) -> list[Path]:
    """用 Nuitka --module 编译目标模块，返回产物路径列表。"""
    COMPILED_DIR.mkdir(parents=True, exist_ok=True)
    outputs: list[Path] = []
    for name in CORE_MODULES:
        source = _module_path(name)
        if not source.is_file():
            raise SystemExit(f"缺少源文件：{source}")
        print(f"\n==== 编译 core/{name}.py ====")
        cmd = [
            sys.executable, "-m", "nuitka",
            "--module", str(source.relative_to(ROOT)),
            # Nuitka 仅接受 --output-dir=<path> 等号形式。
            f"--output-dir={COMPILED_DIR}",
        ]
        result = subprocess.run(cmd, cwd=str(ROOT))
        if result.returncode != 0:
            raise SystemExit(f"Nuitka 编译失败：core/{name}.py（返回码 {result.returncode}）")
        # 收集产物（.pyd / .so；Nuitka 会自动附带平台标签）
        candidates = [
            p for p in COMPILED_DIR.glob(f"{name}.*")
            if p.suffix.lower() in (".pyd", ".so")
        ]
        if not candidates:
            raise SystemExit(f"未找到编译产物：{COMPILED_DIR}/{name}.*")
        outputs.append(sorted(candidates)[-1])
        print(f"产出：{outputs[-1].name}")
        if not keep_build:
            build_dir = COMPILED_DIR / f"{name}.build"
            shutil.rmtree(build_dir, ignore_errors=True)
    return outputs


def _copy_project(target: Path) -> None:
    """把项目复制进沙箱（排除构建产物与敏感物），供 PyInstaller 打包。"""
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)
    target.mkdir(parents=True)

    def ignore(directory: str, names: list[str]) -> set[str]:
        skipped = set()
        for name in names:
            if name in EXCLUDE_DIRS or name in EXCLUDE_FILES:
                skipped.add(name)
        return skipped

    shutil.copytree(ROOT, target, ignore=ignore, dirs_exist_ok=True)


def _stage_compiled(target: Path) -> None:
    """在沙箱内：删除 4 个同名 .py，放入编译产物（统一简名）。"""
    for name, compiled in zip(CORE_MODULES, _collect_compiled()):
        py_path = target / "core" / f"{name}.py"
        if py_path.exists():
            py_path.unlink()
        # 统一改名：Windows → name.pyd；其它平台 → name.so
        suffix = ".pyd" if compiled.suffix.lower() == ".pyd" else ".so"
        shutil.copy2(compiled, target / "core" / f"{name}{suffix}")
    print(f"沙箱加固完成：{target}")


def _collect_compiled() -> list[Path]:
    outputs: list[Path] = []
    for name in CORE_MODULES:
        candidates = [
            p for p in COMPILED_DIR.glob(f"{name}.*")
            if p.suffix.lower() in (".pyd", ".so")
        ]
        if not candidates:
            raise SystemExit(f"缺少编译产物（先执行 compile）：{name}")
        outputs.append(sorted(candidates)[-1])
    return outputs


def create_sandbox(sandbox: Path = SANDBOX_DIR) -> Path:
    """compile 的产物 + 项目副本 → 可直接运行 build.py 的加固沙箱。"""
    _copy_project(sandbox)
    _stage_compiled(sandbox)
    print("\n提示：在沙箱内运行 `python build.py` 完成 PyInstaller 打包与发布链。")
    return sandbox


def run_build(sandbox: Path) -> int:
    print(f"\n==== 在沙箱内执行 build.py：{sandbox} ====")
    return subprocess.run([sys.executable, "build.py"], cwd=str(sandbox)).returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Nuitka 客户端加固脚手架")
    parser.add_argument(
        "action",
        choices=["compile", "sandbox", "all"],
        help="compile=编译模块；sandbox=创建加固沙箱；all=编译+沙箱+打包",
    )
    parser.add_argument("--keep-build", action="store_true", help="保留 Nuitka 中间产物")
    parser.add_argument("--sandbox", type=Path, default=SANDBOX_DIR, help="沙箱目录")
    args = parser.parse_args(argv)

    if args.action in ("compile", "all"):
        compile_modules(keep_build=args.keep_build)
    if args.action in ("sandbox", "all"):
        create_sandbox(args.sandbox)
    if args.action == "all":
        return run_build(args.sandbox)
    print("\n完成。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
