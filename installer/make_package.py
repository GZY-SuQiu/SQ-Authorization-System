#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""发布包制作器：校验发布包 → 生成便携版 ZIP + 安装器素材目录。

用法（在 Windows 构建机上，构建完成之后）::

    python installer/make_package.py --release-package dist/release_package
    python installer/make_package.py --release-package dist/release_package --skip-verify

输出（默认 ./installer_out/）::

    installer_out/
      SQ授权系统-便携版-<版本>.zip      # 解压即用（四个程序 + 清单 + 说明）
      app/                              # 喂给 NSIS / Inno Setup 的干净素材
        ├─ 本地服务器.exe / 管理端.exe / 验证端.exe / 主控端.exe
        ├─ release_manifest.json / release_manifest.sig
        ├─ releases/（白名单副本）
        └─ 安装说明.txt

校验：调用 tools/release_manifest.verify_release_package（清单验签 + 四端
哈希复核 + 多余文件检查）。
"""

from __future__ import annotations

import argparse
import shutil
import sys
import zipfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

APP_NAMES = ("本地服务器.exe", "管理端.exe", "验证端.exe", "主控端.exe")

README_TEXT = """SQ 授权系统 · 使用说明
=====================================
1. 先运行「本地服务器.exe」并保持运行（默认 127.0.0.1:8765）。
2. 首次启动会自动创建主控账号 admin，并在界面显示一次性初始密码。
3. 用「主控端.exe」或「管理端.exe」登录，生成卡密并分发。
4. 用户运行「验证端.exe」，输入卡密完成激活。

注意：
- 请勿删除 release_manifest.json / release_manifest.sig（程序完整性自检要用）。
- 四个程序必须与清单文件放在同一目录。
- 数据文件在 data/ 目录；server_config.json 含服务端密钥，务必与 data/ 一起备份。
"""


def verify_package(package_dir: Path) -> list[str]:
    """完整性校验：卫生扫描 + 清单验签 + 四端哈希复核。"""
    import json

    from core import integrity, release_pubkey
    from tools import release_manifest

    problems = list(release_manifest.verify_release_package(package_dir))

    manifest_path = package_dir / "release_manifest.json"
    signature_path = package_dir / "release_manifest.sig"
    if not manifest_path.is_file() or not signature_path.is_file():
        problems.append("缺少 release_manifest.json / release_manifest.sig")
        return problems
    manifest_bytes = manifest_path.read_bytes()
    signature_text = signature_path.read_text(encoding="ascii", errors="replace").strip()
    public_hex = getattr(release_pubkey, "RELEASE_PUBLIC_KEY_HEX", "")
    if not public_hex:
        problems.append("本地未固定发布公钥（core/release_pubkey.py 缺失），无法验签")
        return problems
    if not integrity.verify_manifest_signature(manifest_bytes, signature_text, public_hex):
        problems.append("发布清单签名校验失败（清单可能被篡改）")
        return problems
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8-sig"))
    except Exception:
        problems.append("发布清单无法解析")
        return problems
    apps = manifest.get("apps") if isinstance(manifest, dict) else None
    if not isinstance(apps, dict) or not apps:
        problems.append("发布清单缺少 apps 登记")
        return problems
    for role, entry in apps.items():
        if not isinstance(entry, dict):
            continue
        relative = str(entry.get("path") or "").strip()
        expected = str(entry.get("sha256") or "").strip().lower()
        target = package_dir / relative
        if not relative or not target.is_file():
            problems.append(f"缺少程序文件：{relative or role}")
            continue
        actual = integrity.sha256_file(target)
        if expected and actual != expected:
            problems.append(f"哈希不一致：{relative}")
    return problems


def _zip_dir(source: Path, target: Path) -> int:
    count = 0
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=7) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(source))
                count += 1
    return count


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="SQ 发布包制作器")
    parser.add_argument("--release-package", required=True, help="dist/release_package 目录")
    parser.add_argument("--output", default=str(ROOT / "installer_out"), help="输出目录")
    parser.add_argument("--skip-verify", action="store_true", help="跳过完整性校验（不推荐）")
    args = parser.parse_args(argv)

    package_dir = Path(args.release_package).expanduser().resolve()
    output_dir = Path(args.output).expanduser().resolve()
    if not package_dir.is_dir():
        print(f"错误：发布包目录不存在：{package_dir}", file=sys.stderr)
        return 2

    missing = [name for name in APP_NAMES if not (package_dir / name).is_file()]
    if missing:
        print(f"错误：发布包缺少程序：{missing}", file=sys.stderr)
        return 2

    if not args.skip_verify:
        problems = verify_package(package_dir)
        if problems:
            print("完整性校验未通过：", file=sys.stderr)
            for item in problems:
                print(f"  - {item}", file=sys.stderr)
            return 1
        print("[OK] 发布包完整性校验通过（清单验签 + 四端哈希复核）")

    # 素材目录
    app_dir = output_dir / "app"
    if app_dir.exists():
        shutil.rmtree(app_dir)
    app_dir.mkdir(parents=True)
    for path in sorted(package_dir.rglob("*")):
        if path.is_file():
            relative = path.relative_to(package_dir)
            destination = app_dir / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)
    (app_dir / "安装说明.txt").write_text(README_TEXT, encoding="utf-8-sig")

    # 版本
    version = "1.0.0"
    try:
        import json

        manifest = json.loads((package_dir / "release_manifest.json").read_text(encoding="utf-8"))
        version = str(manifest.get("version") or version)
    except Exception:
        pass

    # 便携版 ZIP
    stamp = datetime.now().strftime("%Y%m%d")
    zip_path = output_dir / f"SQ授权系统-便携版-{version}-{stamp}.zip"
    count = _zip_dir(app_dir, zip_path)

    print(f"[OK] 安装素材目录：{app_dir}")
    print(f"[OK] 便携版 ZIP：{zip_path}（{count} 个文件）")
    print()
    print("接下来（在 Windows 上生成向导式安装器，二选一）：")
    print("  A. NSIS：  makensis /DAPP_DIR=%s installer/sq_license_setup.nsi" % app_dir)
    print("  B. Inno：  用 Inno Setup 打开 installer/sq_license_setup.iss 并编译")
    print("     （两套脚本已随仓库提供，产物均为单文件 setup.exe）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
