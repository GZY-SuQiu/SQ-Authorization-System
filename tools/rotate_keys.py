#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""密钥轮换辅助：备份当前密钥材料并重置，让服务器 / 构建链重新生成。

背景：发布签名私钥、服务器三密钥一旦流转到不可控位置（外发、多手传递、
备份失守——例如本次审计中发现的"完整包带私钥分发"），必须按泄露处置轮换：
旧密钥签发的激活码、发布清单、响应签名全部作废重发。

用法::

    python tools/rotate_keys.py                    # dry-run：显示将执行的操作
    python tools/rotate_keys.py --apply            # 执行：备份 + 重置
    python tools/rotate_keys.py --apply --backup-dir D:\\sq-key-backup-20261106

执行内容（--apply）::

    1. 备份 release_keys/release_key.json（如存在）到备份目录
    2. 备份 server_config.json 到备份目录
    3. 从 server_config.json 移除 secret_key / offline_* / response_* 字段
       （服务器下次启动自动重新生成——见 core/config.py 的密钥自举逻辑）
    4. 删除 release_keys/release_key.json（build.py 下次构建自动生成新对）
    5. 打印后续步骤指引（重建 → 重签 → 重发）

不做的事：不触碰 license.db。激活记录全部保留；旧会话密钥在轮换后会
自动失效（解密失败 → 视为未激活），客户端**重新激活即恢复**——该行为
已在沙箱实测验证。

重要提醒：执行前先停止本地服务器进程，避免配置被运行中的进程回写覆盖。
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RELEASE_KEY_PATH = ROOT / "release_keys" / "release_key.json"
SERVER_CONFIG_PATH = ROOT / "server_config.json"

# 轮换后由服务器启动自举重新生成的字段（core/config.py 的 _load 逻辑）。
SERVER_SECRET_FIELDS = [
    "secret_key",
    "offline_private_key",
    "offline_public_key",
    "response_private_key",
    "response_public_key",
    "response_key_id",
]


def _stage_backup(backup_dir: Path) -> list[tuple[Path, Path]]:
    """返回 [(源文件, 备份目标)] 清单（不执行）。"""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    plan: list[tuple[Path, Path]] = []
    if RELEASE_KEY_PATH.is_file():
        plan.append((RELEASE_KEY_PATH, backup_dir / f"release_key.{stamp}.json"))
    if SERVER_CONFIG_PATH.is_file():
        plan.append((SERVER_CONFIG_PATH, backup_dir / f"server_config.{stamp}.json"))
    return plan


def run(apply: bool, backup_dir: Path | None) -> int:
    backup_dir = backup_dir or (ROOT / "key-rotation-backup")
    plan = _stage_backup(backup_dir)

    print("=" * 64)
    print("密钥轮换" + ("（执行）" if apply else "（预演：加 --apply 才会执行）"))
    print("=" * 64)

    if not plan:
        print("未找到可轮换的密钥材料（release_keys/release_key.json 与 server_config.json 均不存在）。")
        print("如果是全新环境，无需轮换；按下述步骤直接构建即可。")
    for src, dst in plan:
        print(f"  备份：{src.relative_to(ROOT)}  ->  {dst}")

    config_changes = 0
    if SERVER_CONFIG_PATH.is_file():
        data = json.loads(SERVER_CONFIG_PATH.read_text(encoding="utf-8"))
        security = data.get("security", {}) if isinstance(data, dict) else {}
        present = [f for f in SERVER_SECRET_FIELDS if str(security.get(f) or "").strip()]
        config_changes = len(present)
        print(f"  重置：server_config.json 将移除 {config_changes} 个密钥字段（{', '.join(present) or '无'}）")
    if RELEASE_KEY_PATH.is_file():
        print("  重置：删除 release_keys/release_key.json（build.py 下次自动生成新对）")

    print()
    print("后续步骤（脚本不代做，按序执行）：")
    print("  1) 重启本地服务器 —— 自动生成全新 secret_key / offline / response 密钥")
    print("  2) 本地服务器.exe --print-public-key —— 导出新公钥")
    print("  3) 用新公钥重新固定客户端（删除管理端/验证端/主控端旧配置后重新连接）")
    print("  4) python build.py（或 python tools/build_nuitka.py all）—— 重建发布包")
    print("     新发布密钥对自动生成；发布清单用新密钥签名")
    print("  5) 新客户端与 release_manifest 一起分发；服务器导入新清单（自动退役旧版）")
    print("  6) 旧离线激活码全部作废 —— 需要为用户重新签发")
    print("  7) license.db 保留不动；客户端重新激活即恢复在线会话")

    if apply:
        backup_dir.mkdir(parents=True, exist_ok=True)
        for src, dst in plan:
            shutil.copy2(src, dst)
            print(f"[done] 已备份 {dst.name}")
        if SERVER_CONFIG_PATH.is_file():
            data = json.loads(SERVER_CONFIG_PATH.read_text(encoding="utf-8"))
            security = data.get("security", {})
            for field in SERVER_SECRET_FIELDS:
                security.pop(field, None)
            SERVER_CONFIG_PATH.write_text(
                json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            print("[done] server_config.json 已重置（密钥字段清空）")
        if RELEASE_KEY_PATH.is_file():
            RELEASE_KEY_PATH.unlink()
            print("[done] release_key.json 已删除")
        print()
        print("轮换执行完成。请立即按上方步骤 1-7 继续。")
        print(f"备份位置：{backup_dir}（请妥善保管，确认新链路可用后再归档）")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="密钥轮换辅助（备份+重置）")
    parser.add_argument("--apply", action="store_true", help="真正执行（默认仅预演）")
    parser.add_argument("--backup-dir", type=Path, default=None, help="备份目录")
    args = parser.parse_args(argv)
    return run(args.apply, args.backup_dir)


if __name__ == "__main__":
    raise SystemExit(main())
