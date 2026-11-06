#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""备份恢复演练：备份 → 完整性校验 → 恢复通道 → 结构检查。

用法::

    python tools/backup_drill.py [--db data/license.db] [--backup-dir 目录]

退出码：0 = 全通过；1 = 存在失败项。建议在每次版本发布前对生产备份副本执行。
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
import tempfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

REQUIRED_TABLES = ("licenses", "activations", "admins", "audit_logs")


def drill(db_path: Path, backup_dir: Path | None = None) -> dict:
    from core.database import Database

    result: dict = {"ok": False, "steps": [], "workdir": ""}

    def step(name: str, ok: bool, detail: str = "") -> bool:
        result["steps"].append({"name": name, "ok": bool(ok), "detail": str(detail)})
        return bool(ok)

    if not step("源库存在", db_path.is_file(), str(db_path)):
        return result

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    workdir = backup_dir or Path(tempfile.mkdtemp(prefix="sq-drill-"))
    workdir.mkdir(parents=True, exist_ok=True)
    result["workdir"] = str(workdir)

    db = Database(db_path)
    try:
        backup_path = workdir / f"drill_{stamp}.db"
        db.backup_to(backup_path)
        step("在线备份", backup_path.is_file(), str(backup_path))

        connection = sqlite3.connect(backup_path)
        try:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            step("完整性校验", integrity == "ok", str(integrity))
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            missing = [name for name in REQUIRED_TABLES if name not in tables]
            step("表结构检查", not missing, f"missing={missing or '无'}")
            count = connection.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]
            step("数据可读", True, f"licenses={count}")
        finally:
            connection.close()

        # 恢复通道演练：把备份恢复到独立目标库，验证恢复代码路径可用。
        restore_target = workdir / f"drill_restored_{stamp}.db"
        restored = Database(restore_target)
        try:
            restored.restore_from(backup_path)
        finally:
            restored.close()
        check = sqlite3.connect(restore_target)
        try:
            count = check.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]
            step("恢复通道", True, f"licenses={count}")
        finally:
            check.close()

        result["ok"] = all(item["ok"] for item in result["steps"])
    finally:
        db.close()
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="备份恢复演练")
    parser.add_argument("--db", default=str(ROOT / "data" / "license.db"))
    parser.add_argument("--backup-dir", default="")
    args = parser.parse_args(argv)
    outcome = drill(
        Path(args.db), Path(args.backup_dir) if args.backup_dir else None
    )
    for item in outcome["steps"]:
        print(f"[{'PASS' if item['ok'] else 'FAIL'}] {item['name']} —— {item['detail']}")
    print(
        f"结论：{'通过' if outcome['ok'] else '失败'}"
        f"（工作目录 {outcome.get('workdir', '')}）"
    )
    return 0 if outcome["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
