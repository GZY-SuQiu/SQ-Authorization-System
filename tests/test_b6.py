# -*- coding: utf-8 -*-
"""B6 测试：自动备份与轮转 + 恢复演练工具。"""
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.database import Database
from server.api import MaintenanceWorker


class AutoBackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.db = Database(self.root / "license.db")
        self.backup_dir = self.root / "backups" / "auto"
        self.config_path = self.root / "server_config.json"
        self.config_path.write_text('{"security": {"secret_key": "x"}}', encoding="utf-8")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def _worker(self, *, enabled=True, keep=3):
        return MaintenanceWorker(
            self.db,
            retention={},
            backup={
                "enabled": enabled,
                "keep": keep,
                "dir": self.backup_dir,
                "config_path": self.config_path,
            },
        )

    def test_run_once_creates_backup_pair(self):
        self.db.generate_licenses(count=2, duration_days=7)
        worker = self._worker()
        worker.run_once()

        dbs = list(self.backup_dir.glob("license_auto_*.db"))
        configs = list(self.backup_dir.glob("server_config_auto_*.json"))
        self.assertEqual(len(dbs), 1, dbs)
        self.assertEqual(len(configs), 1, configs)

        connection = sqlite3.connect(dbs[0])
        try:
            count = connection.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(count, 2)

        status = worker.status()
        self.assertIsNotNone(status["last_backup"])
        self.assertIn("license_auto_", status["last_backup"]["path"])

    def test_rotation_keeps_latest(self):
        worker = self._worker(keep=3)
        # 造 5 个旧备份（更早的时间戳前缀）→ 连同新备份共 6 个 → 轮转保留 3
        for index in range(5):
            (self.backup_dir).mkdir(parents=True, exist_ok=True)
            (self.backup_dir / f"license_auto_2026010{index}-000000.db").write_bytes(b"old")
        worker.run_once()
        remaining = sorted(self.backup_dir.glob("license_auto_*.db"))
        self.assertEqual(len(remaining), 3, [p.name for p in remaining])
        # 最新的一份必然保留
        self.assertTrue(any("20261" in p.name for p in remaining))

    def test_disabled_creates_nothing(self):
        worker = self._worker(enabled=False)
        worker.run_once()
        self.assertFalse(self.backup_dir.exists() and any(self.backup_dir.iterdir()))

    def test_backup_failure_does_not_block_maintenance(self):
        # 备份目录指向一个非法路径（文件占位）→ 备份失败但维护照常
        broken = self.root / "broken"
        broken.write_text("file", encoding="utf-8")
        worker = MaintenanceWorker(
            self.db,
            retention={},
            backup={"enabled": True, "keep": 3, "dir": broken, "config_path": None},
        )
        deleted = worker.run_once()  # 不应抛出
        self.assertIsInstance(deleted, dict)
        self.assertIsNotNone(worker.status()["last_error"])


class DrillTests(unittest.TestCase):
    def test_drill_passes(self):
        from tools.backup_drill import drill

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp)
            db = Database(root / "license.db")
            try:
                db.generate_licenses(count=1, duration_days=7)
            finally:
                db.close()
            outcome = drill(root / "license.db", backup_dir=root / "drill")
            self.assertTrue(outcome["ok"], outcome["steps"])
            names = [item["name"] for item in outcome["steps"]]
            self.assertIn("恢复通道", names)

    def test_drill_missing_db(self):
        from tools.backup_drill import drill

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            outcome = drill(Path(tmp) / "missing.db", backup_dir=Path(tmp) / "drill")
            self.assertFalse(outcome["ok"])


if __name__ == "__main__":
    unittest.main()
