import tempfile
import unittest
from pathlib import Path

import requests

from core import offline, security
from core.api_client import ApiClient, ApiError, validate_server_url
from core.config import Config
from core.database import Database
from tests.test_api_hardening import LiveServer, login_ready


class DatabaseServerCoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        Config("server", self.root / "server_config.json")
        self.db = Database(self.root / "license.db")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_batch_filter_and_summary_use_same_scope(self):
        first, first_keys = self.db.generate_licenses(2, note="first")
        second, _ = self.db.generate_licenses(1, note="second")
        self.db.activate_atomic(
            self.db.get_license(first_keys[0])["id"],
            first_keys[0],
            "MACHINE-A",
            "pc",
            None,
            "session",
        )

        self.assertEqual(self.db.count_licenses(batch_no=first), 2)
        self.assertEqual(self.db.count_licenses(batch_no=second), 1)
        self.assertEqual(len(self.db.list_licenses(batch_no=first)), 2)
        summary = {item["batch_no"]: item for item in self.db.list_batches()}
        self.assertEqual(summary[first]["total"], 2)
        self.assertEqual(summary[first]["active"], 1)
        self.assertEqual(summary[first]["unused"], 1)
        self.assertEqual(self.db.count_batches(keyword="second"), 1)

    def test_log_filters_are_applied_to_items_and_total(self):
        self.db.add_log("生成密钥", "admin", "BATCH-1", "共 10 个", "127.0.0.1")
        self.db.add_log("激活失败", "client", "LIC-1", "密钥不存在", "10.0.0.1")
        self.db.add_log("验证成功", "client", "LIC-2", "设备 pc", "10.0.0.2")

        self.assertEqual(self.db.count_logs(action="激活失败"), 1)
        self.assertEqual(self.db.list_logs(action="激活失败")[0]["target"], "LIC-1")
        self.assertEqual(self.db.count_logs(keyword="10.0.0"), 2)
        self.assertEqual(self.db.count_logs(keyword="BATCH-1", action="生成密钥"), 1)
        self.assertEqual(self.db.list_logs(limit=1, offset=1)[0]["action"], "激活失败")

    def test_database_backup_restore_and_integrity_check(self):
        _, keys = self.db.generate_licenses(2, note="backup")
        backup = self.root / "backup.db"
        with self.assertRaises(ValueError):
            self.db.backup_to(self.db.path)
        self.db.backup_to(backup)
        self.db.delete_license(keys[0])
        self.assertEqual(self.db.count_licenses(), 1)

        self.db.restore_from(backup)
        self.assertEqual(self.db.count_licenses(), 2)
        self.assertEqual(self.db.check_health()["integrity"], "ok")

        invalid = self.root / "invalid.db"
        invalid.write_text("not a sqlite database", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.db.restore_from(invalid)

    def test_activation_prefers_persisted_license_expiry(self):
        _, keys = self.db.generate_licenses(1, duration_days=1)
        key = keys[0]
        license_row = self.db.get_license(key)
        expected = "2999-01-01 00:00:00"
        self.db.update_license_expiry(key, expected)

        _, _, actual = self.db.activate_atomic(
            license_row["id"],
            key,
            "MACHINE-EXPIRY",
            "pc",
            "2000-01-01 00:00:00",
            "session",
        )
        self.assertEqual(actual, expected)

    def test_server_url_must_be_a_plain_origin(self):
        self.assertEqual(
            validate_server_url("http://127.0.0.1:8765/"),
            "http://127.0.0.1:8765",
        )
        for value in (
            "http://user:pass@127.0.0.1:8765",
            "http://127.0.0.1:8765/api",
            "http://127.0.0.1:8765?debug=1",
            "http://127.0.0.1:8765#fragment",
        ):
            with self.assertRaises(ApiError):
                validate_server_url(value)


class ApiServerCoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.config = Config("server", self.root / "server_config.json")
        self.db = Database(self.root / "license.db")
        _, self.bootstrap = self.db.ensure_default_admin()
        self.live = LiveServer(self.config, self.db)
        self.live.start()
        self.client = ApiClient(
            f"http://127.0.0.1:{self.live.port}",
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )

    def tearDown(self):
        self.live.stop()
        self.db.close()
        self.tmp.cleanup()

    def test_batch_total_log_filters_and_failed_unbind(self):
        login_ready(self.client, self.bootstrap)
        first = self.client.generate_licenses(count=2, note="filter-a")
        second = self.client.generate_licenses(count=1, note="filter-b")

        filtered = self.client.list_licenses(batch_no=first["batch_no"])
        self.assertEqual(filtered["total"], 2)
        self.assertEqual(len(filtered["items"]), 2)

        batches = self.client.list_batches(keyword=second["batch_no"])
        self.assertEqual(batches["total"], 1)
        self.assertEqual(batches["items"][0]["total"], 1)

        key = first["keys"][0]
        self.client.activate(key, "MACHINE-LOG")
        self.client.verify(key, "MACHINE-LOG")
        logs = self.client.list_logs(keyword="验证成功")
        self.assertGreaterEqual(logs["total"], 1)

        with self.assertRaises(ApiError):
            self.client.unbind(key, "MACHINE-MISSING")

    def test_oversized_request_error_is_signed(self):
        timestamp = security.now_ts()
        nonce = "oversized-request-test"
        response = requests.post(
            f"http://127.0.0.1:{self.live.port}/api/admin/login",
            data=b"x" * 70_000,
            headers={
                "Content-Type": "application/json",
                "X-Client-Timestamp": str(timestamp),
                "X-Client-Nonce": nonce,
            },
            timeout=5,
        )
        self.assertEqual(response.status_code, 413)
        message = security.canonical_response_message(
            "POST",
            "/api/admin/login",
            timestamp,
            nonce,
            413,
            response.content,
            self.config.security["response_key_id"],
        )
        self.assertTrue(
            offline.verify_message(
                self.config.security["response_public_key"],
                message,
                response.headers.get("X-Server-Signature", ""),
            )
        )


if __name__ == "__main__":
    unittest.main()
