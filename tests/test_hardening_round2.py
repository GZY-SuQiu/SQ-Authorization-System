"""Regression tests for the second security hardening pass.

Covers session-secret encryption at rest, constant-time login, per-IP login
throttling, the forced password change after an administrative reset, and the
offline request-code freshness check.
"""

import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

import requests

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import security  # noqa: E402
from core.api_client import ApiClient  # noqa: E402
from core.config import Config  # noqa: E402
from core.database import SESSION_CIPHER_PREFIX, Database  # noqa: E402
from tests.test_api_hardening import LiveServer, login_ready  # noqa: E402


def _raw_session_secret(db: Database) -> str:
    conn = sqlite3.connect(db.path)
    try:
        row = conn.execute("SELECT session_secret FROM activations LIMIT 1").fetchone()
    finally:
        conn.close()
    return row[0] if row else ""


class SessionSecretAtRestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _activate(self, db: Database, key_secret: str = "s3ss10n-s3cr3t"):
        _, keys = db.generate_licenses(1)
        row = db.get_license(keys[0])
        db.activate_atomic(row["id"], keys[0], "MACHINE-1", "pc", None, key_secret)
        return keys[0]

    def test_session_secret_is_encrypted_on_disk(self):
        db = Database(self.root / "license.db", "server-secret-material")
        try:
            key = self._activate(db)
            stored = _raw_session_secret(db)
            self.assertTrue(stored.startswith(SESSION_CIPHER_PREFIX), stored)
            self.assertNotIn("s3ss10n-s3cr3t", stored)
            # The server still needs the plaintext to recompute HMAC signatures.
            self.assertEqual(
                db.get_activation(key, "MACHINE-1")["session_secret"],
                "s3ss10n-s3cr3t",
            )
        finally:
            db.close()

    def test_wrong_key_cannot_recover_the_session_secret(self):
        db = Database(self.root / "license.db", "server-secret-material")
        try:
            key = self._activate(db)
        finally:
            db.close()

        other = Database(self.root / "license.db", "a-different-secret")
        try:
            self.assertIsNone(other.get_activation(key, "MACHINE-1")["session_secret"])
        finally:
            other.close()

    def test_legacy_plaintext_rows_stay_readable(self):
        db = Database(self.root / "license.db")
        try:
            key = self._activate(db)
            self.assertEqual(_raw_session_secret(db), "s3ss10n-s3cr3t")
        finally:
            db.close()

        upgraded = Database(self.root / "license.db", "server-secret-material")
        try:
            # An existing install must not lose its activations on upgrade.
            self.assertEqual(
                upgraded.get_activation(key, "MACHINE-1")["session_secret"],
                "s3ss10n-s3cr3t",
            )
        finally:
            upgraded.close()

    def test_set_activation_session_is_sealed_too(self):
        db = Database(self.root / "license.db", "server-secret-material")
        try:
            key = self._activate(db, "first")
            activation = db.get_activation(key, "MACHINE-1")
            db.set_activation_session(activation["id"], "rotated-secret")
            self.assertNotIn("rotated-secret", _raw_session_secret(db))
            self.assertEqual(
                db.get_activation(key, "MACHINE-1")["session_secret"],
                "rotated-secret",
            )
        finally:
            db.close()

    def test_legacy_rows_are_upgraded_on_startup(self):
        db = Database(self.root / "license.db")
        try:
            key = self._activate(db)
        finally:
            db.close()

        upgraded = Database(self.root / "license.db", "server-secret-material")
        try:
            self.assertEqual(upgraded.seal_legacy_sessions(), 1)
            self.assertTrue(
                _raw_session_secret(upgraded).startswith(SESSION_CIPHER_PREFIX)
            )
            self.assertEqual(
                upgraded.get_activation(key, "MACHINE-1")["session_secret"],
                "s3ss10n-s3cr3t",
            )
            # Idempotent: a second pass has nothing left to do.
            self.assertEqual(upgraded.seal_legacy_sessions(), 0)
        finally:
            upgraded.close()


class ConstantTimeLoginTests(unittest.TestCase):
    def test_unknown_user_still_pays_the_pbkdf2_cost(self):
        from server import api

        seen: list[tuple[str, str, str]] = []
        original = security.verify_password

        def spy(password, password_hash, salt):
            seen.append((password, password_hash, salt))
            return original(password, password_hash, salt)

        security.verify_password = spy
        try:
            self.assertFalse(api._constant_time_login("hunter2", None))
        finally:
            security.verify_password = original

        self.assertEqual(len(seen), 1)
        _, password_hash, salt = seen[0]
        self.assertEqual(password_hash, api._DUMMY_PASSWORD_HASH)
        self.assertEqual(salt, api._DUMMY_SALT)
        self.assertTrue(password_hash.startswith("pbkdf2_sha256$600000$"))


class LoginThrottleTests(unittest.TestCase):
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

    def test_per_ip_guard_blocks_username_rotation(self):
        from server import api

        original = api._rate_allowed
        api._rate_allowed = lambda *_args, **_kwargs: False
        try:
            response = requests.post(
                f"http://127.0.0.1:{self.live.port}/api/admin/login",
                json={"username": "someone-else", "password": "whatever"},
                timeout=5,
            )
        finally:
            api._rate_allowed = original
        self.assertEqual(response.status_code, 429)

    def test_guard_is_cleared_after_a_successful_login(self):
        from server import api

        guard_key = "127.0.0.1|admin"
        api._record_login_failure(guard_key, 300)
        self.assertIn(guard_key, api._login_guard)
        self.client.login("admin", self.bootstrap)
        self.assertNotIn(guard_key, api._login_guard)


class AdminPasswordResetTests(unittest.TestCase):
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

    def test_reset_forces_the_admin_to_change_password(self):
        # 管理员创建走服务器端审批 → 该测试用 db 直连创建（测试主体是 reset 流程）
        self.db.create_admin("operator", "Operator#2026")
        admin = next(
            item for item in self.client.list_admins()["items"]
            if item["username"] == "operator"
        )
        self.assertEqual(int(admin["must_change_password"]), 0)

        self.client.reset_admin_password(admin["id"], "Reset#Pass2026")
        refreshed = self.db.get_admin("operator")
        self.assertEqual(int(refreshed["must_change_password"]), 1)

        # The temporary password still logs in, and the flag reaches the client.
        fresh_client = ApiClient(
            f"http://127.0.0.1:{self.live.port}",
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )
        result = fresh_client.login("operator", "Reset#Pass2026")
        self.assertTrue(result["must_change_password"])


class OfflineRequestCodeAgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from core import pages
        except ImportError as exc:  # pragma: no cover - PySide6 optional
            raise unittest.SkipTest(f"PySide6 unavailable: {exc}") from exc
        cls.pages = pages

    def _error(self, ts: int) -> str:
        return self.pages.OfflinePage._request_age_error({"ts": ts})

    def test_fresh_code_is_accepted(self):
        self.assertEqual(self._error(int(time.time())), "")

    def test_stale_code_is_rejected(self):
        stale = int(time.time()) - (self.pages.REQUEST_CODE_MAX_AGE_DAYS + 1) * 86400
        self.assertIn("超过", self._error(stale))

    def test_missing_timestamp_is_rejected(self):
        self.assertIn("时间戳", self._error(0))

    def test_future_timestamp_is_rejected(self):
        self.assertIn("晚于", self._error(int(time.time()) + 3 * 86400))


class PasswordGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from PySide6.QtWidgets import QApplication, QWidget

            from core.shell import AppShell
        except ImportError as exc:  # pragma: no cover - PySide6 optional
            raise unittest.SkipTest(f"PySide6 unavailable: {exc}") from exc
        cls.QWidget = QWidget
        cls.AppShell = AppShell
        cls.app = QApplication.instance() or QApplication([])

    def _shell(self, flagged: bool):
        shell = self.AppShell(
            "测试窗口",
            {"username": "operator", "must_change_password": flagged},
            "http://127.0.0.1:8765",
        )
        shell.add_page("概览", self.QWidget())
        password_page = self.QWidget()
        shell.add_page("修改密码", password_page, password_gate=True)
        shell.show()
        return shell, password_page

    def test_flagged_account_lands_on_the_password_page(self):
        shell, password_page = self._shell(True)
        try:
            self.assertIs(shell.stack.currentWidget(), password_page)
            # Navigation away stays refused until the password is replaced.
            shell.set_current_page(0)
            self.assertIs(shell.stack.currentWidget(), password_page)
            shell.release_password_gate()
            shell.set_current_page(0)
            self.assertIs(shell.stack.currentWidget(), shell.stack.widget(0))
        finally:
            shell.close()

    def test_normal_account_is_not_gated(self):
        shell, password_page = self._shell(False)
        try:
            self.assertIsNot(shell.stack.currentWidget(), password_page)
            shell.set_current_page(1)
            self.assertIs(shell.stack.currentWidget(), password_page)
        finally:
            shell.close()


if __name__ == "__main__":
    unittest.main()
