"""Regression tests for the verification client's "remember me" login form.

Covers: prefill from config, encrypted password persistence through
``core.secret_store``, clearing when the boxes are unchecked, recovery from an
unreadable (old / foreign) password token, and the non-Windows fallback where
only the account name may be remembered.
"""

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402

import verification.ui as verify_ui  # noqa: E402
from core import secret_store  # noqa: E402
from core.config import Config  # noqa: E402
from verification.ui import VerifyWindow  # noqa: E402


class FakeClient:
    """Minimal ApiClient stand-in used to build a real VerifyWindow."""

    def __init__(self):
        self.base_url = "http://127.0.0.1:8765"
        self.portal_token = ""
        self.portal_token_expires_at = 0
        self.session_secret = None
        self.calls: list[tuple] = []

    # --- surface used by VerifyWindow ----------------------------------
    def set_trusted_public_keys(self, *_args):
        return None

    def set_session_secret(self, secret):
        self.session_secret = secret

    def clear_portal_session(self):
        self.portal_token = ""
        self.portal_token_expires_at = 0

    # --- portal contract ------------------------------------------------
    def portal_login(self, email, password):
        self.calls.append(("portal_login", email, password))
        self.portal_token = "portal-token"
        self.portal_token_expires_at = int(time.time()) + 600
        return {
            "ok": True,
            "email": email,
            "token": "portal-token",
            "expires_in": 600,
            "binding": None,
        }

    def portal_register(self, email, code, password):
        self.calls.append(("portal_register", email, code, password))
        return self.portal_login(email, password)


_SECURE = secret_store.is_secure_available()


class RememberLoginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.config = Config("verification", path=self.root / "verification_config.json")

    def _window(self, client) -> VerifyWindow:
        with mock.patch.object(verify_ui, "ApiClient", return_value=client):
            window = VerifyWindow(self.config)
        self.addCleanup(window.close)
        self.addCleanup(window.deleteLater)
        return window

    def _save_credentials(self, email="user@example.com", password="P@ssw0rd!"):
        self.config.client.update(
            {
                "remember_username": True,
                "remember_password": True,
                "saved_email": email,
                "saved_password": secret_store.protect(password),
            }
        )
        self.config.save()

    # --- prefill / restore ----------------------------------------------
    @unittest.skipUnless(_SECURE, "需要系统级安全存储（Windows DPAPI）")
    def test_saved_credentials_prefill_login_form(self):
        self._save_credentials()
        window = self._window(FakeClient())

        self.assertEqual(window.portal_login_email.text(), "user@example.com")
        self.assertTrue(window.portal_remember_username_check.isChecked())
        self.assertTrue(window.portal_remember_password_check.isChecked())
        self.assertEqual(window.portal_login_password.text(), "P@ssw0rd!")
        self.assertFalse(window.portal_remember_username_check.isEnabled())

    @unittest.skipUnless(_SECURE, "需要系统级安全存储（Windows DPAPI）")
    def test_unreadable_saved_password_is_dropped_without_crash(self):
        self._save_credentials()
        self.config.client["saved_password"] = "dpapi:not-a-valid-token"
        self.config.save()

        window = self._window(FakeClient())

        self.assertFalse(window.portal_remember_password_check.isChecked())
        self.assertEqual(window.portal_login_password.text(), "")
        self.assertEqual(self.config.client["saved_password"], "")
        # 账号仍然记住，密码复选框保持可用。
        self.assertTrue(window.portal_remember_username_check.isChecked())
        self.assertTrue(window.portal_remember_password_check.isEnabled())

    # --- checkbox coupling ----------------------------------------------
    @unittest.skipUnless(_SECURE, "需要系统级安全存储（Windows DPAPI）")
    def test_remember_password_locks_remember_username(self):
        window = self._window(FakeClient())
        self.assertTrue(window.portal_remember_username_check.isEnabled())

        window.portal_remember_password_check.setChecked(True)
        self.assertTrue(window.portal_remember_username_check.isChecked())
        self.assertFalse(window.portal_remember_username_check.isEnabled())

        window.portal_remember_password_check.setChecked(False)
        self.assertTrue(window.portal_remember_username_check.isEnabled())

    # --- persistence ------------------------------------------------------
    @unittest.skipUnless(_SECURE, "需要系统级安全存储（Windows DPAPI）")
    def test_login_success_saves_encrypted_password(self):
        window = self._window(FakeClient())
        window.portal_login_email.setText("User@Example.com")
        window.portal_login_password.setText("P@ssw0rd!")
        window.portal_remember_password_check.setChecked(True)
        window.portal_login()

        self.assertTrue(window.portal_authenticated)
        client_config = self.config.client
        self.assertTrue(client_config["remember_username"])
        self.assertTrue(client_config["remember_password"])
        self.assertEqual(client_config["saved_email"], "user@example.com")
        token = client_config["saved_password"]
        self.assertNotEqual(token, "P@ssw0rd!")
        self.assertNotIn("P@ssw0rd!", token)
        self.assertEqual(secret_store.unprotect(token), "P@ssw0rd!")

        # 配置已落盘，重启后仍可恢复。
        on_disk = json.loads(self.config.path.read_text(encoding="utf-8"))
        self.assertEqual(on_disk["client"]["saved_password"], token)
        self.assertEqual(on_disk["client"]["saved_email"], "user@example.com")

    @unittest.skipUnless(_SECURE, "需要系统级安全存储（Windows DPAPI）")
    def test_unchecking_boxes_clears_saved_credentials(self):
        window = self._window(FakeClient())
        window.portal_login_email.setText("user@example.com")
        window.portal_login_password.setText("P@ssw0rd!")
        window.portal_remember_password_check.setChecked(True)
        window.portal_login()
        self.assertNotEqual(self.config.client["saved_password"], "")

        window.portal_remember_password_check.setChecked(False)
        window.portal_remember_username_check.setChecked(False)
        window.portal_login()

        self.assertEqual(self.config.client["saved_email"], "")
        self.assertEqual(self.config.client["saved_password"], "")
        self.assertFalse(self.config.client["remember_username"])
        self.assertFalse(self.config.client["remember_password"])
        on_disk = json.loads(self.config.path.read_text(encoding="utf-8"))
        self.assertEqual(on_disk["client"]["saved_password"], "")

    @unittest.skipUnless(_SECURE, "需要系统级安全存储（Windows DPAPI）")
    def test_register_auto_login_uses_same_remember_semantics(self):
        window = self._window(FakeClient())
        window.portal_register_email.setText("new@example.com")
        window.portal_register_code.setText("123456")
        window.portal_register_password.setText("P@ssw0rd!")
        window.portal_remember_password_check.setChecked(True)
        window.portal_register()

        self.assertTrue(window.portal_authenticated)
        self.assertEqual(self.config.client["saved_email"], "new@example.com")
        self.assertEqual(
            secret_store.unprotect(self.config.client["saved_password"]), "P@ssw0rd!"
        )

    @unittest.skipUnless(_SECURE, "需要系统级安全存储（Windows DPAPI）")
    def test_storage_failure_only_toasts_and_login_still_succeeds(self):
        window = self._window(FakeClient())
        shown: list[tuple[str, str]] = []
        window.toast.show_message = (
            lambda message, kind="info", msec=3000: shown.append((kind, message))
        )
        window.portal_login_email.setText("user@example.com")
        window.portal_login_password.setText("P@ssw0rd!")
        window.portal_remember_password_check.setChecked(True)

        with mock.patch.object(
            verify_ui.secret_store, "protect", side_effect=RuntimeError("boom")
        ):
            window.portal_login()

        self.assertTrue(window.portal_authenticated)
        warnings = [message for kind, message in shown if kind == "warning"]
        self.assertTrue(warnings)
        self.assertIn("保存失败", warnings[-1])

    # --- unsupported platform --------------------------------------------
    def test_password_checkbox_disabled_without_secure_storage(self):
        with mock.patch.object(
            verify_ui.secret_store, "is_secure_available", return_value=False
        ):
            window = self._window(FakeClient())

            self.assertFalse(window.portal_remember_password_check.isEnabled())
            self.assertIn(
                "不支持安全保存", window.portal_remember_password_check.toolTip()
            )

            # 只允许记住账号，密码不会被写进配置。
            window.portal_remember_username_check.setChecked(True)
            window.portal_login_email.setText("user@example.com")
            window.portal_login_password.setText("P@ssw0rd!")
            window.portal_login()

        self.assertTrue(window.portal_authenticated)
        self.assertEqual(self.config.client["saved_email"], "user@example.com")
        self.assertEqual(self.config.client["saved_password"], "")
        self.assertFalse(self.config.client["remember_password"])


if __name__ == "__main__":
    unittest.main()
