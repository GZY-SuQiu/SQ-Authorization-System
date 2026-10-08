"""P1 MasterUI tests: login password reset entry + admin email UI (headless Qt)."""

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QDialog, QLineEdit  # noqa: E402

from core.api_client import ApiError  # noqa: E402
from core.config import Config  # noqa: E402
from core.shell import ForgotPasswordDialog, LoginDialog  # noqa: E402
from master.ui import (  # noqa: E402
    AdminEmailDialog,
    AdminsPage,
    CreateAdminDialog,
    mask_email,
)


class FakeApiClient:
    """Records the P1 client calls the UI is contracted to make."""

    def __init__(self, admins=None):
        self.base_url = "http://127.0.0.1:8765"
        self.admins = list(admins or [])
        self.calls: list[tuple] = []

    def admin_password_forgot(self, email):
        self.calls.append(("admin_password_forgot", email))
        return {"ok": True}

    def admin_password_reset(self, email, code, new_password):
        self.calls.append(("admin_password_reset", email, code, new_password))
        return {"ok": True}

    def admin_set_email(self, email):
        self.calls.append(("admin_set_email", email))
        return {"ok": True, "email": email, "expires_in": 600}

    def admin_verify_email(self, code):
        self.calls.append(("admin_verify_email", code))
        return {"ok": True}

    def list_admins(self):
        return {"items": [dict(item) for item in self.admins]}

    def create_admin(self, username, password, role):
        self.calls.append(("create_admin", username, password, role))
        return {"ok": True}


class RecordingNotify:
    """Stands in for Toast.show_message(message, kind, msec)."""

    def __init__(self):
        self.messages: list[tuple[str, str]] = []

    def __call__(self, message, kind="info", msec=3000):
        self.messages.append((kind, message))

    def kinds(self) -> list[str]:
        return [kind for kind, _ in self.messages]


ADMIN_ROW = {
    "id": 1,
    "username": "master",
    "role": "master",
    "status": "active",
    "email": "a@domain.com",
    "email_verified_at": "2026-10-07 10:00:00",
    "created_at": "2026-10-01 10:00:00",
    "last_login_at": None,
}


class MasterEmailUITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls._tmp = tempfile.TemporaryDirectory()
        cls.config = Config("master", path=Path(cls._tmp.name) / "master_config.json")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    # --- 登录框：忘记密码入口 -------------------------------------------

    def test_login_dialog_has_forgot_password_entry(self):
        dialog = LoginDialog(self.config, "密钥授权系统 · 主控端", "请登录")
        try:
            self.assertIn("忘记密码", dialog.btn_forgot.text())
            self.assertTrue(dialog.btn_forgot.isEnabled())
        finally:
            dialog.deleteLater()

    def test_forgot_password_dialog_sends_code_and_resets(self):
        client = FakeApiClient()
        dialog = ForgotPasswordDialog(client, "user@example.com")
        self.assertEqual(dialog.email.text(), "user@example.com")

        dialog.send_code()
        self.assertEqual(
            client.calls, [("admin_password_forgot", "user@example.com")]
        )

        dialog.code.setText("123456")
        dialog.new_password.setText("NewPass123")
        dialog.confirm_password.setText("NewPass123")
        dialog.reset_password()
        self.assertIn(
            ("admin_password_reset", "user@example.com", "123456", "NewPass123"),
            client.calls,
        )
        self.assertTrue(dialog.reset_done)
        self.assertIn("密码已重置，请用新密码登录", dialog.status.text())
        dialog.deleteLater()

    def test_forgot_password_mismatch_does_not_call_server(self):
        client = FakeApiClient()
        dialog = ForgotPasswordDialog(client, "user@example.com")
        dialog.code.setText("123456")
        dialog.new_password.setText("NewPass123")
        dialog.confirm_password.setText("OtherPass123")
        dialog.reset_password()
        self.assertEqual(client.calls, [])
        self.assertIn("不一致", dialog.status.text())
        dialog.deleteLater()

    # --- 新建管理员：可选邮箱 -------------------------------------------

    def test_create_admin_dialog_has_email_field(self):
        dialog = CreateAdminDialog(FakeApiClient(), RecordingNotify())
        try:
            self.assertIsInstance(dialog.email, QLineEdit)
            self.assertEqual(dialog.email.text(), "")
        finally:
            dialog.deleteLater()

    def test_create_admin_dialog_sets_email_after_create(self):
        client = FakeApiClient()
        notify = RecordingNotify()
        dialog = CreateAdminDialog(client, notify)
        dialog.username.setText("ops")
        dialog.password.setText("Str0ngPass1")
        dialog.email.setText("ops@example.com")
        dialog.submit()
        self.assertEqual(client.calls[0][0], "create_admin")
        self.assertIn(("admin_set_email", "ops@example.com"), client.calls)
        self.assertEqual(dialog.result(), QDialog.Accepted)
        self.assertIn("success", notify.kinds())
        dialog.deleteLater()

    def test_create_admin_without_email_skips_set_email(self):
        client = FakeApiClient()
        dialog = CreateAdminDialog(client, RecordingNotify())
        dialog.username.setText("ops")
        dialog.password.setText("Str0ngPass1")
        dialog.submit()
        self.assertEqual([name for name, *_ in client.calls], ["create_admin"])
        self.assertEqual(dialog.result(), QDialog.Accepted)
        dialog.deleteLater()

    def test_create_admin_email_failure_still_creates_account(self):
        class BrokenEmailClient(FakeApiClient):
            def admin_set_email(self, email):
                raise ApiError("SMTP 未启用或未配置")

        notify = RecordingNotify()
        dialog = CreateAdminDialog(BrokenEmailClient(), notify)
        dialog.username.setText("ops")
        dialog.password.setText("Str0ngPass1")
        dialog.email.setText("ops@example.com")
        dialog.submit()
        self.assertEqual(dialog.result(), QDialog.Accepted)
        self.assertTrue(
            any("邮箱设置失败" in message for _, message in notify.messages),
            notify.messages,
        )
        dialog.deleteLater()

    # --- 管理员列表：邮箱与验证状态 -------------------------------------

    def test_admins_page_shows_masked_email_and_status(self):
        page = AdminsPage(FakeApiClient([ADMIN_ROW]), RecordingNotify())
        page.refresh()
        headers = [
            page.table.horizontalHeaderItem(col).text()
            for col in range(page.table.columnCount())
        ]
        self.assertIn("邮箱", headers)
        self.assertIn("验证状态", headers)
        email_col = headers.index("邮箱")
        verify_col = headers.index("验证状态")
        self.assertEqual(page.table.item(0, email_col).text(), "a***@domain.com")
        self.assertIn("已验证", page.table.item(0, verify_col).text())

    def test_admins_page_marks_unverified_email(self):
        row = dict(ADMIN_ROW, id=2, username="ops", role="admin", email_verified_at=None)
        page = AdminsPage(FakeApiClient([row]), RecordingNotify())
        page.refresh()
        headers = [
            page.table.horizontalHeaderItem(col).text()
            for col in range(page.table.columnCount())
        ]
        verify_col = headers.index("验证状态")
        self.assertIn("未验证", page.table.item(0, verify_col).text())

    def test_admins_page_has_email_action_button(self):
        page = AdminsPage(FakeApiClient(), RecordingNotify())
        self.assertIn("设置邮箱/重发验证", page.btn_email.text())

    def test_admin_email_dialog_calls_set_and_verify(self):
        client = FakeApiClient()
        notify = RecordingNotify()
        dialog = AdminEmailDialog(client, notify)
        dialog.email.setText("master@example.com")
        dialog.send_code()
        dialog.code.setText("654321")
        dialog.verify()
        self.assertEqual(
            client.calls,
            [
                ("admin_set_email", "master@example.com"),
                ("admin_verify_email", "654321"),
            ],
        )
        self.assertTrue(dialog.email_verified)
        self.assertEqual(dialog.result(), QDialog.Accepted)
        self.assertEqual(notify.kinds().count("success"), 2)
        dialog.deleteLater()

    def test_mask_email_hides_local_part(self):
        self.assertEqual(mask_email("alice@example.com"), "a***@example.com")
        self.assertEqual(mask_email(""), "—")


if __name__ == "__main__":
    unittest.main()
