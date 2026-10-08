"""R2: 登录框「记住账号/记住密码」行为测试（离屏 Qt + 临时 Config）。"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402

from core import secret_store, shell as shell_module  # noqa: E402
from core.api_client import ApiClient, ApiError  # noqa: E402
from core.config import Config  # noqa: E402
from core.shell import LoginDialog  # noqa: E402

PLAINTEXT = "P@ssw0rd-R2"


class LoginRememberTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.config_path = Path(self._tmp.name) / "admin_config.json"
        self.config = Config("admin", path=self.config_path)
        # 登录成功路径里的 public_key() 走网络；测试里让它直接失败，
        # 走 LoginDialog 既有的本地兜底分支，保证离线可跑。
        self._patch(ApiClient, "public_key", side_effect=ApiError("离线测试"))

    def _patch(self, target, attribute, **kwargs):
        patcher = mock.patch.object(target, attribute, **kwargs)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _patch_login_ok(self):
        self._patch(
            ApiClient,
            "login",
            new=lambda self, username, password: {
                "token": "session-token",
                "user": {"username": username},
            },
        )

    def _dialog(self):
        dialog = LoginDialog(self.config, "密钥授权系统 · 管理端", "请登录")
        self.addCleanup(dialog.deleteLater)
        return dialog

    def _saved_client(self):
        return json.loads(self.config_path.read_text(encoding="utf-8"))["client"]

    def _seed_remembered(self):
        client = self.config.client
        client["remember_username"] = True
        client["remember_password"] = True
        client["saved_username"] = "alice"
        client["saved_password"] = secret_store.protect(PLAINTEXT)

    def test_falls_back_to_last_username(self):
        self.config.client["last_username"] = "bob"
        dialog = self._dialog()
        self.assertEqual(dialog.input_user.text(), "bob")
        self.assertFalse(dialog.remember_user.isChecked())
        self.assertFalse(dialog.remember_pass.isChecked())

    def test_prefills_saved_credentials_and_persists_encrypted(self):
        self._seed_remembered()
        dialog = self._dialog()
        self.assertEqual(dialog.input_user.text(), "alice")
        self.assertEqual(dialog.input_pass.text(), PLAINTEXT)
        self.assertTrue(dialog.remember_user.isChecked())
        self.assertTrue(dialog.remember_pass.isChecked())
        # 勾选「记住密码」时「记住账号」被自动勾选并锁定。
        self.assertFalse(dialog.remember_user.isEnabled())

        dialog.input_pass.setText("NewPass-R2-2")
        dialog.input_user.setText("alice2")
        self._patch_login_ok()
        dialog.submit()

        self.assertEqual(dialog.result_data.get("token"), "session-token")
        saved = self._saved_client()
        self.assertTrue(saved["remember_username"])
        self.assertTrue(saved["remember_password"])
        self.assertEqual(saved["saved_username"], "alice2")
        token = saved["saved_password"]
        self.assertNotEqual(token, "NewPass-R2-2")
        self.assertEqual(secret_store.unprotect(token), "NewPass-R2-2")

    def test_unchecking_clears_saved_credentials(self):
        self._seed_remembered()
        dialog = self._dialog()
        dialog.remember_pass.setChecked(False)
        self.assertTrue(dialog.remember_user.isEnabled())
        dialog.remember_user.setChecked(False)
        self._patch_login_ok()
        dialog.submit()

        saved = self._saved_client()
        self.assertFalse(saved["remember_username"])
        self.assertFalse(saved["remember_password"])
        self.assertEqual(saved["saved_username"], "")
        self.assertEqual(saved["saved_password"], "")

    def test_unprotect_failure_unchecks_and_clears_token(self):
        self._seed_remembered()
        self._patch(shell_module, "unprotect", return_value="")
        dialog = self._dialog()
        self.assertEqual(dialog.input_pass.text(), "")
        self.assertFalse(dialog.remember_pass.isChecked())
        self.assertEqual(self.config.client["saved_password"], "")

    def test_password_checkbox_disabled_without_secure_store(self):
        self._seed_remembered()
        self._patch(shell_module, "is_secure_available", return_value=False)
        dialog = self._dialog()
        self.assertFalse(dialog.remember_pass.isEnabled())
        self.assertFalse(dialog.remember_pass.isChecked())
        self.assertTrue(dialog.remember_user.isEnabled())
        self.assertEqual(dialog.input_pass.text(), "")
        self.assertIn("仅可记住账号", dialog.remember_hint.text())

        # 提交时也不能把密码写进配置，旧密文一并清掉。
        dialog.input_pass.setText("Typed-Pass-123")
        self._patch_login_ok()
        dialog.submit()
        saved = self._saved_client()
        self.assertFalse(saved["remember_password"])
        self.assertEqual(saved["saved_password"], "")
        self.assertEqual(saved["saved_username"], "alice")


if __name__ == "__main__":
    unittest.main()
