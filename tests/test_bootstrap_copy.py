"""R2: 服务器首次引导弹窗分项复制测试（离屏 Qt，不启动服务器）。"""

import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication  # noqa: E402

from server.ui import ServerWindow  # noqa: E402

BOOTSTRAP_PASSWORD = "Init-Pass-9f2c"


class RecordingToast:
    """Stands in for Toast.show_message(message, kind, msec)."""

    def __init__(self):
        self.messages: list[tuple[str, str]] = []

    def show_message(self, message, kind="info", msec=3000):
        self.messages.append((message, kind))


class BootstrapCopyStub:
    """最小对象：挂上 ServerWindow 的三个复制方法即可直接单测。"""

    _copy_bootstrap_username = ServerWindow._copy_bootstrap_username
    _copy_bootstrap_password = ServerWindow._copy_bootstrap_password
    _copy_bootstrap_both = ServerWindow._copy_bootstrap_both

    def __init__(self, password: str):
        self._bootstrap_password = password
        self.toast = RecordingToast()


class BootstrapCopyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.clipboard = QApplication.clipboard()
        self.clipboard.clear()
        self.stub = BootstrapCopyStub(BOOTSTRAP_PASSWORD)

    def test_copy_username_only(self):
        self.stub._copy_bootstrap_username()
        self.assertEqual(self.clipboard.text(), "admin")
        self.assertEqual(self.stub.toast.messages, [("账号已复制", "success")])

    def test_copy_password_only(self):
        self.stub._copy_bootstrap_password()
        self.assertEqual(self.clipboard.text(), BOOTSTRAP_PASSWORD)
        self.assertEqual(self.stub.toast.messages, [("密码已复制", "success")])

    def test_copy_both(self):
        self.stub._copy_bootstrap_both()
        self.assertEqual(self.clipboard.text(), f"admin\n{BOOTSTRAP_PASSWORD}")
        self.assertEqual(self.stub.toast.messages, [("账号密码已复制", "success")])

    def test_copy_password_after_plaintext_cleared(self):
        # 关闭弹窗后明文已清空：复制动作不应抛错，只写入空串。
        self.stub._bootstrap_password = ""
        self.stub._copy_bootstrap_password()
        self.assertEqual(self.clipboard.text(), "")
        self.assertEqual(self.stub.toast.messages, [("密码已复制", "success")])


if __name__ == "__main__":
    unittest.main()
