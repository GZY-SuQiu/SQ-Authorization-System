"""控制台隐藏逻辑：只隐藏本 exe 独占的控制台窗口。"""

import unittest
from unittest import mock

from core import winconsole


class HideConsoleWindowTests(unittest.TestCase):
    def test_off_windows_is_noop(self):
        with mock.patch.object(winconsole.sys, "platform", "linux"):
            self.assertFalse(winconsole.hide_console_window())

    def test_shared_console_is_left_alone(self):
        """从 cmd / Windows Terminal 启动时控制台属于终端，不能隐藏。"""
        fake_windll = mock.MagicMock()
        fake_windll.kernel32.GetConsoleWindow.side_effect = AssertionError(
            "共享控制台不应触碰窗口句柄"
        )
        with mock.patch.object(winconsole.sys, "platform", "win32"), mock.patch.object(
            winconsole, "_console_owner_count", lambda: 2
        ), mock.patch.object(winconsole, "_windll", lambda: fake_windll):
            self.assertFalse(winconsole.hide_console_window())
        fake_windll.user32.ShowWindow.assert_not_called()

    def test_owned_console_is_hidden(self):
        fake_windll = mock.MagicMock()
        fake_windll.kernel32.GetConsoleWindow.return_value = 4242
        with mock.patch.object(winconsole.sys, "platform", "win32"), mock.patch.object(
            winconsole, "_console_owner_count", lambda: 1
        ), mock.patch.object(winconsole, "_windll", lambda: fake_windll):
            self.assertTrue(winconsole.hide_console_window())
        fake_windll.user32.ShowWindow.assert_called_once_with(4242, 0)

    def test_missing_console_window_reports_false(self):
        fake_windll = mock.MagicMock()
        fake_windll.kernel32.GetConsoleWindow.return_value = 0
        with mock.patch.object(winconsole.sys, "platform", "win32"), mock.patch.object(
            winconsole, "_console_owner_count", lambda: 1
        ), mock.patch.object(winconsole, "_windll", lambda: fake_windll):
            self.assertFalse(winconsole.hide_console_window())


if __name__ == "__main__":
    unittest.main()
