"""崩溃日志模块测试。"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core import crashlog


class CrashlogTests(unittest.TestCase):
    def test_log_exception_writes_readable_file(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as raw:
            target = Path(raw)
            with mock.patch("core.crashlog.log_dir", return_value=target):
                try:
                    raise ValueError("boom-marker")
                except ValueError as exc:
                    crashlog.log_exception("unit-test", exc)
            files = list(target.glob("crash-*.log"))
            self.assertTrue(files, "未生成崩溃日志文件")
            text = files[0].read_text(encoding="utf-8")
            self.assertIn("unit-test", text)
            self.assertIn("ValueError", text)
            self.assertIn("boom-marker", text)

    def test_install_is_idempotent(self):
        original = sys.excepthook
        try:
            crashlog.install("unit-test")
            hook = sys.excepthook
            crashlog.install("unit-test")
            self.assertIs(sys.excepthook, hook)
        finally:
            sys.excepthook = original


if __name__ == "__main__":
    unittest.main()
