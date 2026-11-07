# -*- coding: utf-8 -*-
"""GUI 静态检查：拦截"实例访问 Qt 枚举"的运行时崩溃模式。

背景：PySide6 6.x 不允许通过**实例**访问枚举成员（如 `login.Accepted`），
正确写法是类访问（`QDialog.DialogCode.Accepted`）或直接按返回值判断
（`if not dialog.exec():`）。此类调用编译期无法发现、沙箱又跑不了 GUI，
曾在真实桌面环境造成 AttributeError 闪退（本检查即为该事故的防回归）。
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 实例访问枚举成员的模式：x.exec() != x.Accepted / == x.Rejected 等
_PATTERN = re.compile(r"\b(\w+)\.exec\(\)\s*[!=]=\s*\1\.(Accepted|Rejected)\b")
_SKIP_DIRS = {".git", "build", "dist", "build_nuitka", "__pycache__", ".pytest_cache", "installer_out"}


class QtEnumAccessTests(unittest.TestCase):
    def test_no_instance_enum_access_on_dialog_results(self):
        offenders = []
        for path in ROOT.rglob("*.py"):
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            if path.name == "test_gui_static.py":
                continue  # 本文件注释中含示例文本，跳过自身
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for match in _PATTERN.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                offenders.append(
                    f"{path.relative_to(ROOT)}:{line} -> {match.group(0)}"
                )
        self.assertEqual(
            offenders,
            [],
            "发现实例访问 Qt 枚举（真实桌面环境会 AttributeError 崩溃）。"
            "请改用 `if not dialog.exec():` 或类访问 QDialog.DialogCode.Accepted。\n"
            + "\n".join(offenders),
        )


if __name__ == "__main__":
    unittest.main()
