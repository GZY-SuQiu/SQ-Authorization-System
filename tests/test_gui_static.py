# -*- coding: utf-8 -*-
"""GUI 静态检查：编译期发现不了、沙箱又跑不了 GUI，靠这里把两类事故拦在构建前。

1. **实例访问 Qt 枚举**：PySide6 6.x 不允许 `login.Accepted` 这种实例访问
   （真实桌面 AttributeError 闪退）。改用 `if not dialog.exec():`。
2. **使用 Qt 名字但缺导入**：如用了 `Qt.CustomContextMenu` 却只 import 了
   QTimer（真实桌面 `name 'Qt' is not defined` 弹窗）。本检查核对每个
   PySide6 名字的使用与导入一致性。
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_PATTERN = re.compile(r"\b(\w+)\.exec\(\)\s*[!=]=\s*\1\.(Accepted|Rejected)\b")
_SKIP_DIRS = {".git", "build", "dist", "build_nuitka", "__pycache__", ".pytest_cache", "installer_out"}

# 检查的使用形态：名字后跟 . 或 (（避开 QSS 里的 "QMenu {" / "::item" 等）
_QT_NAMES = (
    "Qt", "QMenu", "QMessageBox", "QApplication", "QDialog", "QTimer",
    "QTableWidget", "QTableWidgetItem", "QHeaderView", "QLabel", "QLineEdit",
    "QComboBox", "QCheckBox", "QInputDialog", "QPushButton", "QVBoxLayout",
    "QHBoxLayout", "QFormLayout", "QScrollArea", "QFileDialog",
    "QPlainTextEdit", "QSpinBox", "QDialogButtonBox", "QFrame", "QTabWidget",
    "QDoubleSpinBox", "QGridLayout", "QSizePolicy", "QAbstractItemView",
    "QSplitter", "QToolButton", "QShortcut", "QKeySequence",
    "QStackedWidget", "QProgressDialog", "QGroupBox", "QStatusBar",
    "QListWidget", "QDateTimeEdit", "QProgressBar", "QBuffer", "QIODevice",
    "QObject", "QRunnable", "QThreadPool", "Signal", "QEvent",
)


def _iter_source_files():
    for path in ROOT.rglob("*.py"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.name == "test_gui_static.py":
            continue  # 本文件含示例文本，跳过自身
        yield path


def _imported_qt_names(text: str) -> set:
    names = set()

    def add_block(block: str) -> None:
        for part in block.split(","):
            name = part.strip().split(" as ")[0].strip()
            if name and re.fullmatch(r"\w+", name):
                names.add(name)

    for match in re.finditer(r"from PySide6\.\w+ import \(([^)]*)\)", text):
        # 跨行导入块内可能有 "# noqa" 等行内注释：先逐行剥注释再解析
        block = "\n".join(
            line.split("#")[0] for line in match.group(1).splitlines()
        )
        add_block(block)
    for match in re.finditer(r"from PySide6\.\w+ import ([^\n(]+)", text):
        add_block(match.group(1).split("#")[0])
    return names


class QtStaticTests(unittest.TestCase):
    def test_no_instance_enum_access_on_dialog_results(self):
        offenders = []
        for path in _iter_source_files():
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for match in _PATTERN.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                offenders.append(f"{path.relative_to(ROOT)}:{line} -> {match.group(0)}")
        self.assertEqual(
            offenders,
            [],
            "发现实例访问 Qt 枚举（真实桌面会 AttributeError 崩溃）。"
            "请改用 `if not dialog.exec():` 或类访问 QDialog.DialogCode.Accepted。\n"
            + "\n".join(offenders),
        )

    def test_qt_names_are_imported(self):
        offenders = []
        for path in _iter_source_files():
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if "PySide6" not in text and "Qt" not in text:
                continue
            imported = _imported_qt_names(text)
            # 去掉行注释后再查使用（降低误报）
            code = "\n".join(line.split("#")[0] for line in text.splitlines())
            for name in _QT_NAMES:
                if name in imported:
                    continue
                if re.search(rf"(?<![\w.]){re.escape(name)}[.(]", code):
                    offenders.append(f"{path.relative_to(ROOT)} 使用了 {name} 但未导入")
        self.assertEqual(
            offenders,
            [],
            "发现「使用了 Qt 名字但未导入」——真实桌面会 NameError 弹窗/闪退。\n"
            + "\n".join(sorted(set(offenders))),
        )


if __name__ == "__main__":
    unittest.main()
