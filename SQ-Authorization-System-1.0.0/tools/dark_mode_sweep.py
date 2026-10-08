"""Force a dark system palette and scan every page for black bands.

Windows 深色模式下，未显式着色的原生控件会透出深色/黑色背景，用户看到
"白界面 + 黑带"。这个工具在应用主题前强制套用深色 QPalette（模拟系统
深色模式），再逐个窗口、逐个页面、逐个滚动位置截图并扫描整行/整列的
近黑像素带，输出问题清单和 PNG 供人工复核。

Usage:  python tools/dark_mode_sweep.py [outdir]
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtGui import QColor, QPalette  # noqa: E402
from PySide6.QtWidgets import (  # noqa: E402
    QApplication,
    QScrollArea,
    QTabWidget,
)

from core import theme  # noqa: E402
from core.config import Config  # noqa: E402
from core.database import Database  # noqa: E402
from tools.render_pages import FakeClient  # noqa: E402


class TolerantClient(FakeClient):
    """FakeClient that answers unknown API calls with an empty page."""

    def __getattr__(self, _name):
        def _empty(*_args, **_kwargs):
            return {"items": [], "total": 0}

        return _empty

DARK_THRESHOLD = 40
DARK_RATIO = 0.85


def force_dark_palette(app) -> None:
    """Approximate what Windows dark mode hands to Qt at startup."""
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor("#202020"))
    palette.setColor(QPalette.WindowText, QColor("#F0F0F0"))
    palette.setColor(QPalette.Base, QColor("#2A2A2A"))
    palette.setColor(QPalette.AlternateBase, QColor("#252525"))
    palette.setColor(QPalette.Text, QColor("#F0F0F0"))
    palette.setColor(QPalette.Button, QColor("#2A2A2A"))
    palette.setColor(QPalette.ButtonText, QColor("#F0F0F0"))
    palette.setColor(QPalette.ToolTipBase, QColor("#2A2A2A"))
    palette.setColor(QPalette.ToolTipText, QColor("#F0F0F0"))
    app.setPalette(palette)


def dark_lines(image, *, axis: str) -> list[int]:
    """Return indices of rows/columns that are almost entirely near-black."""
    step = max(1, (image.width() if axis == "row" else image.height()) // 80)
    length = image.height() if axis == "row" else image.width()
    other = image.width() if axis == "row" else image.height()
    hits: list[int] = []
    for index in range(length):
        dark = 0
        total = 0
        for offset in range(0, other, step):
            color = (
                image.pixelColor(offset, index)
                if axis == "row"
                else image.pixelColor(index, offset)
            )
            total += 1
            if (
                color.red() < DARK_THRESHOLD
                and color.green() < DARK_THRESHOLD
                and color.blue() < DARK_THRESHOLD
            ):
                dark += 1
        if total and dark / total >= DARK_RATIO:
            hits.append(index)
    return hits


def _scroll_variants(widget) -> list[int]:
    areas = widget.findChildren(QScrollArea)
    values: set[int] = set()
    for area in areas:
        bar = area.verticalScrollBar()
        values.update({0, bar.maximum() // 2, bar.maximum()})
    return sorted(values)


def _shrink_spans(indexes: list[int]) -> str:
    if not indexes:
        return "-"
    spans: list[str] = []
    start = previous = indexes[0]
    for value in indexes[1:]:
        if value != previous + 1:
            spans.append(f"{start}-{previous}")
            start = value
        previous = value
    spans.append(f"{start}-{previous}")
    return ",".join(spans)


def _visit_tabs(widget) -> None:
    for tabs in widget.findChildren(QTabWidget):
        for index in range(tabs.count()):
            tabs.setCurrentIndex(index)
            QApplication.processEvents()


def scan_window(app, name: str, window, outdir: Path) -> list[str]:
    findings: list[str] = []
    window.resize(1440, 900)
    window.show()
    app.processEvents()

    buttons = getattr(window, "_buttons", [])
    pages = range(len(buttons)) if buttons else range(1)
    for index in pages:
        if buttons:
            buttons[index].click()
            app.processEvents()
        page = window.stack.currentWidget() if hasattr(window, "stack") else window
        label = buttons[index].text() if buttons else name
        _visit_tabs(page)
        for value in _scroll_variants(page):
            for area in page.findChildren(QScrollArea):
                bar = area.verticalScrollBar()
                if value <= bar.maximum():
                    bar.setValue(value)
            app.processEvents()
            image = page.grab().toImage()
            rows = dark_lines(image, axis="row")
            cols = dark_lines(image, axis="col")
            if rows or cols:
                findings.append(
                    f"{name} / {label} / scroll={value}: "
                    f"rows[{_shrink_spans(rows)}] cols[{_shrink_spans(cols)}]"
                )
                safe = f"{name}-{index}-{value}".replace(" ", "_")
                image.save(str(outdir / f"{safe}.png"))

    image = window.grab().toImage()
    rows = dark_lines(image, axis="row")
    cols = dark_lines(image, axis="col")
    if rows or cols:
        findings.append(
            f"{name} / <frame>: rows[{_shrink_spans(rows)}] cols[{_shrink_spans(cols)}]"
        )
        image.save(str(outdir / f"{name}-frame.png"))
    for timer in window.findChildren(QTimer):
        timer.stop()
    window.close()
    app.processEvents()
    return findings


def main() -> int:
    outdir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(ROOT) / "build" / "darkmode"
    outdir.mkdir(parents=True, exist_ok=True)

    app = QApplication(sys.argv[:1])
    force_dark_palette(app)
    theme.apply_theme(app)
    app.processEvents()

    from admin.ui import AdminWindow
    from master.ui import MasterWindow
    from server import ui as server_ui
    from verification.ui import VerifyWindow

    findings: list[str] = []
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        tmp_path = Path(tmp)
        client = TolerantClient()

        original_start = server_ui.ServerController.start
        server_ui.ServerController.start = lambda self: None
        db = None
        try:
            db = Database(tmp_path / "license.db")
            server_window = server_ui.ServerWindow(
                Config("server", tmp_path / "server_config.json"), db
            )
            findings += scan_window(app, "server", server_window, outdir)
        finally:
            server_ui.ServerController.start = original_start
            if db is not None:
                db.close()

        builders = [
            (
                "admin",
                lambda: AdminWindow(client, {"username": "admin01", "role": "admin"}),
            ),
            (
                "master",
                lambda: MasterWindow(
                    client,
                    {"username": "master", "role": "master"},
                    Config("master", tmp_path / "master_config.json"),
                ),
            ),
            (
                "verification",
                lambda: VerifyWindow(Config("verification", tmp_path / "verify.json")),
            ),
        ]
        for name, build in builders:
            window = build()
            findings += scan_window(app, name, window, outdir)

    if findings:
        print(f"发现 {len(findings)} 处近黑像素带：")
        for item in findings:
            print("  " + item)
        print(f"截图目录：{outdir}")
        return 1
    print(f"全部窗口/页面/滚动位置均无黑带。截图目录：{outdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
