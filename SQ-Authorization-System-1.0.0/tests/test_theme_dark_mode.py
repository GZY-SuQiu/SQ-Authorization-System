"""深色系统主题下的黑带回归测试。

用户在 Windows 深色模式下看到服务器设置面板滚动时出现黑色横带；
这里强制深色 QPalette 后应用主题，验证：
1. 调色板被强制为浅色（原生控件不再发黑）；
2. 服务器设置滚动区在各滚动位置都不出现整行近黑像素带。
3. 每个滚动区的内容层都是不透明实底——透明层在滚动时新露出的条带
   会保持未绘制状态，在真实 Windows 窗口里就是整条黑带。
"""

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QColor, QPalette  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import QApplication, QScrollArea  # noqa: E402

from core import theme  # noqa: E402
from core.config import Config  # noqa: E402
from core.database import Database  # noqa: E402
from server import ui as server_ui  # noqa: E402
from tools.render_pages import FakeClient  # noqa: E402


class TolerantClient(FakeClient):
    """FakeClient that answers unknown API calls with an empty page."""

    def __getattr__(self, _name):
        def _empty(*_args, **_kwargs):
            return {"items": [], "total": 0}

        return _empty


def _near_black_rows(image, min_ratio: float = 0.85) -> list[int]:
    """Rows where almost every sampled pixel is near-black."""
    step = max(1, image.width() // 80)
    rows: list[int] = []
    for y in range(image.height()):
        dark = 0
        total = 0
        for x in range(0, image.width(), step):
            color = image.pixelColor(x, y)
            total += 1
            if color.red() < 40 and color.green() < 40 and color.blue() < 40:
                dark += 1
        if total and dark / total >= min_ratio:
            rows.append(y)
    return rows


def _transparent_samples(image, limit: int = 4000) -> int:
    """Count fully transparent pixels on a coarse grid."""
    step_x = max(1, image.width() // 40)
    step_y = max(1, image.height() // 60)
    clear = 0
    for y in range(0, image.height(), step_y):
        for x in range(0, image.width(), step_x):
            if image.pixelColor(x, y).alpha() == 0:
                clear += 1
                if clear >= limit:
                    return clear
    return clear


class DarkModeBlackBandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_dark_system_palette_is_overridden_to_light(self):
        dark = QPalette()
        dark.setColor(QPalette.Window, QColor("#1e1e1e"))
        dark.setColor(QPalette.Base, QColor("#101010"))
        dark.setColor(QPalette.Text, QColor("#ffffff"))
        self.app.setPalette(dark)

        theme.apply_theme(self.app)

        window = self.app.palette().color(QPalette.Window)
        base = self.app.palette().color(QPalette.Base)
        self.assertGreaterEqual(window.red() + window.green() + window.blue(), 600)
        self.assertGreaterEqual(base.red() + base.green() + base.blue(), 600)

    def test_scrolled_settings_pane_has_no_black_band(self):
        theme.apply_theme(self.app)
        original_start = server_ui.ServerController.start
        server_ui.ServerController.start = lambda self: None
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        window = None
        db = None
        try:
            config = Config("server", Path(tmp.name) / "server_config.json")
            db = Database(Path(tmp.name) / "license.db")
            window = server_ui.ServerWindow(config, db)
            window.resize(1120, 720)
            window.show()
            QTest.qWait(200)

            pane = window.findChild(QScrollArea)
            self.assertIsNotNone(pane, "未找到设置滚动区")
            bar = pane.verticalScrollBar()
            positions = sorted({0, bar.maximum() // 2, bar.maximum()})
            for value in positions:
                bar.setValue(value)
                QTest.qWait(60)
                rows = _near_black_rows(pane.grab().toImage())
                self.assertEqual(
                    rows,
                    [],
                    f"滚动位置 {value} 出现黑带（{len(rows)} 行）",
                )
        finally:
            if window is not None:
                window.close()
            if db is not None:
                db.close()
            server_ui.ServerController.start = original_start
            tmp.cleanup()

    def test_every_scroll_body_paints_an_opaque_background(self):
        """滚动内容层透明 = 真实窗口滚动时露出黑带，四个端都不能有。"""
        theme.apply_theme(self.app)
        original_start = server_ui.ServerController.start
        server_ui.ServerController.start = lambda self: None
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        windows = []
        try:
            from admin.ui import AdminWindow
            from master.ui import MasterWindow
            from verification.ui import VerifyWindow

            tmp_path = Path(tmp.name)
            db = Database(tmp_path / "license.db")
            windows.append(
                (
                    "server",
                    server_ui.ServerWindow(
                        Config("server", tmp_path / "server_config.json"), db
                    ),
                    db,
                )
            )
            client = TolerantClient()
            windows.append(
                (
                    "admin",
                    AdminWindow(client, {"username": "admin01", "role": "admin"}),
                    None,
                )
            )
            windows.append(
                (
                    "master",
                    MasterWindow(
                        client,
                        {"username": "master", "role": "master"},
                        Config("master", tmp_path / "master_config.json"),
                    ),
                    None,
                )
            )
            windows.append(
                (
                    "verification",
                    VerifyWindow(Config("verification", tmp_path / "verify.json")),
                    None,
                )
            )

            checked = 0
            for name, window, database in windows:
                window.resize(1120, 720)
                window.show()
                QTest.qWait(80)
                areas = window.findChildren(QScrollArea)
                self.assertTrue(areas, f"{name} 没有滚动区，用例前提失效")
                for index, area in enumerate(areas):
                    body = area.widget()
                    if body is None:
                        continue
                    image = body.grab().toImage()
                    clear = _transparent_samples(image)
                    checked += 1
                    self.assertEqual(
                        clear,
                        0,
                        f"{name} 第 {index + 1} 个滚动区内容层有透明像素"
                        f"（{clear} 个采样点），滚动时会露黑带",
                    )
                window.close()
                if database is not None:
                    database.close()
            self.assertGreaterEqual(checked, 3, "至少应检查服务器与验证端滚动区")
        finally:
            server_ui.ServerController.start = original_start
            tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
