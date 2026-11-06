# -*- coding: utf-8 -*-
"""B5 测试：数据看板（趋势 API）+ 二维码矩阵 + 深色主题引擎。"""
import re
import tempfile
import threading
import time
import unittest
from pathlib import Path

import requests
import uvicorn

from core import qr, theme
from core.api_client import ApiClient
from core.config import Config
from core.database import Database
from server.api import create_app


def _free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _LiveServer:
    def __init__(self, app, port):
        self.server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", access_log=False)
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self):
        self.thread.start()
        for _ in range(200):
            if self.server.started:
                return
            time.sleep(0.05)
        raise RuntimeError("测试服务器启动超时")

    def stop(self):
        self.server.should_exit = True
        self.thread.join(timeout=10)


class DarkThemeTests(unittest.TestCase):
    def test_build_dark_qss_replaces_surfaces(self):
        qss = theme.build_dark_qss()
        self.assertGreater(len(qss), 5000)
        # 页面底色 / 深色面生效
        self.assertIn("#151517", qss)
        self.assertIn("#1B1B1C", qss)
        # 浅色主字色被换成浅色文字
        self.assertNotIn("#1D2330", qss)

    def test_build_dark_qss_protects_white_text(self):
        qss = theme.build_dark_qss()
        # 白字（color / selection-color 后的 #FFFFFF）必须保留
        self.assertRegex(qss, r"color:\s*#FFFFFF")

    def test_helpers_exist(self):
        self.assertTrue(callable(theme._dark_palette))
        self.assertTrue(callable(theme._set_titlebar))
        self.assertTrue(callable(theme.build_dark_qss))


class QrTests(unittest.TestCase):
    def test_matrix_shape(self):
        matrix = qr.make_qr_matrix("GSQ-AAAAA-BBBBB-CCCCC-DDDDD")
        self.assertIsNotNone(matrix)
        size = len(matrix)
        self.assertGreater(size, 20)
        for row in matrix:
            self.assertEqual(len(row), size)
        self.assertTrue(any(any(row) for row in matrix))

    def test_empty_returns_none(self):
        self.assertIsNone(qr.make_qr_matrix(""))
        self.assertIsNone(qr.make_qr_matrix("   "))

    def test_long_text_fits(self):
        matrix = qr.make_qr_matrix("A" * 500)
        self.assertIsNotNone(matrix)
        self.assertGreater(len(matrix), 20)

    def test_ascii_preview(self):
        text = qr.matrix_ascii(qr.make_qr_matrix("x"))
        self.assertIn("#", text)


class TrendTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.tmp.name)
        self.config = Config("server", root / "server_config.json")
        self.config.data["security"]["attest_mode"] = "off"
        self.db = Database(root / "license.db", self.config.security["secret_key"])
        _, self.bootstrap = self.db.ensure_default_admin()
        app = create_app(self.config, self.db)
        self.port = _free_port()
        self.live = _LiveServer(app, self.port)
        self.live.start()
        self.admin = ApiClient(
            f"http://127.0.0.1:{self.port}",
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )
        login = self.admin.login("admin", self.bootstrap)
        if login.get("must_change_password"):
            self.admin.change_password(self.bootstrap, "B5Admin#2026")

    def tearDown(self):
        self.live.stop()
        self.db.close()
        self.tmp.cleanup()

    def test_trend_api(self):
        generated = self.admin.generate_licenses(count=3, duration_days=5)
        key = generated["keys"][0]
        requests.post(
            f"http://127.0.0.1:{self.port}/api/client/activate",
            json={"key_code": key, "machine_code": "TREND-11111-22222-33333-44444"},
            timeout=15,
        )

        data = self.admin.metrics_trend(30)
        self.assertEqual(data["days"], 30)
        series = data["series"]
        self.assertEqual(len(series), 30)
        # 今天：新增 3 张、激活 1 台
        self.assertEqual(series[-1]["created"], 3)
        self.assertEqual(series[-1]["activated"], 1)
        # 到期：该卡 5 天后到期 → 在 30 天窗口内合计 1
        self.assertEqual(data["totals"]["expiring"], 1)

        short = self.admin.metrics_trend(7)
        self.assertEqual(short["days"], 7)

    def test_trend_empty_db(self):
        data = self.admin.metrics_trend(7)
        self.assertEqual(data["totals"]["created"], 0)
        self.assertEqual(len(data["series"]), 7)


if __name__ == "__main__":
    unittest.main()
