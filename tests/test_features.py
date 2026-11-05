# -*- coding: utf-8 -*-
"""功能位授权（Feature Flags）测试：规范化单元 + 全链集成。"""
import tempfile
import threading
import time
import unittest
from pathlib import Path

import uvicorn

from core import offline, security
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


class FeatureNormalizationTests(unittest.TestCase):
    def test_normalize_list_dedup_and_lowercase(self):
        result = security.normalize_features(["Pro", "pro", " Cloud ", "cloud"])
        self.assertEqual(result, ["pro", "cloud"])

    def test_normalize_from_string(self):
        result = security.normalize_features("pro, cloud，export、api")
        self.assertEqual(result, ["pro", "cloud", "export", "api"])

    def test_normalize_empty_values(self):
        self.assertEqual(security.normalize_features(None), [])
        self.assertEqual(security.normalize_features([]), [])
        self.assertEqual(security.normalize_features(""), [])
        self.assertEqual(security.normalize_features(" , , "), [])

    def test_normalize_rejects_bad_chars(self):
        for bad in ("has space", "中文功能", "bad!char", "semi;colon"):
            with self.assertRaises(ValueError):
                security.normalize_features([bad])

    def test_normalize_rejects_too_long(self):
        with self.assertRaises(ValueError):
            security.normalize_features(["x" * 33])

    def test_normalize_rejects_too_many(self):
        with self.assertRaises(ValueError):
            security.normalize_features([f"f{i}" for i in range(33)])

    def test_features_roundtrip(self):
        text = security.features_to_text(["pro", "cloud"])
        self.assertEqual(security.features_from_text(text), ["pro", "cloud"])
        self.assertEqual(security.features_to_text([]), "")
        self.assertEqual(security.features_from_text(""), [])
        self.assertEqual(security.features_from_text("{bad json"), [])
        self.assertEqual(security.features_from_text('{"a":1}'), [])

    def test_allowed_charset(self):
        result = security.normalize_features(["a-b.c_d:e", "v2", "x.y"])
        self.assertEqual(result, ["a-b.c_d:e", "v2", "x.y"])


class FeatureApiTests(unittest.TestCase):
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
        self.client = ApiClient(
            f"http://127.0.0.1:{self.port}",
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )
        login = self.client.login("admin", self.bootstrap)
        if login.get("must_change_password"):
            self.client.change_password(self.bootstrap, "FeatureAdmin#2026")

    def tearDown(self):
        self.live.stop()
        self.db.close()
        self.tmp.cleanup()

    def _generate(self, **extra):
        payload = {"count": 1, "duration_days": 30, "max_devices": 1}
        payload.update(extra)
        return self.client.generate_licenses(**payload)

    def test_generate_with_features_and_detail(self):
        generated = self._generate(features=["pro", "cloud", "export"])
        key = generated["keys"][0]
        detail = self.client.license_detail(key)
        self.assertEqual(detail["license"]["features"], ["pro", "cloud", "export"])

    def test_invalid_feature_rejected(self):
        with self.assertRaises(Exception) as ctx:
            self._generate(features=["bad feature!"])
        self.assertIn("功能位", str(ctx.exception))

    def test_activate_and_verify_return_features(self):
        generated = self._generate(features=["pro", "cloud"])
        key = generated["keys"][0]
        activated = self.client.activate(key, "FEAT-AAAAA-BBBBB-CCCCC-DDDDD")
        self.assertTrue(activated.get("ok"), activated)
        self.assertEqual(activated.get("features"), ["pro", "cloud"])

        verified = self.client.verify(key, "FEAT-AAAAA-BBBBB-CCCCC-DDDDD")
        self.assertTrue(verified.get("ok"), verified)
        self.assertEqual(verified.get("features"), ["pro", "cloud"])

        heartbeat = self.client.heartbeat(key, "FEAT-AAAAA-BBBBB-CCCCC-DDDDD")
        self.assertEqual(heartbeat.get("features"), ["pro", "cloud"])

    def test_legacy_license_without_features(self):
        generated = self._generate()
        key = generated["keys"][0]
        activated = self.client.activate(key, "LEGACY-AAAAA-BBBBB-CCCCC-DDDD")
        self.assertTrue(activated.get("ok"), activated)
        self.assertEqual(activated.get("features"), [])

    def test_offline_code_embeds_features(self):
        generated = self._generate(features=["pro", "offline-ok"])
        key = generated["keys"][0]
        machine = "OFFLN-AAAAA-BBBBB-CCCCC-DDDDD"
        result = self.client.offline_code(key, machine)
        self.assertTrue(str(result.get("code", "")).startswith("LICACT1."))
        parsed = offline.parse_activation_code(
            result["code"], self.config.security["offline_public_key"]
        )
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.get("feats"), ["pro", "offline-ok"])

    def test_offline_code_without_features_has_empty_feats(self):
        generated = self._generate()
        key = generated["keys"][0]
        result = self.client.offline_code(key, "NOFEAT-AAAAA-BBBBB-CCCCC-DDDD")
        parsed = offline.parse_activation_code(
            result["code"], self.config.security["offline_public_key"]
        )
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.get("feats"), [])

    def test_sdk_has_feature(self):
        from sdk.sq_license_client import LicenseClient

        generated = self._generate(features=["pro", "cloud"])
        key = generated["keys"][0]
        sdk = LicenseClient(
            f"http://127.0.0.1:{self.port}",
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
            allow_insecure_http=True,
        )
        data = sdk.activate(key, "SDKFT-AAAAA-BBBBB-CCCCC-DDDDD")
        self.assertTrue(data.get("ok"), data)
        self.assertTrue(sdk.has_feature("pro"))
        self.assertTrue(sdk.has_feature("PRO"))  # 大小写不敏感
        self.assertFalse(sdk.has_feature("enterprise"))
        self.assertEqual(sdk.features(), ["pro", "cloud"])


if __name__ == "__main__":
    unittest.main()
