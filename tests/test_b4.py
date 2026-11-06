# -*- coding: utf-8 -*-
"""B4 风控体验测试：同机硬件变更容错置换 + 一键换绑。"""
import tempfile
import threading
import time
import unittest
from pathlib import Path

import requests
import uvicorn

from core import machine
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


class ComponentsUnitTests(unittest.TestCase):
    def test_fingerprint_components_shape(self):
        comps = machine.fingerprint_components()
        self.assertIsInstance(comps, dict)
        for key in ("guid", "vol", "mac", "cpu"):
            self.assertIn(key, comps)
            self.assertIsInstance(comps[key], str)

    def test_guid_plus_one_other(self):
        old = {"guid": "g1", "vol": "v1", "mac": "m1", "cpu": "c1"}
        new = {"guid": "g1", "vol": "v2", "mac": "m1", "cpu": "c2"}
        self.assertTrue(machine.same_machine_by_components(new, old))

    def test_vol_plus_both_others(self):
        old = {"guid": "g1", "vol": "v1", "mac": "m1", "cpu": "c1"}
        new = {"guid": "g2", "vol": "v1", "mac": "m1", "cpu": "c1"}
        self.assertTrue(machine.same_machine_by_components(new, old))

    def test_guid_only_insufficient(self):
        old = {"guid": "g1", "vol": "v1", "mac": "m1", "cpu": "c1"}
        new = {"guid": "g1", "vol": "v2", "mac": "m2", "cpu": "c2"}
        self.assertFalse(machine.same_machine_by_components(new, old))

    def test_vol_plus_one_insufficient(self):
        old = {"guid": "g1", "vol": "v1", "mac": "m1", "cpu": "c1"}
        new = {"guid": "g2", "vol": "v1", "mac": "m1", "cpu": "c2"}
        self.assertFalse(machine.same_machine_by_components(new, old))

    def test_none_sides(self):
        old = {"guid": "g1"}
        self.assertFalse(machine.same_machine_by_components(None, old))
        self.assertFalse(machine.same_machine_by_components(old, None))


class B4ApiTests(unittest.TestCase):
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
            self.admin.change_password(self.bootstrap, "B4Admin#2026")

    def tearDown(self):
        self.live.stop()
        self.db.close()
        self.tmp.cleanup()

    def _generate(self, **extra):
        payload = {"count": 1, "duration_days": 30, "max_devices": 1}
        payload.update(extra)
        return self.admin.generate_licenses(**payload)

    def _activate_raw(self, key, mc, components=None):
        body = {"key_code": key, "machine_code": mc}
        if components is not None:
            body["machine_components"] = components
        return requests.post(
            f"http://127.0.0.1:{self.port}/api/client/activate",
            json=body,
            timeout=15,
        ).json()

    # ------------------------------------------------------------------ #
    # 同机硬件变更容错
    # ------------------------------------------------------------------ #
    def test_rebound_on_component_match(self):
        key = self._generate()["keys"][0]
        comps_a = {"guid": "G-A", "vol": "V-A", "mac": "M-A", "cpu": "C-A"}
        ra = self._activate_raw(key, "DEV-A1111-11111-22222-33333", comps_a)
        self.assertTrue(ra.get("ok"), ra)

        # 换网卡/换盘：新机器码，但 guid + mac 一致 → 自动置换
        comps_b = {"guid": "G-A", "vol": "V-B", "mac": "M-A", "cpu": "C-B"}
        rb = self._activate_raw(key, "DEV-B2222-44444-55555-66666", comps_b)
        self.assertTrue(rb.get("ok"), rb)
        self.assertIn("硬件变更", rb.get("message", ""))

        detail = self.admin.license_detail(key)
        active = [a for a in detail["activations"] if a["status"] == "active"]
        self.assertEqual(len(active), 1)  # 置换而非新增
        self.assertEqual(active[0]["machine_code"], "DEV-B2222-44444-55555-66666")

    def test_no_rebound_on_mismatch(self):
        key = self._generate()["keys"][0]
        self._activate_raw(key, "DEV-A1111-11111-22222-33333",
                           {"guid": "G1", "vol": "V1", "mac": "M1", "cpu": "C1"})
        rb = self._activate_raw(key, "DEV-C3333-77777-88888-99999",
                                {"guid": "G2", "vol": "V2", "mac": "M2", "cpu": "C2"})
        self.assertEqual(rb.get("code"), "limit", rb)

    def test_legacy_no_components_still_limits(self):
        key = self._generate()["keys"][0]
        self._activate_raw(key, "DEV-A1111-11111-22222-33333")
        rb = self._activate_raw(key, "DEV-C3333-77777-88888-99999")
        self.assertEqual(rb.get("code"), "limit", rb)

    # ------------------------------------------------------------------ #
    # 一键换绑
    # ------------------------------------------------------------------ #
    def test_rebind_endpoint_full_flow(self):
        key = self._generate(duration_days=10)["keys"][0]
        ra = self._activate_raw(key, "RB-A1111-22222-33333-44444")
        self.assertTrue(ra.get("ok"), ra)
        self.admin._request(
            "POST", "/api/license/freeze",
            json_body={"key_code": key, "amount": 1, "unit": "hour", "reason": "换机测试"},
        )

        result = self.admin.rebind_license(key)
        self.assertTrue(result.get("ok"), result)
        self.assertTrue(result.get("unfrozen"))
        self.assertEqual(result.get("unbound"), 1)
        self.assertTrue(result.get("guide"))

        # 新设备直接激活成功
        rb = self._activate_raw(key, "RB-B2222-55555-66666-77777")
        self.assertTrue(rb.get("ok"), rb)

    def test_rebind_missing_key(self):
        with self.assertRaises(Exception):
            self.admin.rebind_license("GSQ-00000-00000-00000-00000")

    # ------------------------------------------------------------------ #
    # AI 工具
    # ------------------------------------------------------------------ #
    def test_ai_rebind_tool(self):
        from server.ai_tools import ToolRegistry

        key = self._generate()["keys"][0]
        self._activate_raw(key, "AIT-A1111-22222-33333-44444")
        registry = ToolRegistry(self.db, dict(self.config.security), "GSQ")
        operator = {"username": "admin", "role": "master", "id": 1}
        result = registry.call(
            "rebind_license", {"key_code": key}, operator, "127.0.0.1"
        )
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result.get("unbound"), 1)


if __name__ == "__main__":
    unittest.main()
