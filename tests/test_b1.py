# -*- coding: utf-8 -*-
"""B1 授权能力增强测试：浮动席位 / 试用卡 / 固定到期日。"""
import tempfile
import threading
import time
import unittest
from pathlib import Path

import uvicorn

from core import security
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


class B1ApiTests(unittest.TestCase):
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
        self.admin = self._new_client()
        login = self.admin.login("admin", self.bootstrap)
        if login.get("must_change_password"):
            self.admin.change_password(self.bootstrap, "B1Admin#2026")

    def tearDown(self):
        self.live.stop()
        self.db.close()
        self.tmp.cleanup()

    def _new_client(self) -> ApiClient:
        return ApiClient(
            f"http://127.0.0.1:{self.port}",
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )

    def _generate(self, **extra):
        payload = {"count": 1, "duration_days": 30, "max_devices": 1}
        payload.update(extra)
        return self.admin.generate_licenses(**payload)

    def _expire_lease(self, key: str, machine: str) -> None:
        old = security.shift_time_str(-3600)
        self.db._execute(
            "UPDATE activations SET last_heartbeat_at=?, last_verified_at=?,"
            " activated_at=? WHERE key_code=? AND machine_code=?",
            (old, old, old, key, machine),
        )

    # ------------------------------------------------------------------ #
    # 浮动席位
    # ------------------------------------------------------------------ #
    def test_floating_seats_activate_and_release(self):
        key = self._generate(max_concurrent=2)["keys"][0]
        a, b, c = self._new_client(), self._new_client(), self._new_client()

        ra = a.activate(key, "SEATA-11111-22222-33333-44444")
        self.assertTrue(ra.get("ok"), ra)
        self.assertEqual(ra["seats"]["limit"], 2)
        self.assertEqual(ra["seats"]["in_use"], 1)
        self.assertEqual(ra["seats"]["left"], 1)

        rb = b.activate(key, "SEATB-11111-22222-33333-44444")
        self.assertTrue(rb.get("ok"), rb)
        self.assertEqual(rb["seats"]["left"], 0)

        rc = c.activate(key, "SEATC-11111-22222-33333-44444")
        self.assertEqual(rc.get("code"), "seats_full", rc)

        # 租约全部过期（模拟全部离线）→ 席位释放
        self._expire_lease(key, "SEATA-11111-22222-33333-44444")
        self._expire_lease(key, "SEATB-11111-22222-33333-44444")
        rc2 = c.activate(key, "SEATC-11111-22222-33333-44444")
        self.assertTrue(rc2.get("ok"), rc2)

    def test_floating_ignores_bound_device_limit(self):
        # 浮动模式忽略 max_devices：2 台设备在 max_devices=1 的卡上依次上线
        key = self._generate(max_concurrent=5, max_devices=1)["keys"][0]
        a, b = self._new_client(), self._new_client()
        self.assertTrue(a.activate(key, "FLTA-11111-22222-33333-44444").get("ok"))
        rb = b.activate(key, "FLTB-11111-22222-33333-44444")
        self.assertTrue(rb.get("ok"), rb)

    def test_heartbeat_seat_contention(self):
        key = self._generate(max_concurrent=1)["keys"][0]
        a, b = self._new_client(), self._new_client()
        self.assertTrue(a.activate(key, "HB-A11111-22222-33333-44444").get("ok"))
        rb = b.activate(key, "HB-B11111-22222-33333-44444")
        self.assertEqual(rb.get("code"), "seats_full", rb)

        # A 离线过期 → B 顶替上线
        self._expire_lease(key, "HB-A11111-22222-33333-44444")
        rb2 = b.activate(key, "HB-B11111-22222-33333-44444")
        self.assertTrue(rb2.get("ok"), rb2)

        # A 心跳时租约已过期且席位被 B 占用 → seats_full
        ha = a.heartbeat(key, "HB-A11111-22222-33333-44444")
        self.assertEqual(ha.get("code"), "seats_full", ha)

        # B 正常心跳（占位中，续约成功）
        hb = b.heartbeat(key, "HB-B11111-22222-33333-44444")
        self.assertTrue(hb.get("ok"), hb)
        self.assertEqual(hb["seats"]["limit"], 1)

    def test_non_floating_response_has_no_seats(self):
        key = self._generate()["keys"][0]
        a = self._new_client()
        ra = a.activate(key, "PLAIN-11111-22222-33333-4444" + "4")
        self.assertTrue(ra.get("ok"), ra)
        self.assertNotIn("seats", ra)

    # ------------------------------------------------------------------ #
    # 试用卡
    # ------------------------------------------------------------------ #
    def test_trial_claim_once_per_machine(self):
        generated = self.admin.generate_licenses(
            count=2, duration_days=7, card_type="trial"
        )
        k1, k2 = generated["keys"][0], generated["keys"][1]
        a, b = self._new_client(), self._new_client()

        ra = a.activate(k1, "TRIAL-A1111-22222-33333-44444")
        self.assertTrue(ra.get("ok"), ra)

        # 同机再领同批另一张 → 拒绝
        rb = a.activate(k2, "TRIAL-A1111-22222-33333-44444")
        self.assertEqual(rb.get("code"), "trial_used", rb)

        # 其他机器可正常领取 k2
        rc = b.activate(k2, "TRIAL-B1111-22222-33333-44444")
        self.assertTrue(rc.get("ok"), rc)

        # 本机重激活自己的 k1 → 幂等 already
        rd = a.activate(k1, "TRIAL-A1111-22222-33333-44444")
        self.assertEqual(rd.get("code"), "already", rd)

    def test_trial_renew_rejected(self):
        key = self.admin.generate_licenses(
            count=1, duration_days=7, card_type="trial"
        )["keys"][0]
        with self.assertRaises(Exception) as ctx:
            self.admin._request(
                "POST", "/api/license/renew",
                json_body={"key_code": key, "duration_days": 7, "duration_unit": "day"},
            )
        self.assertIn("试用", str(ctx.exception))

    def test_trial_requires_duration_or_fixed(self):
        with self.assertRaises(Exception) as ctx:
            self.admin.generate_licenses(count=1, card_type="trial", duration_days=0)
        self.assertIn("试用卡", str(ctx.exception))

    # ------------------------------------------------------------------ #
    # 固定到期日
    # ------------------------------------------------------------------ #
    def test_fixed_expiry_activation_keeps_date(self):
        fixed = "2027-06-30 23:59:59"
        key = self._generate(
            expiry_mode="fixed", fixed_expires_at=fixed, duration_days=0
        )["keys"][0]
        detail = self.admin.license_detail(key)
        self.assertEqual(detail["license"]["expires_at"], fixed)
        self.assertEqual(detail["license"]["expiry_mode"], "fixed")

        a = self._new_client()
        ra = a.activate(key, "FIXED-11111-22222-33333-44444")
        self.assertTrue(ra.get("ok"), ra)
        self.assertEqual(ra["expires_at"], fixed)  # 激活不改变到期日

        rv = a.verify(key, "FIXED-11111-22222-33333-44444")
        self.assertEqual(rv["expires_at"], fixed)

    def test_fixed_rejects_past_and_bad_format(self):
        with self.assertRaises(Exception) as ctx:
            self._generate(
                expiry_mode="fixed",
                fixed_expires_at="2020-01-01 00:00:00",
                duration_days=0,
            )
        self.assertIn("晚于", str(ctx.exception))
        with self.assertRaises(Exception) as ctx2:
            self._generate(expiry_mode="fixed", fixed_expires_at="not-a-date", duration_days=0)
        self.assertIn("格式", str(ctx2.exception))

    def test_activation_card_rejects_fixed(self):
        with self.assertRaises(Exception) as ctx:
            self.admin.generate_licenses(
                count=1,
                card_type="activation",
                activation_limit=3,
                expiry_mode="fixed",
                fixed_expires_at="2027-01-01 00:00:00",
            )
        self.assertIn("次数卡", str(ctx.exception))

    # ------------------------------------------------------------------ #
    # 兼容性回归
    # ------------------------------------------------------------------ #
    def test_legacy_renew_still_works(self):
        key = self._generate(duration_days=10)["keys"][0]
        a = self._new_client()
        self.assertTrue(a.activate(key, "RENEW-11111-22222-33333-44444").get("ok"))
        result = self.admin._request(
            "POST", "/api/license/renew",
            json_body={"key_code": key, "duration_days": 5, "duration_unit": "day"},
        )
        self.assertTrue(result.get("ok"), result)


if __name__ == "__main__":
    unittest.main()
