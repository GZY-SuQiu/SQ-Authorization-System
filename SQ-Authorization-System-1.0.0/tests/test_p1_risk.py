"""P1 风控接线测试：新硬件码冻结 + IP 跳动告警。"""

import tempfile
import threading
import time
import unittest
from pathlib import Path

import uvicorn

from core.api_client import ApiClient
from core.config import Config
from core.database import Database
from server import risk
from server.api import create_app


def _free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class FakeMailer:
    """Minimal Mailer-compatible stub that records enqueue calls."""

    def __init__(self):
        self.items = []
        self.running = False

    def start(self):
        self.running = True

    def stop(self, timeout=5.0):
        self.running = False

    def enqueue(self, to_email, template_code, variables=None, dedupe_key=""):
        self.items.append(
            {
                "to_email": to_email,
                "template_code": template_code,
                "variables": dict(variables or {}),
                "dedupe_key": dedupe_key,
            }
        )
        return len(self.items)

    def send_now(self, to_email, template_code, variables=None):
        return None

    def status(self):
        return {
            "enabled": True,
            "host": "fake",
            "port": 0,
            "from_email": "no-reply@example.com",
            "pending": 0,
            "sending": 0,
            "sent": len(self.items),
            "failed": 0,
            "dead": 0,
            "last_error": None,
        }


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


class RiskUnitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db = Database(Path(self.tmp.name) / "license.db")
        _, keys = self.db.generate_licenses(count=1, duration_days=30, max_devices=1)
        self.key = keys[0]
        self.license = self.db.get_license(self.key)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_ip_jump_alerts_after_three_subnets(self):
        self.assertIsNone(
            risk.record_ip_event(self.db, self.license, "M-1", "10.0.1.10", window_minutes=10, threshold=2)
        )
        self.assertIsNone(
            risk.record_ip_event(self.db, self.license, "M-1", "10.0.2.10", window_minutes=10, threshold=2)
        )
        info = risk.record_ip_event(
            self.db, self.license, "M-1", "10.0.3.10", window_minutes=10, threshold=2
        )
        self.assertIsNotNone(info)
        self.assertGreater(info["changes"], 2)
        items, total = self.db.list_risk_events()
        self.assertGreaterEqual(total, 1)
        self.assertEqual(items[0]["kind"], "ip_jump")

    def test_freeze_for_machine_mismatch(self):
        frozen = risk.freeze_for_machine_mismatch(
            self.db, self.key, "NEW-MACHINE", "10.0.0.9"
        )
        self.assertIsNotNone(frozen)
        current = self.db.get_license(self.key)
        self.assertEqual(current["status"], "frozen")
        self.assertIn("machine_mismatch", current.get("freeze_reason") or "")
        items, total = self.db.list_risk_events()
        self.assertGreaterEqual(total, 1)
        self.assertEqual(items[0]["kind"], "machine_mismatch")

    def test_find_activation_by_machine(self):
        self.assertIsNone(self.db.find_activation_by_machine("NO-SUCH-MACHINE"))


class MachineMismatchApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.tmp.name)
        self.config = Config("server", root / "server_config.json")
        self.config.data["security"]["attest_mode"] = "off"
        self.config.data["smtp"]["alert_admin_emails"] = ["ops@example.com"]
        self.db = Database(root / "license.db", self.config.security["secret_key"])
        _, self.bootstrap = self.db.ensure_default_admin()
        self.mailer = FakeMailer()
        app = create_app(self.config, self.db, mailer=self.mailer)
        self.port = _free_port()
        self.live = _LiveServer(app, self.port)
        self.live.start()
        self.client = ApiClient(
            f"http://127.0.0.1:{self.port}",
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )

    def tearDown(self):
        self.live.stop()
        self.db.close()
        self.tmp.cleanup()

    def test_new_machine_freezes_license_and_emails_admins(self):
        login = self.client.login("admin", self.bootstrap)
        if login.get("must_change_password"):
            self.client.change_password(self.bootstrap, "RiskAdmin#2026")
        generated = self.client.generate_licenses(
            count=1, duration_days=30, max_devices=1
        )
        key = generated["keys"][0]

        first = self.client.activate(key, "MACHINE-A", "dev-a")
        self.assertTrue(first.get("ok"), first)
        second = self.client.activate(key, "MACHINE-B", "dev-b")
        self.assertEqual(second.get("code"), "limit", second)

        license = self.db.get_license(key)
        self.assertEqual(license["status"], "frozen")
        events, total = self.db.list_risk_events()
        self.assertGreaterEqual(total, 1)
        self.assertEqual(events[0]["kind"], "machine_mismatch")
        risk_mails = [item for item in self.mailer.items if item["template_code"] == "risk_alert"]
        self.assertTrue(risk_mails, self.mailer.items)


if __name__ == "__main__":
    unittest.main()
