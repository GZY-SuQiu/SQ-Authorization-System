"""审计修复的护栏测试：渠道 SSRF、切换服务器清公钥、审计日志清洗。"""

import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException

from core.api_client import ApiClient
from core.database import Database
from server.api import _channel_url


class ChannelUrlGuardTests(unittest.TestCase):
    def test_private_and_loopback_are_blocked_by_default(self):
        for url in (
            "http://127.0.0.1:8765/hook",
            "http://localhost/hook",
            "http://169.254.169.254/latest/meta-data",
            "http://10.0.0.5/notify",
        ):
            with self.assertRaises(HTTPException, msg=url):
                _channel_url(url)

    def test_private_allowed_when_explicitly_enabled(self):
        self.assertEqual(
            _channel_url("http://127.0.0.1:8765/hook", allow_private=True),
            "http://127.0.0.1:8765/hook",
        )

    def test_public_url_passes(self):
        self.assertEqual(
            _channel_url("https://oapi.dingtalk.com/robot/send?access_token=x"),
            "https://oapi.dingtalk.com/robot/send?access_token=x",
        )


class BaseUrlSwitchTests(unittest.TestCase):
    def test_switching_server_clears_pinned_keys_and_session(self):
        client = ApiClient(
            "http://127.0.0.1:8765",
            allow_insecure_http=True,
            response_public_key="a" * 64,
            response_key_id="ed25519-aaaa",
        )
        client.session_secret = "session-secret"
        client.set_trusted_public_keys("b" * 64, "a" * 64, "ed25519-aaaa")
        client.token = "admin-token"
        client.set_base_url("http://127.0.0.1:9999")
        self.assertEqual(client.response_public_key, "")
        self.assertEqual(client.response_key_id, "")
        self.assertEqual(client.offline_public_key, "")
        self.assertIsNone(client.token)
        self.assertIsNone(client.session_secret)


class AuditLogSanitizeTests(unittest.TestCase):
    def test_control_characters_are_stripped(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as raw:
            db = Database(Path(raw) / "license.db", "log-secret")
            try:
                db.add_log(
                    "操作\n伪造",
                    "user\r\nadmin",
                    "target\x07",
                    "detail" + "\x1b[31m" + "x" * 900,
                    "127.0.0.1\n",
                )
                items = db.list_logs(limit=10)
                self.assertEqual(len(items), 1)
                row = items[0]
                for value in (
                    row["action"],
                    row["actor"],
                    row["target"],
                    row["detail"],
                    row["ip"],
                ):
                    self.assertNotIn("\n", value)
                    self.assertNotIn("\r", value)
                    self.assertNotIn("\x07", value)
                    self.assertNotIn("\x1b", value)
                self.assertLessEqual(len(row["detail"]), 512)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
