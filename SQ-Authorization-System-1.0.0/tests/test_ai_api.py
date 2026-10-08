import json
import tempfile
import unittest
from pathlib import Path

from tests.test_api_hardening import LiveServer, READY_PASSWORD
from core.api_client import ApiClient, ApiError
from core.config import Config
from core.database import Database


class AiApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.config = Config("server", self.root / "server_config.json")
        self.config.data["ai"] = {
            "enabled": True,
            "api_key": "sk-test",
            "base_url": "https://api.openai.com/v1",
            "model": "gpt-5.1",
            "monitor_interval": 8,
        }
        self.db = Database(self.root / "license.db")
        _, self.bootstrap = self.db.ensure_default_admin()
        self.live = LiveServer(self.config, self.db)
        self.live.start()
        self.client = ApiClient(
            f"http://127.0.0.1:{self.live.port}",
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )

    def tearDown(self):
        self.live.stop()
        self.db.close()
        self.tmp.cleanup()

    def _login_ready(self):
        login = self.client.login("admin", self.bootstrap)
        if login.get("must_change_password"):
            self.client.change_password(self.bootstrap, READY_PASSWORD)
        return login

    def test_ai_endpoints_require_authentication(self):
        anonymous = ApiClient(f"http://127.0.0.1:{self.live.port}")
        for call in (anonymous.ai_config, anonymous.ai_status):
            with self.assertRaises(ApiError) as caught:
                call()
            self.assertIn("未登录", str(caught.exception))

    def test_ai_config_never_returns_api_key(self):
        self._login_ready()
        payload = self.client.ai_config()
        self.assertTrue(payload["enabled"])
        self.assertTrue(payload["configured"])
        self.assertNotIn("api_key", payload)
        self.assertEqual(payload["model"], "gpt-5.1")
        self.assertEqual(payload["api_mode"], "responses")
        self.assertEqual(payload["provider"], "OpenAI")
        dumped = json.dumps(payload, ensure_ascii=False)
        for secret in ("sk-test", "api.openai.com", "custom_headers", "system_prompt"):
            self.assertNotIn(secret, dumped)

    def test_ai_status_returns_monitoring_snapshot(self):
        self._login_ready()
        payload = self.client.ai_status()
        self.assertTrue(payload["ai_enabled"])
        self.assertTrue(payload["ai_configured"])
        self.assertIn("stats", payload)
        self.assertEqual(payload["stats"]["total"], 0)
        self.assertIn("logs", payload)
        self.assertIn("server", payload)

    def test_ai_chat_reports_disabled_when_not_configured(self):
        self.config.data["ai"] = dict(self.config.data["ai"], enabled=False)
        # The running app captured its config at creation; a fresh app with the
        # disabled flag is exercised here to keep the assertion deterministic.
        from core.database import Database as _Database
        from server.api import create_app

        other_tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        other_root = Path(other_tmp.name)
        cfg = Config("server", other_root / "server_config.json")
        cfg.data["ai"] = {"enabled": False, "api_key": "sk-test"}
        db = _Database(other_root / "license.db")
        _, bootstrap = db.ensure_default_admin()
        live = LiveServer(cfg, db)
        live.start()
        try:
            client = ApiClient(
                f"http://127.0.0.1:{live.port}",
                response_public_key=cfg.security["response_public_key"],
                response_key_id=cfg.security["response_key_id"],
            )
            login = client.login("admin", bootstrap)
            if login.get("must_change_password"):
                client.change_password(bootstrap, READY_PASSWORD)
            with self.assertRaises(ApiError) as caught:
                client._request("POST", "/api/ai/chat", json_body={"messages": [{"role": "user", "content": "hi"}]})
            self.assertIn("启用", str(caught.exception))
        finally:
            live.stop()
            db.close()
            other_tmp.cleanup()

    def test_client_role_config_drops_ai_secrets(self):
        path = self.root / "admin_config.json"
        path.write_text(
            json.dumps({"ai": {"enabled": True, "api_key": "sk-leaked"}}),
            encoding="utf-8",
        )
        cfg = Config("admin", path)
        dumped = json.dumps({"data": cfg.data, "ai": cfg.ai}, ensure_ascii=False)
        self.assertNotIn("sk-leaked", dumped)
        self.assertEqual(cfg.ai.get("api_key"), "")
        self.assertFalse(cfg.ai.get("enabled"))


if __name__ == "__main__":
    unittest.main()
