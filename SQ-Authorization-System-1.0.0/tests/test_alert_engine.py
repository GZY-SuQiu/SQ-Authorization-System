"""A5 告警引擎测试：阈值判定、事件生命周期、冷却与邮件通知。"""

import tempfile
import unittest
from pathlib import Path

from core.config import Config
from core.database import Database
from server.alert_engine import AlertEngine, evaluate_condition, window_text


class FakeMailer:
    def __init__(self):
        self.items = []

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

    def start(self):
        return None

    def stop(self, timeout=5.0):
        return None

    def status(self):
        return {"enabled": True}


class AlertEngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.tmp.name)
        self.config = Config("server", root / "server_config.json")
        self.config.data["smtp"]["alert_admin_emails"] = ["ops@example.com"]
        self.db = Database(root / "license.db", self.config.security["secret_key"])
        self.mailer = FakeMailer()
        self.engine = AlertEngine(self.db, self.mailer, self.config, interval=999)

    def tearDown(self):
        self.engine.stop(timeout=1)
        self.db.close()
        self.tmp.cleanup()

    def test_condition_helpers(self):
        self.assertTrue(evaluate_condition(5, "gte", 5))
        self.assertTrue(evaluate_condition(5, "gt", 4))
        self.assertFalse(evaluate_condition(5, "lt", 5))
        self.assertTrue(evaluate_condition(5, "eq", 5))
        self.assertFalse(evaluate_condition(5, "unknown", 5))
        self.assertEqual(window_text(600), "10 分钟")
        self.assertEqual(window_text(3600), "1 小时")

    def test_rule_fires_once_and_notifies(self):
        self.db.create_alert_rule(
            name="激活失败过多",
            metric="failed_activations",
            operator="gte",
            threshold=1,
            window_seconds=3600,
            severity="warning",
            cooldown_seconds=3600,
            channels=["email"],
            enabled=True,
        )
        self.db.add_log("激活失败", "client", "GSQ-TEST", "测试失败", "127.0.0.1")

        fired = self.engine.evaluate_once()
        self.assertEqual(len(fired), 1, fired)
        events, total = self.db.list_alert_events(status="firing")
        self.assertGreaterEqual(total, 1)
        self.assertEqual(events[0]["metric"], "failed_activations")
        self.assertEqual(int(events[0]["notified"]), 1)

        alerts = [item for item in self.mailer.items if item["template_code"] == "alert_rule"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["to_email"], "ops@example.com")
        self.assertEqual(alerts[0]["variables"]["rule_name"], "激活失败过多")

        # 同一规则在活动事件期间不会重复触发。
        self.assertEqual(self.engine.evaluate_once(), [])

    def test_recovery_resolves_event(self):
        rule_id = self.db.create_alert_rule(
            name="完整性异常",
            metric="tamper_events",
            operator="gte",
            threshold=10,
            window_seconds=600,
            severity="critical",
            cooldown_seconds=3600,
            channels=["email"],
            enabled=True,
        )
        event_id = self.db.add_alert_event(
            rule_id=rule_id,
            rule_name="完整性异常",
            metric="tamper_events",
            value=99,
            threshold=10,
            operator="gte",
            severity="critical",
            payload={},
        )
        self.engine.evaluate_once()
        events, _ = self.db.list_alert_events()
        statuses = {int(item["id"]): item["status"] for item in events}
        self.assertEqual(statuses.get(int(event_id)), "resolved")

    def test_cooldown_blocks_refire_after_resolve(self):
        rule_id = self.db.create_alert_rule(
            name="激活失败过多",
            metric="failed_activations",
            operator="gte",
            threshold=1,
            window_seconds=3600,
            severity="warning",
            cooldown_seconds=3600,
            channels=["email"],
            enabled=True,
        )
        self.db.add_log("激活失败", "client", "GSQ-TEST", "测试失败", "127.0.0.1")
        self.engine.evaluate_once()
        events, _ = self.db.list_alert_events(status="firing")
        self.assertTrue(events)
        self.db.resolve_alert_event(int(events[0]["id"]))
        # 冷却期内不得重新触发。
        self.assertEqual(self.engine.evaluate_once(), [])
        remaining = self.db.list_alert_events()
        self.assertEqual(len(remaining[0]), 1)


if __name__ == "__main__":
    unittest.main()
