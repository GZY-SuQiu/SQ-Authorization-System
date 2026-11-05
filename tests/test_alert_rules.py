"""A5 Backend：告警规则 / 告警事件 / 指标总览（core.database + server.api）。

覆盖范围：

- DB：规则 CRUD、事件 add/list/latest/ack/resolve/notified、``alert_metrics``
  的 7 个键与第 1 节口径（许可证、心跳、激活失败日志、风控/完整性事件）；
- API：规则增删改查、枚举与范围校验、master 删除权限、事件筛选与
  确认/处理、``/api/metrics/overview`` 返回 7 键；
- 接线：``create_app`` 注入的 alert_engine 会在启动/关闭时被调用。
"""

import tempfile
import threading
import unittest
from datetime import datetime, timedelta
from pathlib import Path

import uvicorn

from core import security
from core.api_client import ApiClient, ApiError
from core.config import Config
from core.database import Database
from server.api import create_app

from tests.test_api_hardening import LiveServer, _free_port, login_ready

ALERT_METRIC_KEYS = {
    "activation_rate",
    "online_devices",
    "expiration_rate",
    "expiring_soon",
    "failed_activations",
    "risk_events",
    "tamper_events",
}

OPERATOR_PASSWORD = "Operator#2026"


class FakeAlertEngine:
    """Records the lifecycle hooks ``create_app`` is required to attach."""

    def __init__(self):
        self.started = 0
        self.stopped = 0
        self.evaluations = 0

    def start(self) -> None:
        self.started += 1

    def stop(self, timeout: float = 5.0) -> None:
        self.stopped += 1

    def evaluate_once(self) -> list[dict]:
        self.evaluations += 1
        return []


class FakeMailer:
    """Minimal mailer surface ``create_app`` touches while wiring."""

    def __init__(self):
        self.started = 0
        self.stopped = 0
        self.items: list[dict] = []

    def start(self) -> None:
        self.started += 1

    def stop(self, timeout: float = 5.0) -> None:
        self.stopped += 1

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
        raise RuntimeError("SMTP 未启用或未配置")

    def status(self) -> dict:
        return {
            "enabled": False,
            "host": "",
            "port": 0,
            "from_email": "",
            "pending": 0,
            "sending": 0,
            "sent": 0,
            "failed": 0,
            "dead": 0,
            "last_error": None,
        }


class AlertLiveServer(LiveServer):
    """``LiveServer`` variant that injects the fake mailer and engine."""

    def __init__(self, config: Config, db: Database, alert_engine=None, mailer=None):
        self.config = config
        self.db = db
        self.port = _free_port()
        app = create_app(config, db, mailer=mailer, alert_engine=alert_engine)
        self.server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=self.port,
                log_level="warning",
                access_log=False,
            )
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)


class AlertRuleDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        Config("server", self.root / "server_config.json")
        self.db = Database(self.root / "license.db")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_rule_crud_round_trip_keeps_channels_list(self):
        rule_id = self.db.create_alert_rule(
            name="激活失败过多",
            metric="failed_activations",
            operator="gte",
            threshold=5,
            window_seconds=600,
            severity="warning",
            cooldown_seconds=3600,
            channels=["email"],
            enabled=True,
            note="联调备注",
        )
        self.assertIsInstance(rule_id, int)

        rule = self.db.get_alert_rule(rule_id)
        self.assertEqual(rule["name"], "激活失败过多")
        self.assertEqual(rule["metric"], "failed_activations")
        self.assertEqual(rule["operator"], "gte")
        self.assertEqual(float(rule["threshold"]), 5.0)
        self.assertEqual(int(rule["window_seconds"]), 600)
        self.assertEqual(rule["severity"], "warning")
        self.assertEqual(int(rule["cooldown_seconds"]), 3600)
        # list/get 必须给出反序列化后的 channels，同时保留原始 JSON。
        self.assertEqual(rule["channels"], ["email"])
        self.assertEqual(rule["channels_json"], '["email"]')
        self.assertEqual(int(rule["enabled"]), 1)
        self.assertEqual(rule["note"], "联调备注")
        self.assertTrue(rule["created_at"])
        self.assertTrue(rule["updated_at"])

        listed = self.db.list_alert_rules()
        self.assertEqual([item["id"] for item in listed], [rule_id])
        self.assertEqual(listed[0]["channels"], ["email"])

        # channels 省略时默认为邮件。
        default_id = self.db.create_alert_rule(
            name="默认渠道", metric="risk_events", operator="gte", threshold=1
        )
        self.assertEqual(self.db.get_alert_rule(default_id)["channels"], ["email"])

        self.assertTrue(
            self.db.update_alert_rule(
                rule_id, name="新名字", threshold=9.5, enabled=False
            )
        )
        rule = self.db.get_alert_rule(rule_id)
        self.assertEqual(rule["name"], "新名字")
        self.assertEqual(float(rule["threshold"]), 9.5)
        self.assertEqual(int(rule["enabled"]), 0)

        self.assertFalse(self.db.update_alert_rule(999999, name="x"))
        self.assertFalse(self.db.delete_alert_rule(999999))
        self.assertTrue(self.db.delete_alert_rule(rule_id))
        self.assertIsNone(self.db.get_alert_rule(rule_id))

    def test_event_lifecycle_and_filters(self):
        rule_id = self.db.create_alert_rule(
            "风控升级", "risk_events", "gte", 1, severity="critical"
        )
        event_id = self.db.add_alert_event(
            rule_id=rule_id,
            rule_name="风控升级",
            metric="risk_events",
            value=3,
            threshold=1,
            operator="gte",
            severity="critical",
            payload={"window_seconds": 600},
        )
        self.assertIsInstance(event_id, int)

        latest = self.db.get_latest_alert_event(rule_id)
        self.assertEqual(latest["id"], event_id)
        self.assertEqual(latest["status"], "firing")
        self.assertEqual(int(latest["notified"]), 0)
        self.assertEqual(latest["payload_json"], '{"window_seconds": 600}')
        self.assertTrue(latest["fired_at"])
        self.assertIsNone(latest["resolved_at"])
        self.assertIsNone(latest["acked_at"])
        self.assertIsNone(self.db.get_latest_alert_event(999999))

        items, total = self.db.list_alert_events()
        self.assertEqual(total, 1)
        self.assertEqual(items[0]["id"], event_id)
        self.assertEqual(items[0]["status"], "firing")
        # limit/offset 边界：1..1000 / >=0
        self.assertEqual(self.db.list_alert_events(limit=0)[1], 1)
        self.assertEqual(self.db.list_alert_events(limit=100000, offset=-5)[1], 1)

        self.assertTrue(self.db.ack_alert_event(event_id))
        acked = self.db.get_latest_alert_event(rule_id)
        self.assertEqual(acked["status"], "acked")
        self.assertTrue(acked["acked_at"])
        self.assertEqual(self.db.list_alert_events(status="acked")[1], 1)
        self.assertEqual(self.db.list_alert_events(status="firing")[1], 0)

        self.db.mark_alert_event_notified(event_id)
        self.assertEqual(int(self.db.get_latest_alert_event(rule_id)["notified"]), 1)

        self.assertTrue(self.db.resolve_alert_event(event_id))
        resolved = self.db.get_latest_alert_event(rule_id)
        self.assertEqual(resolved["status"], "resolved")
        self.assertTrue(resolved["resolved_at"])
        self.assertEqual(self.db.list_alert_events(status="resolved")[1], 1)

        # 已处理事件不能被重新确认回活动状态（否则引擎会永久沉默）。
        self.assertTrue(self.db.ack_alert_event(event_id))
        self.assertEqual(self.db.get_latest_alert_event(rule_id)["status"], "resolved")

        self.assertFalse(self.db.ack_alert_event(999999))
        self.assertFalse(self.db.resolve_alert_event(999999))

    def test_alert_metrics_matches_contract_windows(self):
        now_dt = datetime.now()
        _, keys = self.db.generate_licenses(3, duration_days=30)

        # key[0]：已激活 + 心跳在线。
        lic = self.db.get_license(keys[0])
        result, activation_id, _ = self.db.activate_atomic(
            lic["id"],
            keys[0],
            "MACHINE-A",
            "pc",
            security.compute_expiry(30, "day"),
            "session",
        )
        self.assertEqual(result, "activated")
        self.db.touch_heartbeat(activation_id)

        # key[1]：窗口内过期（expires_at 落在 [now-window, now]，状态 expired）。
        self.db.update_license_expiry(
            keys[1], (now_dt - timedelta(seconds=120)).strftime(security.TIME_FORMAT)
        )
        self.db.sweep_expired()

        # key[2]：3 天后到期的有效许可证。
        self.db.update_license_expiry(
            keys[2], (now_dt + timedelta(days=3)).strftime(security.TIME_FORMAT)
        )
        self.db.set_license_status(keys[2], "active")

        self.db.add_log("激活失败", "client", "GSQ-TEST", "签名错误", "127.0.0.1")
        self.db.add_risk_event(
            "ip_change", "warning", "GSQ-TEST", "MACHINE-A", "10.0.0.1", "换网"
        )
        self.db.add_tamper_event(
            "client", "verify.exe", "hash", "1.0", "MACHINE-A", "10.0.0.1",
            "hash_mismatch", "",
        )

        metrics = self.db.alert_metrics(600)
        self.assertEqual(set(metrics.keys()), ALERT_METRIC_KEYS)
        self.assertEqual(metrics["activation_rate"], 33.33)  # 1/3 已激活
        self.assertEqual(metrics["online_devices"], 1)
        self.assertEqual(metrics["expiration_rate"], 100.0)  # 1/1 已过期
        self.assertEqual(metrics["expiring_soon"], 1)
        self.assertEqual(metrics["failed_activations"], 1)
        self.assertEqual(metrics["risk_events"], 1)
        self.assertEqual(metrics["tamper_events"], 1)

        # 空库/空窗口时比率给 0，而不是 ZeroDivisionError。
        empty = Database(self.root / "empty.db")
        try:
            self.assertEqual(
                empty.alert_metrics(600),
                {
                    "activation_rate": 0.0,
                    "online_devices": 0,
                    "expiration_rate": 0.0,
                    "expiring_soon": 0,
                    "failed_activations": 0,
                    "risk_events": 0,
                    "tamper_events": 0,
                },
            )
        finally:
            empty.close()


class AlertApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.config = Config("server", self.root / "server_config.json")
        self.db = Database(self.root / "license.db")
        _, self.bootstrap = self.db.ensure_default_admin()
        self.db.create_admin("operator", OPERATOR_PASSWORD, role="admin")
        self.engine = FakeAlertEngine()
        self.mailer = FakeMailer()
        self.live = AlertLiveServer(
            self.config, self.db, alert_engine=self.engine, mailer=self.mailer
        )
        self.live.start()
        self.client = ApiClient(
            f"http://127.0.0.1:{self.live.port}",
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )
        login_ready(self.client, self.bootstrap)

    def tearDown(self):
        self.live.stop()
        self.db.close()
        self.tmp.cleanup()

    def _operator_client(self) -> ApiClient:
        client = ApiClient(
            f"http://127.0.0.1:{self.live.port}",
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )
        client.login("operator", OPERATOR_PASSWORD)
        return client

    def test_injected_alert_engine_is_started_and_stopped(self):
        self.assertGreaterEqual(self.engine.started, 1)
        self.assertGreaterEqual(self.mailer.started, 1)
        self.live.stop()
        self.assertGreaterEqual(self.engine.stopped, 1)
        self.assertGreaterEqual(self.mailer.stopped, 1)

    def test_rule_crud_via_api(self):
        created = self.client.create_alert_rule(
            name="激活失败过多",
            metric="failed_activations",
            operator="gte",
            threshold=3,
            window_seconds=600,
            severity="warning",
            cooldown_seconds=3600,
            channels=["email"],
            enabled=True,
            note="看板",
        )
        self.assertTrue(created["ok"])
        rule_id = created["id"]

        items = self.client.alert_rules()["items"]
        self.assertEqual(len(items), 1)
        rule = items[0]
        self.assertEqual(rule["id"], rule_id)
        self.assertEqual(rule["name"], "激活失败过多")
        self.assertEqual(rule["channels"], ["email"])
        self.assertEqual(rule["channels_json"], '["email"]')

        # 部分更新：只改名称/开关，其余字段保持。
        updated = self.client.update_alert_rule(rule_id, name="改名", enabled=False)
        self.assertTrue(updated["ok"])
        rule = self.client.alert_rules()["items"][0]
        self.assertEqual(rule["name"], "改名")
        self.assertEqual(int(rule["enabled"]), 0)
        self.assertEqual(rule["metric"], "failed_activations")

        with self.assertRaises(ApiError) as missing:
            self.client.update_alert_rule(999999, name="x")
        self.assertEqual(self.client.last_context["status_code"], 404)
        self.assertIn("不存在", str(missing.exception))

        self.assertTrue(self.client.delete_alert_rule(rule_id)["ok"])
        self.assertEqual(self.client.alert_rules()["items"], [])
        with self.assertRaises(ApiError) as gone:
            self.client.delete_alert_rule(rule_id)
        self.assertEqual(self.client.last_context["status_code"], 404)
        self.assertIn("不存在", str(gone.exception))

    def test_invalid_enums_are_rejected_with_400(self):
        with self.assertRaises(ApiError) as bad_metric:
            self.client.create_alert_rule(
                name="坏的", metric="not_a_metric", operator="gte", threshold=1
            )
        self.assertEqual(self.client.last_context["status_code"], 400)
        self.assertIn("指标", str(bad_metric.exception))

        with self.assertRaises(ApiError) as bad_operator:
            self.client.create_alert_rule(
                name="坏的", metric="risk_events", operator="foo", threshold=1
            )
        self.assertEqual(self.client.last_context["status_code"], 400)
        self.assertIn("运算符", str(bad_operator.exception))

        with self.assertRaises(ApiError) as bad_severity:
            self.client.create_alert_rule(
                name="坏的",
                metric="risk_events",
                operator="gte",
                threshold=1,
                severity="panic",
            )
        self.assertEqual(self.client.last_context["status_code"], 400)
        self.assertIn("级别", str(bad_severity.exception))

        with self.assertRaises(ApiError) as bad_channel:
            self.client.create_alert_rule(
                name="坏的",
                metric="risk_events",
                operator="gte",
                threshold=1,
                channels=["sms"],
            )
        self.assertEqual(self.client.last_context["status_code"], 400)

        # 数值范围由请求模型兜底（422），阈值必须有限。
        with self.assertRaises(ApiError):
            self.client.create_alert_rule(
                name="窗口越界",
                metric="risk_events",
                operator="gte",
                threshold=1,
                window_seconds=10,
            )
        with self.assertRaises(ApiError) as huge:
            self.client.create_alert_rule(
                name="无穷阈值",
                metric="risk_events",
                operator="gte",
                threshold=float("inf"),
            )
        self.assertEqual(self.client.last_context["status_code"], 400)
        self.assertIn("阈值", str(huge.exception))

        self.assertEqual(self.client.alert_rules()["items"], [])

    def test_delete_rule_requires_master(self):
        rule_id = self.client.create_alert_rule(
            name="仅主控可删", metric="risk_events", operator="gte", threshold=1
        )["id"]
        operator = self._operator_client()

        # 规则写操作允许 admin：新建与更新都放行。
        admin_rule = operator.create_alert_rule(
            name="管理员可建", metric="tamper_events", operator="gte", threshold=2
        )
        self.assertTrue(admin_rule["ok"])
        self.assertTrue(operator.update_alert_rule(rule_id, threshold=5)["ok"])

        with self.assertRaises(ApiError) as denied:
            operator.delete_alert_rule(rule_id)
        self.assertEqual(operator.last_context["status_code"], 403)
        self.assertIn("主控", str(denied.exception))
        self.assertIsNotNone(self.db.get_alert_rule(rule_id))

        # master 可以删除；admin 建立的那条也仍在。
        self.assertTrue(self.client.delete_alert_rule(rule_id)["ok"])
        self.assertIsNone(self.db.get_alert_rule(rule_id))
        self.assertTrue(self.client.delete_alert_rule(admin_rule["id"])["ok"])

    def test_event_listing_ack_resolve_and_metrics(self):
        rule_id = self.client.create_alert_rule(
            name="事件规则", metric="risk_events", operator="gte", threshold=1
        )["id"]
        event_id = self.db.add_alert_event(
            rule_id=rule_id,
            rule_name="事件规则",
            metric="risk_events",
            value=2,
            threshold=1,
            operator="gte",
            severity="critical",
            payload={"window_seconds": 600},
        )

        listing = self.client.alert_events(status="firing")
        self.assertEqual(listing["total"], 1)
        self.assertEqual(listing["items"][0]["id"], event_id)

        self.assertTrue(self.client.ack_alert_event(event_id)["ok"])
        self.assertEqual(self.client.alert_events(status="acked")["total"], 1)
        self.assertEqual(self.client.alert_events(status="firing")["total"], 0)

        self.assertTrue(self.client.resolve_alert_event(event_id)["ok"])
        resolved = self.client.alert_events(status="resolved")
        self.assertEqual(resolved["total"], 1)
        self.assertEqual(resolved["items"][0]["status"], "resolved")

        with self.assertRaises(ApiError) as missing_ack:
            self.client.ack_alert_event(999999)
        self.assertEqual(self.client.last_context["status_code"], 404)
        self.assertIn("不存在", str(missing_ack.exception))
        with self.assertRaises(ApiError) as missing_resolve:
            self.client.resolve_alert_event(999999)
        self.assertEqual(self.client.last_context["status_code"], 404)
        self.assertIn("不存在", str(missing_resolve.exception))

        overview = self.client.metrics_overview()
        self.assertEqual(set(overview.keys()), ALERT_METRIC_KEYS)
        overview_wide = self.client.metrics_overview(3600)
        self.assertEqual(set(overview_wide.keys()), ALERT_METRIC_KEYS)


if __name__ == "__main__":
    unittest.main()
