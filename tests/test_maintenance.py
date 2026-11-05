"""合题批次 B 验收测试（docs/DIALECTIC-REVIEW.md 反题 B/E）。

覆盖范围：

- P2-13 数据保留：``db.run_maintenance`` 只删过期数据、绝不删
  pending/failed/sending，手动/自动维护接口与权限；
- P2-15 告警指标缓存：每个 tick 按 window_seconds 只算一次 7 项指标；
- P1-11 发布自动退役：新清单导入后旧 release_meta / 旧 exe 哈希失效；
- P2-14 日志计数缓存：``count_logs_cached`` 按筛选条件复用结果；
- E 版本单一来源：``server.api.VERSION`` 直接来自 ``core.config.APP_VERSION``。
"""

import json
import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

import uvicorn

from core import offline, security
from core.config import APP_VERSION, Config
from core.database import Database
from server import api as server_api
from server import main as server_main
from server.alert_engine import AlertEngine
from server.api import create_app
from tests.test_api_hardening import LiveServer, _free_port

MASTER_PASSWORD = "MaintMaster#2026"
OPERATOR_PASSWORD = "MaintOps#2026"
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
RELEASE_V1 = "11111111111111111111111111111111"
RELEASE_V2 = "22222222222222222222222222222222"
RELEASE_V3 = "33333333333333333333333333333333"
MAINTENANCE_KEYS = (
    "action_codes",
    "alert_events",
    "audit_logs",
    "channel_outbox",
    "email_outbox",
    "risk_events",
    "tamper_events",
)


def _ago(days: float = 0, seconds: float = 0) -> str:
    return (datetime.now() - timedelta(days=days, seconds=seconds)).strftime(
        security.TIME_FORMAT
    )


def _ahead(minutes: int = 10) -> str:
    return (datetime.now() + timedelta(minutes=minutes)).strftime(
        security.TIME_FORMAT
    )


def _manifest(release_id: str, version: str, entries) -> dict:
    """Minimal signed-manifest shape for release_meta retirement tests."""
    apps = {}
    for role, path, sha256 in entries:
        apps[role] = {"path": path, "sha256": sha256, "size": 4}
    return {
        "format": "sq-release-manifest-v1",
        "version": version,
        "release_id": release_id,
        "generated_at": "2026-10-08T12:00:00+08:00",
        "apps": apps,
        "folder": {},
    }


def _manifest_bytes(manifest: dict) -> bytes:
    return json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


class _NoMailer:
    def enqueue(self, to_email, template_code, variables=None, dedupe_key=""):
        return None

    def send_now(self, to_email, template_code, variables=None):
        return None

    def start(self):
        return None

    def stop(self, timeout=5.0):
        return None

    def status(self):
        return {"enabled": False}


class RetentionPolicyTests(unittest.TestCase):
    """P2-13：保留策略与 ``db.run_maintenance`` 的删除边界。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.config = Config("server", self.root / "server_config.json")
        self.db = Database(
            self.root / "license.db", self.config.security["secret_key"]
        )

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    # -- helpers ---------------------------------------------------------
    def _update(self, table: str, where: str, params: tuple, column: str, value):
        self.db._execute(
            f"UPDATE {table} SET {column} = ? WHERE {where}", (value, *params)
        )

    def _count(self, table: str, where: str = "1 = 1", params: tuple = ()) -> int:
        row = self.db._fetchone(
            f"SELECT COUNT(*) AS n FROM {table} WHERE {where}", params
        )
        return int(row["n"]) if row else 0

    def _seed_outbox(self) -> dict:
        ids = {}
        ids["email_pending"] = self.db.enqueue_email("pending@example.com", "test")
        ids["email_sent_old"] = self.db.enqueue_email("sent-old@example.com", "test")
        self.db.mark_email_sent(ids["email_sent_old"])
        ids["email_sent_new"] = self.db.enqueue_email("sent-new@example.com", "test")
        self.db.mark_email_sent(ids["email_sent_new"])
        ids["email_dead_old"] = self.db.enqueue_email("dead-old@example.com", "test")
        self.db.mark_email_failed(
            ids["email_dead_old"], "smtp down", None, dead=True
        )
        ids["email_failed"] = self.db.enqueue_email("failed@example.com", "test")
        self.db.mark_email_failed(ids["email_failed"], "temporary", _ahead(5))
        channel_id = self.db.create_notification_channel(
            "webhook", "maint-hook", "https://example.com/hook"
        )
        ids["channel_pending"] = self.db.enqueue_channel_message(
            channel_id, "主题", "内容"
        )
        ids["channel_sent_old"] = self.db.enqueue_channel_message(
            channel_id, "旧主题", "内容"
        )
        self.db.mark_channel_message_sent(ids["channel_sent_old"])
        ids["channel_sent_new"] = self.db.enqueue_channel_message(
            channel_id, "新主题", "内容"
        )
        self.db.mark_channel_message_sent(ids["channel_sent_new"])
        ids["channel_dead_old"] = self.db.enqueue_channel_message(
            channel_id, "死信", "内容"
        )
        self.db.mark_channel_message_failed(
            ids["channel_dead_old"], "http 500", None, dead=True
        )
        return ids

    # -- tests -----------------------------------------------------------
    def test_security_config_ships_and_keeps_retention_defaults(self):
        security_conf = self.config.security
        self.assertEqual(security_conf["retention_audit_days"], 180)
        self.assertEqual(security_conf["retention_events_days"], 365)
        self.assertEqual(security_conf["retention_codes_days"], 7)
        self.assertEqual(security_conf["retention_outbox_days"], 30)
        self.assertEqual(security_conf["maintenance_interval_hours"], 24)
        self.assertTrue(security_conf["release_auto_retire_old"])

        # 深度合并：存量 server_config.json 缺新键时补默认值，改过的值保留。
        self.config.data["security"]["retention_audit_days"] = 30
        self.config.save()
        reloaded = Config("server", self.root / "server_config.json")
        self.assertEqual(reloaded.security["retention_audit_days"], 30)
        self.assertEqual(reloaded.security["retention_events_days"], 365)

    def test_run_maintenance_deletes_expired_rows_only(self):
        # audit_logs：旧删新留。
        self.db.add_log("旧日志", "system", "", "", "")
        self.db.add_log("新日志", "system", "", "", "")
        self._update(
            "audit_logs", "action = ?", ("旧日志",), "created_at", _ago(days=200)
        )
        # tamper / risk：365 天窗口外删除，窗口内保留。
        self.db.add_tamper_event(
            "server", "old.exe", HASH_A, "1.0.0", "M1", "127.0.0.1", "旧"
        )
        self.db.add_tamper_event(
            "server", "new.exe", HASH_B, "1.0.0", "M1", "127.0.0.1", "新"
        )
        self._update(
            "tamper_events",
            "exe_name = ?",
            ("old.exe",),
            "created_at",
            _ago(days=400),
        )
        self.db.add_risk_event("ip_jump", "warning", "GSQ-OLD", "M1", "1.1.1.1", "旧")
        self.db.add_risk_event("ip_jump", "warning", "GSQ-NEW", "M1", "1.1.1.1", "新")
        self._update(
            "risk_events",
            "key_code = ?",
            ("GSQ-OLD",),
            "created_at",
            _ago(days=400),
        )
        # alert_events：只清理已恢复的旧事件，活动事件再老也不删。
        resolved_id = self.db.add_alert_event(
            rule_id=1,
            rule_name="旧规则",
            metric="risk_events",
            value=5,
            threshold=1,
            operator="gte",
            severity="warning",
            payload={},
        )
        self.db.resolve_alert_event(resolved_id)
        self._update(
            "alert_events", "id = ?", (resolved_id,), "fired_at", _ago(days=400)
        )
        self._update(
            "alert_events", "id = ?", (resolved_id,), "resolved_at", _ago(days=400)
        )
        firing_id = self.db.add_alert_event(
            rule_id=2,
            rule_name="活动规则",
            metric="risk_events",
            value=9,
            threshold=1,
            operator="gte",
            severity="critical",
            payload={},
        )
        self._update(
            "alert_events", "id = ?", (firing_id,), "fired_at", _ago(days=400)
        )
        # action_codes：过期/已用且超期的删除，仍有效的保留。
        self.db.create_action_code(
            "admin", 1, "old@example.com", "reset", "hash-old", _ago(days=30)
        )
        self.db.create_action_code(
            "admin", 1, "live@example.com", "reset", "hash-live", _ahead(10)
        )
        # outbox：只清理过期的 sent/dead。
        ids = self._seed_outbox()
        self._update(
            "email_outbox",
            "id = ?",
            (ids["email_sent_old"],),
            "sent_at",
            _ago(days=40),
        )
        self._update(
            "email_outbox",
            "id = ?",
            (ids["email_dead_old"],),
            "created_at",
            _ago(days=40),
        )
        self._update(
            "channel_outbox",
            "id = ?",
            (ids["channel_sent_old"],),
            "sent_at",
            _ago(days=40),
        )
        self._update(
            "channel_outbox",
            "id = ?",
            (ids["channel_dead_old"],),
            "created_at",
            _ago(days=40),
        )

        # 先缓存一次计数，维护后缓存必须失效（不能返回旧的全表结果）。
        self.db.count_logs_cached(keyword="", action="旧日志")
        deleted = self.db.run_maintenance(self.config.security)

        self.assertEqual(sorted(deleted), sorted(MAINTENANCE_KEYS))
        self.assertEqual(deleted["audit_logs"], 1)
        self.assertEqual(deleted["tamper_events"], 1)
        self.assertEqual(deleted["risk_events"], 1)
        self.assertEqual(deleted["alert_events"], 1)
        self.assertEqual(deleted["action_codes"], 1)
        self.assertEqual(deleted["email_outbox"], 2)
        self.assertEqual(deleted["channel_outbox"], 2)

        self.assertEqual(self._count("audit_logs", "action = ?", ("旧日志",)), 0)
        self.assertEqual(self.db.count_logs_cached(keyword="", action="旧日志"), 0)
        self.assertEqual(self._count("audit_logs", "action = ?", ("新日志",)), 1)
        self.assertEqual(self._count("tamper_events", "exe_name = ?", ("new.exe",)), 1)
        self.assertEqual(self._count("risk_events", "key_code = ?", ("GSQ-NEW",)), 1)
        events = {int(row["id"]): row for row in self.db.list_alert_events()[0]}
        self.assertNotIn(resolved_id, events)
        self.assertIn(firing_id, events)
        self.assertEqual(self._count("action_codes", "email = ?", ("live@example.com",)), 1)
        self.assertEqual(self._count("email_outbox", "status = ?", ("sent",)), 1)
        self.assertIsNone(
            self.db._fetchone(
                "SELECT id FROM email_outbox WHERE id = ?", (ids["email_dead_old"],)
            )
        )
        self.assertEqual(self._count("channel_outbox", "status = ?", ("sent",)), 1)

    def test_run_maintenance_never_deletes_unfinished_outbox(self):
        ids = self._seed_outbox()
        channel_id = self.db.create_notification_channel(
            "webhook", "sending-hook", "https://example.com/hook"
        )
        # pending/failed/sending 全部人为“过期”，维护任务仍必须保留。
        stale = _ago(days=400)
        for email_id in (ids["email_pending"], ids["email_failed"]):
            self._update(
                "email_outbox", "id = ?", (email_id,), "created_at", stale
            )
        sending_email = self.db.enqueue_email("sending@example.com", "test")
        claimed = self.db.claim_due_emails()
        self.assertTrue(any(int(item["id"]) == int(sending_email) for item in claimed))
        self._update(
            "email_outbox", "id = ?", (sending_email,), "created_at", stale
        )
        self._update(
            "email_outbox", "id = ?", (sending_email,), "claimed_at", stale
        )
        sending_channel = self.db.enqueue_channel_message(channel_id, "在途", "内容")
        claimed = self.db.claim_due_channel_messages()
        self.assertTrue(any(int(item["id"]) == int(sending_channel) for item in claimed))
        self._update(
            "channel_outbox", "id = ?", (sending_channel,), "created_at", stale
        )

        deleted = self.db.run_maintenance(self.config.security)
        self.assertEqual(deleted["email_outbox"], 0)
        self.assertEqual(deleted["channel_outbox"], 0)
        for email_id in (ids["email_pending"], ids["email_failed"], sending_email):
            self.assertIsNotNone(
                self.db._fetchone(
                    "SELECT id FROM email_outbox WHERE id = ?", (email_id,)
                )
            )
        self.assertIsNotNone(
            self.db._fetchone(
                "SELECT id FROM channel_outbox WHERE id = ?", (sending_channel,)
            )
        )

    def test_zero_retention_days_keeps_everything(self):
        self.db.add_log("历史日志", "system", "", "", "")
        self._update(
            "audit_logs",
            "action = ?",
            ("历史日志",),
            "created_at",
            _ago(days=9999),
        )
        deleted = self.db.run_maintenance(
            {
                "retention_audit_days": 0,
                "retention_events_days": 0,
                "retention_codes_days": 0,
                "retention_outbox_days": 0,
            }
        )
        self.assertEqual(sum(deleted.values()), 0)
        self.assertEqual(self._count("audit_logs", "action = ?", ("历史日志",)), 1)


class LogCountCacheTests(unittest.TestCase):
    """P2-14 局部：日志计数按筛选条件做 30 秒缓存。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.config = Config("server", self.root / "server_config.json")
        self.db = Database(self.root / "license.db")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_count_logs_cached_reuses_result_per_filter(self):
        self.db.add_log("测试动作", "tester", "", "", "")
        calls = []
        original = self.db.count_logs

        def counting(**filters):
            calls.append(filters)
            return original(**filters)

        self.db.count_logs = counting
        first = self.db.count_logs_cached(keyword="", action="测试动作")
        self.db.add_log("测试动作", "tester", "", "", "")
        # TTL 内复用同一结果，不再打数据库。
        second = self.db.count_logs_cached(keyword="", action="测试动作")
        self.assertEqual((first, second), (1, 1))
        self.assertEqual(len(calls), 1)
        # 不同筛选条件各自缓存。
        self.db.count_logs_cached(keyword="", action="另一个动作")
        self.assertEqual(len(calls), 2)
        # ttl=0 强制刷新，看到新写入的一行。
        self.assertEqual(
            self.db.count_logs_cached(ttl=0, keyword="", action="测试动作"), 2
        )
        self.assertEqual(len(calls), 3)


class AlertMetricsWindowCacheTests(unittest.TestCase):
    """P2-15：同一 tick 内每个 window_seconds 只算一次 7 项指标。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.config = Config("server", self.root / "server_config.json")
        self.db = Database(
            self.root / "license.db", self.config.security["secret_key"]
        )
        self.engine = AlertEngine(
            self.db, _NoMailer(), self.config, interval=999
        )

    def tearDown(self):
        self.engine.stop(timeout=1)
        self.db.close()
        self.tmp.cleanup()

    def test_alert_metrics_computed_once_per_window_per_tick(self):
        for index, window in enumerate((600, 600, 600, 3600), start=1):
            self.db.create_alert_rule(
                name=f"规则{index}",
                metric="failed_activations",
                operator="gte",
                threshold=999999,
                window_seconds=window,
                severity="warning",
                cooldown_seconds=3600,
                channels=["email"],
                enabled=True,
            )
        calls: list[int] = []
        original = self.db.alert_metrics

        def counting(window):
            calls.append(int(window))
            return original(window)

        self.db.alert_metrics = counting
        self.assertEqual(self.engine.evaluate_once(), [])
        self.assertEqual(len(calls), 2, calls)
        self.assertEqual(calls.count(600), 1)
        self.assertEqual(calls.count(3600), 1)
        self.assertEqual(len(original(600)), 7)
        # 缓存只在一个 tick 内生效：下一次评估各窗口再算一次。
        self.engine.evaluate_once()
        self.assertEqual(len(calls), 4, calls)


class ReleaseRetireTests(unittest.TestCase):
    """P1-11：新发布自动退役旧 release_meta 与旧构建哈希。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.config = Config("server", self.root / "server_config.json")
        self.db = Database(
            self.root / "license.db", self.config.security["secret_key"]
        )

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_retire_old_deactivates_previous_meta_and_hash(self):
        v1 = _manifest(
            RELEASE_V1, "1.0.0", [("verification", "verification.exe", HASH_A)]
        )
        raw1 = _manifest_bytes(v1)
        server_api.import_release_manifest(
            self.db, v1, raw1, note="test", retire_old=True
        )
        self.assertIsNotNone(self.db.match_release_hash(HASH_A))
        self.assertIsNotNone(self.db.match_active_release_meta(RELEASE_V1))

        v2 = _manifest(
            RELEASE_V2, "2.0.0", [("verification", "verification.exe", HASH_B)]
        )
        raw2 = _manifest_bytes(v2)
        server_api.import_release_manifest(
            self.db, v2, raw2, note="test", retire_old=True
        )

        self.assertIsNone(self.db.match_active_release_meta(RELEASE_V1))
        self.assertIsNotNone(self.db.match_active_release_meta(RELEASE_V2))
        self.assertEqual(self.db.count_active_release_meta(), 1)
        # 旧 exe 哈希不再能通过 attest 的白名单检查。
        self.assertIsNone(self.db.match_release_hash(HASH_A))
        self.assertIsNone(self.db.match_release_hash(HASH_A, "verification.exe"))
        self.assertIsNotNone(self.db.match_release_hash(HASH_B))

    def test_retire_old_false_keeps_previous_release(self):
        v1 = _manifest(
            RELEASE_V1, "1.0.0", [("verification", "verification.exe", HASH_A)]
        )
        v2 = _manifest(
            RELEASE_V2, "2.0.0", [("verification", "verification.exe", HASH_B)]
        )
        server_api.import_release_manifest(
            self.db, v1, _manifest_bytes(v1), retire_old=False
        )
        server_api.import_release_manifest(
            self.db, v2, _manifest_bytes(v2), retire_old=False
        )
        self.assertIsNotNone(self.db.match_active_release_meta(RELEASE_V1))
        self.assertIsNotNone(self.db.match_active_release_meta(RELEASE_V2))
        self.assertIsNotNone(self.db.match_release_hash(HASH_A))

    def test_startup_import_honours_release_auto_retire_old(self):
        """server/main.py 的启动导入把配置传给 import_release_manifest。"""
        private_key, public_key = offline.generate_keypair()
        self.config.security["release_public_key"] = public_key
        v1 = _manifest(
            RELEASE_V1, "1.0.0", [("verification", "verification.exe", HASH_A)]
        )
        server_api.import_release_manifest(
            self.db, v1, _manifest_bytes(v1), retire_old=True
        )

        releases = self.root / "releases"
        releases.mkdir()
        v2 = _manifest(
            RELEASE_V2, "2.0.0", [("verification", "verification.exe", HASH_B)]
        )
        raw2 = _manifest_bytes(v2)
        (releases / "release_manifest.json").write_bytes(raw2)
        (releases / "release_manifest.sig").write_text(
            offline.sign_message(private_key, raw2), encoding="utf-8"
        )

        with mock.patch.object(server_main, "APP_DIR", self.root):
            imported = server_main._load_release_manifests(self.db, self.config)
        self.assertEqual(imported, 1)
        self.assertIsNone(self.db.match_active_release_meta(RELEASE_V1))
        self.assertIsNotNone(self.db.match_active_release_meta(RELEASE_V2))

        # 配置关闭时不做退役。
        v3 = _manifest(
            RELEASE_V3, "3.0.0", [("verification", "verification.exe", HASH_C)]
        )
        raw3 = _manifest_bytes(v3)
        (releases / "release_manifest.json").write_bytes(raw3)
        (releases / "release_manifest.sig").write_text(
            offline.sign_message(private_key, raw3), encoding="utf-8"
        )
        self.config.security["release_auto_retire_old"] = False
        with mock.patch.object(server_main, "APP_DIR", self.root):
            self.assertEqual(
                server_main._load_release_manifests(self.db, self.config), 1
            )
        self.assertIsNotNone(self.db.match_active_release_meta(RELEASE_V2))
        self.assertIsNotNone(self.db.match_active_release_meta(RELEASE_V3))


class MaintenanceLiveServer(LiveServer):
    """``LiveServer`` variant that injects the maintenance worker."""

    def __init__(self, config: Config, db: Database, maintenance=None):
        self.config = config
        self.db = db
        self.port = _free_port()
        self.app = create_app(config, db, maintenance=maintenance)
        self.server = uvicorn.Server(
            uvicorn.Config(
                self.app,
                host="127.0.0.1",
                port=self.port,
                log_level="warning",
                access_log=False,
            )
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)


class MaintenanceApiTests(unittest.TestCase):
    """手动/自动维护接口与权限（master 触发、Bearer 查询）。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.config = Config("server", self.root / "server_config.json")
        with server_api._guard_lock:
            server_api._rate_guard.clear()
            server_api._login_guard.clear()
        self.db = Database(
            self.root / "license.db", self.config.security["secret_key"]
        )
        # 已知口令的主控账号，避免一次性密码门槛干扰接口测试。
        self.db.ensure_default_admin(password=MASTER_PASSWORD)
        self.db.create_admin("operator", OPERATOR_PASSWORD, role="admin")
        self.worker = server_api.MaintenanceWorker(
            self.db, self.config.security, interval_seconds=86400.0
        )
        self.live = MaintenanceLiveServer(
            self.config, self.db, maintenance=self.worker
        )
        self.live.start()
        self.base = f"http://127.0.0.1:{self.live.port}"
        # 等启动后的第一次自动维护跑完：既验证“服务器启动后自动运行”，
        # 也保证下面的断言不会被在途的维护任务干扰。
        deadline = time.time() + 5
        while time.time() < deadline and self.worker.status()["last_run_at"] is None:
            time.sleep(0.02)
        self.assertIsNotNone(self.worker.status()["last_run_at"])

    def tearDown(self):
        self.live.stop()
        self.db.close()
        self.tmp.cleanup()

    # -- helpers ---------------------------------------------------------
    def api(self, method, path, body=None, token="", expect=200):
        import requests

        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        response = requests.request(
            method, self.base + path, data=data, headers=headers, timeout=10
        )
        self.assertEqual(
            response.status_code,
            expect,
            f"{method} {path} -> {response.status_code}: {response.text[:400]}",
        )
        return response.json() if response.content else {}

    def _token(self, username: str, password: str) -> str:
        return self.api(
            "POST",
            "/api/admin/login",
            {"username": username, "password": password},
        )["token"]

    def _operator_token(self) -> str:
        return self._token("operator", OPERATOR_PASSWORD)

    def _master_token(self) -> str:
        return self._token("admin", MASTER_PASSWORD)

    # -- tests -----------------------------------------------------------
    def test_worker_runs_automatically_and_stops_with_the_server(self):
        self.assertIsNotNone(self.worker.status()["last_run_at"])
        self.assertTrue(self.worker._thread is not None)
        self.live.stop()
        self.assertIsNone(self.worker._thread)

    def test_manual_run_requires_master_and_reports_deletions(self):
        self.db.add_log("旧日志", "system", "", "", "")
        self.db._execute(
            "UPDATE audit_logs SET created_at = ? WHERE action = ?",
            (_ago(days=200), "旧日志"),
        )
        self.api("POST", "/api/maintenance/run", expect=401)
        self.api(
            "POST", "/api/maintenance/run", token=self._operator_token(), expect=403
        )
        result = self.api(
            "POST", "/api/maintenance/run", token=self._master_token()
        )
        self.assertTrue(result["ok"])
        self.assertEqual(sorted(result["deleted"]), sorted(MAINTENANCE_KEYS))
        self.assertGreaterEqual(result["deleted"]["audit_logs"], 1)
        self.assertIsNotNone(result["last_run_at"])
        self.assertEqual(self.db.count_logs(action="旧日志"), 0)
        self.assertIsNotNone(
            self.db._fetchone(
                "SELECT id FROM audit_logs WHERE action = ?", ("手动维护",)
            )
        )

    def test_status_requires_bearer_and_reports_last_run(self):
        self.api("GET", "/api/maintenance/status", expect=401)
        status = self.api(
            "GET", "/api/maintenance/status", token=self._operator_token()
        )
        self.assertIsNotNone(status["last_run_at"])
        self.assertEqual(sorted(status["deleted"]), sorted(MAINTENANCE_KEYS))
        self.assertGreater(status["interval_seconds"], 0)

    def test_release_import_api_retires_old_release(self):
        private_key, public_key = offline.generate_keypair()
        self.config.security["release_public_key"] = public_key
        token = self._master_token()

        def import_manifest(manifest: dict) -> dict:
            raw = _manifest_bytes(manifest)
            return self.api(
                "POST",
                "/api/release/import",
                {
                    "manifest": raw.decode("utf-8"),
                    "signature": offline.sign_message(private_key, raw),
                },
                token=token,
            )

        v1 = _manifest(
            RELEASE_V1, "1.0.0", [("verification", "verification.exe", HASH_A)]
        )
        self.assertTrue(import_manifest(v1)["ok"])
        v2 = _manifest(
            RELEASE_V2, "2.0.0", [("verification", "verification.exe", HASH_B)]
        )
        self.assertTrue(import_manifest(v2)["ok"])
        self.assertIsNone(self.db.match_active_release_meta(RELEASE_V1))
        self.assertIsNotNone(self.db.match_active_release_meta(RELEASE_V2))
        self.assertIsNone(self.db.match_release_hash(HASH_A))

        # 关闭配置后导入新清单保留旧发布（回滚/灰度窗口）。
        self.config.security["release_auto_retire_old"] = False
        v3 = _manifest(
            RELEASE_V3, "3.0.0", [("verification", "verification.exe", HASH_C)]
        )
        self.assertTrue(import_manifest(v3)["ok"])
        self.assertIsNotNone(self.db.match_active_release_meta(RELEASE_V2))
        self.assertIsNotNone(self.db.match_active_release_meta(RELEASE_V3))


class VersionSourceTests(unittest.TestCase):
    """E：对外 VERSION 与 APP_VERSION 必须同源。"""

    def test_api_version_comes_from_core_config(self):
        self.assertEqual(server_api.VERSION, APP_VERSION)
        source = Path(server_api.__file__).read_text(encoding="utf-8")
        self.assertIn("VERSION = APP_VERSION", source)
        self.assertNotIn('VERSION = "1.0.0"', source)


class ServerUiLogCountCacheTests(unittest.TestCase):
    """P2-14 局部：服务器界面刷新使用计数缓存。"""

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        try:
            from PySide6.QtTest import QTest
            from PySide6.QtWidgets import QApplication

            from server import ui as server_ui
        except ImportError as exc:  # pragma: no cover - PySide6 optional
            raise unittest.SkipTest(f"PySide6 unavailable: {exc}") from exc
        cls.QApplication = QApplication
        cls.QTest = QTest
        cls.server_ui = server_ui
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        # ServerWindow 构造后 300ms 会 auto_start；用 no-op 替换并抽干定时器。
        self._start = self.server_ui.ServerController.start
        self.server_ui.ServerController.start = lambda self: None
        self.addCleanup(self._restore_start)

    def _restore_start(self) -> None:
        self.server_ui.ServerController.start = self._start

    def test_refresh_uses_count_logs_cached(self):
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        config = Config("server", root / "server_config.json")
        db = Database(root / "license.db")
        self.addCleanup(db.close)
        db.add_log("界面日志", "tester", "", "", "")
        window = self.server_ui.ServerWindow(config, db)
        self.addCleanup(window.close)
        calls = []
        original = db.count_logs_cached
        db.count_logs_cached = lambda **filters: (
            calls.append(filters),
            original(**filters),
        )[1]
        window.refresh()
        self.assertTrue(calls)
        self.assertIn("共 1 条", window.log_total.text())
        # 让 300ms auto-start 定时器在 patch 生效期间落地。
        self.QTest.qWait(400)


if __name__ == "__main__":
    unittest.main()
