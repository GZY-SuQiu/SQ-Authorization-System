"""A7 Backend：通知渠道 / 渠道投递队列（core.database + server.api）。

覆盖范围：

- DB：渠道 CRUD、``secret`` 脱敏、outbox 入队/去重/原子领取/发送/失败退避/
  dead、统计与投递记录分页；
- API：渠道读（Bearer）与写（master）权限、kind/url/name/secret 校验、
  404、PUT 留空 secret 保留原值、测试发送、投递记录列表；
- 规则渠道校验：``email`` 与 ``channel:<存在的 id>`` 放行，其余 400；
- 接线：``create_app`` 注入的 channel_dispatcher 在启动/关闭时被调用。
"""

import tempfile
import threading
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

import requests
import uvicorn

from core import security
from core.api_client import ApiClient
from core.config import Config
from core.database import Database
from server.api import create_app

from tests.test_api_hardening import LiveServer, _free_port, login_ready

try:  # 主流程模块缺失时（并行批次）相关用例跳过而不是整文件失败。
    from server import channels
except ImportError:  # pragma: no cover - 仅用于并行开发期
    channels = None

OPERATOR_PASSWORD = "Operator#2026"
READY_PASSWORD = "ReadyPass#2026"


class FakeAlertEngine:
    """Records the lifecycle hooks ``create_app`` is required to attach."""

    def __init__(self):
        self.started = 0
        self.stopped = 0

    def start(self) -> None:
        self.started += 1

    def stop(self, timeout: float = 5.0) -> None:
        self.stopped += 1

    def evaluate_once(self) -> list[dict]:
        return []


class FakeMailer:
    def __init__(self):
        self.started = 0
        self.stopped = 0

    def start(self) -> None:
        self.started += 1

    def stop(self, timeout: float = 5.0) -> None:
        self.stopped += 1

    def enqueue(self, *args, **kwargs):
        return None

    def status(self) -> dict:
        return {"enabled": False}


class FakeChannelDispatcher:
    """Carries no transport so the API falls back to the module sender."""

    def __init__(self):
        self.started = 0
        self.stopped = 0
        self.processed = 0

    def start(self) -> None:
        self.started += 1

    def stop(self, timeout: float = 5.0) -> None:
        self.stopped += 1

    def process_due(self, limit: int = 20) -> int:
        self.processed += 1
        return 0


class ChannelLiveServer(LiveServer):
    """``LiveServer`` variant that injects fake mailer/engine/dispatcher."""

    def __init__(
        self,
        config: Config,
        db: Database,
        alert_engine=None,
        mailer=None,
        channel_dispatcher=None,
    ):
        self.config = config
        self.db = db
        self.port = _free_port()
        app = create_app(
            config,
            db,
            mailer=mailer,
            alert_engine=alert_engine,
            channel_dispatcher=channel_dispatcher,
        )
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


class ChannelDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        Config("server", self.root / "server_config.json")
        self.db = Database(self.root / "license.db")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_channel_crud_round_trip_and_secret_masking(self):
        channel_id = self.db.create_notification_channel(
            "webhook", "主控钩子", "https://example.com/hook", "topsecret", True
        )
        self.assertIsInstance(channel_id, int)

        items = self.db.list_notification_channels()
        self.assertEqual(len(items), 1)
        item = items[0]
        self.assertEqual(item["id"], channel_id)
        self.assertEqual(item["kind"], "webhook")
        self.assertEqual(item["name"], "主控钩子")
        self.assertEqual(item["url"], "https://example.com/hook")
        self.assertEqual(int(item["enabled"]), 1)
        self.assertTrue(item["created_at"])
        self.assertTrue(item["updated_at"])
        # list 绝不返回明文 secret，只给 secret_set。
        self.assertNotIn("secret", item)
        self.assertIs(item["secret_set"], True)

        empty_id = self.db.create_notification_channel(
            "dingtalk", "无密钥", "https://oapi.dingtalk.com/robot/send?access_token=x"
        )
        self.assertIs(self.db.list_notification_channels()[0]["secret_set"], False)

        # get 返回明文 secret，供投递器/测试使用。
        self.assertEqual(
            self.db.get_notification_channel(channel_id)["secret"], "topsecret"
        )
        self.assertIsNone(self.db.get_notification_channel(999999))
        self.assertIsNone(self.db.get_notification_channel("bad"))

        # secret 留空/None 表示保留；其他字段正常更新。
        self.assertTrue(
            self.db.update_notification_channel(
                channel_id, name="改名", enabled=False, secret=""
            )
        )
        channel = self.db.get_notification_channel(channel_id)
        self.assertEqual(channel["name"], "改名")
        self.assertEqual(int(channel["enabled"]), 0)
        self.assertEqual(channel["secret"], "topsecret")
        self.assertTrue(
            self.db.update_notification_channel(channel_id, secret=None, url="https://example.com/v2")
        )
        self.assertEqual(
            self.db.get_notification_channel(channel_id)["secret"], "topsecret"
        )
        self.assertTrue(
            self.db.update_notification_channel(channel_id, secret="next-secret")
        )
        self.assertEqual(
            self.db.get_notification_channel(channel_id)["secret"], "next-secret"
        )
        self.assertFalse(self.db.update_notification_channel(999999, name="x"))

        self.assertTrue(self.db.delete_notification_channel(empty_id))
        self.assertFalse(self.db.delete_notification_channel(empty_id))
        self.assertTrue(self.db.delete_notification_channel(channel_id))
        self.assertEqual(self.db.list_notification_channels(), [])

    def test_enqueue_dedupe_claim_and_retry_semantics(self):
        channel_id = self.db.create_notification_channel(
            "webhook", "投递渠道", "https://example.com/hook", "sec", True
        )

        first = self.db.enqueue_channel_message(
            channel_id, "主题", "正文", payload={"event_id": 7}, dedupe_key="alert:1"
        )
        duplicate = self.db.enqueue_channel_message(
            channel_id, "主题", "正文", payload={"event_id": 7}, dedupe_key="alert:1"
        )
        self.assertIsInstance(first, int)
        self.assertIsNone(duplicate)
        second = self.db.enqueue_channel_message(channel_id, "第二条", "正文")
        self.assertIsInstance(second, int)

        with self.assertRaises(ValueError):
            self.db.enqueue_channel_message(999999, "s", "b")

        # 原子领取：join 渠道信息，并把状态推进到 sending。
        claimed = self.db.claim_due_channel_messages()
        self.assertEqual([m["id"] for m in claimed], [first, second])
        message = claimed[0]
        self.assertEqual(message["kind"], "webhook")
        self.assertEqual(message["url"], "https://example.com/hook")
        self.assertEqual(message["secret"], "sec")
        self.assertEqual(int(message["enabled"]), 1)
        self.assertEqual(message["channel_id"], channel_id)
        self.assertEqual(message["payload"], {"event_id": 7})
        self.assertEqual(message["status"], "sending")
        self.assertEqual(self.db.claim_due_channel_messages(), [])

        self.db.mark_channel_message_sent(first)
        sent = self.db.list_channel_deliveries(status="sent")[0][0]
        self.assertEqual(sent["status"], "sent")
        self.assertTrue(sent["sent_at"])
        self.assertIsNone(sent["last_error"])

        # 失败：attempts+1、写入 last_error、next_retry_at 未到则不领取。
        future = (datetime.now() + timedelta(seconds=300)).strftime(security.TIME_FORMAT)
        self.db.mark_channel_message_failed(second, "boom", future)
        pending_future = self.db.claim_due_channel_messages()
        self.assertEqual(pending_future, [])
        row = self.db.list_channel_deliveries(status="failed")[0][0]
        self.assertEqual(int(row["attempts"]), 1)
        self.assertEqual(row["last_error"], "boom")
        self.assertEqual(row["next_retry_at"], future)

        # 退避到期后可再次领取；达到 max_attempts 自动进 dead。
        past = (datetime.now() - timedelta(seconds=1)).strftime(security.TIME_FORMAT)
        self.db.mark_channel_message_failed(second, "boom", past)
        redo = self.db.claim_due_channel_messages()
        self.assertEqual([m["id"] for m in redo], [second])
        # 继续失败直到 max_attempts：每次先记录失败（due 已过）再领取。
        while True:
            self.db.mark_channel_message_failed(second, "boom", past)
            # list 按 id DESC，second 的 id 最大，永远排在第一条。
            row = self.db.list_channel_deliveries()[0][0]
            if row["status"] == "dead":
                break
            self.assertTrue(self.db.claim_due_channel_messages())
        dead = self.db.list_channel_deliveries(status="dead")[0][0]
        self.assertEqual(int(dead["attempts"]), int(dead["max_attempts"]))
        self.assertIsNone(dead["next_retry_at"])
        self.assertEqual(self.db.claim_due_channel_messages(), [])

        stats = self.db.channel_outbox_stats()
        self.assertEqual(stats["sent"], 1)
        self.assertEqual(stats["dead"], 1)
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["last_error"], "boom")

    def test_claim_skips_messages_of_deleted_channels(self):
        channel_id = self.db.create_notification_channel(
            "webhook", "临时渠道", "https://example.com/hook"
        )
        self.db.enqueue_channel_message(channel_id, "s", "b")
        self.assertTrue(self.db.delete_notification_channel(channel_id))
        # 渠道已删除：消息保持 pending，不会被领走也不会卡在 sending。
        self.assertEqual(self.db.claim_due_channel_messages(), [])
        self.assertEqual(self.db.channel_outbox_stats()["pending"], 1)

    def test_delivery_listing_pagination(self):
        channel_id = self.db.create_notification_channel(
            "wecom", "投递记录", "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=x"
        )
        ids = [
            self.db.enqueue_channel_message(channel_id, f"主题{i}", "正文")
            for i in range(3)
        ]
        claimed = self.db.claim_due_channel_messages()
        self.assertEqual(len(claimed), 3)
        self.db.mark_channel_message_sent(ids[0])
        self.db.mark_channel_message_failed(ids[1], "err", None, dead=True)

        items, total = self.db.list_channel_deliveries()
        self.assertEqual(total, 3)
        self.assertEqual([row["id"] for row in items], list(reversed(ids)))
        self.assertEqual(items[0]["channel_name"], "投递记录")
        self.assertEqual(items[0]["channel_kind"], "wecom")
        self.assertNotIn("secret", items[0])

        self.assertEqual(self.db.list_channel_deliveries(status="sent")[1], 1)
        page, total = self.db.list_channel_deliveries(limit=1, offset=1)
        self.assertEqual(total, 3)
        self.assertEqual(len(page), 1)
        self.assertEqual(page[0]["id"], ids[1])
        # limit/offset 越界会被收敛而不是报错。
        self.assertEqual(self.db.list_channel_deliveries(limit=0, offset=-5)[1], 3)

    @unittest.skipIf(channels is None, "server.channels 尚未就绪")
    def test_dispatcher_transport_receives_joined_channel(self):
        """注入 transport 后直接调 dispatcher.process_due，验证投递接线。"""
        channel_id = self.db.create_notification_channel(
            "webhook", "投递器", "https://example.com/hook", "sign-me", True
        )
        message_id = self.db.enqueue_channel_message(
            channel_id, "告警标题", "告警正文", payload={"event_id": 3}
        )
        transport = mock.Mock(return_value={})
        dispatcher = channels.ChannelDispatcher(self.db, transport=transport, interval=999)
        self.assertEqual(dispatcher.process_due(), 1)
        self.assertEqual(transport.call_count, 1)
        args, kwargs = transport.call_args
        self.assertEqual(args[0], "webhook")
        self.assertEqual(args[1], "https://example.com/hook")
        self.assertEqual(kwargs["secret"], "sign-me")
        self.assertEqual(kwargs["subject"], "告警标题")
        self.assertEqual(kwargs["body"], "告警正文")
        self.assertEqual(kwargs["payload"], {"event_id": 3})
        row = self.db.list_channel_deliveries()[0][0]
        self.assertEqual(row["id"], message_id)
        self.assertEqual(row["status"], "sent")


class ChannelApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.config = Config("server", self.root / "server_config.json")
        self.db = Database(self.root / "license.db")
        _, self.bootstrap = self.db.ensure_default_admin()
        self.db.create_admin("operator", OPERATOR_PASSWORD, role="admin")
        self.engine = FakeAlertEngine()
        self.mailer = FakeMailer()
        self.dispatcher = FakeChannelDispatcher()
        self.live = ChannelLiveServer(
            self.config,
            self.db,
            alert_engine=self.engine,
            mailer=self.mailer,
            channel_dispatcher=self.dispatcher,
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

    def _call(self, method, path, token=None, **kwargs):
        headers = dict(kwargs.pop("headers", {}))
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return requests.request(
            method,
            f"http://127.0.0.1:{self.live.port}{path}",
            headers=headers,
            timeout=5,
            **kwargs,
        )

    def _create_channel(self, token, **overrides):
        payload = {
            "kind": "webhook",
            "name": "主控钩子",
            "url": "https://example.com/hook",
            "secret": "topsecret",
            "enabled": True,
        }
        payload.update(overrides)
        return self._call("POST", "/api/channels", token, json=payload)

    def test_injected_dispatcher_is_started_and_stopped(self):
        self.assertGreaterEqual(self.dispatcher.started, 1)
        self.assertGreaterEqual(self.engine.started, 1)
        self.live.stop()
        self.assertGreaterEqual(self.dispatcher.stopped, 1)
        self.assertGreaterEqual(self.engine.stopped, 1)

    def test_channel_crud_permissions_and_secret_masking(self):
        created = self._create_channel(self.client.token)
        self.assertEqual(created.status_code, 200)
        channel_id = created.json()["id"]
        self.assertTrue(created.json()["ok"])

        # admin 可读、只拿到 secret_set。
        operator = self._operator_client()
        listing = self._call("GET", "/api/channels", operator.token)
        self.assertEqual(listing.status_code, 200)
        items = listing.json()["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["id"], channel_id)
        self.assertNotIn("secret", items[0])
        self.assertIs(items[0]["secret_set"], True)

        # 写操作仅 master。
        denied = self._create_channel(operator.token, name="越权")
        self.assertEqual(denied.status_code, 403)
        denied_update = self._call(
            "PUT", f"/api/channels/{channel_id}", operator.token, json={"name": "x"}
        )
        self.assertEqual(denied_update.status_code, 403)
        denied_delete = self._call(
            "DELETE", f"/api/channels/{channel_id}", operator.token
        )
        self.assertEqual(denied_delete.status_code, 403)
        denied_test = self._call(
            "POST", f"/api/channels/{channel_id}/test", operator.token
        )
        self.assertEqual(denied_test.status_code, 403)

        # PUT 留空 secret 保留原值；显式给值才覆盖。
        updated = self._call(
            "PUT",
            f"/api/channels/{channel_id}",
            self.client.token,
            json={"name": "改名", "enabled": False, "secret": ""},
        )
        self.assertEqual(updated.status_code, 200)
        self.assertTrue(updated.json()["ok"])
        channel = self.db.get_notification_channel(channel_id)
        self.assertEqual(channel["name"], "改名")
        self.assertEqual(int(channel["enabled"]), 0)
        self.assertEqual(channel["secret"], "topsecret")
        changed = self._call(
            "PUT",
            f"/api/channels/{channel_id}",
            self.client.token,
            json={"secret": "new-secret", "enabled": True},
        )
        self.assertEqual(changed.status_code, 200)
        self.assertEqual(
            self.db.get_notification_channel(channel_id)["secret"], "new-secret"
        )

        # 重名 400；不存在的 id 一律 404。
        self.assertEqual(
            self._create_channel(self.client.token, name="改名").status_code, 400
        )
        self.assertEqual(
            self._call(
                "PUT", "/api/channels/999999", self.client.token, json={"name": "x"}
            ).status_code,
            404,
        )
        self.assertEqual(
            self._call("DELETE", "/api/channels/999999", self.client.token).status_code,
            404,
        )
        self.assertEqual(
            self._call(
                "POST", "/api/channels/999999/test", self.client.token
            ).status_code,
            404,
        )

        self.assertEqual(
            self._call(
                "DELETE", f"/api/channels/{channel_id}", self.client.token
            ).status_code,
            200,
        )
        self.assertEqual(
            self._call("GET", "/api/channels", self.client.token).json()["items"], []
        )

    def test_invalid_channel_payloads_are_rejected_with_400(self):
        cases = [
            {"kind": "slack"},
            {"url": "ftp://example.com/hook"},
            {"url": "https://example.com/" + "a" * 520},
            {"name": ""},
            {"name": "x" * 65},
            {"secret": "s" * 257},
        ]
        for patch in cases:
            with self.subTest(patch=patch):
                response = self._create_channel(self.client.token, **patch)
                self.assertEqual(response.status_code, 400, response.text)
        # 非法更新同样 400。
        created = self._create_channel(self.client.token)
        channel_id = created.json()["id"]
        bad = self._call(
            "PUT", f"/api/channels/{channel_id}", self.client.token, json={"kind": "sms"}
        )
        self.assertEqual(bad.status_code, 400)
        bad_url = self._call(
            "PUT",
            f"/api/channels/{channel_id}",
            self.client.token,
            json={"url": "https://example.com/" + "a" * 600},
        )
        self.assertEqual(bad_url.status_code, 400)
        self.assertEqual(
            self._call("GET", "/api/channels", self.client.token).json()["items"][0][
                "kind"
            ],
            "webhook",
        )

    def test_test_endpoint_uses_dispatcher_transport(self):
        channel_id = self._create_channel(self.client.token).json()["id"]
        transport = mock.Mock(return_value={})
        self.dispatcher.transport = transport

        response = self._call(
            "POST", f"/api/channels/{channel_id}/test", self.client.token
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ok"])
        self.assertEqual(transport.call_count, 1)
        args, kwargs = transport.call_args
        self.assertEqual(args[0], "webhook")
        self.assertEqual(args[1], "https://example.com/hook")
        self.assertEqual(kwargs["secret"], "topsecret")

        transport.side_effect = RuntimeError("hook down")
        failed = self._call(
            "POST", f"/api/channels/{channel_id}/test", self.client.token
        )
        self.assertEqual(failed.status_code, 400)
        self.assertIn("hook down", failed.json()["detail"])

    @unittest.skipIf(channels is None, "server.channels 尚未就绪")
    def test_test_endpoint_falls_back_to_module_sender(self):
        channel_id = self._create_channel(self.client.token).json()["id"]
        sender = mock.Mock(return_value={"ok": True})
        with mock.patch("server.channels.send_channel_message", sender):
            response = self._call(
                "POST", f"/api/channels/{channel_id}/test", self.client.token
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(sender.call_count, 1)
        args, kwargs = sender.call_args
        self.assertEqual((args[0], args[1]), ("webhook", "https://example.com/hook"))
        self.assertEqual(kwargs["secret"], "topsecret")

        with mock.patch(
            "server.channels.send_channel_message",
            side_effect=channels.ChannelError("拒绝投递"),
        ):
            failed = self._call(
                "POST", f"/api/channels/{channel_id}/test", self.client.token
            )
        self.assertEqual(failed.status_code, 400)
        self.assertIn("拒绝投递", failed.json()["detail"])

    def test_rule_channels_validation(self):
        missing = self._call(
            "POST",
            "/api/alerts/rules",
            self.client.token,
            json={
                "name": "坏渠道",
                "metric": "risk_events",
                "operator": "gte",
                "threshold": 1,
                "channels": ["channel:999999"],
            },
        )
        self.assertEqual(missing.status_code, 400)
        self.assertIn("不存在", missing.json()["detail"])

        channel_id = self._create_channel(self.client.token).json()["id"]
        created = self._call(
            "POST",
            "/api/alerts/rules",
            self.client.token,
            json={
                "name": "多渠道规则",
                "metric": "risk_events",
                "operator": "gte",
                "threshold": 1,
                "channels": ["email", f"channel:{channel_id}"],
            },
        )
        self.assertEqual(created.status_code, 200)
        rule_id = created.json()["id"]
        rule = self.db.get_alert_rule(rule_id)
        self.assertEqual(rule["channels"], ["email", f"channel:{channel_id}"])

        bad_update = self._call(
            "PUT",
            f"/api/alerts/rules/{rule_id}",
            self.client.token,
            json={"channels": ["channel:999999"]},
        )
        self.assertEqual(bad_update.status_code, 400)
        ok_update = self._call(
            "PUT",
            f"/api/alerts/rules/{rule_id}",
            self.client.token,
            json={"channels": [f"channel:{channel_id}"]},
        )
        self.assertEqual(ok_update.status_code, 200)
        self.assertEqual(
            self.db.get_alert_rule(rule_id)["channels"], [f"channel:{channel_id}"]
        )
        # 既有 A5 行为不变：非 email/channel 值仍 400。
        self.assertEqual(
            self._call(
                "PUT",
                f"/api/alerts/rules/{rule_id}",
                self.client.token,
                json={"channels": ["sms"]},
            ).status_code,
            400,
        )

    def test_channel_deliveries_endpoint(self):
        channel_id = self._create_channel(self.client.token).json()["id"]
        first = self.db.enqueue_channel_message(channel_id, "第一条", "正文")
        second = self.db.enqueue_channel_message(channel_id, "第二条", "正文")
        claimed = self.db.claim_due_channel_messages()
        self.assertEqual(len(claimed), 2)
        self.db.mark_channel_message_sent(first)
        self.db.mark_channel_message_failed(second, "boom", None, dead=True)

        operator = self._operator_client()
        listing = self._call(
            "GET", "/api/channels/deliveries?status=&limit=50&offset=0", operator.token
        )
        self.assertEqual(listing.status_code, 200)
        body = listing.json()
        self.assertEqual(body["total"], 2)
        self.assertEqual([row["id"] for row in body["items"]], [second, first])
        self.assertEqual(body["items"][0]["channel_name"], "主控钩子")
        self.assertEqual(body["items"][0]["subject"], "第二条")
        self.assertNotIn("secret", body["items"][0])

        sent_only = self._call(
            "GET", "/api/channels/deliveries?status=sent", self.client.token
        ).json()
        self.assertEqual(sent_only["total"], 1)
        self.assertEqual(sent_only["items"][0]["status"], "sent")


if __name__ == "__main__":
    unittest.main()
