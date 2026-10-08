"""A7 通知渠道适配器、投递器与引擎派发测试。"""

import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from core.config import Config
from core.database import Database
from server import channels
from server.alert_engine import AlertEngine


class FakeResponse:
    def __init__(self, data=None, status_code=200, text="ok"):
        self._data = data if isinstance(data, dict) else {}
        self.status_code = status_code
        self.text = text

    def json(self):
        return self._data


class AdapterTests(unittest.TestCase):
    def test_webhook_payload_and_signature(self):
        with mock.patch("server.channels.requests.post") as post:
            post.return_value = FakeResponse({"ok": True})
            channels.send_channel_message(
                "webhook",
                "https://example.com/hook",
                secret="s3cret",
                subject="主题",
                body="正文",
                payload={"a": 1},
            )
            args, kwargs = post.call_args
            self.assertEqual(args[0], "https://example.com/hook")
            data = json.loads(kwargs["data"].decode("utf-8"))
            self.assertEqual(data["event"], "主题")
            self.assertEqual(data["payload"], {"a": 1})
            self.assertTrue(kwargs["headers"]["X-SQ-Signature"].startswith("sha256="))

    def test_dingtalk_payload_and_signed_query(self):
        with mock.patch("server.channels.requests.post") as post:
            post.return_value = FakeResponse({"errcode": 0})
            channels.send_channel_message(
                "dingtalk",
                "https://oapi.dingtalk.com/robot/send?access_token=x",
                secret="sec",
                subject="标题",
                body="内容",
            )
            kwargs = post.call_args.kwargs
            self.assertEqual(kwargs["json"]["msgtype"], "markdown")
            self.assertEqual(kwargs["json"]["markdown"]["title"], "标题")
            self.assertIn("timestamp", kwargs["params"])
            self.assertIn("sign", kwargs["params"])

    def test_wecom_error_raises(self):
        with mock.patch("server.channels.requests.post") as post:
            post.return_value = FakeResponse({"errcode": 40013, "errmsg": "invalid corpid"})
            with self.assertRaises(channels.ChannelError):
                channels.send_channel_message(
                    "wecom", "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=x",
                    subject="t", body="b",
                )

    def test_feishu_payload_and_signature(self):
        with mock.patch("server.channels.requests.post") as post:
            post.return_value = FakeResponse({"code": 0})
            channels.send_channel_message(
                "feishu",
                "https://open.feishu.cn/open-apis/bot/v2/hook/x",
                secret="sec",
                subject="标题",
                body="内容",
            )
            kwargs = post.call_args.kwargs
            self.assertEqual(kwargs["json"]["msg_type"], "text")
            self.assertIn("标题", kwargs["json"]["content"]["text"])
            self.assertIn("timestamp", kwargs["json"])
            self.assertIn("sign", kwargs["json"])

    def test_invalid_kind_and_url(self):
        with self.assertRaises(channels.ChannelError):
            channels.send_channel_message("nope", "https://example.com", subject="t", body="b")
        with self.assertRaises(channels.ChannelError):
            channels.send_channel_message("webhook", "ftp://example.com", subject="t", body="b")


class _FakeChannelDB:
    def __init__(self, messages):
        self.messages = messages
        self.sent = []
        self.failed = []

    def claim_due_channel_messages(self, limit=20):
        return list(self.messages)

    def mark_channel_message_sent(self, message_id):
        self.sent.append(int(message_id))

    def mark_channel_message_failed(self, message_id, error, next_retry_at, dead=False):
        self.failed.append((int(message_id), error, next_retry_at, bool(dead)))


class DispatcherTests(unittest.TestCase):
    def test_success_marks_sent_and_parses_payload(self):
        db = _FakeChannelDB(
            [
                {
                    "id": 1,
                    "kind": "webhook",
                    "url": "https://example.com/hook",
                    "secret": "",
                    "subject": "s",
                    "body": "b",
                    "payload": '{"event_id": 7}',
                    "attempts": 0,
                    "max_attempts": 5,
                }
            ]
        )
        transport = mock.Mock()
        dispatcher = channels.ChannelDispatcher(db, transport=transport, interval=999)
        self.assertEqual(dispatcher.process_due(), 1)
        self.assertEqual(db.sent, [1])
        self.assertEqual(transport.call_args.kwargs["payload"], {"event_id": 7})

    def test_failure_backoff_and_dead(self):
        db = _FakeChannelDB(
            [
                {
                    "id": 2,
                    "kind": "webhook",
                    "url": "https://example.com/hook",
                    "secret": "",
                    "subject": "s",
                    "body": "b",
                    "payload": {},
                    "attempts": 4,
                    "max_attempts": 5,
                }
            ]
        )
        transport = mock.Mock(side_effect=channels.ChannelError("boom"))
        dispatcher = channels.ChannelDispatcher(db, transport=transport, interval=999)
        self.assertEqual(dispatcher.process_due(), 0)
        self.assertEqual(len(db.failed), 1)
        message_id, error, retry_at, dead = db.failed[0]
        self.assertEqual(message_id, 2)
        self.assertIn("boom", error)
        self.assertTrue(retry_at)
        self.assertTrue(dead)

    def test_backoff_sequence(self):
        self.assertEqual(channels.backoff_seconds(1), 60)
        self.assertEqual(channels.backoff_seconds(5), 960)
        self.assertEqual(channels.backoff_seconds(99), 3600)


class DispatcherLifecycleTests(unittest.TestCase):
    def test_stop_timeout_then_start_does_not_duplicate_worker(self):
        started = threading.Event()
        release = threading.Event()

        def blocking_transport(*args, **kwargs):
            started.set()
            release.wait(timeout=5)

        db = _FakeChannelDB(
            [
                {
                    "id": 9,
                    "kind": "webhook",
                    "url": "https://example.com/hook",
                    "secret": "",
                    "subject": "s",
                    "body": "b",
                    "payload": {},
                    "attempts": 0,
                    "max_attempts": 5,
                }
            ]
        )
        dispatcher = channels.ChannelDispatcher(db, transport=blocking_transport, interval=0.05)
        dispatcher.start()
        self.assertTrue(started.wait(2), "worker 没有开始投递")
        dispatcher.stop(timeout=0.05)
        self.assertIsNotNone(dispatcher._thread)
        self.assertTrue(dispatcher._thread.is_alive())
        dispatcher.start()  # stop 超时后再次 start 必须复用旧线程
        alive = [t for t in threading.enumerate() if t.name == "sq-channel-dispatcher"]
        self.assertEqual(len(alive), 1, alive)
        release.set()
        dispatcher.stop(timeout=2)
        self.assertFalse(
            dispatcher._thread is not None and dispatcher._thread.is_alive()
        )


class EngineChannelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.tmp.name)
        self.config = Config("server", root / "server_config.json")
        self.db = Database(root / "license.db", self.config.security["secret_key"])

        class _Mailer:
            def enqueue(self, *args, **kwargs):
                return None

            def start(self):
                return None

            def stop(self, timeout=5):
                return None

            def status(self):
                return {"enabled": False}

        self.engine = AlertEngine(self.db, _Mailer(), self.config, interval=999)

    def tearDown(self):
        self.engine.stop(timeout=1)
        self.db.close()
        self.tmp.cleanup()

    def test_rule_dispatches_to_channel_outbox(self):
        channel_id = self.db.create_notification_channel(
            "webhook", "测试渠道", "https://example.com/hook"
        )
        self.db.create_alert_rule(
            name="激活失败告警",
            metric="failed_activations",
            operator="gte",
            threshold=1,
            window_seconds=600,
            severity="warning",
            cooldown_seconds=60,
            channels=[f"channel:{channel_id}"],
            enabled=True,
        )
        self.db.add_log("激活失败", "client", "GSQ-TEST", "测试", "127.0.0.1")
        fired = self.engine.evaluate_once()
        self.assertEqual(len(fired), 1, fired)
        items, total = self.db.list_channel_deliveries()
        self.assertGreaterEqual(total, 1)
        self.assertEqual(items[0]["channel_id"], channel_id)
        self.assertIn("激活失败告警", items[0]["subject"])
        events, _ = self.db.list_alert_events()
        self.assertEqual(int(events[0]["notified"]), 1)


if __name__ == "__main__":
    unittest.main()
