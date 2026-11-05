"""A7 通知渠道端到端验收：告警规则 -> channel_outbox -> 真实 HTTP 投递。

运行：

    python tools/verify_channels_e2e.py

本地起一个 HTTP 接收端，创建 Webhook 渠道与告警规则，触发规则后由
ChannelDispatcher 用真实 requests 投递，校验载荷与 HMAC 签名头。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import socket
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.config import Config  # noqa: E402
from core.database import Database  # noqa: E402
from server.alert_engine import AlertEngine  # noqa: E402
from server.channels import ChannelDispatcher  # noqa: E402

SECRET = "e2e-webhook-secret"


class _Receiver(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 - http.server API
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        with self.server.lock:  # type: ignore[attr-defined]
            self.server.messages.append(  # type: ignore[attr-defined]
                {"path": self.path, "headers": dict(self.headers), "body": body}
            )
        payload = json.dumps({"ok": True}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        return


class _CaptureServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
        super().__init__(("127.0.0.1", port), _Receiver)
        self.messages: list[dict] = []
        self.lock = threading.Lock()
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def start(self):
        self._thread.start()

    def stop(self):
        self.shutdown()
        self.server_close()


class _NoMailer:
    def enqueue(self, *args, **kwargs):
        raise AssertionError("本用例不应走邮件渠道")

    def start(self):
        return None

    def stop(self, timeout=5):
        return None

    def status(self):
        return {"enabled": False}


def _fail(message: str):
    print(f"[FAIL] {message}")
    raise SystemExit(1)


def main() -> int:
    receiver = _CaptureServer()
    receiver.start()
    tmp = tempfile.TemporaryDirectory(prefix="sq_channel_e2e_", ignore_cleanup_errors=True)
    try:
        root = Path(tmp.name)
        config = Config("server", root / "server_config.json")
        config.data["security"]["channel_allow_private_hosts"] = True
        db = Database(root / "license.db", config.security["secret_key"])
        engine = AlertEngine(db, _NoMailer(), config, interval=999)

        channel_id = db.create_notification_channel(
            "webhook",
            "E2E Webhook",
            f"http://127.0.0.1:{receiver.port}/hook",
            secret=SECRET,
        )
        db.create_alert_rule(
            name="激活失败 E2E",
            metric="failed_activations",
            operator="gte",
            threshold=1,
            window_seconds=600,
            severity="warning",
            cooldown_seconds=60,
            channels=[f"channel:{channel_id}"],
            enabled=True,
        )
        db.add_log("激活失败", "client", "GSQ-E2E", "渠道验收", "127.0.0.1")

        fired = engine.evaluate_once()
        if not fired:
            _fail("告警规则没有触发")
        items, total = db.list_channel_deliveries()
        if total < 1 or items[0]["status"] != "pending":
            _fail(f"渠道消息没有进入待投递队列：{items[:1]}")
        print("[ OK ] 规则触发并写入 channel_outbox")

        dispatcher = ChannelDispatcher(db, interval=999)
        sent = dispatcher.process_due()
        if sent != 1:
            _fail(f"投递失败，sent={sent}")
        deadline = time.time() + 10
        while time.time() < deadline and not receiver.messages:
            time.sleep(0.05)
        if not receiver.messages:
            _fail("本地接收端没有收到请求")
        message = receiver.messages[0]
        body_text = message["body"]
        data = json.loads(body_text)
        if data.get("event") != "【密钥授权系统】告警规则触发：激活失败 E2E":
            _fail(f"事件标题不正确：{data.get('event')!r}")
        signature = message["headers"].get("X-SQ-Signature", "")
        expected = "sha256=" + hmac.new(
            SECRET.encode("utf-8"), body_text.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if signature != expected:
            _fail(f"HMAC 签名不匹配：{signature!r} != {expected!r}")
        print("[ OK ] 真实 HTTP 投递成功且 HMAC 签名校验一致")

        sent_items, sent_total = db.list_channel_deliveries(status="sent")
        if sent_total < 1:
            _fail("投递状态没有更新为 sent")
        events, _ = db.list_alert_events()
        if int(events[0]["notified"]) != 1:
            _fail("告警事件 notified 标记未写入")
        print("[ OK ] 投递状态与事件通知标记正确")

        print("== A7 通知渠道端到端验收通过 ==")
        return 0
    finally:
        receiver.stop()
        try:
            db.close()
        except Exception:
            pass
        tmp.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
