"""P1-7: AI task cancellation and bounded shutdown on both ends.

Client: ``ApiClient.ai_chat`` accepts an optional cancel event and the AI page
cancels its in-flight turn when the window closes. Server: ``AiGateway.close``
sets ``_closing``, cancels queued jobs and abandons a running one without
blocking process exit.
"""

import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.api_client import ApiClient, ApiError  # noqa: E402
from core.config import Config  # noqa: E402
from core.database import Database  # noqa: E402
from server.ai_gateway import AiGateway, AiGatewayError  # noqa: E402
from tests.test_ai_gateway import (  # noqa: E402
    FakePoster,
    call_response,
    chat_text_response,
    text_response,
)

try:  # The desktop pieces need Qt; the server tests must still run without it.
    from PySide6.QtWidgets import QApplication, QMainWindow

    from core.ai_page import AIAssistantPage

    QT_AVAILABLE = True
except Exception:  # pragma: no cover - headless CI without PySide6
    QT_AVAILABLE = False


AI_CONFIG = {
    "enabled": True,
    "api_key": "sk-test",
    "api_mode": "chat_completions",
    "vendor_name": "Agnes",
    "base_url": "https://api.agnes-ai.cn/v1",
    "model": "agnes-3.0-flash",
    "monitor_interval": 8,
}


class AiPollingCancelTests(unittest.TestCase):
    """Client side: the polling loop must leave within a second of cancel."""

    @staticmethod
    def _client() -> ApiClient:
        return ApiClient("http://127.0.0.1:9", timeout=1)

    @staticmethod
    def _stub_request(client, *, interval: float = 5.0, calls: list | None = None):
        """Replace the transport with a job that never finishes."""
        calls = calls if calls is not None else []

        def request(method, path, **kwargs):
            calls.append((method, path))
            if method == "POST":
                return {
                    "job_id": "job-cancel-1",
                    "status": "pending",
                    "poll_interval": interval,
                }
            return {"status": "running", "events": [], "event_cursor": 0}

        client._request = request
        return calls

    def test_cancel_event_stops_a_long_polling_loop_within_one_second(self):
        client = self._client()
        self._stub_request(client, interval=5.0)
        cancel = threading.Event()
        errors: list[BaseException] = []

        def run() -> None:
            try:
                client.ai_chat(
                    [{"role": "user", "content": "你好"}], cancel_event=cancel
                )
            except BaseException as exc:  # noqa: BLE001 - asserted below
                errors.append(exc)

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        time.sleep(0.3)
        started = time.monotonic()
        cancel.set()
        worker.join(1.0)
        elapsed = time.monotonic() - started

        self.assertFalse(worker.is_alive(), "取消后轮询没有在 1 秒内退出")
        self.assertLess(elapsed, 1.0)
        self.assertTrue(errors)
        self.assertIsInstance(errors[0], ApiError)
        self.assertIn("取消", str(errors[0]))

    def test_cancel_event_set_before_the_call_skips_the_network(self):
        client = self._client()
        calls = self._stub_request(client)
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(ApiError):
            client.ai_chat([{"role": "user", "content": "你好"}], cancel_event=cancel)
        self.assertEqual(calls, [])

    def test_cancel_event_is_optional_and_the_old_signature_still_works(self):
        client = self._client()
        state = {"polls": 0}

        def request(method, path, **kwargs):
            if method == "POST":
                return {"job_id": "job-ok", "status": "pending", "poll_interval": 0.01}
            state["polls"] += 1
            if state["polls"] >= 2:
                return {
                    "status": "done",
                    "result": {"reply": "完成"},
                    "events": [],
                    "event_cursor": 0,
                }
            return {"status": "running", "events": [], "event_cursor": 0}

        client._request = request
        result = client.ai_chat([{"role": "user", "content": "你好"}])
        self.assertEqual(result["reply"], "完成")

    def test_wait_helper_does_not_sleep_the_whole_interval(self):
        cancel = threading.Event()
        timer = threading.Timer(0.1, cancel.set)
        timer.start()
        started = time.monotonic()
        cancelled = ApiClient._wait_cancellable(5.0, cancel)
        elapsed = time.monotonic() - started
        timer.join(1.0)
        self.assertTrue(cancelled)
        self.assertLess(elapsed, 1.0)


class GatewayCloseTests(unittest.TestCase):
    """Server side: close() is bounded and the tool loop notices it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.config = Config("server", self.root / "server_config.json")
        self.db = Database(self.root / "license.db")
        _, self.bootstrap = self.db.ensure_default_admin()
        self.master = self.db.get_admin("admin")
        self.operator = {
            "id": self.master["id"],
            "username": "admin",
            "role": "master",
        }

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def _gateway(self, poster):
        gateway = AiGateway(
            self.db,
            AI_CONFIG,
            security_config=self.config.security,
            poster=poster,
            max_retries=0,
        )
        self.addCleanup(gateway.close)
        return gateway

    def test_close_sets_closing_and_rejects_new_work(self):
        gateway = self._gateway(FakePoster([text_response("你好")]))
        gateway.close()
        gateway.close()  # idempotent
        self.assertTrue(gateway._closing)
        with self.assertRaises(AiGatewayError):
            gateway.submit_chat(self.operator, [{"role": "user", "content": "hi"}])
        with self.assertRaises(AiGatewayError):
            gateway.chat(self.operator, [{"role": "user", "content": "hi"}])
        self.assertEqual(gateway._poster().calls, [])

    def test_close_between_rounds_abandons_the_tool_loop_quickly(self):
        calls: list[dict] = []
        box: dict = {}

        def poster(url, headers=None, json=None, timeout=None):  # noqa: A002
            calls.append(json)
            box["gateway"]._closing = True
            return call_response("get_stats", {})

        gateway = self._gateway(poster)
        box["gateway"] = gateway
        started = time.monotonic()
        with self.assertRaises(AiGatewayError):
            gateway.chat(self.operator, [{"role": "user", "content": "统计一下"}])
        self.assertLess(time.monotonic() - started, 1.0)
        # The provider was asked once; the loop stopped instead of running the
        # staged tool call or asking the model again.
        self.assertEqual(len(calls), 1)

    def test_close_abandons_a_running_job_without_blocking_exit(self):
        started = threading.Event()
        release = threading.Event()

        def poster(url, headers=None, json=None, timeout=None):  # noqa: A002
            started.set()
            release.wait(5)
            return chat_text_response("迟到的回复")

        gateway = self._gateway(poster)
        finished = threading.Event()
        original_finish = gateway._finish_job

        def finish(job_id, *, result=None, error=""):
            original_finish(job_id, result=result, error=error)
            finished.set()

        gateway._finish_job = finish
        job = gateway.submit_chat(
            self.operator, [{"role": "user", "content": "你好"}]
        )
        self.assertTrue(started.wait(3), "假 provider 没有被调用")

        begin = time.monotonic()
        gateway.close()
        close_elapsed = time.monotonic() - begin
        self.assertLess(close_elapsed, 1.0, "close() 阻塞了进程退出")
        self.assertTrue(gateway._closing)

        snapshot = gateway.chat_job(self.operator, job["job_id"])
        self.assertEqual(snapshot["status"], "failed")
        self.assertIn("关闭", snapshot["error"])

        # Let the (fake) provider return: the loop must then unwind fast.
        release.set()
        self.assertTrue(finished.wait(1.0), "关闭后 run 循环没有尽快返回")
        final = gateway.chat_job(self.operator, job["job_id"])
        self.assertEqual(final["status"], "failed")
        self.assertIn("关闭", final["error"])


@unittest.skipUnless(QT_AVAILABLE, "PySide6 不可用")
class AiPageShutdownTests(unittest.TestCase):
    """The AI page cancels its worker and stops refreshing after shutdown."""

    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def test_shutdown_is_idempotent_and_sets_the_cancel_event(self):
        class QuietClient:
            base_url = "http://127.0.0.1:8765"

            def ai_status(self):
                return {"ai_enabled": True, "ai_configured": True, "ai_model": "m"}

        page = AIAssistantPage(QuietClient(), lambda *_a, **_k: None)
        page.shutdown()
        page.shutdown()
        self.assertTrue(page._shutting_down)
        self.assertTrue(page._cancel_event.is_set())
        self.assertFalse(page.monitor_timer.isActive())

    def test_shutdown_stops_a_running_turn_and_blocks_refreshes(self):
        started = threading.Event()
        observed: dict = {}
        status_calls: list[int] = []

        class CancellableClient:
            base_url = "http://127.0.0.1:8765"

            def ai_status(self):
                status_calls.append(1)
                return {
                    "ai_enabled": True,
                    "ai_configured": True,
                    "ai_model": "gpt-5.1",
                }

            def ai_chat(self, messages, on_event=None, cancel_event=None):
                started.set()
                seen = bool(cancel_event and cancel_event.wait(5))
                observed["cancelled"] = seen
                if seen:
                    raise ApiError("AI 任务已取消")
                return {"reply": "不应到达"}

        page = AIAssistantPage(CancellableClient(), lambda *_a, **_k: None)
        page.refresh_status()
        self.assertEqual(len(status_calls), 1)
        page.input.setPlainText("你好")
        page.send()
        self.assertTrue(started.wait(3), "聊天任务没有启动")

        page.shutdown()
        self.assertTrue(page._cancel_event.is_set())
        self.assertTrue(observed.get("cancelled"), "worker 没有收到取消信号")

        # Refreshing after shutdown must be a no-op.
        page.refresh_status()
        page.start_monitor()
        self.assertEqual(len(status_calls), 1)
        self.assertFalse(page.monitor_timer.isActive())

    def test_window_close_triggers_shutdown_through_the_event_filter(self):
        class QuietClient:
            base_url = "http://127.0.0.1:8765"

            def ai_status(self):
                return {"ai_enabled": True, "ai_configured": True, "ai_model": "m"}

        window = QMainWindow()
        page = AIAssistantPage(QuietClient(), lambda *_a, **_k: None)
        window.setCentralWidget(page)
        try:
            page._install_close_hook()
            window.close()
            self.assertTrue(
                page._shutting_down,
                "关闭窗口后 AI 页面没有取消后台任务",
            )
        finally:
            window.deleteLater()


if __name__ == "__main__":
    unittest.main()
