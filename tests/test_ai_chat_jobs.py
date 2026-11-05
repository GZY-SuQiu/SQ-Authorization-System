"""End-to-end tests for the asynchronous AI chat job queue.

``/api/ai/chat`` used to run the whole tool loop inside the HTTP request. A
slow provider then blew past the desktop client's read timeout and the operator
saw "Read timed out" even though the server was still working. The endpoint now
returns a job id immediately and the client polls ``/api/ai/chat/{job_id}``.
"""

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from core.api_client import ApiClient, ApiError
from core.config import Config
from core.database import Database
from tests.test_api_hardening import LiveServer, READY_PASSWORD


class FakeModelResponse:
    def __init__(self, payload: dict, status_code: int = 200):
        self.payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload, ensure_ascii=False)

    def json(self):
        return self.payload


def chat_text(text: str) -> FakeModelResponse:
    return FakeModelResponse(
        {
            "choices": [{"message": {"role": "assistant", "content": text}}],
            "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6},
        }
    )


class AiChatJobTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.config = Config("server", self.root / "server_config.json")
        self.config.data["ai"] = {
            "enabled": True,
            "api_key": "sk-test",
            "api_mode": "chat_completions",
            "vendor_name": "Agnes",
            "base_url": "https://api.agnes-ai.cn/v1",
            "model": "agnes-3.0-flash",
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
        login = self.client.login("admin", self.bootstrap)
        if login.get("must_change_password"):
            self.client.change_password(self.bootstrap, READY_PASSWORD)

    def tearDown(self):
        self.live.stop()
        self.db.close()
        self.tmp.cleanup()

    def _patch_model(self, *responses: FakeModelResponse):
        """Patch the provider HTTP call the server-side gateway makes."""
        calls = []

        def poster(url, headers=None, json=None, timeout=None):  # noqa: A002
            calls.append({"url": url, "headers": headers or {}, "json": json})
            if not responses:
                raise AssertionError("模型请求次数超出预期")
            item = responses[len(calls) - 1] if len(calls) <= len(responses) else responses[-1]
            return item

        patcher = mock.patch("server.ai_gateway.requests.post", side_effect=poster)
        patcher.start()
        self.addCleanup(patcher.stop)
        return calls

    def _wait_for_job(self, job_id: str, deadline: float = 20.0) -> dict:
        """Drive the same polling loop the desktop client uses."""
        end = time.time() + deadline
        while time.time() < end:
            payload = self.client._request(
                "GET", f"/api/ai/chat/{job_id}", timeout=5, offline_ok=False
            )
            if payload.get("status") in ("done", "failed", "expired"):
                return payload
            time.sleep(0.1)
        self.fail("AI 任务在测试超时前没有结束")

    def test_chat_submits_a_job_and_polls_to_completion(self):
        calls = self._patch_model(chat_text("系统里没有卡密。"))
        submitted = self.client._request(
            "POST",
            "/api/ai/chat",
            json_body={"messages": [{"role": "user", "content": "有多少卡密？"}]},
            timeout=5,
            offline_ok=False,
        )
        self.assertIn("job_id", submitted)
        self.assertEqual(submitted["status"], "pending")
        job_id = submitted["job_id"]

        final = self._wait_for_job(job_id)
        self.assertEqual(final["status"], "done")
        result = final["result"]
        self.assertEqual(result["reply"], "系统里没有卡密。")
        self.assertEqual(result["provider"], "Agnes")
        self.assertEqual(result["model"], "agnes-3.0-flash")
        self.assertTrue(calls)
        self.assertTrue(calls[0]["url"].endswith("/chat/completions"))

    def test_client_ai_chat_hides_the_polling_loop(self):
        self._patch_model(chat_text("好的。"))
        result = self.client.ai_chat([{"role": "user", "content": "你好"}])
        self.assertEqual(result["reply"], "好的。")
        self.assertEqual(result["provider"], "Agnes")

    def test_client_streams_reasoning_and_tool_events(self):
        """The desktop client must forward every event exactly once."""
        self._patch_model(
            FakeModelResponse(
                {
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": None,
                                "reasoning_content": "先查一下卡密数量。",
                                "tool_calls": [
                                    {
                                        "id": "call_1",
                                        "type": "function",
                                        "function": {
                                            "name": "get_stats",
                                            "arguments": "{}",
                                        },
                                    }
                                ],
                            }
                        }
                    ],
                    "usage": {"prompt_tokens": 12, "completion_tokens": 6, "total_tokens": 18},
                }
            ),
            chat_text("系统里没有卡密。"),
        )

        events: list[dict] = []
        result = self.client.ai_chat(
            [{"role": "user", "content": "有多少卡密？"}],
            on_event=events.append,
        )
        self.assertEqual(result["reply"], "系统里没有卡密。")
        kinds = [item.get("type") for item in events]
        self.assertIn("phase", kinds)
        self.assertIn("reasoning", kinds)
        self.assertIn("tool", kinds)
        self.assertIn("tool_result", kinds)
        sequences = [int(item["seq"]) for item in events]
        self.assertEqual(sequences, sorted(sequences))
        self.assertEqual(len(sequences), len(set(sequences)))
        self.assertIn(
            "先查一下卡密数量。",
            [item.get("text") for item in events if item.get("type") == "reasoning"],
        )

    def test_unknown_job_reports_expired_instead_of_hanging(self):
        payload = self.client._request(
            "GET", "/api/ai/chat/deadbeef", timeout=5, offline_ok=False
        )
        self.assertEqual(payload["status"], "expired")
        self.assertIn("过期", payload["error"])

    def test_provider_failure_marks_the_job_failed(self):
        self._patch_model(
            FakeModelResponse({"error": {"message": "余额不足"}}, status_code=402)
        )
        submitted = self.client._request(
            "POST",
            "/api/ai/chat",
            json_body={"messages": [{"role": "user", "content": "你好"}]},
            timeout=5,
            offline_ok=False,
        )
        final = self._wait_for_job(submitted["job_id"])
        self.assertEqual(final["status"], "failed")
        self.assertIn("余额不足", final["error"])

    def test_job_endpoint_requires_authentication(self):
        anonymous = ApiClient(f"http://127.0.0.1:{self.live.port}")
        with self.assertRaises(ApiError):
            anonymous._request("GET", "/api/ai/chat/deadbeef", timeout=5)


if __name__ == "__main__":
    unittest.main()
