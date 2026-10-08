"""P1-6: AI write tools require a two-phase operator confirmation.

A write tool called by the model must never touch the database before the
operator redeems the signed, single-use confirmation token. Read tools stay
immediate, the token is bound to its operator (others get 403), and confirm /
cancel / expiry all leave an audit trail.
"""

import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from core.api_client import ApiClient, ApiError
from core.config import Config
from core.database import Database
from server.ai_gateway import AiConfirmationError, AiGateway
from server.ai_tools import WRITE_TOOL_NAMES, ToolRegistry
from tests.test_ai_gateway import (
    FakePoster,
    chat_call_response,
    chat_text_response,
)
from tests.test_api_hardening import LiveServer, READY_PASSWORD


AI_CONFIG = {
    "enabled": True,
    "api_key": "sk-test",
    "api_mode": "chat_completions",
    "vendor_name": "Agnes",
    "base_url": "https://api.agnes-ai.cn/v1",
    "model": "agnes-3.0-flash",
    "monitor_interval": 8,
}


class ConfirmationGatewayTests(unittest.TestCase):
    """Unit level: the gate lives in the AiGateway call path."""

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

    def _gateway(self, responses=None):
        gateway = AiGateway(
            self.db,
            AI_CONFIG,
            security_config=self.config.security,
            poster=FakePoster(responses or []),
            max_retries=0,
        )
        self.addCleanup(gateway.close)
        return gateway

    def _stage(self, gateway, name="generate_licenses", arguments=None):
        arguments = (
            arguments
            if arguments is not None
            else {"count": 1, "duration_value": 2, "duration_unit": "day"}
        )
        return gateway._run_tool(name, arguments, self.operator, "127.0.0.1")

    # -------------------------------------------------------------- gating
    def test_write_tool_set_covers_every_mutating_tool(self):
        registry = ToolRegistry(self.db, self.config.security)
        self.assertEqual(registry.write_tool_names(), set(WRITE_TOOL_NAMES))
        for name in WRITE_TOOL_NAMES:
            self.assertTrue(registry.is_write_tool(name), name)
        for name in (
            "get_stats",
            "list_licenses",
            "get_license_detail",
            "list_batches",
            "list_logs",
            "list_admins",
        ):
            self.assertFalse(registry.is_write_tool(name), name)

    def test_write_tool_first_call_is_pending_and_changes_nothing(self):
        gateway = self._gateway()
        result = self._stage(
            gateway,
            "generate_licenses",
            {"count": 3, "duration_value": 1, "duration_unit": "day"},
        )
        self.assertEqual(result["status"], "pending_confirmation")
        self.assertTrue(result["confirm_token"])
        self.assertEqual(result["expires_in"], 120)
        self.assertEqual(
            result["preview"],
            {
                "tool": "generate_licenses",
                "arguments_summary": "生成 3 张时长卡（有效期 1 天）",
                "affected_count": 3,
            },
        )
        # Neither the licence table nor the audit log moved.
        self.assertEqual(self.db.count_licenses(), 0)
        self.assertEqual(self.db.list_logs(limit=10, action="AI生成密钥"), [])

    def test_read_tools_still_execute_immediately(self):
        gateway = self._gateway()
        stats = gateway._run_tool("get_stats", {}, self.operator, "")
        self.assertIsInstance(stats, dict)
        self.assertNotIn("status", stats)
        self.assertIn("total", stats)
        listed = gateway._run_tool("list_licenses", {}, self.operator, "")
        self.assertEqual(listed["total"], 0)

    def test_admin_only_write_tool_is_still_rejected_for_admin_role(self):
        gateway = self._gateway()
        admin = {"id": 99, "username": "aidev", "role": "admin"}
        result = gateway._run_tool(
            "create_admin",
            {"username": "x", "password": "Passw0rd!x"},
            admin,
            "",
        )
        self.assertFalse(result["ok"])
        self.assertIn("主控", result["error"])
        self.assertEqual(self.db.get_admin("x"), None)

    def test_missing_target_is_rejected_before_a_token_is_issued(self):
        gateway = self._gateway()
        result = self._stage(gateway, "delete_licenses", {})
        self.assertFalse(result["ok"])
        self.assertIn("key_codes", result["error"])
        with gateway._confirm_lock:
            self.assertEqual(gateway._confirmations, {})

    # ------------------------------------------------------------ confirm
    def test_confirm_executes_once_and_returns_the_tool_result(self):
        gateway = self._gateway()
        pending = self._stage(gateway, "generate_licenses", {"count": 1})
        token = pending["confirm_token"]

        executed = gateway.confirm(token, self.operator, "127.0.0.1")
        self.assertTrue(executed["ok"])
        self.assertEqual(executed["count"], 1)
        self.assertTrue(executed["keys"][0])
        self.assertEqual(self.db.count_licenses(), 1)

        executed_logs = self.db.list_logs(limit=10, action="AI确认执行")
        self.assertEqual(len(executed_logs), 1)
        self.assertEqual(executed_logs[0]["actor"], "AI:admin")

        with self.assertRaises(AiConfirmationError) as caught:
            gateway.confirm(token, self.operator, "127.0.0.1")
        self.assertEqual(caught.exception.status_code, 400)
        self.assertIn("重复", str(caught.exception))
        # The replay must not run the tool a second time.
        self.assertEqual(self.db.count_licenses(), 1)
        self.assertEqual(len(self.db.list_logs(limit=50, action="AI生成密钥")), 1)

    def test_confirm_only_executes_the_staged_arguments(self):
        gateway = self._gateway()
        pending = self._stage(gateway, "generate_licenses", {"count": 2})
        # The token carries a hash of the staged arguments; nothing the caller
        # sends later can change what runs.
        self.assertEqual(pending["preview"]["affected_count"], 2)
        executed = gateway.confirm(pending["confirm_token"], self.operator)
        self.assertEqual(executed["count"], 2)
        self.assertEqual(self.db.count_licenses(), 2)

    def test_concurrent_confirm_only_executes_once(self):
        gateway = self._gateway()
        token = self._stage(gateway, "generate_licenses", {"count": 1})[
            "confirm_token"
        ]
        results: list[dict] = []
        errors: list[BaseException] = []
        barrier = threading.Barrier(3)

        def run() -> None:
            barrier.wait(5)
            try:
                results.append(gateway.confirm(token, self.operator))
            except BaseException as exc:  # noqa: BLE001 - asserted below
                errors.append(exc)

        threads = [threading.Thread(target=run, daemon=True) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait(5)
        for thread in threads:
            thread.join(5)
        self.assertEqual(len(results), 1, results)
        self.assertEqual(len(errors), 1, errors)
        self.assertIsInstance(errors[0], AiConfirmationError)
        self.assertEqual(self.db.count_licenses(), 1)

    def test_confirm_execution_failure_is_reported_and_audited(self):
        gateway = self._gateway()
        pending = self._stage(
            gateway,
            "delete_licenses",
            {"key_codes": ["GSQ-AAAAA-BBBBB-CCCCC-DDDDD"]},
        )
        self.assertEqual(pending["status"], "pending_confirmation")
        result = gateway.confirm(pending["confirm_token"], self.operator)
        self.assertFalse(result["ok"])
        self.assertTrue(result["failed"])
        failed_logs = self.db.list_logs(limit=10, action="AI确认执行失败")
        self.assertEqual(len(failed_logs), 1)
        self.assertEqual(failed_logs[0]["actor"], "AI:admin")
        # A failed execution still consumes the token.
        with self.assertRaises(AiConfirmationError):
            gateway.confirm(pending["confirm_token"], self.operator)

    # ------------------------------------------------------------- cancel
    def test_cancel_prevents_execution_and_is_audited(self):
        gateway = self._gateway()
        pending = self._stage(gateway)
        token = pending["confirm_token"]
        cancelled = gateway.cancel(token, self.operator, "127.0.0.1")
        self.assertTrue(cancelled["ok"])
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertEqual(self.db.count_licenses(), 0)
        logs = self.db.list_logs(limit=10, action="AI取消操作")
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["actor"], "AI:admin")

        with self.assertRaises(AiConfirmationError) as caught:
            gateway.confirm(token, self.operator)
        self.assertEqual(caught.exception.status_code, 400)
        self.assertIn("取消", str(caught.exception))
        self.assertEqual(self.db.count_licenses(), 0)

    # ---------------------------------------------------------- ownership
    def test_another_operator_cannot_confirm_or_cancel(self):
        gateway = self._gateway()
        pending = self._stage(gateway)
        token = pending["confirm_token"]
        intruder = {"id": 999, "username": "aidev", "role": "master"}

        with self.assertRaises(AiConfirmationError) as confirm_error:
            gateway.confirm(token, intruder, "10.0.0.9")
        self.assertEqual(confirm_error.exception.status_code, 403)
        with self.assertRaises(AiConfirmationError) as cancel_error:
            gateway.cancel(token, intruder, "10.0.0.9")
        self.assertEqual(cancel_error.exception.status_code, 403)
        self.assertEqual(self.db.count_licenses(), 0)

        # The owner's token survives the foreign attempts untouched.
        self.assertTrue(gateway.confirm(token, self.operator)["ok"])
        self.assertEqual(self.db.count_licenses(), 1)

    # --------------------------------------------------- expiry / tamper
    def test_expired_token_reports_410_and_is_audited(self):
        gateway = self._gateway()
        pending = self._stage(gateway)
        token = pending["confirm_token"]
        with gateway._confirm_lock:
            for record in gateway._confirmations.values():
                record["expires_at"] = time.time() - 1

        with self.assertRaises(AiConfirmationError) as caught:
            gateway.confirm(token, self.operator)
        self.assertEqual(caught.exception.status_code, 410)
        self.assertIn("过期", str(caught.exception))
        expired = self.db.list_logs(limit=10, action="AI确认过期")
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0]["actor"], "AI:admin")
        self.assertEqual(self.db.count_licenses(), 0)

    def test_tampered_token_is_rejected_and_original_still_works(self):
        gateway = self._gateway()
        pending = self._stage(gateway)
        token = pending["confirm_token"]
        tampered = token[:-2] + ("aa" if not token.endswith("aa") else "bb")
        with self.assertRaises(AiConfirmationError):
            gateway.confirm(tampered, self.operator)
        self.assertEqual(self.db.count_licenses(), 0)
        self.assertTrue(gateway.confirm(token, self.operator)["ok"])
        self.assertEqual(self.db.count_licenses(), 1)

    # --------------------------------------------------------- chat loop
    def test_chat_reports_the_pending_action_to_the_model_and_result(self):
        gateway = self._gateway(
            [
                chat_call_response(
                    "delete_licenses",
                    {"key_codes": ["GSQ-AAAAA-BBBBB-CCCCC-DDDDD"]},
                ),
                chat_text_response("已生成待确认动作，请在确认条中确认。"),
            ]
        )
        events: list[dict] = []
        result = gateway.chat(
            self.operator,
            [{"role": "user", "content": "删除这张卡密"}],
            "127.0.0.1",
            on_event=events.append,
        )
        pending = result["tool_calls"][0]["result"]
        self.assertEqual(pending["status"], "pending_confirmation")
        self.assertEqual(pending["preview"]["tool"], "delete_licenses")
        self.assertIn("tool_pending", [item.get("type") for item in events])
        self.assertEqual(self.db.count_licenses(), 0)
        # The model was handed the pending payload instead of an execution
        # result, so it cannot claim the delete already happened.
        tool_messages = [
            item
            for item in gateway._poster().calls[1]["json"]["messages"]
            if item.get("role") == "tool"
        ]
        self.assertTrue(tool_messages)
        self.assertIn("pending_confirmation", tool_messages[0]["content"])


class ConfirmationApiTests(unittest.TestCase):
    """HTTP level: /api/ai/confirm and /api/ai/cancel."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.config = Config("server", self.root / "server_config.json")
        self.config.data["ai"] = dict(AI_CONFIG)
        self.db = Database(self.root / "license.db")
        _, self.bootstrap = self.db.ensure_default_admin()
        self.db.create_admin("aidev", "SecondPass#2026", "admin")
        self.live = LiveServer(self.config, self.db)
        self.live.start()
        self.master_client = ApiClient(
            f"http://127.0.0.1:{self.live.port}",
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )
        login = self.master_client.login("admin", self.bootstrap)
        if login.get("must_change_password"):
            self.master_client.change_password(self.bootstrap, READY_PASSWORD)
        self.other_client = ApiClient(
            f"http://127.0.0.1:{self.live.port}",
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )
        self.other_client.login("aidev", "SecondPass#2026")

    def tearDown(self):
        self.live.stop()
        self.db.close()
        self.tmp.cleanup()

    def _patch_model(self, *responses):
        calls = []

        def poster(url, headers=None, json=None, timeout=None):  # noqa: A002
            calls.append({"url": url, "json": json})
            if not responses:
                raise AssertionError("模型请求次数超出预期")
            index = min(len(calls) - 1, len(responses) - 1)
            return responses[index]

        patcher = mock.patch("server.ai_gateway.requests.post", side_effect=poster)
        patcher.start()
        self.addCleanup(patcher.stop)
        return calls

    def _stage(self, name: str, arguments: dict) -> dict:
        self._patch_model(
            chat_call_response(name, arguments),
            chat_text_response("请在确认条中确认。"),
        )
        submitted = self.master_client._request(
            "POST",
            "/api/ai/chat",
            json_body={"messages": [{"role": "user", "content": "执行写操作"}]},
            timeout=5,
            offline_ok=False,
        )
        deadline = time.time() + 15
        while time.time() < deadline:
            payload = self.master_client._request(
                "GET", f"/api/ai/chat/{submitted['job_id']}", timeout=5, offline_ok=False
            )
            if payload.get("status") in ("done", "failed", "expired"):
                break
            time.sleep(0.1)
        self.assertEqual(payload["status"], "done", payload)
        return payload["result"]["tool_calls"][0]["result"]

    def test_pending_then_confirm_executes_and_repeat_is_rejected(self):
        pending = self._stage("generate_licenses", {"count": 1})
        self.assertEqual(pending["status"], "pending_confirmation")
        self.assertEqual(self.db.count_licenses(), 0)

        executed = self.master_client.ai_confirm(pending["confirm_token"])
        self.assertTrue(executed["ok"])
        self.assertEqual(self.db.count_licenses(), 1)

        with self.assertRaises(ApiError) as caught:
            self.master_client.ai_confirm(pending["confirm_token"])
        self.assertIn("重复", str(caught.exception))
        self.assertEqual(self.master_client.last_context["status_code"], 400)
        self.assertEqual(self.db.count_licenses(), 1)

    def test_foreign_operator_gets_403_and_owner_can_still_confirm(self):
        pending = self._stage("generate_licenses", {"count": 1})
        with self.assertRaises(ApiError) as caught:
            self.other_client.ai_confirm(pending["confirm_token"])
        self.assertIn("不属于", str(caught.exception))
        self.assertEqual(self.other_client.last_context["status_code"], 403)

        with self.assertRaises(ApiError):
            self.other_client.ai_cancel(pending["confirm_token"])
        self.assertEqual(self.other_client.last_context["status_code"], 403)
        self.assertEqual(self.db.count_licenses(), 0)

        self.assertTrue(self.master_client.ai_confirm(pending["confirm_token"])["ok"])
        self.assertEqual(self.db.count_licenses(), 1)

    def test_cancel_via_api_prevents_execution(self):
        pending = self._stage("generate_licenses", {"count": 1})
        cancelled = self.master_client.ai_cancel(pending["confirm_token"])
        self.assertTrue(cancelled["ok"])
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertEqual(self.db.count_licenses(), 0)

        with self.assertRaises(ApiError) as caught:
            self.master_client.ai_confirm(pending["confirm_token"])
        self.assertIn("取消", str(caught.exception))
        self.assertEqual(self.db.count_licenses(), 0)

    def test_confirm_endpoints_require_authentication(self):
        anonymous = ApiClient(f"http://127.0.0.1:{self.live.port}")
        with self.assertRaises(ApiError):
            anonymous.ai_confirm("whatever")
        with self.assertRaises(ApiError):
            anonymous.ai_cancel("whatever")


if __name__ == "__main__":
    unittest.main()
