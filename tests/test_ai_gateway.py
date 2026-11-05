import json
import tempfile
import unittest
from pathlib import Path

from core.config import Config
from core import security
from core.database import Database
from server.ai_gateway import (
    CHAT_MODE,
    RESPONSES_MODE,
    AiGateway,
    AiGatewayError,
)
from server.ai_tools import ToolError, ToolRegistry


class FakeResponse:
    def __init__(self, payload: dict, status_code: int = 200):
        self.payload = payload
        self.status_code = status_code
        self.text = json.dumps(payload, ensure_ascii=False)

    def json(self):
        return self.payload


class FakePoster:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[dict] = []

    def __call__(self, url, headers=None, json=None, timeout=None):  # noqa: A002
        self.calls.append({"url": url, "headers": headers or {}, "json": json, "timeout": timeout})
        if not self.responses:
            raise AssertionError("FakePoster 收到超出预期的请求")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def text_response(text: str, usage: dict | None = None) -> FakeResponse:
    return FakeResponse(
        {
            "id": "resp_test",
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": text}],
                }
            ],
            "usage": usage or {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
        }
    )


def call_response(name: str, arguments: dict, call_id: str = "call_1") -> FakeResponse:
    return FakeResponse(
        {
            "id": "resp_tool",
            "output": [
                {
                    "type": "function_call",
                    "call_id": call_id,
                    "name": name,
                    "arguments": json.dumps(arguments, ensure_ascii=False),
                }
            ],
            "usage": {"input_tokens": 20, "output_tokens": 8, "total_tokens": 28},
        }
    )


def chat_text_response(text: str, usage: dict | None = None) -> FakeResponse:
    return FakeResponse(
        {
            "id": "chatcmpl_test",
            "choices": [{"message": {"role": "assistant", "content": text}}],
            "usage": usage
            or {"prompt_tokens": 9, "completion_tokens": 4, "total_tokens": 13},
        }
    )


def chat_call_response(name: str, arguments: dict, call_id: str = "call_1") -> FakeResponse:
    return FakeResponse(
        {
            "id": "chatcmpl_tool",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": call_id,
                                "type": "function",
                                "function": {
                                    "name": name,
                                    "arguments": json.dumps(arguments, ensure_ascii=False),
                                },
                            }
                        ],
                    }
                }
            ],
            "usage": {"prompt_tokens": 12, "completion_tokens": 6, "total_tokens": 18},
        }
    )


class AiGatewayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.config = Config("server", self.root / "server_config.json")
        self.db = Database(self.root / "license.db")
        _, self.bootstrap = self.db.ensure_default_admin()
        self.master = self.db.get_admin("admin")
        self.db.set_admin_password(self.master["id"], "ReadyPass#2026")
        self.master = self.db.get_admin("admin")
        self.ai_config = {
            "enabled": True,
            "api_key": "sk-test",
            "base_url": "https://api.openai.com/v1",
            "model": "gpt-5.1",
            "reasoning_effort": "medium",
            "max_output_tokens": 1024,
            "max_tool_rounds": 8,
            "history_limit": 20,
            "monitor_interval": 8,
            "system_prompt": "测试助手",
        }

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def _gateway(self, responses, **kwargs):
        poster = FakePoster(responses)
        gateway = AiGateway(
            self.db,
            self.ai_config,
            poster=poster,
            max_retries=0,
            **kwargs,
        )
        # The gateway owns a chat worker pool; release it so a long test run
        # does not accumulate threads.
        self.addCleanup(gateway.close)
        return gateway, poster

    # ------------------------------------------------------------------
    # Schemas and role filtering
    # ------------------------------------------------------------------
    def test_tool_schemas_hide_admin_tools_from_admin_role(self):
        registry = ToolRegistry(self.db, self.config.security)
        master_names = registry.names("master")
        admin_names = registry.names("admin")
        self.assertIn("list_admins", master_names)
        self.assertIn("create_admin", master_names)
        self.assertIn("reset_admin_password", master_names)
        self.assertNotIn("list_admins", admin_names)
        self.assertNotIn("create_admin", admin_names)
        self.assertNotIn("reset_admin_password", admin_names)
        self.assertIn("revoke_license", admin_names) if "revoke_license" in admin_names else None
        self.assertIn("set_license_status", admin_names)
        self.assertIn("generate_licenses", admin_names)

    def test_admin_role_cannot_execute_admin_tool(self):
        registry = ToolRegistry(self.db, self.config.security)
        admin_operator = {"id": 2, "username": "aidev", "role": "admin"}
        with self.assertRaises(ToolError):
            registry.call("create_admin", {"username": "x", "password": "Passw0rd!x"}, admin_operator)
        with self.assertRaises(ToolError):
            registry.call("list_admins", {}, admin_operator)

    def test_schema_validation_rejects_bad_arguments(self):
        registry = ToolRegistry(self.db, self.config.security)
        operator = {"id": self.master["id"], "username": "admin", "role": "master"}
        with self.assertRaises(ToolError):
            registry.call("generate_licenses", {"count": "many"}, operator)
        with self.assertRaises(ToolError):
            registry.call("generate_licenses", {"count": 1, "card_type": "forever"}, operator)
        with self.assertRaises(ToolError):
            registry.call("generate_licenses", {"count": 1, "unknown": True}, operator)

    def test_list_logs_tool_uses_database_filters(self):
        registry = ToolRegistry(self.db, self.config.security)
        operator = {"id": self.master["id"], "username": "admin", "role": "master"}
        self.db.add_log("生成密钥", "admin", "B1", "共 3 个")
        result = registry.call("list_logs", {"action": "生成密钥", "limit": 5}, operator)
        self.assertEqual(len(result["items"]), 1)
        self.assertEqual(result["items"][0]["target"], "B1")

    # ------------------------------------------------------------------
    # Tool execution writes audit rows
    # ------------------------------------------------------------------
    def test_generate_licenses_tool_writes_audit_log(self):
        registry = ToolRegistry(self.db, self.config.security)
        operator = {"id": self.master["id"], "username": "admin", "role": "master"}
        result = registry.call(
            "generate_licenses",
            {"count": 2, "duration_value": 1, "duration_unit": "week", "note": "AI 生成的周卡"},
            operator,
            "127.0.0.1",
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 2)
        self.assertEqual(len(self.db.list_licenses()), 2)
        logs = self.db.list_logs(limit=10, action="AI生成密钥")
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["actor"], "AI:admin")
        self.assertIn("周", logs[0]["detail"])

    def test_batch_revoke_and_restore_through_tools(self):
        registry = ToolRegistry(self.db, self.config.security)
        operator = {"id": self.master["id"], "username": "admin", "role": "master"}
        created = registry.call("generate_licenses", {"count": 3}, operator)
        batch_no = created["batch_no"]
        revoked = registry.call("set_license_status", {"action": "revoke", "batch_no": batch_no}, operator)
        self.assertEqual(revoked["count"], 3)
        self.assertEqual(self.db.count_licenses(status="revoked"), 3)
        restored = registry.call("set_license_status", {"action": "restore", "batch_no": batch_no}, operator)
        self.assertEqual(restored["count"], 3)
        self.assertEqual(self.db.count_licenses(status="revoked"), 0)

    def test_exhausted_activation_card_cannot_be_restored_by_ai(self):
        registry = ToolRegistry(self.db, self.config.security)
        operator = {"id": self.master["id"], "username": "admin", "role": "master"}
        created = registry.call(
            "generate_licenses",
            {"count": 1, "card_type": "activation", "activation_limit": 1},
            operator,
        )
        key = created["keys"][0]
        lic = self.db.get_license(key)
        self.db.activate_atomic(lic["id"], key, "MACHINE-AI-1", "pc", None)
        self.db.set_license_status(key, "revoked")
        result = registry.call("set_license_status", {"action": "restore", "key_codes": [key]}, operator)
        self.assertFalse(result["ok"])
        self.assertEqual(result["failed"][0]["reason"], "激活次数已用尽，无法恢复")
        self.assertEqual(self.db.get_license(key)["status"], "revoked")

    def test_activation_card_rejects_offline_code(self):
        registry = ToolRegistry(self.db, self.config.security)
        operator = {"id": self.master["id"], "username": "admin", "role": "master"}
        created = registry.call(
            "generate_licenses",
            {"count": 1, "card_type": "activation", "activation_limit": 2},
            operator,
        )
        with self.assertRaises(ToolError) as caught:
            registry.call(
                "create_offline_code",
                {"key_code": created["keys"][0], "machine_code": "MACHINE-OFF-1"},
                operator,
            )
        self.assertIn("次数卡", str(caught.exception))

    # ------------------------------------------------------------------
    # Chat loop
    # ------------------------------------------------------------------
    def test_freeze_and_unfreeze_tools_round_trip(self):
        registry = ToolRegistry(self.db, self.config.security)
        operator = {"id": self.master["id"], "username": "admin", "role": "master"}
        key = registry.call("generate_licenses", {"count": 1}, operator)["keys"][0]
        frozen = registry.call(
            "set_license_status",
            {
                "action": "freeze",
                "key_codes": [key],
                "amount": 2,
                "unit": "hour",
                "reason": "风险排查",
            },
            operator,
        )
        self.assertTrue(frozen["ok"])
        self.assertEqual(frozen["count"], 1)
        self.assertTrue(frozen["frozen_until"])
        self.assertEqual(self.db.get_license(key)["status"], "frozen")
        self.assertEqual(
            len(self.db.list_logs(limit=10, action="AI冻结密钥")), 1
        )

        unfrozen = registry.call(
            "set_license_status", {"action": "unfreeze", "key_codes": [key]}, operator
        )
        self.assertTrue(unfrozen["ok"])
        restored = self.db.get_license(key)
        self.assertIn(restored["status"], ("unused", "activated"))
        self.assertFalse(restored["frozen_until"])
        self.assertEqual(
            len(self.db.list_logs(limit=10, action="AI解冻密钥")), 1
        )

    def test_renew_tool_extends_expiry_and_rejects_activation_cards(self):
        registry = ToolRegistry(self.db, self.config.security)
        operator = {"id": self.master["id"], "username": "admin", "role": "master"}
        key = registry.call(
            "generate_licenses",
            {"count": 1, "duration_value": 1, "duration_unit": "day"},
            operator,
        )["keys"][0]
        license_row = self.db.get_license(key)
        self.db.activate_atomic(
            license_row["id"],
            key,
            "MACHINE-RENEW-1",
            "pc",
            security.compute_expiry(1, "day"),
        )
        before = security.parse_expiry(self.db.get_license(key)["expires_at"])
        renewed = registry.call(
            "renew_licenses",
            {"key_codes": [key], "duration_value": 2, "duration_unit": "day"},
            operator,
        )
        self.assertTrue(renewed["ok"])
        after = security.parse_expiry(renewed["items"][0]["expires_at"])
        self.assertGreater(after, before)
        self.assertEqual(
            len(self.db.list_logs(limit=10, action="AI续期密钥")), 1
        )

        activation_key = registry.call(
            "generate_licenses",
            {"count": 1, "card_type": "activation", "activation_limit": 2},
            operator,
        )["keys"][0]
        rejected = registry.call(
            "renew_licenses",
            {"key_codes": [activation_key], "duration_value": 1, "duration_unit": "day"},
            operator,
        )
        self.assertFalse(rejected["ok"])
        self.assertEqual(rejected["failed"][0]["reason"], "激活次数卡不支持续期")

    def test_delete_tool_removes_licenses_and_writes_audit_log(self):
        registry = ToolRegistry(self.db, self.config.security)
        operator = {"id": self.master["id"], "username": "admin", "role": "master"}
        created = registry.call("generate_licenses", {"count": 2}, operator)
        result = registry.call(
            "delete_licenses", {"key_codes": created["keys"]}, operator
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 2)
        for key in created["keys"]:
            self.assertIsNone(self.db.get_license(key))
        self.assertEqual(len(self.db.list_logs(limit=10, action="AI删除密钥")), 2)

    def test_unbind_tool_requires_an_existing_binding(self):
        registry = ToolRegistry(self.db, self.config.security)
        operator = {"id": self.master["id"], "username": "admin", "role": "master"}
        created = registry.call(
            "generate_licenses", {"count": 1, "max_devices": 2}, operator
        )
        key = created["keys"][0]
        license_row = self.db.get_license(key)
        self.db.activate_atomic(
            license_row["id"], key, "MACHINE-UNBIND-1", "pc", None
        )
        unbound = registry.call(
            "unbind_device",
            {"key_code": key, "machine_code": "machine-unbind-1"},
            operator,
        )
        self.assertTrue(unbound["ok"])
        self.assertEqual(unbound["machine_code"], "MACHINE-UNBIND-1")
        self.assertEqual(len(self.db.list_logs(limit=10, action="AI解绑设备")), 1)
        with self.assertRaises(ToolError) as caught:
            registry.call(
                "unbind_device",
                {"key_code": key, "machine_code": "MACHINE-UNBIND-1"},
                operator,
            )
        self.assertIn("未找到", str(caught.exception))

    def test_status_tool_requires_a_target_and_valid_action(self):
        registry = ToolRegistry(self.db, self.config.security)
        operator = {"id": self.master["id"], "username": "admin", "role": "master"}
        with self.assertRaises(ToolError) as caught:
            registry.call("set_license_status", {"action": "revoke"}, operator)
        self.assertIn("key_codes", str(caught.exception))
        with self.assertRaises(ToolError):
            registry.call(
                "set_license_status", {"action": "explode", "batch_no": "B1"}, operator
            )

    def test_master_admin_tools_create_disable_and_reset(self):
        registry = ToolRegistry(self.db, self.config.security)
        operator = {"id": self.master["id"], "username": "admin", "role": "master"}
        created = registry.call(
            "create_admin",
            {"username": "aidev2", "password": "ReadyPass#2026"},
            operator,
        )
        self.assertTrue(created["ok"])
        self.assertEqual(created["role"], "admin")
        self.assertEqual(
            len(self.db.list_logs(limit=10, action="AI创建管理员")), 1
        )
        with self.assertRaises(ToolError) as duplicate:
            registry.call(
                "create_admin",
                {"username": "aidev2", "password": "ReadyPass#2026"},
                operator,
            )
        self.assertIn("已存在", str(duplicate.exception))
        with self.assertRaises(ToolError):
            registry.call(
                "create_admin",
                {"username": "weakling", "password": "short"},
                operator,
            )

        admin_id = created["id"]
        disabled = registry.call(
            "set_admin_status", {"admin_id": admin_id, "status": "disabled"}, operator
        )
        self.assertTrue(disabled["ok"])
        self.assertEqual(self.db.get_admin("aidev2")["status"], "disabled")
        reset = registry.call(
            "reset_admin_password",
            {"admin_id": admin_id, "password": "NewPass#2026"},
            operator,
        )
        self.assertTrue(reset["ok"])
        self.assertTrue(self.db.get_admin("aidev2")["must_change_password"])

    def test_admin_tools_refuse_self_and_peer_master_targets(self):
        registry = ToolRegistry(self.db, self.config.security)
        operator = {"id": self.master["id"], "username": "admin", "role": "master"}
        peer_id = self.db.create_admin("peer-master", "ReadyPass#2026", "master")
        with self.assertRaises(ToolError):
            registry.call(
                "set_admin_status", {"admin_id": operator["id"], "status": "disabled"}, operator
            )
        with self.assertRaises(ToolError):
            registry.call(
                "set_admin_status", {"admin_id": peer_id, "status": "disabled"}, operator
            )
        with self.assertRaises(ToolError):
            registry.call(
                "reset_admin_password",
                {"admin_id": operator["id"], "password": "NewPass#2026"},
                operator,
            )
        with self.assertRaises(ToolError):
            registry.call(
                "reset_admin_password",
                {"admin_id": peer_id, "password": "NewPass#2026"},
                operator,
            )
        self.assertEqual(self.db.get_admin("peer-master")["status"], "active")
    def test_chat_executes_function_call_then_returns_reply(self):
        gateway, poster = self._gateway(
            [
                call_response("get_stats", {}),
                text_response("当前没有卡密，共 1 个管理员。", {"input_tokens": 3, "output_tokens": 4, "total_tokens": 7}),
            ]
        )
        result = gateway.chat(
            {"id": self.master["id"], "username": "admin", "role": "master"},
            [{"role": "user", "content": "现在系统里有多少卡密？"}],
            "127.0.0.1",
        )
        self.assertIn("管理员", result["reply"])
        self.assertEqual(result["tool_calls"][0]["name"], "get_stats")
        self.assertEqual(result["usage"]["total_tokens"], 35)
        self.assertEqual(len(poster.calls), 2)
        second_input = poster.calls[1]["json"]["input"]
        self.assertTrue(any(item.get("type") == "function_call_output" for item in second_input))
        self.assertEqual(poster.calls[0]["url"], "https://api.openai.com/v1/responses")
        self.assertTrue(poster.calls[0]["headers"]["Authorization"].startswith("Bearer "))

    def test_chat_stages_write_tool_then_confirm_writes_audit_log(self):
        """P1-6: the gateway must not run a write tool on the model's word."""
        gateway, _poster = self._gateway(
            [
                call_response("generate_licenses", {"count": 1, "duration_value": 2, "duration_unit": "day"}),
                text_response("已准备好，请在确认条中确认。"),
            ]
        )
        operator = {"id": self.master["id"], "username": "admin", "role": "master"}
        result = gateway.chat(
            operator,
            [{"role": "user", "content": "生成一张两天卡"}],
            "127.0.0.1",
        )
        pending = result["tool_calls"][0]["result"]
        self.assertEqual(pending["status"], "pending_confirmation")
        self.assertEqual(pending["preview"]["tool"], "generate_licenses")
        self.assertEqual(pending["preview"]["affected_count"], 1)
        self.assertEqual(pending["expires_in"], 120)
        # Nothing ran yet.
        self.assertEqual(self.db.count_licenses(), 0)
        self.assertEqual(len(self.db.list_logs(limit=10, action="AI生成密钥")), 0)

        executed = gateway.confirm(pending["confirm_token"], operator, "127.0.0.1")
        self.assertTrue(executed["ok"])
        self.assertEqual(self.db.count_licenses(), 1)
        logs = self.db.list_logs(limit=10, action="AI生成密钥")
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["actor"], "AI:admin")

    def test_chat_surfaces_tool_rejection_to_the_model(self):
        gateway, poster = self._gateway(
            [
                call_response("create_admin", {"username": "someone", "password": "Passw0rd!x"}),
                text_response("该操作仅主控端可用。"),
            ]
        )
        result = gateway.chat(
            {"id": 99, "username": "aidev", "role": "admin"},
            [{"role": "user", "content": "帮我创建一个管理员"}],
        )
        self.assertEqual(result["reply"], "该操作仅主控端可用。")
        tool_result = result["tool_calls"][0]["result"]
        self.assertFalse(tool_result["ok"])
        self.assertIn("主控", tool_result["error"])
        self.assertNotIn("create_admin", gateway.registry.names("admin"))

    def test_chat_requires_enabled_and_configured_gateway(self):
        gateway, _poster = self._gateway([])
        gateway.config = dict(self.ai_config, enabled=False)
        with self.assertRaises(AiGatewayError):
            gateway.chat({"id": 1, "username": "admin", "role": "master"}, [{"role": "user", "content": "hi"}])
        gateway.config = dict(self.ai_config, api_key="")
        with self.assertRaises(AiGatewayError):
            gateway.chat({"id": 1, "username": "admin", "role": "master"}, [{"role": "user", "content": "hi"}])

    def test_chat_maps_401_to_readable_error(self):
        gateway, _poster = self._gateway(
            [FakeResponse({"error": {"message": "Incorrect API key"}}, status_code=401)]
        )
        with self.assertRaises(AiGatewayError) as caught:
            gateway.chat({"id": 1, "username": "admin", "role": "master"}, [{"role": "user", "content": "hi"}])
        self.assertIn("401", str(caught.exception))

    def test_chat_drops_leading_assistant_history(self):
        gateway, poster = self._gateway([text_response("好的。")])
        gateway.chat(
            {"id": 1, "username": "admin", "role": "master"},
            [
                {"role": "assistant", "content": "旧回复"},
                {"role": "user", "content": "新问题"},
            ],
        )
        sent = poster.calls[0]["json"]["input"]
        self.assertEqual(sent, [{"role": "user", "content": "新问题"}])

    def test_snapshot_reports_status_without_exposing_key(self):
        gateway, _poster = self._gateway([])
        data = gateway.snapshot()
        self.assertTrue(data["ai_enabled"])
        self.assertTrue(data["ai_configured"])
        self.assertEqual(data["ai_model"], "gpt-5.1")
        self.assertNotIn("api_key", json.dumps(data, ensure_ascii=False))
        self.assertIn("stats", data)
        self.assertIn("logs", data)

    def test_public_config_never_returns_api_key(self):
        gateway, _poster = self._gateway([])
        payload = gateway.public_config()
        self.assertTrue(
            {"enabled", "configured", "model", "monitor_interval"} <= set(payload)
        )
        self.assertTrue(payload["enabled"])
        self.assertTrue(payload["configured"])
        dumped = json.dumps(payload, ensure_ascii=False)
        for secret in (
            "sk-test",
            "api_key",
            "custom_headers",
            "base_url",
            "system_prompt",
        ):
            self.assertNotIn(secret, dumped)

    def test_public_config_reports_provider_and_protocol(self):
        gateway, _poster = self._gateway([])
        payload = gateway.public_config()
        self.assertEqual(payload["api_mode"], RESPONSES_MODE)
        gateway.config = dict(self.ai_config, provider="openai", vendor_name="OpenAI")
        payload = gateway.public_config()
        self.assertEqual(payload["provider"], "OpenAI")
        self.assertEqual(payload["api_mode"], RESPONSES_MODE)

    # ------------------------------------------------------------------
    # Protocol selection / endpoint shaping
    # ------------------------------------------------------------------
    def test_api_mode_normalises_provider_aliases(self):
        cases = {
            "openai": RESPONSES_MODE,
            "responses": RESPONSES_MODE,
            "openai_responses": RESPONSES_MODE,
            "OPENAI": RESPONSES_MODE,
            "chat": CHAT_MODE,
            "chat-completions": CHAT_MODE,
            "chatCompletions": CHAT_MODE,
            "openai_compatible": CHAT_MODE,
            "deepseek": CHAT_MODE,
            "moonshot": CHAT_MODE,
        }
        for raw, expected in cases.items():
            gateway, _poster = self._gateway([])
            gateway.config = dict(self.ai_config, api_mode=raw)
            self.assertEqual(gateway.api_mode, expected, raw)

    def test_api_mode_falls_back_to_default_for_blank_values(self):
        gateway, _poster = self._gateway([])
        self.assertEqual(gateway.api_mode, RESPONSES_MODE)
        gateway.config = dict(self.ai_config, api_mode="   ")
        self.assertEqual(gateway.api_mode, RESPONSES_MODE)

    def test_endpoint_appends_v1_and_strips_full_urls(self):
        gateway, _poster = self._gateway([])
        cases = {
            "https://api.deepseek.com": "https://api.deepseek.com/v1/responses",
            "https://api.deepseek.com/": "https://api.deepseek.com/v1/responses",
            "https://api.openai.com/v1": "https://api.openai.com/v1/responses",
            "https://relay.example.com/v1/": "https://relay.example.com/v1/responses",
        }
        for base, expected in cases.items():
            self.assertEqual(gateway.endpoint(RESPONSES_MODE, base), expected, base)
        self.assertEqual(
            gateway.endpoint(CHAT_MODE, "https://api.deepseek.com/v1/chat/completions"),
            "https://api.deepseek.com/v1/chat/completions",
        )
        self.assertEqual(
            gateway.endpoint(RESPONSES_MODE, "https://api.openai.com/v1/responses"),
            "https://api.openai.com/v1/responses",
        )

    def test_custom_headers_cannot_override_transport_headers(self):
        gateway, _poster = self._gateway([])
        gateway.config = dict(
            self.ai_config,
            custom_headers={
                "X-Tenant": "acme",
                "Authorization": "Bearer injected",
                "content-length": "1",
                "": "ignored",
            },
        )
        headers = gateway.headers()
        self.assertEqual(headers["X-Tenant"], "acme")
        self.assertEqual(headers["Authorization"], "Bearer sk-test")
        self.assertNotIn("content-length", {key.lower() for key in headers})
        self.assertNotIn("", headers)

    def test_extra_body_cannot_override_protocol_fields(self):
        gateway, poster = self._gateway([text_response("好的")])
        gateway.config = dict(
            self.ai_config,
            extra_body={"input": "hijacked", "model": "gpt-4o", "top_p": 0.5},
        )
        gateway.chat(
            {"id": self.master["id"], "username": "admin", "role": "master"},
            [{"role": "user", "content": "你好"}],
        )
        sent = poster.calls[0]["json"]
        self.assertEqual(sent["model"], "gpt-5.1")
        self.assertIsInstance(sent["input"], list)
        self.assertEqual(sent["top_p"], 0.5)

    def test_chat_completions_round_trip_executes_tools(self):
        gateway, poster = self._gateway(
            [
                chat_call_response("get_stats", {}),
                chat_text_response("当前没有卡密。"),
            ]
        )
        gateway.config = dict(self.ai_config, api_mode="chat_completions")
        result = gateway.chat(
            {"id": self.master["id"], "username": "admin", "role": "master"},
            [{"role": "user", "content": "有多少卡密？"}],
            "127.0.0.1",
        )
        self.assertEqual(result["reply"], "当前没有卡密。")
        self.assertEqual(result["tool_calls"][0]["name"], "get_stats")
        self.assertEqual(result["usage"]["total_tokens"], 31)
        self.assertEqual(
            poster.calls[0]["url"], "https://api.openai.com/v1/chat/completions"
        )
        first = poster.calls[0]["json"]
        self.assertIn("messages", first)
        self.assertNotIn("input", first)
        self.assertEqual(first["messages"][0]["role"], "system")
        second = poster.calls[1]["json"]["messages"]
        assistant_call = [item for item in second if item.get("tool_calls")]
        self.assertTrue(assistant_call)
        self.assertEqual(
            assistant_call[0]["tool_calls"][0]["function"]["name"], "get_stats"
        )
        tool_messages = [item for item in second if item.get("role") == "tool"]
        self.assertEqual(len(tool_messages), 1)
        self.assertEqual(tool_messages[0]["tool_call_id"], "call_1")
        self.assertIn("ok", tool_messages[0]["content"])

    def test_chat_mode_drops_responses_only_fields(self):
        """Agnes and other compatible vendors reject the flat Responses shape.

        ``/chat/completions`` expects
        ``{"type": "function", "function": {name, description, parameters}}``;
        the Responses shape fails with HTTP 400 ``missing field parameters``.
        """
        gateway, poster = self._gateway([chat_text_response("好的")])
        gateway.config = dict(
            self.ai_config,
            api_mode="chat_completions",
            reasoning_effort="high",
        )
        gateway.chat(
            {"id": self.master["id"], "username": "admin", "role": "master"},
            [{"role": "user", "content": "你好"}],
        )
        sent = poster.calls[0]["json"]
        self.assertNotIn("reasoning", sent)
        self.assertNotIn("input", sent)
        self.assertIn("max_tokens", sent)

    def test_chat_completions_tools_use_nested_function_shape(self):
        gateway, poster = self._gateway([chat_text_response("好的。")])
        gateway.config = dict(self.ai_config, api_mode="chat_completions")
        gateway.chat(
            {"id": self.master["id"], "username": "admin", "role": "master"},
            [{"role": "user", "content": "你好"}],
        )
        tools = poster.calls[0]["json"]["tools"]
        self.assertTrue(tools)
        first = tools[0]
        self.assertEqual(first["type"], "function")
        self.assertIsInstance(first.get("function"), dict)
        self.assertIn("name", first["function"])
        self.assertIn("parameters", first["function"])
        self.assertNotIn("name", first)

    def test_responses_mode_keeps_flat_tool_shape(self):
        gateway, poster = self._gateway([text_response("好的。")])
        gateway.chat(
            {"id": self.master["id"], "username": "admin", "role": "master"},
            [{"role": "user", "content": "你好"}],
        )
        first = poster.calls[0]["json"]["tools"][0]
        self.assertIn("name", first)
        self.assertNotIn("function", first)


    def test_invalid_tool_arguments_are_reported_back_to_the_model(self):
        broken = FakeResponse(
            {
                "output": [
                    {
                        "type": "function_call",
                        "call_id": "call_bad",
                        "name": "get_stats",
                        "arguments": "{not json",
                    }
                ]
            }
        )
        gateway, poster = self._gateway([broken, text_response("参数有误。")])
        result = gateway.chat(
            {"id": self.master["id"], "username": "admin", "role": "master"},
            [{"role": "user", "content": "统计一下"}],
        )
        self.assertEqual(result["reply"], "参数有误。")
        failure = result["tool_calls"][0]
        self.assertEqual(failure["arguments"], {})
        self.assertFalse(failure["result"]["ok"])
        outputs = [
            item
            for item in poster.calls[1]["json"]["input"]
            if item.get("type") == "function_call_output"
        ]
        self.assertIn("JSON", outputs[0]["output"])

    def test_tool_budget_exhaustion_asks_for_summary_without_tools(self):
        gateway, poster = self._gateway(
            [call_response("get_stats", {}), text_response("已总结。")]
        )
        gateway.config = dict(self.ai_config, max_tool_rounds=1)
        result = gateway.chat(
            {"id": self.master["id"], "username": "admin", "role": "master"},
            [{"role": "user", "content": "循环调用工具"}],
        )
        self.assertEqual(result["reply"], "已总结。")
        self.assertEqual(len(poster.calls), 2)
        summary = poster.calls[1]["json"]
        self.assertNotIn("tools", summary)
        self.assertIn("工具调用次数已达上限", summary["instructions"])

    def test_history_is_trimmed_and_leading_assistant_dropped(self):
        gateway, poster = self._gateway([chat_text_response("好的")])
        gateway.config = dict(
            self.ai_config,
            api_mode="chat_completions",
            history_limit=2,
        )
        gateway.chat(
            {"id": self.master["id"], "username": "admin", "role": "master"},
            [
                {"role": "user", "content": "第一条"},
                {"role": "user", "content": "第二条"},
                {"role": "assistant", "content": "中间回复"},
                {"role": "user", "content": "第三条"},
            ],
        )
        messages = poster.calls[0]["json"]["messages"]
        self.assertEqual(messages[0]["role"], "system")
        # Trimming keeps the newest two turns, then the leading assistant
        # message is dropped because both wire protocols reject it.
        self.assertEqual(
            [item["content"] for item in messages[1:]],
            ["第三条"],
        )

    def test_probe_uses_selected_protocol_and_returns_summary(self):
        gateway, poster = self._gateway([chat_text_response("OK")])
        summary = gateway.probe(
            "sk-probe",
            "https://api.deepseek.com",
            "deepseek-chat",
            CHAT_MODE,
        )
        self.assertIn("连接成功", summary)
        self.assertIn("deepseek-chat", summary)
        self.assertEqual(
            poster.calls[0]["url"],
            "https://api.deepseek.com/v1/chat/completions",
        )
        self.assertEqual(poster.calls[0]["headers"]["Authorization"], "Bearer sk-probe")
        self.assertNotIn("sk-probe", summary)

    # ------------------------------------------------------------------
    # Live progress events (reasoning trace in the desktop client)
    # ------------------------------------------------------------------
    def test_chat_streams_progress_events_for_the_live_view(self):
        events: list[dict] = []
        gateway, _poster = self._gateway(
            [
                chat_call_response("get_stats", {}),
                chat_text_response("当前没有卡密。"),
            ]
        )
        gateway.config = dict(self.ai_config, api_mode="chat_completions")
        result = gateway.chat(
            {"id": self.master["id"], "username": "admin", "role": "master"},
            [{"role": "user", "content": "有多少卡密？"}],
            "127.0.0.1",
            on_event=events.append,
        )
        kinds = [item["type"] for item in events]
        self.assertIn("phase", kinds)
        self.assertIn("tool", kinds)
        self.assertIn("tool_result", kinds)
        tool_index = kinds.index("tool")
        self.assertLess(tool_index, kinds.index("tool_result"))
        self.assertEqual(events[tool_index]["name"], "get_stats")
        self.assertEqual(result["reply"], "当前没有卡密。")
        self.assertEqual(result["tool_calls"][0]["name"], "get_stats")

    def test_chat_surfaces_provider_reasoning_content(self):
        gateway, poster = self._gateway(
            [
                FakeResponse(
                    {
                        "choices": [
                            {
                                "message": {
                                    "role": "assistant",
                                    "content": "已完成。",
                                    "reasoning_content": "先读取卡密表，再汇总数量。",
                                }
                            }
                        ],
                        "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
                    }
                )
            ]
        )
        gateway.config = dict(self.ai_config, api_mode="chat_completions")
        events: list[dict] = []
        result = gateway.chat(
            {"id": self.master["id"], "username": "admin", "role": "master"},
            [{"role": "user", "content": "你好"}],
            on_event=events.append,
        )
        self.assertEqual(result["reasoning"], "先读取卡密表，再汇总数量。")
        self.assertEqual(
            [item["text"] for item in events if item["type"] == "reasoning"],
            ["先读取卡密表，再汇总数量。"],
        )
        # Agnes only returns ``reasoning_content`` when the request asks for it.
        self.assertEqual(poster.calls[0]["json"]["reasoning_effort"], "medium")

    def test_offline_code_tool_reads_the_separate_security_config(self):
        gateway, _poster = self._gateway([], security_config=self.config.security)
        operator = {"id": self.master["id"], "username": "admin", "role": "master"}
        created = gateway.registry.call(
            "generate_licenses",
            {"count": 1, "duration_value": 1, "duration_unit": "day"},
            operator,
        )
        key = created["keys"][0]
        self.assertFalse(self.db.get_license(key).get("expires_at"))
        result = gateway.registry.call(
            "create_offline_code",
            {"key_code": key, "machine_code": "MACHINE-OFFLINE-1"},
            operator,
        )
        self.assertTrue(result["code"])
        # The unused duration card must be stamped with its real expiry
        # instead of signing a permanent offline code.
        self.assertTrue(result["expires_at"])
        self.assertEqual(result["expires_at"], self.db.get_license(key)["expires_at"])
        self.assertTrue(gateway.registry.names("master"))


if __name__ == "__main__":
    unittest.main()
