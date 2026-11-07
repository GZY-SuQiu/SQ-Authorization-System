# -*- coding: utf-8 -*-
"""C1 测试：审批体系（注册/管理员/转赠）+ 删除 + 卡密账号强挂钩 + 服务端账号。"""
import tempfile
import threading
import time
import unittest
from pathlib import Path

import requests
import uvicorn

from core.api_client import ApiClient
from core.config import Config
from core.database import Database
from server.api import create_app

PORTAL_PASSWORD = "Portal#Pass2026"


def _free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class FakeMailer:
    """记录 enqueue 的假邮件器（含验证码提取）。"""

    def __init__(self):
        self.items = []
        self.running = False

    def start(self):
        self.running = True

    def stop(self, timeout=5.0):
        self.running = False

    def enqueue(self, to_email, template_code, variables=None, dedupe_key=""):
        self.items.append(
            {
                "to_email": to_email,
                "template_code": str(template_code or ""),
                "variables": dict(variables or {}),
                "dedupe_key": dedupe_key,
            }
        )
        return len(self.items)

    def send_now(self, to_email, template_code, variables=None):
        return None

    def status(self):
        return {
            "enabled": True,
            "host": "fake",
            "port": 0,
            "from_email": "no-reply@example.com",
            "pending": 0,
            "sending": 0,
            "sent": len(self.items),
            "failed": 0,
            "dead": 0,
            "last_error": None,
        }

    def code_for(self, email: str, template_code: str = "") -> str:
        for call in reversed(self.items):
            if str(call["to_email"]).lower() != str(email).lower():
                continue
            if template_code and call["template_code"] != template_code:
                continue
            code = str(call["variables"].get("code") or "")
            if code:
                return code
        return ""


class _LiveServer:
    def __init__(self, app, port):
        self.server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", access_log=False)
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self):
        self.thread.start()
        for _ in range(200):
            if self.server.started:
                return
            time.sleep(0.05)
        raise RuntimeError("测试服务器启动超时")

    def stop(self):
        self.server.should_exit = True
        self.thread.join(timeout=10)


class C1ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        root = Path(self.tmp.name)
        self.config = Config("server", root / "server_config.json")
        self.config.data["security"]["attest_mode"] = "off"
        # 本文件专测新门禁：显式开启（测试进程的默认已放宽）
        self.config.data["security"]["binding_required"] = True
        self.config.data["security"]["approval_enabled"] = True
        self.db = Database(root / "license.db", self.config.security["secret_key"])
        # 测试环境显式创建 admin（服务器启动不再自动创建 —— 新流程由服务端创建）
        _, self.bootstrap = self.db.ensure_default_admin()
        self.mailer = FakeMailer()
        app = create_app(self.config, self.db, mailer=self.mailer)
        self.port = _free_port()
        self.live = _LiveServer(app, self.port)
        self.live.start()
        self.master = ApiClient(
            f"http://127.0.0.1:{self.port}",
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )
        login = self.master.login("admin", self.bootstrap)
        if login.get("must_change_password"):
            self.master.change_password(self.bootstrap, "C1Master#2026")

    def tearDown(self):
        self.live.stop()
        self.db.close()
        self.tmp.cleanup()

    # ------------------------------------------------------------------ #
    def _portal_client(self) -> ApiClient:
        return ApiClient(
            f"http://127.0.0.1:{self.port}",
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )

    def _register(self, email: str, client: ApiClient | None = None):
        """发送验证码并注册，返回原始响应 dict。"""
        target = client or self._portal_client()
        target.portal_send_code(email, "register")
        code = self.mailer.code_for(email, "verify_email")
        self.assertTrue(code, f"未捕获验证码：{email}")
        return target, target.portal_register(email, code, PORTAL_PASSWORD)

    def _approve_pending(self, kind: str = "user_register") -> dict:
        """由主控批准最新一条待处理审批；返回审批记录。"""
        result = self.master.list_approvals(kind, "pending")
        items = result.get("items") or []
        self.assertTrue(items, f"没有待处理的 {kind} 审批")
        approval = items[0]
        self.master.approve_approval(int(approval["id"]), "测试批准")
        return approval

    def _approve_admin_register_directly(self) -> dict:
        """管理员创建审批：服务器端直连 db 处理（该类型 HTTP 端点已禁用）。"""
        items, _ = self.db.list_approvals("admin_register", "pending")
        self.assertTrue(items, "没有待处理的管理员创建审批")
        approval = items[0]
        self.db.review_approval(int(approval["id"]), "approved", "SQ.admin")
        _ok, _detail = self.db.apply_approval(int(approval["id"]), "SQ.admin")
        self.assertTrue(_ok)
        return approval

    def _register_and_approve(self, email: str):
        """注册 → 批准 → 登录，返回已登录的 client。"""
        _, data = self._register(email)
        self.assertTrue(data.get("ok"), data)
        self.assertTrue(data.get("pending_approval"), data)
        self._approve_pending("user_register")
        client = self._portal_client()
        login = client.portal_login(email, PORTAL_PASSWORD)
        self.assertTrue(login.get("ok"), login)
        return client

    # ------------------------------------------------------------------ #
    # 注册审批
    # ------------------------------------------------------------------ #
    def test_register_requires_approval_and_login_blocked(self):
        _, data = self._register("u1@example.com")
        self.assertTrue(data.get("ok"), data)
        self.assertTrue(data.get("pending_approval"))
        self.assertIn("审批", str(data.get("message") or ""))

        # 账号已建但为 pending
        account = self.db.get_portal_account("u1@example.com")
        self.assertEqual(str(account["status"]), "pending")

        # 登录被拒
        client = self._portal_client()
        login = client.portal_login("u1@example.com", PORTAL_PASSWORD)
        self.assertFalse(login.get("ok"))
        self.assertEqual(login.get("code"), "pending_approval")

    def test_approve_activates_account_and_allows_login(self):
        _, data = self._register("u2@example.com")
        self.assertTrue(data.get("pending_approval"))
        approval = self._approve_pending("user_register")
        self.assertEqual(approval.get("kind"), "user_register")

        account = self.db.get_portal_account("u2@example.com")
        self.assertEqual(str(account["status"]), "active")

        client = self._portal_client()
        login = client.portal_login("u2@example.com", PORTAL_PASSWORD)
        self.assertTrue(login.get("ok"), login)

        # 审批已处理 + 邮件通知已入队
        items, _ = self.db.list_approvals("user_register", "approved")
        self.assertTrue(items)
        mails = [
            item for item in self.mailer.items
            if item["template_code"] == "approval_notice"
            and item["to_email"] == "u2@example.com"
        ]
        self.assertTrue(mails, "应发送审批结果邮件")

    def test_reject_disables_account(self):
        _, data = self._register("u3@example.com")
        self.assertTrue(data.get("pending_approval"))
        result = self.master.list_approvals("user_register", "pending")
        approval_id = int(result["items"][0]["id"])
        self.master.reject_approval(approval_id, "拒绝测试")

        account = self.db.get_portal_account("u3@example.com")
        self.assertEqual(str(account["status"]), "disabled")
        client = self._portal_client()
        login = client.portal_login("u3@example.com", PORTAL_PASSWORD)
        self.assertFalse(login.get("ok"))
    # ------------------------------------------------------------------ #
    # 管理员注册审批
    # ------------------------------------------------------------------ #
    def test_admin_create_needs_approval(self):
        result = self.master._request(
            "POST",
            "/api/admin/create",
            json_body={"username": "newmaster", "password": "NewMaster#2026", "role": "master"},
        )
        self.assertTrue(result.get("ok"), result)
        self.assertTrue(result.get("pending_approval"))

        target = self.db.get_admin("newmaster")
        self.assertEqual(str(target["status"]), "disabled")

        # 新管理员登录被拒（直连检查状态码，避免客户端断言干扰）
        blocked = requests.post(
            f"http://127.0.0.1:{self.port}/api/admin/login",
            json={"username": "newmaster", "password": "NewMaster#2026"},
            timeout=15,
        )
        self.assertIn(blocked.status_code, (400, 401, 403))

        # 管理员创建审批只能服务器端处理 → 直连 db 批
        approval = self._approve_admin_register_directly()
        self.assertEqual(approval.get("kind"), "admin_register")
        target = self.db.get_admin("newmaster")
        self.assertEqual(str(target["status"]), "active")

    # ------------------------------------------------------------------ #
    # 卡密转赠
    # ------------------------------------------------------------------ #
    def test_transfer_flow_full(self):
        key = self.master.generate_licenses(count=1, duration_days=30)["keys"][0]
        machine_a = "TRA-A1111-22222-33333-44444"

        client_a = self._register_and_approve("a@example.com")
        bound = client_a.portal_bind(key, machine_a, "dev-a")
        self.assertTrue(bound.get("ok"), bound)
        activated = client_a.activate(key, machine_a, "dev-a")
        self.assertTrue(activated.get("ok"), activated)

        client_b = self._register_and_approve("b@example.com")

        # A 发起转赠
        request_result = client_a.transfer_request(key, "b@example.com")
        self.assertTrue(request_result.get("ok"), request_result)
        # 重复申请被拒
        duplicate = client_a.transfer_request(key, "b@example.com")
        self.assertEqual(duplicate.get("code"), "duplicate")

        # 主控批准
        approval_result = self.master.list_approvals("license_transfer", "pending")
        approval_id = int(approval_result["items"][0]["id"])
        done = self.master.approve_approval(approval_id, "同意转赠")
        self.assertTrue(done.get("ok"), done)

        # 绑定转移到 B；A 无绑定；设备记录被清（需重新激活）
        account_a = self.db.get_portal_account("a@example.com")
        account_b = self.db.get_portal_account("b@example.com")
        self.assertIsNone(self.db.get_portal_binding(int(account_a["id"])))
        binding_b = self.db.get_portal_binding(int(account_b["id"]))
        self.assertIsNotNone(binding_b)
        self.assertEqual(binding_b["key_code"], key)
        activations = self.db.list_activations(key)
        self.assertTrue(all(str(a.get("status")) != "active" for a in activations))

        # B 在新设备重新激活
        rebound = client_b.activate(key, "TRB-B2222-55555-66666-77777", "dev-b")
        self.assertTrue(rebound.get("ok"), rebound)

    # ------------------------------------------------------------------ #
    # 卡密账号强挂钩（binding_required）
    # ------------------------------------------------------------------ #
    def test_binding_required_gate(self):
        key = self.master.generate_licenses(count=1, duration_days=30)["keys"][0]
        base = f"http://127.0.0.1:{self.port}/api/client/activate"
        machine = "GATE-11111-22222-33333-44444"

        # 1) 无账号凭据 → 拒绝
        r = requests.post(base, json={"key_code": key, "machine_code": machine}, timeout=15)
        self.assertEqual(r.json().get("code"), "account_required", r.text)

        # 2) 有账号但未绑卡 → 拒绝
        client = self._register_and_approve("gate@example.com")
        r = client.activate(key, machine, "dev")
        self.assertEqual(r.get("code"), "binding_required", r)

        # 3) SDK 头豁免（独立卡：不占用主卡设备位）
        sdk_key = self.master.generate_licenses(count=1, duration_days=30)["keys"][0]
        r = requests.post(
            base,
            json={"key_code": sdk_key, "machine_code": "SDKM-11111-22222-33333-44444"},
            headers={"X-Client-Kind": "sdk"},
            timeout=15,
        )
        self.assertTrue(r.json().get("ok"), r.text)

        # 4) 绑卡后激活成功
        bound = client.portal_bind(key, machine, "dev")
        self.assertTrue(bound.get("ok"), bound)
        activated = client.activate(key, machine, "dev")
        self.assertTrue(activated.get("ok"), activated)

    # ------------------------------------------------------------------ #
    # 删除
    # ------------------------------------------------------------------ #
    def test_delete_portal_account_cascade(self):
        key = self.master.generate_licenses(count=1, duration_days=30)["keys"][0]
        client = self._register_and_approve("del@example.com")
        self.assertTrue(client.portal_bind(key, "DEL-11111-22222-33333-44444", "dev").get("ok"))
        account = self.db.get_portal_account("del@example.com")

        result = self.master.delete_portal_account(int(account["id"]))
        self.assertTrue(result.get("ok"), result)
        self.assertIsNone(self.db.get_portal_account("del@example.com"))
        lic = self.db.get_license(key)
        self.assertIsNone(self.db.get_binding_by_license(int(lic["id"])))

    def test_admin_register_http_review_forbidden(self):
        """管理员创建审批：主控端 HTTP 不能批（防越权扩编），服务器端可批。"""
        self.master._request(
            "POST", "/api/admin/create",
            json_body={"username": "hx", "password": "Hx#Pass2026", "role": "admin"},
        )
        items, _ = self.db.list_approvals("admin_register", "pending")
        aid = int(items[0]["id"])
        with self.assertRaises(Exception) as ctx:
            self.master.approve_approval(aid, "试图批")
        self.assertIn("服务器端", str(ctx.exception))
        self.assertEqual(str(self.db.get_approval(aid)["status"]), "pending")
        with self.assertRaises(Exception) as ctx2:
            self.master.reject_approval(aid, "试图驳")
        self.assertIn("服务器端", str(ctx2.exception))

        # 服务器端直连可批
        self.db.review_approval(aid, "approved", "SQ.admin")
        ok, _detail = self.db.apply_approval(aid, "SQ.admin")
        self.assertTrue(ok)
        self.assertEqual(str(self.db.get_admin("hx")["status"]), "active")

    def test_pending_admin_cannot_be_enabled_via_http(self):
        """待审批账号不能通过"启用"按钮绕过审批。"""
        self.master._request(
            "POST", "/api/admin/create",
            json_body={"username": "byp", "password": "Byp#Pass2026", "role": "admin"},
        )
        target = self.db.get_admin("byp")
        self.assertEqual(str(target["status"]), "disabled")
        with self.assertRaises(Exception) as ctx:
            self.master._request(
                "POST", "/api/admin/status",
                json_body={"admin_id": int(target["id"]), "status": "active"},
            )
        self.assertIn("审批", str(ctx.exception))
        self.assertEqual(str(self.db.get_admin("byp")["status"]), "disabled")

    def test_delete_pending_admin_voids_approval(self):
        """删除待审批账号 → 其审批自动作废（不悬挂）。"""
        self.master._request(
            "POST", "/api/admin/create",
            json_body={"username": "dv", "password": "Dv#Pass2026", "role": "admin"},
        )
        target = self.db.get_admin("dv")
        self.assertTrue(self.db.delete_admin(int(target["id"])))
        pending_items, _ = self.db.list_approvals("admin_register", "pending")
        self.assertEqual(pending_items, [])
        rejected, _ = self.db.list_approvals("admin_register", "rejected")
        self.assertTrue(any("账号已删除" in (a.get("review_note") or "") for a in rejected))

    def test_delete_admin_protection(self):
        # 1) 删除自己：拒绝
        admin = self.db.get_admin("admin")
        with self.assertRaises(Exception) as ctx:
            self.master.delete_admin(int(admin["id"]))
        self.assertIn("自己", str(ctx.exception))

        # 2) 非"最后一个"的主控可被删除
        self.master._request(
            "POST",
            "/api/admin/create",
            json_body={"username": "m2", "password": "M2Pass#2026", "role": "master"},
        )
        self._approve_admin_register_directly()
        m2 = self.db.get_admin("m2")
        result = self.master.delete_admin(int(m2["id"]))
        self.assertTrue(result.get("ok"), result)
        self.assertIsNone(self.db.get_admin("m2"))

        # 3) 最后一个主控的底层保护（db 层）：拒删
        self.assertFalse(self.db.delete_admin(int(admin["id"])))

    # ------------------------------------------------------------------ #
    # 总开关
    # ------------------------------------------------------------------ #
    def test_approval_disabled_direct_flow(self):
        self.config.security["approval_enabled"] = False
        self.config.save()
        client = self._portal_client()
        client.portal_send_code("direct@example.com", "register")
        code = self.mailer.code_for("direct@example.com", "verify_email")
        data = client.portal_register("direct@example.com", code, PORTAL_PASSWORD)
        self.assertTrue(data.get("ok"), data)
        self.assertFalse(data.get("pending_approval"))
        account = self.db.get_portal_account("direct@example.com")
        self.assertEqual(str(account["status"]), "active")
        self.assertTrue(client.portal_token)

    # ------------------------------------------------------------------ #
    # 服务端登录账号
    # ------------------------------------------------------------------ #
    def test_server_account_lifecycle(self):
        created = self.db.ensure_server_account()
        self.assertTrue(created)
        # 重复调用不重建
        self.assertFalse(self.db.ensure_server_account())
        account = self.db.get_server_account()
        self.assertEqual(account["username"], "SQ.admin")
        self.assertTrue(self.db.verify_server_login("SQ.admin", "SQ12345678"))
        self.assertFalse(self.db.verify_server_login("SQ.admin", "wrong"))
        self.assertFalse(self.db.verify_server_login("nobody", "SQ12345678"))

        ok, msg = self.db.set_server_password("weak")
        self.assertFalse(ok)
        ok, _ = self.db.set_server_password("Server#Pass2026")
        self.assertTrue(ok)
        self.assertTrue(self.db.verify_server_login("SQ.admin", "Server#Pass2026"))

        one_time = self.db.reset_server_password()
        self.assertTrue(self.db.verify_server_login("SQ.admin", one_time))
        self.assertEqual(
            int((self.db.get_server_account() or {}).get("must_change_password") or 0), 1
        )


if __name__ == "__main__":
    unittest.main()
