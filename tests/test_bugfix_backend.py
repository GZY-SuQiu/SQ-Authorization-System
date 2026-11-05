"""BUGFIX 批次 Backend 验收测试（docs/BUGFIX-INTERFACE.md 第 1/2/3/6 节）。

- 问题一：门户资料（显示名/头像）DB 方法与 4 个 profile API 的边界；
- 问题二：sweep/prune 节流、stats_cached 复用、claim 空表不写；
- 问题三：release_meta 导入与 attest 的 release_mismatch 拒绝；
- 问题六：门户用户列表、禁用后登录失败、强制脱绑释放设备。

LiveServer 复用 tests/test_api_hardening.py 的形状；本文件只用 requests
直连服务器，避免与被并行修改的 core/api_client.py 耦合。
"""

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import requests

from core import offline, security
from core.api_client import ApiClient
from core.config import Config
from core.database import Database
from server import api as server_api
from tests.test_api_hardening import LiveServer, login_ready

PORTAL_PASSWORD = "PortalPass#2026"
ADMIN_PASSWORD = "OpsPass#2026"
HASH_A = "a" * 64
HASH_B = "b" * 64
RELEASE_ID = "1a2b3c4d5e6f708192a3b4c5d6e7f809"
AVATAR_LIMIT = 256 * 1024


class _SqlSpy:
    """Wrap the sqlite connection and remember every statement executed."""

    def __init__(self, conn):
        self._conn = conn
        self.statements: list[str] = []

    def execute(self, sql, params=()):
        self.statements.append(" ".join(str(sql).split()))
        return self._conn.execute(sql, params)

    def __getattr__(self, name):
        return getattr(self._conn, name)


class BugfixBackendTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.config = Config("server", self.root / "server_config.json")
        # 模块级登录/限流桶跨测试共享，先清空再启动。
        with server_api._guard_lock:
            server_api._rate_guard.clear()
            server_api._login_guard.clear()
        self.db = Database(
            self.root / "license.db", self.config.security["secret_key"]
        )
        _, self.bootstrap = self.db.ensure_default_admin()
        self.live = LiveServer(self.config, self.db)
        self.live.start()
        self.base = f"http://127.0.0.1:{self.live.port}"

    def tearDown(self):
        self.live.stop()
        self.db.close()
        self.tmp.cleanup()

    # -- helpers ---------------------------------------------------------
    def api(self, method, path, body=None, token="", expect=200, params=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        response = requests.request(
            method,
            self.base + path,
            data=data,
            headers=headers,
            params=params,
            timeout=10,
        )
        self.assertEqual(
            response.status_code,
            expect,
            f"{method} {path} -> {response.status_code}: {response.text[:400]}",
        )
        return response.json() if response.content else {}

    def admin_client(self) -> ApiClient:
        client = ApiClient(
            self.base,
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )
        login_ready(client, self.bootstrap)
        return client

    def create_portal(self, email, display_name="") -> int:
        password_hash, salt = security.hash_password(PORTAL_PASSWORD)
        account_id = self.db.create_portal_account(email, password_hash, salt)
        self.db.mark_portal_email_verified(account_id)
        if display_name:
            self.db.set_portal_display_name(account_id, display_name)
        return account_id

    def portal_login(self, email, password=PORTAL_PASSWORD) -> dict:
        return self.api(
            "POST", "/api/portal/login", {"email": email, "password": password}
        )

    def portal_token(self, email, password=PORTAL_PASSWORD) -> str:
        data = self.portal_login(email, password)
        self.assertTrue(data.get("ok"), data)
        return data["token"]

    # -- 问题一：门户资料 -------------------------------------------------
    def test_portal_profile_crud_and_avatar_boundaries(self):
        account_id = self.create_portal("prof@example.com")
        token = self.portal_token("Prof@Example.com")

        profile = self.api("GET", "/api/portal/profile", token=token)
        self.assertEqual(profile["email"], "prof@example.com")
        self.assertEqual(profile["display_name"], "")
        self.assertTrue(profile["email_verified"])
        self.assertIsNone(profile["avatar"])
        self.api("GET", "/api/portal/profile", expect=401)

        # 显示名去首尾空格，长度 1..32。
        self.assertEqual(
            self.api(
                "PUT",
                "/api/portal/profile",
                {"display_name": "  测试用户  "},
                token=token,
            ),
            {"ok": True},
        )
        self.assertEqual(
            self.api("GET", "/api/portal/profile", token=token)["display_name"],
            "测试用户",
        )
        self.assertEqual(
            self.db.get_portal_profile(account_id)["display_name"], "测试用户"
        )
        self.api(
            "PUT", "/api/portal/profile", {"display_name": "   "}, token=token,
            expect=400,
        )
        self.api(
            "PUT", "/api/portal/profile", {"display_name": "x" * 33}, token=token,
            expect=400,
        )
        self.assertEqual(
            self.db.get_portal_profile(account_id)["display_name"], "测试用户"
        )

        # 头像：白名单 mime + base64 往返。
        payload = (
            b"\x89PNG\r\n\x1a\n"
            + b"\x00\x00\x00\x0d"
            + b"IHDR"
            + (2).to_bytes(4, "big")
            + (2).to_bytes(4, "big")
            + b"\x08\x06\x00\x00\x00"
            + b"z" * 20
        )
        self.assertEqual(
            self.api(
                "POST",
                "/api/portal/avatar",
                {
                    "mime": "image/png",
                    "data_base64": base64.b64encode(payload).decode("ascii"),
                },
                token=token,
            ),
            {"ok": True},
        )
        profile = self.api("GET", "/api/portal/profile", token=token)
        self.assertEqual(profile["avatar"]["mime"], "image/png")
        self.assertEqual(base64.b64decode(profile["avatar"]["data_base64"]), payload)
        self.assertEqual(self.db.get_portal_avatar(account_id), ("image/png", payload))
        self.assertEqual(
            self.db.get_portal_profile(account_id)["avatar_size"], len(payload)
        )

        # login/me 响应同样带 display_name 与 avatar。
        login = self.portal_login("prof@example.com")
        self.assertEqual(login["display_name"], "测试用户")
        self.assertEqual(login["avatar"]["mime"], "image/png")
        me = self.api("GET", "/api/portal/me", token=login["token"])
        self.assertEqual(me["display_name"], "测试用户")
        self.assertEqual(base64.b64decode(me["avatar"]["data_base64"]), payload)

        # mime 白名单与 base64 校验。
        self.api(
            "POST", "/api/portal/avatar",
            {"mime": "image/gif", "data_base64": "QUJD"}, token=token, expect=400,
        )
        self.api(
            "POST", "/api/portal/avatar",
            {"mime": "image/png", "data_base64": "not*base64"}, token=token,
            expect=400,
        )
        self.api(
            "POST", "/api/portal/avatar",
            {"mime": "image/webp", "data_base64": ""}, token=token, expect=400,
        )
        self.assertEqual(self.db.get_portal_avatar(account_id)[1], payload)

        # 256KB 恰好通过（含 base64 放大后的请求体），多 1 字节被拒。
        jpeg_header = (
            b"\xff\xd8"
            + b"\xff\xe0"
            + (16).to_bytes(2, "big")
            + b"\x00" * 14
            + b"\xff\xc0"
            + (17).to_bytes(2, "big")
            + b"\x08"
            + (1).to_bytes(2, "big")
            + (1).to_bytes(2, "big")
            + b"\x03\x01\x11\x00\x02\x11\x00\x03\x11\x00"
        )
        exact_payload = (jpeg_header + b"a" * AVATAR_LIMIT)[:AVATAR_LIMIT]
        exact = base64.b64encode(exact_payload).decode("ascii")
        self.assertEqual(
            self.api(
                "POST", "/api/portal/avatar",
                {"mime": "image/jpeg", "data_base64": exact}, token=token,
            ),
            {"ok": True},
        )
        self.assertEqual(
            self.db.get_portal_profile(account_id)["avatar_size"], AVATAR_LIMIT
        )
        too_big = base64.b64encode(b"a" * (AVATAR_LIMIT + 1)).decode("ascii")
        self.api(
            "POST", "/api/portal/avatar",
            {"mime": "image/jpeg", "data_base64": too_big}, token=token, expect=400,
        )
        # 超限被拒后旧头像保持不变。
        self.assertEqual(
            self.db.get_portal_profile(account_id)["avatar_size"], AVATAR_LIMIT
        )

        self.assertEqual(
            self.api("DELETE", "/api/portal/avatar", token=token), {"ok": True}
        )
        self.assertIsNone(self.api("GET", "/api/portal/profile", token=token)["avatar"])
        self.assertIsNone(self.db.get_portal_avatar(account_id))
        self.api("DELETE", "/api/portal/avatar", expect=401)

    # -- 问题二：性能方法 -------------------------------------------------
    def test_sweep_stats_prune_and_claim_hot_paths(self):
        # sweep_expired：60 秒窗口内只真正执行一次，force 可强制。
        _, keys = self.db.generate_licenses(2, duration_days=1)
        self.db.update_license_expiry(keys[0], "2000-01-01 00:00:00")
        self.assertEqual(self.db.sweep_expired(), 1)
        self.db.update_license_expiry(keys[1], "2000-01-01 00:00:00")
        self.assertEqual(self.db.sweep_expired(), 0)
        self.assertEqual(self.db.sweep_expired(force=True), 1)
        self.assertEqual(self.db.get_license(keys[1])["status"], "expired")

        # stats_cached：ttl 内复用同一份结果，ttl=0 强制刷新。
        stale = self.db.stats_cached(ttl=5)
        self.assertEqual(stale["expired"], 2)
        self.db.generate_licenses(1)
        reused = self.db.stats_cached(ttl=5)
        self.assertEqual(reused, stale)
        self.assertEqual(reused["total"], 2)
        fresh = self.db.stats_cached(ttl=0)
        self.assertEqual(fresh["total"], 3)
        self.assertEqual(fresh["expired"], 2)

        # API 统计走缓存路径。
        client = self.admin_client()
        stats = self.api("GET", "/api/license/stats", token=client.token)
        self.assertEqual(stats["total"], 3)
        self.assertEqual(stats["expired"], 2)

        # prune_nonces：节流窗口内第二次返回 0 且不删除行。
        with self.db._lock:
            self.db._conn.execute(
                "INSERT INTO nonces (nonce, key_code, created_at)"
                " VALUES ('bugfix-n1', '', 1)"
            )
        self.assertEqual(self.db.prune_nonces(100), 1)
        with self.db._lock:
            self.db._conn.execute(
                "INSERT INTO nonces (nonce, key_code, created_at)"
                " VALUES ('bugfix-n2', '', 1)"
            )
        self.assertEqual(self.db.prune_nonces(100), 0)
        self.assertIsNotNone(
            self.db._fetchone("SELECT nonce FROM nonces WHERE nonce = 'bugfix-n2'")
        )

        # claim_due_*：空表只做无锁 SELECT 预检，不开 BEGIN IMMEDIATE。
        spy = _SqlSpy(self.db._conn)
        self.db._conn = spy
        try:
            self.assertEqual(self.db.claim_due_emails(), [])
            self.assertEqual(self.db.claim_due_channel_messages(), [])
        finally:
            self.db._conn = spy._conn
        outbox_sql = [s for s in spy.statements if "outbox" in s]
        # 后台投递线程也可能做同样的预检，只要求全是无锁 SELECT 1。
        self.assertGreaterEqual(len(outbox_sql), 2, spy.statements)
        self.assertTrue(
            all(s.startswith("SELECT 1") for s in outbox_sql), outbox_sql
        )
        self.assertFalse(
            any("BEGIN IMMEDIATE" in s for s in outbox_sql), outbox_sql
        )

    def test_claim_due_paths_still_deliver_when_rows_are_due(self):
        self.db.seed_email_templates(
            {"verify_email": {"subject": "验证码 {{code}}", "body": "{{code}}"}}
        )
        self.assertIsInstance(
            self.db.enqueue_email("due@example.com", "verify_email", {"code": "123456"}),
            int,
        )
        claimed = self.db.claim_due_emails()
        self.assertEqual(len(claimed), 1)
        self.assertEqual(claimed[0]["status"], "sending")
        self.assertEqual(self.db.claim_due_emails(), [])

        channel_id = self.db.create_notification_channel(
            "webhook", "due-channel", "https://example.com/hook"
        )
        self.assertIsInstance(
            self.db.enqueue_channel_message(channel_id, "主题", "内容"), int
        )
        messages = self.db.claim_due_channel_messages()
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["status"], "sending")
        self.assertEqual(self.db.claim_due_channel_messages(), [])

    # -- 问题三：release_meta 与 attest -----------------------------------
    def _signed_manifest(self, release_id: str) -> tuple[dict, bytes, str]:
        from core import integrity

        private_key, public_key = offline.generate_keypair()
        self.config.security["release_public_key"] = public_key
        manifest = {
            "format": integrity.MANIFEST_FORMAT,
            "version": "9.9.9",
            "release_id": release_id,
            "generated_at": "2026-10-08T12:00:00+08:00",
            "apps": {
                "verification": {
                    "path": "verification.exe",
                    "sha256": HASH_B,
                    "size": 4,
                }
            },
            "folder": {},
        }
        raw = json.dumps(
            manifest, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        return manifest, raw, offline.sign_message(private_key, raw)

    def test_release_meta_import_and_attest_release_mismatch(self):
        client = self.admin_client()
        _, raw, signature = self._signed_manifest(RELEASE_ID)
        imported = self.api(
            "POST",
            "/api/release/import",
            {"manifest": raw.decode("utf-8"), "signature": signature},
            token=client.token,
        )
        self.assertEqual(imported, {"ok": True, "imported": 1})

        digest = hashlib.sha256(raw).hexdigest()
        meta = self.db.match_active_release_meta(RELEASE_ID)
        self.assertIsNotNone(meta)
        self.assertEqual(meta["manifest_sha256"], digest)
        self.assertEqual(meta["version"], "9.9.9")
        self.assertEqual(meta["active"], 1)
        self.assertEqual(self.db.count_active_release_meta(), 1)
        self.assertIsNotNone(self.db.match_release_hash(HASH_B, "verification.exe"))

        def attest(**extra):
            body = {
                "role": "verification",
                "exe_name": "verification.exe",
                "exe_hash": HASH_B,
                "version": "9.9.9",
                "machine_code": "MACHINE-REL",
                "local_check": {"ok": True},
            }
            body.update(extra)
            return self.api("POST", "/api/client/attest", body)

        matching = attest(release_id=RELEASE_ID, manifest_sha256=digest)
        self.assertTrue(matching["ok"], matching)
        self.assertTrue(matching["attest_token"])
        # manifest_sha256 允许为空（只校验 release_id）。
        self.assertTrue(attest(release_id=RELEASE_ID)["ok"])
        # 发布标识缺失/未知、清单哈希不一致都要被拒并留下告警。
        self.assertEqual(
            attest(release_id="f" * 32),
            {"ok": False, "code": "release_mismatch"},
        )
        self.assertEqual(
            attest(release_id=RELEASE_ID, manifest_sha256="c" * 64),
            {"ok": False, "code": "release_mismatch"},
        )
        self.assertEqual(attest()["code"], "release_mismatch")
        items, total = self.db.list_tamper_events()
        self.assertEqual(total, 3)
        self.assertTrue(all(item["reason"] == "release_mismatch" for item in items))
        self.assertEqual(
            self.db.list_logs(action="完整性校验失败")[0]["detail"],
            "发布标识与服务器记录不一致",
        )

        # 没有 active release_meta 时不启用发布绑定（老清单/未导入）。
        self.db._execute("UPDATE release_meta SET active = 0")
        self.assertEqual(self.db.count_active_release_meta(), 0)
        self.assertTrue(attest(release_id="0" * 32, manifest_sha256="d" * 64)["ok"])

    def test_startup_import_helper_writes_release_meta(self):
        """server/main.py 可复用 server.api.import_release_manifest。"""
        client = self.admin_client()
        self.assertEqual(client.me()["role"], "master")
        manifest, raw, _ = self._signed_manifest(RELEASE_ID)
        imported = server_api.import_release_manifest(
            self.db, manifest, raw, note="startup auto-import"
        )
        self.assertEqual(imported, 1)
        meta = self.db.match_active_release_meta(RELEASE_ID)
        self.assertEqual(meta["manifest_sha256"], hashlib.sha256(raw).hexdigest())
        row = self.db.match_release_hash(HASH_B, "verification.exe")
        self.assertEqual(row["note"], "startup auto-import (verification)")

    # -- 问题六：用户管理 -------------------------------------------------
    def test_admin_portal_accounts_list_disable_and_force_unbind(self):
        client = self.admin_client()
        key = client.generate_licenses(
            count=1, duration_days=30, max_devices=1
        )["keys"][0]
        lic = self.db.get_license(key)
        alice = self.create_portal("alice@example.com", "Alice")
        bob = self.create_portal("bob@example.com", "Bob")
        self.assertTrue(self.db.bind_portal_license(alice, lic["id"], key))
        expiry = security.compute_expiry(30, "day")
        self.db.update_license_expiry(key, expiry)
        self.db.activate_atomic(
            lic["id"], key, "MACHINE-ALICE", "pc", expiry, "session"
        )
        alice_token = self.portal_token("alice@example.com")

        listing = self.api("GET", "/api/admin/portal_accounts", token=client.token)
        self.assertEqual(listing["total"], 2)
        item = next(row for row in listing["items"] if row["id"] == alice)
        self.assertEqual(item["email"], "alice@example.com")
        self.assertEqual(item["display_name"], "Alice")
        self.assertEqual(item["status"], "active")
        self.assertEqual(item["bound_key"], key)
        self.assertEqual(item["binding_status"], "bound")
        self.assertEqual(item["license_status"], "active")
        self.assertEqual(item["expires_at"], expiry)
        bob_item = next(row for row in listing["items"] if row["id"] == bob)
        self.assertIsNone(bob_item["bound_key"])
        self.assertIsNone(bob_item["license_status"])

        # keyword 同时匹配邮箱与显示名；status 过滤与分页生效。
        by_email = self.api(
            "GET", "/api/admin/portal_accounts", token=client.token,
            params={"keyword": "ALI"},
        )
        self.assertEqual([row["id"] for row in by_email["items"]], [alice])
        by_name = self.api(
            "GET", "/api/admin/portal_accounts", token=client.token,
            params={"keyword": "Bob"},
        )
        self.assertEqual([row["id"] for row in by_name["items"]], [bob])
        disabled = self.api(
            "GET", "/api/admin/portal_accounts", token=client.token,
            params={"status": "disabled"},
        )
        self.assertEqual((disabled["items"], disabled["total"]), ([], 0))
        page = self.api(
            "GET", "/api/admin/portal_accounts", token=client.token,
            params={"limit": 1, "offset": 1},
        )
        self.assertEqual(len(page["items"]), 1)
        self.assertEqual(page["total"], 2)
        self.api(
            "GET", "/api/admin/portal_accounts", token=client.token,
            params={"status": "bogus"}, expect=400,
        )
        self.api("GET", "/api/admin/portal_accounts", expect=401)

        # 禁用：auth_version+1，旧 token 立即失效，登录被拒。
        self.assertEqual(
            self.api(
                "POST", f"/api/admin/portal_accounts/{alice}/status",
                {"status": "disabled"}, token=client.token,
            ),
            {"ok": True},
        )
        self.assertEqual(
            self.db.get_portal_account_by_id(alice)["status"], "disabled"
        )
        # 禁用后旧 token 立刻被挡；重新启用也回不去（auth_version+1）。
        self.api("GET", "/api/portal/profile", token=alice_token, expect=403)
        denied = self.portal_login("alice@example.com")
        self.assertFalse(denied["ok"])
        self.assertEqual(denied["code"], "invalid_credentials")

        # 普通 admin（非 master）同样能改状态与列表。
        self.db.create_admin("ops", ADMIN_PASSWORD, role="admin")
        ops = ApiClient(
            self.base,
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )
        ops.login("ops", ADMIN_PASSWORD)
        self.assertEqual(
            self.api(
                "POST", f"/api/admin/portal_accounts/{alice}/status",
                {"status": "active"}, token=ops.token,
            ),
            {"ok": True},
        )
        self.api("GET", "/api/portal/profile", token=alice_token, expect=401)
        self.assertTrue(self.portal_login("alice@example.com")["ok"])
        self.api(
            "POST", f"/api/admin/portal_accounts/{alice}/status",
            {"status": "bogus"}, token=ops.token, expect=400,
        )
        self.api(
            "POST", "/api/admin/portal_accounts/999999/status",
            {"status": "disabled"}, token=ops.token, expect=404,
        )

        # 强制脱绑：释放设备 + 写历史 + 解绑，重复调用返回 404。
        self.assertEqual(
            self.api(
                "POST", f"/api/admin/portal_accounts/{alice}/unbind", {},
                token=client.token,
            ),
            {"ok": True},
        )
        self.assertEqual(
            self.db.get_activation(key, "MACHINE-ALICE")["status"], "unbound"
        )
        self.assertIsNone(self.db.get_portal_binding(alice))
        history = self.db._fetchone(
            "SELECT * FROM portal_binding_history ORDER BY id DESC LIMIT 1"
        )
        self.assertEqual(history["action"], "unbind")
        self.assertEqual(history["actor"], "admin")
        self.assertIn("强制脱绑", history["reason"])
        self.assertTrue(self.db.list_logs(action="强制脱绑门户账号"))
        self.api(
            "POST", f"/api/admin/portal_accounts/{alice}/unbind", {},
            token=client.token, expect=404,
        )
        self.api(
            "POST", "/api/admin/portal_accounts/999999/unbind", {},
            token=client.token, expect=404,
        )

    def test_unbound_account_reports_null_binding_columns(self):
        account_id = self.create_portal("plain@example.com", "Plain")
        listing = self.api(
            "GET", "/api/admin/portal_accounts",
            token=self.admin_client().token,
        )
        item = next(row for row in listing["items"] if row["id"] == account_id)
        for column in (
            "bound_key",
            "binding_status",
            "license_status",
            "expires_at",
        ):
            self.assertIsNone(item[column], column)
        self.assertEqual(item["email_verified_at"] is not None, True)
        self.assertIsNotNone(item["created_at"])


if __name__ == "__main__":
    unittest.main()
