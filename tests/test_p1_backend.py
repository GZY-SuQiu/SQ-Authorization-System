"""P1 Backend contract tests: accounts, e-mail queue, portal login and binding.

These tests cover the Backend side of docs/P1-INTERFACE.md (sections 3-6):

- core/database.py  e-mail outbox, action codes, portal accounts/bindings,
                    renewal requests and risk/ip events;
- core/security.py  portal tokens and action-code hashing;
- server/api.py     admin e-mail, portal endpoints and SMTP helpers.

The live-server fixture mirrors tests/test_api_hardening.py but injects a fake
mailer so no SMTP traffic leaves the process.
"""

import json
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path

import requests
import uvicorn

from core import security
from core.api_client import ApiClient
from core.config import Config
from core.database import Database
from server.api import create_app
from server import api as server_api
from tests.test_api_hardening import login_ready


PORTAL_PASSWORD = "PortalPass#2026"
ADMIN_RESET_PASSWORD = "AdminNewPass#2026"


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class FakeMailer:
    """Records enqueue calls; implements the documented Mailer surface."""

    def __init__(self, enabled: bool = True):
        self.enabled = bool(enabled)
        self.calls: list[dict] = []
        self.sent: list[dict] = []
        self.started = 0
        self.stopped = 0

    def start(self) -> None:
        self.started += 1

    def stop(self, timeout: float = 5.0) -> None:
        self.stopped += 1

    def enqueue(self, to_email, template_code, variables=None, dedupe_key=""):
        self.calls.append(
            {
                "to_email": str(to_email or ""),
                "template_code": str(template_code or ""),
                "variables": dict(variables or {}),
                "dedupe_key": str(dedupe_key or ""),
            }
        )
        return len(self.calls)

    def process_due(self, limit: int = 20) -> int:
        return 0

    def send_now(self, to_email, template_code, variables=None) -> None:
        if not self.enabled:
            raise RuntimeError("SMTP 未启用或未配置")
        self.sent.append({"to_email": to_email, "template_code": template_code})

    def status(self) -> dict:
        return {
            "enabled": self.enabled,
            "host": "fake.smtp",
            "port": 2525,
            "from_email": "no-reply@example.com",
            "pending": 0,
            "sending": 0,
            "sent": len(self.sent),
            "failed": 0,
            "dead": 0,
            "last_error": None,
        }

    def code_for(self, email: str, template_code: str = "") -> str:
        """Return the newest 6-digit code queued for this address."""
        for call in reversed(self.calls):
            if call["to_email"] != email:
                continue
            if template_code and call["template_code"] != template_code:
                continue
            code = str(call["variables"].get("code") or "")
            if code:
                return code
        raise AssertionError(f"没有为 {email} 记录验证码邮件：{self.calls}")


class LiveServerWithMailer:
    """LiveServer variant that can inject the mailer into create_app."""

    def __init__(self, config: Config, db: Database, mailer):
        self.port = _free_port()
        app = create_app(config, db, mailer=mailer)
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

    def start(self) -> None:
        self.thread.start()
        for _ in range(100):
            if self.server.started:
                return
            time.sleep(0.05)
        raise RuntimeError("测试服务器启动超时")

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5)


class P1DatabaseTests(unittest.TestCase):
    """Direct coverage for the new Database methods (contract section 3/4)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.db = Database(self.root / "license.db")

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def test_email_outbox_dedupe_claim_and_status_flow(self):
        self.db.seed_email_templates(
            {
                "verify_email": {
                    "subject": "验证码 {{code}}",
                    "body": "邮箱 {{email}}，验证码 {{code}}，{{expires_minutes}} 分钟内有效。",
                }
            }
        )
        # Seeding only fills missing codes.
        self.assertEqual(
            self.db.seed_email_templates(
                {
                    "verify_email": {"subject": "ignored", "body": "ignored"},
                    "reset_password": {"subject": "重置 {{code}}", "body": "{{code}}"},
                }
            ),
            1,
        )
        template = self.db.get_email_template("verify_email")
        self.assertIn("验证码", template["subject"])

        first = self.db.enqueue_email(
            "User@Example.com",
            "verify_email",
            {"code": "123456", "email": "<script>x</script>", "expires_minutes": 10},
        )
        self.assertIsInstance(first, int)
        # dedupe_key conflicts return None and write nothing.
        self.assertIsInstance(
            self.db.enqueue_email(
                "user@example.com", "verify_email", {"code": "123456"}, dedupe_key="k1"
            ),
            int,
        )
        self.assertIsNone(
            self.db.enqueue_email(
                "user@example.com", "verify_email", {"code": "999999"}, dedupe_key="k1"
            )
        )

        claimed = self.db.claim_due_emails()
        self.assertEqual(len(claimed), 2)
        row = claimed[0]
        self.assertEqual(row["status"], "sending")
        self.assertEqual(row["to_email"], "user@example.com")
        self.assertIn("123456", row["subject"])
        # Template variables are HTML-escaped when rendered.
        self.assertIn("&lt;script&gt;", row["body"])
        # A claimed row is no longer due.
        self.assertEqual(self.db.claim_due_emails(), [])

        # Failed rows wait for their retry timestamp.
        self.db.mark_email_failed(first, "smtp down", "2999-01-01 00:00:00")
        self.assertEqual(self.db.email_outbox_stats()["failed"], 1)
        self.assertEqual(self.db.claim_due_emails(), [])
        self.db.mark_email_failed(first, "smtp down", "2000-01-01 00:00:00")
        self.assertEqual(len(self.db.claim_due_emails()), 1)
        self.db.mark_email_sent(first)
        stats = self.db.email_outbox_stats()
        self.assertEqual(stats["sent"], 1)
        self.assertIsNone(stats["last_error"])

        # The fifth failure moves a row to dead even without the flag.
        second = self.db.enqueue_email("user@example.com", "verify_email", {"code": "222222"})
        for _ in range(5):
            self.db.mark_email_failed(second, "permanent", None)
        second_row = self.db.list_email_outbox()[0][0]
        self.assertEqual(second_row["status"], "dead")
        self.assertEqual(second_row["attempts"], 5)

        items, total = self.db.list_email_outbox("dead")
        self.assertEqual(total, 1)
        self.assertEqual(items[0]["id"], second)
        self.assertEqual(self.db.list_email_outbox("sent")[1], 1)

    def test_action_code_attempts_expiry_and_one_time_use(self):
        secret = "unit-secret"
        good = security.hash_action_code(secret, "123456")
        self.assertTrue(security.verify_action_code(secret, "123456", good))
        self.assertFalse(security.verify_action_code(secret, "654321", good))
        self.assertFalse(security.verify_action_code(secret, "123456", ""))

        self.db.create_action_code(
            "admin", 1, "A@Example.com", "verify_email", good, "2999-01-01 00:00:00"
        )
        self.assertEqual(
            self.db.count_action_codes("a@example.com", "verify_email", "2000-01-01 00:00:00"),
            1,
        )
        wrong = security.hash_action_code(secret, "000000")
        # Four wrong guesses leave the code alive...
        for _ in range(4):
            self.assertFalse(
                self.db.consume_action_code("admin", "a@example.com", "verify_email", wrong)
            )
        self.assertTrue(
            self.db.consume_action_code("admin", "a@example.com", "verify_email", good)
        )
        # ...and the code is one-time.
        self.assertFalse(
            self.db.consume_action_code("admin", "a@example.com", "verify_email", good)
        )

        # Five wrong guesses burn a fresh code.
        self.db.create_action_code(
            "admin", 1, "a@example.com", "reset_password", good, "2999-01-01 00:00:00"
        )
        for _ in range(5):
            self.assertFalse(
                self.db.consume_action_code("admin", "a@example.com", "reset_password", wrong)
            )
        self.assertFalse(
            self.db.consume_action_code("admin", "a@example.com", "reset_password", good)
        )

        # Expired codes never match.
        self.db.create_action_code(
            "admin", 1, "a@example.com", "verify_email", good, "2000-01-01 00:00:00"
        )
        self.assertFalse(
            self.db.consume_action_code("admin", "a@example.com", "verify_email", good)
        )
        self.assertEqual(
            self.db.count_action_codes("a@example.com", "verify_email", "2990-01-01 00:00:00"),
            0,
        )

    def test_admin_email_helpers(self):
        admin_id = self.db.create_admin("mailer-admin", "Passw0rd!", role="admin")
        self.db.create_admin("other-admin", "Passw0rd!", role="admin")
        self.db.set_admin_email(admin_id, "Admin@Example.com")
        admin = self.db.get_admin_by_email("admin@example.com")
        self.assertEqual(admin["id"], admin_id)
        self.assertEqual(admin["email"], "admin@example.com")
        self.assertIsNone(admin["email_verified_at"])
        self.assertEqual(self.db.list_verified_admin_emails(), [])

        self.db.mark_admin_email_verified(admin_id)
        self.assertEqual(self.db.list_verified_admin_emails(), ["admin@example.com"])

        # Re-setting the same verified address keeps the verification.
        self.db.set_admin_email(admin_id, "admin@example.com")
        self.assertTrue(self.db.get_admin_by_id(admin_id)["email_verified_at"])

        # A different address clears it.
        self.db.set_admin_email(admin_id, "new@example.com")
        self.assertIsNone(self.db.get_admin_by_id(admin_id)["email_verified_at"])

        # The unique index protects the column (case-insensitive by storage).
        other_id = self.db.get_admin("other-admin")["id"]
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.set_admin_email(other_id, "NEW@example.com")

    def test_portal_binding_release_and_history(self):
        _, keys = self.db.generate_licenses(1, duration_days=30, max_devices=1)
        key = keys[0]
        lic = self.db.get_license(key)
        password_hash, salt = security.hash_password(PORTAL_PASSWORD)
        account_a = self.db.create_portal_account("a@example.com", password_hash, salt)
        account_b = self.db.create_portal_account("b@example.com", password_hash, salt)

        self.assertTrue(self.db.bind_portal_license(account_a, lic["id"], key))
        binding = self.db.get_portal_binding(account_a)
        self.assertEqual(binding["status"], "bound")
        self.assertEqual(self.db.get_binding_by_license(lic["id"])["account_id"], account_a)
        # One licence, one account.
        self.assertFalse(self.db.bind_portal_license(account_b, lic["id"], key))
        self.assertIsNone(self.db.get_portal_binding(account_b))

        self.db.activate_atomic(lic["id"], key, "MACHINE-A", "pc-a", None, "session")
        # Unbinding releases the device seats and records history.
        self.assertEqual(self.db.release_license_activations(lic["id"]), 1)
        self.assertEqual(self.db.get_activation(key, "MACHINE-A")["status"], "unbound")
        self.assertTrue(self.db.unbind_portal_license(account_a, "expired", "user"))
        self.assertIsNone(self.db.get_portal_binding(account_a))
        self.db.add_binding_history(account_a, lic["id"], key, "unbind", "expired", "user")
        row = self.db._fetchone("SELECT * FROM portal_binding_history ORDER BY id DESC")
        self.assertEqual(row["action"], "unbind")
        self.assertEqual(row["reason"], "expired")

        # A licence can be rebound once the stale row is released.
        self.assertTrue(self.db.bind_portal_license(account_b, lic["id"], key))
        self.assertEqual(self.db.get_portal_binding(account_b)["account_id"], account_b)

        # Portal passwords bump auth_version.
        before = self.db.get_portal_account("b@example.com")["auth_version"]
        self.db.set_portal_password(account_b, password_hash, salt)
        self.assertEqual(
            self.db.get_portal_account("b@example.com")["auth_version"], before + 1
        )

    def test_renewal_and_risk_events(self):
        _, keys = self.db.generate_licenses(1)
        key = keys[0]
        lic = self.db.get_license(key)
        request_id = self.db.create_renewal_request(1, lic["id"], key, "希望续费")
        items, total = self.db.list_renewal_requests()
        self.assertEqual(total, 1)
        self.assertEqual(items[0]["id"], request_id)
        self.assertEqual(items[0]["status"], "pending")

        self.db.add_risk_event("ip_jump", "warning", key, "M1", "1.2.3.4", "detail")
        events, total = self.db.list_risk_events()
        self.assertEqual(total, 1)
        self.assertEqual(events[0]["kind"], "ip_jump")

        # count_ip_changes counts distinct networks, not raw hits.
        self.db.add_activation_ip_event(lic["id"], key, "M1", "1.2.3.4", "1.2.3.0/24")
        self.db.add_activation_ip_event(lic["id"], key, "M1", "1.2.3.5", "1.2.3.0/24")
        self.db.add_activation_ip_event(lic["id"], key, "M1", "9.9.9.9", "9.9.9.0/24")
        self.assertEqual(self.db.count_ip_changes(key, "2000-01-01 00:00:00"), 2)
        self.assertEqual(self.db.count_ip_changes(key, "2990-01-01 00:00:00"), 0)


class P1ApiTestBase(unittest.TestCase):
    """Live server with an injected fake mailer."""

    mailer_enabled = True

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.root = Path(self.tmp.name)
        self.config = Config("server", self.root / "server_config.json")
        # The e-mail/login rate-limit buckets live at module scope, so a test
        # that just used "admin@example.com" must not starve the next one.
        with server_api._guard_lock:
            server_api._rate_guard.clear()
            server_api._login_guard.clear()
        # Attestation has its own suite; portal binding here must work without
        # a registered release hash.
        self.config.data["security"]["attest_mode"] = "off"
        self.db = Database(
            self.root / "license.db", self.config.security["secret_key"]
        )
        _, self.bootstrap = self.db.ensure_default_admin()
        self.mailer = FakeMailer(enabled=self.mailer_enabled)
        self.live = LiveServerWithMailer(self.config, self.db, self.mailer)
        self.live.start()
        self.base = f"http://127.0.0.1:{self.live.port}"
        self.client = ApiClient(
            self.base,
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )
        login_ready(self.client, self.bootstrap)
        self.admin_token = self.client.token

    def tearDown(self):
        self.live.stop()
        self.db.close()
        self.tmp.cleanup()

    def api(self, method: str, path: str, body=None, token: str = "", expect: int = 200):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = None
        if method != "GET":
            data = json.dumps(body or {}, ensure_ascii=False).encode("utf-8")
        response = requests.request(
            method, self.base + path, data=data, headers=headers, timeout=10
        )
        self.assertEqual(
            response.status_code,
            expect,
            f"{method} {path} -> {response.status_code}: {response.text}",
        )
        return response.json() if response.content else {}

    # -- helpers ---------------------------------------------------------
    def admin_post(self, path, body=None, expect=200, token=None):
        return self.api(
            "POST",
            path,
            body,
            token=self.admin_token if token is None else token,
            expect=expect,
        )

    def set_and_verify_admin_email(self, email: str) -> None:
        response = self.admin_post("/api/admin/email/set", {"email": email})
        self.assertEqual(response["email"], email)
        self.assertEqual(response["expires_in"], 600)
        code = self.mailer.code_for(email, "verify_email")
        self.assertEqual(
            self.admin_post("/api/admin/email/verify", {"code": code}), {"ok": True}
        )

    def register_portal(self, email: str, password: str = PORTAL_PASSWORD) -> str:
        sent = self.api(
            "POST",
            "/api/portal/email/send_code",
            {"email": email, "purpose": "register"},
        )
        self.assertTrue(sent.get("ok"), sent)
        code = self.mailer.code_for(email, "verify_email")
        data = self.api(
            "POST",
            "/api/portal/register",
            {"email": email, "code": code, "password": password},
        )
        self.assertTrue(data.get("ok"), data)
        return data["token"]


class P1ApiTests(P1ApiTestBase):
    def test_admin_email_set_verify_and_me(self):
        me = self.client.me()
        self.assertEqual(me["email"], "")
        self.assertFalse(me["email_verified"])

        response = self.admin_post("/api/admin/email/set", {"email": "Admin@Example.COM"})
        self.assertEqual(
            response,
            {"ok": True, "email": "admin@example.com", "expires_in": 600},
        )
        call = self.mailer.calls[-1]
        self.assertEqual(call["to_email"], "admin@example.com")
        self.assertEqual(call["template_code"], "verify_email")
        self.assertRegex(str(call["variables"].get("code")), r"^\d{6}$")

        me = self.client.me()
        self.assertEqual(me["email"], "admin@example.com")
        self.assertFalse(me["email_verified"])

        self.admin_post("/api/admin/email/verify", {"code": "000000"}, expect=400)
        code = self.mailer.code_for("admin@example.com", "verify_email")
        self.assertEqual(
            self.admin_post("/api/admin/email/verify", {"code": code}), {"ok": True}
        )
        self.assertTrue(self.client.me()["email_verified"])
        # The code cannot be used twice.
        self.admin_post("/api/admin/email/verify", {"code": code}, expect=400)

        # Form validation keeps malformed addresses and codes out.
        self.admin_post("/api/admin/email/set", {"email": "not-an-email"}, expect=422)
        self.admin_post("/api/admin/email/verify", {"code": "12"}, expect=422)

        # Everything above is audited.
        self.assertTrue(self.db.list_logs(action="设置管理员邮箱"))
        self.assertTrue(self.db.list_logs(action="验证管理员邮箱"))

    def test_admin_forgot_password_is_enumeration_safe_and_resets(self):
        self.set_and_verify_admin_email("admin@example.com")
        before = len(self.mailer.calls)

        unknown = self.api(
            "POST", "/api/admin/password/forgot", {"email": "nobody@example.com"}
        )
        self.assertEqual(unknown, {"ok": True})
        self.assertEqual(len(self.mailer.calls), before)

        known = self.api(
            "POST", "/api/admin/password/forgot", {"email": "Admin@Example.com"}
        )
        self.assertEqual(known, {"ok": True})
        call = self.mailer.calls[-1]
        self.assertEqual(call["template_code"], "reset_password")
        self.assertEqual(call["to_email"], "admin@example.com")
        code = call["variables"]["code"]

        old_token = self.admin_token
        self.api(
            "POST",
            "/api/admin/password/reset",
            {
                "email": "admin@example.com",
                "code": code,
                "new_password": ADMIN_RESET_PASSWORD,
            },
        )
        # auth_version was bumped, so the old token is dead.
        self.api("GET", "/api/admin/me", token=old_token, expect=401)
        fresh = ApiClient(
            self.base,
            response_public_key=self.config.security["response_public_key"],
            response_key_id=self.config.security["response_key_id"],
        )
        login = fresh.login("admin", ADMIN_RESET_PASSWORD)
        self.assertTrue(login["token"])
        self.assertEqual(fresh.me()["username"], "admin")

        # A weak password never consumes the code path.
        self.api(
            "POST",
            "/api/admin/password/reset",
            {"email": "admin@example.com", "code": "123456", "new_password": "short"},
            expect=422,
        )

    def test_portal_register_login_me_and_token_namespaces(self):
        token = self.register_portal("user@example.com")

        me = self.api("GET", "/api/portal/me", token=token)
        self.assertTrue(me["ok"])
        self.assertEqual(me["email"], "user@example.com")
        self.assertTrue(me["email_verified"])
        self.assertIsNone(me["binding"])

        login = self.api(
            "POST",
            "/api/portal/login",
            {"email": "User@Example.com", "password": PORTAL_PASSWORD},
        )
        self.assertTrue(login["ok"])
        self.assertEqual(login["expires_in"], 43200)
        self.assertEqual(login["email"], "user@example.com")
        self.assertIsNone(login["binding"])

        bad = self.api(
            "POST",
            "/api/portal/login",
            {"email": "user@example.com", "password": "WrongPass123"},
        )
        self.assertEqual(bad["code"], "invalid_credentials")

        # A portal token never opens admin endpoints, and the admin token
        # never opens portal endpoints.
        self.api("GET", "/api/admin/me", token=token, expect=401)
        self.api("GET", "/api/portal/me", token=self.admin_token, expect=401)

        # Registering an existing address says so without burning a code.
        duplicate = self.api(
            "POST",
            "/api/portal/email/send_code",
            {"email": "user@example.com", "purpose": "register"},
        )
        self.assertEqual(duplicate, {"ok": False, "code": "already_registered"})

        # Portal password reset bumps auth_version and kills the old token.
        self.api(
            "POST",
            "/api/portal/email/send_code",
            {"email": "user@example.com", "purpose": "reset"},
            token=token,
        )
        code = self.mailer.code_for("user@example.com", "reset_password")
        self.api(
            "POST",
            "/api/portal/password/reset",
            {
                "email": "user@example.com",
                "code": code,
                "new_password": "PortalPass#2027",
            },
        )
        self.api("GET", "/api/portal/me", token=token, expect=401)
        relogin = self.api(
            "POST",
            "/api/portal/login",
            {"email": "user@example.com", "password": "PortalPass#2027"},
        )
        self.assertTrue(relogin["ok"])

    def test_portal_bind_conflicts_and_unbind_release(self):
        generated = self.client.generate_licenses(
            count=1, duration_days=30, max_devices=1
        )
        key = generated["keys"][0]
        token_a = self.register_portal("a@example.com")
        token_b = self.register_portal("b@example.com")

        # Unknown keys cannot be bound.
        invalid = self.api(
            "POST",
            "/api/portal/bind",
            {
                "key_code": "GSQ-AAAAA-AAAAA-AAAAA-AAAAA",
                "machine_code": "MACHINE-0",
            },
            token=token_a,
        )
        self.assertEqual(invalid["code"], "invalid_license")

        bound = self.api(
            "POST",
            "/api/portal/bind",
            {
                "key_code": key,
                "machine_code": "MACHINE-A",
                "device_name": "pc-a",
            },
            token=token_a,
        )
        self.assertTrue(bound["ok"])
        self.assertEqual(bound["binding"]["key_code"], key)
        self.assertTrue(bound["activation"]["ok"])
        self.assertEqual(
            self.api("GET", "/api/portal/me", token=token_a)["binding"]["key_code"],
            key,
        )

        # One account, one key; one key, one account.
        self.api(
            "POST",
            "/api/portal/bind",
            {"key_code": key, "machine_code": "MACHINE-A2"},
            token=token_a,
            expect=409,
        )
        self.api(
            "POST",
            "/api/portal/bind",
            {"key_code": key, "machine_code": "MACHINE-B"},
            token=token_b,
            expect=409,
        )

        # A valid licence cannot be released by the user.
        denied = self.api("POST", "/api/portal/unbind", {}, token=token_a, expect=409)
        self.assertEqual(denied["detail"], "授权仍有效，不能自助脱绑，请联系管理员")

        # Once the key is revoked the device seats are released.
        self.client.revoke_license(key)
        self.assertEqual(self.api("POST", "/api/portal/unbind", {}, token=token_a), {"ok": True})
        self.assertEqual(self.db.get_activation(key, "MACHINE-A")["status"], "unbound")
        self.assertIsNone(self.api("GET", "/api/portal/me", token=token_a)["binding"])
        history = self.db._fetchone(
            "SELECT * FROM portal_binding_history ORDER BY id DESC LIMIT 1"
        )
        self.assertEqual(history["action"], "unbind")
        self.assertTrue(self.db.list_logs(action="门户绑定"))
        self.assertTrue(self.db.list_logs(action="门户脱绑"))

    def test_portal_renew_request_writes_row(self):
        generated = self.client.generate_licenses(count=1, duration_days=30)
        key = generated["keys"][0]
        token = self.register_portal("renew@example.com")
        # No binding yet -> explicit error.
        self.api("POST", "/api/portal/renew_request", {"note": "x"}, token=token, expect=400)
        self.api(
            "POST",
            "/api/portal/bind",
            {"key_code": key, "machine_code": "MACHINE-R", "device_name": "pc-r"},
            token=token,
        )
        response = self.api(
            "POST", "/api/portal/renew_request", {"note": "希望续费一年"}, token=token
        )
        self.assertTrue(response["ok"])
        items, total = self.db.list_renewal_requests()
        self.assertEqual(total, 1)
        self.assertEqual(items[0]["note"], "希望续费一年")
        self.assertEqual(items[0]["key_code"], key)

    def test_mailer_lifecycle_and_smtp_endpoints(self):
        # create_app appended start/stop hooks and the fake mailer saw them.
        self.assertGreaterEqual(self.mailer.started, 1)
        status = self.api("GET", "/api/smtp/status", token=self.admin_token)
        self.assertTrue(status["enabled"])
        self.api(
            "POST", "/api/smtp/test", {"to_email": "ops@example.com"},
            token=self.admin_token,
        )
        self.assertEqual(self.mailer.sent[-1]["template_code"], "test_email")

        self.set_and_verify_admin_email("admin@example.com")
        # The fake mailer does not touch the queue, so seed one row directly.
        self.db.seed_email_templates(
            {"verify_email": {"subject": "验证码 {{code}}", "body": "{{code}}"}}
        )
        self.db.enqueue_email(
            "outbox@example.com", "verify_email", {"code": "123456"}
        )
        outbox = self.api("GET", "/api/email/outbox", token=self.admin_token)
        self.assertEqual(outbox["total"], 1)
        self.assertEqual(outbox["items"][0]["template_code"], "verify_email")
        filtered = self.api(
            "GET", "/api/email/outbox?status=pending&limit=1",
            token=self.admin_token,
        )
        self.assertEqual(filtered["total"], 1)
        self.assertLessEqual(len(filtered["items"]), 1)


class P1ApiSmtpDisabledTests(P1ApiTestBase):
    mailer_enabled = False

    def test_smtp_disabled_error_codes(self):
        set_email = self.admin_post(
            "/api/admin/email/set", {"email": "admin@example.com"}, expect=400
        )
        self.assertEqual(set_email["detail"], "SMTP 未启用或未配置")

        register = self.api(
            "POST",
            "/api/portal/email/send_code",
            {"email": "new@example.com", "purpose": "register"},
            expect=400,
        )
        self.assertEqual(register["detail"], "SMTP 未启用或未配置")

        # Reset stays enumeration-safe and audited.
        reset = self.api(
            "POST",
            "/api/portal/email/send_code",
            {"email": "new@example.com", "purpose": "reset"},
        )
        self.assertEqual(reset, {"ok": True})
        self.assertTrue(self.db.list_logs(action="门户重置验证码"))
        self.assertEqual(self.mailer.calls, [])

        test_mail = self.admin_post(
            "/api/smtp/test", {"to_email": "ops@example.com"}, expect=400
        )
        self.assertEqual(test_mail["detail"], "SMTP 未启用或未配置")

        status = self.api("GET", "/api/smtp/status", token=self.admin_token)
        self.assertFalse(status["enabled"])


if __name__ == "__main__":
    unittest.main()
