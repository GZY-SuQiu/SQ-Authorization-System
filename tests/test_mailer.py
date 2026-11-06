"""P1 SMTP 邮件引擎单元测试（unittest）。

FakeDB 按 docs/P1-INTERFACE.md 第 3 节的契约实现邮件方法，不依赖
core/database.py 的并行实现；transport 全部注入，不发真实邮件。
"""

from __future__ import annotations

import base64
import json
import socketserver
import threading
import time
import unittest
from datetime import datetime, timedelta
from unittest import mock

from server import mailer as mailer_module
from server.mailer import (
    DEFAULT_TEMPLATES,
    Mailer,
    backoff_seconds,
    build_mailer,
    render_template,
    send_test_email,
)

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def enabled_config(**overrides) -> dict:
    config = {
        "enabled": True,
        "host": "smtp.example.com",
        "port": 587,
        "username": "",
        "password": "",
        "from_email": "no-reply@example.com",
        "from_name": "密钥授权系统",
        "use_starttls": True,
        "use_ssl": False,
        "timeout": 15,
        "alert_admin_emails": [],
    }
    config.update(overrides)
    return config


class FakeDB:
    """契约第 3 节的测试替身：只记录调用，不碰真实 SQLite。"""

    def __init__(self, templates=None, claim_rows=None, stats=None):
        self.templates = {code: dict(value) for code, value in (templates or {}).items()}
        self.claim_rows = [dict(row) for row in (claim_rows or [])]
        self.stats = dict(stats or {})
        self.enqueue_calls: list[dict] = []
        self.sent_ids: list[int] = []
        self.failed_calls: list[dict] = []
        self.claim_limits: list[int] = []
        self._dedupe: set[str] = set()

    def seed_email_templates(self, templates) -> int:
        added = 0
        for code, template in (templates or {}).items():
            if code not in self.templates:
                self.templates[code] = dict(template)
                added += 1
        return added

    def upsert_email_template(self, code, subject, body, locale="zh-CN") -> None:
        self.templates[code] = {"subject": subject, "body": body, "locale": locale}

    def get_email_template(self, code):
        template = self.templates.get(code)
        return dict(template) if template else None

    def enqueue_email(self, to_email, template_code, variables=None, dedupe_key=""):
        if dedupe_key and dedupe_key in self._dedupe:
            return None
        if dedupe_key:
            self._dedupe.add(dedupe_key)
        self.enqueue_calls.append(
            {
                "to_email": to_email,
                "template_code": template_code,
                "variables": dict(variables or {}),
                "dedupe_key": dedupe_key,
            }
        )
        return len(self.enqueue_calls)

    def claim_due_emails(self, limit=20):
        self.claim_limits.append(int(limit))
        limit = max(0, int(limit))
        rows = self.claim_rows[:limit]
        self.claim_rows = self.claim_rows[limit:]
        return rows

    def mark_email_sent(self, email_id) -> None:
        self.sent_ids.append(int(email_id))

    def mark_email_failed(self, email_id, error, next_retry_at, dead=False) -> None:
        self.failed_calls.append(
            {
                "email_id": int(email_id),
                "error": str(error),
                "next_retry_at": next_retry_at,
                "dead": bool(dead),
            }
        )

    def email_outbox_stats(self) -> dict:
        return dict(self.stats)


class RecordingTransport:
    """记录每次投递；errors 里的收件人会收到异常。"""

    def __init__(self, errors=None):
        self.calls: list[dict] = []
        self.errors = dict(errors or {})

    def __call__(self, config, to_email, subject, body) -> None:
        self.calls.append(
            {
                "config": dict(config),
                "to_email": to_email,
                "subject": subject,
                "body": body,
            }
        )
        error = self.errors.get(to_email)
        if error is not None:
            raise error


class EnqueueTests(unittest.TestCase):
    def test_disabled_enqueue_returns_none_and_writes_nothing(self):
        db = FakeDB()
        mailer = Mailer(db, enabled_config(enabled=False))
        self.assertIsNone(mailer.enqueue("user@example.com", "verify_email", {"code": "123456"}))
        self.assertEqual(db.enqueue_calls, [])

    def test_unconfigured_enqueue_returns_none(self):
        db = FakeDB()
        mailer = Mailer(db, enabled_config(host="", from_email="", username=""))
        self.assertIsNone(mailer.enqueue("user@example.com", "verify_email", {"code": "123456"}))
        self.assertEqual(db.enqueue_calls, [])

    def test_enabled_enqueue_passes_contract_fields(self):
        db = FakeDB()
        mailer = Mailer(db, enabled_config())
        outbox_id = mailer.enqueue(
            "user@example.com",
            "verify_email",
            {"code": "123456"},
            dedupe_key="verify:user@example.com",
        )
        self.assertEqual(outbox_id, 1)
        self.assertEqual(len(db.enqueue_calls), 1)
        call = db.enqueue_calls[0]
        self.assertEqual(call["to_email"], "user@example.com")
        self.assertEqual(call["template_code"], "verify_email")
        self.assertEqual(call["variables"], {"code": "123456"})
        self.assertEqual(call["dedupe_key"], "verify:user@example.com")

    def test_enqueue_seeds_missing_builtin_template(self):
        db = FakeDB(templates={})
        mailer = Mailer(db, enabled_config())

        mailer.enqueue("user@example.com", "verify_email", {"code": "123456"})

        self.assertIn("verify_email", db.templates)
        self.assertEqual(
            db.templates["verify_email"]["body"],
            DEFAULT_TEMPLATES["verify_email"]["body"],
        )

    def test_enqueue_keeps_operator_customised_template(self):
        db = FakeDB(templates={"verify_email": {"subject": "自定义标题", "body": "自定义 {{code}}"}})
        mailer = Mailer(db, enabled_config())

        mailer.enqueue("user@example.com", "verify_email", {"code": "123456"})

        self.assertEqual(db.templates["verify_email"]["subject"], "自定义标题")

    def test_dedupe_conflict_returns_none(self):
        db = FakeDB()
        mailer = Mailer(db, enabled_config())
        first = mailer.enqueue("user@example.com", "test_email", {}, dedupe_key="k1")
        second = mailer.enqueue("user@example.com", "test_email", {}, dedupe_key="k1")
        self.assertIsNotNone(first)
        self.assertIsNone(second)
        self.assertEqual(len(db.enqueue_calls), 1)


class ProcessDueTests(unittest.TestCase):
    def setUp(self):
        self.template = {"subject": "主题 {{name}}", "body": "正文 {{name}}"}
        self.config = enabled_config()

    def _row(self, **overrides) -> dict:
        row = {
            "id": 7,
            "to_email": "user@example.com",
            "template_code": "verify_email",
            "variables": {"name": "小明"},
            # 对齐 core/database.py：attempts 是已失败次数，0 = 首次投递。
            "attempts": 0,
            "max_attempts": 5,
        }
        row.update(overrides)
        return row

    def test_process_due_transports_then_marks_sent(self):
        db = FakeDB(templates={"verify_email": self.template}, claim_rows=[self._row()])
        transport = RecordingTransport()
        mailer = Mailer(db, self.config, transport=transport)

        sent = mailer.process_due(limit=5)

        self.assertEqual(sent, 1)
        self.assertEqual(db.claim_limits, [5])
        self.assertEqual(db.sent_ids, [7])
        self.assertEqual(db.failed_calls, [])
        self.assertEqual(len(transport.calls), 1)
        call = transport.calls[0]
        self.assertEqual(call["to_email"], "user@example.com")
        self.assertEqual(call["subject"], "主题 小明")
        self.assertEqual(call["body"], "正文 小明")
        self.assertEqual(call["config"]["host"], "smtp.example.com")

    def test_variables_json_column_is_parsed_and_escaped(self):
        row = self._row(
            variables=None,
            variables_json=json.dumps({"name": "<b>值</b>"}),
        )
        db = FakeDB(templates={"verify_email": self.template}, claim_rows=[row])
        transport = RecordingTransport()
        mailer = Mailer(db, self.config, transport=transport)

        self.assertEqual(mailer.process_due(), 1)
        self.assertEqual(transport.calls[0]["body"], "正文 &lt;b&gt;值&lt;/b&gt;")

    def test_transport_failure_backs_off_and_batch_continues(self):
        rows = [
            self._row(id=1, to_email="bad@example.com"),
            self._row(id=2, to_email="good@example.com"),
        ]
        db = FakeDB(templates={"verify_email": self.template}, claim_rows=rows)
        transport = RecordingTransport(errors={"bad@example.com": RuntimeError("smtp down")})
        mailer = Mailer(db, self.config, transport=transport)

        sent = mailer.process_due()

        self.assertEqual(sent, 1)
        self.assertEqual(db.sent_ids, [2])
        self.assertEqual(len(db.failed_calls), 1)
        failure = db.failed_calls[0]
        self.assertEqual(failure["email_id"], 1)
        self.assertFalse(failure["dead"])
        self.assertIn("smtp down", failure["error"])
        retry_at = datetime.strptime(failure["next_retry_at"], TIME_FORMAT)
        expected = datetime.now() + timedelta(seconds=60)
        self.assertLessEqual(abs((retry_at - expected).total_seconds()), 10)
        self.assertTrue(mailer.last_error)

    def test_attempts_at_max_marks_dead(self):
        # 已失败 4 次后再失败一次即为第 5 次（max_attempts）→ dead。
        row = self._row(attempts=4, max_attempts=5)
        db = FakeDB(templates={"verify_email": self.template}, claim_rows=[row])
        transport = RecordingTransport(errors={"user@example.com": RuntimeError("nope")})
        mailer = Mailer(db, self.config, transport=transport)

        self.assertEqual(mailer.process_due(), 0)
        self.assertEqual(len(db.failed_calls), 1)
        self.assertTrue(db.failed_calls[0]["dead"])

    def test_second_failure_uses_doubled_backoff(self):
        row = self._row(attempts=1)
        db = FakeDB(templates={"verify_email": self.template}, claim_rows=[row])
        transport = RecordingTransport(errors={"user@example.com": RuntimeError("still down")})
        mailer = Mailer(db, self.config, transport=transport)

        self.assertEqual(mailer.process_due(), 0)
        retry_at = datetime.strptime(db.failed_calls[0]["next_retry_at"], TIME_FORMAT)
        expected = datetime.now() + timedelta(seconds=120)
        self.assertLessEqual(abs((retry_at - expected).total_seconds()), 10)
        self.assertFalse(db.failed_calls[0]["dead"])

    def test_missing_template_does_not_crash_the_batch(self):
        rows = [
            self._row(id=1, template_code="not_a_template"),
            self._row(id=2),
        ]
        db = FakeDB(templates={"verify_email": self.template}, claim_rows=rows)
        transport = RecordingTransport()
        mailer = Mailer(db, self.config, transport=transport)

        sent = mailer.process_due()

        self.assertEqual(sent, 1)
        self.assertEqual(db.sent_ids, [2])
        self.assertEqual(len(db.failed_calls), 1)
        failure = db.failed_calls[0]
        self.assertEqual(failure["email_id"], 1)
        self.assertFalse(failure["dead"])
        self.assertIn("not_a_template", failure["error"])
        self.assertEqual(len(transport.calls), 1)

    def test_builtin_template_fills_in_when_db_row_missing(self):
        row = self._row(variables={"code": "654321"})
        db = FakeDB(templates={}, claim_rows=[row])
        transport = RecordingTransport()
        mailer = Mailer(db, self.config, transport=transport)

        self.assertEqual(mailer.process_due(), 1)
        self.assertIn("654321", transport.calls[0]["body"])

    def test_disabled_mailer_does_not_claim(self):
        db = FakeDB(claim_rows=[self._row()])
        mailer = Mailer(db, enabled_config(enabled=False), transport=RecordingTransport())
        self.assertEqual(mailer.process_due(), 0)
        self.assertEqual(db.claim_limits, [])


class TemplateTests(unittest.TestCase):
    def test_default_templates_cover_all_codes(self):
        self.assertEqual(
            set(DEFAULT_TEMPLATES),
            {
                "verify_email",
                "reset_password",
                "tamper_alert",
                "risk_alert",
                "renewal_request",
                "alert_rule",
                "test_email",
                "approval_notice",
            },
        )
        for code, template in DEFAULT_TEMPLATES.items():
            self.assertTrue(str(template.get("subject") or "").strip(), code)
            self.assertTrue(str(template.get("body") or "").strip(), code)

    def test_render_escapes_html_in_variable_values(self):
        body = render_template("验证码：{{code}}", {"code": '<script>alert("x")</script>'})
        self.assertNotIn("<script>", body)
        self.assertIn("&lt;script&gt;", body)
        self.assertIn("&quot;", body)

    def test_render_missing_variable_is_empty(self):
        self.assertEqual(render_template("值：{{missing}}", {}), "值：")

    def test_render_without_variables_keeps_plain_text(self):
        self.assertEqual(render_template("固定内容", None), "固定内容")

    def test_backoff_curve_caps_at_one_hour(self):
        self.assertEqual(backoff_seconds(1), 60)
        self.assertEqual(backoff_seconds(2), 120)
        self.assertEqual(backoff_seconds(3), 240)
        self.assertEqual(backoff_seconds(5), 960)
        self.assertEqual(backoff_seconds(6), 1920)
        self.assertEqual(backoff_seconds(7), 3600)
        self.assertEqual(backoff_seconds(20), 3600)


class StatusTests(unittest.TestCase):
    def test_status_has_every_contract_key(self):
        stats = {"pending": 2, "sending": 1, "sent": 3, "failed": 4, "dead": 5}
        mailer = Mailer(FakeDB(stats=stats), enabled_config())

        status = mailer.status()

        self.assertEqual(
            set(status),
            {
                "enabled",
                "host",
                "port",
                "from_email",
                "pending",
                "sending",
                "sent",
                "failed",
                "dead",
                "last_error",
            },
        )
        self.assertTrue(status["enabled"])
        self.assertEqual(status["host"], "smtp.example.com")
        self.assertEqual(status["port"], 587)
        self.assertEqual(status["from_email"], "no-reply@example.com")
        for key, value in stats.items():
            self.assertEqual(status[key], value)
        self.assertEqual(status["last_error"], "")

    def test_status_reports_disabled_and_last_error(self):
        mailer = Mailer(FakeDB(stats={}), enabled_config(enabled=False))
        mailer.last_error = "boom"

        status = mailer.status()

        self.assertFalse(status["enabled"])
        self.assertEqual(status["pending"], 0)
        self.assertEqual(status["last_error"], "boom")


class SendTests(unittest.TestCase):
    def test_send_now_uses_injected_transport(self):
        transport = RecordingTransport()
        mailer = Mailer(FakeDB(), enabled_config(), transport=transport)

        mailer.send_now("ops@example.com", "test_email", {"time": "2026-10-07 10:00:00"})

        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(transport.calls[0]["to_email"], "ops@example.com")
        self.assertIn("2026-10-07 10:00:00", transport.calls[0]["body"])

    def test_send_now_disabled_raises_runtime_error(self):
        mailer = Mailer(FakeDB(), enabled_config(enabled=False))
        with self.assertRaisesRegex(RuntimeError, "SMTP 未启用或未配置"):
            mailer.send_now("ops@example.com", "test_email")

    def test_send_test_email_goes_through_transport(self):
        calls: list[tuple] = []

        def fake_transport(config, to_email, subject, body):
            calls.append((dict(config), to_email, subject, body))

        original = mailer_module.default_transport
        mailer_module.default_transport = fake_transport
        try:
            send_test_email(None, enabled_config(), "ops@example.com")
        finally:
            mailer_module.default_transport = original

        self.assertEqual(len(calls), 1)
        config, to_email, subject, body = calls[0]
        self.assertEqual(to_email, "ops@example.com")
        self.assertEqual(config["host"], "smtp.example.com")
        self.assertIn("测试", subject)
        self.assertIn("测试邮件", body)

    def test_send_test_email_without_config_raises(self):
        with self.assertRaisesRegex(RuntimeError, "SMTP 未启用或未配置"):
            send_test_email(
                None,
                enabled_config(host="", from_email="", username=""),
                "ops@example.com",
            )


class WorkerLifecycleTests(unittest.TestCase):
    def test_start_and_stop_are_idempotent_within_timeout(self):
        mailer = Mailer(FakeDB(), enabled_config(), transport=RecordingTransport())

        mailer.start()
        mailer.start()
        self.assertTrue(mailer.is_running())

        started = time.monotonic()
        mailer.stop(timeout=2.0)
        elapsed = time.monotonic() - started
        mailer.stop()

        self.assertLess(elapsed, 2.0)
        self.assertFalse(mailer.is_running())

    def test_stop_without_start_is_safe(self):
        mailer = Mailer(FakeDB(), enabled_config())
        mailer.stop()
        self.assertFalse(mailer.is_running())

    def test_build_mailer_returns_unstarted_mailer(self):
        mailer = build_mailer(FakeDB(), enabled_config())
        self.assertIsInstance(mailer, Mailer)
        self.assertFalse(mailer.is_running())

    def test_mailer_keeps_live_smtp_config_reference(self):
        config = enabled_config()
        mailer = Mailer(FakeDB(), config)
        config["username"] = "live@example.com"
        config["enabled"] = False
        self.assertEqual(mailer.config["username"], "live@example.com")
        self.assertFalse(mailer.is_ready())


class _AuthSMTPHandler(socketserver.StreamRequestHandler):
    """Fake SMTP that replies 503 to MAIL FROM until AUTH succeeds."""

    def handle(self) -> None:
        server: "_AuthSMTPServer" = self.server  # type: ignore[assignment]
        self.wfile.write(b"220 auth-smtp ready\r\n")
        while True:
            line = self.rfile.readline()
            if not line:
                break
            text = line.decode("utf-8", "replace").strip()
            upper = text.upper()
            if upper.startswith("EHLO"):
                server.commands.append("EHLO")
                self.wfile.write(b"250-auth-smtp\r\n250-AUTH PLAIN\r\n250 OK\r\n")
            elif upper.startswith("HELO"):
                server.commands.append("HELO")
                self.wfile.write(b"250 OK\r\n")
            elif upper.startswith("AUTH PLAIN"):
                parts = text.split()
                payload = parts[2] if len(parts) > 2 else ""
                if not payload:
                    self.wfile.write(b"334 \r\n")
                    payload = self.rfile.readline().decode("utf-8", "replace").strip()
                try:
                    decoded = base64.b64decode(payload).decode("utf-8", "replace")
                except Exception:
                    decoded = ""
                if "\x00" in decoded:
                    server.commands.append("AUTH")
                    self.wfile.write(b"235 2.7.0 Authentication successful\r\n")
                else:
                    self.wfile.write(b"535 5.7.8 Authentication failed\r\n")
            elif upper.startswith("MAIL FROM:"):
                if "AUTH" not in server.commands:
                    server.commands.append("MAIL-DENIED")
                    self.wfile.write(b"503 Error: need EHLO and AUTH first\r\n")
                else:
                    server.commands.append("MAIL")
                    self.wfile.write(b"250 OK\r\n")
            elif upper.startswith("RCPT TO:"):
                self.wfile.write(b"250 OK\r\n")
            elif upper.startswith("DATA"):
                self.wfile.write(b"354 End data\r\n")
                while True:
                    data_line = self.rfile.readline()
                    if not data_line or data_line in (b".\r\n", b".\n"):
                        break
                server.commands.append("DATA")
                self.wfile.write(b"250 OK queued\r\n")
            elif upper.startswith("QUIT"):
                self.wfile.write(b"221 Bye\r\n")
                break
            else:
                self.wfile.write(b"250 OK\r\n")


class _AuthSMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _AuthSMTPHandler)
        self.commands: list[str] = []
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self.shutdown()
        self.server_close()


class SmtpAuthenticationTests(unittest.TestCase):
    """复现并验证 503 need EHLO and AUTH first 的修复。"""

    def setUp(self):
        self.server = _AuthSMTPServer()
        self.server.start()
        self.addCleanup(self.server.stop)

    def _config(self, **overrides) -> dict:
        config = enabled_config()
        config.update(
            {
                "host": "127.0.0.1",
                "port": self.server.port,
                "use_starttls": False,
                "use_ssl": False,
                "timeout": 5,
            }
        )
        config.update(overrides)
        return config

    def test_credentials_are_sent_before_mail_from(self):
        mailer_module.default_transport(
            self._config(username="user@example.com", password="secret"),
            "to@example.com",
            "subject",
            "body",
        )
        self.assertIn("AUTH", self.server.commands)
        self.assertIn("MAIL", self.server.commands)
        self.assertLess(
            self.server.commands.index("AUTH"), self.server.commands.index("MAIL")
        )
        self.assertNotIn("MAIL-DENIED", self.server.commands)

    def test_password_only_uses_from_email_as_username(self):
        mailer_module.default_transport(
            self._config(username="", password="secret"),
            "to@example.com",
            "subject",
            "body",
        )
        self.assertIn("AUTH", self.server.commands)
        self.assertIn("MAIL", self.server.commands)

    def test_missing_credentials_fail_with_actionable_error(self):
        with self.assertRaises(RuntimeError) as ctx:
            mailer_module.default_transport(
                self._config(username="", password=""),
                "to@example.com",
                "subject",
                "body",
            )
        self.assertIn("要求认证", str(ctx.exception))
        self.assertNotIn("MAIL", self.server.commands)

    def test_conflicting_encryption_is_rejected(self):
        with self.assertRaises(RuntimeError) as ctx:
            mailer_module.default_transport(
                self._config(
                    username="user@example.com",
                    password="secret",
                    use_ssl=True,
                    use_starttls=True,
                ),
                "to@example.com",
                "subject",
                "body",
            )
        self.assertIn("SSL", str(ctx.exception))

    def test_transport_never_calls_reverse_dns(self):
        """smtplib 默认会调用 socket.getfqdn()，本机可能阻塞十几秒。"""
        with mock.patch(
            "socket.getfqdn",
            side_effect=AssertionError("reverse DNS must not be called"),
        ):
            mailer_module.default_transport(
                self._config(username="user@example.com", password="secret"),
                "to@example.com",
                "subject",
                "body",
            )
        self.assertIn("MAIL", self.server.commands)


if __name__ == "__main__":
    unittest.main()
