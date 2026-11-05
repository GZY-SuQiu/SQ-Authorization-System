"""P1 邮件账号与告警端到端验收工具。

运行：

    python tools/verify_mail_e2e.py

内置一个最小 SMTP 假服务器（标准库 socketserver，不依赖第三方），然后：

1. 门户邮箱注册验证码 -> 注册 -> 登录 -> /me；
2. 管理员绑定邮箱 + 验证码验证；
3. 管理员忘记密码 -> 邮件重置码 -> 重置 -> 新密码登录；
4. 门户绑定许可证 -> /me 显示绑定 -> 有效期内自助脱绑必须 409；
5. 门户续费请求 -> 用户与管理员各收到通知邮件；
6. 校验邮件队列 stats 与 sent 状态。
"""

from __future__ import annotations

import email
import re
import socket
import socketserver
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import uvicorn  # noqa: E402

from core.api_client import ApiClient, ApiError  # noqa: E402
from core.config import Config  # noqa: E402
from core.database import Database  # noqa: E402
from server.api import create_app  # noqa: E402
from server.mailer import Mailer  # noqa: E402
from server.alert_engine import AlertEngine  # noqa: E402

PORTAL_PASSWORD = "PortalPass#2026"
ADMIN_PASSWORD = "AdminPass#2026"
ADMIN_NEW_PASSWORD = "AdminNewPass#2026"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _SMTPHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        server: "FakeSMTPServer" = self.server  # type: ignore[assignment]
        self.wfile.write(b"220 fake-smtp ready\r\n")
        sender = ""
        recipients: list[str] = []
        while True:
            line = self.rfile.readline()
            if not line:
                break
            text = line.decode("utf-8", "replace").strip()
            upper = text.upper()
            if upper.startswith(("EHLO", "HELO")):
                self.wfile.write(b"250-fake-smtp\r\n250 OK\r\n")
            elif upper.startswith("MAIL FROM:"):
                sender = text[10:].strip().strip("<>")
                self.wfile.write(b"250 OK\r\n")
            elif upper.startswith("RCPT TO:"):
                recipients.append(text[8:].strip().strip("<>"))
                self.wfile.write(b"250 OK\r\n")
            elif upper.startswith("DATA"):
                self.wfile.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                chunks: list[bytes] = []
                while True:
                    data_line = self.rfile.readline()
                    if not data_line:
                        break
                    if data_line in (b".\r\n", b".\n"):
                        break
                    if data_line.startswith(b".."):
                        data_line = data_line[1:]
                    chunks.append(data_line)
                with server.lock:
                    server.messages.append(
                        {
                            "from": sender,
                            "to": list(recipients),
                            "data": b"".join(chunks).decode("utf-8", "replace"),
                        }
                    )
                recipients = []
                self.wfile.write(b"250 OK queued\r\n")
            elif upper.startswith("RSET"):
                recipients = []
                self.wfile.write(b"250 OK\r\n")
            elif upper.startswith("NOOP"):
                self.wfile.write(b"250 OK\r\n")
            elif upper.startswith("QUIT"):
                self.wfile.write(b"221 Bye\r\n")
                break
            else:
                self.wfile.write(b"250 OK\r\n")


class FakeSMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _SMTPHandler)
        self.messages: list[dict] = []
        self.lock = threading.Lock()
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self.shutdown()
        self.server_close()


class LiveServer:
    def __init__(self, app, port: int):
        self.port = port
        self.server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", access_log=False)
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self) -> None:
        self.thread.start()
        for _ in range(200):
            if self.server.started:
                return
            time.sleep(0.05)
        raise RuntimeError("测试服务器启动超时")

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)


def _message_body(raw: str) -> tuple[str, str]:
    message = email.message_from_string(raw)
    subject = str(message.get("Subject") or "")
    body = ""
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/html":
                payload = part.get_payload(decode=True) or b""
                body = payload.decode(part.get_content_charset() or "utf-8", "replace")
                break
    if not body:
        payload = message.get_payload(decode=True)
        body = (payload or b"").decode(message.get_content_charset() or "utf-8", "replace")
    return subject, body


def _extract_code(raw: str) -> str:
    subject, body = _message_body(raw)
    match = re.search(r"(?<!\d)(\d{6})(?!\d)", body) or re.search(r"(?<!\d)(\d{6})(?!\d)", subject)
    if not match:
        raise RuntimeError(f"邮件里找不到 6 位验证码：subject={subject!r} body={body[:200]!r}")
    return match.group(1)


def _wait_message(fake: FakeSMTPServer, start_index: int, mailer: Mailer, timeout: float = 30.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            mailer.process_due()
        except Exception:
            pass
        with fake.lock:
            messages = list(fake.messages)
        for message in messages[start_index:]:
            return message
        time.sleep(0.2)
    raise RuntimeError("等待邮件超时")


def _expect(condition, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _api_error_text(callable_, *args, **kwargs) -> str:
    try:
        callable_(*args, **kwargs)
    except ApiError as exc:
        return str(exc)
    except Exception as exc:  # pragma: no cover - diagnostic path
        return f"{type(exc).__name__}: {exc}"
    raise RuntimeError("预期调用失败，但调用成功了")


def main() -> int:
    import inspect

    parameters = inspect.signature(create_app).parameters
    if "mailer" not in parameters or "alert_engine" not in parameters:
        print("server/api.py 的 create_app 还没有 mailer 参数，请先完成 P1 Backend 集成。")
        return 1

    fake = FakeSMTPServer()
    fake.start()
    tmp = tempfile.TemporaryDirectory(prefix="sq_mail_e2e_", ignore_cleanup_errors=True)
    root = Path(tmp.name)
    live = None
    mailer = None
    db = None
    try:
        config = Config("server", root / "server_config.json")
        config.data["security"]["attest_mode"] = "off"
        smtp = {
            "enabled": True,
            "host": "127.0.0.1",
            "port": fake.port,
            "username": "",
            "password": "",
            "from_email": "no-reply@example.com",
            "from_name": "密钥授权系统",
            "use_starttls": False,
            "use_ssl": False,
            "timeout": 10,
            "alert_admin_emails": ["ops@example.com"],
        }
        config.data["smtp"] = smtp

        db = Database(root / "license.db", config.security["secret_key"])
        _, bootstrap = db.ensure_default_admin()
        mailer = Mailer(db, smtp)
        alert_engine = AlertEngine(db, mailer, config, interval=3600)
        app = create_app(config, db, mailer=mailer, alert_engine=alert_engine)
        live = LiveServer(app, _free_port())
        live.start()
        base = f"http://127.0.0.1:{live.port}"
        response_key = config.security["response_public_key"]
        response_key_id = config.security["response_key_id"]

        admin = ApiClient(base, response_public_key=response_key, response_key_id=response_key_id)
        portal = ApiClient(base, response_public_key=response_key, response_key_id=response_key_id)

        login = admin.login("admin", bootstrap)
        if login.get("must_change_password"):
            admin.change_password(bootstrap, ADMIN_PASSWORD)
        print("[ OK ] 主控登录并完成初始改密")

        start = len(fake.messages)
        sent = portal.portal_send_code("user@example.com", "register")
        _expect(sent.get("ok"), f"注册验证码发送失败：{sent}")
        register_code = _extract_code(_wait_message(fake, start, mailer)["data"])
        registered = portal.portal_register("user@example.com", register_code, PORTAL_PASSWORD)
        _expect(registered.get("ok"), f"门户注册失败：{registered}")
        me = portal.portal_me()
        _expect(me.get("email") == "user@example.com", f"/me 返回异常：{me}")
        print("[ OK ] 门户邮箱注册 -> 登录 -> /me 通过")

        start = len(fake.messages)
        set_email = admin.admin_set_email("admin@example.com")
        _expect(set_email.get("ok"), f"管理员设置邮箱失败：{set_email}")
        verify_code = _extract_code(_wait_message(fake, start, mailer)["data"])
        admin.admin_verify_email(verify_code)
        admin_me = admin._request("GET", "/api/admin/me")
        _expect(admin_me.get("email_verified"), f"管理员邮箱未标记验证：{admin_me}")
        print("[ OK ] 管理员邮箱绑定与验证码验证通过")

        start = len(fake.messages)
        forgot = admin.admin_password_forgot("admin@example.com")
        _expect(forgot.get("ok"), f"忘记密码请求异常：{forgot}")
        reset_code = _extract_code(_wait_message(fake, start, mailer)["data"])
        admin.admin_password_reset("admin@example.com", reset_code, ADMIN_NEW_PASSWORD)
        fresh_admin = ApiClient(base, response_public_key=response_key, response_key_id=response_key_id)
        relogin = fresh_admin.login("admin", ADMIN_NEW_PASSWORD)
        _expect(relogin.get("token"), f"重置后新密码登录失败：{relogin}")
        print("[ OK ] 管理员忘记密码 -> 邮件重置码 -> 新密码登录通过")

        generated = fresh_admin.generate_licenses(
            count=1, edition="professional", duration_days=30, max_devices=1
        )
        keys = generated.get("keys") or []
        _expect(keys, f"生成许可证失败：{generated}")
        key_code = keys[0] if isinstance(keys[0], str) else keys[0].get("key_code")
        bound = portal.portal_bind(key_code, "MAIL-E2E-01", "e2e-device")
        _expect(bound.get("ok"), f"门户绑定失败：{bound}")
        me = portal.portal_me()
        _expect(me.get("binding"), f"绑定后 /me 没有 binding：{me}")
        denied = _api_error_text(portal.portal_unbind)
        _expect("不能自助脱绑" in denied, f"有效期内脱绑未被 409 拒绝：{denied}")
        print("[ OK ] 门户绑定许可证；有效期内自助脱绑被拒绝")

        start = len(fake.messages)
        renewal = portal.portal_renew_request("希望续费一年")
        _expect(renewal.get("ok") and renewal.get("request_id"), f"续费请求失败：{renewal}")
        first = _wait_message(fake, start, mailer)
        _expect(first["to"], "续费邮件没有收件人")
        second = _wait_message(fake, start + 1, mailer)
        _expect(second["to"], "管理员续费邮件没有收件人")
        print("[ OK ] 续费请求邮件同时通知用户与管理员")

        # A5：可配置告警规则 -> 事件落库 -> 邮件通知
        rule = fresh_admin.create_alert_rule(
            name="激活失败告警",
            metric="failed_activations",
            operator="gte",
            threshold=1,
            window_seconds=600,
            severity="warning",
            cooldown_seconds=60,
            channels=["email"],
            enabled=True,
        )
        _expect(rule.get("ok"), f"创建告警规则失败：{rule}")
        probe = ApiClient(base, response_public_key=response_key, response_key_id=response_key_id)
        probe.activate("GSQ-NOT-EXIST", "MAIL-E2E-02", "probe")
        start = len(fake.messages)
        fired = alert_engine.evaluate_once()
        _expect(fired, f"告警规则没有触发：{fired}")
        alert_mail = _wait_message(fake, start, mailer)
        _expect(alert_mail["to"], "告警邮件没有收件人")
        events, total = db.list_alert_events(status="firing")
        _expect(total >= 1 and int(events[0]["notified"]) == 1, f"告警事件状态异常：{events[:1]}")
        print("[ OK ] A5 告警规则触发 -> 事件落库 -> 邮件通知通过")

        stats = db.email_outbox_stats()
        _expect(int(stats.get("sent") or 0) >= 6, f"邮件发送数量异常：{stats}")
        print(f"[ OK ] 邮件队列统计：{stats}")

        print("== P1 邮件与邮箱账号端到端验收通过 ==")
        return 0
    finally:
        if mailer is not None:
            try:
                alert_engine.stop(timeout=3)
            except Exception:
                pass
            try:
                mailer.stop(timeout=3)
            except Exception:
                pass
        if live is not None:
            try:
                live.stop()
            except Exception:
                pass
        if db is not None:
            try:
                db.close()
            except Exception:
                pass
        fake.stop()
        tmp.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
