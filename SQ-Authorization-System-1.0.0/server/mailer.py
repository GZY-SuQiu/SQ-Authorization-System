"""P1 SMTP 邮件引擎（契约见 docs/P1-INTERFACE.md 第 2 节）。

对外接口：

- ``DEFAULT_TEMPLATES``：七个内置模板（verify_email / reset_password /
  tamper_alert / risk_alert / renewal_request / alert_rule / test_email）；
- ``Mailer``：SQLite outbox 投递引擎，后台 daemon 线程每 5 秒调用一次
  ``process_due``；``start`` / ``stop`` 幂等；
- ``build_mailer``：构造 Mailer（不自动启动后台线程，调用方按需 ``start``）；
- ``send_test_email``：直接发送测试邮件（不落队列，走模块级 ``default_transport``）。

模板占位符为 ``{{变量名}}``，渲染时变量值做 HTML 转义；未提供的变量渲染为空串。
内置模板使用的变量名（入队方必须一致）：

- ``verify_email`` / ``reset_password``：``code``
- ``tamper_alert``：``role`` ``exe_name`` ``exe_hash`` ``machine_code``
  ``ip`` ``reason`` ``detail`` ``time``
- ``risk_alert``：``key_code`` ``machine_code`` ``ip`` ``time``
- ``renewal_request``：``key_code`` ``account_email`` ``note`` ``time``
- ``alert_rule``：``rule_name`` ``metric_label`` ``value`` ``operator``
  ``threshold`` ``window_text`` ``severity`` ``time``
- ``test_email``：``time``

重试语义（对齐 core/database.py 的实现）：``email_outbox.attempts`` 记录已失败次数，
领取行的 ``attempts=0`` 表示首次投递、``attempts=1`` 表示第二次投递。失败时本次
投递序号为 ``attempts + 1``，退避 ``60 * 2**(序号-1)`` 秒、上限 1 小时；序号达到
``max_attempts`` 时以 ``dead=True`` 落库（mark_email_failed 自身也会校验）。

发送模板优先取数据库（``get_email_template``，允许运维改文案），数据库缺失时回退到
``DEFAULT_TEMPLATES``；两边都没有的 code 记为失败，不会中断整批投递。

本模块只按鸭子类型调用契约第 3 节的 Database 方法，不导入 core.database，
测试可以直接注入 FakeDB。
"""

from __future__ import annotations

import html
import json
import re
import socket
import smtplib
import ssl
import threading
from datetime import datetime, timedelta
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

__all__ = [
    "DEFAULT_TEMPLATES",
    "Mailer",
    "MailTemplateError",
    "backoff_seconds",
    "build_mailer",
    "default_transport",
    "render_template",
    "send_test_email",
]

DEFAULT_MAX_ATTEMPTS = 5
MAX_BACKOFF_SECONDS = 3600
WORKER_INTERVAL_SECONDS = 5.0

_PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")

DEFAULT_TEMPLATES: dict[str, dict] = {
    "verify_email": {
        "subject": "【密钥授权系统】邮箱验证码",
        "body": (
            "您好：\n"
            "\n"
            "您的邮箱验证码是 {{code}}，10 分钟内有效。\n"
            "请勿将验证码转发给他人。\n"
            "\n"
            "密钥授权系统"
        ),
    },
    "reset_password": {
        "subject": "【密钥授权系统】密码重置验证码",
        "body": (
            "您好：\n"
            "\n"
            "您正在重置密码，验证码是 {{code}}，10 分钟内有效。\n"
            "如非本人操作，请忽略本邮件。\n"
            "\n"
            "密钥授权系统"
        ),
    },
    "tamper_alert": {
        "subject": "【密钥授权系统】完整性告警",
        "body": (
            "检测到客户端完整性异常，已触发安全告警。\n"
            "\n"
            "端别：{{role}}\n"
            "程序：{{exe_name}}（{{exe_hash}}）\n"
            "设备：{{machine_code}}\n"
            "IP：{{ip}}\n"
            "原因：{{reason}}\n"
            "详情：{{detail}}\n"
            "时间：{{time}}\n"
            "\n"
            "请登录主控端核查。"
        ),
    },
    "risk_alert": {
        "subject": "【密钥授权系统】安全风险告警",
        "body": (
            "检测到与授权密钥相关的风险事件，请及时核查。\n"
            "\n"
            "密钥：{{key_code}}\n"
            "设备：{{machine_code}}\n"
            "IP：{{ip}}\n"
            "时间：{{time}}\n"
            "\n"
            "详情请登录主控端查看。"
        ),
    },
    "renewal_request": {
        "subject": "【密钥授权系统】续费请求",
        "body": (
            "收到新的续费请求。\n"
            "\n"
            "密钥：{{key_code}}\n"
            "账号：{{account_email}}\n"
            "备注：{{note}}\n"
            "时间：{{time}}\n"
            "\n"
            "请登录主控端处理。"
        ),
    },
    "alert_rule": {
        "subject": "【密钥授权系统】告警规则触发：{{rule_name}}",
        "body": (
            "告警规则已被触发，请及时核查。\n"
            "\n"
            "规则：{{rule_name}}\n"
            "指标：{{metric_label}}\n"
            "当前值：{{value}}\n"
            "条件：{{operator}} {{threshold}}\n"
            "统计窗口：{{window_text}}\n"
            "级别：{{severity}}\n"
            "时间：{{time}}\n"
            "\n"
            "请登录管理端「告警中心」查看并处理。"
        ),
    },
    "test_email": {
        "subject": "【密钥授权系统】SMTP 测试邮件",
        "body": (
            "您好：\n"
            "\n"
            "这是一封 SMTP 测试邮件，收到即表示当前邮件配置可用。\n"
            "发送时间：{{time}}\n"
            "\n"
            "密钥授权系统"
        ),
    },
}


class MailTemplateError(RuntimeError):
    """内置与数据库里都找不到模板 code。"""


def render_template(text, variables: dict | None = None) -> str:
    """把 ``{{变量名}}`` 换成 HTML 转义后的变量值。

    变量缺失时渲染为空串：邮件正文不携带模板原始标记，也不会因为少传一个变量
    抛出异常拖垮整批投递。
    """
    values = variables if isinstance(variables, dict) else {}

    def _replace(match: re.Match) -> str:
        key = match.group(1)
        if key not in values:
            return ""
        return html.escape(str(values[key]), quote=True)

    return _PLACEHOLDER_RE.sub(_replace, str(text or ""))


def backoff_seconds(attempts: int) -> int:
    """第 ``attempts`` 次投递失败后的退避秒数：60 * 2**(attempts-1)，上限 1 小时。"""
    try:
        attempt = int(attempts)
    except (TypeError, ValueError):
        attempt = 1
    shift = min(max(attempt - 1, 0), 20)
    return min(60 * (2 ** shift), MAX_BACKOFF_SECONDS)


def _as_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _error_text(exc: BaseException) -> str:
    message = str(exc).strip()
    if message:
        return f"{type(exc).__name__}: {message}"
    return type(exc).__name__


def _has_sender(config: dict) -> bool:
    return bool(
        str(config.get("from_email") or "").strip()
        or str(config.get("username") or "").strip()
    )


def is_smtp_configured(smtp_config: dict | None) -> bool:
    """主机 + 发件人（发件邮箱或登录用户名）齐备才算配置完成。"""
    return not smtp_config_problem(smtp_config)


def smtp_config_problem(smtp_config: dict | None) -> str:
    """Return a human-readable configuration problem, or '' when usable."""
    config = smtp_config or {}
    if not str(config.get("host") or "").strip():
        return "未填写 SMTP 服务器主机"
    if not _has_sender(config):
        return "未填写发件邮箱或登录用户名"
    if config.get("use_ssl") and config.get("use_starttls"):
        return "SSL 与 STARTTLS 不能同时开启（465 端口用 SSL，587 端口用 STARTTLS）"
    username = str(config.get("username") or "").strip()
    password = str(config.get("password") or "")
    if username and not password:
        return "已填写用户名但缺少密码/授权码"
    if password and not (username or str(config.get("from_email") or "").strip()):
        return "已填写密码/授权码但缺少用户名或发件邮箱"
    return ""


def is_smtp_ready(smtp_config: dict | None) -> bool:
    """已勾选启用且配置完整。"""
    config = smtp_config or {}
    return bool(config.get("enabled")) and is_smtp_configured(config)


def _smtp_failure_message(exc: BaseException) -> str:
    """Turn an SMTP exception into an actionable Chinese message."""
    code = getattr(exc, "smtp_code", None)
    hints = {
        503: "服务器要求先完成 EHLO 与 AUTH：请填写完整的 SMTP 用户名（常见为完整邮箱），并在 465 端口勾选 SSL、587 端口勾选 STARTTLS。",
        530: "服务器要求认证：请填写 SMTP 用户名与密码/授权码。",
        535: "认证失败：QQ/163/企业邮箱通常需要使用“授权码”，而不是网页登录密码。",
        534: "服务器要求应用专用密码（授权码）。",
        550: "发件人或收件人被拒绝：发件邮箱必须与 SMTP 账号匹配，收件地址需真实存在。",
        554: "邮件被判定为垃圾邮件或被拒绝中继，请检查发件人域名与内容。",
        421: "服务器暂时不可用，稍后会自动重试。",
    }
    try:
        hint = hints.get(int(code)) if code is not None else ""
    except (TypeError, ValueError):
        hint = ""
    base = f"SMTP 发送失败：{code} {getattr(exc, 'smtp_error', exc)}"
    return f"{base}。{hint}" if hint else base


def _smtp_local_hostname() -> str:
    """Return an ASCII EHLO name without triggering reverse DNS.

    ``smtplib`` calls ``socket.getfqdn()`` when ``local_hostname`` is omitted.
    On some Windows/DNS setups that call blocks for 10+ seconds per message.
    """
    try:
        raw = socket.gethostname() or ""
    except Exception:
        raw = ""
    cleaned = re.sub(r"[^A-Za-z0-9.-]", "", raw).strip(".-")[:63]
    return cleaned or "localhost"


def default_transport(config: dict, to_email: str, subject: str, body: str) -> None:
    """标准库 SMTP 投递：SSL / STARTTLS / 登录按配置执行。

    任何网络或认证错误都以异常抛出，由调用方负责重试与落库。
    """
    cfg = config or {}
    host = str(cfg.get("host") or "").strip()
    if not host:
        raise RuntimeError("SMTP 未启用或未配置")
    use_ssl = bool(cfg.get("use_ssl"))
    use_starttls = bool(cfg.get("use_starttls"))
    if use_ssl and use_starttls:
        raise RuntimeError(
            "SMTP 配置冲突：SSL 与 STARTTLS 不能同时开启（465 端口用 SSL，587 端口用 STARTTLS）"
        )
    default_port = 465 if use_ssl else (587 if use_starttls else 25)
    port = _as_int(cfg.get("port"), 0) or default_port
    timeout = _as_float(cfg.get("timeout"), 15.0) or 15.0
    username = str(cfg.get("username") or "").strip()
    password = str(cfg.get("password") or "")
    from_email = str(cfg.get("from_email") or "").strip() or username
    # 常见配置：用户名就是完整邮箱。用户只填了密码时自动用发件邮箱作为用户名，
    # 避免“没做 AUTH 就 MAIL FROM”触发 503 need EHLO and AUTH first。
    login_user = username or (from_email if password else "")
    from_name = str(cfg.get("from_name") or "").strip()
    if not from_email:
        raise RuntimeError("SMTP 未启用或未配置")

    local_hostname = str(cfg.get("local_hostname") or "").strip() or _smtp_local_hostname()
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = formataddr((from_name, from_email)) if from_name else from_email
    message["To"] = to_email
    message["Date"] = formatdate(localtime=True)
    # make_msgid 默认也会调用 socket.getfqdn()，显式给域名避免反向 DNS 阻塞。
    message["Message-ID"] = make_msgid(domain=local_hostname)
    message.set_content(body)

    context = ssl.create_default_context()

    def _authenticate_and_send(client) -> None:
        authed = False
        if login_user and password:
            # smtplib 会在 login 内部先发 EHLO；这里显式 EHLO 过也无妨。
            client.login(login_user, password)
            authed = True
        try:
            requires_auth = bool(client.has_extn("auth"))
        except Exception:
            requires_auth = False
        if requires_auth and not authed:
            raise RuntimeError(
                "SMTP 服务器要求认证（AUTH），请填写用户名和密码/授权码后再试"
            )
        client.send_message(message)

    try:
        if use_ssl:
            with smtplib.SMTP_SSL(
                host,
                port,
                timeout=timeout,
                context=context,
                local_hostname=local_hostname,
            ) as client:
                client.ehlo()
                _authenticate_and_send(client)
            return
        with smtplib.SMTP(
            host, port, timeout=timeout, local_hostname=local_hostname
        ) as client:
            client.ehlo()
            if use_starttls:
                client.starttls(context=context)
                # STARTTLS 会重置会话状态，必须重新 EHLO 再做 AUTH。
                client.ehlo()
            _authenticate_and_send(client)
    except smtplib.SMTPAuthenticationError as exc:
        raise RuntimeError(_smtp_failure_message(exc)) from exc
    except smtplib.SMTPResponseException as exc:
        raise RuntimeError(_smtp_failure_message(exc)) from exc
    except smtplib.SMTPServerDisconnected as exc:
        raise RuntimeError(
            "SMTP 连接被服务器断开：请检查端口与加密方式（465=SSL，587=STARTTLS）以及网络是否允许。"
        ) from exc
    except ssl.SSLError as exc:
        raise RuntimeError(
            "SMTP TLS 握手失败：465 端口应勾选 SSL，587 端口应勾选 STARTTLS，且证书需受信任。"
        ) from exc
    except (TimeoutError, OSError) as exc:
        raise RuntimeError(f"SMTP 网络错误：{exc}") from exc


class Mailer:
    """outbox 投递引擎。

    ``transport`` 可注入，签名 ``transport(config, to_email, subject, body) -> None``；
    默认使用 :func:`default_transport`。
    """

    interval_seconds = WORKER_INTERVAL_SECONDS

    def __init__(self, db, smtp_config: dict, transport=None):
        self.db = db
        # 保留调用方字典的引用：服务器界面保存 SMTP 设置后，运行中的 worker
        # 立即使用新配置，不需要重启服务。
        self.config = smtp_config if isinstance(smtp_config, dict) else {}
        self._transport = transport
        self.last_error = ""
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ 状态
    def is_ready(self) -> bool:
        return is_smtp_ready(self.config)

    def is_running(self) -> bool:
        thread = self._thread
        return bool(thread is not None and thread.is_alive())

    def status(self) -> dict:
        stats: dict = {}
        try:
            stats = self.db.email_outbox_stats() or {}
        except Exception as exc:  # 状态查询失败也要能返回完整键
            self.last_error = _error_text(exc)
        return {
            "enabled": self.is_ready(),
            "host": str(self.config.get("host") or ""),
            "port": _as_int(self.config.get("port"), 0),
            "from_email": str(self.config.get("from_email") or ""),
            "pending": _as_int(stats.get("pending"), 0),
            "sending": _as_int(stats.get("sending"), 0),
            "sent": _as_int(stats.get("sent"), 0),
            "failed": _as_int(stats.get("failed"), 0),
            "dead": _as_int(stats.get("dead"), 0),
            "last_error": self.last_error,
        }

    # ---------------------------------------------------------------- 生命周期
    def start(self) -> None:
        """启动后台投递线程；重复调用无副作用。"""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            thread = threading.Thread(
                target=self._run_loop, name="sq-mailer", daemon=True
            )
            self._thread = thread
        thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """在 ``timeout`` 秒内结束后台线程；从未启动或重复调用都是安全的。"""
        self._stop_event.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=max(0.0, _as_float(timeout, 0.0)))
        with self._lock:
            if self._thread is thread and (thread is None or not thread.is_alive()):
                self._thread = None

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.process_due()
            except Exception as exc:  # pragma: no cover - 防御性兜底
                self.last_error = _error_text(exc)
            self._stop_event.wait(self.interval_seconds)

    # ------------------------------------------------------------------ 入队
    def enqueue(
        self,
        to_email: str,
        template_code: str,
        variables: dict | None = None,
        dedupe_key: str = "",
    ) -> int | None:
        """未启用/未配置时返回 None 且不写队列；dedupe 冲突由数据库返回 None。"""
        if not self.is_ready():
            return None
        address = str(to_email or "").strip()
        code = str(template_code or "").strip()
        if not address or not code:
            return None
        self._ensure_template_row(code)
        result = self.db.enqueue_email(
            address, code, variables or {}, str(dedupe_key or "")
        )
        return int(result) if result else None

    def send_now(
        self,
        to_email: str,
        template_code: str,
        variables: dict | None = None,
    ) -> None:
        """同步发送一封模板邮件（不入队）；失败原样抛出异常。"""
        if not self.is_ready():
            raise RuntimeError("SMTP 未启用或未配置")
        template = self._load_template(template_code)
        subject = render_template(template.get("subject", ""), variables)
        body = render_template(template.get("body", ""), variables)
        try:
            self._send(str(to_email or "").strip(), subject, body)
        except Exception as exc:
            self.last_error = _error_text(exc)
            raise
        self.last_error = ""

    # ------------------------------------------------------------------ 投递
    def process_due(self, limit: int = 20) -> int:
        """领取到期邮件并逐条投递，返回成功发送的条数。

        单条邮件（含落库操作）的异常只影响它自己：失败按退避重试，
        达到最大尝试次数进入 dead，其余邮件照常继续。
        ``last_error`` 保留本批最后一条失败原因；整批无失败时清空。
        """
        if not self.is_ready():
            return 0
        try:
            batch = self.db.claim_due_emails(max(1, _as_int(limit, 20)))
        except Exception as exc:
            self.last_error = _error_text(exc)
            return 0
        sent = 0
        failed_any = False
        state_error = ""
        for row in batch or []:
            if not isinstance(row, dict):
                continue
            try:
                self._deliver_row(row)
            except Exception as exc:
                failed_any = True
                self._record_failure(row, exc)
                continue
            # 邮件已经真实发出。状态落库失败绝不能再触发重试，否则会重复发送。
            sent += 1
            try:
                self.db.mark_email_sent(row.get("id"))
            except Exception as exc:
                state_error = f"邮件已发送但状态落库失败：{_error_text(exc)}"
        if not failed_any:
            # 最近一批没有失败时清空 last_error；有失败时保留最后一条原因。
            self.last_error = state_error or ""
        return sent

    def _deliver_row(self, row: dict) -> None:
        code = str(row.get("template_code") or "").strip()
        template = self._load_template(code)
        variables = _row_variables(row)
        subject = render_template(template.get("subject", ""), variables)
        body = render_template(template.get("body", ""), variables)
        if not str(body or "").strip():
            raise MailTemplateError(f"邮件模板内容为空：{code}")
        to_email = str(row.get("to_email") or "").strip()
        if not to_email:
            raise ValueError("收件邮箱为空")
        self._send(to_email, subject, body)

    def _send(self, to_email: str, subject: str, body: str) -> None:
        transport = self._transport or default_transport
        transport(dict(self.config), to_email, subject, body)

    def _ensure_template_row(self, code: str) -> None:
        """内置模板在数据库缺失时补种一行（幂等），保证数据库侧也能渲染。"""
        builtin = DEFAULT_TEMPLATES.get(code)
        if not builtin:
            return
        getter = getattr(self.db, "get_email_template", None)
        seeder = getattr(self.db, "seed_email_templates", None)
        if not callable(getter) or not callable(seeder):
            return
        try:
            if not getter(code):
                seeder({code: dict(builtin)})
        except Exception:  # 补种失败不影响入队/投递路径
            return

    def _load_template(self, code: str) -> dict:
        self._ensure_template_row(code)
        template = None
        getter = getattr(self.db, "get_email_template", None)
        if callable(getter):
            try:
                template = getter(code)
            except Exception:
                template = None
        if not template:
            template = DEFAULT_TEMPLATES.get(code)
        if not template:
            raise MailTemplateError(f"邮件模板不存在：{code}")
        return template

    def _record_failure(self, row: dict, exc: BaseException) -> None:
        error = _error_text(exc)
        self.last_error = error
        attempts = _as_int(row.get("attempts"), 0)
        # 数据库里的 attempts 是已失败次数；本次投递序号 = 已失败次数 + 1。
        attempt_no = max(1, attempts + 1)
        max_attempts = _as_int(row.get("max_attempts"), DEFAULT_MAX_ATTEMPTS)
        if max_attempts <= 0:
            max_attempts = DEFAULT_MAX_ATTEMPTS
        retry_at = (
            datetime.now() + timedelta(seconds=backoff_seconds(attempt_no))
        ).strftime("%Y-%m-%d %H:%M:%S")
        dead = attempt_no >= max_attempts
        try:
            self.db.mark_email_failed(
                row.get("id"), error, retry_at, dead=dead
            )
        except Exception as inner:  # 落库失败也不能中断整批
            self.last_error = _error_text(inner)


def _row_variables(row: dict) -> dict:
    """领取行里的变量：兼容已解析的 ``variables`` 与原始 ``variables_json``。"""
    raw = row.get("variables")
    if isinstance(raw, dict):
        return raw
    if raw is None:
        raw = row.get("variables_json")
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def build_mailer(db, smtp_config: dict) -> Mailer:
    """构造 Mailer；后台线程由调用方显式 ``start()``（便于服务启停配对）。"""
    return Mailer(db, smtp_config)


def send_test_email(db, smtp_config: dict, to_email: str) -> None:
    """直接发送一封内置测试邮件（不落队列、不依赖模板表）。

    走模块级 :func:`default_transport`，测试可替换该符号来拦截发送。
    ``db`` 参数为对齐契约保留：测试邮件不使用模板表与 outbox。
    """
    config = dict(smtp_config or {})
    if not is_smtp_configured(config):
        raise RuntimeError("SMTP 未启用或未配置")
    address = str(to_email or "").strip()
    if not address:
        raise ValueError("收件邮箱不能为空")
    template = DEFAULT_TEMPLATES["test_email"]
    variables = {"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    subject = render_template(template.get("subject", ""), variables)
    body = render_template(template.get("body", ""), variables)
    default_transport(config, address, subject, body)
