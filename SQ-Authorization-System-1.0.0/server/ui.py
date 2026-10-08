import csv
import inspect
import json
import os
import re
import threading
from datetime import datetime
from urllib.parse import urlsplit

import uvicorn
from PySide6.QtCore import QObject, QRunnable, QThreadPool, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QApplication,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import offline, security, theme
from core.api_client import ApiClient
from core.config import APP_AUTHOR, APP_COPYRIGHT, APP_NAME, APP_VERSION, Config
from core.database import Database
from core.widgets import (
    Card,
    confirm,
    PageHeader,
    StatCard,
    StatGrid,
    StatusBadge,
    Toast,
    make_button,
    prepare_table,
    sync_empty_hint,
)
from server.ai_gateway import AiGateway, AiGatewayError, CHAT_MODE, RESPONSES_MODE
from server.api import VERSION, create_app
from server.mailer import build_mailer, send_test_email, smtp_config_problem


class ServerController:
    def __init__(self, config: Config, db: Database):
        self.config = config
        self.db = db
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None
        self._mailer = None
        self.last_error = ""

    def start(self) -> None:
        if self.is_running() or self.is_starting():
            return
        self.last_error = ""
        mailer = build_mailer(self.db, self.config.data.setdefault("smtp", {}))
        self._mailer = mailer
        if mailer.is_ready():
            mailer.start()
        if "mailer" in inspect.signature(create_app).parameters:
            app = create_app(self.config, self.db, mailer=mailer)
        else:
            # 后端尚未接收 mailer 参数时保持服务器可启动（P1 并行期兼容）。
            mailer.stop(timeout=1)
            self._mailer = None
            app = create_app(self.config, self.db)
        cfg = uvicorn.Config(
            app,
            host=self.config.server["host"],
            port=int(self.config.server["port"]),
            log_level="warning",
            access_log=False,
        )
        server = uvicorn.Server(cfg)
        self._server = server

        def run() -> None:
            try:
                server.run()
            except Exception as exc:  # pragma: no cover - depends on host sockets
                self.last_error = str(exc) or exc.__class__.__name__

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        server = self._server
        if server:
            server.should_exit = True
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=3)
        self._server = None
        self._thread = None
        mailer = self._mailer
        if mailer is not None:
            mailer.stop(timeout=3)
        self._mailer = None

    def is_starting(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and not self.is_running())

    def is_running(self) -> bool:
        return bool(
            self._server
            and self._thread
            and self._thread.is_alive()
            and self._server.started
            and not self._server.should_exit
        )

    def url(self) -> str:
        return self.config.server_url()

AI_MODE_LABELS = {
    RESPONSES_MODE: "OpenAI Responses API",
    CHAT_MODE: "通用 Chat Completions（兼容 OpenAI）",
}

# Shorter labels for the settings combo: the long form above would force the
# scrollable settings column wider than the window and clip the buttons.
AI_MODE_ITEMS = {
    RESPONSES_MODE: "Responses API",
    CHAT_MODE: "Chat Completions（兼容）",
}

# Model suggestions per wire protocol; both combos stay editable so any
# vendor model id can be typed in.
AI_MODE_MODELS = {
    RESPONSES_MODE: [
        "gpt-5.1", "gpt-5.1-mini", "gpt-5", "gpt-4.1", "gpt-4.1-mini",
        "gpt-4o", "gpt-4o-mini",
    ],
    CHAT_MODE: [
        "agnes", "agnes-2.5",
        "gpt-4o-mini", "gpt-4o", "gpt-4.1-mini",
        "deepseek-chat", "deepseek-reasoner",
        "qwen-plus", "qwen-max", "glm-4-plus", "moonshot-v1-8k",
    ],
}

AI_ENV_KEYS = ("OPENAI_API_KEY", "AI_API_KEY", "OPENAI_COMPATIBLE_API_KEY")

_PRIVATE_HOST_RE = re.compile(r"^172\.(1[6-9]|2\d|3[01])\.")


def _normalise_ai_mode(raw) -> str:
    """Mirror ``AiGateway.api_mode`` so the combo shows the saved protocol."""
    text = str(raw or "").strip().lower().replace("-", "_")
    if text in ("", "responses", "response", "openai_responses", "openai"):
        return RESPONSES_MODE
    return CHAT_MODE


def _json_text(value) -> str:
    if not isinstance(value, dict) or not value:
        return ""
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)


def _parse_json_object(text: str, label: str) -> dict:
    raw = (text or "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{label}不是合法 JSON：{exc.msg}（第 {exc.lineno} 行）"
        ) from exc
    if not isinstance(data, dict):
        raise ValueError(f'{label}必须是 JSON 对象，例如 {{"key": "value"}}')
    return data


def _ai_base_url_error(base_url: str) -> str:
    """Reject plain http for anything but loopback/LAN endpoints.

    Intranet compatible gateways often speak http, but an API key must not
    travel in clear text to a public host.
    """
    text = (base_url or "").strip().lower()
    if text.startswith("https://"):
        return ""
    if text.startswith("http://"):
        host = urlsplit(text).hostname or ""
        local = host in ("localhost", "127.0.0.1", "::1") or host.startswith("10.")
        local = local or host.startswith("192.168.") or bool(_PRIVATE_HOST_RE.match(host))
        if local:
            return ""
        return "Base URL 使用 http:// 时只能是本机或内网地址，公网地址必须使用 https://"
    return "Base URL 必须以 https:// 开头（本机或内网可用 http://）"


def _format_email_list(values) -> str:
    if isinstance(values, str):
        values = values.replace(";", ",").split(",")
    return ", ".join(str(item).strip() for item in (values or []) if str(item).strip())


def _parse_email_list(text: str) -> list[str]:
    """Split a comma/semicolon separated recipient list; keep `@` entries only."""
    result: list[str] = []
    for item in re.split(r"[,;，；\s]+", str(text or "")):
        email = item.strip().lower()
        if email and "@" in email and email not in result:
            result.append(email)
    return result


class _AiProbeSignals(QObject):
    finished = Signal(bool, str)


class _AiProbeTask(QRunnable):
    """One OpenAI reachability probe off the Qt main thread."""

    def __init__(
        self,
        gateway: AiGateway,
        api_key: str,
        base_url: str,
        model: str,
        mode: str,
        signals: _AiProbeSignals,
    ):
        super().__init__()
        self.setAutoDelete(True)
        self.gateway = gateway
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.mode = mode
        self.signals = signals

    def run(self) -> None:
        try:
            message = self.gateway.probe(
                self.api_key, self.base_url, self.model, self.mode
            )
        except AiGatewayError as exc:
            self.signals.finished.emit(False, str(exc))
            return
        except Exception as exc:  # pragma: no cover - defensive
            self.signals.finished.emit(False, f"连接失败：{exc}")
            return
        self.signals.finished.emit(True, message)


class _SmtpTestSignals(QObject):
    finished = Signal(bool, str)


class _SmtpTestTask(QRunnable):
    """One SMTP test send off the Qt main thread."""

    def __init__(
        self,
        db: Database,
        smtp_config: dict,
        to_email: str,
        signals: _SmtpTestSignals,
    ):
        super().__init__()
        self.setAutoDelete(True)
        self.db = db
        self.smtp_config = dict(smtp_config or {})
        self.to_email = to_email
        self.signals = signals

    def run(self) -> None:
        try:
            send_test_email(self.db, self.smtp_config, self.to_email)
        except Exception as exc:  # pragma: no cover - depends on the SMTP host
            message = str(exc).strip() or exc.__class__.__name__
            self.signals.finished.emit(False, message)
            return
        self.signals.finished.emit(True, "")


class _AiAdvancedDialog(QDialog):
    """JSON editors for the optional vendor-specific request tweaks."""

    def __init__(self, headers_text: str, extra_text: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AI 高级设置")
        self.setModal(True)
        self.setMinimumWidth(520)
        self.headers_text = headers_text
        self.extra_text = extra_text
        self.headers_value: dict = {}
        self.extra_value: dict = {}

        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 22, 24, 20)
        outer.setSpacing(12)
        outer.addWidget(PageHeader("AI 高级设置", "仅兼容接口需要；留空表示不附加"))

        self.headers_edit = QPlainTextEdit(headers_text)
        self.headers_edit.setPlaceholderText('{\n  "X-Api-Version": "2024-01-01"\n}')
        self.extra_edit = QPlainTextEdit(extra_text)
        self.extra_edit.setPlaceholderText('{\n  "top_p": 0.9\n}')
        for edit in (self.headers_edit, self.extra_edit):
            edit.setMinimumHeight(96)

        form = QFormLayout()
        form.setSpacing(10)
        form.addRow("自定义请求头", self.headers_edit)
        form.addRow("附加请求体", self.extra_edit)
        outer.addLayout(form)

        hint = QLabel(
            "请求头会与默认请求头合并；协议头（Authorization、Content-Type 等）"
            "由系统统一生成，同名项会被忽略。"
        )
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        outer.addWidget(hint)

        self.error_label = QLabel("")
        self.error_label.setWordWrap(True)
        self.error_label.setStyleSheet(f"color: {theme.DANGER};")
        outer.addWidget(self.error_label)

        buttons = QDialogButtonBox()
        buttons.addButton("保存", QDialogButtonBox.AcceptRole)
        buttons.addButton("取消", QDialogButtonBox.RejectRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        outer.addWidget(buttons)

    def accept(self) -> None:
        try:
            headers = _parse_json_object(self.headers_edit.toPlainText(), "自定义请求头")
            extra = _parse_json_object(self.extra_edit.toPlainText(), "附加请求体")
        except ValueError as exc:
            self.error_label.setText(str(exc))
            return
        self.headers_value = headers
        self.extra_value = extra
        self.headers_text = _json_text(headers)
        self.extra_text = _json_text(extra)
        super().accept()


class ServerWindow(QMainWindow):
    def __init__(self, config: Config, db: Database, bootstrap_password: str = ""):
        super().__init__()
        self.config = config
        self.db = db
        self.controller = ServerController(config, db)
        # Set while the first-run credential dialog is on screen so the
        # auto-start toast cannot bury the one-time password.
        self._bootstrap_pending = False
        self.client = ApiClient(
            config.server_url(),
            timeout=3,
            allow_insecure_http=True,
            response_public_key=config.security.get("response_public_key", ""),
            response_key_id=config.security.get("response_key_id", ""),
        )

        self.setWindowTitle("密钥授权系统 · 本地服务器")
        self.resize(1120, 720)
        self.setMinimumSize(960, 640)

        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        layout.addWidget(self._build_topbar())
        layout.addWidget(self._build_stats())

        columns = QHBoxLayout()
        columns.setSpacing(16)
        columns.addWidget(self._build_settings_pane(), 0)
        columns.addWidget(self._build_logs(), 1)
        layout.addLayout(columns, 1)

        footer = QLabel(
            f"作者：{APP_AUTHOR}    {APP_NAME} v{APP_VERSION}    {APP_COPYRIGHT}\n"
            "本软件受《中华人民共和国著作权法》保护，未经作者许可不得复制、传播、反编译或用于商业用途。"
        )
        footer.setObjectName("Muted")
        footer.setWordWrap(True)
        layout.addWidget(footer)

        self.toast = Toast(self)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._safe_refresh)
        # 3 秒全量刷新会让 UI 线程与 API 争抢同一个 SQLite 锁，表现为周期性卡顿；
        # 改为 10 秒，并用 stats_cached() 复用统计结果。
        self.timer.start(10000)

        self.refresh()
        if bootstrap_password:
            # Hold auto-start back until the operator has actually seen and
            # dismissed the one-time password.
            self._bootstrap_pending = True
            self._bootstrap_password = bootstrap_password
            QTimer.singleShot(0, self.present_bootstrap_credentials)
        else:
            self._bootstrap_password = ""
            QTimer.singleShot(300, self.auto_start)

    def _build_topbar(self) -> QWidget:
        card = Card(padding=16)
        row = QHBoxLayout()
        row.setSpacing(14)

        titles = QVBoxLayout()
        titles.setSpacing(2)
        brand = QLabel("密钥授权 · 本地服务器")
        brand.setObjectName("Title")
        sub = QLabel(f"数据与验证中枢  ·  v{VERSION}")
        sub.setObjectName("Subtitle")
        titles.addWidget(brand)
        titles.addWidget(sub)

        row.addLayout(titles)
        row.addStretch(1)

        self.status_chip = StatusBadge("● 已停止", "error")
        self.status_chip.setMinimumWidth(96)
        row.addWidget(self.status_chip)

        self.btn_start = make_button("启动服务", "primary", self.on_start)
        self.btn_stop = make_button("停止服务", "danger", self.on_stop)
        self.btn_stop.setEnabled(False)
        row.addWidget(self.btn_start)
        row.addWidget(self.btn_stop)

        card.body.addLayout(row)
        return card

    def _build_stats(self) -> QWidget:
        self.stat_total = StatCard("密钥总数", "0", theme.PRIMARY)
        self.stat_active = StatCard("已激活", "0", theme.SUCCESS)
        self.stat_devices = StatCard("绑定设备", "0", theme.FROZEN)
        self.stat_admins = StatCard("管理员", "0", theme.WARNING)
        return StatGrid(
            [self.stat_total, self.stat_active, self.stat_devices, self.stat_admins],
            columns=4,
            min_card_width=150,
        )

    def _build_settings(self) -> QWidget:
        card = Card(padding=18)
        card.setMinimumWidth(320)
        card.body.addWidget(PageHeader("服务设置", "修改后需重启服务生效"))

        form = QFormLayout()
        form.setSpacing(12)
        form.setLabelAlignment(Qt.AlignLeft)
        self.input_host = QLineEdit(self.config.server["host"])
        self.input_host.setPlaceholderText("127.0.0.1")
        self.input_port = QSpinBox()
        self.input_port.setRange(1, 65535)
        self.input_port.setValue(int(self.config.server["port"]))
        self.input_public = QLineEdit(self.config.server.get("public_base_url", ""))
        self.input_public.setPlaceholderText("留空则使用本机地址（公网可填 https://...）")
        # The settings card lives in a scroll area, but the fields also get an
        # explicit floor so a cramped column can never squash them to nothing.
        for field in (self.input_host, self.input_port, self.input_public):
            field.setMinimumHeight(30)
        form.addRow("监听地址", self.input_host)
        form.addRow("端口", self.input_port)
        form.addRow("公网地址", self.input_public)
        card.body.addLayout(form)

        self.db_label = QLabel(str(self.config.db_path()))
        self.db_label.setObjectName("Muted")
        self.db_label.setWordWrap(True)
        card.body.addWidget(QLabel("数据库文件"))
        card.body.addWidget(self.db_label)

        self.url_label = QLabel("")
        self.url_label.setObjectName("KeyText")
        card.body.addWidget(QLabel("服务地址"))
        card.body.addWidget(self.url_label)

        row = QHBoxLayout()
        row.addWidget(make_button("保存设置", "default", self.on_save))
        row.addWidget(make_button("立即自检", "ghost", self.on_selfcheck))
        card.body.addLayout(row)

        maintenance_title = QLabel("数据库维护")
        maintenance_title.setObjectName("SectionTitle")
        card.body.addWidget(maintenance_title)
        maintenance = QHBoxLayout()
        maintenance.addWidget(make_button("备份数据库", "default", self.on_backup))
        maintenance.addWidget(make_button("恢复数据库", "danger", self.on_restore))
        card.body.addLayout(maintenance)
        card.body.addWidget(make_button("复制客户端公钥", "ghost", self.on_copy_public_keys))
        card.body.addStretch(1)
        return card

    def _build_smtp_settings(self) -> QWidget:
        card = Card(padding=18)
        card.body.addWidget(
            PageHeader("SMTP 邮件", "验证码、找回密码与安全告警 · 保存后重启服务生效")
        )
        smtp = self.config.data.setdefault("smtp", {})

        self.smtp_enabled = QCheckBox("启用 SMTP 邮件")
        self.smtp_enabled.setChecked(bool(smtp.get("enabled", False)))

        self.smtp_host = QLineEdit(str(smtp.get("host") or ""))
        self.smtp_host.setPlaceholderText("例如 smtp.example.com")

        self.smtp_port = QSpinBox()
        self.smtp_port.setRange(1, 65535)
        self.smtp_port.setValue(int(smtp.get("port") or 587))

        self.smtp_username = QLineEdit(str(smtp.get("username") or ""))
        self.smtp_username.setPlaceholderText("通常是完整邮箱地址，可留空")

        self.smtp_password = QLineEdit(str(smtp.get("password") or ""))
        self.smtp_password.setEchoMode(QLineEdit.Password)

        self.smtp_from_email = QLineEdit(str(smtp.get("from_email") or ""))
        self.smtp_from_email.setPlaceholderText("例如 no-reply@example.com")

        self.smtp_from_name = QLineEdit(str(smtp.get("from_name") or "密钥授权系统"))

        self.smtp_starttls = QCheckBox("STARTTLS")
        self.smtp_starttls.setChecked(bool(smtp.get("use_starttls", True)))
        self.smtp_ssl = QCheckBox("SSL")
        self.smtp_ssl.setChecked(bool(smtp.get("use_ssl", False)))

        self.smtp_timeout = QSpinBox()
        self.smtp_timeout.setRange(1, 300)
        self.smtp_timeout.setSuffix(" 秒")
        self.smtp_timeout.setValue(int(smtp.get("timeout") or 15))

        self.smtp_alert_emails = QLineEdit(
            _format_email_list(smtp.get("alert_admin_emails"))
        )
        self.smtp_alert_emails.setPlaceholderText("多个邮箱用英文逗号分隔")

        for field in (
            self.smtp_host,
            self.smtp_port,
            self.smtp_username,
            self.smtp_password,
            self.smtp_from_email,
            self.smtp_from_name,
            self.smtp_starttls,
            self.smtp_ssl,
            self.smtp_timeout,
            self.smtp_alert_emails,
        ):
            field.setMinimumHeight(30)

        form = QFormLayout()
        form.setSpacing(12)
        form.setLabelAlignment(Qt.AlignLeft)
        form.addRow("开关", self.smtp_enabled)
        form.addRow("服务器主机", self.smtp_host)
        form.addRow("端口", self.smtp_port)
        form.addRow("用户名", self.smtp_username)
        form.addRow("密码", self.smtp_password)
        form.addRow("发件邮箱", self.smtp_from_email)
        form.addRow("发件人名称", self.smtp_from_name)
        form.addRow("STARTTLS", self.smtp_starttls)
        form.addRow("SSL", self.smtp_ssl)
        form.addRow("超时", self.smtp_timeout)
        form.addRow("告警收件人", self.smtp_alert_emails)
        card.body.addLayout(form)

        row = QHBoxLayout()
        row.addWidget(make_button("保存 SMTP 设置", "primary", self.on_save_smtp))
        row.addWidget(make_button("发送测试邮件", "default", self.on_test_smtp))
        card.body.addLayout(row)

        self.smtp_status = QLabel(self._smtp_status_text())
        self.smtp_status.setObjectName("Muted")
        self.smtp_status.setWordWrap(True)
        card.body.addWidget(self.smtp_status)
        return card

    def _smtp_status_text(self) -> str:
        smtp = self.config.data.get("smtp") or {}
        if not smtp.get("enabled"):
            return "当前未启用；启用并保存后，验证码、找回密码与安全告警邮件才会发送。"
        host = str(smtp.get("host") or "").strip()
        sender = str(smtp.get("from_email") or smtp.get("username") or "").strip()
        if not host or not sender:
            return "已启用但配置不完整：请填写服务器主机与发件邮箱（或用户名）。"
        return f"已启用 · {host}:{int(smtp.get('port') or 587)} · 发件人 {sender}"

    def _build_settings_pane(self) -> QWidget:
        """Scrollable shell around the settings card.

        The card alone is taller than the space the two-column layout can
        grant it at 1120x720, which used to squeeze the host/port/public
        fields down to a few pixels. Scrolling keeps every field usable.
        """
        pane = QScrollArea()
        pane.setWidgetResizable(True)
        pane.setFrameShape(QFrame.NoFrame)
        pane.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        # 深色系统主题下滚动视口可能透出黑底，形成滚动黑带。
        pane.viewport().setAutoFillBackground(True)
        pane.setMinimumWidth(340)
        pane.setMaximumWidth(430)
        pane.setWidget(self._build_settings_pane_body())
        return pane

    def _build_ai_settings(self) -> QWidget:
        card = Card(padding=18)
        card.body.addWidget(PageHeader("AI 助手", "OpenAI 及兼容接口 · 保存后自动重启服务生效"))
        ai = self.config.ai
        form = QFormLayout()
        form.setSpacing(12)
        form.setLabelAlignment(Qt.AlignLeft)

        self.ai_enabled = QCheckBox("启用 AI 助手")
        self.ai_enabled.setChecked(bool(ai.get("enabled", False)))

        self.ai_mode = QComboBox()
        self.ai_mode.setSizeAdjustPolicy(
            QComboBox.AdjustToMinimumContentsLengthWithIcon
        )
        self.ai_mode.setMinimumContentsLength(14)
        for mode, label in AI_MODE_ITEMS.items():
            self.ai_mode.addItem(label, mode)
        saved_mode = _normalise_ai_mode(ai.get("api_mode") or ai.get("provider"))
        index = self.ai_mode.findData(saved_mode)
        self.ai_mode.setCurrentIndex(index if index >= 0 else 0)

        self.ai_vendor = QLineEdit(str(ai.get("vendor_name") or ""))
        self.ai_vendor.setPlaceholderText("例如 OpenAI / DeepSeek / 通义千问，留空自动判断")

        self.ai_key = QLineEdit()
        self.ai_key = QLineEdit(str(ai.get("api_key") or ""))
        self.ai_key.setEchoMode(QLineEdit.Password)
        self.ai_key.setPlaceholderText(
            "填写后保存；留空则保留已保存的 Key，也可用 AI_API_KEY 环境变量"
        )

        self.ai_base = QLineEdit(str(ai.get("base_url", "https://api.openai.com/v1")))
        self.ai_model = QComboBox()
        self.ai_model.setEditable(True)
        self._fill_ai_models(str(ai.get("model", "gpt-5.1")))

        self.ai_effort = QComboBox()
        for label, value in (
            ("低（更快）", "low"),
            ("中（推荐）", "medium"),
            ("高（更强推理）", "high"),
        ):
            self.ai_effort.addItem(label, value)
        current_effort = str(ai.get("reasoning_effort", "medium"))
        index = self.ai_effort.findData(current_effort)
        self.ai_effort.setCurrentIndex(index if index >= 0 else 1)

        self.ai_tokens = QSpinBox()
        self.ai_tokens.setRange(256, 32768)
        self.ai_tokens.setSingleStep(256)
        self.ai_tokens.setValue(int(ai.get("max_output_tokens", 2048)))

        # Advanced JSON lives in the dialog; it is only written on save.
        self._ai_headers_text = _json_text(ai.get("custom_headers"))
        self._ai_extra_text = _json_text(ai.get("extra_body"))

        for field in (
            self.ai_mode,
            self.ai_vendor,
            self.ai_key,
            self.ai_base,
            self.ai_model,
            self.ai_effort,
            self.ai_tokens,
        ):
            field.setMinimumHeight(30)

        form.addRow("开关", self.ai_enabled)
        form.addRow("接口协议", self.ai_mode)
        form.addRow("提供商名称", self.ai_vendor)
        form.addRow("API Key", self.ai_key)
        form.addRow("Base URL", self.ai_base)
        form.addRow("模型", self.ai_model)
        form.addRow("推理强度", self.ai_effort)
        form.addRow("最大输出", self.ai_tokens)
        card.body.addLayout(form)

        row = QHBoxLayout()
        row.addWidget(make_button("保存并重启", "primary", self.on_save_ai))
        row.addWidget(make_button("测试连接", "default", self.on_test_ai))
        row.addWidget(make_button("高级设置", "ghost", self.on_edit_ai_advanced))
        card.body.addLayout(row)

        self.ai_status = QLabel(self._ai_status_text())
        self.ai_status.setObjectName("Muted")
        self.ai_status.setWordWrap(True)
        card.body.addWidget(self.ai_status)

        self.ai_mode.currentIndexChanged.connect(self._on_ai_mode_changed)
        self._update_ai_placeholders()
        return card

    def _ai_status_text(self) -> str:
        if not self.ai_enabled.isChecked():
            return "当前未启用。开启并保存后，主控端与管理端会出现可用的 AI 助手。"
        if not self._ai_has_key():
            return (
                f"已启用但缺少 {self._ai_vendor_text()} 的 API Key："
                "请在下方填写，或配置 OPENAI_API_KEY / AI_API_KEY 环境变量。"
            )
        label = AI_MODE_LABELS.get(self._current_ai_mode(), "")
        return (
            f"已启用 · {self._ai_vendor_text()} · {label} · "
            f"模型 {self.ai_model.currentText().strip()} · {self.ai_base.text().strip()}"
        )

    def _current_ai_mode(self) -> str:
        return str(self.ai_mode.currentData() or RESPONSES_MODE)

    def _fill_ai_models(self, current: str) -> None:
        """Repopulate the model suggestions for the selected protocol."""
        models = list(AI_MODE_MODELS.get(self._current_ai_mode(), ()))
        text = (current or "").strip() or (models[0] if models else "")
        self.ai_model.blockSignals(True)
        self.ai_model.clear()
        self.ai_model.addItems(models)
        if text and text not in models:
            self.ai_model.addItem(text)
        self.ai_model.setCurrentText(text)
        self.ai_model.blockSignals(False)

    def _update_ai_placeholders(self) -> None:
        if self._current_ai_mode() == CHAT_MODE:
            self.ai_base.setPlaceholderText("例如 https://api.deepseek.com/v1，填到 /v1 即可")
        else:
            self.ai_base.setPlaceholderText("https://api.openai.com/v1")

    def _on_ai_mode_changed(self, _index: int = 0) -> None:
        """Keep model suggestions and status text in step with the protocol."""
        self._fill_ai_models(self.ai_model.currentText())
        self._update_ai_placeholders()
        self.ai_status.setText(self._ai_status_text())

    def _ai_vendor_text(self) -> str:
        vendor = self.ai_vendor.text().strip()
        if vendor:
            return vendor
        return "OpenAI" if self._current_ai_mode() == RESPONSES_MODE else "AI 提供商"

    def _ai_has_key(self) -> bool:
        if self.ai_key.text().strip():
            return True
        if str(self.config.ai.get("api_key") or "").strip():
            return True
        return any(os.environ.get(name, "").strip() for name in AI_ENV_KEYS)

    def _collect_ai_config(self) -> dict | None:
        """Merge the form values into a config dict for the gateway.

        The JSON fields are handed to the gateway untouched: it owns the
        reserved-key rules for headers and body fields.
        """
        try:
            headers = _parse_json_object(self._ai_headers_text, "自定义请求头")
            extra = _parse_json_object(self._ai_extra_text, "附加请求体")
        except ValueError as exc:
            self.toast.show_message(str(exc), "error", 7000)
            return None
        config = dict(self.config.ai)
        config.update(
            {
                "api_mode": self._current_ai_mode(),
                "vendor_name": self.ai_vendor.text().strip(),
                "base_url": self.ai_base.text().strip() or "https://api.openai.com/v1",
                "model": self.ai_model.currentText().strip() or "gpt-5.1",
                "reasoning_effort": str(self.ai_effort.currentData() or "medium"),
                "max_output_tokens": int(self.ai_tokens.value()),
                "custom_headers": headers,
                "extra_body": extra,
            }
        )
        return config

    def on_edit_ai_advanced(self) -> None:
        dialog = _AiAdvancedDialog(self._ai_headers_text, self._ai_extra_text, self)
        if dialog.exec() != QDialog.Accepted:
            return
        self._ai_headers_text = dialog.headers_text
        self._ai_extra_text = dialog.extra_text
        self.toast.show_message("高级设置已记录，点击“保存并重启”后生效", "success")

    def on_save_ai(self) -> None:
        ai = self.config.ai
        config = self._collect_ai_config()
        if config is None:
            return
        base_url = config["base_url"]
        error = _ai_base_url_error(base_url)
        if error:
            self.toast.show_message(error, "error", 7000)
            return
        if self.ai_enabled.isChecked() and not self._ai_has_key():
            self.toast.show_message("启用 AI 前请先填写 API Key", "error", 7000)
            return
        key = self.ai_key.text().strip()
        if key:
            ai["api_key"] = key
        mode = config["api_mode"]
        ai["enabled"] = bool(self.ai_enabled.isChecked())
        ai["api_mode"] = mode
        # ``provider`` is the legacy alias older config files still carry.
        ai["provider"] = "openai" if mode == RESPONSES_MODE else "compatible"
        ai["vendor_name"] = config["vendor_name"]
        ai["base_url"] = base_url
        ai["model"] = config["model"]
        ai["reasoning_effort"] = config["reasoning_effort"]
        ai["max_output_tokens"] = config["max_output_tokens"]
        ai["custom_headers"] = config["custom_headers"]
        ai["extra_body"] = config["extra_body"]
        self.config.save()
        self.db.add_log("AI配置", "server", "", f"保存 AI 设置（{mode}）", "")
        # Keep the key in the (masked) field so the operator can see that it was
        # saved instead of assuming the gateway dropped it after the restart.
        self.ai_key.setText(str(ai.get("api_key") or ""))
        self.ai_status.setText(self._ai_status_text())
        if self.controller.is_running() or self.controller.is_starting():
            self.controller.stop()
            self.on_start()
            self.toast.show_message("AI 设置已保存，服务正在重启", "success")
        else:
            self.toast.show_message("AI 设置已保存", "success")

    def on_test_ai(self) -> None:
        config = self._collect_ai_config()
        if config is None:
            return
        base_url = config["base_url"]
        error = _ai_base_url_error(base_url)
        if error:
            self.toast.show_message(error, "error", 7000)
            return
        # The gateway is assembled here on the UI thread; the worker only probes.
        gateway = AiGateway(self.db, config)
        key = self.ai_key.text().strip() or gateway.api_key
        if not key:
            self.toast.show_message(
                "请先填写 API Key（或设置 OPENAI_API_KEY / AI_API_KEY 环境变量）",
                "warning",
                7000,
            )
            return
        self.ai_status.setText(f"正在测试 {gateway.vendor_name} 连接…")
        signals = _AiProbeSignals()
        signals.finished.connect(self._on_ai_probe_finished)
        QThreadPool.globalInstance().start(
            _AiProbeTask(
                gateway,
                key,
                base_url,
                config["model"],
                config["api_mode"],
                signals,
            )
        )

    def _on_ai_probe_finished(self, ok: bool, message: str) -> None:
        self.ai_status.setText(message)
        self.toast.show_message(
            "AI 连接正常" if ok else "AI 连接失败",
            "success" if ok else "error",
            5000 if ok else 7000,
        )

    def _build_settings_pane_body(self) -> QWidget:
        body = QWidget()
        column = QVBoxLayout(body)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(14)
        column.addWidget(self._build_settings())
        column.addWidget(self._build_smtp_settings())
        column.addWidget(self._build_ai_settings())
        column.addStretch(1)
        return body

    def present_bootstrap_credentials(self) -> None:
        """Modal, copyable first-run credentials; starts the service after."""
        password = self._bootstrap_password
        dialog = QDialog(self)
        dialog.setWindowTitle("首次运行 · 主控账号")
        dialog.setModal(True)

        outer = QVBoxLayout(dialog)
        outer.setContentsMargins(24, 22, 24, 20)
        outer.setSpacing(12)
        outer.addWidget(
            PageHeader(
                "已创建主控账号", "该密码只显示这一次，请立即保存并在登录后修改"
            )
        )

        form = QFormLayout()
        form.setSpacing(10)
        user_field = QLineEdit("admin")
        pass_field = QLineEdit(password)
        for field in (user_field, pass_field):
            field.setReadOnly(True)
            field.setMinimumHeight(30)
            field.setCursorPosition(0)
        form.addRow("用户名", user_field)
        form.addRow("初始密码", pass_field)
        outer.addLayout(form)

        hint = QLabel("服务将在关闭本窗口后自动启动。")
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        outer.addWidget(hint)

        buttons = QDialogButtonBox()
        copy_user_button = QPushButton("复制账号")
        copy_password_button = QPushButton("复制密码")
        copy_button = QPushButton("复制账号密码")
        buttons.addButton("我已保存", QDialogButtonBox.AcceptRole)
        buttons.addButton(copy_user_button, QDialogButtonBox.ActionRole)
        buttons.addButton(copy_password_button, QDialogButtonBox.ActionRole)
        buttons.addButton(copy_button, QDialogButtonBox.ActionRole)

        copy_user_button.clicked.connect(self._copy_bootstrap_username)
        copy_password_button.clicked.connect(self._copy_bootstrap_password)
        copy_button.clicked.connect(self._copy_bootstrap_both)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        outer.addWidget(buttons)

        dialog.setMinimumWidth(460)
        try:
            dialog.exec()
        finally:
            # Drop the plaintext password as soon as the operator dismisses
            # the dialog; nothing here is written to disk.
            self._bootstrap_password = ""
            pass_field.clear()
            self._bootstrap_pending = False
            self.auto_start()

    def _copy_bootstrap_username(self) -> None:
        """首次引导弹窗的复制动作拆成小方法，便于单测直接调用。"""
        QApplication.clipboard().setText("admin")
        self.toast.show_message("账号已复制", "success")

    def _copy_bootstrap_password(self) -> None:
        QApplication.clipboard().setText(str(self._bootstrap_password or ""))
        self.toast.show_message("密码已复制", "success")

    def _copy_bootstrap_both(self) -> None:
        QApplication.clipboard().setText(f"admin\n{self._bootstrap_password or ''}")
        self.toast.show_message("账号密码已复制", "success")

    def _build_logs(self) -> QWidget:
        card = Card(padding=18)
        header = QHBoxLayout()
        header.addWidget(PageHeader("审计日志", "记录登录、密钥、验证与激活事件"))
        header.addStretch(1)
        self.log_total = QLabel("共 0 条")
        self.log_total.setObjectName("Muted")
        header.addWidget(self.log_total)
        header.addWidget(make_button("导出日志", "ghost", self.on_export_logs))
        header.addWidget(make_button("刷新", "ghost", self.refresh))
        card.body.addLayout(header)

        filters = QHBoxLayout()
        self.log_keyword = QLineEdit()
        self.log_keyword.setPlaceholderText("搜索操作、对象、详情、来源")
        self.log_keyword.setClearButtonEnabled(True)
        self.log_keyword.returnPressed.connect(self.refresh)
        self.log_action = QComboBox()
        self.log_action.addItem("全部操作", "")
        for action in (
            "登录成功", "登录失败", "登录锁定", "生成密钥",
            "激活成功", "重复激活", "激活失败", "验证成功", "验证失败",
            "生成离线激活码", "生成离线激活码失败", "吊销密钥", "恢复密钥",
            "续期密钥", "冻结密钥", "解冻密钥", "删除密钥", "解绑设备",
            "吊销批次", "签名校验失败", "重放拦截",
            "创建管理员", "修改管理员状态", "重置管理员密码", "修改自己的密码",
            "AI操作", "AI配置",
            "SMTP配置",
            "备份数据库", "恢复数据库",
        ):
            self.log_action.addItem(action, action)
        self.log_action.currentIndexChanged.connect(lambda _index: self.refresh())
        self.log_action.setMinimumWidth(130)
        filters.addWidget(self.log_keyword, 1)
        filters.addWidget(self.log_action)
        card.body.addLayout(filters)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["时间", "操作", "发起人", "对象", "详情", "来源"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        prepare_table(self.table)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        card.body.addWidget(self.table, 1)
        return card

    def auto_start(self) -> None:
        self.on_start()
        if self.controller.is_running():
            self.toast.show_message("本地服务器已自动启动", "success")

    def on_save(self) -> None:
        self.config.server["host"] = self.input_host.text().strip() or "127.0.0.1"
        self.config.server["port"] = int(self.input_port.value())
        self.config.server["public_base_url"] = self.input_public.text().strip()
        self.config.save()
        self.client.set_base_url(self.config.server_url())
        self.url_label.setText(self.config.server_url())
        self.toast.show_message("设置已保存", "success")

    def _collect_smtp_config(self) -> dict:
        return {
            "enabled": bool(self.smtp_enabled.isChecked()),
            "host": self.smtp_host.text().strip(),
            "port": int(self.smtp_port.value()),
            "username": self.smtp_username.text().strip(),
            "password": self.smtp_password.text().strip(),
            "from_email": self.smtp_from_email.text().strip(),
            "from_name": self.smtp_from_name.text().strip() or "密钥授权系统",
            "use_starttls": bool(self.smtp_starttls.isChecked()),
            "use_ssl": bool(self.smtp_ssl.isChecked()),
            "timeout": int(self.smtp_timeout.value()),
            "alert_admin_emails": _parse_email_list(self.smtp_alert_emails.text()),
        }

    def on_save_smtp(self) -> None:
        config = self._collect_smtp_config()
        if config["enabled"]:
            problem = smtp_config_problem(config)
            if problem:
                self.toast.show_message(f"SMTP 配置有误：{problem}", "error", 8000)
                return
        target = self.config.data.setdefault("smtp", {})
        target.clear()
        target.update(config)
        self.config.save()
        state = "启用" if config["enabled"] else "停用"
        host = config["host"] or "未填主机"
        self.db.add_log("SMTP配置", "server", "", f"保存 SMTP 设置（{state} · {host}）", "")
        self.smtp_status.setText(self._smtp_status_text())
        self.toast.show_message("SMTP 设置已保存", "success")

    def on_test_smtp(self) -> None:
        to_email, accepted = QInputDialog.getText(self, "发送测试邮件", "收件邮箱")
        to_email = str(to_email or "").strip()
        if not accepted or not to_email:
            return
        config = self._collect_smtp_config()
        if not config["host"] or not (config["from_email"] or config["username"]):
            self.toast.show_message(
                "请先填写服务器主机与发件邮箱（或用户名）", "error", 7000
            )
            return
        # SMTP 在 QThreadPool 里执行；UI 线程只负责弹窗与 toast。
        self.toast.show_message("正在发送测试邮件…", "info")
        signals = _SmtpTestSignals(self)
        signals.finished.connect(self._on_smtp_test_finished)
        QThreadPool.globalInstance().start(
            _SmtpTestTask(self.db, config, to_email, signals)
        )

    def _on_smtp_test_finished(self, ok: bool, message: str) -> None:
        if ok:
            self.toast.show_message("测试邮件已发送，请检查收件箱", "success", 5000)
        else:
            self.toast.show_message(f"测试邮件发送失败：{message}", "error", 8000)

    def on_start(self) -> None:
        if self.controller.is_running():
            return
        try:
            self.controller.start()
        except Exception as exc:
            self.toast.show_message(f"启动失败：{exc}", "error")
            return
        QTimer.singleShot(700, self._after_start)

    def _after_start(self) -> None:
        if self.controller.is_running():
            self.toast.show_message("服务已启动", "success")
        elif self.controller.last_error:
            self.toast.show_message(f"启动失败：{self.controller.last_error}", "error", 7000)
        elif self.controller.is_starting():
            self.toast.show_message("启动中，请稍候…", "info")
        else:
            self.toast.show_message("服务未能启动，请检查端口是否被占用", "error", 7000)
        self.refresh()

    def on_stop(self) -> None:
        self.controller.stop()
        self.toast.show_message("服务已停止", "warning")
        self.refresh()

    def on_selfcheck(self) -> None:
        try:
            health = self.db.check_health()
        except Exception as exc:
            self.toast.show_message(f"数据库自检失败：{exc}", "error", 7000)
            return
        if health.get("integrity") != "ok" or health.get("foreign_key_errors"):
            self.toast.show_message(
                f"数据库自检失败：{health.get('integrity')}",
                "error",
                7000,
            )
            return
        try:
            data = self.client.health()
            self.toast.show_message(
                f"自检通过 · 数据库正常 · {data.get('version')} · {data.get('time')}",
                "success",
            )
        except Exception as exc:
            self.toast.show_message(f"数据库正常，但服务未就绪：{exc}", "warning", 7000)

    def on_backup(self) -> None:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default = self.config.db_path().with_name(f"license_backup_{stamp}.db")
        path, _ = QFileDialog.getSaveFileName(
            self,
            "备份授权数据库",
            str(default),
            "SQLite 数据库 (*.db);;所有文件 (*)",
        )
        if not path:
            return
        try:
            self.db.add_log("备份数据库", "server", path, "", "")
            target = self.db.backup_to(path)
        except Exception as exc:
            self.toast.show_message(f"备份失败：{exc}", "error", 7000)
            return
        self.toast.show_message(f"数据库已备份到 {target}", "success", 7000)

    def on_restore(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "恢复授权数据库",
            str(self.config.db_path().parent),
            "SQLite 数据库 (*.db);;所有文件 (*)",
        )
        if not path:
            return
        if not confirm(
            self,
            "恢复数据库",
            "恢复会覆盖当前所有权限、卡密和日志数据。\n"
            "系统会先自动生成一份当前数据的安全备份。是否继续？",
        ):
            return
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safety = self.config.db_path().parent / "backups" / f"before_restore_{stamp}.db"
        was_running = self.controller.is_running()
        if was_running:
            self.controller.stop()
        try:
            self.db.backup_to(safety)
            self.db.restore_from(path)
            self.db.add_log("恢复数据库", "server", path, f"安全备份 {safety}", "")
            self.client.clear_session()
        except Exception as exc:
            self.toast.show_message(f"恢复失败：{exc}", "error", 7000)
            return
        finally:
            if was_running:
                try:
                    self.controller.start()
                    QTimer.singleShot(700, self._after_start)
                except Exception as exc:
                    self.toast.show_message(f"服务重启失败：{exc}", "error", 7000)
        self.refresh()
        self.toast.show_message(f"数据库已恢复，原数据备份在 {safety}", "success", 8000)

    def on_copy_public_keys(self) -> None:
        offline_key = self.config.security.get("offline_public_key", "")
        response_key = self.config.security.get("response_public_key", "")
        text = (
            f"offline_public_key={offline_key}\n"
            f"offline_fingerprint={offline.public_key_fingerprint(offline_key)}\n"
            f"response_public_key={response_key}\n"
            f"response_fingerprint={offline.public_key_fingerprint(response_key)}\n"
            f"response_key_id={self.config.security.get('response_key_id', '')}"
        )
        QApplication.clipboard().setText(text)
        self.toast.show_message("客户端公钥已复制", "success")

    def on_export_logs(self) -> None:
        keyword = self.log_keyword.text().strip()
        action = self.log_action.currentData() or ""
        total = self.db.count_logs(keyword=keyword, action=action)
        if not total:
            self.toast.show_message("当前筛选条件下没有日志", "warning")
            return
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path, _ = QFileDialog.getSaveFileName(
            self,
            "导出审计日志",
            str(self.config.db_path().with_name(f"audit_logs_{stamp}.csv")),
            "CSV 文件 (*.csv);;所有文件 (*)",
        )
        if not path:
            return
        logs = self._all_logs(keyword, action)
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(["时间", "操作", "发起人", "对象", "详情", "来源"])
                for item in logs:
                    writer.writerow([
                        security.csv_safe_cell(item.get("created_at", "")),
                        security.csv_safe_cell(item.get("action", "")),
                        security.csv_safe_cell(item.get("actor", "")),
                        security.csv_safe_cell(item.get("target", "")),
                        security.csv_safe_cell(item.get("detail", "")),
                        security.csv_safe_cell(item.get("ip", "")),
                    ])
        except OSError as exc:
            self.toast.show_message(f"导出失败：{exc}", "error", 7000)
            return
        self.toast.show_message(f"已导出 {len(logs)} 条日志", "success", 5000)

    def _all_logs(self, keyword: str, action: str) -> list:
        """Page through the audit table so an export is never a partial file.

        ``Database.list_logs`` caps a single query at 1000 rows, so the export
        walks the table instead of silently truncating at that ceiling.
        """
        page_size = 1000
        collected: list = []
        offset = 0
        while True:
            chunk = self.db.list_logs(
                limit=page_size, offset=offset, keyword=keyword, action=action
            )
            collected.extend(chunk)
            if len(chunk) < page_size:
                return collected
            offset += page_size

    def _safe_refresh(self) -> None:
        """定时器护栏：数据库/UI 偶发异常只记日志，不让事件循环崩掉。"""
        try:
            self.refresh()
        except Exception as exc:
            try:
                from core import crashlog

                crashlog.log_exception("server-ui-refresh", exc)
            except Exception:
                pass
            # 测试/退出阶段数据库先关闭时，定时器应停掉而不是每 10 秒刷一条日志。
            if "closed database" in str(exc).lower():
                try:
                    self.timer.stop()
                except Exception:
                    pass

    def refresh(self) -> None:
        if self.isMinimized():
            return
        running = self.controller.is_running()
        starting = self.controller.is_starting()
        if running:
            self.status_chip.set_state("● 运行中", "success")
        elif starting:
            self.status_chip.set_state("● 启动中", "info")
        else:
            self.status_chip.set_state("● 已停止", "error")
        self.btn_start.setEnabled(not running and not starting)
        self.btn_stop.setEnabled(running)
        settings_enabled = not running and not starting
        self.input_host.setEnabled(settings_enabled)
        self.input_port.setEnabled(settings_enabled)
        self.input_public.setEnabled(settings_enabled)
        self.url_label.setText(self.controller.url())

        stats_getter = getattr(self.db, "stats_cached", None)
        stats = stats_getter() if callable(stats_getter) else self.db.stats()
        self.stat_total.set_value(stats["total"])
        self.stat_active.set_value(stats["active"])
        self.stat_devices.set_value(stats["devices"])
        self.stat_admins.set_value(stats["admins"])

        keyword = self.log_keyword.text().strip()
        action = self.log_action.currentData() or ""
        logs = self.db.list_logs(limit=50, keyword=keyword, action=action)
        # 10 秒一次的定时刷新走 30 秒计数缓存，避免随日志量增长的全表 COUNT；
        # 后端尚未提供缓存方法时回落到直接计数（并行批次兼容）。
        count_cached = getattr(self.db, "count_logs_cached", None)
        if callable(count_cached):
            total = count_cached(keyword=keyword, action=action)
        else:
            total = self.db.count_logs(keyword=keyword, action=action)
        # The table only previews the newest slice; say so instead of letting the
        # count look like it describes the visible rows.
        if total > len(logs):
            self.log_total.setText(f"共 {total} 条 · 显示最近 {len(logs)} 条")
        else:
            self.log_total.setText(f"共 {total} 条")
        self._fill_log_table(logs)

    def _fill_log_table(self, logs: list) -> None:
        """Repopulate the audit table and resync the empty-state overlay.

        Without the explicit sync a table that was empty on first paint
        keeps showing the placeholder after rows arrive.
        """
        self.table.setRowCount(len(logs))
        for row, item in enumerate(logs):
            values = [
                item.get("created_at", ""),
                item.get("action", ""),
                item.get("actor", ""),
                item.get("target", ""),
                item.get("detail", ""),
                item.get("ip", ""),
            ]
            for col, value in enumerate(values):
                self.table.setItem(row, col, QTableWidgetItem(str(value or "")))
        sync_empty_hint(self.table)

    def closeEvent(self, event) -> None:
        self.controller.stop()
        event.accept()
