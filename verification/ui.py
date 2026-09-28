import time

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPlainTextEdit,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core import machine, offline, security, theme
from core.api_client import ApiClient, ApiError
from core.config import APP_AUTHOR, APP_NAME, APP_VERSION, Config
from core.widgets import Card, Toast, make_button


RESULT_STYLE = {
    "success": (theme.SUCCESS, "#E7F7EE"),
    "warning": (theme.WARNING, "#FEF6E7"),
    "error": (theme.DANGER, "#FDECEA"),
    "info": (theme.TEXT_MUTED, "#F2F4F7"),
}


class VerifyWindow(QMainWindow):
    def __init__(self, config: Config):
        super().__init__()
        self.config = config
        self.client = ApiClient(
            config.client.get("server_url", "http://127.0.0.1:8765"),
            int(config.client.get("timeout", 8)),
        )
        self.client.set_session_secret(config.client.get("session_secret"))
        self.machine_code = machine.machine_code()
        self.device_name = machine.device_name()
        self.verify_max_failures = int(config.client.get("verify_max_failures", 5))
        self.verify_lock_seconds = int(config.client.get("verify_lock_seconds", 120))
        self.heartbeat_enabled = bool(config.client.get("heartbeat_enabled", True))
        self.heartbeat_interval = float(config.client.get("heartbeat_interval", 20))
        self.failure_count = 0
        self.locked_until = 0.0
        self.heartbeat_count = 0
        self.time_offset = 0.0

        self.heartbeat_timer = QTimer(self)
        self.heartbeat_timer.setSingleShot(True)
        self.heartbeat_timer.timeout.connect(self.heartbeat)

        self.setWindowTitle("密钥授权系统 · 验证端")

        content = QWidget()
        content.setObjectName("Root")
        layout = QVBoxLayout(content)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        layout.addWidget(self._build_header())

        body = QHBoxLayout()
        body.setSpacing(14)

        left = QVBoxLayout()
        left.setSpacing(14)
        left.addWidget(self._build_activate_card())
        left.addWidget(self._build_offline_card())
        left.addStretch(1)

        right = QVBoxLayout()
        right.setSpacing(14)
        right.addWidget(self._build_device_card())
        right.addWidget(self._build_result_card(), 1)

        body.addLayout(left, 3)
        body.addLayout(right, 2)
        layout.addLayout(body, 1)

        self.scroll = QScrollArea()
        self.scroll.setWidget(content)
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll.setStyleSheet(
            "QScrollArea { background: transparent; border: none; }"
            "QScrollArea > QWidget > QWidget { background: transparent; }"
        )
        self.setCentralWidget(self.scroll)

        self._fit_to_screen()
        self.toast = Toast(self)

        self.input_key.setText(str(config.client.get("last_key", "")))
        if config.client.get("auto_verify") and self.input_key.text().strip():
            QTimer.singleShot(400, self.verify)

    def _build_header(self) -> QWidget:
        box = QWidget()
        row = QHBoxLayout(box)
        row.setContentsMargins(0, 0, 0, 0)
        titles = QVBoxLayout()
        titles.setSpacing(2)
        brand = QLabel("密钥授权 · 验证端")
        brand.setObjectName("Title")
        sub = QLabel("在本设备上输入密钥完成激活与校验")
        sub.setObjectName("Subtitle")
        titles.addWidget(brand)
        titles.addWidget(sub)
        row.addLayout(titles)
        row.addStretch(1)
        credit = QLabel(f"作者：{APP_AUTHOR}    {APP_NAME} v{APP_VERSION}")
        credit.setObjectName("Muted")
        recent = QVBoxLayout()
        recent.setSpacing(2)
        recent.addStretch(1)
        recent.addWidget(credit)
        row.addLayout(recent)
        return box

    def _build_device_card(self) -> QWidget:
        card = Card(padding=18)
        card.body.addWidget(QLabel("本机信息"))
        info = machine.system_info()

        code_row = QHBoxLayout()
        self.machine_label = QLabel(self.machine_code)
        self.machine_label.setObjectName("KeyText")
        self.machine_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        code_row.addWidget(self.machine_label, 1)
        code_row.addWidget(make_button("复制机器码", "ghost", self.copy_machine))
        card.body.addLayout(code_row)

        meta = QLabel(f"设备名：{info['device_name']}    系统：{info['platform']}")
        meta.setObjectName("Muted")
        meta.setWordWrap(True)
        card.body.addWidget(meta)
        return card

    def _build_activate_card(self) -> QWidget:
        card = Card(padding=18)
        card.body.addWidget(QLabel("激活 / 校验"))

        self.input_server = QLineEdit(self.client.base_url)
        self.input_server.setPlaceholderText("http://127.0.0.1:8765")
        self.input_key = QLineEdit()
        self.input_key.setPlaceholderText("请输入密钥，如 LIC-XXXXX-XXXXX-XXXXX-XXXXX")
        self.input_key.returnPressed.connect(self.activate)

        card.body.addWidget(self._labeled("服务器地址", self.input_server))
        card.body.addWidget(self._labeled("授权密钥", self.input_key))

        self.auto_check = QCheckBox("记住密钥并在下次启动时自动校验")
        self.auto_check.setChecked(bool(self.config.client.get("auto_verify", True)))
        card.body.addWidget(self.auto_check)

        row = QHBoxLayout()
        row.addWidget(make_button("立即激活", "primary", self.activate))
        row.addWidget(make_button("校验状态", "default", self.verify))
        row.addWidget(make_button("连接测试", "ghost", self.test_connection))
        row.addStretch(1)
        card.body.addLayout(row)
        return card

    def _build_offline_card(self) -> QWidget:
        card = Card(padding=18)
        card.body.addWidget(QLabel("离线激活（无网络环境）"))
        hint = QLabel(
            "步骤：① 生成请求码交给管理员 → ② 管理员返回离线激活码 → "
            "③ 粘贴并导入，之后无需联网即可完成离线校验。"
        )
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        card.body.addWidget(hint)

        self.request_output = QPlainTextEdit()
        self.request_output.setReadOnly(True)
        self.request_output.setFixedHeight(64)
        self.request_output.setPlaceholderText("点击“生成请求码”后显示，复制发给管理员")
        card.body.addWidget(self._labeled("本机请求码", self.request_output))
        req_row = QHBoxLayout()
        req_row.addWidget(make_button("生成请求码", "default", self.make_request))
        req_row.addWidget(make_button("复制请求码", "ghost", self.copy_request))
        req_row.addWidget(make_button("保存请求码", "ghost", self.save_request))
        req_row.addStretch(1)
        card.body.addLayout(req_row)

        self.offline_input = QPlainTextEdit()
        self.offline_input.setFixedHeight(64)
        self.offline_input.setPlaceholderText("粘贴管理员返回的离线激活码（LICACT1. 开头）")
        card.body.addWidget(self._labeled("离线激活码", self.offline_input))
        imp_row = QHBoxLayout()
        imp_row.addWidget(make_button("导入离线激活码", "primary", self.import_offline))
        imp_row.addWidget(make_button("离线校验", "default", self.offline_verify))
        imp_row.addStretch(1)
        card.body.addLayout(imp_row)
        return card

    def _build_result_card(self) -> QWidget:
        card = Card(padding=18)
        card.body.addWidget(QLabel("授权状态"))
        self.status_card = QFrame()
        self.status_card.setObjectName("StatCard")
        status_layout = QVBoxLayout(self.status_card)
        status_layout.setContentsMargins(20, 18, 20, 18)
        status_layout.setSpacing(6)
        self.status_title = QLabel("尚未校验")
        self.status_title.setObjectName("Title")
        self.status_detail = QLabel("点击“校验状态”查看当前授权情况")
        self.status_detail.setObjectName("Muted")
        self.status_detail.setWordWrap(True)
        self.online_label = QLabel("心跳：未开启")
        self.online_label.setObjectName("Muted")
        self.online_label.setWordWrap(True)
        self.online_label.setStyleSheet(f"color: {theme.TEXT_MUTED};")
        status_layout.addWidget(self.status_title)
        status_layout.addWidget(self.status_detail)
        status_layout.addWidget(self.online_label)
        card.body.addWidget(self.status_card)
        card.body.addStretch(1)
        return card

    @staticmethod
    def _labeled(label: str, widget: QWidget) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        text = QLabel(label)
        text.setObjectName("Muted")
        layout.addWidget(text)
        layout.addWidget(widget)
        return box

    def _apply_server(self) -> None:
        url = self.input_server.text().strip() or "http://127.0.0.1:8765"
        self.client.set_base_url(url)
        self.config.client["server_url"] = self.client.base_url
        self.config.save()

    def copy_machine(self) -> None:
        QApplication.clipboard().setText(self.machine_code)
        self.toast.show_message("机器码已复制", "success")

    def _offline_public(self) -> str:
        pub = self.config.client.get("offline_public_key") or self.config.security.get(
            "offline_public_key", ""
        )
        if pub:
            return pub
        try:
            data = self.client.public_key()
        except ApiError:
            return ""
        pub = (data or {}).get("public_key", "")
        if pub:
            self.config.client["offline_public_key"] = pub
            self.config.save()
        return pub

    def make_request(self) -> None:
        code = offline.make_request_code(self.machine_code, self.device_name)
        self.request_output.setPlainText(offline.chunk_code(code))
        self.toast.show_message("已生成本机请求码", "success")

    def copy_request(self) -> None:
        code = offline.clean_code(self.request_output.toPlainText())
        if not code:
            self.toast.show_message("请先生成请求码", "warning")
            return
        QApplication.clipboard().setText(code)
        self.toast.show_message("请求码已复制", "success")

    def save_request(self) -> None:
        code = offline.clean_code(self.request_output.toPlainText())
        if not code:
            self.toast.show_message("请先生成请求码", "warning")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "保存请求码", f"request_{self.machine_code}.txt",
            "文本文件 (*.txt);;所有文件 (*)"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig") as fh:
                fh.write(code + "\n")
        except OSError as exc:
            self.toast.show_message(f"保存失败：{exc}", "error")
            return
        self.toast.show_message("请求码已保存", "success")

    def _offline_payload(self) -> dict | None:
        code = self.config.client.get("offline_activation", "")
        if not code:
            return None
        pub = self._offline_public()
        if not pub:
            return None
        payload = offline.parse_activation_code(code, pub)
        if not payload:
            return None
        mc = (payload.get("mc") or "").upper()
        if mc and mc != self.machine_code.upper():
            return None
        return payload

    def _offline_left(self, payload: dict) -> int | None:
        exp = payload.get("exp")
        return security.seconds_left(exp) if exp else None

    def import_offline(self) -> None:
        code = offline.clean_code(self.offline_input.toPlainText())
        if not code:
            self.toast.show_message("请粘贴离线激活码", "warning")
            return
        pub = self._offline_public()
        if not pub:
            self._set_result("error", "无法导入", "缺少公钥，请先联网连接服务器获取公钥后再导入。")
            self.toast.show_message("缺少公钥，请先连接服务器", "error")
            return
        payload = offline.parse_activation_code(code, pub)
        if not payload:
            self._set_result("error", "激活码无效", "签名校验失败，激活码可能被篡改或不属于本系统。")
            self.toast.show_message("激活码无效", "error")
            return
        mc = (payload.get("mc") or "").upper()
        if mc and mc != self.machine_code.upper():
            self._set_result(
                "error", "设备不匹配",
                f"该激活码绑定机器码 {mc}，与本机 {self.machine_code} 不一致。",
            )
            self.toast.show_message("该激活码不属于本机", "error")
            return
        self.config.client["offline_activation"] = code
        self.config.client["offline_key"] = payload.get("key", "")
        self.config.save()
        exp = payload.get("exp")
        remain = security.humanize_remaining(exp) if exp else "永久"
        self.input_key.setText(payload.get("key", ""))
        self._set_result(
            "success", "离线激活成功",
            f"密钥：{payload.get('key', '')}\n"
            f"到期时间：{exp or '永久'}    剩余：{remain}\n"
            f"已保存到本机，可在无网络环境离线运行。",
        )
        self._set_online("info", "离线模式：本地授权校验")
        self.toast.show_message("离线激活成功", "success")

    def offline_verify(self) -> None:
        payload = self._offline_payload()
        if not payload:
            self._set_result("warning", "无离线授权", "尚未导入有效的离线激活码，或公钥缺失。")
            self.toast.show_message("暂无离线授权", "warning")
            return
        left = self._offline_left(payload)
        exp = payload.get("exp")
        if left is not None and left <= 0:
            self._set_result("error", "离线授权已过期", f"到期时间：{exp}")
            self.toast.show_message("离线授权已过期", "error")
            return
        remain = security.humanize_remaining(exp) if exp else "永久"
        self._set_result(
            "success", "离线授权有效",
            f"密钥：{payload.get('key', '')}\n到期时间：{exp or '永久'}    剩余：{remain}",
        )
        self._set_online("info", "离线模式：本地授权校验")

    def _offline_fallback(self, reason: str) -> bool:
        payload = self._offline_payload()
        if not payload:
            return False
        left = self._offline_left(payload)
        exp = payload.get("exp")
        if left is not None and left <= 0:
            self._set_result("error", "授权已过期", f"离线授权已验证且已过期。到期时间：{exp}")
            self.toast.show_message("离线授权已过期", "error")
            return True
        remain = security.humanize_remaining(exp) if exp else "永久"
        self._set_result(
            "success", "离线授权有效",
            f"网络不可用，已回退本地离线校验。\n"
            f"密钥：{payload.get('key', '')}    到期时间：{exp or '永久'}    剩余：{remain}",
        )
        self._set_online("warning", f"离线模式（{reason}）")
        self.toast.show_message("已离线校验", "success")
        return True

    def test_connection(self) -> None:
        self._apply_server()
        try:
            data = self.client.health()
        except ApiError as exc:
            self.toast.show_message(str(exc), "error")
            return
        self.toast.show_message(f"连接正常 · v{data.get('version')}", "success")

    def _set_result(self, kind: str, title: str, detail: str) -> None:
        color, bg = RESULT_STYLE.get(kind, RESULT_STYLE["info"])
        self.status_card.setStyleSheet(
            f"#StatCard {{ background: {bg}; border: 1px solid {color}33; border-radius: 12px; }}"
        )
        self.status_title.setText(title)
        self.status_title.setStyleSheet(f"color: {color};")
        self.status_detail.setText(detail)

    def _remember(self) -> None:
        self.config.client["auto_verify"] = self.auto_check.isChecked()
        self.config.client["last_key"] = (
            self.input_key.text().strip() if self.auto_check.isChecked() else ""
        )
        self._persist_session()

    def _persist_session(self) -> None:
        secret = self.client.session_secret or ""
        if (self.config.client.get("session_secret") or "") != secret:
            self.config.client["session_secret"] = secret
            self.config.save()

    def _register_failure(self) -> None:
        self.failure_count += 1
        if self.failure_count >= self.verify_max_failures:
            self.failure_count = 0
            self.locked_until = time.time() + self.verify_lock_seconds

    def _locked(self) -> bool:
        return time.time() < self.locked_until

    def _set_online(self, kind: str, text: str) -> None:
        color, _ = RESULT_STYLE.get(kind, RESULT_STYLE["info"])
        self.online_label.setText(text)
        self.online_label.setStyleSheet(f"color: {color};")

    def _start_heartbeat(self) -> None:
        if self.heartbeat_enabled:
            self.heartbeat_timer.start(int(self.heartbeat_interval * 1000))

    def heartbeat(self) -> None:
        key = self.input_key.text().strip()
        if not key or not self.client.session_secret:
            return
        try:
            data = self.client.heartbeat(key, self.machine_code)
        except ApiError as exc:
            if not self.client.session_secret:
                self.heartbeat_timer.stop()
                self._persist_session()
                self._set_online("error", "心跳中断：会话已失效，请重新激活")
                return
            self._set_online("warning", f"心跳异常：{exc}")
            self.heartbeat_timer.start(int(self.heartbeat_interval * 1000))
            return
        if data.get("ok"):
            self.heartbeat_count = int(
                data.get("heartbeat_count") or (self.heartbeat_count + 1)
            )
            server_ts = data.get("server_ts")
            if server_ts:
                self.time_offset = time.time() - float(server_ts)
            interval = float(data.get("next_interval") or self.heartbeat_interval)
            hint = ""
            if abs(self.time_offset) > 60:
                hint = f" · 时钟偏差 {self.time_offset:+.0f}s"
            self._set_online(
                "success",
                f"心跳在线 · 第 {self.heartbeat_count} 次 · 下次 {interval:.0f}s{hint}",
            )
            self.heartbeat_timer.start(max(5, int(interval * 1000)))
        else:
            self.heartbeat_timer.stop()
            message = data.get("message", "授权已失效")
            self._set_online("error", f"心跳停止：{message}")
            self._set_result("error", "授权失效", message)

    def activate(self) -> None:
        self._apply_server()
        key = self.input_key.text().strip()
        if not key:
            self.toast.show_message("请输入密钥", "warning")
            return
        try:
            data = self.client.activate(key, self.machine_code, self.device_name)
        except ApiError as exc:
            self._set_result("error", "激活失败", str(exc))
            self.toast.show_message(str(exc), "error")
            return
        if data.get("ok"):
            self._remember()
            self.failure_count = 0
            self.locked_until = 0.0
            kind = "success"
            title = "激活成功" if data.get("code") != "already" else "此设备已激活"
            detail = self._detail(data)
            self._set_result(kind, title, detail)
            self._set_online("info", "心跳：启动中…")
            self._start_heartbeat()
            self.toast.show_message(title, "success")
        else:
            self._persist_session()
            self._register_failure()
            self._set_result("error", data.get("message", "激活失败"), self._detail(data))
            self.toast.show_message(data.get("message", "激活失败"), "error")

    def verify(self) -> None:
        if self._locked():
            remain = max(1, int(self.locked_until - time.time()))
            self._set_result(
                "warning", "已临时锁定", f"连续失败过多，请在 {remain} 秒后重试"
            )
            self.toast.show_message(f"尝试过于频繁，请 {remain} 秒后重试", "warning")
            return
        self._apply_server()
        key = self.input_key.text().strip()
        if not key:
            self.toast.show_message("请先输入密钥", "warning")
            return
        try:
            data = self.client.verify(key, self.machine_code)
        except ApiError as exc:
            if self._offline_fallback(str(exc)):
                return
            self._persist_session()
            self._register_failure()
            self._set_result("error", "校验失败", str(exc))
            self.toast.show_message(str(exc), "error")
            return
        if data.get("ok"):
            self._remember()
            self.failure_count = 0
            self.locked_until = 0.0
            self._set_result("success", "授权有效", self._detail(data))
            self._set_online("info", "心跳：启动中…")
            self._start_heartbeat()
        else:
            self._persist_session()
            self._register_failure()
            self._set_result("error", data.get("message", "授权无效"), self._detail(data))

    @staticmethod
    def _detail(data: dict) -> str:
        expiry = data.get("expires_at") or "永久"
        remaining = data.get("remaining")
        if remaining:
            return f"到期时间：{expiry}    剩余：{remaining}"
        days = data.get("days_left")
        if days is None:
            return f"到期时间：{expiry}"
        return f"到期时间：{expiry}    剩余：{days} 天"

    def _fit_to_screen(self) -> None:
        screen = QApplication.primaryScreen()
        if screen is None:
            self.resize(1080, 640)
            return
        avail = screen.availableGeometry()
        width = min(1120, max(760, avail.width() - 60))
        height = min(720, max(480, avail.height() - 80))
        self.setMinimumSize(720, 460)
        self.resize(width, height)
        self.move(
            avail.x() + max(0, (avail.width() - width) // 2),
            avail.y() + max(0, (avail.height() - height) // 2),
        )

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if self.toast.isVisible():
            self.toast.move(max(12, (self.width() - self.toast.width()) // 2), 20)
