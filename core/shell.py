from PySide6.QtCore import QSettings, Qt, QTimer, Signal
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from . import security, theme
from .api_client import ApiClient, ApiError
from .config import APP_AUTHOR, APP_NAME, APP_VERSION, Config
from .secret_store import is_secure_available, protect, unprotect
from .widgets import confirm, make_button

# The two operator roles get visibly different chrome so a screenshot of the
# sidebar alone says which console is open. 管理端 only runs the key business,
# 主控端 owns the system-level pages.
ROLE_BADGE_ADMIN = "密钥运营"
ROLE_BADGE_MASTER = "系统管理"
ROLE_BADGE_STYLES = {
    "admin": (
        f"background: {theme.PRIMARY_SOFT}; color: {theme.PRIMARY};"
        f" border: 1px solid {theme.PRIMARY_BORDER}; border-radius: 6px;"
        " padding: 3px 8px; font-size: 11px; font-weight: 600;"
    ),
    "master": (
        f"background: {theme.FROZEN_SOFT}; color: {theme.FROZEN};"
        " border: 1px solid #D9CCFF; border-radius: 6px;"
        " padding: 3px 8px; font-size: 11px; font-weight: 600;"
    ),
}
ROLE_ACCENT_COLORS = {"admin": theme.PRIMARY, "master": theme.FROZEN}


def call_client(client, method: str, *args):
    """Invoke one of the P1 mail client methods.

    The client API lands in a separate change; an older client object would
    otherwise crash the dialog with AttributeError.
    """
    handler = getattr(client, method, None)
    if not callable(handler):
        raise ApiError("当前客户端版本不支持邮箱验证码功能，请更新后重试")
    return handler(*args)


class ForgotPasswordDialog(QDialog):
    """Reset a password by email code; shared by the admin and master logins."""

    def __init__(self, client: ApiClient, email: str = "", parent=None):
        super().__init__(parent)
        self.client = client
        self.reset_done = False
        self.setWindowTitle("忘记密码")
        self.setFixedWidth(420)
        self.setModal(True)

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(14)

        heading = QLabel("忘记密码")
        heading.setObjectName("Title")
        hint = QLabel("输入登录邮箱，验证通过后设置新密码")
        hint.setObjectName("Subtitle")
        root.addWidget(heading)
        root.addWidget(hint)

        self.email = QLineEdit(str(email or ""))
        self.email.setPlaceholderText("登录邮箱")
        self.btn_send = make_button("发送验证码", "default", self.send_code)
        self.btn_send.setFixedWidth(112)
        email_row = QWidget()
        email_layout = QHBoxLayout(email_row)
        email_layout.setContentsMargins(0, 0, 0, 0)
        email_layout.setSpacing(8)
        email_layout.addWidget(self.email, 1)
        email_layout.addWidget(self.btn_send)
        root.addWidget(self._labeled("邮箱", email_row))

        self.code = QLineEdit()
        self.code.setPlaceholderText("6 位验证码")
        self.code.setMaxLength(12)
        self.new_password = QLineEdit()
        self.new_password.setPlaceholderText("新密码（至少 8 位，含字母和数字）")
        self.new_password.setEchoMode(QLineEdit.Password)
        self.confirm_password = QLineEdit()
        self.confirm_password.setPlaceholderText("再次输入新密码")
        self.confirm_password.setEchoMode(QLineEdit.Password)
        root.addWidget(self._labeled("验证码", self.code))
        root.addWidget(self._labeled("新密码", self.new_password))
        root.addWidget(self._labeled("确认新密码", self.confirm_password))

        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.setMinimumHeight(20)
        root.addWidget(self.status)

        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(make_button("取消", "ghost", self.reject))
        self.btn_reset = make_button("重置密码", "primary", self.reset_password)
        row.addWidget(self.btn_reset)
        root.addLayout(row)

        # A member timer dies with the dialog, so a pending close can never
        # fire against an already deleted widget (tests drop these fast).
        self._close_timer = QTimer(self)
        self._close_timer.setSingleShot(True)
        self._close_timer.timeout.connect(self.accept)

        self.code.returnPressed.connect(self.new_password.setFocus)
        self.new_password.returnPressed.connect(self.confirm_password.setFocus)
        self.confirm_password.returnPressed.connect(self.reset_password)
        self.email.setFocus()

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

    def _set_status(self, message: str, color: str) -> None:
        self.status.setText(message)
        self.status.setStyleSheet(f"color: {color};")

    def _set_busy(self, busy: bool, button, idle_text: str, busy_text: str) -> None:
        for widget in (
            self.email,
            self.code,
            self.new_password,
            self.confirm_password,
            self.btn_send,
            self.btn_reset,
        ):
            widget.setEnabled(not busy)
        button.setText(busy_text if busy else idle_text)

    def send_code(self) -> None:
        if not self.btn_send.isEnabled():
            return
        email = self.email.text().strip()
        if not email or "@" not in email:
            self._set_status("请输入正确的邮箱地址", theme.DANGER)
            return
        self._set_busy(True, self.btn_send, "发送验证码", "发送中…")
        self._set_status("正在发送验证码…", theme.TEXT_MUTED)
        try:
            call_client(self.client, "admin_password_forgot", email)
        except ApiError as exc:
            self._set_busy(False, self.btn_send, "发送验证码", "发送中…")
            self._set_status(str(exc), theme.DANGER)
            return
        self._set_busy(False, self.btn_send, "发送验证码", "发送中…")
        # The server answers the same way for unknown accounts, so this
        # wording must stay account-agnostic too.
        self._set_status("验证码已发送，请查收邮件（10 分钟内有效）", theme.SUCCESS)
        self.code.setFocus()

    def reset_password(self) -> None:
        if not self.btn_reset.isEnabled():
            return
        email = self.email.text().strip()
        code = self.code.text().strip()
        password = self.new_password.text()
        if not email or "@" not in email:
            self._set_status("请输入正确的邮箱地址", theme.DANGER)
            return
        if not code:
            self._set_status("请输入邮箱验证码", theme.DANGER)
            return
        valid, message = security.password_strength(password)
        if not valid:
            self._set_status(message, theme.DANGER)
            return
        if password != self.confirm_password.text():
            self._set_status("两次输入的新密码不一致", theme.DANGER)
            self.confirm_password.selectAll()
            self.confirm_password.setFocus()
            return
        self._set_busy(True, self.btn_reset, "重置密码", "重置中…")
        self._set_status("正在重置密码…", theme.TEXT_MUTED)
        try:
            call_client(
                self.client, "admin_password_reset", email, code, password
            )
        except ApiError as exc:
            self._set_busy(False, self.btn_reset, "重置密码", "重置中…")
            self._set_status(str(exc), theme.DANGER)
            return
        self.reset_done = True
        for widget in (
            self.email,
            self.code,
            self.new_password,
            self.confirm_password,
            self.btn_send,
            self.btn_reset,
        ):
            widget.setEnabled(False)
        self.btn_reset.setText("已重置")
        self._set_status("密码已重置，请用新密码登录", theme.SUCCESS)
        self._close_timer.start(1200)


class LoginDialog(QDialog):
    def __init__(self, config: Config, title: str, subtitle: str = "", parent=None):
        super().__init__(parent)
        self.config = config
        self.client = ApiClient(
            config.client.get("server_url", config.server_url()),
            int(config.client.get("timeout", 8)),
            ai_timeout=int(config.client.get("ai_timeout", 600) or 600),
            allow_insecure_http=bool(config.client.get("allow_insecure_http", False)),
            response_public_key=config.client.get("response_public_key", ""),
            response_key_id=config.client.get("response_key_id", ""),
        )
        self.result_data: dict = {}

        self.setWindowTitle(title)
        self.setFixedWidth(440)
        self.setModal(True)

        root = QVBoxLayout(self)
        root.setContentsMargins(34, 30, 34, 30)
        root.setSpacing(16)

        brand = QLabel("密钥授权系统")
        brand.setObjectName("Brand")
        heading = QLabel(title)
        heading.setObjectName("Title")
        hint = QLabel(subtitle or "请连接本地服务器并登录")
        hint.setObjectName("Subtitle")
        root.addWidget(brand)
        root.addWidget(heading)
        root.addWidget(hint)

        self.input_server = QLineEdit(self.client.base_url)
        self.input_server.setPlaceholderText("http://127.0.0.1:8765")
        saved_username = str(config.client.get("saved_username", "") or "")
        self.input_user = QLineEdit(
            saved_username or str(config.client.get("last_username", "") or "")
        )
        self.input_user.setPlaceholderText("用户名")
        self.input_pass = QLineEdit()
        self.input_pass.setPlaceholderText("密码")
        self.input_pass.setEchoMode(QLineEdit.Password)
        self.password_toggle = make_button("显示", "ghost", self._toggle_password)
        self.password_toggle.setCheckable(True)
        self.password_toggle.setFixedWidth(58)
        password_row = QWidget()
        password_layout = QHBoxLayout(password_row)
        password_layout.setContentsMargins(0, 0, 0, 0)
        password_layout.setSpacing(8)
        password_layout.addWidget(self.input_pass, 1)
        password_layout.addWidget(self.password_toggle)

        root.addWidget(self._labeled("服务器地址", self.input_server))
        root.addWidget(self._labeled("账号", self.input_user))
        root.addWidget(self._labeled("密码", password_row))

        self._secure_available = bool(is_secure_available())
        self._busy = False
        self.remember_user = QCheckBox("记住账号")
        self.remember_pass = QCheckBox("记住密码（本机加密保存）")
        remember_row = QHBoxLayout()
        remember_row.setSpacing(16)
        remember_row.addWidget(self.remember_user)
        remember_row.addWidget(self.remember_pass)
        remember_row.addStretch(1)
        root.addLayout(remember_row)

        self.remember_hint = QLabel("")
        self.remember_hint.setObjectName("Muted")
        self.remember_hint.setWordWrap(True)
        self.remember_hint.setVisible(not self._secure_available)
        if not self._secure_available:
            self.remember_hint.setText("当前系统不支持安全保存密码，仅可记住账号。")
        root.addWidget(self.remember_hint)

        client_cfg = config.client
        self.remember_user.setChecked(bool(client_cfg.get("remember_username", False)))
        if bool(client_cfg.get("remember_password", False)) and self._secure_available:
            saved_token = str(client_cfg.get("saved_password", "") or "")
            saved_password = unprotect(saved_token) if saved_token else ""
            if saved_password:
                self.input_pass.setText(saved_password)
                self.remember_pass.setChecked(True)
            else:
                # 密文解不开（例如换了 Windows 账户）时不再假装记得密码。
                client_cfg["saved_password"] = ""
                client_cfg["remember_password"] = False
        if not self._secure_available:
            self.remember_pass.setEnabled(False)
        self.remember_pass.toggled.connect(self._on_remember_password_toggled)
        self._sync_remember_lock()

        forgot_row = QHBoxLayout()
        forgot_row.addStretch(1)
        self.btn_forgot = make_button("忘记密码", "ghost", self.forgot_password)
        forgot_row.addWidget(self.btn_forgot)
        root.addLayout(forgot_row)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.setMinimumHeight(20)
        self.status.setStyleSheet(f"color: {theme.DANGER};")
        root.addWidget(self.status)

        self.btn_login = make_button("登 录", "primary", self.submit)
        self.btn_login.setMinimumHeight(40)
        root.addWidget(self.btn_login)

        self._inputs = [self.input_server, self.input_user, self.input_pass]

        credit = QLabel(f"作者：{APP_AUTHOR}    {APP_NAME} v{APP_VERSION}")
        credit.setObjectName("Muted")
        credit.setAlignment(Qt.AlignCenter)
        root.addWidget(credit)

        self.input_server.returnPressed.connect(self.input_user.setFocus)
        self.input_user.returnPressed.connect(self.input_pass.setFocus)
        self.input_pass.returnPressed.connect(self.submit)
        self.input_user.setFocus()

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

    def _toggle_password(self, checked: bool) -> None:
        self.input_pass.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)
        self.password_toggle.setText("隐藏" if checked else "显示")

    def _sync_remember_lock(self) -> None:
        """记住密码开启时锁定「记住账号」——记住密码必然包含账号。"""
        locked = self.remember_pass.isChecked()
        if locked:
            self.remember_user.setChecked(True)
        self.remember_user.setEnabled(not locked and not self._busy)

    def _on_remember_password_toggled(self, _checked: bool) -> None:
        self._sync_remember_lock()

    def _set_busy(self, busy: bool) -> None:
        self._busy = bool(busy)
        for widget in self._inputs:
            widget.setEnabled(not busy)
        self.password_toggle.setEnabled(not busy)
        self.btn_forgot.setEnabled(not busy)
        self.btn_login.setEnabled(not busy)
        self.remember_pass.setEnabled(not busy and self._secure_available)
        self._sync_remember_lock()
        self.btn_login.setText("正在登录…" if busy else "登 录")

    def forgot_password(self) -> None:
        """Open the shared email-code reset dialog for the entered server."""
        url = self.input_server.text().strip() or "http://127.0.0.1:8765"
        try:
            self.client.set_base_url(url)
        except ApiError as exc:
            self._fail(str(exc))
            return
        account = self.input_user.text().strip()
        dialog = ForgotPasswordDialog(
            self.client, account if "@" in account else "", self
        )
        dialog.exec()
        if dialog.reset_done:
            self.status.setText("密码已重置，请用新密码登录")
            self.status.setStyleSheet(f"color: {theme.SUCCESS};")
            self.input_pass.clear()
            self.input_pass.setFocus()

    def _fail(self, message: str) -> None:
        self.status.setText(message)
        self.status.setStyleSheet(f"color: {theme.DANGER};")
        self._set_busy(False)

    def _persist_remembered_credentials(self, username: str, password: str) -> None:
        """保存「记住账号/密码」选择；保存失败不影响本次登录。"""
        try:
            remember_user = bool(self.remember_user.isChecked())
            remember_pass = bool(self.remember_pass.isChecked()) and self._secure_available
            values = self.config.client
            values["remember_username"] = remember_user
            values["remember_password"] = remember_pass
            values["saved_username"] = username if (remember_user or remember_pass) else ""
            values["saved_password"] = protect(password) if remember_pass else ""
            self.config.save()
        except Exception as exc:  # 保存失败只是少一个便利功能，登录照常完成。
            self.status.setText(f"登录成功，但记住登录信息失败：{exc}")
            self.status.setStyleSheet(f"color: {theme.WARNING};")

    def submit(self) -> None:
        if not self.btn_login.isEnabled():
            return
        url = self.input_server.text().strip() or "http://127.0.0.1:8765"
        user = self.input_user.text().strip()
        pwd = self.input_pass.text()
        if not user or not pwd:
            self._fail("请输入账号和密码")
            return
        self._set_busy(True)
        self.status.setText("正在登录…")
        self.status.setStyleSheet(f"color: {theme.TEXT_MUTED};")
        try:
            self.client.set_base_url(url)
            data = self.client.login(user, pwd)
        except ApiError as exc:
            self._fail(str(exc))
            self.input_pass.selectAll()
            self.input_pass.setFocus()
            return
        self.config.client["server_url"] = self.client.base_url
        self.config.client["last_username"] = user
        try:
            key_data = self.client.public_key()
            self.client.apply_public_key_response(key_data)
            self.config.client["offline_public_key"] = self.client.offline_public_key
            self.config.client["response_public_key"] = self.client.response_public_key
            self.config.client["response_key_id"] = self.client.response_key_id
        except ApiError:
            # Login can still proceed on a local-only setup, but signed API
            # checks will remain unavailable until keys are pinned.
            pass
        self.config.save()
        self.result_data = data
        self._persist_remembered_credentials(user, pwd)
        self.accept()


class AppShell(QMainWindow):
    logout = Signal()

    def __init__(self, title: str, user: dict, server_url: str):
        super().__init__()
        self.setWindowTitle(title)
        self.resize(1280, 820)
        self.setMinimumSize(1040, 680)
        self._settings = QSettings("SQ-Authorization-System", title)

        root = QWidget()
        root.setObjectName("Root")
        self.setCentralWidget(root)
        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        outer.addWidget(self._build_sidebar(title, user, server_url))

        self.stack = QStackedWidget()
        outer.addWidget(self.stack, 1)

        self._group = QButtonGroup(self)
        self._group.setExclusive(True)
        self._buttons: list[QPushButton] = []
        self._shortcuts: list[QShortcut] = []

        self.status_label = QLabel(f"{user.get('username', '')} · {server_url}")
        self.status_label.setObjectName("Muted")
        self.statusBar().addPermanentWidget(self.status_label)
        self.statusBar().setSizeGripEnabled(True)

        # An administrator who had their password reset by someone else must
        # replace the handover password before using anything else.
        self._password_locked = bool(user.get("must_change_password"))
        self._password_page: QWidget | None = None
        self._password_enforced = False

        for keys, slot in (("F5", self.refresh_current), ("Ctrl+R", self.refresh_current)):
            shortcut = QShortcut(QKeySequence(keys), self)
            shortcut.activated.connect(slot)
            self._shortcuts.append(shortcut)
        search = QShortcut(QKeySequence("Ctrl+F"), self)
        search.activated.connect(self.focus_search)
        self._shortcuts.append(search)

        geometry = self._settings.value("geometry")
        if geometry is not None:
            self.restoreGeometry(geometry)
        self._center_on_screen()

    def _build_sidebar(self, title: str, user: dict, server_url: str) -> QWidget:
        side = QFrame()
        side.setObjectName("Sidebar")
        side.setFixedWidth(232)
        layout = QVBoxLayout(side)
        layout.setContentsMargins(16, 20, 16, 18)
        layout.setSpacing(8)

        is_master = str(user.get("role") or "").strip().lower() == "master"
        role_key = "master" if is_master else "admin"

        accent = QFrame()
        accent.setObjectName("RoleAccent")
        accent.setFixedHeight(3)
        accent.setStyleSheet(
            f"background: {ROLE_ACCENT_COLORS[role_key]};"
            " border: none; border-radius: 2px;"
        )
        layout.addWidget(accent)

        brand = QLabel("密钥授权系统")
        brand.setObjectName("Brand")
        layout.addWidget(brand)
        self.role_badge = QLabel(
            ROLE_BADGE_MASTER if is_master else ROLE_BADGE_ADMIN
        )
        self.role_badge.setObjectName("RoleBadge")
        self.role_badge.setStyleSheet(ROLE_BADGE_STYLES[role_key])
        self.role_badge.setToolTip(
            "主控端 · 系统管理：拥有管理员管理与系统设置"
            if is_master
            else "管理端 · 密钥运营：仅密钥相关操作"
        )
        layout.addWidget(self.role_badge, 0, Qt.AlignLeft)
        user_label = QLabel(user.get("username", ""))
        user_label.setObjectName("Subtitle")
        user_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(user_label)
        layout.addSpacing(10)

        nav_label = QLabel(
            "功能菜单 · 系统管理" if is_master else "功能菜单 · 密钥运营"
        )
        nav_label.setObjectName("NavLabel")
        layout.addWidget(nav_label)

        self.nav_layout = QVBoxLayout()
        self.nav_layout.setSpacing(4)
        layout.addLayout(self.nav_layout)
        layout.addStretch(1)

        self.server_label = QLabel(server_url)
        self.server_label.setObjectName("Muted")
        self.server_label.setWordWrap(True)
        layout.addWidget(self.server_label)

        layout.addWidget(make_button("退出登录", "ghost", self.confirm_logout))
        return side

    def add_page(self, label: str, widget: QWidget, *, password_gate: bool = False) -> None:
        btn = QPushButton(label)
        btn.setObjectName("NavButton")
        btn.setCheckable(True)
        btn.setCursor(Qt.PointingHandCursor)
        index = self.stack.addWidget(widget)
        if password_gate:
            self._password_page = widget
            changed = getattr(widget, "changed", None)
            if changed is not None and hasattr(changed, "connect"):
                changed.connect(self.release_password_gate)
        btn.setToolTip(label)
        btn.clicked.connect(lambda _checked=False, i=index: self.set_current_page(i))
        self._group.addButton(btn)
        self.nav_layout.addWidget(btn)
        self._buttons.append(btn)
        if len(self._buttons) <= 9:
            shortcut = QShortcut(QKeySequence(f"Ctrl+{len(self._buttons)}"), self)
            shortcut.activated.connect(lambda i=index: self.set_current_page(i))
            self._shortcuts.append(shortcut)
        if len(self._buttons) == 1:
            btn.setChecked(True)
            self.stack.setCurrentIndex(index)

    def set_current_page(self, index: int) -> None:
        if index < 0 or index >= self.stack.count():
            return
        if self._password_locked and self.stack.widget(index) is not self._password_page:
            # Re-check the real page: Qt already toggled the clicked button.
            current = self.stack.currentIndex()
            if 0 <= current < len(self._buttons):
                self._buttons[current].setChecked(True)
            self.statusBar().showMessage("请先修改初始密码", 4000)
            return
        self._switch(index)

    def _switch(self, index: int) -> None:
        self.stack.setCurrentIndex(index)
        if index < len(self._buttons):
            self._buttons[index].setChecked(True)
        page = self.stack.widget(index)
        on_show = getattr(page, "on_show", None)
        if callable(on_show):
            on_show()

    def release_password_gate(self) -> None:
        if not self._password_locked:
            return
        self._password_locked = False
        self.statusBar().showMessage("密码已更新，全部功能已解锁", 5000)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if not self._password_enforced and self._password_locked:
            self._password_enforced = True
            if self._password_page is not None:
                self._switch(self.stack.indexOf(self._password_page))
            self.statusBar().showMessage(
                "该账号的密码已被重置，请先设置新密码", 10000
            )

    def refresh_current(self) -> None:
        page = self.stack.currentWidget()
        for name in ("refresh", "reload"):
            handler = getattr(page, name, None)
            if callable(handler):
                handler()
                return

    def focus_search(self) -> None:
        page = self.stack.currentWidget()
        for name in ("keyword", "search", "filter_input"):
            widget = getattr(page, name, None)
            if widget is not None and hasattr(widget, "setFocus"):
                widget.setFocus()
                if hasattr(widget, "selectAll"):
                    widget.selectAll()
                return

    def confirm_logout(self) -> None:
        if confirm(self, "退出登录", "确定退出当前账号并返回登录界面？"):
            self.logout.emit()

    def _center_on_screen(self) -> None:
        screen = self.screen()
        if screen is None:
            return
        available = screen.availableGeometry()
        frame = self.frameGeometry()
        if available.intersects(frame):
            return
        frame.moveCenter(available.center())
        self.move(frame.topLeft())

    def closeEvent(self, event) -> None:
        self._settings.setValue("geometry", self.saveGeometry())
        super().closeEvent(event)


def run_client_app(app, config: Config, login_title: str, login_subtitle: str, window_factory):

    app.setApplicationName(APP_NAME)
    app.setOrganizationName("SQ-Authorization-System")
    # Login and logout swap top-level windows, so the default "quit when the
    # last window closes" rule would tear the process down mid-swap.
    app.setQuitOnLastWindowClosed(False)

    holder: dict = {}
    switching = {"logout": False}

    def on_last_window_closed() -> None:
        if not switching["logout"]:
            app.quit()

    app.lastWindowClosed.connect(on_last_window_closed)

    def open_login() -> None:
        switching["logout"] = False
        dialog = LoginDialog(config, login_title, login_subtitle)
        if dialog.exec() != QDialog.Accepted:
            app.quit()
            return
        try:
            window = window_factory(dialog.client, dialog.result_data)
        except Exception as exc:  # pragma: no cover - defensive
            from PySide6.QtWidgets import QMessageBox

            QMessageBox.critical(None, "启动失败", f"无法创建主窗口：\n{exc}")
            app.quit()
            return
        holder["window"] = window

        def on_logout() -> None:
            switching["logout"] = True
            holder.pop("window", None)
            window.close()
            window.deleteLater()
            QTimer.singleShot(0, open_login)

        window.logout.connect(on_logout)
        window.show()
        window.raise_()
        window.activateWindow()

    open_login()
    if "window" not in holder:
        return 0
    return app.exec()
