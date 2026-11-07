from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QHeaderView,
    QLabel,
    QMenu,
    QLineEdit,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import security
from core.api_client import ApiClient, ApiError
from core.ai_page import AIAssistantPage
from core.alert_center import AlertCenterPage
from core.approvals_page import ApprovalCenterPage
from core.config import APP_AUTHOR, APP_COPYRIGHT, APP_NAME, APP_VERSION, Config
from core.pages import (
    AboutPage,
    BatchesPage,
    ChangePasswordPage,
    BasePage,
    DashboardPage,
    GeneratePage,
    LicensesPage,
    LogsPage,
    OfflinePage,
    OverviewPage,
    fill_table,
    status_table_item,
)
from core.shell import AppShell, call_client
from core.user_admin import UserAdminPage
from core.widgets import Card, PageHeader, Toast, confirm, make_button

ROLE_TEXT = {"master": "主控", "admin": "管理"}
ADMIN_STATUS_TEXT = {"active": "正常", "disabled": "已禁用"}



def mask_email(email: str) -> str:
    """Keep the domain readable while hiding the local part."""
    text = str(email or "").strip()
    if not text:
        return "—"
    local, sep, domain = text.partition("@")
    if not sep or not local or not domain:
        return "***"
    return f"{local[0]}***@{domain}"



def email_status_item(admin: dict) -> QTableWidgetItem:
    email = str(admin.get("email") or "").strip()
    if not email:
        return QTableWidgetItem("—")
    verified = admin.get("email_verified")
    if verified is None:
        verified = bool(admin.get("email_verified_at"))
    # Reuse the shared status styling: green when verified, orange while the
    # address still needs its code.
    return status_table_item(
        "active" if verified else "expired", "已验证" if verified else "未验证"
    )


class CreateAdminDialog(QDialog):
    def __init__(self, client: ApiClient, notify, parent=None):
        super().__init__(parent)
        self.client = client
        self.notify = notify
        self.setWindowTitle("新建管理员")
        self.setFixedWidth(400)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(14)
        layout.addWidget(PageHeader("新建管理员", "创建后可登录管理端操作密钥"))

        form = QFormLayout()
        form.setSpacing(12)
        self.username = QLineEdit()
        self.username.setPlaceholderText("登录账号")
        self.password = QLineEdit()
        self.password.setPlaceholderText("登录密码")
        self.password.setEchoMode(QLineEdit.Password)
        self.role = QComboBox()
        self.role.addItem("管理端（仅密钥操作）", "admin")
        self.role.addItem("主控端（全部权限）", "master")
        self.email = QLineEdit()
        self.email.setPlaceholderText("可选，用于找回密码与告警收件")
        form.addRow("账号", self.username)
        form.addRow("密码", self.password)
        form.addRow("角色", self.role)
        form.addRow("邮箱", self.email)
        layout.addLayout(form)

        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(make_button("取消", "ghost", self.reject))
        row.addWidget(make_button("创建", "primary", self.submit))
        layout.addLayout(row)

    def submit(self) -> None:
        username = self.username.text().strip()
        password = self.password.text()
        if not username or not password:
            self.notify("请输入账号和密码", "warning")
            return
        email = self.email.text().strip()
        if email and "@" not in email:
            self.notify("请输入正确的邮箱地址", "warning")
            return
        try:
            self.client.create_admin(username, password, self.role.currentData())
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        if email:
            try:
                call_client(self.client, "admin_set_email", email)
            except ApiError as exc:
                # The account exists already; failing to attach the address
                # must not look like the creation itself failed.
                self.notify(f"管理员已创建，但邮箱设置失败：{exc}", "warning")
                self.accept()
                return
        self.notify("管理员已创建", "success")
        self.accept()


class AdminEmailDialog(QDialog):
    """Set the signed-in account's email, then confirm it with a code."""

    def __init__(self, client: ApiClient, notify, parent=None):
        super().__init__(parent)
        self.client = client
        self.notify = notify
        self.email_verified = False
        self.setWindowTitle("设置邮箱 / 重发验证")
        self.setFixedWidth(440)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(14)
        layout.addWidget(
            PageHeader(
                "设置邮箱 / 重发验证",
                "验证码用于登录账号找回密码与告警收件",
            )
        )

        form = QFormLayout()
        form.setSpacing(12)
        self.email = QLineEdit()
        self.email.setPlaceholderText("管理员邮箱")
        self.btn_send = make_button("发送验证码", "default", self.send_code)
        self.btn_send.setFixedWidth(112)
        email_row = QWidget()
        email_layout = QHBoxLayout(email_row)
        email_layout.setContentsMargins(0, 0, 0, 0)
        email_layout.setSpacing(8)
        email_layout.addWidget(self.email, 1)
        email_layout.addWidget(self.btn_send)
        form.addRow("邮箱", email_row)

        self.code = QLineEdit()
        self.code.setPlaceholderText("6 位验证码")
        self.code.setMaxLength(12)
        self.btn_verify = make_button("验证邮箱", "primary", self.verify)
        self.btn_verify.setFixedWidth(112)
        code_row = QWidget()
        code_layout = QHBoxLayout(code_row)
        code_layout.setContentsMargins(0, 0, 0, 0)
        code_layout.setSpacing(8)
        code_layout.addWidget(self.code, 1)
        code_layout.addWidget(self.btn_verify)
        form.addRow("验证码", code_row)
        layout.addLayout(form)

        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(make_button("关闭", "ghost", self.accept))
        layout.addLayout(row)

    def send_code(self) -> None:
        email = self.email.text().strip()
        if not email or "@" not in email:
            self.notify("请输入正确的邮箱地址", "warning")
            return
        try:
            call_client(self.client, "admin_set_email", email)
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        self.notify("验证码已发送，请查收邮件", "success")
        self.code.setFocus()

    def verify(self) -> None:
        code = self.code.text().strip()
        if not code:
            self.notify("请输入验证码", "warning")
            return
        try:
            call_client(self.client, "admin_verify_email", code)
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        self.email_verified = True
        self.notify("邮箱已验证", "success")
        self.accept()


class AdminsPage(BasePage):
    COLUMNS = ["ID", "账号", "角色", "状态", "邮箱", "验证状态", "创建时间", "最近登录"]

    def __init__(self, client, notify):
        super().__init__(client, notify)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        header = QHBoxLayout()
        header.addWidget(PageHeader("管理员管理", "主控端专属：创建、启停与重置密码"))
        header.addStretch(1)
        header.addWidget(make_button("新建管理员", "primary", self.create))
        header.addWidget(make_button("刷新", "ghost", self.refresh))
        layout.addLayout(header)

        actions = QHBoxLayout()
        self.total_label = QLabel("共 0 位")
        self.total_label.setObjectName("Muted")
        actions.addWidget(self.total_label)
        actions.addStretch(1)
        actions.addWidget(make_button("启用/禁用", "default", self.toggle))
        actions.addWidget(make_button("重置密码", "danger", self.reset_password))
        self.btn_email = make_button(
            "设置邮箱/重发验证", "default", self.manage_email
        )
        actions.addWidget(self.btn_email)
        layout.addLayout(actions)

        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        for col in (0, 2, 3, 4, 5, 6, 7):
            self.table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeToContents)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._ctx_menu)
        layout.addWidget(self.table, 1)

    def refresh(self) -> None:
        try:
            data = self.client.list_admins()
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        items = data.get("items", [])
        self.admins = items
        rows = []
        for it in items:
            rows.append([
                it["id"],
                it["username"],
                ROLE_TEXT.get(it["role"], it["role"]),
                ADMIN_STATUS_TEXT.get(it["status"], it["status"]),
                mask_email(it.get("email") or ""),
                "—",
                it["created_at"],
                it["last_login_at"] or "—",
            ])
        fill_table(self.table, rows)
        for row, item in enumerate(items):
            self.table.setItem(
                row, 3, status_table_item(item["status"], ADMIN_STATUS_TEXT.get(item["status"], item["status"]))
            )
            self.table.setItem(row, 5, email_status_item(item))
        self.total_label.setText(f"共 {len(items)} 位")

    def _selected(self) -> dict | None:
        row = self.table.currentRow()
        if row < 0 or row >= len(getattr(self, "admins", [])):
            self.notify("请先选择一位管理员", "warning")
            return None
        return self.admins[row]

    def _ctx_menu(self, pos) -> None:
        if not self.table.indexAt(pos).isValid():
            return
        menu = QMenu(self)
        menu.addAction("启用 / 禁用", self.toggle)
        menu.addAction("重置密码", self.reset_password)
        menu.addAction("设置邮箱 / 验证", self.manage_email)
        menu.addSeparator()
        menu.addAction("复制账号名", self._copy_username)
        menu.addAction("删除账号", self.delete_account)
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _copy_username(self) -> None:
        target = self._selected()
        if target:
            from PySide6.QtWidgets import QApplication

            QApplication.clipboard().setText(str(target.get("username") or ""))
            self.notify("账号名已复制", "success")

    def delete_account(self) -> None:
        """删除管理员（二次确认；系统至少保留一个主控）。"""
        target = self._selected()
        if not target:
            return
        if not confirm(
            self,
            "删除账号",
            f"确定删除账号 {target.get('username')}？\n删除后立即无法登录（不可撤销；日常建议使用禁用）。",
        ):
            return
        try:
            self.client.delete_admin(int(target["id"]))
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        self.notify("账号已删除", "success")
        self.refresh()

    def create(self) -> None:
        dialog = CreateAdminDialog(self.client, self.notify, self)
        if dialog.exec() == QDialog.Accepted:
            self.refresh()

    def manage_email(self) -> None:
        # The /api/admin/email/set contract is bearer-scoped, so this dialog
        # always targets the signed-in account, not the selected table row.
        dialog = AdminEmailDialog(self.client, self.notify, self)
        dialog.exec()
        self.refresh()

    def toggle(self) -> None:
        admin = self._selected()
        if not admin:
            return
        target = "disabled" if admin["status"] == "active" else "active"
        action = "禁用" if target == "disabled" else "启用"
        if not confirm(self, f"{action}管理员", f"确定{action}账号 {admin['username']}？"):
            return
        try:
            self.client.set_admin_status(admin["id"], target)
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        self.notify(f"已{action}", "success")
        self.refresh()

    def reset_password(self) -> None:
        admin = self._selected()
        if not admin:
            return
        if admin.get("role") == "master":
            self.notify("主控账号不能在这里重置，请让该账号使用“修改密码”页面", "warning")
            return
        password, ok = QInputDialog.getText(
            self, "重置密码", f"为 {admin['username']} 输入新密码：",
            QLineEdit.Password,
        )
        if not ok or not password:
            return
        again, ok = QInputDialog.getText(
            self, "重置密码", "再次输入新密码：", QLineEdit.Password,
        )
        if not ok:
            return
        if password != again:
            self.notify("两次输入的新密码不一致", "warning")
            return
        valid, message = security.password_strength(password)
        if not valid:
            self.notify(message, "warning")
            return
        if not confirm(self, "重置密码", f"确定重置账号 {admin['username']} 的密码？"):
            return
        try:
            self.client.reset_admin_password(admin["id"], password)
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        self.notify("密码已重置，该账号的旧登录状态已失效", "success")

    def on_show(self) -> None:
        self.refresh()


class SettingsPage(BasePage):
    def __init__(self, client, notify, config: Config):
        super().__init__(client, notify)
        self.config = config
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)
        layout.addWidget(PageHeader("系统设置", "连接配置与运行状态"))

        card = Card(padding=18)
        card.setMinimumWidth(420)
        card.setMaximumWidth(560)
        card.body.addWidget(PageHeader("服务器连接", "修改后立即生效并保存到本机"))
        form = QFormLayout()
        form.setSpacing(12)
        self.input_server = QLineEdit(self.client.base_url)
        self.input_server.setPlaceholderText("http://127.0.0.1:8765")
        form.addRow("服务器地址", self.input_server)
        card.body.addLayout(form)
        row = QHBoxLayout()
        row.addWidget(make_button("保存并测试", "primary", self.save))
        row.addStretch(1)
        card.body.addLayout(row)

        self.info_label = QLabel("尚未测试")
        self.info_label.setObjectName("Muted")
        self.info_label.setWordWrap(True)
        card.body.addWidget(self.info_label)
        layout.addWidget(card)

        about = Card(padding=18)
        about.setMinimumWidth(420)
        about.setMaximumWidth(560)
        about.body.addWidget(PageHeader("关于", f"{APP_NAME} · v{APP_VERSION}"))
        desc = QLabel(
            "密钥授权系统由四个程序组成：\n"
            "· 本地服务器：数据与验证中枢（FastAPI + SQLite）\n"
            "· 管理端：密钥生成、查询、吊销、冻结\n"
            "· 验证端：机器码采集与激活校验\n"
            "· 主控端：管理员管理与全局设置\n\n"
            f"作者：{APP_AUTHOR}    版本：v{APP_VERSION}\n"
            f"{APP_COPYRIGHT}\n\n"
            "首次启动会生成一次性随机主控密码，请登录后尽快修改。\n\n"
            "本软件受《中华人民共和国著作权法》保护，未经作者许可不得复制、传播、"
            "反编译或用于商业用途。详见“关于”页面中的作者声明与法律声明。"
        )
        desc.setObjectName("Muted")
        desc.setWordWrap(True)
        about.body.addWidget(desc)
        layout.addWidget(about)
        layout.addStretch(1)

    def save(self) -> None:
        url = self.input_server.text().strip() or "http://127.0.0.1:8765"
        previous = self.client.base_url
        try:
            self.client.set_base_url(url)
        except ApiError as exc:
            self.info_label.setText(f"保存失败：{exc}")
            self.notify("服务器地址无效", "error")
            return
        # set_base_url() drops the session token when the address actually
        # changes, so the shell has to say so instead of reporting a plain
        # success and then failing every later request as unauthenticated.
        changed = self.client.base_url != previous
        self.config.client["server_url"] = self.client.base_url
        self.config.save()
        self._sync_shell_url(self.client.base_url)
        try:
            data = self.client.health()
        except ApiError as exc:
            self.info_label.setText(f"已保存，但连接失败：{exc}")
            self.notify("已保存，连接失败", "error")
            if changed:
                self._require_relogin()
            return
        self.info_label.setText(f"连接正常 · 版本 {data.get('version')} · 服务器时间 {data.get('time')}")
        if changed:
            self._require_relogin()
        else:
            self.notify("设置已保存", "success")

    def _sync_shell_url(self, url: str) -> None:
        """Keep the sidebar and status bar showing the address in use."""
        shell = self.window()
        label = getattr(shell, "server_label", None)
        if label is not None:
            label.setText(url)
        status = getattr(shell, "status_label", None)
        if status is not None:
            # Keep whatever operator name the shell already displayed.
            current = status.text()
            head = current.split(" · ", 1)[0].strip() if " · " in current else ""
            status.setText(f"{head} · {url}" if head else url)

    def _require_relogin(self) -> None:
        """Send the operator back to login after the address changed."""
        self.client.clear_session()
        self.notify("服务器地址已更改，请用新地址重新登录", "warning", 7000)
        shell = self.window()
        signal = getattr(shell, "logout", None)
        if signal is not None:
            QTimer.singleShot(0, signal.emit)


class MasterWindow(AppShell):
    def __init__(self, client: ApiClient, user: dict, config: Config):
        super().__init__("密钥授权系统 · 主控端（系统管理）", user, client.base_url)
        self.client = client
        self.config = config

        self.toast = Toast(self)
        self.notify = self.toast.show_message

        self.overview = OverviewPage(client, self.notify)
        self.dashboard = DashboardPage(client, self.notify)
        self.change_password = ChangePasswordPage(client, self.notify)
        self.ai = AIAssistantPage(client, self.notify)
        self.alerts = AlertCenterPage(client, self.notify)
        self.generate = GeneratePage(client, self.notify)
        self.licenses = LicensesPage(client, self.notify)
        self.user_admin = UserAdminPage(client, self.notify)
        self.approvals = ApprovalCenterPage(client, self.notify)
        self.batches = BatchesPage(client, self.notify)
        self.offline = OfflinePage(client, self.notify)
        self.admins = AdminsPage(client, self.notify)
        self.logs = LogsPage(client, self.notify)
        self.settings = SettingsPage(client, self.notify, config)
        self.about = AboutPage(client, self.notify)

        self.add_page("系统概览", self.overview)
        self.add_page("数据看板", self.dashboard)
        self.add_page("AI 助手", self.ai)
        self.add_page("告警中心", self.alerts)
        self.add_page("生成密钥", self.generate)
        self.add_page("密钥管理", self.licenses)
        self.add_page("用户管理", self.user_admin)
        self.add_page("审批中心", self.approvals)
        self.add_page("批次管理", self.batches)
        self.add_page("离线激活", self.offline)
        self.add_page("管理员管理", self.admins)
        self.add_page("审计日志", self.logs)
        self.add_page("修改密码", self.change_password, password_gate=True)
        self.add_page("系统设置", self.settings)
        self.add_page("关于", self.about)

        if not user.get("must_change_password"):
            self.overview.refresh()
            self.licenses.refresh()
            self.admins.refresh()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if self.toast.isVisible():
            self.toast.move(max(12, (self.width() - self.toast.width()) // 2), 20)
