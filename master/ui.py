from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from core.api_client import ApiClient, ApiError
from core.config import APP_AUTHOR, APP_COPYRIGHT, APP_NAME, APP_VERSION, Config
from core.pages import (
    AboutPage,
    BasePage,
    GeneratePage,
    LicensesPage,
    LogsPage,
    OfflinePage,
    OverviewPage,
    fill_table,
)
from core.shell import AppShell
from core.widgets import Card, PageHeader, Toast, confirm, make_button

ROLE_TEXT = {"master": "主控", "admin": "管理"}
ADMIN_STATUS_TEXT = {"active": "正常", "disabled": "已禁用"}


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
        form.addRow("账号", self.username)
        form.addRow("密码", self.password)
        form.addRow("角色", self.role)
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
        try:
            self.client.create_admin(username, password, self.role.currentData())
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        self.notify("管理员已创建", "success")
        self.accept()


class AdminsPage(BasePage):
    COLUMNS = ["ID", "账号", "角色", "状态", "创建时间", "最近登录"]

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
        layout.addLayout(actions)

        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        for col in (0, 2, 3, 4, 5):
            self.table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeToContents)
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
                it["created_at"],
                it["last_login_at"] or "—",
            ])
        fill_table(self.table, rows)
        self.total_label.setText(f"共 {len(items)} 位")

    def _selected(self) -> dict | None:
        row = self.table.currentRow()
        if row < 0 or row >= len(getattr(self, "admins", [])):
            self.notify("请先选择一位管理员", "warning")
            return None
        return self.admins[row]

    def create(self) -> None:
        dialog = CreateAdminDialog(self.client, self.notify, self)
        if dialog.exec() == QDialog.Accepted:
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
        if not confirm(self, "重置密码", f"确定将账号 {admin['username']} 的密码重置为 admin123？"):
            return
        try:
            self.client.reset_admin_password(admin["id"], "admin123")
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        self.notify("密码已重置为 admin123", "success")


class SettingsPage(BasePage):
    def __init__(self, client, notify, config: Config):
        super().__init__(client, notify)
        self.config = config
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)
        layout.addWidget(PageHeader("系统设置", "连接配置与运行状态"))

        card = Card(padding=18)
        card.setFixedWidth(460)
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
        about.setFixedWidth(460)
        about.body.addWidget(PageHeader("关于", f"{APP_NAME} · v{APP_VERSION}"))
        desc = QLabel(
            "密钥授权系统由四个程序组成：\n"
            "· 本地服务器：数据与验证中枢（FastAPI + SQLite）\n"
            "· 管理端：密钥生成、查询、吊销、冻结\n"
            "· 验证端：机器码采集与激活校验\n"
            "· 主控端：管理员管理与全局设置\n\n"
            f"作者：{APP_AUTHOR}    版本：v{APP_VERSION}\n"
            f"{APP_COPYRIGHT}\n\n"
            "默认账号 admin / admin123，请尽快修改。\n\n"
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
        self.client.set_base_url(url)
        self.config.client["server_url"] = self.client.base_url
        self.config.save()
        try:
            data = self.client.health()
        except ApiError as exc:
            self.info_label.setText(f"已保存，但连接失败：{exc}")
            self.notify("已保存，连接失败", "error")
            return
        self.info_label.setText(f"连接正常 · 版本 {data.get('version')} · 服务器时间 {data.get('time')}")
        self.notify("设置已保存", "success")


class MasterWindow(AppShell):
    def __init__(self, client: ApiClient, user: dict, config: Config):
        super().__init__("密钥授权系统 · 主控端", user, client.base_url)
        self.client = client
        self.config = config

        self.toast = Toast(self)
        self.notify = self.toast.show_message

        self.overview = OverviewPage(client, self.notify)
        self.generate = GeneratePage(client, self.notify)
        self.licenses = LicensesPage(client, self.notify)
        self.offline = OfflinePage(client, self.notify)
        self.admins = AdminsPage(client, self.notify)
        self.logs = LogsPage(client, self.notify)
        self.settings = SettingsPage(client, self.notify, config)
        self.about = AboutPage(client, self.notify)

        self.add_page("系统概览", self.overview)
        self.add_page("生成密钥", self.generate)
        self.add_page("密钥管理", self.licenses)
        self.add_page("离线激活", self.offline)
        self.add_page("管理员管理", self.admins)
        self.add_page("审计日志", self.logs)
        self.add_page("系统设置", self.settings)
        self.add_page("关于", self.about)

        self.overview.refresh()
        self.licenses.refresh()
        self.admins.refresh()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if self.toast.isVisible():
            self.toast.move(max(12, (self.width() - self.toast.width()) // 2), 20)
