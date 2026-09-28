from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
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

from . import theme
from .api_client import ApiClient, ApiError
from .config import APP_AUTHOR, APP_NAME, APP_VERSION, Config
from .widgets import make_button


class LoginDialog(QDialog):
    def __init__(self, config: Config, title: str, subtitle: str = "", parent=None):
        super().__init__(parent)
        self.config = config
        self.client = ApiClient(config.client.get("server_url", config.server_url()), int(config.client.get("timeout", 8)))
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
        self.input_user = QLineEdit()
        self.input_user.setPlaceholderText("用户名")
        self.input_pass = QLineEdit()
        self.input_pass.setPlaceholderText("密码")
        self.input_pass.setEchoMode(QLineEdit.Password)

        root.addWidget(self._labeled("服务器地址", self.input_server))
        root.addWidget(self._labeled("账号", self.input_user))
        root.addWidget(self._labeled("密码", self.input_pass))

        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.setStyleSheet(f"color: {theme.DANGER};")
        root.addWidget(self.status)

        self.btn_login = make_button("登 录", "primary", self.submit)
        self.btn_login.setMinimumHeight(40)
        root.addWidget(self.btn_login)

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

    def submit(self) -> None:
        url = self.input_server.text().strip() or "http://127.0.0.1:8765"
        user = self.input_user.text().strip()
        pwd = self.input_pass.text()
        if not user or not pwd:
            self.status.setText("请输入账号和密码")
            return
        self.btn_login.setEnabled(False)
        self.status.setText("正在登录…")
        self.status.setStyleSheet(f"color: {theme.TEXT_MUTED};")
        try:
            self.client.set_base_url(url)
            data = self.client.login(user, pwd)
        except ApiError as exc:
            self.status.setText(str(exc))
            self.status.setStyleSheet(f"color: {theme.DANGER};")
            self.btn_login.setEnabled(True)
            return
        self.config.client["server_url"] = self.client.base_url
        self.config.save()
        self.result_data = data
        self.accept()


class AppShell(QMainWindow):
    logout = Signal()

    def __init__(self, title: str, user: dict, server_url: str):
        super().__init__()
        self.setWindowTitle(title)
        self.resize(1180, 760)

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

    def _build_sidebar(self, title: str, user: dict, server_url: str) -> QWidget:
        side = QFrame()
        side.setObjectName("Sidebar")
        side.setFixedWidth(232)
        layout = QVBoxLayout(side)
        layout.setContentsMargins(16, 20, 16, 18)
        layout.setSpacing(8)

        brand = QLabel("密钥授权系统")
        brand.setObjectName("Brand")
        layout.addWidget(brand)
        role = "主控端" if user.get("role") == "master" else "管理端"
        sub = QLabel(f"{role} · {user.get('username', '')}")
        sub.setObjectName("Subtitle")
        layout.addWidget(sub)
        layout.addSpacing(10)

        self.nav_layout = QVBoxLayout()
        self.nav_layout.setSpacing(4)
        layout.addLayout(self.nav_layout)
        layout.addStretch(1)

        self.server_label = QLabel(server_url)
        self.server_label.setObjectName("Muted")
        self.server_label.setWordWrap(True)
        layout.addWidget(self.server_label)

        layout.addWidget(make_button("退出登录", "ghost", self.logout.emit))
        return side

    def add_page(self, label: str, widget: QWidget) -> None:
        btn = QPushButton(label)
        btn.setObjectName("NavButton")
        btn.setCheckable(True)
        btn.setCursor(Qt.PointingHandCursor)
        index = self.stack.addWidget(widget)
        btn.clicked.connect(lambda: self.stack.setCurrentIndex(index))
        self._group.addButton(btn)
        self.nav_layout.addWidget(btn)
        if self._group.buttons().__len__() == 1:
            btn.setChecked(True)
            self.stack.setCurrentIndex(index)


def run_client_app(app, config: Config, login_title: str, login_subtitle: str, window_factory):
    from PySide6.QtCore import QTimer

    holder: dict = {}

    def open_login() -> None:
        dialog = LoginDialog(config, login_title, login_subtitle)
        if dialog.exec() != QDialog.Accepted:
            app.quit()
            return
        window = window_factory(dialog.client, dialog.result_data)
        window.logout.connect(lambda: (window.close(), QTimer.singleShot(0, open_login)))
        window.show()
        holder["window"] = window

    open_login()
    if "window" not in holder:
        return 0
    return app.exec()
