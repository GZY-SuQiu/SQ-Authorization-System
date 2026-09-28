import threading

import uvicorn
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core import theme
from core.api_client import ApiClient
from core.config import APP_AUTHOR, APP_COPYRIGHT, APP_NAME, APP_VERSION, Config
from core.database import Database
from core.widgets import Card, PageHeader, StatCard, Toast, make_button
from server.api import VERSION, create_app


class ServerController:
    def __init__(self, config: Config, db: Database):
        self.config = config
        self.db = db
        self._server: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self.is_running():
            return
        app = create_app(self.config, self.db)
        cfg = uvicorn.Config(
            app,
            host=self.config.server["host"],
            port=int(self.config.server["port"]),
            log_level="warning",
            access_log=False,
        )
        self._server = uvicorn.Server(cfg)
        self._thread = threading.Thread(target=self._server.run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.should_exit = True
            if self._thread:
                self._thread.join(timeout=3)
            self._server = None
            self._thread = None

    def is_running(self) -> bool:
        return bool(self._server and self._server.started and not self._server.should_exit)

    def url(self) -> str:
        return self.config.server_url()


class ServerWindow(QMainWindow):
    def __init__(self, config: Config, db: Database):
        super().__init__()
        self.config = config
        self.db = db
        self.controller = ServerController(config, db)
        self.client = ApiClient(config.server_url(), timeout=3)

        self.setWindowTitle("密钥授权系统 · 本地服务器")
        self.resize(1120, 720)

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
        columns.addWidget(self._build_settings(), 0)
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
        self.timer.timeout.connect(self.refresh)
        self.timer.start(3000)

        self.refresh()
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

        self.status_chip = QLabel("已停止")
        self.status_chip.setAlignment(Qt.AlignCenter)
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
        box = QWidget()
        row = QHBoxLayout(box)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(16)
        self.stat_total = StatCard("密钥总数", "0", theme.PRIMARY)
        self.stat_active = StatCard("已激活", "0", theme.SUCCESS)
        self.stat_devices = StatCard("绑定设备", "0", "#7A5AF8")
        self.stat_admins = StatCard("管理员", "0", theme.WARNING)
        for card in (self.stat_total, self.stat_active, self.stat_devices, self.stat_admins):
            row.addWidget(card)
        return box

    def _build_settings(self) -> QWidget:
        card = Card(padding=18)
        card.setFixedWidth(380)
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

        card.body.addStretch(1)
        row = QHBoxLayout()
        row.addWidget(make_button("保存设置", "default", self.on_save))
        row.addWidget(make_button("立即自检", "ghost", self.on_selfcheck))
        card.body.addLayout(row)
        return card

    def _build_logs(self) -> QWidget:
        card = Card(padding=18)
        header = QHBoxLayout()
        header.addWidget(PageHeader("审计日志", "记录登录、密钥生成与激活事件"))
        header.addStretch(1)
        header.addWidget(make_button("刷新", "ghost", self.refresh))
        card.body.addLayout(header)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["时间", "操作", "对象", "详情", "来源"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
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
        else:
            self.toast.show_message("启动中，请稍候…", "info")
        self.refresh()

    def on_stop(self) -> None:
        self.controller.stop()
        self.toast.show_message("服务已停止", "warning")
        self.refresh()

    def on_selfcheck(self) -> None:
        try:
            data = self.client.health()
            self.toast.show_message(f"自检通过 · {data.get('version')} · {data.get('time')}", "success")
        except Exception as exc:
            self.toast.show_message(f"自检失败：{exc}", "error")

    def refresh(self) -> None:
        running = self.controller.is_running()
        if running:
            self.status_chip.setText("● 运行中")
            self.status_chip.setStyleSheet(
                f"color: {theme.SUCCESS}; background: #E7F7EE; border-radius: 8px; padding: 6px 12px; font-weight: 600;"
            )
        else:
            self.status_chip.setText("● 已停止")
            self.status_chip.setStyleSheet(
                f"color: {theme.DANGER}; background: #FDECEA; border-radius: 8px; padding: 6px 12px; font-weight: 600;"
            )
        self.btn_start.setEnabled(not running)
        self.btn_stop.setEnabled(running)
        self.input_host.setEnabled(not running)
        self.input_port.setEnabled(not running)
        self.input_public.setEnabled(not running)
        self.url_label.setText(self.controller.url())

        stats = self.db.stats()
        self.stat_total.set_value(stats["total"])
        self.stat_active.set_value(stats["active"])
        self.stat_devices.set_value(stats["devices"])
        self.stat_admins.set_value(stats["admins"])

        logs = self.db.list_logs(100)
        self.table.setRowCount(len(logs))
        for row, item in enumerate(logs):
            values = [
                item.get("created_at", ""),
                item.get("action", ""),
                item.get("target", ""),
                item.get("detail", ""),
                item.get("ip", ""),
            ]
            for col, value in enumerate(values):
                self.table.setItem(row, col, QTableWidgetItem(str(value or "")))

    def closeEvent(self, event) -> None:
        self.controller.stop()
        event.accept()
