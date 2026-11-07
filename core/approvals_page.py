# -*- coding: utf-8 -*-
"""审批中心（主控端页面）：总开关 + 提示文案 + 审批列表（HTTP 版）。"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from .api_client import ApiError
from .pages import BasePage
from .widgets import Card, PageHeader, make_button

_KIND_TEXT = {
    "user_register": "用户注册",
    "admin_register": "管理员注册",
    "license_transfer": "卡密转赠",
}
_STATUS_TEXT = {
    "pending": "待处理",
    "approved": "已通过",
    "rejected": "已拒绝",
}


def _kind_text(kind: str) -> str:
    return _KIND_TEXT.get(str(kind or ""), str(kind or ""))


class ApprovalCenterPage(BasePage):
    """审批中心：与本地服务器同一套业务逻辑（HTTP 通道）。"""

    COLUMNS = ["ID", "类型", "申请人", "目标", "提交时间", "状态", "处理人"]

    def __init__(self, client, notify):
        super().__init__(client, notify)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        header = QHBoxLayout()
        header.addWidget(PageHeader("审批中心", "用户注册 / 管理员注册 / 卡密转赠"))
        header.addStretch(1)
        header.addWidget(make_button("刷新", "ghost", self.reload))
        layout.addLayout(header)

        settings = Card(padding=14)
        row = QHBoxLayout()
        row.setSpacing(10)
        self.toggle = QCheckBox("启用审批")
        self.toggle.setToolTip(
            "开启：用户注册 / 创建管理员 / 卡密转赠都需审批；\n关闭：直接放行。"
        )
        row.addWidget(self.toggle)
        row.addWidget(QLabel("提示文案"))
        self.hint_edit = QLineEdit()
        self.hint_edit.setPlaceholderText(
            "提交申请时展示给用户的提示（如：为避免服务器繁忙，需进行管理员审批）"
        )
        row.addWidget(self.hint_edit, 1)
        row.addWidget(make_button("保存设置", "primary", self._save_settings))
        settings.body.addLayout(row)
        layout.addWidget(settings)

        filters = QHBoxLayout()
        self.kind_box = QComboBox()
        self.kind_box.addItem("全部类型", "")
        self.kind_box.addItem("用户注册", "user_register")
        self.kind_box.addItem("管理员注册", "admin_register")
        self.kind_box.addItem("卡密转赠", "license_transfer")
        self.status_box = QComboBox()
        self.status_box.addItem("待处理", "pending")
        self.status_box.addItem("全部状态", "")
        self.status_box.addItem("已通过", "approved")
        self.status_box.addItem("已拒绝", "rejected")
        self.kind_box.currentIndexChanged.connect(lambda _i: self.reload())
        self.status_box.currentIndexChanged.connect(lambda _i: self.reload())
        filters.addWidget(self.kind_box)
        filters.addWidget(self.status_box)
        filters.addStretch(1)
        self.count_label = QLabel("")
        self.count_label.setObjectName("Muted")
        filters.addWidget(self.count_label)
        layout.addLayout(filters)

        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.setSortingEnabled(False)
        header_view = self.table.horizontalHeader()
        header_view.setSectionResizeMode(2, QHeaderView.Stretch)
        for col in (0, 1, 3, 4, 5, 6):
            header_view.setSectionResizeMode(col, QHeaderView.ResizeToContents)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._ctx_menu)
        layout.addWidget(self.table, 1)

        footer = QHBoxLayout()
        footer.addStretch(1)
        footer.addWidget(make_button("通过", "primary", lambda: self._review(True)))
        footer.addWidget(make_button("拒绝", "danger", lambda: self._review(False)))
        layout.addLayout(footer)

        self._rows: list = []
        self._menu = QMenu(self)
        self._menu.addAction("通过", lambda: self._review(True))
        self._menu.addAction("拒绝", lambda: self._review(False))
        self._menu.addSeparator()
        self._menu.addAction("复制申请人", self._copy_applicant)

    # ------------------------------------------------------------------ #
    def on_show(self) -> None:
        self.reload()

    def reload(self) -> None:
        kind = str(self.kind_box.currentData() or "")
        status = str(self.status_box.currentData() or "")
        try:
            data = self.client.list_approvals(kind, status, 200, 0)
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        items = data.get("items") or []
        self._rows = items
        self.table.setRowCount(0)
        for item in items:
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = [
                str(item.get("id") or ""),
                _kind_text(item.get("kind")),
                str(item.get("applicant") or ""),
                str(item.get("target") or "—"),
                str(item.get("created_at") or ""),
                _STATUS_TEXT.get(str(item.get("status")), str(item.get("status"))),
                str(item.get("reviewer") or "—"),
            ]
            for col, value in enumerate(values):
                self.table.setItem(row, col, QTableWidgetItem(value))
        pending = sum(1 for item in items if str(item.get("status")) == "pending")
        self.count_label.setText(f"当前列表 {len(items)} 条（待处理 {pending} 条）")

    def _current(self) -> dict | None:
        row = self.table.currentRow()
        if row < 0:
            self.notify("请先选择一条审批记录", "warning")
            return None
        if row >= len(self._rows):
            return None
        return self._rows[row]

    def _ctx_menu(self, pos) -> None:
        if not self.table.indexAt(pos).isValid():
            return
        self._menu.popup(self.table.viewport().mapToGlobal(pos))

    def _copy_applicant(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            return
        item = self.table.item(row, 2)
        if item is not None:
            from PySide6.QtWidgets import QApplication

            QApplication.clipboard().setText(item.text())
            self.notify("申请人已复制", "success")

    def _save_settings(self) -> None:
        try:
            self.client.approval_settings(
                bool(self.toggle.isChecked()), self.hint_edit.text().strip()
            )
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        self.notify("审批设置已保存（即刻生效）", "success")

    def _review(self, approve: bool) -> None:
        current = self._current()
        if not current:
            return
        if str(current.get("kind")) == "admin_register":
            QMessageBox.information(
                self,
                "仅服务器端可处理",
                "管理员账号创建审批只能在服务器端处理——请等待服务器主人审批。\n"
                "（该限制用于防止主控端越权扩编。）",
            )
            return
        note, ok = QInputDialog.getText(
            self, "审批备注", "备注（可留空）：" if approve else "驳回原因（可留空）："
        )
        if not ok:
            return
        try:
            if approve:
                result = self.client.approve_approval(current["id"], note or "")
                detail = result.get("detail") or "已通过"
            else:
                self.client.reject_approval(current["id"], note or "")
                detail = "已驳回"
        except ApiError as exc:
            self.notify(str(exc), "error")
            self.reload()
            return
        QMessageBox.information(self, "已处理", str(detail))
        self.reload()
