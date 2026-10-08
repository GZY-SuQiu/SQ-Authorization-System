"""Portal (email account) administration page shared by admin and master.

The page lists the accounts customers registered from the verification
client, shows which licence key each one bound, and lets an operator
enable/disable the account or force the device binding to be released.
"""

from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QTableWidget,
    QVBoxLayout,
)

from .api_client import ApiError
from .pages import BasePage, fill_table, status_table_item
from .widgets import PageHeader, confirm, make_button

ACCOUNT_STATUS_TEXT = {"active": "正常", "disabled": "已禁用"}

# license_status arrives from the backend in the same vocabulary the licence
# tables use; unknown values fall through untouched.
LICENSE_STATUS_TEXT = {
    "active": "正常",
    "alive": "正常",
    "expired": "已过期",
    "revoked": "已吊销",
    "frozen": "已冻结",
    "exhausted": "已用尽",
    "not_active": "未激活",
    "unbound": "未绑定",
    "none": "未绑定",
    "": "未绑定",
}


def account_status_text(value) -> str:
    key = str(value or "").strip()
    return ACCOUNT_STATUS_TEXT.get(key, key or "—")


def license_status_text(value) -> str:
    key = str(value or "").strip().lower()
    return LICENSE_STATUS_TEXT.get(key, key or "未绑定")


class UserAdminPage(BasePage):
    """邮箱注册用户（门户账号）管理：检索、启停与强制脱绑。"""

    COLUMNS = [
        "邮箱",
        "名称",
        "状态",
        "绑定 Key",
        "许可证状态",
        "到期",
        "注册时间",
        "最后登录",
    ]
    PAGE_LIMIT = 200

    def __init__(self, client, notify):
        super().__init__(client, notify)
        self.accounts: list[dict] = []
        self.total = 0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        header = QHBoxLayout()
        header.addWidget(
            PageHeader("用户管理", "邮箱注册用户的状态、绑定 Key 与登录情况")
        )
        header.addStretch(1)
        self.total_label = QLabel("共 0 位用户")
        self.total_label.setObjectName("Muted")
        header.addWidget(self.total_label)
        self.btn_refresh = make_button("刷新", "ghost", self.refresh)
        header.addWidget(self.btn_refresh)
        layout.addLayout(header)

        bar = QHBoxLayout()
        self.keyword = QLineEdit()
        self.keyword.setPlaceholderText("搜索邮箱 / 显示名")
        self.keyword.setClearButtonEnabled(True)
        self.keyword.returnPressed.connect(self.apply_filters)
        self.status = QComboBox()
        self.status.setMinimumWidth(140)
        self.status.addItem("全部状态", "")
        self.status.addItem("正常", "active")
        self.status.addItem("已禁用", "disabled")
        self.status.currentIndexChanged.connect(lambda _index: self.apply_filters())
        self.btn_enable = make_button("启用", "default", self.enable_account)
        self.btn_disable = make_button("禁用", "danger", self.disable_account)
        self.btn_unbind = make_button("强制脱绑", "danger", self.force_unbind)
        bar.addWidget(self.keyword, 1)
        bar.addWidget(self.status)
        bar.addWidget(self.btn_enable)
        bar.addWidget(self.btn_disable)
        bar.addWidget(self.btn_unbind)
        layout.addLayout(bar)

        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        header_view = self.table.horizontalHeader()
        header_view.setSectionResizeMode(0, QHeaderView.Stretch)
        for col in range(1, len(self.COLUMNS)):
            header_view.setSectionResizeMode(col, QHeaderView.ResizeToContents)
        layout.addWidget(self.table, 1)

    # ------------------------------------------------------------ data
    def refresh(self) -> None:
        keyword = self.keyword.text().strip()
        status = self.status.currentData() or ""
        try:
            data = self.client.portal_accounts(
                keyword=keyword,
                status=status,
                limit=self.PAGE_LIMIT,
                offset=0,
            )
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        items = [
            item for item in data.get("items", []) if isinstance(item, dict)
        ]
        self.accounts = items
        try:
            self.total = int(data.get("total") or 0)
        except (TypeError, ValueError):
            self.total = 0
        if self.total < len(items):
            self.total = len(items)

        rows = []
        for item in items:
            rows.append(
                [
                    str(item.get("email") or "—"),
                    str(item.get("display_name") or "—"),
                    account_status_text(item.get("status")),
                    str(item.get("bound_key") or "未绑定"),
                    license_status_text(item.get("license_status")),
                    str(item.get("expires_at") or "未设置"),
                    str(item.get("created_at") or "—"),
                    str(item.get("last_login_at") or "—"),
                ]
            )
        fill_table(self.table, rows)
        for row, item in enumerate(items):
            value = str(item.get("status") or "").strip()
            self.table.setItem(
                row, 2, status_table_item(value, account_status_text(value))
            )
        self._update_total_label()

    def _update_total_label(self) -> None:
        shown = len(self.accounts)
        if self.total > shown:
            self.total_label.setText(f"显示 {shown} / 共 {self.total} 位用户")
            self.total_label.setToolTip(
                "已按当前筛选条件加载前 %d 位用户，可用搜索缩小范围" % self.PAGE_LIMIT
            )
        else:
            self.total_label.setText(f"共 {shown} 位用户")
            self.total_label.setToolTip("")

    def apply_filters(self) -> None:
        self.refresh()

    def _selected(self) -> dict | None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self.accounts):
            self.notify("请先选择一位用户", "warning")
            return None
        return self.accounts[row]

    # --------------------------------------------------------- actions
    def enable_account(self) -> None:
        self._set_account_status("active")

    def disable_account(self) -> None:
        self._set_account_status("disabled")

    def _set_account_status(self, status: str) -> None:
        account = self._selected()
        if not account:
            return
        action = "启用" if status == "active" else "禁用"
        email = str(account.get("email") or "")
        if not confirm(self, f"{action}用户", f"确定{action}账号 {email}？"):
            return
        try:
            self.client.set_portal_account_status(account.get("id"), status)
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        self.notify(f"已{action} {email}", "success")
        self.refresh()

    def force_unbind(self) -> None:
        account = self._selected()
        if not account:
            return
        email = str(account.get("email") or "")
        if not confirm(
            self,
            "强制脱绑",
            f"确定解除账号 {email} 的设备绑定？\n"
            "绑定设备会被释放，用户需要重新绑定授权 Key。",
        ):
            return
        try:
            self.client.admin_unbind_portal_account(account.get("id"))
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        self.notify(f"已强制脱绑 {email}", "success")
        self.refresh()

    def on_show(self) -> None:
        self.refresh()
