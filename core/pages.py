import csv
import json
import time

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QColor, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressDialog,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from . import offline, security, theme
from .api_client import ApiClient, ApiError
from .config import (
    APP_AUTHOR,
    APP_COPYRIGHT,
    APP_NAME,
    APP_VERSION,
    AUTHOR_STATEMENT,
    LEGAL_STATEMENT,
)
from .widgets import (
    Card,
    PageHeader,
    StatCard,
    StatGrid,
    confirm,
    info,
    make_button,
    prepare_table,
)

# Offline request codes are unsigned, so bound how long one stays usable:
# re-issuing an activation code for a machine state from months ago is a
# needless risk, and the device can always produce a fresh request.
REQUEST_CODE_MAX_AGE_DAYS = 30

STATUS_TEXT = {
    "unused": "未使用",
    "active": "已激活",
    "revoked": "已吊销",
    "expired": "已过期",
    "frozen": "已冻结",
    "unbound": "已解绑",
    "disabled": "已禁用",
}

STATUS_COLOR = {
    "unused": theme.TEXT_MUTED,
    "active": theme.SUCCESS,
    "revoked": theme.DANGER,
    "expired": theme.WARNING,
    "frozen": theme.FROZEN,
    "unbound": theme.TEXT_MUTED,
    "disabled": theme.DANGER,
}

STATUS_KIND = {
    "active": "success",
    "revoked": "error",
    "disabled": "error",
    "expired": "warning",
    "frozen": "frozen",
}

EDITION_TEXT = {
    "standard": "标准版",
    "professional": "专业版",
    "enterprise": "企业版",
}


def status_text(status: str) -> str:
    return STATUS_TEXT.get(status, status or "-")


def edition_text(edition: str) -> str:
    return EDITION_TEXT.get(edition, edition or "-")


def duration_text(value, unit: str = "day") -> str:
    return security.duration_text(value, unit)


def devices_text(max_devices: int) -> str:
    return "不限" if not max_devices else f"{max_devices} 台"


def card_mode_text(lic: dict) -> str:
    return "激活次数卡" if (lic.get("card_type") or "duration") == "activation" else "时长卡"


def card_usage_text(lic: dict) -> str:
    """表格与导出共用的“时长 / 次数”文案。"""
    if (lic.get("card_type") or "duration") == "activation":
        limit = int(lic.get("activation_limit") or 0)
        used = int(lic.get("activation_count") or 0)
        return f"{used} / {limit} 次"
    return duration_text(lic.get("duration_days", 0), lic.get("duration_unit"))


def card_status_text(lic: dict) -> str | None:
    """次数用尽的卡密在列表里显示为“已用尽”而不是普通吊销。"""
    if lic.get("auto_revoked") and lic.get("status") == "revoked":
        return "已用尽"
    return None


def machine_codes_text(codes) -> str:
    codes = codes or []
    if not codes:
        return "—"
    if len(codes) <= 2:
        return "、".join(codes)
    return "、".join(codes[:2]) + f" 等 {len(codes)} 台"


def fill_table(table: QTableWidget, rows: list[list[str]]) -> None:
    prepare_table(table)
    table.setRowCount(len(rows))
    for r, values in enumerate(rows):
        for c, value in enumerate(values):
            item = QTableWidgetItem(str(value if value is not None else ""))
            table.setItem(r, c, item)


def status_table_item(status: str, text: str | None = None) -> QTableWidgetItem:
    item = QTableWidgetItem(f"● {text or status_text(status)}")
    item.setForeground(QColor(STATUS_COLOR.get(status, theme.TEXT_MUTED)))
    font = item.font()
    font.setBold(True)
    item.setFont(font)
    item.setData(Qt.UserRole, status)
    return item


# Browsing tables hold a bounded preview; going past it is always announced in
# the UI rather than silently showing a slice of the data.
TABLE_ROW_LIMIT = 5000
# Hard ceiling for one CSV export. Reaching it is reported to the operator.
EXPORT_ROW_LIMIT = 50000


def fetch_all_pages(fetch, *, page_size: int, limit: int) -> tuple[list[dict], int, bool]:
    """Collect every page a list endpoint offers.

    ``fetch(limit, offset)`` must return ``{"items": [...], "total": n}``.
    Returns ``(items, total, complete)``; ``complete`` is False when the
    ``limit`` ceiling stopped the walk before the server ran out of rows.
    """
    items: list[dict] = []
    offset = 0
    total = 0
    while len(items) < limit:
        want = min(page_size, limit - len(items))
        data = fetch(want, offset)
        chunk = [item for item in data.get("items", []) if isinstance(item, dict)]
        total = int(data.get("total") or 0)
        items.extend(chunk)
        if len(chunk) < want:
            return items, total, len(items) >= total
        offset += len(chunk)
        if total and len(items) >= total:
            return items, total, True
    return items, total, len(items) >= total


def table_row_values(table: QTableWidget, row: int) -> list[str]:
    values = []
    for col in range(table.columnCount()):
        item = table.item(row, col)
        values.append(item.text() if item is not None else "")
    return values


def selected_rows(table: QTableWidget) -> list[int]:
    return sorted({index.row() for index in table.selectedIndexes()})


def selected_key_codes(table: QTableWidget) -> list[str]:
    codes: list[str] = []
    seen: set[str] = set()
    for row in selected_rows(table):
        item = table.item(row, 0)
        if item is None:
            continue
        code = item.data(Qt.UserRole) or item.text()
        if code and code not in seen:
            seen.add(code)
            codes.append(code)
    return codes


def safe_filename(name: str, fallback: str = "export.csv") -> str:
    cleaned = "".join(ch for ch in name if ch not in '\\/:*?"<>|').strip()
    return cleaned or fallback


def preview_keys(keys: list[str], limit: int = 5) -> str:
    shown = "\n".join(keys[:limit])
    if len(keys) > limit:
        shown += f"\n… 共 {len(keys)} 个"
    return shown


def write_csv_file(path: str, headers: list[str], rows: list[list[str]]) -> None:
    # Cells are neutralised on the way out: audit details can contain a value
    # the operator did not type (a failed-login username, for example), and a
    # leading =, +, - or @ would be executed as a formula by Excel.
    with open(path, "w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        for row in rows:
            writer.writerow([security.csv_safe_cell(cell) for cell in row])


def export_csv(parent: QWidget, notify, headers: list[str], rows: list[list[str]], default_name: str) -> None:
    if not rows:
        notify("当前没有可导出的数据", "warning")
        return
    path, _ = QFileDialog.getSaveFileName(
        parent, "导出 CSV", default_name, "CSV 文件 (*.csv);;所有文件 (*)"
    )
    if not path:
        return
    if not path.lower().endswith(".csv"):
        path += ".csv"
    try:
        write_csv_file(path, headers, rows)
    except OSError as exc:
        notify(f"导出失败：{exc}", "error")
        return
    notify(f"已导出 {len(rows)} 条记录到 {path}", "success")


class BasePage(QWidget):
    def __init__(self, client: ApiClient, notify):
        super().__init__()
        self.client = client
        self.notify = notify


class ChangePasswordPage(BasePage):
    changed = Signal()

    def __init__(self, client, notify):
        super().__init__(client, notify)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)
        layout.addWidget(PageHeader("修改密码", "修改当前登录账号的密码，旧登录状态会失效"))

        card = Card(padding=20)
        card.setMinimumWidth(420)
        card.setMaximumWidth(560)
        form = QFormLayout()
        form.setSpacing(12)
        self.old_password = QLineEdit()
        self.old_password.setEchoMode(QLineEdit.Password)
        self.new_password = QLineEdit()
        self.new_password.setEchoMode(QLineEdit.Password)
        self.confirm_password = QLineEdit()
        self.confirm_password.setEchoMode(QLineEdit.Password)
        self.old_password.setPlaceholderText("请输入当前密码")
        self.new_password.setPlaceholderText("至少 8 位，包含字母和数字")
        self.confirm_password.setPlaceholderText("再次输入新密码")
        form.addRow("当前密码", self.old_password)
        form.addRow("新密码", self.new_password)
        form.addRow("确认新密码", self.confirm_password)
        card.body.addLayout(form)
        card.body.addWidget(make_button("保存新密码", "primary", self.submit))
        layout.addWidget(card)
        layout.addStretch(1)

    def submit(self) -> None:
        old = self.old_password.text()
        new = self.new_password.text()
        confirm = self.confirm_password.text()
        if not old or not new or not confirm:
            self.notify("请完整填写当前密码、新密码和确认密码", "warning")
            return
        if new != confirm:
            self.notify("两次输入的新密码不一致", "warning")
            return
        ok, msg = security.password_strength(new)
        if not ok:
            self.notify(msg, "warning")
            return
        try:
            self.client.change_password(old, new)
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        self.old_password.clear()
        self.new_password.clear()
        self.confirm_password.clear()
        self.changed.emit()
        self.notify("密码已修改，旧登录状态已失效", "success")


class OverviewPage(BasePage):
    def __init__(self, client, notify):
        super().__init__(client, notify)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        header = QHBoxLayout()
        header.addWidget(PageHeader("系统概览", "授权数据的实时统计"))
        header.addStretch(1)
        header.addWidget(make_button("刷新", "ghost", self.refresh))
        layout.addLayout(header)

        self.cards = {
            "total": StatCard("密钥总数", "0", theme.PRIMARY),
            "active": StatCard("已激活", "0", theme.SUCCESS),
            "unused": StatCard("未使用", "0", theme.FROZEN),
            "devices": StatCard("绑定设备", "0", theme.SUCCESS),
            "revoked": StatCard("已吊销", "0", theme.DANGER),
            "frozen": StatCard("已冻结", "0", theme.FROZEN),
            "expired": StatCard("已过期", "0", theme.WARNING),
            "exhausted": StatCard("已用尽", "0", theme.DANGER),
        }
        layout.addWidget(StatGrid(self.cards.values(), columns=4, min_card_width=150))

        card = Card(padding=18)
        card.body.addWidget(PageHeader("最近生成的密钥", ""))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["密钥", "版本", "状态", "时长 / 次数", "创建时间"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        for col in (1, 2, 3, 4):
            self.table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeToContents)
        card.body.addWidget(self.table, 1)
        layout.addWidget(card, 1)

    def refresh(self) -> None:
        try:
            stats = self.client.stats()
            for key, card in self.cards.items():
                card.set_value(stats.get(key, 0))
            data = self.client.list_licenses(limit=10)
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        rows = []
        for item in data.get("items", []):
            rows.append([
                item["key_code"],
                edition_text(item["edition"]),
                status_text(item["status"]),
                card_usage_text(item),
                item["created_at"],
            ])
        fill_table(self.table, rows)


        for row, item in enumerate(data.get("items", [])):
            self.table.setItem(row, 2, status_table_item(item["status"], card_status_text(item)))

    def on_show(self) -> None:
        self.refresh()


class GeneratePage(BasePage):
    def __init__(self, client, notify):
        super().__init__(client, notify)
        self.last_meta: dict[str, str] = {}
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)
        layout.addWidget(PageHeader("生成密钥", "批量生成授权密钥，参数一次设定"))

        columns = QSplitter(Qt.Horizontal)
        columns.setChildrenCollapsible(False)
        columns.setHandleWidth(6)
        columns.setOpaqueResize(False)
        columns.setStyleSheet(
            "QSplitter::handle { background: transparent; }"
            "QSplitter::handle:hover { background: #EEF4FF; }"
        )

        form_card = Card(padding=18)
        form_card.setMinimumWidth(340)
        form = QFormLayout()
        self.form = form
        form.setSpacing(12)
        self.count = QSpinBox()
        self.count.setRange(1, 500)
        self.count.setValue(1)
        self.edition = QComboBox()
        self.edition.addItem("标准版", "standard")
        self.edition.addItem("专业版", "professional")
        self.edition.addItem("企业版", "enterprise")
        self.card_mode = QComboBox()
        self.card_mode.addItem("时长卡", "duration")
        self.card_mode.addItem("激活次数卡", "activation")
        self.card_mode.addItem("试用卡", "trial")
        self.card_mode.currentIndexChanged.connect(
            lambda _index: self._on_mode_changed()
        )
        self.unit = QComboBox()
        self.unit.addItem("分钟卡", "minute")
        self.unit.addItem("小时卡", "hour")
        self.unit.addItem("天卡", "day")
        self.unit.addItem("星期卡", "week")
        self.unit.addItem("月卡", "month")
        self.unit.addItem("季卡", "quarter")
        self.unit.addItem("年卡", "year")
        self.unit.setCurrentIndex(2)
        self.unit.currentIndexChanged.connect(self._on_unit_changed)
        self.duration = QSpinBox()
        self.duration.setSpecialValueText("永久")
        self.duration.setRange(0, 3650)
        self.duration.setSuffix(" 天")
        self.activation_limit = QSpinBox()
        self.activation_limit.setRange(1, 100000)
        self.activation_limit.setValue(10)
        self.activation_limit.setSuffix(" 次")
        self.devices = QSpinBox()
        self.devices.setRange(0, 999)
        self.devices.setSpecialValueText("不限")
        self.prefix = QLineEdit("GSQ")
        self.features = QLineEdit()
        self.features.setPlaceholderText("选填，逗号分隔，如：pro,cloud,export")
        self.max_concurrent = QSpinBox()
        self.max_concurrent.setRange(0, 999)
        self.max_concurrent.setSpecialValueText("关闭")
        self.max_concurrent.setToolTip("浮动席位：限制同时在线数（0=按绑定设备数计）")
        self.fixed_expiry = QCheckBox("固定到期日")
        self.fixed_expiry_value = QLineEdit()
        self.fixed_expiry_value.setPlaceholderText("YYYY-MM-DD HH:MM:SS")
        self.fixed_expiry_value.setEnabled(False)
        self.fixed_expiry.toggled.connect(self.fixed_expiry_value.setEnabled)
        self.note = QLineEdit()
        self.note.setPlaceholderText("选填，如：某客户/某活动")
        form.addRow("生成数量", self.count)
        form.addRow("版本", self.edition)
        form.addRow("卡密模式", self.card_mode)
        form.addRow("卡类型", self.unit)
        form.addRow("有效期", self.duration)
        form.addRow("可激活次数", self.activation_limit)
        form.addRow("可绑定设备", self.devices)
        form.addRow("密钥前缀", self.prefix)
        form.addRow("功能位", self.features)
        form.addRow("并发席位", self.max_concurrent)
        form.addRow(self.fixed_expiry, self.fixed_expiry_value)
        form.addRow("备注", self.note)
        self._on_mode_changed()
        form_card.body.addLayout(form)
        form_card.body.addStretch(1)
        form_actions = QHBoxLayout()
        form_actions.addWidget(make_button("生成密钥", "primary", self.generate), 1)
        form_actions.addWidget(make_button("重置参数", "ghost", self.reset_form))
        form_card.body.addLayout(form_actions)
        columns.addWidget(form_card)

        result_card = Card(padding=18)
        result_card.setMinimumWidth(360)
        head = QHBoxLayout()
        head.addWidget(PageHeader("生成结果", "可直接复制分发给用户"))
        head.addStretch(1)
        self.batch_label = QLabel("尚未生成")
        self.batch_label.setObjectName("Muted")
        head.addWidget(self.batch_label)
        head.addWidget(make_button("导出卡密", "default", self.export_keys))
        head.addWidget(make_button("复制全部", "ghost", self.copy_all))
        result_card.body.addLayout(head)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText("生成的密钥将显示在这里")
        result_card.body.addWidget(self.output, 1)
        columns.addWidget(result_card)
        columns.setStretchFactor(0, 0)
        columns.setStretchFactor(1, 1)
        columns.setSizes([380, 620])
        layout.addWidget(columns, 1)

    def _set_form_row_visible(self, field: QWidget, visible: bool) -> None:
        label = self.form.labelForField(field)
        if label is not None:
            label.setVisible(visible)
        field.setVisible(visible)

    def _on_mode_changed(self) -> None:
        activation = self.card_mode.currentData() == "activation"
        for field in (self.unit, self.duration, self.devices):
            self._set_form_row_visible(field, not activation)
        self._set_form_row_visible(self.activation_limit, activation)

    def _on_unit_changed(self) -> None:
        unit = self.unit.currentData()
        suffix = {
            "minute": " 分钟",
            "hour": " 小时",
            "day": " 天",
            "week": " 周",
            "month": " 月",
            "quarter": " 季",
            "year": " 年",
        }.get(unit, " 天")
        maximum = {
            "minute": 100000,
            "hour": 100000,
            "day": 36500,
            "week": 5214,
            "month": 1216,
            "quarter": 405,
            "year": 100,
        }.get(unit, 3650)
        self.duration.setSuffix(suffix)
        self.duration.setMaximum(maximum)

    def reset_form(self) -> None:
        self.count.setValue(1)
        self.edition.setCurrentIndex(0)
        self.card_mode.setCurrentIndex(0)
        self.unit.setCurrentIndex(2)
        self.duration.setValue(0)
        self.activation_limit.setValue(10)
        self.devices.setValue(0)
        self.prefix.setText("GSQ")
        self.features.clear()
        self.max_concurrent.setValue(0)
        self.fixed_expiry.setChecked(False)
        self.fixed_expiry_value.clear()
        self.note.clear()
        self.notify("生成参数已重置", "success")

    def generate(self) -> None:
        activation = self.card_mode.currentData() == "activation"
        try:
            feature_text = self.features.text().strip()
            fixed_expiry = (
                self.fixed_expiry_value.text().strip()
                if self.fixed_expiry.isChecked()
                else ""
            )
            data = self.client.generate_licenses(
                count=self.count.value(),
                edition=self.edition.currentData(),
                card_type=self.card_mode.currentData(),
                activation_limit=self.activation_limit.value() if activation else 0,
                duration_days=0 if activation else self.duration.value(),
                duration_unit="day" if activation else self.unit.currentData(),
                max_devices=0 if activation else self.devices.value(),
                max_concurrent=0 if activation else self.max_concurrent.value(),
                expiry_mode="fixed" if fixed_expiry else "relative",
                fixed_expires_at=fixed_expiry,
                features=[
                    part.strip()
                    for part in feature_text.replace("，", ",").split(",")
                    if part.strip()
                ],
                note=self.note.text().strip(),
                prefix=self.prefix.text().strip() or "GSQ",
            )
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        keys = data.get("keys", [])
        self.output.setPlainText("\n".join(keys))
        self.last_meta = {
            "batch_no": data.get("batch_no") or "",
            "edition": self.edition.currentText(),
            "mode": self.card_mode.currentText(),
            "usage": (
                f"{self.activation_limit.value()} 次" if activation
                else duration_text(self.duration.value(), self.unit.currentData())
            ),
            "devices": devices_text(0 if activation else self.devices.value()),
            "note": self.note.text().strip(),
        }
        self.batch_label.setText(f"批次 {self.last_meta['batch_no']} · 共 {len(keys)} 个")
        self.notify(f"已生成 {len(keys)} 个密钥", "success")

    def copy_all(self) -> None:
        text = self.output.toPlainText().strip()
        if not text:
            self.notify("暂无可复制内容", "warning")
            return
        QApplication.clipboard().setText(text)
        self.notify("已复制到剪贴板", "success")

    def export_keys(self) -> None:
        keys = [line.strip() for line in self.output.toPlainText().splitlines() if line.strip()]
        if not keys:
            self.notify("暂无可导出的密钥", "warning")
            return
        meta = self.last_meta
        batch_no = meta.get("batch_no", "")
        default_name = safe_filename(f"{self.prefix.text().strip() or 'GSQ'}_{batch_no or 'keys'}", "keys.csv")
        path, selected = QFileDialog.getSaveFileName(
            self, "导出卡密", default_name,
            "CSV 文件 (*.csv);;文本文件 (*.txt);;所有文件 (*)"
        )
        if not path:
            return
        as_csv = path.lower().endswith(".csv") or (
            not path.lower().endswith(".txt") and "csv" in (selected or "").lower()
        )
        try:
            if as_csv:
                if not path.lower().endswith(".csv"):
                    path += ".csv"
                rows = [
                    [
                        key,
                        batch_no,
                        meta.get("edition", ""),
                        meta.get("mode", ""),
                        meta.get("usage", ""),
                        meta.get("devices", ""),
                        meta.get("note", ""),
                    ]
                    for key in keys
                ]
                write_csv_file(
                    path,
                    ["密钥", "批次", "版本", "卡密模式", "时长 / 次数", "可绑定设备", "备注"],
                    rows,
                )
            else:
                leaf = path.replace("\\", "/").rsplit("/", 1)[-1]
                if not path.lower().endswith(".txt") and "." not in leaf:
                    path += ".txt"
                with open(path, "w", encoding="utf-8-sig") as handle:
                    handle.write("\n".join(keys) + "\n")
        except OSError as exc:
            self.notify(f"导出失败：{exc}", "error")
            return
        self.notify(f"已导出 {len(keys)} 个密钥到 {path}", "success")


class DetailDialog(QDialog):
    def __init__(self, client: ApiClient, key_code: str, notify, parent=None):
        super().__init__(parent)
        self.client = client
        self.key_code = key_code
        self.notify = notify
        self.setWindowTitle(f"密钥详情 · {key_code}")
        self.resize(760, 560)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        self.info_label = QLabel("加载中…")
        self.info_label.setObjectName("Muted")
        self.info_label.setWordWrap(True)
        layout.addWidget(self.info_label)

        head = QHBoxLayout()
        head.addWidget(PageHeader("绑定设备", ""))
        head.addStretch(1)
        head.addWidget(make_button("复制机器码", "default", self.copy_machine))
        head.addWidget(make_button("刷新", "ghost", self.load))
        head.addWidget(make_button("解绑选中设备", "danger", self.unbind_selected))
        layout.addLayout(head)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["设备名", "机器码", "状态", "激活时间", "到期时间"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        for col in range(1, 5):
            self.table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeToContents)
        layout.addWidget(self.table, 1)
        actions = QHBoxLayout()
        actions.addStretch(1)
        actions.addWidget(make_button("一键换绑", "default", self.rebind))
        layout.addLayout(actions)
        self.load()

    def rebind(self) -> None:
        """一键换绑：解冻 + 解绑全部设备 + 引导文案。"""
        answer = QMessageBox.question(
            self,
            "一键换绑",
            f"将对密钥 {self.key_code} 执行：解冻（如需）并解绑全部设备。\n"
            "完成后用户可在新设备重新激活。是否继续？",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            data = self.client.rebind_license(self.key_code)
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        QMessageBox.information(
            self, "换绑完成", data.get("guide") or data.get("message") or "已处理。"
        )
        self.load()

    def load(self) -> None:
        try:
            data = self.client.license_detail(self.key_code)
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        lic = data["license"]
        card_kind = lic.get("card_type") or "duration"
        if card_kind == "activation":
            usage = (
                f"卡密模式：激活次数卡    激活次数：{lic['activation_count']} "
                f"/ {lic['activation_limit']} 次"
            )
            validity = "有效期：不限（次数用尽后自动吊销）"
        else:
            usage = "卡密模式：试用卡" if card_kind == "trial" else "卡密模式：时长卡"
            if str(lic.get("expiry_mode") or "relative") == "fixed":
                validity = f"有效期：固定至 {lic['expires_at'] or '—'}"
            else:
                validity = (
                    f"有效期：{duration_text(lic['duration_days'], lic.get('duration_unit'))}"
                )
            seats = int(lic.get("max_concurrent") or 0)
            if seats > 0:
                validity += f"    并发席位：{seats}"
        state = card_status_text(lic) or status_text(lic["status"])
        feature_values = lic.get("features")
        if not isinstance(feature_values, list):
            try:
                feature_values = json.loads(feature_values) if feature_values else []
            except (TypeError, ValueError):
                feature_values = []
        features_line = (
            f"\n功能位：{', '.join(feature_values)}" if feature_values else ""
        )
        info = (
            f"版本：{edition_text(lic['edition'])}    状态：{state}    {usage}\n"
            f"{validity}    可绑定设备：{devices_text(lic['max_devices'])}{features_line}\n"
            f"创建时间：{lic['created_at']}    到期时间：{lic['expires_at'] or '—'}    "
            f"批次：{lic['batch_no'] or '—'}    备注：{lic['note'] or '—'}"
        )
        if lic["status"] == "frozen":
            info += f"\n冻结至：{lic.get('frozen_until') or '—'}    冻结原因：{lic.get('freeze_reason') or '—'}"
        self.info_label.setText(info)
        self.machines = [a["machine_code"] for a in data["activations"]]
        rows = []
        for a in data["activations"]:
            rows.append([
                a["device_name"] or "—",
                a["machine_code"],
                status_text(a["status"]),
                a["activated_at"],
                a["expires_at"] or "—",
            ])
        fill_table(self.table, rows)
        for row, activation in enumerate(data["activations"]):
            self.table.setItem(row, 2, status_table_item(activation["status"]))


    def copy_machine(self) -> None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self.machines):
            self.notify("请先选择要复制的设备", "warning")
            return
        QApplication.clipboard().setText(self.machines[row])
        self.notify("机器码已复制", "success")

    def unbind_selected(self) -> None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self.machines):
            self.notify("请先选择要解绑的设备", "warning")
            return
        machine = self.machines[row]
        if not confirm(self, "解绑设备", f"确定解绑设备？\n机器码：{machine}"):
            return
        try:
            self.client.unbind(self.key_code, machine)
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        self.notify("已解绑", "success")
        self.load()


class FreezeDialog(QDialog):
    def __init__(self, key_code: str, parent=None):
        super().__init__(parent)
        self.key_code = key_code
        self.setWindowTitle("冻结密钥")
        self.setFixedWidth(420)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)
        layout.addWidget(PageHeader("冻结密钥", f"{key_code}\n冻结期间该密钥无法激活与校验"))

        form = QFormLayout()
        form.setSpacing(12)
        self.amount = QSpinBox()
        self.amount.setRange(1, 100000)
        self.amount.setValue(1)
        self.unit = QComboBox()
        self.unit.addItem("分钟", "minute")
        self.unit.addItem("小时", "hour")
        self.unit.addItem("天", "day")
        self.unit.addItem("周", "week")
        self.unit.addItem("月", "month")
        self.unit.addItem("季", "quarter")
        self.unit.addItem("年", "year")
        self.unit.setCurrentIndex(1)
        self.reason = QLineEdit()
        self.reason.setPlaceholderText("选填，如：检测到违规使用")
        form.addRow("冻结时长", self.amount)
        form.addRow("时长单位", self.unit)
        form.addRow("冻结原因", self.reason)
        layout.addLayout(form)

        actions = QHBoxLayout()
        actions.addStretch(1)
        actions.addWidget(make_button("取消", "ghost", self.reject))
        actions.addWidget(make_button("确认冻结", "primary", self.accept))
        layout.addLayout(actions)

    def values(self) -> tuple[int, str, str]:
        return self.amount.value(), self.unit.currentData(), self.reason.text().strip()


class RenewDialog(QDialog):
    def __init__(self, key_code: str, parent=None):
        super().__init__(parent)
        self.key_code = key_code
        self.setWindowTitle("续期密钥")
        self.setFixedWidth(420)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)
        layout.addWidget(PageHeader("续期密钥", f"{key_code}\n在当前有效期之后延长授权"))

        form = QFormLayout()
        form.setSpacing(12)
        self.amount = QSpinBox()
        self.amount.setRange(1, 36500)
        self.amount.setValue(30)
        self.unit = QComboBox()
        self.unit.addItem("分钟", "minute")
        self.unit.addItem("小时", "hour")
        self.unit.addItem("天", "day")
        self.unit.addItem("周", "week")
        self.unit.addItem("月", "month")
        self.unit.addItem("季", "quarter")
        self.unit.addItem("年", "year")
        self.unit.setCurrentIndex(2)
        form.addRow("延长时长", self.amount)
        form.addRow("时长单位", self.unit)
        layout.addLayout(form)

        actions = QHBoxLayout()
        actions.addStretch(1)
        actions.addWidget(make_button("取消", "ghost", self.reject))
        actions.addWidget(make_button("确认续期", "primary", self.accept))
        layout.addLayout(actions)

    def values(self) -> tuple[int, str]:
        return self.amount.value(), self.unit.currentData()


class LicensesPage(BasePage):
    COLUMNS = ["密钥", "版本", "状态", "时长 / 次数", "可绑定设备", "绑定硬件码", "创建时间", "到期时间", "批次", "备注"]
    PAGE_SIZES = (50, 100, 200, 500)

    def __init__(self, client, notify):
        super().__init__(client, notify)
        self.offset = 0
        self.page_size = 100
        self.total = 0
        # 批量操作互斥（P2-18）：processEvents() 期间禁止再次进入批量执行。
        self._batch_running = False
        self._batch_busy_state: list[bool] = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)
        layout.addWidget(PageHeader("密钥管理", "查询、批量操作、导出或删除密钥"))

        bar = QHBoxLayout()
        self.keyword = QLineEdit()
        self.keyword.setPlaceholderText("搜索密钥 / 备注")
        self.keyword.setClearButtonEnabled(True)
        self.keyword.returnPressed.connect(self.apply_filters)
        self.status = QComboBox()
        for label, value in [("全部状态", ""), ("未使用", "unused"), ("已激活", "active"),
                             ("已冻结", "frozen"), ("已吊销", "revoked"), ("已过期", "expired")]:
            self.status.addItem(label, value)
        self.status.currentIndexChanged.connect(lambda _index: self.apply_filters())
        self.status.setMinimumWidth(120)
        self.batch = QComboBox()
        self.batch.addItem("全部批次", "")
        self.batch.setMinimumWidth(180)
        self.batch.setMaximumWidth(260)
        self.batch.currentIndexChanged.connect(lambda _index: self.apply_filters())
        bar.addWidget(self.keyword, 1)
        bar.addWidget(self.status)
        bar.addWidget(self.batch)
        self.query_button = make_button("查询", "primary", self.apply_filters)
        self.reset_button = make_button("重置", "ghost", self.reset_filters)
        bar.addWidget(self.query_button)
        bar.addWidget(self.reset_button)
        layout.addLayout(bar)

        pager = QHBoxLayout()
        self.total_label = QLabel("共 0 条")
        self.total_label.setObjectName("Muted")
        self.page_label = QLabel("第 1 / 1 页")
        self.page_label.setObjectName("Muted")
        self.size_box = QComboBox()
        for size in self.PAGE_SIZES:
            self.size_box.addItem(f"每页 {size} 条", size)
        self.size_box.setCurrentIndex(self.PAGE_SIZES.index(self.page_size))
        self.size_box.currentIndexChanged.connect(lambda _index: self.change_page_size())
        self.prev_button = make_button("上一页", "ghost", lambda: self.go_page(-1))
        self.next_button = make_button("下一页", "ghost", lambda: self.go_page(1))
        pager.addWidget(self.total_label)
        pager.addWidget(self.page_label)
        pager.addStretch(1)
        pager.addWidget(self.size_box)
        pager.addWidget(self.prev_button)
        pager.addWidget(self.next_button)
        layout.addLayout(pager)

        actions = QHBoxLayout()
        self.detail_button = make_button("查看详情", "default", self.show_detail)
        self.copy_button = make_button("复制选中", "default", self.copy_selected)
        self.export_button = make_button("导出 CSV", "default", self.export_selected)
        actions.addWidget(self.detail_button)
        actions.addWidget(self.copy_button)
        actions.addWidget(self.export_button)
        actions.addStretch(1)
        self.ops_menu = self._build_ops_menu()
        self.ops_button = QToolButton()
        self.ops_button.setText("批量操作  ▾")
        self.ops_button.setPopupMode(QToolButton.InstantPopup)
        self.ops_button.setMenu(self.ops_menu)
        actions.addWidget(self.ops_button)
        layout.addLayout(actions)

        # 批量执行期间禁用的主要操作按钮（结束时按原状态恢复）。
        self._batch_widgets = [
            self.query_button,
            self.reset_button,
            self.detail_button,
            self.copy_button,
            self.export_button,
            self.ops_button,
            self.prev_button,
            self.next_button,
        ]

        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.ExtendedSelection)
        self.table.setSortingEnabled(True)
        self.table.doubleClicked.connect(self.show_detail)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_ops_menu)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        widths = [230, 88, 96, 110, 120, 220, 158, 158, 150, 160]
        for col, width in enumerate(widths):
            self.table.setColumnWidth(col, width)
        copy_shortcut = QShortcut(QKeySequence.StandardKey.Copy, self.table)
        copy_shortcut.setContext(Qt.WidgetWithChildrenShortcut)
        copy_shortcut.activated.connect(self.copy_selected)
        layout.addWidget(self.table, 1)

    def apply_filters(self) -> None:
        self.offset = 0
        self.refresh()

    def reset_filters(self) -> None:
        self.status.blockSignals(True)
        self.batch.blockSignals(True)
        self.keyword.clear()
        self.batch.setCurrentIndex(0)
        self.status.setCurrentIndex(0)
        self.batch.blockSignals(False)
        self.status.blockSignals(False)
        self.offset = 0
        self.refresh()

    def change_page_size(self) -> None:
        size = self.size_box.currentData()
        if size:
            self.page_size = int(size)
        self.offset = 0
        self.refresh()

    def go_page(self, step: int) -> None:
        target = self.offset + step * self.page_size
        if target < 0 or target >= max(self.total, 1):
            return
        self.offset = target
        self.refresh()

    def refresh(self) -> None:
        try:
            data = self.client.list_licenses(
                keyword=self.keyword.text().strip(),
                status=self.status.currentData(),
                batch_no=self.batch.currentData() or "",
                limit=self.page_size,
                offset=self.offset,
            )
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        items = data.get("items", [])
        total = int(data.get("total") or 0)
        self.total = total if total > 0 else self.offset + len(items)
        if self.offset and self.offset >= self.total:
            self.offset = max(0, ((self.total - 1) // self.page_size) * self.page_size)
            self.refresh()
            return
        self.table.setSortingEnabled(False)
        rows = []
        for it in items:
            rows.append([
                it["key_code"],
                edition_text(it["edition"]),
                status_text(it["status"]),
                card_usage_text(it),
                devices_text(it["max_devices"]),
                machine_codes_text(it.get("machine_codes")),
                it["created_at"],
                it["expires_at"] or "—",
                it["batch_no"] or "—",
                it["note"] or "—",
            ])
        fill_table(self.table, rows)
        for row, item in enumerate(items):
            key_item = self.table.item(row, 0)
            if key_item is not None:
                key_item.setData(Qt.UserRole, item["key_code"])
            self.table.setItem(row, 2, status_table_item(item["status"], card_status_text(item)))
        self.table.setSortingEnabled(True)
        pages = max(1, (self.total + self.page_size - 1) // self.page_size)
        current = min(pages, self.offset // self.page_size + 1)
        self.total_label.setText(f"共 {self.total} 条")
        self.page_label.setText(f"第 {current} / {pages} 页")
        self.prev_button.setEnabled(self.offset > 0)
        self.next_button.setEnabled(self.offset + self.page_size < self.total)

    def _build_ops_menu(self) -> QMenu:
        menu = QMenu(self)
        menu.addAction("续期", self.renew_selected)
        menu.addAction("冻结密钥", self.freeze_selected)
        menu.addAction("解冻密钥", self.unfreeze_selected)
        menu.addSeparator()
        menu.addAction("吊销密钥", self.revoke_selected)
        menu.addAction("恢复密钥", self.restore_selected)
        menu.addSeparator()
        menu.addAction("复制选中密钥", self.copy_selected)
        menu.addAction("导出选中为 CSV", self.export_selected)
        menu.addAction("全选本页", self.select_page)
        menu.addSeparator()
        menu.addAction("吊销当前批次（整批）", self.revoke_batch_selected)
        scope = menu.addMenu("对全部筛选结果操作（跨页）")
        scope.addAction("吊销全部筛选结果", self.revoke_all_filtered)
        scope.addAction("恢复全部筛选结果", self.restore_all_filtered)
        scope.addAction("冻结全部筛选结果", self.freeze_all_filtered)
        scope.addAction("解冻全部筛选结果", self.unfreeze_all_filtered)
        scope.addAction("续期全部筛选结果", self.renew_all_filtered)
        menu.addSeparator()
        menu.addAction("删除密钥", self.delete_selected)
        return menu

    def _show_ops_menu(self, pos) -> None:
        if not self.table.indexAt(pos).isValid():
            return
        self.ops_menu.popup(self.table.viewport().mapToGlobal(pos))

    def _selected_keys(self) -> list[str]:
        keys = selected_key_codes(self.table)
        if not keys:
            self.notify("请先选择至少一条密钥", "warning")
        return keys

    def select_page(self) -> None:
        """Select every row on the page so a bulk action covers all of them."""
        self.table.selectAll()
        self.notify(f"已选中本页 {self.table.rowCount()} 条密钥", "info")

    def _current_filters(self) -> dict:
        return {
            "keyword": self.keyword.text().strip(),
            "status": self.status.currentData(),
            "batch_no": self.batch.currentData() or "",
        }

    def _all_filtered_keys(self) -> list[str]:
        """Every key matching the current filters, across every page.

        The table only shows one page at a time, so a bulk action that should
        cover the whole result set has to ask the server for it.
        """
        filters = self._current_filters()
        try:
            items, _total, complete = fetch_all_pages(
                lambda limit, offset: self.client.list_licenses(
                    limit=limit, offset=offset, **filters
                ),
                page_size=500,
                limit=EXPORT_ROW_LIMIT,
            )
        except ApiError as exc:
            self.notify(str(exc), "error")
            return []
        if not complete:
            self.notify(
                f"匹配的密钥超过 {EXPORT_ROW_LIMIT} 条，本次只处理前 {len(items)} 条",
                "warning",
                7000,
            )
        return [str(item.get("key_code") or "") for item in items if item.get("key_code")]

    def _sync_batches(self) -> None:
        try:
            data = self.client.list_batches(limit=200)
        except (ApiError, AttributeError):
            return
        items = data.get("items", []) if isinstance(data, dict) else []
        current = self.batch.currentData()
        self.batch.blockSignals(True)
        self.batch.clear()
        self.batch.addItem("全部批次", "")
        for item in items:
            batch_no = str(item.get("batch_no") or "")
            if not batch_no:
                continue
            total = int(item.get("total") or 0)
            label = f"{batch_no}（{total} 个）"
            self.batch.addItem(label, batch_no)
            tip = str(item.get("note") or "")
            if tip:
                self.batch.setItemData(self.batch.count() - 1, tip, Qt.ToolTipRole)
        index = self.batch.findData(current) if current else 0
        self.batch.setCurrentIndex(index if index >= 0 else 0)
        self.batch.blockSignals(False)

    def on_show(self) -> None:
        self._sync_batches()
        self.refresh()

    def show_detail(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            self.notify("请先选择一条密钥", "warning")
            return
        item = self.table.item(row, 0)
        key = item.data(Qt.UserRole) if item is not None else None
        if not key:
            return
        DetailDialog(self.client, key, self.notify, self).exec()

    def copy_selected(self) -> None:
        keys = self._selected_keys()
        if not keys:
            return
        QApplication.clipboard().setText("\n".join(keys))
        self.notify(f"已复制 {len(keys)} 个密钥", "success")

    def export_selected(self) -> None:
        indexes = selected_rows(self.table)
        scope = "选中" if indexes else "本页"
        if indexes:
            rows = [table_row_values(self.table, row) for row in indexes]
        else:
            rows = [table_row_values(self.table, row) for row in range(self.table.rowCount())]
        batch_no = str(self.batch.currentData() or "全部")
        export_csv(
            self,
            self.notify,
            list(self.COLUMNS),
            rows,
            safe_filename(f"licenses_{batch_no}_{scope}.csv", "licenses.csv"),
        )

    def _batch_busy(self) -> bool:
        """批量执行中再次进入时直接返回并提示（P2-18 互斥）。"""
        if self._batch_running:
            self.notify("批量操作进行中", "warning")
            return True
        return False

    def _set_batch_busy(self, busy: bool) -> None:
        """批量执行期间禁用主要操作按钮，结束后按原状态恢复。"""
        if busy:
            self._batch_busy_state = [
                widget.isEnabled() for widget in self._batch_widgets
            ]
            for widget in self._batch_widgets:
                widget.setEnabled(False)
            return
        for widget, enabled in zip(self._batch_widgets, self._batch_busy_state):
            widget.setEnabled(enabled)
        self._batch_busy_state = []

    def _run_batch(self, keys: list[str], verb: str, title: str, call, confirm_text: str) -> None:
        if self._batch_busy():
            return
        if not confirm(self, title, confirm_text):
            return
        self._batch_running = True
        self._set_batch_busy(True)
        progress = QProgressDialog(f"正在{verb}…", "取消", 0, len(keys), self)
        progress.setWindowTitle(title)
        # 模态进度框挡住其它窗口的点击，processEvents() 期间也不会再触发批量入口。
        progress.setWindowModality(Qt.ApplicationModal)
        progress.setMinimumDuration(0)
        progress.setAutoClose(False)
        progress.setAutoReset(False)
        progress.show()
        ok = 0
        failures: list[str] = []
        try:
            for index, key in enumerate(keys):
                if progress.wasCanceled():
                    break
                progress.setLabelText(f"正在{verb}（{index + 1}/{len(keys)}）\n{key}")
                progress.setValue(index)
                QApplication.processEvents()
                try:
                    call(key)
                    ok += 1
                except ApiError as exc:
                    failures.append(f"{key}：{exc}")
        finally:
            # 异常也必须复位互斥标志、恢复按钮并刷新表格，否则页面会永久卡死。
            try:
                progress.setValue(len(keys))
                progress.close()
            finally:
                self._batch_running = False
                self._set_batch_busy(False)
                try:
                    self.refresh()
                except Exception:
                    # 刷新失败不能掩盖批量过程中的原始异常，也不能跳过互斥复位。
                    pass
        processed = ok + len(failures)
        if failures:
            detail = "\n".join(failures[:12])
            if len(failures) > 12:
                detail += f"\n… 其余 {len(failures) - 12} 条已省略"
            info(self, f"{verb}完成：成功 {ok} 个，失败 {len(failures)} 个。\n\n{detail}", f"{verb}结果")
            self.notify(f"{verb}完成：成功 {ok} 个，失败 {len(failures)} 个", "warning")
        elif processed < len(keys):
            self.notify(f"已取消，完成 {ok} 个", "info")
        else:
            self.notify(f"已{verb} {ok} 个密钥", "success")

    def revoke_selected(self) -> None:
        keys = self._selected_keys()
        if not keys:
            return
        self._run_batch(
            keys,
            "吊销",
            "吊销密钥",
            self.client.revoke_license,
            f"确定吊销选中的 {len(keys)} 个密钥？吊销后已激活设备将失效（之后可恢复）。\n\n{preview_keys(keys)}",
        )

    def restore_selected(self) -> None:
        keys = self._selected_keys()
        if not keys:
            return
        self._run_batch(
            keys,
            "恢复",
            "恢复密钥",
            self.client.restore_license,
            f"确定恢复选中的 {len(keys)} 个密钥？恢复后状态回到吊销前。\n\n{preview_keys(keys)}",
        )

    def renew_selected(self) -> None:
        keys = self._selected_keys()
        if not keys:
            return
        diag = RenewDialog(keys[0], self)
        if len(keys) > 1:
            diag.setWindowTitle(f"批量续期 · {len(keys)} 个密钥")
        if diag.exec() != QDialog.Accepted:
            return
        amount, unit = diag.values()
        span = duration_text(amount, unit)
        self._run_batch(
            keys,
            "续期",
            "续期密钥",
            lambda key: self.client.renew_license(key, amount, unit),
            f"确定为选中的 {len(keys)} 个密钥延长 {span}？\n\n{preview_keys(keys)}",
        )

    def freeze_selected(self) -> None:
        keys = self._selected_keys()
        if not keys:
            return
        diag = FreezeDialog(keys[0], self)
        if len(keys) > 1:
            diag.setWindowTitle(f"批量冻结 · {len(keys)} 个密钥")
        if diag.exec() != QDialog.Accepted:
            return
        amount, unit, reason = diag.values()
        span = duration_text(amount, unit)
        self._run_batch(
            keys,
            "冻结",
            "冻结密钥",
            lambda key: self.client.freeze_license(key, amount, unit, reason),
            f"确定冻结选中的 {len(keys)} 个密钥，时长 {span}？\n\n{preview_keys(keys)}",
        )

    def unfreeze_selected(self) -> None:
        keys = self._selected_keys()
        if not keys:
            return
        self._run_batch(
            keys,
            "解冻",
            "解冻密钥",
            self.client.unfreeze_license,
            f"确定立即解冻选中的 {len(keys)} 个密钥？\n\n{preview_keys(keys)}",
        )

    def revoke_batch_selected(self) -> None:
        if self._batch_busy():
            return
        batch_no = str(self.batch.currentData() or "")
        if not batch_no:
            self.notify("请先在筛选栏选择要吊销的批次", "warning")
            return
        if not confirm(self, "吊销整批密钥", f"确定吊销批次 {batch_no} 下的全部密钥？\n吊销后已激活设备将失效（之后可恢复）。"):
            return
        try:
            data = self.client.revoke_batch(batch_no)
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        self.notify(f"已吊销 {data.get('count', 0)} 个密钥", "success")
        self._sync_batches()
        self.refresh()

    def revoke_all_filtered(self) -> None:
        keys = self._all_filtered_keys()
        if not keys:
            self.notify("当前筛选条件下没有可吊销的密钥", "warning")
            return
        self._run_batch(
            keys,
            "吊销",
            "吊销全部筛选结果",
            self.client.revoke_license,
            f"确定吊销当前筛选条件下的全部 {len(keys)} 个密钥？\n"
            f"吊销后已激活设备将失效（之后可恢复）。\n\n{preview_keys(keys)}",
        )

    def restore_all_filtered(self) -> None:
        keys = self._all_filtered_keys()
        if not keys:
            self.notify("当前筛选条件下没有可恢复的密钥", "warning")
            return
        self._run_batch(
            keys,
            "恢复",
            "恢复全部筛选结果",
            self.client.restore_license,
            f"确定恢复当前筛选条件下的全部 {len(keys)} 个密钥？\n"
            f"只有已吊销的密钥会变化，其余会提示失败。\n\n{preview_keys(keys)}",
        )

    def unfreeze_all_filtered(self) -> None:
        keys = self._all_filtered_keys()
        if not keys:
            self.notify("当前筛选条件下没有可解冻的密钥", "warning")
            return
        self._run_batch(
            keys,
            "解冻",
            "解冻全部筛选结果",
            self.client.unfreeze_license,
            f"确定立即解冻当前筛选条件下的全部 {len(keys)} 个密钥？\n\n{preview_keys(keys)}",
        )

    def freeze_all_filtered(self) -> None:
        keys = self._all_filtered_keys()
        if not keys:
            self.notify("当前筛选条件下没有可冻结的密钥", "warning")
            return
        diag = FreezeDialog(keys[0], self)
        diag.setWindowTitle(f"整批冻结 · {len(keys)} 个密钥")
        if diag.exec() != QDialog.Accepted:
            return
        amount, unit, reason = diag.values()
        span = duration_text(amount, unit)
        self._run_batch(
            keys,
            "冻结",
            "冻结全部筛选结果",
            lambda key: self.client.freeze_license(key, amount, unit, reason),
            f"确定冻结当前筛选条件下的全部 {len(keys)} 个密钥，时长 {span}？\n\n{preview_keys(keys)}",
        )

    def renew_all_filtered(self) -> None:
        keys = self._all_filtered_keys()
        if not keys:
            self.notify("当前筛选条件下没有可续期的密钥", "warning")
            return
        diag = RenewDialog(keys[0], self)
        diag.setWindowTitle(f"整批续期 · {len(keys)} 个密钥")
        if diag.exec() != QDialog.Accepted:
            return
        amount, unit = diag.values()
        span = duration_text(amount, unit)
        self._run_batch(
            keys,
            "续期",
            "续期全部筛选结果",
            lambda key: self.client.renew_license(key, amount, unit),
            f"确定为当前筛选条件下的全部 {len(keys)} 个密钥延长 {span}？\n\n{preview_keys(keys)}",
        )

    def delete_selected(self) -> None:
        keys = self._selected_keys()
        if not keys:
            return
        self._run_batch(
            keys,
            "删除",
            "删除密钥",
            self.client.delete_license,
            f"确定彻底删除选中的 {len(keys)} 个密钥及其激活记录？该操作不可恢复。\n\n{preview_keys(keys)}",
        )


class BatchesPage(BasePage):
    COLUMNS = ["批次号", "总数", "未使用", "已激活", "已冻结", "已吊销", "已用尽", "已过期", "创建时间", "最近生成", "操作人", "备注"]
    EXPORT_LIMIT = 20000
    PAGE_SIZE = 500
    LIST_LIMIT = TABLE_ROW_LIMIT

    def __init__(self, client, notify):
        super().__init__(client, notify)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        header = QHBoxLayout()
        header.addWidget(PageHeader("批次管理", "按批次查看密钥分布，支持整批导出、吊销与恢复"))
        header.addStretch(1)
        header.addWidget(make_button("刷新", "ghost", self.refresh))
        layout.addLayout(header)

        bar = QHBoxLayout()
        self.keyword = QLineEdit()
        self.keyword.setPlaceholderText("搜索批次号 / 备注 / 操作人")
        self.keyword.setClearButtonEnabled(True)
        self.keyword.returnPressed.connect(self.refresh)
        self.total_label = QLabel("共 0 个批次")
        self.total_label.setObjectName("Muted")
        bar.addWidget(self.keyword, 1)
        bar.addWidget(self.total_label)
        bar.addWidget(make_button("查询", "primary", self.refresh))
        bar.addWidget(make_button("重置", "ghost", self.reset_filters))
        layout.addLayout(bar)

        actions = QHBoxLayout()
        actions.addWidget(make_button("复制批次号", "default", self.copy_batch))
        actions.addWidget(make_button("导出批次卡密", "default", self.export_batch_keys))
        actions.addWidget(make_button("导出列表 CSV", "default", self.export_table))
        actions.addStretch(1)
        actions.addWidget(make_button("恢复整批", "default", self.restore_batch))
        actions.addWidget(make_button("吊销整批", "danger", self.revoke_batch))
        layout.addLayout(actions)

        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.ExtendedSelection)
        self.table.setSortingEnabled(True)
        header_view = self.table.horizontalHeader()
        header_view.setSectionResizeMode(QHeaderView.Interactive)
        header_view.setStretchLastSection(True)
        widths = [230, 70, 80, 80, 80, 80, 76, 80, 158, 158, 110, 160]
        for col, width in enumerate(widths):
            self.table.setColumnWidth(col, width)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_menu)
        self.menu = QMenu(self)
        self.menu.addAction("复制批次号", self.copy_batch)
        self.menu.addAction("导出批次卡密", self.export_batch_keys)
        self.menu.addAction("导出列表 CSV", self.export_table)
        self.menu.addSeparator()
        self.menu.addAction("吊销整批", self.revoke_batch)
        self.menu.addAction("恢复整批", self.restore_batch)
        copy_shortcut = QShortcut(QKeySequence.StandardKey.Copy, self.table)
        copy_shortcut.setContext(Qt.WidgetWithChildrenShortcut)
        copy_shortcut.activated.connect(self.copy_batch)
        layout.addWidget(self.table, 1)

    def reset_filters(self) -> None:
        self.keyword.clear()
        self.refresh()

    def refresh(self) -> None:
        keyword = self.keyword.text().strip()
        try:
            items, total, complete = fetch_all_pages(
                lambda limit, offset: self.client.list_batches(
                    keyword=keyword, limit=limit, offset=offset
                ),
                page_size=self.PAGE_SIZE,
                limit=self.LIST_LIMIT,
            )
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        self.table.setSortingEnabled(False)
        rows = []
        for item in items:
            rows.append([
                str(item.get("batch_no") or "—"),
                str(item.get("total") or 0),
                str(item.get("unused") or 0),
                str(item.get("active") or 0),
                str(item.get("frozen") or 0),
                str(item.get("revoked") or 0),
                str(item.get("exhausted") or 0),
                str(item.get("expired") or 0),
                str(item.get("created_at") or "—"),
                str(item.get("last_created_at") or "—"),
                str(item.get("created_by") or "—"),
                str(item.get("note") or "—"),
            ])
        fill_table(self.table, rows)
        self.table.setSortingEnabled(True)
        # A server that omits "total" must not make the label claim fewer
        # batches than are actually on screen.
        total = max(int(total or 0), len(items))
        if complete:
            self.total_label.setText(f"共 {total} 个批次")
            self.total_label.setToolTip("")
        else:
            self.total_label.setText(f"已加载 {len(items)} / 共 {total} 个批次")
            self.total_label.setToolTip(
                f"批次数量超过列表上限（{self.LIST_LIMIT} 个），请用关键词缩小范围"
            )

    def _show_menu(self, pos) -> None:
        if not self.table.indexAt(pos).isValid():
            return
        self.menu.popup(self.table.viewport().mapToGlobal(pos))

    def _selected_batches(self) -> list[str]:
        batches: list[str] = []
        for row in selected_rows(self.table):
            item = self.table.item(row, 0)
            name = item.text().strip() if item is not None else ""
            if name and name != "—" and name not in batches:
                batches.append(name)
        if not batches:
            self.notify("请先选择至少一个批次", "warning")
        return batches

    def copy_batch(self) -> None:
        batches = self._selected_batches()
        if not batches:
            return
        QApplication.clipboard().setText("\n".join(batches))
        self.notify(f"已复制 {len(batches)} 个批次号", "success")

    def export_table(self) -> None:
        indexes = selected_rows(self.table)
        if indexes:
            rows = [table_row_values(self.table, row) for row in indexes]
        else:
            rows = [table_row_values(self.table, row) for row in range(self.table.rowCount())]
        export_csv(self, self.notify, list(self.COLUMNS), rows, "batches.csv")

    def export_batch_keys(self) -> None:
        batches = self._selected_batches()
        if not batches:
            return
        rows: list[list[str]] = []
        truncated = False
        for batch_no in batches:
            offset = 0
            while len(rows) < self.EXPORT_LIMIT:
                try:
                    data = self.client.list_licenses(batch_no=batch_no, limit=500, offset=offset)
                except ApiError as exc:
                    self.notify(str(exc), "error")
                    return
                items = data.get("items", [])
                for it in items:
                    rows.append([
                        str(it.get("key_code", "")),
                        str(it.get("batch_no") or batch_no),
                        card_status_text(it) or status_text(it.get("status", "")),
                        edition_text(it.get("edition", "")),
                        card_mode_text(it),
                        card_usage_text(it),
                        devices_text(it.get("max_devices", 0)),
                        str(it.get("created_at", "")),
                        str(it.get("expires_at") or "—"),
                        str(it.get("note") or "—"),
                    ])
                offset += len(items)
                total = int(data.get("total") or 0)
                if len(items) < 500 or offset >= total:
                    break
            else:
                truncated = True
                break
        name = batches[0] if len(batches) == 1 else "多批次"
        export_csv(
            self,
            self.notify,
            [
                "密钥", "批次", "状态", "版本", "卡密模式", "时长 / 次数",
                "可绑定设备", "创建时间", "到期时间", "备注",
            ],
            rows,
            safe_filename(f"batch_{name}.csv", "batch.csv"),
        )
        if truncated:
            self.notify(f"数据量超过 {self.EXPORT_LIMIT} 条，仅导出前 {self.EXPORT_LIMIT} 条", "warning")

    def revoke_batch(self) -> None:
        batches = self._selected_batches()
        if not batches:
            return
        if not confirm(
            self,
            "吊销整批密钥",
            f"确定吊销以下批次的全部密钥？吊销后已激活设备将失效（之后可恢复）。\n\n{preview_keys(batches)}",
        ):
            return
        revoked = 0
        failures: list[str] = []
        for batch_no in batches:
            try:
                data = self.client.revoke_batch(batch_no)
            except ApiError as exc:
                failures.append(f"{batch_no}：{exc}")
                continue
            revoked += int(data.get("count") or 0)
        if failures:
            info(self, "以下批次吊销失败：\n\n" + "\n".join(failures), "吊销结果")
            self.notify(f"已吊销 {revoked} 个密钥，{len(failures)} 个批次失败", "warning")
        else:
            self.notify(f"已吊销 {revoked} 个密钥", "success")
        self.refresh()

    def restore_batch(self) -> None:
        batches = self._selected_batches()
        if not batches:
            return
        if not confirm(
            self,
            "恢复整批密钥",
            f"确定恢复以下批次中被吊销的全部密钥？恢复后状态回到吊销前。\n\n{preview_keys(batches)}",
        ):
            return
        restored = 0
        failures: list[str] = []
        for batch_no in batches:
            try:
                data = self.client.restore_batch(batch_no)
            except ApiError as exc:
                failures.append(f"{batch_no}：{exc}")
                continue
            restored += int(data.get("count") or 0)
        if failures:
            info(self, "以下批次恢复失败：\n\n" + "\n".join(failures), "恢复结果")
            self.notify(f"已恢复 {restored} 个密钥，{len(failures)} 个批次失败", "warning")
        elif restored:
            self.notify(f"已恢复 {restored} 个密钥", "success")
        else:
            self.notify("所选批次没有处于吊销状态的密钥", "warning")
        self.refresh()

    def on_show(self) -> None:
        self.refresh()


class LogsPage(BasePage):
    COLUMNS = ["时间", "操作", "发起人", "对象", "详情", "来源"]
    PAGE_SIZE = 1000
    FETCH_LIMIT = TABLE_ROW_LIMIT
    EXPORT_LIMIT = EXPORT_ROW_LIMIT

    def __init__(self, client, notify):
        super().__init__(client, notify)
        self.items: list[dict] = []
        self.total = 0
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        header = QHBoxLayout()
        header.addWidget(PageHeader("审计日志", "登录与密钥操作记录"))
        header.addStretch(1)
        self.count_label = QLabel("共 0 条")
        self.count_label.setObjectName("Muted")
        header.addWidget(self.count_label)
        layout.addLayout(header)

        bar = QHBoxLayout()
        self.keyword = QLineEdit()
        self.keyword.setPlaceholderText("搜索操作 / 发起人 / 对象 / 详情 / 来源")
        self.keyword.setClearButtonEnabled(True)
        self.keyword.textChanged.connect(lambda _text: self.apply_filter())
        self.action = QComboBox()
        self.action.addItem("全部操作", "")
        self.action.setMinimumWidth(150)
        self.action.currentIndexChanged.connect(lambda _index: self.apply_filter())
        self.auto = QCheckBox("自动刷新")
        self.auto.toggled.connect(self.toggle_auto)
        bar.addWidget(self.keyword, 1)
        bar.addWidget(self.action)
        bar.addWidget(self.auto)
        bar.addWidget(make_button("复制选中", "default", self.copy_selected))
        bar.addWidget(make_button("导出 CSV", "default", self.export_rows))
        bar.addWidget(make_button("刷新", "ghost", self.refresh))
        layout.addLayout(bar)

        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.ExtendedSelection)
        header_view = self.table.horizontalHeader()
        header_view.setSectionResizeMode(4, QHeaderView.Stretch)
        for col in (0, 1, 2, 3, 5):
            header_view.setSectionResizeMode(col, QHeaderView.ResizeToContents)
        copy_shortcut = QShortcut(QKeySequence.StandardKey.Copy, self.table)
        copy_shortcut.setContext(Qt.WidgetWithChildrenShortcut)
        copy_shortcut.activated.connect(self.copy_selected)
        layout.addWidget(self.table, 1)

        self.timer = QTimer(self)
        self.timer.setInterval(15000)
        self.timer.timeout.connect(self.refresh_silent)

    def toggle_auto(self, enabled: bool) -> None:
        if enabled:
            self.timer.start()
            self.refresh_silent()
        else:
            self.timer.stop()

    def load(self, silent: bool = False) -> None:
        keyword = self.keyword.text().strip()
        action = self.action.currentData() or ""
        try:
            items, total, _complete = fetch_all_pages(
                lambda limit, offset: self.client.list_logs(
                    limit, keyword=keyword, action=action, offset=offset
                ),
                page_size=self.PAGE_SIZE,
                limit=self.FETCH_LIMIT,
            )
        except ApiError as exc:
            if not silent:
                self.notify(str(exc), "error")
            return
        self.items = items
        self.total = total
        self._sync_actions()
        self.apply_filter()

    def _sync_actions(self) -> None:
        current = self.action.currentData()
        if current:
            # The last load was already narrowed to one action, so rebuilding
            # from those rows would shrink the dropdown to that single entry.
            return
        names: list[str] = []
        for item in self.items:
            name = str(item.get("action") or "")
            if name and name not in names:
                names.append(name)
        existing = [self.action.itemData(index) for index in range(self.action.count())]
        if existing[1:] == names:
            return
        self.action.blockSignals(True)
        self.action.clear()
        self.action.addItem("全部操作", "")
        for name in names:
            self.action.addItem(name, name)
        index = self.action.findData(current)
        self.action.setCurrentIndex(index if index >= 0 else 0)
        self.action.blockSignals(False)

    def apply_filter(self) -> None:
        keyword = self.keyword.text().strip().lower()
        action = self.action.currentData()
        rows = []
        for item in self.items:
            if action and item.get("action") != action:
                continue
            values = [
                str(item.get("created_at", "")),
                str(item.get("action", "")),
                str(item.get("actor", "")),
                str(item.get("target", "")),
                str(item.get("detail", "")),
                str(item.get("ip", "")),
            ]
            if keyword and keyword not in " ".join(values).lower():
                continue
            rows.append(values)
        fill_table(self.table, rows)
        loaded = len(self.items)
        total = max(self.total, loaded)
        if total > loaded:
            # The table is a bounded preview; never let the label imply that
            # everything on the server is on screen.
            self.count_label.setText(
                f"显示 {len(rows)} / 已加载 {loaded} / 共 {total} 条"
            )
            self.count_label.setToolTip(
                f"数据量超过预览上限（{self.FETCH_LIMIT} 条），导出会从服务器拉取全量数据"
            )
        elif len(rows) == loaded:
            self.count_label.setText(f"共 {loaded} 条")
            self.count_label.setToolTip("")
        else:
            self.count_label.setText(f"显示 {len(rows)} / 共 {loaded} 条")
            self.count_label.setToolTip("")

    def visible_rows(self) -> list[list[str]]:
        return [table_row_values(self.table, row) for row in range(self.table.rowCount())]

    def copy_selected(self) -> None:
        indexes = selected_rows(self.table)
        rows = [table_row_values(self.table, row) for row in indexes] if indexes else self.visible_rows()
        if not rows:
            self.notify("暂无可复制的日志", "warning")
            return
        text = "\n".join("\t".join(row) for row in rows)
        QApplication.clipboard().setText(text)
        self.notify(f"已复制 {len(rows)} 条日志", "success")

    def export_rows(self) -> None:
        indexes = selected_rows(self.table)
        if indexes:
            rows = [table_row_values(self.table, row) for row in indexes]
            export_csv(self, self.notify, list(self.COLUMNS), rows, "audit_logs.csv")
            return
        # Without a selection the export must cover the whole filtered set, not
        # just the rows the preview table happens to hold.
        keyword = self.keyword.text().strip()
        action = self.action.currentData() or ""
        try:
            items, _total, complete = fetch_all_pages(
                lambda limit, offset: self.client.list_logs(
                    limit, keyword=keyword, action=action, offset=offset
                ),
                page_size=self.PAGE_SIZE,
                limit=self.EXPORT_LIMIT,
            )
        except ApiError as exc:
            self.notify(f"导出失败：{exc}", "error")
            return
        rows = [
            [
                str(item.get("created_at", "")),
                str(item.get("action", "")),
                str(item.get("actor", "")),
                str(item.get("target", "")),
                str(item.get("detail", "")),
                str(item.get("ip", "")),
            ]
            for item in items
        ]
        if not rows:
            self.notify("当前筛选条件下没有可导出的日志", "warning")
            return
        export_csv(self, self.notify, list(self.COLUMNS), rows, "audit_logs.csv")
        if not complete:
            self.notify(
                f"日志超过 {self.EXPORT_LIMIT} 条，本次导出可能不完整", "warning", 7000
            )

    def refresh(self) -> None:
        self.load(silent=False)

    def refresh_silent(self) -> None:
        if not self.isVisible():
            return
        try:
            self.load(silent=True)
        except Exception as exc:
            try:
                from . import crashlog

                crashlog.log_exception("logs-auto-refresh", exc)
            except Exception:
                pass

    def on_show(self) -> None:
        self.refresh()


class OfflinePage(BasePage):
    def __init__(self, client, notify):
        super().__init__(client, notify)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)
        layout.addWidget(PageHeader("离线激活", "为无法联网的设备签发离线激活码"))

        columns = QSplitter(Qt.Horizontal)
        columns.setChildrenCollapsible(False)
        columns.setHandleWidth(6)
        columns.setOpaqueResize(False)
        columns.setStyleSheet(
            "QSplitter::handle { background: transparent; }"
            "QSplitter::handle:hover { background: #EEF4FF; }"
        )

        form_card = Card(padding=18)
        form_card.setMinimumWidth(360)
        form = QFormLayout()
        form.setSpacing(12)
        self.key = QLineEdit()
        self.key.setPlaceholderText("设备方提供的授权密钥")
        self.request = QPlainTextEdit()
        self.request.setPlaceholderText("粘贴设备方的离线请求码（LICREQ1. 开头），可自动解析机器码")
        self.request.setFixedHeight(96)
        self.machine = QLineEdit()
        self.machine.setPlaceholderText("机器码 / 硬件码")
        self.device = QLineEdit()
        self.device.setPlaceholderText("选填，设备名称")
        form.addRow("授权密钥", self.key)
        form.addRow("离线请求码", self.request)
        form.addRow("机器码", self.machine)
        form.addRow("设备名称", self.device)
        form_card.body.addLayout(form)
        form_card.body.addWidget(make_button("解析请求码", "default", self.parse_request))
        form_card.body.addStretch(1)
        form_actions = QHBoxLayout()
        form_actions.addWidget(make_button("生成离线激活码", "primary", self.generate), 1)
        form_actions.addWidget(make_button("清空", "ghost", self.clear_form))
        form_card.body.addLayout(form_actions)
        columns.addWidget(form_card)

        result_card = Card(padding=18)
        result_card.setMinimumWidth(360)
        head = QHBoxLayout()
        head.addWidget(PageHeader("离线激活码", "发送给设备方导入即可完成激活"))
        head.addStretch(1)
        head.addWidget(make_button("保存激活码", "default", self.save_code))
        head.addWidget(make_button("复制激活码", "ghost", self.copy_code))
        result_card.body.addLayout(head)
        self.hint = QLabel("尚未生成")
        self.hint.setObjectName("Muted")
        self.hint.setWordWrap(True)
        result_card.body.addWidget(self.hint)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText("生成的离线激活码将显示在这里")
        result_card.body.addWidget(self.output, 1)
        columns.addWidget(result_card)
        columns.setStretchFactor(0, 0)
        columns.setStretchFactor(1, 1)
        columns.setSizes([420, 580])
        layout.addWidget(columns, 1)

    def parse_request(self) -> None:
        code = offline.clean_code(self.request.toPlainText())
        if not code:
            self.notify("请先粘贴离线请求码", "warning")
            return
        info = offline.parse_request_code(code)
        if not info:
            self.notify("请求码无效或已损坏", "error")
            return
        age_error = self._request_age_error(info)
        if age_error:
            self.notify(age_error, "error")
            return
        self.machine.setText(info.get("mc", ""))
        if info.get("dn"):
            self.device.setText(info["dn"])
        from datetime import datetime

        ts_text = ""
        if info.get("ts"):
            try:
                ts_text = datetime.fromtimestamp(int(info["ts"])).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            except (ValueError, OSError):
                ts_text = ""
        self.notify(
            f"已解析机器码：{info.get('mc', '')}"
            + (f"（{ts_text}）" if ts_text else ""),
            "success",
        )

    @staticmethod
    def _request_age_error(info: dict) -> str:
        """Reject online-request codes that are stale or from the future."""
        ts = int(info.get("ts") or 0)
        if ts <= 0:
            return "请求码缺少时间戳，请让设备重新生成后再试。"
        now = int(time.time())
        if ts > now + 24 * 3600:
            return "请求码时间戳晚于本机时间，请校准系统时间后重试。"
        if now - ts > REQUEST_CODE_MAX_AGE_DAYS * 24 * 3600:
            return (
                f"请求码已超过 {REQUEST_CODE_MAX_AGE_DAYS} 天，"
                "请让设备重新生成后重试。"
            )
        return ""

    def clear_form(self) -> None:
        self.key.clear()
        self.request.clear()
        self.machine.clear()
        self.device.clear()
        self.output.clear()
        self.hint.setText("尚未生成")
        self.notify("已清空离线激活信息", "success")

    def generate(self) -> None:
        key = self.key.text().strip()
        machine = self.machine.text().strip()
        if not key or not machine:
            self.notify("请填写授权密钥与机器码", "warning")
            return
        try:
            data = self.client.offline_code(key, machine, self.device.text().strip())
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        code = data.get("code", "")
        self.output.setPlainText(offline.chunk_code(code))
        remaining = data.get("remaining", "")
        expires = data.get("expires_at") or "—"
        self.hint.setText(
            f"密钥：{data.get('key_code', key)}    机器码：{data.get('machine_code', machine)}\n"
            f"有效期：{data.get('duration_text', '')}    到期时间：{expires}    剩余：{remaining or '—'}"
        )
        self.notify("已生成离线激活码", "success")

    def copy_code(self) -> None:
        code = offline.clean_code(self.output.toPlainText())
        if not code:
            self.notify("暂无可复制内容", "warning")
            return
        QApplication.clipboard().setText(code)
        self.notify("已复制到剪贴板", "success")

    def save_code(self) -> None:
        code = offline.clean_code(self.output.toPlainText())
        if not code:
            self.notify("暂无可保存内容", "warning")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "保存离线激活码", f"offline_{self.machine.text().strip()}.txt",
            "文本文件 (*.txt);;所有文件 (*)"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig") as fh:
                fh.write(code + "\n")
        except OSError as exc:
            self.notify(f"保存失败：{exc}", "error")
            return
        self.notify(f"已保存到 {path}", "success")


class AboutPage(BasePage):
    def __init__(self, client, notify):
        super().__init__(client, notify)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)
        layout.addWidget(PageHeader("关于", f"{APP_NAME} · v{APP_VERSION}"))

        columns = QHBoxLayout()
        columns.setSpacing(16)

        info_card = Card(padding=20)
        info_card.setMinimumWidth(380)
        info_card.setMaximumWidth(480)
        info_card.body.addWidget(QLabel("软件信息"))
        meta = QLabel(
            f"软件名称：{APP_NAME}\n"
            f"版本号：v{APP_VERSION}\n"
            f"作者：{APP_AUTHOR}\n"
            f"版权：{APP_COPYRIGHT}\n"
            "组成：本地服务器 · 管理端 · 验证端 · 主控端"
        )
        meta.setObjectName("Muted")
        meta.setWordWrap(True)
        info_card.body.addWidget(meta)
        info_card.body.addSpacing(6)
        info_card.body.addWidget(QLabel("作者声明"))
        author = QLabel(AUTHOR_STATEMENT)
        author.setObjectName("Muted")
        author.setWordWrap(True)
        info_card.body.addWidget(author)
        info_card.body.addStretch(1)
        columns.addWidget(info_card)

        legal_card = Card(padding=20)
        legal_card.body.addWidget(QLabel("法律声明"))
        legal = QLabel(LEGAL_STATEMENT)
        legal.setObjectName("Muted")
        legal.setWordWrap(True)
        legal.setTextInteractionFlags(Qt.TextSelectableByMouse)
        legal_card.body.addWidget(legal)
        legal_card.body.addStretch(1)
        columns.addWidget(legal_card, 1)

        layout.addLayout(columns, 1)
