from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
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
from .widgets import Card, PageHeader, StatCard, confirm, make_button

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
    "frozen": "#7A5AF8",
    "unbound": theme.TEXT_MUTED,
    "disabled": theme.DANGER,
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


def machine_codes_text(codes) -> str:
    codes = codes or []
    if not codes:
        return "—"
    if len(codes) <= 2:
        return "、".join(codes)
    return "、".join(codes[:2]) + f" 等 {len(codes)} 台"


def fill_table(table: QTableWidget, rows: list[list[str]]) -> None:
    table.setRowCount(len(rows))
    for r, values in enumerate(rows):
        for c, value in enumerate(values):
            item = QTableWidgetItem(str(value if value is not None else ""))
            table.setItem(r, c, item)


class BasePage(QWidget):
    def __init__(self, client: ApiClient, notify):
        super().__init__()
        self.client = client
        self.notify = notify


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

        grid = QHBoxLayout()
        grid.setSpacing(14)
        self.cards = {
            "total": StatCard("密钥总数", "0", theme.PRIMARY),
            "active": StatCard("已激活", "0", theme.SUCCESS),
            "unused": StatCard("未使用", "0", "#7A5AF8"),
            "devices": StatCard("绑定设备", "0", "#12B76A"),
            "revoked": StatCard("已吊销", "0", theme.DANGER),
            "frozen": StatCard("已冻结", "0", "#7A5AF8"),
            "expired": StatCard("已过期", "0", theme.WARNING),
        }
        for card in self.cards.values():
            grid.addWidget(card)
        layout.addLayout(grid)

        card = Card(padding=18)
        card.body.addWidget(PageHeader("最近生成的密钥", ""))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["密钥", "版本", "状态", "有效期", "创建时间"])
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
                duration_text(item["duration_days"], item.get("duration_unit")),
                item["created_at"],
            ])
        fill_table(self.table, rows)


class GeneratePage(BasePage):
    def __init__(self, client, notify):
        super().__init__(client, notify)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)
        layout.addWidget(PageHeader("生成密钥", "批量生成授权密钥，参数一次设定"))

        columns = QHBoxLayout()
        columns.setSpacing(16)

        form_card = Card(padding=18)
        form_card.setFixedWidth(380)
        form = QFormLayout()
        form.setSpacing(12)
        self.count = QSpinBox()
        self.count.setRange(1, 500)
        self.count.setValue(1)
        self.edition = QComboBox()
        self.edition.addItem("标准版", "standard")
        self.edition.addItem("专业版", "professional")
        self.edition.addItem("企业版", "enterprise")
        self.unit = QComboBox()
        self.unit.addItem("分钟卡", "minute")
        self.unit.addItem("小时卡", "hour")
        self.unit.addItem("天卡", "day")
        self.unit.setCurrentIndex(2)
        self.unit.currentIndexChanged.connect(self._on_unit_changed)
        self.duration = QSpinBox()
        self.duration.setSpecialValueText("永久")
        self.duration.setRange(0, 3650)
        self.duration.setSuffix(" 天")
        self.devices = QSpinBox()
        self.devices.setRange(0, 999)
        self.devices.setSpecialValueText("不限")
        self.prefix = QLineEdit("LIC")
        self.note = QLineEdit()
        self.note.setPlaceholderText("选填，如：某客户/某活动")
        form.addRow("生成数量", self.count)
        form.addRow("版本", self.edition)
        form.addRow("卡类型", self.unit)
        form.addRow("有效期", self.duration)
        form.addRow("可绑定设备", self.devices)
        form.addRow("密钥前缀", self.prefix)
        form.addRow("备注", self.note)
        form_card.body.addLayout(form)
        form_card.body.addStretch(1)
        form_card.body.addWidget(make_button("生成密钥", "primary", self.generate))
        columns.addWidget(form_card)

        result_card = Card(padding=18)
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
        columns.addWidget(result_card, 1)
        layout.addLayout(columns, 1)

    def _on_unit_changed(self) -> None:
        unit = self.unit.currentData()
        suffix = {"minute": " 分钟", "hour": " 小时", "day": " 天"}.get(unit, " 天")
        maximum = 3650 if unit == "day" else 100000
        self.duration.setSuffix(suffix)
        self.duration.setMaximum(maximum)

    def generate(self) -> None:
        try:
            data = self.client.generate_licenses(
                count=self.count.value(),
                edition=self.edition.currentData(),
                duration_days=self.duration.value(),
                duration_unit=self.unit.currentData(),
                max_devices=self.devices.value(),
                note=self.note.text().strip(),
                prefix=self.prefix.text().strip() or "LIC",
            )
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        keys = data.get("keys", [])
        self.output.setPlainText("\n".join(keys))
        self.batch_label.setText(f"批次 {data.get('batch_no')} · 共 {len(keys)} 个")
        self.notify(f"已生成 {len(keys)} 个密钥", "success")

    def copy_all(self) -> None:
        text = self.output.toPlainText().strip()
        if not text:
            self.notify("暂无可复制内容", "warning")
            return
        QApplication.clipboard().setText(text)
        self.notify("已复制到剪贴板", "success")

    def export_keys(self) -> None:
        text = self.output.toPlainText().strip()
        if not text:
            self.notify("暂无可导出的密钥", "warning")
            return
        default_name = f"{self.prefix.text().strip() or 'LIC'}_{self.batch_label.text()}.txt"
        default_name = default_name.replace(" ", "_").replace("·", "_").replace("/", "_")
        path, _ = QFileDialog.getSaveFileName(
            self, "导出卡密", default_name, "文本文件 (*.txt);;CSV 文件 (*.csv);;所有文件 (*)"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig") as fh:
                fh.write(text + "\n")
        except OSError as exc:
            self.notify(f"导出失败：{exc}", "error")
            return
        self.notify(f"已导出到 {path}", "success")


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
        head.addWidget(make_button("解绑选中设备", "danger", self.unbind_selected))
        layout.addLayout(head)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["设备名", "机器码", "状态", "激活时间", "到期时间"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        for col in range(1, 5):
            self.table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeToContents)
        layout.addWidget(self.table, 1)
        self.load()

    def load(self) -> None:
        try:
            data = self.client.license_detail(self.key_code)
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        lic = data["license"]
        info = (
            f"版本：{edition_text(lic['edition'])}    状态：{status_text(lic['status'])}    "
            f"有效期：{duration_text(lic['duration_days'], lic.get('duration_unit'))}    可绑定设备：{devices_text(lic['max_devices'])}\n"
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


class LicensesPage(BasePage):
    COLUMNS = ["密钥", "版本", "状态", "有效期", "可绑定设备", "绑定硬件码", "创建时间", "到期时间", "批次", "备注"]

    def __init__(self, client, notify):
        super().__init__(client, notify)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)
        layout.addWidget(PageHeader("密钥管理", "查询、查看、吊销或删除密钥"))

        bar = QHBoxLayout()
        self.keyword = QLineEdit()
        self.keyword.setPlaceholderText("搜索密钥 / 备注 / 批次")
        self.keyword.returnPressed.connect(self.refresh)
        self.status = QComboBox()
        for label, value in [("全部状态", ""), ("未使用", "unused"), ("已激活", "active"),
                             ("已冻结", "frozen"), ("已吊销", "revoked"), ("已过期", "expired")]:
            self.status.addItem(label, value)
        self.status.currentIndexChanged.connect(self.refresh)
        bar.addWidget(self.keyword, 1)
        bar.addWidget(self.status)
        bar.addWidget(make_button("刷新", "ghost", self.refresh))
        layout.addLayout(bar)

        actions = QHBoxLayout()
        self.total_label = QLabel("共 0 条")
        self.total_label.setObjectName("Muted")
        actions.addWidget(self.total_label)
        actions.addStretch(1)
        actions.addWidget(make_button("查看详情", "default", self.show_detail))
        actions.addWidget(make_button("复制密钥", "default", self.copy_selected))
        actions.addWidget(make_button("冻结密钥", "default", self.freeze_selected))
        actions.addWidget(make_button("解冻密钥", "default", self.unfreeze_selected))
        actions.addWidget(make_button("吊销密钥", "danger", self.revoke_selected))
        actions.addWidget(make_button("恢复密钥", "default", self.restore_selected))
        actions.addWidget(make_button("删除密钥", "danger", self.delete_selected))
        layout.addLayout(actions)

        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.doubleClicked.connect(self.show_detail)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        for col in range(1, len(self.COLUMNS)):
            self.table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeToContents)
        layout.addWidget(self.table, 1)

    def refresh(self) -> None:
        try:
            data = self.client.list_licenses(
                keyword=self.keyword.text().strip(),
                status=self.status.currentData(),
                limit=300,
            )
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        items = data.get("items", [])
        self.keys = [it["key_code"] for it in items]
        self.statuses = [it["status"] for it in items]
        rows = []
        for it in items:
            rows.append([
                it["key_code"],
                edition_text(it["edition"]),
                status_text(it["status"]),
                duration_text(it["duration_days"], it.get("duration_unit")),
                devices_text(it["max_devices"]),
                machine_codes_text(it.get("machine_codes")),
                it["created_at"],
                it["expires_at"] or "—",
                it["batch_no"] or "—",
                it["note"] or "—",
            ])
        fill_table(self.table, rows)
        self.total_label.setText(f"共 {data.get('total', len(items))} 条")

    def _selected_key(self) -> str | None:
        row = self.table.currentRow()
        if row < 0 or row >= len(getattr(self, "keys", [])):
            self.notify("请先选择一条密钥", "warning")
            return None
        return self.keys[row]

    def show_detail(self) -> None:
        key = self._selected_key()
        if not key:
            return
        DetailDialog(self.client, key, self.notify, self).exec()

    def copy_selected(self) -> None:
        key = self._selected_key()
        if not key:
            return
        QApplication.clipboard().setText(key)
        self.notify("已复制密钥", "success")

    def revoke_selected(self) -> None:
        key = self._selected_key()
        if not key:
            return
        if not confirm(self, "吊销密钥", f"确定吊销该密钥？吊销后已激活设备将失效（之后可恢复）。\n{key}"):
            return
        try:
            self.client.revoke_license(key)
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        self.notify("已吊销，可在需要时恢复", "success")
        self.refresh()

    def restore_selected(self) -> None:
        key = self._selected_key()
        if not key:
            return
        if not confirm(self, "恢复密钥", f"确定恢复该密钥？恢复后状态将回到吊销前。\n{key}"):
            return
        try:
            self.client.restore_license(key)
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        self.notify("已恢复", "success")
        self.refresh()

    def freeze_selected(self) -> None:
        key = self._selected_key()
        if not key:
            return
        diag = FreezeDialog(key, self)
        if diag.exec() != QDialog.Accepted:
            return
        amount, unit, reason = diag.values()
        try:
            data = self.client.freeze_license(key, amount, unit, reason)
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        self.notify(data.get("message", "已冻结"), "success")
        self.refresh()

    def unfreeze_selected(self) -> None:
        key = self._selected_key()
        if not key:
            return
        if not confirm(self, "解冻密钥", f"确定立即解冻该密钥？\n{key}"):
            return
        try:
            self.client.unfreeze_license(key)
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        self.notify("已解冻", "success")
        self.refresh()

    def delete_selected(self) -> None:
        key = self._selected_key()
        if not key:
            return
        if not confirm(self, "删除密钥", f"确定彻底删除该密钥及其激活记录？\n{key}"):
            return
        try:
            self.client.delete_license(key)
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        self.notify("已删除", "success")
        self.refresh()


class LogsPage(BasePage):
    def __init__(self, client, notify):
        super().__init__(client, notify)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        header = QHBoxLayout()
        header.addWidget(PageHeader("审计日志", "登录与密钥操作记录"))
        header.addStretch(1)
        header.addWidget(make_button("刷新", "ghost", self.refresh))
        layout.addLayout(header)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["时间", "操作", "发起人", "对象", "详情", "来源"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        for col in (0, 1, 2, 3, 5):
            self.table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeToContents)
        layout.addWidget(self.table, 1)

    def refresh(self) -> None:
        try:
            data = self.client.list_logs(300)
        except ApiError as exc:
            self.notify(str(exc), "error")
            return
        rows = []
        for it in data.get("items", []):
            rows.append([
                it.get("created_at", ""),
                it.get("action", ""),
                it.get("actor", ""),
                it.get("target", ""),
                it.get("detail", ""),
                it.get("ip", ""),
            ])
        fill_table(self.table, rows)


class OfflinePage(BasePage):
    def __init__(self, client, notify):
        super().__init__(client, notify)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)
        layout.addWidget(PageHeader("离线激活", "为无法联网的设备签发离线激活码"))

        columns = QHBoxLayout()
        columns.setSpacing(16)

        form_card = Card(padding=18)
        form_card.setFixedWidth(420)
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
        form_card.body.addWidget(make_button("生成离线激活码", "primary", self.generate))
        columns.addWidget(form_card)

        result_card = Card(padding=18)
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
        columns.addWidget(result_card, 1)
        layout.addLayout(columns, 1)

    def parse_request(self) -> None:
        code = offline.clean_code(self.request.toPlainText())
        if not code:
            self.notify("请先粘贴离线请求码", "warning")
            return
        info = offline.parse_request_code(code)
        if not info:
            self.notify("请求码无效或已损坏", "error")
            return
        self.machine.setText(info.get("mc", ""))
        if info.get("dn"):
            self.device.setText(info["dn"])
        from datetime import datetime
        ts_text = ""
        if info.get("ts"):
            try:
                ts_text = datetime.fromtimestamp(int(info["ts"])).strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, OSError):
                ts_text = ""
        self.notify(f"已解析机器码：{info.get('mc', '')}" + (f"（{ts_text}）" if ts_text else ""), "success")

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
        info_card.setFixedWidth(440)
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
