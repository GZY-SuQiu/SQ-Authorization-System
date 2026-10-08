"""告警中心：告警规则配置与告警事件处理（A5）。

页面依赖 ``ApiClient`` 第 6 节契约中的规则/事件/指标 8 个方法，A7 通知
渠道页额外使用第 6 节的 6 个渠道方法；接口暂时不可用时以“—”或空表
降级显示，页面本身仍可离屏构造。
"""


from __future__ import annotations

import json
import math

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QSpinBox,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from . import theme
from .api_client import ApiError
from .pages import BasePage, fill_table, selected_rows
from .widgets import (
    Card,
    PageHeader,
    StatCard,
    StatGrid,
    confirm,
    make_button,
    prepare_table,
)

# metric 取值与中文标签（第 1 / 6 节，不得改名）。
METRIC_CHOICES = (
    ("activation_rate", "激活率"),
    ("online_devices", "在线并发"),
    ("expiration_rate", "过期率"),
    ("expiring_soon", "7 天内到期"),
    ("failed_activations", "激活失败"),
    ("risk_events", "风控事件"),
    ("tamper_events", "完整性告警"),
)
METRIC_LABELS = dict(METRIC_CHOICES)
METRIC_UNITS = {
    "activation_rate": "%",
    "online_devices": " 台",
    "expiration_rate": "%",
    "expiring_soon": " 个",
}
METRIC_ACCENTS = {
    "activation_rate": theme.PRIMARY,
    "online_devices": theme.SUCCESS,
    "expiration_rate": theme.WARNING,
    "expiring_soon": theme.WARNING,
    "failed_activations": theme.DANGER,
    "risk_events": theme.FROZEN,
    "tamper_events": theme.DANGER,
}

OPERATOR_CHOICES = (
    ("gte", "≥"),
    ("gt", "＞"),
    ("lte", "≤"),
    ("lt", "＜"),
    ("eq", "="),
)
OPERATOR_SYMBOLS = dict(OPERATOR_CHOICES)

SEVERITY_CHOICES = (
    ("info", "提示"),
    ("warning", "警告"),
    ("critical", "严重"),
)
SEVERITY_LABELS = dict(SEVERITY_CHOICES)
SEVERITY_COLORS = {
    "info": theme.PRIMARY,
    "warning": theme.WARNING,
    "critical": theme.DANGER,
}

EVENT_STATUS_TEXT = {
    "firing": "触发中",
    "acked": "已确认",
    "resolved": "已处理",
}
EVENT_STATUS_COLORS = {
    "firing": theme.WARNING,
    "acked": theme.FROZEN,
    "resolved": theme.SUCCESS,
}
EVENT_FILTERS = (
    ("全部状态", ""),
    ("触发中", "firing"),
    ("已确认", "acked"),
    ("已处理", "resolved"),
)
EVENT_COLUMNS = ["时间", "规则", "指标", "当前值", "阈值", "级别", "状态", "已通知"]
RULE_COLUMNS = ["名称", "指标", "条件", "窗口", "级别", "冷却", "渠道", "状态"]

CHANNEL_CHOICES = (
    ("webhook", "Webhook"),
    ("dingtalk", "钉钉"),
    ("wecom", "企微"),
    ("feishu", "飞书"),
)
CHANNEL_KIND_LABELS = dict(CHANNEL_CHOICES)
CHANNEL_COLUMNS = ["名称", "类型", "地址", "启用", "状态"]

DELIVERY_STATUS_TEXT = {
    "pending": "待发送",
    "sending": "发送中",
    "sent": "已发送",
    "failed": "失败",
    "dead": "已终止",
}
DELIVERY_STATUS_COLORS = {
    "pending": theme.TEXT_MUTED,
    "sending": theme.FROZEN,
    "sent": theme.SUCCESS,
    "failed": theme.WARNING,
    "dead": theme.DANGER,
}
DELIVERY_FILTERS = (
    ("全部状态", ""),
    ("待发送", "pending"),
    ("发送中", "sending"),
    ("已发送", "sent"),
    ("失败", "failed"),
    ("已终止", "dead"),
)
DELIVERY_COLUMNS = ["时间", "渠道", "主题", "状态", "次数", "错误"]


def format_number(value) -> str:
    """Human-readable number; missing / non-finite values fall back to “—”."""
    if value is None or isinstance(value, bool):
        return "—" if value is None else str(int(value))
    try:
        number = float(value)
    except (TypeError, ValueError):
        return str(value)
    if not math.isfinite(number):
        return "—"
    if number.is_integer():
        return str(int(number))
    return f"{number:g}"


def duration_text(seconds) -> str:
    """Seconds as a compact duration (10 分钟 / 1 小时 / 45 秒)."""
    try:
        value = int(seconds)
    except (TypeError, ValueError):
        return "—"
    if value <= 0:
        return "—"
    if value % 3600 == 0:
        return f"{value // 3600} 小时"
    if value % 60 == 0:
        return f"{value // 60} 分钟"
    return f"{value} 秒"


def parse_channels(value) -> list[str]:
    """Accept the API list shape or the raw JSON column shape."""
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        try:
            value = json.loads(text)
        except (TypeError, ValueError):
            value = [text]
    if not isinstance(value, (list, tuple, set)):
        return []
    channels: list[str] = []
    for item in value:
        name = str(item or "").strip()
        if name and name not in channels:
            channels.append(name)
    return channels


def channels_text(value) -> str:
    channels = parse_channels(value)
    if not channels:
        return "—"
    names = {"email": "邮件"}
    return "、".join(names.get(channel, channel) for channel in channels)


def enabled_flag(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() not in ("", "0", "false", "no", "off")
    return bool(value)


def metric_label(metric: str) -> str:
    text = str(metric or "").strip()
    return METRIC_LABELS.get(text, text or "—")


def _colored_item(text: str, color: str, payload=None) -> QTableWidgetItem:
    item = QTableWidgetItem(f"● {text}")
    item.setForeground(QColor(color))
    font = item.font()
    font.setBold(True)
    item.setFont(font)
    if payload is not None:
        item.setData(Qt.UserRole, payload)
    return item


def severity_item(severity: str) -> QTableWidgetItem:
    name = str(severity or "").strip()
    return _colored_item(
        SEVERITY_LABELS.get(name, name or "—"),
        SEVERITY_COLORS.get(name, theme.TEXT_MUTED),
        name,
    )


def event_status_item(status: str) -> QTableWidgetItem:
    name = str(status or "").strip()
    return _colored_item(
        EVENT_STATUS_TEXT.get(name, name or "—"),
        EVENT_STATUS_COLORS.get(name, theme.TEXT_MUTED),
        name,
    )


def channel_kind_label(kind) -> str:
    name = str(kind or "").strip()
    return CHANNEL_KIND_LABELS.get(name, name or "—")


def delivery_status_item(status: str) -> QTableWidgetItem:
    name = str(status or "").strip()
    return _colored_item(
        DELIVERY_STATUS_TEXT.get(name, name or "—"),
        DELIVERY_STATUS_COLORS.get(name, theme.TEXT_MUTED),
        name,
    )


def delivery_channel_text(item: dict) -> str:
    """Channel name for one delivery row; tolerate several join shapes."""
    for key in ("channel_name", "channel", "name"):
        value = str(item.get(key) or "").strip()
        if value:
            return value
    kind = str(item.get("kind") or "").strip()
    if kind:
        return channel_kind_label(kind)
    channel_id = item.get("channel_id")
    return f"#{channel_id}" if channel_id not in (None, "") else "—"


class ChannelDialog(QDialog):
    """新建 / 编辑一个通知渠道，保存时调用第 6 节 create/update。"""

    def __init__(self, client, notify, channel: dict | None = None, parent=None):
        super().__init__(parent)
        self.client = client
        self.notify = notify
        self.channel = dict(channel) if isinstance(channel, dict) else None

        editing = self.channel is not None
        self.setWindowTitle("编辑通知渠道" if editing else "新建通知渠道")
        self.setMinimumWidth(460)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(14)
        layout.addWidget(
            PageHeader(
                "编辑通知渠道" if editing else "新建通知渠道",
                "告警事件按规则推送到 Webhook / 钉钉 / 企微 / 飞书",
            )
        )

        form = QFormLayout()
        form.setSpacing(12)

        self.kind = QComboBox()
        for value, label in CHANNEL_CHOICES:
            self.kind.addItem(label, value)

        self.name = QLineEdit()
        self.name.setMaxLength(64)
        self.name.setPlaceholderText("如：运维值班群")

        self.url = QLineEdit()
        self.url.setMaxLength(512)
        self.url.setPlaceholderText("https://…")

        self.secret = QLineEdit()
        self.secret.setEchoMode(QLineEdit.Password)
        self.secret.setMaxLength(256)
        self.secret.setPlaceholderText(
            "留空表示不修改密钥" if editing else "选填，签名或加签密钥"
        )

        self.enabled = QCheckBox("启用该渠道")
        self.enabled.setChecked(True)

        form.addRow("类型", self.kind)
        form.addRow("名称", self.name)
        form.addRow("地址", self.url)
        form.addRow("密钥", self.secret)
        form.addRow("", self.enabled)
        layout.addLayout(form)

        actions = QHBoxLayout()
        actions.addStretch(1)
        actions.addWidget(make_button("取消", "ghost", self.reject))
        actions.addWidget(
            make_button("保存" if editing else "创建", "primary", self.submit)
        )
        layout.addLayout(actions)

        if self.channel is not None:
            self._load(self.channel)

    # ------------------------------------------------------------ prefill
    def _load(self, channel: dict) -> None:
        index = self.kind.findData(str(channel.get("kind") or ""))
        if index >= 0:
            self.kind.setCurrentIndex(index)
        self.name.setText(str(channel.get("name") or ""))
        self.url.setText(str(channel.get("url") or ""))
        # list_channels never returns the plaintext secret; leaving the
        # field empty is what keeps the stored value on update.
        self.secret.clear()
        self.enabled.setChecked(enabled_flag(channel.get("enabled", 1)))

    # ------------------------------------------------------------ payload
    def payload(self) -> dict:
        fields = {
            "kind": self.kind.currentData(),
            "name": self.name.text().strip(),
            "url": self.url.text().strip(),
            "enabled": bool(self.enabled.isChecked()),
        }
        secret = self.secret.text()
        # 新建时总是提交 secret（可为空）；编辑时留空表示不修改。
        if self.channel is None or secret:
            fields["secret"] = secret
        return fields

    def submit(self) -> None:
        fields = self.payload()
        if not fields["name"]:
            self.notify("请填写渠道名称", "warning")
            self.name.setFocus()
            return
        if not fields["url"]:
            self.notify("请填写渠道地址", "warning")
            self.url.setFocus()
            return
        if not fields["url"].lower().startswith(("http://", "https://")):
            self.notify("渠道地址必须以 http:// 或 https:// 开头", "warning")
            self.url.setFocus()
            return
        try:
            if self.channel is None:
                self.client.create_channel(**fields)
                self.notify("通知渠道已创建", "success")
            else:
                self.client.update_channel(self.channel.get("id"), **fields)
                self.notify("通知渠道已更新", "success")
        except (ApiError, AttributeError) as exc:
            self.notify(str(exc), "error")
            return
        self.accept()


class AlertRuleDialog(QDialog):
    """新建 / 编辑一条告警规则，保存时调用第 6 节 create/update。"""

    def __init__(self, client, notify, rule: dict | None = None, parent=None):
        super().__init__(parent)
        self.client = client
        self.notify = notify
        self.rule = dict(rule) if isinstance(rule, dict) else None

        editing = self.rule is not None
        self.setWindowTitle("编辑告警规则" if editing else "新建告警规则")
        self.setMinimumWidth(460)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(14)
        layout.addWidget(
            PageHeader(
                "编辑告警规则" if editing else "新建告警规则",
                "指标超过阈值时触发告警，冷却期内不重复通知",
            )
        )

        form = QFormLayout()
        form.setSpacing(12)
        self.name = QLineEdit()
        self.name.setMaxLength(64)
        self.name.setPlaceholderText("如：激活率过低")

        self.metric = QComboBox()
        for value, label in METRIC_CHOICES:
            self.metric.addItem(label, value)

        self.operator = QComboBox()
        for value, symbol in OPERATOR_CHOICES:
            self.operator.addItem(symbol, value)
        self.operator.setCurrentIndex(0)

        self.threshold = QDoubleSpinBox()
        self.threshold.setRange(-1000000000.0, 1000000000.0)
        self.threshold.setDecimals(2)
        self.threshold.setSingleStep(1.0)
        self.threshold.setValue(0.0)

        self.window_seconds = QSpinBox()
        self.window_seconds.setRange(60, 86400)
        self.window_seconds.setValue(600)
        self.window_seconds.setSuffix(" 秒")

        self.severity = QComboBox()
        for value, label in SEVERITY_CHOICES:
            self.severity.addItem(label, value)
        self.severity.setCurrentIndex(1)

        self.cooldown_seconds = QSpinBox()
        self.cooldown_seconds.setRange(60, 86400)
        self.cooldown_seconds.setValue(3600)
        self.cooldown_seconds.setSuffix(" 秒")

        # 渠道区：邮件 + 每个启用渠道一个复选框，值 ``channel:<id>``。
        self.channels = QCheckBox("邮件")
        self.channels.setChecked(True)
        self.channel_boxes: dict[str, QCheckBox] = {"email": self.channels}
        self.channel_hint = QLabel("")
        self.channel_hint.setObjectName("Muted")
        self.channel_hint.setWordWrap(True)
        self.channel_hint.setVisible(False)
        self._channels_loaded = False
        self._preserved_channels: list[str] = []

        channel_box = QWidget()
        channel_layout = QVBoxLayout(channel_box)
        channel_layout.setContentsMargins(0, 0, 0, 0)
        channel_layout.setSpacing(6)
        channel_layout.addWidget(self.channels)
        self._channel_layout = channel_layout
        channel_layout.addWidget(self.channel_hint)
        self._load_channels()

        self.note = QLineEdit()
        self.note.setMaxLength(200)
        self.note.setPlaceholderText("选填，最多 200 字")

        self.enabled = QCheckBox("启用该规则")
        self.enabled.setChecked(True)

        form.addRow("名称", self.name)
        form.addRow("指标", self.metric)
        form.addRow("运算符", self.operator)
        form.addRow("阈值", self.threshold)
        form.addRow("窗口秒", self.window_seconds)
        form.addRow("级别", self.severity)
        form.addRow("冷却秒", self.cooldown_seconds)
        form.addRow("渠道", channel_box)
        form.addRow("备注", self.note)
        form.addRow("", self.enabled)
        layout.addLayout(form)

        actions = QHBoxLayout()
        actions.addStretch(1)
        actions.addWidget(make_button("取消", "ghost", self.reject))
        actions.addWidget(
            make_button("保存" if editing else "创建", "primary", self.submit)
        )
        layout.addLayout(actions)

        if self.rule is not None:
            self._load(self.rule)

    # ------------------------------------------------------------ prefill
    @staticmethod
    def _select_data(combo: QComboBox, value, fallback: int = 0) -> None:
        index = combo.findData(str(value)) if value is not None else -1
        if index < 0:
            index = min(max(fallback, 0), max(combo.count() - 1, 0))
        combo.setCurrentIndex(index)

    @staticmethod
    def _clamp(value, low: int, high: int, fallback: int) -> int:
        try:
            number = int(value)
        except (TypeError, ValueError):
            return fallback
        return max(low, min(high, number))

    def _load(self, rule: dict) -> None:
        self.name.setText(str(rule.get("name") or ""))
        self._select_data(self.metric, rule.get("metric"), 0)
        self._select_data(self.operator, rule.get("operator"), 0)
        try:
            self.threshold.setValue(float(rule.get("threshold") or 0.0))
        except (TypeError, ValueError):
            self.threshold.setValue(0.0)
        self.window_seconds.setValue(
            self._clamp(rule.get("window_seconds"), 60, 86400, 600)
        )
        self._select_data(self.severity, rule.get("severity"), 1)
        self.cooldown_seconds.setValue(
            self._clamp(rule.get("cooldown_seconds"), 60, 86400, 3600)
        )
        raw_channels = rule.get("channels")
        if raw_channels is None:
            raw_channels = rule.get("channels_json")
        values = parse_channels(raw_channels)
        self.channels.setChecked("email" in values)
        for value, box in self.channel_boxes.items():
            if value != "email":
                box.setChecked(value in values)
        hidden = [
            value
            for value in values
            if value != "email" and value not in self.channel_boxes
        ]
        if hidden:
            if self._channels_loaded:
                # 停用/已删除的渠道不再列出；保留会让后端以“渠道不存在”
                # 为由拒绝整个请求，所以保存时移除并提示。
                self.channel_hint.setText(
                    "规则引用了已停用或已删除的渠道，保存时将从规则中移除"
                )
                self.channel_hint.setVisible(True)
            else:
                # 列表不可用时无法判断渠道是否仍存在，保留原值避免误删。
                self._preserved_channels = hidden
        self.note.setText(str(rule.get("note") or ""))
        self.enabled.setChecked(enabled_flag(rule.get("enabled", 1)))

    def _load_channels(self) -> None:
        """Append one checkbox per enabled channel (contract section 7)."""
        try:
            data = self.client.list_channels()
        except (ApiError, AttributeError) as exc:
            self.channel_hint.setText(f"渠道列表暂不可用：{exc}")
            self.channel_hint.setVisible(True)
            return
        self._channels_loaded = True
        items = data.get("items") if isinstance(data, dict) else None
        for item in items or []:
            if not isinstance(item, dict) or not enabled_flag(item.get("enabled", 1)):
                continue
            channel_id = item.get("id")
            if channel_id in (None, ""):
                continue
            try:
                value = f"channel:{int(channel_id)}"
            except (TypeError, ValueError):
                value = f"channel:{str(channel_id).strip()}"
            if value in self.channel_boxes:
                continue
            name = str(item.get("name") or "").strip() or value
            box = QCheckBox(f"{name}（{channel_kind_label(item.get('kind'))}）")
            box.setToolTip(str(item.get("url") or ""))
            self.channel_boxes[value] = box
            # Keep the hint label last so new boxes go above it.
            self._channel_layout.insertWidget(self._channel_layout.count() - 1, box)

    # ------------------------------------------------------------ payload
    def payload(self) -> dict:
        return {
            "name": self.name.text().strip(),
            "metric": self.metric.currentData(),
            "operator": self.operator.currentData(),
            "threshold": float(self.threshold.value()),
            "window_seconds": int(self.window_seconds.value()),
            "severity": self.severity.currentData(),
            "cooldown_seconds": int(self.cooldown_seconds.value()),
            "channels": self._selected_channels(),
            "enabled": bool(self.enabled.isChecked()),
            "note": self.note.text().strip(),
        }

    def _selected_channels(self) -> list[str]:
        channels: list[str] = []
        if self.channels.isChecked():
            channels.append("email")
        for value, box in self.channel_boxes.items():
            if value != "email" and box.isChecked() and value not in channels:
                channels.append(value)
        for value in self._preserved_channels:
            if value not in channels:
                channels.append(value)
        return channels

    def submit(self) -> None:
        fields = self.payload()
        if not fields["name"]:
            self.notify("请填写规则名称", "warning")
            self.name.setFocus()
            return
        if not fields["channels"]:
            self.notify("请至少选择一个通知渠道", "warning")
            return
        try:
            if self.rule is None:
                self.client.create_alert_rule(**fields)
                self.notify("告警规则已创建", "success")
            else:
                self.client.update_alert_rule(self.rule.get("id"), **fields)
                self.notify("告警规则已更新", "success")
        except (ApiError, AttributeError) as exc:
            self.notify(str(exc), "error")
            return
        self.accept()


class AlertCenterPage(BasePage):
    """Alert center (rules / events / notification channels) for both clients."""

    EVENT_PAGE_SIZE = 200
    DELIVERY_PAGE_SIZE = 200
    REFRESH_INTERVAL_MS = 15000
    METRICS_WINDOW_SECONDS = 600

    def __init__(self, client, notify):
        super().__init__(client, notify)
        self.rules: list[dict] = []
        self.events: list[dict] = []
        self.events_total = 0
        self.channels: list[dict] = []
        self.deliveries: list[dict] = []
        self.deliveries_total = 0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        header = QHBoxLayout()
        header.addWidget(PageHeader("告警中心", "配置告警规则并跟踪触发事件"))
        header.addStretch(1)
        header.addWidget(make_button("刷新全部", "ghost", self.refresh))
        layout.addLayout(header)

        self.cards: dict[str, StatCard] = {}
        for metric, label in METRIC_CHOICES:
            self.cards[metric] = StatCard(
                label, "—", METRIC_ACCENTS.get(metric, theme.PRIMARY)
            )
        layout.addWidget(StatGrid(self.cards.values(), columns=4, min_card_width=150))

        self.tabs = QTabWidget()
        self.rules_tab = QWidget()
        self.events_tab = QWidget()
        self.channels_tab = QWidget()
        self.tabs.addTab(self.rules_tab, "告警规则")
        self.tabs.addTab(self.events_tab, "告警事件")
        self.tabs.addTab(self.channels_tab, "通知渠道")
        layout.addWidget(self.tabs, 1)

        self._build_rules_tab()
        self._build_events_tab()
        self._build_channels_tab()

        # The timer is a member of the page, so it is destroyed together with
        # the window; it is also stopped whenever the page is hidden.
        self.events_timer = QTimer(self)
        self.events_timer.setInterval(self.REFRESH_INTERVAL_MS)
        self.events_timer.timeout.connect(self._auto_refresh)

    # ------------------------------------------------------------ tabs
    def _build_rules_tab(self) -> None:
        layout = QVBoxLayout(self.rules_tab)
        layout.setContentsMargins(0, 6, 0, 0)
        card = Card(padding=16)

        bar = QHBoxLayout()
        bar.addWidget(make_button("新建", "primary", self.create_rule))
        bar.addWidget(make_button("编辑", "default", self.edit_rule))
        bar.addWidget(make_button("启用/停用", "default", self.toggle_rule))
        bar.addWidget(make_button("删除", "danger", self.delete_rule))
        bar.addStretch(1)
        self.rules_count_label = QLabel("共 0 条")
        self.rules_count_label.setObjectName("Muted")
        bar.addWidget(self.rules_count_label)
        bar.addWidget(make_button("刷新", "ghost", self.refresh_rules))
        card.body.addLayout(bar)

        self.rules_table = QTableWidget(0, len(RULE_COLUMNS))
        self.rules_table.setHorizontalHeaderLabels(RULE_COLUMNS)
        prepare_table(self.rules_table)
        self.rules_table.verticalHeader().setVisible(False)
        self.rules_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.rules_table.setSelectionMode(QTableWidget.SingleSelection)
        header_view = self.rules_table.horizontalHeader()
        header_view.setSectionResizeMode(0, QHeaderView.Stretch)
        for column in range(1, len(RULE_COLUMNS)):
            header_view.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        card.body.addWidget(self.rules_table, 1)
        layout.addWidget(card)

    def _build_events_tab(self) -> None:
        layout = QVBoxLayout(self.events_tab)
        layout.setContentsMargins(0, 6, 0, 0)
        card = Card(padding=16)

        bar = QHBoxLayout()
        self.event_status = QComboBox()
        for label, value in EVENT_FILTERS:
            self.event_status.addItem(label, value)
        self.event_status.setMinimumWidth(120)
        bar.addWidget(self.event_status)
        bar.addWidget(make_button("确认", "default", self.ack_event))
        bar.addWidget(make_button("标记已处理", "default", self.resolve_event))
        bar.addStretch(1)
        self.events_count_label = QLabel("共 0 条")
        self.events_count_label.setObjectName("Muted")
        bar.addWidget(self.events_count_label)
        bar.addWidget(make_button("刷新", "ghost", self.refresh_events))
        card.body.addLayout(bar)

        self.events_table = QTableWidget(0, len(EVENT_COLUMNS))
        self.events_table.setHorizontalHeaderLabels(EVENT_COLUMNS)
        prepare_table(self.events_table)
        self.events_table.verticalHeader().setVisible(False)
        self.events_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.events_table.setSelectionMode(QTableWidget.SingleSelection)
        header_view = self.events_table.horizontalHeader()
        header_view.setSectionResizeMode(1, QHeaderView.Stretch)
        for column in (0, 2, 3, 4, 5, 6, 7):
            header_view.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        card.body.addWidget(self.events_table, 1)
        layout.addWidget(card)

        self.event_status.currentIndexChanged.connect(
            lambda _index: self.refresh_events()
        )

    def _build_channels_tab(self) -> None:
        layout = QVBoxLayout(self.channels_tab)
        layout.setContentsMargins(0, 6, 0, 0)
        layout.setSpacing(12)

        channels_card = Card(padding=16)
        bar = QHBoxLayout()
        bar.addWidget(make_button("新建", "primary", self.create_channel))
        bar.addWidget(make_button("编辑", "default", self.edit_channel))
        bar.addWidget(make_button("删除", "danger", self.delete_channel))
        bar.addWidget(make_button("测试", "default", self.test_channel))
        bar.addStretch(1)
        self.channels_count_label = QLabel("共 0 条")
        self.channels_count_label.setObjectName("Muted")
        bar.addWidget(self.channels_count_label)
        bar.addWidget(make_button("刷新", "ghost", self.refresh_channels))
        channels_card.body.addLayout(bar)

        self.channels_table = QTableWidget(0, len(CHANNEL_COLUMNS))
        self.channels_table.setHorizontalHeaderLabels(CHANNEL_COLUMNS)
        prepare_table(self.channels_table)
        self.channels_table.verticalHeader().setVisible(False)
        self.channels_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.channels_table.setSelectionMode(QTableWidget.SingleSelection)
        header_view = self.channels_table.horizontalHeader()
        header_view.setSectionResizeMode(0, QHeaderView.Stretch)
        for column in range(1, len(CHANNEL_COLUMNS)):
            header_view.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        channels_card.body.addWidget(self.channels_table, 1)
        layout.addWidget(channels_card, 1)

        deliveries_card = Card(padding=16)
        deliveries_bar = QHBoxLayout()
        deliveries_title = QLabel("投递记录")
        deliveries_title.setObjectName("SectionTitle")
        deliveries_bar.addWidget(deliveries_title)
        deliveries_bar.addSpacing(10)
        self.delivery_status = QComboBox()
        for label, value in DELIVERY_FILTERS:
            self.delivery_status.addItem(label, value)
        self.delivery_status.setMinimumWidth(120)
        deliveries_bar.addWidget(self.delivery_status)
        deliveries_bar.addStretch(1)
        self.deliveries_count_label = QLabel("共 0 条")
        self.deliveries_count_label.setObjectName("Muted")
        deliveries_bar.addWidget(self.deliveries_count_label)
        deliveries_bar.addWidget(
            make_button("刷新", "ghost", self.refresh_deliveries)
        )
        deliveries_card.body.addLayout(deliveries_bar)

        self.deliveries_table = QTableWidget(0, len(DELIVERY_COLUMNS))
        self.deliveries_table.setHorizontalHeaderLabels(DELIVERY_COLUMNS)
        prepare_table(self.deliveries_table)
        self.deliveries_table.verticalHeader().setVisible(False)
        self.deliveries_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.deliveries_table.setSelectionMode(QTableWidget.SingleSelection)
        header_view = self.deliveries_table.horizontalHeader()
        header_view.setSectionResizeMode(5, QHeaderView.Stretch)
        for column in (0, 1, 2, 3, 4):
            header_view.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        deliveries_card.body.addWidget(self.deliveries_table, 1)
        layout.addWidget(deliveries_card, 1)

        self.delivery_status.currentIndexChanged.connect(
            lambda _index: self.refresh_deliveries()
        )

    # ------------------------------------------------------------ metrics
    @staticmethod
    def metric_value_text(metric: str, value) -> str:
        if value is None:
            return "—"
        text = format_number(value)
        if text == "—":
            return text
        return f"{text}{METRIC_UNITS.get(metric, '')}"

    def _set_metrics(self, data) -> None:
        source = data if isinstance(data, dict) else {}
        for metric, card in self.cards.items():
            card.set_value(self.metric_value_text(metric, source.get(metric)))

    def refresh_metrics(self, silent: bool = False) -> None:
        if not silent:
            QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            data = self.client.metrics_overview(
                window_seconds=self.METRICS_WINDOW_SECONDS
            )
        except (ApiError, AttributeError) as exc:
            self._set_metrics(None)
            if not silent:
                self.notify(str(exc), "error")
            return
        finally:
            if not silent:
                QApplication.restoreOverrideCursor()
        self._set_metrics(data)

    # ------------------------------------------------------------ rules
    def refresh_rules(self, silent: bool = False) -> None:
        if not silent:
            QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            data = self.client.alert_rules()
        except (ApiError, AttributeError) as exc:
            if not silent:
                self.notify(str(exc), "error")
            return
        finally:
            if not silent:
                QApplication.restoreOverrideCursor()
        items = data.get("items") if isinstance(data, dict) else None
        self.rules = [item for item in (items or []) if isinstance(item, dict)]
        self._fill_rules()

    def _fill_rules(self) -> None:
        rows = []
        for rule in self.rules:
            operator = str(rule.get("operator") or "").strip()
            raw_channels = rule.get("channels")
            if raw_channels is None:
                raw_channels = rule.get("channels_json")
            rows.append(
                [
                    str(rule.get("name") or "—"),
                    metric_label(rule.get("metric")),
                    f"{OPERATOR_SYMBOLS.get(operator, operator or '—')} "
                    f"{format_number(rule.get('threshold'))}",
                    duration_text(rule.get("window_seconds")),
                    SEVERITY_LABELS.get(
                        str(rule.get("severity") or ""), str(rule.get("severity") or "—")
                    ),
                    duration_text(rule.get("cooldown_seconds")),
                    channels_text(raw_channels),
                    "启用" if enabled_flag(rule.get("enabled", 1)) else "停用",
                ]
            )
        fill_table(self.rules_table, rows)
        for row, rule in enumerate(self.rules):
            name_item = self.rules_table.item(row, 0)
            if name_item is not None:
                name_item.setData(Qt.UserRole, rule.get("id"))
                note = str(rule.get("note") or "")
                if note:
                    name_item.setToolTip(note)
            self.rules_table.setItem(row, 4, severity_item(rule.get("severity")))
            enabled = enabled_flag(rule.get("enabled", 1))
            self.rules_table.setItem(
                row,
                7,
                _colored_item(
                    "启用" if enabled else "停用",
                    theme.SUCCESS if enabled else theme.TEXT_MUTED,
                    "enabled" if enabled else "disabled",
                ),
            )
        self.rules_count_label.setText(f"共 {len(self.rules)} 条")

    def _selected_rule(self) -> dict | None:
        rows = selected_rows(self.rules_table)
        if not rows:
            self.notify("请先选择一条告警规则", "warning")
            return None
        row = rows[0]
        if row < 0 or row >= len(self.rules):
            return None
        return self.rules[row]

    def create_rule(self) -> None:
        dialog = AlertRuleDialog(self.client, self.notify, parent=self)
        if dialog.exec() == QDialog.Accepted:
            self.refresh_rules()

    def edit_rule(self) -> None:
        rule = self._selected_rule()
        if rule is None:
            return
        dialog = AlertRuleDialog(self.client, self.notify, rule, self)
        if dialog.exec() == QDialog.Accepted:
            self.refresh_rules()

    def toggle_rule(self) -> None:
        rule = self._selected_rule()
        if rule is None:
            return
        enabled = not enabled_flag(rule.get("enabled", 1))
        try:
            self.client.update_alert_rule(rule.get("id"), enabled=enabled)
        except (ApiError, AttributeError) as exc:
            self.notify(str(exc), "error")
            return
        self.notify("规则已启用" if enabled else "规则已停用", "success")
        self.refresh_rules()

    def delete_rule(self) -> None:
        rule = self._selected_rule()
        if rule is None:
            return
        name = str(rule.get("name") or "")
        if not confirm(self, "删除告警规则", f"确定删除规则“{name}”？"):
            return
        try:
            self.client.delete_alert_rule(rule.get("id"))
        except (ApiError, AttributeError) as exc:
            # A 403 from the server is surfaced verbatim; the page makes no
            # assumption about which role is allowed to delete.
            self.notify(str(exc), "error")
            return
        self.notify("告警规则已删除", "success")
        self.refresh_rules()

    # ------------------------------------------------------------ events
    def refresh_events(self, silent: bool = False) -> None:
        status = self.event_status.currentData() or ""
        if not silent:
            QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            data = self.client.alert_events(
                status=status, limit=self.EVENT_PAGE_SIZE, offset=0
            )
        except (ApiError, AttributeError) as exc:
            if not silent:
                self.notify(str(exc), "error")
            return
        finally:
            if not silent:
                QApplication.restoreOverrideCursor()
        items = data.get("items") if isinstance(data, dict) else None
        self.events = [item for item in (items or []) if isinstance(item, dict)]
        try:
            raw_total = data.get("total") if isinstance(data, dict) else None
            self.events_total = int(raw_total or len(self.events))
        except (TypeError, ValueError):
            self.events_total = len(self.events)
        self._fill_events()

    def _fill_events(self) -> None:
        rows = []
        for event in self.events:
            rule_name = str(event.get("rule_name") or "").strip()
            if not rule_name:
                rule_id = event.get("rule_id")
                rule_name = f"#{rule_id}" if rule_id not in (None, "") else "—"
            rows.append(
                [
                    str(event.get("fired_at") or "—"),
                    rule_name,
                    metric_label(event.get("metric")),
                    format_number(event.get("value")),
                    format_number(event.get("threshold")),
                    SEVERITY_LABELS.get(
                        str(event.get("severity") or ""),
                        str(event.get("severity") or "—"),
                    ),
                    EVENT_STATUS_TEXT.get(
                        str(event.get("status") or ""),
                        str(event.get("status") or "—"),
                    ),
                    "是" if enabled_flag(event.get("notified")) else "否",
                ]
            )
        fill_table(self.events_table, rows)
        for row, event in enumerate(self.events):
            time_item = self.events_table.item(row, 0)
            if time_item is not None:
                time_item.setData(Qt.UserRole, event.get("id"))
            self.events_table.setItem(row, 5, severity_item(event.get("severity")))
            self.events_table.setItem(row, 6, event_status_item(event.get("status")))
        loaded = len(self.events)
        if self.events_total > loaded:
            self.events_count_label.setText(f"显示 {loaded} / 共 {self.events_total} 条")
        else:
            self.events_count_label.setText(f"共 {loaded} 条")

    def _selected_event(self) -> dict | None:
        rows = selected_rows(self.events_table)
        if not rows:
            self.notify("请先选择一条告警事件", "warning")
            return None
        row = rows[0]
        if row < 0 or row >= len(self.events):
            return None
        return self.events[row]

    def ack_event(self) -> None:
        event = self._selected_event()
        if event is None:
            return
        try:
            self.client.ack_alert_event(event.get("id"))
        except (ApiError, AttributeError) as exc:
            self.notify(str(exc), "error")
            return
        self.notify("告警事件已确认", "success")
        self.refresh_events()

    def resolve_event(self) -> None:
        event = self._selected_event()
        if event is None:
            return
        try:
            self.client.resolve_alert_event(event.get("id"))
        except (ApiError, AttributeError) as exc:
            self.notify(str(exc), "error")
            return
        self.notify("告警事件已标记为已处理", "success")
        self.refresh_events()

    # ------------------------------------------------------------ channels
    def refresh_channels(self, silent: bool = False) -> None:
        if not silent:
            QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            data = self.client.list_channels()
        except (ApiError, AttributeError) as exc:
            self.channels = []
            self._fill_channels()
            self.channels_count_label.setText("渠道接口不可用")
            self.channels_count_label.setToolTip(str(exc))
            if not silent:
                self.notify(str(exc), "error")
            return
        finally:
            if not silent:
                QApplication.restoreOverrideCursor()
        items = data.get("items") if isinstance(data, dict) else None
        self.channels = [item for item in (items or []) if isinstance(item, dict)]
        self._fill_channels()
        self.channels_count_label.setToolTip("")

    def _fill_channels(self) -> None:
        rows = []
        for channel in self.channels:
            kind = str(channel.get("kind") or "").strip()
            enabled = enabled_flag(channel.get("enabled", 1))
            rows.append(
                [
                    str(channel.get("name") or "—"),
                    channel_kind_label(kind),
                    str(channel.get("url") or "—"),
                    "启用" if enabled else "停用",
                    "密钥已配置"
                    if enabled_flag(channel.get("secret_set"))
                    else "未配置密钥",
                ]
            )
        fill_table(self.channels_table, rows)
        for row, channel in enumerate(self.channels):
            name_item = self.channels_table.item(row, 0)
            if name_item is not None:
                name_item.setData(Qt.UserRole, channel.get("id"))
                url = str(channel.get("url") or "")
                if url:
                    name_item.setToolTip(url)
            enabled = enabled_flag(channel.get("enabled", 1))
            self.channels_table.setItem(
                row,
                3,
                _colored_item(
                    "启用" if enabled else "停用",
                    theme.SUCCESS if enabled else theme.TEXT_MUTED,
                    "enabled" if enabled else "disabled",
                ),
            )
        self.channels_count_label.setText(f"共 {len(self.channels)} 条")

    def _selected_channel(self) -> dict | None:
        rows = selected_rows(self.channels_table)
        if not rows:
            self.notify("请先选择一个通知渠道", "warning")
            return None
        row = rows[0]
        if row < 0 or row >= len(self.channels):
            return None
        return self.channels[row]

    def create_channel(self) -> None:
        dialog = ChannelDialog(self.client, self.notify, parent=self)
        if dialog.exec() == QDialog.Accepted:
            self.refresh_channels()

    def edit_channel(self) -> None:
        channel = self._selected_channel()
        if channel is None:
            return
        dialog = ChannelDialog(self.client, self.notify, channel, self)
        if dialog.exec() == QDialog.Accepted:
            self.refresh_channels()

    def delete_channel(self) -> None:
        channel = self._selected_channel()
        if channel is None:
            return
        name = str(channel.get("name") or "")
        if not confirm(self, "删除通知渠道", f"确定删除渠道“{name}”？"):
            return
        try:
            self.client.delete_channel(channel.get("id"))
        except (ApiError, AttributeError) as exc:
            self.notify(str(exc), "error")
            return
        self.notify("通知渠道已删除", "success")
        self.refresh_channels()

    def test_channel(self) -> None:
        channel = self._selected_channel()
        if channel is None:
            return
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            self.client.test_channel(channel.get("id"))
        except (ApiError, AttributeError) as exc:
            self.notify(str(exc), "error")
            return
        finally:
            QApplication.restoreOverrideCursor()
        self.notify("测试消息已发送", "success")

    def refresh_deliveries(self, silent: bool = False) -> None:
        status = self.delivery_status.currentData() or ""
        if not silent:
            QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            data = self.client.channel_deliveries(
                status=status, limit=self.DELIVERY_PAGE_SIZE, offset=0
            )
        except (ApiError, AttributeError) as exc:
            self.deliveries = []
            self.deliveries_total = 0
            self._fill_deliveries()
            self.deliveries_count_label.setText("投递记录接口不可用")
            self.deliveries_count_label.setToolTip(str(exc))
            if not silent:
                self.notify(str(exc), "error")
            return
        finally:
            if not silent:
                QApplication.restoreOverrideCursor()
        items = data.get("items") if isinstance(data, dict) else None
        self.deliveries = [item for item in (items or []) if isinstance(item, dict)]
        try:
            raw_total = data.get("total") if isinstance(data, dict) else None
            self.deliveries_total = int(raw_total or len(self.deliveries))
        except (TypeError, ValueError):
            self.deliveries_total = len(self.deliveries)
        self._fill_deliveries()
        self.deliveries_count_label.setToolTip("")

    def _fill_deliveries(self) -> None:
        rows = []
        for item in self.deliveries:
            status = str(item.get("status") or "").strip()
            rows.append(
                [
                    str(item.get("created_at") or "—"),
                    delivery_channel_text(item),
                    str(item.get("subject") or "—"),
                    DELIVERY_STATUS_TEXT.get(status, status or "—"),
                    format_number(item.get("attempts")),
                    str(item.get("last_error") or item.get("error") or "—"),
                ]
            )
        fill_table(self.deliveries_table, rows)
        for row, item in enumerate(self.deliveries):
            time_item = self.deliveries_table.item(row, 0)
            if time_item is not None:
                time_item.setData(Qt.UserRole, item.get("id"))
            self.deliveries_table.setItem(
                row, 3, delivery_status_item(item.get("status"))
            )
        loaded = len(self.deliveries)
        if self.deliveries_total > loaded:
            self.deliveries_count_label.setText(
                f"显示 {loaded} / 共 {self.deliveries_total} 条"
            )
        else:
            self.deliveries_count_label.setText(f"共 {loaded} 条")

    # ------------------------------------------------------------ lifecycle
    def refresh(self) -> None:
        self.refresh_metrics()
        self.refresh_rules()
        self.refresh_events()
        self.refresh_channels()
        self.refresh_deliveries()

    def _auto_refresh(self) -> None:
        try:
            if not self.isVisible():
                return
            self.refresh_events(silent=True)
        except RuntimeError:
            # The C++ widget was destroyed while the timer was pending.
            try:
                self.events_timer.stop()
            except RuntimeError:
                pass

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if not self.events_timer.isActive():
            self.events_timer.start()

    def hideEvent(self, event) -> None:
        self.events_timer.stop()
        super().hideEvent(event)

    def on_show(self) -> None:
        self.refresh()
