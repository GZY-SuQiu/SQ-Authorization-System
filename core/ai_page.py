"""AI assistant page for the management clients.

The page deliberately treats the gateway as a black box: it sends a bounded
conversation history to ``/api/ai/chat`` and accepts the common response
shapes used by OpenAI-compatible gateways.  Work happens on the global Qt
thread pool so a slow model never freezes the rest of the desktop client.
"""

from __future__ import annotations

import threading
from typing import Any

from PySide6.QtCore import QEvent, QObject, QRunnable, QThreadPool, QTimer, Qt, Signal
from PySide6.QtWidgets import (
    QGridLayout,
    QHeaderView,
    QTableWidget,
    QTableWidgetItem,
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from . import theme
from .api_client import ApiError
from .pages import BasePage
from .widgets import (
    Card,
    PageHeader,
    StatusBadge,
    confirm,
    make_button,
)


class ChatInput(QPlainTextEdit):
    """Multiline input where Enter submits and Shift+Enter adds a newline."""

    submitted = Signal()

    def keyPressEvent(self, event) -> None:
        if event.key() in (Qt.Key_Return, Qt.Key_Enter) and not (
            event.modifiers() & (Qt.ShiftModifier | Qt.ControlModifier | Qt.AltModifier)
        ):
            self.submitted.emit()
            event.accept()
            return
        super().keyPressEvent(event)


class _ChatSignals(QObject):
    finished = Signal(int, dict)
    failed = Signal(int, str)
    event = Signal(int, dict)


class _ChatTask(QRunnable):
    def __init__(
        self,
        request_id: int,
        client,
        messages: list[dict],
        signals: _ChatSignals,
        cancel_event=None,
    ):
        super().__init__()
        self.setAutoDelete(True)
        self.request_id = request_id
        self.client = client
        self.messages = messages
        self.signals = signals
        self.cancel_event = cancel_event

    def run(self) -> None:
        def forward(event: object) -> None:
            """Hop from the worker thread onto the UI thread via Qt signals."""
            if isinstance(event, dict):
                self.signals.event.emit(self.request_id, dict(event))

        chat = self.client.ai_chat
        try:
            try:
                data = chat(
                    self.messages, on_event=forward, cancel_event=self.cancel_event
                )
            except TypeError as exc:
                # Older clients expose fewer keyword arguments; degrade in
                # steps instead of failing the whole turn.
                message = str(exc)
                if "cancel_event" in message:
                    try:
                        data = chat(self.messages, on_event=forward)
                    except TypeError as inner:
                        if "on_event" not in str(inner):
                            raise
                        data = chat(self.messages)
                elif "on_event" in message:
                    data = chat(self.messages)
                else:
                    raise
        except Exception as exc:  # pragma: no cover - exercised through the page
            self.signals.failed.emit(
                self.request_id, str(exc) or exc.__class__.__name__
            )
            return
        if not isinstance(data, dict):
            self.signals.failed.emit(self.request_id, "AI 服务返回的数据格式无效")
            return
        self.signals.finished.emit(self.request_id, data)


class _ConfirmationSignals(QObject):
    finished = Signal(str, dict)
    failed = Signal(str, str)


class _ConfirmationTask(QRunnable):
    """Runs one ``ai_confirm`` / ``ai_cancel`` call off the UI thread."""

    def __init__(self, mode: str, client, token: str, signals: _ConfirmationSignals):
        super().__init__()
        self.setAutoDelete(True)
        self.mode = "cancel" if mode == "cancel" else "confirm"
        self.client = client
        self.token = token
        self.signals = signals

    def run(self) -> None:
        try:
            name = "ai_cancel" if self.mode == "cancel" else "ai_confirm"
            method = getattr(self.client, name, None)
            if not callable(method):
                raise RuntimeError("当前客户端不支持待确认操作")
            data = method(self.token)
        except Exception as exc:
            self.signals.failed.emit(self.mode, str(exc) or exc.__class__.__name__)
            return
        if not isinstance(data, dict):
            self.signals.failed.emit(self.mode, "服务器返回的数据格式无效")
            return
        self.signals.finished.emit(self.mode, data)


def _local_ai_defaults() -> dict:
    """Read display defaults without creating or exposing a server config."""
    try:
        from .config import AI_DEFAULT_CONFIG
    except Exception:  # pragma: no cover - defensive for partial installs
        return {}
    return AI_DEFAULT_CONFIG if isinstance(AI_DEFAULT_CONFIG, dict) else {}


class AIAssistantPage(BasePage):
    """Conversation page shared by the admin and master clients."""

    MAX_HISTORY_MESSAGES = 40
    # Keep the live reasoning pane light; only the tail is ever shown.
    LIVE_REASONING_LIMIT = 6000
    # Finished bubbles keep a bounded trace so a huge answer cannot stall
    # the word-wrapped layout.
    REASONING_DISPLAY_LIMIT = 12000
    API_MODE_LABELS = {
        "responses": "OpenAI Responses API",
        "chat_completions": "通用 Chat Completions",
    }

    def __init__(self, client, notify):
        super().__init__(client, notify)
        self.conversation: list[dict] = []
        self._request_id = 0
        self._pending: dict | None = None
        self._gateway_ready: bool | None = None
        self._server_model = ""
        # Live "thinking" bubble: state is plain data, widgets are rebuilt
        # when a turn starts so a rerender can never leave stale references.
        self._live_state: dict | None = None
        self._live_widgets: dict | None = None
        # P1-6/P1-7 state: the staged write action awaiting the operator and
        # the cancellation flag used when the window closes.
        self._pending_action: dict | None = None
        self._confirm_busy = False
        self._cancel_event = threading.Event()
        self._shutting_down = False
        self._close_hooked_window = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        header = QHBoxLayout()
        header.addWidget(PageHeader("AI 助手", "基于授权数据执行查询与操作"))
        header.addStretch(1)
        header.addWidget(make_button("复制对话", "default", self.copy_conversation))
        header.addWidget(make_button("新对话", "ghost", self.clear_conversation))
        layout.addLayout(header)

        columns = QSplitter(Qt.Horizontal)
        columns.setChildrenCollapsible(False)
        columns.setHandleWidth(6)
        columns.setOpaqueResize(False)
        columns.setStyleSheet(
            "QSplitter::handle { background: transparent; }"
            "QSplitter::handle:hover { background: #EEF4FF; }"
        )

        settings = Card(padding=18)
        settings.setMinimumWidth(290)
        settings.setMaximumWidth(380)
        settings.body.addWidget(PageHeader("会话设置", "模型参数由服务端提供"))
        self.status_badge = StatusBadge("检查中", "neutral")
        settings.body.addWidget(self.status_badge, 0, Qt.AlignLeft)
        self.gateway_info = QLabel("正在读取提供商信息")
        self.gateway_info.setObjectName("Muted")
        self.gateway_info.setWordWrap(True)
        self.gateway_info.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.gateway_info.setStyleSheet("font-weight: 600;")
        settings.body.addWidget(self.gateway_info)
        self.status_detail = QLabel("正在检查 AI 服务")
        self.status_detail.setObjectName("Muted")
        self.status_detail.setWordWrap(True)
        settings.body.addWidget(self.status_detail)

        settings.body.addSpacing(4)
        monitor_title = QLabel("实时监控")
        monitor_title.setObjectName("SectionTitle")
        settings.body.addWidget(monitor_title)
        self.monitor_updated = QLabel("等待刷新")
        self.monitor_updated.setObjectName("Muted")
        settings.body.addWidget(self.monitor_updated)
        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(6)
        self.monitor_labels: dict[str, QLabel] = {}
        for index, (key, label) in enumerate(
            (
                ("total", "密钥总数"),
                ("active", "已激活"),
                ("devices", "绑定设备"),
                ("revoked", "已吊销"),
            )
        ):
            name = QLabel(label)
            name.setObjectName("Muted")
            value = QLabel("—")
            value.setStyleSheet(f"color: {theme.TEXT}; font-weight: 700; font-size: 16px;")
            value.setObjectName("MetricValue")
            self.monitor_labels[key] = value
            grid.addWidget(name, (index // 2) * 2, index % 2)
            grid.addWidget(value, (index // 2) * 2 + 1, index % 2)
        settings.body.addLayout(grid)
        settings.body.addWidget(QLabel("最近动态"))
        self.monitor_logs = QTableWidget(0, 2)
        self.monitor_logs.setHorizontalHeaderLabels(["操作", "对象"])
        self.monitor_logs.verticalHeader().setVisible(False)
        self.monitor_logs.setEditTriggers(QTableWidget.NoEditTriggers)
        self.monitor_logs.setSelectionMode(QTableWidget.NoSelection)
        self.monitor_logs.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.monitor_logs.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.monitor_logs.setMinimumHeight(150)
        settings.body.addWidget(self.monitor_logs)

        settings.body.addSpacing(4)
        settings.body.addWidget(QLabel("当前模型"))
        self.model = QLineEdit()
        self.model.setReadOnly(True)
        self.model.setFocusPolicy(Qt.NoFocus)
        self.model.setPlaceholderText("服务端默认模型")
        settings.body.addWidget(self.model)
        settings.body.addSpacing(8)
        settings.body.addWidget(QLabel("常用指令"))
        for label, prompt in (
            ("授权概览", "汇总当前授权状态，列出需要优先处理的风险。"),
            ("异常验证", "检查最近的验证失败记录，归纳异常原因。"),
            ("即将到期", "列出 7 天内即将到期的授权密钥和影响范围。"),
        ):
            settings.body.addWidget(
                make_button(
                    label,
                    "default",
                    lambda _checked=False, value=prompt: self._use_prompt(value),
                )
            )
        settings.body.addStretch(1)
        settings.body.addWidget(
            make_button("刷新状态", "ghost", lambda: self.refresh_status())
        )
        columns.addWidget(settings)

        chat_card = Card(padding=18)
        chat_card.setMinimumWidth(480)
        self.chat_area = QScrollArea()
        self.chat_area.setWidgetResizable(True)
        self.chat_area.setFrameShape(QFrame.NoFrame)
        self.chat_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.chat_area.viewport().setAutoFillBackground(True)
        self.chat_container = QWidget()
        # 滚动内容层必须有实底：透明层在滚动时新露出的条带会变成黑带。
        self.chat_container.setObjectName("ScrollBody")
        self.chat_layout = QVBoxLayout(self.chat_container)
        self.chat_layout.setContentsMargins(2, 2, 10, 2)
        self.chat_layout.setSpacing(10)
        self.chat_layout.setAlignment(Qt.AlignTop)
        self.chat_area.setWidget(self.chat_container)
        chat_card.body.addWidget(self.chat_area, 1)

        # Two-phase confirmation bar (P1-6): shown only when the gateway
        # stages a write action for this operator to approve.
        self.confirm_bar = QFrame()
        self.confirm_bar.setObjectName("ConfirmBar")
        self.confirm_bar.setStyleSheet(
            "QFrame#ConfirmBar {"
            f" background: {theme.WARNING_SOFT};"
            f" border: 1px solid {theme.BORDER_STRONG};"
            " border-radius: 8px; }"
        )
        confirm_layout = QHBoxLayout(self.confirm_bar)
        confirm_layout.setContentsMargins(12, 10, 12, 10)
        confirm_layout.setSpacing(10)
        self.confirm_label = QLabel("")
        self.confirm_label.setWordWrap(True)
        self.confirm_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        confirm_layout.addWidget(self.confirm_label, 1)
        self.confirm_button = make_button("确认执行", "primary", self.confirm_action)
        confirm_layout.addWidget(self.confirm_button)
        self.cancel_button = make_button("取消", "ghost", self.cancel_action)
        confirm_layout.addWidget(self.cancel_button)
        self.confirm_bar.setVisible(False)
        chat_card.body.addWidget(self.confirm_bar)

        self.compose = QWidget()
        compose_layout = QHBoxLayout(self.compose)
        compose_layout.setContentsMargins(0, 0, 0, 0)
        compose_layout.setSpacing(10)
        self.input = ChatInput()
        self.input.setPlaceholderText("输入消息")
        self.input.setFixedHeight(86)
        self.input.submitted.connect(self.send)
        compose_layout.addWidget(self.input, 1)
        self.send_button = make_button("发送", "primary", self.send)
        self.send_button.setMinimumHeight(44)
        compose_layout.addWidget(self.send_button, 0, Qt.AlignBottom)
        chat_card.body.addWidget(self.compose)

        columns.addWidget(chat_card)
        columns.setStretchFactor(0, 0)
        columns.setStretchFactor(1, 1)
        columns.setSizes([330, 760])
        layout.addWidget(columns, 1)

        self._render_conversation()

        self.monitor_timer = QTimer(self)
        self.monitor_timer.setInterval(8000)
        self.monitor_timer.timeout.connect(lambda: self.refresh_status(silent=True))
        self._monitor_running = False
        app = QApplication.instance()
        if app is not None:
            # Application shutdown must cancel polling even if the window is
            # closed without the page ever seeing a close event.
            app.aboutToQuit.connect(self.shutdown)

    # ------------------------------------------------------------ status
    def refresh(self) -> None:
        self.refresh_status()

    def refresh_status(self, *, silent: bool = False) -> None:
        if self._shutting_down:
            return
        try:
            data = self.client.ai_status()
        except ApiError as exc:
            self._gateway_ready = None
            self.status_badge.set_state("● 状态不可用", "warning")
            self.gateway_info.setText("提供商信息暂不可用")
            self.status_detail.setText(str(exc))
            if not silent:
                self.notify(str(exc), "warning")
            self._sync_send_state()
            return
        except Exception as exc:  # defensive for non-standard API clients
            self._gateway_ready = None
            self.status_badge.set_state("● 状态不可用", "warning")
            self.gateway_info.setText("提供商信息暂不可用")
            self.status_detail.setText(str(exc))
            if not silent:
                self.notify(str(exc), "warning")
            self._sync_send_state()
            return

        enabled = data.get("enabled")
        if enabled is None:
            enabled = data.get("ai_enabled")
        configured = data.get("configured")
        if configured is None:
            configured = data.get("ai_configured")
        if configured is None:
            configured = data.get("api_key_configured")
        if configured is None:
            configured = data.get("has_api_key")

        provider, api_mode, model = self._gateway_fields(data)
        self._server_model = model
        self.model.setText(model)
        self.model.setPlaceholderText("服务端默认模型")
        self.gateway_info.setText(self._gateway_summary(provider, api_mode, model))

        if enabled is False:
            self._gateway_ready = False
            self.status_badge.set_state("● 未启用", "error")
            self.status_detail.setText("本地服务器未启用 AI 助手")
        elif configured is False:
            self._gateway_ready = False
            self.status_badge.set_state("● 缺少密钥", "warning")
            self.status_detail.setText("本地服务器尚未配置 API Key")
        else:
            self._gateway_ready = True
            self.status_badge.set_state("● 可用", "success")
            self.status_detail.setText("服务端网关可用")
        self._apply_monitor(data)
        self._sync_monitor_timer(data)
        self._sync_send_state()

    def _gateway_fields(self, data: dict) -> tuple[str, str, str]:
        """Resolve provider, protocol and model without ever touching secrets."""
        provider = str(data.get("ai_provider") or data.get("provider") or "").strip()
        api_mode = str(data.get("ai_api_mode") or data.get("api_mode") or "").strip()
        model = str(data.get("ai_model") or data.get("model") or "").strip()

        if not provider or not api_mode or not model:
            fallback = self._ai_config_fallback()
            provider = provider or str(
                fallback.get("provider") or fallback.get("vendor_name") or ""
            ).strip()
            api_mode = api_mode or str(fallback.get("api_mode") or "").strip()
            model = model or str(fallback.get("model") or "").strip()

        if not provider or not api_mode or not model:
            defaults = _local_ai_defaults()
            provider = provider or str(defaults.get("vendor_name") or "").strip()
            api_mode = api_mode or str(defaults.get("api_mode") or "").strip()
            model = model or str(defaults.get("model") or "").strip()
        return provider, api_mode, model

    def _ai_config_fallback(self) -> dict:
        getter = getattr(self.client, "ai_config", None)
        if not callable(getter):
            return {}
        try:
            data = getter()
        except Exception:
            return {}
        return data if isinstance(data, dict) else {}

    @classmethod
    def _gateway_summary(cls, provider: str, api_mode: str, model: str) -> str:
        parts = [provider, cls.API_MODE_LABELS.get(api_mode, api_mode), model]
        return " · ".join(part for part in parts if part) or "提供商信息不可用"

    def _sync_send_state(self, busy: bool | None = None) -> None:
        if busy is None:
            busy = self._pending is not None
        self.send_button.setEnabled(not busy and self._gateway_ready is not False)

    # ----------------------------------------------------------- compose
    def send(self) -> None:
        if self._shutting_down or self._pending is not None:
            return
        content = self.input.toPlainText().strip()
        if not content:
            self.notify("请输入消息", "warning")
            self.input.setFocus()
            return
        if self._gateway_ready is False:
            self.notify(self.status_detail.text() or "AI 服务当前不可用", "warning")
            self.input.setFocus()
            return

        index = len(self.conversation)
        self.conversation.append({"role": "user", "content": content})
        self.input.clear()
        self._render_conversation()

        self._request_id += 1
        request_id = self._request_id
        self._pending = {"id": request_id, "prompt": content, "index": index}
        self._set_busy(True)
        self._start_live_view()

        history = [
            {"role": str(item.get("role") or ""), "content": str(item.get("content") or "")}
            for item in self.conversation[-self.MAX_HISTORY_MESSAGES:]
            if item.get("role") in ("user", "assistant")
        ]
        signals = _ChatSignals()
        signals.finished.connect(self._on_chat_finished)
        signals.failed.connect(self._on_chat_failed)
        signals.event.connect(self._on_chat_event)
        task = _ChatTask(
            request_id,
            self.client,
            history,
            signals,
            self._cancel_event,
        )
        QThreadPool.globalInstance().start(task)

    def _set_busy(self, busy: bool) -> None:
        self._sync_send_state(busy)
        self.send_button.setText("生成中…" if busy else "发送")
        self.input.setEnabled(not busy)
        self.model.setEnabled(True)

    def _on_chat_finished(self, request_id: int, data: dict) -> None:
        if self._shutting_down or request_id != self._request_id:
            return
        self._set_busy(False)
        content = self._extract_content(data)
        if not content:
            self._restore_failed_prompt("AI 服务未返回内容")
            return
        self._pending = None
        message = {"role": "assistant", "content": content}
        reasoning = str(data.get("reasoning") or "").strip()
        if reasoning:
            message["reasoning"] = reasoning
        tool_names = self._tool_names(data)
        if tool_names:
            message["tools"] = tool_names
        model = str(data.get("model") or "").strip()
        if model:
            message["model"] = model
        self.conversation.append(message)
        pending_action = self._pending_from_result(data)
        if pending_action is not None:
            self._show_confirm_bar(pending_action)
        self._render_conversation()

    def _on_chat_failed(self, request_id: int, message: str) -> None:
        if self._shutting_down or request_id != self._request_id:
            return
        self._set_busy(False)
        self._restore_failed_prompt(message or "AI 请求失败")

    def _restore_failed_prompt(self, message: str) -> None:
        pending = self._pending
        if pending:
            index = int(pending.get("index", -1))
            if 0 <= index < len(self.conversation):
                item = self.conversation[index]
                if item.get("role") == "user" and item.get("content") == pending.get("prompt"):
                    self.conversation.pop(index)
            self.input.setPlainText(str(pending.get("prompt") or ""))
        self._pending = None
        self._render_conversation()
        self.notify(message, "error")
        self.input.setFocus()

    def _use_prompt(self, prompt: str) -> None:
        self.input.setPlainText(prompt)
        self.input.setFocus()

    # ------------------------------------------------------ confirmation
    @staticmethod
    def _pending_from_result(data: dict) -> dict | None:
        """Extract the first staged write action from a chat result."""
        calls = data.get("tool_calls")
        if not isinstance(calls, list):
            return None
        for item in calls:
            if not isinstance(item, dict):
                continue
            result = item.get("result")
            if not isinstance(result, dict):
                continue
            if result.get("status") != "pending_confirmation":
                continue
            token = str(result.get("confirm_token") or "").strip()
            if not token:
                continue
            preview = result.get("preview")
            if not isinstance(preview, dict):
                preview = {}
            return {
                "tool": str(preview.get("tool") or item.get("name") or ""),
                "arguments_summary": str(preview.get("arguments_summary") or ""),
                "affected_count": preview.get("affected_count"),
                "expires_in": result.get("expires_in"),
                "token": token,
            }
        return None

    def _show_confirm_bar(self, action: dict) -> None:
        self._pending_action = action
        self._set_confirm_busy(False)
        tool = str(action.get("tool") or "写操作")
        summary = str(action.get("arguments_summary") or "").strip()
        count = action.get("affected_count")
        head = f"待确认：{tool}"
        try:
            if count is not None and int(count) >= 0:
                head += f" · 影响 {int(count)} 项"
        except (TypeError, ValueError):
            pass
        try:
            expires = int(action.get("expires_in") or 0)
        except (TypeError, ValueError):
            expires = 0
        if expires > 0:
            head += f" · 令牌 {expires} 秒内有效"
        text = head + ("\n" + summary if summary else "")
        self.confirm_label.setText(text)
        self.confirm_bar.setVisible(True)
        QTimer.singleShot(0, self._scroll_to_bottom)

    def _hide_confirm_bar(self) -> None:
        self._pending_action = None
        self._set_confirm_busy(False)
        try:
            self.confirm_bar.setVisible(False)
        except RuntimeError:  # pragma: no cover - widget already destroyed
            pass

    def _set_confirm_busy(self, busy: bool) -> None:
        self._confirm_busy = bool(busy)
        try:
            self.confirm_button.setEnabled(not busy)
            self.cancel_button.setEnabled(not busy)
            self.confirm_button.setText("执行中…" if busy else "确认执行")
            self.cancel_button.setText("取消中…" if busy else "取消")
        except RuntimeError:  # pragma: no cover - widget already destroyed
            pass

    def confirm_action(self) -> None:
        """Execute the staged write action after the operator approves it."""
        action = self._pending_action
        if self._shutting_down or self._confirm_busy or not action:
            return
        self._set_confirm_busy(True)
        self._run_confirmation("confirm", str(action.get("token") or ""))

    def cancel_action(self) -> None:
        """Cancel the staged write action so the server never executes it."""
        action = self._pending_action
        if self._shutting_down or self._confirm_busy or not action:
            return
        self._set_confirm_busy(True)
        self._run_confirmation("cancel", str(action.get("token") or ""))

    def _run_confirmation(self, mode: str, token: str) -> None:
        signals = _ConfirmationSignals()
        signals.finished.connect(self._on_confirmation_finished)
        signals.failed.connect(self._on_confirmation_failed)
        QThreadPool.globalInstance().start(
            _ConfirmationTask(mode, self.client, token, signals)
        )

    def _on_confirmation_finished(self, mode: str, data: dict) -> None:
        if self._shutting_down:
            return
        action = self._pending_action or {}
        tool = str(action.get("tool") or "").strip()
        self._hide_confirm_bar()
        if mode == "cancel":
            content = f"已取消待确认操作：{tool or '写操作'}"
            self.conversation.append({"role": "assistant", "content": content})
            self._render_conversation()
            self.notify(content, "success")
            return
        content = self._confirmation_summary(data, action)
        message = {"role": "assistant", "content": content}
        if tool:
            message["tools"] = [tool]
        self.conversation.append(message)
        self._render_conversation()
        self.notify(
            content,
            "error" if isinstance(data, dict) and data.get("ok") is False else "success",
        )

    def _on_confirmation_failed(self, mode: str, message: str) -> None:
        if self._shutting_down:
            return
        label = "取消操作" if mode == "cancel" else "确认执行"
        text = f"{label}失败：{message or '未知错误'}"
        self._hide_confirm_bar()
        self.conversation.append({"role": "assistant", "content": text})
        self._render_conversation()
        self.notify(text, "error")

    @staticmethod
    def _confirmation_summary(data: dict, action: dict) -> str:
        """Render a compact result line without echoing secrets."""
        tool = str(action.get("tool") or "").strip()
        head = f"{tool} 已确认执行" if tool else "操作已确认执行"
        payload = data if isinstance(data, dict) else {}
        if payload.get("ok") is False:
            return f"{tool or '操作'} 执行失败：{payload.get('error') or '未知错误'}"
        details: list[str] = []
        count = payload.get("count")
        if isinstance(count, int) and not isinstance(count, bool):
            details.append(f"影响 {count} 项")
        if payload.get("batch_no"):
            details.append(f"批次 {payload['batch_no']}")
        keys = payload.get("keys")
        if isinstance(keys, list) and keys:
            details.append(f"首个卡密 {keys[0]}")
        if payload.get("key_code") and not keys:
            details.append(f"卡密 {payload['key_code']}")
        username = payload.get("username")
        if username and not keys:
            details.append(f"账号 {username}")
        if payload.get("machine_code"):
            details.append(f"设备 {payload['machine_code']}")
        return head + ("（" + " · ".join(details) + "）" if details else "")

    # ---------------------------------------------------------- lifecycle
    def shutdown(self) -> None:
        """Cancel in-flight AI work and stop refreshing; safe to call twice.

        P1-7: the desktop client must not stay resident for the whole 600
        second AI budget after the window closes.
        """
        if self._shutting_down:
            return
        self._shutting_down = True
        self._cancel_event.set()
        try:
            self.stop_monitor()
        except RuntimeError:  # pragma: no cover - widget already destroyed
            pass
        self._pending_action = None
        self._pending = None
        try:
            self.confirm_bar.setVisible(False)
        except RuntimeError:  # pragma: no cover - widget already destroyed
            pass
        pool = QThreadPool.globalInstance()
        try:
            # Drop queued runnables, then give the running one a bounded grace
            # period to notice the cancellation flag.
            pool.clear()
        except RuntimeError:  # pragma: no cover - defensive
            pass
        try:
            pool.waitForDone(500)
        except (RuntimeError, TypeError):  # pragma: no cover - older Qt
            pass

    def _install_close_hook(self) -> None:
        """Watch the top-level window so closing it cancels AI work.

        The admin/master windows are owned by other modules, so the page hooks
        their ``QEvent.Close`` instead of overriding ``closeEvent`` there.
        """
        try:
            window = self.window()
        except RuntimeError:  # pragma: no cover - widget already destroyed
            return
        if window is None or window is self or window is self._close_hooked_window:
            return
        self._close_hooked_window = window
        window.installEventFilter(self)

    def eventFilter(self, obj, event) -> bool:  # noqa: N802 - Qt override
        try:
            if event.type() == QEvent.Close:
                self.shutdown()
        except RuntimeError:  # pragma: no cover - defensive
            pass
        return super().eventFilter(obj, event)

    # ---------------------------------------------------------- rendering
    def _render_conversation(self) -> None:
        # A full rerender rebuilds every bubble; drop the live view first so
        # no stale Qt references survive the widget teardown.
        self._live_state = None
        self._live_widgets = None
        while self.chat_layout.count():
            item = self.chat_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

        if not self.conversation:
            empty = QLabel("暂无对话")
            empty.setObjectName("Muted")
            empty.setAlignment(Qt.AlignCenter)
            empty.setMinimumHeight(220)
            self.chat_layout.addWidget(empty)
        else:
            for message in self.conversation:
                self._add_bubble(message)
        QTimer.singleShot(0, self._scroll_to_bottom)

    def _add_bubble(self, message: dict) -> None:
        role = "user" if message.get("role") == "user" else "assistant"
        content = str(message.get("content") or "")
        frame = QFrame()
        frame.setObjectName("ChatBubble")
        frame.setStyleSheet(self._bubble_style(role))
        frame.setMaximumWidth(760)
        frame.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        body = QVBoxLayout(frame)
        body.setContentsMargins(14, 11, 14, 12)
        body.setSpacing(6)

        meta_text = "你" if role == "user" else "AI 助手"
        if role == "assistant" and message.get("model"):
            meta_text += f" · {message['model']}"
        meta = QLabel(meta_text)
        meta.setObjectName("Muted")
        body.addWidget(meta)

        if role == "assistant":
            reasoning = str(message.get("reasoning") or "").strip()
            if reasoning:
                self._add_reasoning_section(body, reasoning)

        text = QLabel(content)
        text.setWordWrap(True)
        text.setTextFormat(Qt.MarkdownText)
        text.setTextInteractionFlags(Qt.TextSelectableByMouse)
        text.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        body.addWidget(text)

        names = message.get("tools") or []
        if names:
            tools = QLabel("工具：" + "、".join(str(name) for name in names))
            tools.setObjectName("Muted")
            tools.setWordWrap(True)
            body.addWidget(tools)

        self._place_bubble(frame, role)

    @staticmethod
    def _bubble_style(role: str) -> str:
        if role == "user":
            return (
                "QFrame#ChatBubble {"
                f" background: {theme.PRIMARY_SOFT};"
                f" border: 1px solid {theme.PRIMARY_BORDER};"
                " border-radius: 8px; }"
            )
        return (
            "QFrame#ChatBubble {"
            f" background: {theme.SURFACE};"
            f" border: 1px solid {theme.BORDER};"
            " border-radius: 8px; }"
        )

    def _scroll_to_bottom(self) -> None:
        bar = self.chat_area.verticalScrollBar()
        bar.setValue(bar.maximum())

    # ------------------------------------------------------------ helpers
    @staticmethod
    def _text_from(value: Any) -> str:
        if isinstance(value, str):
            return value.strip()
        if isinstance(value, list):
            parts = []
            for item in value:
                text = AIAssistantPage._text_from(item)
                if text:
                    parts.append(text)
            return "\n".join(parts).strip()
        if isinstance(value, dict):
            for key in ("text", "content", "value"):
                text = AIAssistantPage._text_from(value.get(key))
                if text:
                    return text
        return ""

    @staticmethod
    def _extract_content(data: dict) -> str:
        for key in ("content", "reply", "answer", "output_text", "output", "text"):
            text = AIAssistantPage._text_from(data.get(key))
            if text:
                return text
        message = data.get("message")
        text = AIAssistantPage._text_from(message)
        if text:
            return text
        choices = data.get("choices")
        if isinstance(choices, list):
            for choice in choices:
                if not isinstance(choice, dict):
                    continue
                text = AIAssistantPage._text_from(choice.get("message"))
                if not text:
                    text = AIAssistantPage._text_from(choice.get("text"))
                if text:
                    return text
        return ""

    @staticmethod
    def _tool_names(data: dict) -> list[str]:
        raw = data.get("tool_events") or data.get("tool_calls") or data.get("tools")
        if not isinstance(raw, list):
            return []
        names: list[str] = []
        for item in raw:
            if isinstance(item, dict):
                name = item.get("name") or item.get("tool") or item.get("type")
            else:
                name = item
            name = str(name or "").strip()
            if name and name not in names:
                names.append(name)
        return names

    def copy_conversation(self) -> None:
        if not self.conversation:
            self.notify("暂无可复制的对话", "warning")
            return
        lines = []
        for item in self.conversation:
            role = "你" if item.get("role") == "user" else "AI 助手"
            lines.append(f"{role}：{item.get('content', '')}")
        QApplication.clipboard().setText("\n\n".join(lines))
        self.notify(f"已复制 {len(self.conversation)} 条消息", "success")

    def clear_conversation(self) -> None:
        if not self.conversation and self._pending is None:
            self.notify("当前没有对话", "warning")
            return
        if self.conversation and not confirm(self, "新对话", "确定清空当前对话？"):
            return
        self._request_id += 1
        self._pending = None
        self._hide_confirm_bar()
        self.conversation.clear()
        self.input.clear()
        self._set_busy(False)
        self._render_conversation()
        self.notify("已开始新对话", "success")

    def _apply_monitor(self, data: dict) -> None:
        stats = data.get("stats")
        if isinstance(stats, dict):
            mapping = {
                "total": ("total", "keys"),
                "active": ("active",),
                "devices": ("devices",),
                "revoked": ("revoked",),
            }
            for key, sources in mapping.items():
                label = self.monitor_labels.get(key)
                if label is None:
                    continue
                value: Any = None
                for source in sources:
                    if source in stats:
                        value = stats.get(source)
                        break
                label.setText("—" if value is None else str(value))
        logs = data.get("logs")
        if isinstance(logs, list):
            rows = logs[:8]
            self.monitor_logs.setRowCount(len(rows))
            for row, item in enumerate(rows):
                item = item if isinstance(item, dict) else {}
                action = str(item.get("action") or "")
                target = str(item.get("target") or item.get("actor") or "")
                self.monitor_logs.setItem(row, 0, QTableWidgetItem(action))
                self.monitor_logs.setItem(row, 1, QTableWidgetItem(target))
        server = data.get("server")
        when = ""
        if isinstance(server, dict):
            when = str(server.get("time") or "")
        self.monitor_updated.setText(f"更新于 {when}" if when else "已更新")

    def _sync_monitor_timer(self, data: dict) -> None:
        try:
            interval = int(data.get("monitor_interval") or 8)
        except (TypeError, ValueError):
            interval = 8
        interval = max(3, min(interval, 300))
        self.monitor_timer.setInterval(interval * 1000)

    def start_monitor(self) -> None:
        if not self._shutting_down and not self._monitor_running:
            self._monitor_running = True
            self.monitor_timer.start()

    def stop_monitor(self) -> None:
        self._monitor_running = False
        self.monitor_timer.stop()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._install_close_hook()
        self.start_monitor()

    def hideEvent(self, event) -> None:
        self.stop_monitor()
        super().hideEvent(event)

    def on_show(self) -> None:
        self.refresh_status(silent=True)

    # ------------------------------------------------------- live thinking
    def _place_bubble(self, frame: QFrame, role: str) -> QWidget:
        """Align one bubble left (assistant) or right (user)."""
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        if role == "user":
            row.addStretch(1)
            row.addWidget(frame, 0)
        else:
            row.addWidget(frame, 0)
            row.addStretch(1)
        holder = QWidget()
        holder.setObjectName("Transparent")
        holder.setLayout(row)
        self.chat_layout.addWidget(holder)
        return holder

    def _add_reasoning_section(self, body: QVBoxLayout, reasoning: str) -> None:
        """Collapsed-by-default trace so the answer stays the focus."""
        toggle = make_button("思考过程", "ghost", None)
        toggle.setCheckable(True)
        toggle.setCursor(Qt.PointingHandCursor)
        shown = reasoning
        if len(shown) > self.REASONING_DISPLAY_LIMIT:
            shown = "（内容过长，仅显示最后部分）\n" + shown[-self.REASONING_DISPLAY_LIMIT:]
        detail = QLabel(shown)
        detail.setWordWrap(True)
        detail.setTextFormat(Qt.PlainText)
        detail.setTextInteractionFlags(Qt.TextSelectableByMouse)
        detail.setStyleSheet(
            f"color: {theme.TEXT_SOFT}; background: {theme.SURFACE}; border: 1px solid {theme.BORDER};"
            " border-radius: 6px; padding: 8px 10px;"
        )
        detail.setVisible(False)

        def toggle_detail(checked: bool) -> None:
            detail.setVisible(bool(checked))
            toggle.setText("收起思考过程" if checked else "思考过程")
            QTimer.singleShot(0, self._scroll_to_bottom)

        toggle.toggled.connect(toggle_detail)
        body.addWidget(toggle, 0, Qt.AlignLeft)
        body.addWidget(detail)

    def _start_live_view(self) -> None:
        """Create the placeholder bubble that streams phases and reasoning."""
        self._clear_live_view()
        self._live_state = {"phase": "正在连接 AI 服务…", "reasoning": "", "steps": []}

        frame = QFrame()
        frame.setObjectName("ChatBubble")
        frame.setStyleSheet(self._bubble_style("assistant"))
        frame.setMaximumWidth(760)
        frame.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        body = QVBoxLayout(frame)
        body.setContentsMargins(14, 11, 14, 12)
        body.setSpacing(6)

        meta = QLabel("AI 助手 · 进行中")
        meta.setObjectName("Muted")
        body.addWidget(meta)

        phase = QLabel(str(self._live_state["phase"]))
        phase.setWordWrap(True)
        body.addWidget(phase)

        reasoning = QPlainTextEdit()
        reasoning.setObjectName("ReasoningView")
        reasoning.setReadOnly(True)
        reasoning.setFrameShape(QFrame.NoFrame)
        reasoning.setMinimumHeight(64)
        reasoning.setMaximumHeight(180)
        reasoning.setStyleSheet(
            f"QPlainTextEdit#ReasoningView {{ background: {theme.SURFACE}; border: 1px solid {theme.BORDER}; border-radius: 6px; color: {theme.TEXT_SOFT}; padding: 6px; }}"
        )
        reasoning.setVisible(False)
        body.addWidget(reasoning)

        steps = QLabel("")
        steps.setObjectName("Muted")
        steps.setWordWrap(True)
        steps.setVisible(False)
        body.addWidget(steps)

        holder = self._place_bubble(frame, "assistant")
        self._live_widgets = {
            "holder": holder,
            "phase": phase,
            "reasoning": reasoning,
            "steps": steps,
        }
        self._sync_live_view()

    def _on_chat_event(self, request_id: int, event: dict) -> None:
        """Render one streamed gateway event (phase / reasoning / tool)."""
        if request_id != self._request_id or self._live_state is None:
            return
        kind = str(event.get("type") or "").strip().lower()
        text = str(event.get("text") or "").strip()
        name = str(event.get("name") or "").strip()
        state = self._live_state
        if kind == "reasoning":
            if text:
                merged = str(state.get("reasoning") or "") + text
                state["reasoning"] = merged[-self.LIVE_REASONING_LIMIT:]
        elif kind == "phase":
            if text:
                state["phase"] = text
        elif kind == "tool":
            label = text or (f"执行工具：{name}" if name else "执行工具")
            self._record_live_step(label)
            state["phase"] = label
        elif kind == "tool_result":
            base = text or (f"工具 {name} 完成" if name else "工具执行完成")
            if event.get("ok") is False and "失败" not in base:
                base += "（失败）"
            self._record_live_step(base)
            state["phase"] = base
        elif kind == "tool_pending":
            base = text or (f"{name} 等待人工确认" if name else "等待人工确认")
            self._record_live_step(base)
            state["phase"] = base
        elif kind in ("content", "message", "delta") and text:
            state["phase"] = "正在生成回复…"
        self._sync_live_view()

    def _record_live_step(self, label: str) -> None:
        state = self._live_state
        if state is None or not label:
            return
        steps = state.setdefault("steps", [])
        if not steps or steps[-1] != label:
            steps.append(label)
        if len(steps) > 20:
            del steps[: len(steps) - 20]

    def _sync_live_view(self) -> None:
        widgets = self._live_widgets
        state = self._live_state
        if not widgets or state is None:
            return
        phase = str(state.get("phase") or "").strip()
        widgets["phase"].setText(phase or "正在思考…")

        trace = str(state.get("reasoning") or "").strip()
        view = widgets["reasoning"]
        if trace:
            if view.toPlainText() != trace:
                view.setPlainText(trace)
            bar = view.verticalScrollBar()
            bar.setValue(bar.maximum())
            if view.isHidden():
                view.setVisible(True)
        steps = state.get("steps") or []
        label = widgets["steps"]
        if steps:
            label.setText("工具：" + "、".join(str(step) for step in steps))
            if label.isHidden():
                label.setVisible(True)
        QTimer.singleShot(0, self._scroll_to_bottom)

    def _clear_live_view(self) -> None:
        widgets = self._live_widgets
        self._live_widgets = None
        self._live_state = None
        holder = (widgets or {}).get("holder")
        if holder is None:
            return
        try:
            self.chat_layout.removeWidget(holder)
        except RuntimeError:  # pragma: no cover - widget already destroyed
            return
        holder.setParent(None)
        holder.deleteLater()
