"""Headless UI tests for the shared AI assistant page."""

import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import QApplication, QPushButton  # noqa: E402

from core import ai_page as ai_page_module  # noqa: E402
from core.ai_page import AIAssistantPage, ChatInput  # noqa: E402
from core.api_client import ApiError  # noqa: E402


@pytest.fixture(scope="module")
def qt_app():
    app = QApplication.instance() or QApplication([])
    yield app


def wait_until(qt_app, predicate, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        qt_app.processEvents()
        if predicate():
            return
        QTest.qWait(10)
    assert predicate()


class FakeAIClient:
    base_url = "http://127.0.0.1:8765"

    def __init__(self, *, reply: str = "已查询完成", fail: bool = False):
        self.reply = reply
        self.fail = fail
        self.calls: list[dict] = []

    def ai_status(self) -> dict:
        return {"ai_enabled": True, "ai_configured": True, "ai_model": "gpt-5.1"}

    def ai_chat(self, messages) -> dict:
        self.calls.append({"messages": messages})
        if self.fail:
            raise ApiError("上游连接失败")
        return {
            "reply": self.reply,
            "model": "gpt-5.1",
            "tool_calls": [{"name": "list_licenses"}],
        }


class ProviderAIClient(FakeAIClient):
    """Snapshot that already carries provider/protocol fields."""

    def ai_status(self) -> dict:
        return {
            "ai_enabled": True,
            "ai_configured": True,
            "ai_provider": "DeepSeek",
            "ai_api_mode": "chat_completions",
            "ai_model": "deepseek-chat",
        }


class ConfigOnlyAIClient(FakeAIClient):
    """Older status snapshot plus the /api/ai/config fallback endpoint."""

    def ai_status(self) -> dict:
        return {"ai_enabled": True, "ai_configured": True}

    def ai_config(self) -> dict:
        return {
            "provider": "Moonshot",
            "api_mode": "chat_completions",
            "model": "kimi-k2",
        }


class UnreachableAIClient(FakeAIClient):
    def ai_status(self) -> dict:
        raise ApiError("本地服务器未启动")


class FakeConfig:
    def __init__(self):
        self.client = {}


def test_extract_content_supports_gateway_response_shapes():
    assert AIAssistantPage._extract_content({"content": "直接回复"}) == "直接回复"
    assert AIAssistantPage._extract_content({"reply": "网关回复"}) == "网关回复"
    assert AIAssistantPage._extract_content(
        {"choices": [{"message": {"content": "兼容回复"}}]}
    ) == "兼容回复"
    assert AIAssistantPage._extract_content(
        {"output": [{"content": [{"type": "output_text", "text": "响应回复"}]}]}
    ) == "响应回复"


def test_chat_input_enter_submits_and_shift_enter_adds_newline(qt_app):
    editor = ChatInput()
    submitted: list[bool] = []
    editor.submitted.connect(lambda: submitted.append(True))

    QTest.keyClick(editor, Qt.Key_Return, Qt.ShiftModifier)
    QTest.keyClick(editor, Qt.Key_Return)

    assert submitted == [True]
    assert editor.toPlainText() == "\n"


def test_ai_page_sends_context_and_renders_reply(qt_app):
    client = FakeAIClient(reply="当前共有 3 个可用密钥。")
    page = AIAssistantPage(client, lambda *_args, **_kwargs: None)
    page.refresh_status()
    assert page.status_badge.text() == "● 可用"
    assert page.model.text() == "gpt-5.1"

    page.input.setPlainText("查询可用密钥")
    page.send()
    wait_until(qt_app, lambda: page._pending is None and len(page.conversation) == 2)

    assert client.calls[-1]["messages"] == [
        {"role": "user", "content": "查询可用密钥"}
    ]
    assert page.conversation[-1]["content"] == "当前共有 3 个可用密钥。"
    assert page.conversation[-1]["tools"] == ["list_licenses"]
    assert "list_licenses" in " ".join(
        label.text()
        for label in page.findChildren(ai_page_module.QLabel)
        if label.text()
    )


def test_status_renders_provider_and_protocol_labels(qt_app):
    page = AIAssistantPage(ProviderAIClient(), lambda *_args, **_kwargs: None)
    page.refresh_status()

    assert page.status_badge.text() == "● 可用"
    assert page.model.text() == "deepseek-chat"
    assert page.gateway_info.text() == (
        "DeepSeek · 通用 Chat Completions · deepseek-chat"
    )
    assert page.send_button.isEnabled()


def test_status_falls_back_to_ai_config_endpoint(qt_app):
    page = AIAssistantPage(ConfigOnlyAIClient(), lambda *_args, **_kwargs: None)
    page.refresh_status()

    assert page.status_badge.text() == "● 可用"
    assert page.model.text() == "kimi-k2"
    assert page.gateway_info.text() == (
        "Moonshot · 通用 Chat Completions · kimi-k2"
    )


def test_status_falls_back_to_local_defaults(qt_app):
    page = AIAssistantPage(FakeAIClient(), lambda *_args, **_kwargs: None)
    page.refresh_status()

    assert page.status_badge.text() == "● 可用"
    assert page.model.text() == "gpt-5.1"
    assert page.gateway_info.text() == (
        "OpenAI · OpenAI Responses API · gpt-5.1"
    )


def test_status_failure_disables_sending_and_keeps_input(qt_app):
    messages: list[tuple[str, str]] = []
    page = AIAssistantPage(
        UnreachableAIClient(),
        lambda message, kind="info": messages.append((kind, message)),
    )
    page.refresh_status()

    assert page.status_badge.text() == "● 状态不可用"
    assert page.gateway_info.text() == "提供商信息暂不可用"
    assert messages[-1][0] == "warning"
    assert len(messages) == 1

    # The monitor timer polls quietly; it must not repeat the warning.
    page.refresh_status(silent=True)
    assert len(messages) == 1
    assert page.conversation == []


def test_ai_page_restores_prompt_when_request_fails(qt_app, monkeypatch):
    client = FakeAIClient(fail=True)
    messages: list[tuple[str, str]] = []
    page = AIAssistantPage(
        client, lambda message, kind="info": messages.append((kind, message))
    )
    page.input.setPlainText("执行失败也要保留输入")
    page.send()
    wait_until(qt_app, lambda: page._pending is None)

    assert page.conversation == []
    assert page.input.toPlainText() == "执行失败也要保留输入"
    assert messages[-1][0] == "error"


def test_clear_conversation_resets_pending_state(qt_app, monkeypatch):
    client = FakeAIClient()
    page = AIAssistantPage(client, lambda *_args, **_kwargs: None)
    page.conversation = [{"role": "user", "content": "旧消息"}]
    monkeypatch.setattr(ai_page_module, "confirm", lambda *_args, **_kwargs: True)

    page.clear_conversation()

    assert page.conversation == []
    assert page.send_button.isEnabled()
    assert page.input.toPlainText() == ""


class StreamingAIClient(FakeAIClient):
    """Client that reports progress events while the turn runs."""

    def __init__(self, *, reply: str = "已查询完成", reasoning: str = ""):
        super().__init__(reply=reply)
        self.reasoning = reasoning

    def ai_chat(self, messages, on_event=None) -> dict:
        self.calls.append({"messages": messages})
        for event in (
            {"type": "phase", "text": "正在思考…"},
            {"type": "reasoning", "text": "先查一下卡密数量。"},
            {"type": "tool", "text": "执行工具：get_stats", "name": "get_stats"},
            {"type": "tool_result", "text": "get_stats 执行完成", "ok": True},
        ):
            if on_event is not None:
                on_event(dict(event))
        return {
            "reply": self.reply,
            "model": "gpt-5.1",
            "reasoning": self.reasoning,
            "tool_calls": [{"name": "get_stats"}],
        }


def test_live_view_streams_phase_reasoning_and_tools(qt_app):
    page = AIAssistantPage(FakeAIClient(), lambda *_a, **_k: None)
    page.refresh_status()
    page._start_live_view()

    request_id = page._request_id
    # Stale ids (a cleared conversation) must be ignored outright.
    page._on_chat_event(request_id + 1, {"type": "phase", "text": "不该出现"})
    page._on_chat_event(request_id, {"type": "phase", "text": "正在思考…"})
    page._on_chat_event(request_id, {"type": "reasoning", "text": "先查一下卡密数量。"})
    page._on_chat_event(
        request_id,
        {"type": "tool", "text": "执行工具：get_stats", "name": "get_stats"},
    )

    widgets = page._live_widgets
    assert widgets is not None
    assert widgets["phase"].text() == "执行工具：get_stats"
    assert "先查一下卡密数量。" in widgets["reasoning"].toPlainText()
    assert not widgets["reasoning"].isHidden()
    assert "get_stats" in widgets["steps"].text()

    page._clear_live_view()
    assert page._live_widgets is None
    assert page._live_state is None


def test_finished_reply_keeps_a_collapsed_reasoning_section(qt_app):
    client = StreamingAIClient(reply="共 3 张卡密。", reasoning="先读卡密表，再汇总。")
    page = AIAssistantPage(client, lambda *_a, **_k: None)
    page.refresh_status()
    page.input.setPlainText("有多少卡密？")
    page.send()
    wait_until(qt_app, lambda: page._pending is None and len(page.conversation) == 2)

    assert page.conversation[-1]["content"] == "共 3 张卡密。"
    assert page.conversation[-1]["reasoning"] == "先读卡密表，再汇总。"
    # The live placeholder is gone and the trace lives in the answer bubble.
    assert page._live_widgets is None
    labels = [label for label in page.findChildren(ai_page_module.QLabel)]
    trace = next(label for label in labels if "先读卡密表，再汇总。" in label.text())
    assert trace.isHidden()
    toggles = [button for button in page.findChildren(QPushButton)]
    toggle = next(button for button in toggles if button.text() == "思考过程")
    toggle.setChecked(True)
    assert not trace.isHidden()
    assert toggle.text() == "收起思考过程"


def test_ai_nav_item_is_present_in_admin_and_master(qt_app):
    from admin.ui import AdminWindow
    from master.ui import MasterWindow

    client = FakeAIClient()
    user = {"username": "admin", "role": "master", "must_change_password": True}
    windows = [
        AdminWindow(client, user),
        MasterWindow(client, user, FakeConfig()),
    ]
    try:
        for window in windows:
            labels = [button.text() for button in window._buttons]
            assert "AI 助手" in labels
            assert window.ai in [
                window.stack.widget(index) for index in range(window.stack.count())
            ]
    finally:
        for window in windows:
            window.close()
            window.deleteLater()
