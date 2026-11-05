"""告警中心 UI 测试：离屏 Qt + FakeClient（unittest）。"""

import os
import unittest
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtWidgets import QApplication, QDialog
except ImportError as exc:  # pragma: no cover - 环境缺少 PySide6 时跳过
    raise unittest.SkipTest(f"PySide6 不可用：{exc}")

from core.alert_center import (  # noqa: E402
    AlertCenterPage,
    AlertRuleDialog,
    ChannelDialog,
)
from core.api_client import ApiError  # noqa: E402

METRIC_KEYS = (
    "activation_rate",
    "online_devices",
    "expiration_rate",
    "expiring_soon",
    "failed_activations",
    "risk_events",
    "tamper_events",
)


def setUpModule() -> None:
    if QApplication.instance() is None:
        QApplication([])


class FakeClient:
    def __init__(self):
        self.role = "master"
        self.metrics = {
            "activation_rate": 91.5,
            "online_devices": 3,
            "expiration_rate": 0.0,
            "expiring_soon": 2,
            "failed_activations": 1,
            "risk_events": 0,
            "tamper_events": 4,
        }
        self.rules = [
            {
                "id": 1,
                "name": "激活率过低",
                "metric": "activation_rate",
                "operator": "lt",
                "threshold": 80,
                "window_seconds": 600,
                "severity": "warning",
                "cooldown_seconds": 3600,
                "channels": ["email"],
                "enabled": 1,
                "note": "关注激活",
            },
            {
                "id": 2,
                "name": "完整性告警",
                "metric": "tamper_events",
                "operator": "gte",
                "threshold": 1,
                "window_seconds": 300,
                "severity": "critical",
                "cooldown_seconds": 60,
                "channels": [],
                "enabled": 0,
                "note": "",
            },
        ]
        self.events = [
            {
                "id": 11,
                "rule_id": 1,
                "rule_name": "激活率过低",
                "metric": "activation_rate",
                "value": 62.5,
                "threshold": 80,
                "operator": "lt",
                "severity": "warning",
                "status": "firing",
                "notified": 1,
                "fired_at": "2026-10-07 10:00:00",
            },
            {
                "id": 12,
                "rule_id": 2,
                "rule_name": "完整性告警",
                "metric": "tamper_events",
                "value": 2,
                "threshold": 1,
                "operator": "gte",
                "severity": "critical",
                "status": "resolved",
                "notified": 0,
                "fired_at": "2026-10-07 09:00:00",
            },
        ]
        self.created: list[dict] = []
        self.updated: list[tuple] = []
        self.deleted: list = []
        self.acked: list = []
        self.resolved: list = []
        self.event_queries: list[dict] = []
        self.delete_error = ""
        self.channels = [
            {
                "id": 1,
                "kind": "webhook",
                "name": "运维 Webhook",
                "url": "https://example.com/hooks/sq",
                "secret_set": True,
                "enabled": 1,
                "created_at": "2026-10-07 09:00:00",
                "updated_at": "2026-10-07 09:00:00",
            },
            {
                "id": 2,
                "kind": "dingtalk",
                "name": "值班群",
                "url": "https://oapi.dingtalk.com/robot/send?access_token=abc",
                "secret_set": False,
                "enabled": 0,
                "created_at": "2026-10-07 09:10:00",
                "updated_at": "2026-10-07 09:10:00",
            },
            {
                "id": 3,
                "kind": "feishu",
                "name": "飞书告警",
                "url": "https://open.feishu.cn/open-apis/bot/v2/hook/xyz",
                "secret_set": False,
                "enabled": 1,
                "created_at": "2026-10-07 09:20:00",
                "updated_at": "2026-10-07 09:20:00",
            },
        ]
        self.deliveries = [
            {
                "id": 101,
                "channel_id": 1,
                "channel_name": "运维 Webhook",
                "subject": "激活率过低",
                "status": "sent",
                "attempts": 1,
                "last_error": None,
                "created_at": "2026-10-07 10:05:00",
            },
            {
                "id": 102,
                "channel_id": 3,
                "channel_name": "飞书告警",
                "subject": "完整性告警",
                "status": "failed",
                "attempts": 2,
                "last_error": "HTTP 500：内部错误",
                "created_at": "2026-10-07 10:06:00",
            },
        ]
        self.channel_created: list[dict] = []
        self.channel_updated: list[tuple] = []
        self.channel_deleted: list[int] = []
        self.channel_tested: list[int] = []
        self.delivery_queries: list[dict] = []

    # -- 第 6 节契约方法 -------------------------------------------------
    def alert_rules(self) -> dict:
        return {"items": [dict(rule) for rule in self.rules]}

    def create_alert_rule(self, **fields) -> dict:
        self.created.append(fields)
        return {"ok": True, "id": 99}

    def update_alert_rule(self, rule_id: int, **fields) -> dict:
        self.updated.append((rule_id, fields))
        return {"ok": True}

    def delete_alert_rule(self, rule_id: int) -> dict:
        self.deleted.append(rule_id)
        if self.delete_error:
            raise ApiError(self.delete_error)
        return {"ok": True}

    def alert_events(self, status: str = "", limit: int = 200, offset: int = 0) -> dict:
        self.event_queries.append(
            {"status": status, "limit": limit, "offset": offset}
        )
        rows = [
            event for event in self.events if not status or event["status"] == status
        ]
        return {
            "items": [dict(event) for event in rows[offset:offset + limit]],
            "total": len(rows),
        }

    def ack_alert_event(self, event_id: int) -> dict:
        self.acked.append(event_id)
        return {"ok": True}

    def resolve_alert_event(self, event_id: int) -> dict:
        self.resolved.append(event_id)
        return {"ok": True}

    def metrics_overview(self, window_seconds: int = 600) -> dict:
        return dict(self.metrics)

    # -- A7 第 6 节渠道方法 ---------------------------------------------
    def list_channels(self) -> dict:
        return {"items": [dict(item) for item in self.channels]}

    def create_channel(self, kind, name, url, secret="", enabled=True) -> dict:
        self.channel_created.append(
            {
                "kind": kind,
                "name": name,
                "url": url,
                "secret": secret,
                "enabled": enabled,
            }
        )
        return {"ok": True, "id": 42}

    def update_channel(self, channel_id: int, **fields) -> dict:
        self.channel_updated.append((channel_id, fields))
        return {"ok": True}

    def delete_channel(self, channel_id: int) -> dict:
        self.channel_deleted.append(channel_id)
        return {"ok": True}

    def test_channel(self, channel_id: int) -> dict:
        self.channel_tested.append(channel_id)
        return {"ok": True}

    def channel_deliveries(
        self, status: str = "", limit: int = 200, offset: int = 0
    ) -> dict:
        self.delivery_queries.append(
            {"status": status, "limit": limit, "offset": offset}
        )
        rows = [row for row in self.deliveries if not status or row["status"] == status]
        return {
            "items": [dict(row) for row in rows[offset:offset + limit]],
            "total": len(rows),
        }


class AlertCenterPageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = FakeClient()
        self.messages: list[tuple[str, str]] = []

        def notify(message: str, kind: str = "info", msec: int = 3000) -> None:
            self.messages.append((kind, message))

        self.notify = notify

    # ------------------------------------------------------------ 构造
    def test_page_constructs_with_tabs_and_metric_cards(self) -> None:
        page = AlertCenterPage(self.client, self.notify)
        self.assertEqual(page.tabs.count(), 3)
        self.assertEqual(
            [page.tabs.tabText(index) for index in range(3)],
            ["告警规则", "告警事件", "通知渠道"],
        )
        self.assertEqual(len(page.cards), 7)
        for metric in METRIC_KEYS:
            self.assertIn(metric, page.cards)
            self.assertEqual(page.cards[metric].value_label.text(), "—")
        self.assertEqual(page.events_timer.interval(), 15000)
        page.deleteLater()

    # ------------------------------------------------------------ 列表
    def test_tables_follow_client_data(self) -> None:
        page = AlertCenterPage(self.client, self.notify)
        page.refresh()

        self.assertEqual(page.rules_table.rowCount(), 2)
        self.assertEqual(page.rules_count_label.text(), "共 2 条")
        self.assertEqual(page.rules_table.item(0, 1).text(), "激活率")
        self.assertEqual(page.rules_table.item(0, 2).text(), "＜ 80")
        self.assertEqual(page.rules_table.item(1, 7).text(), "● 停用")

        self.assertEqual(page.events_table.rowCount(), 2)
        self.assertEqual(page.events_count_label.text(), "共 2 条")
        self.assertEqual(page.events_table.item(0, 1).text(), "激活率过低")
        self.assertEqual(page.events_table.item(0, 7).text(), "是")
        self.assertEqual(self.client.event_queries[-1]["limit"], 200)

        self.assertEqual(page.cards["online_devices"].value_label.text(), "3 台")
        self.assertEqual(page.cards["activation_rate"].value_label.text(), "91.5%")
        page.deleteLater()

    def test_event_status_filter_queries_backend(self) -> None:
        page = AlertCenterPage(self.client, self.notify)
        page.refresh_events()
        self.assertEqual(page.events_table.rowCount(), 2)

        page.event_status.setCurrentIndex(1)  # 触发中 → firing
        self.assertEqual(self.client.event_queries[-1]["status"], "firing")
        self.assertEqual(page.events_table.rowCount(), 1)
        self.assertEqual(page.events_table.item(0, 0).text(), "2026-10-07 10:00:00")
        page.deleteLater()

    def test_missing_metrics_degrade_to_dash(self) -> None:
        class MetricsDownClient(FakeClient):
            def metrics_overview(self, window_seconds: int = 600) -> dict:
                raise ApiError("指标接口不可用")

        page = AlertCenterPage(MetricsDownClient(), self.notify)
        page.refresh_metrics()
        for metric in METRIC_KEYS:
            self.assertEqual(page.cards[metric].value_label.text(), "—")
        page.deleteLater()

    # ------------------------------------------------------------ 规则对话框
    def test_rule_dialog_create_calls_client_with_fields(self) -> None:
        dialog = AlertRuleDialog(self.client, self.notify)
        dialog.name.setText("高风控事件")
        dialog.metric.setCurrentIndex(dialog.metric.findData("risk_events"))
        dialog.operator.setCurrentIndex(dialog.operator.findData("gt"))
        dialog.threshold.setValue(5.5)
        dialog.window_seconds.setValue(1800)
        dialog.severity.setCurrentIndex(dialog.severity.findData("critical"))
        dialog.cooldown_seconds.setValue(120)
        dialog.note.setText("测试备注")
        dialog.submit()

        self.assertEqual(dialog.result(), QDialog.Accepted)
        self.assertEqual(
            self.client.created,
            [
                {
                    "name": "高风控事件",
                    "metric": "risk_events",
                    "operator": "gt",
                    "threshold": 5.5,
                    "window_seconds": 1800,
                    "severity": "critical",
                    "cooldown_seconds": 120,
                    "channels": ["email"],
                    "enabled": True,
                    "note": "测试备注",
                }
            ],
        )
        dialog.deleteLater()

    def test_rule_dialog_edit_prefills_and_updates(self) -> None:
        dialog = AlertRuleDialog(self.client, self.notify, self.client.rules[0])
        self.assertEqual(dialog.name.text(), "激活率过低")
        self.assertTrue(dialog.channels.isChecked())
        self.assertTrue(dialog.enabled.isChecked())
        dialog.threshold.setValue(75.0)
        dialog.submit()

        self.assertEqual(len(self.client.updated), 1)
        rule_id, fields = self.client.updated[0]
        self.assertEqual(rule_id, 1)
        self.assertEqual(fields["threshold"], 75.0)
        self.assertEqual(fields["metric"], "activation_rate")
        self.assertEqual(fields["operator"], "lt")
        dialog.deleteLater()

    def test_rule_dialog_keeps_actions_on_create(self) -> None:
        dialog = AlertRuleDialog(self.client, self.notify)
        dialog.name.clear()
        dialog.submit()
        self.assertEqual(self.client.created, [])
        self.assertTrue(any(kind == "warning" for kind, _ in self.messages))
        dialog.deleteLater()

    # ------------------------------------------------------------ 事件操作
    def test_event_ack_calls_client(self) -> None:
        page = AlertCenterPage(self.client, self.notify)
        page.refresh_events()
        page.events_table.selectRow(0)
        page.ack_event()

        self.assertEqual(self.client.acked, [11])
        self.assertEqual(self.client.resolved, [])
        self.assertTrue(any(kind == "success" for kind, _ in self.messages))
        page.deleteLater()

    def test_event_resolve_calls_client(self) -> None:
        page = AlertCenterPage(self.client, self.notify)
        page.refresh_events()
        page.events_table.selectRow(1)
        page.resolve_event()
        self.assertEqual(self.client.resolved, [12])
        page.deleteLater()

    # ------------------------------------------------------------ 删除失败
    def test_delete_failure_message_is_surfaced_verbatim(self) -> None:
        self.client.delete_error = "仅主控账号可删除"
        page = AlertCenterPage(self.client, self.notify)
        page.refresh_rules()
        page.rules_table.selectRow(0)
        with mock.patch("core.alert_center.confirm", return_value=True):
            page.delete_rule()

        self.assertEqual(self.client.deleted, [1])
        self.assertIn(("error", "仅主控账号可删除"), self.messages)
        self.assertEqual(page.rules_table.rowCount(), 2)
        page.deleteLater()

    # ------------------------------------------------------------ 定时器
    def test_auto_refresh_is_inert_while_page_is_hidden(self) -> None:
        page = AlertCenterPage(self.client, self.notify)
        page._auto_refresh()
        self.assertEqual(self.client.event_queries, [])
        page.deleteLater()
        # 窗口销毁后触发一个待处理的定时器信号也不应抛 RuntimeError。
        page._auto_refresh()

    # --------------------------------------------------------- 通知渠道页
    def test_channels_tab_is_the_third_tab(self) -> None:
        page = AlertCenterPage(self.client, self.notify)
        self.assertEqual(page.tabs.count(), 3)
        self.assertEqual(page.tabs.widget(2), page.channels_tab)
        self.assertEqual(page.tabs.tabText(2), "通知渠道")
        self.assertEqual(
            [
                page.channels_table.horizontalHeaderItem(col).text()
                for col in range(page.channels_table.columnCount())
            ],
            ["名称", "类型", "地址", "启用", "状态"],
        )
        self.assertEqual(
            [
                page.deliveries_table.horizontalHeaderItem(col).text()
                for col in range(page.deliveries_table.columnCount())
            ],
            ["时间", "渠道", "主题", "状态", "次数", "错误"],
        )
        page.deleteLater()

    def test_channels_and_deliveries_tables_follow_client_data(self) -> None:
        page = AlertCenterPage(self.client, self.notify)
        page.refresh_channels()
        self.assertEqual(page.channels_table.rowCount(), 3)
        self.assertEqual(page.channels_count_label.text(), "共 3 条")
        self.assertEqual(page.channels_table.item(0, 0).text(), "运维 Webhook")
        self.assertEqual(page.channels_table.item(0, 1).text(), "Webhook")
        self.assertEqual(page.channels_table.item(0, 3).text(), "● 启用")
        self.assertEqual(page.channels_table.item(1, 3).text(), "● 停用")
        self.assertEqual(page.channels_table.item(0, 4).text(), "密钥已配置")

        page.refresh_deliveries()
        self.assertEqual(page.deliveries_table.rowCount(), 2)
        self.assertEqual(page.deliveries_count_label.text(), "共 2 条")
        self.assertEqual(page.deliveries_table.item(0, 1).text(), "运维 Webhook")
        self.assertEqual(page.deliveries_table.item(0, 3).text(), "● 已发送")
        self.assertEqual(page.deliveries_table.item(0, 4).text(), "1")
        self.assertEqual(
            page.deliveries_table.item(1, 5).text(), "HTTP 500：内部错误"
        )
        self.assertEqual(self.client.delivery_queries[-1]["limit"], 200)
        self.assertEqual(self.client.delivery_queries[-1]["offset"], 0)

        page.delivery_status.setCurrentIndex(
            page.delivery_status.findData("failed")
        )
        self.assertEqual(self.client.delivery_queries[-1]["status"], "failed")
        self.assertEqual(page.deliveries_table.rowCount(), 1)
        self.assertEqual(page.deliveries_table.item(0, 3).text(), "● 失败")
        page.deleteLater()

    def test_delivery_table_only_shows_first_page(self) -> None:
        self.client.deliveries = [
            {
                "id": index,
                "channel_id": 1,
                "channel_name": "运维 Webhook",
                "subject": f"告警 {index}",
                "status": "sent",
                "attempts": 0,
                "last_error": None,
                "created_at": "2026-10-07 10:00:00",
            }
            for index in range(260)
        ]
        page = AlertCenterPage(self.client, self.notify)
        page.refresh_deliveries()
        self.assertEqual(page.deliveries_table.rowCount(), 200)
        self.assertEqual(page.deliveries_count_label.text(), "显示 200 / 共 260 条")
        self.assertEqual(self.client.delivery_queries[-1]["limit"], 200)
        self.assertEqual(self.client.delivery_queries[-1]["offset"], 0)
        page.deleteLater()

    # ------------------------------------------------------------ 渠道对话框
    def test_channel_dialog_create_sends_all_fields(self) -> None:
        dialog = ChannelDialog(self.client, self.notify)
        dialog.kind.setCurrentIndex(dialog.kind.findData("dingtalk"))
        dialog.name.setText("值班群")
        dialog.url.setText("https://oapi.dingtalk.com/robot/send?access_token=abc")
        dialog.secret.setText("SECret")
        dialog.enabled.setChecked(False)
        dialog.submit()

        self.assertEqual(dialog.result(), QDialog.Accepted)
        self.assertEqual(
            self.client.channel_created,
            [
                {
                    "kind": "dingtalk",
                    "name": "值班群",
                    "url": "https://oapi.dingtalk.com/robot/send?access_token=abc",
                    "secret": "SECret",
                    "enabled": False,
                }
            ],
        )
        dialog.deleteLater()

    def test_channel_dialog_edit_keeps_secret_when_blank(self) -> None:
        channel = self.client.channels[0]
        dialog = ChannelDialog(self.client, self.notify, channel)
        self.assertEqual(dialog.kind.currentData(), "webhook")
        self.assertEqual(dialog.name.text(), "运维 Webhook")
        self.assertEqual(dialog.url.text(), channel["url"])
        self.assertEqual(dialog.secret.text(), "")
        self.assertIn("留空", dialog.secret.placeholderText())
        dialog.name.setText("运维 Webhook 2")
        dialog.submit()

        self.assertEqual(len(self.client.channel_updated), 1)
        channel_id, fields = self.client.channel_updated[0]
        self.assertEqual(channel_id, 1)
        self.assertEqual(fields["name"], "运维 Webhook 2")
        self.assertEqual(fields["kind"], "webhook")
        self.assertTrue(fields["enabled"])
        self.assertNotIn("secret", fields)
        dialog.deleteLater()

    def test_channel_dialog_edit_sends_new_secret(self) -> None:
        dialog = ChannelDialog(self.client, self.notify, self.client.channels[2])
        dialog.secret.setText("new-secret")
        dialog.submit()
        _channel_id, fields = self.client.channel_updated[0]
        self.assertEqual(fields["secret"], "new-secret")
        dialog.deleteLater()

    # --------------------------------------------------------- 规则渠道多选
    def test_rule_dialog_lists_enabled_channels_and_saves_ids(self) -> None:
        dialog = AlertRuleDialog(self.client, self.notify)
        self.assertIn("channel:1", dialog.channel_boxes)
        self.assertIn("channel:3", dialog.channel_boxes)
        # 已停用的渠道不出现在规则编辑器里。
        self.assertNotIn("channel:2", dialog.channel_boxes)
        dialog.name.setText("多渠道规则")
        dialog.channel_boxes["channel:3"].setChecked(True)
        dialog.submit()

        self.assertEqual(len(self.client.created), 1)
        self.assertEqual(
            self.client.created[0]["channels"], ["email", "channel:3"]
        )
        dialog.deleteLater()

    def test_rule_dialog_edit_prefills_channel_checkbox(self) -> None:
        rule = dict(self.client.rules[0], channels=["email", "channel:1"])
        dialog = AlertRuleDialog(self.client, self.notify, rule)
        self.assertTrue(dialog.channel_boxes["channel:1"].isChecked())
        dialog.channel_boxes["channel:1"].setChecked(False)
        dialog.submit()

        _rule_id, fields = self.client.updated[-1]
        self.assertEqual(fields["channels"], ["email"])
        dialog.deleteLater()

    # ------------------------------------------------------------ 降级
    def test_channels_tab_degrades_when_api_unavailable(self) -> None:
        class ChannelsDownClient(FakeClient):
            def list_channels(self) -> dict:
                raise ApiError("渠道接口不可用")

            def channel_deliveries(
                self, status: str = "", limit: int = 200, offset: int = 0
            ) -> dict:
                raise ApiError("投递记录接口不可用")

        page = AlertCenterPage(ChannelsDownClient(), self.notify)
        page.refresh_channels()
        page.refresh_deliveries()
        self.assertEqual(page.channels_table.rowCount(), 0)
        self.assertEqual(page.deliveries_table.rowCount(), 0)
        self.assertIn("不可用", page.channels_count_label.text())
        self.assertIn("不可用", page.deliveries_count_label.text())
        self.assertTrue(any(kind == "error" for kind, _ in self.messages))
        page.deleteLater()

    def test_rule_dialog_keeps_email_when_channels_unavailable(self) -> None:
        class ChannelsDownClient(FakeClient):
            def list_channels(self) -> dict:
                raise ApiError("渠道接口不可用")

        client = ChannelsDownClient()
        dialog = AlertRuleDialog(client, self.notify)
        self.assertIn("不可用", dialog.channel_hint.text())
        dialog.name.setText("仅邮件规则")
        dialog.submit()
        self.assertEqual(dialog.result(), QDialog.Accepted)
        self.assertEqual(client.created[0]["channels"], ["email"])
        dialog.deleteLater()


if __name__ == "__main__":
    unittest.main()
