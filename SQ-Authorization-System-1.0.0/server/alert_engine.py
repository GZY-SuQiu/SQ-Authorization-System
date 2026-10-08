"""A5 可配置告警规则引擎（主流程模块）。

设计：

- 规则由 ``alert_rules`` 表持久化，管理端可视化配置；
- 引擎每 30 秒读取启用规则，按 ``window_seconds`` 计算指标并比较阈值；
- 同一规则同时只保留一个活动事件；事件恢复后写 ``resolved``；
- 冷却窗口内同一规则不会重复触发（防止指标抖动导致告警风暴）；
- 通知只走邮件（A5 阶段），收件人由 ``server.alerting`` 解析；
- 任何异常都必须被吞掉，告警引擎绝不能影响授权主流程。
"""

from __future__ import annotations

import threading
import time
from datetime import datetime

from core import security

from . import alerting

__all__ = [
    "METRIC_LABELS",
    "OPERATOR_LABELS",
    "SEVERITY_LABELS",
    "evaluate_condition",
    "window_text",
    "AlertEngine",
]

METRIC_LABELS = {
    "activation_rate": "激活率(%)",
    "online_devices": "在线并发(台)",
    "expiration_rate": "过期率(%)",
    "expiring_soon": "7 天内到期(个)",
    "failed_activations": "激活失败(次)",
    "risk_events": "风控事件(次)",
    "tamper_events": "完整性告警(次)",
}

OPERATOR_LABELS = {
    "gte": "≥",
    "gt": "＞",
    "lte": "≤",
    "lt": "＜",
    "eq": "=",
}

SEVERITY_LABELS = {
    "info": "提示",
    "warning": "警告",
    "critical": "严重",
}

_COMPARATORS = {
    "gte": lambda value, threshold: value >= threshold,
    "gt": lambda value, threshold: value > threshold,
    "lte": lambda value, threshold: value <= threshold,
    "lt": lambda value, threshold: value < threshold,
    "eq": lambda value, threshold: value == threshold,
}

_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


def evaluate_condition(value: float, operator: str, threshold: float) -> bool:
    """Return whether ``value <operator> threshold`` holds."""
    compare = _COMPARATORS.get(str(operator or "").strip().lower())
    if compare is None:
        return False
    try:
        return bool(compare(float(value), float(threshold)))
    except (TypeError, ValueError):
        return False


def window_text(seconds: int) -> str:
    """Human-readable window such as ``10 分钟`` or ``1 小时``."""
    try:
        total = max(1, int(seconds))
    except (TypeError, ValueError):
        total = 600
    if total % 3600 == 0 and total >= 3600:
        return f"{total // 3600} 小时"
    if total % 60 == 0 and total >= 60:
        return f"{total // 60} 分钟"
    return f"{total} 秒"


def _seconds_since(timestamp: str) -> float:
    try:
        moment = datetime.strptime(str(timestamp or ""), _TIME_FORMAT)
    except ValueError:
        return 10**9
    return max(0.0, (datetime.now() - moment).total_seconds())


class AlertEngine:
    """Periodic rule evaluator; thread lifecycle is idempotent."""

    def __init__(self, db, mailer, config, interval: float = 30.0):
        self.db = db
        self.mailer = mailer
        self.config = config
        self.interval = max(5.0, float(interval or 30.0))
        self.smtp_config = (getattr(config, "data", {}) or {}).get("smtp") or {}
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        stop_event = threading.Event()
        self._stop_event = stop_event
        self._thread = threading.Thread(
            target=self._loop, args=(stop_event,), name="sq-alert-engine", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        stop_event = getattr(self, "_stop_event", None)
        if stop_event is not None:
            stop_event.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=max(0.1, float(timeout)))
        # 只有线程确实退出才释放引用；否则 stop 超时后再 start 会留下两个 worker。
        if thread is None or not thread.is_alive():
            self._thread = None

    def _loop(self, stop_event: threading.Event) -> None:
        while not stop_event.wait(self.interval):
            try:
                self.evaluate_once()
            except Exception:
                # Alerting must never kill its own worker thread.
                pass

    # ------------------------------------------------------------------ #
    # Evaluation
    # ------------------------------------------------------------------ #
    def evaluate_once(self) -> list[dict]:
        """Evaluate every enabled rule once; return newly fired events.

        P2-15：同一个 tick 内按 window_seconds 缓存 ``db.alert_metrics``，
        同窗口的规则共享同一份 7 项指标，避免每条规则重复计算。
        """
        fired: list[dict] = []
        try:
            rules = self.db.list_alert_rules() or []
        except Exception:
            return fired
        metrics_by_window: dict[int, dict] = {}
        for rule in rules:
            if not isinstance(rule, dict) or not rule.get("enabled"):
                continue
            try:
                window = self._rule_window(rule)
                if window not in metrics_by_window:
                    metrics_by_window[window] = self.db.alert_metrics(window) or {}
                fired_event = self._evaluate_rule(rule, metrics_by_window[window])
            except Exception:
                continue
            if fired_event:
                fired.append(fired_event)
        return fired

    @staticmethod
    def _rule_window(rule: dict) -> int:
        """Parse the rule window exactly as ``_evaluate_rule`` consumes it."""
        try:
            return int(rule.get("window_seconds") or 600)
        except (TypeError, ValueError):
            return 600

    def _evaluate_rule(self, rule: dict, metrics: dict | None = None) -> dict | None:
        rule_id = int(rule.get("id") or 0)
        if rule_id <= 0:
            return None
        metric = str(rule.get("metric") or "").strip()
        operator = str(rule.get("operator") or "gte").strip().lower()
        try:
            threshold = float(rule.get("threshold") or 0)
        except (TypeError, ValueError):
            return None
        window = self._rule_window(rule)
        if metrics is None:
            # 兼容单独调用：没有 tick 级缓存时就地计算一次。
            metrics = self.db.alert_metrics(window) or {}
        try:
            value = float(metrics.get(metric) or 0.0)
        except (TypeError, ValueError):
            value = 0.0
        breached = evaluate_condition(value, operator, threshold)

        latest = None
        try:
            latest = self.db.get_latest_alert_event(rule_id)
        except Exception:
            latest = None

        if not breached:
            if latest and str(latest.get("status")) in ("firing", "acked"):
                try:
                    self.db.resolve_alert_event(int(latest.get("id") or 0))
                except Exception:
                    pass
            return None

        if latest and str(latest.get("status")) in ("firing", "acked"):
            return None
        if latest and str(latest.get("status")) == "resolved":
            try:
                cooldown = max(0, int(rule.get("cooldown_seconds") or 0))
            except (TypeError, ValueError):
                cooldown = 0
            if _seconds_since(latest.get("fired_at")) < cooldown:
                return None

        event_id = self.db.add_alert_event(
            rule_id=rule_id,
            rule_name=str(rule.get("name") or ""),
            metric=metric,
            value=value,
            threshold=threshold,
            operator=operator,
            severity=str(rule.get("severity") or "warning"),
            payload={"window_seconds": window, "metrics": metrics},
        )
        event_id = int(event_id or 0)
        if event_id:
            self._notify(rule, event_id, value, window)
        return {
            "rule_id": rule_id,
            "event_id": event_id,
            "metric": metric,
            "value": value,
            "threshold": threshold,
            "operator": operator,
        }

    # ------------------------------------------------------------------ #
    # Notification
    # ------------------------------------------------------------------ #
    def _notify(self, rule: dict, event_id: int, value: float, window: int) -> None:
        channels = rule.get("channels")
        if not isinstance(channels, list) or not channels:
            channels = ["email"]
        recipients = (
            alerting.admin_alert_emails(self.db, self.smtp_config)
            if "email" in channels
            else []
        )
        metric = str(rule.get("metric") or "")
        operator = str(rule.get("operator") or "gte").lower()
        try:
            threshold = float(rule.get("threshold") or 0)
        except (TypeError, ValueError):
            threshold = 0.0
        severity = str(rule.get("severity") or "warning").lower()
        variables = {
            "rule_name": str(rule.get("name") or ""),
            "metric_label": METRIC_LABELS.get(metric, metric),
            "value": f"{value:g}",
            "operator": OPERATOR_LABELS.get(operator, operator),
            "threshold": f"{threshold:g}",
            "window_text": window_text(window),
            "severity": SEVERITY_LABELS.get(severity, severity),
            "time": datetime.now().strftime(_TIME_FORMAT),
        }
        sent = 0
        for email in recipients:
            try:
                outbox_id = self.mailer.enqueue(
                    email, "alert_rule", variables, dedupe_key=f"alert:{event_id}:{email}"
                )
            except Exception:
                outbox_id = None
            if outbox_id:
                sent += 1
        sent += self._notify_channels(channels, event_id, variables)
        if sent:
            try:
                self.db.mark_alert_event_notified(event_id)
            except Exception:
                pass

    def _notify_channels(self, channels, event_id: int, variables: dict) -> int:
        """Queue alert_rule messages to A7 webhook-style channels."""
        queued = 0
        for entry in channels or []:
            text = str(entry or "").strip()
            if not text.startswith("channel:"):
                continue
            try:
                channel_id = int(text.split(":", 1)[1])
            except (TypeError, ValueError):
                continue
            try:
                channel = self.db.get_notification_channel(channel_id)
            except Exception:
                channel = None
            if not channel or not channel.get("enabled"):
                continue
            try:
                from .mailer import DEFAULT_TEMPLATES, render_template

                template = DEFAULT_TEMPLATES["alert_rule"]
                subject = render_template(template["subject"], variables)
                body = render_template(template["body"], variables)
                message_id = self.db.enqueue_channel_message(
                    channel_id,
                    subject,
                    body,
                    payload={"event_id": event_id},
                    dedupe_key=f"alert:{event_id}:channel:{channel_id}",
                )
            except Exception:
                message_id = None
            if message_id:
                queued += 1
        return queued
