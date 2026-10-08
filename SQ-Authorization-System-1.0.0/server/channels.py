"""A7 通知渠道适配器与投递器（主流程模块）。

支持 Webhook / 钉钉 / 企微 / 飞书四种渠道：

- 统一写入 ``channel_outbox``，由后台线程投递、指数退避重试；
- Webhook 支持 HMAC-SHA256 签名头；钉钉/飞书支持官方加签；
- 任何渠道异常只影响该条投递，不影响规则引擎和授权主流程。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
import urllib.parse
from datetime import datetime, timedelta

import requests

from core import security

__all__ = [
    "CHANNEL_KINDS",
    "CHANNEL_LABELS",
    "ChannelError",
    "ChannelDispatcher",
    "backoff_seconds",
    "send_channel_message",
]

CHANNEL_KINDS = ("webhook", "dingtalk", "wecom", "feishu")

CHANNEL_LABELS = {
    "webhook": "Webhook",
    "dingtalk": "钉钉",
    "wecom": "企业微信",
    "feishu": "飞书",
}

MAX_BACKOFF_SECONDS = 3600
WORKER_INTERVAL_SECONDS = 5.0


class ChannelError(RuntimeError):
    """渠道配置无效或对方返回错误。"""


def backoff_seconds(attempt: int) -> int:
    """Exponential backoff matching the email outbox semantics."""
    try:
        number = max(1, int(attempt))
    except (TypeError, ValueError):
        number = 1
    return min(MAX_BACKOFF_SECONDS, 60 * (2 ** (number - 1)))


def _sign_hex(secret: str, body: bytes) -> str:
    return hmac.new(
        str(secret).encode("utf-8"), body, hashlib.sha256
    ).hexdigest()


def _dingtalk_sign(secret: str, timestamp_ms: int | None = None) -> tuple[str, str]:
    timestamp = str(timestamp_ms or int(time.time() * 1000))
    string_to_sign = f"{timestamp}\n{secret}"
    digest = hmac.new(
        str(secret).encode("utf-8"), string_to_sign.encode("utf-8"), hashlib.sha256
    ).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(digest).decode("ascii"))
    return timestamp, sign


def _feishu_sign(secret: str, timestamp: int | None = None) -> tuple[str, str]:
    moment = str(timestamp or int(time.time()))
    string_to_sign = f"{moment}\n{secret}"
    digest = hmac.new(
        string_to_sign.encode("utf-8"), digestmod=hashlib.sha256
    ).digest()
    return moment, base64.b64encode(digest).decode("ascii")


def _check_response(response, kind: str) -> dict:
    if response.status_code < 200 or response.status_code >= 300:
        excerpt = str(getattr(response, "text", "") or "")[:200]
        raise ChannelError(f"HTTP {response.status_code}：{excerpt}")
    try:
        data = response.json()
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}
    if kind == "dingtalk" and int(data.get("errcode") or 0) != 0:
        raise ChannelError(str(data.get("errmsg") or "钉钉返回错误"))
    if kind == "wecom" and int(data.get("errcode") or 0) != 0:
        raise ChannelError(str(data.get("errmsg") or "企业微信返回错误"))
    if kind == "feishu" and int(data.get("code") or 0) != 0:
        raise ChannelError(str(data.get("msg") or "飞书返回错误"))
    return data


def send_channel_message(
    kind,
    url,
    secret="",
    subject="",
    body="",
    payload=None,
    timeout=10.0,
) -> dict:
    """Send one message to a channel; raise ChannelError on failure."""
    channel = str(kind or "").strip().lower()
    target = str(url or "").strip()
    if channel not in CHANNEL_KINDS:
        raise ChannelError(f"不支持的通知渠道类型：{kind}")
    if not target.lower().startswith(("http://", "https://")):
        raise ChannelError("渠道地址必须是 http(s) URL")
    request_timeout = max(1.0, min(float(timeout or 10.0), 60.0))
    extra = payload if isinstance(payload, dict) else {}

    if channel == "webhook":
        data = {
            "event": str(subject or ""),
            "text": str(body or ""),
            "payload": extra,
        }
        raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if secret:
            headers["X-SQ-Signature"] = "sha256=" + _sign_hex(secret, raw)
        response = requests.post(
            target, data=raw, headers=headers, timeout=request_timeout, allow_redirects=False
        )
        return _check_response(response, channel)

    if channel == "dingtalk":
        data = {
            "msgtype": "markdown",
            "markdown": {"title": str(subject or "告警"), "text": str(body or "")},
        }
        params = {}
        if secret:
            timestamp, sign = _dingtalk_sign(secret)
            params = {"timestamp": timestamp, "sign": sign}
        response = requests.post(
            target,
            json=data,
            params=params,
            timeout=request_timeout,
            allow_redirects=False,
        )
        return _check_response(response, channel)

    if channel == "wecom":
        data = {
            "msgtype": "markdown",
            "markdown": {"content": str(body or "")},
        }
        response = requests.post(
            target, json=data, timeout=request_timeout, allow_redirects=False
        )
        return _check_response(response, channel)

    # feishu
    text = f"{subject}\n{body}" if subject else str(body or "")
    data = {"msg_type": "text", "content": {"text": text}}
    if secret:
        timestamp, sign = _feishu_sign(secret)
        data["timestamp"] = timestamp
        data["sign"] = sign
    response = requests.post(
        target, json=data, timeout=request_timeout, allow_redirects=False
    )
    return _check_response(response, channel)


class ChannelDispatcher:
    """Background worker draining ``channel_outbox``."""

    def __init__(self, db, transport=send_channel_message, interval: float = WORKER_INTERVAL_SECONDS):
        self.db = db
        self.transport = transport
        self.interval = max(1.0, float(interval or WORKER_INTERVAL_SECONDS))
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        stop_event = threading.Event()
        self._stop_event = stop_event
        self._thread = threading.Thread(
            target=self._loop,
            args=(stop_event,),
            name="sq-channel-dispatcher",
            daemon=True,
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
                self.process_due()
            except Exception:
                pass

    def process_due(self, limit: int = 20) -> int:
        """Deliver due messages; return the number sent successfully."""
        try:
            messages = self.db.claim_due_channel_messages(limit)
        except Exception:
            return 0
        sent = 0
        for message in messages or []:
            message_id = int(message.get("id") or 0)
            if message_id <= 0:
                continue
            try:
                payload = message.get("payload")
                if isinstance(payload, str):
                    try:
                        payload = json.loads(payload)
                    except Exception:
                        payload = {}
                self.transport(
                    str(message.get("kind") or ""),
                    str(message.get("url") or ""),
                    secret=str(message.get("secret") or ""),
                    subject=str(message.get("subject") or ""),
                    body=str(message.get("body") or ""),
                    payload=payload if isinstance(payload, dict) else {},
                    timeout=10.0,
                )
            except Exception as exc:
                attempts = int(message.get("attempts") or 0) + 1
                max_attempts = int(message.get("max_attempts") or 5)
                dead = attempts >= max_attempts
                retry_at = (
                    datetime.now() + timedelta(seconds=backoff_seconds(attempts))
                ).strftime(security.TIME_FORMAT)
                try:
                    self.db.mark_channel_message_failed(
                        message_id, str(exc)[:500], retry_at, dead=dead
                    )
                except Exception:
                    pass
                continue
            sent += 1
            # 已经投递成功；状态落库失败不能触发重发。
            try:
                self.db.mark_channel_message_sent(message_id)
            except Exception:
                pass
        return sent
