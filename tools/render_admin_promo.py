"""Render promo-ready captures of the management client.

The normal page renderer is tuned for layout review: it renders the master
shell once per page at 1x.  Promo captures need representative data, a clean
focus state, and a 2x raster so the UI stays sharp when it is scaled inside a
1920x1080 composition.

Usage:
    python tools/render_admin_promo.py [outdir]

Set ``PROMO_CAPTURE_SCALE=1`` to force a 1x render. The native Windows
platform is used by default because the offscreen backend can miss CJK
glyph shaping on some Windows installations.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

os.environ.setdefault(
    "QT_QPA_PLATFORM",
    os.environ.get("PROMO_CAPTURE_PLATFORM", "windows"),
)
os.environ.setdefault("PROMO_CAPTURE_SCALE", "2")
os.environ.setdefault("QT_SCALE_FACTOR", os.environ["PROMO_CAPTURE_SCALE"])

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from core import theme  # noqa: E402
from tools.render_pages import LOGS, FakeClient  # noqa: E402
from admin.ui import AdminWindow  # noqa: E402


PROMPT_BATCHES = [
    {
        "batch_no": "B20261003",
        "total": 50,
        "unused": 42,
        "active": 8,
        "frozen": 0,
        "revoked": 0,
        "exhausted": 0,
        "expired": 0,
        "created_at": "2026-10-03 09:20:00",
        "last_created_at": "2026-10-03 09:20:00",
        "created_by": "admin01",
        "note": "华东区客户",
    },
    {
        "batch_no": "B20260930",
        "total": 32,
        "unused": 18,
        "active": 13,
        "frozen": 1,
        "revoked": 0,
        "exhausted": 0,
        "expired": 0,
        "created_at": "2026-09-30 10:22:11",
        "last_created_at": "2026-09-30 10:22:11",
        "created_by": "admin01",
        "note": "渠道活动",
    },
    {
        "batch_no": "B20260928",
        "total": 24,
        "unused": 8,
        "active": 10,
        "frozen": 0,
        "revoked": 4,
        "exhausted": 2,
        "expired": 0,
        "created_at": "2026-09-28 14:00:00",
        "last_created_at": "2026-09-28 14:00:00",
        "created_by": "master",
        "note": "激活次数卡",
    },
    {
        "batch_no": "B20260921",
        "total": 22,
        "unused": 6,
        "active": 10,
        "frozen": 2,
        "revoked": 2,
        "exhausted": 0,
        "expired": 2,
        "created_at": "2026-09-21 08:00:00",
        "last_created_at": "2026-09-21 08:00:00",
        "created_by": "admin01",
        "note": "续期与冻结示例",
    },
]

PROMO_LOGS = [
    {
        "id": 430,
        "created_at": "2026-10-03 09:20:01",
        "actor": "admin01",
        "action": "generate",
        "target": "B20261003",
        "result": "success",
        "ip": "127.0.0.1",
        "detail": "批量生成 50 个专业版密钥",
    },
    {
        "id": 429,
        "created_at": "2026-10-03 09:18:44",
        "actor": "admin01",
        "action": "renew",
        "target": "SQAA-B2C3-D4E5-F6G7",
        "result": "success",
        "ip": "127.0.0.1",
        "detail": "续期 30 天",
    },
    {
        "id": 428,
        "created_at": "2026-10-03 09:12:10",
        "actor": "admin01",
        "action": "freeze",
        "target": "SQAA-9H8I-7J6K-5L4M",
        "result": "success",
        "ip": "127.0.0.1",
        "detail": "冻结 24 小时：风险排查",
    },
    {
        "id": 427,
        "created_at": "2026-10-03 09:05:37",
        "actor": "client",
        "action": "activate",
        "target": "SQAA-B2C3-D4E5-F6G7",
        "result": "success",
        "ip": "192.168.1.28",
        "detail": "设备 A1B2C3D4E5F6A7B8",
    },
    {
        "id": 426,
        "created_at": "2026-10-03 08:58:20",
        "actor": "client",
        "action": "verify",
        "target": "SQAA-6T7U-8V9W-0X1Y",
        "result": "failure",
        "ip": "192.168.1.44",
        "detail": "密钥已吊销",
    },
    {
        "id": 425,
        "created_at": "2026-10-03 08:40:02",
        "actor": "admin01",
        "action": "unbind",
        "target": "SQAA-9H8I-7J6K-5L4M",
        "result": "success",
        "ip": "127.0.0.1",
        "detail": "解绑机器码 0F1E2D3C4B5A6978",
    },
    *LOGS,
]

DURATION_KEYS = [
    f"SQ-PRO-{index:04d}-A7F2" for index in range(1, 21)
]
ACTIVATION_KEYS = [
    f"GSQ-ACT-{index:04d}-B8E1" for index in range(1, 31)
]


class PromoClient(FakeClient):
    """Stable, representative API responses used only for captures."""

    def health(self):
        return {"version": "1.0.0", "time": "2026-10-03 09:20:00"}

    def stats(self):
        return {
            "total": 128,
            "unused": 74,
            "active": 41,
            "frozen": 3,
            "revoked": 6,
            "expired": 4,
            "exhausted": 2,
            "devices": 41,
            "batches": 7,
            "activations_today": 5,
            "activations_7d": 22,
        }

    def list_licenses(self, **kwargs):
        items = [
            {
                "key_code": "SQAA-B2C3-D4E5-F6G7",
                "batch_no": "B20260930",
                "edition": "professional",
                "status": "active",
                "duration_days": 365,
                "duration_unit": "day",
                "max_devices": 3,
                "bound_count": 1,
                "machine_codes": ["A1B2C3D4E5F6A7B8"],
                "created_at": "2026-09-30 10:22:11",
                "activated_at": "2026-09-30 12:01:00",
                "expires_at": "2027-09-30 12:01:00",
                "frozen_until": None,
                "note": "华东区客户",
            },
            {
                "key_code": "SQAA-9H8I-7J6K-5L4M",
                "batch_no": "B20260930",
                "edition": "enterprise",
                "status": "frozen",
                "duration_days": 30,
                "duration_unit": "day",
                "max_devices": 3,
                "bound_count": 2,
                "machine_codes": ["0F1E2D3C4B5A6978", "8877665544332211"],
                "created_at": "2026-09-29 09:10:00",
                "activated_at": "2026-09-29 09:30:00",
                "expires_at": "2026-10-29 09:30:00",
                "frozen_until": "2026-10-05 00:00:00",
                "note": "风险排查",
            },
            {
                "key_code": "SQAA-0N1O-2P3Q-4R5S",
                "batch_no": "B20260921",
                "edition": "standard",
                "status": "unused",
                "duration_days": 1,
                "duration_unit": "year",
                "max_devices": 1,
                "bound_count": 0,
                "machine_codes": [],
                "created_at": "2026-09-21 08:00:00",
                "activated_at": None,
                "expires_at": None,
                "frozen_until": None,
                "note": "",
            },
            {
                "key_code": "SQAA-6T7U-8V9W-0X1Y",
                "batch_no": "B20260921",
                "edition": "standard",
                "status": "revoked",
                "duration_days": 90,
                "duration_unit": "day",
                "max_devices": 2,
                "bound_count": 1,
                "machine_codes": ["1234123412341234"],
                "created_at": "2026-09-20 08:00:00",
                "activated_at": "2026-09-20 09:00:00",
                "expires_at": "2026-12-19 09:00:00",
                "frozen_until": None,
                "note": "违规使用",
            },
            {
                "key_code": "GSQ-2A3B-4C5D-6E7F-8G9H",
                "batch_no": "B20260928",
                "edition": "standard",
                "card_type": "activation",
                "status": "active",
                "duration_days": 0,
                "duration_unit": "day",
                "activation_limit": 10,
                "activation_count": 3,
                "auto_revoked": 0,
                "max_devices": 0,
                "machine_codes": ["A1B2C3D4E5F6A7B8", "9988776655443322"],
                "created_at": "2026-10-01 09:15:00",
                "activated_at": "2026-10-01 09:20:00",
                "expires_at": None,
                "frozen_until": None,
                "note": "次卡客户",
            },
            {
                "key_code": "GSQ-9Z8Y-7X6W-5V4U-3T2S",
                "batch_no": "B20260928",
                "edition": "standard",
                "card_type": "activation",
                "status": "revoked",
                "duration_days": 0,
                "duration_unit": "day",
                "activation_limit": 5,
                "activation_count": 5,
                "auto_revoked": 1,
                "max_devices": 0,
                "machine_codes": ["1111222233334444", "5555666677778888"],
                "created_at": "2026-09-28 14:00:00",
                "activated_at": "2026-09-28 14:05:00",
                "expires_at": None,
                "frozen_until": None,
                "note": "次数已用尽",
            },
        ]
        keyword = str(kwargs.get("keyword") or "").lower()
        status = str(kwargs.get("status") or "")
        batch_no = str(kwargs.get("batch_no") or "")
        if keyword:
            items = [
                item
                for item in items
                if keyword
                in " ".join(
                    str(item.get(key) or "")
                    for key in ("key_code", "note", "batch_no")
                ).lower()
            ]
        if status:
            items = [item for item in items if item.get("status") == status]
        if batch_no:
            items = [item for item in items if item.get("batch_no") == batch_no]
        return {"items": items, "total": len(items)}

    def list_batches(self, keyword="", limit=500, offset=0, **kwargs):
        items = PROMPT_BATCHES
        if keyword:
            needle = str(keyword).lower()
            items = [
                item
                for item in items
                if needle
                in " ".join(
                    str(item.get(key) or "")
                    for key in ("batch_no", "note", "created_by")
                ).lower()
            ]
        return {"items": items[offset : offset + limit], "total": len(items)}

    def list_logs(self, limit=300, **kwargs):
        items = PROMO_LOGS
        keyword = str(kwargs.get("keyword") or "").lower()
        action = str(kwargs.get("action") or "")
        if keyword:
            items = [
                item
                for item in items
                if keyword
                in " ".join(str(value) for value in item.values()).lower()
            ]
        if action:
            items = [item for item in items if item.get("action") == action]
        return {"items": items[:limit], "total": len(items)}

    def generate_licenses(self, **kwargs):
        card_type = kwargs.get("card_type")
        keys = ACTIVATION_KEYS if card_type == "activation" else DURATION_KEYS
        count = int(kwargs.get("count") or 0)
        return {
            "keys": keys[:count],
            "batch_no": "B20261003",
        }

    def offline_code(self, key, machine, device=""):
        return {
            "key_code": key,
            "machine_code": machine,
            "duration_text": "365 天",
            "expires_at": "2027-10-03 09:20:00",
            "remaining": "365 天",
            "code": (
                "LICACT1."
                "SQ-PRO-0001-A7F2.A1B2C3D4E5F6A7B8."
                "eyJleHAiOjE4MjM1MDg4MDAsImRldmljZSI6IuWNjuS4nOWMuuWu"
                "ciJ9.Ed25519-Promo-Signature"
            ),
        }

    def ai_status(self):
        return {
            "enabled": True,
            "configured": True,
            "provider": "DeepSeek",
            "api_mode": "chat_completions",
            "model": "deepseek-chat",
            "monitor_interval": 30,
            "stats": {"total": 128, "active": 41, "devices": 41, "revoked": 6},
            "logs": PROMO_LOGS[:6],
            "server": {"time": "2026-10-03 09:20:00"},
        }


def _save_png(widget, path: Path) -> tuple[int, int, float]:
    pixmap = widget.grab()
    if not pixmap.save(str(path)):
        raise RuntimeError(f"could not save {path}")
    return pixmap.width(), pixmap.height(), float(pixmap.devicePixelRatio())


def _clear_focus(window) -> None:
    focus = QApplication.focusWidget()
    if focus is not None:
        focus.clearFocus()
    window.setFocus()
    QApplication.processEvents()


def _configure_generate(page, *, activation: bool) -> None:
    page.reset_form()
    page.count.setValue(30 if activation else 20)
    page.edition.setCurrentIndex(1 if activation else 1)
    page.card_mode.setCurrentIndex(1 if activation else 0)
    if activation:
        page.activation_limit.setValue(10)
        page.prefix.setText("GSQ")
        page.note.setText("渠道活动")
    else:
        page.unit.setCurrentIndex(2)
        page.duration.setValue(365)
        page.devices.setValue(3)
        page.prefix.setText("SQ-PRO")
        page.note.setText("华东区客户")
    page.generate()


def _configure_offline(page) -> None:
    page.key.setText("SQAA-B2C3-D4E5-F6G7")
    page.machine.setText("A1B2C3D4E5F6A7B8")
    page.device.setText("华东区工作站")
    page.generate()


def _configure_ai(page, *, thinking: bool) -> None:
    if thinking:
        page.conversation = [
            {
                "role": "user",
                "content": "检查今天的授权风险，并列出需要处理的密钥。",
            }
        ]
        page._request_id = 1
        page._pending = {"id": 1, "prompt": page.conversation[0]["content"], "index": 0}
        page._set_busy(True)
        page._render_conversation()
        page._start_live_view()
        page._on_chat_event(
            1,
            {
                "type": "reasoning",
                "text": "先检查最近验证失败记录，再核对冻结与即将到期的密钥。",
            },
        )
        page._on_chat_event(
            1,
            {"type": "tool", "name": "query_logs", "text": "查询最近验证失败记录"},
        )
        page._on_chat_event(
            1,
            {
                "type": "reasoning",
                "text": "发现 1 个已吊销密钥仍被尝试校验，另有 3 个密钥将在 7 天内到期。",
            },
        )
        page._on_chat_event(
            1,
            {"type": "tool", "name": "get_stats", "text": "汇总授权状态与到期风险"},
        )
    else:
        page.conversation = [
            {
                "role": "user",
                "content": "检查今天的授权风险，并列出需要处理的密钥。",
            },
            {
                "role": "assistant",
                "content": (
                    "今天有 1 个已吊销密钥仍在尝试校验，来源 192.168.1.44；"
                    "另有 3 个密钥将在 7 天内到期。建议先确认异常来源，"
                    "再为华东区客户完成续期。"
                ),
                "reasoning": (
                    "已核对最近 24 小时的验证失败记录，并与 7 天内到期的授权做交叉检查。"
                ),
                "tools": ["query_logs", "get_stats", "list_expiring"],
                "model": "deepseek-chat",
            },
        ]
        page._pending = None
        page._set_busy(False)
        page._render_conversation()
    QTest.qWait(80)
    bar = page.chat_area.verticalScrollBar()
    bar.setValue(bar.maximum())
    QApplication.processEvents()


def main() -> int:
    outdir = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "build" / "promo_admin")
    outdir.mkdir(parents=True, exist_ok=True)

    app = QApplication.instance() or QApplication(sys.argv[:1])
    theme.apply_theme(app)

    client = PromoClient()
    window = AdminWindow(client, {"username": "admin01", "role": "admin"})
    window.setAttribute(Qt.WA_DontShowOnScreen, True)
    window.resize(1440, 900)
    window.show()
    QTest.qWait(250)

    overview_index = window.stack.indexOf(window.overview)
    ai_index = window.stack.indexOf(window.ai)
    generate_index = window.stack.indexOf(window.generate)
    licenses_index = window.stack.indexOf(window.licenses)
    batches_index = window.stack.indexOf(window.batches)
    offline_index = window.stack.indexOf(window.offline)
    logs_index = window.stack.indexOf(window.logs)

    captures: list[dict] = []

    def capture(name: str, index: int, description: str) -> None:
        window.set_current_page(index)
        QTest.qWait(120)
        window.toast._timer.stop()
        window.toast.hide()
        _clear_focus(window)
        path = outdir / f"{name}.png"
        width, height, pixel_ratio = _save_png(window, path)
        captures.append(
            {
                "file": path.name,
                "description": description,
                "width": width,
                "height": height,
                "logical_width": round(width / pixel_ratio),
                "logical_height": round(height / pixel_ratio),
                "pixel_ratio": pixel_ratio,
            }
        )
        print(f"saved {path} ({width}x{height})")

    capture("admin-overview", overview_index, "管理端系统概览与实时统计")

    _configure_generate(window.generate, activation=False)
    capture("admin-generate-duration", generate_index, "批量生成时长卡密钥")

    _configure_generate(window.generate, activation=True)
    capture("admin-generate-activation", generate_index, "激活次数卡模式")

    capture("admin-licenses", licenses_index, "密钥管理、搜索与批量操作")
    capture("admin-batches", batches_index, "批次管理与整批操作")

    window.set_current_page(offline_index)
    _configure_offline(window.offline)
    capture("admin-offline", offline_index, "离线激活码签发")

    capture("admin-logs", logs_index, "审计日志与操作留痕")

    # The AI monitor column is deliberately information-dense; give it a
    # slightly taller canvas so the model and prompt controls stay readable.
    window.resize(1600, 1000)
    window.ai.monitor_logs.setMinimumHeight(96)
    window.ai.monitor_logs.setMaximumHeight(96)
    QTest.qWait(120)
    window.set_current_page(ai_index)
    _configure_ai(window.ai, thinking=False)
    capture("admin-ai", ai_index, "AI 助手最终回复、工具调用与模型信息")

    window.set_current_page(ai_index)
    _configure_ai(window.ai, thinking=True)
    capture("admin-ai-thinking", ai_index, "AI 助手实时思考与工具执行状态")

    manifest = {
        "role": "管理端",
        "captured_at": "2026-10-03T09:20:00+08:00",
        "render": {
            "base_window": "1440x900",
            "ai_window": "1600x1000",
            "scale": int(os.environ.get("PROMO_CAPTURE_SCALE", "2")),
            "platform": os.environ.get("QT_QPA_PLATFORM", "windows"),
            "theme": "SQ light",
        },
        "captures": captures,
    }
    (outdir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"saved {outdir / 'manifest.json'}")

    window.close()
    QTest.qWait(50)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
