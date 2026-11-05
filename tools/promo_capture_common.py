"""Shared helpers for the promo-video client captures.

Renders the real PySide6 windows offscreen at 2x device pixel ratio so the
promo compositions can crop and zoom without softening the UI.

Environment knobs:
    PROMO_CAPTURE_DIR    output root (default: <workspace>/promo-video/assets/captures)
    PROMO_CAPTURE_SCALE  device pixel ratio (default 2)
"""

from __future__ import annotations

import os
import sys
import hashlib
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
_WINDOWS_FONTS = Path(r"C:\Windows\Fonts")
if _WINDOWS_FONTS.is_dir():
    # The offscreen platform ships no font database on Windows; pointing it
    # at the system font directory is what keeps CJK text from rendering as
    # tofu boxes.
    os.environ.setdefault("QT_QPA_FONTDIR", str(_WINDOWS_FONTS))

APP_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = APP_ROOT.parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

CAPTURES = Path(
    os.environ.get("PROMO_CAPTURE_DIR", WORKSPACE / "promo-video" / "assets" / "captures")
)
SCALE = int(os.environ.get("PROMO_CAPTURE_SCALE", "2"))

from PySide6.QtCore import QPoint, Qt  # noqa: E402
from PySide6.QtGui import QImage, QPainter  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402


def make_app() -> QApplication:
    """Create (or reuse) the QApplication with the product theme applied."""
    from core import theme

    app = QApplication.instance() or QApplication(sys.argv[:1])
    theme.apply_theme(app)
    return app


def pump(ms: int = 250) -> None:
    """Let layout, timers and deferred single-shots settle."""
    app = QApplication.instance()
    if app is not None:
        app.processEvents()
    QTest.qWait(ms)
    if app is not None:
        app.processEvents()


def render_image(widget, scale: int = SCALE) -> QImage:
    """Render one widget into a fresh image at ``scale`` device pixel ratio."""
    image = QImage(
        max(1, widget.width()) * scale,
        max(1, widget.height()) * scale,
        QImage.Format_ARGB32_Premultiplied,
    )
    image.setDevicePixelRatio(scale)
    image.fill(Qt.transparent)
    painter = QPainter(image)
    try:
        widget.render(painter, QPoint(0, 0))
    finally:
        painter.end()
    return image


def save_image(image: QImage, relpath: str | Path) -> Path:
    target = Path(relpath)
    if not target.is_absolute():
        target = CAPTURES / target
    target.parent.mkdir(parents=True, exist_ok=True)
    if not image.save(str(target)):
        raise RuntimeError(f"cannot save {target}")
    print(f"saved {target}  ({image.width()}x{image.height()})")
    return target


def grab(widget, relpath: str | Path, scale: int = SCALE) -> Path:
    """Save ``widget`` as a PNG under the capture root."""
    return save_image(render_image(widget, scale), relpath)


# --------------------------------------------------------------------------
# Demo data.  Everything is deterministic so re-running the capture script
# produces byte-identical tables.
# --------------------------------------------------------------------------

STATS = {
    "total": 1286,
    "unused": 742,
    "active": 436,
    "frozen": 18,
    "revoked": 61,
    "expired": 29,
    "batches": 12,
    "devices": 508,
    "activations_today": 37,
    "activations_7d": 214,
}

LICENSES = [
    {
        "key_code": "GSQ-7K2M-4P9Q-8R3T-6V1W",
        "batch_no": "B20261001",
        "edition": "professional",
        "card_type": "duration",
        "status": "active",
        "duration_days": 365,
        "duration_unit": "year",
        "max_devices": 3,
        "bound_count": 2,
        "machine_codes": ["8F3A21C4D9E07B56", "2C77E1B4A0983F6D"],
        "created_at": "2026-10-01 09:15:22",
        "activated_at": "2026-10-01 09:41:05",
        "expires_at": "2027-10-01 09:41:05",
        "frozen_until": None,
        "note": "华东区客户",
    },
    {
        "key_code": "GSQ-3N8B-1X5C-7Z2D-9Q4F",
        "batch_no": "B20261001",
        "edition": "enterprise",
        "card_type": "duration",
        "status": "active",
        "duration_days": 730,
        "duration_unit": "day",
        "max_devices": 5,
        "bound_count": 3,
        "machine_codes": [
            "A1B2C3D4E5F60718",
            "0F1E2D3C4B5A6978",
            "9988776655443322",
        ],
        "created_at": "2026-10-01 09:15:22",
        "activated_at": "2026-10-01 10:02:47",
        "expires_at": "2028-09-30 10:02:47",
        "frozen_until": None,
        "note": "集团总部",
    },
    {
        "key_code": "GSQ-5H7J-9K1L-3M5N-7P9R",
        "batch_no": "B20260930",
        "edition": "standard",
        "card_type": "duration",
        "status": "frozen",
        "duration_days": 30,
        "duration_unit": "month",
        "max_devices": 1,
        "bound_count": 1,
        "machine_codes": ["7C9E1F3B5D7A9C2E"],
        "created_at": "2026-09-30 14:20:11",
        "activated_at": "2026-09-30 15:00:00",
        "expires_at": "2026-11-14 15:00:00",
        "frozen_until": "2026-10-06 00:00:00",
        "note": "客户申请临时冻结",
    },
    {
        "key_code": "GSQ-2B4D-6F8H-0J2L-4N6P",
        "batch_no": "B20260930",
        "edition": "professional",
        "card_type": "duration",
        "status": "active",
        "duration_days": 90,
        "duration_unit": "quarter",
        "max_devices": 2,
        "bound_count": 1,
        "machine_codes": ["3E5D7C9B1A2F4E68"],
        "created_at": "2026-09-30 10:11:03",
        "activated_at": "2026-09-30 10:30:22",
        "expires_at": "2026-12-29 10:30:22",
        "frozen_until": None,
        "note": "试用转正式",
    },
    {
        "key_code": "GSQ-8R6T-4V2W-0X8Y-6Z4A",
        "batch_no": "B20260929",
        "edition": "standard",
        "card_type": "duration",
        "status": "unused",
        "duration_days": 1,
        "duration_unit": "week",
        "max_devices": 1,
        "bound_count": 0,
        "machine_codes": [],
        "created_at": "2026-09-29 16:40:00",
        "activated_at": None,
        "expires_at": None,
        "frozen_until": None,
        "note": "渠道体验卡",
    },
    {
        "key_code": "GSQ-9Y7W-5V3U-1T9S-7R5Q",
        "batch_no": "B20260929",
        "edition": "standard",
        "card_type": "duration",
        "status": "expired",
        "duration_days": 12,
        "duration_unit": "hour",
        "max_devices": 1,
        "bound_count": 1,
        "machine_codes": ["6A4C2E0F8B7D5A39"],
        "created_at": "2026-09-29 08:30:00",
        "activated_at": "2026-09-29 08:35:12",
        "expires_at": "2026-09-29 20:35:12",
        "frozen_until": None,
        "note": "现场演示",
    },
    {
        "key_code": "GSQ-1A3C-5E7G-9J1L-3N5P",
        "batch_no": "B20260928",
        "edition": "enterprise",
        "card_type": "duration",
        "status": "revoked",
        "duration_days": 100,
        "duration_unit": "year",
        "max_devices": 8,
        "bound_count": 4,
        "machine_codes": [
            "1234123412341234",
            "8765432187654321",
            "1122334455667788",
            "8877665544332211",
        ],
        "created_at": "2026-09-28 09:00:00",
        "activated_at": "2026-09-28 09:20:00",
        "expires_at": "2126-09-14 09:20:00",
        "frozen_until": None,
        "note": "违规共享，已吊销",
    },
    {
        "key_code": "GSQ-4F6H-8J0K-2L4N-6P8R",
        "batch_no": "B20260928",
        "edition": "professional",
        "card_type": "duration",
        "status": "active",
        "duration_days": 45,
        "duration_unit": "minute",
        "max_devices": 1,
        "bound_count": 1,
        "machine_codes": ["5B7D9F1A3C5E7082"],
        "created_at": "2026-09-28 08:10:00",
        "activated_at": "2026-09-28 08:12:40",
        "expires_at": "2026-09-28 08:57:40",
        "frozen_until": None,
        "note": "",
    },
    {
        "key_code": "GSQ-6T8V-0X2Z-4B6D-8F0H",
        "batch_no": "B20260927",
        "edition": "standard",
        "card_type": "activation",
        "status": "active",
        "duration_days": 0,
        "duration_unit": "day",
        "activation_limit": 10,
        "activation_count": 3,
        "auto_revoked": 0,
        "max_devices": 0,
        "bound_count": 3,
        "machine_codes": [
            "A1B2C3D4E5F6A7B8",
            "9988776655443322",
            "7A7B7C7D7E7F8081",
        ],
        "created_at": "2026-09-27 11:05:00",
        "activated_at": "2026-09-27 11:20:31",
        "expires_at": None,
        "frozen_until": None,
        "note": "次卡客户",
    },
    {
        "key_code": "GSQ-2Z4X-6V8T-0R2P-4N6L",
        "batch_no": "B20260927",
        "edition": "standard",
        "card_type": "activation",
        "status": "revoked",
        "duration_days": 0,
        "duration_unit": "day",
        "activation_limit": 5,
        "activation_count": 5,
        "auto_revoked": 1,
        "max_devices": 0,
        "bound_count": 5,
        "machine_codes": [
            "1111222233334444",
            "5555666677778888",
            "9999000011112222",
            "3333444455556666",
            "7777888899990000",
        ],
        "created_at": "2026-09-27 10:00:00",
        "activated_at": "2026-09-27 10:04:11",
        "expires_at": None,
        "frozen_until": None,
        "note": "次数用尽自动吊销",
    },
    {
        "key_code": "GSQ-8L0N-2P4R-6T8V-0X2Z",
        "batch_no": "B20260926",
        "edition": "professional",
        "card_type": "duration",
        "status": "active",
        "duration_days": 6,
        "duration_unit": "month",
        "max_devices": 3,
        "bound_count": 2,
        "machine_codes": ["4D6F8A0C2E4B6801", "9C1E3A5B7D9F0C24"],
        "created_at": "2026-09-26 13:25:00",
        "activated_at": "2026-09-26 13:40:09",
        "expires_at": "2027-03-26 13:40:09",
        "frozen_until": None,
        "note": "设计团队",
    },
    {
        "key_code": "GSQ-0H2J-4L6N-8P0R-2T4V",
        "batch_no": "B20260926",
        "edition": "standard",
        "card_type": "duration",
        "status": "unused",
        "duration_days": 3,
        "duration_unit": "day",
        "max_devices": 1,
        "bound_count": 0,
        "machine_codes": [],
        "created_at": "2026-09-26 09:12:00",
        "activated_at": None,
        "expires_at": None,
        "frozen_until": None,
        "note": "",
    },
    {
        "key_code": "GSQ-6R8T-0V2X-4Z6B-8D0F",
        "batch_no": "B20260925",
        "edition": "enterprise",
        "card_type": "duration",
        "status": "unused",
        "duration_days": 2,
        "duration_unit": "year",
        "max_devices": 10,
        "bound_count": 0,
        "machine_codes": [],
        "created_at": "2026-09-25 15:30:00",
        "activated_at": None,
        "expires_at": None,
        "frozen_until": None,
        "note": "年度框架协议",
    },
    {
        "key_code": "GSQ-4N6P-8R0T-2V4X-6Z8B",
        "batch_no": "B20260925",
        "edition": "standard",
        "card_type": "duration",
        "status": "frozen",
        "duration_days": 20,
        "duration_unit": "hour",
        "max_devices": 2,
        "bound_count": 1,
        "machine_codes": ["2E4C6A8B0D1F3E5C"],
        "created_at": "2026-09-25 10:45:00",
        "activated_at": "2026-09-25 11:00:00",
        "expires_at": "2026-09-26 07:00:00",
        "frozen_until": "2026-10-04 12:00:00",
        "note": "风控排查中",
    },
]

BATCHES = [
    {
        "batch_no": "B20261001",
        "total": 200,
        "unused": 126,
        "active": 68,
        "frozen": 2,
        "revoked": 3,
        "exhausted": 0,
        "expired": 1,
        "created_at": "2026-10-01 09:15:22",
        "last_created_at": "2026-10-01 09:15:22",
        "created_by": "master",
        "note": "国庆活动批次",
    },
    {
        "batch_no": "B20260930",
        "total": 150,
        "unused": 84,
        "active": 52,
        "frozen": 5,
        "revoked": 6,
        "exhausted": 0,
        "expired": 3,
        "created_at": "2026-09-30 10:11:03",
        "last_created_at": "2026-09-30 14:20:11",
        "created_by": "admin01",
        "note": "华东区渠道",
    },
    {
        "batch_no": "B20260929",
        "total": 120,
        "unused": 63,
        "active": 41,
        "frozen": 3,
        "revoked": 8,
        "exhausted": 0,
        "expired": 5,
        "created_at": "2026-09-29 08:30:00",
        "last_created_at": "2026-09-29 16:40:00",
        "created_by": "admin01",
        "note": "渠道体验卡",
    },
    {
        "batch_no": "B20260928",
        "total": 100,
        "unused": 38,
        "active": 47,
        "frozen": 2,
        "revoked": 9,
        "exhausted": 0,
        "expired": 4,
        "created_at": "2026-09-28 08:10:00",
        "last_created_at": "2026-09-28 09:00:00",
        "created_by": "master",
        "note": "企业客户批量",
    },
    {
        "batch_no": "B20260927",
        "total": 80,
        "unused": 24,
        "active": 31,
        "frozen": 1,
        "revoked": 12,
        "exhausted": 9,
        "expired": 3,
        "created_at": "2026-09-27 10:00:00",
        "last_created_at": "2026-09-27 11:05:00",
        "created_by": "admin02",
        "note": "激活次数卡测试",
    },
    {
        "batch_no": "B20260926",
        "total": 96,
        "unused": 41,
        "active": 46,
        "frozen": 2,
        "revoked": 4,
        "exhausted": 0,
        "expired": 3,
        "created_at": "2026-09-26 09:12:00",
        "last_created_at": "2026-09-26 13:25:00",
        "created_by": "admin01",
        "note": "设计团队月卡",
    },
    {
        "batch_no": "B20260925",
        "total": 60,
        "unused": 33,
        "active": 19,
        "frozen": 3,
        "revoked": 2,
        "exhausted": 0,
        "expired": 3,
        "created_at": "2026-09-25 10:45:00",
        "last_created_at": "2026-09-25 15:30:00",
        "created_by": "master",
        "note": "年度框架协议",
    },
    {
        "batch_no": "B20260921",
        "total": 300,
        "unused": 233,
        "active": 42,
        "frozen": 0,
        "revoked": 17,
        "exhausted": 0,
        "expired": 8,
        "created_at": "2026-09-21 08:00:00",
        "last_created_at": "2026-09-21 08:00:00",
        "created_by": "master",
        "note": "季度备货",
    },
]

LOGS = [
    {
        "id": 2141,
        "created_at": "2026-10-01 10:02:47",
        "actor": "admin01",
        "action": "activate",
        "target": "GSQ-3N8B-1X5C-7Z2D-9Q4F",
        "result": "success",
        "ip": "192.168.1.24",
        "detail": "设备 0F1E2D3C4B5A6978",
    },
    {
        "id": 2140,
        "created_at": "2026-10-01 09:41:05",
        "actor": "admin01",
        "action": "activate",
        "target": "GSQ-7K2M-4P9Q-8R3T-6V1W",
        "result": "success",
        "ip": "192.168.1.24",
        "detail": "设备 8F3A21C4D9E07B56",
    },
    {
        "id": 2139,
        "created_at": "2026-10-01 09:15:22",
        "actor": "master",
        "action": "generate",
        "target": "B20261001",
        "result": "success",
        "ip": "127.0.0.1",
        "detail": "批量生成 200 个密钥（专业版 / 年卡）",
    },
    {
        "id": 2138,
        "created_at": "2026-10-01 08:58:10",
        "actor": "master",
        "action": "login",
        "target": "-",
        "result": "success",
        "ip": "127.0.0.1",
        "detail": "主控端登录",
    },
    {
        "id": 2137,
        "created_at": "2026-09-30 15:00:00",
        "actor": "admin01",
        "action": "freeze",
        "target": "GSQ-5H7J-9K1L-3M5N-7P9R",
        "result": "success",
        "ip": "192.168.1.24",
        "detail": "冻结至 2026-10-06（客户申请）",
    },
    {
        "id": 2136,
        "created_at": "2026-09-30 12:01:00",
        "actor": "admin01",
        "action": "renew",
        "target": "GSQ-2B4D-6F8H-0J2L-4N6P",
        "result": "success",
        "ip": "192.168.1.24",
        "detail": "续期 90 天",
    },
    {
        "id": 2135,
        "created_at": "2026-09-30 11:20:02",
        "actor": "-",
        "action": "verify",
        "target": "GSQ-1A3C-5E7G-9J1L-3N5P",
        "result": "failure",
        "ip": "192.168.1.44",
        "detail": "密钥已吊销",
    },
    {
        "id": 2134,
        "created_at": "2026-09-30 10:11:03",
        "actor": "admin01",
        "action": "generate",
        "target": "B20260930",
        "result": "success",
        "ip": "192.168.1.24",
        "detail": "批量生成 150 个密钥（标准版 / 月卡）",
    },
    {
        "id": 2133,
        "created_at": "2026-09-29 16:40:00",
        "actor": "admin01",
        "action": "revoke_batch",
        "target": "B20260922",
        "result": "success",
        "ip": "192.168.1.24",
        "detail": "整批吊销 87 个密钥",
    },
    {
        "id": 2132,
        "created_at": "2026-09-29 14:22:31",
        "actor": "master",
        "action": "restore",
        "target": "GSQ-6T8V-0X2Z-4B6D-8F0H",
        "result": "success",
        "ip": "127.0.0.1",
        "detail": "恢复密钥并清空冻结状态",
    },
    {
        "id": 2131,
        "created_at": "2026-09-29 09:05:44",
        "actor": "verification",
        "action": "offline_verify",
        "target": "GSQ-4N6P-8R0T-2V4X-6Z8B",
        "result": "success",
        "ip": "离线",
        "detail": "离线激活码校验通过（RSA 签名有效）",
    },
    {
        "id": 2130,
        "created_at": "2026-09-28 09:20:00",
        "actor": "master",
        "action": "revoke",
        "target": "GSQ-1A3C-5E7G-9J1L-3N5P",
        "result": "success",
        "ip": "127.0.0.1",
        "detail": "违规共享，吊销并解绑全部设备",
    },
    {
        "id": 2129,
        "created_at": "2026-09-28 08:12:40",
        "actor": "admin02",
        "action": "activate",
        "target": "GSQ-4F6H-8J0K-2L4N-6P8R",
        "result": "failure",
        "ip": "192.168.1.51",
        "detail": "激活次数已用尽",
    },
]

ADMINS = [
    {
        "id": 1,
        "username": "master",
        "role": "master",
        "status": "active",
        "created_at": "2026-09-01 08:00:00",
        "last_login_at": "2026-10-01 08:58:10",
    },
    {
        "id": 2,
        "username": "admin01",
        "role": "admin",
        "status": "active",
        "created_at": "2026-09-02 08:00:00",
        "last_login_at": "2026-10-01 09:41:05",
    },
    {
        "id": 3,
        "username": "admin02",
        "role": "admin",
        "status": "active",
        "created_at": "2026-09-05 09:30:00",
        "last_login_at": "2026-09-30 18:22:31",
    },
    {
        "id": 4,
        "username": "ops-viewer",
        "role": "admin",
        "status": "disabled",
        "created_at": "2026-09-12 14:00:00",
        "last_login_at": "2026-09-12 14:05:12",
    },
]

AI_STATUS = {
    "enabled": True,
    "configured": True,
    "ai_provider": "DeepSeek",
    "ai_api_mode": "chat_completions",
    "ai_model": "deepseek-chat",
    "monitor_interval": 8,
    "server": {"time": "2026-10-01 10:05:12"},
    "stats": {
        "total": STATS["total"],
        "active": STATS["active"],
        "devices": STATS["devices"],
        "revoked": STATS["revoked"],
    },
    "logs": LOGS[:6],
}

AI_CONFIG = {
    "provider": "DeepSeek",
    "vendor_name": "DeepSeek",
    "api_mode": "chat_completions",
    "model": "deepseek-chat",
    "base_url": "https://api.deepseek.com/v1",
    "reasoning_effort": "medium",
}

AI_CONVERSATION = [
    {
        "role": "user",
        "content": "列出 7 天内即将到期的密钥，并吊销批次 B20260922。",
    },
    {
        "role": "assistant",
        "content": (
            "已查询到 **3 个密钥** 将在 7 天内到期：\n\n"
            "| 密钥 | 版本 | 到期时间 |\n"
            "| --- | --- | --- |\n"
            "| GSQ-5H7J-9K1L-3M5N-7P9R | 标准版 | 2026-10-06 15:00 |\n"
            "| GSQ-9Y7W-5V3U-1T9S-7R5Q | 标准版 | 2026-10-04 08:35 |\n"
            "| GSQ-4N6P-8R0T-2V4X-6Z8B | 标准版 | 2026-10-03 07:00 |\n\n"
            "批次 **B20260922** 共 87 个密钥已整批吊销，操作日志已记录。"
        ),
        "reasoning": (
            "先调用 license_query 按 expires_at 排序筛选 7 天内到期的密钥；"
            "再确认批次 B20260922 的存在与范围，用户已明确要求吊销，直接执行 "
            "batch_revoke，最后回读批次状态确认 87 个密钥全部为 revoked。"
        ),
        "tools": ["license_query", "batch_revoke"],
        "model": "deepseek-chat",
    },
]

MASTER_USER = {"username": "master", "role": "master", "must_change_password": False}
ADMIN_USER = {"username": "admin01", "role": "admin", "must_change_password": False}

DEVICE_NAMES = [
    "DESIGN-PC-07",
    "FINANCE-NB-12",
    "ENG-WS-03",
    "OPS-SRV-01",
    "QC-PC-21",
    "DEV-MAC-09",
    "SALES-NB-18",
    "TEST-VM-04",
]


def _demo_activations(license_row: dict) -> list[dict]:
    """Build device-binding rows for the key-detail dialog."""
    status = str(license_row.get("status") or "active")
    rows = []
    for index, code in enumerate(license_row.get("machine_codes") or []):
        row_status = "active"
        if status == "revoked":
            row_status = "revoked"
        elif status == "frozen" and index == 0:
            row_status = "frozen"
        rows.append(
            {
                "device_name": DEVICE_NAMES[index % len(DEVICE_NAMES)],
                "machine_code": code,
                "status": row_status,
                "activated_at": license_row.get("activated_at")
                or license_row.get("created_at")
                or "—",
                "expires_at": license_row.get("expires_at"),
            }
        )
    return rows


class FakeClient:
    """Deterministic stand-in for :class:`core.api_client.ApiClient`."""

    def __init__(self, *, offset: int = 0) -> None:
        self.base_url = "http://127.0.0.1:8765"
        self.offline_public_key = ""
        self._offset = offset
        self._session_cleared = False

    # -- connection ------------------------------------------------------
    def set_base_url(self, url: str) -> None:
        self.base_url = url

    def clear_session(self) -> None:
        self._session_cleared = True

    def health(self) -> dict:
        return {"version": "1.0.0", "time": "2026-10-01 10:05:12"}

    def me(self) -> dict:
        return MASTER_USER

    # -- data ------------------------------------------------------------
    def stats(self) -> dict:
        return dict(STATS)

    def list_licenses(self, **params) -> dict:
        items = [dict(item) for item in LICENSES]
        keyword = str(params.get("keyword") or "").strip().lower()
        status = str(params.get("status") or "")
        batch_no = str(params.get("batch_no") or "")
        if keyword:
            items = [
                item
                for item in items
                if keyword
                in " ".join(
                    [
                        str(item.get("key_code", "")),
                        str(item.get("note", "")),
                        str(item.get("batch_no", "")),
                    ]
                ).lower()
            ]
        if status:
            items = [item for item in items if item.get("status") == status]
        if batch_no:
            items = [item for item in items if item.get("batch_no") == batch_no]
        total = len(items)
        limit = int(params.get("limit") or 20)
        offset = int(params.get("offset") or 0)
        return {"items": items[offset : offset + limit], "total": total}

    def license_detail(self, key_code: str) -> dict:
        for item in LICENSES:
            if item["key_code"] == key_code:
                detail = dict(item)
                detail.setdefault("activation_limit", 0)
                detail.setdefault("activation_count", 0)
                detail.setdefault("auto_revoked", 0)
                return {
                    "license": detail,
                    "activations": _demo_activations(detail),
                }
        raise AssertionError(f"unknown key {key_code}")

    def list_batches(self, **params) -> dict:
        items = [dict(item) for item in BATCHES]
        keyword = str(params.get("keyword") or "").strip().lower()
        if keyword:
            items = [
                item
                for item in items
                if keyword
                in f"{item.get('batch_no')} {item.get('note')}".lower()
            ]
        total = len(items)
        limit = int(params.get("limit") or 50)
        offset = int(params.get("offset") or 0)
        return {"items": items[offset : offset + limit], "total": total}

    def list_logs(self, limit: int = 200, **params) -> dict:
        items = [dict(item) for item in LOGS]
        keyword = str(params.get("keyword") or "").strip().lower()
        action = str(params.get("action") or "")
        if action:
            items = [item for item in items if item.get("action") == action]
        if keyword:
            items = [
                item
                for item in items
                if keyword
                in " ".join(str(value) for value in item.values()).lower()
            ]
        total = len(items)
        offset = int(params.get("offset") or 0)
        return {"items": items[offset : offset + limit], "total": total}

    def list_admins(self) -> dict:
        return {"items": [dict(item) for item in ADMINS]}

    # -- AI --------------------------------------------------------------
    def ai_status(self) -> dict:
        return dict(AI_STATUS)

    def ai_config(self) -> dict:
        return dict(AI_CONFIG)

    # -- mutations (only used to populate "after" states) ----------------
    def generate_licenses(self, **payload) -> dict:
        prefix = str(payload.get("prefix") or "GSQ").upper()
        count = min(int(payload.get("count") or 1), 500)
        keys = [f"{prefix}-{self._code(index)}" for index in range(count)]
        return {
            "keys": keys,
            "batch_no": "B20261003",
            "count": count,
        }

    def _code(self, index: int) -> str:
        alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
        digest = hashlib.sha256(f"{self._offset}:{index}".encode()).digest()
        chars = [alphabet[byte % len(alphabet)] for byte in digest[:20]]
        return "-".join("".join(chars[start : start + 5]) for start in range(0, 20, 5))

    def offline_code(self, key_code: str, machine_code: str = "", device_name: str = "") -> dict:
        return {
            "code": (
                "LICACT1."
                "eyJraWQiOiJvZmZsaW5lLTIwMjYiLCJrZXkiOiJHU1EtN0syTS00UDlRLThS"
                "M1QtNlYxVyIsIm1jIjoiOEYzQTIxQzREOUUwN0I1NiIsImV4cCI6IjIwMjct"
                "MTAtMDEiLCJzaWciOiJSU0EtMjA0OCJ9"
            ),
            "key_code": key_code,
            "machine_code": machine_code,
            "expires_at": "2027-10-01 09:41:05",
            "duration_text": "年卡 · 365 天",
            "remaining": "365 天",
        }

    def revoke_batch(self, batch_no: str) -> dict:
        return {"batch_no": batch_no, "revoked": 87}

    def restore_batch(self, batch_no: str) -> dict:
        return {"batch_no": batch_no, "restored": 87}

    def freeze_license(self, key_code: str, amount: int, unit: str = "hour", reason: str = ""):
        return {"key_code": key_code, "amount": amount, "unit": unit, "reason": reason}

    def unfreeze_license(self, key_code: str) -> dict:
        return {"key_code": key_code}

    def renew_license(self, key_code: str, amount: int, unit: str = "day") -> dict:
        return {"key_code": key_code, "amount": amount, "unit": unit}

    def unbind(self, key_code: str, machine_code: str) -> dict:
        return {"key_code": key_code, "machine_code": machine_code}
