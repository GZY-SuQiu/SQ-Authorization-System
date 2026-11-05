"""Render each PySide6 page offscreen to PNG for visual inspection.

Usage:  python tools/render_pages.py [outdir]
"""
from __future__ import annotations

import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication, QStyleFactory  # noqa: E402

from core import theme  # noqa: E402
from core.pages import (  # noqa: E402
    AboutPage,
    ChangePasswordPage,
    GeneratePage,
    LicensesPage,
    LogsPage,
    OfflinePage,
    OverviewPage,
)
from core.shell import AppShell  # noqa: E402

LICENSES = [
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
        "max_devices": 0,
        "bound_count": 2,
        "machine_codes": ["0F1E2D3C4B5A6978", "8877665544332211"],
        "created_at": "2026-09-29 09:10:00",
        "activated_at": "2026-09-29 09:30:00",
        "expires_at": "2026-10-29 09:30:00",
        "frozen_until": "2026-10-05 00:00:00",
        "note": "",
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
        "batch_no": "B20260930",
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

LOGS = [
    {
        "id": 412,
        "created_at": "2026-09-30 12:01:00",
        "actor": "admin01",
        "action": "activate",
        "target": "SQAA-B2C3-D4E5-F6G7",
        "result": "success",
        "ip": "127.0.0.1",
        "detail": "设备 A1B2C3D4E5F6A7B8",
    },
    {
        "id": 411,
        "created_at": "2026-09-30 11:50:22",
        "actor": "master",
        "action": "freeze",
        "target": "SQAA-9H8I-7J6K-5L4M",
        "result": "success",
        "ip": "127.0.0.1",
        "detail": "冻结至 2026-10-05",
    },
    {
        "id": 410,
        "created_at": "2026-09-30 11:20:02",
        "actor": "-",
        "action": "verify",
        "target": "SQAA-6T7U-8V9W-0X1Y",
        "result": "failure",
        "ip": "192.168.1.44",
        "detail": "密钥已吊销",
    },
]


class FakeClient:
    base_url = "http://127.0.0.1:8765"

    def __init__(self) -> None:
        self.offline_public_key = ""

    def set_base_url(self, url: str) -> None:
        self.base_url = url

    def stats(self):
        return {
            "total": 128,
            "unused": 74,
            "active": 41,
            "frozen": 3,
            "revoked": 6,
            "expired": 4,
            "batches": 7,
            "activations_today": 5,
            "activations_7d": 22,
        }

    def list_licenses(self, **kwargs):
        return {"items": LICENSES, "total": len(LICENSES)}

    def list_logs(self, limit=300, **kwargs):
        return {"items": LOGS, "total": len(LOGS)}

    def list_admins(self):
        return {
            "items": [
                {
                    "id": 1,
                    "username": "master",
                    "role": "master",
                    "status": "active",
                    "created_at": "2026-09-01 08:00:00",
                    "last_login_at": "2026-09-30 09:12:00",
                },
                {
                    "id": 2,
                    "username": "admin01",
                    "role": "admin",
                    "status": "active",
                    "created_at": "2026-09-02 08:00:00",
                    "last_login_at": "2026-09-30 12:00:00",
                },
            ]
        }

    def health(self):
        return {"version": "1.0.0", "time": "2026-09-30 12:30:00"}

    def me(self):
        return {"username": "master", "role": "master"}


def main() -> int:
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "build", "shots")
    os.makedirs(outdir, exist_ok=True)

    app = QApplication(sys.argv[:1])
    style_name = os.environ.get("RENDER_STYLE")
    if style_name:
        avail = sorted({s.lower() for s in QStyleFactory.keys()})
        for cand in (style_name, f"{style_name}style"):
            if cand.lower() in avail:
                app.setStyle(QStyleFactory.create(cand))
                break
        else:
            print(f"[warn] style {style_name!r} unavailable; have {avail}")
    theme.apply_theme(app)
    if os.environ.get("RENDER_LEGACY_HANDLE") == "1":
        qss = app.styleSheet()
        for rule in (
            "QSplitter::handle { background: transparent; border: none; }",
            "QSplitter::handle:hover { background: #FFFFFF; }",
        ):
            qss = qss.replace(rule, "")
        app.setStyleSheet(qss)

    client = FakeClient()
    notify = lambda *a, **k: None  # noqa: E731

    shell = AppShell("密钥授权系统 · 主控端", {"username": "master", "role": "master"}, client.base_url)
    shell.resize(1440, 900)

    factories = [
        ("overview", OverviewPage),
        ("generate", GeneratePage),
        ("licenses", LicensesPage),
        ("offline", OfflinePage),
        ("logs", LogsPage),
        ("password", ChangePasswordPage),
        ("about", AboutPage),
    ]
    pages = []
    for name, factory in factories:
        try:
            pages.append((name, factory(client, notify)))
        except Exception as exc:  # pragma: no cover - diagnostics only
            print(f"[warn] cannot build {name}: {type(exc).__name__}: {exc}")
    for name, page in pages:
        shell.add_page(name, page)

    for name, page in pages:
        on_show = getattr(page, "on_show", None)
        if callable(on_show):
            try:
                on_show()
            except Exception as exc:  # pragma: no cover - diagnostics only
                print(f"[warn] {name}.on_show: {exc}")

    shell.show()

    def shoot() -> None:
        try:
            for index, (name, _page) in enumerate(pages):
                try:
                    shell.set_current_page(index)
                    app.processEvents()
                except Exception as exc:  # pragma: no cover - diagnostics only
                    print(f"[warn] page {name}: {exc}")
                    continue
                path = os.path.join(outdir, f"{index:02d}-{name}.png")
                shell.grab().save(path)
                print("saved", path)
        finally:
            app.quit()

    QTimer.singleShot(400, shoot)
    app.exec()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
