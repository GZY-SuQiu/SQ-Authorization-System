"""Capture the 主控端 / 管理端 windows for the promo video.

Usage:  python tools/promo_capture_clients.py

Writes 2x PNGs under <workspace>/promo-video/assets/captures/{master,admin}/.
"""

from __future__ import annotations

import io
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import promo_capture_common  # noqa: E402,F401  (sets the Qt env first)

from promo_capture_common import (  # noqa: E402
    ADMIN_USER,
    AI_CONVERSATION,
    CAPTURES,
    MASTER_USER,
    FakeClient,
    grab,
    make_app,
    pump,
    render_image,
)

from PySide6.QtCore import QBuffer, QIODevice  # noqa: E402
from PIL import Image, ImageDraw, ImageFilter  # noqa: E402

from admin.ui import AdminWindow  # noqa: E402
from core import offline  # noqa: E402
from core.config import Config  # noqa: E402
from core.pages import DetailDialog  # noqa: E402
from master.ui import MasterWindow  # noqa: E402

MASTER_SIZE = (1600, 1000)
ADMIN_SIZE = (1600, 1000)


def quiet(*_args, **_kwargs) -> None:
    """Swallow toasts so transient popups never land in a capture."""


def silence(window) -> None:
    window.notify = quiet
    for index in range(window.stack.count()):
        page = window.stack.widget(index)
        if page is not None:
            page.notify = quiet


def show_page(window, page, settle: int = 320) -> None:
    index = window.stack.indexOf(page)
    if index < 0:
        raise RuntimeError(f"page {page!r} is not in the shell")
    window.set_current_page(index)
    pump(settle)


def fit_monitor_rows(page, rows: int = 4) -> None:
    """Size the AI monitor table to whole rows so no row is cut in half."""
    table = page.monitor_logs
    if table.rowCount() == 0:
        return
    table.resizeRowsToContents()
    visible = min(rows, table.rowCount())
    height = table.horizontalHeader().height() + table.rowHeight(0) * visible + 2
    table.setFixedHeight(height)


def qimage_to_pil(image):
    buffer = QBuffer()
    buffer.open(QIODevice.WriteOnly)
    if not image.save(buffer, "PNG"):
        raise RuntimeError("cannot encode dialog image")
    return Image.open(io.BytesIO(bytes(buffer.data()))).convert("RGBA")


def overlay_dialog(background: Path, dialog, relpath: str, dim: int = 46) -> Path:
    """Center a dialog over its parent capture with a soft shadow."""
    bg = Image.open(background).convert("RGBA")
    shot = qimage_to_pil(render_image(dialog))

    if dim:
        bg = Image.alpha_composite(bg, Image.new("RGBA", bg.size, (18, 24, 38, dim)))

    radius = 16
    pad = 70
    shadow = Image.new("RGBA", (shot.width + pad * 2, shot.height + pad * 2), (0, 0, 0, 0))
    mask = Image.new("L", shot.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [0, 0, shot.width - 1, shot.height - 1], radius=radius, fill=255
    )
    plate = Image.new("RGBA", shadow.size, (0, 0, 0, 0))
    plate.paste((10, 16, 30, 150), (pad, pad + 18), mask)
    shadow = Image.alpha_composite(shadow, plate)
    shadow = shadow.filter(ImageFilter.GaussianBlur(22))

    canvas = Image.new("RGBA", bg.size, (0, 0, 0, 0))
    x = (bg.width - shadow.width) // 2
    y = (bg.height - shadow.height) // 2
    canvas.alpha_composite(shadow, (x, y))
    bg = Image.alpha_composite(bg, canvas)

    target = CAPTURES / relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    bg.alpha_composite(shot, ((bg.width - shot.width) // 2, (bg.height - shot.height) // 2))
    bg.convert("RGB").save(target, quality=95)
    print(f"saved {target}  ({bg.width}x{bg.height})")
    return target


# --------------------------------------------------------------------------
# 主控端
# --------------------------------------------------------------------------


def capture_master(app, tmp: Path) -> None:
    config = Config("master", tmp / "master_config.json")
    client = FakeClient()
    window = MasterWindow(client, dict(MASTER_USER), config)
    window.resize(*MASTER_SIZE)
    window.show()
    silence(window)
    pump(500)

    # 01 系统概览 --------------------------------------------------------
    show_page(window, window.overview)
    grab(window, "master/01-overview.png")

    # 02 AI 助手 ---------------------------------------------------------
    show_page(window, window.ai)
    window.ai.conversation = [dict(message) for message in AI_CONVERSATION]
    window.ai._render_conversation()
    window.ai.refresh_status(silent=True)
    pump(260)
    fit_monitor_rows(window.ai)
    pump(140)
    grab(window, "master/02-ai-assistant.png")

    # 03 生成密钥 · 时长卡 ------------------------------------------------
    show_page(window, window.generate)
    page = window.generate
    page.count.setValue(50)
    page.edition.setCurrentIndex(1)  # 专业版
    page.card_mode.setCurrentIndex(0)  # 时长卡
    page.unit.setCurrentIndex(6)  # 年卡
    page.duration.setValue(1)
    page.devices.setValue(3)
    page.prefix.setText("GSQ")
    page.note.setText("国庆活动批次")
    page.generate()
    pump(220)
    grab(window, "master/03-generate-duration.png")

    # 03b 生成密钥 · 激活次数卡 -------------------------------------------
    page.card_mode.setCurrentIndex(1)
    page.activation_limit.setValue(10)
    page.count.setValue(20)
    page.note.setText("次卡客户")
    page.generate()
    pump(220)
    grab(window, "master/03b-generate-activation.png")

    # 04 密钥管理 --------------------------------------------------------
    show_page(window, window.licenses)
    window.licenses.table.selectRow(0)
    pump(160)
    licenses_shot = grab(window, "master/04-licenses.png")

    # 04b 密钥详情 -------------------------------------------------------
    detail = DetailDialog(client, "GSQ-3N8B-1X5C-7Z2D-9Q4F", quiet, window)
    detail.resize(880, 620)
    detail.show()
    pump(300)
    overlay_dialog(licenses_shot, detail, "master/04b-license-detail.png")
    detail.close()

    # 05 批次管理 --------------------------------------------------------
    show_page(window, window.batches)
    window.batches.table.selectRow(0)
    pump(160)
    grab(window, "master/05-batches.png")

    # 06 离线激活 --------------------------------------------------------
    show_page(window, window.offline)
    offline_page = window.offline
    request_code = offline.make_request_code("8F3A21C4D9E07B56", "DESIGN-PC-07")
    offline_page.request.setPlainText(request_code)
    offline_page.parse_request()
    offline_page.key.setText("GSQ-7K2M-4P9Q-8R3T-6V1W")
    offline_page.device.setText("DESIGN-PC-07")
    offline_page.generate()
    pump(220)
    grab(window, "master/06-offline.png")

    # 07 管理员管理 ------------------------------------------------------
    show_page(window, window.admins)
    window.admins.table.selectRow(1)
    pump(160)
    grab(window, "master/07-admins.png")

    # 08 审计日志 --------------------------------------------------------
    show_page(window, window.logs)
    pump(200)
    grab(window, "master/08-logs.png")

    # 09 系统设置 --------------------------------------------------------
    show_page(window, window.settings)
    window.settings.info_label.setText(
        "连接正常 · 版本 1.0.0 · 服务器时间 2026-10-01 10:05:12"
    )
    pump(160)
    grab(window, "master/09-settings.png")

    # 10 关于 ------------------------------------------------------------
    show_page(window, window.about)
    grab(window, "master/10-about.png")

    window.close()


# --------------------------------------------------------------------------
# 管理端
# --------------------------------------------------------------------------


def capture_admin(app, tmp: Path) -> None:
    client = FakeClient(offset=17)
    window = AdminWindow(client, dict(ADMIN_USER))
    window.resize(*ADMIN_SIZE)
    window.show()
    silence(window)
    pump(500)

    show_page(window, window.overview)
    grab(window, "admin/01-overview.png")

    show_page(window, window.ai)
    window.ai.conversation = [dict(message) for message in AI_CONVERSATION]
    window.ai._render_conversation()
    window.ai.refresh_status(silent=True)
    pump(260)
    fit_monitor_rows(window.ai)
    pump(140)
    grab(window, "admin/02-ai-assistant.png")

    show_page(window, window.generate)
    page = window.generate
    page.count.setValue(30)
    page.edition.setCurrentIndex(0)
    page.card_mode.setCurrentIndex(0)
    page.unit.setCurrentIndex(4)  # 月卡
    page.duration.setValue(1)
    page.devices.setValue(2)
    page.note.setText("渠道体验卡")
    page.generate()
    pump(220)
    grab(window, "admin/03-generate.png")

    show_page(window, window.licenses)
    window.licenses.table.selectRow(2)
    pump(160)
    grab(window, "admin/04-licenses.png")

    show_page(window, window.batches)
    window.batches.table.selectRow(2)
    pump(160)
    grab(window, "admin/05-batches.png")

    show_page(window, window.offline)
    offline_page = window.offline
    offline_page.request.setPlainText(
        offline.make_request_code("2C77E1B4A0983F6D", "FINANCE-NB-12")
    )
    offline_page.parse_request()
    offline_page.key.setText("GSQ-2B4D-6F8H-0J2L-4N6P")
    offline_page.generate()
    pump(220)
    grab(window, "admin/06-offline.png")

    show_page(window, window.logs)
    pump(200)
    grab(window, "admin/07-logs.png")

    show_page(window, window.about)
    grab(window, "admin/08-about.png")

    window.close()


def main() -> int:
    app = make_app()
    with tempfile.TemporaryDirectory(prefix="promo-capture-") as tmpdir:
        tmp = Path(tmpdir)
        capture_master(app, tmp)
        capture_admin(app, tmp)
    print(f"captures -> {CAPTURES}")
    return 0


if __name__ == "__main__":
    os.environ.setdefault("PROMO_CAPTURE_SCALE", "2")
    raise SystemExit(main())
