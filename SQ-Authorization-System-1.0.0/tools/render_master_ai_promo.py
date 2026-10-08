"""Render the AI assistant page in the master shell for the promo.

The AI page is shared by the management and master clients.  The s6b scene
labels the frame "主控端", so this companion renderer provides a matching
master-shell variant while the admin captures remain the default for the
management scenes.

Usage:
    python tools/render_master_ai_promo.py [outdir]
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Reuse the promo capture environment and representative data.
from tools import render_admin_promo as admin_capture  # noqa: E402

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from core import theme  # noqa: E402
from core.config import Config  # noqa: E402
from master.ui import MasterWindow  # noqa: E402




def main() -> int:
    outdir = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "build" / "promo_master_ai")
    outdir.mkdir(parents=True, exist_ok=True)

    app = QApplication.instance() or QApplication(sys.argv[:1])
    theme.apply_theme(app)

    client = admin_capture.PromoClient()
    config = Config("master", outdir / "master_config.json")
    window = MasterWindow(
        client,
        {"username": "master", "role": "master"},
        config,
    )
    window.setAttribute(Qt.WA_DontShowOnScreen, True)
    window.resize(1600, 1000)
    window.show()
    QTest.qWait(250)

    ai_index = window.stack.indexOf(window.ai)
    window.set_current_page(ai_index)
    window.ai.monitor_logs.setMinimumHeight(96)
    window.ai.monitor_logs.setMaximumHeight(96)

    captures: list[dict] = []

    def capture(name: str, mode: str, description: str) -> None:
        admin_capture._configure_ai(window.ai, thinking=mode == "thinking")
        QTest.qWait(120)
        window.toast._timer.stop()
        window.toast.hide()
        admin_capture._clear_focus(window)
        path = outdir / f"{name}.png"
        width, height, pixel_ratio = admin_capture._save_png(window, path)
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

    capture("master-ai-thinking", "thinking", "主控端 AI 助手实时思考与工具执行状态")
    capture("master-ai-final", "final", "主控端 AI 助手最终回复与工具调用")

    manifest = {
        "role": "主控端",
        "captured_at": "2026-10-03T09:20:00+08:00",
        "render": {
            "window": "1600x1000",
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
