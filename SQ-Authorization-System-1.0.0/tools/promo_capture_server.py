"""Capture the 本地服务器 window for the promo video.

Usage:  python tools/promo_capture_server.py

Writes 2x PNGs under <workspace>/promo-video/assets/captures/server/.
The controller's ``start`` hook is disabled so the capture never binds a port,
the config/database live in a throwaway temp directory, and the service-settings
card is hidden so the AI card (the thing the promo talks about) is on screen
without scrolling. The seeded AI provider is fictional demo data.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import promo_capture_common  # noqa: E402,F401  (sets the Qt env first)

from promo_capture_common import CAPTURES, grab, make_app, pump  # noqa: E402

from PySide6.QtWidgets import QScrollArea  # noqa: E402

from core.config import Config  # noqa: E402
from core.database import Database  # noqa: E402
from server import ui as server_ui  # noqa: E402

WINDOW_SIZE = (1280, 860)

DEMO_AI = {
    "enabled": True,
    "vendor_name": "Agnes",
    "api_mode": "chat",
    "base_url": "https://api.agnes.ai/v1",
    "model": "agnes-2.0-flash",
    "api_key": "sk-demo-000000000000000000000000",
    "reasoning_effort": "medium",
    "max_tokens": 2048,
}


def seed_ai(config: Config) -> None:
    """Pre-fill the AI form so the capture shows a configured provider."""
    ai = config.ai
    for key, value in DEMO_AI.items():
        ai[key] = value
    config.save()


def hide_service_card(window) -> None:
    """Drop the service-settings card so the AI card lands at the top."""
    pane = window.findChild(QScrollArea)
    if pane is None:
        return
    body = pane.widget()
    layout = body.layout() if body is not None else None
    if layout is None or layout.count() == 0:
        return
    first = layout.itemAt(0).widget()
    if first is not None:
        first.setVisible(False)


def ai_card(window):
    """The AI settings card widget inside the scrolling settings pane."""
    pane = window.findChild(QScrollArea)
    body = pane.widget() if pane is not None else None
    layout = body.layout() if body is not None else None
    if layout is None or layout.count() < 2:
        return None
    return layout.itemAt(1).widget()


def main() -> int:
    make_app()

    # Never bind a real port just to take a screenshot.
    server_ui.ServerController.start = lambda self: None

    with tempfile.TemporaryDirectory(prefix="promo-server-") as tmpdir:
        tmp = Path(tmpdir)
        config = Config("server", tmp / "server_config.json")
        seed_ai(config)
        db = Database(tmp / "license.db")
        window = server_ui.ServerWindow(config, db)
        window.resize(*WINDOW_SIZE)
        window.show()
        # Drain the delayed auto-start so it cannot fire after the window closes.
        pump(500)

        # Never publish the authoring machine's real database path.
        window.db_label.setText(r"data\license.db")
        hide_service_card(window)
        pump(400)
        grab(window, "server/01-ai.png")

        # Close-up of just the AI card: the promo frame crops the window anyway,
        # and this keeps the form fields at ~1.25x instead of ~0.4x.
        card = ai_card(window)
        if card is not None:
            grab(card, "server/02-ai-card.png")

        window.close()
        db.close()

    print(f"captures -> {CAPTURES / 'server'}")
    return 0


if __name__ == "__main__":
    os.environ.setdefault("PROMO_CAPTURE_SCALE", "2")
    raise SystemExit(main())
