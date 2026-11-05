"""Render the 本地服务器 window offscreen so its layout can be inspected.

The shared page renderer does not cover this window, which is how the
collapsed settings form shipped unnoticed.

Usage:  python tools/render_server.py [outdir]
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parent.parent
if ROOT not in sys.path:
    sys.path.insert(0, str(ROOT))

from PySide6.QtTest import QTest  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from core import theme  # noqa: E402
from core.config import Config  # noqa: E402
from core.database import Database  # noqa: E402
from server import ui as server_ui  # noqa: E402

SIZES = ((1120, 720), (960, 640))


def main() -> int:
    outdir = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "build" / "server")
    outdir.mkdir(parents=True, exist_ok=True)

    app = QApplication.instance() or QApplication([])
    theme.apply_theme(app)

    # Do not bind a real port just to take a screenshot.
    server_ui.ServerController.start = lambda self: None

    tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    config = Config("server", Path(tmp.name) / "server_config.json")
    db = Database(Path(tmp.name) / "license.db")
    window = server_ui.ServerWindow(config, db)
    window.show()
    # Drain the delayed auto-start so it cannot fire after the window closes.
    QTest.qWait(400)

    for width, height in SIZES:
        window.resize(width, height)
        QTest.qWait(120)
        target = outdir / f"server-{width}x{height}.png"
        window.grab().save(str(target))
        print(f"saved {target}")

    window.close()
    db.close()
    tmp.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
