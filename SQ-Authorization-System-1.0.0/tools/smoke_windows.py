"""Construct every top-level window offscreen to catch UI regressions.

Usage:  python tools/smoke_windows.py

Builds the admin shell, the master shell and the verification window against a
stub API client, renders each one once, and reports any construction error. It
runs headless, so it is safe on a build machine or in CI.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from PySide6.QtWidgets import QApplication  # noqa: E402

from core import theme  # noqa: E402
from core.config import Config  # noqa: E402
from tools.render_pages import FakeClient  # noqa: E402


def main() -> int:
    app = QApplication(sys.argv[:1])
    theme.apply_theme(app)

    outdir = Path(ROOT) / "build" / "smoke"
    outdir.mkdir(parents=True, exist_ok=True)

    failures = 0
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        tmp_path = Path(tmp)
        client = FakeClient()

        from admin.ui import AdminWindow
        from master.ui import MasterWindow
        from verification.ui import VerifyWindow

        builders = [
            (
                "admin",
                lambda: AdminWindow(
                    client, {"username": "admin01", "role": "admin"}
                ),
            ),
            (
                "master",
                lambda: MasterWindow(
                    client,
                    {"username": "master", "role": "master"},
                    Config("master", tmp_path / "master_config.json"),
                ),
            ),
            (
                "verification",
                lambda: VerifyWindow(Config("verification", tmp_path / "verify.json")),
            ),
        ]

        for name, build in builders:
            try:
                window = build()
            except Exception as exc:  # pragma: no cover - diagnostics only
                failures += 1
                print(f"[fail] {name}: {type(exc).__name__}: {exc}")
                continue
            try:
                window.resize(1440, 900)
                window.show()
                app.processEvents()
                path = outdir / f"{name}.png"
                window.grab().save(str(path))
                print(f"[ok] {name} -> {path}")
            except Exception as exc:  # pragma: no cover - diagnostics only
                failures += 1
                print(f"[fail] {name} render: {type(exc).__name__}: {exc}")
            finally:
                window.close()

    if failures:
        print(f"{failures} 个窗口构造失败")
        return 1
    print("全部窗口构造正常")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
