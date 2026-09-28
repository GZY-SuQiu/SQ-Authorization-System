import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PySide6.QtWidgets import QApplication

from core import theme
from core.config import get_config


def main() -> int:
    config = get_config()
    app = QApplication(sys.argv)
    theme.apply_theme(app)

    from verification.ui import VerifyWindow

    window = VerifyWindow(config)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
