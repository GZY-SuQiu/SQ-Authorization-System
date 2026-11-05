import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PySide6.QtWidgets import QApplication

from core import crashlog, integrity, theme
from core.config import get_config


def main() -> int:
    crashlog.install("verification")
    # 修复通道必须早于完整性门禁：门禁失败会直接 SystemExit(1)，
    # 清单被同步工具改坏时就没有机会执行 --repair-manifest。
    repair_code = integrity.run_repair_cli("verification")
    if repair_code is not None:
        return repair_code
    config = get_config("verification")
    app = QApplication(sys.argv)
    integrity.run_startup_gate("verification")
    theme.apply_theme(app)

    from verification.ui import VerifyWindow

    window = VerifyWindow(config)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
