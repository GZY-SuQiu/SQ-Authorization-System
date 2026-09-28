import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PySide6.QtWidgets import QApplication

from core import theme
from core.config import get_config
from core.shell import run_client_app


def main() -> int:
    config = get_config()
    app = QApplication(sys.argv)
    theme.apply_theme(app)

    from master.ui import MasterWindow

    return run_client_app(
        app,
        config,
        "主控端登录",
        "使用主控账号登录，管理全局授权与管理员",
        lambda client, user: MasterWindow(client, user, config),
    )


if __name__ == "__main__":
    raise SystemExit(main())
