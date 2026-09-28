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

    from admin.ui import AdminWindow

    return run_client_app(
        app,
        config,
        "管理端登录",
        "连接本地服务器，管理密钥的生成与分发",
        lambda client, user: AdminWindow(client, user),
    )


if __name__ == "__main__":
    raise SystemExit(main())
