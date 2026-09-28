import argparse
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import theme
from core.config import get_config
from core.database import Database


def main() -> int:
    parser = argparse.ArgumentParser(description="密钥授权本地服务器")
    parser.add_argument("--headless", action="store_true", help="无界面模式，仅运行后端服务")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args()

    config = get_config()
    if args.host:
        config.server["host"] = args.host
    if args.port:
        config.server["port"] = args.port

    db = Database(config.db_path())
    created = db.ensure_default_admin()

    if args.headless:
        import uvicorn

        from server.api import create_app

        app = create_app(config, db)
        uvicorn.run(app, host=config.server["host"], port=int(config.server["port"]), log_level="info")
        return 0

    from PySide6.QtWidgets import QApplication

    from server.ui import ServerWindow

    app = QApplication(sys.argv)
    theme.apply_theme(app)
    window = ServerWindow(config, db)
    window.show()
    if created:
        window.toast.show_message("首次运行已创建主控账号 admin / admin123，请尽快修改", "warning", 8000)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
