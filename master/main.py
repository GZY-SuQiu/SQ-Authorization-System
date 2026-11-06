import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PySide6.QtWidgets import QApplication

from core import crashlog, integrity, theme
from core.config import get_config
from core.shell import run_client_app


def main() -> int:
    crashlog.install("master")
    # 修复通道必须早于完整性门禁：门禁失败会直接 SystemExit(1)，
    # 清单被同步工具改坏时就没有机会执行 --repair-manifest。
    repair_code = integrity.run_repair_cli("master")
    if repair_code is not None:
        return repair_code
    config = get_config("master")
    app = QApplication(sys.argv)
    integrity.run_startup_gate("master")
    theme.apply_theme(app, mode=config.client.get("theme_mode"))

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
