import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import crashlog, security, theme
from core.config import APP_DIR, APP_NAME, APP_VERSION, get_config
from core.database import Database


def _load_release_manifests(db: Database, config) -> int:
    """Import the signed release whitelist found next to the executable.

    Best effort by design: a missing, unsigned or malformed manifest must never
    keep the licence server from starting. Returns the number of upserted apps.
    """
    from core import integrity

    manifest_path = APP_DIR / "releases" / integrity.MANIFEST_NAME
    signature_path = APP_DIR / "releases" / integrity.SIGNATURE_NAME
    if not manifest_path.is_file() or not signature_path.is_file():
        return 0
    manifest_bytes = manifest_path.read_bytes()
    signature = signature_path.read_text(encoding="utf-8").strip()
    public_key = config.security.get("release_public_key", "")
    if not public_key:
        public_key = integrity.load_release_public_key()
    if not integrity.verify_manifest_signature(manifest_bytes, signature, public_key):
        print("警告：发布清单签名校验未通过，已跳过导入。")
        return 0
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    if not isinstance(manifest, dict):
        return 0
    if manifest.get("format") != integrity.MANIFEST_FORMAT:
        print("警告：发布清单格式不受支持，已跳过导入。")
        return 0
    apps = manifest.get("apps")
    if not isinstance(apps, dict):
        return 0
    try:
        # 启动导入同时写 release_hashes 与 release_meta（attest 的 release 绑定校验）。
        from server.api import import_release_manifest

        return int(
            import_release_manifest(
                db,
                manifest,
                manifest_bytes,
                note="startup auto-import",
                retire_old=bool(
                    config.security.get("release_auto_retire_old", True)
                ),
            )
        )
    except ImportError:
        pass
    version = str(manifest.get("version", "") or "")
    imported = 0
    for name, entry in apps.items():
        if not isinstance(entry, dict):
            continue
        file_name = str(entry.get("path", "") or "").strip()
        sha256 = str(entry.get("sha256", "") or "").strip().lower()
        if not file_name or len(sha256) != 64:
            continue
        db.upsert_release_hash(
            file_name=file_name,
            sha256=sha256,
            size=entry.get("size", 0),
            version=version,
            active=1,
            note="startup auto-import",
        )
        imported += 1
    if imported:
        db.add_log(
            "导入发布清单",
            "system",
            version,
            f"启动自动导入 {imported} 个应用哈希",
            "",
        )
    return imported


def _reset_master_password(db: Database) -> int:
    """Issue a fresh one-time password for the built-in admin account.

    This replaces the old advice of deleting license.db when the master
    password is lost, which threw away every license along with it.
    """
    admin = db.get_admin("admin")
    if not admin:
        print("未找到 admin 账号，请先正常启动一次本地服务器完成初始化。")
        return 1
    password = security.generate_bootstrap_password()
    db.set_admin_password(admin["id"], password, must_change_password=True)
    db.add_log("重置主控密码", "命令行", "admin", "使用 --reset-master-password", "")
    print("已重置 admin 账号密码（数据未改动）。")
    print(f"一次性密码：{password}")
    print("请立即登录主控端并修改密码；旧登录状态已全部失效。")
    return 0


def main() -> int:
    crashlog.install("server")
    parser = argparse.ArgumentParser(description="密钥授权本地服务器")
    parser.add_argument("--headless", action="store_true", help="无界面模式，仅运行后端服务")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument(
        "--print-public-key", action="store_true", help="输出客户端固定公钥后退出"
    )
    parser.add_argument(
        "--reset-master-password",
        action="store_true",
        help="为 admin 账号生成新的一次性密码并输出，然后退出（不会清空数据）",
    )
    parser.add_argument(
        "--repair-manifest",
        metavar="目录",
        default=None,
        help="从指定目录导入已签名发布清单，修复本程序目录后退出（先于完整性门禁）",
    )
    parser.add_argument("--version", action="store_true", help="显示版本后退出")
    parser.add_argument(
        "--show-console",
        action="store_true",
        help="GUI 模式下保留控制台窗口（调试用）",
    )
    args = parser.parse_args()

    try:
        from core import integrity
    except ImportError:
        # core.integrity lands with a separate batch; the server must still be
        # runnable from a source checkout where it is absent.
        integrity = None

    if integrity is not None and args.repair_manifest is not None:
        # 修复通道先于完整性门禁：清单损坏时门禁会直接 SystemExit(1)。
        return integrity.print_repair_result(
            integrity.repair_manifest(args.repair_manifest, role="server")
        )

    if integrity is not None:
        integrity.run_startup_gate("server", gui=not args.headless)

    config = get_config("server")
    if args.version:
        print(f"{APP_NAME} 本地服务器 v{APP_VERSION}")
        return 0
    if args.host:
        config.server["host"] = args.host
    if args.port:
        config.server["port"] = args.port

    if args.print_public_key:
        print(
            json.dumps(
                {
                    "offline_public_key": config.security.get("offline_public_key", ""),
                    "response_public_key": config.security.get("response_public_key", ""),
                    "response_key_id": config.security.get("response_key_id", ""),
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
        )
        return 0

    # The config secret seals activation session secrets inside license.db, so a
    # stolen database file alone cannot be used to forge device signatures.
    db = Database(config.db_path(), config.security.get("secret_key"))
    created, bootstrap_password = db.ensure_default_admin()
    upgraded_sessions = db.seal_legacy_sessions()
    if upgraded_sessions:
        db.add_log(
            "升级会话密钥", "system", "", f"加密存储 {upgraded_sessions} 条", ""
        )

    # The signed release manifest next to the executable seeds the executable
    # whitelist. Failures are warnings only: a broken manifest must not stop
    # the licence server from starting.
    try:
        imported = _load_release_manifests(db, config)
        if imported:
            print(f"已导入发布清单：{imported} 个应用哈希")
    except Exception as exc:
        print(f"警告：导入发布清单失败（{exc}），服务器继续启动。")

    if args.reset_master_password:
        return _reset_master_password(db)

    if args.headless:
        import uvicorn

        from server.api import create_app

        app = create_app(config, db)
        if created:
            print("首次运行已创建主控账号：admin")
            print(f"一次性初始密码：{bootstrap_password}")
            print("请登录后立即在“系统设置”中修改密码。")
        uvicorn.run(
            app,
            host=config.server["host"],
            port=int(config.server["port"]),
            log_level="info",
        )
        return 0

    from PySide6.QtWidgets import QApplication

    if not args.show_console:
        from core import winconsole

        winconsole.hide_console_window()

    from server.ui import ServerWindow

    app = QApplication(sys.argv)
    theme.apply_theme(app)
    # The one-time password is handed to the window so it can be shown in a
    # modal dialog. A toast would be replaced by the "service started"
    # notice about a second later, which is how the old build lost it.
    window = ServerWindow(config, db, bootstrap_password=bootstrap_password or "")
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
