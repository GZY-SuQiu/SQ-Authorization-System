"""Preview the session-secret encryption upgrade against a copy of a real DB.

Usage: python tools/check_session_migration.py [path-to-license.db]

Copies the database to a temp directory first, so the original is never
touched. Prints how many activations still hold plaintext session secrets and
how many rows the upgrade would seal.
"""

import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.database import SESSION_CIPHER_PREFIX, Database  # noqa: E402


def main() -> int:
    source = Path(sys.argv[1] if len(sys.argv) > 1 else "data/license.db")
    if not source.exists():
        print(f"未找到数据库：{source}")
        return 1

    workdir = tempfile.mkdtemp(prefix="sq-session-check-")
    copy_path = os.path.join(workdir, "license.db")
    try:
        shutil.copyfile(source, copy_path)
        conn = sqlite3.connect(copy_path)
        total = conn.execute("SELECT COUNT(*) FROM activations").fetchone()[0]
        legacy = conn.execute(
            "SELECT COUNT(*) FROM activations WHERE session_secret IS NOT NULL"
            " AND session_secret != '' AND session_secret NOT LIKE ?",
            (SESSION_CIPHER_PREFIX + "%",),
        ).fetchone()[0]
        conn.close()
        print(f"激活记录：{total}    仍为明文的会话密钥：{legacy}")

        db = Database(copy_path, "preview-key")
        try:
            upgraded = db.seal_legacy_sessions()
            print(f"本次可升级：{upgraded}")
            print(f"再次执行：{db.seal_legacy_sessions()}（应为 0）")
            print(f"完整性检查：{db.check_health()['integrity']}")
        finally:
            db.close()
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
