import random
import sqlite3
import threading
from pathlib import Path

from . import security

SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt          TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin',
    status        TEXT NOT NULL DEFAULT 'active',
    created_at    TEXT NOT NULL,
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS licenses (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    key_code      TEXT UNIQUE NOT NULL,
    edition       TEXT NOT NULL DEFAULT 'standard',
    duration_days INTEGER NOT NULL DEFAULT 0,
    duration_unit TEXT NOT NULL DEFAULT 'day',
    max_devices   INTEGER NOT NULL DEFAULT 1,
    status        TEXT NOT NULL DEFAULT 'unused',
    batch_no      TEXT,
    note          TEXT,
    created_by    TEXT,
    created_at    TEXT NOT NULL,
    activated_at  TEXT,
    expires_at    TEXT
);

CREATE TABLE IF NOT EXISTS activations (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id       INTEGER NOT NULL,
    key_code         TEXT NOT NULL,
    machine_code     TEXT NOT NULL,
    device_name      TEXT,
    status           TEXT NOT NULL DEFAULT 'active',
    activated_at     TEXT NOT NULL,
    expires_at       TEXT,
    last_verified_at TEXT,
    session_secret   TEXT,
    last_heartbeat_at TEXT,
    heartbeat_count  INTEGER NOT NULL DEFAULT 0,
    UNIQUE(key_code, machine_code)
);

CREATE TABLE IF NOT EXISTS nonces (
    nonce      TEXT PRIMARY KEY,
    key_code   TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    actor      TEXT,
    action     TEXT NOT NULL,
    target     TEXT,
    detail     TEXT,
    ip         TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_licenses_status ON licenses(status);
CREATE INDEX IF NOT EXISTS idx_licenses_batch ON licenses(batch_no);
CREATE INDEX IF NOT EXISTS idx_activations_key ON activations(key_code);
CREATE INDEX IF NOT EXISTS idx_logs_created ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_nonces_created ON nonces(created_at);
"""


MIGRATIONS = {
    "licenses": {
        "duration_unit": "TEXT NOT NULL DEFAULT 'day'",
        "frozen_until": "TEXT",
        "prev_status": "TEXT",
        "freeze_reason": "TEXT",
    },
    "activations": {
        "session_secret": "TEXT",
        "last_heartbeat_at": "TEXT",
        "heartbeat_count": "INTEGER NOT NULL DEFAULT 0",
    },
}


def _row_to_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        for table, columns in MIGRATIONS.items():
            existing = {
                row["name"] for row in self._conn.execute(f"PRAGMA table_info({table})")
            }
            for name, decl in columns.items():
                if name not in existing:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _fetchone(self, sql: str, params: tuple = ()):
        with self._lock:
            cur = self._conn.execute(sql, params)
            return cur.fetchone()

    def _fetchall(self, sql: str, params: tuple = ()):
        with self._lock:
            cur = self._conn.execute(sql, params)
            return cur.fetchall()

    def _execute(self, sql: str, params: tuple = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur.lastrowid

    def ensure_default_admin(self, username: str = "admin", password: str = "admin123") -> bool:
        if self._fetchone("SELECT id FROM admins LIMIT 1"):
            return False
        self.create_admin(username, password, role="master")
        return True

    def create_admin(self, username: str, password: str, role: str = "admin") -> int:
        pw_hash, salt = security.hash_password(password)
        return self._execute(
            "INSERT INTO admins (username, password_hash, salt, role, status, created_at)"
            " VALUES (?, ?, ?, ?, 'active', ?)",
            (username.strip(), pw_hash, salt, role, security.now_str()),
        )

    def get_admin(self, username: str) -> dict | None:
        return _row_to_dict(
            self._fetchone("SELECT * FROM admins WHERE username = ?", (username.strip(),))
        )

    def get_admin_by_id(self, admin_id: int) -> dict | None:
        return _row_to_dict(self._fetchone("SELECT * FROM admins WHERE id = ?", (admin_id,)))

    def list_admins(self) -> list[dict]:
        rows = self._fetchall(
            "SELECT id, username, role, status, created_at, last_login_at"
            " FROM admins ORDER BY id ASC"
        )
        return [dict(r) for r in rows]

    def set_admin_status(self, admin_id: int, status: str) -> None:
        self._execute("UPDATE admins SET status = ? WHERE id = ?", (status, admin_id))

    def set_admin_password(self, admin_id: int, password: str) -> None:
        pw_hash, salt = security.hash_password(password)
        self._execute(
            "UPDATE admins SET password_hash = ?, salt = ? WHERE id = ?",
            (pw_hash, salt, admin_id),
        )

    def touch_admin_login(self, admin_id: int) -> None:
        self._execute(
            "UPDATE admins SET last_login_at = ? WHERE id = ?",
            (security.now_str(), admin_id),
        )

    def _unique_key(self, prefix: str) -> str:
        for _ in range(20):
            code = security.generate_key(prefix)
            if not self._fetchone("SELECT id FROM licenses WHERE key_code = ?", (code,)):
                return code
        raise RuntimeError("无法生成唯一密钥，请重试")

    def generate_licenses(
        self,
        count: int,
        edition: str = "standard",
        duration_days: int = 0,
        max_devices: int = 1,
        note: str = "",
        created_by: str = "",
        prefix: str = "LIC",
        duration_unit: str = "day",
    ) -> tuple[str, list[str]]:
        batch_no = (
            f"B{security.now_str().replace('-', '').replace(':', '').replace(' ', '')}"
            f"{random.randint(100, 999)}"
        )
        created_at = security.now_str()
        unit = security.normalize_unit(duration_unit)
        keys: list[str] = []
        with self._lock:
            for _ in range(max(1, count)):
                code = self._unique_key(prefix)
                while code in keys:
                    code = self._unique_key(prefix)
                self._conn.execute(
                    "INSERT INTO licenses (key_code, edition, duration_days, duration_unit,"
                    " max_devices, status, batch_no, note, created_by, created_at)"
                    " VALUES (?, ?, ?, ?, ?, 'unused', ?, ?, ?, ?)",
                    (code, edition, duration_days, unit, max_devices, batch_no, note, created_by, created_at),
                )
                keys.append(code)
            self._conn.commit()
        return batch_no, keys

    def get_license(self, key_code: str) -> dict | None:
        return _row_to_dict(
            self._fetchone(
                "SELECT * FROM licenses WHERE key_code = ?", (security.normalize_key(key_code),)
            )
        )

    def list_licenses(
        self,
        keyword: str = "",
        status: str = "",
        batch_no: str = "",
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict]:
        sql = "SELECT * FROM licenses WHERE 1 = 1"
        params: list = []
        if keyword:
            sql += " AND (key_code LIKE ? OR note LIKE ? OR batch_no LIKE ?)"
            like = f"%{keyword.strip()}%"
            params += [like, like, like]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if batch_no:
            sql += " AND batch_no = ?"
            params.append(batch_no)
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        rows = [dict(r) for r in self._fetchall(sql, tuple(params))]
        codes = self.bound_machine_codes([r["key_code"] for r in rows])
        for row in rows:
            row["machine_codes"] = codes.get(row["key_code"], [])
        return rows

    def bound_machine_codes(self, key_codes: list[str]) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        codes = [security.normalize_key(k) for k in (key_codes or []) if k]
        if not codes:
            return result
        for i in range(0, len(codes), 500):
            chunk = codes[i:i + 500]
            placeholders = ",".join("?" for _ in chunk)
            rows = self._fetchall(
                f"SELECT key_code, machine_code FROM activations"
                f" WHERE status = 'active' AND key_code IN ({placeholders})"
                f" ORDER BY id ASC",
                tuple(chunk),
            )
            for r in rows:
                result.setdefault(r["key_code"], []).append(r["machine_code"])
        return result

    def count_licenses(self, keyword: str = "", status: str = "") -> int:
        sql = "SELECT COUNT(*) AS n FROM licenses WHERE 1 = 1"
        params: list = []
        if keyword:
            sql += " AND (key_code LIKE ? OR note LIKE ? OR batch_no LIKE ?)"
            like = f"%{keyword.strip()}%"
            params += [like, like, like]
        if status:
            sql += " AND status = ?"
            params.append(status)
        row = self._fetchone(sql, tuple(params))
        return int(row["n"]) if row else 0

    def set_license_status(self, key_code: str, status: str) -> None:
        code = security.normalize_key(key_code)
        if status in ("revoked", "expired"):
            lic = self.get_license(code)
            if lic and lic["status"] not in ("revoked", "expired", "frozen"):
                self._execute(
                    "UPDATE licenses SET prev_status = ? WHERE key_code = ?",
                    (lic["status"], code),
                )
        self._execute(
            "UPDATE licenses SET status = ? WHERE key_code = ?",
            (status, code),
        )
        if status in ("revoked", "expired"):
            self._execute(
                "UPDATE activations SET status = 'unbound' WHERE key_code = ?",
                (code,),
            )

    def restore_license(self, key_code: str) -> str | None:
        code = security.normalize_key(key_code)
        lic = self.get_license(code)
        if not lic or lic["status"] not in ("revoked", "expired"):
            return None
        target = lic["prev_status"] or "unused"
        if target in ("revoked", "expired", "frozen"):
            target = "unused"
        self._execute(
            "UPDATE licenses SET status = ?, prev_status = NULL, frozen_until = NULL,"
            " freeze_reason = NULL WHERE key_code = ?",
            (target, code),
        )
        return target

    def freeze_license(self, key_code: str, frozen_until: str, reason: str = "") -> str | None:
        code = security.normalize_key(key_code)
        lic = self.get_license(code)
        if not lic or lic["status"] in ("revoked", "expired"):
            return None
        prev = lic["prev_status"] if lic["status"] == "frozen" else lic["status"]
        if prev in ("revoked", "expired", "frozen"):
            prev = "unused"
        self._execute(
            "UPDATE licenses SET status = 'frozen', frozen_until = ?, prev_status = ?,"
            " freeze_reason = ? WHERE key_code = ?",
            (frozen_until, prev, reason, code),
        )
        return prev

    def unfreeze_license(self, key_code: str) -> str | None:
        code = security.normalize_key(key_code)
        lic = self.get_license(code)
        if not lic or lic["status"] != "frozen":
            return None
        target = lic["prev_status"] or "active"
        if target in ("revoked", "expired", "frozen"):
            target = "unused"
        self._execute(
            "UPDATE licenses SET status = ?, frozen_until = NULL, prev_status = NULL,"
            " freeze_reason = NULL WHERE key_code = ?",
            (target, code),
        )
        return target

    def release_expired_freeze(self, key_code: str = "") -> int:
        now = security.now_str()
        sql = (
            "UPDATE licenses SET status = COALESCE(prev_status, 'active'), prev_status = NULL,"
            " frozen_until = NULL, freeze_reason = NULL"
            " WHERE status = 'frozen' AND frozen_until IS NOT NULL AND frozen_until <= ?"
        )
        params: tuple = (now,)
        if key_code:
            sql += " AND key_code = ?"
            params = (now, security.normalize_key(key_code))
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur.rowcount

    def revoke_batch(self, batch_no: str) -> int:
        with self._lock:
            self._conn.execute(
                "UPDATE licenses SET prev_status = status WHERE batch_no = ?"
                " AND status NOT IN ('revoked', 'expired', 'frozen')",
                (batch_no,),
            )
            cur = self._conn.execute(
                "UPDATE licenses SET status = 'revoked' WHERE batch_no = ? AND status != 'revoked'",
                (batch_no,),
            )
            self._conn.execute(
                "UPDATE activations SET status = 'unbound'"
                " WHERE key_code IN (SELECT key_code FROM licenses WHERE batch_no = ?)",
                (batch_no,),
            )
            self._conn.commit()
            return cur.rowcount

    def delete_license(self, key_code: str) -> None:
        code = security.normalize_key(key_code)
        self._execute("DELETE FROM activations WHERE key_code = ?", (code,))
        self._execute("DELETE FROM licenses WHERE key_code = ?", (code,))

    def get_activation(self, key_code: str, machine_code: str) -> dict | None:
        return _row_to_dict(
            self._fetchone(
                "SELECT * FROM activations WHERE key_code = ? AND machine_code = ?",
                (security.normalize_key(key_code), machine_code),
            )
        )

    def list_activations(self, key_code: str) -> list[dict]:
        rows = self._fetchall(
            "SELECT * FROM activations WHERE key_code = ? ORDER BY id DESC",
            (security.normalize_key(key_code),),
        )
        return [dict(r) for r in rows]

    def count_active_activations(self, license_id: int) -> int:
        row = self._fetchone(
            "SELECT COUNT(*) AS n FROM activations WHERE license_id = ? AND status = 'active'",
            (license_id,),
        )
        return int(row["n"]) if row else 0

    def create_activation(
        self,
        license_id: int,
        key_code: str,
        machine_code: str,
        device_name: str,
        expires_at: str | None,
    ) -> int:
        now = security.now_str()
        return self._execute(
            "INSERT INTO activations (license_id, key_code, machine_code, device_name,"
            " status, activated_at, expires_at, last_verified_at)"
            " VALUES (?, ?, ?, ?, 'active', ?, ?, ?)",
            (license_id, security.normalize_key(key_code), machine_code, device_name, now, expires_at, now),
        )

    def reactivate_activation(self, activation_id: int, device_name: str, expires_at: str | None) -> None:
        now = security.now_str()
        self._execute(
            "UPDATE activations SET status = 'active', device_name = ?, activated_at = ?,"
            " expires_at = ?, last_verified_at = ? WHERE id = ?",
            (device_name, now, expires_at, now, activation_id),
        )

    def update_activation_verified(self, activation_id: int) -> None:
        self._execute(
            "UPDATE activations SET last_verified_at = ? WHERE id = ?",
            (security.now_str(), activation_id),
        )

    def set_activation_session(self, activation_id: int, session_secret: str) -> None:
        self._execute(
            "UPDATE activations SET session_secret = ? WHERE id = ?",
            (session_secret, activation_id),
        )

    def touch_heartbeat(self, activation_id: int) -> None:
        self._execute(
            "UPDATE activations SET last_heartbeat_at = ?,"
            " heartbeat_count = heartbeat_count + 1 WHERE id = ?",
            (security.now_str(), activation_id),
        )

    def seen_nonce(self, nonce: str, key_code: str = "", now: int | None = None) -> bool:
        if not nonce:
            return True
        now = security.now_ts() if now is None else now
        with self._lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO nonces (nonce, key_code, created_at) VALUES (?, ?, ?)",
                (nonce, security.normalize_key(key_code), now),
            )
            self._conn.commit()
            return cur.rowcount == 0

    def prune_nonces(self, before_ts: int) -> int:
        with self._lock:
            cur = self._conn.execute("DELETE FROM nonces WHERE created_at < ?", (before_ts,))
            self._conn.commit()
            return cur.rowcount

    def unbind_activation(self, key_code: str, machine_code: str) -> None:
        self._execute(
            "UPDATE activations SET status = 'unbound' WHERE key_code = ? AND machine_code = ?",
            (security.normalize_key(key_code), machine_code),
        )

    def update_license_expiry(self, key_code: str, expires_at: str | None) -> None:
        self._execute(
            "UPDATE licenses SET expires_at = ? WHERE key_code = ?",
            (expires_at, security.normalize_key(key_code)),
        )

    def set_license_activated(self, key_code: str) -> None:
        self._execute(
            "UPDATE licenses SET status = 'active', activated_at = ? WHERE key_code = ? AND status = 'unused'",
            (security.now_str(), security.normalize_key(key_code)),
        )

    def stats(self) -> dict:
        def scalar(sql: str, params: tuple = ()) -> int:
            row = self._fetchone(sql, params)
            return int(row["n"]) if row else 0

        return {
            "total": scalar("SELECT COUNT(*) AS n FROM licenses"),
            "unused": scalar("SELECT COUNT(*) AS n FROM licenses WHERE status = 'unused'"),
            "active": scalar("SELECT COUNT(*) AS n FROM licenses WHERE status = 'active'"),
            "revoked": scalar("SELECT COUNT(*) AS n FROM licenses WHERE status = 'revoked'"),
            "frozen": scalar("SELECT COUNT(*) AS n FROM licenses WHERE status = 'frozen'"),
            "expired": scalar("SELECT COUNT(*) AS n FROM licenses WHERE status = 'expired'"),
            "devices": scalar("SELECT COUNT(*) AS n FROM activations WHERE status = 'active'"),
            "admins": scalar("SELECT COUNT(*) AS n FROM admins"),
            "batches": scalar("SELECT COUNT(DISTINCT batch_no) AS n FROM licenses WHERE batch_no IS NOT NULL"),
        }

    def add_log(self, action: str, actor: str = "", target: str = "", detail: str = "", ip: str = "") -> None:
        self._execute(
            "INSERT INTO audit_logs (actor, action, target, detail, ip, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (actor, action, target, detail, ip, security.now_str()),
        )

    def list_logs(self, limit: int = 200) -> list[dict]:
        rows = self._fetchall(
            "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in rows]
