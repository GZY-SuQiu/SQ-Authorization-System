import secrets
import sqlite3
import threading
import time
import uuid
from pathlib import Path

import base64
import hashlib
import os

import hmac
import html
import json
import re

from datetime import datetime, timedelta
import math

from . import security

SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    username              TEXT UNIQUE NOT NULL,
    password_hash         TEXT NOT NULL,
    salt                  TEXT NOT NULL,
    role                  TEXT NOT NULL DEFAULT 'admin',
    status                TEXT NOT NULL DEFAULT 'active',
    auth_version          INTEGER NOT NULL DEFAULT 0,
    must_change_password  INTEGER NOT NULL DEFAULT 0,
    created_at            TEXT NOT NULL,
    last_login_at         TEXT,
    email                 TEXT,
    email_verified_at     TEXT
);

-- P1: admin e-mail binding. The columns are declared both here (fresh
-- databases) and in MIGRATIONS (databases created by older builds), which
-- is the same pattern the auth_version column already uses.
CREATE UNIQUE INDEX IF NOT EXISTS idx_admins_email ON admins(email)
  WHERE email IS NOT NULL AND email <> '';

CREATE TABLE IF NOT EXISTS licenses (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    key_code      TEXT UNIQUE NOT NULL,
    edition       TEXT NOT NULL DEFAULT 'standard',
    card_type     TEXT NOT NULL DEFAULT 'duration',
    duration_days INTEGER NOT NULL DEFAULT 0,
    duration_unit TEXT NOT NULL DEFAULT 'day',
    activation_limit INTEGER NOT NULL DEFAULT 0,
    activation_count INTEGER NOT NULL DEFAULT 0,
    auto_revoked  INTEGER NOT NULL DEFAULT 0,
    max_devices   INTEGER NOT NULL DEFAULT 1,
    status        TEXT NOT NULL DEFAULT 'unused',
    batch_no      TEXT,
    note          TEXT,
    created_by    TEXT,
    created_at    TEXT NOT NULL,
    activated_at  TEXT,
    expires_at    TEXT,
    features      TEXT NOT NULL DEFAULT '',
    expiry_mode   TEXT NOT NULL DEFAULT 'relative',
    max_concurrent INTEGER NOT NULL DEFAULT 0
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

CREATE TABLE IF NOT EXISTS trial_claims (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    machine_code TEXT NOT NULL,
    batch_no     TEXT NOT NULL,
    key_code     TEXT,
    claimed_at   TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_trial_claims_unique
    ON trial_claims(machine_code, batch_no);

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
CREATE INDEX IF NOT EXISTS idx_licenses_expires ON licenses(expires_at);
CREATE INDEX IF NOT EXISTS idx_activations_key ON activations(key_code);
CREATE INDEX IF NOT EXISTS idx_logs_created ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_nonces_created ON nonces(created_at);

-- 服务端性能（问题二）：统计/列表/心跳热路径用到的复合索引。
CREATE INDEX IF NOT EXISTS idx_activations_license_status ON activations(license_id, status);
CREATE INDEX IF NOT EXISTS idx_activations_heartbeat ON activations(last_heartbeat_at);
CREATE INDEX IF NOT EXISTS idx_logs_action_created ON audit_logs(action, created_at);
CREATE INDEX IF NOT EXISTS idx_licenses_created ON licenses(created_at);

CREATE TABLE IF NOT EXISTS release_hashes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_name TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '',
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  UNIQUE(file_name, sha256)
);
CREATE INDEX IF NOT EXISTS idx_release_hashes_hash ON release_hashes(sha256, active);

-- 问题三：已导入发布清单的发布标识，用于把客户端绑定到具体构建。
CREATE TABLE IF NOT EXISTS release_meta (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  release_id TEXT UNIQUE NOT NULL,
  manifest_sha256 TEXT NOT NULL DEFAULT '',
  version TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_release_meta_active ON release_meta(active, release_id);

CREATE TABLE IF NOT EXISTS tamper_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  role TEXT,
  exe_name TEXT,
  exe_hash TEXT,
  version TEXT,
  machine_code TEXT,
  ip TEXT,
  reason TEXT,
  detail TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tamper_events_created ON tamper_events(created_at);

-- P1: e-mail queue, one-time codes, portal accounts and risk events.
CREATE TABLE IF NOT EXISTS email_templates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE NOT NULL,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  locale TEXT NOT NULL DEFAULT 'zh-CN',
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS email_outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  to_email TEXT NOT NULL,
  template_code TEXT NOT NULL,
  variables_json TEXT NOT NULL DEFAULT '{}',
  subject TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  next_retry_at TEXT,
  last_error TEXT,
  claimed_at TEXT,
  dedupe_key TEXT UNIQUE,
  created_at TEXT NOT NULL,
  sent_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_email_outbox_due ON email_outbox(status, next_retry_at);

CREATE TABLE IF NOT EXISTS action_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subject_type TEXT NOT NULL,
  subject_id INTEGER NOT NULL DEFAULT 0,
  email TEXT NOT NULL,
  purpose TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  used_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_action_codes_lookup ON action_codes(subject_type, email, purpose);

CREATE TABLE IF NOT EXISTS portal_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  auth_version INTEGER NOT NULL DEFAULT 0,
  email_verified_at TEXT,
  display_name TEXT NOT NULL DEFAULT '',
  avatar_mime TEXT NOT NULL DEFAULT '',
  avatar_data BLOB,
  created_at TEXT NOT NULL,
  last_login_at TEXT
);
CREATE TABLE IF NOT EXISTS portal_account_licenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL UNIQUE REFERENCES portal_accounts(id) ON DELETE CASCADE,
  license_id INTEGER NOT NULL UNIQUE REFERENCES licenses(id) ON DELETE CASCADE,
  key_code TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'bound',
  bound_at TEXT NOT NULL,
  unbound_at TEXT,
  unbind_reason TEXT
);
CREATE TABLE IF NOT EXISTS portal_binding_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL,
  license_id INTEGER NOT NULL,
  key_code TEXT NOT NULL,
  action TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  actor TEXT NOT NULL DEFAULT 'user',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS renewal_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL,
  license_id INTEGER NOT NULL,
  key_code TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL,
  handled_at TEXT
);
CREATE TABLE IF NOT EXISTS risk_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'warning',
  key_code TEXT,
  machine_code TEXT,
  ip TEXT,
  detail TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_risk_events_created ON risk_events(created_at);
CREATE TABLE IF NOT EXISTS activation_ip_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  license_id INTEGER NOT NULL,
  key_code TEXT NOT NULL,
  machine_code TEXT NOT NULL,
  ip TEXT NOT NULL,
  subnet TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_activation_ip_key ON activation_ip_events(key_code, created_at);

-- A5: configurable alert rules and fired events (contract section 2).
CREATE TABLE IF NOT EXISTS alert_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  metric TEXT NOT NULL,
  operator TEXT NOT NULL,             -- gte/gt/lte/lt/eq
  threshold REAL NOT NULL,
  window_seconds INTEGER NOT NULL DEFAULT 600,
  severity TEXT NOT NULL DEFAULT 'warning',   -- info/warning/critical
  cooldown_seconds INTEGER NOT NULL DEFAULT 3600,
  channels_json TEXT NOT NULL DEFAULT '["email"]',
  enabled INTEGER NOT NULL DEFAULT 1,
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alert_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id INTEGER NOT NULL,
  rule_name TEXT NOT NULL DEFAULT '',
  metric TEXT NOT NULL,
  value REAL NOT NULL,
  threshold REAL NOT NULL,
  operator TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'warning',
  status TEXT NOT NULL DEFAULT 'firing',      -- firing/resolved/acked
  payload_json TEXT NOT NULL DEFAULT '{}',
  notified INTEGER NOT NULL DEFAULT 0,
  fired_at TEXT NOT NULL,
  resolved_at TEXT,
  acked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_alert_events_rule ON alert_events(rule_id, id);
CREATE INDEX IF NOT EXISTS idx_alert_events_status ON alert_events(status, id);

-- A7: notification channels and their delivery queue (contract section 1).
CREATE TABLE IF NOT EXISTS notification_channels (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,                 -- webhook / dingtalk / wecom / feishu
  name TEXT NOT NULL UNIQUE,
  url TEXT NOT NULL,
  secret TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS channel_outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  channel_id INTEGER NOT NULL,
  subject TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL DEFAULT '',
  payload_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'pending',   -- pending/sending/sent/failed/dead
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  next_retry_at TEXT,
  last_error TEXT,
  claimed_at TEXT,
  dedupe_key TEXT UNIQUE,
  created_at TEXT NOT NULL,
  sent_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_channel_outbox_due ON channel_outbox(status, next_retry_at);
"""


MIGRATIONS = {
    "admins": {
        "auth_version": "INTEGER NOT NULL DEFAULT 0",
        "must_change_password": "INTEGER NOT NULL DEFAULT 0",
        "email": "TEXT",
        "email_verified_at": "TEXT",
    },
    "licenses": {
        "duration_unit": "TEXT NOT NULL DEFAULT 'day'",
        "frozen_until": "TEXT",
        "prev_status": "TEXT",
        "freeze_reason": "TEXT",
        "card_type": "TEXT NOT NULL DEFAULT 'duration'",
        "activation_limit": "INTEGER NOT NULL DEFAULT 0",
        "activation_count": "INTEGER NOT NULL DEFAULT 0",
        "auto_revoked": "INTEGER NOT NULL DEFAULT 0",
        "features": "TEXT NOT NULL DEFAULT ''",
        "expiry_mode": "TEXT NOT NULL DEFAULT 'relative'",
        "max_concurrent": "INTEGER NOT NULL DEFAULT 0",
    },
    "activations": {
        "session_secret": "TEXT",
        "last_heartbeat_at": "TEXT",
        "heartbeat_count": "INTEGER NOT NULL DEFAULT 0",
    },
    "portal_accounts": {
        "display_name": "TEXT NOT NULL DEFAULT ''",
        "avatar_mime": "TEXT NOT NULL DEFAULT ''",
        "avatar_data": "BLOB",
    },
    "email_outbox": {"claimed_at": "TEXT"},
    "channel_outbox": {"claimed_at": "TEXT"},
}


# 恢复备份时必须存在的表字段，防止结构残缺的文件覆盖线上库。
RESTORE_REQUIRED_COLUMNS = {
    "admins": {"id", "username", "password_hash", "salt", "role", "status"},
    "licenses": {"id", "key_code", "status", "created_at"},
    "activations": {"id", "key_code", "machine_code", "status"},
    "audit_logs": {"id", "action", "created_at"},
}


CARD_TYPE_DURATION = "duration"
CARD_TYPE_ACTIVATION = "activation"
CARD_TYPE_TRIAL = "trial"

ACTION_CODE_MAX_ATTEMPTS = 5

# 服务端性能（问题二）：读路径每次请求都会触发的重活最多每窗口执行一次。
SWEEP_THROTTLE_SECONDS = 60.0
NONCE_PRUNE_THROTTLE_SECONDS = 60.0

# 门户账号热路径（鉴权/资料）不读取头像 BLOB，列表里只需要元数据。
PORTAL_ACCOUNT_COLUMNS = (
    "id, email, password_hash, salt, status, auth_version,"
    " email_verified_at, display_name, avatar_mime,"
    " created_at, last_login_at"
)

# Placeholders in mail templates use {{name}}; values are HTML-escaped when a
# text is rendered so a hostile variable can never inject markup into the
# outgoing message.
_TEMPLATE_PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")


def render_template_text(text, variables=None) -> str:
    """Substitute {{name}} placeholders with HTML-escaped variable values."""
    values = variables if isinstance(variables, dict) else {}

    def replace(match: "re.Match") -> str:
        value = values.get(match.group(1), "")
        if value is None:
            value = ""
        return html.escape(str(value), quote=True)

    return _TEMPLATE_PLACEHOLDER.sub(replace, str(text or ""))


def is_activation_card(lic: dict | None) -> bool:
    """True when the licence is an activation-count card (激活次数卡)."""
    if not lic:
        return False
    # Accept both dict rows and raw sqlite3.Row objects from inside transactions.
    try:
        card_type = lic["card_type"]
    except (KeyError, IndexError, TypeError):
        card_type = None
    return str(card_type or CARD_TYPE_DURATION) == CARD_TYPE_ACTIVATION


def is_exhausted_card(lic: dict | sqlite3.Row | None) -> bool:
    """True once an activation-count card has consumed its full quota."""
    if not is_activation_card(lic):
        return False
    try:
        return int(lic["auto_revoked"] or 0) == 1
    except (KeyError, IndexError, TypeError, ValueError):
        return False


def _row_to_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None


# Activation session secrets let the server recompute client HMAC signatures, so
# they cannot be stored as a one-way hash. They are sealed with a key derived
# from the server config secret, which lives outside license.db, so a stolen
# database file alone is no longer enough to forge device signatures.
SESSION_CIPHER_PREFIX = "enc:v1:"
SESSION_CIPHER_AAD = b"sq-activation-session"


def derive_session_cipher_key(material: str | None) -> bytes | None:
    """Derive the AES-GCM key used to seal activation session secrets."""
    if not material or not isinstance(material, str):
        return None
    return hashlib.sha256(("sq-session-cipher-v1:" + material).encode("utf-8")).digest()


class Database:
    def __init__(self, path: str | Path, secret_material: str | None = None):
        self.path = str(path)
        self.session_key = derive_session_cipher_key(secret_material)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            self.path,
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        # 性能节流状态（问题二）：用单调时钟计窗，None 表示还没跑过。
        self._sweep_at: float | None = None
        self._prune_nonces_at: float | None = None
        self._stats_cache_at: float | None = None
        self._stats_cache_value: dict | None = None
        # P2-14：服务端界面按筛选条件复用日志计数，避免每 10 秒全表 COUNT。
        self._log_count_cache: dict[tuple, tuple[float, int]] = {}
        # 浮动席位租约窗口（秒）；调用方可覆盖（create_app 读取 security 配置）。
        self.seat_lease_seconds = 90
        # Legacy databases predate columns that SCHEMA indexes reference (for
        # example admins.email), so upgrade existing tables first. The second
        # pass then catches tables that this SCHEMA run just created.
        self._migrate()
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        for table, columns in MIGRATIONS.items():
            existing = {
                row["name"] for row in self._conn.execute(f"PRAGMA table_info({table})")
            }
            if not existing:
                # The table is created by SCHEMA further down the init path.
                continue
            for name, decl in columns.items():
                if name not in existing:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")

    def check_health(self) -> dict:
        with self._lock:
            row = self._conn.execute("PRAGMA integrity_check").fetchone()
            integrity = str(row[0]) if row else "unknown"
            foreign_key_errors = len(self._conn.execute("PRAGMA foreign_key_check").fetchall())
        return {
            "integrity": integrity,
            "foreign_key_errors": foreign_key_errors,
        }

    def backup_to(self, path: str | Path) -> Path:
        """Write a consistent online SQLite backup without stopping the API."""
        target = Path(path)
        if target.resolve() == Path(self.path).resolve():
            raise ValueError("不能覆盖当前正在使用的数据库")
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
        try:
            with self._lock:
                destination = sqlite3.connect(temporary)
                try:
                    self._conn.backup(destination)
                    destination.commit()
                finally:
                    destination.close()
            temporary.replace(target)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        return target

    def restore_from(self, path: str | Path) -> None:
        """Replace the live database from a validated SQLite backup."""
        source_path = Path(path)
        if not source_path.is_file():
            raise FileNotFoundError("备份文件不存在")
        if source_path.resolve() == Path(self.path).resolve():
            raise ValueError("不能从当前数据库本身恢复")

        source = sqlite3.connect(str(source_path))
        try:
            check = source.execute("PRAGMA integrity_check").fetchone()
            if not check or str(check[0]).lower() != "ok":
                raise ValueError("备份文件完整性校验失败")
            tables = {
                str(row[0])
                for row in source.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            required = {"admins", "licenses", "activations", "audit_logs"}
            if not required.issubset(tables):
                raise ValueError("所选文件不是本系统的数据库备份")
            for table, columns in RESTORE_REQUIRED_COLUMNS.items():
                found = {
                    str(row[1]) for row in source.execute(f"PRAGMA table_info({table})")
                }
                if not columns.issubset(found):
                    missing = ", ".join(sorted(columns - found))
                    raise ValueError(f"备份缺少必要字段：{table}.{missing}")
            if source.execute("PRAGMA foreign_key_check").fetchall():
                raise ValueError("备份存在关联数据错误，已拒绝恢复")
            with self._lock:
                source.backup(self._conn)
                # Mirror __init__: upgrade the restored tables before the
                # schema indexes are (re)created.
                self._migrate()
                self._conn.executescript(SCHEMA)
                self._migrate()
                self._conn.commit()
        except sqlite3.DatabaseError as exc:
            raise ValueError("无法读取该数据库备份") from exc
        finally:
            source.close()

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
            return cur.lastrowid

    # ------------------------------------------------------------------
    # Administrators
    # ------------------------------------------------------------------
    def ensure_default_admin(
        self, username: str = "admin", password: str | None = None
    ) -> tuple[bool, str | None]:
        """Create the first master account with a random one-time password."""
        if self._fetchone("SELECT id FROM admins LIMIT 1"):
            return False, None
        initial_password = password or security.generate_bootstrap_password()
        self.create_admin(
            username,
            initial_password,
            role="master",
            must_change_password=password is None,
        )
        return True, initial_password

    def create_admin(
        self,
        username: str,
        password: str,
        role: str = "admin",
        must_change_password: bool = False,
    ) -> int:
        pw_hash, salt = security.hash_password(password)
        return self._execute(
            "INSERT INTO admins (username, password_hash, salt, role, status,"
            " auth_version, must_change_password, created_at)"
            " VALUES (?, ?, ?, ?, 'active', 0, ?, ?)",
            (
                username.strip(),
                pw_hash,
                salt,
                role,
                int(bool(must_change_password)),
                security.now_str(),
            ),
        )

    def get_admin(self, username: str) -> dict | None:
        return _row_to_dict(
            self._fetchone("SELECT * FROM admins WHERE username = ?", (username.strip(),))
        )

    def get_admin_by_id(self, admin_id: int) -> dict | None:
        return _row_to_dict(self._fetchone("SELECT * FROM admins WHERE id = ?", (admin_id,)))

    def list_admins(self) -> list[dict]:
        rows = self._fetchall(
            "SELECT id, username, role, status, must_change_password,"
            " email, email_verified_at, created_at, last_login_at"
            " FROM admins ORDER BY id ASC"
        )
        return [dict(r) for r in rows]

    def set_admin_status(self, admin_id: int, status: str) -> None:
        self._execute(
            "UPDATE admins SET status = ?, auth_version = auth_version + 1"
            " WHERE id = ?",
            (status, admin_id),
        )

    def set_admin_password(
        self, admin_id: int, password: str, must_change_password: bool = False
    ) -> None:
        pw_hash, salt = security.hash_password(password)
        self._execute(
            "UPDATE admins SET password_hash = ?, salt = ?,"
            " auth_version = auth_version + 1, must_change_password = ?"
            " WHERE id = ?",
            (pw_hash, salt, int(bool(must_change_password)), admin_id),
        )

    def touch_admin_login(self, admin_id: int) -> None:
        self._execute(
            "UPDATE admins SET last_login_at = ? WHERE id = ?",
            (security.now_str(), admin_id),
        )

    # ------------------------------------------------------------------
    # Licenses
    # ------------------------------------------------------------------
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
        prefix: str = "GSQ",
        duration_unit: str = "day",
        card_type: str = CARD_TYPE_DURATION,
        activation_limit: int = 0,
        features: list[str] | None = None,
        max_concurrent: int = 0,
        expiry_mode: str = "relative",
        fixed_expires_at: str | None = None,
    ) -> tuple[str, list[str]]:
        # UUID-backed batch IDs are collision-resistant. The old second-level
        # timestamp plus three random digits was reproducible under load.
        batch_no = f"B{uuid.uuid4().hex}"
        created_at = security.now_str()
        raw_kind = str(card_type or "").strip().lower()
        if raw_kind == CARD_TYPE_TRIAL:
            kind = CARD_TYPE_TRIAL
        elif raw_kind == CARD_TYPE_ACTIVATION:
            kind = CARD_TYPE_ACTIVATION
        else:
            kind = CARD_TYPE_DURATION
        limit = int(activation_limit or 0)
        # 功能位（Feature Flags）：规范化为列表并序列化存储；空列表存空串。
        feature_list = security.normalize_features(features)
        feature_text = security.features_to_text(feature_list)
        # 浮动席位（max_concurrent>0）：时长卡/试用卡按“同时在线数”计，忽略绑定
        # 设备上限；次数卡是激活次数模型，不支持浮动席位（强制归零）。
        seats = max(0, int(max_concurrent or 0))
        mode = "fixed" if str(expiry_mode or "").strip().lower() == "fixed" else "relative"
        if kind == CARD_TYPE_ACTIVATION:
            seats = 0
        if kind == CARD_TYPE_ACTIVATION:
            if limit <= 0:
                raise ValueError("激活次数卡必须设置大于 0 的激活次数")
            # 次数卡按“可激活台数”计数，用尽即自动吊销，因此不再叠加时长与设备数限制。
            unit = "day"
            duration_days = 0
            max_devices = 0
        elif kind == CARD_TYPE_TRIAL:
            limit = 0
            unit = security.normalize_unit(duration_unit)
            if int(duration_days or 0) <= 0 and mode != "fixed":
                raise ValueError("试用卡必须设置大于 0 的有效期或固定到期时间")
        else:
            limit = 0
            unit = security.normalize_unit(duration_unit)
        fixed_at = None
        if mode == "fixed":
            fixed_at = str(fixed_expires_at or "").strip()
            if security.parse_expiry(fixed_at) is None:
                raise ValueError("固定到期时间格式无效")
        keys: list[str] = []
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                for _ in range(max(1, int(count))):
                    code = self._unique_key(prefix)
                    while code in keys:
                        code = self._unique_key(prefix)
                    self._conn.execute(
                        "INSERT INTO licenses (key_code, edition, card_type, duration_days,"
                        " duration_unit, activation_limit, max_devices, status, batch_no,"
                        " note, created_by, created_at, features, max_concurrent,"
                        " expiry_mode, expires_at)"
                        " VALUES (?, ?, ?, ?, ?, ?, ?, 'unused', ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            code,
                            edition,
                            kind,
                            duration_days,
                            unit,
                            limit,
                            max_devices,
                            batch_no,
                            note,
                            created_by,
                            created_at,
                            feature_text,
                            seats,
                            mode,
                            fixed_at,
                        ),
                    )
                    keys.append(code)
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return batch_no, keys

    def get_license(self, key_code: str) -> dict | None:
        return _row_to_dict(
            self._fetchone(
                "SELECT * FROM licenses WHERE key_code = ?", (security.normalize_key(key_code),)
            )
        )

    @staticmethod
    def _license_filters(
        keyword: str = "", status: str = "", batch_no: str = ""
    ) -> tuple[str, list]:
        sql = ""
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
        return sql, params

    def list_licenses(
        self,
        keyword: str = "",
        status: str = "",
        batch_no: str = "",
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict]:
        self.sweep_expired()
        where, params = self._license_filters(keyword, status, batch_no)
        sql = "SELECT * FROM licenses WHERE 1 = 1" + where
        limit = max(1, min(int(limit or 200), 500))
        offset = max(0, min(int(offset or 0), 1_000_000))
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

    def count_licenses(
        self, keyword: str = "", status: str = "", batch_no: str = ""
    ) -> int:
        self.sweep_expired()
        where, params = self._license_filters(keyword, status, batch_no)
        row = self._fetchone(
            "SELECT COUNT(*) AS n FROM licenses WHERE 1 = 1" + where,
            tuple(params),
        )
        return int(row["n"]) if row else 0

    def list_batches(
        self, keyword: str = "", limit: int = 200, offset: int = 0
    ) -> list[dict]:
        self.sweep_expired()
        where = " WHERE batch_no IS NOT NULL AND batch_no <> ''"
        params: list = []
        if keyword:
            like = f"%{keyword.strip()}%"
            where += " AND (batch_no LIKE ? OR note LIKE ? OR created_by LIKE ?)"
            params += [like, like, like]
        limit = max(1, min(int(limit or 200), 500))
        offset = max(0, min(int(offset or 0), 1_000_000))
        sql = (
            "SELECT batch_no, COUNT(*) AS total,"
            " SUM(CASE WHEN status = 'unused' THEN 1 ELSE 0 END) AS unused,"
            " SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) AS active,"
            " SUM(CASE WHEN status = 'frozen' THEN 1 ELSE 0 END) AS frozen,"
            " SUM(CASE WHEN status = 'revoked' THEN 1 ELSE 0 END) AS revoked,"
            " SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END) AS expired,"
            " SUM(CASE WHEN auto_revoked = 1 THEN 1 ELSE 0 END) AS exhausted,"
            " SUM(CASE WHEN card_type = 'activation' THEN 1 ELSE 0 END) AS activation_cards,"
            " MIN(created_at) AS created_at, MAX(created_at) AS last_created_at,"
            " MAX(created_by) AS created_by, MAX(note) AS note"
            " FROM licenses" + where +
            " GROUP BY batch_no ORDER BY MAX(id) DESC LIMIT ? OFFSET ?"
        )
        rows = self._fetchall(sql, tuple(params + [limit, offset]))
        return [dict(r) for r in rows]

    def count_batches(self, keyword: str = "") -> int:
        self.sweep_expired()
        where = " WHERE batch_no IS NOT NULL AND batch_no <> ''"
        params: list = []
        if keyword:
            like = f"%{keyword.strip()}%"
            where += " AND (batch_no LIKE ? OR note LIKE ? OR created_by LIKE ?)"
            params += [like, like, like]
        row = self._fetchone(
            "SELECT COUNT(DISTINCT batch_no) AS n FROM licenses" + where,
            tuple(params),
        )
        return int(row["n"]) if row else 0

    # ------------------------------------------------------------------
    # A5: configurable alert rules, events and metric overview
    # ------------------------------------------------------------------
    ALERT_RULE_FIELDS = (
        "name",
        "metric",
        "operator",
        "threshold",
        "window_seconds",
        "severity",
        "cooldown_seconds",
        "channels",
        "enabled",
        "note",
    )

    @staticmethod
    def _alert_int(value, default: int, minimum: int, maximum: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            parsed = default
        return max(minimum, min(parsed, maximum))

    @staticmethod
    def _alert_float(value, default: float = 0.0) -> float:
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return default
        return parsed if math.isfinite(parsed) else default

    @staticmethod
    def _alert_channels(channels) -> list[str]:
        """Normalize the channel list persisted in ``channels_json``.

        A5 only supports e-mail; anything else is stored as-is for A7 but
        the API layer rejects unknown channels. An empty list falls back to
        e-mail, matching the engine's own default.
        """
        if channels is None:
            return ["email"]
        if isinstance(channels, str):
            channels = [channels]
        if not isinstance(channels, (list, tuple, set)):
            return ["email"]
        result: list[str] = []
        for item in channels:
            value = str(item or "").strip().lower()
            if value and value not in result:
                result.append(value)
        return result or ["email"]

    @staticmethod
    def _alert_rule_dict(row) -> dict:
        """Decode ``channels_json`` so callers always see a channel list."""
        rule = dict(row)
        try:
            parsed = json.loads(rule.get("channels_json") or "[]")
        except (TypeError, ValueError):
            parsed = []
        if not isinstance(parsed, list):
            parsed = []
        rule["channels"] = [str(item) for item in parsed if str(item or "").strip()]
        return rule

    def create_alert_rule(
        self,
        name,
        metric,
        operator,
        threshold,
        window_seconds=600,
        severity="warning",
        cooldown_seconds=3600,
        channels=None,
        enabled=True,
        note="",
    ) -> int:
        now = security.now_str()
        return self._execute(
            "INSERT INTO alert_rules (name, metric, operator, threshold,"
            " window_seconds, severity, cooldown_seconds, channels_json, enabled,"
            " note, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(name or "").strip()[:64],
                str(metric or "").strip()[:64],
                str(operator or "gte").strip().lower()[:16],
                self._alert_float(threshold),
                self._alert_int(window_seconds, 600, 60, 86400),
                str(severity or "warning").strip().lower()[:16],
                self._alert_int(cooldown_seconds, 3600, 60, 86400),
                json.dumps(self._alert_channels(channels), ensure_ascii=False),
                1 if enabled else 0,
                str(note or "")[:200],
                now,
                now,
            ),
        )

    def list_alert_rules(self) -> list[dict]:
        rows = self._fetchall("SELECT * FROM alert_rules ORDER BY id DESC")
        return [self._alert_rule_dict(row) for row in rows]

    def get_alert_rule(self, rule_id) -> dict | None:
        try:
            rid = int(rule_id)
        except (TypeError, ValueError):
            return None
        row = self._fetchone("SELECT * FROM alert_rules WHERE id = ?", (rid,))
        return self._alert_rule_dict(row) if row is not None else None

    def update_alert_rule(self, rule_id, **fields) -> bool:
        try:
            rid = int(rule_id)
        except (TypeError, ValueError):
            return False
        if not self._fetchone("SELECT id FROM alert_rules WHERE id = ?", (rid,)):
            return False
        assignments: list[str] = []
        params: list = []
        for key in self.ALERT_RULE_FIELDS:
            if key not in fields:
                continue
            value = fields[key]
            if key == "channels":
                assignments.append("channels_json = ?")
                params.append(
                    json.dumps(self._alert_channels(value), ensure_ascii=False)
                )
            elif key == "enabled":
                assignments.append("enabled = ?")
                params.append(1 if value else 0)
            elif key == "threshold":
                assignments.append("threshold = ?")
                params.append(self._alert_float(value))
            elif key == "window_seconds":
                assignments.append("window_seconds = ?")
                params.append(self._alert_int(value, 600, 60, 86400))
            elif key == "cooldown_seconds":
                assignments.append("cooldown_seconds = ?")
                params.append(self._alert_int(value, 3600, 60, 86400))
            elif key == "name":
                assignments.append("name = ?")
                params.append(str(value or "").strip()[:64])
            elif key == "note":
                assignments.append("note = ?")
                params.append(str(value or "")[:200])
            else:
                # metric / operator / severity
                assignments.append(f"{key} = ?")
                params.append(str(value or "").strip().lower()[:64])
        if not assignments:
            return True
        assignments.append("updated_at = ?")
        params.append(security.now_str())
        params.append(rid)
        with self._lock:
            cur = self._conn.execute(
                "UPDATE alert_rules SET " + ", ".join(assignments) + " WHERE id = ?",
                tuple(params),
            )
            return int(cur.rowcount or 0) > 0

    def delete_alert_rule(self, rule_id) -> bool:
        try:
            rid = int(rule_id)
        except (TypeError, ValueError):
            return False
        with self._lock:
            cur = self._conn.execute("DELETE FROM alert_rules WHERE id = ?", (rid,))
            return int(cur.rowcount or 0) > 0

    def add_alert_event(
        self,
        rule_id,
        rule_name,
        metric,
        value,
        threshold,
        operator,
        severity,
        payload=None,
    ) -> int:
        try:
            payload_json = json.dumps(
                payload if isinstance(payload, dict) else {}, ensure_ascii=False
            )
        except (TypeError, ValueError):
            payload_json = "{}"
        return self._execute(
            "INSERT INTO alert_events (rule_id, rule_name, metric, value, threshold,"
            " operator, severity, status, payload_json, notified, fired_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, 'firing', ?, 0, ?)",
            (
                int(rule_id or 0),
                str(rule_name or "")[:64],
                str(metric or "")[:64],
                self._alert_float(value),
                self._alert_float(threshold),
                str(operator or "gte").strip().lower()[:16],
                str(severity or "warning").strip().lower()[:16],
                payload_json,
                security.now_str(),
            ),
        )

    def list_alert_events(self, status="", limit=200, offset=0) -> tuple[list[dict], int]:
        limit = self._bounded_limit(limit, 200)
        offset = self._bounded_offset(offset)
        where = ""
        params: list = []
        wanted = str(status or "").strip()
        if wanted:
            where = " WHERE status = ?"
            params.append(wanted[:32])
        rows = self._fetchall(
            "SELECT * FROM alert_events" + where + " ORDER BY id DESC LIMIT ? OFFSET ?",
            tuple(params + [limit, offset]),
        )
        total_row = self._fetchone(
            "SELECT COUNT(*) AS n FROM alert_events" + where, tuple(params)
        )
        return [dict(r) for r in rows], (int(total_row["n"]) if total_row else 0)

    def get_latest_alert_event(self, rule_id) -> dict | None:
        try:
            rid = int(rule_id)
        except (TypeError, ValueError):
            return None
        return _row_to_dict(
            self._fetchone(
                "SELECT * FROM alert_events WHERE rule_id = ? ORDER BY id DESC LIMIT 1",
                (rid,),
            )
        )

    def resolve_alert_event(self, event_id) -> bool:
        """Mark an event resolved; idempotent, False only when missing."""
        try:
            eid = int(event_id)
        except (TypeError, ValueError):
            return False
        with self._lock:
            row = self._conn.execute(
                "SELECT status FROM alert_events WHERE id = ?", (eid,)
            ).fetchone()
            if row is None:
                return False
            if str(row["status"]) != "resolved":
                self._conn.execute(
                    "UPDATE alert_events SET status = 'resolved', resolved_at = ?"
                    " WHERE id = ?",
                    (security.now_str(), eid),
                )
            return True

    def ack_alert_event(self, event_id) -> bool:
        """Acknowledge a firing event; never revives a resolved one."""
        try:
            eid = int(event_id)
        except (TypeError, ValueError):
            return False
        with self._lock:
            row = self._conn.execute(
                "SELECT status FROM alert_events WHERE id = ?", (eid,)
            ).fetchone()
            if row is None:
                return False
            if str(row["status"]) == "firing":
                self._conn.execute(
                    "UPDATE alert_events SET status = 'acked', acked_at = ?"
                    " WHERE id = ?",
                    (security.now_str(), eid),
                )
            return True

    def mark_alert_event_notified(self, event_id) -> None:
        try:
            eid = int(event_id)
        except (TypeError, ValueError):
            return None
        self._execute(
            "UPDATE alert_events SET notified = 1 WHERE id = ?", (eid,)
        )
        return None

    def alert_metrics(self, window_seconds=600) -> dict:
        """Contract section 1 metric snapshot for the given window.

        All timestamps are compared as ``security.now_str()`` text in the
        fixed ``security.TIME_FORMAT`` so lexical and chronological order
        agree. ``sweep_expired`` runs first (same as ``stats``) so the
        expiration metrics see materialized statuses.
        """
        try:
            window = int(window_seconds)
        except (TypeError, ValueError):
            window = 600
        window = max(1, min(window, 30 * 86400))
        self.sweep_expired()
        now = security.now_str()
        now_at = security.parse_expiry(now) or datetime.now()
        start = (now_at - timedelta(seconds=window)).strftime(security.TIME_FORMAT)
        soon = (now_at + timedelta(days=7)).strftime(security.TIME_FORMAT)

        activation = self._fetchone(
            "SELECT COUNT(*) AS total,"
            " SUM(CASE WHEN activated_at IS NOT NULL AND activated_at <> ''"
            " THEN 1 ELSE 0 END) AS activated"
            " FROM licenses WHERE created_at >= ? AND created_at <= ?",
            (start, now),
        )
        online = self._fetchone(
            "SELECT COUNT(*) AS n FROM activations WHERE status = 'active'"
            " AND last_heartbeat_at IS NOT NULL AND last_heartbeat_at >= ?",
            (start,),
        )
        expiration = self._fetchone(
            "SELECT COUNT(*) AS total,"
            " SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END) AS expired"
            " FROM licenses WHERE expires_at IS NOT NULL AND expires_at <> ''"
            " AND expires_at >= ? AND expires_at <= ?",
            (start, now),
        )
        expiring = self._fetchone(
            "SELECT COUNT(*) AS n FROM licenses"
            " WHERE expires_at IS NOT NULL AND expires_at <> ''"
            " AND expires_at > ? AND expires_at <= ?"
            " AND status NOT IN ('revoked', 'expired') AND auto_revoked = 0",
            (now, soon),
        )
        failed = self._fetchone(
            "SELECT COUNT(*) AS n FROM audit_logs WHERE action = '激活失败'"
            " AND created_at >= ? AND created_at <= ?",
            (start, now),
        )
        risk_count = self._fetchone(
            "SELECT COUNT(*) AS n FROM risk_events"
            " WHERE created_at >= ? AND created_at <= ?",
            (start, now),
        )
        tamper_count = self._fetchone(
            "SELECT COUNT(*) AS n FROM tamper_events"
            " WHERE created_at >= ? AND created_at <= ?",
            (start, now),
        )

        def ratio(numerator: int, denominator: int) -> float:
            if denominator <= 0:
                return 0.0
            return round(numerator * 100.0 / denominator, 2)

        activation_total = int(activation["total"] or 0) if activation else 0
        activation_count = int(activation["activated"] or 0) if activation else 0
        expiration_total = int(expiration["total"] or 0) if expiration else 0
        expiration_count = int(expiration["expired"] or 0) if expiration else 0
        return {
            "activation_rate": ratio(activation_count, activation_total),
            "online_devices": int(online["n"] or 0) if online else 0,
            "expiration_rate": ratio(expiration_count, expiration_total),
            "expiring_soon": int(expiring["n"] or 0) if expiring else 0,
            "failed_activations": int(failed["n"] or 0) if failed else 0,
            "risk_events": int(risk_count["n"] or 0) if risk_count else 0,
            "tamper_events": int(tamper_count["n"] or 0) if tamper_count else 0,
        }

    def sweep_expired(self, force: bool = False) -> int:
        """Materialize effective expiry before list/stat/read operations.

        读路径每次请求都会调用这里，因此真正的 UPDATE 被节流到
        ``SWEEP_THROTTLE_SECONDS`` 内最多执行一次；返回实际改动的行数
        （被节流时返回 0）。必须看到最新状态的写路径可传 ``force=True``。
        """
        now_mono = time.monotonic()
        with self._lock:
            if (
                not force
                and self._sweep_at is not None
                and now_mono - self._sweep_at < SWEEP_THROTTLE_SECONDS
            ):
                return 0
            self._sweep_at = now_mono
            now = security.now_str()
            healed = self._conn.execute(
                "UPDATE licenses SET status = 'revoked', prev_status = NULL,"
                " frozen_until = NULL, freeze_reason = NULL"
                " WHERE auto_revoked = 1 AND status != 'revoked'"
            )
            cur = self._conn.execute(
                "UPDATE licenses SET prev_status = CASE"
                " WHEN prev_status IS NULL THEN status ELSE prev_status END,"
                " status = 'expired'"
                " WHERE status NOT IN ('expired', 'revoked')"
                " AND expires_at IS NOT NULL AND expires_at <= ?",
                (now,),
            )
            return healed.rowcount + cur.rowcount

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
        # Device bindings are preserved. Revocation is an authorization state,
        # not an instruction to erase the customer's device history.

    def restore_license(self, key_code: str) -> str | None:
        self.sweep_expired()
        code = security.normalize_key(key_code)
        lic = self.get_license(code)
        if not lic:
            return None
        if is_exhausted_card(lic):
            # 次数用尽触发的自动吊销是终态，不能像普通吊销那样恢复。
            if lic["status"] != "revoked":
                self._execute(
                    "UPDATE licenses SET status = 'revoked', prev_status = NULL,"
                    " frozen_until = NULL, freeze_reason = NULL WHERE key_code = ?",
                    (code,),
                )
            return "__exhausted__"
        if lic["status"] != "revoked":
            return None
        if security.is_expired(lic.get("expires_at")):
            return "__expired__"
        target = lic["prev_status"] or "unused"
        if target in ("revoked", "expired", "frozen"):
            target = "unused"
        self._execute(
            "UPDATE licenses SET status = ?, prev_status = NULL, frozen_until = NULL,"
            " freeze_reason = NULL WHERE key_code = ?",
            (target, code),
        )
        return target

    def renew_license(
        self, key_code: str, duration_days: int, duration_unit: str = "day"
    ) -> tuple[str, str] | None:
        """Extend a finite license; permanent licenses are not modified."""
        self.sweep_expired()
        code = security.normalize_key(key_code)
        lic = self.get_license(code)
        if not lic:
            return None
        if is_activation_card(lic):
            # 次数卡没有有效期，续期无从生效，直接拒绝。
            return None
        if not lic.get("expires_at"):
            return None
        if int(duration_days or 0) <= 0:
            return None
        base = security.parse_expiry(lic["expires_at"])
        from datetime import datetime, timedelta

        now = datetime.now()
        start = base if base and base > now else now
        seconds = int(duration_days) * security.unit_seconds(duration_unit)
        new_expiry = (start + timedelta(seconds=seconds)).strftime(security.TIME_FORMAT)
        target = lic["status"]
        if target == "expired":
            target = lic.get("prev_status") or "unused"
            if target in ("revoked", "expired", "frozen"):
                target = "unused"
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "UPDATE licenses SET expires_at = ?, status = ?, prev_status = NULL,"
                    " frozen_until = NULL, freeze_reason = NULL WHERE key_code = ?",
                    (new_expiry, target, code),
                )
                # Keep existing device bindings aligned with the renewed
                # license expiry; otherwise a valid renewal would still be
                # rejected by the copied activation expiry.
                self._conn.execute(
                    "UPDATE activations SET expires_at = ? WHERE key_code = ?",
                    (new_expiry, code),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return target, new_expiry

    def freeze_license(self, key_code: str, frozen_until: str, reason: str = "") -> str | None:
        self.sweep_expired()
        code = security.normalize_key(key_code)
        now = security.now_str()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                lic = self._conn.execute(
                    "SELECT * FROM licenses WHERE key_code = ?", (code,)
                ).fetchone()
                if (
                    not lic
                    or is_exhausted_card(lic)
                    or lic["status"] in ("revoked", "expired")
                ):
                    self._conn.commit()
                    return None
                if security.is_expired(lic["expires_at"]):
                    self._conn.execute(
                        "UPDATE licenses SET prev_status = CASE"
                        " WHEN prev_status IS NULL THEN status ELSE prev_status END,"
                        " status = 'expired', frozen_until = NULL,"
                        " freeze_reason = NULL WHERE key_code = ?",
                        (code,),
                    )
                    self._conn.commit()
                    return None
                prev = lic["prev_status"] if lic["status"] == "frozen" else lic["status"]
                if prev in ("revoked", "expired", "frozen"):
                    prev = "unused"
                cur = self._conn.execute(
                    "UPDATE licenses SET status = 'frozen', frozen_until = ?,"
                    " prev_status = ?, freeze_reason = ?"
                    " WHERE key_code = ? AND auto_revoked = 0"
                    " AND status NOT IN ('revoked', 'expired')"
                    " AND (expires_at IS NULL OR expires_at > ?)",
                    (frozen_until, prev, reason, code, now),
                )
                self._conn.commit()
                return prev if cur.rowcount else None
            except Exception:
                self._conn.rollback()
                raise

    def unfreeze_license(self, key_code: str) -> str | None:
        self.sweep_expired()
        code = security.normalize_key(key_code)
        now = security.now_str()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                lic = self._conn.execute(
                    "SELECT * FROM licenses WHERE key_code = ?", (code,)
                ).fetchone()
                if not lic or lic["status"] != "frozen":
                    self._conn.commit()
                    return None
                if is_exhausted_card(lic):
                    self._conn.execute(
                        "UPDATE licenses SET status = 'revoked', prev_status = NULL,"
                        " frozen_until = NULL, freeze_reason = NULL WHERE key_code = ?",
                        (code,),
                    )
                    self._conn.commit()
                    return "__exhausted__"
                if security.is_expired(lic["expires_at"]):
                    self._conn.execute(
                        "UPDATE licenses SET status = 'expired', frozen_until = NULL,"
                        " freeze_reason = NULL WHERE key_code = ?",
                        (code,),
                    )
                    self._conn.commit()
                    return "__expired__"
                target = lic["prev_status"] or "active"
                if target in ("revoked", "expired", "frozen"):
                    target = "unused"
                cur = self._conn.execute(
                    "UPDATE licenses SET status = ?, frozen_until = NULL,"
                    " prev_status = NULL, freeze_reason = NULL"
                    " WHERE key_code = ? AND status = 'frozen' AND auto_revoked = 0"
                    " AND (expires_at IS NULL OR expires_at > ?)",
                    (target, code, now),
                )
                self._conn.commit()
                return target if cur.rowcount else None
            except Exception:
                self._conn.rollback()
                raise


    def release_expired_freeze(self, key_code: str = "") -> int:
        self.sweep_expired()
        now = security.now_str()
        sql = (
            "UPDATE licenses SET status = CASE"
            " WHEN auto_revoked = 1 THEN 'revoked'"
            " WHEN expires_at IS NOT NULL AND expires_at <= ? THEN 'expired'"
            " ELSE COALESCE(prev_status, 'active') END,"
            " prev_status = NULL, frozen_until = NULL, freeze_reason = NULL"
            " WHERE status = 'frozen' AND frozen_until IS NOT NULL AND frozen_until <= ?"
        )
        params: tuple = (now, now)
        if key_code:
            sql += " AND key_code = ?"
            params = (now, now, security.normalize_key(key_code))
        with self._lock:
            cur = self._conn.execute(sql, params)
            return cur.rowcount

    def revoke_batch(self, batch_no: str) -> int:
        self.sweep_expired()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "UPDATE licenses SET prev_status = status WHERE batch_no = ?"
                    " AND status NOT IN ('revoked', 'expired', 'frozen')",
                    (batch_no,),
                )
                cur = self._conn.execute(
                    "UPDATE licenses SET status = 'revoked' WHERE batch_no = ?"
                    " AND status != 'revoked'",
                    (batch_no,),
                )
                # Preserve activations for the same reason as individual revoke.
                self._conn.commit()
                return cur.rowcount
            except Exception:
                self._conn.rollback()
                raise


    def restore_batch(self, batch_no: str) -> int:
        """Undo revoke_batch for a whole batch.

        Each revoked key returns to the status it held before the batch
        revoke; a key whose licence has since run out stays expired, exactly
        like the single-key restore. Returns the number of rows restored.
        """
        self.sweep_expired()
        now = security.now_str()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                cur = self._conn.execute(
                    "UPDATE licenses SET status = CASE"
                    " WHEN expires_at IS NOT NULL AND expires_at <= ? THEN 'expired'"
                    " WHEN prev_status IS NULL"
                    "   OR prev_status IN ('revoked', 'expired', 'frozen')"
                    "   THEN 'unused'"
                    " ELSE prev_status END,"
                    " prev_status = NULL, frozen_until = NULL, freeze_reason = NULL"
                    " WHERE batch_no = ? AND status = 'revoked' AND auto_revoked = 0",
                    (now, batch_no),
                )
                self._conn.commit()
                return cur.rowcount
            except Exception:
                self._conn.rollback()
                raise

    def delete_license(self, key_code: str) -> None:
        code = security.normalize_key(key_code)
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute("DELETE FROM activations WHERE key_code = ?", (code,))
                self._conn.execute("DELETE FROM licenses WHERE key_code = ?", (code,))
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    # ------------------------------------------------------------------
    # Activations
    # ------------------------------------------------------------------
    def get_activation(self, key_code: str, machine_code: str) -> dict | None:
        row = _row_to_dict(
            self._fetchone(
                "SELECT * FROM activations WHERE key_code = ? AND machine_code = ?",
                (security.normalize_key(key_code), machine_code),
            )
        )
        if row:
            row["session_secret"] = self._unseal_secret(row.get("session_secret"))
        return row

    def find_activation_by_machine(self, machine_code: str) -> dict | None:
        """Look up the most recent activation for a machine code.

        Used by tamper/risk alerting to resolve which licence (and therefore
        which bound portal mailbox) an alert belongs to.
        """
        machine = str(machine_code or "").strip().upper()
        if not machine:
            return None
        return _row_to_dict(
            self._fetchone(
                "SELECT * FROM activations WHERE machine_code = ?"
                " ORDER BY last_heartbeat_at DESC, id DESC LIMIT 1",
                (machine,),
            )
        )

    def list_activations(self, key_code: str) -> list[dict]:
        # Never expose the session secret through the administrative API.
        rows = self._fetchall(
            "SELECT id, license_id, key_code, machine_code, device_name, status,"
            " activated_at, expires_at, last_verified_at, last_heartbeat_at,"
            " heartbeat_count FROM activations WHERE key_code = ? ORDER BY id DESC",
            (security.normalize_key(key_code),),
        )
        return [dict(r) for r in rows]

    def count_active_activations(self, license_id: int) -> int:
        row = self._fetchone(
            "SELECT COUNT(*) AS n FROM activations WHERE license_id = ? AND status = 'active'",
            (license_id,),
        )
        return int(row["n"]) if row else 0

    def activate_atomic(
        self,
        license_id: int,
        key_code: str,
        machine_code: str,
        device_name: str,
        expires_at: str | None,
        session_secret: str | None = None,
    ) -> tuple[str, int | None, str | None]:
        """Atomically check the seat limit and create/reactivate one binding."""
        session_secret = self._seal_secret(session_secret)
        code = security.normalize_key(key_code)
        machine = (machine_code or "").strip().upper()
        now = security.now_str()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                lic = self._conn.execute(
                    "SELECT * FROM licenses WHERE id = ?", (license_id,)
                ).fetchone()
                if not lic:
                    self._conn.commit()
                    return "not_found", None, None
                if is_exhausted_card(lic):
                    if lic["status"] != "revoked":
                        self._conn.execute(
                            "UPDATE licenses SET status = 'revoked', prev_status = NULL,"
                            " frozen_until = NULL, freeze_reason = NULL WHERE id = ?",
                            (license_id,),
                        )
                    self._conn.commit()
                    return "exhausted", None, None
                if lic["status"] not in ("unused", "active") or security.is_expired(
                    lic["expires_at"]
                ):
                    self._conn.commit()
                    return "invalid", None, None

                existing = self._conn.execute(
                    "SELECT * FROM activations WHERE key_code = ? AND machine_code = ?",
                    (code, machine),
                ).fetchone()
                # Prefer the expiry persisted on the license. Concurrent first
                # activations can compute slightly different timestamps; the
                # database value is the single source of truth.
                effective_expiry = lic["expires_at"] or expires_at

                # 试用卡防重领：同机同批次仅允许领一张（重激活自己的记录不受限）。
                is_trial = str(lic["card_type"] or "") == CARD_TYPE_TRIAL
                if is_trial and existing is None:
                    claim = self._conn.execute(
                        "SELECT key_code FROM trial_claims"
                        " WHERE machine_code = ? AND batch_no = ?",
                        (machine, lic["batch_no"] or ""),
                    ).fetchone()
                    if claim and str(claim["key_code"] or "") != code:
                        self._conn.commit()
                        return "trial_used", None, None

                count_card = is_activation_card(lic)
                limit = int(lic["activation_limit"] or 0)
                used = int(lic["activation_count"] or 0)
                if count_card and existing is None and (limit <= 0 or used >= limit):
                    # 同一机器重复激活不重复计数，只有首次绑定新机器才消耗次数。
                    self._conn.commit()
                    return "exhausted", None, None

                if existing and existing["status"] == "active":
                    self._conn.execute(
                        "UPDATE activations SET device_name = ?, last_verified_at = ?,"
                        " session_secret = COALESCE(?, session_secret),"
                        " expires_at = COALESCE(?, expires_at) WHERE id = ?",
                        (device_name, now, session_secret, effective_expiry, existing["id"]),
                    )
                    if is_trial:
                        self._record_trial_claim(machine, lic, code, now)
                    self._conn.commit()
                    return "already", existing["id"], effective_expiry

                max_concurrent = int(lic["max_concurrent"] or 0)
                if max_concurrent > 0:
                    # 浮动席位模式：以“活跃租约”（心跳/校验窗口内）计数并发，
                    # 不占用固定设备位；席位满时拒绝本次上线（返回 seats_full，
                    # 不触发换机风控——属于正常竞争，由客户端稍后重试）。
                    since = security.shift_time_str(-int(self.seat_lease_seconds))
                    row = self._conn.execute(
                        "SELECT COUNT(*) AS n FROM activations"
                        " WHERE license_id = ? AND status = 'active'"
                        " AND (last_heartbeat_at >= ? OR last_verified_at >= ?"
                        " OR activated_at >= ?)",
                        (license_id, since, since, since),
                    ).fetchone()
                    if int(row["n"]) >= max_concurrent:
                        self._conn.commit()
                        return "seats_full", None, None
                else:
                    max_devices = int(lic["max_devices"] or 0)
                    if max_devices:
                        row = self._conn.execute(
                            "SELECT COUNT(*) AS n FROM activations"
                            " WHERE license_id = ? AND status = 'active'",
                            (license_id,),
                        ).fetchone()
                        if int(row["n"]) >= max_devices:
                            self._conn.commit()
                            return "limit", None, None

                if existing:
                    self._conn.execute(
                        "UPDATE activations SET status = 'active', device_name = ?,"
                        " activated_at = ?, expires_at = ?, last_verified_at = ?,"
                        " session_secret = COALESCE(?, session_secret) WHERE id = ?",
                        (
                            device_name,
                            now,
                            effective_expiry,
                            now,
                            session_secret,
                            existing["id"],
                        ),
                    )
                    activation_id = existing["id"]
                else:
                    cur = self._conn.execute(
                        "INSERT INTO activations (license_id, key_code, machine_code,"
                        " device_name, status, activated_at, expires_at,"
                        " last_verified_at, session_secret)"
                        " VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?)",
                        (
                            license_id,
                            code,
                            machine,
                            device_name,
                            now,
                            effective_expiry,
                            now,
                            session_secret,
                        ),
                    )
                    activation_id = cur.lastrowid
                    if count_card:
                        used += 1
                if count_card:
                    exhausted = used >= limit
                    self._conn.execute(
                        "UPDATE licenses SET activation_count = ?, status = ?,"
                        " auto_revoked = ?, prev_status = ?,"
                        " activated_at = COALESCE(activated_at, ?),"
                        " expires_at = COALESCE(expires_at, ?) WHERE id = ?",
                        (
                            used,
                            "revoked" if exhausted else "active",
                            1 if exhausted else 0,
                            None if exhausted else lic["prev_status"],
                            now,
                            effective_expiry,
                            license_id,
                        ),
                    )
                else:
                    self._conn.execute(
                        "UPDATE licenses SET status = 'active', activated_at = COALESCE(activated_at, ?),"
                        " expires_at = COALESCE(expires_at, ?) WHERE id = ?",
                        (now, effective_expiry, license_id),
                    )
                if is_trial:
                    self._record_trial_claim(machine, lic, code, now)
                self._conn.commit()
                return "activated", activation_id, effective_expiry
            except Exception:
                self._conn.rollback()
                raise

    def create_activation(
        self,
        license_id: int,
        key_code: str,
        machine_code: str,
        device_name: str,
        expires_at: str | None,
    ) -> int:
        result, activation_id, _ = self.activate_atomic(
            license_id, key_code, machine_code, device_name, expires_at
        )
        if result in ("activated", "already") and activation_id is not None:
            return activation_id
        if result == "limit":
            raise RuntimeError("设备数已达上限")
        if result == "exhausted":
            raise RuntimeError("激活次数已用尽")
        raise RuntimeError("无法创建激活记录")

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

    def _record_trial_claim(self, machine: str, lic, key_code: str, now: str) -> None:
        """记录试用卡领取（同机同批次幂等；调用方须持有事务）。"""
        self._conn.execute(
            "INSERT OR IGNORE INTO trial_claims (machine_code, batch_no, key_code,"
            " claimed_at) VALUES (?, ?, ?, ?)",
            (machine, str(lic["batch_no"] or ""), key_code, now),
        )

    def count_active_seats(self, key_code, since: str, exclude_machine: str = "") -> int:
        """浮动席位：窗口内活跃（心跳/校验/首次激活）的设备数，可排除本机。"""
        sql = (
            "SELECT COUNT(*) AS n FROM activations WHERE key_code = ?"
            " AND status = 'active' AND (last_heartbeat_at >= ? OR"
            " last_verified_at >= ? OR activated_at >= ?)"
        )
        params: list = [security.normalize_key(key_code), str(since), str(since), str(since)]
        if exclude_machine:
            sql += " AND machine_code <> ?"
            params.append(str(exclude_machine).strip().upper())
        row = self._fetchone(sql, tuple(params))
        return int(row["n"]) if row else 0

    def activation_seat_active(self, activation, since: str) -> bool:
        """该激活记录的租约是否仍在窗口内。"""
        if not activation:
            return False
        for field in ("last_heartbeat_at", "last_verified_at", "activated_at"):
            try:
                value = str(activation[field] or "")
            except (KeyError, IndexError, TypeError):
                value = ""
            if value and value >= str(since):
                return True
        return False

    def _seal_secret(self, value: str | None) -> str | None:
        """Encrypt a session secret before it touches the database file."""
        if not value or self.session_key is None:
            return value
        if value.startswith(SESSION_CIPHER_PREFIX):
            return value
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        nonce = os.urandom(12)
        sealed = AESGCM(self.session_key).encrypt(
            nonce, value.encode("utf-8"), SESSION_CIPHER_AAD
        )
        blob = base64.urlsafe_b64encode(nonce + sealed).decode("ascii")
        return SESSION_CIPHER_PREFIX + blob

    def _unseal_secret(self, value: str | None) -> str | None:
        """Reverse :meth:`_seal_secret`; fail closed when the key is missing."""
        if not value or not isinstance(value, str):
            return value
        if not value.startswith(SESSION_CIPHER_PREFIX):
            # Rows written before encryption was introduced stay readable.
            return value
        if self.session_key is None:
            return None
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        try:
            raw = base64.urlsafe_b64decode(
                value[len(SESSION_CIPHER_PREFIX):].encode("ascii")
            )
            if len(raw) <= 12:
                return None
            return AESGCM(self.session_key).decrypt(
                raw[:12], raw[12:], SESSION_CIPHER_AAD
            ).decode("utf-8")
        except Exception:
            return None

    def set_activation_session(self, activation_id: int, session_secret: str) -> None:
        self._execute(
            "UPDATE activations SET session_secret = ? WHERE id = ?",
            (self._seal_secret(session_secret), activation_id),
        )

    def seal_legacy_sessions(self) -> int:
        """Encrypt session secrets written before encryption existed.

        Returns the number of rows upgraded so the caller can report it.
        Legacy plaintext rows stay readable either way, so this is a best-effort
        upgrade rather than a prerequisite for running.
        """
        if self.session_key is None:
            return 0
        rows = self._fetchall(
            "SELECT id, session_secret FROM activations"
            " WHERE session_secret IS NOT NULL AND session_secret != ''"
            " AND session_secret NOT LIKE ?",
            (SESSION_CIPHER_PREFIX + "%",),
        )
        if not rows:
            return 0
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                for row in rows:
                    self._conn.execute(
                        "UPDATE activations SET session_secret = ? WHERE id = ?",
                        (self._seal_secret(row[1]), row[0]),
                    )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return len(rows)

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
            return cur.rowcount == 0

    def prune_nonces(self, before_ts: int) -> int:
        """Delete stale nonces; at most one real pass per minute.

        调用方签名保持不变（仍然传入自己想要的截止时间戳）；落在节流窗口
        内的调用只报告 0 条删除，不做任何写入。
        """
        now_mono = time.monotonic()
        with self._lock:
            if (
                self._prune_nonces_at is not None
                and now_mono - self._prune_nonces_at < NONCE_PRUNE_THROTTLE_SECONDS
            ):
                return 0
            self._prune_nonces_at = now_mono
            cur = self._conn.execute("DELETE FROM nonces WHERE created_at < ?", (before_ts,))
            return cur.rowcount

    def unbind_activation(self, key_code: str, machine_code: str) -> int:
        machine = (machine_code or "").strip().upper()
        with self._lock:
            cur = self._conn.execute(
                "UPDATE activations SET status = 'unbound'"
                " WHERE key_code = ? AND machine_code = ? AND status = 'active'",
                (security.normalize_key(key_code), machine),
            )
            return cur.rowcount

    def update_license_expiry(self, key_code: str, expires_at: str | None) -> None:
        self._execute(
            "UPDATE licenses SET expires_at = ? WHERE key_code = ?",
            (expires_at, security.normalize_key(key_code)),
        )

    def set_license_activated(self, key_code: str) -> None:
        self._execute(
            "UPDATE licenses SET status = 'active', activated_at = ?"
            " WHERE key_code = ? AND status = 'unused'",
            (security.now_str(), security.normalize_key(key_code)),
        )

    # ------------------------------------------------------------------
    # Statistics and audit
    # ------------------------------------------------------------------
    def stats(self) -> dict:
        self.sweep_expired()

        def scalar(sql: str, params: tuple = ()) -> int:
            row = self._fetchone(sql, params)
            return int(row["n"]) if row else 0

        now = security.now_str()
        return {
            "total": scalar("SELECT COUNT(*) AS n FROM licenses"),
            "unused": scalar("SELECT COUNT(*) AS n FROM licenses WHERE status = 'unused'"),
            "active": scalar("SELECT COUNT(*) AS n FROM licenses WHERE status = 'active'"),
            "revoked": scalar("SELECT COUNT(*) AS n FROM licenses WHERE status = 'revoked'"),
            "frozen": scalar("SELECT COUNT(*) AS n FROM licenses WHERE status = 'frozen'"),
            "expired": scalar("SELECT COUNT(*) AS n FROM licenses WHERE status = 'expired'"),
            "exhausted": scalar("SELECT COUNT(*) AS n FROM licenses WHERE auto_revoked = 1"),
            "devices": scalar(
                "SELECT COUNT(*) AS n FROM activations a JOIN licenses l ON l.id = a.license_id"
                " WHERE a.status = 'active'"
                " AND l.status NOT IN ('revoked', 'expired') AND l.auto_revoked = 0"
                " AND (l.expires_at IS NULL OR l.expires_at > ?)",
                (now,),
            ),
            "admins": scalar("SELECT COUNT(*) AS n FROM admins"),
            "batches": scalar(
                "SELECT COUNT(DISTINCT batch_no) AS n FROM licenses"
                " WHERE batch_no IS NOT NULL AND batch_no <> ''"
            ),
        }

    def stats_cached(self, ttl: float = 5.0) -> dict:
        """Return ``stats()``, reusing the last result inside ``ttl`` seconds.

        服务端界面会高频轮询统计；5 秒内复用同一份结果可以避免重复的
        全表 COUNT。``ttl<=0`` 时总是重新计算（测试与强制刷新用）。
        """
        try:
            window = max(0.0, float(ttl))
        except (TypeError, ValueError):
            window = 5.0
        now_mono = time.monotonic()
        with self._lock:
            if (
                self._stats_cache_value is not None
                and self._stats_cache_at is not None
                and now_mono - self._stats_cache_at < window
            ):
                return dict(self._stats_cache_value)
        result = self.stats()
        with self._lock:
            self._stats_cache_at = time.monotonic()
            self._stats_cache_value = dict(result)
        return result

    @staticmethod
    def _clean_log_field(value, limit: int) -> str:
        """Strip control characters and bound length before writing audit rows."""
        text = "".join(ch for ch in str(value or "") if ch >= " " and ch != "\x7f")
        return text[:limit]

    def add_log(self, action: str, actor: str = "", target: str = "", detail: str = "", ip: str = "") -> None:
        self._execute(
            "INSERT INTO audit_logs (actor, action, target, detail, ip, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                self._clean_log_field(actor, 64),
                self._clean_log_field(action, 64),
                self._clean_log_field(target, 128),
                self._clean_log_field(detail, 512),
                self._clean_log_field(ip, 64),
                security.now_str(),
            ),
        )

    @staticmethod
    def _log_filters(
        keyword: str = "", action: str = "", start_at: str = "", end_at: str = ""
    ) -> tuple[str, list]:
        sql = ""
        params: list = []
        if keyword:
            like = f"%{keyword.strip()}%"
            sql += (
                " AND (actor LIKE ? OR action LIKE ? OR target LIKE ?"
                " OR detail LIKE ? OR ip LIKE ?)"
            )
            params += [like, like, like, like, like]
        if action:
            sql += " AND action = ?"
            params.append(action.strip())
        if start_at:
            sql += " AND created_at >= ?"
            params.append(start_at.strip())
        if end_at:
            sql += " AND created_at <= ?"
            params.append(end_at.strip())
        return sql, params

    def list_logs(
        self,
        limit: int = 200,
        offset: int = 0,
        keyword: str = "",
        action: str = "",
        start_at: str = "",
        end_at: str = "",
    ) -> list[dict]:
        where, params = self._log_filters(keyword, action, start_at, end_at)
        limit = max(1, min(int(limit or 200), 1000))
        offset = max(0, min(int(offset or 0), 1_000_000))
        rows = self._fetchall(
            "SELECT * FROM audit_logs WHERE 1 = 1" + where +
            " ORDER BY id DESC LIMIT ? OFFSET ?",
            tuple(params + [limit, offset]),
        )
        return [dict(r) for r in rows]

    def count_logs(
        self,
        keyword: str = "",
        action: str = "",
        start_at: str = "",
        end_at: str = "",
    ) -> int:
        where, params = self._log_filters(keyword, action, start_at, end_at)
        row = self._fetchone(
            "SELECT COUNT(*) AS n FROM audit_logs WHERE 1 = 1" + where,
            tuple(params),
        )
        return int(row["n"]) if row else 0

    def count_logs_cached(
        self,
        ttl: float = 30.0,
        keyword: str = "",
        action: str = "",
        start_at: str = "",
        end_at: str = "",
    ) -> int:
        """Return ``count_logs`` reusing the last result per filter for ``ttl``.

        服务端界面每 10 秒刷新一次日志页，全表 COUNT 会随日志量线性变贵；
        同一筛选条件在 TTL 内复用上次结果。``ttl<=0`` 总是重新计算
        （导出等需要精确值的路径直接调用 ``count_logs``）。
        """
        try:
            window = max(0.0, float(ttl))
        except (TypeError, ValueError):
            window = 30.0
        key = (
            str(keyword or "").strip(),
            str(action or "").strip(),
            str(start_at or "").strip(),
            str(end_at or "").strip(),
        )
        now_mono = time.monotonic()
        with self._lock:
            cached = self._log_count_cache.get(key)
            if cached is not None and now_mono - cached[0] < window:
                return int(cached[1])
        total = self.count_logs(
            keyword=key[0], action=key[1], start_at=key[2], end_at=key[3]
        )
        with self._lock:
            self._log_count_cache[key] = (time.monotonic(), int(total))
            # 关键词搜索可以产生很多组合，缓存只保留最近若干条。
            while len(self._log_count_cache) > 32:
                self._log_count_cache.pop(next(iter(self._log_count_cache)))
        return int(total)

    def list_log_actions(self) -> list[str]:
        rows = self._fetchall(
            "SELECT DISTINCT action FROM audit_logs WHERE action <> '' ORDER BY action"
        )
        return [str(row["action"]) for row in rows]

    def purge_logs(self, before: str) -> int:
        """删除 before（含）之前的审计日志，返回删除条数。"""
        cutoff = str(before or "").strip()
        if len(cutoff) < 10:
            raise ValueError("清理时间格式不正确")
        with self._lock:
            cur = self._conn.execute("DELETE FROM audit_logs WHERE created_at <= ?", (cutoff,))
            self._conn.commit()
        return int(cur.rowcount or 0)

    # ------------------------------------------------------------------
    # P2-13: data retention
    # ------------------------------------------------------------------
    @staticmethod
    def _retention_cutoff(value, default_days: float) -> str | None:
        """Text cutoff for one retention window; ``None`` disables the category.

        ``0``/负数表示该类数据永久保留；非法值回落到默认窗口。时间与
        ``security.now_str()`` 使用同一本地格式，保证文本比较与时间顺序一致。
        """
        try:
            days = float(value)
        except (TypeError, ValueError):
            days = float(default_days)
        if days <= 0:
            return None
        days = min(days, 36500.0)
        return (datetime.now() - timedelta(days=days)).strftime(security.TIME_FORMAT)

    def _delete_before(self, table: str, where: str, params: tuple) -> int:
        with self._lock:
            cur = self._conn.execute(f"DELETE FROM {table} WHERE {where}", params)
            self._conn.commit()
        return int(cur.rowcount or 0)

    def run_maintenance(self, retention: dict | None = None) -> dict:
        """Delete only rows past their retention window; return per-table counts.

        ``retention`` accepts the ``server_config.json → security`` mapping (or
        any dict with the same keys). 队列必须保持投递语义：邮件/渠道 outbox
        只清理 sent/dead 终态，pending/failed/sending 一律保留；告警事件只
        清理 resolved 历史，firing/acked 保持“同规则单活动事件”的不变量。
        """
        settings = dict(retention or {})
        audit_cutoff = self._retention_cutoff(
            settings.get("retention_audit_days"), 180
        )
        event_cutoff = self._retention_cutoff(
            settings.get("retention_events_days"), 365
        )
        code_cutoff = self._retention_cutoff(
            settings.get("retention_codes_days"), 7
        )
        outbox_cutoff = self._retention_cutoff(
            settings.get("retention_outbox_days"), 30
        )

        deleted: dict[str, int] = {
            "audit_logs": 0,
            "tamper_events": 0,
            "risk_events": 0,
            "alert_events": 0,
            "action_codes": 0,
            "email_outbox": 0,
            "channel_outbox": 0,
        }
        if audit_cutoff:
            deleted["audit_logs"] = self._delete_before(
                "audit_logs", "created_at <= ?", (audit_cutoff,)
            )
            with self._lock:
                self._log_count_cache.clear()
        if event_cutoff:
            deleted["tamper_events"] = self._delete_before(
                "tamper_events", "created_at <= ?", (event_cutoff,)
            )
            deleted["risk_events"] = self._delete_before(
                "risk_events", "created_at <= ?", (event_cutoff,)
            )
            deleted["alert_events"] = self._delete_before(
                "alert_events",
                "status = 'resolved' AND COALESCE(resolved_at, fired_at) <= ?",
                (event_cutoff,),
            )
        if code_cutoff:
            deleted["action_codes"] = self._delete_before(
                "action_codes",
                "(expires_at <= ? OR (used_at IS NOT NULL AND used_at <> ''"
                " AND used_at <= ?))",
                (code_cutoff, code_cutoff),
            )
        if outbox_cutoff:
            deleted["email_outbox"] = self._delete_before(
                "email_outbox",
                "(status = 'sent' AND sent_at IS NOT NULL AND sent_at <> ''"
                " AND sent_at <= ?)"
                " OR (status = 'dead' AND created_at <= ?)",
                (outbox_cutoff, outbox_cutoff),
            )
            deleted["channel_outbox"] = self._delete_before(
                "channel_outbox",
                "(status = 'sent' AND sent_at IS NOT NULL AND sent_at <> ''"
                " AND sent_at <= ?)"
                " OR (status = 'dead' AND created_at <= ?)",
                (outbox_cutoff, outbox_cutoff),
            )
        return deleted

    # ------------------------------------------------------------------
    # Release integrity (hashes and tamper events)
    # ------------------------------------------------------------------
    @staticmethod
    def _bounded_limit(limit, default: int = 500) -> int:
        """Clamp a caller-supplied page size into 1..1000."""
        try:
            value = int(limit)
        except (TypeError, ValueError):
            value = default
        return max(1, min(value, 1000))

    @staticmethod
    def _bounded_offset(offset) -> int:
        try:
            value = int(offset)
        except (TypeError, ValueError):
            value = 0
        return max(0, min(value, 1_000_000))

    def upsert_release_hash(
        self,
        file_name,
        sha256,
        size=0,
        version="",
        active=1,
        note="",
    ) -> None:
        """Insert a release hash or refresh the existing (file_name, sha256) row.

        On conflict only size/version/active/note are refreshed; created_at is
        deliberately left at the original registration time so the audit trail
        keeps when the build was first seen.
        """
        name = str(file_name or "").strip()[:255]
        digest = str(sha256 or "").strip().lower()[:128]
        try:
            size_value = max(0, int(size or 0))
        except (TypeError, ValueError):
            size_value = 0
        self._execute(
            "INSERT INTO release_hashes (file_name, version, sha256, size, active,"
            " note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(file_name, sha256) DO UPDATE SET"
            " size = excluded.size, version = excluded.version,"
            " active = excluded.active, note = excluded.note",
            (
                name,
                str(version or "")[:64],
                digest,
                size_value,
                1 if active else 0,
                str(note or "")[:255],
                security.now_str(),
            ),
        )

    def list_release_hashes(self, limit=500) -> list[dict]:
        limit = self._bounded_limit(limit, 500)
        rows = self._fetchall(
            "SELECT * FROM release_hashes ORDER BY file_name ASC, id ASC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in rows]

    def count_active_release_hashes(self) -> int:
        row = self._fetchone(
            "SELECT COUNT(*) AS n FROM release_hashes WHERE active = 1"
        )
        return int(row["n"]) if row else 0

    def match_release_hash(self, sha256, file_name="") -> dict | None:
        digest = str(sha256 or "").strip().lower()
        if not digest:
            return None
        name = str(file_name or "").strip()
        if name:
            row = self._fetchone(
                "SELECT * FROM release_hashes WHERE sha256 = ? AND active = 1"
                " AND file_name = ? ORDER BY id DESC LIMIT 1",
                (digest, name),
            )
        else:
            row = self._fetchone(
                "SELECT * FROM release_hashes WHERE sha256 = ? AND active = 1"
                " ORDER BY id DESC LIMIT 1",
                (digest,),
            )
        return _row_to_dict(row)

    def set_release_hash_active(self, file_name, sha256, active) -> bool:
        name = str(file_name or "").strip()
        digest = str(sha256 or "").strip().lower()
        if not name or not digest:
            return False
        with self._lock:
            cur = self._conn.execute(
                "UPDATE release_hashes SET active = ?"
                " WHERE file_name = ? AND sha256 = ?",
                (1 if active else 0, name, digest),
            )
            return int(cur.rowcount or 0) > 0

    # ------------------------------------------------------------------
    # Release identity (问题三): release_id + manifest digest
    # ------------------------------------------------------------------
    def upsert_release_meta(
        self, release_id, manifest_sha256, version="", active=1,
        retire_others: bool = False,
    ) -> None:
        """Record or refresh one release_meta row.

        ``created_at`` keeps the first-seen time; re-importing the same
        release_id refreshes the manifest digest, version and active flag.
        An empty release_id is ignored (老清单没有发布标识，不参与绑定).
        ``retire_others=True`` 在同一事务里把其它 release_meta 置为
        inactive（P1-11 发布自动退役）。
        """
        rid = str(release_id or "").strip().lower()[:64]
        if not rid:
            return
        params = (
            rid,
            str(manifest_sha256 or "").strip().lower()[:64],
            str(version or "")[:64],
            1 if active else 0,
            security.now_str(),
        )
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "INSERT INTO release_meta (release_id, manifest_sha256, version,"
                    " active, created_at) VALUES (?, ?, ?, ?, ?)"
                    " ON CONFLICT(release_id) DO UPDATE SET"
                    " manifest_sha256 = excluded.manifest_sha256,"
                    " version = excluded.version, active = excluded.active",
                    params,
                )
                if retire_others:
                    self._conn.execute(
                        "UPDATE release_meta SET active = 0 WHERE release_id <> ?",
                        (rid,),
                    )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def retire_release_hashes_except(self, keep_hashes) -> int:
        """Deactivate whitelisted hashes that are not part of the newest manifest.

        ``release_hashes`` 没有 release_id 归属列；新清单一到手时，只有清单
        里出现的 sha256 仍算当前构建，其余哈希置为 inactive，旧 exe 便无法
        再通过 attest 的白名单检查。返回被停用的行数。
        """
        digests = []
        for value in keep_hashes or ():
            digest = str(value or "").strip().lower()
            if digest and digest not in digests:
                digests.append(digest)
        with self._lock:
            if digests:
                placeholders = ",".join("?" for _ in digests)
                cur = self._conn.execute(
                    "UPDATE release_hashes SET active = 0"
                    f" WHERE active = 1 AND sha256 NOT IN ({placeholders})",
                    tuple(digests),
                )
            else:
                cur = self._conn.execute(
                    "UPDATE release_hashes SET active = 0 WHERE active = 1"
                )
            self._conn.commit()
        return int(cur.rowcount or 0)

    def count_active_release_meta(self) -> int:
        row = self._fetchone(
            "SELECT COUNT(*) AS n FROM release_meta WHERE active = 1"
        )
        return int(row["n"]) if row else 0

    def list_active_release_meta(self, limit=200) -> list[dict]:
        limit = self._bounded_limit(limit, 200)
        rows = self._fetchall(
            "SELECT * FROM release_meta WHERE active = 1"
            " ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in rows]

    def match_active_release_meta(self, release_id) -> dict | None:
        rid = str(release_id or "").strip().lower()
        if not rid:
            return None
        return _row_to_dict(
            self._fetchone(
                "SELECT * FROM release_meta"
                " WHERE release_id = ? AND active = 1 LIMIT 1",
                (rid,),
            )
        )

    def add_tamper_event(
        self,
        role,
        exe_name,
        exe_hash,
        version,
        machine_code,
        ip,
        reason,
        detail="",
    ) -> int:
        return self._execute(
            "INSERT INTO tamper_events (role, exe_name, exe_hash, version,"
            " machine_code, ip, reason, detail, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(role or "")[:64],
                str(exe_name or "")[:255],
                str(exe_hash or "").strip().lower()[:128],
                str(version or "")[:64],
                str(machine_code or "").strip().upper()[:128],
                str(ip or "")[:128],
                str(reason or "")[:255],
                str(detail or "")[:8192],
                security.now_str(),
            ),
        )

    def list_tamper_events(self, limit=200, offset=0) -> tuple[list[dict], int]:
        limit = self._bounded_limit(limit, 200)
        offset = self._bounded_offset(offset)
        rows = self._fetchall(
            "SELECT * FROM tamper_events ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        total_row = self._fetchone("SELECT COUNT(*) AS n FROM tamper_events")
        return [dict(r) for r in rows], (int(total_row["n"]) if total_row else 0)

    # ------------------------------------------------------------------
    # E-mail templates and outbox (P1)
    # ------------------------------------------------------------------
    @staticmethod
    def _normalize_email(email) -> str:
        return str(email or "").strip().lower()

    def seed_email_templates(self, templates: dict) -> int:
        """Insert templates that are still missing; existing codes are kept."""
        if not isinstance(templates, dict):
            return 0
        now = security.now_str()
        inserted = 0
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                for code, item in templates.items():
                    if not isinstance(item, dict) or item.get("subject") is None:
                        continue
                    cur = self._conn.execute(
                        "INSERT OR IGNORE INTO email_templates (code, subject, body,"
                        " locale, updated_at) VALUES (?, ?, ?, ?, ?)",
                        (
                            str(code or "").strip()[:64],
                            str(item.get("subject") or ""),
                            str(item.get("body") or ""),
                            str(item.get("locale") or "zh-CN")[:16],
                            now,
                        ),
                    )
                    inserted += int(cur.rowcount or 0)
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return inserted

    def upsert_email_template(self, code, subject, body, locale="zh-CN") -> None:
        name = str(code or "").strip()[:64]
        if not name:
            raise ValueError("邮件模板 code 不能为空")
        self._execute(
            "INSERT INTO email_templates (code, subject, body, locale, updated_at)"
            " VALUES (?, ?, ?, ?, ?)"
            " ON CONFLICT(code) DO UPDATE SET subject = excluded.subject,"
            " body = excluded.body, locale = excluded.locale,"
            " updated_at = excluded.updated_at",
            (
                name,
                str(subject or ""),
                str(body or ""),
                str(locale or "zh-CN")[:16],
                security.now_str(),
            ),
        )

    def get_email_template(self, code) -> dict | None:
        return _row_to_dict(
            self._fetchone(
                "SELECT * FROM email_templates WHERE code = ?",
                (str(code or "").strip()[:64],),
            )
        )

    def enqueue_email(
        self, to_email, template_code, variables=None, dedupe_key=""
    ) -> int | None:
        """Queue one mail; a dedupe_key collision returns None and writes nothing."""
        email = self._normalize_email(to_email)
        if not email or "@" not in email or len(email) > 254:
            raise ValueError("收件邮箱无效")
        code = str(template_code or "").strip()[:64]
        if not code:
            raise ValueError("邮件模板 code 不能为空")
        payload = variables if isinstance(variables, dict) else {}
        try:
            variables_json = json.dumps(
                payload, ensure_ascii=False, separators=(",", ":")
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("邮件变量无法序列化") from exc
        if len(variables_json) > 65536:
            raise ValueError("邮件变量过大")
        # The rendered copy is stored next to the queue row so a later
        # template edit cannot change a message that is already waiting.
        template = self.get_email_template(code) or {}
        subject = render_template_text(template.get("subject") or "", payload)
        body = render_template_text(template.get("body") or "", payload)
        key = str(dedupe_key or "").strip()[:200] or None
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO email_outbox (to_email, template_code, variables_json,"
                " subject, body, status, attempts, max_attempts, next_retry_at,"
                " last_error, dedupe_key, created_at)"
                " VALUES (?, ?, ?, ?, ?, 'pending', 0, 5, NULL, NULL, ?, ?)"
                " ON CONFLICT(dedupe_key) DO NOTHING",
                (email, code, variables_json, subject, body, key, security.now_str()),
            )
            if not cur.rowcount:
                return None
            return int(cur.lastrowid)

    def claim_due_emails(self, limit=20) -> list[dict]:
        """Atomically move due pending/failed rows to 'sending' and return them."""
        limit = min(self._bounded_limit(limit, 20), 500)
        now = security.now_str()
        from datetime import datetime, timedelta

        stale_before = (datetime.now() - timedelta(seconds=300)).strftime(
            security.TIME_FORMAT
        )
        eligible = (
            "((status IN ('pending', 'failed') AND attempts < max_attempts"
            " AND (next_retry_at IS NULL OR next_retry_at <= ?))"
            " OR (status = 'sending' AND attempts < max_attempts"
            " AND (claimed_at IS NULL OR claimed_at <= ?)))"
        )
        # 无到期行时直接返回，避免每轮轮询都开一次 BEGIN IMMEDIATE 抢写锁。
        if not self._fetchone(
            f"SELECT 1 FROM email_outbox WHERE {eligible} LIMIT 1",
            (now, stale_before),
        ):
            return []
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                rows = self._conn.execute(
                    f"SELECT id FROM email_outbox WHERE {eligible}"
                    " ORDER BY id ASC LIMIT ?",
                    (now, stale_before, limit),
                ).fetchall()
                ids = [int(row["id"]) for row in rows]
                if not ids:
                    self._conn.commit()
                    return []
                placeholders = ",".join("?" for _ in ids)
                self._conn.execute(
                    "UPDATE email_outbox SET status = 'sending', claimed_at = ?"
                    f" WHERE id IN ({placeholders})",
                    (now, *ids),
                )
                claimed = self._conn.execute(
                    f"SELECT * FROM email_outbox WHERE id IN ({placeholders})"
                    " ORDER BY id ASC",
                    tuple(ids),
                ).fetchall()
                self._conn.commit()
                return [dict(row) for row in claimed]
            except Exception:
                self._conn.rollback()
                raise

    def mark_email_sent(self, email_id) -> None:
        self._execute(
            "UPDATE email_outbox SET status = 'sent', sent_at = ?,"
            " last_error = NULL, next_retry_at = NULL WHERE id = ?",
            (security.now_str(), int(email_id)),
        )

    def mark_email_failed(self, email_id, error, next_retry_at, dead=False) -> None:
        """Record one failed attempt; the row dies at max_attempts or on demand."""
        message = str(error or "")[:2000]
        with self._lock:
            row = self._conn.execute(
                "SELECT attempts, max_attempts FROM email_outbox WHERE id = ?",
                (int(email_id),),
            ).fetchone()
            if not row:
                return
            attempts = int(row["attempts"] or 0) + 1
            max_attempts = int(row["max_attempts"] or 5)
            is_dead = bool(dead) or attempts >= max_attempts
            self._conn.execute(
                "UPDATE email_outbox SET status = ?, attempts = ?, last_error = ?,"
                " next_retry_at = ? WHERE id = ?",
                (
                    "dead" if is_dead else "failed",
                    attempts,
                    message,
                    None if is_dead else next_retry_at,
                    int(email_id),
                ),
            )

    def email_outbox_stats(self) -> dict:
        stats = {
            "pending": 0,
            "sending": 0,
            "sent": 0,
            "failed": 0,
            "dead": 0,
            "total": 0,
        }
        for row in self._fetchall(
            "SELECT status, COUNT(*) AS n FROM email_outbox GROUP BY status"
        ):
            status = str(row["status"] or "")
            count = int(row["n"] or 0)
            stats["total"] += count
            if status in stats:
                stats[status] = count
        last = self._fetchone(
            "SELECT last_error FROM email_outbox"
            " WHERE last_error IS NOT NULL AND last_error <> ''"
            " ORDER BY id DESC LIMIT 1"
        )
        stats["last_error"] = str(last["last_error"]) if last else None
        return stats

    def list_email_outbox(self, status="", limit=200, offset=0) -> tuple[list[dict], int]:
        limit = self._bounded_limit(limit, 200)
        offset = self._bounded_offset(offset)
        where = ""
        params: list = []
        if str(status or "").strip():
            where = " WHERE status = ?"
            params.append(str(status).strip()[:32])
        rows = self._fetchall(
            "SELECT * FROM email_outbox" + where + " ORDER BY id DESC LIMIT ? OFFSET ?",
            tuple(params + [limit, offset]),
        )
        total_row = self._fetchone(
            "SELECT COUNT(*) AS n FROM email_outbox" + where, tuple(params)
        )
        return [dict(r) for r in rows], (int(total_row["n"]) if total_row else 0)

    # ------------------------------------------------------------------
    # Notification channels and channel outbox (A7)
    # ------------------------------------------------------------------
    def create_notification_channel(self, kind, name, url, secret="", enabled=True) -> int:
        now = security.now_str()
        return self._execute(
            "INSERT INTO notification_channels (kind, name, url, secret, enabled,"
            " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(kind or "").strip().lower()[:32],
                str(name or "").strip()[:64],
                str(url or "").strip()[:512],
                str(secret or "")[:256],
                1 if enabled else 0,
                now,
                now,
            ),
        )

    def list_notification_channels(self) -> list[dict]:
        """List channels for the UI; the plaintext secret never leaves the DB."""
        rows = self._fetchall(
            "SELECT id, kind, name, url, secret, enabled, created_at, updated_at"
            " FROM notification_channels ORDER BY id DESC"
        )
        items: list[dict] = []
        for row in rows:
            item = dict(row)
            item["secret_set"] = bool(str(item.pop("secret", "") or ""))
            items.append(item)
        return items

    def get_notification_channel(self, channel_id) -> dict | None:
        """Return one channel including the plaintext secret for delivery."""
        try:
            cid = int(channel_id)
        except (TypeError, ValueError):
            return None
        return _row_to_dict(
            self._fetchone("SELECT * FROM notification_channels WHERE id = ?", (cid,))
        )

    def update_notification_channel(self, channel_id, **fields) -> bool:
        """Partial update; an empty/None secret keeps the stored one."""
        try:
            cid = int(channel_id)
        except (TypeError, ValueError):
            return False
        if not self._fetchone("SELECT id FROM notification_channels WHERE id = ?", (cid,)):
            return False
        assignments: list[str] = []
        params: list = []
        for key in ("kind", "name", "url", "secret", "enabled"):
            if key not in fields:
                continue
            value = fields[key]
            if key == "secret":
                # An empty secret means "keep the current one"; the API
                # layer never passes a blank value through.
                if value is None or str(value) == "":
                    continue
                assignments.append("secret = ?")
                params.append(str(value)[:256])
            elif key == "enabled":
                assignments.append("enabled = ?")
                params.append(1 if value else 0)
            elif key == "kind":
                assignments.append("kind = ?")
                params.append(str(value or "").strip().lower()[:32])
            elif key == "name":
                assignments.append("name = ?")
                params.append(str(value or "").strip()[:64])
            else:  # url
                assignments.append("url = ?")
                params.append(str(value or "").strip()[:512])
        if not assignments:
            return True
        assignments.append("updated_at = ?")
        params.append(security.now_str())
        params.append(cid)
        with self._lock:
            cur = self._conn.execute(
                "UPDATE notification_channels SET " + ", ".join(assignments)
                + " WHERE id = ?",
                tuple(params),
            )
            return int(cur.rowcount or 0) > 0

    def delete_notification_channel(self, channel_id) -> bool:
        try:
            cid = int(channel_id)
        except (TypeError, ValueError):
            return False
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM notification_channels WHERE id = ?", (cid,)
            )
            return int(cur.rowcount or 0) > 0

    def enqueue_channel_message(
        self, channel_id, subject, body, payload=None, dedupe_key=""
    ) -> int | None:
        """Queue one channel message; a dedupe_key collision returns None."""
        try:
            cid = int(channel_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("通知渠道无效") from exc
        if cid <= 0 or not self._fetchone(
            "SELECT id FROM notification_channels WHERE id = ?", (cid,)
        ):
            raise ValueError("通知渠道不存在")
        extra = payload if isinstance(payload, dict) else {}
        try:
            payload_json = json.dumps(
                extra, ensure_ascii=False, separators=(",", ":")
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("通知载荷无法序列化") from exc
        if len(payload_json) > 65536:
            raise ValueError("通知载荷过大")
        key = str(dedupe_key or "").strip()[:200] or None
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO channel_outbox (channel_id, subject, body,"
                " payload_json, status, attempts, max_attempts, next_retry_at,"
                " last_error, dedupe_key, created_at)"
                " VALUES (?, ?, ?, ?, 'pending', 0, 5, NULL, NULL, ?, ?)"
                " ON CONFLICT(dedupe_key) DO NOTHING",
                (
                    cid,
                    str(subject or ""),
                    str(body or ""),
                    payload_json,
                    key,
                    security.now_str(),
                ),
            )
            if not cur.rowcount:
                return None
            return int(cur.lastrowid)

    def claim_due_channel_messages(self, limit=20) -> list[dict]:
        """Atomically claim due pending/failed rows and join their channel.

        Same contract as ``claim_due_emails``: ``BEGIN IMMEDIATE`` plus a
        status flip to ``sending`` so two dispatchers never send the same
        row. Messages whose channel vanished are left untouched.
        """
        limit = min(self._bounded_limit(limit, 20), 500)
        now = security.now_str()
        claimed: list = []
        from datetime import datetime, timedelta

        stale_before = (datetime.now() - timedelta(seconds=300)).strftime(
            security.TIME_FORMAT
        )
        eligible = (
            "((m.status IN ('pending', 'failed') AND m.attempts < m.max_attempts"
            " AND (m.next_retry_at IS NULL OR m.next_retry_at <= ?))"
            " OR (m.status = 'sending' AND m.attempts < m.max_attempts"
            " AND (m.claimed_at IS NULL OR m.claimed_at <= ?)))"
        )
        # 同 claim_due_emails：空表/无到期行时不碰写锁。
        if not self._fetchone(
            "SELECT 1 FROM channel_outbox AS m"
            " JOIN notification_channels AS c ON c.id = m.channel_id"
            f" WHERE {eligible} LIMIT 1",
            (now, stale_before),
        ):
            return []
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                rows = self._conn.execute(
                    "SELECT m.id FROM channel_outbox AS m"
                    " JOIN notification_channels AS c ON c.id = m.channel_id"
                    f" WHERE {eligible}"
                    " ORDER BY m.id ASC LIMIT ?",
                    (now, stale_before, limit),
                ).fetchall()
                ids = [int(row["id"]) for row in rows]
                if not ids:
                    self._conn.commit()
                    return []
                placeholders = ",".join("?" for _ in ids)
                self._conn.execute(
                    "UPDATE channel_outbox SET status = 'sending', claimed_at = ?"
                    f" WHERE id IN ({placeholders})",
                    (now, *ids),
                )
                claimed = self._conn.execute(
                    "SELECT m.*, c.kind AS channel_kind, c.name AS channel_name,"
                    " c.url AS channel_url, c.secret AS channel_secret,"
                    " c.enabled AS channel_enabled"
                    " FROM channel_outbox AS m"
                    " JOIN notification_channels AS c ON c.id = m.channel_id"
                    f" WHERE m.id IN ({placeholders}) ORDER BY m.id ASC",
                    tuple(ids),
                ).fetchall()
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        messages: list[dict] = []
        for row in claimed:
            item = dict(row)
            item["kind"] = item.pop("channel_kind", "")
            item["channel_name"] = item.pop("channel_name", "")
            item["url"] = item.pop("channel_url", "")
            item["secret"] = item.pop("channel_secret", "")
            item["enabled"] = item.pop("channel_enabled", 0)
            try:
                payload = json.loads(item.get("payload_json") or "{}")
            except (TypeError, ValueError):
                payload = {}
            item["payload"] = payload if isinstance(payload, dict) else {}
            messages.append(item)
        return messages

    def mark_channel_message_sent(self, message_id) -> None:
        self._execute(
            "UPDATE channel_outbox SET status = 'sent', sent_at = ?,"
            " last_error = NULL, next_retry_at = NULL WHERE id = ?",
            (security.now_str(), int(message_id)),
        )

    def mark_channel_message_failed(
        self, message_id, error, next_retry_at, dead=False
    ) -> None:
        """Record one failed attempt; the row dies at max_attempts or on demand."""
        message = str(error or "")[:2000]
        with self._lock:
            row = self._conn.execute(
                "SELECT attempts, max_attempts FROM channel_outbox WHERE id = ?",
                (int(message_id),),
            ).fetchone()
            if not row:
                return
            attempts = int(row["attempts"] or 0) + 1
            max_attempts = int(row["max_attempts"] or 5)
            is_dead = bool(dead) or attempts >= max_attempts
            self._conn.execute(
                "UPDATE channel_outbox SET status = ?, attempts = ?,"
                " last_error = ?, next_retry_at = ? WHERE id = ?",
                (
                    "dead" if is_dead else "failed",
                    attempts,
                    message,
                    None if is_dead else next_retry_at,
                    int(message_id),
                ),
            )

    def channel_outbox_stats(self) -> dict:
        stats = {
            "pending": 0,
            "sending": 0,
            "sent": 0,
            "failed": 0,
            "dead": 0,
            "total": 0,
        }
        for row in self._fetchall(
            "SELECT status, COUNT(*) AS n FROM channel_outbox GROUP BY status"
        ):
            status = str(row["status"] or "")
            count = int(row["n"] or 0)
            stats["total"] += count
            if status in stats:
                stats[status] = count
        last = self._fetchone(
            "SELECT last_error FROM channel_outbox"
            " WHERE last_error IS NOT NULL AND last_error <> ''"
            " ORDER BY id DESC LIMIT 1"
        )
        stats["last_error"] = str(last["last_error"]) if last else None
        return stats

    def list_channel_deliveries(
        self, status="", limit=200, offset=0
    ) -> tuple[list[dict], int]:
        limit = self._bounded_limit(limit, 200)
        offset = self._bounded_offset(offset)
        where = ""
        params: list = []
        if str(status or "").strip():
            where = " WHERE m.status = ?"
            params.append(str(status).strip()[:32])
        rows = self._fetchall(
            "SELECT m.*, c.name AS channel_name, c.kind AS channel_kind"
            " FROM channel_outbox AS m"
            " LEFT JOIN notification_channels AS c ON c.id = m.channel_id"
            + where
            + " ORDER BY m.id DESC LIMIT ? OFFSET ?",
            tuple(params + [limit, offset]),
        )
        total_row = self._fetchone(
            "SELECT COUNT(*) AS n FROM channel_outbox AS m" + where,
            tuple(params),
        )
        return [dict(r) for r in rows], (int(total_row["n"]) if total_row else 0)

    # ------------------------------------------------------------------
    # Administrators: e-mail binding (P1)
    # ------------------------------------------------------------------
    def set_admin_email(self, admin_id, email) -> None:
        """Store a lowercase e-mail; re-setting the same address keeps its check."""
        value = self._normalize_email(email)
        self._execute(
            "UPDATE admins SET email = ?,"
            " email_verified_at = CASE WHEN email = ? AND email_verified_at IS NOT NULL"
            " THEN email_verified_at ELSE NULL END"
            " WHERE id = ?",
            (value, value, int(admin_id)),
        )

    def get_admin_by_email(self, email) -> dict | None:
        value = self._normalize_email(email)
        if not value:
            return None
        return _row_to_dict(
            self._fetchone("SELECT * FROM admins WHERE email = ? LIMIT 1", (value,))
        )

    def mark_admin_email_verified(self, admin_id) -> None:
        self._execute(
            "UPDATE admins SET email_verified_at = ? WHERE id = ?",
            (security.now_str(), int(admin_id)),
        )

    def list_verified_admin_emails(self) -> list[str]:
        rows = self._fetchall(
            "SELECT email FROM admins WHERE status = 'active'"
            " AND email IS NOT NULL AND email <> ''"
            " AND email_verified_at IS NOT NULL ORDER BY id ASC"
        )
        return [str(row["email"]).strip().lower() for row in rows]

    # ------------------------------------------------------------------
    # One-time action codes (P1)
    # ------------------------------------------------------------------
    def create_action_code(
        self, subject_type, subject_id, email, purpose, code_hash, expires_at
    ) -> int:
        return self._execute(
            "INSERT INTO action_codes (subject_type, subject_id, email, purpose,"
            " code_hash, expires_at, attempts, used_at, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, 0, NULL, ?)",
            (
                str(subject_type or "").strip()[:32],
                int(subject_id or 0),
                self._normalize_email(email),
                str(purpose or "").strip()[:32],
                str(code_hash or "").strip()[:128],
                str(expires_at or "")[:32],
                security.now_str(),
            ),
        )

    def consume_action_code(self, subject_type, email, purpose, code_hash) -> bool:
        """Consume the newest live code; wrong guesses burn attempts, then the code."""
        stype = str(subject_type or "").strip()[:32]
        value = self._normalize_email(email)
        kind = str(purpose or "").strip()[:32]
        candidate = str(code_hash or "").strip()
        now = security.now_str()
        if not stype or not value or not kind or not candidate:
            return False
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT id, code_hash, attempts, expires_at FROM action_codes"
                    " WHERE subject_type = ? AND email = ? AND purpose = ?"
                    " AND used_at IS NULL ORDER BY id DESC LIMIT 1",
                    (stype, value, kind),
                ).fetchone()
                if not row:
                    self._conn.commit()
                    return False
                attempts = int(row["attempts"] or 0)
                if attempts >= ACTION_CODE_MAX_ATTEMPTS or str(
                    row["expires_at"] or ""
                ) <= now:
                    self._conn.execute(
                        "UPDATE action_codes SET used_at = ? WHERE id = ?",
                        (now, int(row["id"])),
                    )
                    self._conn.commit()
                    return False
                try:
                    matched = hmac.compare_digest(
                        str(row["code_hash"] or ""), candidate
                    )
                except TypeError:
                    matched = False
                if matched:
                    self._conn.execute(
                        "UPDATE action_codes SET used_at = ? WHERE id = ?",
                        (now, int(row["id"])),
                    )
                    self._conn.commit()
                    return True
                attempts += 1
                burned = attempts >= ACTION_CODE_MAX_ATTEMPTS
                self._conn.execute(
                    "UPDATE action_codes SET attempts = ?, used_at = CASE WHEN ?"
                    " THEN ? ELSE used_at END WHERE id = ?",
                    (
                        attempts,
                        int(burned),
                        now,
                        int(row["id"]),
                    ),
                )
                self._conn.commit()
                return False
            except Exception:
                self._conn.rollback()
                raise

    def count_action_codes(self, email, purpose, since) -> int:
        row = self._fetchone(
            "SELECT COUNT(*) AS n FROM action_codes"
            " WHERE email = ? AND purpose = ? AND created_at >= ?",
            (
                self._normalize_email(email),
                str(purpose or "").strip()[:32],
                str(since or ""),
            ),
        )
        return int(row["n"]) if row else 0

    # ------------------------------------------------------------------
    # Portal accounts and licence binding (P1)
    # ------------------------------------------------------------------
    def create_portal_account(self, email, password_hash, salt) -> int:
        return self._execute(
            "INSERT INTO portal_accounts (email, password_hash, salt, status,"
            " auth_version, email_verified_at, created_at, last_login_at)"
            " VALUES (?, ?, ?, 'active', 0, NULL, ?, NULL)",
            (
                self._normalize_email(email),
                str(password_hash or ""),
                str(salt or ""),
                security.now_str(),
            ),
        )

    def get_portal_account(self, email) -> dict | None:
        value = self._normalize_email(email)
        if not value:
            return None
        return _row_to_dict(
            self._fetchone(
                f"SELECT {PORTAL_ACCOUNT_COLUMNS} FROM portal_accounts WHERE email = ?",
                (value,),
            )
        )

    def get_portal_account_by_id(self, account_id) -> dict | None:
        try:
            value = int(account_id)
        except (TypeError, ValueError):
            return None
        return _row_to_dict(
            self._fetchone(
                f"SELECT {PORTAL_ACCOUNT_COLUMNS} FROM portal_accounts WHERE id = ?",
                (value,),
            )
        )

    def touch_portal_login(self, account_id) -> None:
        self._execute(
            "UPDATE portal_accounts SET last_login_at = ? WHERE id = ?",
            (security.now_str(), int(account_id)),
        )

    def set_portal_password(self, account_id, password_hash, salt) -> None:
        """Replace the password and bump auth_version, invalidating old tokens."""
        self._execute(
            "UPDATE portal_accounts SET password_hash = ?, salt = ?,"
            " auth_version = auth_version + 1 WHERE id = ?",
            (str(password_hash or ""), str(salt or ""), int(account_id)),
        )

    def mark_portal_email_verified(self, account_id) -> None:
        self._execute(
            "UPDATE portal_accounts SET email_verified_at = ? WHERE id = ?",
            (security.now_str(), int(account_id)),
        )

    # ------------------------------------------------------------------
    # Portal profile: display name and avatar (问题一)
    # ------------------------------------------------------------------
    def get_portal_profile(self, account_id) -> dict:
        """Return the profile fields the verification portal renders."""
        try:
            value = int(account_id)
        except (TypeError, ValueError):
            return {}
        row = self._fetchone(
            "SELECT email, display_name, email_verified_at, avatar_mime,"
            " length(avatar_data) AS avatar_size"
            " FROM portal_accounts WHERE id = ?",
            (value,),
        )
        if not row:
            return {}
        return {
            "email": str(row["email"] or ""),
            "display_name": str(row["display_name"] or ""),
            "email_verified_at": row["email_verified_at"],
            "avatar_mime": str(row["avatar_mime"] or ""),
            "avatar_size": int(row["avatar_size"] or 0),
        }

    def set_portal_display_name(self, account_id, display_name) -> None:
        try:
            value = int(account_id)
        except (TypeError, ValueError):
            return
        name = str(display_name or "").strip()[:32]
        self._execute(
            "UPDATE portal_accounts SET display_name = ? WHERE id = ?",
            (name, value),
        )

    def set_portal_avatar(self, account_id, mime, data: bytes) -> None:
        try:
            value = int(account_id)
        except (TypeError, ValueError):
            return
        if isinstance(data, (bytes, bytearray)):
            payload = bytes(data)
        else:
            payload = bytes(data or b"")
        self._execute(
            "UPDATE portal_accounts SET avatar_mime = ?, avatar_data = ?"
            " WHERE id = ?",
            (str(mime or "").strip()[:64], sqlite3.Binary(payload), value),
        )

    def clear_portal_avatar(self, account_id) -> None:
        try:
            value = int(account_id)
        except (TypeError, ValueError):
            return
        self._execute(
            "UPDATE portal_accounts SET avatar_mime = '', avatar_data = NULL"
            " WHERE id = ?",
            (value,),
        )

    def get_portal_avatar(self, account_id) -> tuple[str, bytes] | None:
        try:
            value = int(account_id)
        except (TypeError, ValueError):
            return None
        row = self._fetchone(
            "SELECT avatar_mime, avatar_data FROM portal_accounts WHERE id = ?",
            (value,),
        )
        if not row:
            return None
        mime = str(row["avatar_mime"] or "")
        blob = row["avatar_data"]
        if not mime or blob is None:
            return None
        return mime, bytes(blob)

    def get_portal_binding(self, account_id) -> dict | None:
        try:
            value = int(account_id)
        except (TypeError, ValueError):
            return None
        return _row_to_dict(
            self._fetchone(
                "SELECT * FROM portal_account_licenses"
                " WHERE account_id = ? AND status = 'bound' LIMIT 1",
                (value,),
            )
        )

    def get_binding_by_license(self, license_id) -> dict | None:
        try:
            value = int(license_id)
        except (TypeError, ValueError):
            return None
        return _row_to_dict(
            self._fetchone(
                "SELECT * FROM portal_account_licenses"
                " WHERE license_id = ? AND status = 'bound' LIMIT 1",
                (value,),
            )
        )

    def bind_portal_license(self, account_id, license_id, key_code) -> bool:
        """Claim the (account, licence) pair atomically; False when taken."""
        try:
            account = int(account_id)
            license_pk = int(license_id)
        except (TypeError, ValueError):
            return False
        code = security.normalize_key(key_code)
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    "SELECT id FROM portal_account_licenses"
                    " WHERE status = 'bound' AND (account_id = ? OR license_id = ?)"
                    " LIMIT 1",
                    (account, license_pk),
                ).fetchone()
                if existing:
                    self._conn.commit()
                    return False
                # Past unbinds keep their row for auditing, but the table also
                # enforces UNIQUE(account_id)/UNIQUE(license_id): clear stale
                # unbound rows for either side before inserting the new claim.
                self._conn.execute(
                    "DELETE FROM portal_account_licenses"
                    " WHERE status != 'bound' AND (account_id = ? OR license_id = ?)",
                    (account, license_pk),
                )
                self._conn.execute(
                    "INSERT INTO portal_account_licenses (account_id, license_id, key_code,"
                    " status, bound_at, unbound_at, unbind_reason)"
                    " VALUES (?, ?, ?, 'bound', ?, NULL, NULL)",
                    (account, license_pk, code, security.now_str()),
                )
                self._conn.commit()
                return True
            except Exception:
                self._conn.rollback()
                raise

    def unbind_portal_license(self, account_id, reason, actor="user") -> bool:
        try:
            account = int(account_id)
        except (TypeError, ValueError):
            return False
        with self._lock:
            cur = self._conn.execute(
                "UPDATE portal_account_licenses SET status = 'unbound',"
                " unbound_at = ?, unbind_reason = ?"
                " WHERE account_id = ? AND status = 'bound'",
                (security.now_str(), str(reason or "")[:255], account),
            )
            return int(cur.rowcount or 0) > 0

    def add_binding_history(
        self, account_id, license_id, key_code, action, reason, actor
    ) -> None:
        self._execute(
            "INSERT INTO portal_binding_history (account_id, license_id, key_code,"
            " action, reason, actor, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                int(account_id or 0),
                int(license_id or 0),
                security.normalize_key(key_code),
                str(action or "")[:32],
                str(reason or "")[:500],
                str(actor or "user")[:32],
                security.now_str(),
            ),
        )

    def release_license_activations(self, license_id, reason="portal_unbind") -> int:
        """Free every active device seat of a licence; returns rows released."""
        try:
            value = int(license_id)
        except (TypeError, ValueError):
            return 0
        with self._lock:
            cur = self._conn.execute(
                "UPDATE activations SET status = 'unbound'"
                " WHERE license_id = ? AND status = 'active'",
                (value,),
            )
            return int(cur.rowcount or 0)

    # ------------------------------------------------------------------
    # Portal account administration (问题六)
    # ------------------------------------------------------------------
    def list_portal_accounts(
        self, keyword="", status="", limit=200, offset=0
    ) -> tuple[list[dict], int]:
        """Paged portal-account list joined with the bound licence."""
        self.sweep_expired()
        where = " WHERE 1 = 1"
        params: list = []
        term = str(keyword or "").strip()[:128]
        if term:
            like = f"%{term}%"
            where += " AND (a.email LIKE ? OR a.display_name LIKE ?)"
            params += [like, like]
        state = str(status or "").strip().lower()[:32]
        if state:
            where += " AND a.status = ?"
            params.append(state)
        limit = self._bounded_limit(limit, 200)
        offset = self._bounded_offset(offset)
        rows = self._fetchall(
            "SELECT a.id, a.email, a.display_name, a.status, a.email_verified_at,"
            " a.created_at, a.last_login_at,"
            " b.key_code AS bound_key, b.status AS binding_status,"
            " l.status AS license_status, l.expires_at AS expires_at"
            " FROM portal_accounts AS a"
            " LEFT JOIN portal_account_licenses AS b"
            "   ON b.account_id = a.id AND b.status = 'bound'"
            " LEFT JOIN licenses AS l ON l.id = b.license_id"
            + where
            + " ORDER BY a.id DESC LIMIT ? OFFSET ?",
            tuple(params + [limit, offset]),
        )
        total_row = self._fetchone(
            "SELECT COUNT(*) AS n FROM portal_accounts AS a" + where,
            tuple(params),
        )
        return [dict(r) for r in rows], (int(total_row["n"]) if total_row else 0)

    def set_portal_account_status(self, account_id, status) -> bool:
        """Enable or disable a portal account; bumps auth_version."""
        state = str(status or "").strip().lower()
        if state not in ("active", "disabled"):
            return False
        try:
            value = int(account_id)
        except (TypeError, ValueError):
            return False
        with self._lock:
            cur = self._conn.execute(
                "UPDATE portal_accounts SET status = ?,"
                " auth_version = auth_version + 1 WHERE id = ?",
                (state, value),
            )
            return int(cur.rowcount or 0) > 0

    def admin_unbind_portal_account(self, account_id, reason, actor) -> bool:
        """Release the bound device seats, unbind and record the history row."""
        try:
            value = int(account_id)
        except (TypeError, ValueError):
            return False
        text = str(reason or "").strip()[:255] or "管理员强制脱绑"
        operator = str(actor or "").strip()[:32] or "admin"
        with self._lock:
            binding = self.get_portal_binding(value)
            if not binding:
                return False
            license_id = int(binding.get("license_id") or 0)
            key_code = str(binding.get("key_code") or "")
            self.release_license_activations(license_id, "admin_unbind")
            self.unbind_portal_license(value, text, operator)
            self.add_binding_history(
                value, license_id, key_code, "unbind", text, operator
            )
            return True

    # ------------------------------------------------------------------
    # Renewal requests and risk events (P1)
    # ------------------------------------------------------------------
    def create_renewal_request(self, account_id, license_id, key_code, note="") -> int:
        return self._execute(
            "INSERT INTO renewal_requests (account_id, license_id, key_code, note,"
            " status, created_at, handled_at)"
            " VALUES (?, ?, ?, ?, 'pending', ?, NULL)",
            (
                int(account_id or 0),
                int(license_id or 0),
                security.normalize_key(key_code),
                str(note or "")[:500],
                security.now_str(),
            ),
        )

    def list_renewal_requests(self, limit=200, offset=0) -> tuple[list[dict], int]:
        limit = self._bounded_limit(limit, 200)
        offset = self._bounded_offset(offset)
        rows = self._fetchall(
            "SELECT * FROM renewal_requests ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        total_row = self._fetchone("SELECT COUNT(*) AS n FROM renewal_requests")
        return [dict(r) for r in rows], (int(total_row["n"]) if total_row else 0)

    def add_risk_event(self, kind, severity, key_code, machine_code, ip, detail="") -> int:
        return self._execute(
            "INSERT INTO risk_events (kind, severity, key_code, machine_code, ip,"
            " detail, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(kind or "")[:64],
                str(severity or "warning")[:32],
                security.normalize_key(key_code) or None,
                str(machine_code or "").strip().upper()[:128] or None,
                str(ip or "")[:128] or None,
                str(detail or "")[:8192],
                security.now_str(),
            ),
        )

    def list_risk_events(self, limit=200, offset=0) -> tuple[list[dict], int]:
        limit = self._bounded_limit(limit, 200)
        offset = self._bounded_offset(offset)
        rows = self._fetchall(
            "SELECT * FROM risk_events ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        total_row = self._fetchone("SELECT COUNT(*) AS n FROM risk_events")
        return [dict(r) for r in rows], (int(total_row["n"]) if total_row else 0)

    def add_activation_ip_event(self, license_id, key_code, machine_code, ip, subnet) -> int:
        return self._execute(
            "INSERT INTO activation_ip_events (license_id, key_code, machine_code, ip,"
            " subnet, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                int(license_id or 0),
                security.normalize_key(key_code),
                str(machine_code or "").strip().upper()[:128],
                str(ip or "")[:128],
                str(subnet or "")[:64],
                security.now_str(),
            ),
        )

    def count_ip_changes(self, key_code, since) -> int:
        """Distinct networks seen for a key since a timestamp (falls back to IP)."""
        row = self._fetchone(
            "SELECT COUNT(DISTINCT CASE WHEN subnet IS NOT NULL AND subnet <> ''"
            " THEN subnet ELSE ip END) AS n FROM activation_ip_events"
            " WHERE key_code = ? AND created_at >= ?",
            (security.normalize_key(key_code), str(since or "")),
        )
        return int(row["n"]) if row else 0

    def recent_activation_ip_events(self, key_code, limit: int = 50) -> list[dict]:
        """Most recent IP observations for a key, newest first.

        换机分级风控用它判断"新硬件码是否来自旧设备用过的网络段"。
        """
        rows = self._fetchall(
            "SELECT machine_code, ip, subnet, created_at FROM activation_ip_events"
            " WHERE key_code = ? ORDER BY id DESC LIMIT ?",
            (security.normalize_key(key_code), max(1, min(int(limit or 50), 500))),
        )
        return [dict(row) for row in rows]
