import copy
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path


APP_NAME = "密钥授权系统"
APP_VERSION = "1.0.0"
APP_AUTHOR = "苏丠"
APP_COPYRIGHT = "© 2026 苏丠  保留所有权利"

AUTHOR_STATEMENT = (
    f"{APP_NAME}（含本地服务器、管理端、验证端、主控端四个程序）\n"
    f"由 {APP_AUTHOR} 独立设计与开发，著作权归作者所有。"
)

LEGAL_STATEMENT = (
    "1. 本软件受《中华人民共和国著作权法》及相关法律法规保护，未经作者书面许可，"
    "任何单位或个人不得复制、传播、修改、反编译、出售或用于任何商业用途。\n"
    "2. 本软件仅限用于合法的软件授权管理场景，使用者须确保其使用行为符合当地法律法规，"
    "不得用于侵犯他人合法权益或其他违法活动。\n"
    "3. 使用者因使用本软件产生的一切后果由使用者自行承担；作者不对因使用或无法使用"
    "本软件造成的任何直接或间接损失负责。\n"
    "4. 本软件按“现状”提供，作者保留随时修改、更新和终止本软件的权利。"
)

ROLES = ("server", "admin", "master", "verification")
CONFIG_FILENAMES = {
    "server": "server_config.json",
    "admin": "admin_config.json",
    "master": "master_config.json",
    "verification": "verification_config.json",
}
LEGACY_CONFIG_FILENAME = "config.json"


def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


APP_DIR = app_dir()
LEGACY_CONFIG_PATH = APP_DIR / LEGACY_CONFIG_FILENAME


def asset_path(*parts: str) -> Path:
    """Resolve a bundled asset in both a source checkout and a frozen exe.

    PyInstaller unpacks ``--add-data`` payloads into ``sys._MEIPASS``, which
    is not the folder holding the executable.
    """
    base = Path(getattr(sys, "_MEIPASS", APP_DIR))
    return base.joinpath("assets", *parts)

CLIENT_DEFAULT_CONFIG = {
    "server_url": "http://127.0.0.1:8765",
    "timeout": 8,
    # AI chat runs a whole tool loop on the server, so it needs its own, much
    # longer budget than ordinary REST calls.
    "ai_timeout": 600,
    "heartbeat_enabled": True,
    "heartbeat_interval": 20,
    "heartbeat_jitter": 0.35,
    "verify_max_failures": 5,
    "verify_lock_seconds": 120,
    "auto_verify": True,
    "allow_insecure_http": False,
    "offline_public_key": "",
    "response_public_key": "",
    "response_key_id": "",
    # 登录记忆：saved_password 由 core.secret_store 加密后写入（Windows DPAPI）。
    "remember_username": False,
    "remember_password": False,
    "saved_username": "",
    "saved_email": "",
    "saved_password": "",
    "session_secret": "",
    "last_key": "",
    "offline_activation": "",
    "offline_key": "",
}

AI_DEFAULT_CONFIG = {
    # Server-side OpenAI gateway. The API key never leaves the local server;
    # clients only see whether a key is configured, never the key itself.
    "enabled": False,
    # provider: openai=Responses API；compatible=通用 /chat/completions
    "provider": "openai",
    "api_mode": "responses",
    "custom_headers": {},
    "extra_body": {},
    "tool_choice": "auto",
    "vendor_name": "OpenAI",
    "api_key": "",
    "base_url": "https://api.openai.com/v1",
    "model": "gpt-5.1",
    "reasoning_effort": "medium",
    "max_output_tokens": 2048,
    "max_tool_rounds": 8,
    "timeout_seconds": 60,
    "monitor_interval": 8,
    "history_limit": 20,
    "system_prompt": (
        "You are the built-in operations assistant for the licence system. "
        "Always answer in Simplified Chinese. You may call tools to query and "
        "modify licence data, including generating, revoking, restoring, renewing, "
        "freezing and deleting keys, bulk revoking or restoring batches, and, for "
        "the master role, administrator management. Confirm the target before any "
        "write, then report the result and scope. Never invent data that no tool "
        "returned."
    ),
}

SMTP_DEFAULT_CONFIG = {
    "enabled": False,
    "host": "",
    "port": 587,
    "username": "",
    "password": "",
    "from_email": "",
    "from_name": "密钥授权系统",
    "use_starttls": True,
    "use_ssl": False,
    "timeout": 15,
    "alert_admin_emails": [],
}

SERVER_DEFAULT_CONFIG = {
    "server": {
        "host": "127.0.0.1",
        "port": 8765,
        "public_base_url": "",
    },
    "database": {
        "path": "data/license.db",
    },
    "security": {
        "secret_key": "",
        "key_prefix": "GSQ",
        "token_ttl_hours": 12,
        "signature_window_seconds": 300,
        "max_time_skew_seconds": 300,
        "login_max_attempts": 5,
        "login_lock_seconds": 300,
        "activation_max_attempts": 30,
        "activation_lock_seconds": 60,
        "max_request_bytes": 65536,
        "cors_origins": [],
        "offline_private_key": "",
        "offline_public_key": "",
        "response_private_key": "",
        "response_public_key": "",
        "response_key_id": "",
        # 客户端完整性自检（C1）：off/auto/strict，token 有效期与发布公钥。
        "attest_mode": "auto",
        "attest_token_ttl_seconds": 600,
        "release_public_key": "",
        # SDK 嵌入第三方宿主程序：必须显式开启豁免并配置共享密钥，请求需带
        # X-SDK-Token（HMAC(shared_secret, machine_code)）才放行。
        "sdk_attest_exempt": False,
        "sdk_shared_secret": "",
        # 有 active release_meta 时是否强制 attest 携带非空 manifest_sha256。
        "require_manifest_hash": False,
        # 导入新发布清单时自动把其它 release_meta 与旧构建哈希置为 inactive，
        # 让旧 release_id / 旧 exe 哈希都无法再换到 attest_token。
        "release_auto_retire_old": True,
        # 是否允许通知渠道指向内网/本机地址（内网 Webhook 场景才打开）。
        "channel_allow_private_hosts": False,
        # P1 风控：同一 Key 在窗口内出现的不同 IP 网段数超过阈值时告警。
        "ip_jump_window_minutes": 10,
        "ip_jump_alert_threshold": 2,
        # P2-13 数据保留：按天清理历史数据，0 表示该类数据永久保留。
        "retention_audit_days": 180,
        "retention_events_days": 365,
        "retention_codes_days": 7,
        "retention_outbox_days": 30,
        # 后台维护线程的运行间隔（小时）。
        "maintenance_interval_hours": 24,
    },
    "client": copy.deepcopy(CLIENT_DEFAULT_CONFIG),
    "ai": copy.deepcopy(AI_DEFAULT_CONFIG),
    "smtp": copy.deepcopy(SMTP_DEFAULT_CONFIG),
}

CLIENT_DEFAULT = {"client": copy.deepcopy(CLIENT_DEFAULT_CONFIG)}


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


_HARDENED_PATHS: set[str] = set()


def _harden_permissions(path: Path) -> None:
    """Restrict a config file to the current user.

    ``chmod(0o600)`` is honoured on POSIX but only toggles the read-only
    attribute on Windows, so the server config (which holds the HMAC and
    Ed25519 secrets) gets an explicit ACL there instead. Both steps are
    best effort: a failure must never prevent the program from saving.
    """
    try:
        path.chmod(0o600)
    except OSError:
        pass
    if os.name != "nt":
        return
    key = str(path).casefold()
    if key in _HARDENED_PATHS:
        return
    user = os.environ.get("USERNAME", "").strip()
    if not user:
        return
    try:
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
            check=False,
            capture_output=True,
            timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return
    _HARDENED_PATHS.add(key)


def _read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return raw if isinstance(raw, dict) else {}


class Config:
    """Role-specific configuration.

    Only the server role is allowed to create or persist private server keys.
    Client roles keep pinned public keys and connection preferences only.
    """

    def __init__(self, role: str = "server", path: Path | None = None):
        role = (role or "server").strip().lower()
        if role not in ROLES:
            raise ValueError(f"未知程序角色：{role}")
        self.role = role
        self.path = Path(path) if path else APP_DIR / CONFIG_FILENAMES[role]
        self.data = self._load()

    def _load(self) -> dict:
        raw = _read_json(self.path)
        default_role_path = APP_DIR / CONFIG_FILENAMES[self.role]
        if not raw and self.path == default_role_path:
            raw = _read_json(LEGACY_CONFIG_PATH)

        if self.role == "server":
            data = _deep_merge(SERVER_DEFAULT_CONFIG, raw)
            dirty = False
            security = data["security"]
            if not security.get("secret_key"):
                security["secret_key"] = secrets.token_hex(32)
                dirty = True
            if not security.get("offline_private_key"):
                from . import offline

                private_key, public_key = offline.generate_keypair()
                security["offline_private_key"] = private_key
                security["offline_public_key"] = public_key
                dirty = True
            elif not security.get("offline_public_key"):
                from . import offline

                security["offline_public_key"] = offline.public_from_private(
                    security["offline_private_key"]
                )
                dirty = True
            if not security.get("response_private_key"):
                from . import offline

                private_key, public_key = offline.generate_keypair()
                security["response_private_key"] = private_key
                security["response_public_key"] = public_key
                security["response_key_id"] = f"ed25519-{public_key[:16]}"
                dirty = True
            elif not security.get("response_public_key"):
                from . import offline

                security["response_public_key"] = offline.public_from_private(
                    security["response_private_key"]
                )
                dirty = True
            if not security.get("response_key_id"):
                security["response_key_id"] = (
                    f"ed25519-{str(security['response_public_key'])[:16]}"
                )
                dirty = True
                data["security"] = security
            if dirty or not self.path.exists():
                self._write(data)
            return data

        # Client programs must never inherit server secrets from a legacy
        # shared config.json. Only public key material and user preferences
        # are migrated.
        client_raw = raw.get("client") if isinstance(raw.get("client"), dict) else {}
        security_raw = raw.get("security") if isinstance(raw.get("security"), dict) else {}
        safe_client = {
            key: value
            for key, value in client_raw.items()
            if key in CLIENT_DEFAULT_CONFIG
        }
        # Preserve only the legacy public offline key, never the private key.
        if not safe_client.get("offline_public_key") and security_raw.get("offline_public_key"):
            safe_client["offline_public_key"] = security_raw["offline_public_key"]
        data = _deep_merge(CLIENT_DEFAULT, {"client": safe_client})
        if raw.get("security") or client_raw.get("offline_private_key"):
            self._write(data)
        return data

    def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        _harden_permissions(self.path)

    def save(self) -> None:
        self._write(self.data)

    def db_path(self) -> Path:
        if self.role != "server":
            raise RuntimeError("只有服务端配置可以访问授权数据库")
        path = Path(self.data["database"]["path"])
        if not path.is_absolute():
            path = APP_DIR / path
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def server_url(self) -> str:
        if self.role != "server":
            return str(self.client.get("server_url") or CLIENT_DEFAULT_CONFIG["server_url"])
        public = (self.data["server"]["public_base_url"] or "").strip()
        if public:
            return public.rstrip("/")
        return f"http://{self.data['server']['host']}:{self.data['server']['port']}"

    @property
    def server(self) -> dict:
        return self.data.setdefault("server", {})

    @property
    def security(self) -> dict:
        return self.data.setdefault("security", {})

    @property
    def client(self) -> dict:
        return self.data.setdefault("client", {})

    @property
    def ai(self) -> dict:
        # Server-side gateway settings. Client roles only read display
        # defaults; the API key never leaves the local server.
        if self.role == "server":
            return self.data.setdefault("ai", copy.deepcopy(AI_DEFAULT_CONFIG))
        safe = copy.deepcopy(AI_DEFAULT_CONFIG)
        safe["api_key"] = ""
        return safe

    @property
    def smtp(self) -> dict:
        # SMTP 凭据只存在于服务端配置中；客户端角色永远拿不到已保存的密码。
        if self.role == "server":
            return self.data.setdefault("smtp", copy.deepcopy(SMTP_DEFAULT_CONFIG))
        safe = copy.deepcopy(SMTP_DEFAULT_CONFIG)
        safe["password"] = ""
        return safe


_instances: dict[str, Config] = {}


def get_config(role: str = "server") -> Config:
    role = (role or "server").strip().lower()
    if role not in ROLES:
        raise ValueError(f"未知程序角色：{role}")
    if role not in _instances:
        _instances[role] = Config(role)
    return _instances[role]


def reset_config_cache() -> None:
    _instances.clear()
