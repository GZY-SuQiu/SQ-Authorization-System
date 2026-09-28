import json
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


def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


APP_DIR = app_dir()
CONFIG_PATH = APP_DIR / "config.json"

DEFAULT_CONFIG = {
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
        "key_prefix": "LIC",
        "token_ttl_hours": 12,
        "signature_window_seconds": 300,
        "max_time_skew_seconds": 300,
        "login_max_attempts": 5,
        "login_lock_seconds": 300,
        "offline_private_key": "",
        "offline_public_key": "",
    },
    "client": {
        "server_url": "http://127.0.0.1:8765",
        "timeout": 8,
        "heartbeat_enabled": True,
        "heartbeat_interval": 20,
        "heartbeat_jitter": 0.35,
        "verify_max_failures": 5,
        "verify_lock_seconds": 120,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


class Config:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else CONFIG_PATH
        self.data = self._load()

    def _load(self) -> dict:
        raw = {}
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                raw = {}
        data = _deep_merge(DEFAULT_CONFIG, raw)
        dirty = False
        if not data["security"]["secret_key"]:
            import secrets

            data["security"]["secret_key"] = secrets.token_hex(32)
            dirty = True
        if not data["security"]["offline_private_key"]:
            from . import offline

            priv, pub = offline.generate_keypair()
            data["security"]["offline_private_key"] = priv
            data["security"]["offline_public_key"] = pub
            dirty = True
        elif not data["security"]["offline_public_key"]:
            from . import offline

            data["security"]["offline_public_key"] = offline.public_from_private(
                data["security"]["offline_private_key"]
            )
            dirty = True
        if dirty:
            self._write(data)
        return data

    def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def save(self) -> None:
        self._write(self.data)

    def db_path(self) -> Path:
        p = Path(self.data["database"]["path"])
        if not p.is_absolute():
            p = APP_DIR / p
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def server_url(self) -> str:
        public = (self.data["server"]["public_base_url"] or "").strip()
        if public:
            return public.rstrip("/")
        return f"http://{self.data['server']['host']}:{self.data['server']['port']}"

    @property
    def server(self) -> dict:
        return self.data["server"]

    @property
    def security(self) -> dict:
        return self.data["security"]

    @property
    def client(self) -> dict:
        return self.data["client"]


_instance: Config | None = None


def get_config() -> Config:
    global _instance
    if _instance is None:
        _instance = Config()
    return _instance
