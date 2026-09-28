import base64
import hashlib
import hmac
import json
import random
import secrets
import time
from datetime import datetime, timedelta

KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
SIGN_TIME_WINDOW = 300

UNIT_SECONDS = {"minute": 60, "hour": 3600, "day": 86400}
UNIT_TEXT = {"minute": "分钟", "hour": "小时", "day": "天"}
DEFAULT_UNIT = "day"


def normalize_unit(unit: str) -> str:
    return unit if unit in UNIT_SECONDS else DEFAULT_UNIT


def unit_seconds(unit: str) -> int:
    return UNIT_SECONDS.get(normalize_unit(unit), 86400)


def duration_text(value: int, unit: str = DEFAULT_UNIT) -> str:
    value = int(value or 0)
    if value <= 0:
        return "永久"
    return f"{value} {UNIT_TEXT[normalize_unit(unit)]}"


def now_str() -> str:
    return datetime.now().strftime(TIME_FORMAT)


def now_ts() -> int:
    return int(time.time())


def generate_key(prefix: str = "LIC", groups: int = 4, group_len: int = 5) -> str:
    parts = [
        "".join(secrets.choice(KEY_ALPHABET) for _ in range(group_len))
        for _ in range(groups)
    ]
    body = "-".join(parts)
    return f"{prefix}-{body}" if prefix else body


def normalize_key(key: str) -> str:
    return (key or "").strip().upper()


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return digest.hex(), salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    digest, _ = hash_password(password, salt)
    return hmac.compare_digest(digest, password_hash)


def compute_expiry(value: int, unit: str = DEFAULT_UNIT) -> str | None:
    try:
        value = int(value or 0)
    except (TypeError, ValueError):
        value = 0
    if value <= 0:
        return None
    seconds = value * unit_seconds(unit)
    return (datetime.now() + timedelta(seconds=seconds)).strftime(TIME_FORMAT)


def compute_freeze_until(amount: int, unit: str = "hour") -> str | None:
    try:
        amount = int(amount or 0)
    except (TypeError, ValueError):
        amount = 0
    if amount <= 0:
        return None
    seconds = amount * unit_seconds(unit)
    return (datetime.now() + timedelta(seconds=seconds)).strftime(TIME_FORMAT)


def is_expired(expires_at: str | None) -> bool:
    if not expires_at:
        return False
    try:
        dt = datetime.strptime(expires_at, TIME_FORMAT)
    except ValueError:
        return False
    return dt < datetime.now()


def seconds_left(expires_at: str | None) -> int | None:
    if not expires_at:
        return None
    try:
        dt = datetime.strptime(expires_at, TIME_FORMAT)
    except ValueError:
        return None
    return int((dt - datetime.now()).total_seconds())


def days_left(expires_at: str | None) -> int | None:
    if not expires_at:
        return None
    try:
        dt = datetime.strptime(expires_at, TIME_FORMAT)
    except ValueError:
        return None
    return (dt - datetime.now()).days


def format_seconds(total: int | None) -> str:
    if total is None:
        return "永久"
    if total <= 0:
        return "已过期"
    days, rem = divmod(int(total), 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days > 0:
        return f"{days}天{hours}小时"
    if hours > 0:
        return f"{hours}小时{minutes}分钟"
    if minutes > 0:
        return f"{minutes}分钟{secs}秒"
    return f"{secs}秒"


def humanize_remaining(expires_at: str | None) -> str:
    if not expires_at:
        return "永久"
    return format_seconds(seconds_left(expires_at))


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def create_token(payload: dict, secret: str, ttl_seconds: int = 12 * 3600) -> str:
    body = dict(payload)
    body["exp"] = now_ts() + ttl_seconds
    raw = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    encoded = _b64e(raw)
    sig = hmac.new(secret.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded}.{_b64e(sig)}"


def verify_token(token: str, secret: str) -> dict | None:
    try:
        encoded, sig = token.split(".", 1)
    except (ValueError, AttributeError):
        return None
    expected = hmac.new(secret.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
    if not hmac.compare_digest(_b64e(expected), sig):
        return None
    try:
        payload = json.loads(_b64d(encoded))
    except Exception:
        return None
    if int(payload.get("exp", 0)) < now_ts():
        return None
    return payload


def generate_session_secret() -> str:
    return secrets.token_hex(32)


def make_nonce() -> str:
    return secrets.token_hex(16)


def _body_digest(body: bytes | str | None) -> str:
    if body is None:
        body = b""
    if isinstance(body, str):
        body = body.encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def canonical_message(
    method: str, path: str, timestamp: int | str, nonce: str, body: bytes | str | None
) -> str:
    return "\n".join(
        [method.upper(), path, str(int(timestamp)), nonce or "", _body_digest(body)]
    )


def sign_request(
    secret: str,
    method: str,
    path: str,
    timestamp: int | str,
    nonce: str,
    body: bytes | str | None,
) -> str:
    msg = canonical_message(method, path, timestamp, nonce, body)
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_request_signature(
    secret: str,
    method: str,
    path: str,
    timestamp: int | str,
    nonce: str,
    body: bytes | str | None,
    signature: str,
) -> bool:
    if not secret or not signature or not nonce:
        return False
    expected = sign_request(secret, method, path, timestamp, nonce, body)
    return hmac.compare_digest(expected, signature)


def sign_response(secret: str, body: bytes | str | None) -> str:
    return hmac.new(
        secret.encode("utf-8"), _body_digest(body).encode("ascii"), hashlib.sha256
    ).hexdigest()


def verify_response_signature(secret: str, body: bytes | str | None, signature: str) -> bool:
    if not secret or not signature:
        return False
    return hmac.compare_digest(sign_response(secret, body), signature)


def within_time_window(timestamp: int | str, now: int | None = None, window: int = SIGN_TIME_WINDOW) -> bool:
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    now = now_ts() if now is None else now
    return abs(now - ts) <= window


def password_strength(password: str) -> tuple[bool, str]:
    pw = password or ""
    if len(pw) < 8:
        return False, "密码长度至少 8 位"
    if len(pw) > 128:
        return False, "密码长度不能超过 128 位"
    if not any(c.isalpha() for c in pw):
        return False, "密码需包含字母"
    if not any(c.isdigit() for c in pw):
        return False, "密码需包含数字"
    return True, ""


def heartbeat_jitter(base: float, spread: float = 0.3) -> float:
    base = max(1.0, float(base or 1.0))
    spread = max(0.0, min(float(spread or 0.0), 0.9))
    return round(random.uniform(base * (1 - spread), base * (1 + spread)), 3)


def time_offset(server_time_str: str, local_now: datetime | None = None) -> float:
    try:
        server_dt = datetime.strptime(server_time_str, TIME_FORMAT)
    except (TypeError, ValueError):
        return 0.0
    local = local_now or datetime.now()
    return (local - server_dt).total_seconds()
