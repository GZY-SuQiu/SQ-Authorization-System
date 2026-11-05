import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import math
import socket
import threading
import time
from urllib.parse import urlsplit

import sqlite3
from datetime import datetime, timedelta

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from core import image_guard, offline, security
from core.config import APP_VERSION, Config
from core.database import Database, is_activation_card, is_exhausted_card

from .ai_gateway import AiConfirmationError, AiGateway, AiGatewayError
from . import alerting, risk

# 版本单一来源（E）：对外仍叫 VERSION，但不再保留第二份硬编码副本。
VERSION = APP_VERSION


class SafeModel(BaseModel):
    """Reject malformed Unicode before values reach SQLite or responses."""

    @field_validator("*", mode="before")
    @classmethod
    def _valid_unicode(cls, value):
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError("字符串包含无效 Unicode 字符") from exc
        return value


class _NullMailer:
    """Fail-closed stand-in used until ``server/mailer.py`` is available.

    ``create_app`` imports the real mailer module lazily (parallel batches
    land at different times), so the API must stay importable and startable
    while that file does not exist yet. Every send path reports SMTP as
    disabled instead of raising at import time.
    """

    _DISABLED_MESSAGE = "SMTP 未启用或未配置"

    def __init__(self, db=None, smtp_config: dict | None = None):
        self.db = db
        self.smtp_config = dict(smtp_config or {})

    def start(self) -> None:
        return None

    def stop(self, timeout: float = 5.0) -> None:
        return None

    def enqueue(
        self, to_email: str, template_code: str, variables=None, dedupe_key: str = ""
    ):
        return None

    def process_due(self, limit: int = 20) -> int:
        return 0

    def send_now(self, to_email: str, template_code: str, variables=None) -> None:
        raise RuntimeError(self._DISABLED_MESSAGE)

    def status(self) -> dict:
        try:
            port = int(self.smtp_config.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        return {
            "enabled": False,
            "host": str(self.smtp_config.get("host") or ""),
            "port": port,
            "from_email": str(self.smtp_config.get("from_email") or ""),
            "pending": 0,
            "sending": 0,
            "sent": 0,
            "failed": 0,
            "dead": 0,
            "last_error": None,
        }
_login_guard: dict[str, list[float]] = {}
_rate_guard: dict[str, list[float]] = {}
_guard_lock = threading.Lock()
_MAX_GUARD_KEYS = 10_000
_MAX_REQUEST_BYTES_DEFAULT = 64 * 1024

# P1: e-mail codes stay valid for ten minutes and are typed as 6 digits.
ACTION_CODE_TTL_SECONDS = 600
PORTAL_TOKEN_TTL_SECONDS = 12 * 3600
EMAIL_MAX_LENGTH = 254
# Deliberately simple: one non-empty local part, a dotted domain, no
# whitespace or second '@'. Keeps validation dependency-free.
EMAIL_PATTERN = r"^[^@\s]{1,64}@[^@\s]{1,189}\.[^@\s]{2,63}$"
ACTION_CODE_PATTERN = r"^\d{6}$"

# 问题一：头像上传契约（mime 白名单 + 256KB 原始字节上限）。
PORTAL_AVATAR_MIMES = ("image/png", "image/jpeg", "image/webp")
PORTAL_AVATAR_MAX_BYTES = 256 * 1024
PORTAL_AVATAR_PATH = "/api/portal/avatar"
# 256KB 原始数据经 base64 后约 342KB；只给这一条路由放宽请求体上限，
# 其余接口继续沿用 config.security["max_request_bytes"]。
PORTAL_AVATAR_BODY_MAX_BYTES = 400 * 1024

# A fixed, unusable credential pair. Unknown usernames are still run through
# the full PBKDF2 routine against this value so login latency does not reveal
# whether an account exists.
_DUMMY_SALT = "a7f1c93e5b2d40689af13c7e5d0b2a64"
_DUMMY_PASSWORD_HASH = (
    "pbkdf2_sha256$600000$"
    "9147cab7e1f4370c897c08b1b5dd23ea3c866714415c7e239db897018e97a826"
)

def _constant_time_login(password: str, admin: dict | None) -> bool:
    """Verify a password with the same work factor for unknown accounts."""
    password_hash = admin["password_hash"] if admin else _DUMMY_PASSWORD_HASH
    salt = admin["salt"] if admin else _DUMMY_SALT
    matched = security.verify_password(password, password_hash, salt)
    return bool(admin) and matched


def _prune_guard(store: dict[str, list[float]], now: float, window: float) -> None:
    stale = [key for key, values in store.items() if not values or now - max(values) >= window]
    for key in stale:
        store.pop(key, None)
    while len(store) > _MAX_GUARD_KEYS:
        store.pop(next(iter(store)), None)


def _login_allowed(key: str, max_attempts: int, lock_seconds: int) -> bool:
    now = time.time()
    with _guard_lock:
        _prune_guard(_login_guard, now, lock_seconds)
        records = [t for t in _login_guard.get(key, []) if now - t < lock_seconds]
        _login_guard[key] = records
        return len(records) < max_attempts


def _record_login_failure(key: str, lock_seconds: int) -> None:
    now = time.time()
    with _guard_lock:
        _prune_guard(_login_guard, now, lock_seconds)
        records = [t for t in _login_guard.get(key, []) if now - t < lock_seconds]
        records.append(now)
        _login_guard[key] = records


def _clear_login_failures(key: str) -> None:
    with _guard_lock:
        _login_guard.pop(key, None)


def _rate_clear(key: str) -> None:
    """Forget a rate-limit bucket, used once a caller proves itself."""
    with _guard_lock:
        _rate_guard.pop(key, None)


def _audit_text(value, limit: int = 64) -> str:
    """Clean an untrusted string before it is written to the audit log.

    Failed logins record whatever the caller sent as the username, so it is
    stripped of control characters and bounded in length. The value itself is
    kept verbatim otherwise, because the audit trail must stay truthful; the
    CSV export neutralises spreadsheet formulas on the way out.
    """
    text = "".join(ch for ch in str(value or "") if ch >= " " and ch != "\x7f")
    return text[:limit]


def _rate_allowed(key: str, max_attempts: int, window_seconds: int) -> bool:
    now = time.time()
    with _guard_lock:
        _prune_guard(_rate_guard, now, window_seconds)
        records = [t for t in _rate_guard.get(key, []) if now - t < window_seconds]
        if len(records) >= max_attempts:
            _rate_guard[key] = records
            return False
        records.append(now)
        _rate_guard[key] = records
        return True


def _check_signed_request(
    request: Request, raw_body: bytes, secret: str, window: int
) -> tuple[bool, str]:
    ts = request.headers.get("X-Client-Timestamp", "")
    nonce = request.headers.get("X-Client-Nonce", "")
    sig = request.headers.get("X-Client-Signature", "")
    if not ts or not nonce or not sig:
        return False, "缺少请求签名"
    if not security.within_time_window(ts, window=window):
        return False, "请求时间戳已过期"
    if not security.verify_request_signature(
        secret,
        request.method,
        request.url.path,
        ts,
        nonce,
        raw_body,
        sig,
        request.url.query,
    ):
        return False, "请求签名校验失败"
    return True, ""


def _read_payload(raw: bytes) -> dict:
    try:
        data = json.loads(raw or b"{}")
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _payload_text(payload: dict, name: str, max_length: int = 128) -> str:
    value = payload.get(name, "")
    if not isinstance(value, str):
        return ""
    value = value.strip()
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return ""
    return value if 0 < len(value) <= max_length else ""


def _client_ip(request: Request) -> str:
    if request.client:
        return request.client.host
    return "unknown"


def _frozen_block(lic: dict | None) -> dict | None:
    if not lic or lic["status"] != "frozen":
        return None
    if security.is_long_freeze(lic.get("frozen_until")):
        # 换机风控的远期冻结显示"剩余 N 万天"没有任何操作意义，
        # 统一按长期锁定呈现，由管理员解冻/换绑处理。
        tip = "该密钥已被长期锁定（需管理员解冻/换绑）"
    else:
        remaining = security.humanize_remaining(lic.get("frozen_until"))
        tip = f"该密钥已被冻结，剩余 {remaining}"
    reason = lic.get("freeze_reason") or ""
    if reason:
        tip += f"（原因：{reason}）"
    return {"ok": False, "code": "frozen", "message": tip}


def _expiry_for_license(db: Database, lic: dict) -> str | None:
    expiry = lic.get("expires_at")
    if not expiry and lic.get("duration_days") and int(lic["duration_days"]) > 0:
        expiry = security.compute_expiry(
            int(lic["duration_days"]), lic.get("duration_unit") or "day"
        )
        db.update_license_expiry(lic["key_code"], expiry)
    return expiry


def _activation_fields(lic: dict | None) -> dict:
    """Expose the remaining activations of an activation-count card.

    Duration cards return an empty mapping so their response shape is unchanged.
    """
    if not is_activation_card(lic):
        return {}
    limit = int(lic.get("activation_limit") or 0)
    used = int(lic.get("activation_count") or 0)
    return {
        "card_type": "activation",
        "activation_limit": limit,
        "activation_count": used,
        "activation_left": max(0, limit - used),
    }


def do_activate(
    db: Database,
    key_code: str,
    machine_code: str,
    device_name: str,
    ip: str,
    session_secret: str,
) -> dict:
    key_code = security.normalize_key(key_code)
    machine_code = (machine_code or "").strip().upper()
    if not key_code or not machine_code:
        return {"ok": False, "code": "bad_request", "message": "密钥和机器码不能为空"}

    db.release_expired_freeze(key_code)
    db.sweep_expired()
    lic = db.get_license(key_code)
    if not lic:
        db.add_log("激活失败", "client", key_code, "密钥不存在", ip)
        return {"ok": False, "code": "not_found", "message": "密钥不存在，请核对后重试"}
    if is_exhausted_card(lic):
        db.add_log("激活失败", "client", key_code, "激活次数已用尽", ip)
        return {
            "ok": False,
            "code": "exhausted",
            "message": "该密钥激活次数已用尽，授权已被吊销",
        }
    blocked = _frozen_block(lic)
    if blocked:
        db.add_log("激活失败", "client", key_code, "密钥已冻结", ip)
        return blocked
    if lic["status"] == "revoked":
        db.add_log("激活失败", "client", key_code, "密钥已吊销", ip)
        return {"ok": False, "code": "revoked", "message": "该密钥已被吊销，无法激活"}
    if lic["status"] == "expired" or security.is_expired(lic.get("expires_at")):
        db.set_license_status(key_code, "expired")
        db.add_log("激活失败", "client", key_code, "密钥已过期", ip)
        return {"ok": False, "code": "expired", "message": "该密钥已过期"}

    expiry = _expiry_for_license(db, lic)
    result, activation_id, effective_expiry = db.activate_atomic(
        lic["id"],
        key_code,
        machine_code,
        device_name,
        expiry,
        session_secret,
    )
    if result == "not_found":
        db.add_log("激活失败", "client", key_code, "密钥不存在", ip)
        return {"ok": False, "code": "not_found", "message": "密钥不存在，请核对后重试"}
    if result == "invalid":
        db.add_log("激活失败", "client", key_code, "密钥状态已失效", ip)
        return {"ok": False, "code": "expired", "message": "该密钥已失效"}
    if result == "limit":
        db.add_log("激活失败", "client", key_code, "设备数达上限", ip)
        max_devices = int(lic["max_devices"] or 0)
        return {
            "ok": False,
            "code": "limit",
            "message": f"该密钥最多绑定 {max_devices} 台设备，已达上限",
        }
    if result == "exhausted":
        db.add_log("激活失败", "client", key_code, "激活次数已用尽", ip)
        return {
            "ok": False,
            "code": "exhausted",
            "message": "该密钥激活次数已用尽，授权已被吊销",
        }
    if activation_id is None:
        db.add_log("激活失败", "client", key_code, "激活记录创建失败", ip)
        return {"ok": False, "code": "internal_error", "message": "激活记录创建失败"}

    is_already = result == "already"
    db.add_log(
        "激活成功" if not is_already else "重复激活",
        "client",
        key_code,
        f"设备 {device_name or machine_code}",
        ip,
    )
    fresh = db.get_license(key_code) or lic
    payload = {
        "ok": True,
        "code": "already" if is_already else "activated",
        "message": "该设备已激活" if is_already else "激活成功",
        "session_secret": session_secret,
        "expires_at": effective_expiry,
        "days_left": security.days_left(effective_expiry),
        "remaining": security.humanize_remaining(effective_expiry),
        "server_ts": security.now_ts(),
    }
    payload.update(_activation_fields(fresh))
    payload["features"] = security.features_from_text(fresh.get("features"))
    if payload.get("activation_left") == 0:
        payload["message"] += "，该密钥激活次数已用尽"
    return payload


def do_verify(
    db: Database, key_code: str, machine_code: str, ip: str = ""
) -> dict:
    key_code = security.normalize_key(key_code)
    machine_code = (machine_code or "").strip().upper()
    if not key_code or not machine_code:
        return {"ok": False, "code": "bad_request", "message": "密钥和机器码不能为空"}

    db.release_expired_freeze(key_code)
    db.sweep_expired()
    lic = db.get_license(key_code)
    if not lic:
        db.add_log("验证失败", "client", key_code, "密钥不存在", ip)
        return {"ok": False, "code": "not_found", "message": "密钥不存在"}
    if is_exhausted_card(lic):
        db.add_log("验证失败", "client", key_code, "激活次数已用尽", ip)
        return {
            "ok": False,
            "code": "exhausted",
            "message": "该密钥激活次数已用尽，授权已被吊销",
        }
    blocked = _frozen_block(lic)
    if blocked:
        db.add_log("验证失败", "client", key_code, "密钥已冻结", ip)
        return blocked
    if lic["status"] == "revoked":
        db.add_log("验证失败", "client", key_code, "密钥已吊销", ip)
        return {"ok": False, "code": "revoked", "message": "该密钥已被吊销"}
    if lic["status"] == "expired" or security.is_expired(lic.get("expires_at")):
        db.set_license_status(key_code, "expired")
        db.add_log("验证失败", "client", key_code, "密钥已过期", ip)
        return {"ok": False, "code": "expired", "message": "该密钥已过期"}

    act = db.get_activation(key_code, machine_code)
    if not act or act["status"] != "active":
        db.add_log("验证失败", "client", key_code, "本设备尚未激活", ip)
        return {"ok": False, "code": "not_activated", "message": "本设备尚未激活"}

    expiry = act["expires_at"] or lic.get("expires_at")
    if security.is_expired(expiry):
        db.add_log("验证失败", "client", key_code, "设备授权已过期", ip)
        return {"ok": False, "code": "expired", "message": "该密钥已过期"}
    db.update_activation_verified(act["id"])
    db.add_log(
        "验证成功",
        "client",
        key_code,
        f"设备 {act.get('device_name') or machine_code}",
        ip,
    )
    payload = {
        "ok": True,
        "code": "valid",
        "message": "验证通过",
        "expires_at": expiry,
        "days_left": security.days_left(expiry),
        "remaining": security.humanize_remaining(expiry),
    }
    payload.update(_activation_fields(lic))
    payload["features"] = security.features_from_text(lic.get("features"))
    return payload


class LoginBody(SafeModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class GenerateBody(SafeModel):
    count: int = Field(default=1, ge=1, le=500)
    edition: str = Field(default="standard", max_length=32)
    card_type: str = Field(default="duration", max_length=16)
    duration_days: int = Field(default=0, ge=0, le=36500)
    duration_unit: str = Field(default="day", max_length=16)
    activation_limit: int = Field(default=0, ge=0, le=100000)
    max_devices: int = Field(default=1, ge=0, le=10000)
    features: list[str] = Field(default_factory=list, max_length=32)
    note: str = Field(default="", max_length=500)
    prefix: str = Field(default="", max_length=16)


class KeyBody(SafeModel):
    key_code: str = Field(min_length=1, max_length=128)


class UnbindBody(SafeModel):
    key_code: str = Field(min_length=1, max_length=128)
    machine_code: str = Field(min_length=1, max_length=128)


class BatchBody(SafeModel):
    batch_no: str = Field(min_length=1, max_length=128)


class FreezeBody(SafeModel):
    key_code: str = Field(min_length=1, max_length=128)
    amount: int = Field(default=1, ge=1, le=100000)
    unit: str = Field(default="hour", max_length=16)
    reason: str = Field(default="", max_length=200)


class RenewBody(SafeModel):
    key_code: str = Field(min_length=1, max_length=128)
    duration_days: int = Field(ge=1, le=36500)
    duration_unit: str = Field(default="day", max_length=16)


class AdminCreateBody(SafeModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)
    role: str = Field(default="admin", max_length=16)


class AdminStatusBody(SafeModel):
    admin_id: int = Field(ge=1)
    status: str = Field(max_length=16)


class AdminPasswordBody(SafeModel):
    admin_id: int = Field(ge=1)
    password: str = Field(min_length=1, max_length=128)


class ChangePasswordBody(SafeModel):
    old_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=128)


class ActivateBody(SafeModel):
    key_code: str = Field(min_length=1, max_length=128)
    machine_code: str = Field(min_length=1, max_length=128)
    device_name: str = Field(default="", max_length=128)


class OfflineCodeBody(SafeModel):
    key_code: str = Field(min_length=1, max_length=128)
    machine_code: str = Field(min_length=1, max_length=128)
    device_name: str = Field(default="", max_length=128)


class AiMessage(SafeModel):
    role: str = Field(default="user", max_length=16)
    content: str = Field(default="", max_length=8000)


class AiChatBody(SafeModel):
    messages: list[AiMessage] = Field(default_factory=list, max_length=100)


class AiConfirmBody(SafeModel):
    confirm_token: str = Field(min_length=1, max_length=4096)


# Bound the detail fields so a hostile client cannot bloat tamper_events. The
# manifest ceiling is larger because it is a real signed release document.
MAX_INTEGRITY_DETAIL_CHARS = 8192
MAX_MANIFEST_CHARS = 256 * 1024
MAX_SIGNATURE_CHARS = 256


class AttestBody(SafeModel):
    role: str = Field(default="", max_length=64)
    exe_name: str = Field(default="", max_length=64)
    exe_hash: str = Field(min_length=64, max_length=64)
    version: str = Field(default="", max_length=64)
    machine_code: str = Field(default="", max_length=128)
    # 问题三：发布绑定。缺少 release_meta 的服务器仍然忽略这两个字段。
    release_id: str = Field(default="", max_length=64)
    manifest_sha256: str = Field(default="", max_length=64)
    local_check: dict | None = None

    @field_validator("exe_hash")
    @classmethod
    def _valid_exe_hash(cls, value: str) -> str:
        digest = str(value or "").strip().lower()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("exe_hash 必须是 64 位十六进制字符串")
        return digest

    @field_validator("manifest_sha256")
    @classmethod
    def _valid_manifest_sha256(cls, value: str) -> str:
        digest = str(value or "").strip().lower()
        if not digest:
            return ""
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("manifest_sha256 必须是空串或 64 位十六进制字符串")
        return digest


class IntegrityReportBody(SafeModel):
    role: str = Field(default="", max_length=64)
    exe_name: str = Field(default="", max_length=64)
    exe_hash: str = Field(min_length=64, max_length=64)
    version: str = Field(default="", max_length=64)
    machine_code: str = Field(default="", max_length=128)
    reason: str = Field(default="", max_length=128)
    detail: str = Field(default="", max_length=MAX_INTEGRITY_DETAIL_CHARS)

    @field_validator("exe_hash")
    @classmethod
    def _valid_exe_hash(cls, value: str) -> str:
        digest = str(value or "").strip().lower()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("exe_hash 必须是 64 位十六进制字符串")
        return digest

    @field_validator("detail", mode="before")
    @classmethod
    def _freeze_detail(cls, value):
        """Accept the structured detail the client sends and store it as JSON."""
        if value is None:
            return ""
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        return value


class ReleaseImportBody(SafeModel):
    manifest: str = Field(min_length=1, max_length=MAX_MANIFEST_CHARS)
    signature: str = Field(min_length=1, max_length=MAX_SIGNATURE_CHARS)


class ReleaseStatusBody(SafeModel):
    file_name: str = Field(min_length=1, max_length=255)
    sha256: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    active: bool = True


class _EmailModel(SafeModel):
    """Base for payloads carrying one e-mail address.

    Addresses are lowercased on input so they match the lowercase form every
    database method stores and queries.
    """

    @field_validator("email", mode="before", check_fields=False)
    @classmethod
    def _normalize_email(cls, value):
        if isinstance(value, str):
            return value.strip().lower()
        return value


def _email_field():
    return Field(
        min_length=3, max_length=EMAIL_MAX_LENGTH, pattern=EMAIL_PATTERN
    )


class AdminEmailSetBody(_EmailModel):
    email: str = _email_field()


class AdminEmailVerifyBody(SafeModel):
    code: str = Field(min_length=6, max_length=6, pattern=ACTION_CODE_PATTERN)


class AdminPasswordForgotBody(_EmailModel):
    email: str = _email_field()


class AdminPasswordResetBody(_EmailModel):
    email: str = _email_field()
    code: str = Field(min_length=6, max_length=6, pattern=ACTION_CODE_PATTERN)
    new_password: str = Field(min_length=8, max_length=128)


class PortalSendCodeBody(_EmailModel):
    email: str = _email_field()
    purpose: str = Field(min_length=1, max_length=16)


class PortalRegisterBody(_EmailModel):
    email: str = _email_field()
    code: str = Field(min_length=6, max_length=6, pattern=ACTION_CODE_PATTERN)
    password: str = Field(min_length=8, max_length=128)


class PortalLoginBody(_EmailModel):
    email: str = _email_field()
    password: str = Field(min_length=1, max_length=256)


class PortalBindBody(SafeModel):
    key_code: str = Field(min_length=1, max_length=128)
    machine_code: str = Field(min_length=1, max_length=128)
    device_name: str = Field(default="", max_length=128)


class PortalRenewBody(SafeModel):
    note: str = Field(default="", max_length=500)


class PortalPasswordResetBody(_EmailModel):
    email: str = _email_field()
    code: str = Field(min_length=6, max_length=6, pattern=ACTION_CODE_PATTERN)
    new_password: str = Field(min_length=8, max_length=128)


class PortalProfileBody(SafeModel):
    """Display name for PUT /api/portal/profile (1..32 after trimming)."""

    display_name: str = Field(default="", max_length=64)


class PortalAvatarBody(SafeModel):
    mime: str = Field(default="", max_length=64)
    data_base64: str = Field(default="")


class PortalAccountStatusBody(SafeModel):
    status: str = Field(default="", max_length=16)


class SmtpTestBody(SafeModel):
    to_email: str = Field(
        min_length=3, max_length=EMAIL_MAX_LENGTH, pattern=EMAIL_PATTERN
    )

    @field_validator("to_email", mode="before")
    @classmethod
    def _normalize_to_email(cls, value):
        if isinstance(value, str):
            return value.strip().lower()
        return value


class ChannelBody(SafeModel):
    """Full payload of ``POST /api/channels`` (contract section 4).

    Field limits are enforced by hand so every contract violation maps to
    a 400 instead of a Pydantic 422.
    """

    kind: str
    name: str
    url: str
    secret: str = ""
    enabled: bool = True


class ChannelUpdateBody(SafeModel):
    """Partial payload of ``PUT /api/channels/{id}``; absent/None = keep.

    ``secret`` keeps the stored value when it is omitted, ``null`` or an
    empty string; that is what the UI sends for "do not change".
    """

    kind: str | None = None
    name: str | None = None
    url: str | None = None
    secret: str | None = None
    enabled: bool | None = None


class _NullAlertEngine:
    """Fail-closed stand-in used until ``server/alert_engine.py`` is available.

    ``create_app`` imports the real engine lazily (parallel batches land at
    different times), so the API must stay importable and startable while
    that file does not exist yet. It evaluates nothing and triggers nothing.
    """

    def __init__(self, db=None, mailer=None, config=None):
        self.db = db
        self.mailer = mailer
        self.config = config

    def start(self) -> None:
        return None

    def stop(self, timeout: float = 5.0) -> None:
        return None

    def evaluate_once(self) -> list[dict]:
        return []


class _NullChannelDispatcher:
    """Fail-closed stand-in used until ``server/channels.py`` is available.

    ``create_app`` imports the real dispatcher lazily (parallel A7 batches
    land at different times), so the API must stay importable and startable
    while that file does not exist yet. It claims and delivers nothing.
    """

    def __init__(self, db=None):
        self.db = db

    def start(self) -> None:
        return None

    def stop(self, timeout: float = 5.0) -> None:
        return None

    def process_due(self, limit: int = 20) -> int:
        return 0


class MaintenanceWorker:
    """Background data-retention worker (P2-13).

    启动后先跑一次（清理过期数据），随后每隔 ``interval_seconds`` 再跑；
    ``start``/``stop`` 幂等，只有线程真正退出才释放引用（与 AlertEngine /
    ChannelDispatcher 相同的生命周期约定）。
    """

    def __init__(
        self,
        db,
        retention: dict | None = None,
        interval_seconds: float = 86400.0,
    ):
        self.db = db
        self.retention = dict(retention or {})
        try:
            interval = float(interval_seconds)
        except (TypeError, ValueError):
            interval = 86400.0
        self.interval = max(1.0, interval)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self.last_run_at: str | None = None
        self.last_deleted: dict | None = None
        self.last_error: str | None = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        stop_event = threading.Event()
        self._stop_event = stop_event
        self._thread = threading.Thread(
            target=self._loop,
            args=(stop_event,),
            name="sq-maintenance",
            daemon=True,
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        stop_event = getattr(self, "_stop_event", None)
        if stop_event is not None:
            stop_event.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=max(0.1, float(timeout)))
        # 只有线程确实退出才释放引用；否则 stop 超时后再 start 会留下两个 worker。
        if thread is None or not thread.is_alive():
            self._thread = None

    def _loop(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            try:
                self.run_once()
            except Exception as exc:
                with self._lock:
                    self.last_error = str(exc)[:500] or exc.__class__.__name__
            if stop_event.wait(self.interval):
                return

    # ------------------------------------------------------------------ #
    # Maintenance
    # ------------------------------------------------------------------ #
    def run_once(self) -> dict:
        """Run one retention pass and remember when/how much it deleted."""
        deleted = self.db.run_maintenance(self.retention)
        with self._lock:
            self.last_run_at = security.now_str()
            self.last_deleted = dict(deleted)
            self.last_error = None
        return deleted

    def status(self) -> dict:
        with self._lock:
            return {
                "last_run_at": self.last_run_at,
                "deleted": dict(self.last_deleted or {}),
                "interval_seconds": round(self.interval, 3),
                "last_error": self.last_error,
            }


# A7 notification channel enums (contract section 4). ``server.channels``
# is the source of truth; this fallback keeps the API validatable while the
# adapters module is still missing.
CHANNEL_KINDS = ("webhook", "dingtalk", "wecom", "feishu")
CHANNEL_NAME_MAX = 64
CHANNEL_URL_MAX = 512
CHANNEL_SECRET_MAX = 256


def _channel_kind(value, kinds=CHANNEL_KINDS) -> str:
    kind = str(value or "").strip().lower()
    if kind not in kinds:
        raise HTTPException(status_code=400, detail="不支持的通知渠道类型")
    return kind


def _channel_name(value) -> str:
    name = str(value or "").strip()
    if not 1 <= len(name) <= CHANNEL_NAME_MAX:
        raise HTTPException(
            status_code=400,
            detail=f"渠道名称长度必须为 1-{CHANNEL_NAME_MAX} 字符",
        )
    return name


def _channel_url(value, *, allow_private: bool = False) -> str:
    url = str(value or "").strip()
    remainder = url.split("://", 1)[1] if "://" in url else ""
    if (
        not url.lower().startswith(("http://", "https://"))
        or len(url) > CHANNEL_URL_MAX
        or not remainder
        or any(char.isspace() for char in url)
    ):
        raise HTTPException(
            status_code=400,
            detail=f"渠道地址必须是 http(s) URL 且不超过 {CHANNEL_URL_MAX} 字符",
        )
    try:
        parsed = urlsplit(url)
        host = str(parsed.hostname or "").strip()
    except ValueError:
        host = ""
    if not host:
        raise HTTPException(status_code=400, detail="渠道地址缺少有效主机名")
    if not allow_private:
        candidates: list[str] = []
        lowered = host.lower()
        if lowered in ("localhost",) or lowered.endswith(".local"):
            candidates.append("127.0.0.1")
        try:
            candidates.append(str(ipaddress.ip_address(host)))
        except ValueError:
            # 域名不做同步解析：慢 DNS 会阻塞创建接口十几秒；投递时由
            # requests 自行解析。内网域名场景由 channel_allow_private_hosts
            # 开关或部署侧网络策略控制。
            pass
        for candidate in candidates:
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if (
                address.is_private
                or address.is_loopback
                or address.is_link_local
                or address.is_multicast
                or address.is_reserved
            ):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "渠道地址指向内网/本机地址，已被安全策略拒绝；"
                        "如需内网 Webhook，请在 server_config.json 设置 "
                        "security.channel_allow_private_hosts=true"
                    ),
                )
    return url


def _channel_secret(value) -> str:
    secret = "" if value is None else str(value)
    if len(secret) > CHANNEL_SECRET_MAX:
        raise HTTPException(
            status_code=400,
            detail=f"渠道密钥长度不能超过 {CHANNEL_SECRET_MAX} 字符",
        )
    return secret


# A5 alert rule enums (contract sections 1 and 4).


# A5 alert rule enums (contract sections 1 and 4).
ALERT_METRICS = (
    "activation_rate",
    "online_devices",
    "expiration_rate",
    "expiring_soon",
    "failed_activations",
    "risk_events",
    "tamper_events",
)
ALERT_OPERATORS = ("gte", "gt", "lte", "lt", "eq")
ALERT_SEVERITIES = ("info", "warning", "critical")
ALERT_CHANNELS = ("email",)


class AlertRuleBody(SafeModel):
    """Full payload of ``POST /api/alerts/rules`` (contract section 4)."""

    name: str = Field(min_length=1, max_length=64)
    metric: str = Field(min_length=1, max_length=64)
    operator: str = Field(default="gte", min_length=1, max_length=16)
    threshold: float
    window_seconds: int = Field(default=600, ge=60, le=86400)
    severity: str = Field(default="warning", min_length=1, max_length=16)
    cooldown_seconds: int = Field(default=3600, ge=60, le=86400)
    channels: list[str] = Field(default_factory=lambda: ["email"])
    enabled: bool = True
    note: str = Field(default="", max_length=200)


class AlertRuleUpdateBody(SafeModel):
    """Partial payload of ``PUT /api/alerts/rules/{id}``; absent = keep."""

    name: str | None = Field(default=None, min_length=1, max_length=64)
    metric: str | None = Field(default=None, min_length=1, max_length=64)
    operator: str | None = Field(default=None, min_length=1, max_length=16)
    threshold: float | None = None
    window_seconds: int | None = Field(default=None, ge=60, le=86400)
    severity: str | None = Field(default=None, min_length=1, max_length=16)
    cooldown_seconds: int | None = Field(default=None, ge=60, le=86400)
    channels: list[str] | None = None
    enabled: bool | None = None
    note: str | None = Field(default=None, max_length=200)


def _alert_channel_supported(channel, db) -> bool:
    """``email`` or ``channel:<existing id>`` (contract section 5)."""
    text = str(channel or "").strip()
    if text == "email":
        return True
    if not text.startswith("channel:"):
        return False
    try:
        channel_id = int(text.split(":", 1)[1])
    except (TypeError, ValueError):
        return False
    if channel_id <= 0 or db is None:
        return False
    try:
        return db.get_notification_channel(channel_id) is not None
    except Exception:
        return False


def _validate_alert_rule_fields(fields: dict, db=None) -> None:
    """Reject unsupported enums, channels and non-finite numbers (400)."""
    metric = fields.get("metric")
    if metric is not None and metric not in ALERT_METRICS:
        raise HTTPException(status_code=400, detail="不支持的告警指标")
    operator = fields.get("operator")
    if operator is not None and operator not in ALERT_OPERATORS:
        raise HTTPException(status_code=400, detail="不支持的比较运算符")
    severity = fields.get("severity")
    if severity is not None and severity not in ALERT_SEVERITIES:
        raise HTTPException(status_code=400, detail="不支持的告警级别")
    threshold = fields.get("threshold")
    if threshold is not None:
        try:
            finite = math.isfinite(float(threshold))
        except (TypeError, ValueError):
            finite = False
        if not finite:
            raise HTTPException(status_code=400, detail="阈值必须是有限数值")
    channels = fields.get("channels")
    if channels is not None:
        if not isinstance(channels, list) or not channels:
            raise HTTPException(status_code=400, detail="告警渠道不能为空")
        for channel in channels:
            if _alert_channel_supported(channel, db):
                continue
            if isinstance(channel, str) and channel.startswith("channel:"):
                raise HTTPException(status_code=400, detail="告警渠道不存在")
            raise HTTPException(status_code=400, detail="暂不支持该告警渠道")


def _clean_alert_rule_fields(fields: dict) -> dict:
    """Trim text fields and normalize enum casing before validation."""
    cleaned = dict(fields)
    for key in ("name", "metric", "operator", "severity"):
        value = cleaned.get(key)
        if isinstance(value, str):
            cleaned[key] = value.strip()
    for key in ("operator", "severity"):
        value = cleaned.get(key)
        if isinstance(value, str):
            cleaned[key] = value.lower()
    return cleaned


def import_release_manifest(
    db,
    manifest: dict,
    manifest_bytes: bytes,
    note: str = "manifest import",
    retire_old: bool = False,
) -> int:
    """Apply one *verified* release manifest (问题三).

    Shared by ``POST /api/release/import`` and the startup import in
    ``server/main.py`` (which should call this after signature verification).
    Upserts every app hash and records ``release_meta`` with the manifest
    sha256, release id and version (active=1) so attest can bind clients to
    one exact build. Manifests without ``release_id`` only refresh hashes.
    ``retire_old=True``（P1-11）把其它 release_meta 与不在新清单里的旧
    构建哈希置为 inactive，旧 release_id / 旧 exe 都无法再 attest。
    Returns the number of app hashes written.
    """
    apps = manifest.get("apps") if isinstance(manifest, dict) else None
    if not isinstance(apps, dict):
        return 0
    version = str(manifest.get("version", "") or "")
    imported = 0
    manifest_hashes: set[str] = set()
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
            note=f"{note} ({name})",
        )
        manifest_hashes.add(sha256)
        imported += 1
    release_id = str(manifest.get("release_id", "") or "").strip().lower()[:64]
    if release_id:
        raw = (
            bytes(manifest_bytes)
            if manifest_bytes
            else json.dumps(
                manifest, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        )
        db.upsert_release_meta(
            release_id,
            hashlib.sha256(raw).hexdigest(),
            version,
            active=1,
            retire_others=bool(retire_old),
        )
        # 只有带 release_id 的清单才算“一次发布”；没有发布标识的老清单
        # 不参与绑定，也不触发旧哈希退役。至少写入一个哈希才允许退役，
        # 避免清单字段损坏时把白名单清空。
        if retire_old and imported:
            db.retire_release_hashes_except(manifest_hashes)
    return imported


def create_app(
    config: Config,
    db: Database,
    mailer=None,
    alert_engine=None,
    channel_dispatcher=None,
    maintenance=None,
) -> FastAPI:
    secret = config.security["secret_key"]


    ttl = int(config.security.get("token_ttl_hours", 12) * 3600)
    default_prefix = config.security.get("key_prefix", "GSQ") or "GSQ"

    def checked_unit(value: int, unit: str) -> str:
        cleaned = (unit or "day").strip().lower()
        if not security.valid_unit(cleaned):
            raise HTTPException(status_code=400, detail="不支持的时长单位")
        if int(value or 0) > security.unit_max_value(cleaned):
            raise HTTPException(status_code=400, detail="有效期超出该单位的允许范围")
        return cleaned
    sign_window = int(config.security.get("signature_window_seconds", 300))
    login_max_attempts = int(config.security.get("login_max_attempts", 5))
    login_lock_seconds = int(config.security.get("login_lock_seconds", 300))
    login_ip_max_attempts = max(
        int(config.security.get("login_ip_max_attempts", 0)) or login_max_attempts * 4,
        20,
    )
    activation_max_attempts = int(config.security.get("activation_max_attempts", 30))
    activation_lock_seconds = int(config.security.get("activation_lock_seconds", 60))
    # Verify/heartbeat are throttled on failure only: a correctly signed
    # request from a licensed device is never counted, so a large office
    # behind one address cannot throttle itself.
    verify_fail_max_attempts = max(
        int(config.security.get("verify_fail_max_attempts", 0)) or activation_max_attempts,
        20,
    )
    verify_fail_lock_seconds = int(
        config.security.get("verify_fail_lock_seconds", 0)
    ) or activation_lock_seconds
    max_request_bytes = int(
        config.security.get("max_request_bytes", _MAX_REQUEST_BYTES_DEFAULT)
    )
    heartbeat_base = float(config.client.get("heartbeat_interval", 20))
    heartbeat_spread = float(config.client.get("heartbeat_jitter", 0.35))
    offline_private = config.security.get("offline_private_key", "") or ""
    offline_public = config.security.get("offline_public_key", "") or ""
    response_private = config.security.get("response_private_key", "") or ""
    response_public = config.security.get("response_public_key", "") or ""
    response_key_id = config.security.get("response_key_id", "") or ""
    if not response_private or not response_public:
        raise RuntimeError("服务端响应签名密钥未配置")

    app = FastAPI(title="密钥授权本地服务器", version=VERSION)
    ai_config = config.data.get("ai") or {}
    ai_gateway = AiGateway(db, ai_config, security_config=config.security)
    # ``add_event_handler`` was removed in modern FastAPI/Starlette; the
    # router-level hook below works on both old and new releases.
    app.router.on_shutdown.append(ai_gateway.close)

    # ------------------------------------------------------------------
    # Mailer wiring (P1)
    # ------------------------------------------------------------------
    smtp_config = config.data.get("smtp")
    if not isinstance(smtp_config, dict):
        smtp_config = {}
        config.data["smtp"] = smtp_config
    mailer_module = None
    try:
        # Lazy import on purpose: the mailer lands in its own file during the
        # P1 parallel batches, and create_app must stay importable meanwhile.
        from . import mailer as mailer_module
    except ImportError:
        mailer_module = None
    if mailer is None:
        if mailer_module is None:
            mailer = _NullMailer(db, smtp_config)
        else:
            factory = getattr(mailer_module, "build_mailer", None)
            if callable(factory):
                mailer = factory(db, smtp_config)
            else:
                mailer = mailer_module.Mailer(db, smtp_config)
    templates = getattr(mailer_module, "DEFAULT_TEMPLATES", None)
    if isinstance(templates, dict) and templates:
        # seed_email_templates only inserts missing codes, so an operator who
        # edited a template in the database keeps their version.
        try:
            db.seed_email_templates(templates)
        except Exception:
            pass
    start_mailer = getattr(mailer, "start", None)
    if callable(start_mailer):
        app.router.on_startup.append(start_mailer)
    stop_mailer = getattr(mailer, "stop", None)
    if callable(stop_mailer):
        app.router.on_shutdown.append(stop_mailer)

    # ------------------------------------------------------------------
    # Alert engine wiring (A5)
    # ------------------------------------------------------------------
    if alert_engine is None:
        try:
            # Lazy import on purpose, mirroring the mailer above: the engine
            # lands in its own file during the parallel A5 batches.
            from .alert_engine import AlertEngine as _AlertEngine
        except ImportError:
            alert_engine = _NullAlertEngine(db, mailer, config)
        else:
            alert_engine = _AlertEngine(db, mailer, config)
    start_engine = getattr(alert_engine, "start", None)
    if callable(start_engine):
        app.router.on_startup.append(start_engine)
    stop_engine = getattr(alert_engine, "stop", None)
    if callable(stop_engine):
        app.router.on_shutdown.append(stop_engine)

    # ------------------------------------------------------------------
    # Channel dispatcher wiring (A7)
    # ------------------------------------------------------------------
    channels_module = None
    try:
        # Lazy import on purpose, mirroring the mailer/engine wiring above:
        # the adapters land in their own file during the parallel A7 batches.
        from . import channels as channels_module
    except ImportError:
        channels_module = None
    channel_kinds = tuple(
        getattr(channels_module, "CHANNEL_KINDS", None) or CHANNEL_KINDS
    )
    if channel_dispatcher is None:
        if channels_module is None:
            channel_dispatcher = _NullChannelDispatcher(db)
        else:
            channel_dispatcher = channels_module.ChannelDispatcher(db)
    start_dispatcher = getattr(channel_dispatcher, "start", None)
    if callable(start_dispatcher):
        app.router.on_startup.append(start_dispatcher)
    stop_dispatcher = getattr(channel_dispatcher, "stop", None)
    if callable(stop_dispatcher):
        app.router.on_shutdown.append(stop_dispatcher)

    # ------------------------------------------------------------------
    # Data retention worker wiring (P2-13)
    # ------------------------------------------------------------------
    if maintenance is None:
        try:
            interval_hours = float(
                config.security.get("maintenance_interval_hours", 24) or 24
            )
        except (TypeError, ValueError):
            interval_hours = 24.0
        maintenance = MaintenanceWorker(
            db,
            retention=config.security,
            interval_seconds=interval_hours * 3600.0,
        )
    start_maintenance = getattr(maintenance, "start", None)
    if callable(start_maintenance):
        app.router.on_startup.append(start_maintenance)
    stop_maintenance = getattr(maintenance, "stop", None)
    if callable(stop_maintenance):
        app.router.on_shutdown.append(stop_maintenance)
    # 测试与运维排查可以拿到实例；也便于未来接入别的启停入口。
    app.state.maintenance = maintenance

    def _smtp_enabled() -> bool:
        """The mailer is the source of truth; config is the fallback."""
        getter = getattr(mailer, "status", None)
        if callable(getter):
            try:
                snapshot = getter()
            except Exception:
                snapshot = None
            if isinstance(snapshot, dict) and "enabled" in snapshot:
                return bool(snapshot.get("enabled"))
        return bool(smtp_config.get("enabled"))

    def _risk_windows() -> tuple[int, int]:
        try:
            window = int(config.security.get("ip_jump_window_minutes", 10) or 10)
        except (TypeError, ValueError):
            window = 10
        try:
            threshold = int(config.security.get("ip_jump_alert_threshold", 2) or 2)
        except (TypeError, ValueError):
            threshold = 2
        return max(1, min(window, 1440)), max(0, min(threshold, 100))

    def _after_client_ip(key_code: str, machine_code: str, ip: str) -> None:
        """Record a client IP and mail an alert when the subnet keeps jumping."""
        try:
            window, threshold = _risk_windows()
            license = db.get_license(security.normalize_key(key_code))
            info = risk.record_ip_event(
                db,
                license,
                machine_code,
                ip,
                window_minutes=window,
                threshold=threshold,
            )
            if info and license:
                alerting.notify_ip_jump(
                    db,
                    mailer,
                    license=license,
                    machine_code=machine_code,
                    ip=ip,
                    changes=int(info.get("changes") or 0),
                    window_minutes=int(info.get("window_minutes") or window),
                    smtp_config=smtp_config,
                )
        except Exception:
            # Risk telemetry must never break licensing traffic.
            pass

    def _resolve_license_id(machine_code: str):
        try:
            finder = getattr(db, "find_activation_by_machine", None)
            if callable(finder):
                activation = finder(machine_code)
                if activation:
                    return int(activation.get("license_id") or 0) or None
        except Exception:
            pass
        return None

    def _code_since(seconds: int) -> str:
        return (datetime.now() - timedelta(seconds=seconds)).strftime(
            security.TIME_FORMAT
        )

    def _code_send_limited(email: str, purpose: str) -> bool:
        """True when this e-mail+purpose already used its sending budget.

        Two layers: the in-memory guard answers instantly, and action_codes
        keeps the window across restarts (60s/1, 600s/5).
        """
        if not _rate_allowed(f"code60|{email}|{purpose}", 1, 60):
            return True
        if not _rate_allowed(f"code600|{email}|{purpose}", 5, 600):
            return True
        try:
            if db.count_action_codes(email, purpose, _code_since(60)) >= 1:
                return True
            if db.count_action_codes(email, purpose, _code_since(600)) >= 5:
                return True
        except Exception:
            # Rate limiting is a guard, not part of correctness.
            return False
        return False

    def _issue_action_code(
        subject_type: str, subject_id: int, email: str, purpose: str
    ) -> str:
        code = security.generate_action_code()
        expires_at = (
            datetime.now() + timedelta(seconds=ACTION_CODE_TTL_SECONDS)
        ).strftime(security.TIME_FORMAT)
        db.create_action_code(
            subject_type,
            subject_id,
            email,
            purpose,
            security.hash_action_code(secret, code),
            expires_at,
        )
        return code

    def _enqueue_code_mail(
        email: str, purpose: str, code: str, username: str = ""
    ) -> None:
        template_code = (
            "reset_password" if purpose == "reset_password" else "verify_email"
        )
        mailer.enqueue(
            email,
            template_code,
            {
                "code": code,
                "email": email,
                "username": username,
                "purpose": purpose,
                "expires_minutes": ACTION_CODE_TTL_SECONDS // 60,
            },
        )

    @app.exception_handler(AiGatewayError)
    async def ai_error_handler(request: Request, exc: AiGatewayError):
        return JSONResponse(status_code=400, content={"detail": str(exc)})


    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        # Do not echo parser input: malformed surrogate code points cannot be
        # encoded by JSONResponse and may also leak submitted secrets.
        details = [
            {
                "loc": [str(part) for part in error.get("loc", ())],
                "msg": str(error.get("msg", "请求参数无效")),
                "type": str(error.get("type", "value_error")),
            }
            for error in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": details})

    cors_origins = [
        str(origin).strip()
        for origin in config.security.get("cors_origins", [])
        if str(origin).strip()
    ]
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=[
                "Authorization",
                "Content-Type",
                "X-Client-Timestamp",
                "X-Client-Nonce",
                "X-Client-Signature",
                "X-Attest-Token",
            ],
        )

    @app.middleware("http")
    async def enforce_size_and_sign_response(request: Request, call_next):
        def error_response(detail: str, status_code: int) -> Response:
            return Response(
                content=json.dumps(
                    {"detail": detail},
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8"),
                status_code=status_code,
                media_type="application/json",
            )

        async def sign_response(response: Response) -> Response:
            body_iterator = getattr(response, "body_iterator", None)
            if body_iterator is None:
                body = bytes(response.body)
            else:
                chunks: list[bytes] = []
                async for chunk in body_iterator:
                    chunks.append(chunk)
                body = b"".join(chunks)

            headers = dict(response.headers)
            headers.pop("content-length", None)
            signed_response = Response(
                content=body,
                status_code=response.status_code,
                headers=headers,
                media_type=response.media_type,
            )
            request_ts = request.headers.get("X-Client-Timestamp", "")
            request_nonce = request.headers.get("X-Client-Nonce", "")
            message = security.canonical_response_message(
                request.method,
                request.url.path,
                request_ts,
                request_nonce,
                signed_response.status_code,
                body,
                response_key_id,
                request.url.query,
            )
            signed_response.headers["X-Server-Signature"] = offline.sign_message(
                response_private, message
            )
            signed_response.headers["X-Server-Key-Id"] = response_key_id
            signed_response.headers["X-Server-Signed-At"] = str(security.now_ts())
            signed_response.headers["Cache-Control"] = "no-store"
            return signed_response

        if request.method in ("POST", "PUT", "PATCH"):
            # 头像上传要携带 256KB 原始数据的 base64，单独放宽这一条路由；
            # 其它接口继续使用配置里的 max_request_bytes。
            body_limit = max_request_bytes
            if request.url.path == PORTAL_AVATAR_PATH:
                body_limit = max(body_limit, PORTAL_AVATAR_BODY_MAX_BYTES)
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    parsed_length = int(content_length)
                    if parsed_length < 0 or parsed_length > body_limit:
                        return await sign_response(error_response("请求体过大", 413))
                except ValueError:
                    return await sign_response(error_response("Content-Length 无效", 400))
            chunks: list[bytes] = []
            total = 0
            too_large = False
            async for chunk in request.stream():
                total += len(chunk)
                if total > body_limit:
                    too_large = True
                    break
                chunks.append(chunk)
            if too_large:
                return await sign_response(error_response("请求体过大", 413))
            request._body = b"".join(chunks)

        response = await call_next(request)
        return await sign_response(response)

    # Reachable while an operator still has to replace a handover password.
    PASSWORD_GATE_EXEMPT = ("/api/admin/change_password", "/api/admin/me")

    def current_admin(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="未登录或登录状态无效")
        payload = security.verify_token(authorization.split(" ", 1)[1].strip(), secret)
        if not payload:
            raise HTTPException(status_code=401, detail="登录已过期，请重新登录")
        if payload.get("typ") == "portal":
            # A portal session must never unlock the admin API, even though it
            # is signed with the same server secret.
            raise HTTPException(status_code=401, detail="登录凭证无效")
        try:
            admin_id = int(payload.get("uid", 0))
        except (TypeError, ValueError):
            raise HTTPException(status_code=401, detail="登录凭证无效")
        admin = db.get_admin_by_id(admin_id)
        if not admin:
            raise HTTPException(status_code=401, detail="账号不存在")
        if admin["status"] != "active":
            raise HTTPException(status_code=403, detail="账号已被禁用")
        try:
            token_version = int(payload.get("ver", -1))
        except (TypeError, ValueError):
            raise HTTPException(status_code=401, detail="登录凭证无效")
        if token_version != int(admin.get("auth_version") or 0):
            raise HTTPException(status_code=401, detail="登录状态已失效，请重新登录")
        if admin.get("must_change_password") and request.url.path not in PASSWORD_GATE_EXEMPT:
            # The UI already forces the password page, but the flag has to hold
            # for direct API calls too.
            raise HTTPException(
                status_code=403,
                detail="当前账号仍在使用初始/重置密码，请先修改密码后再使用其它功能",
            )
        return admin

    def require_master(admin: dict = Depends(current_admin)) -> dict:
        if admin["role"] != "master":
            raise HTTPException(status_code=403, detail="需要主控权限")
        return admin

    def current_portal(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> dict:
        """Resolve a portal session: typ=portal, active account, live version."""
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="未登录或登录状态无效")
        payload = security.verify_portal_token(
            authorization.split(" ", 1)[1].strip(), secret
        )
        if not payload:
            raise HTTPException(status_code=401, detail="登录已过期，请重新登录")
        try:
            account_id = int(payload.get("uid", 0))
        except (TypeError, ValueError):
            raise HTTPException(status_code=401, detail="登录凭证无效")
        account = db.get_portal_account_by_id(account_id)
        if not account:
            raise HTTPException(status_code=401, detail="账号不存在")
        if account["status"] != "active":
            raise HTTPException(status_code=403, detail="账号已被禁用")
        try:
            token_version = int(payload.get("ver", -1))
        except (TypeError, ValueError):
            raise HTTPException(status_code=401, detail="登录凭证无效")
        if token_version != int(account.get("auth_version") or 0):
            raise HTTPException(status_code=401, detail="登录状态已失效，请重新登录")
        return account

    def _client_failure_limited(bucket: str, ip: str) -> bool:
        """Count one failed client call and report whether to back off.

        Only failures reach here, so a signed request from a licensed device
        is never throttled by other tenants sharing its address.
        """
        return not _rate_allowed(
            f"{bucket}|{ip}", verify_fail_max_attempts, verify_fail_lock_seconds
        )

    def _client_rate_limited() -> dict:
        return {
            "ok": False,
            "code": "rate_limited",
            "message": "请求过于频繁，请稍后再试",
        }

    # ------------------------------------------------------------------
    # Client attestation (executable whitelist gate)
    # ------------------------------------------------------------------
    def _attestation_enforced() -> bool:
        """Report whether activate/verify/heartbeat have to carry a token.

        ``off`` never enforces; ``auto`` only once a release has actually been
        registered, so a fresh install without a manifest keeps working.
        """
        mode = str(config.security.get("attest_mode", "auto") or "auto").strip().lower()
        if mode == "off":
            return False
        if mode == "auto":
            return db.count_active_release_hashes() > 0
        return True

    def _attestation_ttl() -> int:
        try:
            value = int(config.security.get("attest_token_ttl_seconds", 600) or 600)
        except (TypeError, ValueError):
            value = 600
        return max(60, min(value, 24 * 3600))

    def _attestation_denied() -> HTTPException:
        return HTTPException(
            status_code=403, detail="客户端完整性校验未通过，已拒绝访问"
        )

    def _attestation_role_text(role) -> str:
        """Normalize a client-declared role without trusting its casing.

        Legacy client bodies carry no role field at all; the token is then only
        checked against the machine binding.
        """
        if isinstance(role, str):
            return role.strip().lower()
        value = getattr(role, "role", "")
        return str(value or "").strip().lower()

    def _require_attestation(request: Request, machine_code: str, role="") -> None:
        """Raise 403 unless the caller holds a live token for this machine.

        The token hash is re-checked against ``release_hashes`` on every call,
        so deactivating a build in /api/release/status revokes access immediately
        instead of waiting for the token to expire.
        """
        if not _attestation_enforced():
            return
        client_kind = str(request.headers.get("X-Client-Kind", "") or "").strip().lower()
        if client_kind == "sdk" and bool(config.security.get("sdk_attest_exempt", False)):
            # SDK 无法进入发布白名单。豁免必须同时满足：显式开启开关 +
            # 配置共享密钥 + 提供绑定机器码的 HMAC 凭证。
            shared = str(config.security.get("sdk_shared_secret") or "").strip()
            provided = str(request.headers.get("X-SDK-Token", "") or "").strip()
            if shared and provided:
                expected = security.hash_action_code(
                    shared, str(machine_code or "").upper()
                )
                if hmac.compare_digest(provided, expected):
                    db.add_log(
                        "SDK免attest放行",
                        "sdk",
                        str(machine_code or ""),
                        "共享密钥校验通过",
                        _client_ip(request),
                    )
                    return
            # 缺少共享密钥或校验失败：回落到正常 attest 检查。
        token = request.headers.get("X-Attest-Token", "")
        if not token:
            raise _attestation_denied()
        valid, payload = security.verify_attest_token(
            secret, token, machine_code, _attestation_role_text(role)
        )
        if not valid or not payload:
            raise _attestation_denied()
        if not db.match_release_hash(payload.get("hash", "")):
            raise _attestation_denied()


    @app.get("/api/health")
    def health():
        return {
            "status": "ok",
            "version": VERSION,
            "time": security.now_str(),
            "ts": security.now_ts(),
            "server": f"{config.server['host']}:{config.server['port']}",
        }

    @app.get("/api/public_key")
    def public_key():
        return {
            "public_key": offline_public,
            "offline_public_key": offline_public,
            "response_public_key": response_public,
            "response_key_id": response_key_id,
            "offline_key_fingerprint": offline.public_key_fingerprint(offline_public),
            "response_key_fingerprint": offline.public_key_fingerprint(response_public),
            "algorithm": "ed25519",
        }

    @app.post("/api/admin/login")
    def login(body: LoginBody, request: Request):
        ip = _client_ip(request)
        username = body.username.strip()
        if not username:
            raise HTTPException(status_code=400, detail="用户名不能为空")
        guard_key = f"{ip}|{username.lower()}"
        if not _login_allowed(guard_key, login_max_attempts, login_lock_seconds):
            db.add_log("登录锁定", username, "", "尝试过于频繁", ip)
            raise HTTPException(status_code=429, detail="尝试过于频繁，请稍后再试")
        # Cap attempts per source address too: the composite key above is
        # trivially evaded by rotating the username.
        if not _rate_allowed(
            f"login-ip|{ip}", login_ip_max_attempts, login_lock_seconds
        ):
            db.add_log("登录锁定", username, "", "同 IP 尝试过于频繁", ip)
            raise HTTPException(status_code=429, detail="尝试过于频繁，请稍后再试")
        admin = db.get_admin(username)
        if not _constant_time_login(body.password, admin):
            _record_login_failure(guard_key, login_lock_seconds)
            db.add_log("登录失败", _audit_text(username), "", "用户名或密码错误", ip)
            raise HTTPException(status_code=401, detail="用户名或密码错误")
        if admin["status"] != "active":
            db.add_log("登录失败", admin["username"], "", "账号已禁用", ip)
            raise HTTPException(status_code=403, detail="账号已被禁用")
        _clear_login_failures(guard_key)
        # A successful login also clears the per-address budget. Otherwise junk
        # attempts from a shared NAT would lock the real administrator out for
        # the rest of the window even though their own bucket is clean.
        _rate_clear(f"login-ip|{ip}")
        db.touch_admin_login(admin["id"])
        db.add_log("登录成功", admin["username"], "", f"角色 {admin['role']}", ip)
        token = security.create_token(
            {
                "uid": admin["id"],
                "username": admin["username"],
                "role": admin["role"],
                "ver": int(admin.get("auth_version") or 0),
            },
            secret,
            ttl,
        )
        return {
            "token": token,
            "username": admin["username"],
            "role": admin["role"],
            "must_change_password": bool(admin.get("must_change_password")),
            "expires_in": ttl,
        }

    @app.get("/api/admin/me")
    def me(admin: dict = Depends(current_admin)):
        return {
            "id": admin["id"],
            "username": admin["username"],
            "role": admin["role"],
            "must_change_password": bool(admin.get("must_change_password")),
            "email": str(admin.get("email") or ""),
            "email_verified": bool(admin.get("email_verified_at")),
        }

    @app.post("/api/admin/email/set")
    def admin_email_set(
        body: AdminEmailSetBody,
        request: Request,
        admin: dict = Depends(current_admin),
    ):
        ip = _client_ip(request)
        email = body.email
        if not _smtp_enabled():
            db.add_log("设置管理员邮箱失败", admin["username"], email, "SMTP 未启用", ip)
            raise HTTPException(status_code=400, detail="SMTP 未启用或未配置")
        if _code_send_limited(email, "verify_email"):
            raise HTTPException(status_code=429, detail="验证码发送过于频繁，请稍后再试")
        try:
            db.set_admin_email(admin["id"], email)
        except sqlite3.IntegrityError:
            db.add_log("设置管理员邮箱失败", admin["username"], email, "邮箱被占用", ip)
            raise HTTPException(status_code=400, detail="该邮箱已被其他管理员使用")
        code = _issue_action_code("admin", admin["id"], email, "verify_email")
        _enqueue_code_mail(email, "verify_email", code, admin["username"])
        db.add_log("设置管理员邮箱", admin["username"], email, "已发送验证码", ip)
        return {"ok": True, "email": email, "expires_in": ACTION_CODE_TTL_SECONDS}

    @app.post("/api/admin/email/verify")
    def admin_email_verify(
        body: AdminEmailVerifyBody,
        request: Request,
        admin: dict = Depends(current_admin),
    ):
        ip = _client_ip(request)
        email = str(admin.get("email") or "").strip().lower()
        if not email:
            raise HTTPException(status_code=400, detail="请先设置邮箱")
        if not db.consume_action_code(
            "admin", email, "verify_email",
            security.hash_action_code(secret, body.code),
        ):
            db.add_log("验证管理员邮箱失败", admin["username"], email, "验证码无效", ip)
            raise HTTPException(status_code=400, detail="验证码错误或已过期")
        db.mark_admin_email_verified(admin["id"])
        db.add_log("验证管理员邮箱", admin["username"], email, "", ip)
        return {"ok": True}

    @app.post("/api/admin/password/forgot")
    def admin_password_forgot(
        body: AdminPasswordForgotBody, request: Request
    ):
        ip = _client_ip(request)
        email = body.email
        # Anti-enumeration: the caller never learns whether the address is
        # known, verified, or whether SMTP is configured.
        target = db.get_admin_by_email(email)
        if not target or not target.get("email_verified_at"):
            db.add_log(
                "请求管理员密码重置", "anonymous", email, "未发送（防枚举）", ip
            )
            return {"ok": True}
        if not _smtp_enabled():
            db.add_log(
                "请求管理员密码重置", target["username"], email, "SMTP 未启用", ip
            )
            return {"ok": True}
        if _code_send_limited(email, "reset_password"):
            db.add_log(
                "请求管理员密码重置", target["username"], email, "发送过于频繁", ip
            )
            return {"ok": True}
        code = _issue_action_code(
            "admin", target["id"], email, "reset_password"
        )
        try:
            _enqueue_code_mail(email, "reset_password", code, target["username"])
        except Exception:
            db.add_log(
                "请求管理员密码重置", target["username"], email, "邮件入队失败", ip
            )
            return {"ok": True}
        db.add_log(
            "请求管理员密码重置", target["username"], email, "已发送验证码", ip
        )
        return {"ok": True}

    @app.post("/api/admin/password/reset")
    def admin_password_reset(
        body: AdminPasswordResetBody, request: Request
    ):
        ip = _client_ip(request)
        email = body.email
        ok, msg = security.password_strength(body.new_password)
        if not ok:
            raise HTTPException(status_code=400, detail=msg)
        target = db.get_admin_by_email(email)
        consumed = False
        if target:
            consumed = db.consume_action_code(
                "admin", email, "reset_password",
                security.hash_action_code(secret, body.code),
            )
        if not target or not consumed:
            db.add_log("管理员邮箱重置密码失败", "anonymous", email, "验证码无效", ip)
            raise HTTPException(status_code=400, detail="验证码错误或已过期")
        # set_admin_password bumps auth_version, so every previously issued
        # admin token stops working immediately.
        db.set_admin_password(
            target["id"], body.new_password, must_change_password=False
        )
        db.add_log(
            "管理员邮箱重置密码", target["username"], email, "旧登录状态已失效", ip
        )
        return {"ok": True}

    @app.post("/api/license/generate")
    def generate(body: GenerateBody, admin: dict = Depends(current_admin)):
        card_type = (body.card_type or "duration").strip().lower()
        if card_type not in ("duration", "activation"):
            raise HTTPException(status_code=400, detail="不支持的卡密模式")
        if card_type == "activation":
            if body.activation_limit < 1:
                raise HTTPException(
                    status_code=400, detail="激活次数卡必须设置 1 次以上的激活次数"
                )
            # 次数卡的“可用激活台数”就是它的限制，不再叠加时长与设备数。
            unit = "day"
            duration_days = 0
            max_devices = 0
        else:
            unit = checked_unit(body.duration_days, body.duration_unit)
            duration_days = body.duration_days
            max_devices = body.max_devices
        try:
            feature_list = security.normalize_features(body.features)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        batch_no, keys = db.generate_licenses(
            count=body.count,
            edition=body.edition or "standard",
            duration_days=duration_days,
            max_devices=max_devices,
            note=body.note,
            created_by=admin["username"],
            prefix=(body.prefix or default_prefix).upper(),
            duration_unit=unit,
            card_type=card_type,
            activation_limit=body.activation_limit,
            features=feature_list,
        )
        detail = f"共 {len(keys)} 个"
        if card_type == "activation":
            detail += f" | 激活次数卡 {body.activation_limit} 次"
        db.add_log("生成密钥", admin["username"], batch_no, detail, "")
        return {"batch_no": batch_no, "count": len(keys), "keys": keys}

    @app.get("/api/license/list")
    def list_licenses(
        keyword: str = Query(default="", max_length=128),
        status: str = Query(default="", max_length=32),
        batch_no: str = Query(default="", max_length=128),
        limit: int = Query(default=200, ge=1, le=500),
        offset: int = Query(default=0, ge=0, le=1_000_000),
        admin: dict = Depends(current_admin),
    ):
        items = db.list_licenses(keyword, status, batch_no, limit, offset)
        total = db.count_licenses(keyword, status, batch_no)
        return {"items": items, "total": total}

    @app.get("/api/license/batches")
    def list_batches(
        keyword: str = Query(default="", max_length=128),
        limit: int = Query(default=200, ge=1, le=500),
        offset: int = Query(default=0, ge=0, le=1_000_000),
        admin: dict = Depends(current_admin),
    ):
        return {
            "items": db.list_batches(keyword, limit, offset),
            "total": db.count_batches(keyword),
        }

    @app.get("/api/license/detail")
    def license_detail(
        key_code: str = Query(min_length=1, max_length=128),
        admin: dict = Depends(current_admin),
    ):
        lic = db.get_license(key_code)
        if not lic:
            raise HTTPException(status_code=404, detail="密钥不存在")
        # 功能位在库内为 JSON 文本；序列化前转为列表，客户端可直接使用。
        lic["features"] = security.features_from_text(lic.get("features"))
        return {"license": lic, "activations": db.list_activations(key_code)}

    @app.post("/api/license/offline_code")
    def offline_code(body: OfflineCodeBody, admin: dict = Depends(current_admin)):
        key_code = security.normalize_key(body.key_code)
        machine_code = (body.machine_code or "").strip().upper()
        if not key_code or not machine_code:
            raise HTTPException(status_code=400, detail="密钥和机器码不能为空")
        db.release_expired_freeze(key_code)
        db.sweep_expired()
        lic = db.get_license(key_code)
        if not lic:
            db.add_log("生成离线激活码失败", admin["username"], key_code, "密钥不存在", "")
            raise HTTPException(status_code=404, detail="密钥不存在")
        if is_activation_card(lic):
            # 离线激活码无法回写激活次数，必须拒绝，否则会绕过次数限制。
            db.add_log(
                "生成离线激活码失败", admin["username"], key_code, "次数卡不支持离线激活", ""
            )
            raise HTTPException(
                status_code=400,
                detail="激活次数卡不支持离线激活码，请在联网状态下激活",
            )
        if lic["status"] == "frozen":
            _frozen_tip = (
                "长期锁定（需管理员解冻/换绑）"
                if security.is_long_freeze(lic.get("frozen_until"))
                else f"剩余 {security.humanize_remaining(lic.get('frozen_until'))}"
            )
            db.add_log("生成离线激活码失败", admin["username"], key_code, "密钥已冻结", "")
            raise HTTPException(
                status_code=400,
                detail=f"该密钥已被冻结（{_frozen_tip}），无法生成离线激活码",
            )
        if lic["status"] == "revoked":
            db.add_log("生成离线激活码失败", admin["username"], key_code, "密钥已吊销", "")
            raise HTTPException(status_code=400, detail="该密钥已被吊销，无法生成离线激活码")
        if lic["status"] == "expired" or security.is_expired(lic.get("expires_at")):
            db.set_license_status(key_code, "expired")
            db.add_log("生成离线激活码失败", admin["username"], key_code, "密钥已过期", "")
            raise HTTPException(status_code=400, detail="该密钥已过期，无法生成离线激活码")
        if not offline_private:
            raise HTTPException(status_code=500, detail="服务器未配置离线签名私钥")

        expiry = _expiry_for_license(db, lic)
        result, activation_id, effective_expiry = db.activate_atomic(
            lic["id"],
            key_code,
            machine_code,
            body.device_name,
            expiry,
        )
        if result == "limit":
            max_devices = int(lic["max_devices"] or 0)
            db.add_log("生成离线激活码失败", admin["username"], key_code, "设备数达上限", "")
            raise HTTPException(
                status_code=400,
                detail=f"该密钥最多绑定 {max_devices} 台设备，已达上限",
            )
        if result not in ("activated", "already") or activation_id is None:
            db.add_log("生成离线激活码失败", admin["username"], key_code, f"状态 {result}", "")
            raise HTTPException(status_code=400, detail="该密钥当前无法生成离线激活码")

        payload = offline.build_activation_payload(
            machine_code=machine_code,
            key_code=key_code,
            edition=lic["edition"],
            duration_days=lic["duration_days"],
            expires_at=effective_expiry,
            max_devices=lic["max_devices"],
            note=lic["note"] or "",
            features=security.features_from_text(lic.get("features")),
        )
        code = offline.make_activation_code(payload, offline_private)
        db.add_log("生成离线激活码", admin["username"], key_code, f"设备 {machine_code}", "")
        return {
            "ok": True,
            "code": code,
            "key_code": key_code,
            "machine_code": machine_code,
            "expires_at": effective_expiry,
            "remaining": security.humanize_remaining(effective_expiry),
            "duration_text": security.duration_text(
                lic["duration_days"], lic.get("duration_unit") or "day"
            ),
        }

    @app.post("/api/license/revoke")
    def revoke(body: KeyBody, admin: dict = Depends(current_admin)):
        if not db.get_license(body.key_code):
            raise HTTPException(status_code=404, detail="密钥不存在")
        db.set_license_status(body.key_code, "revoked")
        db.add_log(
            "吊销密钥",
            admin["username"],
            security.normalize_key(body.key_code),
            "",
            "",
        )
        return {"ok": True, "message": "已吊销"}

    @app.post("/api/license/restore")
    def restore(body: KeyBody, admin: dict = Depends(current_admin)):
        if not db.get_license(body.key_code):
            raise HTTPException(status_code=404, detail="密钥不存在")
        target = db.restore_license(body.key_code)
        if target == "__exhausted__":
            raise HTTPException(
                status_code=400,
                detail="该密钥激活次数已用尽，无法恢复；如需继续使用请重新生成",
            )
        if target == "__expired__":
            raise HTTPException(
                status_code=400,
                detail="该密钥已过有效期，不能直接恢复，请先续期",
            )
        if target is None:
            raise HTTPException(status_code=400, detail="该密钥当前不可恢复（仅吊销状态可恢复）")
        db.add_log(
            "恢复密钥",
            admin["username"],
            security.normalize_key(body.key_code),
            f"恢复为 {target}",
            "",
        )
        return {"ok": True, "status": target, "message": "已恢复，设备绑定保持不变"}

    @app.post("/api/license/renew")
    def renew(body: RenewBody, admin: dict = Depends(current_admin)):
        existing = db.get_license(body.key_code)
        if existing and is_activation_card(existing):
            raise HTTPException(status_code=400, detail="激活次数卡按次数使用，不支持续期")
        unit = checked_unit(body.duration_days, body.duration_unit)
        result = db.renew_license(
            body.key_code, body.duration_days, unit
        )
        if result is None:
            raise HTTPException(
                status_code=400,
                detail="该密钥不存在、为永久密钥或续期参数无效",
            )
        target, new_expiry = result
        db.add_log(
            "续期密钥",
            admin["username"],
            security.normalize_key(body.key_code),
            f"{security.duration_text(body.duration_days, unit)} -> {new_expiry}",
            "",
        )
        return {
            "ok": True,
            "status": target,
            "expires_at": new_expiry,
            "remaining": security.humanize_remaining(new_expiry),
            "message": "续期成功",
        }

    @app.post("/api/license/freeze")
    def freeze(body: FreezeBody, admin: dict = Depends(current_admin)):
        if not db.get_license(body.key_code):
            raise HTTPException(status_code=404, detail="密钥不存在")
        unit = checked_unit(body.amount, body.unit)
        frozen_until = security.compute_freeze_until(body.amount, unit)
        if not frozen_until:
            raise HTTPException(status_code=400, detail="冻结时长必须大于 0")
        prev = db.freeze_license(body.key_code, frozen_until, body.reason)
        if prev is None:
            raise HTTPException(status_code=400, detail="该密钥已过期或吊销，无法冻结")
        span = security.duration_text(body.amount, unit)
        db.add_log(
            "冻结密钥",
            admin["username"],
            security.normalize_key(body.key_code),
            f"{span} | {body.reason}",
            "",
        )
        return {"ok": True, "frozen_until": frozen_until, "message": f"已冻结 {span}"}

    @app.post("/api/license/unfreeze")
    def unfreeze(body: KeyBody, admin: dict = Depends(current_admin)):
        if not db.get_license(body.key_code):
            raise HTTPException(status_code=404, detail="密钥不存在")
        target = db.unfreeze_license(body.key_code)
        if target == "__exhausted__":
            raise HTTPException(
                status_code=400,
                detail="该密钥激活次数已用尽，无法解冻；如需继续使用请重新生成",
            )
        if target == "__expired__":
            raise HTTPException(status_code=400, detail="该密钥已过期，无法解冻，请续期")
        if target is None:
            raise HTTPException(status_code=400, detail="该密钥当前不处于冻结状态")
        db.add_log(
            "解冻密钥",
            admin["username"],
            security.normalize_key(body.key_code),
            f"恢复为 {target}",
            "",
        )
        return {"ok": True, "status": target, "message": "已解冻"}

    @app.post("/api/license/revoke_batch")
    def revoke_batch(body: BatchBody, admin: dict = Depends(current_admin)):
        count = db.revoke_batch(body.batch_no)
        db.add_log("吊销批次", admin["username"], body.batch_no, f"共 {count} 个", "")
        return {"ok": True, "count": count}

    @app.post("/api/license/restore_batch")
    def restore_batch(body: BatchBody, admin: dict = Depends(current_admin)):
        count = db.restore_batch(body.batch_no)
        db.add_log("恢复批次", admin["username"], body.batch_no, f"共 {count} 个", "")
        return {"ok": True, "count": count}

    @app.post("/api/license/delete")
    def delete_license(body: KeyBody, admin: dict = Depends(current_admin)):
        if not db.get_license(body.key_code):
            raise HTTPException(status_code=404, detail="密钥不存在")
        db.delete_license(body.key_code)
        db.add_log("删除密钥", admin["username"], security.normalize_key(body.key_code), "", "")
        return {"ok": True}

    @app.post("/api/license/unbind")
    def unbind(body: UnbindBody, admin: dict = Depends(current_admin)):
        changed = db.unbind_activation(body.key_code, body.machine_code)
        if not changed:
            raise HTTPException(status_code=404, detail="未找到对应的有效设备绑定")
        db.add_log(
            "解绑设备",
            admin["username"],
            security.normalize_key(body.key_code),
            body.machine_code.strip().upper(),
            "",
        )
        return {"ok": True}

    @app.get("/api/license/stats")
    def stats(admin: dict = Depends(current_admin)):
        return db.stats_cached()

    @app.get("/api/admin/list")
    def admin_list(admin: dict = Depends(require_master)):
        return {"items": db.list_admins()}

    @app.post("/api/admin/create")
    def admin_create(body: AdminCreateBody, admin: dict = Depends(require_master)):
        username = body.username.strip()
        if not username:
            raise HTTPException(status_code=400, detail="用户名不能为空")
        if db.get_admin(username):
            raise HTTPException(status_code=400, detail="用户名已存在")
        if body.role not in ("admin", "master"):
            raise HTTPException(status_code=400, detail="角色非法")
        ok, msg = security.password_strength(body.password)
        if not ok:
            raise HTTPException(status_code=400, detail=msg)
        admin_id = db.create_admin(username, body.password, body.role)
        db.add_log(
            "创建管理员",
            admin["username"],
            username,
            f"角色 {body.role}",
            "",
        )
        return {"ok": True, "id": admin_id}

    @app.post("/api/admin/status")
    def admin_status(body: AdminStatusBody, admin: dict = Depends(require_master)):
        if body.status not in ("active", "disabled"):
            raise HTTPException(status_code=400, detail="状态非法")
        target = db.get_admin_by_id(body.admin_id)
        if not target:
            raise HTTPException(status_code=404, detail="管理员不存在")
        if target["id"] == admin["id"]:
            raise HTTPException(status_code=400, detail="不能修改自己的状态")
        if target["role"] == "master":
            raise HTTPException(status_code=403, detail="不能禁用另一位主控账号")
        db.set_admin_status(target["id"], body.status)
        db.add_log(
            "修改管理员状态",
            admin["username"],
            target["username"],
            body.status,
            "",
        )
        return {"ok": True}

    @app.post("/api/admin/password")
    def admin_password(body: AdminPasswordBody, admin: dict = Depends(require_master)):
        target = db.get_admin_by_id(body.admin_id)
        if not target:
            raise HTTPException(status_code=404, detail="管理员不存在")
        if target["id"] == admin["id"]:
            raise HTTPException(status_code=400, detail="请在“修改密码”页面修改自己的密码")
        if target["role"] == "master":
            raise HTTPException(status_code=403, detail="不能重置另一位主控账号的密码")
        ok, msg = security.password_strength(body.password)
        if not ok:
            raise HTTPException(status_code=400, detail=msg)
        # Force the target to pick a password only they know.
        db.set_admin_password(target["id"], body.password, must_change_password=True)
        db.add_log("重置管理员密码", admin["username"], target["username"], "", "")
        return {"ok": True}

    @app.post("/api/admin/change_password")
    def change_password(
        body: ChangePasswordBody, admin: dict = Depends(current_admin)
    ):
        fresh = db.get_admin_by_id(admin["id"])
        if not fresh or not security.verify_password(
            body.old_password, fresh["password_hash"], fresh["salt"]
        ):
            raise HTTPException(status_code=400, detail="旧密码错误")
        ok, msg = security.password_strength(body.new_password)
        if not ok:
            raise HTTPException(status_code=400, detail=msg)
        if security.verify_password(
            body.new_password, fresh["password_hash"], fresh["salt"]
        ):
            raise HTTPException(status_code=400, detail="新密码不能与旧密码相同")
        db.set_admin_password(fresh["id"], body.new_password, must_change_password=False)
        updated = db.get_admin_by_id(fresh["id"])
        new_token = security.create_token(
            {
                "uid": updated["id"],
                "username": updated["username"],
                "role": updated["role"],
                "ver": int(updated.get("auth_version") or 0),
            },
            secret,
            ttl,
        )
        db.add_log("修改自己的密码", admin["username"], "", "", "")
        return {
            "ok": True,
            "token": new_token,
            "message": "密码已修改，旧登录状态已失效",
        }

    # ------------------------------------------------------------------
    # Portal account administration (问题六): 管理端与主控端都可用
    # ------------------------------------------------------------------
    @app.get("/api/admin/portal_accounts")
    def admin_portal_accounts(
        keyword: str = Query(default="", max_length=128),
        status: str = Query(default="", max_length=32),
        limit: int = Query(default=200, ge=1, le=500),
        offset: int = Query(default=0, ge=0, le=1_000_000),
        admin: dict = Depends(current_admin),
    ):
        state = (status or "").strip().lower()
        if state and state not in ("active", "disabled"):
            raise HTTPException(status_code=400, detail="状态非法")
        items, total = db.list_portal_accounts(keyword, state, limit, offset)
        return {"items": items, "total": total}

    @app.post("/api/admin/portal_accounts/{account_id}/status")
    def admin_portal_account_status(
        account_id: int,
        body: PortalAccountStatusBody,
        admin: dict = Depends(current_admin),
    ):
        state = (body.status or "").strip().lower()
        if state not in ("active", "disabled"):
            raise HTTPException(status_code=400, detail="状态非法")
        target = db.get_portal_account_by_id(account_id)
        if not target:
            raise HTTPException(status_code=404, detail="账号不存在")
        db.set_portal_account_status(target["id"], state)
        db.add_log(
            "修改门户账号状态", admin["username"], target["email"], state, ""
        )
        return {"ok": True}

    @app.post("/api/admin/portal_accounts/{account_id}/unbind")
    def admin_portal_account_unbind(
        account_id: int,
        request: Request,
        admin: dict = Depends(current_admin),
    ):
        target = db.get_portal_account_by_id(account_id)
        if not target:
            raise HTTPException(status_code=404, detail="账号不存在")
        binding = db.get_portal_binding(target["id"])
        if not binding:
            raise HTTPException(status_code=404, detail="该账号当前没有绑定密钥")
        key_code = str(binding.get("key_code") or "")
        if not db.admin_unbind_portal_account(
            target["id"], "管理员强制脱绑", admin["username"]
        ):
            raise HTTPException(status_code=404, detail="该账号当前没有绑定密钥")
        db.add_log(
            "强制脱绑门户账号",
            admin["username"],
            target["email"],
            key_code,
            _client_ip(request),
        )
        return {"ok": True}

    # ------------------------------------------------------------------
    # Verification portal: e-mail accounts, login and licence binding (P1)
    # ------------------------------------------------------------------
    def _portal_binding_view(account_id: int):
        """Add licence status/expiry so the client can render the binding.

        ``get_portal_binding`` only stores the account-licence relation; the
        verification UI needs the licence state to decide which buttons are
        available without waiting for a heartbeat.
        """
        binding = db.get_portal_binding(account_id)
        if not binding:
            return None
        view = dict(binding)
        try:
            license = db.get_license(str(binding.get("key_code") or ""))
        except Exception:
            license = None
        if license:
            view["license_status"] = license.get("status")
            view["expires_at"] = license.get("expires_at")
            view["edition"] = license.get("edition")
            view["max_devices"] = license.get("max_devices")
            view["remaining"] = security.humanize_remaining(
                license.get("expires_at")
            )
        return view

    def _portal_profile_view(account: dict) -> dict:
        """Profile payload shared by profile/login/me (问题一)."""
        avatar = db.get_portal_avatar(int(account.get("id") or 0))
        return {
            "display_name": str(account.get("display_name") or ""),
            "avatar": (
                {
                    "mime": avatar[0],
                    "data_base64": base64.b64encode(avatar[1]).decode("ascii"),
                }
                if avatar
                else None
            ),
        }

    def _portal_send_reset_code(email: str, ip: str) -> dict:
        """Reset-code path for the portal: always answers ok:true.

        A caller must not be able to learn whether the address is registered
        or whether SMTP is configured, so every branch returns success and
        the decision is only visible in the audit log.
        """
        account = db.get_portal_account(email)
        if not account:
            db.add_log("门户重置验证码", email, "", "账号不存在，防枚举返回成功", ip)
            return {"ok": True}
        if not _smtp_enabled():
            db.add_log("门户重置验证码", email, "", "SMTP 未启用，防枚举返回成功", ip)
            return {"ok": True}
        if _code_send_limited(email, "reset_password"):
            db.add_log("门户重置验证码", email, "", "发送过于频繁", ip)
            return {"ok": True}
        code = _issue_action_code(
            "portal", account["id"], email, "reset_password"
        )
        try:
            _enqueue_code_mail(email, "reset_password", code)
        except Exception:
            db.add_log("门户重置验证码", email, "", "邮件入队失败", ip)
            return {"ok": True}
        db.add_log("门户重置验证码", email, "", "已发送", ip)
        return {"ok": True}

    @app.post("/api/portal/email/send_code")
    def portal_send_code(body: PortalSendCodeBody, request: Request):
        ip = _client_ip(request)
        email = body.email
        purpose = (body.purpose or "").strip().lower()
        if purpose in ("reset", "reset_password"):
            return _portal_send_reset_code(email, ip)
        if purpose != "register":
            raise HTTPException(status_code=400, detail="不支持的验证码用途")
        if db.get_portal_account(email):
            return {"ok": False, "code": "already_registered"}
        if not _smtp_enabled():
            db.add_log("门户注册验证码", email, "", "SMTP 未启用", ip)
            raise HTTPException(status_code=400, detail="SMTP 未启用或未配置")
        if _code_send_limited(email, "register"):
            db.add_log("门户注册验证码", email, "", "发送过于频繁", ip)
            return {"ok": True}
        code = _issue_action_code("portal", 0, email, "register")
        try:
            _enqueue_code_mail(email, "register", code)
            db.add_log("门户注册验证码", email, "", "已发送", ip)
        except Exception:
            db.add_log("门户注册验证码", email, "", "邮件入队失败", ip)
        return {"ok": True}

    @app.post("/api/portal/register")
    def portal_register(body: PortalRegisterBody, request: Request):
        ip = _client_ip(request)
        email = body.email
        if db.get_portal_account(email):
            return {"ok": False, "code": "already_registered"}
        ok, msg = security.password_strength(body.password)
        if not ok:
            raise HTTPException(status_code=400, detail=msg)
        if not db.consume_action_code(
            "portal", email, "register",
            security.hash_action_code(secret, body.code),
        ):
            db.add_log("门户注册失败", email, "", "验证码无效", ip)
            raise HTTPException(status_code=400, detail="验证码错误或已过期")
        password_hash, salt = security.hash_password(body.password)
        try:
            account_id = db.create_portal_account(email, password_hash, salt)
        except sqlite3.IntegrityError:
            return {"ok": False, "code": "already_registered"}
        db.mark_portal_email_verified(account_id)
        token = security.create_portal_token(
            {"uid": account_id, "ver": 0}, secret, PORTAL_TOKEN_TTL_SECONDS
        )
        db.add_log("门户注册", email, "", "", ip)
        return {
            "ok": True,
            "token": token,
            "expires_in": PORTAL_TOKEN_TTL_SECONDS,
            "email": email,
        }

    @app.post("/api/portal/login")
    def portal_login(body: PortalLoginBody, request: Request):
        ip = _client_ip(request)
        email = body.email
        guard_key = f"portal|{ip}|{email}"
        if not _login_allowed(guard_key, login_max_attempts, login_lock_seconds):
            db.add_log("门户登录锁定", email, "", "尝试过于频繁", ip)
            raise HTTPException(status_code=429, detail="尝试过于频繁，请稍后再试")
        if not _rate_allowed(
            f"portal-login-ip|{ip}", login_ip_max_attempts, login_lock_seconds
        ):
            db.add_log("门户登录锁定", email, "", "同 IP 尝试过于频繁", ip)
            raise HTTPException(status_code=429, detail="尝试过于频繁，请稍后再试")
        account = db.get_portal_account(email)
        # Always run the full PBKDF2 routine, even for unknown addresses, so
        # response time does not reveal whether the account exists.
        matched = _constant_time_login(body.password, account)
        if not account or not matched or account.get("status") != "active":
            _record_login_failure(guard_key, login_lock_seconds)
            db.add_log("门户登录失败", email, "", "邮箱或密码错误", ip)
            return {
                "ok": False,
                "code": "invalid_credentials",
                "message": "邮箱或密码错误",
            }
        _clear_login_failures(guard_key)
        _rate_clear(f"portal-login-ip|{ip}")
        db.touch_portal_login(account["id"])
        token = security.create_portal_token(
            {
                "uid": account["id"],
                "ver": int(account.get("auth_version") or 0),
            },
            secret,
            PORTAL_TOKEN_TTL_SECONDS,
        )
        db.add_log("门户登录成功", email, "", "", ip)
        profile = _portal_profile_view(account)
        return {
            "ok": True,
            "token": token,
            "expires_in": PORTAL_TOKEN_TTL_SECONDS,
            "email": email,
            "display_name": profile["display_name"],
            "avatar": profile["avatar"],
            "binding": _portal_binding_view(account["id"]),
        }

    @app.get("/api/portal/me")
    def portal_me(account: dict = Depends(current_portal)):
        profile = _portal_profile_view(account)
        return {
            "ok": True,
            "email": account["email"],
            "email_verified": bool(account.get("email_verified_at")),
            "display_name": profile["display_name"],
            "avatar": profile["avatar"],
            "binding": _portal_binding_view(account["id"]),
        }

    @app.get("/api/portal/profile")
    def portal_profile(account: dict = Depends(current_portal)):
        profile = _portal_profile_view(account)
        return {
            "ok": True,
            "email": account["email"],
            "display_name": profile["display_name"],
            "email_verified": bool(account.get("email_verified_at")),
            "avatar": profile["avatar"],
        }

    @app.put("/api/portal/profile")
    def portal_update_profile(
        body: PortalProfileBody, account: dict = Depends(current_portal)
    ):
        name = (body.display_name or "").strip()
        if not 1 <= len(name) <= 32:
            raise HTTPException(status_code=400, detail="显示名称长度需为 1-32 个字符")
        db.set_portal_display_name(account["id"], name)
        db.add_log("更新门户资料", account["email"], "", f"显示名 {name}", "")
        return {"ok": True}

    @app.post("/api/portal/avatar")
    def portal_upload_avatar(
        body: PortalAvatarBody, account: dict = Depends(current_portal)
    ):
        mime = (body.mime or "").strip().lower()
        if mime not in PORTAL_AVATAR_MIMES:
            raise HTTPException(status_code=400, detail="头像格式仅支持 PNG/JPEG/WebP")
        try:
            raw = base64.b64decode((body.data_base64 or "").strip(), validate=True)
        except (binascii.Error, ValueError):
            raise HTTPException(status_code=400, detail="头像数据不是有效的 base64")
        if not raw:
            raise HTTPException(status_code=400, detail="头像数据为空")
        if len(raw) > PORTAL_AVATAR_MAX_BYTES:
            raise HTTPException(status_code=400, detail="头像文件不能超过 256KB")
        problem = image_guard.avatar_problem(mime, raw)
        if problem:
            raise HTTPException(status_code=400, detail=problem)
        db.set_portal_avatar(account["id"], mime, raw)
        db.add_log("更新门户头像", account["email"], "", f"{mime} {len(raw)} 字节", "")
        return {"ok": True}

    @app.delete("/api/portal/avatar")
    def portal_delete_avatar(account: dict = Depends(current_portal)):
        db.clear_portal_avatar(account["id"])
        db.add_log("移除门户头像", account["email"], "", "", "")
        return {"ok": True}

    @app.post("/api/portal/bind")
    def portal_bind(
        body: PortalBindBody,
        request: Request,
        account: dict = Depends(current_portal),
    ):
        ip = _client_ip(request)
        key_code = security.normalize_key(body.key_code)
        machine_code = (body.machine_code or "").strip().upper()
        if not key_code or not machine_code:
            raise HTTPException(status_code=400, detail="密钥和机器码不能为空")
        if db.get_portal_binding(account["id"]):
            raise HTTPException(status_code=409, detail="当前邮箱已绑定密钥，请先脱绑")
        lic = db.get_license(key_code)
        if not lic:
            db.add_log("门户绑定失败", account["email"], key_code, "密钥不存在", ip)
            return {
                "ok": False,
                "code": "invalid_license",
                "message": "密钥不存在，请核对后重试",
            }
        occupied = db.get_binding_by_license(lic["id"])
        if occupied and int(occupied.get("account_id") or 0) != int(account["id"]):
            raise HTTPException(status_code=409, detail="该密钥已被其它邮箱绑定")
        # Binding a device still goes through the executable whitelist gate.
        _require_attestation(request, machine_code, "")
        session_secret = security.generate_session_secret()
        result = do_activate(
            db, key_code, machine_code, body.device_name, ip, session_secret
        )
        if not result.get("ok"):
            db.add_log(
                "门户绑定失败", account["email"], key_code, str(result.get("code")), ip
            )
            return {
                "ok": False,
                "code": "invalid_license",
                "message": result.get("message") or "该密钥当前不可用",
            }
        if not db.bind_portal_license(account["id"], lic["id"], key_code):
            # Lost a race against another account: undo the device seat this
            # request just consumed so the winner keeps a clean state.
            db.unbind_activation(key_code, machine_code)
            raise HTTPException(status_code=409, detail="该密钥已被其它邮箱绑定")
        db.add_binding_history(
            account["id"], lic["id"], key_code, "bind", "", "user"
        )
        db.add_log(
            "门户绑定", account["email"], key_code,
            f"设备 {body.device_name or machine_code}", ip,
        )
        return {
            "ok": True,
            "binding": _portal_binding_view(account["id"]),
            "activation": result,
        }

    @app.post("/api/portal/unbind")
    def portal_unbind(
        request: Request, account: dict = Depends(current_portal)
    ):
        ip = _client_ip(request)
        binding = db.get_portal_binding(account["id"])
        if not binding:
            raise HTTPException(status_code=400, detail="当前没有绑定密钥")
        key_code = str(binding["key_code"])
        lic = db.get_license(key_code)
        still_valid = bool(lic) and not is_exhausted_card(lic) and (
            lic["status"] not in ("expired", "revoked")
            and not security.is_expired(lic.get("expires_at"))
        )
        if still_valid:
            db.add_log("门户脱绑被拒", account["email"], key_code, "授权仍有效", ip)
            raise HTTPException(
                status_code=409,
                detail="授权仍有效，不能自助脱绑，请联系管理员",
            )
        if not lic:
            reason = "授权记录已不存在，用户自助脱绑"
        elif is_exhausted_card(lic):
            reason = "授权次数已用尽，用户自助脱绑"
        elif lic["status"] == "revoked":
            reason = "授权已被吊销，用户自助脱绑"
        else:
            reason = "授权已过期，用户自助脱绑"
        released = db.release_license_activations(
            binding["license_id"], "portal_unbind"
        )
        db.unbind_portal_license(account["id"], reason, "user")
        db.add_binding_history(
            account["id"], binding["license_id"], key_code, "unbind", reason, "user"
        )
        db.add_log(
            "门户脱绑", account["email"], key_code,
            f"释放设备 {released} 台", ip,
        )
        return {"ok": True}

    @app.post("/api/portal/renew_request")
    def portal_renew_request(
        body: PortalRenewBody,
        request: Request,
        account: dict = Depends(current_portal),
    ):
        ip = _client_ip(request)
        binding = db.get_portal_binding(account["id"])
        if not binding:
            raise HTTPException(status_code=400, detail="请先绑定密钥")
        request_id = db.create_renewal_request(
            account["id"], binding["license_id"], binding["key_code"], body.note
        )
        db.add_log(
            "门户续费请求", account["email"], binding["key_code"], body.note[:64], ip
        )
        try:
            license = db.get_license(binding["key_code"])
            if license:
                alerting.notify_renewal_request(
                    db,
                    mailer,
                    license=license,
                    account_email=account["email"],
                    note=body.note,
                    smtp_config=smtp_config,
                )
        except Exception:
            pass
        return {"ok": True, "request_id": request_id}

    @app.post("/api/portal/password/reset")
    def portal_password_reset(
        body: PortalPasswordResetBody, request: Request
    ):
        ip = _client_ip(request)
        email = body.email
        ok, msg = security.password_strength(body.new_password)
        if not ok:
            raise HTTPException(status_code=400, detail=msg)
        account = db.get_portal_account(email)
        consumed = False
        if account:
            consumed = db.consume_action_code(
                "portal", email, "reset_password",
                security.hash_action_code(secret, body.code),
            )
        if not account or not consumed:
            db.add_log("门户重置密码失败", email, "", "验证码无效", ip)
            raise HTTPException(status_code=400, detail="验证码错误或已过期")
        password_hash, salt = security.hash_password(body.new_password)
        # set_portal_password bumps auth_version, invalidating every portal
        # token issued before the reset.
        db.set_portal_password(account["id"], password_hash, salt)
        db.add_log("门户重置密码", email, "", "旧登录状态已失效", ip)
        return {"ok": True}

    @app.get("/api/logs")
    def logs(
        keyword: str = Query(default="", max_length=128),
        action: str = Query(default="", max_length=64),
        start_at: str = Query(default="", max_length=32),
        end_at: str = Query(default="", max_length=32),
        limit: int = Query(default=200, ge=1, le=1000),
        offset: int = Query(default=0, ge=0, le=1_000_000),
        admin: dict = Depends(current_admin),
    ):
        filters = (keyword, action, start_at, end_at)
        return {
            "items": db.list_logs(limit, offset, *filters),
            "total": db.count_logs(*filters),
        }

    @app.get("/api/ai/config")
    def ai_config(admin: dict = Depends(current_admin)):
        return ai_gateway.public_config()

    @app.get("/api/ai/status")
    def ai_status(admin: dict = Depends(current_admin)):
        return ai_gateway.snapshot()

    @app.post("/api/ai/chat")
    def ai_chat(body: AiChatBody, request: Request, admin: dict = Depends(current_admin)):
        messages = [{"role": item.role, "content": item.content} for item in body.messages]
        return ai_gateway.submit_chat(admin, messages, _client_ip(request))

    @app.get("/api/ai/chat/{job_id}")
    def ai_chat_status(
        job_id: str,
        after: int = 0,
        admin: dict = Depends(current_admin),
    ):
        return ai_gateway.chat_job(admin, job_id, after)

    @app.post("/api/ai/confirm")
    def ai_confirm(
        body: AiConfirmBody, request: Request, admin: dict = Depends(current_admin)
    ):
        """Execute a staged write action after the operator confirms it."""
        try:
            return ai_gateway.confirm(body.confirm_token, admin, _client_ip(request))
        except AiConfirmationError as exc:
            raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc

    @app.post("/api/ai/cancel")
    def ai_cancel(
        body: AiConfirmBody, request: Request, admin: dict = Depends(current_admin)
    ):
        """Cancel a staged write action; it can never run afterwards."""
        try:
            return ai_gateway.cancel(body.confirm_token, admin, _client_ip(request))
        except AiConfirmationError as exc:
            raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc

    @app.post("/api/client/activate")
    def activate(body: ActivateBody, request: Request):
        ip = _client_ip(request)
        _require_attestation(request, body.machine_code, "")
        if not _rate_allowed(
            f"activate|{ip}", activation_max_attempts, activation_lock_seconds
        ):
            raise HTTPException(status_code=429, detail="激活尝试过于频繁，请稍后再试")
        session_secret = security.generate_session_secret()
        result = do_activate(
            db,
            body.key_code,
            body.machine_code,
            body.device_name,
            ip,
            session_secret,
        )
        if result.get("code") == "limit":
            # A new machine on a full licence: a change seen from a network the
            # key has used before is a likely legitimate device move and only
            # alerted; a change from another network freezes the key (clone
            # suspicion) and notifies the owner plus administrators.
            try:
                outcome = risk.handle_machine_mismatch(
                    db,
                    body.key_code,
                    body.machine_code,
                    ip,
                    same_subnet_grace=bool(
                        config.security.get("machine_mismatch_same_subnet_grace", True)
                    ),
                )
                if outcome and outcome.get("license"):
                    alerting.notify_machine_mismatch(
                        db,
                        mailer,
                        license=outcome["license"],
                        machine_code=body.machine_code,
                        ip=ip,
                        reason=outcome.get("reason") or "",
                        smtp_config=smtp_config,
                        event_kind="frozen" if outcome.get("frozen") else "subnet_warn",
                    )
            except Exception:
                pass
        elif result.get("ok"):
            _after_client_ip(body.key_code, body.machine_code, ip)
        return result

    @app.post("/api/client/verify")
    async def verify(request: Request):
        raw = await request.body()
        ip = _client_ip(request)
        payload = _read_payload(raw)
        key_code = security.normalize_key(_payload_text(payload, "key_code"))
        machine_code = _payload_text(payload, "machine_code").upper()
        if not key_code or not machine_code:
            if _client_failure_limited("verify", ip):
                return _client_rate_limited()
            return {
                "ok": False,
                "code": "bad_request",
                "message": "密钥和机器码不能为空",
            }

        # Gate on the executable whitelist before the activation lookup, so an
        # unregistered client cannot use this endpoint to probe which keys exist.
        _require_attestation(request, machine_code, "")
        act = db.get_activation(key_code, machine_code)
        if not act or not act.get("session_secret"):
            if _client_failure_limited("verify", ip):
                return _client_rate_limited()
            return {
                "ok": False,
                "code": "unauthenticated",
                "message": "本设备尚未激活或会话已失效，请重新激活",
            }
        secret_sess = act["session_secret"]
        ok, msg = _check_signed_request(request, raw, secret_sess, sign_window)
        if not ok:
            if _client_failure_limited("verify", ip):
                return _client_rate_limited()
            db.add_log("签名校验失败", "client", key_code, msg, ip)
            return {"ok": False, "code": "signature_invalid", "message": msg}

        ts = int(request.headers.get("X-Client-Timestamp", "0"))
        nonce = request.headers.get("X-Client-Nonce", "")
        db.prune_nonces(ts - sign_window - 60)
        if db.seen_nonce(nonce, key_code):
            db.add_log("重放拦截", "client", key_code, "nonce 重复", _client_ip(request))
            return {"ok": False, "code": "replay", "message": "重复请求已被拦截"}

        result = do_verify(db, key_code, machine_code, _client_ip(request))
        if result.get("ok"):
            _after_client_ip(key_code, machine_code, ip)
        result["server_ts"] = security.now_ts()
        return result

    @app.post("/api/client/heartbeat")
    async def heartbeat(request: Request):
        raw = await request.body()
        ip = _client_ip(request)
        payload = _read_payload(raw)
        key_code = security.normalize_key(_payload_text(payload, "key_code"))
        machine_code = _payload_text(payload, "machine_code").upper()
        if not key_code or not machine_code:
            if _client_failure_limited("heartbeat", ip):
                return _client_rate_limited()
            return {
                "ok": False,
                "code": "bad_request",
                "message": "密钥和机器码不能为空",
            }

        _require_attestation(request, machine_code, "")
        act = db.get_activation(key_code, machine_code)
        if not act or not act.get("session_secret"):
            if _client_failure_limited("heartbeat", ip):
                return _client_rate_limited()
            return {"ok": False, "code": "unauthenticated", "message": "尚未激活"}
        secret_sess = act["session_secret"]
        ok, msg = _check_signed_request(request, raw, secret_sess, sign_window)
        if not ok:
            if _client_failure_limited("heartbeat", ip):
                return _client_rate_limited()
            return {"ok": False, "code": "signature_invalid", "message": msg}

        ts = int(request.headers.get("X-Client-Timestamp", "0"))
        nonce = request.headers.get("X-Client-Nonce", "")
        db.prune_nonces(ts - sign_window - 60)
        if db.seen_nonce(nonce, key_code):
            return {"ok": False, "code": "replay", "message": "重复请求已被拦截"}

        interval = security.heartbeat_jitter(heartbeat_base, heartbeat_spread)
        server_ts = security.now_ts()
        if act["status"] != "active":
            return {
                "ok": False,
                "code": "not_active",
                "message": "授权未处于激活状态",
                "next_interval": interval,
                "server_ts": server_ts,
            }
        db.release_expired_freeze(key_code)
        db.sweep_expired()
        lic = db.get_license(key_code)
        expiry = act["expires_at"] or (lic["expires_at"] if lic else None)
        if is_exhausted_card(lic):
            return {
                "ok": False,
                "code": "exhausted",
                "message": "该密钥激活次数已用尽，授权已被吊销",
                "next_interval": interval,
                "server_ts": server_ts,
            }
        if lic and lic["status"] == "frozen":
            if security.is_long_freeze(lic.get("frozen_until")):
                message = "授权已被长期锁定（需管理员解冻/换绑）"
            else:
                remaining = security.humanize_remaining(lic.get("frozen_until"))
                message = f"授权已被冻结，剩余 {remaining}"
            reason = lic.get("freeze_reason") or ""
            if reason:
                message += f"（原因：{reason}）"
            return {
                "ok": False,
                "code": "frozen",
                "message": message,
                "frozen_until": lic.get("frozen_until"),
                "next_interval": interval,
                "server_ts": server_ts,
            }
        if lic and lic["status"] == "revoked":
            return {
                "ok": False,
                "code": "revoked",
                "message": "该密钥已被吊销",
                "next_interval": interval,
                "server_ts": server_ts,
            }
        if security.is_expired(expiry):
            return {
                "ok": False,
                "code": "expired",
                "message": "授权已失效",
                "next_interval": interval,
                "server_ts": server_ts,
            }
        db.touch_heartbeat(act["id"])
        _after_client_ip(key_code, machine_code, ip)
        payload = {
            "ok": True,
            "code": "alive",
            "message": "在线",
            "expires_at": expiry,
            "days_left": security.days_left(expiry),
            "remaining": security.humanize_remaining(expiry),
            "next_interval": interval,
            "server_ts": server_ts,
            "heartbeat_count": int(act.get("heartbeat_count") or 0) + 1,
        }
        payload.update(_activation_fields(lic))
        if lic is not None:
            payload["features"] = security.features_from_text(lic.get("features"))
        return payload


    # ------------------------------------------------------------------
    # Attestation and integrity reporting (no Bearer token)
    # ------------------------------------------------------------------
    @app.post("/api/client/attest")
    def attest(body: AttestBody, request: Request):
        ip = _client_ip(request)
        if not _rate_allowed(f"attest|{ip}", 60, 60):
            return _client_rate_limited()
        exe_hash = str(body.exe_hash or "").strip().lower()
        # 问题三：一旦有 active 的 release_meta，客户端必须声明匹配的
        # 发布标识（以及非空清单哈希）才可能拿到 attest_token。
        if db.count_active_release_meta():
            release_id = str(body.release_id or "").strip().lower()
            manifest_sha = str(body.manifest_sha256 or "").strip().lower()
            record = (
                db.match_active_release_meta(release_id) if release_id else None
            )
            require_manifest_hash = bool(
                config.security.get("require_manifest_hash", False)
            )
            mismatch = (
                record is None
                or (require_manifest_hash and not manifest_sha)
                or (
                    manifest_sha
                    and manifest_sha != str(record.get("manifest_sha256") or "")
                )
            )
            if mismatch:
                detail = (
                    f"release_id={release_id[:64] or '(空)'}"
                    f" manifest_sha256={manifest_sha[:64] or '(空)'}"
                )
                db.add_tamper_event(
                    role=body.role,
                    exe_name=body.exe_name,
                    exe_hash=exe_hash,
                    version=body.version,
                    machine_code=body.machine_code,
                    ip=ip,
                    reason="release_mismatch",
                    detail=detail,
                )
                db.add_log(
                    "完整性校验失败",
                    _audit_text(body.role) or "client",
                    _audit_text(body.exe_name),
                    "发布标识与服务器记录不一致",
                    ip,
                )
                try:
                    alerting.notify_tamper(
                        db,
                        mailer,
                        role=body.role,
                        exe_name=body.exe_name,
                        exe_hash=exe_hash,
                        machine_code=body.machine_code,
                        ip=ip,
                        reason="release_mismatch",
                        detail=detail,
                        smtp_config=smtp_config,
                        license_id=_resolve_license_id(body.machine_code),
                    )
                except Exception:
                    pass
                return {"ok": False, "code": "release_mismatch"}
        # Only a hash that is currently whitelisted may leave with a token, but
        # the check is unconditional: attest_mode=off merely stops enforcing the
        # gate on activate/verify/heartbeat, it does not hand out free tokens.
        if not db.match_release_hash(exe_hash):
            db.add_tamper_event(
                role=body.role,
                exe_name=body.exe_name,
                exe_hash=exe_hash,
                version=body.version,
                machine_code=body.machine_code,
                ip=ip,
                reason="unknown_build",
                detail="提交的可执行文件哈希不在服务器发布白名单中",
            )
            db.add_log(
                "完整性校验失败",
                _audit_text(body.role) or "client",
                _audit_text(body.exe_name),
                f"未知版本哈希 {exe_hash[:16]}",
                ip,
            )
            try:
                alerting.notify_tamper(
                    db,
                    mailer,
                    role=body.role,
                    exe_name=body.exe_name,
                    exe_hash=exe_hash,
                    machine_code=body.machine_code,
                    ip=ip,
                    reason="unknown_build",
                    detail="提交的可执行文件哈希不在服务器发布白名单中",
                    smtp_config=smtp_config,
                    license_id=_resolve_license_id(body.machine_code),
                )
            except Exception:
                pass
            return {
                "ok": False,
                "code": "unknown_build",
                "message": "该程序未在服务器发布白名单中，已记录完整性告警",
            }
        ttl_value = _attestation_ttl()
        token = security.create_attest_token(
            secret, exe_hash, body.machine_code, body.role, ttl_value
        )
        return {"ok": True, "attest_token": token, "expires_in": ttl_value}

    @app.post("/api/client/integrity_report")
    def integrity_report(body: IntegrityReportBody, request: Request):
        ip = _client_ip(request)
        if not _rate_allowed(f"integrity-report|{ip}", 30, 60):
            return _client_rate_limited()
        db.add_tamper_event(
            role=body.role,
            exe_name=body.exe_name,
            exe_hash=body.exe_hash,
            version=body.version,
            machine_code=body.machine_code,
            ip=ip,
            reason=body.reason,
            detail=body.detail,
        )
        db.add_log(
            "完整性告警",
            _audit_text(body.role) or "client",
            _audit_text(body.exe_name),
            _audit_text(body.reason, 128),
            ip,
        )
        try:
            alerting.notify_tamper(
                db,
                mailer,
                role=body.role,
                exe_name=body.exe_name,
                exe_hash=body.exe_hash,
                machine_code=body.machine_code,
                ip=ip,
                reason=body.reason,
                detail=str(body.detail or "")[:500],
                smtp_config=smtp_config,
                license_id=_resolve_license_id(body.machine_code),
            )
        except Exception:
            pass
        return {"ok": True}

    # ------------------------------------------------------------------
    # Release whitelist and tamper log (Bearer token)
    # ------------------------------------------------------------------
    @app.get("/api/release/list")
    def release_list(admin: dict = Depends(current_admin)):
        items = db.list_release_hashes(500)
        return {"items": items, "total": len(items)}

    @app.post("/api/release/import")
    def release_import(body: ReleaseImportBody, admin: dict = Depends(require_master)):
        try:
            manifest = json.loads(body.manifest)
        except Exception:
            raise HTTPException(status_code=400, detail="发布清单不是有效的 JSON")
        if not isinstance(manifest, dict) or manifest.get("format") != "sq-release-manifest-v1":
            raise HTTPException(status_code=400, detail="发布清单格式不受支持")
        # core.integrity belongs to another batch; the lazy import keeps this
        # module importable before that file lands.
        from core import integrity

        public_key = config.security.get("release_public_key", "")
        if not public_key:
            public_key = integrity.load_release_public_key()
        manifest_bytes = json.dumps(
            manifest, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        signature = body.signature.strip()
        verified = integrity.verify_manifest_signature(
            manifest_bytes, signature, public_key
        )
        if not verified:
            # Clients may reserialise the manifest before sending it, so retry
            # against the exact bytes the caller supplied.
            verified = integrity.verify_manifest_signature(
                body.manifest.encode("utf-8"), signature, public_key
            )
        if not verified:
            db.add_log("导入发布清单失败", admin["username"], "", "签名校验未通过", "")
            raise HTTPException(status_code=400, detail="发布清单签名校验未通过")
        apps = manifest.get("apps")
        if not isinstance(apps, dict):
            raise HTTPException(status_code=400, detail="发布清单缺少 apps")
        # 复用启动导入的同一段逻辑：写 release_hashes + release_meta（问题三）。
        imported = import_release_manifest(
            db,
            manifest,
            body.manifest.encode("utf-8"),
            note="manifest import",
            retire_old=bool(config.security.get("release_auto_retire_old", True)),
        )
        db.add_log(
            "导入发布清单",
            admin["username"],
            str(manifest.get("version", "") or ""),
            f"导入 {imported} 个应用哈希",
            "",
        )
        return {"ok": True, "imported": imported}

    @app.post("/api/release/status")
    def release_status(
        body: ReleaseStatusBody, admin: dict = Depends(require_master)
    ):
        changed = db.set_release_hash_active(body.file_name, body.sha256, body.active)
        if not changed:
            raise HTTPException(status_code=404, detail="发布哈希不存在")
        db.add_log(
            "更新发布状态",
            admin["username"],
            body.file_name,
            "启用" if body.active else "停用",
            "",
        )
        return {"ok": True}

    @app.get("/api/tamper/events")
    def tamper_events(
        limit: int = Query(default=200, ge=1, le=1000),
        offset: int = Query(default=0, ge=0, le=1_000_000),
        admin: dict = Depends(current_admin),
    ):
        items, total = db.list_tamper_events(limit, offset)
        return {"items": items, "total": total}

    # ------------------------------------------------------------------
    # SMTP status and delivery records (P1)
    # ------------------------------------------------------------------
    @app.get("/api/smtp/status")
    def smtp_status(admin: dict = Depends(current_admin)):
        getter = getattr(mailer, "status", None)
        if callable(getter):
            return getter()
        return {
            "enabled": False,
            "host": "",
            "port": 0,
            "from_email": "",
            "pending": 0,
            "sending": 0,
            "sent": 0,
            "failed": 0,
            "dead": 0,
            "last_error": None,
        }

    @app.post("/api/smtp/test")
    def smtp_test(
        body: SmtpTestBody,
        request: Request,
        admin: dict = Depends(require_master),
    ):
        try:
            mailer.send_now(body.to_email, "test_email", {"email": body.to_email})
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except Exception as exc:
            db.add_log(
                "发送测试邮件失败", admin["username"], body.to_email, str(exc)[:200],
                _client_ip(request),
            )
            raise HTTPException(status_code=400, detail=f"发送失败：{exc}")
        db.add_log(
            "发送测试邮件", admin["username"], body.to_email, "", _client_ip(request)
        )
        return {"ok": True}

    @app.get("/api/email/outbox")
    def email_outbox(
        status: str = Query(default="", max_length=32),
        limit: int = Query(default=200, ge=1, le=1000),
        offset: int = Query(default=0, ge=0, le=1_000_000),
        admin: dict = Depends(current_admin),
    ):
        items, total = db.list_email_outbox(status, limit, offset)
        return {"items": items, "total": total}

    # ------------------------------------------------------------------
    # A7: notification channels (contract sections 4 and 5)
    # ------------------------------------------------------------------
    def _send_test_message(channel: dict) -> None:
        """Send one test message synchronously through the dispatcher.

        The dispatcher transport is preferred so an injected dispatcher
        (including a test double) really handles the probe; when it has no
        transport the module-level sender is resolved on every call so
        ``server.channels.send_channel_message`` stays monkeypatchable.
        """
        transport = getattr(channel_dispatcher, "transport", None)
        if not callable(transport):
            transport = getattr(channels_module, "send_channel_message", None)
        if not callable(transport):
            raise RuntimeError("通知渠道模块尚未就绪")
        transport(
            str(channel.get("kind") or ""),
            str(channel.get("url") or ""),
            secret=str(channel.get("secret") or ""),
            subject=f"通知渠道测试：{channel.get('name') or ''}",
            body="这是一条来自密钥授权系统的测试消息，收到即表示渠道可用。",
            payload={"test": True},
            timeout=10.0,
        )

    @app.get("/api/channels")
    def list_channels(admin: dict = Depends(current_admin)):
        return {"items": db.list_notification_channels()}

    @app.post("/api/channels")
    def create_channel(
        body: ChannelBody,
        request: Request,
        admin: dict = Depends(require_master),
    ):
        fields = {
            "kind": _channel_kind(body.kind, channel_kinds),
            "name": _channel_name(body.name),
            "url": _channel_url(
                body.url,
                allow_private=bool(
                    config.security.get("channel_allow_private_hosts", False)
                ),
            ),
            "secret": _channel_secret(body.secret),
            "enabled": bool(body.enabled),
        }
        try:
            channel_id = db.create_notification_channel(**fields)
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail="渠道名称已存在")
        db.add_log(
            "新建通知渠道", admin["username"], str(channel_id), fields["name"],
            _client_ip(request),
        )
        return {"ok": True, "id": channel_id}

    @app.put("/api/channels/{channel_id}")
    def update_channel(
        channel_id: int,
        body: ChannelUpdateBody,
        request: Request,
        admin: dict = Depends(require_master),
    ):
        if not db.get_notification_channel(channel_id):
            raise HTTPException(status_code=404, detail="渠道不存在")
        fields: dict = {}
        for key, value in body.model_dump(exclude_unset=True).items():
            if key == "secret":
                if value is None or value == "":
                    continue  # 留空表示保留原密钥
                fields["secret"] = _channel_secret(value)
                continue
            if value is None:
                continue
            if key == "kind":
                fields["kind"] = _channel_kind(value, channel_kinds)
            elif key == "name":
                fields["name"] = _channel_name(value)
            elif key == "url":
                fields["url"] = _channel_url(
                    value,
                    allow_private=bool(
                        config.security.get("channel_allow_private_hosts", False)
                    ),
                )
            elif key == "enabled":
                fields["enabled"] = bool(value)
        try:
            updated = db.update_notification_channel(channel_id, **fields)
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail="渠道名称已存在")
        if not updated:
            raise HTTPException(status_code=404, detail="渠道不存在")
        db.add_log(
            "更新通知渠道", admin["username"], str(channel_id),
            ",".join(sorted(fields)), _client_ip(request),
        )
        return {"ok": True}

    @app.delete("/api/channels/{channel_id}")
    def delete_channel(
        channel_id: int,
        request: Request,
        admin: dict = Depends(require_master),
    ):
        if not db.delete_notification_channel(channel_id):
            raise HTTPException(status_code=404, detail="渠道不存在")
        db.add_log(
            "删除通知渠道", admin["username"], str(channel_id), "",
            _client_ip(request),
        )
        return {"ok": True}

    @app.post("/api/channels/{channel_id}/test")
    def test_channel(
        channel_id: int,
        request: Request,
        admin: dict = Depends(require_master),
    ):
        channel = db.get_notification_channel(channel_id)
        if not channel:
            raise HTTPException(status_code=404, detail="渠道不存在")
        try:
            _send_test_message(channel)
        except Exception as exc:
            db.add_log(
                "测试通知渠道失败", admin["username"], str(channel_id),
                str(exc)[:200], _client_ip(request),
            )
            raise HTTPException(status_code=400, detail=f"发送失败：{exc}")
        db.add_log(
            "测试通知渠道", admin["username"], str(channel_id), "",
            _client_ip(request),
        )
        return {"ok": True}

    @app.get("/api/channels/deliveries")
    def channel_deliveries(
        status: str = Query(default="", max_length=32),
        limit: int = Query(default=200, ge=1, le=1000),
        offset: int = Query(default=0, ge=0, le=1_000_000),
        admin: dict = Depends(current_admin),
    ):
        items, total = db.list_channel_deliveries(status, limit, offset)
        return {"items": items, "total": total}

    # ------------------------------------------------------------------
    # A5: alert rules, events and metric overview (contract section 4)
    # ------------------------------------------------------------------
    @app.get("/api/alerts/rules")
    def alert_rules(admin: dict = Depends(current_admin)):
        return {"items": db.list_alert_rules()}

    @app.post("/api/alerts/rules")
    def create_alert_rule(
        body: AlertRuleBody,
        request: Request,
        admin: dict = Depends(current_admin),
    ):
        fields = _clean_alert_rule_fields(body.model_dump())
        if not fields["name"]:
            raise HTTPException(status_code=400, detail="规则名称不能为空")
        _validate_alert_rule_fields(fields, db)
        rule_id = db.create_alert_rule(**fields)
        db.add_log(
            "新建告警规则", admin["username"], str(rule_id), fields["name"],
            _client_ip(request),
        )
        return {"ok": True, "id": rule_id}

    @app.put("/api/alerts/rules/{rule_id}")
    def update_alert_rule(
        rule_id: int,
        body: AlertRuleUpdateBody,
        request: Request,
        admin: dict = Depends(current_admin),
    ):
        if not db.get_alert_rule(rule_id):
            raise HTTPException(status_code=404, detail="告警规则不存在")
        fields = {
            key: value
            for key, value in body.model_dump(exclude_unset=True).items()
            if value is not None
        }
        fields = _clean_alert_rule_fields(fields)
        if "name" in fields and not fields["name"]:
            raise HTTPException(status_code=400, detail="规则名称不能为空")
        _validate_alert_rule_fields(fields, db)
        if fields and not db.update_alert_rule(rule_id, **fields):
            raise HTTPException(status_code=404, detail="告警规则不存在")
        db.add_log(
            "更新告警规则", admin["username"], str(rule_id),
            ",".join(sorted(fields)), _client_ip(request),
        )
        return {"ok": True}

    @app.delete("/api/alerts/rules/{rule_id}")
    def delete_alert_rule(
        rule_id: int,
        request: Request,
        admin: dict = Depends(require_master),
    ):
        if not db.delete_alert_rule(rule_id):
            raise HTTPException(status_code=404, detail="告警规则不存在")
        db.add_log(
            "删除告警规则", admin["username"], str(rule_id), "", _client_ip(request)
        )
        return {"ok": True}

    @app.get("/api/alerts/events")
    def alert_events(
        status: str = Query(default="", max_length=32),
        limit: int = Query(default=200, ge=1, le=1000),
        offset: int = Query(default=0, ge=0, le=1_000_000),
        admin: dict = Depends(current_admin),
    ):
        items, total = db.list_alert_events(status, limit, offset)
        return {"items": items, "total": total}

    @app.post("/api/alerts/events/{event_id}/ack")
    def ack_alert_event(
        event_id: int,
        request: Request,
        admin: dict = Depends(current_admin),
    ):
        if not db.ack_alert_event(event_id):
            raise HTTPException(status_code=404, detail="告警事件不存在")
        db.add_log(
            "确认告警事件", admin["username"], str(event_id), "", _client_ip(request)
        )
        return {"ok": True}

    @app.post("/api/alerts/events/{event_id}/resolve")
    def resolve_alert_event(
        event_id: int,
        request: Request,
        admin: dict = Depends(current_admin),
    ):
        if not db.resolve_alert_event(event_id):
            raise HTTPException(status_code=404, detail="告警事件不存在")
        db.add_log(
            "处理告警事件", admin["username"], str(event_id), "", _client_ip(request)
        )
        return {"ok": True}

    @app.get("/api/metrics/overview")
    def metrics_overview(
        window_seconds: int = Query(default=600, ge=60, le=86400),
        admin: dict = Depends(current_admin),
    ):
        return db.alert_metrics(window_seconds)

    # ------------------------------------------------------------------
    # Data retention / maintenance (P2-13)
    # ------------------------------------------------------------------
    @app.post("/api/maintenance/run")
    def run_maintenance_endpoint(
        request: Request,
        admin: dict = Depends(require_master),
    ):
        runner = getattr(maintenance, "run_once", None)
        if not callable(runner):
            raise HTTPException(status_code=503, detail="维护任务不可用")
        try:
            deleted = runner()
        except Exception as exc:
            raise HTTPException(
                status_code=500, detail=f"维护任务执行失败：{exc}"
            )
        deleted = dict(deleted or {})
        db.add_log(
            "手动维护",
            admin["username"],
            "",
            f"清理 {sum(int(value or 0) for value in deleted.values())} 条",
            _client_ip(request),
        )
        reporter = getattr(maintenance, "status", None)
        status = reporter() if callable(reporter) else {}
        return {
            "ok": True,
            "deleted": deleted,
            "last_run_at": status.get("last_run_at"),
        }

    @app.get("/api/maintenance/status")
    def maintenance_status(admin: dict = Depends(current_admin)):
        reporter = getattr(maintenance, "status", None)
        if not callable(reporter):
            return {
                "last_run_at": None,
                "deleted": {},
                "interval_seconds": None,
                "last_error": None,
            }
        return reporter()

    return app
