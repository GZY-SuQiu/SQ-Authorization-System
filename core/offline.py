import base64
import hashlib
import hmac
import json
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .security import (
    TIME_FORMAT,
    _b64d,
    _b64e,
    is_expired,
    now_str,
    now_ts,
    parse_expiry,
)

_REQUEST_PREFIX = "LICREQ1."
_ACTIVATION_PREFIX = "LICACT1."
_CODE_CHUNK = 64


def _seed_bytes(private_hex: str) -> bytes:
    try:
        seed = bytes.fromhex((private_hex or "").strip())
    except ValueError as exc:
        raise ValueError("私钥格式错误") from exc
    if len(seed) != 32:
        raise ValueError("Ed25519 私钥长度必须为 32 字节")
    return seed


def _public_key_bytes(public_hex: str) -> bytes:
    try:
        public_key = bytes.fromhex((public_hex or "").strip())
    except ValueError as exc:
        raise ValueError("公钥格式错误") from exc
    if len(public_key) != 32:
        raise ValueError("Ed25519 公钥长度必须为 32 字节")
    return public_key


def generate_keypair() -> tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()
    seed = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return seed.hex(), public_key.hex()


def sign_raw(message: bytes, seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 私钥长度必须为 32 字节")
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    return private_key.sign(message)


def verify_raw(signature, message: bytes, public_key: bytes) -> bool:
    """Verify an Ed25519 signature given as raw bytes or base64 text."""
    if isinstance(signature, str):
        try:
            signature = base64.b64decode(signature)
        except Exception:
            return False
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        return False
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(bytes(public_key)).verify(
            bytes(signature), message
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def public_from_private(private_hex: str) -> str:
    private_key = Ed25519PrivateKey.from_private_bytes(_seed_bytes(private_hex))
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def sign_message(private_hex: str, message: bytes) -> str:
    """Sign a byte message and return a URL-safe base64 signature."""
    return _b64e(sign_raw(message, _seed_bytes(private_hex)))


def verify_message(public_hex: str, message: bytes, signature: str) -> bool:
    try:
        signature_bytes = _b64d(signature)
    except Exception:
        return False
    try:
        return verify_raw(signature_bytes, message, _public_key_bytes(public_hex))
    except ValueError:
        return False


def public_key_fingerprint(public_hex: str) -> str:
    try:
        raw = _public_key_bytes(public_hex)
    except ValueError:
        return ""
    return hashlib.sha256(raw).hexdigest()[:32]


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode("utf-8")


def chunk_code(code: str, size: int = _CODE_CHUNK) -> str:
    text = (code or "").strip()
    if not text:
        return ""
    return "\n".join(text[i:i + size] for i in range(0, len(text), size))


def clean_code(code: str) -> str:
    return "".join((code or "").split())


def _text(value, max_length: int) -> str:
    if not isinstance(value, str):
        return ""
    value = value.strip()
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return ""
    return value if 0 < len(value) <= max_length else ""


def make_request_code(machine_code: str, device_name: str = "") -> str:
    payload = {
        "v": 1,
        "mc": (machine_code or "").strip().upper(),
        "dn": (device_name or "").strip(),
        "ts": now_ts(),
    }
    return _REQUEST_PREFIX + _b64e(_canonical(payload))


def parse_request_code(code: str) -> dict | None:
    text = clean_code(code)
    if not text.startswith(_REQUEST_PREFIX):
        return None
    try:
        payload = json.loads(_b64d(text[len(_REQUEST_PREFIX):]))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    machine = _text(payload.get("mc"), 128)
    if not machine:
        return None
    device = _text(payload.get("dn"), 128)
    return {
        "v": 1,
        "mc": machine.upper(),
        "dn": device,
        "ts": payload.get("ts") if isinstance(payload.get("ts"), int) else 0,
    }


def make_activation_code(payload: dict, private_hex: str) -> str:
    body = dict(payload)
    body["v"] = 1
    body["ts"] = now_ts()
    raw = _canonical(body)
    signature = sign_raw(raw, _seed_bytes(private_hex))
    return _ACTIVATION_PREFIX + _b64e(raw) + "." + _b64e(signature)


def parse_activation_code(code: str, public_hex: str) -> dict | None:
    text = clean_code(code)
    if not text.startswith(_ACTIVATION_PREFIX):
        return None
    body = text[len(_ACTIVATION_PREFIX):]
    try:
        raw_b64, sig_b64 = body.split(".", 1)
        raw = _b64d(raw_b64)
        signature = _b64d(sig_b64)
    except Exception:
        return None
    try:
        public_key = _public_key_bytes(public_hex)
    except ValueError:
        return None
    if not verify_raw(signature, raw, public_key):
        return None
    try:
        payload = json.loads(raw)
    except Exception:
        return None
    if not isinstance(payload, dict) or payload.get("v", 1) != 1:
        return None
    machine = _text(payload.get("mc"), 128)
    key = _text(payload.get("key"), 128)
    if not machine or not key:
        return None
    expires_at = payload.get("exp")
    if expires_at is not None and (
        not isinstance(expires_at, str) or parse_expiry(expires_at) is None
    ):
        return None
    try:
        duration = max(0, int(payload.get("dur", 0) or 0))
        devices = max(0, int(payload.get("dev", 1) or 0))
    except (TypeError, ValueError):
        return None
    payload["mc"] = machine.upper()
    payload["key"] = key.upper()
    payload["ed"] = _text(payload.get("ed"), 32) or "standard"
    payload["dur"] = duration
    payload["dev"] = devices
    payload["note"] = _text(payload.get("note"), 500)
    raw_features = payload.get("feats")
    payload["feats"] = (
        [str(item) for item in raw_features if isinstance(item, str) and str(item).strip()]
        if isinstance(raw_features, list)
        else []
    )
    return payload


# --------------------------------------------------------------------------- #
# 离线激活码最终判定（判定收口层）
# --------------------------------------------------------------------------- #
# 设计：验证端 UI 层不再自行实现"回拨/机器码/过期"判定，统一调用本模块的
# evaluate_activation_payload()。本模块随 Nuitka 加固一并编译为原生扩展后，
# 三条判定天然进入编译域（patch Python 层无法改变判定结果）。
CLOCK_SKEW_TOLERANCE_SECONDS = 6 * 3600
# 编译后该盐藏于原生代码；源码分发场景下配合加固方案使用。
_WATERMARK_SALT = "sq-offline-watermark-v1:9f2c7b31e5"


def seal_watermark(machine_code: str, ts: int) -> str:
    """为"最近一次校验时间"生成 HMAC 防伪标记。"""
    material = f"{str(machine_code or '').strip().upper()}|{int(ts)}"
    return hmac.new(
        _WATERMARK_SALT.encode("utf-8"), material.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def verify_watermark(machine_code: str, ts: int, signature: str) -> bool:
    """校验防伪标记；失败视为该记录被编辑（弃用）。"""
    if not signature or not ts:
        return False
    try:
        expected = seal_watermark(machine_code, int(ts))
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(expected, str(signature).strip())


def effective_last_seen(machine_code: str, entries) -> int:
    """多点 watermark 取最大值；签名无效的条目忽略（视为被编辑）。"""
    best = 0
    for entry in entries or []:
        try:
            ts_value = int(entry[0] or 0)
            sig_value = str(entry[1] or "")
        except (IndexError, TypeError, ValueError):
            continue
        if ts_value > 0 and verify_watermark(machine_code, ts_value, sig_value):
            best = max(best, ts_value)
    return best


def check_rolled_back(machine_code: str, last_seen: int, now: float) -> bool:
    """是否检测到时钟回拨（当前时间显著早于已见 watermark）。"""
    return bool(last_seen) and float(now) < int(last_seen) - CLOCK_SKEW_TOLERANCE_SECONDS


def evaluate_activation_payload(
    payload: dict,
    machine_code: str,
    *,
    last_seen: int = 0,
    now: float | None = None,
) -> dict:
    """离线激活码的最终判定（回拨 / 机器码绑定 / 到期）。

    调用前应先完成签名校验（parse_activation_code）。返回
    ``{"ok": bool, "code": str, "message": str}``，code 取值：
    ``clock_rolled_back`` / ``machine_mismatch`` / ``expired`` / ``ok``。
    """
    import time as _time

    current = float(now if now is not None else _time.time())
    if check_rolled_back(machine_code, last_seen, current):
        return {
            "ok": False,
            "code": "clock_rolled_back",
            "message": "检测到本机时间被回拨，已拒绝。请校正系统时间后重试。",
        }
    if not isinstance(payload, dict):
        return {"ok": False, "code": "invalid", "message": "激活码无效"}
    bound = str(payload.get("mc") or "").strip().upper()
    target = str(machine_code or "").strip().upper()
    if bound and target and bound != target:
        return {
            "ok": False,
            "code": "machine_mismatch",
            "message": f"该激活码绑定机器码 {bound}，与本机 {target} 不一致。",
        }
    exp = payload.get("exp")
    if exp and is_expired(exp):
        return {
            "ok": False,
            "code": "expired",
            "message": f"激活码已过期（到期时间：{exp}）。",
        }
    return {"ok": True, "code": "ok", "message": "校验通过"}


def build_activation_payload(
    machine_code: str,
    key_code: str,
    edition: str,
    duration_days: int,
    expires_at: str | None,
    max_devices: int = 1,
    note: str = "",
    features: list[str] | None = None,
) -> dict:
    payload = {
        "mc": (machine_code or "").strip().upper(),
        "key": (key_code or "").strip().upper(),
        "ed": edition or "standard",
        "dur": int(duration_days or 0),
        "exp": expires_at,
        "dev": int(max_devices or 0),
        "note": note or "",
    }
    feature_items = [str(item) for item in (features or []) if str(item or "").strip()]
    if feature_items:
        # 功能位只在非空时写入：旧客户端对未知字段安全忽略；
        # 旧激活码（无该字段）解析结果 feats 为空列表，行为不变。
        payload["feats"] = feature_items
    return payload
