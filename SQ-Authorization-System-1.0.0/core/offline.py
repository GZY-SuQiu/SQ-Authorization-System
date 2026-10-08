import base64
import hashlib
import json
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .security import TIME_FORMAT, _b64d, _b64e, now_str, now_ts, parse_expiry

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
    return payload


def build_activation_payload(
    machine_code: str,
    key_code: str,
    edition: str,
    duration_days: int,
    expires_at: str | None,
    max_devices: int = 1,
    note: str = "",
) -> dict:
    return {
        "mc": (machine_code or "").strip().upper(),
        "key": (key_code or "").strip().upper(),
        "ed": edition or "standard",
        "dur": int(duration_days or 0),
        "exp": expires_at,
        "dev": int(max_devices or 0),
        "note": note or "",
    }
