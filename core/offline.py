import hashlib
import json
import secrets

from .security import TIME_FORMAT, _b64d, _b64e, now_str, now_ts

_REQUEST_PREFIX = "LICREQ1."
_ACTIVATION_PREFIX = "LICACT1."
_CODE_CHUNK = 64

_ED_BITS = 256
_ED_Q = 2 ** 255 - 19
_ED_L = 2 ** 252 + 27742317777372353535851937790883648493


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _expmod(base: int, exp: int, mod: int) -> int:
    return pow(base, exp, mod)


def _inv(x: int) -> int:
    return pow(x, _ED_Q - 2, _ED_Q)


_ED_D = (-121665 * _inv(121666)) % _ED_Q
_ED_I = pow(2, (_ED_Q - 1) // 4, _ED_Q)
_BY = (4 * _inv(5)) % _ED_Q


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_ED_D * y * y + 1)
    x = pow(xx, (_ED_Q + 3) // 8, _ED_Q)
    if (x * x - xx) % _ED_Q != 0:
        x = (x * _ED_I) % _ED_Q
    if x % 2 != 0:
        x = _ED_Q - x
    return x


_ED_B = (_xrecover(_BY), _BY % _ED_Q)


def _edwards(p: tuple[int, int], q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p
    x2, y2 = q
    k = _ED_D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + k)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - k)
    return (x3 % _ED_Q, y3 % _ED_Q)


def _scalarmult(point: tuple[int, int], scalar: int) -> tuple[int, int]:
    result = (0, 1)
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _edwards(result, addend)
        addend = _edwards(addend, addend)
        scalar >>= 1
    return result


def _encode_int(value: int) -> bytes:
    return value.to_bytes(32, "little")


def _encode_point(point: tuple[int, int]) -> bytes:
    x, y = point
    data = bytearray(y.to_bytes(32, "little"))
    data[31] |= (x & 1) << 7
    return bytes(data)


def _bit(data: bytes, index: int) -> int:
    return (data[index // 8] >> (index % 8)) & 1


def _public_key(seed: bytes) -> bytes:
    h = _sha512(seed)
    a = 2 ** (_ED_BITS - 2) + sum(2 ** i * _bit(h, i) for i in range(3, _ED_BITS - 2))
    return _encode_point(_scalarmult(_ED_B, a))


def _hint(data: bytes) -> int:
    h = _sha512(data)
    return sum(2 ** i * _bit(h, i) for i in range(2 * _ED_BITS))


def sign_raw(message: bytes, seed: bytes) -> bytes:
    h = _sha512(seed)
    a = 2 ** (_ED_BITS - 2) + sum(2 ** i * _bit(h, i) for i in range(3, _ED_BITS - 2))
    r = _hint(bytes(h[32:64]) + message)
    big_r = _scalarmult(_ED_B, r)
    s = (r + _hint(_encode_point(big_r) + _public_key(seed) + message) * a) % _ED_L
    return _encode_point(big_r) + _encode_int(s)


def _decode_point(data: bytes) -> tuple[int, int]:
    if len(data) != 32:
        raise ValueError("点长度错误")
    y = int.from_bytes(data, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != (data[31] >> 7) & 1:
        x = _ED_Q - x
    point = (x, y)
    if (-x * x + y * y - 1 - _ED_D * x * x * y * y) % _ED_Q != 0:
        raise ValueError("点不在曲线上")
    return point


def verify_raw(signature: bytes, message: bytes, public_key: bytes) -> bool:
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        big_r = _decode_point(signature[:32])
        a = _decode_point(public_key)
        s = int.from_bytes(signature[32:], "little")
        h = _hint(signature[:32] + public_key + message)
        left = _scalarmult(_ED_B, s)
        right = _edwards(big_r, _scalarmult(a, h))
        return left == right
    except Exception:
        return False


def generate_keypair() -> tuple[str, str]:
    seed = secrets.token_bytes(32)
    return seed.hex(), _public_key(seed).hex()


def _seed_bytes(private_hex: str) -> bytes:
    return bytes.fromhex((private_hex or "").strip())


def _public_hex(private_hex: str) -> str:
    return _public_key(_seed_bytes(private_hex)).hex()


def public_from_private(private_hex: str) -> str:
    return _public_hex(private_hex)


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode("utf-8")


def chunk_code(code: str, size: int = _CODE_CHUNK) -> str:
    text = (code or "").strip()
    if not text:
        return ""
    return "\n".join(text[i:i + size] for i in range(0, len(text), size))


def clean_code(code: str) -> str:
    return "".join((code or "").split())


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
    if not payload.get("mc"):
        return None
    return payload


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
        public_key = bytes.fromhex((public_hex or "").strip())
    except ValueError:
        return None
    if not verify_raw(signature, raw, public_key):
        return None
    try:
        payload = json.loads(raw)
    except Exception:
        return None
    if not payload.get("mc"):
        return None
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
