"""小型本机机密存储：Windows 用 DPAPI 加密，其它平台退回 Base64。

用途：客户端"记住密码"功能。DPAPI 密文只能由当前 Windows 用户解开，
文件被拷走也无法直接还原明文。非 Windows 平台没有等价能力，退回 Base64
只是兼容（不是安全存储），界面会据此提示用户。
"""

from __future__ import annotations

import base64
import ctypes
import sys

__all__ = ["protect", "unprotect", "is_secure_available"]

_DPAPI_PREFIX = "dpapi:"
_B64_PREFIX = "b64:"
_CRYPTPROTECT_UI_FORBIDDEN = 0x01


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.c_uint32),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


def is_secure_available() -> bool:
    """True when OS-level protection (DPAPI) is available."""
    return sys.platform == "win32"


def _make_blob(data: bytes):
    buffer = ctypes.create_string_buffer(data, len(data))
    blob = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    return blob, buffer


def _local_free(pointer) -> None:
    try:
        ctypes.windll.kernel32.LocalFree(pointer)
    except Exception:
        pass


def protect(text: str) -> str:
    """Encrypt ``text`` for this OS user; return a prefixed token."""
    value = str(text or "")
    if not value:
        return ""
    if sys.platform == "win32":
        try:
            blob_in, buffer_in = _make_blob(value.encode("utf-8"))
            blob_out = _DataBlob()
            ok = ctypes.windll.crypt32.CryptProtectData(
                ctypes.byref(blob_in),
                None,
                None,
                None,
                None,
                _CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(blob_out),
            )
            if ok:
                try:
                    sealed = ctypes.string_at(blob_out.pbData, blob_out.cbData)
                finally:
                    _local_free(blob_out.pbData)
                return _DPAPI_PREFIX + base64.b64encode(sealed).decode("ascii")
        except Exception:
            pass
    return _B64_PREFIX + base64.b64encode(value.encode("utf-8")).decode("ascii")


def unprotect(token: str) -> str:
    """Decrypt a token produced by :func:`protect`; return '' on failure."""
    raw = str(token or "")
    if not raw:
        return ""
    try:
        if raw.startswith(_DPAPI_PREFIX):
            if sys.platform != "win32":
                return ""
            sealed = base64.b64decode(raw[len(_DPAPI_PREFIX):], validate=True)
            blob_in, buffer_in = _make_blob(sealed)
            blob_out = _DataBlob()
            ok = ctypes.windll.crypt32.CryptUnprotectData(
                ctypes.byref(blob_in),
                None,
                None,
                None,
                None,
                _CRYPTPROTECT_UI_FORBIDDEN,
                ctypes.byref(blob_out),
            )
            if ok:
                try:
                    plain = ctypes.string_at(blob_out.pbData, blob_out.cbData)
                finally:
                    _local_free(blob_out.pbData)
                return plain.decode("utf-8", "replace")
            return ""
        if raw.startswith(_B64_PREFIX):
            return base64.b64decode(raw[len(_B64_PREFIX):], validate=True).decode(
                "utf-8", "replace"
            )
    except Exception:
        return ""
    return ""
