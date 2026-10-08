"""头像图片安全校验：魔术字节 + 像素上限，防止解码炸弹。

只依赖标准库解析 PNG/JPEG/WebP 头部尺寸，不解码像素数据。
"""

from __future__ import annotations

__all__ = ["MAX_DIMENSION", "MAX_PIXELS", "image_size", "avatar_problem"]

MAX_DIMENSION = 4096
MAX_PIXELS = 16 * 1024 * 1024


def _u24_le(data: bytes, offset: int) -> int:
    return data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16)


def image_size(mime: str, data: bytes) -> tuple[int, int] | None:
    """Return (width, height) parsed from the header, or None when invalid."""
    kind = str(mime or "").strip().lower()
    raw = bytes(data or b"")
    if kind == "image/png":
        if len(raw) < 24 or raw[:8] != b"\x89PNG\r\n\x1a\n":
            return None
        return int.from_bytes(raw[16:20], "big"), int.from_bytes(raw[20:24], "big")
    if kind in ("image/jpeg", "image/jpg"):
        if len(raw) < 4 or raw[:2] != b"\xff\xd8":
            return None
        index = 2
        while index + 9 < len(raw):
            if raw[index] != 0xFF:
                index += 1
                continue
            marker = raw[index + 1]
            if marker in (0xD8, 0xD9):
                index += 2
                continue
            if marker == 0xDA:
                break
            if index + 4 > len(raw):
                break
            segment_length = int.from_bytes(raw[index + 2 : index + 4], "big")
            if segment_length < 2:
                break
            is_sof = 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC)
            if is_sof:
                if index + 9 > len(raw):
                    break
                height = int.from_bytes(raw[index + 5 : index + 7], "big")
                width = int.from_bytes(raw[index + 7 : index + 9], "big")
                return width, height
            index += 2 + segment_length
        return None
    if kind == "image/webp":
        if len(raw) < 30 or raw[:4] != b"RIFF" or raw[8:12] != b"WEBP":
            return None
        chunk = raw[12:16]
        if chunk == b"VP8X":
            return _u24_le(raw, 24) + 1, _u24_le(raw, 27) + 1
        if chunk == b"VP8L":
            if raw[20] != 0x2F:
                return None
            bits = int.from_bytes(raw[21:25], "little")
            return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
        if chunk == b"VP8 ":
            width = int.from_bytes(raw[26:28], "little") & 0x3FFF
            height = int.from_bytes(raw[28:30], "little") & 0x3FFF
            return width, height
    return None


def avatar_problem(mime: str, data: bytes) -> str:
    """Return a human-readable problem string, or '' when the image is safe."""
    size = image_size(mime, data)
    if size is None:
        return "图片内容与声明的格式不符，或不是有效的 PNG/JPEG/WebP"
    width, height = size
    if width <= 0 or height <= 0:
        return "图片尺寸无效"
    if width > MAX_DIMENSION or height > MAX_DIMENSION or width * height > MAX_PIXELS:
        return (
            f"图片像素过大（{width}x{height}），请压缩到 4096x4096 以内"
            f"且不超过 {MAX_PIXELS // (1024 * 1024)} 百万像素"
        )
    return ""
