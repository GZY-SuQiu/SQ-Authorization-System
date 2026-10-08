"""头像图片尺寸校验测试。"""

import unittest

from core import image_guard


def _png(width: int, height: int) -> bytes:
    return (
        b"\x89PNG\r\n\x1a\n"
        + b"\x00\x00\x00\x0d"
        + b"IHDR"
        + width.to_bytes(4, "big")
        + height.to_bytes(4, "big")
        + b"\x08\x06\x00\x00\x00"
    )


def _jpeg(width: int, height: int) -> bytes:
    return (
        b"\xff\xd8"
        + b"\xff\xc0"
        + (17).to_bytes(2, "big")
        + b"\x08"
        + height.to_bytes(2, "big")
        + width.to_bytes(2, "big")
        + b"\x03\x01\x11\x00\x02\x11\x00\x03\x11\x00"
    )


class ImageGuardTests(unittest.TestCase):
    def test_small_images_pass(self):
        self.assertEqual(image_guard.image_size("image/png", _png(64, 64)), (64, 64))
        self.assertEqual(image_guard.avatar_problem("image/png", _png(64, 64)), "")
        self.assertEqual(image_guard.image_size("image/jpeg", _jpeg(320, 200)), (320, 200))
        self.assertEqual(image_guard.avatar_problem("image/jpeg", _jpeg(320, 200)), "")

    def test_oversized_pixels_are_rejected(self):
        problem = image_guard.avatar_problem("image/png", _png(99999, 99999))
        self.assertIn("像素过大", problem)

    def test_wrong_magic_is_rejected(self):
        problem = image_guard.avatar_problem("image/png", b"not-a-real-png" + b"x" * 40)
        self.assertIn("不符", problem)
        self.assertIsNone(image_guard.image_size("image/webp", b"RIFFxxxxWEBP" + b"x" * 40))

    def test_webp_vp8x_dimensions(self):
        raw = (
            b"RIFF"
            + (30).to_bytes(4, "little")
            + b"WEBP"
            + b"VP8X"
            + (10).to_bytes(4, "little")
            + b"\x00" * 4
            + (63).to_bytes(3, "little")
            + (63).to_bytes(3, "little")
        )
        self.assertEqual(image_guard.image_size("image/webp", raw), (64, 64))


if __name__ == "__main__":
    unittest.main()
