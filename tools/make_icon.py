"""Generate the SQ应用图标 (the "SQ" mark) used by all four programs.

Usage:  python tools/make_icon.py

Writes assets/icon/sq.png (512px), assets/icon/sq.ico (16-256px) and
assets/icon/sq.svg. Re-run after changing the colours below; the SVG is
written from the same numbers so the three files stay in sync.
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets" / "icon"

# Brand colours, matched to core/theme.py.
TOP = (74, 134, 255)
BOTTOM = (23, 64, 196)
WHITE = (255, 255, 255)

CANVAS = 1024
RADIUS = 232
INSET = 30
BORDER = 5
MARK = "SQ"
FONT_SIZE = 430
FONT_CANDIDATES = (
    r"C:\Windows\Fonts\segoeuib.ttf",
    r"C:\Windows\Fonts\arialbd.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
)


def _font() -> ImageFont.FreeTypeFont:
    for path in FONT_CANDIDATES:
        if Path(path).exists():
            return ImageFont.truetype(path, FONT_SIZE)
    raise SystemExit("找不到可用的粗体字体，请在 FONT_CANDIDATES 中补充路径")


def _gradient(size: int) -> Image.Image:
    """Diagonal top-left -> bottom-right gradient."""
    image = Image.new("RGB", (size, size))
    pixels = image.load()
    for y in range(size):
        for x in range(size):
            # 0 at the top-left corner, 1 at the bottom-right corner.
            ratio = (x + y) / (2 * (size - 1))
            pixels[x, y] = tuple(
                round(TOP[channel] + (BOTTOM[channel] - TOP[channel]) * ratio)
                for channel in range(3)
            )
    return image


def _rounded_mask(size: int) -> Image.Image:
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        (0, 0, size - 1, size - 1), radius=RADIUS, fill=255
    )
    return mask


def render(size: int = CANVAS) -> Image.Image:
    icon = _gradient(size).convert("RGBA")
    icon.putalpha(_rounded_mask(size))

    draw = ImageDraw.Draw(icon)
    # A faint inner ring keeps the mark readable on very light desktops.
    draw.rounded_rectangle(
        (INSET, INSET, size - INSET - 1, size - INSET - 1),
        radius=RADIUS - INSET,
        outline=WHITE + (70,),
        width=BORDER,
    )

    font = _font()
    left, top, right, bottom = draw.textbbox((0, 0), MARK, font=font)
    # Centre the ink, not the font box, so the mark looks optically centred.
    draw.text(
        (size / 2 - (left + right) / 2, size / 2 - (top + bottom) / 2),
        MARK,
        font=font,
        fill=WHITE + (255,),
    )
    return icon


def _svg() -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {CANVAS} {CANVAS}">
  <defs>
    <linearGradient id="sq" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#{TOP[0]:02X}{TOP[1]:02X}{TOP[2]:02X}"/>
      <stop offset="1" stop-color="#{BOTTOM[0]:02X}{BOTTOM[1]:02X}{BOTTOM[2]:02X}"/>
    </linearGradient>
  </defs>
  <rect width="{CANVAS}" height="{CANVAS}" rx="{RADIUS}" fill="url(#sq)"/>
  <rect x="{INSET}" y="{INSET}" width="{CANVAS - 2 * INSET}" height="{CANVAS - 2 * INSET}"
        rx="{RADIUS - INSET}" fill="none" stroke="#FFFFFF" stroke-opacity="0.27"
        stroke-width="{BORDER}"/>
  <text x="{CANVAS / 2}" y="{CANVAS / 2}" fill="#FFFFFF"
        font-family="Segoe UI, Arial, sans-serif" font-size="{FONT_SIZE}"
        font-weight="700" text-anchor="middle" dominant-baseline="central">{MARK}</text>
</svg>
"""


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    icon = render()

    png_path = OUT / "sq.png"
    icon.resize((512, 512), Image.LANCZOS).save(png_path)

    ico_path = OUT / "sq.ico"
    icon.save(
        ico_path,
        format="ICO",
        sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)],
    )

    svg_path = OUT / "sq.svg"
    svg_path.write_text(_svg(), encoding="utf-8")

    for path in (png_path, ico_path, svg_path):
        print(f"已生成 {path}  ({path.stat().st_size / 1024:.1f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
