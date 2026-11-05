"""Build the two remaining promo-video shot assets from the best captures.

The HyperFrames project at ``promo-video/`` references two shot images that do
not exist yet (``npx hyperframes lint`` reports them as missing):

    assets/shots/06-verify.png   验证端 · 激活成功（场景 s5-verify）
    assets/shots/07-server.png   本地服务器 · AI 设置（场景 s6a-providers）

The other shots (03/04/05) are 4320x2700, i.e. a 1.6 frame ratio.  Source
captures live in ``promo-video/assets/captures``:

    06-verify  <- verify/02-success.png    2560x1760 (1.4545) -> pad to 1.6
    07-server  <- server/02-ai-settings.png 2880x1800 (1.6)   -> straight resize

Padding keeps the whole window visible; cropping to 1.6 would clip the bottom
of the result cards, and ``object-fit: cover`` in the composition would then
crop it again at render time.

Usage:  python tools/make_video_shots.py [--width 4320]
"""
from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
PROJECT = ROOT.parent / "promo-video"
CAPTURES = PROJECT / "assets" / "captures"
SHOTS = PROJECT / "assets" / "shots"

# name -> (source capture, frame ratio)
JOBS = {
    "06-verify.png": (CAPTURES / "verify" / "02-success.png", 1.6),
    "07-server.png": (CAPTURES / "server" / "02-ai-settings.png", 1.6),
}


def pad_to_ratio(image: Image.Image, ratio: float) -> Image.Image:
    """Centre ``image`` on a canvas of ``ratio``, filled with its corner colour."""
    width, height = image.size
    target_width = round(height * ratio)
    if target_width < width:
        target_height = round(width / ratio)
        pad = (0, (target_height - height) // 2)
        size = (width, target_height)
    else:
        pad = ((target_width - width) // 2, 0)
        size = (target_width, height)
    if size == image.size:
        return image
    fill = image.convert("RGB").getpixel((0, 0))
    canvas = Image.new("RGB", size, fill)
    canvas.paste(image.convert("RGB"), pad)
    return canvas


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--width", type=int, default=4320, help="output width in pixels")
    args = parser.parse_args()

    SHOTS.mkdir(parents=True, exist_ok=True)
    missing = 0
    for name, (source, ratio) in JOBS.items():
        if not source.exists():
            print(f"[skip] missing capture: {source}")
            missing += 1
            continue
        with Image.open(source) as raw:
            image = pad_to_ratio(raw.convert("RGB"), ratio)
        height = round(args.width / ratio)
        image = image.resize((args.width, height), Image.LANCZOS)
        target = SHOTS / name
        image.save(target)
        print(f"saved {target}  {image.width}x{image.height}")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
