"""Compose promotional images from the raw offscreen window captures.

Raw captures live in ``build/promo/raw`` (produced by ``render_promo_admin.py``
and ``render_promo_client.py``).  This tool frames them as product cards and
writes the finished promo set to ``build/promo``:

    hero-overview.png   2400x1350  combined product hero
    card-master.png     1920x1080  主控端
    card-admin-ai.png   1920x1080  管理端 · AI 助手
    card-verification.png 1920x1080  验证端
    card-server.png     1920x1080  本地服务器
    feature-grid.png    1920x1080  九宫格功能总览

Usage:  python tools/make_promo_shots.py [--only hero|master|admin|verify|server|features]
"""
from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "build" / "promo" / "raw"
RAW_DIRS = [
    RAW,
    ROOT / "build" / "promo_admin_final",
    ROOT / "build" / "promo_client_final",
    ROOT / "build" / "promo_clients_final",
    ROOT / "build" / "promo_verify_final",
]
OUT = ROOT / "build" / "promo"
ICON = ROOT / "assets" / "icon" / "sq.png"

FONT_DIR = Path("C:/Windows/Fonts")
FONT_REGULAR = FONT_DIR / "msyh.ttc"
FONT_BOLD = FONT_DIR / "msyhbd.ttc"
FONT_LIGHT = FONT_DIR / "msyhl.ttc"

PRIMARY = (47, 107, 255)
PRIMARY_DARK = (23, 73, 199)
INK = (17, 24, 39)
BODY = (55, 65, 81)
MUTED = (122, 134, 154)
LINE = (226, 232, 240)
CARD_BG = (255, 255, 255)
SUCCESS = (22, 138, 74)
FROZEN = (105, 65, 198)
WARNING = (183, 110, 0)

CANVAS_CARD = (1920, 1080)
CANVAS_HERO = (2400, 1350)


def font(size: int, *, bold: bool = False, light: bool = False) -> ImageFont.FreeTypeFont:
    path = FONT_BOLD if bold else (FONT_LIGHT if light else FONT_REGULAR)
    return ImageFont.truetype(str(path), size)


def text_size(draw: ImageDraw.ImageDraw, value: str, f: ImageFont.FreeTypeFont) -> tuple[int, int]:
    box = draw.textbbox((0, 0), value, font=f)
    return box[2] - box[0], box[3] - box[1]


def draw_text(
    draw: ImageDraw.ImageDraw,
    xy: tuple[int, int],
    value: str,
    f: ImageFont.FreeTypeFont,
    fill: tuple[int, int, int] = INK,
    *,
    anchor: str = "la",
) -> None:
    draw.text(xy, value, font=f, fill=fill, anchor=anchor)


def wrap(draw: ImageDraw.ImageDraw, value: str, f: ImageFont.FreeTypeFont, width: int) -> list[str]:
    lines: list[str] = []
    current = ""
    no_line_start = "，。、；：！？）》」』%…"
    for char in value:
        candidate = current + char
        if text_size(draw, candidate, f)[0] <= width or not current:
            current = candidate
        else:
            if char in no_line_start and lines:
                # Keep closing punctuation attached to the line it follows.
                lines[-1] += char
                current = ""
                continue
            lines.append(current)
            current = char
    if current:
        lines.append(current)
    return lines


def draw_wrapped(
    draw: ImageDraw.ImageDraw,
    xy: tuple[int, int],
    value: str,
    f: ImageFont.FreeTypeFont,
    width: int,
    fill: tuple[int, int, int] = BODY,
    *,
    line_gap: int = 14,
) -> int:
    y = xy[1]
    for line in wrap(draw, value, f, width):
        draw_text(draw, (xy[0], y), line, f, fill)
        y += text_size(draw, line, f)[1] + line_gap
    return y


def vertical_gradient(size: tuple[int, int], top: tuple[int, int, int], bottom: tuple[int, int, int]) -> Image.Image:
    strip = Image.new("RGB", (1, size[1]))
    for y in range(size[1]):
        ratio = y / max(1, size[1] - 1)
        strip.putpixel(
            (0, y),
            tuple(round(top[i] + (bottom[i] - top[i]) * ratio) for i in range(3)),
        )
    return strip.resize(size, Image.BILINEAR)


def mix(color: tuple[int, int, int], other: tuple[int, int, int], ratio: float) -> tuple[int, int, int]:
    """Blend ``ratio`` of ``other`` into ``color`` (0.0 keeps color, 1.0 gives other)."""
    return tuple(round(color[i] + (other[i] - color[i]) * ratio) for i in range(3))


def draw_overlay(canvas: Image.Image, paint) -> None:
    """Draw translucent shapes on a scratch layer so they blend with the canvas.

    ``ImageDraw.Draw(image, "RGBA")`` replaces pixels rather than blending them,
    so translucent fills must be composited from their own layer.
    """
    layer = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
    paint(ImageDraw.Draw(layer, "RGBA"))
    canvas.alpha_composite(layer)


def rounded_mask(size: tuple[int, int], radius: int) -> Image.Image:
    scale = 2
    mask = Image.new("L", (size[0] * scale, size[1] * scale), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        (0, 0, size[0] * scale - 1, size[1] * scale - 1),
        radius=radius * scale,
        fill=255,
    )
    return mask.resize(size, Image.LANCZOS)


def paste_shot(
    base: Image.Image,
    shot: Image.Image,
    xy: tuple[int, int],
    *,
    width: int | None = None,
    radius: int = 22,
    blur: int = 26,
    offset: tuple[int, int] = (0, 16),
    opacity: int = 70,
    border: tuple[int, int, int] = (214, 222, 236),
) -> tuple[int, int]:
    if width and width != shot.width:
        height = round(shot.height * width / shot.width)
        shot = shot.resize((width, height), Image.LANCZOS)
    mask = rounded_mask(shot.size, radius)
    shadow = Image.new("RGBA", base.size, (0, 0, 0, 0))
    block = Image.new("RGBA", shot.size, (15, 30, 70, opacity))
    shadow.paste(block, (xy[0] + offset[0], xy[1] + offset[1]), mask)
    shadow = shadow.filter(ImageFilter.GaussianBlur(blur))
    base.alpha_composite(shadow)
    layer = Image.new("RGBA", base.size, (0, 0, 0, 0))
    layer.paste(shot, xy, mask)
    base.alpha_composite(layer)
    edge = Image.new("RGBA", shot.size, (0, 0, 0, 0))
    ImageDraw.Draw(edge).rounded_rectangle(
        (0, 0, shot.width - 1, shot.height - 1),
        radius=radius,
        outline=border + (255,),
        width=2,
    )
    base.paste(edge, xy, edge)
    return shot.size


def add_background(canvas: Image.Image, *, tint: int = 0) -> None:
    def paint(draw: ImageDraw.ImageDraw) -> None:
        for x in range(0, canvas.width, 96):
            draw.line((x, 0, x, canvas.height), fill=(47, 107, 255, 10), width=1)
        for y in range(0, canvas.height, 96):
            draw.line((0, y, canvas.width, y), fill=(47, 107, 255, 10), width=1)
        if tint:
            draw.polygon(
                [(canvas.width, 0), (canvas.width, tint), (canvas.width - tint, 0)],
                fill=(47, 107, 255, 16),
            )

    draw_overlay(canvas, paint)


def load_raw(name: str) -> Image.Image | None:
    names = [name] if isinstance(name, str) else list(name)
    for directory in RAW_DIRS:
        for candidate in names:
            path = directory / candidate
            if path.exists():
                return Image.open(path).convert("RGBA")
    searched = [str(d / n) for d in RAW_DIRS for n in names]
    print(f"[skip] missing raw capture; tried {searched}")
    return None


def icon_image(size: int, radius: int = 0) -> Image.Image:
    if ICON.exists():
        img = Image.open(ICON).convert("RGBA").resize((size, size), Image.LANCZOS)
        if radius:
            mask = rounded_mask((size, size), radius)
            img.putalpha(Image.composite(img.getchannel("A"), Image.new("L", (size, size), 0), mask))
        return img
    img = Image.new("RGBA", (size, size), PRIMARY + (255,))
    return img


def draw_brand(canvas: Image.Image, draw: ImageDraw.ImageDraw, *, x: int, y: int, icon: int = 60) -> int:
    canvas.alpha_composite(icon_image(icon, radius=14), (x, y))
    draw_text(draw, (x + icon + 18, y + 2), "密钥授权系统", font(38, bold=True), INK)
    draw_text(draw, (x + icon + 20, y + 48), "v1.0.0 · Windows 10 / 11", font(22), MUTED)
    return x + icon + 18


def draw_pill(
    draw: ImageDraw.ImageDraw,
    xy: tuple[int, int],
    value: str,
    f: ImageFont.FreeTypeFont,
    *,
    fg: tuple[int, int, int] = BODY,
    bg: tuple[int, int, int] = (255, 255, 255),
    border: tuple[int, int, int] = LINE,
    pad: tuple[int, int] = (26, 14),
) -> tuple[int, int]:
    width, height = text_size(draw, value, f)
    box = (xy[0], xy[1], xy[0] + width + pad[0] * 2, xy[1] + height + pad[1] * 2)
    draw.rounded_rectangle(box, radius=(box[3] - box[1]) // 2, fill=bg, outline=border, width=2)
    draw_text(draw, ((box[0] + box[2]) // 2, (box[1] + box[3]) // 2), value, f, fg, anchor="mm")
    return box[2] - box[0], box[3] - box[1]


def compose_card(
    out_name: str,
    *,
    eyebrow: str,
    title: str,
    subtitle: str,
    bullets: list[str],
    shot_name: str,
    shoot_width: int = 1180,
) -> bool:
    shot = load_raw(shot_name)
    if shot is None:
        return False

    canvas = vertical_gradient(CANVAS_CARD, (255, 255, 255), (238, 243, 251)).convert("RGBA")
    add_background(canvas)
    draw = ImageDraw.Draw(canvas, "RGBA")
    draw.rectangle((0, 0, CANVAS_CARD[0], 8), fill=PRIMARY + (255,))

    draw_brand(canvas, draw, x=96, y=62)

    top_pill = "免安装 · 离线可用 · 数据自持"
    pill_font = font(24)
    pill_w, _ = text_size(draw, top_pill, pill_font)
    draw_pill(draw, (CANVAS_CARD[0] - 96 - (pill_w + 52), 74), top_pill, pill_font)

    draw_text(draw, (100, 296), eyebrow, font(26, bold=True), PRIMARY)
    title_size = 88
    while title_size > 52 and text_size(draw, title, font(title_size, bold=True))[0] > 580:
        title_size -= 4
    draw_text(draw, (100, 334), title, font(title_size, bold=True), INK)

    subtitle_font = font(34)
    sub_y = 472
    sub_end = draw_wrapped(draw, (100, sub_y), subtitle, subtitle_font, 560, MUTED, line_gap=12)

    rule_y = sub_end + 22
    draw.rounded_rectangle((100, rule_y, 160, rule_y + 5), radius=3, fill=PRIMARY + (255,))

    bullet_font = font(27)
    y = rule_y + 48
    for bullet in bullets:
        draw.ellipse((100, y + 6, 130, y + 36), fill=(238, 244, 255, 255), outline=(215, 226, 255, 255), width=2)
        draw.line((108, y + 21, 114, y + 27), fill=PRIMARY + (255,), width=4)
        draw.line((114, y + 27, 124, y + 15), fill=PRIMARY + (255,), width=4)
        y = draw_wrapped(draw, (148, y), bullet, bullet_font, 470, BODY, line_gap=10) + 26

    draw_text(draw, (100, 1000), "作者：苏丠 · © 2026 保留所有权利", font(22), MUTED)

    paste_shot(canvas, shot, (680, 272), width=shoot_width)

    OUT.mkdir(parents=True, exist_ok=True)
    target = OUT / out_name
    canvas.convert("RGB").save(target, quality=95)
    print(f"saved {target}")
    return True


def compose_hero() -> bool:
    master = load_raw(["master-overview.png", "admin-overview.png"])
    verify = load_raw(["verify-active.png", "verification-active.png"])
    if master is None:
        return False

    canvas = vertical_gradient(CANVAS_HERO, (255, 255, 255), (235, 241, 251)).convert("RGBA")
    add_background(canvas, tint=420)
    draw = ImageDraw.Draw(canvas, "RGBA")
    draw.rectangle((0, 0, CANVAS_HERO[0], 10), fill=PRIMARY + (255,))

    title_font = font(112, bold=True)
    title = "密钥授权系统"
    title_w, _ = text_size(draw, title, title_font)
    lockup_w = 84 + 20 + title_w
    lock_x = (CANVAS_HERO[0] - lockup_w) // 2
    canvas.alpha_composite(icon_image(84, radius=20), (lock_x, 86))
    draw_text(draw, (lock_x + 104, 116), title, title_font, INK)

    subtitle = "本地部署 · 免安装 · 一套搞定卡密生成、绑定与验证"
    subtitle_font = font(40)
    subtitle_w, _ = text_size(draw, subtitle, subtitle_font)
    draw_text(draw, ((CANVAS_HERO[0] - subtitle_w) // 2, 282), subtitle, subtitle_font, MUTED)

    chips = ["批量生成卡密", "硬件绑定", "离线激活", "审计日志", "AI 助手", "备份恢复"]
    chip_font = font(26)
    widths = [text_size(draw, chip, chip_font)[0] + 76 for chip in chips]
    gap = 18
    total = sum(widths) + gap * (len(chips) - 1)
    x = (CANVAS_HERO[0] - total) // 2
    for chip, width in zip(chips, widths):
        draw.rounded_rectangle((x, 356, x + width, 420), radius=32, fill=(255, 255, 255, 255), outline=LINE + (255,), width=2)
        draw.ellipse((x + 26, 380, x + 40, 394), fill=PRIMARY + (255,))
        draw_text(draw, (x + 52, 388), chip, chip_font, BODY, anchor="lm")
        x += width + gap

    paste_shot(canvas, master, (150, 500), width=1300, blur=34, offset=(0, 20), opacity=80)
    if verify is not None:
        paste_shot(canvas, verify, (1560, 830), width=660, blur=30, offset=(0, 18), opacity=80)

    OUT.mkdir(parents=True, exist_ok=True)
    target = OUT / "hero-overview.png"
    canvas.convert("RGB").save(target, quality=95)
    print(f"saved {target}")
    return True


FEATURES = [
    ("卡", "批量生成卡密", "分钟 / 小时 / 天 / 周 / 月 / 季 / 年多档时长，一次批量生成", PRIMARY),
    ("次", "激活次数卡", "按激活台数计费，次数用尽自动吊销，同机重复激活不计数", SUCCESS),
    ("绑", "硬件绑定", "卡密与设备硬件码绑定，支持解绑与换机，一码一机", FROZEN),
    ("离", "离线激活", "Ed25519 签名离线激活码，内网与断网环境照常使用", WARNING),
    ("冻", "冻结 / 吊销 / 恢复", "临时冻结到期自动恢复，吊销可回滚，状态全程可追溯", PRIMARY),
    ("批", "批次管理", "按批次聚合统计生成与激活量，支持整批吊销", SUCCESS),
    ("审", "审计日志", "登录与操作全记录，关键词筛选、分页浏览、CSV 导出", FROZEN),
    ("备", "备份与恢复", "一键备份与恢复数据库，完整性校验，安全可靠", WARNING),
    ("AI", "AI 助手", "用自然语言查询授权数据、执行发卡与吊销操作", PRIMARY),
]


def compose_features() -> bool:
    canvas = vertical_gradient(CANVAS_CARD, (255, 255, 255), (238, 243, 251)).convert("RGBA")
    add_background(canvas)
    draw = ImageDraw.Draw(canvas, "RGBA")
    draw.rectangle((0, 0, CANVAS_CARD[0], 8), fill=PRIMARY + (255,))
    draw_brand(canvas, draw, x=96, y=62)

    draw_text(draw, (96, 172), "功能特性", font(70, bold=True), INK)
    draw_text(draw, (96, 286), "从发卡到验证，一套系统全部搞定", font(30), MUTED)

    margin = 96
    gap = 28
    columns = 3
    card_w = (CANVAS_CARD[0] - margin * 2 - gap * (columns - 1)) // columns
    card_h = 200
    top = 352
    for index, (glyph, title, desc, color) in enumerate(FEATURES):
        row, col = divmod(index, columns)
        x = margin + col * (card_w + gap)
        y = top + row * (card_h + gap)
        draw.rounded_rectangle((x, y, x + card_w, y + card_h), radius=16, fill=(255, 255, 255, 255), outline=LINE + (255,), width=2)
        glyph_bg = mix(color, (255, 255, 255), 0.88)
        glyph_border = mix(color, (255, 255, 255), 0.62)
        draw.rounded_rectangle((x + 28, y + 36, x + 92, y + 100), radius=16, fill=glyph_bg + (255,), outline=glyph_border + (255,), width=2)
        glyph_font = font(36, bold=True) if len(glyph) == 1 else font(30, bold=True)
        draw_text(draw, (x + 60, y + 68), glyph, glyph_font, color, anchor="mm")
        draw_text(draw, (x + 116, y + 34), title, font(32, bold=True), INK)
        draw_wrapped(draw, (x + 116, y + 86), desc, font(23), card_w - 148, MUTED, line_gap=8)

    OUT.mkdir(parents=True, exist_ok=True)
    target = OUT / "feature-grid.png"
    canvas.convert("RGB").save(target, quality=95)
    print(f"saved {target}")
    return True


def draw_arrow(canvas: Image.Image, points: list[tuple[int, int]], *, width: int = 5) -> None:
    import math

    def paint(draw: ImageDraw.ImageDraw) -> None:
        draw.line(points, fill=PRIMARY + (170,), width=width, joint="curve")
        (x1, y1), (x2, y2) = points[-2], points[-1]
        angle = math.atan2(y2 - y1, x2 - x1)
        size = 18
        head = [
            (x2, y2),
            (x2 - size * math.cos(angle - 0.5), y2 - size * math.sin(angle - 0.5)),
            (x2 - size * math.cos(angle + 0.5), y2 - size * math.sin(angle + 0.5)),
        ]
        draw.polygon(head, fill=PRIMARY + (200,))

    draw_overlay(canvas, paint)


def draw_node(
    draw: ImageDraw.ImageDraw,
    *,
    x: int,
    y: int,
    w: int,
    h: int,
    glyph: str,
    title: str,
    desc: str,
    color: tuple[int, int, int],
    tag: str,
    glyph_size: int = 30,
    title_size: int = 34,
    desc_size: int = 22,
    box: int = 68,
) -> None:
    draw.rounded_rectangle((x, y, x + w, y + h), radius=18, fill=(255, 255, 255, 255), outline=LINE + (255,), width=2)
    draw.rounded_rectangle(
        (x + 26, y + 26, x + 26 + box, y + 26 + box),
        radius=16,
        fill=mix(color, (255, 255, 255), 0.88) + (255,),
        outline=mix(color, (255, 255, 255), 0.62) + (255,),
        width=2,
    )
    draw_text(draw, (x + 26 + box // 2, y + 26 + box // 2), glyph, font(glyph_size, bold=True), color, anchor="mm")
    draw_text(draw, (x + 26 + box + 20, y + 26), title, font(title_size, bold=True), INK)
    draw_wrapped(
        draw,
        (x + 26 + box + 20, y + 26 + title_size + 16),
        desc,
        font(desc_size),
        w - (26 + box + 20) - 24,
        MUTED,
        line_gap=8,
    )
    draw_text(draw, (x + 26, y + h - 40), tag, font(21), color)


def compose_suite() -> bool:
    canvas = vertical_gradient(CANVAS_CARD, (255, 255, 255), (238, 243, 251)).convert("RGBA")
    add_background(canvas)
    draw = ImageDraw.Draw(canvas, "RGBA")
    draw.rectangle((0, 0, CANVAS_CARD[0], 8), fill=PRIMARY + (255,))
    draw_brand(canvas, draw, x=96, y=62)

    draw_text(draw, (96, 172), "四端协同", font(70, bold=True), INK)
    draw_text(draw, (96, 286), "一个本地服务端，配合管理、验证与主控三个程序", font(30), MUTED)

    left_nodes = [
        (420, "主", "主控端", "管理员账号 · 系统级设置", FROZEN, "MASTER"),
        (620, "管", "管理端", "批量发卡 · 密钥与批次管理", PRIMARY, "ADMIN"),
        (820, "验", "验证端", "联网激活 · 离线激活 · 心跳校验", SUCCESS, "CLIENT"),
    ]
    for y, glyph, title, desc, color, tag in left_nodes:
        draw_node(draw, x=120, y=y, w=440, h=170, glyph=glyph, title=title, desc=desc, color=color, tag=tag)
        draw_arrow(canvas, [(568, y + 85), (660, y + 85), (660, 702), (744, 702)])

    draw_node(
        draw,
        x=752,
        y=576,
        w=420,
        h=252,
        glyph="服",
        title="本地服务器",
        desc="REST API 签发与校验，默认 127.0.0.1:8765",
        color=PRIMARY,
        tag="SERVER",
        glyph_size=36,
        title_size=40,
        desc_size=24,
        box=76,
    )
    draw_arrow(canvas, [(1180, 702), (1376, 702)])
    draw_node(
        draw,
        x=1392,
        y=576,
        w=408,
        h=252,
        glyph="库",
        title="SQLite 数据库",
        desc="license.db 本地自持，一键备份与恢复",
        color=WARNING,
        tag="DATA",
        glyph_size=36,
        title_size=36,
        desc_size=24,
        box=76,
    )

    OUT.mkdir(parents=True, exist_ok=True)
    target = OUT / "suite-lineup.png"
    draw_text(
        draw,
        (96, 1004),
        "四个程序可同机部署，也可分开部署；本地服务器支持 headless 无界面运行。",
        font(24),
        MUTED,
    )
    canvas.convert("RGB").save(target, quality=95)
    print(f"saved {target}")
    return True
CARDS = {
    "master": dict(
        out_name="card-master.png",
        eyebrow="MASTER CONSOLE",
        title="主控端",
        subtitle="最高权限，管理员与全站数据统一管控",
        bullets=[
            "独立管理管理员：创建、启用 / 禁用、重置密码",
            "系统级设置：心跳、会话、安全策略集中调整",
            "密钥 · 批次 · 日志 · 备份，一个界面全掌握",
        ],
        shot_name=["master-admins.png", "admin-batches.png", "admin-licenses.png"],
    ),
    "admin": dict(
        out_name="card-admin-ai.png",
        eyebrow="ADMIN CONSOLE",
        title="管理端",
        subtitle="批量发卡，AI 助手让授权管理更高效",
        bullets=[
            "一次生成多枚卡密，多档时长、多版本可选",
            "AI 助手对话式查询与操作，效率翻倍",
            "批次统计、冻结吊销、CSV 导出一步到位",
        ],
        shot_name=["admin-ai.png", "admin-ai-thinking.png"],
    ),
    "verify": dict(
        out_name="card-verification.png",
        eyebrow="CLIENT",
        title="验证端",
        subtitle="一键激活，联网 / 离线双模式",
        bullets=[
            "卡密 + 硬件码绑定，一码一机防止外泄",
            "离线激活码 Ed25519 签名，断网可用",
            "心跳校验带随机抖动，状态实时可控",
        ],
        shot_name=["verify-active.png", "verification-active.png"],
        shoot_width=1120,
    ),
    "server": dict(
        out_name="card-server.png",
        eyebrow="LOCAL SERVER",
        title="本地服务器",
        subtitle="数据自持，内网环境也能稳定运行",
        bullets=[
            "单文件 exe 免安装，双击即可启动服务",
            "本地 REST API + SQLite，端口 8765",
            "一键备份 / 恢复数据库，附完整性校验",
        ],
        shot_name=["server-console.png", "server.png"],
        shoot_width=1120,
    ),
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", choices=["hero", "features", "suite", *CARDS.keys()])
    parser.add_argument("--readme", action="store_true", help="also write max-1400px copies under build/promo/readme")
    args = parser.parse_args()

    if not RAW.exists():
        print(f"no raw captures at {RAW}; run the render_promo_* tools first")
        return 2

    produced = 0
    if args.only in (None, "hero") and compose_hero():
        produced += 1
    if args.only in (None, "features") and compose_features():
        produced += 1
    if args.only in (None, "suite") and compose_suite():
        produced += 1
    for key, config in CARDS.items():
        if args.only in (None, key) and compose_card(**config):
            produced += 1

    print(f"{produced} promo image(s) written to {OUT}")
    if args.readme:
        readme = OUT / "readme"
        readme.mkdir(parents=True, exist_ok=True)
        for path in sorted(OUT.glob("*.png")):
            with Image.open(path) as image:
                if image.width > 1400:
                    height = round(image.height * 1400 / image.width)
                    image = image.resize((1400, height), Image.LANCZOS)
                image.convert("RGB").save(readme / path.name)
        print(f"readme-sized copies written to {readme}")
    return 0 if produced else 1


if __name__ == "__main__":
    raise SystemExit(main())
