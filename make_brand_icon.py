#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate Home Assistant brand images for the jd_smart (小京鱼) integration.

Outputs into custom_components/jd_smart/brand/:
    icon.png       256x256   (Integrations page)
    icon@2x.png    512x512   (hDPI)
    logo.png       landscape (config page header)
    logo@2x.png    landscape hDPI

The mark is an ORIGINAL fish motif in JD red — not a copy of JD's trademarked
「小京鱼」logo. To use the official app icon instead, drop your own 256x256
icon.png / 512x512 icon@2x.png into the brand/ folder (they take priority).

Requires Pillow:  pip install Pillow
"""
from __future__ import annotations

import os
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
BRAND = os.path.join(HERE, "custom_components", "jd_smart", "brand")

RED = (225, 37, 27, 255)      # JD red  #E1251B
WHITE = (255, 255, 255, 255)
GREY = (90, 96, 104, 255)

SS = 8                         # supersample factor for smooth edges


def _fish(d: ImageDraw.ImageDraw, cx: float, cy: float, scale: float,
          color=WHITE, eye=RED) -> None:
    """Draw a stylized fish centered roughly on (cx, cy)."""
    bw, bh = 0.86 * scale, 0.54 * scale          # body width / height
    # body
    d.ellipse([cx - bw / 2, cy - bh / 2, cx + bw / 2, cy + bh / 2], fill=color)
    # forked tail (swept back, on the left)
    tx = cx - bw / 2 + 0.03 * scale
    tw, th = 0.34 * scale, 0.46 * scale
    d.polygon([(tx, cy),
               (tx - tw, cy - th / 2),
               (tx - tw, cy + th / 2)], fill=color)
    # notch the tail into a fork
    notch = 0.15 * scale
    d.polygon([(tx - tw, cy - th / 2),
               (tx - tw, cy + th / 2),
               (tx - tw + notch, cy)], fill=eye)   # carve with bg colour
    # dorsal fin (swept back, on top)
    d.polygon([(cx - 0.02 * scale, cy - bh / 2 + 0.02 * scale),
               (cx - 0.30 * scale, cy - bh / 2 - 0.16 * scale),
               (cx + 0.16 * scale, cy - bh / 2 + 0.02 * scale)], fill=color)
    # eye
    ex, ey, er = cx + bw * 0.27, cy - bh * 0.12, 0.045 * scale
    d.ellipse([ex - er, ey - er, ex + er, ey + er], fill=eye)


def make_icon(size: int) -> Image.Image:
    S = size * SS
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, S - 1, S - 1], radius=int(S * 0.225), fill=RED)
    # carve the tail-fork with the red background colour
    _fish(d, cx=S * 0.54, cy=S * 0.52, scale=S * 0.62, color=WHITE, eye=RED)
    return img.resize((size, size), Image.LANCZOS)


def _load_font(paths, size):
    for p in paths:
        try:
            return ImageFont.truetype(p, size)
        except OSError:
            continue
    return None


def make_logo(height: int) -> Image.Image:
    S = height * SS
    W = int(S * 3.4)
    img = Image.new("RGBA", (W, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # mark on the left: small red rounded square + white fish
    pad = S * 0.06
    sq = S - 2 * pad
    d.rounded_rectangle([pad, pad, pad + sq, pad + sq],
                        radius=int(sq * 0.225), fill=RED)
    _fish(d, cx=pad + sq * 0.54, cy=pad + sq * 0.52, scale=sq * 0.62)

    name_font = _load_font(
        [r"C:\Windows\Fonts\msyhbd.ttc", r"C:\Windows\Fonts\msyh.ttc",
         "/usr/share/fonts/truetype/noto/NotoSansCJK-Bold.ttc"], int(S * 0.46))
    sub_font = _load_font(
        [r"C:\Windows\Fonts\arialbd.ttf", r"C:\Windows\Fonts\msyh.ttc"],
        int(S * 0.20))

    tx = pad + sq + S * 0.18
    if name_font is not None:
        d.text((tx, S * 0.20), "小京鱼", font=name_font, fill=RED)
        if sub_font is not None:
            d.text((tx + S * 0.02, S * 0.66), "JD Smart", font=sub_font, fill=GREY)
    # trim transparent margins, then scale to target height
    bbox = img.getbbox()
    if bbox:
        img = img.crop(bbox)
    new_w = int(img.width * height / img.height)
    return img.resize((new_w, height), Image.LANCZOS)


def main() -> None:
    os.makedirs(BRAND, exist_ok=True)
    make_icon(256).save(os.path.join(BRAND, "icon.png"))
    make_icon(512).save(os.path.join(BRAND, "icon@2x.png"))
    make_logo(128).save(os.path.join(BRAND, "logo.png"))
    make_logo(256).save(os.path.join(BRAND, "logo@2x.png"))
    print("wrote brand images to", BRAND)


if __name__ == "__main__":
    main()
