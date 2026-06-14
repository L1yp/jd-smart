#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate Home Assistant brand images for the jd_smart (小京鱼) integration.

Outputs into custom_components/jd_smart/brand/:
    icon.png       256x256   (Integrations page)
    icon@2x.png    512x512   (hDPI)
    logo.png       landscape (config page header)
    logo@2x.png    landscape hDPI

The mark is the official 小京鱼 (com.jd.smart) app icon, downloaded from the
App Store CDN and converted/resized to the PNG sizes Home Assistant expects
(iOS-style rounded corners with transparent edges). If the download fails and a
previous brand/icon@2x.png exists, that is reused; otherwise it falls back to an
original fish motif so the script never hard-fails offline.

HA 2026.3+ auto-loads this brand/ folder via /api/brands/integration/jd_smart/*,
so no submission to the home-assistant/brands repo is needed.

Requires Pillow:  pip install Pillow
"""
from __future__ import annotations

import io
import os
import urllib.request

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
BRAND = os.path.join(HERE, "custom_components", "jd_smart", "brand")

# Official 小京鱼 app icon (App Store CDN). 1024x1024 master PNG.
APP_ICON_URL = (
    "https://is1-ssl.mzstatic.com/image/thumb/Purple112/v4/f8/7d/f1/"
    "f87df136-3b88-374e-67f5-1c8f1a3e5add/"
    "AppIcon-0-0-1x_U007emarketing-0-0-0-9-0-0-sRGB-0-0-0-GLES2_U002c0-512MB-85-220-0-0.png/"
    "1024x1024bb.png"
)

RED = (225, 37, 27, 255)      # JD red — fallback mark only
WHITE = (255, 255, 255, 255)
GREY = (96, 102, 112, 255)
RADIUS_FRAC = 0.2237          # iOS app-icon corner radius
SS = 8                        # supersample factor for the fallback fish


def _fish(d, cx, cy, scale, color=WHITE, eye=RED):
    bw, bh = 0.86 * scale, 0.54 * scale
    d.ellipse([cx - bw / 2, cy - bh / 2, cx + bw / 2, cy + bh / 2], fill=color)
    tx = cx - bw / 2 + 0.03 * scale
    tw, th = 0.34 * scale, 0.46 * scale
    d.polygon([(tx, cy), (tx - tw, cy - th / 2), (tx - tw, cy + th / 2)], fill=color)
    notch = 0.15 * scale
    d.polygon([(tx - tw, cy - th / 2), (tx - tw, cy + th / 2),
               (tx - tw + notch, cy)], fill=eye)
    d.polygon([(cx - 0.02 * scale, cy - bh / 2 + 0.02 * scale),
               (cx - 0.30 * scale, cy - bh / 2 - 0.16 * scale),
               (cx + 0.16 * scale, cy - bh / 2 + 0.02 * scale)], fill=color)
    ex, ey, er = cx + bw * 0.27, cy - bh * 0.12, 0.045 * scale
    d.ellipse([ex - er, ey - er, ex + er, ey + er], fill=eye)


def _fish_mark(size=1024):
    """Fallback original mark: JD-red square + white fish (opaque, square)."""
    S = size * SS
    img = Image.new("RGBA", (S, S), RED)
    _fish(ImageDraw.Draw(img), cx=S * 0.54, cy=S * 0.52, scale=S * 0.62)
    return img.resize((size, size), Image.LANCZOS)


def get_mark():
    """Return an opaque square RGBA master for the brand mark."""
    try:
        req = urllib.request.Request(APP_ICON_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            img = Image.open(io.BytesIO(r.read())).convert("RGBA")
        print("mark: official app icon (App Store CDN)")
        return img
    except Exception as e:  # noqa: BLE001 — offline / CDN change is non-fatal
        print("mark: download failed (%s)" % e)
    cached = os.path.join(BRAND, "icon@2x.png")
    if os.path.exists(cached):
        print("mark: reusing existing brand/icon@2x.png")
        return Image.open(cached).convert("RGBA")
    print("mark: falling back to original fish")
    return _fish_mark()


def round_corners(img, frac=RADIUS_FRAC):
    img = img.convert("RGBA")
    w, h = img.size
    mask = Image.new("L", (w, h), 0)
    ImageDraw.Draw(mask).rounded_rectangle(
        [0, 0, w - 1, h - 1], radius=int(min(w, h) * frac), fill=255)
    out = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    out.paste(img, (0, 0), mask)
    return out


def _load_font(paths, size):
    for p in paths:
        try:
            return ImageFont.truetype(p, size)
        except OSError:
            continue
    return None


def _darken(rgba, f):
    return (int(rgba[0] * f), int(rgba[1] * f), int(rgba[2] * f), 255)


def make_logo(mark_rounded, mark_raw, base=512):
    S = base
    pad = int(S * 0.05)
    side = S - 2 * pad
    m = mark_rounded.resize((side, side), Image.LANCZOS)
    img = Image.new("RGBA", (int(S * 4.2), S), (0, 0, 0, 0))
    img.paste(m, (pad, pad), m)
    d = ImageDraw.Draw(img)

    # tie the wordmark colour to the icon's background hue
    bg = mark_raw.convert("RGB").getpixel((mark_raw.width // 2, int(mark_raw.height * 0.06)))
    text_col = _darken((*bg, 255), 0.62)

    name_font = _load_font(
        [r"C:\Windows\Fonts\msyhbd.ttc", r"C:\Windows\Fonts\msyh.ttc",
         "/usr/share/fonts/truetype/noto/NotoSansCJK-Bold.ttc"], int(S * 0.42))
    sub_font = _load_font(
        [r"C:\Windows\Fonts\arialbd.ttf", r"C:\Windows\Fonts\msyh.ttc"], int(S * 0.17))

    tx = pad + side + int(S * 0.16)
    if name_font is not None:
        d.text((tx, int(S * 0.18)), "小京鱼", font=name_font, fill=text_col)
        if sub_font is not None:
            d.text((tx + 4, int(S * 0.66)), "JD Smart", font=sub_font, fill=GREY)
    bbox = img.getbbox()
    return img.crop(bbox) if bbox else img


def _save_h(img, h, path):
    w = max(1, round(img.width * h / img.height))
    img.resize((w, h), Image.LANCZOS).save(path)


def main():
    os.makedirs(BRAND, exist_ok=True)
    raw = get_mark()
    icon = round_corners(raw)
    icon.resize((512, 512), Image.LANCZOS).save(os.path.join(BRAND, "icon@2x.png"))
    icon.resize((256, 256), Image.LANCZOS).save(os.path.join(BRAND, "icon.png"))
    logo = make_logo(icon, raw)
    _save_h(logo, 256, os.path.join(BRAND, "logo@2x.png"))
    _save_h(logo, 128, os.path.join(BRAND, "logo.png"))
    print("wrote brand images to", BRAND)


if __name__ == "__main__":
    main()
