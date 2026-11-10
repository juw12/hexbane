"""Draw the Hexbane app icons: a hexagon broken by a slash ("breaks the hex").

    python tools/make_icons.py

Writes web/icons/icon-192.png, icon-512.png and apple-touch-icon.png (180 px). The art keeps a
safe zone of about 20% so the icons can be used as maskable PWA icons.
"""

from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parent.parent
BACKGROUND = (15, 20, 32)      # matches theme_color #0f1420
HEX_BLUE = (96, 165, 250)      # brand blue
SLASH_GREEN = (52, 211, 153)   # "safe" green
SUPERSAMPLE = 4


def hexagon(cx: float, cy: float, radius: float) -> list[tuple[float, float]]:
    """Pointy-top hexagon corner points."""
    return [
        (cx + radius * math.cos(math.radians(angle)), cy + radius * math.sin(math.radians(angle)))
        for angle in range(-90, 270, 60)
    ]


def draw_icon(size: int) -> Image.Image:
    big = size * SUPERSAMPLE
    centre = big / 2
    image = Image.new("RGB", (big, big), BACKGROUND)

    # Soft blue glow behind the hexagon.
    glow = Image.new("RGB", (big, big), BACKGROUND)
    ImageDraw.Draw(glow).polygon(hexagon(centre, centre, big * 0.30), fill=(37, 72, 130))
    image = Image.blend(image, glow.filter(ImageFilter.GaussianBlur(big * 0.08)), 0.9)

    draw = ImageDraw.Draw(image)
    radius = big * 0.29
    ring = big * 0.055
    corners = hexagon(centre, centre, radius)
    draw.line(corners + corners[:2], fill=HEX_BLUE, width=round(ring), joint="curve")

    # The slash that breaks the hex, with a background-coloured halo so it reads as a cut.
    start = (centre - radius * 0.62, centre + radius * 0.52)
    end = (centre + radius * 0.62, centre - radius * 0.52)
    halo = round(ring * 2.3)
    draw.line([start, end], fill=BACKGROUND, width=halo)
    for point in (start, end):
        draw.ellipse([point[0] - halo / 2, point[1] - halo / 2, point[0] + halo / 2, point[1] + halo / 2], fill=BACKGROUND)
    stroke = round(ring * 1.15)
    draw.line([start, end], fill=SLASH_GREEN, width=stroke)
    for point in (start, end):
        draw.ellipse([point[0] - stroke / 2, point[1] - stroke / 2, point[0] + stroke / 2, point[1] + stroke / 2], fill=SLASH_GREEN)

    return image.resize((size, size), Image.LANCZOS)


def main() -> None:
    icons = ROOT / "web" / "icons"
    icons.mkdir(parents=True, exist_ok=True)
    for name, size in (("icon-192.png", 192), ("icon-512.png", 512), ("apple-touch-icon.png", 180)):
        draw_icon(size).save(icons / name, optimize=True)
        print("wrote", icons / name)


if __name__ == "__main__":
    main()
