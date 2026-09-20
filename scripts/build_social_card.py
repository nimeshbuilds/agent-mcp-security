#!/usr/bin/env python3
"""Render Invarune's original code-defined brand as a 1280x640 social card."""
from pathlib import Path

from PIL import Image, ImageDraw
from build_brand_assets import NAVY, MINT, PAPER, MUTED, font, glyph

ROOT = Path(__file__).resolve().parents[1]


def main():
    image = Image.new("RGB", (1280, 640), NAVY)
    draw = ImageDraw.Draw(image)
    draw.polygon([(920, 0), (1280, 0), (1280, 640), (1110, 640), (810, 220)], fill="#102331")
    for x in range(965, 1350, 90):
        draw.line([(x, 0), (x - 270, 640)], fill="#193341", width=1)
    glyph(draw, 1024, 244, 168, "#204652", "#137164")
    draw.text((72, 56), "NIMESHBUILD / SECURITY ENGINEERING", font=font(17, True), fill=MUTED)
    glyph(draw, 63, 127, 104)
    draw.text((191, 122), "Invarune", font=font(90, True), fill=PAPER)
    draw.text((197, 227), "EVIDENCE FOR AGENT SECURITY", font=font(18, True), fill=MINT)
    draw.line([(72, 295), (927, 295)], fill="#2a4351", width=2)
    draw.text((72, 333), "One command. Evidence you can inspect.", font=font(30, True), fill=PAPER)
    draw.rounded_rectangle((72, 398, 856, 474), radius=12, fill="#112c38", outline="#32666b", width=2)
    draw.text((96, 418), "$ invscan ./my-agent", font=font(28, True), fill=MINT)
    draw.text((74, 522), "AI AGENTS  /  MCP SERVERS  /  SOURCE + BUILT IMAGES", font=font(17, True), fill=MUTED)
    draw.text((74, 564), "github.com/nimeshbuilds/invarune", font=font(17), fill=PAPER)
    path = ROOT / "docs/assets/brand/invarune-social.png"
    image.save(path, optimize=True)
    print(path.relative_to(ROOT))


if __name__ == "__main__":
    main()
