#!/usr/bin/env python3
"""Rebuild the original Invarune vector identity and PNG previews (Pillow needed)."""
from pathlib import Path
from html import escape

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs/assets/brand"
NAVY, MINT, PAPER, TEAL, MUTED = "#0B1220", "#35E3B1", "#F2F6FA", "#087E78", "#9BABBE"
POLYGONS = (
    ((26, 4), (8, 14), (8, 50), (26, 60), (26, 47), (19, 43), (19, 21), (26, 17)),
    ((38, 4), (56, 14), (56, 50), (38, 60), (38, 47), (45, 43), (45, 21), (38, 17)),
    ((32, 22), (42, 32), (32, 42), (22, 32)),
)


def glyph_svg(first, accent):
    return "".join('<polygon fill="{}" points="{}"/>'.format(
        color, " ".join(f"{x},{y}" for x, y in points))
        for points, color in zip(POLYGONS, (first, accent, accent)))


def svg(width, height, body, title):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
            f'role="img" aria-labelledby="title"><title id="title">{escape(title)}</title>'
            f'{body}</svg>\n')


def font(size, bold=False):
    candidates = [
        Path("/System/Library/Fonts/Supplemental") / ("Arial Bold.ttf" if bold else "Arial.ttf"),
        Path("/usr/share/fonts/truetype/liberation2") / ("LiberationSans-Bold.ttf" if bold else "LiberationSans-Regular.ttf"),
        Path("/usr/share/fonts/truetype/dejavu") / ("DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"),
    ]
    for path in candidates:
        if path.is_file():
            return ImageFont.truetype(str(path), size)
    raise RuntimeError("Install Arial, Liberation Sans, or DejaVu Sans to render PNG previews")


def glyph(draw, x, y, size, first=PAPER, accent=MINT):
    for points, color in zip(POLYGONS, (first, accent, accent)):
        draw.polygon([(x + a * size / 64, y + b * size / 64) for a, b in points], fill=color)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for theme, first, accent in (("dark", PAPER, MINT), ("light", NAVY, TEAL), ("mono", NAVY, NAVY)):
        (OUT / f"invarune-mark-{theme}.svg").write_text(
            svg(64, 64, glyph_svg(first, accent), "Invarune evidence mark"), encoding="utf-8")
        lockup = (f'<g transform="translate(8,8)">{glyph_svg(first, accent)}</g>'
                  f'<g fill="{first}" font-family="Arial, Liberation Sans, sans-serif">'
                  '<text x="91" y="47" font-size="42" font-weight="700">Invarune</text>'
                  '<text x="93" y="69" font-size="12" letter-spacing="1.4">BY NIMESHBUILD</text></g>')
        (OUT / f"invarune-logo-{theme}.svg").write_text(
            svg(300, 88, lockup, "Invarune by NimeshBuild"), encoding="utf-8")

    icon = Image.new("RGBA", (512, 512), (0, 0, 0, 0))
    glyph(ImageDraw.Draw(icon), 0, 0, 512)
    icon.save(OUT / "invarune-mark.png")
    tile = Image.new("RGB", (512, 512), NAVY)
    glyph(ImageDraw.Draw(tile), 64, 64, 384)
    tile.save(OUT / "invarune-avatar.png")

    hero = Image.new("RGB", (1600, 680), NAVY)
    d = ImageDraw.Draw(hero)
    # Quiet geometry keeps the mark readable at narrow README widths.
    d.polygon([(1190, 0), (1600, 0), (1600, 680), (1510, 680), (1110, 280)], fill="#101D2E")
    d.line([(1380, 0), (1180, 340), (1380, 680)], fill="#203346", width=2)
    glyph(d, 1265, 180, 255, "#233C4B", "#176050")
    d.text((88, 70), "NIMESHBUILD  /  SECURITY ENGINEERING", font=font(21, True), fill=MUTED)
    glyph(d, 75, 173, 158)
    d.text((258, 164), "Invarune", font=font(120, True), fill=PAPER)
    d.text((266, 305), "BY NIMESHBUILD", font=font(24, True), fill=MINT)
    d.line([(90, 399), (1100, 399)], fill="#263647", width=2)
    d.text((89, 441), "Evidence for agent security.", font=font(47, True), fill=PAPER)
    x = 90
    for label in ("AI AGENTS", "MCP SERVERS", "BUILT IMAGES"):
        width = int(d.textlength(label, font=font(20, True))) + 42
        d.rounded_rectangle((x, 552, x + width, 602), radius=8, outline="#365064", width=2)
        d.text((x + 21, 566), label, font=font(20, True), fill=MUTED)
        x += width + 16
    hero.save(OUT / "invarune-banner.png")
    print(f"Brand assets written to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
