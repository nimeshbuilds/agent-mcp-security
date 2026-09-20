# Invarune by NimeshBuild

**Invarune** is pronounced **IN-vuh-roon**. The name combines *invariant*, a property that stays consistent, with *rune*, a readable symbol. It connects repeatable checks with evidence that people can inspect. The name describes the product's approach; it does not claim that every risk can be decided deterministically.

**Tagline:** Evidence for agent security.

![Invarune identity](assets/brand/invarune-banner.png)

## Identity assets

The original geometric mark has two bounded sides and a central evidence diamond. It was drawn for this project, without copying an external logo. The vector masters scale without raster artifacts; PNG exports support repository previews and avatars.

| Asset | Use |
|---|---|
| [Dark-background logo](assets/brand/invarune-logo-dark.svg) | Light wordmark and mint mark on navy or other dark backgrounds |
| [Light-background logo](assets/brand/invarune-logo-light.svg) | Navy wordmark and teal mark on white or pale backgrounds |
| [Monochrome logo](assets/brand/invarune-logo-mono.svg) | Single-color printing |
| [Dark-background mark](assets/brand/invarune-mark-dark.svg) / [light-background mark](assets/brand/invarune-mark-light.svg) / [monochrome mark](assets/brand/invarune-mark-mono.svg) | Compact icon use |
| [Transparent PNG mark](assets/brand/invarune-mark.png) | Raster icon on dark backgrounds, 512 x 512 |
| [Avatar](assets/brand/invarune-avatar.png) | Square navy tile, 512 x 512 |
| [Banner](assets/brand/invarune-banner.png) | Repository or presentation hero, 1600 x 680 |

Use **Invarune** in prose, **invscan** for the command, and **by NimeshBuild** for parent-brand attribution. Keep at least one diamond-width of clear space around the standalone mark. Prefer a 24 px or larger mark. Preserve proportions and colors; use the supplied monochrome version when color is unavailable. The wordmark SVG uses Arial with Liberation Sans and sans-serif fallbacks; its lettering is editable text. The icon itself is entirely vector geometry.

| Color | Hex | Purpose |
|---|---|---|
| Ink navy | `#0B1220` | Dark surfaces and primary text |
| Signal mint | `#35E3B1` | Brand accent on dark surfaces |
| Paper | `#F2F6FA` | Pale surfaces and text on navy |
| Deep teal | `#087E78` | Brand accent on light surfaces |
| Muted steel | `#9BABBE` | Supporting text on navy |

Mint is an accent for dark surfaces; use deep teal for small text on light surfaces. Avoid using the mark as an assurance seal or implying endorsement by the organizations whose publications inform the control catalog.

## Rebuilding and compatibility

Run `python3 scripts/build_brand_assets.py` with Pillow installed and Arial, Liberation Sans, or DejaVu Sans available. This optional authoring step is separate from the dependency-free scanner. The [PDF builder](PUBLISHING.md) draws the same polygon geometry directly into the document.

Version 0.5.0 adds the `invarune` command while retaining `ai-security-scan`, `scan.py`, and `python3 -m ai_security_scan`. Both installed command names call the same implementation. The distribution name, repository address, JSON/SARIF machine tool name, rule IDs, and baseline format stay stable. Reports add a branded display name. Branding does not erase findings or change the deterministic severity gate.

The [name-screening record](BRAND_RESEARCH.md) documents dated searches, discarded names, and limitations. No trademark registration, domain purchase, or package-name reservation was performed.

Version 0.11.0 promotes `invscan` as the primary command. `invarune` and `ai-security-scan` remain equivalent compatibility aliases; the product name remains Invarune by NimeshBuild.
