# Controlbook artifact validation

Verified 19 September 2026. Final artifact: `output/pdf/nimeshbuild-agent-mcp-security-controlbook.pdf`.

| Check | Result |
|---|---|
| Pages | 64 |
| Controls | 66 |
| Acceptance checks | 132 |
| Primary-source references | 75 |
| Research benchmark entries | 9 |
| Static-rule index | 42 rules |
| Control titles and acceptance text | All present in extracted PDF text |
| Source IDs and titles | All present |
| Source hyperlinks | All 75 source URLs embedded; 76 unique external links including the repository |
| Text outside page boundaries | None detected by PDF character-bounds inspection |
| Render review | All 64 pages rendered and visually inspected; cover, dense cards, source entries, and assessment fields also reviewed at larger scale |

The final PDF uses an original vector NimeshBuild wordmark/motif, a navy/teal palette, embedded Arial text, clickable source references, a linked contents page, bookmarks, consistent page numbers, and spaces for assessment evidence. No third-party logo or full external standard is reproduced.

Build environment: Python **3.12.14**, ReportLab **4.4.9**, pypdf **6.10.0**, pdfplumber **0.11.9**, and Poppler rendering. Scanner tests passed independently on Python **3.9.6** and **3.12.14**: **91 tests**, no failures, errors, or skips.

PDF SHA-256:

```text
f580c742968fa6dfdc2d6953429c6b7781e2f02a7dbf47439c8fb0813d1b9f1c
```

Run `scripts/verify_controlbook.py` to verify the catalog and text/link relationships. Repeat rendering and visual inspection after any content, typography, or dependency change; this validation applies to the recorded artifact only.

This validates document completeness and layout. It does not validate an agent deployment, certify external-framework compliance, or claim that the referenced attack benchmarks were run. Draft, gated, release-page-only, and version-sensitive source limitations remain explicit in the source directory and source map.
