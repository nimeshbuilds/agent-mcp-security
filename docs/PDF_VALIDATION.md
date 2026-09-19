# Controlbook artifact validation

Verified 19 September 2026. Final artifact: `output/pdf/nimeshbuild-agent-mcp-security-controlbook.pdf`.

| Check | Result |
|---|---|
| Pages | 65 |
| Controls | 66 |
| Acceptance checks | 132 |
| Primary-source references | 75 |
| Research benchmark entries | 9 |
| Static-rule index | 42 rules |
| Control titles and acceptance text | All present in extracted PDF text |
| Source IDs and titles | All present |
| Source hyperlinks | All 75 source URLs embedded; 76 unique external links including the repository |
| Text outside page boundaries | None detected by PDF character-bounds inspection |
| Render review | All 65 pages rendered and visually inspected in contact sheets; updated contents, analyst workflow, dense cards, and source entries also reviewed at larger scale |

The final PDF uses an original vector NimeshBuild wordmark/motif, a navy/teal palette, embedded Arial text, clickable source references, a linked contents page, bookmarks, consistent page numbers, and spaces for assessment evidence. No third-party logo or full external standard is reproduced.

Build environment: Python **3.12.14**, ReportLab **4.4.9**, pypdf **6.10.0**, pdfplumber **0.11.9**, and Poppler rendering. Scanner version **0.2.0** tests passed independently on Python **3.9.6** and **3.12.14**: **153 tests**, no failures, errors, or skips. The added analyst page documents control routing, deterministic evidence and response validation, advisory outcomes, data transmission, and default budgets.

PDF SHA-256:

```text
2c77748f93c4721d701494b8107969509c0091f960f6647a344d980a756a82cd
```

Run `scripts/verify_controlbook.py` to verify the catalog and text/link relationships. Repeat rendering and visual inspection after any content, typography, or dependency change; this validation applies to the recorded artifact only.

This validates document completeness and layout. It does not validate an agent deployment, certify external-framework compliance, or claim that the referenced attack benchmarks were run. Draft, gated, release-page-only, and version-sensitive source limitations remain explicit in the source directory and source map.
