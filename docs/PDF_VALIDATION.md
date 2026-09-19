# PDF artifact validation

Verified 19 September 2026. Final artifact: `output/pdf/invarune-security-controlbook.pdf`.

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
| Render review | All 65 pages rendered and visually inspected in contact sheets; updated cover, analyst workflow, dense cards, and source entries also reviewed at larger scale |

The final PDF uses an original Invarune geometric mark and wordmark with NimeshBuild attribution, a navy/mint/teal palette, embedded Arial text, clickable source references, a linked contents page, bookmarks, consistent page numbers, and spaces for assessment evidence. No third-party logo or full external standard is reproduced. The cover and PDF metadata carry the Invarune name and "Evidence for agent security." tagline. The [brand kit](BRAND.md) provides reusable SVG/PNG assets and the [name research](BRAND_RESEARCH.md) records the preliminary collision checks.

Build environment: Python **3.12.14**, ReportLab **4.4.9**, pypdf **6.10.0**, pdfplumber **0.11.9**, and Poppler rendering. The controlbook rebuilt byte-identically during the scanner version **0.8.0** release. Scanner tests and packaging are recorded separately in [implementation validation](VALIDATION.md). The analyst page documents control routing, deterministic evidence and response validation, advisory outcomes, data transmission, and default budgets.

PDF SHA-256:

```text
ecd12ee5d9c4ab70cfebe4f34db1a91747fa6d87df3ff4b97dc5af080d20061b
```

Run `scripts/verify_controlbook.py` to verify the catalog and text/link relationships. Repeat rendering and visual inspection after any content, typography, or dependency change; this validation applies to the recorded artifact only.

This validates document completeness and layout. It does not validate an agent deployment, certify external-framework compliance, or claim that the referenced attack benchmarks were run. Draft, gated, release-page-only, and version-sensitive source limitations remain explicit in the source directory and source map.

## Comparative benchmark report

Final artifact: `output/pdf/invarune-benchmark-report.pdf`, **6 pages**. The original Invarune mark, NimeshBuild attribution, navy/teal palette, embedded fonts and consistent page numbers accompany an executive summary, eight-project comparison table, exact tool scope, manual triage, mitigation layers, ten shared development fixtures and reproduction links.

The document is built from the final v0.8.0 receipts: eight pinned public projects, 149 review candidates and 15 coverage gaps. It distinguishes actual source scans from Cisco's partial offline metadata check and tools researched but not executed. No finding-count ranking or production accuracy claim is made.

All six pages were rendered and visually inspected; the comparison and manual-triage tables were also inspected at larger scale. PDF character-bounds inspection found no text outside pages. All pages contain extracted text, with **19 unique external links**. The existing controlbook's 65 pages were rendered and visually reviewed again in the same release. These checks cover the recorded PDFs, not every rendering engine.

Benchmark PDF SHA-256:

```text
9aa60a8ffd353a451aa3c2da2b7293b69c6f9f7ba6400fed60099126f6f98f78
```

Rebuild using `python3 scripts/build_benchmark_report.py` and repeat rendering and visual inspection. See [publication instructions](PUBLISHING.md) and the [detailed benchmark evidence](BENCHMARK_RESULTS.md).
