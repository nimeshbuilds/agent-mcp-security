# Fresh deterministic invscan 0.11 reports

These scans ran through the installed `invscan` wheel outside the checkout, without enabling any model. Each target was scanned twice, and all four output formats matched byte for byte.

| Fixture | Open / justified / disabled | Expected exit | Report |
|---|---|---|---|
| Vulnerable source | 11 / 0 / 0 | 1 | [Markdown](source/report.md) |
| Safer source | 0 / 0 / 0 | 0 | [Markdown](safer/report.md) |
| Reviewed source | 9 / 1 / 1 | 1 | [Markdown](reviewed/report.md) |
| Built Linux image archive | 3 / 0 / 0 | 1 | [Markdown](image/report.md) |

Each directory includes HTML, Markdown, JSON and SARIF. These inert fixtures validate scanner/report workflows; counts are not production accuracy or security certification. [Actual paired-scan receipt](../../../benchmarks/validation-v011/fixture-receipt.json). For the redesigned fillable PDF with actual optional Codex and Headroom, see the [new live example](../invscan-v011/README.md).
