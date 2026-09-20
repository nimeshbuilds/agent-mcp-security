# Invarune 0.14 validation

The released scanner adds skill/tool instruction checks, selective scans, a complete offline inventory, transparent metrics and terminal-only output by default. Final implementation SHA-256: `a10cff2be83ee83ef7f016e0d9644b42b2cc9869528a91763840970dc87765f1`.

- [Local tests](test-receipt.json): **925 tests passed** on Python 3.12.14; Python 3.9.6 passed with **30 explicit optional-PDF skips**.
- [Fresh installed quickstart](../quickstart-v014/README.md): **61 actual steps**, all CLI aliases, source/image/skill scans, exact selectors, terminal no-file behavior, editable PDF roundtrips and real Headroom integration with six loopback gateway protocols. This does not imply live model or Windows validation.
- [Repeated public scans and competitor comparison](../comparison-v014/README.md): eight pinned projects, 4,120 exported files, **146 Invarune patterns and 21 gaps**, with all 32 full reports matching two actual executions.
- [Unchanged 113-assertion corpus](../comparison-v014/accuracy-after.json): **58 TP / 52 TN / 1 FP / 2 FN**. The separate [81-case skill/tool corpus](../comparison-v014/skills-tools-accuracy.json) has **331 assertions: 40 TP / 288 TN / 0 FP / 3 FN**. These are authored source-pattern labels, not production vulnerability truth.
- [121-page controlbook QA](controlbook-receipt.json): all 46 rule algorithms/limits/remediations, 66 controls, 132 checks and 76 sources; clickable navigation and every page visually inspected.
- [Actual optional-model runs](../../examples/reports/v014/README.md): live Codex completed four finding reviews and twelve selected check answers (two potential gaps, ten insufficient evidence). The Claude sign-in failure and first Codex timeout are retained. All four runs have identical deterministic findings, controls and metrics.
- [PDF validation](skill-pdfs-receipt.json): all 97 pages across static, Claude-attempt and completed Codex reports visually reviewed; 80 editable fields in each match the bound review data. The [nine-page benchmark PDF](benchmark-pdf-receipt.json) is separately validated.
- [Built documentation](site-build-receipt.json): strict MkDocs build, local links, anchors, search and byte-preserved downloads checked. Browser inspection covered the dashboard's new skill chart, exhaustive scan guide and completed Codex HTML report.

Integration tests cover selected control/rule denominators, zero-detector review plans, source/image scope, stale justification bindings, terminal control-character injection, bounded local Markdown references, late metadata in large JSON, no target execution and model-independent static findings/gates. Runtime security and broader semantic/language attacks remain unresolved; the reports retain these limitations.
