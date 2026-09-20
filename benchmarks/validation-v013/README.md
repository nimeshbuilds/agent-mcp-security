# Invarune 0.13 validation evidence

This release combines benchmark-driven detector fixes with the Invarune repository identity and visual evidence dashboard. Production implementation SHA-256: `8d56fcf24bb47474196842268b3512ce8df00a81a3371f7fce63757fa1a8f309`.

- [Full local validation](test-receipt.json): **845 tests passed** on Python 3.12.14 with optional PDF packages. Python 3.9.6 passed the same suite with **29 explicit optional-PDF skips**. All final package files match the built wheel and installed-quickstart snapshot.
- [Installed quickstart](../quickstart-v013/README.md): **53 actual steps passed** in a fresh clone and environment, including all CLI aliases, source/image scans, edited PDF imports and **72 loopback requests across six protocols** using Headroom 0.37.0. No live provider or new authentication was involved.
- [Paired accuracy](../comparison-v013/before-after-accuracy.json): the same **113 corpus cases** changed from **55 TP / 51 TN / 2 FP / 5 FN** to **58 TP / 52 TN / 1 FP / 2 FN**. Four mismatches improved; no label or case was removed. These are development-visible rule-presence fixtures, not production vulnerability precision/recall.
- [Fresh scanner comparison](../comparison-v013/README.md): the same eight pinned projects and 4,120 exported files; **146 Invarune observations / 15 gaps**. All 32 source report files match both repeated executions. The complete cross-tool ledger contains 1,114 observations with explicit scope/status differences.
- Eight new source SARIF reports pass the pinned official OASIS 2.1.0 Errata 01 schema.
- [Nine-page PDF QA](pdf-receipt.json): every page rendered and visually inspected, all seven contents links and nine bookmarks resolve. The original brand mark, comparison charts and remaining limitations are visible.
- Fifteen dashboard provenance tests and deterministic regeneration check fixture labels/hashes, implementation binding, complete observation accounting and unsupported status handling. These checks prevent inconsistent artifacts from becoming promotional charts; they do not establish source vulnerability truth.

The detector changes have 22 paired/adversarial regression methods covering literal reflection, YAML scalar/anchor boundaries, downloaded shell command text, local requirement paths, explicit credential-source identifiers and placeholder tokens. Three interprocedural/guard limitations remain in the published corpus. Parser/coverage gaps are preserved.

Full-suite, wheel, CI and publication receipts accompany this release. Execution coverage is distinct from detector accuracy. Earlier validations remain in their original versioned directories. The 0.13 benchmark does not claim a successful Claude adjudication or confirmed public-project TP percentage.
