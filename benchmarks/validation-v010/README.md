# Invarune 0.10 validation evidence

Validated on 19 September 2026. These results describe finite, development-visible tests and the explicitly recorded installations; they do not establish zero false positives/negatives or universal framework/provider compatibility.

The later [portability follow-up](portability-receipt.json) adds four confinement regressions: **740 tests pass locally and all seven CI jobs pass** at `ee493b1`. Windows also passed its **17-step installed quickstart**, with PDF and gateway steps explicitly skipped. The 153 benchmark cases, 20 prepared model payloads, historical evidence bytes and production scanner fingerprint are unchanged. [Successful CI](https://github.com/nimeshbuilds/agent-mcp-security/actions/runs/35476883185). The measurements below retain the original release-validation scope.

- **736 tests passed** under Python 3.12.14 with optional PDF packages. Python 3.9.6 ran the same suite with **25 explicit PDF skips**, zero failures and errors.
- Coverage.py 7.16.1 measured **6,426 / 6,810 statements (94.36%)** and **2,929 / 3,274 branches (89.46%)**, combined **92.77%**. No exclusions. Parent-process coverage excludes separately exercised subprocess code.
- Five real deterministic CLI targets were scanned twice; all four report formats matched byte for byte. Fixture findings were 11 vulnerable, 0 safer, 9 open + 1 justified + 1 disabled reviewed, 3 image and 0 self-scan. All findings received static fix plans.
- The v0.10 wheel was installed and exercised outside the checkout. Twelve actual source/image scans covered initial reports and fresh review imports from HTML, Markdown, JSON, SARIF and PDF. All final outputs included the five report formats.
- **27 SARIF artifacts** passed the pinned official OASIS schema: seven fixture/provider reports, twelve installed review reports and eight fresh public-project reports.
- The 24-method PDF module passed with ReportLab 4.5.1 / pypdf 6.19.0, and again with lower-bound ReportLab 4.4.9 / pypdf 6.10.0.
- The [fresh quickstart](../quickstart-v010/README.md) executes 31 steps, including actual PDF editing/import and 72 loopback requests across six protocols. Loopback tests do not claim live vendor validation.
- A limited live Codex finding review returned concrete actions for two selected findings and three additional concerns. A separate live Codex control review returned one grounded check with actions and a valid source quote. Both ran through the real optional adapter; judgments remain unverified.
- The requested Claude full scan failed authentication, as did one blinded benchmark attempt. No Claude assessment or TP rate was generated. All deterministic evidence remains available.

[Unit/coverage/schema receipt](test-receipt.json) · [paired fixture receipt](fixture-receipt.json) · [provider/static-independence receipt](live-provider-receipt.json) · [actual grounded control-stage receipt](control-provider/codex_cli.json) · [installed five-format receipt](installed-review-receipt.json).

Reproduce the automated suite with `python3 -m unittest discover -s tests -v`. Install `.[pdf]` for PDF tests, or `requirements-qa.txt` for the pinned QA toolchain. Accuracy reproduction is documented in [RULE_ACCURACY](../../docs/RULE_ACCURACY.md); all 113 labels and known mismatches remain public in this repository. Live provider commands require the relevant official CLI and authorized account; the suite itself is offline/loopback.
