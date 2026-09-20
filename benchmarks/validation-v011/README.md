# Invarune 0.11 validation evidence

The release provides the `invscan` CLI, comprehensive offline help with topic navigation and examples, default guarded Headroom optimization for optional AI review, and a revised scan-report layout. These are finite implementation tests, not a claim of zero false positives/negatives or a security certification.

- **765 tests passed** on Python 3.12.14 with PDF dependencies. Python 3.9.6 ran the same suite with **28 explicit optional-PDF skips**, no failures/errors.
- Parent-process coverage: **6,733/7,119 statements (94.58%)**, **3,066/3,422 branches (89.60%)**, **92.96% combined**, no exclusions.
- **43 actual quickstart steps** passed in a fresh clone and venv. All three installed CLI names ran outside the checkout; source/image PDF editing and fresh justification import succeeded.
- **72 loopback requests across all six API/gateway protocols** used actual Headroom, and captured payloads matched the original JSON digests and exact source evidence. This is transport validation, not live vendor validation.
- Actual Headroom SDK proof preserved **1,002 synthetic cases and 20 real security-review payloads**, with no runtime network/process attempts. Actual request evidence shrank 5.76% for the HTTP baseline and 5.58% for the CLI baseline; token counts and billing were not measured.
- Eight actual deterministic CLI scans covered four fixtures, with identical paired four-format reports. Actual limited Codex review returned two finding answers and three additional concerns with fix guidance, while static fields and SARIF remained unchanged. Nine findings were outside its cap; controls were not requested in that live run.
- Claude remains unauthenticated; no new Claude review is claimed. All package/help/default static paths work without any model login.
- **All eight CI jobs passed** at implementation commit `17b1e7b`, covering Windows, macOS, three Linux Python versions, built images, package/report/schema checks and real Headroom. Windows passed 765 tests with 36 explicit skips and a narrower 28-step quickstart; Linux Headroom passed 36 steps including 72 requests with PDF excluded.
- The **published release wheel and PDF** were downloaded back and hash-verified. Installing that downloaded wheel in another fresh environment passed version, complete help, examples and a safer source scan outside the checkout.

[Unit/coverage/wheel receipt](test-receipt.json) · [quickstart receipt](../quickstart-v011/README.md) · [Headroom proofs](../token-optimization-v011/README.md) · [paired deterministic scans](fixture-receipt.json) · [actual Codex/Headroom scan](live-provider-receipt.json) · [new reports](../../examples/reports/invscan-v011/README.md).

[PDF validation](pdf-receipt.json) · [eight-job CI receipt](ci-receipt.json) · [downloaded-release validation](release-receipt.json) · [download release](https://github.com/nimeshbuilds/agent-mcp-security/releases/tag/v0.11.0).

Reproduce with `python3 -m unittest discover -s tests -v`; the installed user commands are documented in the [CLI-first quickstart](../../docs/QUICKSTART.md). Install `.[ai,pdf]` on Python 3.10+ for the actual optional SDK/PDF paths. The existing source-pattern accuracy corpus remains unchanged; this release does not claim a new detector-accuracy result.
