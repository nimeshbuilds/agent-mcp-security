# Standalone CLI release validation — Invarune 0.15.0

The [release downloads](https://github.com/nimeshbuilds/invarune/releases/tag/v0.15.0) provide native `invscan` distributions with a private Python runtime, PDF export/import, Headroom and inert examples. Follow [Download or build](../../docs/INSTALLATION.md) for the installation recipes. No scanner detector, catalog, score, or benchmark result changed in this packaging work.

## Five tested native targets

**All five platform jobs and the release-assembly gate passed** in [native build run 36041416239](https://github.com/nimeshbuilds/invarune/actions/runs/36041416239), at packaging commit [`e869d467`](https://github.com/nimeshbuilds/invarune/commit/e869d467f3cd12e0af165b5c914c0df56817d7d0). The workflow verifies that `ai_security_scan` and `pyproject.toml` exactly match the original `v0.15.0` tag. The tag predates the native packaging tools; reproduce these builds from the recorded packaging commit.

| Build/test host | CPU | Scenario steps | Native CLI invocations | Result |
|---|---|---:|---:|---|
| Ubuntu 22.04 | x86-64 | 57 | 59 | Passed |
| Ubuntu 22.04 | ARM64 | 57 | 59 | Passed |
| macOS 15 | Apple Silicon | 57 | 59 | Passed |
| macOS 15 | Intel | 57 | 59 | Passed |
| Windows Server 2022 | x86-64 | 57 | 59 | Passed |

Each job builds on its own architecture, extracts the actual distribution archive, copies the complete application outside the source checkout, and executes it with an isolated home and **no Python on the scanner's PATH**. A separate controller uses Python only for test orchestration and fixture utilities. These are tested hosts, not claimed minimum OS versions or evidence for every desktop configuration.

The [aggregate build receipt](standalone-release-validation.json) binds the exact five archive hashes, source snapshot, build commit and workflow. The release includes each target's detailed `.build-manifest.json` and `.validation.json`, plus a separate `SHA256SUMS-standalone.txt`. Assembly rejects a missing platform, failed validation, changed archive, dirty build or differing source snapshot.

## What actually ran

The native validator uses the [ten-scenario command manifest](../../examples/scenarios/scenarios.json). It omits the two historical Python-package aliases, `invarune` and `ai-security-scan`, because native archives provide `invscan`. The remaining **57 manifest steps include 55 native invocations**; the other two steps are controller utilities. Four additional native invocations exercise external process compatibility, both TLS trust cases and Unicode output, giving **59 native invocations per platform**.

- Offline version, comprehensive help, scan/control/source inventories and security questions.
- Terminal-only and selected source/skill scans, scoped resource limits, intentional findings and incomplete-result exits.
- Saved image archives, CI thresholds, baselines, justified/disabled exceptions and stale-decision rejection.
- HTML, JSON, Markdown, SARIF and PDF exports; edited decisions imported from all five formats with finding identity, evidence and severity preserved.
- **17 real loopback HTTP requests across six protocol adapters** per platform, actual default Headroom use, and one bounded evidence follow-up. Responses are explicitly scripted fixtures; there are zero real model calls or provider logins.
- HTTPS against a temporary local CA: explicit `ca_file` succeeds; an untrusted certificate fails before an HTTP payload is sent. Both paths retain deterministic findings.
- A real external native Git version subprocess, routed through the provider adapter and correctly rejected as an unsupported provider version. This proves child-process compatibility, not vendor login or inference.
- A non-ASCII target path and filename, with piped terminal output decoded as strict UTF-8.

PDF form edits here are controller edits, not a claim of browser/PDF-viewer interaction. The separately recorded [actual HTML editor test](../scenarios-v015/README.md#actual-html-editor-and-download), [live provider experiments](../scenarios-v015/README.md#real-subscription-cli-and-unavailable-providers), and [Docker integration](../scenarios-v015/ci-receipt.json) retain their own scope. Native release validation does not execute target code, start containers, authenticate to accounts or measure model security judgment.

## Published downloads and installation recipes

The [public-download verification](public-download-verification.json) records fresh HTTPS downloads of **all 17 new release assets**, with exact byte matches to the tested CI artifacts and all 16 entries in the standalone checksum file verified. Original wheel, source, PDF and checksum assets remain intact.

The [installation-recipe receipt](installation-recipe-verification.json) records execution of the **exact first four macOS/Linux shell blocks** in the installation guide on Apple Silicon: download, checksum verification, extraction, help/version, PATH setup, the first PDF report, offline question and scan inventory. The safer fixture yields 2 scanned files, 0 findings and exit 0. The [downloaded-archive execution receipt](downloaded-macos-arm64.validation.json) separately repeats the full 57-step/59-invocation native validation on the publicly downloaded Mac archive.

Windows and both Linux architectures were executed in native CI using extracted archives. The PowerShell `Invoke-WebRequest`/`Expand-Archive` installation recipe was reviewed but was not separately executed against the published downloads. The existing wheel's documented `[ai,pdf]` installation was also tested in a fresh Python 3.12 environment with version and offline-question checks.

## Failures retained and validation limits

The [first native attempt](https://github.com/nimeshbuilds/invarune/actions/runs/36040137176) and [diagnostic attempt](https://github.com/nimeshbuilds/invarune/actions/runs/36040742487) passed Linux and Windows but stopped on both Macs while the controller's loopback gateway awaited readiness. A longer wait alone did not resolve it. The final change removes unnecessary reverse DNS from the numeric loopback fixture; a regression test rejects any DNS lookup. Both Mac validations then passed. Earlier failed attempts are not counted as successful release evidence.

The separate [ten-job source/package CI run](https://github.com/nimeshbuilds/invarune/actions/runs/36041386992) passed after one Windows job retry. Its first attempt hit a 10-second Node timeout in an existing HTML-editor test; the retry ran unchanged code and passed. [CI run details and attempts](ci-validation.json). Host-specific optional skips remain in the job logs.

These archives are not Developer ID signed/notarized on macOS, and the Windows executable is unsigned. Installation instructions preserve operating-system protections and offer wheel/source alternatives. No compatibility claim is made for Alpine/musl, Windows ARM64, older untested operating systems, every provider CLI, or every enterprise trust policy. Build manifests inventory the build environment and bundled files; they are not a complete native-library SBOM or a claim of bit-for-bit reproducibility.

For build, test and publication commands, see [the developer release guide](../../docs/developer/testing-and-releasing.md#build-standalone-cli-downloads).
