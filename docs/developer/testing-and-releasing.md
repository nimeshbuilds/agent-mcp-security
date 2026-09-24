# Testing, packaging and release evidence

Validate the behavior your change affects, then use the broader release workflow when producing a distributable build. Keep each result tied to its inputs: unit tests, synthetic accuracy labels, installed CLI checks, public-project comparisons and live model reviews measure different things.

Commands below run from the repository root after the [development setup](../../CONTRIBUTING.md). Use new output directories for each run so earlier evidence remains intact. Nothing here requires executing an untrusted target repository.

## Focused development checks

| Changed area | Start with |
|---|---|
| Parser or detector | `tests.test_rules`, `tests.test_callflow_permissions`, `tests.test_instruction_extensions`, `tests.test_tool_effects`, the relevant language-accuracy suite, `tests.test_security_boundaries` |
| Traversal or path handling | `tests.test_scanner`, `tests.test_exclusion_identity`, `tests.test_analysis_profiles` |
| Images | `tests.test_image_archive`, `tests.test_image_assessment`, `tests.test_image_runtime`, `tests.test_image_cli` |
| Catalog and explorer | `tests.test_catalog`, `tests.test_catalog_explorer`, `tests.test_catalog_explorer_integration`, `tests.test_cli_usability` |
| Exceptions/import | `tests.test_review_policy`, `tests.test_review_workspace`, `tests.test_review_roundtrip_cli` |
| Report treatment and display | `tests.test_report_assessment`, `tests.test_remediation`, `tests.test_report_html`, `tests.test_report_pdf` |
| AI protocol/evidence | `tests.test_judge_integration`, `tests.test_analyst_protocol`, `tests.test_analyst_investigation`, `tests.test_evidence`, `tests.test_token_optimizer` |
| Benchmark publication/provenance | `tests.test_benchmark_v015_publication`, `tests.test_benchmark_dashboard`; preserve first blind results, source labels and presentation-only repeat identity |

For example:

```sh
python -m unittest tests.test_catalog tests.test_catalog_explorer tests.test_catalog_explorer_integration -v
python scripts/evaluate_accuracy.py --format markdown
```

The accuracy evaluator's default regression gate does not require every documented challenge case to pass. Read the reported false positives/negatives and suite denominators. Do not interpret an evaluator exit 0 as zero known mistakes. [Accuracy interpretation](../RULE_ACCURACY.md).

## Full suite and optional dependencies

```sh
python -m unittest discover -s tests -v
```

The dependency-free installation can skip optional PDF cases explicitly. To exercise the richer environment, install the QA pins and AI extra in the development environment, then rerun:

```sh
python -m pip install -r requirements-qa.txt
python -m pip install -e '.[ai]'
python -m unittest discover -s tests -v
```

`requirements-qa.txt` includes the tested PDF libraries, coverage and JSON Schema validation. The `ai` extra includes the pinned Headroom dependency on Python 3.10+; Python 3.9 retains the tested fallback. Installation can contact the configured package index. Ordinary tests use inert fixtures, local HTTP servers and controlled subprocesses; they do not contact paid model providers.

To capture branch coverage:

```sh
python -c "from pathlib import Path; Path('test-output').mkdir(exist_ok=True)"
python -m coverage run --branch --source=ai_security_scan -m unittest discover -s tests -v
python -m coverage report --show-missing
python -m coverage json -o test-output/coverage.json
```

This measures the instrumented parent process; separately spawned CLI interpreters do not automatically contribute coverage. Statement/branch percentages are implementation exercise measurements, not evidence that all security scenarios were tested.

## Installed workflows

The most direct reproduction of the documented installation path is:

```sh
python scripts/validate_quickstart.py --output test-output/developer-quickstart
```

The validator creates a fresh local Git clone, overlays its explicitly listed current-worktree inputs, creates a new environment and installs the package. It checks all three installed aliases from outside the checkout, source/image fixtures, review configuration, PDF export/import, catalog examples and loopback gateways. The receipt lists the exact snapshot files and hashes. Uncommitted changes in listed inputs are intentionally included; do not label that snapshot a pristine commit without checking the receipt.

On Python 3.10+ the full gateway portion verifies actual default Headroom use, captured JSON equality and preserved source evidence across finding/control requests. It does not log in, call a real model or start a target container. Package installation may use the network. `--skip-pdf` and `--skip-gateway` support narrower environments; disclose those omissions and their reduced step counts.

For the installed five-format review contract, with `invscan` on PATH and PDF dependencies installed:

```sh
python scripts/validate_report_review.py --command invscan --output test-output/developer-report-review
```

Use a new empty directory. The helper runs source and archive scans, edits canonical user fields, imports the reports and validates bound decisions, summaries and statuses. Fixture findings intentionally produce nonzero scan exits; the helper checks those expected codes instead of treating every nonzero result as a harness failure.

## Keep the scenario guide executable

The [ten-scenario guide](../SCENARIOS.md) is backed by [a command manifest](../../examples/scenarios/scenarios.json) and [an installed-workflow validator](../../scripts/validate_scenarios.py). Each walkthrough puts one command in each tagged fence. The validator checks all 59 command fences across the hub, setup page and ten walkthrough pages before execution, rejects missing/duplicate/moved/changed steps, and binds all 12 guide files to the executed snapshot. It then records observed exit codes, evidence assertions and explicit external prerequisites. A new CLI option must be mapped into the guide; an option's presence in the coverage table alone does not establish live service compatibility.

```sh
python scripts/validate_scenarios.py --check-docs-only
python scripts/validate_scenarios.py --output test-output/scenarios
```

Use a fresh output directory. The default scenario run installs optional PDF/AI dependencies in a new environment and exercises inert fixtures plus a loopback gateway. It does not authenticate to a real provider or pull a registry image. The separately recorded live CLI experiment and runtime prerequisites retain their own scope. [Recorded scenario results](../../benchmarks/scenarios-v015/README.md).

## Package and platform checks

Build a wheel in a fresh output directory:

```sh
python -m pip wheel --no-deps --wheel-dir test-output/developer-wheels .
```

Install that wheel into another clean environment and run from outside the repository. Use the exact filename printed by the build, not an old wheel selected by a broad wildcard. Check `invscan`, `invarune` and `ai-security-scan`; all must dispatch to the same `cli:main`. Catalog JSON files are packaged through `tool.setuptools.package-data`, so test explorer and report generation after installation, not only import/version.

[`tests.yml`](../../.github/workflows/tests.yml) currently separates ten jobs:

- Unit/workflow jobs on Linux Python 3.9, 3.12 and 3.14, macOS Python 3.12 and Windows Python 3.12.
- A Linux Python 3.12 installed Headroom/loopback quickstart job.
- A package/schema job covering wheel installation, aliases, review formats and SARIF validation.
- A Linux Docker built-image integration job.
- Two complete installed scenario-guide jobs on Linux and Windows, including PDF and six local gateway protocols.

The older Windows quickstart step deliberately skips PDF and gateway portions; the separate full scenario-guide job exercises both on Windows. Do not present that narrowed Windows recipe as the full optional-integration run. Preserve `.gitattributes` LF rules: historical SHA-256 receipts bind literal bytes, and CRLF conversion can invalidate evidence even when text looks identical.

The real image helper is Linux-oriented and needs a working Docker daemon:

```sh
python scripts/validate_image_scan.py
```

It builds an inert `FROM scratch` fixture with network disabled, exports/scans it and removes its temporary tag. It does not start the fixture container. Windows/macOS archive unit tests are useful but are not a substitute for this runtime/export integration.

`scripts/validate_sarif.py` validates reports against the pinned OASIS SARIF schema supplied with `--schema`. The helper does not download it; the CI workflow records the official URL and exact expected SHA-256. Preserve that digest check when reproducing the schema job.

The [v0.15 SARIF receipt](../../benchmarks/validation-v015/sarif-receipt.json) records 28 validated files with separate current-public, archived and local-workflow groups. Keep the exact input hashes and disclose whether reports are new executions or preserved artifacts. Schema conformance does not establish every semantic requirement or behavior in downstream consumers.

## Research, PDF and model validation

For a control-catalog change:

```sh
python scripts/sync_control_docs.py
python scripts/build_controlbook.py
python scripts/verify_controlbook.py
```

These update generated catalog documentation/PDF outputs; inspect the diffs. Text completeness checks do not establish readable page layout. Follow [PDF validation](../PDF_VALIDATION.md) for rendering, visual inspection and fillable-form requirements. PDF authoring dependencies in `requirements-pdf.txt` are distinct from the scanner's base runtime.

For an existing comparison artifact's input bindings:

```sh
python scripts/build_finding_comparison_report.py --validate-only
```

This validates recorded comparison inputs; it does not rerun scanners or models. A new external comparison needs new versioned output paths, pinned repositories/tool versions, native results, normalized predicates and disclosed disagreements. Follow [benchmark results](../BENCHMARK_RESULTS.md) and the [comparison evidence](../../benchmarks/comparison-v010/README.md). Do not overwrite an old ledger or count missing tool output as a negative finding.

Live model/official CLI checks are separate opt-in operations. Inspect the bounded helper first:

```sh
python scripts/validate_cli_providers.py --help
```

`--allow-live-requests` explicitly enables its real requests. Account authentication, entitlements, vendor versions and costs apply. A successful protocol/login check does not measure security judgment accuracy. A failed or unavailable provider stays recorded as such; it is not a successful adjudication. Source audits performed by an agent are not independent human ground truth. [Provider evidence](../CLI_PROVIDER_RESEARCH.md).

## Assemble a reviewable release

### Build standalone CLI downloads

The [installation guide](../INSTALLATION.md) offers ready-to-run downloads as well as Python package and source routes. Standalone builds include their Python interpreter, the catalog, PDF dependencies and Headroom. Official model-provider CLIs and container runtimes remain separate installations.

Use the packaging commit recorded in the native build manifest, or the current default branch. The original `v0.15.0` tag predates the standalone build tooling; the workflow checks that the scanner itself still matches that tag. Build on each target OS and architecture using Python 3.12 and the pinned release dependencies:

```sh
python -m pip install -r requirements-release.txt '.[ai,pdf]'
python scripts/build_standalone.py --output dist/standalone --work-dir build/standalone --expected-version 0.15.0
```

These are native builds, not cross-compilation. The [standalone workflow](../../.github/workflows/standalone.yml) runs on Linux x86-64/ARM64, macOS Intel/Apple Silicon and Windows x86-64. It verifies that the scanner and package metadata match the named release tag before building. Run it from GitHub Actions with the existing numeric release version, or use:

```sh
gh workflow run standalone.yml -f version=0.15.0
```

Each archive preserves the full application directory. On Unix, tar preserves the bundle's required symbolic links. Keep the directory intact; copying only the executable is not a supported installation. [PyInstaller's native bundle model](https://pyinstaller.org/en/stable/operating-mode.html) and [symbolic-link and child-process requirements](https://pyinstaller.org/en/stable/common-issues-and-pitfalls.html) explain these constraints.

The workflow validates the **extracted archive**, runs the CLI outside its source checkout with no Python executable on the child PATH, checks the documented workflows, and retains a validation receipt. Fixture preparation uses a separate controller Python process; the distributed CLI does not depend on it. Local scripted gateway responses test transport, Headroom and the evidence controller, not live model accuracy. Native subprocess handling also needs validation because bundled library search paths must not leak into external provider or image-runtime processes.

Release artifacts include each native archive, build manifest, validation receipt and `SHA256SUMS-standalone.txt`. Preserve the existing wheel/source/PDF assets and their original checksum file when adding standalone downloads to an existing release. The workflow has read-only repository permissions and uploads CI artifacts; publishing those tested files to a release is a separate maintainer action. Verify the release downloads again after upload. Native builds have recorded provenance and dependency versions, but are not claimed to be bit-for-bit reproducible or vendor-notarized.

The [0.15.0 native release evidence](../../benchmarks/standalone-v015/README.md) records all five extracted-archive executions, public-download checks, exact build provenance, prior failed attempts and the tested installation recipe.

1. Freeze the intended code/catalog/docs snapshot. Run focused checks, the full suite, the accuracy regression gate and installed workflows appropriate to the change.
2. Record commands, exit codes, optional skips, environment versions, source/input hashes and observed outcomes. Keep private paths, real credentials and proprietary evidence out of publication artifacts.
3. Build/install the wheel outside the checkout, validate report schemas and review replay, and check generated PDFs visually when changed.
4. Run the CI matrix for the actual candidate commit. A local run and a previous green commit do not stand in for that result.
5. Follow [publishing](../PUBLISHING.md) for versioned distribution and artifact handling. Verify downloaded release assets against the published hashes and test the downloaded wheel, not just the local build.
6. Link a new versioned receipt. Preserve prior receipts unchanged and state which measurements were reused versus freshly run.

The [0.12.0 validation receipt](../../benchmarks/validation-v012/README.md) records 793 tests, a 53-step fresh-install quickstart and eight passing CI jobs, with platform skips and measurement limits. Those are results for its recorded revision. A documentation-only contribution does not create a new detector-accuracy measurement, and a future release should report its own observed counts.
