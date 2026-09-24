# Developer guide

These guides explain how Invarune works and how to change it without weakening its evidence or review boundaries. The installed entry point is `invscan`; `invarune` and `ai-security-scan` call the same `ai_security_scan.cli:main` function.

The scanner, offline explorer and optional security analyst serve different purposes:

| Component | What it does | What it does not establish |
|---|---|---|
| Deterministic scanner | Reads bounded source/configuration or a supported built Linux image and emits repeatable pattern findings. | Complete data flow, exploitability, runtime protection or compliance. |
| Offline explorer | Explains the bundled controls, acceptance checks, detectors and source relationships. | A scan result, a model judgment or a selected subset of rules to execute. |
| Optional analyst | Reviews selected findings and, in full mode, active acceptance checks using bounded evidence. | Verified deployment facts or authority to modify deterministic outcomes. |

## Start with the change you want to make

| Your change | Read first | Relevant entry points |
|---|---|---|
| Discover/select scans, change coverage docs | [Scan inventory and selection](scan-inventory.md) | `scan_catalog.describe_scans`, `scoring.build_scoring` |
| Add or refine a detection | [Detection algorithms](detection-algorithms.md) and [adding checks](adding-checks.md) | `analyzer.analyze_file`, `_Findings.add`, `rules.RULES` |
| Add research/control content | [Adding checks](adding-checks.md#add-a-control-source-or-explanation) | `data/controls.json`, `data/sources.json`, `data/control_explanations.json` |
| Explain a CLI or traversal result | [Architecture](architecture.md) | `cli.main`, `scanner.scan`, `fs.read_confined` |
| Change built-image analysis | [Architecture](architecture.md#built-image-pipeline) | `image_scan.scan_image`, `materialize_image`, `assess_image` |
| Change report fields or review behavior | [Reports and reviews](reports-and-reviews.md) | `write_reports`, `build_workspace`, `apply_review_workspace` |
| Integrate an API or official CLI | [AI adapters](ai-adapters.md) | `judge.review`, `judge.review_controls`, `cli_judge.run_cli` |
| Validate and distribute a release | [Testing and release](testing-and-releasing.md) | `unittest`, accuracy evaluator, wheel and workflow validators |

The Python functions described here are implementation boundaries used by this repository, not a promise of a separately versioned public SDK. The CLI, report schemas, finding identity and documented compatibility behavior have explicit tests.

## First local development loop

Follow [CONTRIBUTING](../../CONTRIBUTING.md) to create an environment and install the checkout in editable mode. Then inspect a control and run the inert comparison fixture:

```sh
invscan --ask 'What do you check for prompt injection?'
invscan --explain-control AUTH-01
invscan examples/safer --output test-output/developer-safer
python -m unittest tests.test_catalog_explorer tests.test_scanner -v
```

The explorer commands do not scan or call a model. The safer fixture is expected to return exit 0 with two selected files and no findings or gaps. A zero-finding fixture is a workflow check, not a proof of detector completeness.

Use a deliberate output directory: reports replace their own filenames. Keep evidence, generated reports and configuration outside a real target when practical. The scanner automatically excludes explicitly selected output/configuration paths, but arbitrary redirected stdout inside the target can still alter the input.

## Read the current evidence correctly

The [0.12 release receipt](../../benchmarks/validation-v012/README.md) records 793 tests, a 53-step fresh-install quickstart and eight passing CI jobs for the recorded revision. Platform-specific optional skips are disclosed. These numbers are historical measurements, not a target to copy into a new release note.

The [accuracy corpus](../RULE_ACCURACY.md), [public-project comparison](../BENCHMARK_RESULTS.md), [live-provider checks](../CLI_PROVIDER_RESEARCH.md) and [PDF verification](../PDF_VALIDATION.md) answer different questions. Keep their units, versions and limitations separate when evaluating a change.

For user-facing behavior, the [complete CLI reference](../CLI.md) and `invscan --help` remain the command reference. The [security explorer guide](../SECURITY_EXPLORER.md) describes readable lookup behavior; the [research directory](../RESEARCH.md) explains source provenance.
