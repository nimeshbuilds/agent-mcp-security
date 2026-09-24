# Ten scenario workflows — Invarune 0.15.0

These receipts accompany the [ten-scenario guide](../../docs/SCENARIOS.md), alongside the [quick start](../../docs/QUICKSTART.md). They measure executable product workflows on shipped inert examples, not production vulnerability accuracy or universal service compatibility. No scanner detector, catalog, package version or benchmark outcome changed for this documentation work.

## Installed command scenarios

**Passed: all 10 scenarios / 59 manifest command steps** on Python 3.12.14, macOS, with installed Invarune 0.15.0, Headroom 0.37.0, ReportLab 4.5.1 and pypdf 6.19.0. [Machine-readable execution receipt](receipt.json).

The final run verified all 11 tagged documentation blocks and all 65 flag spellings plus positional target against the parser. The API lab made **17 actual HTTP requests across six protocols**, including one controlled evidence follow-up. These were scripted local responses, with **zero real model calls** in the automatic runner. The independent live Codex test is below.

| Scenario | Passed command steps |
| --- | ---: |
| 01 Install, discover and ask offline | 18 |
| 02 Scan source and generate every report | 4 |
| 03 Select checks and find malicious skills or tools | 3 |
| 04 Constrain scope and recognize incomplete scans | 5 |
| 05 Inspect built image archives without running them | 4 |
| 06 Use CI gates and reviewed baselines | 4 |
| 07 Keep justified and disabled exceptions auditable | 1 |
| 08 Rescan edited reports in all five formats | 8 |
| 09 Exercise API gateways, optimization and bounded investigation | 10 |
| 10 Use authenticated provider CLIs and seamless interactive login | 2 |

Eight focused regression tests passed for documentation drift, exact flag boundaries, typed assertions and scripted gateway behavior. The source-code detector implementation remains unchanged. The receipt binds the guide snapshot at execution time; subsequent validation-result prose does not change its tested command blocks.


The [command manifest](../../examples/scenarios/scenarios.json) defines exact arguments, expected exits and assertions for every tagged recipe. The [validator](../../scripts/validate_scenarios.py) checks command drift and assigns every current CLI option to a scenario. The fresh local Git clone overlays the explicitly inventoried current-worktree inputs before installation; its base commit and file hashes are recorded. Installed commands execute from a separate directory containing only copied inert examples and report-editing helpers, with no importable scanner source package.

All deliberately nonzero exits are asserted: risky findings return 1; resource exhaustion, stale decisions, pending runtime validation and exhausted AI budgets return 2. Review imports must preserve finding IDs, evidence and severity, and record exceptions as justified rather than passed. A scripted gateway response is not a real security review.

## Real subscription CLI and unavailable providers

[Fresh external validation](external-receipt.json) records actual installed-CLI execution on 24 September 2026, separate from the loopback lab:

- Codex 0.154.0 was already signed in. Its default `gpt-6-astra` review completed in about 73 seconds with exit 0, one triage request and two control requests. It requested and received `delivery.py` lines 13–41, then produced one potential-gap and one insufficient-evidence answer. The deterministic findings/summary matched a fresh static baseline.
- Headroom 0.37.0 handled all three calls: 13,524 → 13,096 evidence-payload bytes. The 428-byte reduction is not a tokenizer or cost measurement.
- Claude 2.1.214 was installed but logged out. Grok 0.2.60 rejected its existing profile because active extensions/instructions violated the adapter's restrictions. Real attempts with each returned exit 2, retained static results and emitted four report formats. Neither is presented as successful live inference or browser sign-in.
- Docker and Podman were not installed on this local host. The receipt links the separately dated, successful actual Docker-built-image CI evidence. It does not claim a fresh local runtime export, Podman run or registry pull.

Model interpretations are advisory and were not independently adjudicated as vulnerabilities. Model access, login, provider versions, profiles and service availability can change. The automatic scenario runner never launches an account login or a real model request.

## Actual HTML editor and download

[Chrome form/download receipt](html-ui-receipt.json) records a real UI workflow, rather than scripted capsule edits. The test opened an installed-CLI report for `examples/vulnerable --scans AI002`, selected a finding justification, entered its reason/reviewer/evidence reference, and clicked **Download reviewed HTML**. The actual downloaded bytes were imported in a fresh scan of the same target and scope.

The result changed from exit 1 / one open finding to exit 0 / one justified finding. Finding identity, severity, location and source evidence stayed identical. The test did not mutate the DOM through injected JavaScript or use a report-capsule editing helper. This validates that browser path; it does not establish support in every browser or PDF viewer.

## Continuous checks and reproduction

```sh
python scripts/validate_scenarios.py --check-docs-only
python scripts/validate_scenarios.py --output test-output/scenarios
```

The full runner requires Git and Python 3.10+ and installs the AI/PDF extras into a fresh environment. It records its exact dependency versions. Package installation can use the configured package index; the scan examples themselves use only local files and the scripted loopback server. Source/report fixtures never execute target code or start target containers.

Linux and Windows scenario jobs are defined in [the test workflow](../../.github/workflows/tests.yml); the docs workflow also checks command drift before publication. Current execution status is available from [GitHub Actions](https://github.com/nimeshbuilds/invarune/actions/workflows/tests.yml). A configured job alone is not proof that a particular run passed; any recorded CI receipt names the exact commit and results.
