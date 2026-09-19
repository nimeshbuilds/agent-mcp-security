# Command-line reference

`ai-security-scan` performs bounded, read-only source triage and writes Markdown, JSON, and SARIF reports. The deterministic scan needs no model, credentials, network, or third-party Python package. The optional model analyst is enabled only with `--judge-config`.

The CLI identifies patterns that need review. A finding does not by itself prove exploitability, and no finding does not establish security, compliance, or complete control coverage. Consult the report's scope, skipped files, parse errors, limitations, and control statuses alongside its severity counts.

## Invocation

Requires Python 3.9 or newer. These entry points share the same flags and exit policy:

```sh
# From this repository, without installation:
python3 scan.py /absolute/path/to/agent-or-mcp-repo --output ./scan-report
python3 -m ai_security_scan /absolute/path/to/agent-or-mcp-repo --output ./scan-report

# After installing the package:
ai-security-scan /absolute/path/to/agent-or-mcp-repo --output ./scan-report

ai-security-scan --help
ai-security-scan --version
```

Use the absolute path to `scan.py` when invoking the script from another working directory. Relative target, output, baseline, and judge configuration paths resolve from the current working directory. Prefer absolute paths for automation. The target must be a real directory, not a symbolic link. The output directory must differ from the target root; it may be inside the target and is excluded from the scan automatically.

Long options require their complete spelling. Abbreviations such as `--judge-conf` are rejected to avoid selecting an unintended option.

## Scan scope and limits

| Argument | Default | Meaning |
| --- | --- | --- |
| `target` | Required for a scan | Repository directory to inspect. No target is accepted with a catalog inspection command. |
| `--exclude GLOB` | None | Additional relative-path exclusion; repeat to add patterns. Quote patterns so the shell does not expand them. |
| `--max-file-bytes N` | `1000000` | Maximum bytes in a single source file. Larger files are skipped with a coverage gap. |
| `--max-total-bytes N` | `50000000` | Total file-read budget. Rejected reads count toward it; failed reads are charged conservatively. Growth detection reserves one sentinel byte. |
| `--max-files N` | `20000` | Maximum number of source/configuration files to scan. |
| `--max-entries N` | `100000` | Maximum traversed directory and file entries. |

All deterministic scan limits must be positive integers. Limits are bounds, not a request to silently truncate coverage: hitting a limit produces an incomplete report and exit code 2. Default excluded directories, user exclusions, and unsupported file extensions are outside the selected scope. Symbolic links, unreadable files, unsupported encoding in selected files, parse errors, and other gaps remain visible in the reports.

```sh
ai-security-scan ./repository --exclude 'generated/*' --exclude 'fixtures/*'
ai-security-scan ./repository --max-file-bytes 2000000 --max-total-bytes 100000000
```

Glob matching is case-sensitive against relative paths; this is not a `.gitignore` parser. The scanner does not automatically interpret the target's `.gitignore` as a security policy. It does not install dependencies, execute target code, run the target's tests, probe deployed MCP endpoints, or query vulnerability feeds.

## Reports and exit policy

| Argument | Default | Meaning |
| --- | --- | --- |
| `--output PATH` | `scan-report` | Directory for `report.json`, `report.md`, and `report.sarif`. |
| `--fail-on LEVEL` | `high` | Gate on open findings at or above `critical`, `high`, `medium`, `low`, or `info`. `none` disables this severity gate only. |
| `--quiet` | Disabled | Suppress scan progress and human summaries. Operational and optional review errors remain on stderr. |
| `--summary-json` | Disabled | Emit one JSON summary on stdout instead of the human summary. Diagnostics remain on stderr. |

`--quiet` and `--summary-json` are mutually exclusive. Both keep the same findings, report artifacts, baseline handling, and exit gate as the default human output. Default deterministic runs with identical files, configuration, runtime, and scanner implementation are reproducible; enabling a model does not make model responses reproducible.

| Exit | Interpretation |
| --- | --- |
| `0` | The selected scan scope completed and no open deterministic finding reached the configured threshold. This is not a security or compliance pass. |
| `1` | Open deterministic findings meet the configured threshold. |
| `2` | Invalid input, operational failure, incomplete deterministic scan, requested judge failure, or incomplete control analyst review. This takes precedence over the finding gate. |

```sh
# Fail for medium, high, and critical open findings.
ai-security-scan ./repository --fail-on medium --quiet

# Keep findings in reports without a severity-based exit failure.
# Coverage gaps and operational failures still exit 2.
ai-security-scan ./repository --fail-on none

# Capture a JSON summary while retaining the command's exit status.
ai-security-scan ./repository --output ./reports --summary-json > ./summary.json
```

`summary.json` in the example is outside the target. Redirecting stdout into the source tree can change the scanned input; keep external summary captures outside the target or explicitly exclude them.

## JSON summary contract

`--summary-json` emits a single JSON object with sorted keys and schema version `1.0`. On a scan that produced reports, it contains:

| Field | Contents |
| --- | --- |
| `schema_version`, `type` | `"1.0"` and `"scan_summary"`. |
| `status` | `completed` or `incomplete`. A completed scan can still have findings and exit 1. |
| `tool`, `scan_id` | Scanner/runtime identity, implementation hash, and deterministic scan identifier copied from the report. |
| `summary` | The report's exact deterministic counts: open/suppressed findings, severity counts, scanned files, read/charged bytes, coverage gaps, and selected-scope completion. |
| `scope` | Resolved target path and exact scan configuration, including exclusions and resource limits. |
| `coverage` | Errors, skipped files/reasons, enabled rules, unmatched baseline IDs, limitations, control/check totals, statically mapped control count, and control status counts. |
| `optional_review.judge` | Whether finding triage was enabled, its status/mode, submission counts, and error if present. |
| `optional_review.analyst` | Whether full control review was enabled, its status, and detailed control/check/evidence/request coverage if present. |
| `execution` | Severity threshold, whether the deterministic finding gate triggered, and exit code. |
| `exit_code` | The command's exit code, convenient for CI consumers. |
| `reports` | Absolute paths under keys `json`, `markdown`, and `sarif`. |

Counts and statuses are copied or aggregated from the written report. Model opinions cannot alter deterministic severity, findings, or control statuses. `no_pattern_detected` means the applicable static patterns were not found, `findings_suppressed` means explicitly baselined findings exist, and runtime/manual statuses remain unresolved validation work.

If an operational error prevents normal completion, stdout still contains a JSON object with `status: "operational_error"`, a redacted error, `exit_code: 2`, and paths for reports already written, if any. It does not fabricate counts or claim that unwritten reports exist. Argument parsing errors—including incompatible flags—follow the standard CLI convention: explanatory stderr, exit 2, and no JSON document. Consumers must check the exit code and handle an empty stdout.

## Finding baselines

| Argument | Meaning |
| --- | --- |
| `--baseline PATH` | Load explicit finding IDs and nonempty justifications. Matched findings remain in reports with `suppressed` status. |
| `--write-baseline PATH` | Write a candidate baseline containing the current finding IDs. This does not suppress the current scan. |
| `--baseline-reason TEXT` | Required nonempty justification for a candidate baseline. |

```sh
ai-security-scan ./repository --write-baseline ./candidate-baseline.json \
  --baseline-reason 'Candidate for owner review; verify each finding before acceptance'

# After reviewing and editing the candidate to retain only accepted exceptions:
ai-security-scan ./repository --baseline ./reviewed-baseline.json --summary-json
```

The candidate writer includes all current findings. Review it before using it as an accepted baseline. An accepted finding is a documented decision, not evidence that the pattern is harmless. IDs depend on rule, relative path, line, and source evidence, so code changes can require a new review. Reports expose unmatched baseline IDs; unused exceptions do not silently remove different findings. Baseline files and the optional judge configuration are excluded from target scanning automatically.

## Rule and control inspection

These commands do not scan files, call a model, or require a target:

```sh
ai-security-scan --list-rules > ./rules.json
ai-security-scan --list-controls > ./controls.json
ai-security-scan --explain-rule AI002 > ./AI002.json
```

`--list-rules` preserves the full JSON rule array. `--list-controls` preserves the full JSON catalog array, including acceptance checks and primary-source mappings. `--explain-rule ID` emits rule metadata, severity, description, remediation, CWE references, rule source links, ruleset version, mapped control IDs, the mapped control records and their sources, and an explicit interpretation limit.

The three inspection modes are mutually exclusive, reject unknown rule IDs, and cannot be combined with a target, `--quiet`, or `--summary-json`. Their JSON output is already their result; they do not write scan report artifacts.

## Optional security analyst

| Argument | Default | Meaning |
| --- | --- | --- |
| `--judge-config PATH` | Disabled | Explicitly authorize bounded redacted payloads to the configured endpoint. Without this flag, no LLM is called. |
| `--judge-mode full\|findings` | `full` | Full mode triages findings and reviews every control, including controls without static findings. Findings mode triages findings only. |
| `--judge-include-source` | Disabled | Add neighboring source to finding triage; requires `--judge-config`. Full mode's separately bounded evidence selection does not depend on this flag. |
| `--judge-max-findings N` | `100` | Open findings submitted to finding triage; accepts 1–500. All findings remain in the deterministic report. |
| `--analyst-max-calls N` | `12` | Control-review request budget, 0–100. Finding triage uses one additional request. Zero leaves controls explicitly unreviewed. |
| `--analyst-batch-size N` | `6` | Controls per review request, 1–20. Smaller batches can need more calls. |
| `--analyst-max-files N` | `200` | Files considered for source evidence, 0–20000. |
| `--analyst-max-bytes N` | `2000000` | Source-evidence read budget, 0–50000000. |
| `--analyst-max-chars N` | `120000` | Retained redacted source characters, 0–1000000. |
| `--analyst-time-budget N` | `180` | Scheduling/time budget in seconds, greater than zero and at most 3600. This is not a hard process deadline. |

```sh
ai-security-scan ./repository --judge-config ./trusted-judge.json --summary-json
ai-security-scan ./repository --judge-config ./trusted-judge.json --judge-mode findings
ai-security-scan ./repository --judge-config ./trusted-judge.json \
  --analyst-batch-size 3 --analyst-max-calls 24 --analyst-time-budget 600
```

Full review currently covers all 66 controls and 132 checks. Every control is reviewed because even mapped static patterns provide only partial assurance. The model can identify contextual concerns or evidence gaps that deterministic patterns cannot resolve. Source selection, budgets, schema checking, evidence validation, and the absence of tool dispatch are deterministic boundaries; the model's security conclusions remain nondeterministic.

Unsupported claims and missing evidence stay unresolved. The analyst cannot turn code review into runtime validation, suppress findings, modify target files, or change the deterministic severity gate. Judge errors preserve deterministic report content and produce exit 2. The CLI reports incomplete analyst review on stderr even with `--quiet`.

See [JUDGE.md](JUDGE.md) for all native protocols, exact custom gateway URLs, environment-based credentials, TLS options, adapter limits, and API configuration. See [ANALYST.md](ANALYST.md) for control review routing, evidence budgets, validation, and uncertainty handling. The [test matrix](TEST_MATRIX.md) documents tested scenarios and remaining validation limits.
