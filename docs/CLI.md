# Invarune command-line reference

New to Invarune? Follow the [quick-start guide](QUICKSTART.md) for your first source or image report, optional AI review and expected results.

`invscan` performs bounded, read-only agent/MCP/skill and built-image triage. By default results appear in the terminal without creating report files. Explicit `--report`, `--output` or `--pdf` requests standalone reports. Deterministic source-directory and image-archive scans need no model, credentials, network, or third-party Python package. Image references use the selected container runtime; registry pulls require `--pull`. The optional model analyst is enabled only with `--judge-config` or `--judge-cli`.

The CLI identifies patterns that need review. A finding does not by itself prove exploitability, and no finding does not establish security, compliance, or complete control coverage. Consult the report's scope, skipped files, parse errors, limitations, and control statuses alongside its severity counts.

## Invocation

Requires Python 3.9 or newer. These entry points share the same flags and exit policy:

```sh
# Primary installed command (setup: see the quickstart):
invscan /absolute/path/to/agent-or-mcp-repo --output ./scan-report

invscan --help
invscan --version

# Compatibility entry points, if needed:
invarune /absolute/path/to/agent-or-mcp-repo --output ./scan-report
ai-security-scan /absolute/path/to/agent-or-mcp-repo --output ./scan-report
python3 -m ai_security_scan /absolute/path/to/agent-or-mcp-repo --output ./scan-report
python3 scan.py /absolute/path/to/agent-or-mcp-repo --output ./scan-report
```

The existing `invarune` and `ai-security-scan` commands remain supported aliases of `invscan`. All three call the same implementation. The package distribution remains `agent-mcp-security-scan` and the module remains `ai_security_scan`; no package or domain registration is implied by the product name.

Use the absolute path to `scan.py` when invoking the script from another working directory. Relative target, output, baseline, review, and judge configuration paths resolve from the current working directory. Prefer absolute paths for automation. The target must be a real directory, not a symbolic link. The output directory must differ from the target root; it may be inside the target and is excluded from the scan automatically.

Long options require their complete spelling. Abbreviations such as `--judge-conf` are rejected to avoid selecting an unintended option.

## Complete offline help

The installed CLI ships the complete reference in both `-h` and `--help`, including every option and default, the offline security explorer, numeric ranges, all input modes, supported file types and default exclusions, image formats and limits, report/exit behavior, baselines, review dispositions, editable five-format report import, optional PDF export, every judge configuration field, native/custom gateway JSON examples, and CLI examples including official login and model selection. The reference is included in the installed wheel; a source checkout or internet connection is not needed to read it.

```sh
invscan --help
invscan --help-topic images
invscan --help-topic gateways
invscan --help-topic security
invscan --examples

# Save the complete reference for review or offline distribution.
invscan --help > cli-help.txt
```

`--help-topic` selects all, quickstart, source, scans, skills, images, reports, review, baseline, ai, login, gateways, limits, exit-codes, catalog or security. The security and catalog topics explain the same offline explorer. `--examples` prints the complete command cookbook; `--help-topic all` matches `--help`.

Help exits 0 without scanning, unpacking images, starting runtime processes, loading a judge configuration, or contacting endpoints. `--version` prints the scanner version and exits. Tests check that every registered public option is documented, adapter/format inventories match implementation constants, example commands parse, and the displayed judge/baseline JSON is accepted by the actual loaders.

## Container-image input

Choose exactly one positional source directory, `--image REFERENCE`, or `--image-archive PATH`. Image mode inspects built **Linux** images without a source checkout and never starts a container. Hosts may be Linux, macOS, or Windows.

| Argument | Default | Meaning |
| --- | --- | --- |
| `--image REFERENCE` | None | Save and inspect an existing local image through the selected runtime. No implicit pull. |
| `--image-archive PATH` | None | Inspect a Docker-save or OCI-layout tar archive, optionally gzip-compressed; no runtime needed. |
| `--image-runtime docker\|podman` | `docker` | Runtime executable/store used by `--image`. |
| `--pull` | Disabled | Explicitly fetch the image before saving; requires `--image`. |
| `--image-platform OS/ARCH[/VARIANT]` | None | Select one platform; required when the archive would otherwise be ambiguous. |
| `--image-max-archive-bytes N` | `2000000000` | Export/archive and outer-archive expansion budget. Positive integer. |
| `--image-max-unpacked-bytes N` | `4000000000` | Cumulative expanded-layer data; separately bounds final materialized bytes. Positive integer. |
| `--image-max-entries N` | `500000` | Archive/layer headers and implicit-directory expansion. Positive integer. |
| `--image-max-layers N` | `200` | Maximum selected image layers. Positive integer. |
| `--image-timeout SECONDS` | `300` | Shared pull/export deadline; finite and greater than zero. Not an archive-analysis timeout. |

```sh
invscan --image my-agent:latest --output ./image-report
invscan --image my-mcp-server:latest --image-runtime podman
invscan --image ghcr.io/example/agent:1.2.3 --pull --image-platform linux/amd64
invscan --image-archive ./agent-image.tar --output ./image-report
```

Image exclusions are relative to the container filesystem root and apply to final packaged files and retained file revisions. Configuration/history/inventory/permission assessment remains separate. Binary-only images receive metadata checks; compiled logic, CVEs, signature trust and runtime deployment behavior are unassessed. See the [image guide](IMAGE_SCANNING.md) for archive compatibility, platform/runtime requirements, per-phase budgets, disk sizing, provenance, and binary-only scope reporting.

## Scan scope and limits

| Argument | Default | Meaning |
| --- | --- | --- |
| `target` | Required for source scans | Repository directory; omit with image inputs or help/version/catalog commands. |
| `--exclude GLOB` | None | Additional relative-path exclusion; repeat to add patterns. Quote patterns so the shell does not expand them. |
| `--max-file-bytes N` | `1000000` | Maximum bytes in a single source file. Larger files are skipped with a coverage gap. |
| `--max-total-bytes N` | `50000000` | Total file-read budget. Rejected reads count toward it; failed reads are charged conservatively. Growth detection reserves one sentinel byte. |
| `--max-files N` | `20000` | Maximum number of source/configuration files to scan. |
| `--max-entries N` | `100000` | Maximum traversed directory and file entries. |

All deterministic scan limits must be positive integers. Limits are bounds, not a request to silently truncate coverage: hitting a limit produces an incomplete report and exit code 2. Default excluded directories, user exclusions, and unsupported file extensions are outside the selected scope. Symbolic links, unreadable files, unsupported encoding in selected files, parse errors, and other gaps remain visible in the reports.

```sh
invscan ./repository --exclude 'generated/*' --exclude 'fixtures/*'
invscan ./repository --max-file-bytes 2000000 --max-total-bytes 100000000
```

Glob matching is case-sensitive against relative paths; this is not a `.gitignore` parser. The scanner does not automatically interpret the target's `.gitignore` as a security policy. It does not install dependencies, execute target code, run the target's tests, probe deployed MCP endpoints, or query vulnerability feeds.

## Select scans and inspect their algorithms

Use `invscan --list-scans` or `invscan --explain-scan AI043` for every rule and control, deterministic algorithms, supported input forms, source organizations, fixes and limits. Add `--catalog-format json` for machine-readable inventory. These are standalone offline commands.

`invscan TARGET --scans AI001,AI043 --scans AUTH-01` combines rule and control selectors. IDs are case-insensitive and deduplicated; unknown/empty IDs fail before scanning. Control selection enables its mapped rules and review plan; direct rule selection adds its mapped control plans without enabling additional rules. An unmapped control enables no static detectors. Shared bounded syntax, metadata and integrity checks still run and retain operational gaps. Reports, scoring, AI review and replay bindings record the exact selection. [Complete coverage guide](SCAN_COVERAGE.md).

## Reports and exit policy

| Argument | Default | Meaning |
| --- | --- | --- |
| `--output PATH` | Unset; terminal only | Directory for `report.html`, `report.json`, `report.md`, and `report.sarif`, plus `report.pdf` when requested. |
| `--report [DIR]` | Unset; supplied without DIR uses `scan-report` | Write HTML, Markdown, JSON and SARIF; mutually exclusive with `--output`. |
| `--pdf` | Disabled | Add a fillable PDF with charts, clickable contents and review fields; requires the optional `pdf` extra. Implies report output to `scan-report` when no output directory is supplied. Portable formats stay dependency-free. |
| `--fail-on LEVEL` | `high` | Gate on open findings at or above `critical`, `high`, `medium`, `low`, or `info`. `none` disables this severity gate only. |
| `--quiet` | Disabled | Suppress scan progress and human summaries. Operational and optional review errors remain on stderr. |
| `--summary-json` | Disabled | Emit one JSON summary on stdout instead of the human summary. Diagnostics remain on stderr. |

`--quiet` and `--summary-json` are mutually exclusive. Both keep the same findings, baseline handling, and exit gate; reports are written only when explicitly requested. With no reporting flag, no report files are created. Default deterministic runs with identical files, configuration, runtime, and scanner implementation are reproducible; enabling a model does not make model responses reproducible.

Open `report.html` locally for the complete branded report. It contains its styling, logo and a fixed CSP-hashed local script for saving review edits, with no external scripts/fonts/images or network requests. Reading and navigation work without the script; the Download reviewed HTML button needs it to preserve live form values. Markdown offers a portable equivalent, while JSON exposes the assessment for downstream automation. SARIF retains deterministic findings plus the editable review capsule.

HTML and Markdown start with the scan outcome, immediate concerns, affected files, accepted baseline risks, and coverage limitations. Repeated findings are grouped by rule, status, and image evidence context, with each location preserved. Critical findings receive review priority P0, high P1, medium P2, and low/info P3; these labels are ordering guidance, not deadlines or a numerical security rating. The action plan includes suggested ownership, direct remediation, and additional defense layers, each with expected benefit, verification work, residual limits, and source mappings.

Defense layers are recommendations marked `proposed_not_verified`. The scan does not assume they exist or reduce the finding's severity because they could exist. Baseline exceptions remain visible and do not count as remediation. Scope completion and zero findings do not establish that runtime or manual controls work. Image metadata, build history, retained-layer exposures, and current packaged-code findings retain their distinct contexts. Optional model assessments cannot change deterministic priority or the severity gate. See the [report guide](REPORTS.md) for the full interpretation and verification workflow.

| Exit | Interpretation |
| --- | --- |
| `0` | The selected scan scope completed and no open deterministic finding reached the configured threshold. This is not a security or compliance pass. |
| `1` | Open deterministic findings meet the configured threshold. |
| `2` | Invalid input, operational failure, incomplete deterministic scan, requested judge failure, or incomplete control analyst review. This takes precedence over the finding gate. |

```sh
# Fail for medium, high, and critical open findings.
invscan ./repository --fail-on medium --quiet

# Keep findings in reports without a severity-based exit failure.
# Coverage gaps and operational failures still exit 2.
invscan ./repository --fail-on none

# Capture a JSON summary while retaining the command's exit status.
invscan ./repository --output ./reports --summary-json > ./summary.json
```

`summary.json` in the example is outside the target. Redirecting stdout into the source tree can change the scanned input; keep external summary captures outside the target or explicitly exclude them.

## User review dispositions

`--review-report PATH` is mutually exclusive with `--review-config` and imports explicitly authorized user fields from HTML, Markdown, JSON, SARIF or a fillable scan PDF. A fresh source/image target is required. No target, model, credential, executable or registry pull is replayed from the report. Unchanged bindings can carry granular finding/check exceptions forward; stale decisions and explicit runtime/human follow-ups return exit 2. Use a new output directory. All fields, formats, bounds and examples are in the [review workflow](REVIEW_WORKFLOW.md) and offline `--help`.

`--review-config PATH` selects a trusted JSON file with `justified` or `disabled` entries keyed by rule ID, control ID, or individual `CONTROL:INDEX` check ID. It is optional and never auto-discovered. Justification requires a nonblank reason. Excluded items retain their evidence and user reason but contribute neither a pass nor a failure to active counts. Rule dispositions affect the finding gate; control/check dispositions affect the checklist and optional analyst queue only. Shared static analysis still collects evidence and reports parse/resource gaps.

See [the schema and full examples](REVIEW_CONFIGURATION.md), also included in `--help`. `--list-controls` includes `check_ids` alongside the original check text. Invalid policy files fail with exit 2 before scanning or model requests. The same policy applies to source and image scans.

## JSON summary contract

`--summary-json` emits a single JSON object with sorted keys and schema version `1.0`. On a scan that produced reports, it contains:

| Field | Contents |
| --- | --- |
| `schema_version`, `type` | `"1.0"` and `"scan_summary"`. |
| `status` | `completed` or `incomplete`. A completed scan can still have findings and exit 1. |
| `tool`, `scan_id` | Scanner/runtime identity, implementation hash, and deterministic scan identifier copied from the report. |
| `summary` | The report's exact deterministic counts: open/suppressed findings, justified/disabled finding counts when configured, severity counts, scanned files, read/charged bytes, coverage gaps, and selected-scope completion. |
| `assessment` | Compact deterministic executive `posture`, `metrics`, and guidance catalog provenance. The complete grouped findings, action plan, defense layers, sources, and unresolved validation work remain in `report.json`. |
| `scope` | Resolved source target path, or displayed image reference/archive basename, and exact scan configuration. |
| `image` | Present for image inputs: identity, acquisition, inventories, per-phase counters, analysis scope and explicit binary/CVE limits. |
| `coverage` | Errors, skipped files/reasons, enabled rules, unmatched baseline IDs, limitations, control/check totals, statically mapped control count, and control status counts. |
| `review_policy` | Present with `--review-config`: redacted user entries, policy hash, active and excluded counts, and assurance limits. `coverage.total_controls/total_checks` then use active denominators; separate `catalog_controls/catalog_checks` preserve full inventory totals. `statically_mapped_controls` counts active controls; `catalog_statically_mapped_controls` preserves its full-catalog counterpart. |
| `optional_review.judge` | Whether finding triage was enabled, its status/mode, submission counts, and error if present. |
| `optional_review.analyst` | Whether full control review was enabled, its status, and detailed control/check/evidence/request coverage if present. |
| `execution` | Severity threshold, whether the deterministic finding gate triggered, and exit code. |
| `exit_code` | The command's exit code, convenient for CI consumers. |
| `reports` | Absolute paths under keys `html`, `json`, `markdown`, and `sarif`. |

Counts and statuses are copied or aggregated from the written report. Model opinions cannot alter deterministic severity, findings, or control statuses. `no_pattern_detected` means the applicable static patterns were not found, `findings_suppressed` means explicitly baselined findings exist, and runtime/manual statuses remain unresolved validation work.

If an operational error prevents normal completion, stdout still contains a JSON object with `status: "operational_error"`, a redacted error, `exit_code: 2`, and paths for reports already written, if any. It does not fabricate counts or claim that unwritten reports exist. Argument parsing errors—including incompatible flags—follow the standard CLI convention: explanatory stderr, exit 2, and no JSON document. Consumers must check the exit code and handle an empty stdout.

## Finding baselines

| Argument | Meaning |
| --- | --- |
| `--baseline PATH` | Load explicit finding IDs and nonempty justifications. Matched findings remain in reports with `suppressed` status. |
| `--write-baseline PATH` | Write a candidate baseline containing the current finding IDs. This does not suppress the current scan. |
| `--baseline-reason TEXT` | Required nonempty justification for a candidate baseline. |

```sh
invscan ./repository --write-baseline ./candidate-baseline.json \
  --baseline-reason 'Candidate for owner review; verify each finding before acceptance'

# After reviewing and editing the candidate to retain only accepted exceptions:
invscan ./repository --baseline ./reviewed-baseline.json --summary-json
```

The candidate writer includes all current findings. Review it before using it as an accepted baseline. An accepted finding is a documented decision, not evidence that the pattern is harmless. IDs depend on rule, relative path, line, and source evidence, so code changes can require a new review. Reports expose unmatched baseline IDs; unused exceptions do not silently remove different findings. Baseline files and the optional judge configuration are excluded from target scanning automatically.

## Offline security explorer and catalog inspection

Ask what the bundled catalog covers before running a scan. All explorer commands work offline without a target, model, provider configuration or login. They read packaged catalog data only, do not fetch source URLs and do not write scan reports. A lookup is not an assessment of your code or deployment.

| Argument | Default output | Meaning |
| --- | --- | --- |
| `--list-topics` | Text | Control inventory grouped by security subject, with partial static mapping indicators. |
| `--ask QUERY` | Text | Bounded deterministic lookup using literal tokens and known aliases; quote multiword questions. |
| `--explain-control ID` | Text | Why a control matters, its checks, partial static mappings, source organizations and other validation needs. |
| `--explain-check CONTROL:INDEX` | Text | One acceptance check and its parent control context; index starts at 1. |
| `--list-sources` | Text | The 78-entry source registry with provenance and scope limits. |
| `--explain-source ID` | Text | Source details and control relationships, distinguishing primary citations from thematic alignment. |
| `--list-rules` | Legacy JSON | Full deterministic rule metadata array. |
| `--list-controls` | Legacy JSON | Full control array with acceptance checks, stable check IDs, rule mappings and sources. |
| `--explain-rule ID` | Legacy JSON | Rule metadata, mapped controls, sources and interpretation limits. |
| `--catalog-format text\|json` | Per-command above | Select output for one catalog command; cannot be used alone or with a scan. |

```sh
invscan --list-topics
invscan --ask 'What do you check for prompt injection?'
invscan --ask 'MCP authentication' --catalog-format json
invscan --ask 'What NSA and CISA guidance do you use?'
invscan --explain-control AUTH-01
invscan --explain-check AUTH-01:1
invscan --list-sources
invscan --explain-source JOINT-AGENTIC
invscan --explain-rule AI002 --catalog-format text

# Existing JSON consumers keep their original defaults and shapes.
invscan --list-rules > ./rules.json
invscan --list-controls > ./controls.json
invscan --explain-rule AI002 > ./AI002.json

# New commands provide deterministic rich JSON when explicitly selected.
invscan --explain-control AUTH-01 --catalog-format json > ./auth-control.json
```

`--ask` accepts at most **1,000 characters** and returns at most **eight ranked matches**. Ranking reflects literal catalog relevance, not confidence, exploitability or detector accuracy. It is not generative chat and cannot answer arbitrary security questions or inspect a repository. No-match responses are explicit; use `--list-topics`, narrower terms or exact IDs. Empty, invalid and oversized queries are errors.

Choose one catalog command. Explicit source/image inputs, scan options, model/login options and output controls such as `--quiet`, `--summary-json`, `--output` or `--pdf` are incompatible. Completed lookups, including no match, exit **0**; invalid input, unknown IDs in explain commands and incompatible options exit **2**. Neither exit is a security verdict.

All **66 controls / 132 checks** are explained, but the **47 deterministic rules map partially to 30 controls**. A mapped rule does not establish an individual check as passing. Runtime and owner validation remain necessary. Primary control citations, suggested thematic alignments and technical rule references are separate relationships; source versions and dates are stored research snapshots, not live verification or official compliance certification. See the [security explorer guide](SECURITY_EXPLORER.md) for a worked investigation.

## Optional security analyst

| Argument | Default | Meaning |
| --- | --- | --- |
| `--judge-config PATH` | Disabled | Explicitly authorize bounded redacted payloads to the configured API/gateway or official CLI. No model is called without this or --judge-cli. |
| `--judge-cli codex\|claude\|grok` | Disabled | Official CLI transport, mutually exclusive with config-file selection. Interactive scans sign in when needed, then resume. |
| `--judge-model MODEL` | Provider policy | With `--judge-cli`, override Astra / Opus / Grok Build defaults. Explicit `default` selects the vendor-configured model. |
| `--judge-executable PATH` | Vendor command on PATH | Trusted absolute executable or bare command name; for CLI scans or standalone login. |
| `--judge-cli-home PATH` | Existing Grok profile | Grok-only existing absolute `GROK_HOME`, for scan or login. Must pass extension inspection. |
| `--judge-timeout SECONDS` | `60` | CLI invocation deadline including probes, range 0.1–300; with `--judge-cli`. |
| `--judge-login auto\|never` | `auto` | Automatic official login only on interactive terminals. Quiet/JSON/noninteractive scans never prompt. One login attempt per scan. |
| `--login-timeout SECONDS` | `300` | Separate interactive login deadline, range 1–900. Excluded from analyst scheduling time. |
| `--login codex\|claude\|grok` | Disabled | Standalone official login from Invarune; no target, scan, report or model request. Requires terminal output. |
| `--judge-mode full\|findings` | `full` | Full mode triages findings and reviews every active selected control/check, including controls without static findings. Findings mode triages findings only. |
| `--judge-include-source` | Disabled | Add neighboring source to finding triage; requires `--judge-config` or `--judge-cli`. Full mode's separately bounded evidence selection does not depend on this flag. |
| `--judge-max-findings N` | `100` | Open findings submitted to finding triage; accepts 1–500. All findings remain in the deterministic report. |
| `--token-optimizer headroom\|compact\|off` | Config value, otherwise `headroom` | Lossless encoding of model evidence JSON; explicit flag overrides API or CLI JSON configuration. Requires `--judge-config` or `--judge-cli`. |
| `--analyst-investigation-rounds N` | `2` | Maximum evidence-request rounds per batch, 0–3. Zero uses seed excerpts only. Exact ranges must come from captured file IDs; no target execution or arbitrary paths/URLs. Requests and final conclusions share budgets. |
| `--analyst-max-calls N` | `36` | Shared control conclusion and evidence-request call budget, 0–100. One conclusion call is reserved per remaining batch. Finding triage uses one additional request. Zero leaves active controls explicitly unreviewed. |
| `--analyst-batch-size N` | `6` | Controls per review request, 1–20. Smaller batches can need more calls. |
| `--analyst-max-files N` | `200` | Files considered for source evidence, 0–20000. |
| `--analyst-max-bytes N` | `2000000` | Source-evidence read budget, 0–50000000. |
| `--analyst-max-chars N` | `120000` | Retained redacted source characters, 0–1000000. |
| `--analyst-time-budget N` | `600` | Scheduling/time budget in seconds, greater than zero and at most 3600. This is not a hard process deadline. |

```sh
invscan ./repository --judge-config ./trusted-judge.json --summary-json
invscan ./repository --judge-config ./trusted-judge.json --judge-mode findings
invscan ./repository --judge-config ./trusted-judge.json \
  --analyst-batch-size 3 --analyst-max-calls 24 --analyst-time-budget 600
```

Enabled AI review defaults to guarded Headroom 0.37.0 lossless JSON compaction; install it with `python -m pip install '.[ai]'` on Python 3.10+. The profile preserves all evidence and does not invoke a model, summarize source or add retrieval tools. Python 3.9, missing/unsupported Headroom or optimizer failure uses built-in compaction with a visible fallback receipt. `--token-optimizer compact` chooses the built-in encoder; `--token-optimizer off` keeps spaced JSON. The same `token_optimizer` field works in API and CLI JSON configs, and the explicit flag takes precedence. Receipts measure evidence bytes, not billed tokens or cost. Installing optional packages never enables a model without `--judge-cli` or `--judge-config`.

The default full-review catalog contains 66 controls and 132 checks. Every active selected check is queued because even mapped static patterns provide only partial assurance; failed or exhausted review can leave checks unanswered. Explicit `--review-config` checklist exceptions are retained for audit and excluded from model requests and active review totals. The model can identify contextual concerns or evidence gaps that deterministic patterns cannot resolve. Seed selection, authorization of requested snapshot ranges, budgets, schema checking, evidence validation, and the absence of tool dispatch are deterministic boundaries; the model's security conclusions remain nondeterministic.

Unsupported claims and missing evidence stay unresolved. The analyst cannot turn code review into runtime validation, suppress findings, modify target files, or change the deterministic severity gate. Judge errors preserve deterministic report content and produce exit 2. The CLI reports incomplete analyst review on stderr even with `--quiet`.

See [JUDGE.md](JUDGE.md) for all native protocols, exact custom gateway URLs, environment-based credentials, TLS options, adapter limits, and API configuration. See [ANALYST.md](ANALYST.md) for control review routing, evidence budgets, validation, and uncertainty handling. The [test matrix](TEST_MATRIX.md) documents tested scenarios and remaining validation limits.
