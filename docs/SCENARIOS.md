# Ten end-to-end scenarios

Use these workflows after the [quick start](QUICKSTART.md). Each starts with a practical question, uses shipped examples, and tells you what result to expect. The examples target **Invarune 0.15.0**. They cover the product's feature groups; they do not imply that a static scanner can validate every security property of an application.

## Prepare once

Clone the repository and activate the environment using the [macOS/Linux or Windows quickstart instructions](QUICKSTART.md#1-install-the-cli-and-get-your-first-report). Run this guide from the repository root. The installation includes the primary `invscan` executable and the equivalent `invarune` and `ai-security-scan` aliases.

Install the optional packages in that same environment so PDF and Headroom examples work:

```sh
python -m pip install '.[ai,pdf]'
invscan --version
```

Expect `0.15.0`. Python **3.10+** is needed for the Headroom package; base scans support Python 3.9 with the built-in optimizer fallback. No example executes an agent, MCP server, skill instruction or image container. The local gateway lab returns scripted responses; the separately marked live CLI example sends the inert example source to your selected model provider.

Commands use relative paths and run one at a time in an activated shell. Scan exits **1** and **2** are deliberate in some scenarios. Do not join the whole guide with `&&` or treat every nonzero scan exit as a broken installation. In Bash/Zsh inspect `$?` immediately after a command; in PowerShell inspect `$LASTEXITCODE`. Most examples write to a separate `scan-report/scenarios/` directory. The bare `--report` demonstration writes directly to `scan-report`. Repeating report commands replaces those files. Scenario 8 deliberately creates a changed source copy and requires `scan-report/scenarios/08-changed-source` not to exist; use a fresh checkout or move your previous scenario output aside before repeating the full guide.

| Scenario | The question it answers | Prerequisites |
| --- | --- | --- |
| [1. Explore coverage offline](#1-explore-coverage-without-an-ai-account) | What does the scanner check, why, and according to whom? | Base CLI |
| [2. Scan source and read a report](#2-scan-an-agent-or-mcp-codebase-and-read-the-result) | What needs fixing, and how do I share the evidence? | PDF extra for PDF export |
| [3. Inspect skills and choose checks](#3-inspect-skills-and-select-exactly-what-to-scan) | Does this skill or tool description contain a supported malicious-instruction pattern? | Base CLI |
| [4. Control scope and resource limits](#4-control-scope-and-see-when-a-scan-is-incomplete) | What was included, excluded or left unresolved? | Base CLI |
| [5. Scan a built image](#5-scan-a-built-image-without-its-source-checkout) | What can be inspected from a packaged artifact? | No runtime for the included archive |
| [6. Gate CI and maintain a baseline](#6-gate-ci-and-record-a-reviewed-baseline) | How can CI fail on actionable findings while retaining accepted risks? | Base CLI |
| [7. Record scoped exceptions](#7-record-a-justification-or-disable-an-assessment-item) | How do I document an exception without calling it a pass? | Base CLI |
| [8. Edit a report and rescan](#8-carry-review-decisions-through-all-five-report-formats) | Can reviewers feed their decisions back into a fresh scan? | PDF extra for PDF import |
| [9. Connect an API or gateway](#9-connect-api-gateways-and-test-optional-review-locally) | How do protocols, optimizer settings and bounded review behave? | AI extra for actual Headroom; local lab needs no key |
| [10. Use a subscription CLI](#10-use-a-signed-in-cli-for-a-real-evidence-investigation) | Can an optional reviewer investigate missing source context using my CLI login? | An installed, supported vendor CLI and account |

## 1. Explore coverage without an AI account

Before scanning, learn what a check means. These commands use the bundled catalog: no model call, login, API configuration, file scan or generated report is involved. `--ask` is deterministic search, so it also works without agentic AI.

<!-- invscan-scenario:01 -->
```sh
invscan --version
invscan --help
invscan -h
invscan --help-topic all
invscan --examples
invscan --list-scans --catalog-format json
invscan --explain-scan AI043
invscan --list-rules
invscan --list-controls
invscan --explain-rule AI002
invscan --list-topics
invscan --ask 'How do you check prompt injection?'
invscan --explain-control AUTH-01
invscan --explain-check AUTH-01:1
invscan --list-sources
invscan --explain-source MITRE-ATLAS
invarune --version
ai-security-scan --version
```

Expect **47 deterministic rules**, **66 controls**, **132 acceptance checks** and **78 source records**. An explanation connects a scan to its control, supported input patterns, suggested fix and source organizations. A control mapping is partial detector coverage, not a compliance certification. Queries without a matching topic return an explicit no-match result.

`--help` is the complete offline reference; `--help-topic` narrows it, and `--examples` shows the cookbook. The legacy rule/control JSON commands remain useful to automation. [Explorer details](SECURITY_EXPLORER.md) · [Every scan and its limits](SCAN_COVERAGE.md).

## 2. Scan an agent or MCP codebase and read the result

Start with the inert safer and deliberately vulnerable source examples. The scanner reads their supported files; it never imports or runs them. Then export the full vulnerable fixture assessment to all five formats.

<!-- invscan-scenario:02 -->
```sh
invscan examples/safer
invscan examples/vulnerable --report scan-report/scenarios/02-source --pdf --summary-json  # Expected exit 1
invscan examples/safer --output scan-report/scenarios/02-safe --summary-json
invscan examples/safer --report --summary-json
```

The safer fixture has **2 scanned files, 0 findings and exit 0**. The full vulnerable fixture has **11 open findings and exit 1** with the default high-severity gate. Neither result proves deployed safety or exploitability.

Without an output flag, results and fix guidance print in the terminal and no report files are created. `--report DIR` and `--output DIR` save HTML, Markdown, JSON and SARIF. `--pdf` adds a fillable PDF; `--report` without a directory uses `scan-report`.

Open the saved HTML from your file manager. Read the executive summary, immediate concerns, exact finding locations, fix instructions, proposed mitigation layers and coverage gaps. The PDF adds charts, clickable navigation and review fields. JSON provides stable structured evidence; SARIF is for compatible code-review systems. The report intentionally has no overall security score. Mapping reach and review completion describe coverage, not verified safety; accepted exceptions are removed from active denominators without earning pass credit. AI review adds advisory outcomes and its own completion figures rather than a higher security grade. [Reading reports and metrics](REPORTS.md).

## 3. Inspect skills and select exactly what to scan

Use the risky skill fixture to exercise supported instruction overrides, sensitive-transfer directives, approval/concealment bypasses and contradictory read-only tool annotations. These are risk-pattern detections, not a universal judgment of intent.

<!-- invscan-scenario:03 -->
```sh
invscan examples/vulnerable --scans AI001,AI002 --summary-json  # Expected exit 1
invscan examples/vulnerable --scan GOV-01 --summary-json
invscan examples/skills/risky --scans AI043,AI044,AI045,AI046 --report scan-report/scenarios/03-skills --summary-json  # Expected exit 1
```

Selecting **AI043–AI046** on the risky fixture yields **four findings and exit 1**. Comma-separated and repeated selectors combine; `--scan` is an alias for `--scans`. A direct rule selection does not silently enable other rules sharing its control.

Selecting **GOV-01** produces a review plan with **zero static detectors**. That is intentional: no matching finding does not mean the governance checks passed. Optional AI can review selected active checks later, but organizational or runtime evidence may still be missing.

Skill scanning includes recognized instruction files, bounded local Markdown references and supported associated code/configuration. Remote references, arbitrary prose semantics and runtime behavior remain outside the static guarantee. [Complete skill and tool scope](SCAN_COVERAGE.md).

## 4. Control scope and see when a scan is incomplete

For a large repository, scope should be deliberate and incomplete analysis visible. First exclude a known fixture file, then deliberately exhaust a small read budget.

<!-- invscan-scenario:04 -->
```sh
invscan examples/vulnerable --exclude requirements.txt --exclude Dockerfile --max-file-bytes 1000000 --max-total-bytes 5000000 --max-files 100 --max-entries 1000 --fail-on none --summary-json
invscan examples/safer --max-file-bytes 10 --fail-on none --summary-json  # Expected exit 2
invscan examples/safer --max-total-bytes 10 --fail-on none --summary-json  # Expected exit 2
invscan examples/safer --max-files 1 --fail-on none --summary-json  # Expected exit 2
invscan examples/safer --max-entries 1 --fail-on none --summary-json  # Expected exit 2
```

An exclusion changes selected scope; it is not a finding justification. Quote glob patterns so your shell does not expand them. Matching is case-sensitive against paths relative to the selected root; this is not a `.gitignore` parser.

Hitting a file, byte or traversal limit produces an explicit **coverage gap and exit 2**. `--fail-on none` cannot convert incomplete analysis into a successful scan. Inspect `scope`, exclusions and `coverage_gaps` before interpreting a zero-finding summary. Limits bound work; increasing them does not extend the supported language analysis. [All source limits](CLI.md#scan-scope-and-limits).

## 5. Scan a built image without its source checkout

The included Docker-save archive can be inspected on macOS, Linux or Windows without Docker or Podman. Image scanning never starts the target container.

<!-- invscan-scenario:05 -->
```sh
invscan --image-archive examples/images/demo-agent.tar --image-platform linux/amd64 --image-max-archive-bytes 10000000 --image-max-unpacked-bytes 20000000 --image-max-entries 1000 --image-max-layers 10 --report scan-report/scenarios/05-image --summary-json  # Expected exit 1
invscan --image-archive examples/images/demo-agent.tar --scans AI001 --summary-json
invscan --help-topic images
invscan --image-archive examples/images/demo-agent.tar --image-max-archive-bytes 1 --summary-json  # Expected exit 2
```

The complete demo archive scan yields **three findings, zero coverage gaps and exit 1**. The report separates packaged source from image configuration/history and retained-layer evidence. A selected scan may deliberately return a different count. Very small archive/layer budgets should produce **exit 2**, not a clean result.

For your own image, save an image with `docker image save` or provide an OCI-layout tar archive, optionally gzip-compressed. A `docker export` filesystem dump lacks the required image metadata. `--image-platform` selects a platform when necessary. Archive, expanded-byte, entry and layer limits constrain resource use; `--image-timeout` applies to runtime pull/export, not archive analysis.

### Optional runtime and registry routes

These commands require your actual image reference and a working selected runtime. They are alternatives to the self-contained archive example, not commands to paste with the placeholder unchanged:

```sh
invscan --image YOUR_LOCAL_IMAGE --image-runtime docker --image-timeout 300 --report scan-report/scenarios/05-docker
invscan --image YOUR_LOCAL_IMAGE --image-runtime podman --report scan-report/scenarios/05-podman
invscan --image YOUR_REGISTRY_IMAGE --pull --image-platform linux/amd64 --report scan-report/scenarios/05-registry
```

Pulls are explicit and can require registry credentials and network access. Binary-only images receive metadata assessment; compiled logic, dependency CVEs, signatures and deployed sandbox behavior are not validated by this scanner. See the [image guide](IMAGE_SCANNING.md) and the validation record below for the distinction between fresh archive tests, actual Docker CI and unavailable local runtimes.

## 6. Gate CI and record a reviewed baseline

A CI gate should distinguish findings from incomplete work. This example writes a baseline candidate, then explicitly applies it only to the same inert fixture.

<!-- invscan-scenario:06 -->
```sh
invscan examples/vulnerable --quiet  # Expected exit 1
invscan examples/vulnerable --fail-on none --summary-json
invscan examples/vulnerable --write-baseline scan-report/scenarios/06-baseline.json --baseline-reason 'TEST ONLY: accepted inert documentation fixture; not production approval.' --summary-json  # Expected exit 1
invscan examples/vulnerable --baseline scan-report/scenarios/06-baseline.json --report scan-report/scenarios/06-baselined --summary-json
```

Writing a candidate baseline leaves the **11 findings open and exit 1**. Applying the fixture-only accepted baseline retains them as **suppressed**, leaves **zero open findings**, and returns **exit 0**. A baseline matches stable finding IDs; it is not a general waiver for future findings and is not proof of a fix.

In a real pipeline, inspect a candidate and replace the example reason with a reviewed acceptance record before applying it. `--baseline-reason` is required when writing a candidate. Do not automatically accept every finding in production.

`--fail-on` accepts `critical`, `high`, `medium`, `low`, `info` or `none`. `--summary-json` emits one machine-readable summary; `--quiet` suppresses human output while preserving diagnostics and exit codes. They are mutually exclusive. `none` disables the finding threshold only; errors and incomplete scans still return 2. [Baseline format and behavior](CLI.md#finding-baselines).

## 7. Record a justification or disable an assessment item

Use trusted configuration when a review decision applies to a rule, control or individual check. Invarune never automatically trusts a policy found inside the assessed codebase.

<!-- invscan-scenario:07 -->
```sh
invscan examples/vulnerable --review-config examples/review-config.json --report scan-report/scenarios/07-policy --summary-json  # Expected exit 1
```

The shipped example produces **9 open findings, 1 justified finding and 1 disabled finding**, with **exit 1** because other high findings remain. The reasons are explicitly illustrative; do not use them as real evidence for your system.

`justified` requires a nonblank reason and remains labeled **justified**, never passed. `disabled` means excluded from active assessment while preserving audit evidence. Both receive neither pass nor failure credit in active counts. Rule exceptions affect matching findings; control/check exceptions affect review scope and do not automatically waive mapped findings. Invalid policies return exit 2 before optional AI calls. [Complete schema and precedence](REVIEW_CONFIGURATION.md).

## 8. Carry review decisions through all five report formats

Reuse the full report from scenario 2, record one finding exception and one checklist exception for the inert fixture, and rescan the same explicit target using each report format. The preparation helper edits only the canonical review fields; it does not fabricate a fresh scan or change evidence.

<!-- invscan-scenario:08 -->
```sh
python examples/scenarios/prepare_reviews.py --initial scan-report/scenarios/02-source --output scan-report/scenarios/08-edited --stale-target scan-report/scenarios/08-changed-source
invscan examples/vulnerable --review-report scan-report/scenarios/08-edited/reviewed.html --report scan-report/scenarios/08-final-html --summary-json  # Expected exit 1
invscan examples/vulnerable --review-report scan-report/scenarios/08-edited/reviewed.md --report scan-report/scenarios/08-final-md --summary-json  # Expected exit 1
invscan examples/vulnerable --review-report scan-report/scenarios/08-edited/reviewed.json --report scan-report/scenarios/08-final-json --summary-json  # Expected exit 1
invscan examples/vulnerable --review-report scan-report/scenarios/08-edited/reviewed.sarif --report scan-report/scenarios/08-final-sarif --summary-json  # Expected exit 1
invscan examples/vulnerable --review-report scan-report/scenarios/08-edited/reviewed.pdf --report scan-report/scenarios/08-final-pdf --summary-json  # Expected exit 1
invscan scan-report/scenarios/08-changed-source --review-report scan-report/scenarios/08-edited/reviewed.json --report scan-report/scenarios/08-stale --summary-json  # Expected exit 2
invscan examples/vulnerable --review-report scan-report/scenarios/08-edited/runtime-pending.json --fail-on none --report scan-report/scenarios/08-runtime-pending --summary-json  # Expected exit 2
```

Each final report retains **10 open findings, 1 justified finding and 1 justified checklist item**, so its expected exit remains **1**. The other findings are still actionable. The original evidence is retained; the accepted item is **justified**, not passed. The changed-source command must return **exit 2** because its old review is stale. The pending-runtime example also returns **exit 2**, even with `--fail-on none`, because a finding threshold cannot waive unfinished validation. HTML, Markdown, JSON, SARIF and PDF carry the same bound decision. Imports never select the target or launch a model on your behalf.

For an actual human review, open HTML, fill the review fields and choose **Download reviewed HTML**; saving the browser's original source does not reliably capture live form edits. In a compatible PDF editor, save the AcroForm fields. Markdown/JSON/SARIF expose an editable review capsule. Record `needs_runtime_validation` when testing is outstanding; that remains unresolved and causes exit 2 on import. Changing source evidence or selected scope makes a decision stale and requires re-review.

The scripted workflow tests field editing and replay, not every third-party PDF viewer. [Review workflow](REVIEW_WORKFLOW.md) · [PDF compatibility and limits](PDF_REVIEW.md).

## 9. Connect API gateways and test optional review locally

Use the local lab to verify optional review without a paid account. It starts a loopback HTTP endpoint, creates protocol-specific trusted configurations, returns scripted finding/control responses, and records actual requests. It is a transport and controller demonstration, **not a security analyst or model-accuracy benchmark**.

Start the following server in a **second terminal**, with the same environment activated and the same repository working directory. Wait for the “Scripted loopback gateway ready” message, then leave it running until all scenario 9 commands finish. Stop it with Ctrl+C afterward.

<!-- invscan-scenario:09-server -->
```sh
# Run in a second terminal; leave it open until scenario 9 finishes.
python examples/scenarios/local_gateway.py --output scan-report/scenarios/09-gateway
```

Back in your first terminal:

<!-- invscan-scenario:09 -->
```sh
invscan examples/safer --scans EXEC-05 --judge-config scan-report/scenarios/09-gateway/custom.json --analyst-max-calls 3 --analyst-batch-size 1 --analyst-time-budget 60 --report scan-report/scenarios/09-custom --summary-json
invscan examples/safer --scans EXEC-05 --judge-config scan-report/scenarios/09-gateway/openai_chat.json --analyst-max-calls 3 --analyst-batch-size 1 --analyst-time-budget 60 --report scan-report/scenarios/09-openai_chat --summary-json
invscan examples/safer --scans EXEC-05 --judge-config scan-report/scenarios/09-gateway/openai_responses.json --analyst-max-calls 3 --analyst-batch-size 1 --analyst-time-budget 60 --report scan-report/scenarios/09-openai_responses --summary-json
invscan examples/safer --scans EXEC-05 --judge-config scan-report/scenarios/09-gateway/anthropic.json --analyst-max-calls 3 --analyst-batch-size 1 --analyst-time-budget 60 --report scan-report/scenarios/09-anthropic --summary-json
invscan examples/safer --scans EXEC-05 --judge-config scan-report/scenarios/09-gateway/gemini.json --analyst-max-calls 3 --analyst-batch-size 1 --analyst-time-budget 60 --report scan-report/scenarios/09-gemini --summary-json
invscan examples/safer --scans EXEC-05 --judge-config scan-report/scenarios/09-gateway/ollama.json --analyst-max-calls 3 --analyst-batch-size 1 --analyst-time-budget 60 --report scan-report/scenarios/09-ollama --summary-json
invscan examples/investigation/context-tools --scans EXEC-05 --judge-config scan-report/scenarios/09-gateway/investigation.json --analyst-max-calls 3 --analyst-batch-size 1 --analyst-investigation-rounds 1 --analyst-max-files 10 --analyst-max-bytes 100000 --analyst-max-chars 20000 --analyst-time-budget 60 --token-optimizer compact --report scan-report/scenarios/09-investigation --summary-json
invscan examples/vulnerable --judge-config scan-report/scenarios/09-gateway/custom.json --judge-mode findings --judge-include-source --judge-max-findings 1 --token-optimizer off --report scan-report/scenarios/09-findings --summary-json  # Expected exit 1
invscan examples/safer --scans EXEC-05 --judge-config scan-report/scenarios/09-gateway/custom.json --analyst-max-calls 0 --report scan-report/scenarios/09-exhausted --summary-json  # Expected exit 2
```

The supported adapters are **OpenAI Chat Completions, OpenAI Responses, Anthropic, Gemini, Ollama and custom JSON**. The lab checks the six request/response envelopes. The `custom` adapter supports a request template and response path; this is not a claim that every possible API protocol works without adaptation.

Enabled review defaults to finding triage plus active selected controls. `--judge-mode findings` restricts it to finding triage. `--judge-include-source` adds neighboring source for triage; the full analyst separately captures bounded evidence. `--judge-max-findings` bounds finding triage: the findings-only lab sends one of the fixture's 11 findings and records the other ten as omitted, while retaining every deterministic finding in the report. Installing the AI extra alone never enables review.

Headroom is the default optimizer when review is enabled; `compact` uses built-in compaction and `off` preserves spaced JSON. The optimization receipt records actual engine/fallback and byte counts. Source evidence must remain unchanged; byte reductions are not measured token or billing savings.

### Connect your real service

Copy the matching [example configurations](JUDGE.md) to a trusted location outside the scanned target. Replace its endpoint/model and reference an environment variable for credentials. For example, after configuring `judge.json`:

```sh
invscan examples/investigation/context-tools --scans EXEC-05 --judge-config judge.json --analyst-investigation-rounds 2 --analyst-max-calls 3 --analyst-batch-size 1 --report scan-report/scenarios/09-live-gateway
```

Configure HTTPS, API-key header/prefix, fixed or environment-backed headers, extra request fields, deadlines, request/response size limits, output-token limits and a private CA as your gateway requires. Native Anthropic version headers and custom JSON request/response mapping are documented in the [adapter reference](JUDGE.md). Loopback HTTP supports local testing. Remote HTTP requires an explicit insecure opt-in; use HTTPS for real services. Custom CA configuration does not disable certificate verification. Remote authentication, account entitlements, service availability and judgment accuracy require separate live evidence.

## 10. Use a signed-in CLI for a real evidence investigation

Use an installed official Codex, Claude Code or Grok Build CLI with an eligible account. Invarune selects a provider-specific default model; it does not install those vendor CLIs, grant subscription access or bypass usage limits.

<!-- invscan-scenario:10 -->
```sh
invscan --help-topic login
invscan --help-topic ai
```

### Live Codex example

The following is the live command exercised separately from the scripted gateway lab:

```sh
invscan examples/investigation/context-tools --scans EXEC-05 --judge-cli codex --judge-login never --judge-timeout 180 --analyst-batch-size 1 --analyst-max-calls 3 --analyst-time-budget 600 --analyst-investigation-rounds 2 --report scan-report/scenarios/10-codex --summary-json
```

This inert example needs cross-file context. The model can request exact line ranges from inventoried, hash-verified, redacted source snapshots. The controller validates file IDs, requested ranges, active checks and budgets; it does not execute target code, invoke target tools, browse arbitrary URLs or read arbitrary local paths. Conclusions include the proposed risk, boundary, counterevidence, citations and limits. Inspect actual requests and accepted/denied receipts rather than assuming that enabling AI resolved every uncertainty.

### Login and provider alternatives

If a provider is signed out, start its supported interactive login from Invarune:

```sh
invscan --login codex --login-timeout 300
invscan --login claude --login-timeout 300
invscan --login grok --login-timeout 300
```

Choose **one** provider you use. Complete its browser/device authorization yourself. An interactive scan with the default `--judge-login auto` can also launch login and resume. `--judge-login never`, quiet mode, JSON-summary mode and noninteractive execution never prompt. Automated login simulations are not proof of a completed vendor browser login.

Replace `codex` with `claude` or `grok` in the scan command only after the provider's prerequisites are satisfied. `--judge-model` overrides the default; `--judge-executable` selects a trusted vendor binary. Grok's optional `--judge-cli-home` must name an absolute clean profile that passes extension/instruction inspection; no credentials are copied automatically. [Provider requirements and actual availability](CLI_PROVIDER_RESEARCH.md).

Full-review limits cover control calls, controls per batch, evidence files, read bytes, retained characters, scheduling time and investigation rounds. A triage request is additional to the control-call budget. Set rounds to `0` for seed-only review. Exhausted budgets, failed authentication or missing responses stay visible and can yield exit 2. Even successful model advice cannot lower deterministic severity, waive findings or turn manual/runtime controls into verified passes. [Controlled analyst](ANALYST.md).

## Feature coverage and reproducible validation

Every current parser option is assigned to one of the ten workflows below. The validator checks this inventory against the actual CLI parser, so a newly added option requires a documentation update. **Mapped does not mean every external provider, image registry or parameter combination was live-tested.** The execution receipt distinguishes actual commands from documented conditional routes.

| Scenario | Complete CLI surface |
| --- | --- |
| 1. Offline help and catalog | `--ask`, `--catalog-format`, `--examples`, `--explain-check`, `--explain-control`, `--explain-rule`, `--explain-scan`, `--explain-source`, `--help`, `--help-topic`, `--list-controls`, `--list-rules`, `--list-scans`, `--list-sources`, `--list-topics`, `--version`, `-h` |
| 2. Source and report output | `--output`, `--pdf`, `--report`, `target` |
| 3. Selected scans and skills | `--scan`, `--scans` |
| 4. Source scope and budgets | `--exclude`, `--max-entries`, `--max-file-bytes`, `--max-files`, `--max-total-bytes` |
| 5. Built-image routes and limits | `--image`, `--image-archive`, `--image-max-archive-bytes`, `--image-max-entries`, `--image-max-layers`, `--image-max-unpacked-bytes`, `--image-platform`, `--image-runtime`, `--image-timeout`, `--pull` |
| 6. CI output, gates and baselines | `--baseline`, `--baseline-reason`, `--fail-on`, `--quiet`, `--summary-json`, `--write-baseline` |
| 7. Trusted exceptions | `--review-config` |
| 8. Report review imports | `--review-report` |
| 9. API review, investigation and optimization | `--analyst-batch-size`, `--analyst-investigation-rounds`, `--analyst-max-bytes`, `--analyst-max-calls`, `--analyst-max-chars`, `--analyst-max-files`, `--analyst-time-budget`, `--judge-config`, `--judge-include-source`, `--judge-max-findings`, `--judge-mode`, `--token-optimizer` |
| 10. Vendor CLIs and login | `--judge-cli`, `--judge-cli-home`, `--judge-executable`, `--judge-login`, `--judge-model`, `--judge-timeout`, `--login`, `--login-timeout` |

Configuration files add capabilities beyond flags:

| Scenario | Configuration and report features |
| --- | --- |
| 7 | Rule/control/check `status` and `reason`; explicit trusted input; justified/disabled counts and precedence. |
| 8 | `decision`, `reason`, `reviewer`, `reviewed_at`, `evidence_ref`; preserved scan bindings; notes, accepted exceptions, pending human/runtime validation and stale decisions. |
| 9 | `provider`, `model`, `endpoint`; `api_key_env`, `api_key_header`, `api_key_prefix`, `headers`; `extra_body`, `request_template`, `response_path`, `anthropic_version`; `timeout_seconds`, `max_request_bytes`, `max_response_bytes`, `max_output_tokens`; `allow_insecure_http`, `ca_file`, `token_optimizer`. |
| 10 | CLI JSON alternatives for `provider`, `model`, `executable`, `timeout_seconds`, `max_request_bytes`, `max_response_bytes`, `cli_home` and `token_optimizer`. |



### How these recipes are checked

The [scenario manifest](../examples/scenarios/scenarios.json) and [validator](../scripts/validate_scenarios.py) bind these command blocks to actual installed executions. To check documentation drift or rerun the self-contained examples:

```sh
python scripts/validate_scenarios.py --check-docs-only
python scripts/validate_scenarios.py --output test-output/scenarios
```

The full validator needs Git and Python 3.10+, creates a fresh clone/environment, installs AI/PDF extras, and runs `invscan` outside the source checkout. It verifies the expected findings, intentional nonzero exits, five-format review imports, strict evidence retention, actual Headroom and scripted gateway calls. No model credentials are required for this runner. Installation can download packages. Scenario 10's automatic portion checks offline provider help; its real inference and account prerequisites have a separate executed receipt.

**Executed locally on 24 September 2026:** all **10 scenarios / 59 command steps passed** from a fresh installation, including **17 actual HTTP requests across six loopback protocols**, one requested evidence follow-up, and Headroom 0.37.0. Eight focused regression tests verify the guide/manifest contract and fixture behavior. [Exact commands, input hashes, assertions and dependency versions](../benchmarks/scenarios-v015/receipt.json).

**Separately exercised:** the [fresh live CLI receipt](../benchmarks/scenarios-v015/external-receipt.json) records successful Codex investigation and explicit Claude/Grok unavailable-provider behavior. It also records that neither Docker nor Podman was installed locally. Actual Docker-built-image integration is covered by the separately dated linked CI evidence; Podman, registry pulls and vendor browser login are conditional routes, not invented successes.

The [actual Chrome form/download/import test](../benchmarks/scenarios-v015/html-ui-receipt.json) verified a saved finding justification through the real HTML button and a fresh installed scan. The automated five-format editor is separately labeled and does not claim to test every PDF viewer.

See the [full scenario validation record](../benchmarks/scenarios-v015/README.md). CI reruns the command contract before publishing docs and executes the scenario runner on Linux and Windows. All 65 current flag spellings plus the positional target are documented; 53 spellings are exercised by the automatic command matrix. The remaining flags depend on live providers or image runtimes and retain their explicit prerequisites.

The [complete CLI reference](CLI.md) defines every option and the [scan inventory](SCAN_COVERAGE.md) describes each detector. These scenarios teach product workflows; neither matching their expected output nor a successful model answer establishes that your deployment is secure.
