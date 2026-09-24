# Learn invscan by doing

<div class="inv-scenario-hero" markdown="1">

<p class="inv-eyebrow">TEN GUIDED WALKTHROUGHS · INVARUNE 0.15.0</p>

## One task. Clear steps. A result you can check.

Choose a walkthrough below. Each has its own page with the prerequisites, one copyable command per action, and an expected result before you move on.

[Start with your first report →](walkthroughs/02-source.md){ .md-button .md-button--primary }
[Prepare your workspace](walkthroughs/setup.md){ .md-button }

</div>

<div class="inv-route-strip" markdown="1">

**1 · Prepare** your terminal and example files.  
**2 · Follow** one instruction at a time.  
**3 · Check** the result before continuing.

</div>

## Choose a walkthrough

Start with **02 · Create your first report** if this is your first scan. You can take the others as needed; only the report-review walkthrough depends on an earlier report.

<div class="inv-scenario-grid">
<a class="inv-scenario-card" id="1-explore-coverage-without-an-ai-account" href="walkthroughs/01-explore.md">
<span class="inv-scenario-number">01</span>
<span class="inv-scenario-tag">No account · No files created</span>
<h3>Explore coverage offline</h3>
<p>Ask a question, inspect a check, and trace it to the original guidance.</p>
<span class="inv-scenario-action">Open walkthrough <span aria-hidden="true">→</span></span>
</a>
<a class="inv-scenario-card" id="2-scan-an-agent-or-mcp-codebase-and-read-the-result" href="walkthroughs/02-source.md">
<span class="inv-scenario-number">02</span>
<span class="inv-scenario-tag">Start here · Source scanning</span>
<h3>Create your first report</h3>
<p>Scan two examples, open the HTML/PDF, and find what to fix first.</p>
<span class="inv-scenario-action">Open walkthrough <span aria-hidden="true">→</span></span>
</a>
<a class="inv-scenario-card" id="3-inspect-skills-and-select-exactly-what-to-scan" href="walkthroughs/03-skills.md">
<span class="inv-scenario-number">03</span>
<span class="inv-scenario-tag">No account · Focused checks</span>
<h3>Inspect skills and tools</h3>
<p>Find risky instructions and choose the exact rules you want to run.</p>
<span class="inv-scenario-action">Open walkthrough <span aria-hidden="true">→</span></span>
</a>
<a class="inv-scenario-card" id="4-control-scope-and-see-when-a-scan-is-incomplete" href="walkthroughs/04-scope.md">
<span class="inv-scenario-number">04</span>
<span class="inv-scenario-tag">No account · Coverage gaps</span>
<h3>Control scan scope</h3>
<p>Set exclusions and limits, then recognize an incomplete scan.</p>
<span class="inv-scenario-action">Open walkthrough <span aria-hidden="true">→</span></span>
</a>
<a class="inv-scenario-card" id="5-scan-a-built-image-without-its-source-checkout" href="walkthroughs/05-images.md">
<span class="inv-scenario-number">05</span>
<span class="inv-scenario-tag">No Docker needed for the example</span>
<h3>Scan a built image</h3>
<p>Inspect the included image archive without starting a container.</p>
<span class="inv-scenario-action">Open walkthrough <span aria-hidden="true">→</span></span>
</a>
<a class="inv-scenario-card" id="6-gate-ci-and-record-a-reviewed-baseline" href="walkthroughs/06-ci.md">
<span class="inv-scenario-number">06</span>
<span class="inv-scenario-tag">No account · CI workflow</span>
<h3>Use gates and baselines</h3>
<p>See CI exit codes in action and apply a reviewed finding baseline.</p>
<span class="inv-scenario-action">Open walkthrough <span aria-hidden="true">→</span></span>
</a>
<a class="inv-scenario-card" id="7-record-a-justification-or-disable-an-assessment-item" href="walkthroughs/07-exceptions.md">
<span class="inv-scenario-number">07</span>
<span class="inv-scenario-tag">No account · Review policy</span>
<h3>Record an exception</h3>
<p>Use a justification or exclusion while keeping the audit evidence.</p>
<span class="inv-scenario-action">Open walkthrough <span aria-hidden="true">→</span></span>
</a>
<a class="inv-scenario-card" id="8-carry-review-decisions-through-all-five-report-formats" href="walkthroughs/08-review.md">
<span class="inv-scenario-number">08</span>
<span class="inv-scenario-tag">Browser review · Optional five-format lab</span>
<h3>Edit a report and rescan</h3>
<p>Fill in a review decision, download it, and import it into a fresh scan.</p>
<span class="inv-scenario-action">Open walkthrough <span aria-hidden="true">→</span></span>
</a>
<a class="inv-scenario-card" id="9-connect-api-gateways-and-test-optional-review-locally" href="walkthroughs/09-gateways.md">
<span class="inv-scenario-number">09</span>
<span class="inv-scenario-tag">Source workspace · No model account</span>
<h3>Try a local API gateway</h3>
<p>Send review requests and follow bounded evidence requests in a local lab.</p>
<span class="inv-scenario-action">Open walkthrough <span aria-hidden="true">→</span></span>
</a>
<a class="inv-scenario-card" id="10-use-a-signed-in-cli-for-a-real-evidence-investigation" href="walkthroughs/10-provider-cli.md">
<span class="inv-scenario-number">10</span>
<span class="inv-scenario-tag">Optional · Real account and network</span>
<h3>Connect your provider CLI</h3>
<p>Sign in through invscan and run optional review with your provider.</p>
<span class="inv-scenario-action">Open walkthrough <span aria-hidden="true">→</span></span>
</a>
</div>

## Prepare once

The [workspace setup page](walkthroughs/setup.md) has separate macOS/Linux and PowerShell instructions. Choose the native download for the local examples, or a source workspace for the full helper-script labs. Keep your terminal in the example workspace so the paths can be copied directly.

No model account is needed for walkthroughs **1–9**. Walkthrough 9 uses scripted local answers; walkthrough 10 clearly marks real account login and inference. The scanner never executes the target agent, MCP server, skill instructions or image container in these examples.

<div class="inv-result" markdown="1">

**A finding is an expected result in some examples.** Exit **1** means findings reached the configured threshold. Exit **2** means an error or incomplete work. Each step says what to expect; these codes do not mean the installation failed.

</div>

## Feature coverage and reproducible validation

The walkthroughs keep the full feature coverage of the previous guide. Advanced variants are expandable so you can finish the main task first.

<details class="inv-option" markdown="1">
<summary>See which walkthrough covers each CLI feature</summary>

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

</details>

<details class="inv-option" markdown="1">
<summary>How the commands are tested, and what was not live-tested</summary>

Every tagged command is checked against the [scenario manifest](../examples/scenarios/scenarios.json). The validator rejects a missing, duplicate, moved or changed command and records the input hashes for the hub, setup guide and all ten walkthrough pages.

The installed-workflow runner exercises **59 commands across ten scenarios**, including the optional local labs: source/skills/image archives, review configuration, all five report imports, six local API protocols, real Headroom use and bounded evidence requests. It runs the scanner outside its source checkout, with inert example files. Live provider login/inference, Podman and registry pulls are conditional routes, not simulated successes.

[Walkthrough validation](../benchmarks/walkthroughs-v015/README.md) · [Earlier scenario evidence](../benchmarks/scenarios-v015/README.md) · [Native packages on five platforms](../benchmarks/standalone-v015/README.md) · [Actual browser review test](../benchmarks/scenarios-v015/html-ui-receipt.json) · [Separately recorded provider outcomes](../benchmarks/scenarios-v015/external-receipt.json)

To check the guide from a source workspace:

```sh
python scripts/validate_scenarios.py --check-docs-only
```

To execute its self-contained command matrix in a fresh installation:

```sh
python scripts/validate_scenarios.py --output test-output/scenarios
```

The runner requires Git and Python 3.10+, and installs the AI/PDF extras. Use a new output directory. Its requests go to a scripted loopback gateway; it does not authenticate to real providers or make paid model calls. See the [developer validation guide](developer/testing-and-releasing.md#keep-the-scenario-guide-executable).

</details>

These walkthroughs teach workflows, not a security certification. For detector scope and known limits, use [every scan and its coverage](SCAN_COVERAGE.md). For the complete option reference, use [CLI help](CLI.md).
