# Use your signed-in provider CLI

<p class="inv-eyebrow">WALKTHROUGH 10 · LIVE OPTIONAL REVIEW</p>

Run a bounded evidence investigation through an installed Codex, Claude Code or Grok Build CLI. Invarune can start the provider's supported login flow and chooses a provider-specific model by default.

<div class="inv-journey-meta" markdown="1">

**You need:** The [installed scanner](../INSTALLATION.md), the shipped `examples/investigation/context-tools` fixture, an installed supported vendor CLI, and an eligible account. Use a terminal at the prepared workspace root with `invscan` on PATH. Standalone releases include Headroom; source/wheel users need the AI extra for Headroom.

**You will create:** A report containing real optional model advice, evidence-request receipts and explicit review limits.

</div>

The help commands below work offline. Login and scanning use your actual provider account and may consume its usage allowance. Invarune does not bundle vendor CLIs, grant subscriptions or bypass account limits. For a no-account demonstration, use [the local gateway walkthrough](09-gateways.md).

## 1. Check the login and review options

<div class="inv-step" markdown="1">

Read the built-in login guide first.

<!-- invscan-step:10:login_help -->
```sh
invscan --help-topic login
```

<div class="inv-result" markdown="1">

**You should see** help for `--login`, `--judge-login` and their interactive behavior. No sign-in or network request happens just by reading help.

</div>

Then read the optional reviewer settings.

<!-- invscan-step:10:ai_help -->
```sh
invscan --help-topic ai
```

<div class="inv-result" markdown="1">

**You should see** `--judge-cli`, `--judge-executable`, `--judge-model` and `--judge-cli-home`, plus the review modes and limits. No model is invoked.

</div>

</div>

## 2. Sign in through Invarune

<div class="inv-step" markdown="1">

Choose **one** installed provider below. If you are already signed in with the intended account, continue to step 3. Otherwise, run its login command and complete the provider's browser/device authorization yourself.

<details class="inv-option" markdown="1" open>
<summary>Codex</summary>

Start the official Codex login flow from Invarune.

```sh
invscan --login codex --login-timeout 300
```

<div class="inv-result" markdown="1">

**You should see** the provider's sign-in instructions or authenticated status. Complete authorization before the timeout and wait for the command to finish. If it fails, read the diagnostic before scanning.

</div>

</details>

<details class="inv-option" markdown="1">
<summary>Claude Code</summary>

Start the official Claude Code login flow from Invarune.

```sh
invscan --login claude --login-timeout 300
```

<div class="inv-result" markdown="1">

**You should see** the provider's supported account authorization flow. Complete it with an eligible account. Launching the flow by itself does not mean sign-in succeeded.

</div>

</details>

<details class="inv-option" markdown="1">
<summary>Grok Build</summary>

Use the official Grok Build executable, not a similarly named community CLI, and start its login flow.

```sh
invscan --login grok --login-timeout 300
```

<div class="inv-result" markdown="1">

**You should see** the provider's supported sign-in flow or authentication status. Its profile must also pass Invarune's extension/instruction preflight before a scan can submit evidence.

</div>

</details>

Interactive scans default to `--judge-login auto`, which can launch a needed login and resume the scan. The commands in step 3 use `--judge-login never` and JSON summaries because sign-in has already happened here. Quiet, JSON-summary and noninteractive scans never prompt for login.

</div>

## 3. Run a bounded live investigation

<div class="inv-step" markdown="1">

For Codex, run the command below. It sends the inert cross-file example for selected-control review, allows at most three control calls and two investigation rounds, and saves the results.

```sh
invscan examples/investigation/context-tools --scans EXEC-05 --judge-cli codex --judge-login never --judge-timeout 180 --analyst-batch-size 1 --analyst-max-calls 3 --analyst-time-budget 600 --analyst-investigation-rounds 2 --report scan-report/scenarios/10-codex --summary-json
```

<div class="inv-result" markdown="1">

**You should see** a JSON summary after the request finishes, or an explicit authentication, preflight or provider diagnostic. Open `scan-report/scenarios/10-codex/report.html` when generated. Model outputs vary; a successful request does not guarantee a particular conclusion or number of follow-up requests.

</div>

<details class="inv-option" markdown="1">
<summary>Use Claude Code for the same investigation</summary>

After completing Claude's prerequisites and sign-in, run:

```sh
invscan examples/investigation/context-tools --scans EXEC-05 --judge-cli claude --judge-login never --judge-timeout 180 --analyst-batch-size 1 --analyst-max-calls 3 --analyst-time-budget 600 --analyst-investigation-rounds 2 --report scan-report/scenarios/10-claude --summary-json
```

<div class="inv-result" markdown="1">

**You should see** the actual outcome in `scan-report/scenarios/10-claude/` when a report is generated. Missing or expired authentication remains an explicit failure; it is not treated as a completed review.

</div>

</details>

<details class="inv-option" markdown="1">
<summary>Use Grok Build for the same investigation</summary>

After completing Grok Build's prerequisites, sign-in and profile setup, run:

```sh
invscan examples/investigation/context-tools --scans EXEC-05 --judge-cli grok --judge-login never --judge-timeout 180 --analyst-batch-size 1 --analyst-max-calls 3 --analyst-time-budget 600 --analyst-investigation-rounds 2 --report scan-report/scenarios/10-grok --summary-json
```

<div class="inv-result" markdown="1">

**You should see** a report in `scan-report/scenarios/10-grok/` or a specific preflight/authentication diagnostic. A profile with active unsupported extensions or instructions is rejected before inference.

</div>

An optional `--judge-cli-home` must name an absolute, existing clean profile that passes inspection. Credentials are not copied automatically. Follow [the provider requirements](../CLI_PROVIDER_RESEARCH.md) before choosing a separate profile.

</details>

</div>

## 4. Inspect what the model actually reviewed

<div class="inv-step" markdown="1">

In your generated report, read the advisory outcomes and inspect the investigation/request receipts. Check the selected controls, evidence citations, accepted and denied requests, stated counterevidence and remaining limitations.

<div class="inv-result" markdown="1">

**You should see** the requested model and actual review status. When additional evidence was requested, receipts explain which file ranges were served or rejected. Headroom is the default optimizer when available; its receipt records the actual engine or fallback.

</div>

The controller validates requested file IDs, line ranges, active checks and budgets against inventoried, hash-verified, redacted snapshots. It does not execute the target, call its tools, browse arbitrary URLs or read arbitrary paths. Model advice cannot lower deterministic severity, waive findings or certify manual/runtime controls.

</div>

## Adjust the review deliberately

| Setting | When to change it |
|---|---|
| `--judge-model` | Override Invarune's provider-specific default. Account/model availability still applies. |
| `--judge-executable` | Select a trusted vendor binary when normal executable discovery is unsuitable. |
| `--judge-timeout` | Bound an individual CLI request's wall time. |
| `--analyst-max-calls` / `--analyst-batch-size` | Bound control calls and controls per batch. Finding triage is additional to this control-call budget. |
| `--analyst-investigation-rounds` | Use `0` for seed-only review or allow bounded evidence follow-ups. |
| `--analyst-time-budget` | Bound investigation scheduling time; unfinished review remains visible. |

File, byte and retained-character limits are also available in [the analyst reference](../ANALYST.md). Exhausted budgets, failed authentication and missing responses can return exit 2. These limits do not guarantee a monetary cap or that cancellation immediately stops remote usage.

## What has actually been exercised

The automatic scenario runner verifies the two offline help commands. The [separate live receipt](../../benchmarks/scenarios-v015/external-receipt.json) records successful Codex investigation and explicit unavailable-provider behavior for Claude/Grok. It does not claim a successful live scan through every account, completed browser login for every provider, or model-accuracy validation.

[Provider prerequisites and containment](../CLI_PROVIDER_RESEARCH.md) · [Controlled analyst design](../ANALYST.md) · [Full CLI reference](../CLI.md)

[Return to all walkthroughs](../SCENARIOS.md){ .md-button .md-button--primary }

<div class="inv-journey-nav" markdown="1">

[← Try a local API gateway](09-gateways.md)

[All walkthroughs](../SCENARIOS.md)

</div>
