# Try optional review with a local gateway

<p class="inv-eyebrow">WALKTHROUGH 09 · API REVIEW &amp; INVESTIGATION</p>

See how optional review sends a request, records an answer and asks for bounded extra evidence. This local lab needs no API key and makes no real model calls.

<div class="inv-journey-meta" markdown="1">

**You need:** A [source workspace](setup.md#source-workspace-for-the-full-lab), AI/PDF extras, and two terminals at the repository root. Keep `invscan` on PATH in both. The gateway helper is a repository script, so standalone-download users need this extra source/Python preparation too.

**You will create:** Local gateway configurations, request receipts, and scan reports showing optional review and its limits.

</div>

The gateway returns clearly labeled scripted answers. This demonstrates transport and controller behavior; it does not measure a model's security judgment. The scanned examples are read as data and never executed.

## 1. Start the gateway in a second terminal

<div class="inv-step" markdown="1">

Open terminal **B**, activate the same environment, and change to the same repository root. Run the helper and leave that terminal open.

<!-- invscan-step:09:gateway_server -->
```sh
# Run in a second terminal; leave it open until scenario 9 finishes.
python examples/scenarios/local_gateway.py --output scan-report/scenarios/09-gateway
```

<div class="inv-result" markdown="1">

**You should see** **“Scripted loopback gateway ready”**. The helper writes its configurations into `scan-report/scenarios/09-gateway/` and listens only on `127.0.0.1`. Wait for this message before continuing.

</div>

</div>

## 2. Review one control through the gateway

<div class="inv-step" markdown="1">

Back in terminal **A**, select `EXEC-05` and send its bounded review request to the local custom-JSON endpoint. Leave terminal B running.

<!-- invscan-step:09:api_custom -->
```sh
invscan examples/safer --scans EXEC-05 --judge-config scan-report/scenarios/09-gateway/custom.json --analyst-max-calls 3 --analyst-batch-size 1 --analyst-time-budget 60 --report scan-report/scenarios/09-custom --summary-json
```

<div class="inv-result" markdown="1">

**You should see** **exit 0**, **0 open findings**, and an enabled analyst that reviewed **1 control**. Open `scan-report/scenarios/09-custom/report.html`. Its two acceptance checks are **insufficient evidence**, not verified passes.

</div>

Open `scan-report/scenarios/09-gateway/requests.json` in your editor to inspect the actual local request receipts. In the report, inspect the optimization receipt: Headroom is the default when review is enabled and available. Installing the AI extra by itself never enables review.

</div>

## 3. Allow one request for more evidence

<div class="inv-step" markdown="1">

Use the cross-file example and allow one bounded investigation round. This command also switches to the built-in compact optimizer so you can compare its recorded engine.

<!-- invscan-step:09:investigation -->
```sh
invscan examples/investigation/context-tools --scans EXEC-05 --judge-config scan-report/scenarios/09-gateway/investigation.json --analyst-max-calls 3 --analyst-batch-size 1 --analyst-investigation-rounds 1 --analyst-max-files 10 --analyst-max-bytes 100000 --analyst-max-chars 20000 --analyst-time-budget 60 --token-optimizer compact --report scan-report/scenarios/09-investigation --summary-json
```

<div class="inv-result" markdown="1">

**You should see** **exit 0**, **1 served evidence request** and **1 completed investigation round** in `scan-report/scenarios/09-investigation/report.json`. The optimizer is recorded as `builtin_compact`.

</div>

Open the HTML report to inspect the evidence-request receipts. The controller supplies validated line ranges from inventoried source snapshots. It does not run the target, invoke its tools or read arbitrary paths. A completed request still does not prove a control works at runtime.

</div>

## 4. See what happens when review runs out of budget

<div class="inv-step" markdown="1">

Keep the gateway running and set the analyst call budget to zero.

<!-- invscan-step:09:exhausted_ai_budget -->
```sh
invscan examples/safer --scans EXEC-05 --judge-config scan-report/scenarios/09-gateway/custom.json --analyst-max-calls 0 --report scan-report/scenarios/09-exhausted --summary-json  # Expected exit 2
```

<div class="inv-result" markdown="1">

**You should see** **exit 2** and an analyst status of **incomplete** in `scan-report/scenarios/09-exhausted/`. Missing review does not become a clean result just because the deterministic scan found nothing.

</div>

</div>

## Optional: try other review modes

<details class="inv-option" markdown="1">
<summary>Review one finding without reviewing controls</summary>

Keep terminal B running. This scans all the vulnerable fixture's supported files, then sends only one finding for advisory triage. Neighboring source is included and the optimizer is disabled for this request.

<!-- invscan-step:09:findings_only -->
```sh
invscan examples/vulnerable --judge-config scan-report/scenarios/09-gateway/custom.json --judge-mode findings --judge-include-source --judge-max-findings 1 --token-optimizer off --report scan-report/scenarios/09-findings --summary-json  # Expected exit 1
```

<div class="inv-result" markdown="1">

**You should see** **11 open findings** and **exit 1**. In `scan-report/scenarios/09-findings/report.json`, `judge.selected_findings` is **1**, `judge.omitted_open_findings` is **10**, and the full analyst is disabled. The ten omitted findings remain in the deterministic result.

</div>

`--judge-mode findings` limits optional review to finding triage. `--judge-include-source` controls neighboring source for this triage mode; the full analyst separately captures bounded evidence. `--token-optimizer off` preserves spaced JSON rather than applying compaction.

</details>

<details class="inv-option" markdown="1">
<summary>Exercise the other five API adapters</summary>

These alternatives use the same running scripted gateway. Run each command separately. Each returns **exit 0**, **0 open findings**, **1 reviewed control**, and **2 insufficient-evidence checks**. No remote provider or account is contacted.

### OpenAI Chat Completions envelope

Send the selected control through the Chat Completions adapter.

<!-- invscan-step:09:api_openai_chat -->
```sh
invscan examples/safer --scans EXEC-05 --judge-config scan-report/scenarios/09-gateway/openai_chat.json --analyst-max-calls 3 --analyst-batch-size 1 --analyst-time-budget 60 --report scan-report/scenarios/09-openai_chat --summary-json
```

<div class="inv-result" markdown="1">

**You should see** the expected local result in `scan-report/scenarios/09-openai_chat/`, with the Headroom optimization receipt.

</div>

### OpenAI Responses envelope

Repeat with the Responses adapter.

<!-- invscan-step:09:api_openai_responses -->
```sh
invscan examples/safer --scans EXEC-05 --judge-config scan-report/scenarios/09-gateway/openai_responses.json --analyst-max-calls 3 --analyst-batch-size 1 --analyst-time-budget 60 --report scan-report/scenarios/09-openai_responses --summary-json
```

<div class="inv-result" markdown="1">

**You should see** the expected local result in `scan-report/scenarios/09-openai_responses/`.

</div>

### Anthropic envelope

Repeat with the native Anthropic adapter.

<!-- invscan-step:09:api_anthropic -->
```sh
invscan examples/safer --scans EXEC-05 --judge-config scan-report/scenarios/09-gateway/anthropic.json --analyst-max-calls 3 --analyst-batch-size 1 --analyst-time-budget 60 --report scan-report/scenarios/09-anthropic --summary-json
```

<div class="inv-result" markdown="1">

**You should see** the expected local result in `scan-report/scenarios/09-anthropic/`.

</div>

### Gemini envelope

Repeat with the Gemini adapter.

<!-- invscan-step:09:api_gemini -->
```sh
invscan examples/safer --scans EXEC-05 --judge-config scan-report/scenarios/09-gateway/gemini.json --analyst-max-calls 3 --analyst-batch-size 1 --analyst-time-budget 60 --report scan-report/scenarios/09-gemini --summary-json
```

<div class="inv-result" markdown="1">

**You should see** the expected local result in `scan-report/scenarios/09-gemini/`.

</div>

### Ollama envelope

Repeat with the Ollama adapter. This fixture does not need a running Ollama model.

<!-- invscan-step:09:api_ollama -->
```sh
invscan examples/safer --scans EXEC-05 --judge-config scan-report/scenarios/09-gateway/ollama.json --analyst-max-calls 3 --analyst-batch-size 1 --analyst-time-budget 60 --report scan-report/scenarios/09-ollama --summary-json
```

<div class="inv-result" markdown="1">

**You should see** the expected local result in `scan-report/scenarios/09-ollama/`. Inspect `09-gateway/requests.json` to compare the adapter records.

</div>

</details>

## 5. Stop the local gateway

<div class="inv-step" markdown="1">

After finishing the optional variants, return to terminal **B** and press **Ctrl+C**.

<div class="inv-result" markdown="1">

**You should see** the shell prompt return. Your reports, generated configurations and request receipts remain available for inspection. Restart the helper before running another local gateway example; it chooses a port and rewrites its configurations at startup.

</div>

</div>

## Connect your real service when ready

<details class="inv-option" markdown="1">
<summary>Send a real request to an API or custom gateway</summary>

**This uses actual network inference and your provider account.** Copy a matching [example configuration](../JUDGE.md) to a trusted location outside the scanned target. Name it `judge.json` at the repository root for the command below. Replace its endpoint and model, configure an environment-variable credential reference, and use HTTPS. Do not copy a scripted lab configuration unchanged into production.

Once that configuration is ready, run:

```sh
invscan examples/investigation/context-tools --scans EXEC-05 --judge-config judge.json --analyst-investigation-rounds 2 --analyst-max-calls 3 --analyst-batch-size 1 --report scan-report/scenarios/09-live-gateway
```

<div class="inv-result" markdown="1">

**You should see** an actual provider response or an explicit provider/configuration diagnostic. Open `scan-report/scenarios/09-live-gateway/report.html` when generated and inspect the accepted findings, check outcomes, citations and investigation receipts. There is no fixed model answer or promised finding count; failed or incomplete review can return exit 2.

</div>

The [adapter reference](../JUDGE.md) covers API-key headers/prefixes, fixed or environment-backed headers, extra request fields, Anthropic version headers, custom request templates and response paths, timeouts, byte/output-token limits, and private CAs. Custom CA support retains certificate verification. Loopback HTTP is permitted for the lab; remote HTTP needs an explicit insecure opt-in.

The custom adapter can map supported JSON protocols; it does not automatically speak every possible API. Model availability, credentials and judgment accuracy need separate live evidence. Byte reductions in the optimizer receipt are not measured billing or token savings.

</details>


<div class="inv-journey-nav" markdown="1">

[← Edit a report and rescan](08-review.md)

[All walkthroughs](../SCENARIOS.md)

[Connect your provider CLI →](10-provider-cli.md)

</div>
