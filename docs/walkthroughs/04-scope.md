# Control scope and spot incomplete scans

<p class="inv-eyebrow">WALKTHROUGH 04 · SCOPE & LIMITS</p>

Exclude a file deliberately, then make a scan hit a limit so you know how incomplete analysis is reported.

<div class="inv-journey-meta" markdown="1">

**You need:** A [prepared workspace](setup.md) with `invscan` on PATH. Stay in the extracted bundle folder or repository root. No AI account is needed.

**You will create:** Terminal summaries only. No report files are created.

</div>

## 1. Choose files and resource limits

<div class="inv-step" markdown="1">

Exclude two fixture files and set explicit read and traversal budgets.

<!-- invscan-step:04:bounded_scope -->
```sh
invscan examples/vulnerable --exclude requirements.txt --exclude Dockerfile --max-file-bytes 1000000 --max-total-bytes 5000000 --max-files 100 --max-entries 1000 --fail-on none --summary-json
```

<div class="inv-result" markdown="1">

**You should see** A complete selected-scope scan, **0 coverage gaps**, and exit **0**. `Dockerfile` and `requirements.txt` are excluded. Other findings may remain: `--fail-on none` turns off the finding threshold, not the detectors.

</div>

An exclusion changes scope; it is not a justification for a finding. Paths are case-sensitive and relative to the scan root. Quote glob patterns to prevent your shell from expanding them.

</div>
## 2. Intentionally make the file budget too small

<div class="inv-step" markdown="1">

Allow only ten bytes per file on the safer example.

<!-- invscan-step:04:file_budget -->
```sh
invscan examples/safer --max-file-bytes 10 --fail-on none --summary-json  # Expected exit 2
```

<div class="inv-result" markdown="1">

**You should see** An explicit coverage gap, an incomplete selected scope, and exit **2**—even with `--fail-on none`. Do not interpret a zero-finding summary from this command as a clean scan.

</div>

</div>
## 3. Read the gap before changing a limit

<div class="inv-step" markdown="1">

Inspect `coverage_gaps` and `scope` in the JSON summary from the previous step. Identify the file or limit the scanner could not fully assess.

If this happens in your real repository, choose an appropriate higher limit or narrow the intended scope, then run a new scan. Increasing a size budget does not add support for an unsupported language or runtime property.

<div class="inv-result" markdown="1">

**You should see** A specific reason for incomplete work rather than a silent success. Exit **2** remains distinct from the exit **1** used for findings.

</div>

</div>
## Try the other limits

<details class="inv-option" markdown="1">
<summary>Limit total read bytes</summary>

Run this independently after the preceding command.

<!-- invscan-step:04:total_budget -->
```sh
invscan examples/safer --max-total-bytes 10 --fail-on none --summary-json  # Expected exit 2
```

<div class="inv-result" markdown="1">

**You should see** An incomplete scan and exit **2** because the total read budget is too small.

</div>

</details>
<details class="inv-option" markdown="1">
<summary>Limit the number of files</summary>

Allow only one file from the two-file safer fixture.

<!-- invscan-step:04:count_budget -->
```sh
invscan examples/safer --max-files 1 --fail-on none --summary-json  # Expected exit 2
```

<div class="inv-result" markdown="1">

**You should see** An incomplete scan and exit **2**.

</div>

</details>
<details class="inv-option" markdown="1">
<summary>Limit filesystem traversal entries</summary>

Set the traversal entry budget to one.

<!-- invscan-step:04:entry_budget -->
```sh
invscan examples/safer --max-entries 1 --fail-on none --summary-json  # Expected exit 2
```

<div class="inv-result" markdown="1">

**You should see** An incomplete scan and exit **2**. Traversal limits constrain discovery, not just bytes read.

</div>

</details>

**Done:** You can distinguish selected scope, an intentional exclusion and incomplete analysis. [Source scope and limits](../CLI.md#scan-scope-and-limits).

<div class="inv-journey-nav" markdown="1">

[← Inspect skills and tools](03-skills.md)

[All walkthroughs](../SCENARIOS.md)

[Scan a built image →](05-images.md)

</div>
