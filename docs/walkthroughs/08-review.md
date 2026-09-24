# Review a report, then scan again

<p class="inv-eyebrow">WALKTHROUGH 08 · HUMAN REVIEW</p>

Open a scan report, record a decision in its review form, and carry that decision into a fresh scan. Start with the browser workflow; the optional lab below exercises all five report formats.

<div class="inv-journey-meta" markdown="1">

**You need:** Complete [walkthrough 2](02-source.md) first to create `scan-report/scenarios/02-source/report.html`. Use the same example workspace and `invscan` version. No AI account is needed.

**You will create:** A reviewed HTML file and a new scan report that explains whether its decision was applied, stale or unresolved.

</div>

## 1. Open your initial report

<div class="inv-step" markdown="1">

In your file manager, open `scan-report/scenarios/02-source/report.html` in a browser. Read the executive summary and a finding's evidence before making a decision.

<div class="inv-result" markdown="1">

**You should see** **11 open findings** from the vulnerable fixture, along with the report's editable review workspace. Keep this original report as your starting evidence.

</div>

</div>

## 2. Fill in one finding's review fields

<div class="inv-step" markdown="1">

In the review workspace, choose **one finding item** and leave every other item's fields blank. For this inert example, enter:

| Field | What to enter for this demonstration |
|---|---|
| Decision | `justified` |
| Reason | `TEST ONLY: accepting one inert walkthrough fixture finding; this is not production approval.` |
| Reviewer | Your name or team name |
| Reviewed at | Today's date, optionally |
| Evidence reference | A reference to this walkthrough, optionally |

<div class="inv-result" markdown="1">

**You should see** your decision and reason in that finding's form. Selecting `justified` records an accepted exception. There is no manual “pass” or “fixed” option.

</div>

For a real review, write the actual rationale and evidence. To track unfinished testing, choose `needs_runtime_validation` or `needs_human_review` instead; these remain unresolved on import.

</div>

## 3. Download the edited report

<div class="inv-step" markdown="1">

Click **Download reviewed HTML** in the report. Move the downloaded file into `scan-report/scenarios/` and rename it **`08-human-reviewed.html`**. Keep it separate from the original report.

<div class="inv-result" markdown="1">

**You should see** `scan-report/scenarios/08-human-reviewed.html` in your workspace. Use the report's download button: ordinary browser **Save As** may not capture the live form edits.

</div>

</div>

## 4. Run a fresh scan with your decision

<div class="inv-step" markdown="1">

Return to the terminal at your workspace root. Scan the same target and supply the file you just downloaded.

```sh
invscan examples/vulnerable --review-report scan-report/scenarios/08-human-reviewed.html --report scan-report/scenarios/08-human-final --summary-json
```

<div class="inv-result" markdown="1">

**You should see** **10 open findings**, **1 justified finding**, and **exit 1** if you edited exactly one finding and left the fixture unchanged. Open `scan-report/scenarios/08-human-final/report.html` and inspect the review-import audit and the justification you entered.

</div>

The remaining findings are still open. The new report comes from a fresh scan: importing a report does not select a target, run a model, or grant pass credit. Changed source, scope, scanner or catalog can make an old decision stale.

</div>

## Optional: exercise all five formats

<details class="inv-option" markdown="1">
<summary>Run the scripted HTML, Markdown, JSON, SARIF and PDF round-trip lab</summary>

This lab edits the canonical review fields automatically so you can compare format behavior. It is separate from the browser steps above and does not test every PDF viewer.

**Extra preparation:** Even if you downloaded the standalone CLI, this lab needs the repository's helper scripts and a Python environment with the PDF extra. Follow [source workspace setup](setup.md#source-workspace-for-the-full-lab), install its AI/PDF extras, and run from the **repository root** with `invscan` on PATH. Repeat [walkthrough 2](02-source.md) in that checkout to produce all five initial reports. The destination `scan-report/scenarios/08-changed-source` must not already exist; move a previous lab output aside before repeating.

### A. Prepare the demonstration reviews

Create one finding justification, one checklist justification, and a deliberately changed source copy. The helper only edits report review fields and creates inert test inputs.

<!-- invscan-step:08:prepare -->
```sh
python examples/scenarios/prepare_reviews.py --initial scan-report/scenarios/02-source --output scan-report/scenarios/08-edited --stale-target scan-report/scenarios/08-changed-source
```

<div class="inv-result" markdown="1">

**You should see** `"decisions": 2` and five `reviewed.*` files in `scan-report/scenarios/08-edited/`, plus `runtime-pending.json`. These demonstration reasons do not approve a real system.

</div>

### B. Import the HTML version

Rescan using the prepared HTML review.

<!-- invscan-step:08:replay_html -->
```sh
invscan examples/vulnerable --review-report scan-report/scenarios/08-edited/reviewed.html --report scan-report/scenarios/08-final-html --summary-json  # Expected exit 1
```

<div class="inv-result" markdown="1">

**You should see** **10 open findings**, **1 justified finding**, **1 justified checklist item** and **exit 1**. The new report is in `scan-report/scenarios/08-final-html/`.

</div>

### C. Import the Markdown version

Use the same review decisions from the Markdown capsule.

<!-- invscan-step:08:replay_md -->
```sh
invscan examples/vulnerable --review-report scan-report/scenarios/08-edited/reviewed.md --report scan-report/scenarios/08-final-md --summary-json  # Expected exit 1
```

<div class="inv-result" markdown="1">

**You should see** the same counts and **exit 1**, with a separate report in `scan-report/scenarios/08-final-md/`.

</div>

### D. Import the JSON version

Replay the canonical JSON review fields.

<!-- invscan-step:08:replay_json -->
```sh
invscan examples/vulnerable --review-report scan-report/scenarios/08-edited/reviewed.json --report scan-report/scenarios/08-final-json --summary-json  # Expected exit 1
```

<div class="inv-result" markdown="1">

**You should see** the same counts and **exit 1**, with the report in `scan-report/scenarios/08-final-json/`.

</div>

### E. Import the SARIF version

Read the review capsule carried inside the SARIF document.

<!-- invscan-step:08:replay_sarif -->
```sh
invscan examples/vulnerable --review-report scan-report/scenarios/08-edited/reviewed.sarif --report scan-report/scenarios/08-final-sarif --summary-json  # Expected exit 1
```

<div class="inv-result" markdown="1">

**You should see** the same counts and **exit 1**, with the report in `scan-report/scenarios/08-final-sarif/`.

</div>

### F. Import the PDF version

Read the editable review fields from the prepared scan PDF.

<!-- invscan-step:08:replay_pdf -->
```sh
invscan examples/vulnerable --review-report scan-report/scenarios/08-edited/reviewed.pdf --report scan-report/scenarios/08-final-pdf --summary-json  # Expected exit 1
```

<div class="inv-result" markdown="1">

**You should see** the same counts and **exit 1**, with the report in `scan-report/scenarios/08-final-pdf/`. Compare the import audit across all five outputs: each applied two decisions without enabling AI.

</div>

### G. Confirm that changed evidence needs another review

Scan the changed source copy while supplying its old review.

<!-- invscan-step:08:stale_review -->
```sh
invscan scan-report/scenarios/08-changed-source --review-report scan-report/scenarios/08-edited/reviewed.json --report scan-report/scenarios/08-stale --summary-json  # Expected exit 2
```

<div class="inv-result" markdown="1">

**You should see** **exit 2**, **2 stale decisions** and **0 applied decisions**. The old approval does not silently transfer to different evidence. Inspect `scan-report/scenarios/08-stale/report.html` for the reason.

</div>

### H. Keep unfinished runtime validation visible

Import the prepared review that requests a runtime test, even with the finding gate disabled.

<!-- invscan-step:08:runtime_pending -->
```sh
invscan examples/vulnerable --review-report scan-report/scenarios/08-edited/runtime-pending.json --fail-on none --report scan-report/scenarios/08-runtime-pending --summary-json  # Expected exit 2
```

<div class="inv-result" markdown="1">

**You should see** **exit 2** and **1 unresolved review item**. `--fail-on none` cannot waive unfinished validation. The 11 deterministic findings stay open.

</div>

</details>

## Choose a review format

| Format | How to make your own edits |
|---|---|
| **HTML** | Fill the form and use **Download reviewed HTML**. |
| **PDF** | Use a compatible form editor and save an editable PDF. Do not flatten or print it to PDF. |
| **Markdown** | Edit the review JSON between `INVARUNE_REVIEW_BEGIN` and `INVARUNE_REVIEW_END`. |
| **JSON** | Edit item fields in `review_workspace.items`. |
| **SARIF** | Edit item fields in `runs[0].properties.invarune_review.items`. |

Preserve identifiers, evidence bindings and schema fields. Only the review fields are imported; changing ordinary prose or severity labels does not change the scan evidence. General controlbook and benchmark PDFs are not review inputs—use a fillable report from a specific scan.

[Full review workflow](../REVIEW_WORKFLOW.md) · [PDF editor compatibility](../PDF_REVIEW.md) · [Recorded browser download/import test](../../benchmarks/scenarios-v015/html-ui-receipt.json)


<div class="inv-journey-nav" markdown="1">

[← Record an exception](07-exceptions.md)

[All walkthroughs](../SCENARIOS.md)

[Try a local API gateway →](09-gateways.md)

</div>
