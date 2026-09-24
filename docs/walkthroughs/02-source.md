# Create your first security report

<p class="inv-eyebrow">WALKTHROUGH 02 · SOURCE SCANNING</p>

Scan a safer example, scan an intentionally risky example, and open a report that tells you where to start fixing issues.

<div class="inv-journey-meta" markdown="1">

**You need:** A [prepared workspace](setup.md) with `invscan` on PATH. Stay in the extracted bundle folder or repository root. No AI account is needed. PDF support is included in native downloads; source installs need the PDF extra from setup.

**You will create:** An HTML report, a fillable PDF and JSON/Markdown/SARIF files in `scan-report/scenarios/02-source/`.

</div>

## 1. Try a terminal-only scan

<div class="inv-step" markdown="1">

Run the safer example first. The scanner reads its files; it does not run the example program.

<!-- invscan-step:02:terminal -->
```sh
invscan examples/safer
```

<div class="inv-result" markdown="1">

**You should see** **2 scanned files**, **0 findings**, and exit **0**. The results appear in your terminal, and this command creates no report files. Zero findings means no configured pattern matched, not that the target is proven secure.

</div>

</div>
## 2. Generate a report with real fixture findings

<div class="inv-step" markdown="1">

Now scan the deliberately vulnerable example and save all five report formats.

<!-- invscan-step:02:source_reports -->
```sh
invscan examples/vulnerable --report scan-report/scenarios/02-source --pdf --summary-json  # Expected exit 1
```

<div class="inv-result" markdown="1">

**You should see** **11 open findings**, **0 coverage gaps**, and exit **1**. This is expected: the example intentionally contains risky patterns. The final line is a JSON summary.

</div>

</div>
## 3. Open the report

<div class="inv-step" markdown="1">

In your file manager, open the following folder from your workspace:

`scan-report/scenarios/02-source/`

Open **`report.html`** in a browser. For the printable, fillable version, open **`report.pdf`**.

<div class="inv-result" markdown="1">

**You should see** An opening summary, immediate concerns, finding locations, suggested fixes, mitigation layers and remaining coverage gaps. The PDF includes charts, clickable navigation and review fields.

</div>

Read one finding end to end:

1. Check the file and line referenced in its evidence.
2. Read **why it matters** and the suggested fix.
3. Check the mapped AI security control and source guidance.
4. Read the limits and any deployment validation still needed.

Do not execute the vulnerable example programs. They are inert scan inputs.

</div>
## 4. Know which file to share

<div class="inv-step" markdown="1">

Choose a format for the person or tool receiving your results.

| File in the report folder | Use it for |
|---|---|
| `report.html` | Browsing findings and entering review decisions |
| `report.pdf` | Sharing a printable report or filling review fields |
| `report.json` | Detailed structured evidence and automation |
| `report.md` | Reading or editing the review capsule as text |
| `report.sarif` | Compatible code-review systems |

<div class="inv-result" markdown="1">

**You should see** The same scan evidence across the formats. There is no overall security grade: coverage and review completion do not establish safety. [How to read the report](../REPORTS.md).

</div>

</div>
## Optional output choices

<details class="inv-option" markdown="1">
<summary>Use an explicit output directory or the default report folder</summary>

The older `--output` spelling also saves reports. Try it on the safer example:

<!-- invscan-step:02:output_alias -->
```sh
invscan examples/safer --output scan-report/scenarios/02-safe --summary-json
```

Expect **0 findings**, exit **0**, and files in `scan-report/scenarios/02-safe/`. This command does not request a PDF.

To use the default output folder, pass `--report` without a directory:

<!-- invscan-step:02:default_report -->
```sh
invscan examples/safer --report --summary-json
```

Expect **0 findings**, exit **0**, and `scan-report/report.html` plus JSON/Markdown/SARIF. Repeating either command replaces files in its selected output directory.

</details>

**Done:** Keep `02-source` for [walkthrough 8: edit a report and rescan](08-review.md). To scan your own code, replace `examples/vulnerable` with your agent or MCP repository path; quote paths containing spaces.

<div class="inv-journey-nav" markdown="1">

[← Explore coverage offline](01-explore.md)

[All walkthroughs](../SCENARIOS.md)

[Inspect skills and tools →](03-skills.md)

</div>
