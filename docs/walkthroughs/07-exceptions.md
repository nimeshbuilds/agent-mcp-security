# Record an exception without calling it a pass

<p class="inv-eyebrow">WALKTHROUGH 07 · JUSTIFICATIONS &amp; SCOPE</p>

Apply an explicit review policy and see exactly which findings remain open, which are justified, and which are disabled.

<div class="inv-journey-meta" markdown="1">

**You need:** The [installed CLI](../INSTALLATION.md), `examples/vulnerable` and `examples/review-config.json`. No AI account is needed. Run from the prepared workspace root containing `examples/`, with `invscan` on PATH.

**You will create:** A report with auditable reasons and separate open, justified and disabled counts.

</div>

## 1. Read the example policy

<div class="inv-step" markdown="1">

Open `examples/review-config.json` in your editor before running the scan. It contains these four illustrative decisions:

| Item | Decision | What it changes |
|---|---|---|
| Rule `AI018` | `disabled` | Excludes matching findings from active assessment, while preserving them in the report. |
| Rule `AI024` | `justified` | Records an accepted exception for matching findings. |
| Control `GOV-01` | `disabled` | Excludes this control from active review scope. |
| Check `AUTH-01:2` | `justified` | Records an exception for this acceptance check. |

<div class="inv-result" markdown="1">

**You should see** a `status` and a nonblank `reason` for each decision. Every supplied reason begins with **EXAMPLE ONLY**. These reasons explain the workflow; they are not evidence about your deployment.

</div>

A rule decision affects matching findings. A control or check decision changes review scope and does not automatically waive findings mapped to it.

</div>

## 2. Apply the policy explicitly

<div class="inv-step" markdown="1">

Pass the policy as a trusted input and save the resulting assessment.

<!-- invscan-step:07:policy -->
```sh
invscan examples/vulnerable --review-config examples/review-config.json --report scan-report/scenarios/07-policy --summary-json  # Expected exit 1
```

<div class="inv-result" markdown="1">

**You should see** **9 open findings**, **1 justified finding**, **1 disabled finding**, and **exit 1**. Other high-severity findings remain open.

</div>

Invarune does not automatically trust a policy it discovers inside the codebase being scanned. This command selects the file deliberately.

</div>

## 3. Check the reasons in the report

<div class="inv-step" markdown="1">

Open `scan-report/scenarios/07-policy/report.html`. Find the `AI024` finding and check its justified label and recorded reason. Then inspect `AI018` and the control/check review scope.

<div class="inv-result" markdown="1">

**You should see** the original evidence alongside each exception. The report also records one justified check and one disabled control. Neither justified nor disabled items earn pass credit or count against active totals.

</div>

There is no numerical security score. A justification records a user decision; it does not become a verified pass.

</div>

## Apply this to your own review

Copy the example configuration to a location you trust outside your assessed target. Keep only decisions you actually intend to apply, replace every illustrative reason with your own rationale, and pass that file with `--review-config`. A justified item needs a nonblank reason; invalid policies return exit 2 before optional AI calls.

Use [the full schema and precedence rules](../REVIEW_CONFIGURATION.md) when combining rule, control and check decisions. If you prefer to review individual findings in a report instead of writing policy, continue to the next walkthrough.


<div class="inv-journey-nav" markdown="1">

[← Use gates and baselines](06-ci.md)

[All walkthroughs](../SCENARIOS.md)

[Edit a report and rescan →](08-review.md)

</div>
