# Inspect a skill and choose your checks

<p class="inv-eyebrow">WALKTHROUGH 03 · SKILLS & TOOLS</p>

Find supported risky instruction patterns in a skill, then see how selecting rules changes what gets assessed.

<div class="inv-journey-meta" markdown="1">

**You need:** A [prepared workspace](setup.md) with `invscan` on PATH. Stay in the extracted bundle folder or repository root. No AI account is needed.

**You will create:** A focused skill report in `scan-report/scenarios/03-skills/`.

</div>

## 1. Scan the risky skill example

<div class="inv-step" markdown="1">

Inspect instruction overrides, sensitive-transfer directives, approval/concealment bypasses and read-only annotation conflicts using AI043–AI046.

<!-- invscan-step:03:skill_metadata -->
```sh
invscan examples/skills/risky --scans AI043,AI044,AI045,AI046 --report scan-report/scenarios/03-skills --summary-json  # Expected exit 1
```

<div class="inv-result" markdown="1">

**You should see** **4 findings**, **0 coverage gaps**, and exit **1**. Open `scan-report/scenarios/03-skills/report.html` to read the instruction evidence and suggested fixes. The scanner does not follow the skill’s instructions.

</div>

</div>
## 2. Select just two source rules

<div class="inv-step" markdown="1">

Use a comma-separated list to focus a different scan on AI001 and AI002.

<!-- invscan-step:03:selected_rules -->
```sh
invscan examples/vulnerable --scans AI001,AI002 --summary-json  # Expected exit 1
```

<div class="inv-result" markdown="1">

**You should see** A terminal JSON summary with selected rule IDs **AI001** and **AI002**, and exit **1**. No report files are created. Other rules sharing a mapped control are not silently enabled.

</div>

</div>
## 3. Recognize a control that needs other evidence

<div class="inv-step" markdown="1">

Select governance control GOV-01 using the equivalent singular `--scan` spelling.

<!-- invscan-step:03:manual_control -->
```sh
invscan examples/vulnerable --scan GOV-01 --summary-json
```

<div class="inv-result" markdown="1">

**You should see** **0 selected static rules**, **2 active acceptance checks**, **0 findings**, and exit **0**. This is a review plan—not a passed governance control. Organizational evidence still needs review.

</div>

</div>

**Done:** You can inspect a skill and choose an exact assessment scope. Comma-separated and repeated `--scans` selections combine. Static skill coverage includes recognized instruction files, bounded local Markdown references and supported associated code/configuration. Remote references, arbitrary prose meaning and runtime behavior remain outside that guarantee. [Full scan scope](../SCAN_COVERAGE.md).

<div class="inv-journey-nav" markdown="1">

[← Create your first report](02-source.md)

[All walkthroughs](../SCENARIOS.md)

[Control scan scope →](04-scope.md)

</div>
