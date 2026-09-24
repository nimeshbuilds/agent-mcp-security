# Explore what invscan checks

<p class="inv-eyebrow">WALKTHROUGH 01 · OFFLINE</p>

Learn how to ask a security question, find a scan, and trace it to a control and its source guidance.

<div class="inv-journey-meta" markdown="1">

**You need:** A [prepared workspace](setup.md) with `invscan` on PATH. Stay in the extracted bundle folder or repository root. No AI account is needed.

**You will create:** No files. These commands read the bundled catalog and print to your terminal; they do not scan a target or call a model.

</div>

## 1. Check that invscan is ready

<div class="inv-step" markdown="1">

Run this in your prepared terminal.

<!-- invscan-step:01:version -->
```sh
invscan --version
```

<div class="inv-result" markdown="1">

**You should see** `0.15.0` and exit **0**. If the command is missing, return to [workspace setup](setup.md) before continuing.

</div>

</div>
## 2. Ask a security question

<div class="inv-step" markdown="1">

Ask about prompt injection in plain English. The answer comes from deterministic catalog search.

<!-- invscan-step:01:question -->
```sh
invscan --ask 'How do you check prompt injection?'
```

<div class="inv-result" markdown="1">

**You should see** A topic answer with relevant checks, controls and source guidance. No login or agentic mode is required. An unmatched question returns an explicit no-match response.

</div>

</div>
## 3. Find the available scans

<div class="inv-step" markdown="1">

List the rules and find **AI043** in the output.

<!-- invscan-step:01:rules -->
```sh
invscan --list-rules
```

<div class="inv-result" markdown="1">

**You should see** **47 deterministic rules.** A listed rule describes a supported risk pattern; the list is not a guarantee of complete security coverage.

</div>

</div>
## 4. Understand one scan

<div class="inv-step" markdown="1">

Ask for the explanation of AI043 before using it on a skill.

<!-- invscan-step:01:rule -->
```sh
invscan --explain-scan AI043
```

<div class="inv-result" markdown="1">

**You should see** The scan’s purpose, supported inputs, mapped controls, fix guidance and limitations. You can try it on a risky skill in [walkthrough 3](03-skills.md).

</div>

</div>
## 5. Read the control behind a security requirement

<div class="inv-step" markdown="1">

Start with the authentication control.

<!-- invscan-step:01:control -->
```sh
invscan --explain-control AUTH-01
```

Read its first acceptance check in detail:

<!-- invscan-step:01:check -->
```sh
invscan --explain-check AUTH-01:1
```

<div class="inv-result" markdown="1">

**You should see** The **AUTH-01** control and check **AUTH-01:1**, including why they matter and how to validate them. A detector mapping is partial coverage, not a compliance certification.

</div>

</div>
## Explore more when you need it

<details class="inv-option" markdown="1">
<summary>Find topics, list every control, or export the scan inventory</summary>

List the available plain-English topics:

<!-- invscan-step:01:topics -->
```sh
invscan --list-topics
```

List the controls:

<!-- invscan-step:01:controls -->
```sh
invscan --list-controls
```

Export the scan inventory as JSON for tools or automation:

<!-- invscan-step:01:inventory -->
```sh
invscan --list-scans --catalog-format json
```

<div class="inv-result" markdown="1">

**You should see** A catalog containing **66 controls**, **132 acceptance checks** and the **47-rule** inventory. The JSON command prints JSON; it does not save a file.

</div>

</details>
<details class="inv-option" markdown="1">
<summary>Trace the original guidance and benchmark sources</summary>

List the source registry, then inspect the MITRE ATLAS record.

<!-- invscan-step:01:sources -->
```sh
invscan --list-sources
```

<!-- invscan-step:01:source -->
```sh
invscan --explain-source MITRE-ATLAS
```

<div class="inv-result" markdown="1">

**You should see** **78 source records**, with the MITRE ATLAS explanation linking to its original guidance. Source references explain the design of a control; they do not certify this scanner.

</div>

</details>
<details class="inv-option" markdown="1">
<summary>Open the full reference and example cookbook</summary>

Read the full help reference:

<!-- invscan-step:01:full_help -->
```sh
invscan --help
```

The short help flag gives the same reference:

<!-- invscan-step:01:short_help -->
```sh
invscan -h
```

Show all focused help topics:

<!-- invscan-step:01:all_help -->
```sh
invscan --help-topic all
```

Browse runnable examples:

<!-- invscan-step:01:cookbook -->
```sh
invscan --examples
```

The older rule explainer remains available:

<!-- invscan-step:01:rule_alias -->
```sh
invscan --explain-rule AI002
```

All of these commands work offline and return exit **0**.

</details>
<details class="inv-option" markdown="1">
<summary>Python package only: check the alternate command names</summary>

Skip this section if you downloaded a native archive. Wheel/source installations also provide these two aliases:

<!-- invscan-step:01:invarune -->
```sh
invarune --version
```

<!-- invscan-step:01:ai-security-scan -->
```sh
ai-security-scan --version
```

Both should print `0.15.0`. Native archives provide `invscan` only.

</details>

**Done:** You can find a scan, understand its limits and identify its source guidance. [Explorer reference](../SECURITY_EXPLORER.md) · [Coverage matrix](../SCAN_COVERAGE.md).

<div class="inv-journey-nav" markdown="1">

[All walkthroughs](../SCENARIOS.md)

[Create your first report →](02-source.md)

</div>
