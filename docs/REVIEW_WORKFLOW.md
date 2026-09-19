# Review a report and scan again

Invarune 0.9 adds an editable review workspace to every newly generated HTML, Markdown, JSON and SARIF report. `--pdf` adds a branded, fillable PDF of the same scan. All five formats can supply user decisions to `--review-report`.

The workflow always performs a **fresh source or image scan**. It compares current evidence with the prior report, carries forward applicable user decisions, and produces a new result with an import audit. A report never supplies executable instructions, automatic model authorization or a replacement for the target being assessed.

## Create the initial report

The four portable formats remain dependency-free. For PDF export and PDF import, install the optional extra in your scanner environment:

```sh
python3 -m pip install '.[pdf]'
invarune /absolute/path/to/agent-repo --pdf --output /absolute/path/to/initial-report
```

For a built image instead:

```sh
invarune --image-archive ./agent-image.tar --pdf --output ./initial-image-report
```

Keep reports outside the source target and preserve the initial report. You can add an explicitly selected `--judge-cli` or `--judge-config`; model review remains optional. Neither an imported report nor a filled form enables it automatically.

## Review the evidence and fill the fields

The reports explain the scan's purpose, effective settings, deterministic techniques, optional analyst workflow and known blind spots. Charts show **observed counts or catalog mapping**, never a percentage secure or a measured accuracy score. Runtime behavior, deployment controls and human processes remain separate validation work.

Every finding, acceptance check and recorded scan gap has its own review item. Only these fields are editable:

| Field | Meaning |
|---|---|
| `decision` | Empty, `justified`, `disabled`, `note`, `needs_runtime_validation`, or `needs_human_review`. |
| `reason` | Your rationale, result summary or outstanding question. Required for every nonempty decision; at most 8,000 characters. |
| `reviewer` | Who made the decision. Required for justified/disabled items; at most 200 characters. This is recorded text, not authenticated identity. |
| `reviewed_at` | Optional ISO date or timestamp, such as `2026-09-19`; at most 64 characters. It does not implement automatic expiration. |
| `evidence_ref` | Optional ticket, test-result reference or evidence location; at most 2,000 characters. Invarune never follows or executes it. |

Use `note` to record context without excluding an item. A blank decision requires the accompanying fields to stay blank. There is no manually selected `pass` or `fixed` status: a justification is an accepted user exception, not proof that a security control works.

| Format | How to save a review the CLI can import |
|---|---|
| HTML | Fill the local form and click **Download reviewed HTML**. The button preserves the edited fields and embedded review data. Browser Save As may not preserve live form values. A separate JSON download is also available. |
| PDF | Open the scan's `report.pdf` in a compatible form editor, fill the fields and save an editable PDF. Do not flatten it, print it to PDF, or remove attachments/form fields. |
| Markdown | Edit the five fields in the fenced JSON block between `INVARUNE_REVIEW_BEGIN` and `INVARUNE_REVIEW_END`. Keep valid JSON and preserve the markers. Ordinary prose edits are not imported. |
| JSON | Edit item fields inside `review_workspace.items`. Other report edits do not alter scan findings. |
| SARIF | Edit item fields inside `runs[0].properties.invarune_review.items`. Ordinary SARIF suppressions or message edits are not imported as user decisions. |

Keep item identifiers, subjects, evidence bindings, origin metadata and schema fields unchanged. HTML's save helper is one fixed local script allowed by a content-policy hash; it does not call a service or run source/model content. Reading and navigation still work without JavaScript; saving HTML form edits needs that local helper.

The general controlbook and benchmark PDFs explain the system. They are not scan review inputs: import the **fillable PDF generated from a specific scan**, which carries that scan's evidence bindings and review fields.

## Run a fresh scan using the reviewed report

```sh
invarune /absolute/path/to/agent-repo --review-report ./reviewed-report.html --pdf --output ./final-report
invarune --image-archive ./agent-image.tar --review-report ./reviewed-report.pdf --output ./final-image-report
```

Use `.md`, `.json` or `.sarif` instead of `.html` with the same flag. Choose a new output directory: the CLI rejects overwriting the imported file, including recognized aliases. The selected target must exist; source is still needed for a source scan, while an image scan needs its image/archive.

The report retains the original selected configuration and hashes needed to compare context. **Your current CLI flags select the new scan.** Repeat intended exclusions and limits; they are not silently restored from the document. Credentials, executable paths, model settings and registry pulls are never replayed from a report. Select a model again explicitly if you want another advisory review. `--review-report` and `--review-config` are mutually exclusive; an explicitly supplied legacy baseline remains a separate input.

## Interpret the final result

| Imported decision or change | Result |
|---|---|
| Unchanged finding, justified/disabled | Applies only to that finding. Other occurrences of the same rule remain active. Evidence and original severity remain visible. |
| Unchanged checklist item, justified/disabled | Excludes that acceptance check from active counts and optional analyst requests. It does not waive mapped findings. |
| `note` | Retains your note; no exclusion or positive credit. |
| Explicit runtime/human follow-up | Remains unresolved; the requested review is incomplete and returns exit 2. |
| Changed evidence, scope, scanner or catalog | The prior decision is stale/unapplied and retained for re-review. The fresh finding is not silently exempted. |
| Previously reviewed item absent from a complete comparable scan | Recorded as `not_redetected`. This does not establish remediation or prove a vulnerability was fixed. |
| No comparable coverage for an absent item | Recorded as `out_of_scope`; the review remains incomplete. |
| A coverage gap | Notes can document it, but justifying/disabling the gap is rejected. Scanning errors stay actionable. |

Justified and disabled items earn no positive credit and do not count against active totals. There is no numerical security score. User notes are retained locally in the review audit rather than being automatically added to model finding payloads.

The new report's executive assessment and `review_import` record show applied, stale, not-redetected, out-of-scope and unresolved items, the prior scan ID, and the imported artifact's SHA-256. The fresh report has a new scan identity. Its refreshed review workspace can be edited and imported again.

Exit 0 means the selected scan/review completed below the chosen open-finding threshold; exit 1 means findings reached it; exit 2 means incomplete/failed work. `--fail-on none` cannot waive stale review decisions, explicit validation follow-ups, PDF export errors or scan gaps. Unanswered runtime questions in the ordinary control catalog remain unvalidated even when a static-only scan exits 0.

## Boundaries and portability

Imports are explicit trusted user decisions. Digests detect context changes; they are not digital signatures or proof that a reviewer performed the stated test. Binding source bytes does not validate a different deployment's compensating controls. Owners must confirm that their evidence and exceptions apply to the actual deployment.

The importer reads only the designated review data and validates strict identifiers, fields and limits. It does not execute HTML/PDF actions, scan document links, trust model prose, or accept arbitrary report severity edits. Inputs are bounded to 50,000,000 bytes, capsules to 4,000,000 bytes and 10,000 items. Oversized or ambiguous imports fail explicitly. If a newly scanned scope exceeds the capsule limit, all four static reports retain their findings, explain why editable review is unavailable, and return exit 2. No partial capsule or partial set of imported decisions is accepted; choose a smaller explicit scope and repeat the review. PDF form values, canonical fields and supported appearance text must agree; unsupported or flattened PDFs require an editable original. These checks do not establish pixel-for-pixel visibility in every viewer. Document/capsule/stream limits are not a complete CPU or memory sandbox around the optional PDF parser; import reports from your trusted review workflow.

PDF export/import supports at most 2,000 review items and portable Western-text AcroForms. Non-Western review text and PDF editors that replace the supported appearance/font structure should use HTML, Markdown, JSON or SARIF instead. PDF export failures leave the four portable reports available and return exit 2. This PDF scope is explicit rather than silently losing form data.

Reports from earlier versions without a review workspace must be regenerated. Preserve the original evidence and reviewed file as audit artifacts. See [quick start](QUICKSTART.md), [complete CLI reference](CLI.md), [review configuration](REVIEW_CONFIGURATION.md), and [report interpretation](REPORTS.md).
