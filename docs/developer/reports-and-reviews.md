# Reports, exceptions and review imports

Reports preserve three separate kinds of evidence: what static analysis observed, what the user explicitly accepted or excluded, and what an optional model suggested. Keep those categories separate when adding fields, rendering summaries or calculating counts.

The user workflow is documented in [reviewing and rescanning reports](../REVIEW_WORKFLOW.md). This guide describes the implementation contract.

## Report construction

`scanner.scan()` returns a schema `1.0` static report. `image_scan.scan_image()` adds image identity and merged image evidence before review policy runs. Key sections are:

| Section | Meaning |
|---|---|
| `tool`, `scan_id`, `configuration` | Implementation identity and selected deterministic scope. |
| `files`, `inventory` | Selected manifest and observed inventory, not a complete dependency or asset inventory. |
| `findings` | Stable finding IDs, rule metadata, location, redacted evidence and disposition. |
| `controls` | Catalog checks, mapped static signals and review requirements. |
| `summary`, `coverage` | Active finding counts, selected-scope completeness, errors, skips and analysis limits. |
| `review_policy`, `review_import`, `review_workspace` | Explicit user decisions, fresh binding audit and editable capsule. |
| `judge`, `analyst` | Optional advisory results and their own coverage/failures. |
| `methodology`, `assessment`, `remediation`, `advice_coverage`, `scoring` | Provenance, executive interpretation, treatment proposals and explicit scope/answer metrics; no universal security score. |
| `run_configuration`, `execution` | Selected execution options and the resulting CLI gate, when populated by the coordinator. |

[`report.prepare_report()`](../../ai_security_scan/report.py) enriches a copy in memory with methodology, remediation, assessment and scoring. The terminal path uses this without writing report artifacts. `report.write_reports()` prepares the report and writes `report.json`, `report.md`, `report.sarif` and `report.html`. `atomic_write()` uses a temporary sibling and replacement, rejects symlink output destinations and emits UTF-8/LF. Each file replacement is atomic; the four-file set is not a transaction. Do not describe a partly failed export as a complete bundle.

The CLI requests [`report_pdf.render_pdf()`](../../ai_security_scan/report_pdf.py) separately when `--pdf` is enabled. An optional PDF failure preserves the four portable reports, adds export failure information and returns exit 2. If a review capsule exceeds its limits, reports are also preserved with `review_workspace_unavailable`; they must not advertise editable replay as available.

`build_assessment()` groups findings for the executive view. `build_remediation()` attaches steps and verification scenarios to every finding, including exceptions. Suggested layers are `proposed_not_verified`; reporting must not assume they are deployed or silently reduce risk.

## Finding and check dispositions

[`review_policy.py`](../../ai_security_scan/review_policy.py) provides `validate_review_config()`, `load_review_config()` and `apply_review_config()`. The public configuration accepts exactly `schema_version`, `rules`, `controls` and `checks`. It is loaded only when explicitly selected; a target repository cannot auto-enable its own exceptions.

```json
{
  "schema_version": "1.0",
  "rules": {
    "AI018": {"status": "disabled", "reason": "EXAMPLE: reviewed in a separate release assessment."}
  },
  "checks": {
    "AUTH-01:2": {"status": "justified", "reason": "EXAMPLE: owner reviewed external authentication evidence."}
  }
}
```

Do not reuse example rationales as evidence. A real exception needs an accountable rationale for the selected scope.

The validator rejects unknown IDs/fields, duplicate keys, unsupported JSON values, invalid text and a whole-control exception combined with one of its child-check exceptions. Configurations are capped at 1,000,000 bytes; reasons at 8,000 characters. `justified` requires a nonblank reason; `disabled` permits a documented default reason.

Rules still execute. A rule exception changes the status of retained findings; it does not skip detector execution. A control/check exception removes acceptance checks from active review, but never waives unrelated or mapped static findings. The internal `finding_dispositions` argument to `apply_review_config()` supports granular imported decisions; it is not a fifth public JSON field.

| Status | Counting and audit behavior |
|---|---|
| `open` | Counts toward active severity and finding gates. |
| `suppressed` | Explicit matching baseline ID and reason; retained separately. |
| `justified` | User exception, excluded from active counts; never a validated pass. |
| `disabled` | User exclusion, excluded from active counts; evidence remains. |

Explicit rule/finding dispositions take precedence over baseline suppression while retaining the original status and baseline rationale. Applying the same policy again is idempotent; changing policy requires the original static report. `review_policy.counts` keeps catalog, active, justified and disabled counts separate. `excluded_controls` is the total with no active checks; `mixed_excluded_controls` is its mixed-disposition subset, not an additional disjoint total.

Static control status is retained under `static_status` when policy recomputes the view. A control with only excluded checks can be `justified`, `disabled` or `excluded_from_review`; none means its acceptance criteria passed. Operational failures remain coverage gaps and cannot be waived by policy.

## Editable workspace schema

[`review_workspace.py`](../../ai_security_scan/review_workspace.py) builds a canonical capsule with `schema_version: "1.0"`, `kind: "invarune_review"`, `origin` and `items`. `origin` records the static scan ID, tool identity, safe target description, selected configuration/image limits, and manifest/catalog/evidence/scope hashes. It does not supply a target command, model endpoint or credentials for replay.

Each item has immutable `id`, `kind`, `subject`, `binding_sha256`, plus these editable strings:

| Field | Limit | Contract |
|---|---:|---|
| `decision` | 32 characters | Blank, `justified`, `disabled`, `note`, `needs_runtime_validation` or `needs_human_review`. |
| `reason` | 8,000 | Required and nonblank for every nonblank decision. |
| `reviewer` | 200 | Required for justified/disabled; an audit label, not an authenticated signature. |
| `reviewed_at` | 64 | Optional valid ISO date or timestamp. |
| `evidence_ref` | 2,000 | Optional reference text; never automatically fetched or executed. |

Item IDs are `finding:<finding-id>`, `check:<CONTROL>:<one-based-index>` and `gap:<digest>`. Gaps allow notes and unresolved-review decisions only. There is no manual `pass` or `fixed` decision. Blank decisions require the other editable fields to remain blank; use `note` for commentary.

`build_workspace()` excludes model text and advisory status from capsule identity. An identical static scan with and without AI review must produce the same capsule unless explicit user decisions differ. Findings bind their evidence, manifest entry, baseline provenance, selected scope, scanner implementation/version, catalog and image identity. Checks bind the whole selected manifest, acceptance text, mapped rules and coverage gaps. Changing code or scope can therefore invalidate an exception even if its visible title is unchanged.

## Import only the designated capsule

`load_review_report()` reads a bounded regular non-symlink file. It parses data without executing HTML, report commands or embedded instructions.

| Format | Canonical capsule location |
|---|---|
| JSON report | `review_workspace`; a standalone `invarune_review` capsule is also accepted. |
| SARIF | `runs[0].properties.invarune_review`, with exactly one run. |
| Markdown | One fenced JSON block between `<!-- INVARUNE_REVIEW_BEGIN -->` and `<!-- INVARUNE_REVIEW_END -->`. |
| HTML | One `<script type="application/json" id="invarune-review">` element. |
| PDF | Attached canonical capsule plus validated AcroForm edits, through `extract_review_workspace()`. |

Input reports are capped at 50,000,000 bytes, capsules at 4,000,000 bytes and workspaces at 10,000 items. Duplicate keys, unknown rows/fields, invalid bindings and ambiguous capsules are errors. Ordinary report prose, edited severity, model advice and unbound display text cannot override a finding.

PDF adds a 2,000-item form limit and rejects encrypted/active documents, unexpected attachments, ambiguous widgets and mismatches between field values and visible appearances. Forms use Western `cp1252` editable text; use JSON for other Unicode. Saving must regenerate appearances. Do not silently repair a form whose displayed decision differs from its stored value. See [PDF validation](../PDF_VALIDATION.md).

## Fresh replay and incomplete outcomes

`apply_review_workspace(report, workspace)` requires an original fresh static report without a previous policy/import applied. The CLI prevents using `--review-config` and `--review-report` together. Baselines remain explicit and contribute to binding provenance.

Replay compares immutable identity before redaction, applies only unchanged items and carries user fields into a refreshed capsule. `review_import` records the imported artifact hash, original scan ID and these outcomes:

- `applied`: the selected decision still matches fresh evidence.
- `stale`: the item exists but its context/binding changed; the old decision is not applied.
- `not_redetected`: a former item is absent from a complete compatible scope. This does not establish a fix.
- `out_of_scope`: absence cannot be interpreted because scope or completeness changed.
- `unresolved`: an applied decision explicitly still needs runtime or human review.

Stale, out-of-scope or unresolved decisions make `review_import.incomplete` true. The CLI returns exit 2, which takes precedence over the normal finding gate. A plain note does not create a failing gate; blank unreviewed catalog checks do not automatically fail a deterministic-only scan. Source read errors, analyst omissions and failed exports have their own explicit incomplete paths.

## Tests for contract changes

```sh
python -m unittest tests.test_review_policy tests.test_review_workspace tests.test_review_policy_reports -v
python -m unittest tests.test_review_policy_cli tests.test_review_roundtrip_cli tests.test_report_review_editor -v
python -m unittest tests.test_report_pdf -v
```

The last group needs PDF dependencies. Test source/config/catalog drift, retained image context, policy precedence, count partitions, report round trips, malformed imports, redaction and operational-failure precedence. Keep SARIF static results stable with/without model advice. For an installed five-format reproduction, use the [release validator](testing-and-releasing.md#installed-workflows).
