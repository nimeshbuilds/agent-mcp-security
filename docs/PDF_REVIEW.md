# Fillable PDF security reviews

Invarune can add a branded, interactive `report.pdf` to its normal HTML, Markdown, JSON and SARIF outputs. The four portable report formats use only the Python standard library when explicitly requested. A scan without report flags prints results in the terminal; `--pdf` implies report exports. PDF export and import require the optional extra:

```sh
# From this repository checkout, preferably in a virtual environment:
python3 -m pip install '.[pdf]'
invarune ./agent-repository --pdf --output first-report
invarune --image-archive agent-image.tar --pdf --output image-report
```

The PDF opens with actual finding/gap/file counts and severity charts. It includes clickable contents and bookmarks, the sanitized scan configuration, deterministic versus optional analyst coverage, known miss scenarios, the selected rule inventory from the 46-rule catalog, observed finding evidence and proposed mitigation layers, control-check text with source links, and interactive fields for every bound finding, check and coverage gap within the PDF item limit. Charts describe observed counts and catalog mappings; they are not accuracy scores, percent secure or verified control effectiveness.

## Edit, save and rescan

1. Open the PDF in an editor that supports interactive AcroForm fields.
2. Review the evidence. Choose a decision and enter a reason, reviewer, date and evidence reference in the corresponding fields.
3. Save an edited copy. Preserve the form and its embedded attachment. Do not flatten, print-to-PDF, rename fields or replace review decisions with freehand annotations.
4. Import that explicitly selected copy while scanning the same explicit target into a new output directory:

```sh
invarune ./agent-repository --review-report reviewed-copy.pdf --pdf --output reviewed-report
```

The importer starts from fresh source/image evidence. It does not replay commands, gateways, models or targets from the PDF. A changed file, scope, catalog or item binding makes the old decision stale; an edited PDF cannot silently justify different evidence. The original four report formats also support the bound review workflow and can be used when a PDF editor cannot preserve the form.

| Decision | Meaning |
|---|---|
| Unreviewed | The form's representation of a blank decision. Existing scanner semantics remain. |
| `justified` | An explicit human exception with a reason and reviewer. Excluded from active totals and applicable gates; never counted as a pass. |
| `disabled` | An explicit scope exception with a reason and reviewer. Retained for audit and excluded from active totals; never counted as a pass. |
| `note` | Commentary with a reason. Does not waive the finding or check. |
| `needs_runtime_validation` | Records outstanding environment-dependent validation and keeps the imported review incomplete. |
| `needs_human_review` | Records outstanding human validation and keeps the imported review incomplete. |

All nonblank decisions require a reason. Coverage gaps cannot be justified or disabled. A control/check decision does not automatically waive a shared rule's findings. Existing rule/control/check exception semantics remain described in [review configuration](REVIEW_CONFIGURATION.md).

## Why the PDF contains an attachment

Every exported PDF embeds `invarune-review.json`, the exact canonical review workspace. Its origin and item bindings identify the source/configuration/catalog/evidence to which the fields apply. When the complete original report fits within the attachment limit, `invarune-report.json` is also included for audit. Import uses the bound review workspace, not free text scraped from report paragraphs or annotations.

Field names are stable positions in the canonical item list: `ivr.INDEX.decision`, `ivr.INDEX.reason`, `ivr.INDEX.reviewer`, `ivr.INDEX.reviewed_at`, and `ivr.INDEX.evidence_ref`. The immutable item ID and binding stay in the capsule. Editing a field changes only a proposed human review value; the core importer validates the decision and its applicability.

The PDF importer validates both the canonical `/AcroForm/Fields` tree and each page's `/Widget` annotations. Every expected field must occur exactly once, have the expected type, and connect to its canonical widget. Canonical and widget values must agree, and the appearance stream's text must match the field value. A stale appearance, orphan widget, altered decision label, missing field, unknown field or duplicate capsule is rejected. It also rejects zero-area/off-page widgets, hidden widget flags, invisible text modes and unsupported degenerate appearance transforms. The importer does not blindly reattach ambiguous widgets or treat a successful visual render as proof that logical field data is correct.

## Compatibility and limits

- PDF input is capped at **50 MB**, the review capsule at **4 MB**, and PDF workspaces at **2,000 items**. Other report formats support the core workflow's own bounds. An optional PDF failure remains an operational error; it does not turn the source scan into a pass.
- Reasons allow 8,000 characters, reviewers 200, dates 64 and evidence references 2,000. Long form values may scroll inside their fields rather than fitting on a printed page.
- The portable form uses standard Western Type 1 fonts. Western text, including accented names, is supported. Non-Western prefilled review fields should use the Unicode JSON workflow. Static report text preserves unsupported characters as explicit escapes rather than silently dropping them.
- Import supports the exporter's ordinary text/dropdown AcroForms and bounded uncompressed/Flate streams. Encrypted PDFs, XFA, active document/form actions, JavaScript, nested widget appearances and embedded/CID form fonts are rejected. A PDF editor that changes those structures may require JSON review instead.
- Save with regenerated field appearances. A PDF that requests `/NeedAppearances` regeneration is not accepted as a finished review. Signed/flattened or damaged PDFs are not repaired automatically.
- These checks validate the supported review data and appearance-text relationship, not complete pixel visibility across all PDF viewers. Byte, capsule, item and appearance-stream limits do not provide a full CPU/memory sandbox around pypdf. They do not constitute a general-purpose PDF malware scanner, digital-signature verifier or operating-system sandbox for arbitrary third-party PDF parsers.

If import fails, preserve the edited PDF and use the editable JSON review workspace to record the same decision. Do not delete coverage errors or replace an unknown result with a passing label.

The [controlbook](../output/pdf/invarune-security-controlbook.pdf) explains the coverage/miss matrix and human/runtime workflow. The [benchmark PDF](../output/pdf/invarune-benchmark-report.pdf) adds navigation and measured coverage charts while preserving its dated 0.8.0 execution receipts. The PDF workflow is part of 0.9.0; those benchmark observations were not rerun or relabeled as 0.9.0 measurements.
