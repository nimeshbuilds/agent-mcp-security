# PDF artifact validation

Verified 19 September 2026 for the Invarune **0.9.0** document workflow. The expanded controlbook and comparative report were rebuilt with clickable contents, bookmarks, coverage charts, explicit deterministic/optional-review boundaries, configuration guidance and a human review/import workflow. Their original Invarune branding carries NimeshBuild attribution. No external organization's logo or full standard is reproduced.

| Artifact | Pages | Bookmarks | Link annotations | Unique external URLs | Interactive fields |
|---|---:|---:|---:|---:|---:|
| [Security controlbook](../output/pdf/invarune-security-controlbook.pdf) | 71 | 70 | 312 | 76 | 0 |
| [Comparative benchmark report](../output/pdf/invarune-benchmark-report.pdf) | 9 | 8 | 37 | 20 | 0 |
| [Actual source review roundtrip](../examples/reports/review-workflow/source/final-pdf/report.pdf) | 99 | 10 | 151 | 43 | 715 |

Every page of all three PDFs (**179 pages**) was rendered with Poppler and visually reviewed in contact sheets. New coverage/configuration/review-flow pages, the benchmark tables, dense source entries, mitigation prose and populated review forms were also inspected at larger scale. All pages contain extracted text; character-bounds inspection found **zero characters outside page boundaries**. Every internal link resolves to an existing page: **30** in the controlbook, **16** in the benchmark PDF and **20** in the scan PDF. All **88 bookmarks** resolve to valid pages. These checks apply to the recorded files and rendering environment, not every PDF viewer.

The controlbook includes **66 controls, 132 acceptance checks, 75 primary-source references, nine research benchmark entries and the 42-rule inventory**. `scripts/verify_controlbook.py` confirmed all control/check text, source IDs/titles and all 75 source URLs. Catalog charts show 26 controls with a static rule mapping and 40 without one. These are mapping counts, not passed controls or percent secure. Source/version limitations remain explicit.

The benchmark PDF preserves the actual **0.8.0** measurements: eight public projects, 149 pattern observations, 15 coverage gaps, 24 conventional-tool source scans, a partial Cisco metadata track and ten development fixtures. New navigation, measured coverage charts and the 0.9.0 workflow do not rerun or relabel those observations. Counts do not rank security quality or establish production accuracy. See [the detailed benchmark report](BENCHMARK_RESULTS.md).

Both authored PDFs reproduced **byte-identically** on repeated builds in the recorded environment:

```text
invarune-security-controlbook.pdf
05ad8a5ae72f9ad4b72b555d224698d432d4bf4fe6780d883aa744bd87da16ca

invarune-benchmark-report.pdf
1ea4c5e1ae9dede387ed7ebd787f7d73ca0129ee3d23d5012a90c4f1bb36f4d3
```

Build/render environment: Python **3.12.14**, ReportLab **4.4.9**, pypdf **6.10.0**, pdfplumber **0.11.9**, and Poppler. These are the bundled lower-bound PDF dependencies. The dedicated PDF tests also passed with the QA environment's ReportLab **4.5.1** and pypdf **6.19.0**.

## Optional scan PDF and form validation

The published [source scan PDF](../examples/reports/review-workflow/source/final-pdf/report.pdf) is the output of an actual installed CLI scan importing an edited PDF, not a mock report. `scripts/validate_report_review.py` ran **12 real CLI scans**: initial source/image scans and five review-format imports for each target. No model requests or target/container execution were needed. The selected source scan retained **10 open findings and one justified finding**, with **131 active checks and one justified check**, zero coverage gaps and exit **1** for remaining findings. The deliberate inert fixture exception is explicitly labeled test-only; it establishes no production safeguard. See the [published run receipt](../examples/reports/review-workflow/receipt.json).

The final scan PDF has **143 bound items** (11 findings and 132 checks), **715 canonical fields and 715 matching widgets**. Reloading its embedded capsule and form fields reproduces the adjacent JSON report's workspace exactly. All two imported decisions applied; none were stale, out of scope or unresolved. The final output was generated using the installed 0.9.0 wheel with Python **3.12.14**, ReportLab **4.5.1** and pypdf **6.19.0**. Its SHA-256 is:

```text
4a5e8353220064529e7f90428c45a1e6bc5d4dc0070f7e8a90954b9b5b5020d0
```

The reviewer can inspect the [edited PDF input](../examples/reports/review-workflow/source/reviewed.pdf), which has current appearances, then compare the fresh output. Optional-model content is separately covered by an explicitly synthetic advisory test PDF, including finding reasoning, additional concerns, per-check statuses, evidence quotations, omitted responses and proposed runtime experiments. That conditional advisory page was rendered and visually inspected; it is not presented as a live model result.

`tests/test_report_pdf.py` contains **23 tests** covering optional dependency failure, repeatable export, source/configuration/image limits and actual optional-review coverage, full check text, attachment roundtrip, canonical field and page-widget agreement, current appearance text, edited/re-exported Western Unicode, dropdown choices, complete advisory finding/check/citation content, explicit human check dispositions, and operational layout errors. PDF tests use an actual generated document; edits regenerate appearances through pypdf.

Adversarial fixtures reject stale canonical values, altered appearances, missing/duplicate/unknown/wrong-type fields, orphan/duplicate/hidden widgets, zero-area/off-page geometry, invisible text rendering mode, degenerate transforms, unsupported font size, changed decision labels, duplicate/missing/unexpected capsules, active actions, encryption, malformed/oversized JSON and excessive/truncated decompression. Gap dropdowns omit `justified` and `disabled`. A missing or unavailable complete review workspace prevents PDF export instead of silently losing review items.

An additional five-format audit applied explicit test-only human decisions, wrote HTML/Markdown/JSON/SARIF/PDF, loaded each format and verified exact canonical workspace, evidence bindings and justification counts. Accented reviewer names and euro-symbol reasons survived PDF edit and re-export. These are controlled fixture checks, not a claim of universal compatibility with third-party PDF editors.

The importer checks supported structural and appearance-text relationships. It does **not** prove complete pixel visibility across all PDF viewers, authenticate the human reviewer, verify digital signatures, scan arbitrary PDFs for malware, or provide a CPU/memory sandbox around pypdf. Input, attachment, item and appearance-stream bounds reduce exposure but do not replace parser isolation. Unsupported editors/forms should use the bound JSON workflow. See [PDF review compatibility and limits](PDF_REVIEW.md) and [review semantics](REVIEW_WORKFLOW.md).

## Reproduction and historical artifacts

```sh
python3 scripts/build_controlbook.py
python3 scripts/verify_controlbook.py
python3 scripts/build_benchmark_report.py
python3 -m unittest discover -s tests -p 'test_report_pdf.py' -v
```

Repeat all-page rendering, structural/form validation and visual inspection after any content, typography or dependency change. General scanner, CLI and packaging evidence is recorded in [implementation validation](VALIDATION.md).

Historical 0.8.0 artifacts were independently inspected as **65-page** controlbook and **six-page** benchmark PDF. Their former hashes are retained here for provenance; these are not hashes of the expanded current documents:

```text
0.8.0 controlbook: ecd12ee5d9c4ab70cfebe4f34db1a91747fa6d87df3ff4b97dc5af080d20061b
0.8.0 benchmark:   9aa60a8ffd353a451aa3c2da2b7293b69c6f9f7ba6400fed60099126f6f98f78
```
