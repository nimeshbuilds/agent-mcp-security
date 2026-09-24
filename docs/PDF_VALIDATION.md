# PDF artifact validation

## Current v0.15 security controlbook

The [current Invarune controlbook](../output/pdf/invarune-security-controlbook.pdf) was regenerated from scanner **0.15.0** and the frozen rule/catalog metadata. It has **123 pages, 123 bookmarks, 81 internal links and 79 unique external URLs**, including all **78 source records**. Its **47 exact scan contracts** describe the predicate, supported algorithm, limits, agent/MCP relevance, optional review, remediation and source relationships. All **66 controls and 132 acceptance checks** are present; static rules partially map to 30 controls. Mapping is not a passed control or security score.

The revised explanations cover bounded Python argument/return flow, recognized and convention-based tool input boundaries, narrow JavaScript wrappers and inline registrations, finite literal constraints, world-writable permissions, instruction/schema metadata and read-only tool effect conflicts. Optional review describes captured-evidence range requests, counterevidence, deterministic controller limits and unchanged static results. Source entries show their individual access dates. The [cover preview](assets/controlbook-cover.png) is rendered from this edition.

All **123 pages** were rendered with Poppler and visually inspected in six contact sheets. The cover, contents, execution coverage, analyst workflow, SSRF/filesystem rules, instruction rules, tool effects, permissions and new source-reference pages were also reviewed at full size. A final correction changed two option names on the CLI field-guide page: every page was rendered again, 122 page PNGs matched the previously reviewed bytes exactly, and the sole changed page 11 was visually inspected at full size. No clipping or overlap was observed; word-bounds inspection found zero words outside pages. Every internal destination and bookmark resolves. The final repeat build was byte-identical in the recorded environment.

The [hash-bound controlbook QA receipt](../benchmarks/validation-v015/controlbook-receipt.json) records artifact, catalog, builder and verifier hashes, rendered-page hash provenance, completeness checks and dependency versions. This is a reference book with no editable fields. Operational scan reports have separate bound review forms and validation receipts. These checks do not establish scanner accuracy, source-site availability, compliance or identical behavior in every PDF viewer. The v0.14 edition is retained at its archived path below.

## Historical release: v0.14

These versioned PDFs were regenerated from the **0.14.0** implementation and current catalogs. Their QA receipts identify exact artifact, source/input and builder hashes; they do not relabel historical scans as new measurements.

| Artifact | Pages | Bookmarks | Internal links | Unique external URLs | Editable fields |
| --- | ---: | ---: | ---: | ---: | ---: |
| [Current benchmark update](../output/pdf/invarune-benchmark-v014.pdf) | 9 | 9 | 7 | 14 | 0 |
| [Archived v0.14 security controlbook](../output/pdf/invarune-security-controlbook-v014.pdf) | 121 | 121 | 80 | 77 | 0 |
| [Selected deterministic skill/tool scan](../examples/reports/v014/skills-static/report.pdf) | 27 | 12 | 69 | 8 | 80 |
| [Selected Claude authentication-failure scan](../examples/reports/v014/skills-claude/report.pdf) | 31 | 13 | 71 | 8 | 80 |
| [Selected successful Codex review](../examples/reports/v014/skills-codex/report.pdf) | 39 | 13 | 71 | 8 | 80 |

All **227 pages** were rendered with Poppler and visually inspected at contact-sheet scale; selected dense, executive, finding and form pages were also inspected at full size. The receipts record no clipping or overlap. All internal destinations resolve. The benchmark and controlbook also reproduced byte-identically on repeat builds. These checks describe the recorded rendering environment, not every PDF viewer.

The [benchmark QA receipt](../benchmarks/validation-v014/benchmark-pdf-receipt.json) binds the current eight-project comparison and separate skill/tool evaluation to the PDF. It checks expected metric text and the absence of misleading historical-comparison links. The measured 146 source patterns, 21 gaps and both fixture denominators remain separate; no independent production vulnerability truth or model adjudication is claimed.

The [controlbook QA receipt](../benchmarks/validation-v014/controlbook-receipt.json) verifies **46 rule predicates, algorithms, limitations, agent/skill relevance and remediation**, plus **66 controls, 132 checks and 76 source records**. The current catalog maps rules partially to **30 controls**. These are documented coverage relationships, not passed controls. All control/check text and source links are present.

The [selected scan PDF receipt](../benchmarks/validation-v014/skill-pdfs-receipt.json) verifies each PDF's **16 bound review items, 80 canonical fields and 80 matching widgets**, including supported appearances. Strict extraction reproduces the adjacent JSON review workspace and embedded full report exactly. The downloadable example copies match their corresponding output PDFs byte-for-byte.

All three selected scan PDFs retain the same four deterministic findings (three high, one medium), six selected controls and twelve checks. The deterministic run has AI disabled and exits 1. Claude was requested but signed out: zero accepted answers, twelve unreviewed checks and exit 2. Its PDF does not claim successful Claude analysis. The [successful Codex PDF](../examples/reports/v014/skills-codex/report.pdf) and [HTML report](../examples/reports/v014/skills-codex/report.html) completed 12/12 selected answers, with ten insufficient-evidence answers and two potential gaps. Its exit remains 1 from the same static severity gate; answer completion does not establish a passed control. These are inert-fixture examples, not public vulnerability assessments. [Run details](../examples/reports/v014/README.md).

Current PDF generation and structural checks used ReportLab **4.5.1** and pypdf **6.19.0**. The scanner implementation fingerprint for the current benchmark and skill reports is `a10cff2be83ee83ef7f016e0d9644b42b2cc9869528a91763840970dc87765f1`. Exact PDF hashes are in the linked receipts.

## Historical benchmark publication: v0.13

The [updated benchmark PDF](../output/pdf/invarune-benchmark-v013.pdf) has **9 pages and 9 bookmarks**, with a clickable contents page, vector charts, source/finding comparison tables and the original Invarune mark. Every page was rendered with Poppler and visually inspected. All internal destinations resolve; the [hash-bound QA receipt](../benchmarks/validation-v013/pdf-receipt.json) records artifact/input hashes and link counts. This is an explanatory benchmark publication, not an editable operational scan report. Earlier PDF measurements below remain historical.

## Historical v0.9 document workflow

The counts and hashes in this section describe the former **0.9.0** documents, verified 19 September 2026. The controlbook at the current download path has since been replaced by the 121-page 0.14 edition above; the old 71-page counts and hash do not describe that current file.

Verified 19 September 2026 for the Invarune **0.9.0** document workflow. The expanded controlbook and comparative report were rebuilt with clickable contents, bookmarks, coverage charts, explicit deterministic/optional-review boundaries, configuration guidance and a human review/import workflow. Their original Invarune branding carries NimeshBuild attribution. No external organization's logo or full standard is reproduced.

| Artifact | Pages | Bookmarks | Link annotations | Unique external URLs | Interactive fields |
|---|---:|---:|---:|---:|---:|
| Historical 0.9 controlbook (superseded; current edition above) | 71 | 70 | 312 | 76 | 0 |
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

## Version 0.10 report and comparison artifacts

The new **13-page finding comparison PDF** contains charts, clickable contents, current/historical provenance, exact match/unknown accounting, a 50-observation source audit and source links. The actual Claude adjudication attempt produced no model answers; its point estimate is explicitly unavailable. The **119-page Claude-enabled scan PDF** preserves 11 deterministic findings with concrete fix plans, all 66 controls and 132 checks, and 715 fillable fields for 143 review items. Its cover and executive summary clearly report the authentication failure and incomplete optional work; it is not a successfully Claude-reviewed report.

All **132 pages** were rendered with Poppler and visually inspected. Every internal link and outline destination resolves, all external links use HTTPS, and the scan PDF's extracted bound review workspace matches its JSON report. The comparison's source-hash appendix was adjusted to keep complete hashes and the reproduction instructions together on its final page. The PDFs have separate purposes: the comparison is a research document; only the operational scan report accepts review-form edits.

[Exact artifact hashes, page/link/field counts and validation receipt](../benchmarks/validation-v010/pdf-receipt.json). This inspection does not establish every PDF viewer's editing behavior; the automated fresh-scan import workflow separately verifies actual field edits and re-export.

## Version 0.11 decision-first scan report

The fresh [Invarune 0.11 scan PDF](../examples/reports/invscan-v011/report.pdf) opens with the actual result, immediate concerns, observed locations and linked first actions. The priorities chart and complete findings follow before the configuration and methodology appendices. Each finding retains its concrete fix plan, conditional agent/MCP relevance, source references, mitigating layers and a link to its review fields. The [cover preview](assets/invscan-v011-report-cover.png) is rendered directly from this final PDF.

All **114 pages** were rendered with Poppler and visually inspected in 19 contact sheets; the executive summary, priorities, finding details, configuration, optimization receipt and first review forms were also inspected at larger scale. No layout defects were observed. Word-bounds inspection found **zero words outside page boundaries**. All **336 internal links** resolve to valid pages, all **12 bookmarks** resolve to pages containing their named headings, and all **156 external link annotations** use HTTPS. Navigation was verified structurally, without claiming native PDF viewer interaction or rechecking external website availability.

The document contains **143 bound review items**, **715 canonical fields** and **715 matching widgets**. Strict extraction reproduces the adjacent JSON workspace exactly, and both embedded JSON attachments match their corresponding report data. A disposable copy was edited at the first and last review items, changing all five fields for each with regenerated appearances; strict reimport preserved those ten changes and every other field and evidence binding. The published PDF remained unchanged. This verifies the supported pypdf workflow, not every third-party editor.

This was an actual installed-CLI scan: **11 deterministic findings**, **two model finding answers** from two selected findings, **three additional advisory concerns**, and **nine open findings outside the model cap**. Full control review was not requested. The exit code remains **1** because the static finding gate triggered; model advice does not establish an implemented safeguard or confirmed vulnerability. The actual Headroom **0.37.0** receipt records evidence JSON reduced from **3,558 to 3,430 bytes**, saving **128 bytes** without fallback. Those figures exclude instructions, schemas and provider wrappers; model token and cost savings were not measured.

The report was checked with Python **3.12.14**, ReportLab **4.4.9**, pypdf **6.10.0**, pdfplumber **0.11.9** and Poppler **26.05.0**. Its SHA-256 is:

```text
bed01706affa81d4e8ba87c0372078a81b44a9a45ffb22305f7546b02c8a5b8d
```

[Version 0.11 PDF validation receipt](../benchmarks/validation-v011/pdf-receipt.json) records the implementation fingerprint, exact artifact hashes, navigation destinations, form roundtrip and bounded inspection results. The earlier 0.9 and 0.10 artifacts and receipts above remain historical evidence.

## v0.15 context investigation PDFs

The final [deterministic context PDF](../examples/reports/v015/context-static/report.pdf) has **15 pages**, 12 bookmarks and 29 internal links. The [live Codex context PDF](../examples/reports/v015/context-codex/report.pdf) has **22 pages**, 13 bookmarks and 31 internal links. Both have ten canonical fields and ten matching widgets with appearance streams, and their embedded full reports and five-format review capsules match the adjacent JSON. [Hash-bound QA receipt](../benchmarks/validation-v015/context-pdfs-receipt.json).

All 37 pages were rendered and inspected; the Codex opening, investigation evidence and review fields were also inspected individually. No clipping, overlap or out-of-page words were observed. The opening now states the one model-proposed gap and one insufficient-evidence answer separately from the zero static matches. These are actual bounded-review outputs, not model accuracy or deployment assurance. Earlier candidate outputs retain their original hashes; [execution history and exact scope](../examples/reports/v015/README.md).
