# Reports and PDF library

Choose a document by the question you want to answer. The PDFs below are existing, versioned artifacts; a newer CLI release does not silently update their measurements. Open a PDF link to read it or save a local copy. HTML and Markdown alternatives make the scan evidence accessible without a PDF viewer.

| Start here when you want to… | Recommended document |
| --- | --- |
| See measured improvements and cross-tool coverage | [Visual benchmark dashboard](BENCHMARK_DASHBOARD.md) and [v0.14 benchmark PDF](../output/pdf/invarune-benchmark-v014.pdf) |
| See current findings, priorities, fixes and editable review fields | [Selected skill/tool scan PDF: Invarune 0.14, 27 pages](../examples/reports/v014/skills-static/report.pdf), or [successful Codex review PDF, 39 pages](../examples/reports/v014/skills-codex/report.pdf) |
| Understand the controls and their sources | [Security controlbook, 121 pages](../output/pdf/invarune-security-controlbook.pdf) |
| Compare actual scanner findings and uncertainty | [Finding comparison, 13 pages](../output/pdf/invarune-finding-comparison-v010.pdf), then the [benchmark guide](BENCHMARK_GUIDE.md) |
| Learn how accepted justifications survive a fresh scan | [Review roundtrip PDF, 99 pages](../examples/reports/review-workflow/source/final-pdf/report.pdf) and the [workflow](REVIEW_WORKFLOW.md) |
| Inspect detection accuracy and known misses | [Current paired labeled results](../benchmarks/comparison-v014/accuracy-after.json) and [accuracy methodology](RULE_ACCURACY.md) |

## Current release evidence

The [v0.14 benchmark update](../output/pdf/invarune-benchmark-v014.pdf) and [complete comparison](../benchmarks/comparison-v014/README.md) include fresh source runs and the separate skill/tool corpus. The [121-page controlbook](../output/pdf/invarune-security-controlbook.pdf) documents every rule and control. [Installed workflow validation](../benchmarks/quickstart-v014/README.md).

### Selected skill/tool scans: deterministic, successful AI and failed AI

These are actual **0.14.0 installed-CLI scans** of the same deliberately suspicious, inert skill/tool fixture, selecting **AI043–AI046**. The selected scope contains **four rules, six mapped controls and twelve acceptance checks**. Every run retains the same **four deterministic findings** (three high, one medium) and zero deterministic coverage gaps. The fixture was never installed or executed.

| Run and report formats | Actual result |
| --- | --- |
| **Deterministic:** [HTML](../examples/reports/v014/skills-static/report.html) · [PDF, 27 pages](../examples/reports/v014/skills-static/report.pdf) · [Markdown](../examples/reports/v014/skills-static/report.md) · [JSON](../examples/reports/v014/skills-static/report.json) · [SARIF](../examples/reports/v014/skills-static/report.sarif) | Model disabled. Four findings, twelve checks requiring further evidence, exit 1 from the static severity gate. |
| **Successful Codex review:** [HTML](../examples/reports/v014/skills-codex/report.html) · [PDF, 39 pages](../examples/reports/v014/skills-codex/report.pdf) · [Markdown](../examples/reports/v014/skills-codex/report.md) · [JSON](../examples/reports/v014/skills-codex/report.json) · [SARIF](../examples/reports/v014/skills-codex/report.sarif) | Finding triage and full selected control review completed: **12/12 accepted answers**, comprising **10 insufficient-evidence answers and 2 potential gaps**. All four static findings remain; exit 1. |
| **Claude requested, signed out:** [HTML](../examples/reports/v014/skills-claude/report.html) · [PDF, 31 pages](../examples/reports/v014/skills-claude/report.pdf) · [Markdown](../examples/reports/v014/skills-claude/report.md) · [JSON](../examples/reports/v014/skills-claude/report.json) · [SARIF](../examples/reports/v014/skills-claude/report.sarif) | Authentication failed, **0/12 model answers**, all twelve checks unreviewed. Four deterministic findings remain; exit 2 reports incomplete requested review. This is not a successfully Claude-reviewed assessment. |

See the [run explanation and earlier Codex attempt](../examples/reports/v014/README.md) for reproduction, precise scope and preserved failure evidence. The final Codex run's **100% answer coverage means every selected check received an answer, not that any control passed**; ten answers explicitly lacked enough evidence. The selected mapping-reach figure likewise measures partial detector availability, not security. Model advice did not change finding counts, severity or the gate.

All three current scan PDFs each have **16 bound review items and 80 editable fields**. Their form, attachment, navigation and all-page visual checks are recorded in the [v0.14 skill PDF receipt](../benchmarks/validation-v014/skill-pdfs-receipt.json). These examples cover a selected skill/tool scope; use the historical full-catalog reports below when comparing the larger checklist presentation.


## Research and benchmark PDFs

Current scan coverage is documented in the [exhaustive scan matrix](SCAN_COVERAGE.md). These are reading references. They do not contain the editable scan-review workspace and cannot be imported as a reviewed scan report.

| Open or download | Version and validated length | Contents and interpretation |
| --- | --- | --- |
| [Current benchmark update](../output/pdf/invarune-benchmark-v014.pdf) | **0.14.0 · 9 pages** | Fresh scans of eight pinned projects: 146 patterns and 21 explicit gaps. The unchanged 113-assertion comparison and separate 81-case/331-assertion skill/tool corpus retain distinct denominators. Charts, source links and provenance receipts; no production TP claim. |
| [Historical benchmark update](../output/pdf/invarune-benchmark-v013.pdf) | **0.13.0 · 9 pages** | Same 113 labels before/after; fresh eight-project comparison; three source precision fixes; charts, clickable contents, remaining gaps and complete-ledger links. No public-project TP percentage is claimed. |
| [Security controlbook](../output/pdf/invarune-security-controlbook.pdf) | 0.14 edition · **121 pages** | 66 project-defined controls, 132 checks, 76 source records, nine research benchmark entries and 46 individual algorithm/limits/fix pages. Includes source organizations, scope and limitations. Listing a research benchmark does not mean Invarune executed it. |
| [Finding-by-finding scanner comparison](../output/pdf/invarune-finding-comparison-v010.pdf) | Final Invarune **0.10.0** comparison · **13 pages** | The 1,117-observation ledger, conservative cross-tool matches, a 50-observation source audit, unknowns and reproduction links. The Claude adjudication attempt failed authentication; no model TP percentage is available. |
| [Earlier real-project benchmark report](../output/pdf/invarune-benchmark-report.pdf) | **0.8.0 measurements**, expanded in the 0.9 document workflow · **9 pages** | Eight pinned public projects, complementary source scanners, coverage gaps, mitigation context and ten shared development fixtures. Its refreshed layout did not turn the recorded 0.8 measurements into a new scan. |

For the controlbook, continue with the [readable checklist](SECURITY_CHECKLIST.md), [source map](SOURCE_MAP.md), [research notes](RESEARCH.md) and [benchmark landscape](BENCHMARK_LANDSCAPE.md). For measured results, the [benchmark guide](BENCHMARK_GUIDE.md) links directly to the complete ledger, source audit, fixture labels and execution receipts.

## Editable scan reports

These PDFs contain bound finding/check review fields. A saved decision is a user annotation or accepted exception, never an automatically validated pass. Import requires a fresh, explicitly selected source/image target; changed scanner, scope or evidence bindings can correctly make an old decision stale. Read the [review workflow](REVIEW_WORKFLOW.md) and [PDF compatibility limits](PDF_REVIEW.md) before editing.

| Open or download | Version and validated length | What actually happened |
| --- | --- | --- |
| [Historical full-scope decision-first scan PDF](../examples/reports/invscan-v011/report.pdf) | **0.11.0 · 114 pages · 715 fields** | Actual installed CLI scan of the deliberately vulnerable fixture: 11 open deterministic findings; successful, limited Codex review of two findings, three additional advisory concerns, nine findings outside the cap. Full control review was not requested. Exit 1 came from the static finding gate. |
| [Claude authentication-failure scan PDF](../examples/reports/cli-claude-v010/report.pdf) | **0.10.0 · 119 pages · 715 fields** | Full Claude review was requested, but authentication failed. Eleven deterministic findings and their fix plans remain; zero model answers and all 132 checks unreviewed are explicit. Exit 2 reflects incomplete optional work. This is not a successfully Claude-reviewed report. |
| [Completed source review roundtrip PDF](../examples/reports/review-workflow/source/final-pdf/report.pdf) | **0.9.0 · 99 pages · 715 fields** | Actual fresh scan imported one test-only finding justification and one check justification. It retained 10 open findings, one justified finding and 131 active checks; exit 1. No model or target application ran. |
| [Edited source PDF used as review input](../examples/reports/review-workflow/source/reviewed.pdf) | **0.9.0 fixture input** | The saved AcroForm edits used for the roundtrip above. Inspect this input alongside the final report and receipt. Its fixture justifications establish no production safeguard. |

The historical 0.11 PDF places immediate concerns and linked locations on page 1, complete findings from page 4, optional advisory evidence from page 17, configuration from page 32 and review forms from page 43. Each finding includes a sourced fix plan, conditional agent/MCP relevance, verification work and remaining runtime needs. Proposed defenses are not counted as already deployed.

Read that same historical 0.11 result as [HTML](../examples/reports/invscan-v011/report.html), [Markdown](../examples/reports/invscan-v011/report.md), [JSON](../examples/reports/invscan-v011/report.json) or [SARIF](../examples/reports/invscan-v011/report.sarif). The [run explanation](../examples/reports/invscan-v011/README.md) records its exact limited model scope. Its Headroom receipt measures **3,558 → 3,430 evidence-JSON bytes**, not model tokens or billed cost savings. Model judgments remain unverified advice and cannot change deterministic severity or gates.

The Claude failure has equivalent [HTML](../examples/reports/cli-claude-v010/report.html), [Markdown](../examples/reports/cli-claude-v010/report.md) and [failure audit](../examples/reports/cli-claude-v010/report.json). The separate [0.10 limited Codex example](../examples/reports/cli-codex-v010/README.md) successfully obtained two finding opinions and three additional concerns; it has four report formats and no published PDF. Neither limited Codex example substitutes for a complete control review or successful Claude validation.

## More results to explore

| Evidence collection | Readable starting point | What it demonstrates |
| --- | --- | --- |
| Deterministic source, safer source, exceptions and built image | [0.11 fixture reports](../examples/reports/v011/README.md) | Four-format, repeated installed-CLI scans with the model disabled. The safer fixture's zero findings is not a production safety claim. |
| Eight pinned public projects | [Per-project results and report links](../benchmarks/real-world/RESULTS.md) | Historical 0.8 source observations, examined-file counts and coverage gaps, with HTML/Markdown/JSON/SARIF for each project. |
| Five-format source/image review import | [Executed workflow and 12-scan receipt](../examples/reports/review-workflow/README.md) | Saved decisions applied to a fresh source scan and a fresh image scan through every supported review format. |
| Historical offline explorer and installed workflows | [0.12 validation](../benchmarks/validation-v012/README.md), [53-step quickstart](../benchmarks/quickstart-v012/README.md) | CLI/package/workflow checks, not a rerun of the research benchmark or a new PDF edition. |
| Optional request compaction | [Measured Headroom evidence](../benchmarks/token-optimization-v011/README.md) | Typed evidence preservation and byte reductions under the recorded environment; no measured token or production security accuracy claim. |

## Validation, provenance and reuse

Page counts and artifact hashes come from the [PDF validation record](PDF_VALIDATION.md), the current [benchmark](../benchmarks/validation-v014/benchmark-pdf-receipt.json), [controlbook](../benchmarks/validation-v014/controlbook-receipt.json) and [skill PDF](../benchmarks/validation-v014/skill-pdfs-receipt.json) receipts, the [0.10 PDF receipt](../benchmarks/validation-v010/pdf-receipt.json) and the [0.11 PDF receipt](../benchmarks/validation-v011/pdf-receipt.json). These record all-page rendering and visual inspection, structural navigation checks and supported form roundtrips. They do not guarantee every third-party PDF viewer or editor. The current 0.14 PDFs were regenerated and verified for this release; historical report files retain their recorded measurements.

Keep the research documents, benchmark source versions and scan versions separate when citing them. A source-pattern observation is not a confirmed vulnerability; a model likelihood is not independent ground truth; a justification is not proof of remediation. The [benchmark guide](BENCHMARK_GUIDE.md) explains the measured denominators and unresolved cases.

Read the [publication and source notice](../NOTICE.md) before reuse. NimeshBuild's documents are engineering syntheses, and cited organizations have not endorsed the project. Third-party sources retain their own licenses and access terms. Publication or download does not independently grant a license to the original project or to third-party standards, datasets, source code or rule packs.
