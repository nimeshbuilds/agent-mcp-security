# Architecture and trust boundaries

Invarune has one CLI coordinator, bounded analysis components and separate presentation/review layers. Target files are data throughout source and image analysis. No target module, package installer, test suite or build script is imported or executed by the scanner.

## Module map

Paths below are relative to the repository root.

| Responsibility | Implementation | Main boundary |
|---|---|---|
| CLI parsing and orchestration | `ai_security_scan/cli.py`, `cli_help.py` | `parser()`, `main()`, `judge_payload()`, `_json_summary()` |
| Source selection and aggregation | `scanner.py` | `scan()`, `load_controls()`, `load_baseline()` |
| Confined file reads | `fs.py` | `read_confined()` |
| Source-pattern detection | `analyzer.py`, `callflow.py`, `rules.py` | `analyze_file()`, `analyze_file_errors()`, `_Findings` |
| Agent-facing instructions and tool contracts | `threats.py`, `tool_effects.py` | Bounded instruction grammars, structured tool descriptions and explicit read-only/write-effect conflicts |
| Image acquisition | `image_runtime.py` | `export_image()` |
| Archive verification and reconstruction | `image_archive.py` | `materialize_image()` |
| Image metadata and retained-layer assessment | `image_assessment.py`, `image_scan.py` | `assess_image()`, `scan_image()`, `_merge_assessment()` |
| Executable scan inventory | `scan_catalog.py` | `describe_scans()`, `render_scans()`; precise rule coverage and review plans. |
| Offline security explanations | `catalog.py`, `data/control_explanations.json` | `describe_catalog()`, `render_catalog()` |
| Redaction and model evidence | `security.py`, `evidence.py` | `redact()`, `redact_object()`, `build_evidence()` |
| Optional review | `judge.py`, `cli_judge.py`, `analyst.py` | HTTP/CLI transport, normalized responses, `run_analyst()` |
| User exceptions and fresh review imports | `review_policy.py`, `review_workspace.py` | Policy validation, binding and conservative reapplication |
| Remediation and executive interpretation | `remediation.py`, `assessment.py`, `methodology.py` | `build_remediation()`, `build_assessment()`, `build_methodology()` |
| Portable and PDF reports | `report.py`, `report_html.py`, `report_pdf.py` | `prepare_report()`, `write_reports()`, `html_report()`, `render_pdf()` |

## CLI coordination

Help, version and catalog modes (including scan inventory) return before source/image acquisition or optional review. Catalog-only commands reject scan/judge/output options rather than silently ignoring them. Legacy `--list-rules`, `--list-controls` and `--explain-rule` retain their JSON defaults; the new explorer defaults to readable text.

For a scan, `main()` resolves explicit rule/control selection and validates combinations and limits, loads explicit review input and baselines, chooses one acquisition path, applies user dispositions to the completed static report, and then optionally requests advisory review. `prepare_report()` adds methodology, remediation, advice coverage, optional review workspace, executive assessment and scope metrics in memory before presentation. `write_reports()` invokes that preparation when exporting. Without explicit report flags, the CLI renders the enriched result in the terminal without report artifacts; requested exports write four portable formats. Optional PDF export is handled afterward. The final exit decision preserves operational incompleteness over severity gating.

```text
explicit source directory -> scanner.scan ----------------------+
                                                               |
image archive/reference -> scan_image -> source + image merge --+--> user review dispositions
                                                                    |
                                             optional triage / full analyst
                                                                    |
                                      deterministic interpretation + reports
```

Review import is a fresh-scan workflow. Loading an old report does not restore a target, credentials, model endpoint or executable. See [review bindings](reports-and-reviews.md).

## Source pipeline

`scanner.scan(root, ...)` rejects a symbolic-link target root, canonicalizes the selected directory and captures its filesystem identity. It walks deterministically: directory and filename order is sorted, symlinks are not followed, and selected file reads are bounded.

Selection uses `EXTENSIONS`, `MANIFESTS`, special filenames and `EXCLUDED_DIRS`. User globs use case-sensitive `fnmatch`, not `.gitignore` semantics. Explicit output/configuration exclusions also record filesystem identities so aliases or hardlinks do not accidentally enter the source evidence. Unsupported extensions and declared exclusions are outside selected scope; a failed read or invalid selected input remains a coverage gap.

`fs.read_confined()` opens relative components with directory descriptors and `O_NOFOLLOW` where supported, verifies a regular file and reads at most the bound plus a growth-detection byte. Its portable fallback rejects visible symlinks and confines resolved paths, but does not provide the same concurrent-filesystem guarantees as descriptor-based traversal. Callers should supply a canonical root and must not weaken these checks to accommodate a path alias.

Selected text is decoded as UTF-8, accepting a BOM. The report records path, byte count, SHA-256 and analysis profile. Profiles are deliberately limited:

| Profile | Implementation scope |
|---|---|
| `python_ast` | AST parsing, local alias/value tracking and bounded same-file call propagation; exact supported guards, explicit unsupported-flow gaps; no whole-program proof. |
| `javascript_lexical` | Tokens, balanced calls and narrow direct-return wrapper summaries; not a complete JavaScript/TypeScript parser. |
| `json_structured` | Structured JSON/JSONC checks with ambiguous input failures visible. |
| `configuration_lexical` | Selected configuration/text patterns; not complete YAML/template semantics. |
| `generic_text` | Applicable generic signals; no implied language-specific data flow. |

`analyze_file()` emits findings and accepts an analysis-error collector so a partial flow limitation preserves other findings. `analyze_file_errors(..., include_flow=False)` checks remaining parsing/threat limitations without duplicating the flow pass. External direct callers may request its default complete analysis. Do not suppress the former because the latter returns no findings. `_Findings.add()` deduplicates by rule and line and includes bounded source evidence. The scanner assigns a finding ID from rule, relative location and raw evidence before publishing redacted evidence. It then applies an explicit baseline and aggregates mapped controls. A control with no matching finding becomes `no_pattern_detected`, not `pass`.

## Built-image pipeline

`scan_image()` is a context manager yielding `(report, evidence_root)`. Its private workspace must remain alive through optional evidence collection and report generation; cleanup occurs when the context closes.

1. For `--image`, `export_image()` invokes the trusted Docker/Podman runtime. A missing image does not imply a pull. `--pull` explicitly permits registry acquisition.
2. `materialize_image()` validates a Docker-save or OCI-layout archive, selects the requested platform and applies supported layers, whiteouts and link semantics under bounded extraction rules.
3. The reconstructed final filesystem is placed under a private `rootfs/` evidence directory and passed to `scanner.scan()`.
4. `assess_image()` inspects image defaults, build history, inventories, stored permissions and retained-layer evidence under separate bounds.
5. `_merge_assessment()` preserves image provenance, reconciles findings and controls, and applies the baseline to the merged result.

Image defaults differ from a developer checkout: packaged `dist`, `build`, `node_modules`, vendor and virtual-environment contents are not excluded merely because source scanning normally skips those directories. User image globs are container-relative and also apply to retained revisions; metadata/history assessment remains separate.

Keep `final_filesystem`, `runtime_configuration`, `retained_layer` and `build_history` findings distinct. A deleted secret can remain exposed in a distributed layer; historical code does not prove current execution. Binary-only images can yield `metadata_only` without analyzing compiled logic. Archive digest consistency is not publisher authentication. Image scanning does not start the container, query CVE feeds or establish deployed overrides. [Supported formats and budgets](../IMAGE_SCANNING.md).

## Offline explorer pipeline

`describe_catalog(action, value=None)` returns a new JSON-serializable answer; `render_catalog()` turns it into plain text. It loads only bundled catalogs, rules and remediation guidance. Cached internal records are copied before exposure so caller mutations cannot rewrite subsequent answers.

`--ask` is bounded lookup, not an agent. Input is limited to 1,000 characters before and after normalization; control/format characters and invalid Unicode are rejected. NFKC/case normalization, fixed tokenization, curated aliases and fixed field weights determine ranking. User text never becomes a regular expression or executable command. Exact known IDs return details; ordinary queries return at most eight matches with matched fields and stable ordering. Broad scope questions return a topic overview. An unmatched query returns `no_match`, not a clean scan.

The public engine actions are `topics`, `controls`, `rules`, `sources`, `control`, `check`, `rule`, `source` and `ask`. List actions take no value; detail actions require a known ID of the matching kind. The common answer envelope contains `schema_version: "1.0"`, `mode: "deterministic_catalog"`, `action`, `status`, catalog counts, `assurance` and `scan_guidance`. A detail action adds its singular record; a list action adds its plural list.

Ask answers add the original/normalized query, `search_method`, `limit`, `total_matches`, `returned_matches`, `truncated` and `results`. Each result has `kind`, `id`, `title`, `score`, `matched_fields`, a suggested inspection `command` and rich `detail`; ordinary lexical results also expose matched/unmatched terms. These suggested commands are static strings for the user, never executed by search. Unknown ID-like queries return no match; an unknown ID supplied to an explicit explanation action raises `ValueError`. CLI no-match exits 0; malformed queries or explicit invalid IDs exit 2.

For ordinary search, generic question words are removed when substantive terms remain. A document must cover at least half the query terms. Results sort first by covered-term count, then weighted field score, then stable kind/ID tie-breaks. Exact aliases and titles receive extra weight; source benchmark records have an explicit benchmark-query preference. All scoring rules are visible in `_ask()` and `_search_documents()`; there are no embeddings, learned rankings, agent calls or network fallbacks.

Control sources preserve `primary_control_source` and `thematic_alignment`; detector/remediation references use `rule_technical_reference`. Source backlinks are derived only from existing mappings and exact reference relationships. Catalog relevance scores are not confidence, severity or compliance scores.

## Optional investigation loop

The deterministic scan completes before optional model work. Evidence capture validates the existing manifest and snapshots bounded, redacted text. The model receives seed excerpts plus opaque file IDs and definition hints. It can return final conclusions, or request exact line ranges for a selected check with a risk hypothesis and counterevidence rationale.

The controller validates IDs, selected checks, range bounds and shared budgets before returning text from those snapshots. It never uses a model-supplied path, fetches a URL, executes a command, imports target code or rereads a changed target. Every served/denied request has a receipt. A conclusion call is reserved for each remaining batch; optional exploration cannot consume those reservations. Defaults permit two rounds per batch, up to 36 control-review calls and 600 seconds of scheduling time; finding triage is separate. Zero investigation rounds restores seed-only review.

Final exact-quote validation binds citations to delivered evidence; it does not validate the model’s reasoning. Structured analysis distinguishes hypothesis, boundary, counterevidence and conclusion limits. Legacy final responses remain compatible and their missing structure stays explicit. Models never change static severities, resolve user exceptions or lower the gate. See [AI adapters](ai-adapters.md) for schemas and tests.

## Repeatability and boundaries

The scan identity incorporates selected evidence, settings, controls, baseline and tool metadata. `tool.implementation_sha256` hashes the package's Python module names and bytes; it is not a digest of the entire repository. Python version is also recorded. Catalog-specific hashes and provenance appear in their relevant report sections.

Preserve deterministic ordering and avoid implicit timestamps, machine-specific scratch paths or remote lookups in static results. A new module or code edit can legitimately change the implementation fingerprint even when detector outcomes remain the same. Optional model responses remain nondeterministic and are excluded from static finding decisions and review bindings.

Continue with [adding checks](adding-checks.md), [report contracts](reports-and-reviews.md) or [AI adapter boundaries](ai-adapters.md).

For scan inventory, selection semantics, terminal/export modes and metric formulas, see [scan inventory and selection](scan-inventory.md) and the generated [user coverage guide](../SCAN_COVERAGE.md).
