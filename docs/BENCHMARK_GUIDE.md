# Benchmark evidence guide

**Current release:** [visual benchmark dashboard](BENCHMARK_DASHBOARD.md), [fresh v0.15 execution evidence](../benchmarks/comparison-v015/README.md), and [updated benchmark PDF](../output/pdf/invarune-benchmark-v015.pdf). Earlier results below retain their original versions and scope.

The published experiments show what Invarune and selected tools observed on bounded inputs, where their outputs overlapped, and which questions remain unresolved. They do not establish a universal scanner ranking, zero false positives/negatives, or a count of confirmed exploitable vulnerabilities.

Start with the [current benchmark PDF](../output/pdf/invarune-benchmark-v015.pdf) and [v0.15 finding ledger](../benchmarks/comparison-v015/FINDINGS.md). The current experiment preserves the same eight project exports and original development corpora, then adds a clearly separated harder challenge. The first blind candidate found only four of 16 risky cases; that result exposed missing tool-entrypoint input modeling and composed instruction gaps. It is retained beside fixes made after disclosure and a separate final sealed check. The [controlbook](../output/pdf/invarune-security-controlbook.pdf) documents controls and current static scope; referenced attack suites were not all executed.

| Current v0.15 track | Denominator | What must stay visible |
| --- | --- | --- |
| Original paired development corpus | 113 rule-presence assertions | Identical source bytes and labels before/after |
| Original skill/tool corpus | 81 cases, 331 assertions | Old schema-description scope label and resulting mismatch |
| Corrected skill/tool revision | Same 81 inputs, 331 assertions | Exactly one explicitly changed label, separately scored |
| First harder challenge | 32 cases: 16 source-flow, 16 metadata | Poor initial blind result and all post-disclosure development results |
| Final sealed confirmation | Eight separate cases | First execution retained; identical presentation-only repeat labeled separately |
| Equivalent metadata peer comparison | Same 16 descriptions, plus four separate sealed descriptions | Cisco YARA-only scope; disabled analyzers unmeasured |
| Public-source comparison | Same 4,120 exported files across eight projects | Native observations, parser gaps, scope differences and exact repeatability |
| Source audit examples | 12 purposively selected locations | Assistant review, not human adjudication or production TP precision |

[Read all current results and reproduction commands](../benchmarks/comparison-v015/README.md), [why the harder challenge mattered](../benchmarks/comparison-v015/CHALLENGE.md), and [the official peer-capability research](../benchmarks/comparison-v015/RESEARCH.md). A model's opinion does not supply these fixture labels. The [report library](REPORT_LIBRARY.md) separates deterministic and optional-model examples.

The detailed experiment walkthrough below is **historical v0.10 evidence**. Its [13-page finding comparison PDF](../output/pdf/invarune-finding-comparison-v010.pdf) and [1,117-observation ledger](../benchmarks/comparison-v010/FINDINGS.md) retain their original counts. The [earlier nine-page benchmark PDF](../output/pdf/invarune-benchmark-report.pdf) preserves the 0.8 experiment.

## Keep the evidence tracks separate

| Track | Measured scope | What its result can support |
| --- | --- | --- |
| Public-project source comparison | Eight pinned projects; final Invarune 0.10.0 plus specified external versions and rule packs | Observed patterns, scope gaps, repeatability and source-location overlap. No vulnerability ground truth. |
| Selected source audit | 50 observations at 33 locations across seven projects | Whether the selected source supports the stated predicate, with deployment questions retained. Codex agent-assisted, not independent human adjudication. |
| Blinded optional-model adjudication | 153 selected observations, prepared as 20 batches | Preparation and one actual authentication failure. Zero valid model answers; no measured likely-TP rate. |
| Static accuracy corpus | 113 project-authored, development-visible rule-presence labels | Regression behavior and known labeled mismatches. Not production precision or recall. |
| Shared API-pattern fixtures | Five positive and five negative labels for each of three relevant tools | Agreement with those ten labels; different from the 1,117 public-project observations. |
| Package, report and provider workflow tests | Versioned tests, installed CLI runs, form imports and bounded provider probes | The specific executed workflows, not detector accuracy or effective deployed controls. |

The current CLI release does not relabel earlier evidence. The detailed comparison records initial 0.9.0 runs and final **0.10.0** runs; the earlier readable per-project reports retain **0.8.0**. The 0.11 report-layout and 0.12 explorer validations are separate from these research measurements.

## The eight public projects and actual inputs

The projects were selected for agent/MCP ecosystem diversity before scanning and pinned to complete commit IDs. The shared export contains **4,120 first-party implementation/configuration files**. Source bytes and per-file hashes were verified before and after analysis. Tests, examples, documentation, dependencies and generated trees were excluded consistently; relevant manifests, production prompts and implementation templates remained.

| Project | Role | Read its historical report |
| --- | --- | --- |
| MCP reference servers | Educational reference MCP implementations | [Findings and evidence](../examples/reports/real-world/mcp-reference/report.md) |
| GitHub MCP Server | MCP server implementation | [Findings and evidence](../examples/reports/real-world/github-mcp/report.md) |
| AutoGen | Agent framework and integrations | [Findings and evidence](../examples/reports/real-world/autogen/report.md) |
| CrewAI | Agent orchestration and tools | [Findings and evidence](../examples/reports/real-world/crewai/report.md) |
| LangGraph | Graph runtime and checkpoints | [Findings and evidence](../examples/reports/real-world/langgraph/report.md) |
| OpenHands | Agent development application | [Findings and evidence](../examples/reports/real-world/openhands/report.md) |
| Pydantic AI | Typed agent, graph and evaluation framework | [Findings and evidence](../examples/reports/real-world/pydantic-ai/report.md) |
| FastMCP | MCP server/client framework | [Findings and evidence](../examples/reports/real-world/fastmcp/report.md) |

The [selection manifest](../benchmarks/real-world/manifest.json) records pinned revisions, licenses, directories and limits. The [public-project methodology](../benchmarks/real-world/README.md) describes exact export rules, and the [results index](../benchmarks/real-world/RESULTS.md) links every historical report and receipt. For final 0.10 normalized evidence, use the [complete ledger](../benchmarks/comparison-v010/FINDINGS.md) and its [machine-readable records](../benchmarks/comparison-v010/observations.json).

No target application, install hook, dependency setup, MCP server or exploit was executed. The reproducible Invarune comparison disabled the optional analyst, baselines and review exceptions. Tools received the same exported bytes, but their supported languages and chosen rules still differ; equal input does not imply equal analysis coverage.

## Findings and incomplete work

| Tool and measured configuration | Source observations | Reported limitations |
| --- | ---: | --- |
| Invarune 0.10.0 | 149 | 15 coverage gaps; partial static patterns, not whole-program or runtime proof. |
| Semgrep CE 1.177.0, frozen 225-rule security-audit pack | 27 | Seven parser warnings; other commercial analyses and packs were not measured. |
| Bandit 1.9.4, default Python plugins | 938 | Five parser errors; two exports without Python are unsupported, not clean results. |
| Gitleaks 8.30.1, directory mode | 3 | Git history and live credential validity were not tested; no exhaustive per-file scan inventory is inferred. |
| **Total source observations** | **1,117** | Different scanner observations are retained separately, without a fabricated shared vulnerability denominator. |

A separate **Cisco MCP Scanner 4.8.4** YARA-only run inspected 14 literal filesystem tool descriptions and returned zero findings. This is partial static metadata, outside the 1,117 source-observation total. It does not validate live tool discovery, computed schemas, authorization or MCP behavior. Snyk Agent Scan was researched but not run in the source-only experiment; it receives no score or clean-result claim.

The retained fresh comparison includes **40 initial source invocations** and **16 final Invarune invocations**. Initial runs included two Invarune executions per project plus Semgrep, Bandit and Gitleaks; final Invarune was again run twice per project. Intermediate development reruns are excluded from that count. Repeatability applies to the recorded scanner/runtime/settings. Timing on the shared development host is not a speed ranking.

Inspect [run statuses](../benchmarks/comparison-v010/run-status.json), [external execution receipts](../benchmarks/comparison-v010/external-results/summary.json), [tool/ruleset lock](../benchmarks/comparison-v010/tool-lock.json) and the [Cisco receipt](../benchmarks/comparison-v010/external-results/cisco-metadata.json). The [comparison narrative](../benchmarks/comparison-v010/README.md) explains provenance and final Invarune receipts.

## What “matched” and “tool-only” mean

Matching requires the **same project, pinned path, explicitly compatible family and intersecting inclusive line spans**. It does not use nearest-line guessing. A one-to-one pair exists only when both observations have exactly one candidate counterpart. Multiple candidates remain ambiguous; same-location observations with incompatible families are location-only relations.

| Invarune compared with | One-to-one pairs | Ambiguous edges | Invarune observations without a family match | Other-tool observations without a family match |
| --- | ---: | ---: | ---: | ---: |
| Semgrep | 7 | 0 | 142 | 20 |
| Bandit | 12 | 5 | 132 | 925 |
| Gitleaks | 1 | 0 | 148 | 2 |

The five ambiguous Invarune/Bandit edges connect five Invarune observations to one Bandit observation. They are not five unique shared vulnerabilities. The [overlap records](../benchmarks/comparison-v010/overlaps.json) retain all six tool-pair comparisons and exhaustive unmatched IDs; the [family map](../benchmarks/comparison-v010/rule-family-map.json) states the compatibility predicates.

**Tool-only does not mean missed vulnerability.** A pickle import, a deserialization call, an intentional execution capability and a dependency-pinning policy can represent different review questions. A supported pattern can be safe in context; a tool can also lack a relevant rule or successful language coverage. Agreement is useful for navigation, never a true-positive label by itself.

## Source audit, model opinions and unknowns

The [selected source audit](../benchmarks/comparison-v010/SOURCE_AUDIT.md) reviewed **50 of 1,117 observations**: 28 Invarune, nine Semgrep, ten Bandit and three Gitleaks. It recorded **42 supported source predicates and eight conditional mismatches**, with zero evidence-read errors. The other **1,067 observations were not audited**. All 50 remain unconfirmed as deployed vulnerabilities; 33 require runtime validation and 17 are marked not established.

This was Codex agent-assisted work involving the scanner's implementer, not independent human ground truth. Selection was purposive, and part of the evidence retained historical 0.9 metadata with a separately verified correspondence to the final 0.10 ledger. The [JSON audit](../benchmarks/comparison-v010/source-audit.json) preserves original identities, source hashes, line citations and uncertainty.

Examples explain why context matters: fixed SQL identifiers can satisfy an interpolation pattern; a deliberately enabled source loader still needs an unauthorized-input path; a public analytics key is not established private-credential exposure. **All three Gitleaks observations remain valid lexical matches** even though the selected security predicate did not establish a leaked private credential. The audit did not search unflagged code for vulnerabilities, so it cannot measure false negatives or recall.

Separately, the frozen model-review selection covered **120 spans / 153 observations / 101 tool-project-family strata** before model outcomes. All 153 cases were prepared, but the actual Claude CLI invocation failed authentication on the first eight-case batch; the other 145 observations were not submitted. There were **zero valid model answers and 153 unknowns**. The likely-TP percentage is **unavailable, not 0%**. See the [adjudication protocol](../benchmarks/comparison-v010/ADJUDICATION.md), [frozen selection](../benchmarks/comparison-v010/adjudication-selection.json), [preparation receipt](../benchmarks/comparison-v010/adjudication-prepared/preparation.json) and [actual attempt](../benchmarks/comparison-v010/adjudication-live/model-adjudication.json).

The successful, limited Codex scan examples in the [report library](REPORT_LIBRARY.md) concern inert demonstration fixtures. They are not replacement adjudication of the 153 selected public-project observations.

## Accuracy labels and known misses

The [published rule-accuracy results](../benchmarks/accuracy-current.md) record scanner **0.10.0**, corpus **1.2.0**, and **113 labeled rule-presence cases**: 105 regression cases plus eight challenge cases. The overall counts are **55 TP, 51 TN, two FP and five FN**. Precision is **55/57 = 96.49%** and recall **55/60 = 91.67%**, strictly for these project-authored labels. Challenge mismatches remain included even though the default regression gate passes.

Known misses include reflection, cross-function URL flow, JavaScript wrappers, YAML aliases and nested shell expansion. Known false alarms include YAML block-scalar documentation and a constrained URL branch. Read every mismatch and [per-rule JSON result](../benchmarks/accuracy-current.json), rather than treating an aggregate percentage as a production guarantee. The [methodology](RULE_ACCURACY.md) documents scope, mutation checks and unscored detections.

Corpus versions matter. `AI041` was corrected because every nonempty `DANGEROUSLY_OMIT_AUTH` value disables the Inspector safeguard, including the string `false`. That required correcting an old expected label and adding cases. It is not an accuracy improvement on unchanged corpus bytes. The [label-correction record](../benchmarks/AI041_LABEL_CORRECTION.md) and archived corpora preserve the distinction.

The separate [shared API-pattern receipt](../benchmarks/comparison-v010/external-results/shared-pattern-fixtures.json) contains only ten development fixtures: five positive and five negative labels. Invarune, Semgrep and Bandit each matched all ten, with zero label mismatches. This does not establish 100% production recall or precision; Gitleaks and MCP metadata tools are outside that scope and receive no artificial true negatives.

## Reproduce and verify without overwriting history

Use a separate checkout/output directory, preserve the published receipts, and record the scanner version and corpus digests for every new run. The same source commits do not guarantee identical output after a detector, Python, catalog or configuration change.

```sh
# Re-evaluate the labeled corpus; fixture source is not executed.
python3 scripts/evaluate_accuracy.py --format markdown

# Inspect reproduction settings before selecting fresh output locations.
python3 scripts/scan_public_projects.py --help
python3 scripts/benchmark_competitors.py --help
python3 scripts/compare_scanner_findings.py --help
python3 scripts/adjudicate_scanner_findings.py --help
```

Follow the [public-project export protocol](../benchmarks/real-world/README.md#reproduce-the-scans) to fetch exact commits and verify manifests. Follow the [external-tool reproduction guide](../benchmarks/external-tools/README.md#reproduce) for pinned installations and rule-pack checksums, then the [fresh comparison instructions](../benchmarks/comparison-v010/README.md#reproduce-or-inspect) for normalization, matching and provenance checks. The [adjudication guide](../benchmarks/comparison-v010/ADJUDICATION.md#reproduction) separates preparation, synthetic pipeline tests and explicit live review. Preparation is not a model answer.

For historical v0.14 software behavior, use [0.14 validation](../benchmarks/validation-v014/README.md) and the [61-step installed quickstart receipt](../benchmarks/quickstart-v014/README.md). Test/branch coverage measures executed implementation paths, not detection accuracy. The [Headroom experiment](../benchmarks/token-optimization-v011/README.md) measures evidence-JSON bytes and preservation, not model token costs or security effectiveness.

## Sources and reuse terms

The [research protocol](../benchmarks/comparison-v010/RESEARCH.md) and [publication notice](../NOTICE.md) identify attribution and scope limits. Upstream code and publications retain their own terms; pinned license notices accompany the [source manifest](../benchmarks/real-world/manifest.json). The Semgrep rule pack is not redistributed: the project records its provenance and digest and publishes normalized observations rather than full licensed rule text. Private raw model responses and local full-source staging are not the public benchmark dataset.

No cited organization or upstream project has endorsed these findings. Public access is not an independent license grant, an official compliance assessment or proof that a vulnerability was disclosed or confirmed.
