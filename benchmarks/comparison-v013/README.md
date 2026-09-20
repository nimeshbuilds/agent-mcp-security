# Invarune v0.13: fresh benchmark results and reproduction

The unchanged 113-assertion development corpus improved from **55 TP / 51 TN / 2 FP / 5 FN** in v0.12.0 to **58 TP / 52 TN / 1 FP / 2 FN** in v0.13.0. On the eight unchanged public source exports, Invarune observations decreased from **149 to 146** after three narrowly scoped precision fixes. All **15 analysis coverage gaps remain visible**. These are development measurements of rule-pattern assertions and source observations, not a production vulnerability accuracy claim or a ranking of security tools.

Read the [visual dashboard](../../docs/BENCHMARK_DASHBOARD.md), [updated benchmark PDF](../../output/pdf/invarune-benchmark-v013.pdf), or [all 1,114 observation rows](FINDINGS.md). The canonical project is [nimeshbuilds/invarune](https://github.com/nimeshbuilds/invarune).

## What changed, and what remains

| Unchanged corpus: 113 assertions | Frozen v0.12.0 | Final v0.13.0 |
|---|---:|---:|
| True positive | 55 | 58 |
| True negative | 51 | 52 |
| False positive | 2 | 1 |
| False negative | 5 | 2 |
| Precision: TP / (TP + FP) | 96.49% | 98.31% |
| Recall: TP / (TP + FN) | 91.67% | 96.67% |
| Analysis-error cases | 0 | 0 |

Four labeled assertions improved: constant Python reflection (`AI003`), a nested download/shell command (`AI019`), a bounded YAML permission alias (`AI027`), and a YAML block string that should not imply disabled authentication (`AI026`). Labels, sources and case identities were not changed. The remaining mismatches are all `AI014`: interprocedural URL flow and a JavaScript wrapper remain false negatives; a validated dynamic URL remains a false positive. Cross-function trust and validation reasoning remain limited.

The [paired accuracy receipt](before-after-accuracy.json) binds the exact [before](accuracy-before.json) and [after](accuracy-after.json) report bytes, unchanged corpus hash, individual changed assertions and all remaining mismatches. The corpus is project-authored and was visible during development. New targeted regression tests are separate from this paired denominator; no case was removed or relabeled to improve the result.

The real-source change was three fewer precision artifacts: an AutoGen repeated-character documentation token placeholder, an AutoGen local self-install requirement, and a CrewAI environment-variable-name field. One OpenHands image declaration has a narrower source span (lines 11–13 to 12–13); it is the same finding, not another removed risk. [Source delta](source-delta.json) preserves the original four removed/one added span identities and the reviewed classification into three removals plus one span change. [Development gap review](gap-review.json) explains the eight purposive cases examined; it is not an exhaustive TP review.

## Fresh tool executions and scope

Runs took place on **2026-09-20 UTC** (September 19 in the operator's local time). The baseline came from Git revision `317c2fee15109468b616a1955d7979aeea5800ea`, independently of later working-tree edits. Its implementation hash was `e2980c182d71dbe78b1acfb9057adcf8568c1a9738a8f7abc8073287644843d2`. The final v0.13.0 implementation hash was `8d56fcf24bb47474196842268b3512ce8df00a81a3371f7fce63757fa1a8f309`, with ruleset 1.4.0. See [baseline identity](baseline-identity.json), [before executions](before-executions.json), [after executions](after-executions.json), and [external executions](external-executions.json).

There were **56 actual source-scanner CLI invocations**: 16 baseline Invarune runs, 24 external-tool runs, and 16 final Invarune runs. Invarune ran twice per project in each phase; all four report formats were byte-identical within every repeat pair. The study also ran one separate Cisco metadata call, two external shared-fixture CLI calls, direct Invarune analysis of that fixture subset, and one full 113-case evaluator call per Invarune version. There were no model calls or live-server tests. Target code, builds, package hooks and MCP servers were never executed.

External engines and rules were deliberately held at the same pinned versions for comparison; this is **not a claim that they are the latest releases**. The [tool lock](tool-lock.json) gives versions, official upstream links and hashes. The locally retained Semgrep `p/security-audit` pack has 225 rules and SHA-256 `b109a039df712f30c6d3e25e1e8358053fd0f1c91b92d0e8d2871cd141fe602f`; a moving registry name alone is insufficient for reproduction.

| Tool / version | Native observations | Analysis limitations in this run |
|---|---:|---|
| Invarune 0.13.0 | 146 | 15 explicit coverage gaps; bounded static analysis |
| Semgrep CE 1.177.0 | 27 | 7 parser warnings; selected 225-rule pack |
| Bandit 1.9.4 | 938 | 5 parse errors; 2 exports unsupported because they contain no Python |
| Gitleaks 8.30.1 | 3 | Secret-pattern scope; no credential validity checks |
| Cisco MCP Scanner 4.8.4 | 0 | Separate YARA-only scan of 14 literal description items; not a source scan |

The [public corpus manifest](../real-world/manifest.json) pins repository commits and selection rules. All tools were offered the same 4,120 exported source/configuration files; the source manifests were verified before and after scanning. Invarune examined 4,081 files. The other 39 comprise 38 unsupported extensions and one binary-file coverage gap. Counts of files reported by different tools have different definitions. Complete source coverage is separate from rule coverage: passing syntax analysis cannot establish an absence of vulnerabilities.

Invarune's 15 gaps are CrewAI 10, LangGraph 1, OpenHands 2, and Pydantic AI 2; the [coverage receipt](source-coverage-after.json) lists exact reasons and paths. Templates and parse/analyzer failures remain in the input and report. Unsupported tool/project combinations are not zero findings or true negatives. The [run-status ledger](run-status.json) retains process exit codes, errors and unsupported statuses.

## Pinned projects and complete final reports

Each project name links to the exact upstream revision. Invarune's column is **observations / coverage gaps**. External columns are native observation counts, not confirmed vulnerabilities. The full report downloads are actual final CLI outputs: 32 files totaling 13,276,818 bytes, verified against both repeat-execution receipts in the [publication manifest](published-report-manifest.json).

| Pinned project | Invarune / gaps | Semgrep | Bandit | Gitleaks | Full Invarune reports |
|---|---:|---:|---:|---:|---|
| [MCP reference servers](https://github.com/modelcontextprotocol/servers/tree/d73f99efbfd40c3aa1b61e88728b3d49fb52608f) | 61 / 0 | 0 | 0 | 0 | [HTML](invarune-reports/mcp-reference/report.html) · [MD](invarune-reports/mcp-reference/report.md) · [JSON](invarune-reports/mcp-reference/report.json) · [SARIF](invarune-reports/mcp-reference/report.sarif) |
| [GitHub MCP Server](https://github.com/github/github-mcp-server/tree/85598ba6e1256f7ebf4867b95d63b833c4549264) | 15 / 0 | 1 | unsupported | 0 | [HTML](invarune-reports/github-mcp/report.html) · [MD](invarune-reports/github-mcp/report.md) · [JSON](invarune-reports/github-mcp/report.json) · [SARIF](invarune-reports/github-mcp/report.sarif) |
| [AutoGen](https://github.com/microsoft/autogen/tree/027ecf0a379bcc1d09956d46d12d44a3ad9cee14) | 11 / 0 | 6 | 183 | 0 | [HTML](invarune-reports/autogen/report.html) · [MD](invarune-reports/autogen/report.md) · [JSON](invarune-reports/autogen/report.json) · [SARIF](invarune-reports/autogen/report.sarif) |
| [CrewAI](https://github.com/crewAIInc/crewAI/tree/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e) | 27 / 10 | 8 | 232 | 0 | [HTML](invarune-reports/crewai/report.html) · [MD](invarune-reports/crewai/report.md) · [JSON](invarune-reports/crewai/report.json) · [SARIF](invarune-reports/crewai/report.sarif) |
| [LangGraph](https://github.com/langchain-ai/langgraph/tree/aa742fb31e2827d569b843e3600aeda2e0528e4b) | 23 / 1 | 8 | 84 | 1 | [HTML](invarune-reports/langgraph/report.html) · [MD](invarune-reports/langgraph/report.md) · [JSON](invarune-reports/langgraph/report.json) · [SARIF](invarune-reports/langgraph/report.sarif) |
| [OpenHands](https://github.com/OpenHands/OpenHands/tree/a07364828c8f202e7745c6bce3dcef3915ae7ac1) | 9 / 2 | 0 | unsupported | 1 | [HTML](invarune-reports/openhands/report.html) · [MD](invarune-reports/openhands/report.md) · [JSON](invarune-reports/openhands/report.json) · [SARIF](invarune-reports/openhands/report.sarif) |
| [Pydantic AI](https://github.com/pydantic/pydantic-ai/tree/c4898abb54dc25ae6f6aef208a4c0661b30a455e) | 0 / 2 | 2 | 344 | 0 | [HTML](invarune-reports/pydantic-ai/report.html) · [MD](invarune-reports/pydantic-ai/report.md) · [JSON](invarune-reports/pydantic-ai/report.json) · [SARIF](invarune-reports/pydantic-ai/report.sarif) |
| [FastMCP](https://github.com/PrefectHQ/fastmcp/tree/9c35c017cd89e4d50a9f512c8eafde68c301ec70) | 0 / 0 | 2 | 95 | 1 | [HTML](invarune-reports/fastmcp/report.html) · [MD](invarune-reports/fastmcp/report.md) · [JSON](invarune-reports/fastmcp/report.json) · [SARIF](invarune-reports/fastmcp/report.sarif) |

## Finding-by-finding overlap

The [observation ledger](observations.json) preserves every native observation, exact source span, source revision, report hash, tool version, rule ID and unreviewed adjudication status. [Family definitions](rule-family-map.json) provide mapping rationales and predicate caveats. Matching requires the same project, same relative file, an explicitly compatible family, and overlapping inclusive line spans. No nearby-line heuristic is used. Many-to-many matches remain ambiguous; same-location/different-family observations are retained separately.

| Left / right tool | One-to-one matches | Ambiguous edges | Location-only edges | No family match: left / right |
|---|---:|---:|---:|---:|
| invarune / semgrep | 7 | 0 | 0 | 139 / 20 |
| invarune / bandit | 12 | 5 | 0 | 129 / 925 |
| invarune / gitleaks | 1 | 0 | 0 | 145 / 2 |
| semgrep / bandit | 15 | 0 | 3 | 12 / 923 |
| semgrep / gitleaks | 0 | 0 | 0 | 27 / 3 |
| bandit / gitleaks | 0 | 0 | 0 | 938 / 3 |

The five ambiguous Invarune/Bandit edges involve five Invarune observations and one Bandit observation; edge counts are not unique finding counts. The complete [overlap ledger](overlaps.json) lists every matched, ambiguous, location-only and unmatched observation ID. Tool-only does not mean another tool missed a vulnerability: imports versus calls, configuration policy versus exploitability, language support, rule scope and parser gaps differ. Tool agreement does not supply a true-positive label.

This study performs **no confirmed-vulnerability adjudication** of the 1,114 real-source observations. Their true-positive percentage is unknown, not 0%. A new [deterministic stratified review selection](adjudication-selection.json) is available for future review, but no model outcomes or manual labels from the older v0.10 study have been carried forward. The purposive precision fixes described above do not justify extrapolating a corpus-wide TP rate.

## Shared fixtures and complementary tools

The freshly executed [shared-pattern fixture comparison](external-results/shared-pattern-fixtures.json) covers ten existing assertions: five risky API patterns and five corresponding safe cases for eval, shell-enabled subprocesses, unsafe YAML, pickle deserialization and disabled TLS verification. Invarune, Semgrep and Bandit each returned **5 TP / 5 TN / 0 FP / 0 FN** within that narrowly matched scope. The receipt retains native rule mappings, actual external calls and their errors. This tiny development subset is not an independent benchmark or an overall tool ranking. Gitleaks and Cisco have different scopes and are excluded, rather than awarded artificial true negatives.

The tools are complementary: Invarune connects selected static agent/MCP configuration patterns to a controls catalog and reports evidence gaps; Semgrep supplies broader language/rule coverage; Bandit provides Python API audit signals, including intentionally broad checks; Gitleaks specializes in secret patterns. Cisco's MCP-specific metadata analyzers address a different surface. Only its local YARA analyzer ran here, on a conservative extraction of literal TypeScript tool names/descriptions with empty schema placeholders. This is not a captured `tools/list` response, full schema review, behavioral analysis or prompt-injection robustness test. Its zero count cannot clear an MCP deployment. [Cisco receipt](external-results/cisco-metadata.json).

[Primary-source competitor research](../external-tools/RESEARCH.md) documents the earlier selection and why Snyk Agent Scan was researched but not executed in this source-only study. No cloud credentials were supplied, private code was uploaded, or untrusted server was launched. A universal “best scanner” claim is not supported by these measurements.

## Reproduction

Use a separate output tree to preserve these published receipts. The recorded runtime is Python 3.12.14. Install the exact external versions in isolated environments and obtain the official rule pack matching `tool-lock.json`; the Semgrep pack itself is not redistributed. Every exact scanner command also appears in its individual receipt.

```sh
python scripts/scan_public_projects.py --fetch --prepare-only
mkdir -p tmp/reproduce-v013/records
cp -R benchmarks/real-world/snapshots tmp/reproduce-v013/records/snapshots
python scripts/evaluate_accuracy.py --output tmp/reproduce-v013/accuracy-after.json --fail-on none
python scripts/scan_public_projects.py --source-root tmp/real-world-src --output-root tmp/reproduce-v013/invarune-after --records-root tmp/reproduce-v013/records --repeats 2
python scripts/benchmark_competitors.py --source-root tmp/real-world-src --tool-lock benchmarks/comparison-v013/tool-lock.json --semgrep tmp/benchmark-tools/python/bin/semgrep --semgrep-config tmp/benchmark-tools/semgrep-security-audit.yaml --bandit tmp/benchmark-tools/python/bin/bandit --gitleaks tmp/benchmark-tools/gitleaks --cisco tmp/benchmark-tools/cisco/bin/mcp-scanner --output tmp/reproduce-v013/external-results --raw-output tmp/reproduce-v013/external-raw
python scripts/compare_scanner_findings.py --experiment comparison-v013 --source-root tmp/real-world-src --invarune-reports tmp/reproduce-v013/invarune-after --invarune-receipts tmp/reproduce-v013/records/receipts --external-results tmp/reproduce-v013/external-results --external-raw tmp/reproduce-v013/external-raw --output tmp/reproduce-v013/comparison --local-context tmp/reproduce-v013
```

The first command fetches only the public pinned Git objects and exports regular blobs without executing the targets. An offline rerun can omit it when verified exports already exist. The default external command above also runs the shared subset; in the recorded study, source scans ran with `--skip-synthetic` and that same subset function ran separately after the final production freeze. `--fail-on none` changes only the evaluator's process gate: all FP/FN results still count.

To reproduce the before measurement, extract `ai_security_scan`, `scripts/evaluate_accuracy.py`, `scripts/scan_public_projects.py`, `benchmarks/static_accuracy.json`, `benchmarks/real-world/manifest.json` and `benchmarks/real-world/snapshots` from the pinned baseline Git revision into an isolated directory, then run that package and its evaluator with the same public exports and options. Do not use the current package for the baseline. [Baseline identity](baseline-identity.json) records the source/archive/corpus hashes, and every [before execution](before-executions.json) retains its version and byte hashes. Elapsed times are single-host observations with different scopes and are not throughput rankings.

## Publication and limitations

Source evidence comes from public upstream projects. [Third-party notices](../../NOTICE.md) and [copied upstream licenses](../real-world/licenses/) and pinned license references must accompany reuse of excerpts. Original external raw outputs remain local because they may contain licensed rule text or source excerpts; the published normalized results retain hashes and conservative predicates. The [publication audit](report-publication-audit.json) records checks for secrets/private paths and verifies every published report against the actual repeated execution hashes.

This study does not cover deployed authorization, runtime prompt injection, tool poisoning, memory poisoning, model output safety, exploitability, or image-only analysis. Those require separate evidence and tests. Additional static regression tests demonstrate bounded cases, not completeness across all language semantics or absence of false positives and false negatives.
