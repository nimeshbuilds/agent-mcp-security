# Invarune v0.14: fresh benchmark results and reproduction

The unchanged 113-assertion development corpus remains **58 TP / 52 TN / 1 FP / 2 FN**. The separate skill/tool instruction corpus contains **81 cases and 331 assertions**, with **40 TP / 288 TN / 0 FP / 3 FN**. These labels establish static pattern evidence, not malicious author intent or confirmed exploitation.

Across the same eight pinned public source exports, Invarune reports **146 observations** and **21 coverage gaps**, versus 146 observations and 15 gaps in archived v0.13.0. No rule-pattern counts are interpreted as confirmed vulnerabilities or a ranking of tools.

Read the [visual dashboard](../../docs/BENCHMARK_DASHBOARD.md), [v0.14 benchmark PDF](../../output/pdf/invarune-benchmark-v014.pdf), [complete observation ledger](FINDINGS.md), or the full project reports below. The canonical repository is [nimeshbuilds/invarune](https://github.com/nimeshbuilds/invarune).

## Paired unchanged development benchmark

| Same 113 assertions | Archived v0.13.0 | Final v0.14.0 |
|---|---:|---:|
| True positive | 58 | 58 |
| True negative | 52 | 52 |
| False positive | 1 | 1 |
| False negative | 2 | 2 |
| Precision: TP / (TP + FP) | 98.31% | 98.31% |
| Recall: TP / (TP + FN) | 96.67% | 96.67% |

There were **0 changed assertions**. Case IDs, sources, labels and the corpus SHA-256 stayed identical: `eb7f1eba93f8e9842634cbd12687dde5bea879505d99d367621214583e54dde3`. [Before](accuracy-before.json), [after](accuracy-after.json) and the [paired receipt](before-after-accuracy.json) retain all case-level outcomes and implementation hashes. This project-authored development corpus covers the original 42 rules; its denominator is not expanded to imply that it validates all 46 rules.

The remaining original-corpus false negatives concern interprocedural URL flow and a JavaScript wrapper; the false positive is a validated dynamic URL. These limits are retained in the metrics. The corpus was visible during development, so these are not independent or production accuracy estimates.

## Separate skill and tool instruction corpus

[The new evaluator output](skills-tools-accuracy.json) and [provenance receipt](skills-tools-evaluation-receipt.json) bind 81 cases, 331 explicit rule-presence assertions, corpus version 1.0.0, and the exact final scanner implementation. Positive and negative labels may share a case; assertions are not independent samples. Nothing from this new corpus is merged into the original 113-assertion before/after denominator.

Measured precision is **100.00%** (40 / 40); recall is **93.02%** (40 / 43). All 3 known misses remain included. Those percentages describe project-authored instruction-pattern fixtures, not model resistance, deployed safety or the proportion of malicious packages.

| Remaining skill/tool mismatch | Expected rule | Outcome |
|---|---|
| `challenge-multilingual-override` | `AI043` | false negative |
| `challenge-semantic-exfiltration` | `AI044` | false negative |
| `challenge-indirect-override` | `AI043` | false negative |

The new rules inspect declared agent-facing instructions or literal tool metadata for hierarchy overrides, sensitive-data transfer directives, covert action/approval bypass, and a read-only annotation conflicting with a destructive description. Static text is a reviewable signal; authorization, execution, disclosure and author intent need separate evidence. Dynamic metadata, obfuscations outside supported forms and model behavior remain limited.

## Actual fresh executions and frozen scope

Runs were executed on **2026-09-20 UTC**. The baseline was extracted from Git `085135540b06109e93fe99c7ed0dd320dca34237`, with implementation `8d56fcf24bb47474196842268b3512ce8df00a81a3371f7fce63757fa1a8f309`. The final version is **0.14.0**, ruleset **1.5.0**, implementation `a10cff2be83ee83ef7f016e0d9644b42b2cc9869528a91763840970dc87765f1`. [Baseline identity](baseline-identity.json), [before executions](before-executions.json), [after executions](after-executions.json), and [external executions](external-executions.json) preserve actual commands, UTC timestamps, exit reasons and byte hashes.

The primary comparison contains **56 actual source-scanner CLI calls**: 16 archived baseline runs, 24 external-tool runs and 16 final Invarune runs. Each Invarune project ran twice in each phase, with all four report formats byte-identical within its pair. Separately, Cisco ran one offline metadata call; Semgrep and Bandit ran the shared ten-fixture subset, alongside direct Invarune analysis. Each current full-corpus evaluation is recorded independently. No target code, builds, dependency hooks, MCP server or model was executed.

An earlier candidate final freeze completed 16 additional source calls before a terminal-output sanitization defect prompted a new implementation freeze. These superseded calls and their original hashes remain in [superseded-executions.json](superseded-executions.json); they are excluded from the current 56-call comparison. Their outputs were archived privately, and current reports were regenerated by executing the final implementation rather than editing metadata. The initial candidate also evaluated both fixture corpora and the shared subset; these evaluations are not substituted for current runs.

External tool versions and rule bytes were held fixed for comparability, not described as the latest release. The [tool lock](tool-lock.json) retains official release links and hashes. The Semgrep pack is the locally frozen 225-rule `p/security-audit` pack, SHA-256 `b109a039df712f30c6d3e25e1e8358053fd0f1c91b92d0e8d2871cd141fe602f`. A moving registry name alone cannot reproduce it.

| Tool / version | Native observations | Analysis scope or limitations |
|---|---:|---|
| Invarune 0.14.0 | 146 | 21 explicit coverage gaps; bounded static analysis |
| Semgrep CE 1.177.0 | 27 | Seven parser warnings; selected 225-rule pack |
| Bandit 1.9.4 | 938 | Five parse errors; two unsupported exports with no Python |
| Gitleaks 8.30.1 | 3 | Secret-pattern scope; credential validity not checked |
| Cisco MCP Scanner 4.8.4 | 0 | Separate YARA-only track: 14 literal metadata items |

The [pinned source manifest](../real-world/manifest.json) selects the same 4,120 exported files, verified before and after scanning. It removes conventional tests, examples, documentation and vendor/build trees and explicitly excludes `AGENTS.md` and `CLAUDE.md`. This production-source sample therefore cannot establish complete skill-package coverage. Literal tool descriptions present in selected production code remain available. Skill/tool fixtures are a separate assessment of the new detectors, not a reason to change the paired source scope.

Invarune examined **4,081 files**. Unsupported extensions and input/analysis gaps remain separately listed in [source coverage](source-coverage-after.json). The [source delta](source-delta.json) compares exact pattern identities and examined-file bytes, preserving any added/removed coverage errors.

Newly surfaced coverage limitations:

| Project | Source | Limitation |
|---|---|---|
| crewai | `lib/crewai-tools/tool.specs.json` | Instruction-threat inspection is bounded to 1000000 characters for source metadata; remaining instruction/tool metadata needs review. |
| crewai | `lib/crewai/src/crewai/tools/base_tool.py` | Dynamic tool description at line 765 was not resolved; instruction-threat checks require literal metadata. |
| openhands | `src/i18n/translation.json` | Instruction-threat inspection is bounded to 1000000 characters for source metadata; remaining instruction/tool metadata needs review. |
| pydantic-ai | `pydantic_ai_slim/pydantic_ai/capabilities/capability.py` | Dynamic tool description at line 296 was not resolved; instruction-threat checks require literal metadata. |
| pydantic-ai | `pydantic_ai_slim/pydantic_ai/models/xai.py` | Dynamic tool description at line 1245 was not resolved; instruction-threat checks require literal metadata. |
| fastmcp | `fastmcp_slim/fastmcp/server/server.py` | Dynamic tool description at line 1956 was not resolved; instruction-threat checks require literal metadata. |

A coverage gap is not a vulnerability finding or a clean pass. Counts of files reported by different tools use different definitions; parser success also does not imply complete rule or runtime coverage.

## Pinned projects and complete final reports

All **32 final reports** (13,638,833 bytes) are actual CLI outputs, verified against both executions in the [publication manifest](published-report-manifest.json). Project names link to exact upstream revisions. Invarune's column is **observations / gaps**; external columns contain native observations, not confirmed vulnerabilities.

| Pinned project | Invarune / gaps | Semgrep | Bandit | Gitleaks | Full final reports |
|---|---:|---:|---:|---:|---|
| [MCP reference servers](https://github.com/modelcontextprotocol/servers/tree/d73f99efbfd40c3aa1b61e88728b3d49fb52608f) | 61 / 0 | 0 | 0 | 0 | [HTML](invarune-reports/mcp-reference/report.html) · [MD](invarune-reports/mcp-reference/report.md) · [JSON](invarune-reports/mcp-reference/report.json) · [SARIF](invarune-reports/mcp-reference/report.sarif) |
| [GitHub MCP Server](https://github.com/github/github-mcp-server/tree/85598ba6e1256f7ebf4867b95d63b833c4549264) | 15 / 0 | 1 | unsupported | 0 | [HTML](invarune-reports/github-mcp/report.html) · [MD](invarune-reports/github-mcp/report.md) · [JSON](invarune-reports/github-mcp/report.json) · [SARIF](invarune-reports/github-mcp/report.sarif) |
| [AutoGen](https://github.com/microsoft/autogen/tree/027ecf0a379bcc1d09956d46d12d44a3ad9cee14) | 11 / 0 | 6 | 183 | 0 | [HTML](invarune-reports/autogen/report.html) · [MD](invarune-reports/autogen/report.md) · [JSON](invarune-reports/autogen/report.json) · [SARIF](invarune-reports/autogen/report.sarif) |
| [CrewAI](https://github.com/crewAIInc/crewAI/tree/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e) | 27 / 12 | 8 | 232 | 0 | [HTML](invarune-reports/crewai/report.html) · [MD](invarune-reports/crewai/report.md) · [JSON](invarune-reports/crewai/report.json) · [SARIF](invarune-reports/crewai/report.sarif) |
| [LangGraph](https://github.com/langchain-ai/langgraph/tree/aa742fb31e2827d569b843e3600aeda2e0528e4b) | 23 / 1 | 8 | 84 | 1 | [HTML](invarune-reports/langgraph/report.html) · [MD](invarune-reports/langgraph/report.md) · [JSON](invarune-reports/langgraph/report.json) · [SARIF](invarune-reports/langgraph/report.sarif) |
| [OpenHands](https://github.com/OpenHands/OpenHands/tree/a07364828c8f202e7745c6bce3dcef3915ae7ac1) | 9 / 3 | 0 | unsupported | 1 | [HTML](invarune-reports/openhands/report.html) · [MD](invarune-reports/openhands/report.md) · [JSON](invarune-reports/openhands/report.json) · [SARIF](invarune-reports/openhands/report.sarif) |
| [Pydantic AI](https://github.com/pydantic/pydantic-ai/tree/c4898abb54dc25ae6f6aef208a4c0661b30a455e) | 0 / 4 | 2 | 344 | 0 | [HTML](invarune-reports/pydantic-ai/report.html) · [MD](invarune-reports/pydantic-ai/report.md) · [JSON](invarune-reports/pydantic-ai/report.json) · [SARIF](invarune-reports/pydantic-ai/report.sarif) |
| [FastMCP](https://github.com/PrefectHQ/fastmcp/tree/9c35c017cd89e4d50a9f512c8eafde68c301ec70) | 0 / 1 | 2 | 95 | 1 | [HTML](invarune-reports/fastmcp/report.html) · [MD](invarune-reports/fastmcp/report.md) · [JSON](invarune-reports/fastmcp/report.json) · [SARIF](invarune-reports/fastmcp/report.sarif) |

## Exhaustive observations and overlap

The [ledger](observations.json) preserves all **1,114 observations**, including native rule IDs, source revision/spans, tool versions, report hashes and unreviewed status. [Rule families](rule-family-map.json) state why particular API/configuration surfaces are comparable and preserve applicability caveats. The four instruction-metadata families have no assumed equivalent in the selected external rules.

A match requires the same project and relative path, an explicitly compatible family, and overlapping inclusive source spans. Nearby lines do not qualify. Many-to-many cases remain ambiguous; unrelated or unmapped families at the same location remain location-only relations.

| Left / right tool | One-to-one | Ambiguous edges | Location-only edges | No family match: left / right |
|---|---:|---:|---:|---:|
| invarune / semgrep | 7 | 0 | 0 | 139 / 20 |
| invarune / bandit | 12 | 5 | 0 | 129 / 925 |
| invarune / gitleaks | 1 | 0 | 0 | 145 / 2 |
| semgrep / bandit | 15 | 0 | 3 | 12 / 923 |
| semgrep / gitleaks | 0 | 0 | 0 | 27 / 3 |
| bandit / gitleaks | 0 | 0 | 0 | 938 / 3 |

The five ambiguous Invarune/Bandit edges involve five Invarune observations and one Bandit observation. Edge counts are not unique findings. [All overlap partitions](overlaps.json) and [run statuses](run-status.json) retain unmatched cases and analysis failures. A tool-only observation is not automatically another tool's false negative: imports versus calls, policy checks versus exploitation, supported languages and parser gaps differ. Agreement supplies no true-positive label.

**Production true-positive percentage is unknown**, not 0%. None of these 1,114 observations has been assigned a confirmed-vulnerability label in this study. A [new deterministic review selection](adjudication-selection.json) is available for future review, but no old model/manual labels have been reused and no model adjudication was performed.

## Shared fixtures and complementary tools

The [fresh ten-fixture comparison](external-results/shared-pattern-fixtures.json) uses five risky and five safe API patterns: eval, shell-enabled subprocesses, unsafe YAML, pickle deserialization and disabled TLS verification. Invarune, Semgrep and Bandit each scored **5 TP / 5 TN / 0 FP / 0 FN** on that narrow existing subset. Native rule mappings and actual external execution receipts are retained. These development fixtures are not an overall accuracy ranking; Gitleaks and Cisco are excluded because their scopes differ, with no artificial true negatives awarded.

Invarune adds agent/MCP control context and explicit gaps; Semgrep supplies broader language/rule coverage; Bandit provides Python API audit signals; Gitleaks specializes in secret patterns. Cisco's MCP metadata analyzers address a different surface. Only its local YARA analyzer ran here, on 14 literal TypeScript names/descriptions with empty schema placeholders. It did not inspect a captured `tools/list` response, complete input schemas, live behavior or model robustness. Its zero count does not clear a deployment. [Cisco receipt](external-results/cisco-metadata.json).

[Primary-source competitor research](../external-tools/RESEARCH.md) documents the earlier tool selection and why Snyk Agent Scan was researched but not executed in this source-only study. No private code or credentials were uploaded.

## Reproduction

Use a separate output tree so historical artifacts remain intact. Recorded runtime: Python 3.12.14. Install exact external versions in isolated environments and obtain the official rule pack matching the tool lock; the Semgrep rule pack itself is not redistributed. Exact per-project commands are also retained in individual receipts.

```sh
python scripts/scan_public_projects.py --fetch --prepare-only
mkdir -p tmp/reproduce-v014/records
cp -R benchmarks/real-world/snapshots tmp/reproduce-v014/records/snapshots
python scripts/evaluate_accuracy.py --output tmp/reproduce-v014/accuracy-after.json --fail-on none
python scripts/evaluate_accuracy.py --corpus benchmarks/skills_tools_accuracy.json --output tmp/reproduce-v014/skills-tools-accuracy.json --fail-on none
python scripts/scan_public_projects.py --source-root tmp/real-world-src --output-root tmp/reproduce-v014/invarune-after --records-root tmp/reproduce-v014/records --repeats 2
python scripts/benchmark_competitors.py --source-root tmp/real-world-src --tool-lock benchmarks/comparison-v014/tool-lock.json --semgrep tmp/benchmark-tools/python/bin/semgrep --semgrep-config tmp/benchmark-tools/semgrep-security-audit.yaml --bandit tmp/benchmark-tools/python/bin/bandit --gitleaks tmp/benchmark-tools/gitleaks --cisco tmp/benchmark-tools/cisco/bin/mcp-scanner --output tmp/reproduce-v014/external-results --raw-output tmp/reproduce-v014/external-raw
python scripts/compare_scanner_findings.py --experiment comparison-v014 --tool-lock benchmarks/comparison-v014/tool-lock.json --source-root tmp/real-world-src --invarune-reports tmp/reproduce-v014/invarune-after --invarune-receipts tmp/reproduce-v014/records/receipts --external-results tmp/reproduce-v014/external-results --external-raw tmp/reproduce-v014/external-raw --output tmp/reproduce-v014/comparison --local-context tmp/reproduce-v014
```

The first command fetches only pinned public Git objects and exports regular blobs; it does not execute targets. Omit it for an offline rerun with existing verified exports. The combined external command also evaluates the shared subset; the recorded study ran source scans with `--skip-synthetic` and evaluated that same subset separately after each candidate freeze. `--fail-on none` changes only the evaluator process gate, while all misses and false alarms remain scored.

To reproduce the before phase, extract `ai_security_scan`, the two evaluator/public-scan scripts, the unchanged 113-case corpus, the public source manifest and snapshots from pinned Git 0851355 into an isolated directory. Run that archived package and evaluator against the same exports and flags. Do not use the current package for the baseline. Times are single-host observations across different scopes, not throughput rankings.

## Publication and limitations

[Third-party notices](../../NOTICE.md), [copied upstream licenses](../real-world/licenses/) and pinned upstream license references accompany public source excerpts. Raw external tool outputs stay local because they may contain licensed rule text or source excerpts; normalized output retains provenance hashes. The [publication audit](report-publication-audit.json) records privacy/secret checks and verifies all 32 published outputs against both actual final executions.

Static evidence cannot establish deployed authorization, actual data disclosure, prompt-injection resistance, malicious package intent, complete memory/tool poisoning coverage or exploitability. This source-only comparison also does not benchmark built-image scanning. Those questions need their own evidence, scope and runtime tests.
