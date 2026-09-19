# Invarune: real project scans and scanner comparison

![Invarune by NimeshBuild](assets/brand/invarune-logo-light.svg)

**Research edition · 19 September 2026** · [Download the branded benchmark PDF](../output/pdf/invarune-benchmark-report.pdf)

<!-- BEGIN MEASURED SUMMARY -->
**Eight pinned projects. 4,120 shared input files. Four complementary scanners actually executed, plus Invarune.** Invarune 0.8.0 examined **4,081 files**, emitted **149 static review candidates**, and retained **15 coverage gaps**. Semgrep reported **27 observations**, Bandit **938**, and Gitleaks **3**; these are different units of review work, not comparable vulnerability totals. Cisco separately scanned **14 literal tool descriptions** with its YARA analyzer.

Two actual Invarune executions per project produced byte-identical HTML, Markdown, JSON and SARIF reports. The comparison includes every incomplete result and unsupported input.
<!-- END MEASURED SUMMARY -->

The main result is that these tools expose **different security review work**. The data supports using complementary layers. It does not support a universal winner, a count of confirmed vulnerabilities, or a production accuracy ranking. Ten small shared development fixtures were matched correctly by Invarune, Semgrep CE and Bandit; that verifies those specific API patterns, not the security of the projects below.

## What was actually tested

Eight official agent/MCP repositories were pinned to full commit IDs before scanning. The experiment exported 4,120 first-party source/configuration files, preserving their bytes and upstream paths. Tests, examples, documentation, dependencies and generated trees were excluded consistently; dependency manifests/lockfiles, embedded production prompts and implementation templates remained. Each scanner received the same exported source bytes, while its own supported languages and rules determined actual analysis coverage. The [selection manifest](../benchmarks/real-world/manifest.json) and [per-file source manifests](../benchmarks/real-world/snapshots/) make that scope auditable.

No target code, install script, public server, MCP command or container was executed. Invarune's optional analyst was disabled. No baseline or user justification suppressed findings. Semgrep CE 1.177.0 used a frozen official 225-rule security-audit pack; Bandit 1.9.4 used all default Python plugins; Gitleaks 8.30.1 used its packaged secret-detection rules in directory mode. [Tool locks, settings and provenance](../benchmarks/external-tools/tool-lock.json) identify the exact versions and pack SHA-256.

## Findings and coverage, together

Cells show **observations / analysis gaps** where the tool reports gaps. An observation is a static pattern requiring context review. The gap types differ: Invarune includes work-budget/input/parser failures; the Semgrep and Bandit values here are parser warnings/errors. Unsupported input is excluded from clean-result claims.

<!-- BEGIN COMPARISON TABLE -->
| Pinned project / commit | Invarune candidates / gaps | Semgrep observations / parser warnings | Bandit observations / parser errors | Gitleaks observations | Detailed Invarune reports |
|---|---:|---:|---:|---:|---|
| [MCP reference servers](https://github.com/modelcontextprotocol/servers/tree/d73f99efbfd40c3aa1b61e88728b3d49fb52608f) · `d73f99efbfd4` | 61 / 0 | 0 / 0 | 0 / 0 | 0 | [HTML](../examples/reports/real-world/mcp-reference/report.html) · [Markdown](../examples/reports/real-world/mcp-reference/report.md) |
| [GitHub MCP Server](https://github.com/github/github-mcp-server/tree/85598ba6e1256f7ebf4867b95d63b833c4549264) · `85598ba6e125` | 15 / 0 | 1 / 1 | Unsupported: no Python | 0 | [HTML](../examples/reports/real-world/github-mcp/report.html) · [Markdown](../examples/reports/real-world/github-mcp/report.md) |
| [AutoGen](https://github.com/microsoft/autogen/tree/027ecf0a379bcc1d09956d46d12d44a3ad9cee14) · `027ecf0a379b` | 13 / 0 | 6 / 0 | 183 / 0 | 0 | [HTML](../examples/reports/real-world/autogen/report.html) · [Markdown](../examples/reports/real-world/autogen/report.md) |
| [CrewAI](https://github.com/crewAIInc/crewAI/tree/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e) · `3831e8b6c86f` | 28 / 10 | 8 / 5 | 232 / 5 | 0 | [HTML](../examples/reports/real-world/crewai/report.html) · [Markdown](../examples/reports/real-world/crewai/report.md) |
| [LangGraph](https://github.com/langchain-ai/langgraph/tree/aa742fb31e2827d569b843e3600aeda2e0528e4b) · `aa742fb31e28` | 23 / 1 | 8 / 0 | 84 / 0 | 1 | [HTML](../examples/reports/real-world/langgraph/report.html) · [Markdown](../examples/reports/real-world/langgraph/report.md) |
| [OpenHands](https://github.com/OpenHands/OpenHands/tree/a07364828c8f202e7745c6bce3dcef3915ae7ac1) · `a07364828c8f` | 9 / 2 | 0 / 1 | Unsupported: no Python | 1 | [HTML](../examples/reports/real-world/openhands/report.html) · [Markdown](../examples/reports/real-world/openhands/report.md) |
| [Pydantic AI](https://github.com/pydantic/pydantic-ai/tree/c4898abb54dc25ae6f6aef208a4c0661b30a455e) · `c4898abb54dc` | 0 / 2 | 2 / 0 | 344 / 0 | 0 | [HTML](../examples/reports/real-world/pydantic-ai/report.html) · [Markdown](../examples/reports/real-world/pydantic-ai/report.md) |
| [FastMCP](https://github.com/PrefectHQ/fastmcp/tree/9c35c017cd89e4d50a9f512c8eafde68c301ec70) · `9c35c017cd89` | 0 / 0 | 2 / 0 | 95 / 0 | 1 | [HTML](../examples/reports/real-world/fastmcp/report.html) · [Markdown](../examples/reports/real-world/fastmcp/report.md) |
<!-- END COMPARISON TABLE -->

Gitleaks reported three patterns across the corpus; its JSON format does not provide an exhaustive per-file scan inventory, so the table does not invent a zero-gap claim. Bandit includes low-severity audit observations such as assertions and imports. Semgrep CE's measured pack covers a different set of source patterns. Counts therefore cannot be compared as vulnerability totals or used to rank scanner quality.

The [full Invarune results index](../benchmarks/real-world/RESULTS.md) adds severity distributions, examined-file counts, execution gates, repeatability checks and every HTML/Markdown/JSON/SARIF artifact. The [external comparison receipts](../benchmarks/external-tools/results/summary.json) contain process outcomes, actual tool-reported file counts, warning locations and elapsed times. Timings come from a shared development machine, include different work per tool and are not a controlled speed ranking.

## Immediate review work and mitigating layers

The [manual review record](../benchmarks/real-world/TRIAGE.md) follows selected initial observations back to pinned upstream code. It is a diagnostic sample, not exhaustive adjudication or a precision estimate.

| Observed surface | What the evidence supports | Next validation and useful mitigating layers |
|---|---|---|
| AutoGen executes Python from serialized tool configuration | A real execution capability; upstream warns that configurations must be trusted. An untrusted attack path was not demonstrated. | Verify who may supply/change configurations, enforce provenance and authorization, and isolate intentional execution with separate filesystem, network and credential boundaries. |
| AutoGen experimental memory loads pickle data | A deserialization sink exists. Whether an attacker can control the local artifact is deployment-dependent. | Trace tool/model write access, validate artifact permissions/provenance, and use a non-executable serialization format where possible. |
| LangGraph constructs SQL statements | One manually reviewed call binds values separately and was a false positive for that call. Other findings remain unverified. | Review every interpolated component and helper; keep value binding, constrained identifiers and least-privilege database roles. A parameter list alone does not prove every interpolation safe. |
| MCP reference servers expose permissive CORS in test-oriented transports | Intentional reference/testing configuration; upstream does not present the collection as production-ready. | For derived deployments, validate origin handling, authentication and host/network exposure. Apply gateway policy and runtime authorization as separate verified controls. |
| Secret-like values, dependency ranges and configuration settings | Some initial observations were placeholders, labels, embedded examples or settings superseded later in the file. A pattern alone does not prove a leaked key or vulnerable build. | Follow values to their consumers; verify real credential storage and injection, frozen lockfile installs, integrity/provenance, and the effective deployed configuration. |
| Parser and analysis-budget gaps | Some selected files were not fully analyzed. Retaining them prevents a false clean result. | Review the listed files using a suitable parser and a deployment-aware security review. Analyze templates after rendering in a controlled build and keep source/release provenance. |

These are proposed mitigation layers, not verified reductions in residual risk. Source scanning cannot establish that a gateway, sandbox, identity policy or egress boundary is active and correctly configured. The detailed Invarune reports preserve that distinction.

## What real testing changed

Manual review found clear false positives in initial scans: a PEM opening marker with no key material, SDK placeholders and error labels, and a Docker setup stage whose root user was replaced by the final runtime user. These observations informed narrow detector fixes and regression tests before the final rescan. The project did not exclude the noisy files or blanket-suppress the affected repositories. Initial finding IDs, scan IDs, severities and implementation hashes remain in [the original triage record](../benchmarks/real-world/triage-initial.json).

The SQL example also demonstrates a remaining context limit: one reviewed composed query was safely parameterized, and its finding was not removed by a broad name-based exception. The reports still require analyst judgment about reachability, trust boundaries and compensating controls. The corpus is now development-visible and must not be described as held-out validation.

## Shared API-pattern check

This separate track executes Semgrep and Bandit against the same ten existing project-authored fixtures and evaluates Invarune's matching rules. The five subjects are dynamic `eval`, shell-enabled subprocess execution, unsafe PyYAML loading, pickle deserialization and Requests certificate-verification bypass. Each has one positive and one negative label.

| Scanner | Positive labels matched | Negative labels matched | False-positive label mismatches | False-negative label mismatches |
|---|---:|---:|---:|---:|
| Invarune 0.8.0 | 5 / 5 | 5 / 5 | 0 | 0 |
| Semgrep CE 1.177.0 | 5 / 5 | 5 / 5 | 0 | 0 |
| Bandit 1.9.4 | 5 / 5 | 5 / 5 | 0 | 0 |

These are API-pattern presence assertions, not confirmed vulnerability labels. Unrelated findings are retained but unscored. Gitleaks and MCP metadata tools have different scopes and receive no artificial true negatives. This small, development-visible set is not an independent benchmark or a production precision/recall estimate. [Every case, mapping, raw-output digest and actual execution receipt](../benchmarks/external-tools/results/shared-pattern-fixtures.json) is published. Its parent is corpus 1.1.0; the preserved [1.0.0 corpus](../benchmarks/static_accuracy-v100.json) is a different byte set.

## MCP-specific tools and why the layers complement each other

| Layer | Tool assessed | Measured scope and interpretation |
|---|---|---|
| Agent/MCP source and control review | Invarune | Deterministic source triage, control mappings, evidence, coverage gaps and mitigation guidance. Optional analyst review was not used in this experiment. |
| Cross-language source analysis | Semgrep CE | Local 225-rule official audit pack. Paid/proprietary analyses and other packs were not measured. |
| Python security checks | Bandit | AST checks and audit observations. Non-Python inputs are explicitly unsupported. |
| Secret patterns | Gitleaks | Current-directory content, with secret values redacted. Git history and live credential validation were not measured. |
| MCP metadata patterns | Cisco MCP Scanner 4.8.4 | A real YARA-only scan of 14 literal filesystem tool descriptions completed with zero findings. This partial static extraction is not a captured runtime inventory; schemas, computed metadata and execution behavior remain unassessed. |
| Installed agent/MCP/skill discovery and analysis | Snyk Agent Scan 0.6.3 researched | Not executed: its normal MCP workflow starts configured servers and requires a Snyk API token for cloud analysis. That falls outside this source-only experiment. No score or clean result is assigned. |

The shortlist was selected for relevant scope, established maintainers, CLI availability, structured output and reproducible local modes. It is not an exhaustive market survey. [Primary-source research](../benchmarks/external-tools/RESEARCH.md), [external methodology](../benchmarks/external-tools/README.md), and [Cisco's actual metadata receipt](../benchmarks/external-tools/results/cisco-metadata.json) document those distinctions. Container CVE analysis, runtime authorization, deployed OAuth, sandbox escapes and active prompt-injection testing require separate experiments; source or metadata findings do not substitute for those layers.

## Provenance, licensing and reproduction

All repositories and license documents are pinned in the corpus manifest; [copied upstream license notices](../benchmarks/real-world/licenses/) accompany the research artifacts. The exported upstream implementations remain in ignored local staging; reports retain bounded evidence and source links. This work makes no claim of upstream endorsement, certification or a newly confirmed vulnerability, and no upstream disclosure message was sent.

External tools are isolated research dependencies, not bundled scanner engines. In particular, Semgrep's rule pack is retained locally with a published digest and source URL; it is not redistributed. Normalized external results omit full rule text, source snippets and secret values while recording raw-output hashes. A future changed rule pack must be treated as a new experiment rather than silently replacing this one.

From the repository root:

```bash
# Fetch exact public commits and export only the pinned source scope.
python3 scripts/scan_public_projects.py --fetch --prepare-only

# Run Invarune twice per project and verify all four report formats match.
python3 scripts/scan_public_projects.py

# Show every setting for the separately installed external scanners.
python3 scripts/benchmark_competitors.py --help
```

Follow the [complete external reproduction commands](../benchmarks/external-tools/README.md#reproduce) for pinned installs, checksum verification and actual CLI execution. Use the [public scan methodology](../benchmarks/real-world/README.md) for exact source/runtime/version requirements. Failures and coverage gaps remain in the published results; they are not converted into passing checks.
