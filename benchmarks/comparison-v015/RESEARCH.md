# v0.15 gap audit and benchmark design

Research checked 2026-09-23. This audit distinguishes broader product capability from the exact offline configurations executed in this study. Published rankings require equivalent inputs, tasks and independently supported labels; more warnings alone do not establish a better security result.

## What the previous comparison actually showed

The v0.14 ledger contains 938 Bandit, 146 Invarune, 27 Semgrep and 3 Gitleaks observations. **802 of Bandit’s 938 observations** fall into five broad categories: 518 asserts, 106 empty exception handlers, 77 subprocess calls without a shell, 51 subprocess imports and 50 partial executable paths. These are useful audit surfaces, but counting them as 802 additional exploitable vulnerabilities would be unsupported. [Archived complete ledger](../comparison-v014/observations.json).

Concrete source inspection found a valuable missing policy check: AutoGen makes the optional Jupyter execution bind directory world writable (`os.chmod(bind_dir, 0o777)`). That is relevant to an agent’s execution workspace; actual exposure still depends on ownership, mounting and isolation. [Pinned source](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-ext/src/autogen_ext/code_executors/docker_jupyter/_jupyter_server.py#L328), [Bandit permission rule](https://bandit.readthedocs.io/en/latest/plugins/b103_set_bad_file_permissions.html).

Several apparent gaps are poor candidates for warning-count inflation. FastMCP uses `yaml.BaseLoader`, which does not construct arbitrary Python objects; CrewAI deliberately renders trusted Markdown through Jinja; Semgrep’s pickle family includes serialization as well as deserialization; CrewAI archive calls use safe extraction helpers whose containment and link handling require reading their implementations. A pattern match needs a precise risk predicate before it becomes a new detector.

The unchanged development corpus already exposed more important agent-specific gaps: URL flow through local helpers, a JavaScript wrapper, and a validated-URL false alarm. Those should be addressed with bounded argument/return summaries and reject-path reasoning, not larger regular expressions. Skill metadata additionally needs bounded instruction composition and clear semantic limits. A model can investigate a residual ambiguity using verified evidence but cannot convert absence of evidence into a clean result.

## Current official peer capabilities and fair scope

| Product | Officially documented capability | Scope used here / consequence |
|---|---|---|
| Semgrep | Language-aware rule scanning; its wider platform includes additional SAST, dependency, secrets and contextual features. | CE 1.177.0 with the same frozen 225-rule security-audit pack. The result cannot rank the whole commercial platform. [Official platform](https://semgrep.dev/), [MCP guide](https://semgrep.dev/blog/2025/a-security-engineers-guide-to-mcp/). |
| Bandit | Python security AST plugins, including dangerous APIs, imports and file permission checks. | 1.9.4 default plugins without inline suppression. Imports, API calls and vulnerability claims remain separate. [Official plugin index](https://bandit.readthedocs.io/en/latest/plugins/index.html). |
| Gitleaks | Secret detection with configurable patterns, entropy and allowlists. | 8.30.1 pinned defaults; no live credential verification. A literal’s validity is unknown. [Official documentation](https://github.com/gitleaks/gitleaks). |
| Cisco MCP Scanner | Offline metadata, YARA, API and LLM analyzers; behavioral source analysis, readiness, vulnerable packages and optional malware checks. | 4.8.4 local YARA only on identical supplied metadata. Disabled analyzers are unmeasured, never counted as misses. [Official repository](https://github.com/cisco-ai-defense/mcp-scanner), [architecture](https://github.com/cisco-ai-defense/mcp-scanner/blob/main/docs/architecture.md). |
| Snyk Agent Scan | Agent skill and MCP analysis with prompt-injection, tool-poisoning, cross-origin and toxic-flow risk classes. | Researched; its CLI does support direct skill files. No authenticated analysis-service run was performed here because no SNYK_TOKEN was configured; MCP configuration scans contact configured servers, unlike the source-only export track. Do not infer product accuracy from non-execution. [Official risk reference](https://github.com/snyk/agent-scan/blob/main/docs/risks.md), [issue codes](https://github.com/snyk/agent-scan/blob/main/docs/issue-codes.md). |

The pinned versions provide continuity with v0.14, not a claim to the latest release. All external source scans are fresh executions on the identical 4,120-file exports; existing report bytes are not relabeled as new runs. Native warnings and parse failures remain in the ledger.

## Separate questions need separate tracks

1. **Paired development regression:** Keep the original 113 assertions and the 331 skill/tool assertions unchanged. Publish before/after changes, remaining misses and false alarms without changing denominators.
2. **Public-source observations:** Offer the exact same eight pinned exports to each source scanner. Preserve rule IDs, locations, file manifests, errors and timings. Report overlap by compatible risk family and overlapping source spans; overlap is not correctness.
3. **Blinded challenge:** A separate benchmark author sealed 32 new cases (16 source-flow, 16 MCP metadata) and labels before the initial detector freeze. Record that first score. This is within-project separation, not independent third-party validation. Any tuning after labels are disclosed makes subsequent results development results. [Commitment](challenge-commitment.json).
4. **Equivalent metadata:** Supply the same 16 literal descriptors to Invarune and Cisco’s offline YARA analyzer. Compare instruction-risk presence at the tool level and preserve every native finding. Semgrep, Bandit and Gitleaks do not receive artificial true negatives for unsupported instruction analysis.
5. **Source audit examples:** Review concrete code around selected peer-only locations. Labels describe verified source predicates and contextual qualifications, not exploitability or deployed true-positive percentages. The sample is purposive, so percentages cannot generalize to all observations.
6. **Optional investigator:** Run on disclosed residual cases separately, showing static result, requested evidence, validated citations, model result and unresolved runtime questions. Model opinions are not the fixture ground truth, and model answer rate is not security accuracy.

## Runtime benchmarks that cannot be replaced by a repository scan

[AgentDojo](https://github.com/ethz-spylab/agentdojo) evaluates attacks and defenses in dynamic tool-calling tasks. [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) evaluates indirect prompt injection against tool-integrated agents, including direct harm and data stealing. Their outcomes depend on the agent/model, tool execution environment and attack setup. A static package scan does not produce an AgentDojo or InjecAgent attack-success rate. These are valuable future deployment-validation tracks; their source repositories are not substituted for actually running their benchmarks.

The next useful research directions are bounded cross-file dependency summaries, capability-to-effect mismatch analysis, executable tool contracts, and longitudinal descriptor-change detection. These require additional parsing/runtime evidence and independent evaluations. No patentability, uniqueness, universal false-positive guarantee or overall market ranking is asserted.
