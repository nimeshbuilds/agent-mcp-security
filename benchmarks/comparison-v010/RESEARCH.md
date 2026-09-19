# Current scanner shortlist and scope

Checked 19 September 2026 using primary documentation and official package/release metadata. These are relevant established tools for different security layers; this shortlist is not an objective overall ranking or exhaustive market survey.

| Tool | Current version checked | What was actually executed | Why relevant / comparison boundary |
|---|---|---|---|
| Semgrep CE | 1.177.0 | Eight source exports; frozen 225-rule official audit pack; ten shared fixtures | Cross-language source analysis. CE plus one selected pack is not the full paid offering. |
| Bandit | 1.9.4 | Eight exports offered, six with Python; ten shared fixtures | Python AST checks and audit signals; other languages unsupported. |
| Gitleaks | 8.30.1 | Eight directory scans, packaged rules, redacted results | Secret patterns; does not prove live credential validity or cover all agent behavior. |
| Cisco MCP Scanner | 4.8.4 | YARA over 14 literal tool descriptions | MCP metadata patterns; live inventory, behavioral/LLM/API modes not measured. |
| Snyk Agent Scan | 0.6.3 | Researched, not executed | Installed component discovery/cloud analysis; standard MCP discovery executes server commands and requires service authentication. |
| SPLX Agentic Radar | 0.14.1 | Researched, not executed | Static workflow/tool/MCP visibility for supported application frameworks. This corpus is primarily framework/server implementation code; workflow inventory is a different unit from vulnerability findings. |
| Promptfoo MCP red teaming | Documentation checked | Researched, not executed | Runtime client/server and multi-server attack testing; requires an operational target and model/provider configuration outside this source-only experiment. |

Semgrep's official documentation distinguishes its community engine from proprietary cross-file/framework analyses. This experiment uses the local CE engine and pinned audit pack, with metrics and update checks disabled. Sources: [CE language/analysis support](https://docs.semgrep.dev/semgrep-ce-languages), [official package](https://pypi.org/project/semgrep/1.177.0/), [rules license](https://semgrep.dev/legal/rules-license/).

Bandit documents Python AST processing followed by security plugins. Its plugin catalogue includes broad review signals such as assertions, imports and exception handling; those are retained in the comparison rather than quietly removed to make counts appear similar. Sources: [official documentation](https://bandit.readthedocs.io/en/latest/), [plugin catalogue](https://bandit.readthedocs.io/en/latest/plugins/index.html), [official package](https://pypi.org/project/bandit/1.9.4/).

Gitleaks provides source-directory and Git-history secret scanning. This run used directory content, packaged defaults and complete redaction. The official 8.30.1 archive checksum was verified during installation; its release and checksum provenance remain in the tool lock. Sources: [official repository](https://github.com/gitleaks/gitleaks), [8.30.1 release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1).

Cisco documents static MCP JSON scanning without a live server, with YARA available as a deterministic analyzer. Other modes perform different work; the installed 4.8.4 CLI was run only with `--analyzers yara static --tools`. Names/descriptions were extracted from literal source declarations and schemas were format placeholders, so this does not assert a complete tool inventory. Sources: [official scanner](https://github.com/cisco-ai-defense/mcp-scanner), [static mode](https://github.com/cisco-ai-defense/mcp-scanner/blob/main/docs/static-scanning.md), [4.8.4 package](https://pypi.org/project/cisco-ai-mcp-scanner/4.8.4/).

Snyk Agent Scan 0.6.3 is current in official release metadata. Its standard MCP scan retrieves component information by starting configured stdio servers, then uses its analysis service. It was not run against these source exports and receives no score or clean-result credit. Sources: [official README](https://github.com/snyk/agent-scan), [CLI behavior](https://github.com/snyk/agent-scan/blob/main/docs/cli-reference.md), [0.6.3 release](https://github.com/snyk/agent-scan/releases/tag/v0.6.3).

Agentic Radar documents local static workflow graphs, tool identification, MCP detection and vulnerability mapping for LangGraph, CrewAI, n8n, OpenAI Agents and AutoGen. Optional prompt hardening requires model credentials; its `test` command launches an application workflow. The official repository was not archived, but its last pushed change was dated November 2025 at this check, so current package availability should not be described as proof of frequent maintenance. Sources: [official repository and usage](https://github.com/splx-ai/agentic-radar), [official package](https://pypi.org/project/agentic-radar/0.14.1/), [MCP detection announcement](https://splx.ai/blog/agentic-radar-now-detects-mcp-servers-in-agentic-workflows).

Promptfoo's MCP guide covers attack testing through trusted clients, tool poisoning in multi-server environments and related authorization/data-exposure scenarios. Those runtime tests answer questions source scans cannot. No Promptfoo invocation or adversarial network interaction was performed here. Source: [official MCP security testing guide](https://www.promptfoo.dev/docs/red-team/mcp-security-testing/).

These distinctions prevent a market comparison from confusing inventory, a potential dangerous capability, a policy finding, an active runtime attack success and a confirmed exploitable vulnerability. More tools or more findings alone do not establish better detection. The published review predicates and adjudication provenance are required before reporting TP percentages.
