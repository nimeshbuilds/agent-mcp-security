# External scanner comparison

Invarune by NimeshBuild • research executed 19 September 2026

This is a reproducible comparison of **actual local scans**, with separate tracks for public project observations and a small shared API-pattern fixture set. It does not establish an overall best scanner. Finding counts, severity vocabularies and coverage differ substantially; more findings do not establish better detection, and zero findings do not establish security.

The [public corpus manifest](../real-world/manifest.json) was selected before scanning. It contains eight pinned agent/MCP projects and 4,120 exported files. Every source scanner receives the same exported bytes, verified against per-file SHA-256 manifests before and after execution. The upstream programs, package installation scripts, MCP commands and containers are never executed.

## Results and receipts

The current machine-readable results are in [results/summary.json](results/summary.json). Each project directory contains normalized findings with rule, file, line, severity, process status, wall time and raw-output SHA-256. [Shared fixture results](results/shared-pattern-fixtures.json) include every scored assertion and rule mapping. [Cisco metadata results](results/cisco-metadata.json) contain the separate partial-metadata scan receipt.

| Project | Semgrep CE findings | Bandit findings | Gitleaks findings |
|---|---:|---:|---:|
| MCP reference servers | 0 | 0 | 0 |
| GitHub MCP Server | 1† | Unsupported: no Python | 0 |
| AutoGen | 6 | 183 | 0 |
| CrewAI | 8† | 232† | 0 |
| LangGraph | 8 | 84 | 1 |
| OpenHands | 0† | Unsupported: no Python | 1 |
| Pydantic AI | 2 | 344 | 0 |
| FastMCP | 2 | 95 | 1 |

† Partial analysis: Semgrep reports seven parsing warnings across GitHub MCP, CrewAI and OpenHands; Bandit reports five CrewAI template files that cannot be parsed as ordinary Python. These are coverage gaps, not clean results. The exported CrewAI templates intentionally contain placeholders. Gitleaks does not provide a per-file scanned inventory in this JSON format; the harness does not invent one.

The three Gitleaks observations are JWT or generic-key pattern matches in LangGraph's CLI constants, OpenHands' default configuration and FastMCP's Google auth provider. Their locations are published with the secret/matched text omitted. These require context review; a pattern match alone does not establish an active credential or exposure.

Bandit reports all default plugins, including assertion, import and other audit observations. Its 938 observations should not be equated to 938 exploitable vulnerabilities or directly compared to Semgrep's 27 observations. The tools also apply different language and file filters. See each receipt's `files_reported_scanned`, errors and rule counts.

On the **ten shared development fixtures**, Invarune, Semgrep CE and Bandit each matched five positive and five negative labels, with zero mismatches. The five subjects are dynamic `eval`, `subprocess` with `shell=True`, unsafe PyYAML loading, pickle deserialization and explicit Requests TLS verification bypass. This is a basic interoperability/coverage check, not evidence of production precision, recall or superiority. The fixtures were authored for this project, are development-visible, are not held out, and deliberately cover matching API semantics. Other findings in those files are recorded but unscored. Gitleaks and MCP metadata tools are outside this fixture scope; they receive no artificial true negatives.

Cisco MCP Scanner's packaged YARA analyzer completed an additional real scan of **14 literal tool descriptions** extracted from the pinned reference filesystem server, with zero findings. This is a partial metadata track: the input is not a live `tools/list` capture; schemas, computed metadata, runtime behavior and other servers are unassessed. No server was started. It is not ranked against source SAST.

## Why these tools

The selection favors established maintainers, relevant security surfaces, an available CLI, auditable versions, structured output and a reproducible local mode. It is a purposive shortlist, not an exhaustive market ranking. Research links and exact distinctions are in [RESEARCH.md](RESEARCH.md).

| Tool | Version assessed | Useful complementary layer | Executed here |
|---|---|---|---|
| Semgrep Community Edition | 1.177.0 | Cross-language source patterns and local analysis | Eight source exports; official 225-rule `p/security-audit` pack; ten fixtures |
| Bandit | 1.9.4 | Python AST security checks and audit signals | Eight exports offered; six contain Python; ten fixtures |
| Gitleaks | 8.30.1 | Credential-pattern detection | Eight directory scans; packaged defaults; output redacted |
| Cisco MCP Scanner | 4.8.4 | MCP metadata poisoning/injection patterns; optional additional analyzers | YARA-only partial metadata scan, 14 descriptions |
| Snyk Agent Scan | 0.6.3 researched | Discovery and analysis of installed MCP/agent/skill components | Not executed: runtime/cloud workflow and API token prerequisite |

Snyk's normal MCP configuration scan starts configured stdio servers and sends component metadata to its analysis API. The source-only experiment does not provide that runtime or credential. This is an explicit scope exclusion, not a failed security check or zero findings. Cisco's API, LLM, behavioral, package-vulnerability and malware modes also were not measured.

## Method and limits

- Source selection: first-party implementation and package/runtime configuration; uniform exclusions for tests, docs, examples, vendor/generated trees and non-code assets. Embedded production prompts and dependency locks remain. Exact inclusion policies and every exported file are recorded upstream in the corpus manifests.
- Invarune is a separate scanner, not a wrapper around these tools. These external CLIs are installed only in ignored research environments. Their rules and binaries are not shipped with Invarune.
- Semgrep: frozen local `p/security-audit` pack; 225 rules; metrics and version checks disabled; no registry lookup during a scan; two jobs; ten-second per-rule/file timeout; 20 MB file limit. `--no-rewrite-rule-ids` retains canonical rule IDs. This measures CE and this pack, not paid/proprietary Semgrep analyses or all available community rules.
- Bandit: all packaged defaults and all severities/confidences. The comparison uses explicit empty exclusions and ignores inline `nosec`, allowing the common exported corpus to determine scope.
- Gitleaks: directory mode, not Git history; explicit `useDefault=true`; no external baseline/ignore file; inline allow comments ignored; 100% secret redaction; default recursive decoding; no archive traversal; 20 MB target limit.
- Tool-specific inline suppressions are disabled consistently. No scanner output is manually deleted to improve results. Tool configuration inherited from target repositories is excluded or overridden. API credentials are not inherited by child processes. The real user home value is preserved; explicit Semgrep settings are isolated in the research output directory.
- Host: Apple Silicon macOS. External Python CLIs use Python 3.12.13. Each receipt records the observed wall time of that invocation. These are serial local run observations with cache effects and different work performed, not a controlled throughput or resource-usage ranking. No cost or latency of optional LLM/API analysis is included.
- Partial parsing, unsupported input, timeouts, execution failure and invalid output are separate statuses. A tool that cannot scan an input is not credited with a clean result. Findings can coexist with analysis errors.
- Real-project findings lack exhaustive independent ground truth. No production precision/recall, vulnerability count, CVE claim, certification, vendor endorsement or universal winner is inferred. The corpus has become development-visible and is unsuitable for future claims of held-out performance.
- Source scans do not validate deployed auth policy, permission boundaries, network egress, runtime prompt injection behavior, dependency CVEs or container execution. Those need additional layers and separate experiments. The metadata track does not fill those gaps.

## Reproduce

1. Prepare exactly the pinned public source exports from the repository root:

   ```bash
   python3 scripts/scan_public_projects.py --fetch --prepare-only
   ```

2. Install the pinned versions from [tool-lock.json](tool-lock.json) into an isolated research environment. The exact Python package environments and PyPI distribution SHA-256 provenance are published beside this document. For example:

   ```bash
   uv venv --python 3.12 tmp/benchmark-tools/python
   uv pip install --python tmp/benchmark-tools/python/bin/python semgrep==1.177.0 bandit==1.9.4
   uv venv --python 3.12 tmp/benchmark-tools/cisco
   uv pip install --python tmp/benchmark-tools/cisco/bin/python cisco-ai-mcp-scanner==4.8.4
   ```

   Download Gitleaks 8.30.1 for your platform from its [official release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1) and verify its SHA-256 against that release's checksums. The recorded archive/binary checksums describe the actual Darwin arm64 binary used here; another platform's binary will differ.

3. Retrieve `https://semgrep.dev/c/p/security-audit` into `tmp/benchmark-tools/semgrep-security-audit.yaml` and verify SHA-256 `b109a039df712f30c6d3e25e1e8358053fd0f1c91b92d0e8d2871cd141fe602f`. The pack is retained locally and is not redistributed under the [Semgrep Rules License](https://semgrep.dev/legal/rules-license/). The registry URL can change; the harness rejects changed content. If the registry no longer provides those exact bytes, reproduce with an already retained matching copy or record a new experiment and lock. Do not silently call it the same ruleset.

4. Execute the research harness:

   ```bash
   python3 scripts/benchmark_competitors.py \
     --source-root tmp/real-world-src \
     --semgrep tmp/benchmark-tools/python/bin/semgrep \
     --semgrep-config tmp/benchmark-tools/semgrep-security-audit.yaml \
     --bandit tmp/benchmark-tools/python/bin/bandit \
     --gitleaks tmp/benchmark-tools/gitleaks \
     --cisco tmp/benchmark-tools/cisco/bin/mcp-scanner
   ```

The default results directory contains sanitized normalized JSON suitable for review. Raw outputs, exact local commands and unmodified rule packs remain under ignored `tmp/benchmark-tools/`; they can include licensed rule text and source excerpts. Keep those raw files out of publication. SHA-256 receipts bind the normalized report to the local raw execution evidence. The optional `--cisco` track needs only its separately installed CLI; omitting it still runs every source comparison and shared fixture. `--help` documents all harness flags.

Thirteen offline contract tests cover failure classification, unsupported denominators, rule mapping, source drift, symlinks, metadata extraction, secret/source omission, canonical rule identifiers and exact lock metadata. Actual third-party executions are recorded separately from those harness tests.
