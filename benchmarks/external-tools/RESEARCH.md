# Scanner research notes

Research date: 19 September 2026. Primary documentation was checked before choosing execution modes. Exact installed versions, distribution hashes, pack fingerprints and Python environments are stored in this directory. The following sources support capabilities; our measured outcomes come from the run receipts, not vendor claims.

## Semgrep Community Edition

Semgrep documents an open-source local engine with community-supported language coverage. Its paid Code offering adds analyses beyond CE, including cross-file and framework-specific capabilities. Consequently the current experiment identifies the engine and rule pack and does not generalize results to the paid offering. Sources: [official CE language/analysis comparison](https://docs.semgrep.dev/semgrep-ce-languages), [official CE product description](https://semgrep.dev/products/community-edition/), [CLI reference](https://docs.semgrep.dev/cli-reference), [official PyPI package](https://pypi.org/project/semgrep/1.177.0/).

The official security-audit pack resolves to 225 rules at the measured SHA-256. The current rules license limits redistribution; it is therefore a local research dependency rather than bundled product content. Published results retain identifiers and finding locations, not the pack or its full messages/metadata. Sources: [rules repository](https://github.com/semgrep/semgrep-rules), [license text](https://semgrep.dev/legal/rules-license/).

## Bandit

Bandit builds Python ASTs and applies security plugins. It is a useful Python-specific comparator with default plugin coverage and machine-readable output. Its reports include lower-severity audit observations, so counting every report item as an exploitable vulnerability would misrepresent its purpose. Sources: [official documentation](https://bandit.readthedocs.io/en/latest/), [plugin catalog](https://bandit.readthedocs.io/en/latest/plugins/index.html), [official package](https://pypi.org/project/bandit/1.9.4/).

## Gitleaks

Gitleaks specializes in detecting secret patterns and supports directory and Git-history workflows. Directory mode is the compatible choice for this fixed current-source experiment. It was installed from the official 8.30.1 release and its downloaded archive matched the release's SHA-256 list. Configuration and ignore behavior were made explicit; results were redacted before normalization. Sources: [official repository and usage](https://github.com/gitleaks/gitleaks), [8.30.1 release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1), [official checksums](https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt).

## Cisco MCP Scanner

Cisco's scanner supports several analysis modes. Its documented static mode accepts prepared MCP tool, prompt and resource JSON. YARA can analyze that data without starting an MCP server or supplying LLM/API credentials. Behavioral/API/LLM/package modes perform different work and are outside this measured configuration. A partial static description extraction is suitable for demonstrating the local metadata mode, but does not substitute for runtime discovery or analysis of server implementation. Sources: [official repository](https://github.com/cisco-ai-defense/mcp-scanner), [static/offline mode documentation](https://github.com/cisco-ai-defense/mcp-scanner/blob/main/docs/static-scanning.md), [4.8.4 release](https://github.com/cisco-ai-defense/mcp-scanner/releases/tag/4.8.4), [official package](https://pypi.org/project/cisco-ai-mcp-scanner/4.8.4/).

## Snyk Agent Scan

The current project covers installed agent components, MCP configurations and skills. Its documented setup requires a Snyk API token. Standard stdio MCP discovery executes configured server commands, while analysis sends component information to Snyk's API. That workflow is outside this source-only, no-target-execution comparison. It remains a relevant candidate for a separately consented runtime/cloud study; no result is fabricated for it here. Version 0.6.3 was researched and not installed/executed. Sources: [official README](https://github.com/snyk/agent-scan), [CLI reference](https://github.com/snyk/agent-scan/blob/main/docs/cli-reference.md), [0.6.3 release](https://github.com/snyk/agent-scan/releases/tag/v0.6.3).

## What the shortlist establishes

These tools cover different layers: source-code patterns, Python AST checks, secret patterns, and MCP metadata/agent discovery. For this selected corpus and experiment, combining complementary layers is better supported by the evidence than naming one universal winner. The experiment does not test all market offerings, paid engines, runtime red-team products, hosted analysis, container CVE databases or deployment-specific controls. Those omissions are study limits, not evidence that the tools lack useful security coverage.
