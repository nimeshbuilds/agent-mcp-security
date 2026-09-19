# Invarune public-project scan results

Actual offline scans of **8 pinned projects**, offering **4,120 identical exported files** to each source scanner. Invarune examined **4,081 files**, emitted **149 static review candidates**, and reported **15 coverage gaps** in this run set.

These are unverified patterns, not confirmed vulnerabilities or a precision/recall benchmark. A zero-finding result does not prove security. Exit 0 means the configured high-severity gate was not triggered; exit 2 marks incomplete analysis. See [methodology](README.md), [initial manual triage](TRIAGE.md), and the [competitor comparison](../external-tools/README.md).

| Project / pinned revision | Exported / examined files | Critical / high / medium / low | Gaps | Exit | Runs / byte identical | Reports |
|---|---:|---:|---:|---:|---|---|
| [MCP reference servers](https://github.com/modelcontextprotocol/servers/tree/d73f99efbfd40c3aa1b61e88728b3d49fb52608f) / `d73f99efbfd4` | 86 / 86 | 0 / 0 / 2 / 59 | 0 | 0 | 2 / yes | [HTML](../../examples/reports/real-world/mcp-reference/report.html) · [Markdown](../../examples/reports/real-world/mcp-reference/report.md) · [JSON](../../examples/reports/real-world/mcp-reference/report.json) · [SARIF](../../examples/reports/real-world/mcp-reference/report.sarif) |
| [GitHub MCP Server](https://github.com/github/github-mcp-server/tree/85598ba6e1256f7ebf4867b95d63b833c4549264) / `85598ba6e125` | 163 / 156 | 0 / 0 / 0 / 15 | 0 | 0 | 2 / yes | [HTML](../../examples/reports/real-world/github-mcp/report.html) · [Markdown](../../examples/reports/real-world/github-mcp/report.md) · [JSON](../../examples/reports/real-world/github-mcp/report.json) · [SARIF](../../examples/reports/real-world/github-mcp/report.sarif) |
| [AutoGen](https://github.com/microsoft/autogen/tree/027ecf0a379bcc1d09956d46d12d44a3ad9cee14) / `027ecf0a379b` | 786 / 759 | 0 / 5 / 3 / 5 | 0 | 1 | 2 / yes | [HTML](../../examples/reports/real-world/autogen/report.html) · [Markdown](../../examples/reports/real-world/autogen/report.md) · [JSON](../../examples/reports/real-world/autogen/report.json) · [SARIF](../../examples/reports/real-world/autogen/report.sarif) |
| [CrewAI](https://github.com/crewAIInc/crewAI/tree/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e) / `3831e8b6c86f` | 968 / 967 | 0 / 26 / 2 / 0 | 10 | 2 | 2 / yes | [HTML](../../examples/reports/real-world/crewai/report.html) · [Markdown](../../examples/reports/real-world/crewai/report.md) · [JSON](../../examples/reports/real-world/crewai/report.json) · [SARIF](../../examples/reports/real-world/crewai/report.sarif) |
| [LangGraph](https://github.com/langchain-ai/langgraph/tree/aa742fb31e2827d569b843e3600aeda2e0528e4b) / `aa742fb31e28` | 211 / 211 | 0 / 23 / 0 / 0 | 1 | 2 | 2 / yes | [HTML](../../examples/reports/real-world/langgraph/report.html) · [Markdown](../../examples/reports/real-world/langgraph/report.md) · [JSON](../../examples/reports/real-world/langgraph/report.json) · [SARIF](../../examples/reports/real-world/langgraph/report.sarif) |
| [OpenHands](https://github.com/OpenHands/OpenHands/tree/a07364828c8f202e7745c6bce3dcef3915ae7ac1) / `a07364828c8f` | 1237 / 1233 | 0 / 2 / 3 / 4 | 2 | 2 | 2 / yes | [HTML](../../examples/reports/real-world/openhands/report.html) · [Markdown](../../examples/reports/real-world/openhands/report.md) · [JSON](../../examples/reports/real-world/openhands/report.json) · [SARIF](../../examples/reports/real-world/openhands/report.sarif) |
| [Pydantic AI](https://github.com/pydantic/pydantic-ai/tree/c4898abb54dc25ae6f6aef208a4c0661b30a455e) / `c4898abb54dc` | 386 / 386 | 0 / 0 / 0 / 0 | 2 | 2 | 2 / yes | [HTML](../../examples/reports/real-world/pydantic-ai/report.html) · [Markdown](../../examples/reports/real-world/pydantic-ai/report.md) · [JSON](../../examples/reports/real-world/pydantic-ai/report.json) · [SARIF](../../examples/reports/real-world/pydantic-ai/report.sarif) |
| [FastMCP](https://github.com/PrefectHQ/fastmcp/tree/9c35c017cd89e4d50a9f512c8eafde68c301ec70) / `9c35c017cd89` | 283 / 283 | 0 / 0 / 0 / 0 | 0 | 0 | 2 / yes | [HTML](../../examples/reports/real-world/fastmcp/report.html) · [Markdown](../../examples/reports/real-world/fastmcp/report.md) · [JSON](../../examples/reports/real-world/fastmcp/report.json) · [SARIF](../../examples/reports/real-world/fastmcp/report.sarif) |

Scanner version(s): **0.8.0**. Python version(s): **3.12.14**. No optional LLM judge, review exceptions, baselines, target builds, target tests, live MCP calls or target dependency installation were used.

## Run receipts

Each receipt contains actual run timestamps, elapsed time, exit reason, tool implementation hash, selected-source manifest digest, all four artifact hashes and the normalized command. Wall times include report generation and were collected on a shared development machine; they are reproducibility metadata, not a controlled speed ranking.

- **MCP reference servers:** [receipt](receipts/mcp-reference.json), [source manifest](snapshots/mcp-reference.json), elapsed 0.257s, 0.212s.
- **GitHub MCP Server:** [receipt](receipts/github-mcp.json), [source manifest](snapshots/github-mcp.json), elapsed 0.272s, 0.256s.
- **AutoGen:** [receipt](receipts/autogen.json), [source manifest](snapshots/autogen.json), elapsed 1.557s, 1.655s.
- **CrewAI:** [receipt](receipts/crewai.json), [source manifest](snapshots/crewai.json), elapsed 3.667s, 3.570s.
- **LangGraph:** [receipt](receipts/langgraph.json), [source manifest](snapshots/langgraph.json), elapsed 1.435s, 1.398s.
- **OpenHands:** [receipt](receipts/openhands.json), [source manifest](snapshots/openhands.json), elapsed 2.188s, 2.181s.
- **Pydantic AI:** [receipt](receipts/pydantic-ai.json), [source manifest](snapshots/pydantic-ai.json), elapsed 2.481s, 2.488s.
- **FastMCP:** [receipt](receipts/fastmcp.json), [source manifest](snapshots/fastmcp.json), elapsed 1.282s, 1.287s.

## Coverage interpretation

The exported corpus includes languages and file types that individual tools do not analyze. Invarune's Go/C#/other generic-text profile checks selected secrets and text patterns; it does not provide language-specific dataflow for those languages. Python uses bounded local AST analysis; JavaScript/TypeScript uses bounded lexical analysis. Per-project profile counts and skipped-file reasons are in the reports.

Production template files remain in scope. They can legitimately fail Python/JSON parsing before template rendering. Large Python modules may exceed deterministic work budgets, and binary/non-UTF-8 or unsupported inputs need another analyzer. The results retain these gaps rather than narrowing the corpus after viewing findings.
