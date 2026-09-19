# Real scans of public agent and MCP projects

Invarune by NimeshBuild was run against eight pinned upstream repositories. The [results](RESULTS.md) link every HTML, Markdown, JSON and SARIF report, including incomplete scans. The [competitor comparison](../external-tools/README.md) uses the same source exports where the tools support source scanning.

This is a development-visible ecosystem sample. It is not a random sample, an independent certification, or a benchmark with established vulnerability ground truth. Finding counts do not rank scanner accuracy. [Manual review](TRIAGE.md) identified both context-dependent capabilities and clear false positives in initial scans; these observations informed narrowly scoped detector fixes before the final rescan. Original findings, scan IDs, implementation hashes and coverage errors remain in [triage-initial.json](triage-initial.json).

## Selection and frozen scope

Projects were selected for ecosystem diversity before any scan results: MCP servers, a server/client framework, agent orchestration libraries, graph execution/checkpoint libraries, and an agent application. The exact revisions, upstream license links, implementation directories, exclusions and byte limits are in [manifest.json](manifest.json).

| Project | Role in this sample | Selected implementation scope |
|---|---|---|
| [MCP reference servers](https://github.com/modelcontextprotocol/servers) | Steering-group reference implementations | `src`, package files and root MCP config |
| [GitHub MCP Server](https://github.com/github/github-mcp-server) | Official MCP server | `cmd`, `internal`, `pkg`, `ui`, agent plugin and runtime/package config |
| [AutoGen](https://github.com/microsoft/autogen) | Agent framework and integrations | Python agent/core/extensions/studio/CLI packages, `.NET` implementations and package metadata |
| [CrewAI](https://github.com/crewAIInc/crewAI) | Agent orchestration and tools | CLI, core, files, tools and agent packages, plus package metadata |
| [LangGraph](https://github.com/langchain-ai/langgraph) | Graph runtime, checkpoints and SDK | Runtime/checkpoint/CLI/Python SDK implementation directories and package metadata |
| [OpenHands](https://github.com/OpenHands/OpenHands) | Agent development application | Current upstream `src`, Electron, launcher, Docker, configuration and Helm implementation |
| [Pydantic AI](https://github.com/pydantic/pydantic-ai) | Typed agent/graph/evaluation framework and CLI | Four implementation packages and package metadata |
| [FastMCP](https://github.com/PrefectHQ/fastmcp) | MCP server/client framework | Slim, tasks and remote packages, plus package metadata |

The MCP reference repository explicitly describes its servers as educational reference implementations rather than production-ready solutions. Its intentional testing configurations are labeled accordingly. FastMCP's former `jlowin/fastmcp` URL redirects to `PrefectHQ/fastmcp`. Project identity and licensing were verified from the official repositories; the source revision and license document for each observation are pinned in the manifest. Copied upstream license notices are under [licenses](licenses/).

Uniform exclusions remove test, example, documentation, benchmark, vendor and generated/build directories, plus conventional test filenames and non-code asset extensions. Dependency manifests and lockfiles are retained. Production prompts and code-generation templates inside the selected implementation directories remain in scope. Scope was not reduced after discovering noisy findings or parser failures. The selection is focused on first-party implementation and configuration; it is not a scan of every tracked file in every repository.

## What actually ran

The runner exports regular files directly from immutable Git blobs without checking out source, following submodules, invoking smudge filters, executing hooks, importing target code, installing target dependencies, building images, or starting MCP servers. Target instructions such as `AGENTS.md` are treated as repository data and are outside the selected source scope.

Each exported path, Git blob ID, file mode, byte size and SHA-256 is recorded in [snapshots](snapshots/). The runner verifies the full manifest digest and every source byte before and after scanning, and rejects missing, changed or extra files and symlinks. Every source scanner receives those same exported bytes. A tool's actual language coverage, skipped files, rule pack and exclusions still differ and must be considered when comparing output.

Invarune is invoked with no optional judge, no baseline and no review configuration. Its default high-severity findings gate remains enabled. An exit of 1 records a triggered findings gate; exit 2 records an operational or analysis coverage problem, even if findings are also present. Neither state is hidden. Two actual executions per project verify byte-identical output across all four report formats; receipts retain both timings and artifact hashes.

Reported wall times were measured on a shared development machine, with other work potentially running. They include scanning and report serialization and are not controlled performance measurements. All findings remain review candidates. No exploit was executed, no public service was probed, and no upstream issue or disclosure message was created.

## Reproduce the scans

Use Python 3.12 to match the published runtime and work from this repository. For a first run, explicitly permit downloading the public pinned commits:

```bash
python3 scripts/scan_public_projects.py --fetch --prepare-only
python3 scripts/scan_public_projects.py
```

The first command only prepares source exports and verifies published snapshot manifests. It does not run target code. With existing bare Git object stores, `--prepare-only` performs the same export offline without `--fetch`. Subsequent scans run fully offline against the verified exports:

```bash
python3 scripts/scan_public_projects.py --project autogen --project github-mcp
python3 scripts/scan_public_projects.py --repeats 3
python3 scripts/scan_public_projects.py --help
```

Source export defaults to `tmp/real-world-src/<project>`, reports to `examples/reports/real-world/<project>`, and receipts to this directory. `--git-root`, `--source-root`, `--output-root`, `--records-root`, `--manifest`, `--project`, `--timeout` and `--repeats` expose every runner setting. Existing exports with changed bytes are rejected rather than overwritten. The runner does not fetch the latest branch tip: only the full commit IDs in the manifest are used.

Exact report hashes require the same scanner implementation, Python parser/runtime, catalog and configuration. Pinned source bytes alone are not sufficient for identical output across scanner releases. [Receipts](receipts/) record implementation hashes, versions, flags, timestamps, source digests, per-rule counts, exit reasons and artifact hashes.

## Known limits revealed by this corpus

Initial scans reached the bounded Python analysis work limit in four large source files: CrewAI's flow runtime, LangGraph's pregel runtime, and Pydantic AI's Anthropic and OpenAI model modules. These are explicit incomplete-analysis states, not findings-free passes. CrewAI's unrendered Python/JSON templates, OpenHands' JSON syntax and one source file containing a NUL byte exposed additional parser/input limitations. Final reports show the observed gaps for their exact implementation.

Go and C# files receive Invarune's generic text checks, not language-specific execution/dataflow analysis. No source-only result proves deployed authentication, OAuth audience validation, tool authorization, sandbox isolation, prompt-injection resilience or dependency safety. The optional analyst can provide bounded advisory review, but was deliberately disabled in this reproducible deterministic comparison.

The synthetic rule corpus remains a separate track. Version 1.1.0 updates the AI011 positive fixture from a marker-only string to nonfunctional synthetic encoded material after the rule was refined to require a plausible private-key body. Assertion labels are unchanged; the previous corpus remains at [static_accuracy-v100.json](../static_accuracy-v100.json). Metrics from different corpus versions must not be represented as results from identical bytes.
