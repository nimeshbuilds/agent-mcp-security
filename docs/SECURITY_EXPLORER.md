# Offline security explorer

Invarune **0.12.0** can explain the security catalog before you scan anything. Use `invscan --ask` to find relevant controls, checks, rules and sources; then open an exact item for its rationale and evidence requirements. The answers come from bundled data and deterministic lookup. No model, API key, provider configuration, login, network connection or target directory is needed.

Install the [released 0.12.0 wheel](https://github.com/nimeshbuilds/agent-mcp-security/releases/tag/v0.12.0) or follow the [quickstart](QUICKSTART.md) to install the checkout. The `invarune` and `ai-security-scan` aliases support the same flags. [Actual installed examples](../examples/security-explorer/README.md) show the resulting text and JSON.

## Start with a security question

```sh
invscan --list-topics
invscan --ask 'What do you check for prompt injection?'
invscan --ask 'How is MCP authentication covered?'
invscan --ask 'What NSA and CISA guidance do you use?'
invscan --help-topic security
```

`--ask` matches literal query tokens and curated aliases. It does not generate new prose, follow links, inspect local code or execute text from your question. Quotes keep a multiword question together as one shell argument. Queries are limited to **1,000 characters**, and results to **eight ranked matches**. The rank describes lexical relevance to the bundled catalog; it is not a vulnerability probability or accuracy score.

The nine topics cover governance, identity and authorization, MCP protocol and tools, agent behavior and context, execution and application security, data and privacy, supply chain, operations and resilience, and security validation. `--list-topics` prints their identifiers and grouped control inventory, including partial static mapping indicators. `--help-topic security` includes example questions. Exact rule, control, check and source IDs can also be looked up; explicit explain commands are useful when you know the item you need.

This is an offline reference, not general security chat. A question outside the vocabulary can return no match, even when its subject matters to security. No match says nothing about your application's safety. Try fewer relevant terms, inspect the topic list, or select a known ID. Empty, invalid and oversized questions fail instead of being sent to a model.

## Follow a concern to its checks

For MCP authentication:

```sh
invscan --explain-control AUTH-01
invscan --explain-check AUTH-01:1
invscan --explain-rule AI041 --catalog-format text
```

`AUTH-01` is **Authenticate protected operations on every request**. Its first check, `AUTH-01:1`, asks you to trace authentication to every protected HTTP entry point, including tool calls, subscriptions and retries. Check IDs use a one-based `CONTROL:INDEX` suffix. A control explanation includes why it matters, all its acceptance checks, its validation approach, mapped rule metadata and source organizations. A check explanation retains the parent context.

For prompt injection, compare these two controls:

```sh
invscan --explain-control AGT-03
invscan --explain-control TEST-01
```

`AGT-03`, separating untrusted content from authoritative instructions, has partial static coverage through `AI032`. `TEST-01`, measuring prompt-injection security and useful task completion, requires dynamic testing and has no deterministic rule mapping. Merely recognizing an unsafe message-construction pattern cannot establish resistance to adversarial tool output, prove an authorization boundary works, or measure task success under attack.

The catalog explains **66 controls and 132 acceptance checks**. Its **42 rules provide partial static mappings to 26 controls**. Those are mapping counts, not pass rates. Even a mapped control still needs evidence for the complete acceptance check. Explorer output does not run the scanner, produce findings or mark any check as passed.

## Inspect where a control came from

```sh
invscan --list-sources
invscan --explain-source JOINT-AGENTIC
invscan --explain-source MCP-AUTH
invscan --explain-source CIS-MCP-2026
invscan --explain-source NSA-AGENTIC
```

The registry contains **75 sources** with organization, title, URL, kind, version/date, scope and limitations. Technical references attached to rules are identified separately. URLs are printed for follow-up reading; explorer commands do not open them or verify that the website has remained unchanged.

| Relationship | Meaning | Example |
| --- | --- | --- |
| Primary control source | The project's control record directly cites this source. This is still the project's mapping, not an official certification. | `AUTH-01` directly cites `MCP-AUTH`. |
| Thematic alignment | The registry suggests related controls for further review; it does not claim a directly cited requirement or complete standard coverage. | `CIS-MCP-2026` has thematic control alignments and no direct control citations. |
| Rule technical reference | The rule links a source explaining the detected API, configuration or security behavior. It does not replace a control's own citation. | `AI026` and `AI041` reference `MCP-SECURITY`, while `AUTH-01` cites `MCP-AUTH`. |

`JOINT-AGENTIC` is the substantive joint guidance. `NSA-AGENTIC` and `CISA-AGENTIC` document release provenance and participation; those announcements are not separate scored benchmarks. The source explanation preserves such scope limits. Framework references, commercial standards, research attack suites and government guidance do not share a single compliance or accuracy score. See the [research methodology](RESEARCH.md) and [complete source map](SOURCE_MAP.md).

## Select readable text or structured JSON

New explorer commands default to human-readable text. Add `--catalog-format json` for deterministic rich records:

```sh
invscan --ask 'MCP authentication' --catalog-format json
invscan --explain-control AUTH-01 --catalog-format json > ./auth-control.json
invscan --explain-check AUTH-01:1 --catalog-format json
invscan --explain-source JOINT-AGENTIC --catalog-format json
invscan --list-topics --catalog-format json
invscan --list-sources --catalog-format json
```

For compatibility, `--list-rules`, `--list-controls` and `--explain-rule` keep their existing default JSON output and shapes. Choose text explicitly for a readable view:

```sh
invscan --list-rules --catalog-format text
invscan --list-controls --catalog-format text
invscan --explain-rule AI002 --catalog-format text

# Existing automation remains valid.
invscan --list-rules > ./rules.json
invscan --list-controls > ./controls.json
invscan --explain-rule AI002 > ./AI002.json
```

Choose exactly one catalog command. `--catalog-format` only modifies that command; it is not a scan-report format selector. Explicit scan, source/image, model, login and output options are incompatible with catalog inspection. For example, do not combine `--ask` with a target, `--judge-cli`, `--output`, `--pdf` or `--summary-json`.

A completed lookup, including an honest no-match response, exits **0**. Invalid input, an unknown ID in an explain command, or incompatible options exit **2**. Neither value is a security verdict. Catalog commands write only their selected stdout result; shell redirection in the examples saves that result without creating scan artifacts.

## Run a separate assessment when ready

```sh
invscan /absolute/path/to/agent-or-mcp-repo --output ./scan-report
invscan --image-archive ./agent-image.tar --output ./image-report
```

A scan applies the supported deterministic rules to the selected source or image and writes the normal reports. Optional model review requires a separate explicit `--judge-cli` or `--judge-config` option on that scan. The explorer never enables it. Runtime and human checks remain visible in the [report workflow](REPORTS.md), and the [complete CLI reference](CLI.md) documents scope, budgets, exits and every option.
