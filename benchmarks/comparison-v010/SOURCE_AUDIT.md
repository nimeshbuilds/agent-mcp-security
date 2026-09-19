# Selected source audit: pattern evidence and applicability

**Codex agent-assisted review. No Claude adjudication, independent human ground truth, target execution or confirmed vulnerabilities.**

The audit reviewed **50 observations at 33 locations across seven projects** from the frozen 1,117-observation ledger. **42 source predicates are supported and eight are conditional mismatches**. All 50 remain unconfirmed as deployed vulnerabilities; 33 retain an explicit runtime-validation question and 17 are marked not established. Source evidence was available for every selected predicate, with zero evidence-read errors.

[Machine-readable audit](source-audit.json) preserves all selected IDs, judgments, source hashes, pinned links and uncertainty. The 1,067 other ledger observations remain unaudited. These counts are **not production precision**, recall, vulnerability counts, or a ranking of scanners.

## Counts and denominators

| Tool | Selected / ledger observations | Source predicate supported | Conditional mismatch | Insufficient source evidence | Confirmed vulnerabilities |
|---|---:|---:|---:|---:|---:|
| bandit | 10 / 938 | 10 | 0 | 0 | 0 |
| gitleaks | 3 / 3 | 0 | 3 | 0 | 0 |
| invarune | 28 / 149 | 23 | 5 | 0 | 0 |
| semgrep | 9 / 27 | 9 | 0 | 0 | 0 |

A supported pattern means the API or configuration exists. Fixed SQL identifiers, a deliberately enabled code loader, an internal assertion, or an HTML entity decoder can satisfy that predicate without demonstrating a vulnerability. A conditional mismatch addresses the benchmark security interpretation, not necessarily a scanner’s native matching rule. **All three Gitleaks lexical observations remain valid literal matches**; the reviewed literals are public analytics keys or a documentation placeholder, so private-credential exposure was not established.

## Selection, provenance and limits

Before reading source: include every location in frozen adjudication-selection.json containing Invarune (28 observations plus all 16 co-located observations); then round-robin gitleaks, semgrep, bandit, taking remaining non-Invarune locations ranked by SHA-256 of invarune-source-audit-v1: plus location_id, retaining every observation at each chosen span, until 50 total observations. Selection uses metadata only and is purposive, not random or representative.

The parent frozen selection has 153 observations at 120 locations. This audit retains all 28 selected Invarune observations and every co-located competitor observation. Historical `observations-v090.json` raw-file SHA-256: `b663ffcb2859f86c50eb0b29594b36f4765cc9cbb199868309e922d95cae3164`. Selection-file SHA-256: `19c3dc57b1f582e0c0f239c0f6448b8717bede5775e09f59d8f8a05b3e06f8c3`. Exact chosen IDs are stored under `selection.selected_observation_ids`. The parent selection binds canonical JSON from `observations-selection-v1.json`; both that digest and its raw-file digest are recorded separately.

Every cited source file (44 distinct files) matched the SHA-256 and Git blob identifiers in the pinned [source snapshots](../real-world/snapshots/). Target revisions come from those manifests and the frozen ledger; exported directories are not independent Git checkouts. No source package was imported or executed.

The lead reviewer saw tool metadata and contributed scanner implementation. A delegated reviewer received family predicates and source references without tool names or severities for 24 observations, but the overall review is **not blind or independent**. The frozen ledger records Invarune 0.9.0 observations; this evidence review does not replace that provenance with a later release number. The current 0.10.0 ledger was separately compared: all 50 selected IDs, rules, paths/spans, source revisions/manifests, families and conditional predicates match. Original version metadata remains unchanged in audit rows, and the current raw-file digest is recorded under `current_ledger_correspondence`.

Runtime access, effective permissions, CI behavior and deployment protections remain unverified. CI workflows and some repository content were excluded from the original source export. No unflagged-code search for vulnerabilities was performed, so false negatives and recall cannot be measured.

## What the source changes about the interpretation

- **Shared code-execution and persistence patterns:** AutoGen tool configuration executes supplied source/import strings, while several agent-memory components deserialize local pickle files. These are real APIs; unauthorized control over configuration or persisted bytes must still be established. Review their actual import, storage and approval boundaries.
- **Intentional or constrained APIs:** CrewAI validates JWTs after a diagnostic unverified decode; flow scripts require an explicit default-disabled opt-in; a visualizer chooses HTML icons from a fixed set. LangGraph’s selected SQL helper only receives fixed migration-table names, and its pickle fallback defaults off. These facts should accompany the finding rather than being reduced to a vulnerability label.
- **Invarune-only mismatches in this selection:** an MCP documentation placeholder, a local `.` installation reference, an environment-variable lookup name, and a UI error message were mistaken for the conditional security meaning. A shared public analytics key adds the fifth Invarune mismatch. These are concrete triage/detector improvement candidates, with original observations preserved.
- **Competitor-only context:** a Bandit assertion is an internal kernel-start postcondition; a Semgrep pickle operation serializes rather than deserializes; XML import/API observations identify a real external-response parsing boundary but do not prove XXE. The Gitleaks-only analytics key and documentation example do not establish private-secret exposure.
- **Location quality:** three MCP Dockerfile findings point to the blank line before the actual `FROM` instruction. The unpinned-tag pattern is still present. Correct the location separately; do not count it as a missing detection.

For public-key distinctions, the pinned callers establish how the values are used. [Supabase’s key-type documentation](https://supabase.com/docs/guides/getting-started/api-keys) distinguishes legacy public `anon` keys from privileged secrets, and [PostHog’s API documentation](https://posthog.com/docs/api) distinguishes public ingestion tokens from authenticated private endpoints. Neither source verifies the reviewed deployments’ access policies.

## Every reviewed location

Each entry links to the pinned source. Co-located observations are grouped for readability; all 50 separate IDs and judgments remain in JSON. “Only” below means only among observations at that selected span, not absence of findings elsewhere in the repository.

### 1. autogen — python/packages/agbench/src/agbench/res/Dockerfile:1

**Source pattern supported · Invarune-only location · vulnerability not established.**

Observations: `obs-54e2f679ee42810f13da6c1a` (invarune `AI024`).

The Dockerfile selects a Python base image by tag and contains no content digest in the FROM reference. This supports the reproducibility policy signal, but does not establish an unsafe image or compromised build; the exported agbench scope does not include its build caller or release-resolution pipeline.

**AI/MCP relevance:** Indirect AI relevance if this benchmark container is built or reused to run agents; no MCP trust-boundary crossing is shown.

**Proposed action:** Pin the base image digest and record its provenance for reproducible benchmark builds; inspect the actual build/release resolution before assessing impact.

Evidence: [python/packages/agbench/src/agbench/res/Dockerfile:1–6](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/agbench/src/agbench/res/Dockerfile#L1-L6).

### 2. autogen — python/packages/autogen-core/src/autogen_core/tools/_function_tool.py:159

**Source pattern supported · shared location · vulnerability requires runtime validation.**

Observations: `obs-6fd61774b95443d31a0c52bf` (semgrep `python.lang.security.audit.exec-detected.exec-detected`); `obs-a0eea4251d112d520ab05559` (invarune `AI001`); `obs-bedd4960c3d1a36946ec2bb3` (bandit `B102`).

FunctionTool._from_config executes import text derived from config.global_imports; import_to_str formats caller-provided import names without a restricted execution environment. The loader warns that configuration must be trusted and performs provider/schema checks, but those checks do not establish the provenance or authorization of these import strings. Attacker control over an accepted configuration and its deployment entry point still require validation.

**AI/MCP relevance:** Relevant when an agent platform imports FunctionTool configurations from users, model output, shared galleries, or MCP-mediated storage; model tool-call arguments alone are not this configuration path.

**Proposed action:** Trace who can submit accepted FunctionTool configurations and preserve trusted-code-only loading; if untrusted configuration is supported, use an isolation or explicit approval boundary before executing its imports.

Evidence: [python/packages/autogen-core/src/autogen_core/tools/_function_tool.py:143–167](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-core/src/autogen_core/tools/_function_tool.py#L143-L167); [python/packages/autogen-core/src/autogen_core/code_executor/_func_with_reqs.py:58–75](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-core/src/autogen_core/code_executor/_func_with_reqs.py#L58-L75); [python/packages/autogen-core/src/autogen_core/code_executor/_func_with_reqs.py:272–277](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-core/src/autogen_core/code_executor/_func_with_reqs.py#L272-L277); [python/packages/autogen-core/src/autogen_core/_component_config.py:241–298](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-core/src/autogen_core/_component_config.py#L241-L298).

### 3. autogen — python/packages/autogen-core/src/autogen_core/tools/_function_tool.py:171

**Source pattern supported · shared location · vulnerability requires runtime validation.**

Observations: `obs-a141934ee7626eca5bc2baf3` (bandit `B102`); `obs-b2796b42eeb8fc0d2aee0b71` (semgrep `python.lang.security.audit.exec-detected.exec-detected`); `obs-fe547577ed886a91cd33da3f` (invarune `AI001`).

FunctionTool._from_config executes config.source_code as Python and then retrieves the defined callable. The configuration schema accepts a source string, and the same class can serialize an existing trusted function into that field; loading explicitly warns callers to trust the source. This is a real code-execution interface, while malicious configuration reachability and authorization are not established by the cited code.

**AI/MCP relevance:** Relevant if an AI or MCP workflow can supply tool definitions across a trust boundary; normal invocation of an already-created tool passes arguments to its callable and does not use this exec site.

**Proposed action:** Validate configuration provenance and caller authorization for every loading entry point; keep untrusted generated or imported tool source behind an appropriate execution boundary.

Evidence: [python/packages/autogen-core/src/autogen_core/tools/_function_tool.py:20–27](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-core/src/autogen_core/tools/_function_tool.py#L20-L27); [python/packages/autogen-core/src/autogen_core/tools/_function_tool.py:105–141](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-core/src/autogen_core/tools/_function_tool.py#L105-L141); [python/packages/autogen-core/src/autogen_core/tools/_function_tool.py:143–181](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-core/src/autogen_core/tools/_function_tool.py#L143-L181); [python/packages/autogen-core/src/autogen_core/_component_config.py:241–298](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-core/src/autogen_core/_component_config.py#L241-L298).

### 4. autogen — python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/_memory_bank.py:82

**Source pattern supported · shared location · vulnerability requires runtime validation.**

Observations: `obs-2f81af7022a056475a108a00` (invarune `AI005`); `obs-8df234b76575f0ce3cd9e6b9` (semgrep `python.lang.security.deserialization.pickle.avoid-pickle`); `obs-af037693ccbb476066a1e50a` (bandit `B301`).

The flagged call deserializes the memo dictionary from a local pickle file when reset is false and the file exists. The directory may come from application configuration, and the same class writes the file with pickle.dump; the load site does not authenticate its bytes. An attacker must be able to replace that file or influence the configured storage location before loading, which this source review does not establish.

**AI/MCP relevance:** Relevant to agent-memory persistence if a model tool, shared volume, downloaded memory bundle, or another principal can write the memory store; ordinary memo text is not itself deserialized as pickle bytes.

**Proposed action:** Check directory ownership, write permissions, and any memory-import paths; prefer a data-only serialization format or enforce trusted storage before loading existing memory files.

Evidence: [python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/_memory_bank.py:45–90](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/_memory_bank.py#L45-L90); [python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/_memory_bank.py:107–114](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/_memory_bank.py#L107-L114); [python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/memory_controller.py:90–125](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/memory_controller.py#L90-L125).

### 5. autogen — python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/_string_similarity_map.py:48

**Source pattern supported · shared location · vulnerability requires runtime validation.**

Observations: `obs-27a67e6c7586a2ae5ea86028` (semgrep `python.lang.security.deserialization.pickle.avoid-pickle`); `obs-63f6a75df32c615b424f7c00` (bandit `B301`); `obs-8c87028c58b5dd4fc68cca07` (invarune `AI005`).

The flagged call deserializes a string-pair dictionary from a local pickle file when reset is false. MemoryBank supplies the storage directory, and StringSimilarityMap also persists its own dictionary to that file; there is no integrity check at the load site. Exploitability depends on an untrusted party being able to supply or modify those stored bytes before initialization, not merely on controlling a stored string value.

**AI/MCP relevance:** Relevant if the agent memory directory is writable through tools, shared across trust levels, or populated by untrusted imports; no direct MCP input-to-pickle path was established.

**Proposed action:** Validate storage ownership and import provenance, and consider a data-only dictionary format; assess actual cross-principal write access before assigning security impact.

Evidence: [python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/_string_similarity_map.py:28–56](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/_string_similarity_map.py#L28-L56); [python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/_string_similarity_map.py:67–73](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/_string_similarity_map.py#L67-L73); [python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/_memory_bank.py:56–74](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/_memory_bank.py#L56-L74).

### 6. autogen — python/packages/autogen-ext/src/autogen_ext/tools/mcp/_workbench.py:179

**Conditional predicate mismatch · Invarune-only location · vulnerability not established.**

Observations: `obs-e50b009ca6ade97896a4f355` (invarune `AI010`).

The credential-shaped literal is inside the McpWorkbench documentation example, not executed module configuration. Its token-shaped suffix is a single repeated placeholder character, verified without reproducing the value. It therefore falls within the predicate exclusion for examples/placeholders; no real embedded credential is established.

**AI/MCP relevance:** The example demonstrates passing credentials to an MCP server, but the flagged value itself provides no evidence of a live credential or exposure.

**Proposed action:** Exclude this documentation placeholder from credential findings while retaining the source/hash evidence; do not initiate credential rotation based on this observation.

Evidence: [python/packages/autogen-ext/src/autogen_ext/tools/mcp/_workbench.py:155–193](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-ext/src/autogen_ext/tools/mcp/_workbench.py#L155-L193).

### 7. autogen — python/packages/autogen-studio/autogenstudio/web/app.py:60

**Source pattern supported · Invarune-only location · vulnerability requires runtime validation.**

Observations: `obs-e70f4a637f40ea622fd74ead` (invarune `AI009`).

The outer FastAPI application is constructed with debug=True, and the UI CLI runs that application with a configurable host that defaults to loopback. The mounted API is a separate FastAPI instance without the explicit debug flag, so the finding does not prove that every API error exposes debugging details. Reachable error paths, middleware behavior, and deployed network exposure require validation.

**AI/MCP relevance:** Relevant to deployments of the agent-workflow UI and its MCP routes if debugging responses become available to another trust domain; the source alone does not establish exposed secrets or a debugger console.

**Proposed action:** Use an explicit production debug setting and inspect the deployed outer-app error responses and access controls before assessing disclosure impact.

Evidence: [python/packages/autogen-studio/autogenstudio/web/app.py:58–84](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-studio/autogenstudio/web/app.py#L58-L84); [python/packages/autogen-studio/autogenstudio/web/app.py:183–210](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-studio/autogenstudio/web/app.py#L183-L210); [python/packages/autogen-studio/autogenstudio/cli.py:25–84](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-studio/autogenstudio/cli.py#L25-L84).

### 8. autogen — python/packages/autogen-studio/autogenstudio/web/auth/manager.py:101

**Source pattern supported · Invarune-only location · vulnerability requires runtime validation.**

Observations: `obs-07bbba345e8ffc4bd889cc64` (invarune `AI033`).

When JWT decoding raises InvalidTokenError, the warning emits the first ten characters of the supplied Authorization token. The value has an actual credential-input role, but the substring and suffix truncate it; this is not evidence that a complete reusable JWT is logged. Entry to this branch depends on enabled authentication and a configured signing secret, and the sensitivity of the emitted prefix and any downstream log filtering require deployment validation.

**AI/MCP relevance:** Relevant to the agent UI authentication boundary if credential fragments reach logs accessible to other principals; no MCP-specific path or complete-token disclosure is established.

**Proposed action:** Prefer a non-secret request correlation identifier over a token prefix, and verify actual authentication configuration, log filters, retention, and access before assessing impact.

Evidence: [python/packages/autogen-studio/autogenstudio/web/auth/manager.py:61–102](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-studio/autogenstudio/web/auth/manager.py#L61-L102); [python/packages/autogen-studio/autogenstudio/web/auth/middleware.py:43–76](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-studio/autogenstudio/web/auth/middleware.py#L43-L76).

### 9. autogen — python/packages/autogen-studio/requirements.txt:1

**Conditional predicate mismatch · Invarune-only location · vulnerability not established.**

Observations: `obs-c86c09e8c3c9e66ab1c4e378` (invarune `AI025`).

The entire flagged requirements file is a local-directory self-install reference, with no named direct dependency or version range on line 1. Dependencies are declared separately in pyproject.toml, including some ranges, but that does not make the reported line a version-range declaration. The conditional predicate therefore mismatches this location, and no dependency vulnerability is established.

**AI/MCP relevance:** Only indirect dependency-management relevance for installing the AI UI; this line does not demonstrate an AI/MCP trust-boundary failure.

**Proposed action:** Exclude local path/self-install requirement syntax from this conditional rule and assess named dependency constraints at their actual declarations and install workflow.

Evidence: [python/packages/autogen-studio/requirements.txt:1–1](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-studio/requirements.txt#L1-L1); [python/packages/autogen-studio/pyproject.toml:20–39](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-studio/pyproject.toml#L20-L39).

### 10. crewai — lib/crewai-core/src/crewai_core/auth/utils.py:34

**Source pattern supported · Invarune-only location · vulnerability not established.**

Observations: `obs-1c7676d54fc01693af03d92e` (invarune `AI017`).

The function does decode once with signature verification disabled, so the API-level pattern is present. It then returns a separate decode that verifies signature, issuer, audience, time claims, and required claims; the unverified result is used only to explain issuer/audience validation errors. The caller persists the token only after validation returns, so this source does not establish an authentication bypass.

**AI/MCP relevance:** Relevant to authentication supporting CrewAI services, but the reviewed unverified decode is diagnostic and is not the identity data returned to the caller.

**Proposed action:** Retain the independent verification and distinguish diagnostic unverified decoding from accepted claims; a cleanup could remove or constrain the diagnostic decode without classifying this as a proven bypass.

Evidence: [lib/crewai-core/src/crewai_core/auth/utils.py:13–71](https://github.com/crewAIInc/crewAI/blob/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e/lib/crewai-core/src/crewai_core/auth/utils.py#L13-L71); [lib/crewai-core/src/crewai_core/auth/oauth2.py:169–183](https://github.com/crewAIInc/crewAI/blob/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e/lib/crewai-core/src/crewai_core/auth/oauth2.py#L169-L183).

### 11. crewai — lib/crewai-tools/src/crewai_tools/tools/singlestore_search_tool/singlestore_search_tool.py:309

**Source pattern supported · Invarune-only location · vulnerability not established.**

Observations: `obs-8f3c6bd37e6b8472f1464f38` (invarune `AI036`).

The query interpolates a table identifier into SHOW COLUMNS, so SQL string construction is present. Before interpolation, the function retrieves existing table names from the database and rejects configured names outside that set; this is not an interpolated search-value parameter. No attacker-controlled schema or demonstrated injection is established, though identifier quoting and unusual database names remain relevant to correctness and a separate trust-boundary review.

**AI/MCP relevance:** Relevant to initialization of an AI database-search tool if an untrusted principal can control the schema or table configuration; model search input does not reach this flagged interpolation site.

**Proposed action:** Use driver-supported identifier quoting or a strict identifier policy and review schema ownership; keep any review of the separate free-form search-query interface distinct from this observation.

Evidence: [lib/crewai-tools/src/crewai_tools/tools/singlestore_search_tool/singlestore_search_tool.py:123–175](https://github.com/crewAIInc/crewAI/blob/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e/lib/crewai-tools/src/crewai_tools/tools/singlestore_search_tool/singlestore_search_tool.py#L123-L175); [lib/crewai-tools/src/crewai_tools/tools/singlestore_search_tool/singlestore_search_tool.py:268–321](https://github.com/crewAIInc/crewAI/blob/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e/lib/crewai-tools/src/crewai_tools/tools/singlestore_search_tool/singlestore_search_tool.py#L268-L321); [lib/crewai-tools/src/crewai_tools/tools/singlestore_search_tool/singlestore_search_tool.py:356–415](https://github.com/crewAIInc/crewAI/blob/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e/lib/crewai-tools/src/crewai_tools/tools/singlestore_search_tool/singlestore_search_tool.py#L356-L415).

### 12. crewai — lib/crewai/src/crewai/flow/runtime/_actions.py:309

**Source pattern supported · shared location · vulnerability not established.**

Observations: `obs-7e181661e3f1b20351fb7623` (bandit `B102`); `obs-99459ada0894679bc171817f` (invarune `AI001`); `obs-d2f6e220182280ed859e2c24` (semgrep `python.lang.security.audit.exec-detected.exec-detected`).

ScriptAction parses configured Python source, wraps it in a function, and executes the compiled module to create the handler. Before compilation it requires an explicit environment opt-in that is disabled by default, and runtime state/input are passed as arguments rather than interpolated into source. The schema identifies this as trusted, unsandboxed project code; the source pattern is real but unauthorized execution is not established.

**AI/MCP relevance:** Relevant if an AI/MCP system is allowed to author flow definitions and an operator enables script execution; ordinary runtime text arguments alone do not control the compiled code.

**Proposed action:** Preserve the default-disabled opt-in and trusted-definition boundary; verify provenance and approval of enabled flow definitions before treating this intended code-loading feature as a vulnerability.

Evidence: [lib/crewai/src/crewai/flow/runtime/_actions.py:41–50](https://github.com/crewAIInc/crewAI/blob/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e/lib/crewai/src/crewai/flow/runtime/_actions.py#L41-L50); [lib/crewai/src/crewai/flow/runtime/_actions.py:252–310](https://github.com/crewAIInc/crewAI/blob/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e/lib/crewai/src/crewai/flow/runtime/_actions.py#L252-L310); [lib/crewai/src/crewai/flow/runtime/_actions.py:376–410](https://github.com/crewAIInc/crewAI/blob/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e/lib/crewai/src/crewai/flow/runtime/_actions.py#L376-L410); [lib/crewai/src/crewai/flow/flow_definition.py:517–540](https://github.com/crewAIInc/crewAI/blob/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e/lib/crewai/src/crewai/flow/flow_definition.py#L517-L540).

### 13. crewai — lib/crewai/src/crewai/flow/visualization/assets/interactive.js:2449

**Source pattern supported · Invarune-only location · vulnerability not established.**

Observations: `obs-371f930a99632085f749bc13` (invarune `AI040`).

The theme updater assigns an HTML template to innerHTML, so the rendering-interface pattern is present. Its only interpolated field is selected between two fixed icon names by a Boolean, and saved theme data is compared to a constant before that Boolean is passed. No attacker-supplied HTML reaches this site in the examined function, so XSS is not established and sanitization is unnecessary for the current closed set.

**AI/MCP relevance:** This is presentation code in the agent-flow visualizer; agent outputs and MCP data do not reach the flagged icon template through the reviewed path.

**Proposed action:** Retain the closed icon-name selection, or use DOM construction/text attributes for clarity; avoid flagging this site as XSS without a changed input path.

Evidence: [lib/crewai/src/crewai/flow/visualization/assets/interactive.js:2444–2493](https://github.com/crewAIInc/crewAI/blob/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e/lib/crewai/src/crewai/flow/visualization/assets/interactive.js#L2444-L2493).

### 14. crewai — lib/crewai/src/crewai/rag/chromadb/config.py:63

**Conditional predicate mismatch · Invarune-only location · vulnerability not established.**

Observations: `obs-47bf7ae427bc4238ea1e723e` (invarune `AI010`).

The flagged api_key_env_var argument contains the public name of an environment variable, not an API credential value. The adjacent api_key argument retrieves the value from the environment at runtime. This fails the literal-credential predicate and does not establish a hard-coded secret.

**AI/MCP relevance:** Relevant to configuring embeddings for agent retrieval, but this literal is a lookup identifier and shows no AI/MCP credential leak.

**Proposed action:** Exclude credential-source field names such as api_key_env_var from literal-secret detections; review secret handling separately only if runtime evidence warrants it.

Evidence: [lib/crewai/src/crewai/rag/chromadb/config.py:48–65](https://github.com/crewAIInc/crewAI/blob/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e/lib/crewai/src/crewai/rag/chromadb/config.py#L48-L65).

### 15. crewai — lib/crewai/src/crewai/utilities/file_handler.py:166

**Source pattern supported · shared location · vulnerability requires runtime validation.**

Observations: `obs-81166d0350adf66e74367477` (invarune `AI005`); `obs-d458ba104cf579bcda4fe144` (bandit `B301`); `obs-ef98ec42537a4249fe5e1b9f` (semgrep `python.lang.security.deserialization.pickle.avoid-pickle`).

PickleHandler.load opens the selected local file and passes it to pickle.load. CrewTrainingHandler invokes that loader when reading agent training data. File locking addresses concurrent access; the inspected code does not authenticate stored bytes. Who can replace the file or select its name is a deployment question, so code execution exploitability is not established.

**AI/MCP relevance:** Relevant when agent training state is shared, restored, or writable by a less-trusted actor. It is a persistence boundary, not an MCP protocol defect.

**Proposed action:** Prefer a schema-validated data format; otherwise constrain file ownership, restore/import paths, and integrity of training artifacts, then test rejected tampered files in an isolated environment.

Evidence: [lib/crewai/src/crewai/utilities/file_handler.py:119–137](https://github.com/crewAIInc/crewAI/blob/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e/lib/crewai/src/crewai/utilities/file_handler.py#L119-L137); [lib/crewai/src/crewai/utilities/file_handler.py:143–168](https://github.com/crewAIInc/crewAI/blob/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e/lib/crewai/src/crewai/utilities/file_handler.py#L143-L168); [lib/crewai/src/crewai/utilities/training_handler.py:7–31](https://github.com/crewAIInc/crewAI/blob/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e/lib/crewai/src/crewai/utilities/training_handler.py#L7-L31).

### 16. github-mcp — ui/package.json:23

**Source pattern supported · Invarune-only location · vulnerability requires runtime validation.**

Observations: `obs-3458005aa664de8b6ca9050c` (invarune `AI025`).

The UI manifest declares react-markdown using a caret range. Its retained lockfile resolves the dependency to an exact version with an integrity value, reducing installation variability when enforced. The source signal is a non-exact declaration, not a demonstrated malicious dependency or vulnerable installed package. CI workflows are outside this corpus.

**AI/MCP relevance:** This dependency renders content in an MCP application UI; relevance depends on the shipped UI and its build process.

**Proposed action:** Retain and enforce the reviewed lockfile with a frozen install, verify package integrity and provenance, and review update changes. A range alone does not require changing an intentional library compatibility policy.

Evidence: [ui/package.json:16–24](https://github.com/github/github-mcp-server/blob/85598ba6e1256f7ebf4867b95d63b833c4549264/ui/package.json#L16-L24); [ui/package-lock.json:4929–4942](https://github.com/github/github-mcp-server/blob/85598ba6e1256f7ebf4867b95d63b833c4549264/ui/package-lock.json#L4929-L4942).

### 17. langgraph — libs/checkpoint-postgres/langgraph/store/postgres/aio.py:243

**Source pattern supported · shared location · vulnerability not established.**

Observations: `obs-09546c3198342d166d316a44` (bandit `B608`); `obs-4ddb4c81e24f598c3004c606` (invarune `AI036`).

The helper interpolates a table identifier into SQL. Both calls visible inside setup pass fixed internal migration-table names; migration values elsewhere use parameters. This confirms the construction pattern but does not show attacker-controlled SQL or a SQL-injection vulnerability at the selected operation.

**AI/MCP relevance:** This is infrastructure for an agent memory store, but the shown operation is database setup rather than a model-selected runtime query.

**Proposed action:** Keep the helper private with fixed or allowlisted identifiers; use the driver identifier-composition API if generalized. Continue binding values separately and test that any future identifier input cannot escape its allowed set.

Evidence: [libs/checkpoint-postgres/langgraph/store/postgres/aio.py:227–258](https://github.com/langchain-ai/langgraph/blob/aa742fb31e2827d569b843e3600aeda2e0528e4b/libs/checkpoint-postgres/langgraph/store/postgres/aio.py#L227-L258).

### 18. langgraph — libs/checkpoint/langgraph/checkpoint/serde/jsonplus.py:288

**Source pattern supported · shared location · vulnerability requires runtime validation.**

Observations: `obs-27ec4fefe614760939428e2a` (semgrep `python.lang.security.deserialization.pickle.avoid-pickle`); `obs-659f911073e228706189e98e` (bandit `B301`); `obs-69462511f170662b8c792c81` (invarune `AI005`).

The serializer calls pickle.loads only when pickle_fallback is enabled and the typed input is marked as pickle. The constructor defaults that option to false and the class explicitly warns about checkpoint-writer trust. A real deserialization API exists, but an active vulnerable deployment or attacker-controlled checkpoint is not demonstrated.

**AI/MCP relevance:** Checkpoint restoration is part of agent state persistence; concern rises if lower-trust actors can modify checkpoint records and the optional fallback is enabled.

**Proposed action:** Keep pickle fallback disabled where feasible, migrate serialized state to an explicitly allowed format, and restrict checkpoint write/restore access. Test the deployed serializer configuration and invalid or tampered checkpoint rejection.

Evidence: [libs/checkpoint/langgraph/checkpoint/serde/jsonplus.py:81–115](https://github.com/langchain-ai/langgraph/blob/aa742fb31e2827d569b843e3600aeda2e0528e4b/libs/checkpoint/langgraph/checkpoint/serde/jsonplus.py#L81-L115); [libs/checkpoint/langgraph/checkpoint/serde/jsonplus.py:253–290](https://github.com/langchain-ai/langgraph/blob/aa742fb31e2827d569b843e3600aeda2e0528e4b/libs/checkpoint/langgraph/checkpoint/serde/jsonplus.py#L253-L290).

### 19. langgraph — libs/cli/langgraph_cli/constants.py:5

**Conditional predicate mismatch · shared location · vulnerability requires runtime validation.**

Observations: `obs-e173692debf2e9c9a7712872` (gitleaks `jwt`); `obs-fbf5c99722322e3ed2a1ea08` (invarune `AI010`).

The literal is explicitly a public analytics API key, and the decoded payload identifies the legacy anon role; decoding is not signature or live-service validation. The caller uses it for analytics ingestion. This does not satisfy the benchmark predicate of a leaked private credential, although backend grants and row-level policies remain unverified.

**AI/MCP relevance:** Adjacent CLI telemetry, rather than an agent tool authorization secret. Public-key abuse or misconfigured data policies would need a separate service assessment.

**Proposed action:** Document the public role so secret triage can distinguish it from privileged credentials; independently verify least-privilege analytics grants and row-level policies. Do not rotate a documented public key solely because its JWT shape matched.

Evidence: [libs/cli/langgraph_cli/constants.py:4–6](https://github.com/langchain-ai/langgraph/blob/aa742fb31e2827d569b843e3600aeda2e0528e4b/libs/cli/langgraph_cli/constants.py#L4-L6); [libs/cli/langgraph_cli/analytics.py:65–81](https://github.com/langchain-ai/langgraph/blob/aa742fb31e2827d569b843e3600aeda2e0528e4b/libs/cli/langgraph_cli/analytics.py#L65-L81).

Native lexical matching is preserved; the mismatch concerns private-credential interpretation.

### 20. mcp-reference — src/everything/Dockerfile:1

**Source pattern supported · Invarune-only location · vulnerability requires runtime validation.**

Observations: `obs-fe3d2e805fb94e3cf1ae6360` (invarune `AI024`).

The Dockerfile stage uses a Node image tag without a content digest. This supports a reproducibility-policy signal; it does not show a compromised base image or deployed vulnerability. Package-lock-based installation in later stages does not pin the base image itself.

**AI/MCP relevance:** Applicable if this reference MCP server image is actually built or distributed; demonstration packaging alone does not establish production exposure.

**Proposed action:** Resolve an approved base-image digest, record provenance and update policy, rebuild, and verify the resulting image configuration and final filesystem.

Evidence: [src/everything/Dockerfile:1–11](https://github.com/modelcontextprotocol/servers/blob/d73f99efbfd40c3aa1b61e88728b3d49fb52608f/src/everything/Dockerfile#L1-L11).

### 21. mcp-reference — src/everything/Dockerfile:9

**Source pattern supported · Invarune-only location · vulnerability requires runtime validation.**

Observations: `obs-4fc8e5f51d0476d9098bd1c8` (invarune `AI024`).

The Dockerfile stage uses a Node image tag without a content digest. This supports a reproducibility-policy signal; it does not show a compromised base image or deployed vulnerability. Package-lock-based installation in later stages does not pin the base image itself.

**AI/MCP relevance:** Applicable if this reference MCP server image is actually built or distributed; demonstration packaging alone does not establish production exposure.

**Proposed action:** Resolve an approved base-image digest, record provenance and update policy, rebuild, and verify the resulting image configuration and final filesystem.

Evidence: [src/everything/Dockerfile:9–20](https://github.com/modelcontextprotocol/servers/blob/d73f99efbfd40c3aa1b61e88728b3d49fb52608f/src/everything/Dockerfile#L9-L20).

Location note: reported line 9 is blank; the actual pattern starts on line 10.

### 22. mcp-reference — src/everything/transports/sse.ts:12

**Source pattern supported · Invarune-only location · vulnerability requires runtime validation.**

Observations: `obs-67316f6246581253dc1d5bbe` (invarune `AI007`).

The SSE transport configures wildcard CORS and attaches it to its Express application. The source comment explicitly describes Inspector direct-connect testing, and the file exposes SSE/message routes. Authentication, browser credentials behavior, external ingress and whether this test-oriented transport is deployed were not validated.

**AI/MCP relevance:** Direct MCP transport/browser-origin boundary if this SSE entry point is exposed to clients. A wildcard origin is not by itself a demonstrated cross-origin data theft.

**Proposed action:** Use explicit approved origins for deployed browser clients, validate session authorization independently of CORS, and test origin/credential combinations against the deployed ingress.

Evidence: [src/everything/transports/sse.ts:8–17](https://github.com/modelcontextprotocol/servers/blob/d73f99efbfd40c3aa1b61e88728b3d49fb52608f/src/everything/transports/sse.ts#L8-L17); [src/everything/transports/sse.ts:25–44](https://github.com/modelcontextprotocol/servers/blob/d73f99efbfd40c3aa1b61e88728b3d49fb52608f/src/everything/transports/sse.ts#L25-L44); [src/everything/transports/sse.ts:58–77](https://github.com/modelcontextprotocol/servers/blob/d73f99efbfd40c3aa1b61e88728b3d49fb52608f/src/everything/transports/sse.ts#L58-L77).

### 23. mcp-reference — src/filesystem/package.json:28

**Source pattern supported · Invarune-only location · vulnerability requires runtime validation.**

Observations: `obs-53016403e1d57f5dd4457ee3` (invarune `AI025`).

The filesystem server manifest declares the MCP SDK using a caret range. The repository lockfile resolves a concrete SDK version and integrity value. This is a declaration-policy observation; effective frozen-install enforcement and package vulnerability status were not established by the source audit.

**AI/MCP relevance:** The SDK supplies protocol implementation for a filesystem MCP server, so build reproducibility and reviewed updates affect its delivered trust boundary.

**Proposed action:** Use the reviewed lockfile with a frozen verified install; review and test SDK updates and the final shipped image/package. Keep declaration ranges only where the compatibility policy intentionally requires them.

Evidence: [src/filesystem/package.json:27–32](https://github.com/modelcontextprotocol/servers/blob/d73f99efbfd40c3aa1b61e88728b3d49fb52608f/src/filesystem/package.json#L27-L32); [package-lock.json:155–176](https://github.com/modelcontextprotocol/servers/blob/d73f99efbfd40c3aa1b61e88728b3d49fb52608f/package-lock.json#L155-L176).

### 24. mcp-reference — src/memory/Dockerfile:11

**Source pattern supported · Invarune-only location · vulnerability requires runtime validation.**

Observations: `obs-23423a55a8ee490ab0566a11` (invarune `AI024`).

The Dockerfile stage uses a Node image tag without a content digest. This supports a reproducibility-policy signal; it does not show a compromised base image or deployed vulnerability. Package-lock-based installation in later stages does not pin the base image itself.

**AI/MCP relevance:** Applicable if this reference MCP server image is actually built or distributed; demonstration packaging alone does not establish production exposure.

**Proposed action:** Resolve an approved base-image digest, record provenance and update policy, rebuild, and verify the resulting image configuration and final filesystem.

Evidence: [src/memory/Dockerfile:11–22](https://github.com/modelcontextprotocol/servers/blob/d73f99efbfd40c3aa1b61e88728b3d49fb52608f/src/memory/Dockerfile#L11-L22).

Location note: reported line 11 is blank; the actual pattern starts on line 12.

### 25. mcp-reference — src/sequentialthinking/Dockerfile:11

**Source pattern supported · Invarune-only location · vulnerability requires runtime validation.**

Observations: `obs-a5c0abc42d2b89662cd1443e` (invarune `AI024`).

The Dockerfile stage uses a Node image tag without a content digest. This supports a reproducibility-policy signal; it does not show a compromised base image or deployed vulnerability. Package-lock-based installation in later stages does not pin the base image itself.

**AI/MCP relevance:** Applicable if this reference MCP server image is actually built or distributed; demonstration packaging alone does not establish production exposure.

**Proposed action:** Resolve an approved base-image digest, record provenance and update policy, rebuild, and verify the resulting image configuration and final filesystem.

Evidence: [src/sequentialthinking/Dockerfile:11–22](https://github.com/modelcontextprotocol/servers/blob/d73f99efbfd40c3aa1b61e88728b3d49fb52608f/src/sequentialthinking/Dockerfile#L11-L22).

Location note: reported line 11 is blank; the actual pattern starts on line 12.

### 26. openhands — docker/Dockerfile:28

**Source pattern supported · Invarune-only location · vulnerability requires runtime validation.**

Observations: `obs-cf2475a04d5644932ce6ca9d` (invarune `AI024`).

The frontend-build stage selects a Node image tag without a digest. The same stage copies package-lock.json and runs npm ci, which constrains application packages but does not pin the base image. No compromised image or reachable runtime flaw is demonstrated.

**AI/MCP relevance:** This stage builds an agent UI that is later packaged with an agent server and automation services; applicability depends on this Dockerfile being used for distribution.

**Proposed action:** Pin and verify the approved build-stage image digest and preserve the frozen package installation; rebuild and record the resulting artifact provenance.

Evidence: [docker/Dockerfile:18–34](https://github.com/OpenHands/OpenHands/blob/a07364828c8f202e7745c6bce3dcef3915ae7ac1/docker/Dockerfile#L18-L34); [docker/Dockerfile:73–79](https://github.com/OpenHands/OpenHands/blob/a07364828c8f202e7745c6bce3dcef3915ae7ac1/docker/Dockerfile#L73-L79).

### 27. openhands — src/components/features/chat/mono-component.tsx:6

**Source pattern supported · Invarune-only location · vulnerability not established.**

Observations: `obs-b84aca086ad3f71c7519b8d0` (invarune `AI040`).

The component assigns input to innerHTML on a newly created textarea, returns its value, and renders the resulting string as a React child. That is a real HTML-parsing interface used as an entity decoder, with no insertion of the temporary node shown. Source context substantially reduces the concern; this audit did not execute a browser or demonstrate XSS.

**AI/MCP relevance:** Used for agent chat/event presentation through a command-text component. Relevance would require unsafe interpretation of attacker-controlled text in the actual renderer, not merely the presence of innerHTML.

**Proposed action:** Retain plain-string React rendering and avoid inserting the temporary element. Consider an explicit entity-decoding utility and add browser tests for markup-like command text before declaring this path safe or exploitable.

Evidence: [src/components/features/chat/mono-component.tsx:1–37](https://github.com/OpenHands/OpenHands/blob/a07364828c8f202e7745c6bce3dcef3915ae7ac1/src/components/features/chat/mono-component.tsx#L1-L37); [src/components/conversation-events/chat/event-content-helpers/get-event-content.tsx:38–65](https://github.com/OpenHands/OpenHands/blob/a07364828c8f202e7745c6bce3dcef3915ae7ac1/src/components/conversation-events/chat/event-content-helpers/get-event-content.tsx#L38-L65).

### 28. openhands — src/hooks/query/use-backends-health.ts:33

**Conditional predicate mismatch · Invarune-only location · vulnerability not established.**

Observations: `obs-23b29aaefb11a30298bce6b0` (invarune `AI010`).

The selected literal is a human-readable error message. Its identifier contains API_KEY, but functions compare it to health-error strings; it is not a credential value. This is a conditional credential-rule mismatch at the reported location, not evidence of a leaked key.

**AI/MCP relevance:** The surrounding hook monitors agent backends, but this string only labels an authentication/network error in the UI.

**Proposed action:** Refine triage to distinguish error labels from credential material; keep actual backend keys separate and redacted. No credential rotation is justified by this literal alone.

Evidence: [src/hooks/query/use-backends-health.ts:29–59](https://github.com/OpenHands/OpenHands/blob/a07364828c8f202e7745c6bce3dcef3915ae7ac1/src/hooks/query/use-backends-health.ts#L29-L59).

### 29. openhands — config/defaults.json:42

**Conditional predicate mismatch · competitor-only location · vulnerability requires runtime validation.**

Observations: `obs-ab1abbdc34c711202b854521` (gitleaks `generic-api-key`).

The configuration supplies a PostHog client project key used by the browser telemetry module. Both local build comments and the consumer identify a public client-side analytics role. The benchmark private-credential predicate is therefore unsupported; ingestion abuse, privacy settings and server-side access remain separate questions.

**AI/MCP relevance:** Adjacent agent-UI telemetry; this value is not shown to authorize agent tools or read private analytics data.

**Proposed action:** Document public telemetry-key classification and validate analytics privacy and ingestion controls separately. Keep personal/server API keys out of client bundles and do not treat this public value alone as a secret incident.

Evidence: [config/defaults.json:41–44](https://github.com/OpenHands/OpenHands/blob/a07364828c8f202e7745c6bce3dcef3915ae7ac1/config/defaults.json#L41-L44); [src/services/telemetry.ts:60–88](https://github.com/OpenHands/OpenHands/blob/a07364828c8f202e7745c6bce3dcef3915ae7ac1/src/services/telemetry.ts#L60-L88); [docker/Dockerfile:39–46](https://github.com/OpenHands/OpenHands/blob/a07364828c8f202e7745c6bce3dcef3915ae7ac1/docker/Dockerfile#L39-L46).

Native lexical matching is preserved; the mismatch concerns private-credential interpretation.

### 30. crewai — lib/crewai-tools/src/crewai_tools/tools/arxiv_paper_tool/arxiv_paper_tool.py:9

**Source pattern supported · competitor-only location · vulnerability requires runtime validation.**

Observations: `obs-24e79c015edc3ced865b2898` (bandit `B405`); `obs-3031250433a8a3c44c95c219` (semgrep `python.lang.security.use-defused-xml.use-defused-xml`).

The file imports ElementTree and later parses an external HTTP response with ET.fromstring. The configured host is a fixed arXiv endpoint and the query is encoded, but the response is read and parsed without a visible size bound in this function. This supports an XML-parser review surface; entity behavior and runtime library protections were not tested, so XXE or denial of service is not confirmed.

**AI/MCP relevance:** This agent research tool consumes external document metadata; a malicious or compromised response would enter the parsing boundary.

**Proposed action:** Use HTTPS where supported, bound response size, use a hardened parser for untrusted documents, and test oversized/entity-bearing responses against supported runtime versions. Review PDF download behavior separately from this selected XML observation.

Evidence: [lib/crewai-tools/src/crewai_tools/tools/arxiv_paper_tool/arxiv_paper_tool.py:1–35](https://github.com/crewAIInc/crewAI/blob/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e/lib/crewai-tools/src/crewai_tools/tools/arxiv_paper_tool/arxiv_paper_tool.py#L1-L35); [lib/crewai-tools/src/crewai_tools/tools/arxiv_paper_tool/arxiv_paper_tool.py:78–101](https://github.com/crewAIInc/crewAI/blob/3831e8b6c86f78cb3cde18ebf7be0d197b958f0e/lib/crewai-tools/src/crewai_tools/tools/arxiv_paper_tool/arxiv_paper_tool.py#L78-L101).

### 31. autogen — python/packages/autogen-ext/src/autogen_ext/code_executors/docker_jupyter/_docker_jupyter.py:192

**Source pattern supported · competitor-only location · vulnerability not established.**

Observations: `obs-82ff7d0a4f630df0f1db6dea` (bandit `B101`).

An assert checks that a kernel identifier was assigned after start returns. The start method validates the requested kernel name and stores the server result; the selected assert is an internal postcondition, not a shown authorization check. Python optimization removing this statement is not evidence of an agent sandbox bypass.

**AI/MCP relevance:** This belongs to an agent code executor, but its relationship to a security boundary is indirect and unproven.

**Proposed action:** Use an explicit exception if this postcondition must be enforced in optimized builds, and test failed kernel startup separately from code-execution isolation controls.

Evidence: [python/packages/autogen-ext/src/autogen_ext/code_executors/docker_jupyter/_docker_jupyter.py:188–195](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-ext/src/autogen_ext/code_executors/docker_jupyter/_docker_jupyter.py#L188-L195); [python/packages/autogen-ext/src/autogen_ext/code_executors/docker_jupyter/_docker_jupyter.py:258–263](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-ext/src/autogen_ext/code_executors/docker_jupyter/_docker_jupyter.py#L258-L263).

### 32. fastmcp — fastmcp_slim/fastmcp/server/auth/providers/google.py:245

**Conditional predicate mismatch · competitor-only location · vulnerability not established.**

Observations: `obs-be342960cf98e3b44b7acdcf` (gitleaks `generic-api-key`).

The selected string is inside the GoogleProvider documentation example and visibly contains an ellipsis placeholder. The runtime constructor receives client_secret as a parameter rather than using this example literal. This contradicts a claim of an exposed usable secret at the selected location.

**AI/MCP relevance:** The component supplies MCP OAuth, but the flagged example is instructional text rather than configured authentication material.

**Proposed action:** Use unmistakable placeholder examples or an environment-variable example; verify real deployments obtain their own secret through approved configuration. This excerpt alone does not call for credential rotation.

Evidence: [fastmcp_slim/fastmcp/server/auth/providers/google.py:225–257](https://github.com/PrefectHQ/fastmcp/blob/9c35c017cd89e4d50a9f512c8eafde68c301ec70/fastmcp_slim/fastmcp/server/auth/providers/google.py#L225-L257).

Native lexical matching is preserved; the mismatch concerns private-credential interpretation.

### 33. autogen — python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/_memory_bank.py:114

**Source pattern supported · competitor-only location · vulnerability not established.**

Observations: `obs-6fbb3b0a1975249a424dfea9` (semgrep `python.lang.security.deserialization.pickle.avoid-pickle`).

The selected operation is pickle.dump: it writes the in-memory memo dictionary, rather than deserializing attacker-provided bytes. A separate load path exists elsewhere in the same class, but this selected serializer call is not itself an unpickling sink. The broad pickle-family predicate is present; it should not be counted as an additional demonstrated code-execution vulnerability.

**AI/MCP relevance:** Serializes agent memory that may later be restored; risk depends on the entire storage/restore trust boundary.

**Proposed action:** Prefer a constrained data format for durable memory and secure its storage. Track the read-side sink separately so a serialization observation is not misrepresented as an independent deserialization issue.

Evidence: [python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/_memory_bank.py:107–114](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/_memory_bank.py#L107-L114); [python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/_memory_bank.py:68–84](https://github.com/microsoft/autogen/blob/027ecf0a379bcc1d09956d46d12d44a3ad9cee14/python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/_memory_bank.py#L68-L84).

This audit supplies review evidence and proposed follow-up. It does not mark any scanner control as passed, waive findings, change the frozen ledger, or certify a project’s security.
