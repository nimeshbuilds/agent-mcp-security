# Invarune by NimeshBuild

AI agent and MCP security report

Scan ID: `a7483423f5469d9f691860138aa040fefc1c0bf4ae1ef71863a0bb000f1658d3`

This is static security triage, not certification or proof that a system is secure.

## Contents

- [Summary and immediate concerns](#executive-assessment)
- [Methods, configuration and blind spots](#methods-configuration-and-blind-spots)
- [Editable review and fresh scan](#editable-review-and-fresh-scan)
- [Scan details](#scan-details)

## Executive assessment

### Critical/high findings need prompt review

The scanner found 4 open critical/high patterns among 11 open findings\. Confirm exposure and prioritize the actions below\. Detector severity is not proof of exploitability or deployed risk\.

| Open findings | Critical/high | Affected files | Accepted baseline findings | Coverage gaps |
|---:|---:|---:|---:|---:|
| 11 | 4 | 8 | 0 | 0 |

**66 active controls** still require applicability and effectiveness validation. A completed static scan or optional review cannot establish a control pass.

**Fix guidance:** 11/11 observed findings have a deterministic fix plan and agent/MCP context. Model fix plans: 0/0 finding assessments and 0/0 answered checks. These are proposed changes requiring verification.

**What the scanner found:** Supply chain: 4; Data protection: 2; Deserialization: 2; Tool execution: 2; Configuration: 1. These are detected pattern categories, not confirmed attack paths.

**Execution:** exit 1; severity threshold high. The exit threshold does not change the review priorities below.

**Optional model review:** disabled. This overview and the mitigation guidance work offline without a model.

## Immediate concerns and first actions

P0: critical, P1: high, P2: medium, P3: low/info\. These are deterministic review priorities based on detector severity, not incident confirmation, remediation SLAs, likelihood estimates, or residual\-risk scores\. Confidence describes the detected pattern; applicability must be checked\.

| Priority | What the scanner found | Occurrences | First action | Suggested owner |
|---|---|---:|---|---|
| P1 | [AI001: Dynamic Python code execution](#group-45290f4fa5c7) (source) | 2 | Trace the input to eval/exec and replace it with fixed operations; if generated execution is essential, isolate it before accepting untrusted input\. | Agent/tool developer |
| P1 | [AI005: Executable deserialization requires trusted inputs](#group-9ee5075ce1a1) (source) | 2 | Establish who can produce and replace the input; migrate to a nonexecutable data format or restrict verified legacy artifacts to an isolated conversion path\. | Application/model pipeline owner |
| P2 | [AI009: Application debug mode enabled](#group-50316e5c3385) (source) | 1 | Verify the effective deployed setting, disable debug behavior, and confirm representative errors do not expose a debugger or sensitive details\. | Application and platform owner |
| P2 | [AI033: Potential secret included in logging call](#group-6a434c96603a) (source) | 2 | Verify the logged value safely, remove it before formatting/export, and rotate it if real exposure is confirmed\. | Application/observability owner |
| P3 | [AI024: Container image is not digest pinned](#group-0cc3d39352a0) (source) | 4 | Identify the approved image digest and enforce it in the effective build or deployment while preserving a reviewed update process\. | Container/release owner |

## What could reduce the risk

The layers below are **proposed and unverified**. They can reduce exposure or impact only when correctly implemented and tested. Fix the underlying issue where applicable. No suggested layer, baseline exception, or model opinion lowers a finding's recorded severity.

Before accepting lower residual risk, record deployment evidence, negative-test results, owner, review date, and expiry. Confirm that requests cannot bypass the control and retest after changes.

<a id="group-45290f4fa5c7"></a>

### AI001: Dynamic Python code execution

**HIGH** · open · 2 occurrences · source

**Observed evidence:** [python/packages/autogen\-core/src/autogen\_core/tools/\_function\_tool\.py:159](#finding-4e20cb4340397cc0), [python/packages/autogen\-core/src/autogen\_core/tools/\_function\_tool\.py:171](#finding-43e902f64605b9e0)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If external or generated content reaches this expression, it could execute Python with the process identity and access its files, credentials, and network\.

**Address the cause:** Trace the input to eval/exec and replace it with fixed operations; if generated execution is essential, isolate it before accepting untrusted input\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Enforce action policy outside the model | Have an execution service allow only named operations, permitted argument values, and caller\-owned target resources before invoking a tool\. | Exercise disallowed operations, additional arguments, cross\-tenant identifiers, and direct calls that bypass the agent planner\. | Authorized operations can still be harmful when business constraints are incomplete; prompt instructions cannot enforce this boundary\. |
| Isolate tool execution | Run the risky tool in a separate, disposable identity with no host mounts, ambient credentials, or unnecessary outbound access\. | In a test environment, attempt reads outside the workspace, forbidden network connections, and resource exhaustion; retain policy and denial evidence\. | Isolation limits reachable assets; it does not make injected code trustworthy or rule out a runtime escape\. |

Related controls: EXEC\-02

Guidance sources (engineering synthesis): [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools); [OWASP\-AGENT\-CS](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html); [OWASP\-LLM2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/); [TECH\-PYTHON\-SECURITY](https://docs.python.org/3/library/security_warnings.html)

<a id="group-9ee5075ce1a1"></a>

### AI005: Executable deserialization requires trusted inputs

**HIGH** · open · 2 occurrences · source

**Observed evidence:** [python/packages/autogen\-ext/src/autogen\_ext/experimental/task\_centric\_memory/\_memory\_bank\.py:82](#finding-b1e75a0bec774077), [python/packages/autogen\-ext/src/autogen\_ext/experimental/task\_centric\_memory/\_string\_similarity\_map\.py:48](#finding-5bbbbf180b68c4f8)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If an attacker can supply or replace the serialized input, loading it may execute code even before the application examines the returned object\.

**Address the cause:** Establish who can produce and replace the input; migrate to a nonexecutable data format or restrict verified legacy artifacts to an isolated conversion path\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Verify artifact identity before use | Require reviewed artifact provenance plus a digest or signature checked against an independently trusted identity or manifest\. | Substitute bytes, producer identity, or verification metadata in a controlled test and confirm the consumer rejects the artifact\. | Authenticity establishes the producer and bytes; an approved producer can still ship vulnerable or malicious content\. |
| Separate artifact conversion from production | Perform necessary conversion of legacy serialized artifacts in a disposable environment without production data or credentials\. | Demonstrate that a conversion job cannot reach production services and only approved output formats are promoted\. | Conversion output still needs integrity, format, and downstream behavior review; isolation is not proof of benign content\. |

Related controls: EXEC\-06

Guidance sources (engineering synthesis): [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely); [NIST\-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final); [OPENSSF\-MODEL\-SIGNING](https://openssf.org/blog/2025/04/04/launch-of-model-signing-v1-0-openssf-ai-ml-working-group-secures-the-machine-learning-supply-chain/); [SLSA\-12](https://slsa.dev/spec/v1.2/); [TECH\-PYTHON\-SECURITY](https://docs.python.org/3/library/security_warnings.html); [TECH\-PYTORCH\-SERIAL](https://pytorch.org/docs/stable/notes/serialization.html)

<a id="group-50316e5c3385"></a>

### AI009: Application debug mode enabled

**MEDIUM** · open · 1 occurrences · source

**Observed evidence:** [python/packages/autogen\-studio/autogenstudio/web/app\.py:60](#finding-aeffdafc90f11c4d)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If debug behavior is active on a reachable deployment, errors or a framework debugger may disclose internals or permit additional actions\.

**Address the cause:** Verify the effective deployed setting, disable debug behavior, and confirm representative errors do not expose a debugger or sensitive details\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Separate operational diagnostics from client errors | Return minimal errors to clients and retain necessary diagnostic detail only in protected, redacted server\-side records\. | Trigger representative failures and confirm public responses exclude stack traces, credentials, paths, and debug consoles\. | Redaction can miss unexpected formats, and authorized log readers may still see sensitive operational context\. |
| Enforce reviewed deployment defaults | Gate releases on approved runtime settings and reject deployments that restore the unsafe option through overrides\. | Evaluate the rendered deployment and running workload, then attempt a rollout containing the forbidden override\. | A source configuration or successful build does not establish the effective production runtime policy\. |

Related controls: DATA\-03

Guidance sources (engineering synthesis): [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [NCSC\-SECURE\-AI](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development); [NIST\-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final); [OWASP\-MCP10](https://owasp.org/projects/mcp-top-10)

<a id="group-6a434c96603a"></a>

### AI033: Potential secret included in logging call

**MEDIUM** · open · 2 occurrences · source

**Observed evidence:** [python/packages/autogen\-studio/autogenstudio/web/auth/manager\.py:98](#finding-189a10a56b01dd40), [python/packages/autogen\-studio/autogenstudio/web/auth/manager\.py:101](#finding-4e7a3b8d9bf357c3)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If this value is a real secret, log readers, exporters, or retained telemetry copies may gain its permissions beyond the original application boundary\.

**Address the cause:** Verify the logged value safely, remove it before formatting/export, and rotate it if real exposure is confirmed\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Minimize and protect retained telemetry | Collect only necessary nonsecret events, redact before export, and limit access, retention, and downstream replication\. | Inject recognizable synthetic secret values and trace their absence through application, proxy, tracing, and archived logs\. | Redaction tests cover selected formats; already exported copies and authorized readers remain part of the exposure assessment\. |
| Limit credentials available to the workload | Give this component a distinct identity and only the downstream scopes and lifetime needed for its approved operations\. | Use its runtime identity to attempt forbidden service operations, then revoke it and confirm subsequent access fails\. | A compromised component can still use its allowed permissions until credentials expire or revocation takes effect\. |

Related controls: DATA\-03

Guidance sources (engineering synthesis): [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [JOINT\-AGENTIC](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services); [NCSC\-SECURE\-AI](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development); [NIST\-GENAI](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf); [OWASP\-MCP10](https://owasp.org/projects/mcp-top-10)

<a id="group-0cc3d39352a0"></a>

### AI024: Container image is not digest pinned

**LOW** · open · 4 occurrences · source

**Observed evidence:** [dotnet/src/Microsoft\.AutoGen/AgentHost/Dockerfile:4](#finding-bc22c181ad320cef), [dotnet/src/Microsoft\.AutoGen/AgentHost/Dockerfile:10](#finding-a8da66ae7685eaac), [python/packages/agbench/src/agbench/res/Dockerfile:1](#finding-c3bb633a271176f8), [python/packages/autogen\-studio/Dockerfile:1](#finding-b3091c71a13b232b)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If a mutable image tag changes, a rebuild or deployment may consume unreviewed bytes; the scan does not establish that the current image is vulnerable\.

**Address the cause:** Identify the approved image digest and enforce it in the effective build or deployment while preserving a reviewed update process\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Verify artifact identity before use | Require reviewed artifact provenance plus a digest or signature checked against an independently trusted identity or manifest\. | Substitute bytes, producer identity, or verification metadata in a controlled test and confirm the consumer rejects the artifact\. | Authenticity establishes the producer and bytes; an approved producer can still ship vulnerable or malicious content\. |
| Keep pinned artifacts maintained | Review known\-vulnerability and maintenance evidence for the actual resolved artifacts and apply updates through a repeatable release process\. | Demonstrate a dependency update, relevant regression checks, and deployment or rollback of the resulting approved artifact\. | This source/image scan does not provide a current CVE verdict, and a vulnerability database cannot identify every unknown flaw\. |

Related controls: SUP\-01, SUP\-03

Guidance sources (engineering synthesis): [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [NIST\-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final); [NSA\-DATA](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/); [OPENSSF\-MODEL\-SIGNING](https://openssf.org/blog/2025/04/04/launch-of-model-signing-v1-0-openssf-ai-ml-working-group-secures-the-machine-learning-supply-chain/); [OPENSSF\-SCORECARD](https://securityscorecards.dev/); [SLSA\-12](https://slsa.dev/spec/v1.2/)

### What remains unknown

- Actual reachability, deployment configuration, upstream validation, data sensitivity, and exploitability require verification\.
- Authentication, authorization, tenant isolation, tool approvals, prompt\-injection resistance, and recovery need runtime or human evidence\.
- Suggested defense layers have not been verified as deployed\. There is no calculated residual\-risk score or automatic severity reduction\.
- No dependency CVE feed or live adversarial agent/MCP benchmark was run\. Excluded and unsupported files remain outside the selected scope\.

Guidance catalog version: 1\.0\.0; SHA-256: `dadde42b9b4e7f65d34d897f716649ed0b49b1fc561e5e45a9eadbac43c5eed1`. The catalog is bundled and does not contact external sources during a scan.

## Methods, configuration and blind spots

Find repeatable security patterns and organize the remaining assurance work for agents, MCP servers and built images\.

| Catalog measure | Count |
|---|---:|
| Deterministic rules | 42 |
| Controls with partial static mapping | 26 |
| Controls without static mapping | 40 |
| Catalog acceptance checks | 132 |

Mapping counts describe available checks, not percent secure, detection accuracy or validated control effectiveness\.

### How the layers operate

1. Choose an explicit code/image target and scan configuration; no target code or container is started\.
2. Collect bounded deterministic evidence, record hashes, rule matches, exclusions and coverage gaps\.
3. When explicitly enabled, select bounded evidence for finding triage and every active control check; findings\-only mode narrows this step\.
4. Run advisory model requests under fixed limits; validate response schemas, known identifiers and exact evidence quotes\. The model cannot select files or execute tools through the review controller\.
5. Retain unsupported claims and runtime/human requirements; record user review decisions separately from model advice\.
6. Import an explicitly selected reviewed report with a fresh target scan; revalidate evidence bindings, retain stale decisions for audit and recompute the result\.

### What each layer can and cannot establish

#### Execution and data flow

**Deterministic:** Python AST checks with bounded local aliases/values; JavaScript/TypeScript tokens and balanced calls identify selected eval, shell, deserialization, SQL and template patterns\.

**Optional model review:** A model can explain a retrieved call path, question whether input is trusted and identify contextual concerns the pattern rules do not encode\.

**Can miss or misclassify:** Cross\-file flows, dynamic imports, wrappers, reflection, generated code, unsupported languages and runtime values can hide a risk\. A dangerous API can also be intentional and correctly constrained\.

**Runtime/human evidence:** Exercise actual entry points with authorized negative tests; verify input provenance, execution privileges and sandbox boundaries\.

#### MCP identity, authorization and tools

**Deterministic:** Selected configuration/code signals flag insecure transport, explicit authentication bypass, token passthrough, broad tool grants and unpinned server launch packages\.

**Optional model review:** A model can review supplied authorization logic, tool descriptions and trust\-boundary evidence for missing assumptions or inconsistent checks\.

**Can miss or misclassify:** Configuration may differ from deployment\. External gateways, identity providers, token audience checks and tenant boundaries may be absent from retrieved evidence\.

**Runtime/human evidence:** Test expired/wrong\-audience tokens, cross\-tenant access, per\-tool authorization, consent binding and the deployed MCP transport\.

#### Prompt injection, retrieval and memory

**Deterministic:** Selected patterns identify external content placed in privileged model messages and explicit approval/sandbox bypass\. This is not an attack simulation\.

**Optional model review:** A model can reason about untrusted\-content handling, persistent memory, tool\-output influence and missing approval boundaries in the supplied excerpts\.

**Can miss or misclassify:** Adaptive attacks, multi\-turn interactions and tool chains depend on runtime behavior\. Retrieval can omit the relevant code; a model can overlook an attack or be influenced by hostile evidence\.

**Runtime/human evidence:** Run isolated adversarial agent/MCP evaluations with attack\-success and legitimate\-task measurements, plus human review of consequential actions\.

#### Secrets and data handling

**Deterministic:** Selected literal credentials, plausible private\-key material, credential\-bearing URLs, logging patterns and browser credential exposure are flagged and redacted best\-effort\.

**Optional model review:** A model can identify sensitive data flows and retention concerns when the supplied evidence explains their context\.

**Can miss or misclassify:** Encoded, split or runtime\-fetched credentials can be missed; labels/test values can resemble secrets\. Neither layer establishes whether a credential is live or redaction is complete\.

**Runtime/human evidence:** Verify secret stores, credential rotation, logging/retention policy, egress destinations and actual data\-access permissions\.

#### Built images and supply chain

**Deterministic:** Image archives are reconstructed without starting containers; supported packaged source, metadata, retained credentials, stored permissions and package inventories are inspected\.

**Optional model review:** A model can interpret supplied image/source evidence, flag missing deployment context and propose verification work\.

**Can miss or misclassify:** Compiled logic, live deployment overrides, signature trust and dependency CVEs are not assessed\. Package inventory and archive consistency do not establish safety or publisher identity\.

**Runtime/human evidence:** Use vulnerability/advisory analysis, provenance/signature verification and deployment testing alongside the static image assessment\.

#### Operations and control effectiveness

**Deterministic:** The catalog retains governance, monitoring, recovery, approval and isolation checks even where no deterministic rule maps to them\.

**Optional model review:** Full review queues every active acceptance check and can identify evidence gaps or propose runtime/human validation; it can cite exact submitted source text\.

**Can miss or misclassify:** A valid citation proves that a quote exists, not that the model's interpretation is correct\. Policies, external services, incident procedures and production outcomes may be unavailable\.

**Runtime/human evidence:** Record owner\-reviewed evidence, operational exercises and runtime results\. A written justification remains an accepted exception, never an automatically validated pass\.

### Recorded scan configuration

These are settings and limits, not proof of completed coverage. Current CLI flags select a fresh scan; imported reports do not execute commands, select targets, restore credentials or enable model review.

```text
{
  "image_limits": {},
  "invocation": {
    "optional_review": {
      "analyst_limits": {
        "batch_size": 6,
        "max_bytes": 2000000,
        "max_calls": 12,
        "max_chars": 120000,
        "max_files": 200,
        "max_seconds": 180
      },
      "cli_login": "auto",
      "cli_timeout_seconds": null,
      "effective_transport": {},
      "enabled": false,
      "findings_limit": 100,
      "include_finding_source": false,
      "mode": "full",
      "provider": null,
      "transport_replay": "Endpoints, credentials, headers, executable paths and identity stores are not embedded for automatic replay."
    },
    "reporting": {
      "failure_threshold": "high",
      "formats": [
        "html",
        "markdown",
        "json",
        "sarif"
      ]
    },
    "review_inputs": {
      "baseline": false,
      "review_config": false,
      "review_report": false
    },
    "schema_version": "1.0"
  },
  "source_and_packaged_file_scope": {
    "default_excluded_directories": [
      ".cache",
      ".git",
      ".hg",
      ".mypy_cache",
      ".next",
      ".pytest_cache",
      ".svn",
      ".tox",
      ".venv",
      "__pycache__",
      "build",
      "coverage",
      "dist",
      "node_modules",
      "vendor",
      "venv"
    ],
    "exclude": [],
    "explicit_exclusion_identity_scope": "Existing selected files and directories, including case aliases and file hardlinks; inputs must remain stable during the scan. Device/inode identities are not persisted in reports.",
    "explicit_exclusion_matching": "resolved_paths_and_snapshot_filesystem_identities",
    "generated_outputs_and_judge_config_excluded": true,
    "max_entries": 100000,
    "max_file_bytes": 20000000,
    "max_files": 20000,
    "max_total_bytes": 300000000
  }
}
```

## Scan details

Scanned **759 files**; **11 open findings**, **0 suppressed findings**, and **0 coverage gaps**.

| Critical | High | Medium | Low | Info |
|---:|---:|---:|---:|---:|
| 0 | 4 | 3 | 4 | 0 |

Source I/O: **4232838 bytes read**, **4232838 bytes charged** against the budget, including **0 conservatively charged bytes** for failed reads. Each read reserves a sentinel byte to detect growth.

### Analysis depth

File counts describe inspected inputs, not complete semantic coverage. Syntax/read failures remain listed as coverage gaps.

| Profile | Files | Analysis scope |
|---|---:|---|
| configuration\_lexical | 14 | Selected text/configuration patterns; YAML anchors, block\-scalar semantics and dynamic templates are not fully resolved\. |
| generic\_text | 292 | Generic secret, URL and applicable text signals only; language\-specific execution and dataflow are not analyzed\. |
| javascript\_lexical | 124 | Bounded JavaScript/TypeScript tokens, calls and configuration signals; not a full JS/TS parser or control\-flow analysis\. |
| json\_structured | 4 | Parsed JSON/JSONC fields and selected configuration rules; runtime values and referenced files are not resolved\. |
| python\_ast | 325 | Python syntax, bounded local aliases/value tracking and selected security sinks; no whole\-program or interprocedural proof\. |

Severity failure threshold: **high** · Process exit code: **1**.

A clean pattern scan is not a control pass. Validate applicability and exploitability before remediation; runtime and manual checks remain required.

## Findings

<a id="finding-4e20cb4340397cc0"></a>

### AI001 — Dynamic Python code execution

**HIGH** · Confidence: medium · Status: open

Location: python/packages/autogen\-core/src/autogen\_core/tools/\_function\_tool\.py:159–159 · Finding ID: `3267af939c6985b894806d14`

eval or exec receives a nonliteral expression\. If agent, user, or tool content can reach it, it can execute arbitrary Python\. Static analysis does not establish the full data flow\.

```text
                exec(import_code, exec_globals)
```

**Remediation:** Replace dynamic execution with an allowlisted operation dispatcher; use ast\.literal\_eval only for bounded literal parsing\. Isolate unavoidable execution with no ambient credentials and strict resource limits\.

#### Fix plan and agent/MCP relevance

Replace dynamic Python evaluation with a bounded operation interface\.

**Why this matters for agents/MCP:** An agent can convert a prompt or MCP tool result into an eval/exec argument\. If that value reaches this call, model influence becomes Python execution with the tool process identity\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Trace the expression from its producer to this exact call; a nonliteral expression alone does not establish external control or an active agent path\.
- Trusted fixed startup code and deliberately isolated code\-execution services need different treatment; document which boundary applies\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Remove the interpreter boundary | Replace eval/exec with a dictionary of fixed callable operations and validate a small JSON argument schema before selecting a callable\. Do not permit callers to name arbitrary modules, attributes or Python expressions\. | Send unsupported operation names and extra arguments through the same tool entry point; verify rejection before any callable executes\. |
| 2\. Choose a bounded data parser | For data, prefer JSON plus explicit type, length and nesting limits\. Use ast\.literal\_eval only when Python literals are genuinely required, with independent input and resource bounds; it is not a general untrusted\-input sandbox\. | Exercise malformed, oversized and deeply nested values in an isolated test and confirm bounded failure without evaluating names or calls\. |
| 3\. Isolate required generated execution | If code execution is the product feature, route it to a disposable worker with a separate identity, scoped workspace, no ambient credentials, bounded CPU/memory/time and denied\-by\-default egress\. | Attempt a forbidden workspace read, network request and long\-running task in a test worker; retain denials and verify cleanup\. |

**Remaining validation:**

- A permitted operation may still violate tenant or business policy; authorize target resources outside the model\.
- Rescanning can confirm removal of a recognized expression, not sandbox strength or absence of alternate execution paths\.

Related controls: EXEC\-02

Fix guidance sources: [REM\-PY\-AST](https://docs.python.org/3/library/ast.html#ast.literal_eval); [OWASP\-AGENT\-CS](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-95

- [Reference](https://docs.python.org/3/library/security_warnings.html)
- [Reference](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)

<a id="finding-43e902f64605b9e0"></a>

### AI001 — Dynamic Python code execution

**HIGH** · Confidence: medium · Status: open

Location: python/packages/autogen\-core/src/autogen\_core/tools/\_function\_tool\.py:171–171 · Finding ID: `34f362cd01faaef85332b14e`

eval or exec receives a nonliteral expression\. If agent, user, or tool content can reach it, it can execute arbitrary Python\. Static analysis does not establish the full data flow\.

```text
            exec(config.source_code, exec_globals)
```

**Remediation:** Replace dynamic execution with an allowlisted operation dispatcher; use ast\.literal\_eval only for bounded literal parsing\. Isolate unavoidable execution with no ambient credentials and strict resource limits\.

#### Fix plan and agent/MCP relevance

Replace dynamic Python evaluation with a bounded operation interface\.

**Why this matters for agents/MCP:** An agent can convert a prompt or MCP tool result into an eval/exec argument\. If that value reaches this call, model influence becomes Python execution with the tool process identity\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Trace the expression from its producer to this exact call; a nonliteral expression alone does not establish external control or an active agent path\.
- Trusted fixed startup code and deliberately isolated code\-execution services need different treatment; document which boundary applies\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Remove the interpreter boundary | Replace eval/exec with a dictionary of fixed callable operations and validate a small JSON argument schema before selecting a callable\. Do not permit callers to name arbitrary modules, attributes or Python expressions\. | Send unsupported operation names and extra arguments through the same tool entry point; verify rejection before any callable executes\. |
| 2\. Choose a bounded data parser | For data, prefer JSON plus explicit type, length and nesting limits\. Use ast\.literal\_eval only when Python literals are genuinely required, with independent input and resource bounds; it is not a general untrusted\-input sandbox\. | Exercise malformed, oversized and deeply nested values in an isolated test and confirm bounded failure without evaluating names or calls\. |
| 3\. Isolate required generated execution | If code execution is the product feature, route it to a disposable worker with a separate identity, scoped workspace, no ambient credentials, bounded CPU/memory/time and denied\-by\-default egress\. | Attempt a forbidden workspace read, network request and long\-running task in a test worker; retain denials and verify cleanup\. |

**Remaining validation:**

- A permitted operation may still violate tenant or business policy; authorize target resources outside the model\.
- Rescanning can confirm removal of a recognized expression, not sandbox strength or absence of alternate execution paths\.

Related controls: EXEC\-02

Fix guidance sources: [REM\-PY\-AST](https://docs.python.org/3/library/ast.html#ast.literal_eval); [OWASP\-AGENT\-CS](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-95

- [Reference](https://docs.python.org/3/library/security_warnings.html)
- [Reference](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)

<a id="finding-b1e75a0bec774077"></a>

### AI005 — Executable deserialization requires trusted inputs

**HIGH** · Confidence: medium · Status: open

Location: python/packages/autogen\-ext/src/autogen\_ext/experimental/task\_centric\_memory/\_memory\_bank\.py:82–82 · Finding ID: `e7b59756ebdbaf6453e8bf68`

Pickle\-compatible deserialization can execute code\. This finding identifies a dangerous trust boundary, not proof that the serialized input is attacker controlled\.

```text
                self.uid_memo_dict = pickle.load(f)
```

**Remediation:** Use a nonexecutable serialization format with schema validation\. If compatibility requires pickle, accept only authenticated artifacts from a strictly controlled producer\.

#### Fix plan and agent/MCP relevance

Replace executable object deserialization or tightly authenticate its producer\.

**Why this matters for agents/MCP:** A cached agent state, plugin artifact or MCP\-uploaded file may reach pickle\-compatible loading\. Deserialization can execute producer\-selected code before downstream data validation\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Identify the producer and every write path to the artifact, including shared caches, object stores and task workspaces\.
- The finding identifies a dangerous loader; it does not show that its input is attacker controlled\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Migrate to data\-only serialization | Replace pickle, dill, joblib or equivalent object loading with JSON or another nonexecutable format plus a versioned schema\. Reconstruct only explicitly supported application types\. | Roundtrip required benign state and reject unexpected type markers, fields and oversized collections without importing producer\-selected code\. |
| 2\. Control unavoidable legacy artifacts | If compatibility requires executable deserialization, authenticate the exact bytes against a producer/key or registry digest established independently of the artifact location\. Restrict cache and artifact writers\. | Alter one byte and change the producer identity in test artifacts; verify rejection before the deserializer is called\. |
| 3\. Quarantine conversion | Convert legacy artifacts in a disposable credential\-free worker with resource and network limits, then export validated data to the main service\. | Verify conversion cannot read main\-service secrets or contact forbidden destinations and that failed conversions publish no partial trusted state\. |

**Remaining validation:**

- A valid signature identifies a producer; it does not make a compromised or malicious producer safe\.
- Schema validation after pickle loading is too late to prevent execution during loading\.

Related controls: EXEC\-06

Fix guidance sources: [TECH\-PYTHON\-SECURITY](https://docs.python.org/3/library/security_warnings.html); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-502

- [Reference](https://docs.python.org/3/library/security_warnings.html)

<a id="finding-5bbbbf180b68c4f8"></a>

### AI005 — Executable deserialization requires trusted inputs

**HIGH** · Confidence: medium · Status: open

Location: python/packages/autogen\-ext/src/autogen\_ext/experimental/task\_centric\_memory/\_string\_similarity\_map\.py:48–48 · Finding ID: `49ef15a1e06ab2906b0ae813`

Pickle\-compatible deserialization can execute code\. This finding identifies a dangerous trust boundary, not proof that the serialized input is attacker controlled\.

```text
                self.uid_text_dict = pickle.load(f)
```

**Remediation:** Use a nonexecutable serialization format with schema validation\. If compatibility requires pickle, accept only authenticated artifacts from a strictly controlled producer\.

#### Fix plan and agent/MCP relevance

Replace executable object deserialization or tightly authenticate its producer\.

**Why this matters for agents/MCP:** A cached agent state, plugin artifact or MCP\-uploaded file may reach pickle\-compatible loading\. Deserialization can execute producer\-selected code before downstream data validation\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Identify the producer and every write path to the artifact, including shared caches, object stores and task workspaces\.
- The finding identifies a dangerous loader; it does not show that its input is attacker controlled\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Migrate to data\-only serialization | Replace pickle, dill, joblib or equivalent object loading with JSON or another nonexecutable format plus a versioned schema\. Reconstruct only explicitly supported application types\. | Roundtrip required benign state and reject unexpected type markers, fields and oversized collections without importing producer\-selected code\. |
| 2\. Control unavoidable legacy artifacts | If compatibility requires executable deserialization, authenticate the exact bytes against a producer/key or registry digest established independently of the artifact location\. Restrict cache and artifact writers\. | Alter one byte and change the producer identity in test artifacts; verify rejection before the deserializer is called\. |
| 3\. Quarantine conversion | Convert legacy artifacts in a disposable credential\-free worker with resource and network limits, then export validated data to the main service\. | Verify conversion cannot read main\-service secrets or contact forbidden destinations and that failed conversions publish no partial trusted state\. |

**Remaining validation:**

- A valid signature identifies a producer; it does not make a compromised or malicious producer safe\.
- Schema validation after pickle loading is too late to prevent execution during loading\.

Related controls: EXEC\-06

Fix guidance sources: [TECH\-PYTHON\-SECURITY](https://docs.python.org/3/library/security_warnings.html); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-502

- [Reference](https://docs.python.org/3/library/security_warnings.html)

<a id="finding-aeffdafc90f11c4d"></a>

### AI009 — Application debug mode enabled

**MEDIUM** · Confidence: high · Status: open

Location: python/packages/autogen\-studio/autogenstudio/web/app\.py:60–60 · Finding ID: `8f8e715e8f65d28379ca9bd4`

Debug mode is explicitly enabled in server code or configuration\. Depending on the framework and deployment, error details or a debugger may become externally accessible\.

```text
app = FastAPI(lifespan=lifespan, debug=True)
```

**Remediation:** Disable debug mode in deployed services and return sanitized errors while retaining protected server\-side diagnostics\.

#### Fix plan and agent/MCP relevance

Disable deployed debug behavior without losing protected diagnostics\.

**Why this matters for agents/MCP:** An agent API or MCP server may handle secrets, prompts and privileged tools\. A reachable development debugger or verbose exception page can reveal that state and, in some frameworks, permit code execution\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Resolve the framework and final deployment settings; debug behavior varies and a test\-only setting is not evidence of public exposure\.
- A framework debug flag, log level and interactive debugger are different controls and may require separate settings\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Disable runtime debug and debugger switches | Set the production server/framework debug option to false, remove development\-server launch flags, and use the supported production server configuration\. | Start the deployed configuration in staging and trigger a controlled exception; verify there is no interactive debugger or detailed client traceback\. |
| 2\. Separate user errors from protected logs | Return a minimal error identifier and safe message\. Keep detailed server diagnostics in access\-controlled logs with credential/prompt redaction\. | Use a synthetic secret marker in a failing request and confirm it is absent from the HTTP/MCP error and unauthorized log views\. |
| 3\. Prevent accidental re\-enablement | Remove debug overrides from environment files, image defaults and orchestration manifests; require an explicit separate development profile\. | Inspect effective deployment settings and validate the production startup fails or alerts if the development profile is selected\. |

**Remaining validation:**

- Disabling debug does not remove injection defects or secrets already emitted to clients and logs\.

Related controls: DATA\-03

Fix guidance sources: [REM\-FLASK\-DEBUG](https://flask.palletsprojects.com/en/stable/debugging/); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design)

Weakness mappings: CWE\-489

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-189a10a56b01dd40"></a>

### AI033 — Potential secret included in logging call

**MEDIUM** · Confidence: medium · Status: open

Location: python/packages/autogen\-studio/autogenstudio/web/auth/manager\.py:98–98 · Finding ID: `4c41f364f09aeb4440e11ab1`

A logging call directly references a credential\-named variable or field\. Log processors and retention can broaden access to secrets\.

```text
            logger.warning(f"Expired token received: {token[:10]}...")
```

**Remediation:** Log nonsecret identifiers and outcomes; redact credentials before formatting and restrict log access and retention\.

#### Fix plan and agent/MCP relevance

Remove credential values from logging before formatting or export\.

**Why this matters for agents/MCP:** Agent traces and MCP logs commonly cross observability vendors, support systems and retention tiers\. Logging a credential widens who can use the underlying model or tool authority beyond its intended worker\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A credential\-named variable may hold a nonsecret identifier; classify the value and its logging path without disclosing it\.
- Check structured logs, exception serialization, tracing spans and downstream collectors as well as the source logging call\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Log identifiers and outcomes instead | Replace logged secret variables with request IDs, credential fingerprints suitable for the system, or nonsecret status\. Redact at the source before string formatting and serialization\. | Run success/error paths with a synthetic credential marker and confirm it is absent from local logs, structured fields and exported traces\. |
| 2\. Contain confirmed historical exposure | Rotate actual exposed credentials and locate affected log copies, dashboards and exports\. Restrict access and apply the applicable retention/deletion policy\. | Verify the old credential is invalid and unauthorized users cannot query affected log records; retain incident evidence in a protected form\. |
| 3\. Prevent regressions across the pipeline | Add secret\-safe logging helpers and tests for request headers, nested dictionaries and exception objects; avoid logging entire model/client configurations\. | Exercise nested credential fields and failures in the deployed collector path and confirm redaction happens before external transmission\. |

**Remaining validation:**

- Pattern\-based redaction can miss novel secrets or encoded values; minimize collected content and permissions rather than relying on masking alone\.

Related controls: DATA\-03

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-532

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-4e7a3b8d9bf357c3"></a>

### AI033 — Potential secret included in logging call

**MEDIUM** · Confidence: medium · Status: open

Location: python/packages/autogen\-studio/autogenstudio/web/auth/manager\.py:101–101 · Finding ID: `c895143b34bac6dbd8bd111d`

A logging call directly references a credential\-named variable or field\. Log processors and retention can broaden access to secrets\.

```text
            logger.warning(f"Invalid token received: {token[:10]}...")
```

**Remediation:** Log nonsecret identifiers and outcomes; redact credentials before formatting and restrict log access and retention\.

#### Fix plan and agent/MCP relevance

Remove credential values from logging before formatting or export\.

**Why this matters for agents/MCP:** Agent traces and MCP logs commonly cross observability vendors, support systems and retention tiers\. Logging a credential widens who can use the underlying model or tool authority beyond its intended worker\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- A credential\-named variable may hold a nonsecret identifier; classify the value and its logging path without disclosing it\.
- Check structured logs, exception serialization, tracing spans and downstream collectors as well as the source logging call\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Log identifiers and outcomes instead | Replace logged secret variables with request IDs, credential fingerprints suitable for the system, or nonsecret status\. Redact at the source before string formatting and serialization\. | Run success/error paths with a synthetic credential marker and confirm it is absent from local logs, structured fields and exported traces\. |
| 2\. Contain confirmed historical exposure | Rotate actual exposed credentials and locate affected log copies, dashboards and exports\. Restrict access and apply the applicable retention/deletion policy\. | Verify the old credential is invalid and unauthorized users cannot query affected log records; retain incident evidence in a protected form\. |
| 3\. Prevent regressions across the pipeline | Add secret\-safe logging helpers and tests for request headers, nested dictionaries and exception objects; avoid logging entire model/client configurations\. | Exercise nested credential fields and failures in the deployed collector path and confirm redaction happens before external transmission\. |

**Remaining validation:**

- Pattern\-based redaction can miss novel secrets or encoded values; minimize collected content and permissions rather than relying on masking alone\.

Related controls: DATA\-03

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-532

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-bc22c181ad320cef"></a>

### AI024 — Container image is not digest pinned

**LOW** · Confidence: low · Status: open

Location: dotnet/src/Microsoft\.AutoGen/AgentHost/Dockerfile:4–4 · Finding ID: `1b457f2ddf5f7bd1f2b8ff83`

A container base or deployment image uses a mutable reference rather than a content digest\. The bytes can change between builds or deployments\.

```text
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
```

**Remediation:** Pin approved image digests, track provenance and SBOMs, and update through reviewed vulnerability\-remediation workflows\.

#### Fix plan and agent/MCP relevance

Pin the approved image content digest and maintain a reviewed update process\.

**Why this matters for agents/MCP:** Agent/MCP deployments may execute a different tool stack when a mutable image tag moves\. That changes the code holding credentials and enforcing tool policy without a matching application source change\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Inspect the image selected by the actual build/deployment and platform; tags may already be constrained by external admission policy\.
- Digest pinning controls content identity, not whether the pinned content is safe or current\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Record and pin the intended digest | Replace mutable base/deployment references with the approved registry image@sha256 digest, retaining a human\-readable version where useful\. Record the intended platform or multi\-platform index\. | Resolve the approved reference through the build/deployment system and verify the running image digest matches the recorded artifact/platform\. |
| 2\. Review provenance and contents | Associate the digest with build provenance, an SBOM and a separate vulnerability scan; verify the publisher and build process before approving it\. | Trace the selected digest to the expected build and verify the SBOM and vulnerability results apply to that exact artifact\. |
| 3\. Update pins deliberately | Use automation to propose digest updates, rebuild and run agent/MCP regression and policy checks, then roll out the reviewed artifact\. | Exercise rollback to a previously approved digest and confirm updates do not silently widen runtime permissions\. |

**Remaining validation:**

- A digest can preserve a vulnerable version indefinitely if updates are neglected; this scanner does not perform a CVE feed lookup\.

Related controls: SUP\-01, SUP\-03

Fix guidance sources: [REM\-DOCKER\-BUILD](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-829

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-a8da66ae7685eaac"></a>

### AI024 — Container image is not digest pinned

**LOW** · Confidence: low · Status: open

Location: dotnet/src/Microsoft\.AutoGen/AgentHost/Dockerfile:10–10 · Finding ID: `9bda7648d4ee61ecefd32bf1`

A container base or deployment image uses a mutable reference rather than a content digest\. The bytes can change between builds or deployments\.

```text
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
```

**Remediation:** Pin approved image digests, track provenance and SBOMs, and update through reviewed vulnerability\-remediation workflows\.

#### Fix plan and agent/MCP relevance

Pin the approved image content digest and maintain a reviewed update process\.

**Why this matters for agents/MCP:** Agent/MCP deployments may execute a different tool stack when a mutable image tag moves\. That changes the code holding credentials and enforcing tool policy without a matching application source change\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Inspect the image selected by the actual build/deployment and platform; tags may already be constrained by external admission policy\.
- Digest pinning controls content identity, not whether the pinned content is safe or current\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Record and pin the intended digest | Replace mutable base/deployment references with the approved registry image@sha256 digest, retaining a human\-readable version where useful\. Record the intended platform or multi\-platform index\. | Resolve the approved reference through the build/deployment system and verify the running image digest matches the recorded artifact/platform\. |
| 2\. Review provenance and contents | Associate the digest with build provenance, an SBOM and a separate vulnerability scan; verify the publisher and build process before approving it\. | Trace the selected digest to the expected build and verify the SBOM and vulnerability results apply to that exact artifact\. |
| 3\. Update pins deliberately | Use automation to propose digest updates, rebuild and run agent/MCP regression and policy checks, then roll out the reviewed artifact\. | Exercise rollback to a previously approved digest and confirm updates do not silently widen runtime permissions\. |

**Remaining validation:**

- A digest can preserve a vulnerable version indefinitely if updates are neglected; this scanner does not perform a CVE feed lookup\.

Related controls: SUP\-01, SUP\-03

Fix guidance sources: [REM\-DOCKER\-BUILD](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-829

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-c3bb633a271176f8"></a>

### AI024 — Container image is not digest pinned

**LOW** · Confidence: low · Status: open

Location: python/packages/agbench/src/agbench/res/Dockerfile:1–1 · Finding ID: `b0db6980d83276c2aae4395b`

A container base or deployment image uses a mutable reference rather than a content digest\. The bytes can change between builds or deployments\.

```text
FROM mcr.microsoft.com/devcontainers/python:3.11
```

**Remediation:** Pin approved image digests, track provenance and SBOMs, and update through reviewed vulnerability\-remediation workflows\.

#### Fix plan and agent/MCP relevance

Pin the approved image content digest and maintain a reviewed update process\.

**Why this matters for agents/MCP:** Agent/MCP deployments may execute a different tool stack when a mutable image tag moves\. That changes the code holding credentials and enforcing tool policy without a matching application source change\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Inspect the image selected by the actual build/deployment and platform; tags may already be constrained by external admission policy\.
- Digest pinning controls content identity, not whether the pinned content is safe or current\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Record and pin the intended digest | Replace mutable base/deployment references with the approved registry image@sha256 digest, retaining a human\-readable version where useful\. Record the intended platform or multi\-platform index\. | Resolve the approved reference through the build/deployment system and verify the running image digest matches the recorded artifact/platform\. |
| 2\. Review provenance and contents | Associate the digest with build provenance, an SBOM and a separate vulnerability scan; verify the publisher and build process before approving it\. | Trace the selected digest to the expected build and verify the SBOM and vulnerability results apply to that exact artifact\. |
| 3\. Update pins deliberately | Use automation to propose digest updates, rebuild and run agent/MCP regression and policy checks, then roll out the reviewed artifact\. | Exercise rollback to a previously approved digest and confirm updates do not silently widen runtime permissions\. |

**Remaining validation:**

- A digest can preserve a vulnerable version indefinitely if updates are neglected; this scanner does not perform a CVE feed lookup\.

Related controls: SUP\-01, SUP\-03

Fix guidance sources: [REM\-DOCKER\-BUILD](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-829

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-b3091c71a13b232b"></a>

### AI024 — Container image is not digest pinned

**LOW** · Confidence: low · Status: open

Location: python/packages/autogen\-studio/Dockerfile:1–1 · Finding ID: `6b3993abfce0612f48fb97d5`

A container base or deployment image uses a mutable reference rather than a content digest\. The bytes can change between builds or deployments\.

```text
FROM python:3.10-slim
```

**Remediation:** Pin approved image digests, track provenance and SBOMs, and update through reviewed vulnerability\-remediation workflows\.

#### Fix plan and agent/MCP relevance

Pin the approved image content digest and maintain a reviewed update process\.

**Why this matters for agents/MCP:** Agent/MCP deployments may execute a different tool stack when a mutable image tag moves\. That changes the code holding credentials and enforcing tool policy without a matching application source change\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Inspect the image selected by the actual build/deployment and platform; tags may already be constrained by external admission policy\.
- Digest pinning controls content identity, not whether the pinned content is safe or current\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Record and pin the intended digest | Replace mutable base/deployment references with the approved registry image@sha256 digest, retaining a human\-readable version where useful\. Record the intended platform or multi\-platform index\. | Resolve the approved reference through the build/deployment system and verify the running image digest matches the recorded artifact/platform\. |
| 2\. Review provenance and contents | Associate the digest with build provenance, an SBOM and a separate vulnerability scan; verify the publisher and build process before approving it\. | Trace the selected digest to the expected build and verify the SBOM and vulnerability results apply to that exact artifact\. |
| 3\. Update pins deliberately | Use automation to propose digest updates, rebuild and run agent/MCP regression and policy checks, then roll out the reviewed artifact\. | Exercise rollback to a previously approved digest and confirm updates do not silently widen runtime permissions\. |

**Remaining validation:**

- A digest can preserve a vulnerable version indefinitely if updates are neglected; this scanner does not perform a CVE feed lookup\.

Related controls: SUP\-01, SUP\-03

Fix guidance sources: [REM\-DOCKER\-BUILD](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-829

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

## Control checklist and coverage

These are project-defined checks mapped to published guidance. They are not official benchmark scores. `no_pattern_detected` means only that the mapped detector did not fire. `findings_detected` requires investigation, not an automatic compliance failure.

### GOV\-01: Inventory every agent, MCP server, tool, and model

Category: Governance · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Record owner, deployment, model/version, MCP transport/version, exposed tools, data classes, and external endpoints\.
- [ ] Reconcile approved inventory with deployed configurations; investigate unregistered agents and servers\.
- [Source](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10)

### GOV\-02: Model trust boundaries and attack paths

Category: Governance · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Diagram user, model, memory, tool, server, gateway, and downstream service boundaries with their credentials\.
- [ ] Identify who controls each input and the highest\-impact action reachable if that input is malicious\.
- [Source](https://github.com/mitre-atlas/atlas-data)
- [Source](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)

### GOV\-03: Define authorized use and accountable owners

Category: Governance · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Assign an owner to each autonomous action and document permitted purposes, forbidden outcomes, and escalation routes\.
- [ ] Record impact, reversibility, approval requirements, and accepted residual risk before production use\.
- [Source](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10)
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services)

### GOV\-04: Maintain evidence and risk exceptions

Category: Governance · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Give each control an owner, evidence link, validation date, result, and next review date\.
- [ ] Time\-limit exceptions and require a compensating control; distinguish untested behavior from demonstrated failure\.
- [Source](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)
- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)

### GOV\-05: Reassess changes in autonomy and integrations

Category: Governance · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Review security impact when adding a model, tool, server, data source, skill, or broader permission\.
- [ ] Require deployment evidence for the complete configured system; a model\-only score is insufficient\.
- [Source](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development)

### GOV\-06: Assign shared security responsibilities across AI providers

Category: Governance · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] For each model, gateway, orchestrator, MCP service, and cloud provider, document which party implements each applicable safeguard and which customer configuration it depends on\.
- [ ] Obtain current supplier evidence for inherited safeguards, identify unowned gaps, and record reassessment triggers in the service review\.
- [Source](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1)
- [Source](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1)

### AUTH\-01: Authenticate protected operations on every request

Category: Identity and authorization · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Trace authentication to every protected HTTP entry point, including tool calls, subscriptions, and retries\.
- [ ] Verify missing, expired, revoked, or malformed credentials cannot invoke a protected operation\.

Partial static rules: AI026, AI041
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

### AUTH\-02: Authorize the exact action and target

Category: Identity and authorization · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Check user/agent identity, tenant, tool, target object, and requested operation immediately before execution\.
- [ ] Deny by default; test read\-only callers against write tools and object identifiers owned by another user\.

Partial static rules: AI027
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services)
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

### AUTH\-03: Validate access\-token cryptography and claims

Category: Identity and authorization · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Verify signature with trusted keys, allowed algorithms, expected issuer/audience, expiry, and required scopes\.
- [ ] Reject unsigned tokens and tokens minted for another service; decoding a JWT alone is not validation\.

Partial static rules: AI017
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)

### AUTH\-04: Prevent token passthrough and confused deputy use

Category: Identity and authorization · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Use audience\-bound MCP credentials and separately authorized downstream credentials; never forward arbitrary caller tokens\.
- [ ] Ensure a proxy cannot use its broader service identity to perform an action the caller cannot authorize\.

Partial static rules: AI028
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [Source](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

### AUTH\-05: Constrain credential lifetime and exposure

Category: Identity and authorization · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Use short\-lived scoped credentials where supported, protect refresh tokens, and validate rotation and revocation\.
- [ ] Avoid tokens in query strings, model context, source, child\-process arguments, and diagnostic output\.

Partial static rules: AI010, AI011, AI030, AI034
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

### AUTH\-06: Bind OAuth flows and validate redirects

Category: Identity and authorization · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Test PKCE support and S256, exact registered redirects, transaction binding, and authorization\-response issuer validation\.
- [ ] Reject replayed codes, mismatched issuers, unsafe redirect schemes, and unsolicited callback transactions\.

Partial static rules: AI038
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

### AUTH\-07: Secure OAuth discovery and registration

Category: Identity and authorization · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Validate discovered metadata and client metadata URLs before fetching; constrain schemes, destinations, redirects, and response sizes\.
- [ ] Document trust policy for client registration and prevent discovery from reaching internal metadata or privileged network services\.
- [Source](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

### AUTH\-08: Bind delegation to identity, scope, and expiry

Category: Identity and authorization · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Carry authenticated initiator and delegation identity through multi\-agent calls instead of trusting identity fields in text\.
- [ ] Prevent agents from granting themselves privileges; limit delegation scope, depth, lifetime, and downstream audiences\.
- [Source](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)

### AUTH\-09: Manage agent identity enrollment and retirement

Category: Identity and authorization · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Enroll agents under an accountable sponsor and approved workload identity; verify identity claims before issuing credentials or granting discovery and execution access\.
- [ ] Test retirement, sponsor departure, redeployment, and identity compromise; remove stale credentials, cached grants, registrations, and downstream access\.
- [Source](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach)
- [Source](https://www.nccoe.nist.gov/publications/other/accelerating-adoption-software-and-ai-agent-identity-and-authorization-concept)

### MCP\-01: Validate transport exposure and origin

Category: MCP protocol and tools · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] For HTTP, reject invalid Origin values and verify local deployments bind only to intended interfaces\.
- [ ] Use TLS for remote protected endpoints; test DNS rebinding and proxy/header behavior in deployment\.

Partial static rules: AI006, AI007, AI008, AI029
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)

### MCP\-02: Validate tool arguments and results

Category: MCP protocol and tools · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Apply schemas and semantic bounds before executing every tool; reject unknown properties where appropriate\.
- [ ] Bound sizes and nesting; validate declared structured output and render errors without leaking secrets\.
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

### MCP\-03: Treat descriptions and annotations as untrusted

Category: MCP protocol and tools · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Inspect descriptions, schemas, resources, icons, and results for instructions that cross tool or user boundaries\.
- [ ] Never let readOnlyHint, destructiveHint, or other server claims replace independent authorization and approval policy\.
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [Source](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)

### MCP\-04: Detect tool substitution and metadata changes

Category: MCP protocol and tools · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Bind tool approval to verified server identity and the reviewed tool definition or version\.
- [ ] Revalidate changes after reconnect/list updates; disambiguate collisions across servers without trusting display names\.
- [Source](https://owasp.org/projects/mcp-top-10)

### MCP\-05: Protect state handles and legacy sessions

Category: MCP protocol and tools · Status: no\_pattern\_detected · Validation: dynamic

Partial static coverage only; absence of a finding is not a pass

- [ ] Authorize every state handle against its owner and tenant; enforce expiry, unpredictability, and replay boundaries\.
- [ ] For older sessionful protocol versions, test session hijacking and cross\-user resumption; a session ID is not authentication\.

Partial static rules: AI038
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [Source](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

### MCP\-06: Constrain sampling and returned model context

Category: MCP protocol and tools · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Apply host policy and user control to sampling requests, context sharing, model selection, and associated tool access\.
- [ ] Test whether an untrusted server can induce disclosure from unrelated conversations or recursively consume model budget\.
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/client/sampling)

### MCP\-07: Secure elicitation and URL interactions

Category: MCP protocol and tools · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Keep sensitive credential collection out of form\-mode elicitation; validate and visibly identify URL destinations\.
- [ ] Test cancellation, phishing URLs, unsolicited interactions, and replayed completion state against the selected protocol version\.
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)

### MCP\-08: Enforce filesystem isolation independently of roots

Category: MCP protocol and tools · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Treat declared roots as scoped information, not an operating\-system sandbox or complete authorization mechanism\.
- [ ] Enforce allowed paths at file access and test traversal, symlinks, alternate encodings, and writes outside the workspace\.

Partial static rules: AI015
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/client/roots)

### MCP\-09: Constrain local server launch and inherited environment

Category: MCP protocol and tools · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Approve executable and package identity before starting a stdio server; use argument arrays and a minimal environment\.
- [ ] Restrict proxy process\-spawn APIs and child filesystem/network permissions; separate stdout protocol traffic from logs\.

Partial static rules: AI018, AI031
- [Source](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- [Source](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)

### MCP\-10: Apply version\-aware metadata, caching, and cancellation

Category: MCP protocol and tools · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Record supported revisions and test their capability, metadata, header consistency, stream, and cancellation rules\.
- [ ] Prevent caches and request continuations from crossing authorization contexts; do not apply legacy handshake assumptions universally\.
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports)
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)

### AGT\-01: Enforce action policy outside the model

Category: Agent behavior and context · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Place allow/deny decisions at the execution boundary using trusted policy inputs and constrained tool capabilities\.
- [ ] Show that an injected instruction cannot disable policy, choose privileged credentials, or bypass approval\.

Partial static rules: AI027, AI031
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses)

### AGT\-02: Bind approval to the action executed

Category: Agent behavior and context · Status: no\_pattern\_detected · Validation: dynamic

Partial static coverage only; absence of a finding is not a pass

- [ ] Present actual recipient, target, arguments, data disclosure, and consequences for high\-impact approval\.
- [ ] Invalidate approval if arguments or target change; test races, delayed retries, and approval reuse\.

Partial static rules: AI031
- [Source](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)

### AGT\-03: Separate untrusted content from authoritative instructions

Category: Agent behavior and context · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Track origin and trust level for web pages, documents, messages, OCR, tool results, and repository instructions\.
- [ ] Test direct and indirect goal hijacking; formatting delimiters and prompt warnings alone are not access controls\.

Partial static rules: AI032
- [Source](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)

### AGT\-04: Protect retrieval and persistent memory

Category: Agent behavior and context · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Enforce document and memory ACLs at retrieval and update time, including vector search metadata filters\.
- [ ] Test poisoned memory persistence, cross\-tenant retrieval, provenance loss, deletion, and stale privileged context\.
- [Source](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

### AGT\-05: Keep objectives and authority bounded across agents

Category: Agent behavior and context · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Constrain delegated tasks and verify messages against authenticated senders, expected schemas, and allowed transitions\.
- [ ] Test impersonation, conflicting instructions, cascading failure, and privilege growth across handoffs\.
- [Source](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

### AGT\-06: Protect agent configuration and skills

Category: Agent behavior and context · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Inventory skill files, prompts, hooks, memory seed files, MCP configuration, and other executable workflow inputs\.
- [ ] Require review for changes that add commands, access, or persistence; external repository text cannot become trusted policy\.
- [Source](https://github.com/mitre-atlas/atlas-data)
- [Source](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development)

### AGT\-07: Prevent sensitive context leaving through legitimate tools

Category: Agent behavior and context · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Apply destination and data policies to URLs, searches, tickets, messages, uploads, and telemetry generated by agents\.
- [ ] Use canary data to test encoded leakage and combinations of otherwise permitted tools\.
- [Source](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)

### EXEC\-01: Prevent shell and command injection

Category: Execution and application security · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Find shell execution and constructed command strings; use fixed executables, argument arrays, and allowed argument values\.
- [ ] Test untrusted tool inputs containing shell syntax, option injection, command substitution, and hostile filenames\.

Partial static rules: AI002, AI003, AI012
- [Source](https://owasp.org/projects/mcp-top-10)
- [Source](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

### EXEC\-02: Constrain generated\-code execution

Category: Execution and application security · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Locate eval, exec, dynamic imports, templates, notebooks, and interpreter tools accepting model or user content\.
- [ ] Run required code execution in a disposable restricted environment with explicit filesystem, network, CPU, and time limits\.

Partial static rules: AI001, AI013

Open finding IDs: 3267af939c6985b894806d14, 34f362cd01faaef85332b14e
- [Source](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)

### EXEC\-03: Parameterize database and query operations

Category: Execution and application security · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Use bound query parameters and allowed query shapes; inspect SQL, NoSQL, graph, and search\-language construction\.
- [ ] Separate read/write database identities and test whether generated queries can escape permitted objects or operations\.

Partial static rules: AI036
- [Source](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

### EXEC\-04: Constrain file and archive access

Category: Execution and application security · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Resolve and enforce allowed paths at access time; constrain uploads, downloads, extraction, temporary files, and permissions\.
- [ ] Test symlink races, archive traversal, absolute paths, overwrite attempts, and secret\-directory reads\.

Partial static rules: AI015, AI016, AI037
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/client/roots)
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

### EXEC\-05: Prevent SSRF and unsafe network destinations

Category: Execution and application security · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Restrict destinations and schemes at connection time; revalidate DNS resolution and each redirect\.
- [ ] Test loopback, private/link\-local IPv4 and IPv6, cloud metadata, alternate encodings, and redirect\-to\-private cases\.

Partial static rules: AI014
- [Source](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

### EXEC\-06: Reject unsafe parsing and deserialization

Category: Execution and application security · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Inspect pickle, unsafe YAML, object deserialization, XML entity expansion, and unconstrained recursive parsers\.
- [ ] Use data\-only formats with byte, nesting, and type limits; test malformed input and expansion attacks\.

Partial static rules: AI004, AI005, AI035

Open finding IDs: e7b59756ebdbaf6453e8bf68, 49ef15a1e06ab2906b0ae813
- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)

### EXEC\-07: Render model and tool output safely

Category: Execution and application security · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Use context\-specific escaping for HTML/Markdown, avoid unsafe DOM sinks, and validate links and embedded media\.
- [ ] Test active SVG/HTML, malicious URLs, terminal escapes, and spreadsheet formulas in exported reports\.

Partial static rules: AI039, AI040
- [Source](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

### DATA\-01: Detect and remove embedded credentials

Category: Data and privacy · Status: no\_pattern\_detected · Validation: static

Partial static coverage only; absence of a finding is not a pass

- [ ] Inspect code, examples, configuration, notebooks, test fixtures, and generated artifacts for secret\-like values\.
- [ ] Verify actual exposures with the owner, rotate real credentials, and remove them from reachable history and artifacts\.

Partial static rules: AI010, AI011, AI030, AI034
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

### DATA\-02: Minimize data sent to models and gateways

Category: Data and privacy · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Map which prompts, tool outputs, memory, and code leave the environment and identify the receiving provider/gateway\.
- [ ] Document allowed data classes, processing location, retention, and training use; redact before transmission where required\.
- [Source](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)

### DATA\-03: Protect logs, traces, and error responses

Category: Data and privacy · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Redact secrets and sensitive payloads before logs, traces, exception strings, and dashboards persist them\.
- [ ] Test the failure paths and provider errors as well as success paths; restrict access and export destinations\.

Partial static rules: AI009, AI033

Open finding IDs: 8f8e715e8f65d28379ca9bd4, 4c41f364f09aeb4440e11ab1, c895143b34bac6dbd8bd111d
- [Source](https://owasp.org/projects/mcp-top-10)

### DATA\-04: Track provenance and integrity of AI data

Category: Data and privacy · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Record source, owner, version, transformation history, and integrity evidence for datasets, retrieval corpora, and memory seeds\.
- [ ] Quarantine unexpected changes and test how poisoned or stale data is detected, removed, and replaced\.
- [Source](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/)

### DATA\-05: Enforce retention and deletion across copies

Category: Data and privacy · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Apply expiry and deletion to prompts, embeddings, caches, memory, tool artifacts, backups, and provider\-held data\.
- [ ] Verify deleting a source record removes or invalidates dependent retrieval content and access grants\.
- [Source](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)

### DATA\-06: Protect stored data and keys

Category: Data and privacy · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Check transport verification, storage access controls, encryption settings, key separation, and backup permissions\.
- [ ] Validate key rotation and denied access using a principal outside the authorized tenant or operational role\.
- [Source](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/)
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

### SUP\-01: Pin and inventory executable dependencies

Category: Supply chain · Status: findings\_detected · Validation: static

Partial static coverage only; absence of a finding is not a pass

- [ ] Review lockfiles and exact versions or immutable digests for packages, images, MCP servers, models, and plugins\.
- [ ] Flag runtime installs, floating tags, remote scripts, and dependency sources outside approved registries\.

Partial static rules: AI018, AI024, AI025

Open finding IDs: 1b457f2ddf5f7bd1f2b8ff83, 9bda7648d4ee61ecefd32bf1, b0db6980d83276c2aae4395b, 6b3993abfce0612f48fb97d5
- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)

### SUP\-02: Check vulnerability and maintenance exposure

Category: Supply chain · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Run appropriate package/container advisory tools against resolved dependencies and save database date and tool version\.
- [ ] Triage reachability, fix availability, support status, and transitive dependencies; source pattern scans do not establish CVE coverage\.
- [Source](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development)

### SUP\-03: Verify artifact identity and provenance

Category: Supply chain · Status: findings\_detected · Validation: manual

Partial static coverage only; absence of a finding is not a pass

- [ ] Verify publisher identity, hashes/signatures, build provenance, and intended origin before enabling artifacts\.
- [ ] Review model loading and serialization behavior; an integrity hash cannot make an untrusted publisher safe\.

Partial static rules: AI019, AI024, AI035

Open finding IDs: 1b457f2ddf5f7bd1f2b8ff83, 9bda7648d4ee61ecefd32bf1, b0db6980d83276c2aae4395b, 6b3993abfce0612f48fb97d5
- [Source](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/)
- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)

### SUP\-04: Protect build, release, and configuration changes

Category: Supply chain · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Restrict CI credentials and workflow permissions; review actions, build scripts, and release provenance\.
- [ ] Prevent untrusted contributions from executing with deployment secrets or changing approved agent policies\.

Partial static rules: AI020
- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)

### SUP\-05: Harden runtime isolation and deployment defaults

Category: Supply chain · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Review root/privileged containers, host mounts, Docker sockets, unrestricted egress, debug mode, and public management endpoints\.
- [ ] Separate agent execution from control\-plane credentials and audit storage; test isolation in the deployed environment\.

Partial static rules: AI021, AI022, AI023, AI031, AI042
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

### SUP\-06: Separate and protect model development environments

Category: Supply chain · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] When training or fine\-tuning, isolate development, evaluation, and production identities, data access, registries, and release permissions\.
- [ ] Protect datasets, weights, adapters, and configuration separately; monitor modifications and demonstrate that an untrusted training job cannot replace an approved production artifact\.
- [Source](https://csrc.nist.gov/pubs/sp/800/218/a/final)

### OPS\-01: Produce attributable audit events

Category: Operations and resilience · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Record initiating identity, delegated identity, tool/server/version, approved arguments, decision, outcome, and correlation identifiers\.
- [ ] Protect log integrity and clock consistency; ensure agents cannot erase their own action history\.
- [Source](https://owasp.org/projects/mcp-top-10)

### OPS\-02: Bound work, spending, and concurrency

Category: Operations and resilience · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Set server\-enforced limits for iterations, tokens, tool calls, recursion, parallelism, bytes, cost, and elapsed time\.
- [ ] Exercise stuck loops and amplification paths; verify limits apply across retries and child agents\.
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses)

### OPS\-03: Make cancellation and shutdown effective

Category: Operations and resilience · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Provide a tested stop mechanism that revokes work, credentials, queued actions, and child tasks\.
- [ ] Measure stop latency and verify cancelled or disconnected requests cannot later commit prohibited side effects\.
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services)

### OPS\-04: Fail safely and prevent duplicate side effects

Category: Operations and resilience · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Deny or escalate when policy, identity, or approval checks fail; prevent fallback paths from widening privilege\.
- [ ] Test outages, partial failures, timeouts, retries, idempotency, and recovery of transactions with external effects\.
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses)

### OPS\-05: Monitor behavior and support rollback

Category: Operations and resilience · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Alert on unusual tool use, new destinations, scope growth, repeated denials, cost spikes, and unexpected state changes\.
- [ ] Validate alerts with seeded events and test rollback of models, prompts, tools, policies, and poisoned memory\.
- [Source](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development)

### OPS\-06: Practice incident response and disclosure

Category: Operations and resilience · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Maintain procedures to isolate agents, revoke credentials, preserve evidence, notify owners, and recover trusted state\.
- [ ] Exercise an AI\-specific incident and define approved vulnerability/intelligence\-sharing channels without exposing sensitive evidence\.
- [Source](https://www.cisa.gov/news-events/alerts/2025/01/14/cisa-releases-jcdc-ai-cybersecurity-collaboration-playbook-and-fact-sheet)

### TEST\-01: Measure prompt\-injection security and useful task completion

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Run paired benign and adversarial workflows with representative tools and attacker\-controlled external content\.
- [ ] Record attacker success, authorized task success, blocked benign actions, and the observed unauthorized side effect\.
- [Source](https://github.com/ethz-spylab/agentdojo)
- [Source](https://github.com/uiuc-kang-lab/InjecAgent)

### TEST\-02: Test adaptively and repeat scenarios

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Vary payload wording, placement, modality, attacker knowledge, and attempts; rerun after changing defenses\.
- [ ] Report per\-scenario outcomes, sample counts, attack budget, uncertainty, and model/harness versions instead of only an average\.
- [Source](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations)

### TEST\-03: Exercise MCP authentication and protocol abuse

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] In an isolated test environment, exercise invalid tokens, wrong audiences, origin abuse, malicious servers, and protocol fuzzing\.
- [ ] Adapt scenarios to the deployed MCP revision and transports; preserve request/response evidence with secrets removed\.
- [Source](https://github.com/AIS2Lab/MCPSecBench)
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

### TEST\-04: Verify cross\-tenant and cross\-agent isolation

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Create two principals and attempt cross\-access to objects, memory, caches, handles, subscriptions, and execution results\.
- [ ] Repeat after reconnect, delegation, failed authentication, concurrent requests, and privilege revocation\.
- [Source](https://github.com/agiresearch/ASB)

### TEST\-05: Test approval, policy, and sandbox bypass

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Use explicit forbidden\-action canaries to verify enforcement survives hostile content, tool substitution, and delayed execution\.
- [ ] Confirm paths through retries, fallback models, alternate tools, and child agents enforce the same boundary\.
- [Source](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)

### TEST\-06: Verify conventional application security

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Run language\-aware SAST, dependency review, secret scanning, and authorized integration tests for exposed services\.
- [ ] Exercise reachable injection, XSS, SSRF, path traversal, deserialization, and access\-control risks with safe fixtures\.
- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)
- [Source](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

### TEST\-07: Validate resource exhaustion and observability

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Simulate oversized messages, slow peers, streaming floods, repeated errors, runaway agents, and unavailable dependencies\.
- [ ] Verify quotas, shutdown, telemetry, and alerts work together without leaking payloads or losing attribution\.
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses)

### TEST\-08: Evaluate the optional security judge itself

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Treat repository text and model verdicts as untrusted; test prompt injection, fabricated locations, invalid JSON, and timeouts\.
- [ ] Compare against labeled cases, retain deterministic results, document model variability, and never equate a judge approval with control validation\.
- [Source](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations)
- [Source](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)

### TEST\-09: Evaluate model\-layer attacks for hosted or customized models

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Where applicable, assess suspicious triggers, model extraction, and disclosure of private training examples under an explicit attacker access and query budget\.
- [ ] Retest acquired or retrained models and adapters before release; document measured failures, model identity, coverage limits, and accepted residual risk\.
- [Source](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro)
- [Source](https://csrc.nist.gov/pubs/sp/800/218/a/final)

## Coverage and limitations

- Static pattern and local syntax analysis do not prove exploitability, authentication, isolation, or absence of vulnerabilities\.
- Python receives AST\-based call checks; other source languages receive selected textual/configuration checks, not whole\-program dataflow\.
- No dependencies are installed, target code executed, services contacted, or CVE feed queried\.
- Default excluded directories and unsupported files remain outside the selected scan scope\.
- Prompt injection resistance, authorization, tenant separation, runtime egress, and human approval need adversarial/runtime validation\.
- Evidence redaction is best\-effort; reports and optional judge payloads can still contain sensitive code or data\.

### Inventory

Dependency manifests: 11; agent/MCP signal files: 499.

Dependency manifests are inventoried, not checked against a vulnerability database.

### Scan errors

None.

### Excluded or skipped paths

| Path | Reason | Coverage gap |
|---|---|---|
| dotnet/src/AutoGen\.Anthropic/AutoGen\.Anthropic\.csproj | unsupported\_extension | outside scope |
| dotnet/src/AutoGen\.AzureAIInference/AutoGen\.AzureAIInference\.csproj | unsupported\_extension | outside scope |
| dotnet/src/AutoGen\.Core/AutoGen\.Core\.csproj | unsupported\_extension | outside scope |
| dotnet/src/AutoGen\.DotnetInteractive/AutoGen\.DotnetInteractive\.csproj | unsupported\_extension | outside scope |
| dotnet/src/AutoGen\.Gemini/AutoGen\.Gemini\.csproj | unsupported\_extension | outside scope |
| dotnet/src/AutoGen\.LMStudio/AutoGen\.LMStudio\.csproj | unsupported\_extension | outside scope |
| dotnet/src/AutoGen\.Mistral/AutoGen\.Mistral\.csproj | unsupported\_extension | outside scope |
| dotnet/src/AutoGen\.Ollama/AutoGen\.Ollama\.csproj | unsupported\_extension | outside scope |
| dotnet/src/AutoGen\.OpenAI\.V1/AutoGen\.OpenAI\.V1\.csproj | unsupported\_extension | outside scope |
| dotnet/src/AutoGen\.OpenAI/AutoGen\.OpenAI\.csproj | unsupported\_extension | outside scope |
| dotnet/src/AutoGen\.SemanticKernel/AutoGen\.SemanticKernel\.csproj | unsupported\_extension | outside scope |
| dotnet/src/AutoGen\.SourceGenerator/AutoGen\.SourceGenerator\.csproj | unsupported\_extension | outside scope |
| dotnet/src/AutoGen\.WebAPI/AutoGen\.WebAPI\.csproj | unsupported\_extension | outside scope |
| dotnet/src/AutoGen/AutoGen\.csproj | unsupported\_extension | outside scope |
| dotnet/src/Microsoft\.AutoGen/AgentChat/Microsoft\.AutoGen\.AgentChat\.csproj | unsupported\_extension | outside scope |
| dotnet/src/Microsoft\.AutoGen/AgentHost/Microsoft\.AutoGen\.AgentHost\.csproj | unsupported\_extension | outside scope |
| dotnet/src/Microsoft\.AutoGen/Agents/Microsoft\.AutoGen\.Agents\.csproj | unsupported\_extension | outside scope |
| dotnet/src/Microsoft\.AutoGen/Agents/protos/agent\_events\.proto | unsupported\_extension | outside scope |
| dotnet/src/Microsoft\.AutoGen/Contracts/Microsoft\.AutoGen\.Contracts\.csproj | unsupported\_extension | outside scope |
| dotnet/src/Microsoft\.AutoGen/Core\.Grpc/Microsoft\.AutoGen\.Core\.Grpc\.csproj | unsupported\_extension | outside scope |
| dotnet/src/Microsoft\.AutoGen/Core/Microsoft\.AutoGen\.Core\.csproj | unsupported\_extension | outside scope |
| dotnet/src/Microsoft\.AutoGen/Extensions/Aspire/Microsoft\.AutoGen\.Extensions\.Aspire\.csproj | unsupported\_extension | outside scope |
| dotnet/src/Microsoft\.AutoGen/Extensions/MEAI/Microsoft\.AutoGen\.Extensions\.MEAI\.csproj | unsupported\_extension | outside scope |
| dotnet/src/Microsoft\.AutoGen/Extensions/SemanticKernel/Microsoft\.AutoGen\.Extensions\.SemanticKernel\.csproj | unsupported\_extension | outside scope |
| dotnet/src/Microsoft\.AutoGen/RuntimeGateway\.Grpc/Microsoft\.AutoGen\.RuntimeGateway\.Grpc\.csproj | unsupported\_extension | outside scope |
| python/packages/autogen\-studio/frontend/src/components/views/teambuilder/builder/builder\.css | unsupported\_extension | outside scope |
| python/packages/autogen\-studio/frontend/src/styles/global\.css | unsupported\_extension | outside scope |

## Optional LLM judge

Disabled. No LLM request was made.
## Editable review and fresh scan

Edit only decision, reason, reviewer, reviewed_at and evidence_ref in the JSON block below. Keep IDs, bindings, subjects and origin unchanged. Save this Markdown file and pass it to a fresh scan with --review-report. JSON and SARIF expose the same editable fields; HTML provides a Download reviewed HTML button and optional PDF provides fillable fields.

Allowed decisions: empty (no decision), justified, disabled, note, needs_runtime_validation, needs_human_review. Nonempty decisions need a reason; justified/disabled decisions also need a reviewer. Evidence references are plain text, never fetched or executed. Gap records cannot waive scan failures.

Justifications are user exceptions, not validated passes. They are excluded from active counts without positive or negative credit. Evidence changes leave decisions unapplied and visible for re-review. Explicit pending runtime/human validation remains incomplete. A finding not detected on a fresh complete scan is not proof that a vulnerability was fixed.

Example: invscan /explicit/path/to/repository --review-report ./reviewed-report.md --output ./new-report

### Review fields

<!-- INVARUNE_REVIEW_BEGIN -->
```json
{
  "items": [
    {
      "binding_sha256": "f0eade5e3441459d54ebba4849933e6d6c42f3f50e5899ea821ccfaa8166786f",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:3267af939c6985b894806d14",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI001 Dynamic Python code execution \u2014 python/packages/autogen-core/src/autogen_core/tools/_function_tool.py:159"
    },
    {
      "binding_sha256": "7bac19c71e9604afe7cfd33865425bc5cf3d565599c957505478057889a22e8b",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:34f362cd01faaef85332b14e",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI001 Dynamic Python code execution \u2014 python/packages/autogen-core/src/autogen_core/tools/_function_tool.py:171"
    },
    {
      "binding_sha256": "334fe5c408d28fb2fde7931e5d2b1622871c58b33d804899156a251a7e585928",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:e7b59756ebdbaf6453e8bf68",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI005 Executable deserialization requires trusted inputs \u2014 python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/_memory_bank.py:82"
    },
    {
      "binding_sha256": "48666bfff61fd47acb769505e2c37fda6cbdb4badac8cabaf8f4e1609bb61c4f",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:49ef15a1e06ab2906b0ae813",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI005 Executable deserialization requires trusted inputs \u2014 python/packages/autogen-ext/src/autogen_ext/experimental/task_centric_memory/_string_similarity_map.py:48"
    },
    {
      "binding_sha256": "589f118130e697cb7879ed59862475735500523f18be692fc95c6f2fc4021d28",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:8f8e715e8f65d28379ca9bd4",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI009 Application debug mode enabled \u2014 python/packages/autogen-studio/autogenstudio/web/app.py:60"
    },
    {
      "binding_sha256": "1858afb74eff4ace37e2d74b9ab84a7408017fbf745be61abde2cb3d6e38a88e",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:4c41f364f09aeb4440e11ab1",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI033 Potential secret included in logging call \u2014 python/packages/autogen-studio/autogenstudio/web/auth/manager.py:98"
    },
    {
      "binding_sha256": "bb03fa781819a9593f3653ff1a3637c22098be76a07f3426b1143fa240f250bf",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:c895143b34bac6dbd8bd111d",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI033 Potential secret included in logging call \u2014 python/packages/autogen-studio/autogenstudio/web/auth/manager.py:101"
    },
    {
      "binding_sha256": "48cb4299c7076ccef73952496ff9b1b0d5f2b9991f9a7293ea7fbcb5d8fb190d",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:1b457f2ddf5f7bd1f2b8ff83",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI024 Container image is not digest pinned \u2014 dotnet/src/Microsoft.AutoGen/AgentHost/Dockerfile:4"
    },
    {
      "binding_sha256": "76c839dd4de6d846f7d21e67ea950608149eb1928a6bb3a2a91c917df74f705b",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:9bda7648d4ee61ecefd32bf1",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI024 Container image is not digest pinned \u2014 dotnet/src/Microsoft.AutoGen/AgentHost/Dockerfile:10"
    },
    {
      "binding_sha256": "5e4e88cddf5cc5b9581534ed024a2f49134aa4d8052e5583ddbeca44a365ec4e",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:b0db6980d83276c2aae4395b",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI024 Container image is not digest pinned \u2014 python/packages/agbench/src/agbench/res/Dockerfile:1"
    },
    {
      "binding_sha256": "b329cf9a74da04a107d9bed9fbaf97b971b473226d33e5ba6712f693620ba8d4",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:6b3993abfce0612f48fb97d5",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI024 Container image is not digest pinned \u2014 python/packages/autogen-studio/Dockerfile:1"
    },
    {
      "binding_sha256": "fabb9027e96b49fc1cb5f51ca777ed307f80b2ea247cd70e627c3447f1b3be89",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-01:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-01:1 Record owner, deployment, model/version, MCP transport/version, exposed tools, data classes, and external endpoints."
    },
    {
      "binding_sha256": "74282461dac3ccf978063413c21597747e6446dceb04b027222c1737eca048c4",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-01:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-01:2 Reconcile approved inventory with deployed configurations; investigate unregistered agents and servers."
    },
    {
      "binding_sha256": "a9a002615634fc915147456ef8946479b7adfd3850a5fabc173875b7b183fa82",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-02:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-02:1 Diagram user, model, memory, tool, server, gateway, and downstream service boundaries with their credentials."
    },
    {
      "binding_sha256": "397f6d59ea3ed61538fe7c17131de6b20026a697777f8c393c05e972ee2fac26",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-02:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-02:2 Identify who controls each input and the highest-impact action reachable if that input is malicious."
    },
    {
      "binding_sha256": "10aa89e7736f4a394f26d91d2b5b942d98ea914970361d0123abcb513e0a9089",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-03:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-03:1 Assign an owner to each autonomous action and document permitted purposes, forbidden outcomes, and escalation routes."
    },
    {
      "binding_sha256": "e446f8b794afb44ce94f5631d04fb805d29fc3bb57daac948efec8092f0deb58",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-03:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-03:2 Record impact, reversibility, approval requirements, and accepted residual risk before production use."
    },
    {
      "binding_sha256": "5967f2f8a0f4f5322dda720ded46ba4c7817f7b33d267d9a491f04e102a21e19",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-04:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-04:1 Give each control an owner, evidence link, validation date, result, and next review date."
    },
    {
      "binding_sha256": "4dcaebcac1ed12cf8e0909ab9c60dc1ee9163f488938f9da694703db14a5c09f",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-04:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-04:2 Time-limit exceptions and require a compensating control; distinguish untested behavior from demonstrated failure."
    },
    {
      "binding_sha256": "844e0330264bced8807663305dea2bf16ef2e06f22454a78f95ab34ee9deba1d",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-05:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-05:1 Review security impact when adding a model, tool, server, data source, skill, or broader permission."
    },
    {
      "binding_sha256": "693ae4ee765bb18471911435b10d931ff08bfb38d3f254232b9412c3ab75520e",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-05:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-05:2 Require deployment evidence for the complete configured system; a model-only score is insufficient."
    },
    {
      "binding_sha256": "86c6273d301758c6d38fd70c3b120c648af4177996a48396b06b56514b6fb95a",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-06:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-06:1 For each model, gateway, orchestrator, MCP service, and cloud provider, document which party implements each applicable safeguard and which customer configuration it depends on."
    },
    {
      "binding_sha256": "b9d5e1015f91eeb3d79b6432b1c626b43e952ce728c9d5224b405b02cbd4d654",
      "decision": "",
      "evidence_ref": "",
      "id": "check:GOV-06:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "GOV-06:2 Obtain current supplier evidence for inherited safeguards, identify unowned gaps, and record reassessment triggers in the service review."
    },
    {
      "binding_sha256": "15a50a16e3b96969aa327e384d4f3022214680060b0dd9a30721f628898185d1",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-01:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-01:1 Trace authentication to every protected HTTP entry point, including tool calls, subscriptions, and retries."
    },
    {
      "binding_sha256": "75cdfb646a579b7e54d4349418d4391a979c60e5d8a28cef7d7e0519249c2fac",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-01:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-01:2 Verify missing, expired, revoked, or malformed credentials cannot invoke a protected operation."
    },
    {
      "binding_sha256": "a8db7c42a51b610cec830d9c6c98263f54d9cd64e3462c4aa66af9aa6cc04fa7",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-02:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-02:1 Check user/agent identity, tenant, tool, target object, and requested operation immediately before execution."
    },
    {
      "binding_sha256": "30e12e7ccd6fe44f536d93bb238c95160b3ea6f2c90fa3ae9bf46b0914f426ed",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-02:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-02:2 Deny by default; test read-only callers against write tools and object identifiers owned by another user."
    },
    {
      "binding_sha256": "0960fc2fe3c1ecede8c32ed12b4a9657cf51e6f17d3a89ec8a12ac09147f1ec9",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-03:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-03:1 Verify signature with trusted keys, allowed algorithms, expected issuer/audience, expiry, and required scopes."
    },
    {
      "binding_sha256": "11675e57dcbd139f581c3181eafbdf3f71fdf00817348dd3e7596e3b5720bd51",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-03:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-03:2 Reject unsigned tokens and tokens minted for another service; decoding a JWT alone is not validation."
    },
    {
      "binding_sha256": "d4d55185e620d6a8866a22d95d5412eb999bca20825e80fd3546afec674101f8",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-04:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-04:1 Use audience-bound MCP credentials and separately authorized downstream credentials; never forward arbitrary caller tokens."
    },
    {
      "binding_sha256": "d3e592436514b5d3c551a517af3998b34a3913746c25e3c7df252d2e1cae556f",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-04:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-04:2 Ensure a proxy cannot use its broader service identity to perform an action the caller cannot authorize."
    },
    {
      "binding_sha256": "fbc7e62b520b94c34d0e2e738a829ce2b2e2b921aaa87b197d00a4e5ff77dbcc",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-05:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-05:1 Use short-lived scoped credentials where supported, protect refresh tokens, and validate rotation and revocation."
    },
    {
      "binding_sha256": "d7b94b71e6a53a2c61b91ce712b7abc31017b874f397febbd0593eba931e826e",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-05:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-05:2 Avoid tokens in query strings, model context, source, child-process arguments, and diagnostic output."
    },
    {
      "binding_sha256": "44bd1e7d2a8d4c3bb807cf526d512e918dd3ecc8e883f521b9f0dbe1d0bcfc35",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-06:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-06:1 Test PKCE support and S256, exact registered redirects, transaction binding, and authorization-response issuer validation."
    },
    {
      "binding_sha256": "c19e8a6604fa56b54d8dbeef55192c42d04cd83269beb2d90b4639ab3b7f8ee0",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-06:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-06:2 Reject replayed codes, mismatched issuers, unsafe redirect schemes, and unsolicited callback transactions."
    },
    {
      "binding_sha256": "5654cf2835b301fcb3150c7be8f269f31f46648b60830e4eb877fffe2484c4f3",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-07:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-07:1 Validate discovered metadata and client metadata URLs before fetching; constrain schemes, destinations, redirects, and response sizes."
    },
    {
      "binding_sha256": "afaac89d0bf57696f7b48356f2f34a0a496246cdfc9dc5775b31f4dfe6ee9e17",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-07:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-07:2 Document trust policy for client registration and prevent discovery from reaching internal metadata or privileged network services."
    },
    {
      "binding_sha256": "2424c78bd35e3ff2577de52d8c787611a967a57c4e83f9699261b3a8ef8dc1bc",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-08:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-08:1 Carry authenticated initiator and delegation identity through multi-agent calls instead of trusting identity fields in text."
    },
    {
      "binding_sha256": "2b4331feee6939d040526492bd5957ebd32bb80923018d3a666214c09201d626",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-08:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-08:2 Prevent agents from granting themselves privileges; limit delegation scope, depth, lifetime, and downstream audiences."
    },
    {
      "binding_sha256": "71de7d2a2bee865afcf80c66bc94ef65fffb130bc9205a7a6eb30cb6d6c073ea",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-09:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-09:1 Enroll agents under an accountable sponsor and approved workload identity; verify identity claims before issuing credentials or granting discovery and execution access."
    },
    {
      "binding_sha256": "9b583c0fc873cb55cae330dba5d5f90b74dcbce5193ffcd5f79012e320924ff1",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AUTH-09:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AUTH-09:2 Test retirement, sponsor departure, redeployment, and identity compromise; remove stale credentials, cached grants, registrations, and downstream access."
    },
    {
      "binding_sha256": "0c2a1f9f4272219a6210322a39239b2a58366c62819e52b6657fb5abaa047c4f",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-01:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-01:1 For HTTP, reject invalid Origin values and verify local deployments bind only to intended interfaces."
    },
    {
      "binding_sha256": "ad3f2634f322f74f782ed80ebd86074596944e6523833e3f61971b497a13af3d",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-01:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-01:2 Use TLS for remote protected endpoints; test DNS rebinding and proxy/header behavior in deployment."
    },
    {
      "binding_sha256": "d9a3db35e0ab74792133dab94c01c91b800898cee4c593b35c41599d0750b09f",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-02:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-02:1 Apply schemas and semantic bounds before executing every tool; reject unknown properties where appropriate."
    },
    {
      "binding_sha256": "f1318f00e95ee841512b24316b95d250b6e3c18d0fc608258b6073e51b880909",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-02:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-02:2 Bound sizes and nesting; validate declared structured output and render errors without leaking secrets."
    },
    {
      "binding_sha256": "0f28d8aacaff1de371321bbdd62d8de16f15bfb242f882eccbda9251b525b45a",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-03:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-03:1 Inspect descriptions, schemas, resources, icons, and results for instructions that cross tool or user boundaries."
    },
    {
      "binding_sha256": "97212557a70050b2745d602bf13277dc37fe5f28b18da1a6198dced95f8ca931",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-03:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-03:2 Never let readOnlyHint, destructiveHint, or other server claims replace independent authorization and approval policy."
    },
    {
      "binding_sha256": "8859fd71ec5588869307d7766b568ebf23a4cdc0fd96f0b3c7969a9356ad9048",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-04:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-04:1 Bind tool approval to verified server identity and the reviewed tool definition or version."
    },
    {
      "binding_sha256": "c596769db6f3077288a54a7f3ba27d9c54177dc579cf4a52de8ed78bfaced050",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-04:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-04:2 Revalidate changes after reconnect/list updates; disambiguate collisions across servers without trusting display names."
    },
    {
      "binding_sha256": "37daaca637d003e5b37a5bac2703d2c7cbe0aa5747adf8faeb3d7105f74b6316",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-05:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-05:1 Authorize every state handle against its owner and tenant; enforce expiry, unpredictability, and replay boundaries."
    },
    {
      "binding_sha256": "53ba31ad9dbf5dfad84a481148e71162719ad127a4a00e3f969aa2145eeab530",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-05:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-05:2 For older sessionful protocol versions, test session hijacking and cross-user resumption; a session ID is not authentication."
    },
    {
      "binding_sha256": "3c1a0198c1f9c6dec75da74bdb162941d56f913c2eabd6f0766d4a194b206e64",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-06:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-06:1 Apply host policy and user control to sampling requests, context sharing, model selection, and associated tool access."
    },
    {
      "binding_sha256": "54fec691b06c97aa2737dcc87b73aba6ca334c939aafe8d68ed1394495bc015e",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-06:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-06:2 Test whether an untrusted server can induce disclosure from unrelated conversations or recursively consume model budget."
    },
    {
      "binding_sha256": "0fc9b1d8617ab9430a6546b6c8e0f695dd5c50e0acd4a68c96221f5accd5333a",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-07:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-07:1 Keep sensitive credential collection out of form-mode elicitation; validate and visibly identify URL destinations."
    },
    {
      "binding_sha256": "bef6d560011563f1df2934b0b09b4422eedbd1eaf06650e53345103f9858bbe7",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-07:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-07:2 Test cancellation, phishing URLs, unsolicited interactions, and replayed completion state against the selected protocol version."
    },
    {
      "binding_sha256": "aff5342e4a1f97d599c2a462362b07a6cff301a169b3e2d59774d31742c01194",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-08:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-08:1 Treat declared roots as scoped information, not an operating-system sandbox or complete authorization mechanism."
    },
    {
      "binding_sha256": "8398ab49e5a90fa935b47ee5000490bf6001e2b5f565c7c359328fd6303b7b86",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-08:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-08:2 Enforce allowed paths at file access and test traversal, symlinks, alternate encodings, and writes outside the workspace."
    },
    {
      "binding_sha256": "06dab7ecf928ca09a7a6ae1d7d6d90a98090b6e1f42d4ef748d01e3b49ff3919",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-09:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-09:1 Approve executable and package identity before starting a stdio server; use argument arrays and a minimal environment."
    },
    {
      "binding_sha256": "01d9c7aea14bb4c5a35addd4640a3a8191f64dba72cc1e885ef8b7c45339d5e8",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-09:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-09:2 Restrict proxy process-spawn APIs and child filesystem/network permissions; separate stdout protocol traffic from logs."
    },
    {
      "binding_sha256": "a32f3d82b1315a6cf0e2faf487b79250cea7d6d0d0b0a4ae652e9cdb3e044073",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-10:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-10:1 Record supported revisions and test their capability, metadata, header consistency, stream, and cancellation rules."
    },
    {
      "binding_sha256": "2bea8056f9f63cb47d63fdffb9c23ccb44e77c9b8b3cd2a4f9ba0afad2a736e8",
      "decision": "",
      "evidence_ref": "",
      "id": "check:MCP-10:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "MCP-10:2 Prevent caches and request continuations from crossing authorization contexts; do not apply legacy handshake assumptions universally."
    },
    {
      "binding_sha256": "e165e259a9d9b76834f429bfa70cf90869feac94d66a2147355a380ae22884cc",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-01:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-01:1 Place allow/deny decisions at the execution boundary using trusted policy inputs and constrained tool capabilities."
    },
    {
      "binding_sha256": "3263d7b8225c93bc5d0a107961edd08e780055d0c298912b3f7b69bd156338ac",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-01:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-01:2 Show that an injected instruction cannot disable policy, choose privileged credentials, or bypass approval."
    },
    {
      "binding_sha256": "07c41d53f2840c9959197e5dda80de5593b3e3769d25bf74c5d9ce36b7ee06a0",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-02:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-02:1 Present actual recipient, target, arguments, data disclosure, and consequences for high-impact approval."
    },
    {
      "binding_sha256": "dc482e4bff9586bb511b6ac0d84a4bca4d09a3cfc64e0604128f4ae6a1e8cd5d",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-02:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-02:2 Invalidate approval if arguments or target change; test races, delayed retries, and approval reuse."
    },
    {
      "binding_sha256": "5020a987ef76320eb9127ddaf417e58332e62c9f310c95d9828482507edbd155",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-03:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-03:1 Track origin and trust level for web pages, documents, messages, OCR, tool results, and repository instructions."
    },
    {
      "binding_sha256": "df189ac2360cfdad7d253ccfdcd8d58370ebe7784670ead89fcc2fad17594df7",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-03:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-03:2 Test direct and indirect goal hijacking; formatting delimiters and prompt warnings alone are not access controls."
    },
    {
      "binding_sha256": "464b2557d56de4100985a2ae26f56e0aa586eae6865255e8e1b7b0b746f6f294",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-04:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-04:1 Enforce document and memory ACLs at retrieval and update time, including vector search metadata filters."
    },
    {
      "binding_sha256": "fc5696df768a74dae5d7bc2cbbd5b130f31bd112307171cd7feaba4e5a6b83c6",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-04:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-04:2 Test poisoned memory persistence, cross-tenant retrieval, provenance loss, deletion, and stale privileged context."
    },
    {
      "binding_sha256": "2bf9e077a0ef81fcd94a452251ece0ba2595ccda59e492a5b05c049f25bcb71f",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-05:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-05:1 Constrain delegated tasks and verify messages against authenticated senders, expected schemas, and allowed transitions."
    },
    {
      "binding_sha256": "a1c95eb3f9dc58ab59fffa10f257d57bb8e7caf74b9679ad5787ef9b143d9471",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-05:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-05:2 Test impersonation, conflicting instructions, cascading failure, and privilege growth across handoffs."
    },
    {
      "binding_sha256": "6f7d5d7b0f112805ccb3e6715e9c2a19236d1f5c447938fdcd8459d58607db79",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-06:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-06:1 Inventory skill files, prompts, hooks, memory seed files, MCP configuration, and other executable workflow inputs."
    },
    {
      "binding_sha256": "a6ea48d255d99a01aee428b19ffac001712a02bb5fea0adad65fb33b0ef41cd9",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-06:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-06:2 Require review for changes that add commands, access, or persistence; external repository text cannot become trusted policy."
    },
    {
      "binding_sha256": "b040256b9374bfbb30ea65c1650318c610dd88af47d253a49d7c9c1662f7310e",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-07:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-07:1 Apply destination and data policies to URLs, searches, tickets, messages, uploads, and telemetry generated by agents."
    },
    {
      "binding_sha256": "549f733b3098c8170ba63034c24d24ca811f0b0d55ccfc24ef019b6c72a34493",
      "decision": "",
      "evidence_ref": "",
      "id": "check:AGT-07:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AGT-07:2 Use canary data to test encoded leakage and combinations of otherwise permitted tools."
    },
    {
      "binding_sha256": "70bd4dc2ffbc5daa580591f4e74ed2583a3e3f0c87c9d277914a698ae8d2d2bc",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-01:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-01:1 Find shell execution and constructed command strings; use fixed executables, argument arrays, and allowed argument values."
    },
    {
      "binding_sha256": "0befd991ae4b26c8c2288e74efedb2b2f93f908c74c14d1835a693ab370bd570",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-01:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-01:2 Test untrusted tool inputs containing shell syntax, option injection, command substitution, and hostile filenames."
    },
    {
      "binding_sha256": "38dbb6b3f8f80d1ce92fa79481e2f0f61734904601d25890d924fb37c682a165",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-02:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-02:1 Locate eval, exec, dynamic imports, templates, notebooks, and interpreter tools accepting model or user content."
    },
    {
      "binding_sha256": "7fe36f5ae7cbc038b6f5534b9bc0f6987d86a13ddf5c835db1801f62acfa8170",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-02:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-02:2 Run required code execution in a disposable restricted environment with explicit filesystem, network, CPU, and time limits."
    },
    {
      "binding_sha256": "f3832d1973f9c03b9b841b08484357bb5b2c4effbac0903ff617a61d0fff0dda",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-03:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-03:1 Use bound query parameters and allowed query shapes; inspect SQL, NoSQL, graph, and search-language construction."
    },
    {
      "binding_sha256": "5cc37f31d3c065c86ec66b809a62d1ae9c84a84fe3be4418a5b32c53e1d840df",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-03:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-03:2 Separate read/write database identities and test whether generated queries can escape permitted objects or operations."
    },
    {
      "binding_sha256": "c2a744f7942cee73d8c1a628231d93c941bac572277b7c06be8f3a31704dd8cd",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-04:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-04:1 Resolve and enforce allowed paths at access time; constrain uploads, downloads, extraction, temporary files, and permissions."
    },
    {
      "binding_sha256": "8bde8d6440b503e5dbd7f7f20a40d3cc13cfe69721b995060b556ea1a5fef992",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-04:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-04:2 Test symlink races, archive traversal, absolute paths, overwrite attempts, and secret-directory reads."
    },
    {
      "binding_sha256": "a1e973bb5b5011647a413785008565d20ad0c224c57b33b0f45a8413d08f5e3b",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-05:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-05:1 Restrict destinations and schemes at connection time; revalidate DNS resolution and each redirect."
    },
    {
      "binding_sha256": "07ebaf424650aa51be636e7de5bfa8e170e5201aaa78390b989a3c3bf07dc7e4",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-05:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-05:2 Test loopback, private/link-local IPv4 and IPv6, cloud metadata, alternate encodings, and redirect-to-private cases."
    },
    {
      "binding_sha256": "f1e62f947d2c7592392c4598f8c3ec356e58961a6ae0ec3f381e4e3a015aa429",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-06:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-06:1 Inspect pickle, unsafe YAML, object deserialization, XML entity expansion, and unconstrained recursive parsers."
    },
    {
      "binding_sha256": "d4dd98abf81dcece0445b13c859c86134e9f46b15d3c4d6db2b92916c384b765",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-06:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-06:2 Use data-only formats with byte, nesting, and type limits; test malformed input and expansion attacks."
    },
    {
      "binding_sha256": "3e4bbc9024ccb4a73d81893fb95f4a9e398a4224fd5ee91c8ea6df10dcdcaed9",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-07:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-07:1 Use context-specific escaping for HTML/Markdown, avoid unsafe DOM sinks, and validate links and embedded media."
    },
    {
      "binding_sha256": "38ed141705a00166b0237bd98588bbb486659b319cf1616c86c3cc0a5409dac4",
      "decision": "",
      "evidence_ref": "",
      "id": "check:EXEC-07:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "EXEC-07:2 Test active SVG/HTML, malicious URLs, terminal escapes, and spreadsheet formulas in exported reports."
    },
    {
      "binding_sha256": "d65e473f9235d5631ea67e9085633a82ad7f6861e633543d51523d917dce733a",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-01:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-01:1 Inspect code, examples, configuration, notebooks, test fixtures, and generated artifacts for secret-like values."
    },
    {
      "binding_sha256": "595dd950ac64898a2668cb26246ac1bfe0b5b4fe6d40c3357489df01696bb279",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-01:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-01:2 Verify actual exposures with the owner, rotate real credentials, and remove them from reachable history and artifacts."
    },
    {
      "binding_sha256": "e749900f776def0912d3a98f7842e41a93e5543c84eba540acc78570aae0543a",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-02:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-02:1 Map which prompts, tool outputs, memory, and code leave the environment and identify the receiving provider/gateway."
    },
    {
      "binding_sha256": "11141a944afebfc0482f1fec9978bb8d70ddb9c8c43c8b37e6f5b0d2afdf46a0",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-02:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-02:2 Document allowed data classes, processing location, retention, and training use; redact before transmission where required."
    },
    {
      "binding_sha256": "a86c87a5cc47cb77b7d382c7b08bad816080962953c1064028208b3414d37069",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-03:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-03:1 Redact secrets and sensitive payloads before logs, traces, exception strings, and dashboards persist them."
    },
    {
      "binding_sha256": "cfcc3b0f839aa4a7bd4b5a018747b82c7fa8b6b9c8cc327e1e6774dfb9ee08dd",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-03:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-03:2 Test the failure paths and provider errors as well as success paths; restrict access and export destinations."
    },
    {
      "binding_sha256": "87026809b76ad376d2b27494e94011b8a42fb33d3a03b21a0d60c548a4090b97",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-04:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-04:1 Record source, owner, version, transformation history, and integrity evidence for datasets, retrieval corpora, and memory seeds."
    },
    {
      "binding_sha256": "7fcc31c281dcf5da785c3e582b0566d3f993652be9d7efd661a003d3123e0aa4",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-04:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-04:2 Quarantine unexpected changes and test how poisoned or stale data is detected, removed, and replaced."
    },
    {
      "binding_sha256": "09de94a5d10828eaf7ecb603400785603acb313728ef88e5980de8d55d311f9a",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-05:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-05:1 Apply expiry and deletion to prompts, embeddings, caches, memory, tool artifacts, backups, and provider-held data."
    },
    {
      "binding_sha256": "447f30939b929ad2e5eae32662fa41c9a68ae59f85a1912682c3dc4bb5e71c11",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-05:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-05:2 Verify deleting a source record removes or invalidates dependent retrieval content and access grants."
    },
    {
      "binding_sha256": "143a88d3a6b1a46191e4f31be3b8f21796c239b1f420b2d5a86fd5237ce9bfe5",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-06:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-06:1 Check transport verification, storage access controls, encryption settings, key separation, and backup permissions."
    },
    {
      "binding_sha256": "3b2ffc1e3f9e94472f204f0e48f561c451c365d223ebf0c4dde86a2260769f8e",
      "decision": "",
      "evidence_ref": "",
      "id": "check:DATA-06:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "DATA-06:2 Validate key rotation and denied access using a principal outside the authorized tenant or operational role."
    },
    {
      "binding_sha256": "00db017a2b0cd8aaa06a534bcf1fb8ccb9b093d03417cbd10030a49b9d73d674",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-01:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-01:1 Review lockfiles and exact versions or immutable digests for packages, images, MCP servers, models, and plugins."
    },
    {
      "binding_sha256": "50bdde21b2714f213497dc1f46451f4c3c9c6fd159df784d63260a6543fadb6a",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-01:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-01:2 Flag runtime installs, floating tags, remote scripts, and dependency sources outside approved registries."
    },
    {
      "binding_sha256": "90d36b989ebc98ef78f8439183a0b9e1cf26e4c509e96ee04e95fae29aeb55c3",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-02:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-02:1 Run appropriate package/container advisory tools against resolved dependencies and save database date and tool version."
    },
    {
      "binding_sha256": "fbb38f6b645da99006f5aae77f2810c99eec891ca193d6a44c42ac97cc663ee1",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-02:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-02:2 Triage reachability, fix availability, support status, and transitive dependencies; source pattern scans do not establish CVE coverage."
    },
    {
      "binding_sha256": "3ecb2fc047bb3b0ee51fa4e5a0cfd007737d9d7acadab53c9f664a7aae07cd49",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-03:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-03:1 Verify publisher identity, hashes/signatures, build provenance, and intended origin before enabling artifacts."
    },
    {
      "binding_sha256": "29f200a78a9c8b5994afd1beed70325a6f84c73539bebe51f477772595d85669",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-03:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-03:2 Review model loading and serialization behavior; an integrity hash cannot make an untrusted publisher safe."
    },
    {
      "binding_sha256": "08449a13075960057de315b574148ccde2dd0156a59b345ee1b1059ebab4826e",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-04:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-04:1 Restrict CI credentials and workflow permissions; review actions, build scripts, and release provenance."
    },
    {
      "binding_sha256": "b7f747cd97909f8f13cecce86485f12e83d448300fa91f5289204cfa518b66a7",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-04:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-04:2 Prevent untrusted contributions from executing with deployment secrets or changing approved agent policies."
    },
    {
      "binding_sha256": "9d5a1e3643089c57de5186c08194c7771924bb4bb59cb0a27557c927116762c3",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-05:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-05:1 Review root/privileged containers, host mounts, Docker sockets, unrestricted egress, debug mode, and public management endpoints."
    },
    {
      "binding_sha256": "6650f7de2d215dac53ae0c5f4808c6c1e540ad6b821ad6d2e87707e86ca559e9",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-05:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-05:2 Separate agent execution from control-plane credentials and audit storage; test isolation in the deployed environment."
    },
    {
      "binding_sha256": "0f95ed4d9fba0f01b8b17e272f212150b28f8e1022d9ac7e2b705cacb984ec46",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-06:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-06:1 When training or fine-tuning, isolate development, evaluation, and production identities, data access, registries, and release permissions."
    },
    {
      "binding_sha256": "db19ed47eb281e405dbd32a8cb09e824e9f86cef5e872ac8795ce25b51b5c793",
      "decision": "",
      "evidence_ref": "",
      "id": "check:SUP-06:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "SUP-06:2 Protect datasets, weights, adapters, and configuration separately; monitor modifications and demonstrate that an untrusted training job cannot replace an approved production artifact."
    },
    {
      "binding_sha256": "7261984c866aa2ab031296e37330240aad55033f731f2f3e58cc030964ada12a",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-01:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-01:1 Record initiating identity, delegated identity, tool/server/version, approved arguments, decision, outcome, and correlation identifiers."
    },
    {
      "binding_sha256": "25c11ac37140e8fcd00d6a48d3801add622f214add3e2863e3d83bda5ce35583",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-01:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-01:2 Protect log integrity and clock consistency; ensure agents cannot erase their own action history."
    },
    {
      "binding_sha256": "3ed834b72859c5e396a5948f6ad3a92d9e194de97e247d732d769eda63026534",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-02:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-02:1 Set server-enforced limits for iterations, tokens, tool calls, recursion, parallelism, bytes, cost, and elapsed time."
    },
    {
      "binding_sha256": "445b5145e810f002edadad13f2423ad2ec727a0456da5a935edebd9852e71e9f",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-02:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-02:2 Exercise stuck loops and amplification paths; verify limits apply across retries and child agents."
    },
    {
      "binding_sha256": "81de8dfc4a4b8f8f5f2c2d62f85c0600e17d7a71d161d099736f554cf67c4edd",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-03:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-03:1 Provide a tested stop mechanism that revokes work, credentials, queued actions, and child tasks."
    },
    {
      "binding_sha256": "d3da9653e3ea1816d1059a3fc7c28e0ef80bda00e31d56ec8de0b0bbdf214e84",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-03:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-03:2 Measure stop latency and verify cancelled or disconnected requests cannot later commit prohibited side effects."
    },
    {
      "binding_sha256": "eb9c3689e3d40513fefc702515fd1fb1aa90867762b49d208603de1d98285738",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-04:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-04:1 Deny or escalate when policy, identity, or approval checks fail; prevent fallback paths from widening privilege."
    },
    {
      "binding_sha256": "e211c6f6f10dc6199160909f9946ec23a92dd47a8546f8d87b5e83cdb757e30b",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-04:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-04:2 Test outages, partial failures, timeouts, retries, idempotency, and recovery of transactions with external effects."
    },
    {
      "binding_sha256": "346ec7563440ef3d985550a964ce07fdf6ead6353aaad8fe0a8d4dcc406cab9a",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-05:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-05:1 Alert on unusual tool use, new destinations, scope growth, repeated denials, cost spikes, and unexpected state changes."
    },
    {
      "binding_sha256": "fc3a40fc88708ba1841060ed2b51c323df1cb07ffca8e9fb6407e13c84776ba7",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-05:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-05:2 Validate alerts with seeded events and test rollback of models, prompts, tools, policies, and poisoned memory."
    },
    {
      "binding_sha256": "a9bd4962aa094542ec038aeff7e9ef29fb6530bf2423c03286aacde8cb49a708",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-06:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-06:1 Maintain procedures to isolate agents, revoke credentials, preserve evidence, notify owners, and recover trusted state."
    },
    {
      "binding_sha256": "ef28a261b56a7540bd9c184fbd1e4c3d6b508dd9cd25cc633f0d77c4ca9551c3",
      "decision": "",
      "evidence_ref": "",
      "id": "check:OPS-06:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "OPS-06:2 Exercise an AI-specific incident and define approved vulnerability/intelligence-sharing channels without exposing sensitive evidence."
    },
    {
      "binding_sha256": "e3e763e63ddb6b5506846bc6c2e8aa761b0532e44d9fd9408d0d972ad97b9de8",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-01:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-01:1 Run paired benign and adversarial workflows with representative tools and attacker-controlled external content."
    },
    {
      "binding_sha256": "e3d938f7bb1f7fd35f1e101fec61386f10ded0ab059d3370f4d5f515b418dff1",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-01:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-01:2 Record attacker success, authorized task success, blocked benign actions, and the observed unauthorized side effect."
    },
    {
      "binding_sha256": "ff60ea4c269b3f67c60907006938a5a438c82799bb864e510ee4ab3d9332f00b",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-02:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-02:1 Vary payload wording, placement, modality, attacker knowledge, and attempts; rerun after changing defenses."
    },
    {
      "binding_sha256": "2cb8bc2ada857c34558ce80ada91c9b21b7419da71b871a70ef05a6f55e27b2b",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-02:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-02:2 Report per-scenario outcomes, sample counts, attack budget, uncertainty, and model/harness versions instead of only an average."
    },
    {
      "binding_sha256": "eb4cdc1f1b20ac6977c7d8d3e78f4085b0d90572999bbc80871b9dc4e94d8a69",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-03:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-03:1 In an isolated test environment, exercise invalid tokens, wrong audiences, origin abuse, malicious servers, and protocol fuzzing."
    },
    {
      "binding_sha256": "365adcba4603f05d6e3ca876e769023fa345eb7b9644c549cb3161e0a1883eb9",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-03:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-03:2 Adapt scenarios to the deployed MCP revision and transports; preserve request/response evidence with secrets removed."
    },
    {
      "binding_sha256": "641a75cacfa1c02d889c8596539ae71f3ece2875bf8b2a5c6cf19f87301fdcd6",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-04:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-04:1 Create two principals and attempt cross-access to objects, memory, caches, handles, subscriptions, and execution results."
    },
    {
      "binding_sha256": "24bc44df88a760ee954713fb38557f01c7c93b88560851f0fc8afd25421d7209",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-04:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-04:2 Repeat after reconnect, delegation, failed authentication, concurrent requests, and privilege revocation."
    },
    {
      "binding_sha256": "8f1d161e90e8d8d0e5e52fdcc5b92509680fd4b8bd6dc1a45c64446059bb70a2",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-05:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-05:1 Use explicit forbidden-action canaries to verify enforcement survives hostile content, tool substitution, and delayed execution."
    },
    {
      "binding_sha256": "2c18deb1765157e6000a9f2268be3d781bff5098294a7d301048a64ede27f390",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-05:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-05:2 Confirm paths through retries, fallback models, alternate tools, and child agents enforce the same boundary."
    },
    {
      "binding_sha256": "5a18aa6772ab691bf1abf8b7d95c3e32c20b7fc0e1918ff886186976f762cbe8",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-06:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-06:1 Run language-aware SAST, dependency review, secret scanning, and authorized integration tests for exposed services."
    },
    {
      "binding_sha256": "e638431e70dc400c427b46dc77bb9b0e8b42d34a5220a563cc7fc069ae33f61d",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-06:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-06:2 Exercise reachable injection, XSS, SSRF, path traversal, deserialization, and access-control risks with safe fixtures."
    },
    {
      "binding_sha256": "eabb974722a0b872cd327da961ca609632496c2a7ebb66e8d7fb87571bf856b4",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-07:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-07:1 Simulate oversized messages, slow peers, streaming floods, repeated errors, runaway agents, and unavailable dependencies."
    },
    {
      "binding_sha256": "f25a1f3ab94ea16be0eedadf39089957d3040870ce8e01b5c95da7ee53253e14",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-07:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-07:2 Verify quotas, shutdown, telemetry, and alerts work together without leaking payloads or losing attribution."
    },
    {
      "binding_sha256": "468c7cf2f6303dc6244d0cbbd1e1438c4095eca95e11ca64357a7abb3495199f",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-08:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-08:1 Treat repository text and model verdicts as untrusted; test prompt injection, fabricated locations, invalid JSON, and timeouts."
    },
    {
      "binding_sha256": "3c51f867553ceed774bc6bbee06e91de6b54d4fb6d1a539973916896c4c45e24",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-08:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-08:2 Compare against labeled cases, retain deterministic results, document model variability, and never equate a judge approval with control validation."
    },
    {
      "binding_sha256": "3ddf2717aa39a894ecca4ef67bf121874ad1668077abacd8808d7b1fb77f7427",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-09:1",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-09:1 Where applicable, assess suspicious triggers, model extraction, and disclosure of private training examples under an explicit attacker access and query budget."
    },
    {
      "binding_sha256": "a6657505672a959c13ccc63d87b7bf6666e1920bc4030e1852d12fc8847b80ae",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-09:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-09:2 Retest acquired or retrained models and adapters before release; document measured failures, model identity, coverage limits, and accepted residual risk."
    }
  ],
  "kind": "invarune_review",
  "origin": {
    "catalog_sha256": "1ce59f52efcdab26074adc7164eb269aeb7235012835ad40fc64a94cfae03d7d",
    "configuration": {
      "default_excluded_directories": [
        ".cache",
        ".git",
        ".hg",
        ".mypy_cache",
        ".next",
        ".pytest_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "node_modules",
        "vendor",
        "venv"
      ],
      "exclude": [],
      "generated_outputs_and_judge_config_excluded": true,
      "max_entries": 100000,
      "max_file_bytes": 20000000,
      "max_files": 20000,
      "max_total_bytes": 300000000
    },
    "evidence_sha256": "90f1d75f620c67c19c16d88c735883cc91ea7663d6404c7c6c9d7b1c89597f97",
    "image_limits": {},
    "manifest_sha256": "331be7d4fc84dcfadc121cdc9c727c66dce08070dc09087472a33661955d2e04",
    "scan_id": "a7483423f5469d9f691860138aa040fefc1c0bf4ae1ef71863a0bb000f1658d3",
    "scope_sha256": "1ac0e3943777ebb10c33d20ef4246e6527b1a0664e1b3cffac249558e9730f36",
    "target": {
      "description": "Selected source directory; paths are relative.",
      "kind": "source",
      "platform": ""
    },
    "tool": {
      "implementation_sha256": "8d56fcf24bb47474196842268b3512ce8df00a81a3371f7fce63757fa1a8f309",
      "name": "agent-mcp-security-scan",
      "version": "0.13.0"
    }
  },
  "schema_version": "1.0"
}
```
<!-- INVARUNE_REVIEW_END -->

