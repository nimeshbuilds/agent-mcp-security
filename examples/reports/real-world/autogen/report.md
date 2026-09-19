# Invarune by NimeshBuild

AI agent and MCP security report

Scan ID: `443fbea356cf28fae6b967da032bca7873af6975496b23b8a2581511e575790d`

This is static security triage, not certification or proof that a system is secure.

## Executive assessment

### Critical/high findings need prompt review

The scanner found 5 open critical/high patterns among 13 open findings\. Confirm exposure and prioritize the actions below\. Detector severity is not proof of exploitability or deployed risk\.

| Open findings | Critical/high | Affected files | Accepted baseline findings | Coverage gaps |
|---:|---:|---:|---:|---:|
| 13 | 5 | 10 | 0 | 0 |

**66 active controls** still require applicability and effectiveness validation. A completed static scan or optional review cannot establish a control pass.

**What the scanner found:** Supply chain: 5; Data protection: 2; Deserialization: 2; Tool execution: 2; Configuration: 1; Secrets: 1. These are detected pattern categories, not confirmed attack paths.

**Execution:** exit 1; severity threshold high. The exit threshold does not change the review priorities below.

**Optional model review:** disabled. This overview and the mitigation guidance work offline without a model.

## Immediate concerns and first actions

P0: critical, P1: high, P2: medium, P3: low/info\. These are deterministic review priorities based on detector severity, not incident confirmation, remediation SLAs, likelihood estimates, or residual\-risk scores\. Confidence describes the detected pattern; applicability must be checked\.

| Priority | What the scanner found | Occurrences | First action | Suggested owner |
|---|---|---:|---|---|
| P1 | [AI001: Dynamic Python code execution](#group-45290f4fa5c7) (source) | 2 | Trace the input to eval/exec and replace it with fixed operations; if generated execution is essential, isolate it before accepting untrusted input\. | Agent/tool developer |
| P1 | [AI005: Executable deserialization requires trusted inputs](#group-9ee5075ce1a1) (source) | 2 | Establish who can produce and replace the input; migrate to a nonexecutable data format or restrict verified legacy artifacts to an isolated conversion path\. | Application/model pipeline owner |
| P1 | [AI010: Credential\-like literal in source or configuration](#group-57a1992f928c) (source) | 1 | Determine whether the value is real without reproducing it; revoke or rotate a real exposed credential and remove retained copies through the incident process\. | Credential/service owner |
| P2 | [AI009: Application debug mode enabled](#group-50316e5c3385) (source) | 1 | Verify the effective deployed setting, disable debug behavior, and confirm representative errors do not expose a debugger or sensitive details\. | Application and platform owner |
| P2 | [AI033: Potential secret included in logging call](#group-6a434c96603a) (source) | 2 | Verify the logged value safely, remove it before formatting/export, and rotate it if real exposure is confirmed\. | Application/observability owner |
| P3 | [AI024: Container image is not digest pinned](#group-0cc3d39352a0) (source) | 4 | Identify the approved image digest and enforce it in the effective build or deployment while preserving a reviewed update process\. | Container/release owner |
| P3 | [AI025: Direct dependency is not exactly pinned](#group-35a2b5731941) (source) | 1 | Check the effective install command and lockfile; enforce a verified resolution and document intentionally flexible development declarations\. | Dependency/build owner |

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

<a id="group-57a1992f928c"></a>

### AI010: Credential\-like literal in source or configuration

**HIGH** · open · 1 occurrences · source

**Observed evidence:** [python/packages/autogen\-ext/src/autogen\_ext/tools/mcp/\_workbench\.py:179](#finding-ef0d80173753ef78)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If the detected literal is a live credential, anyone with access to the source, image layers, or copied artifacts may use its granted permissions\.

**Address the cause:** Determine whether the value is real without reproducing it; revoke or rotate a real exposed credential and remove retained copies through the incident process\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Investigate and contain confirmed secret exposure | For a real exposed credential, identify reachable systems, revoke or rotate it, and review access records for misuse\. | Confirm the old credential no longer works and record the exposure window, affected copies, and follow\-up owner\. | Successful rotation stops future use of that credential but cannot reverse access or data loss that already occurred\. |
| Use managed credential injection and revocation | Load secrets at runtime through an approved store or workload identity; keep them out of source, artifacts, and model context\. | Test rotation and revocation without disclosing values; inspect build layers and launch metadata for retained copies\. | Deleting a file or hiding a later image layer does not revoke a credential or erase copies already distributed\. |
| Limit credentials available to the workload | Give this component a distinct identity and only the downstream scopes and lifetime needed for its approved operations\. | Use its runtime identity to attempt forbidden service operations, then revoke it and confirm subsequent access fails\. | A compromised component can still use its allowed permissions until credentials expire or revocation takes effect\. |

Related controls: AUTH\-05, DATA\-01

Guidance sources (engineering synthesis): [CISA\-JCDC](https://www.cisa.gov/news-events/alerts/2025/01/14/cisa-releases-jcdc-ai-cybersecurity-collaboration-playbook-and-fact-sheet); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [JOINT\-AGENTIC](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely); [MCP\-AUTH](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization); [MCP\-AUTH\-SEC](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices); [NIST\-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final)

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

<a id="group-35a2b5731941"></a>

### AI025: Direct dependency is not exactly pinned

**LOW** · open · 1 occurrences · source

**Observed evidence:** [python/packages/autogen\-studio/requirements\.txt:1](#finding-67eb6d4ab1a7fd8c)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If the actual install is not constrained by an enforced lockfile or hash, dependency versions may change without a corresponding reviewed source change\.

**Address the cause:** Check the effective install command and lockfile; enforce a verified resolution and document intentionally flexible development declarations\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Resolve and install reviewed dependency bytes | Use a committed lock or approved artifact manifest, enforce it during installation, and retain the resolved dependency inventory\. | Build in a clean environment and compare resolved bytes; modify a lock or artifact and verify the release gate rejects it\. | An exact version or digest can still identify a vulnerable artifact; mutable transitive dependencies must also be constrained\. |
| Keep pinned artifacts maintained | Review known\-vulnerability and maintenance evidence for the actual resolved artifacts and apply updates through a repeatable release process\. | Demonstrate a dependency update, relevant regression checks, and deployment or rollback of the resulting approved artifact\. | This source/image scan does not provide a current CVE verdict, and a vulnerability database cannot identify every unknown flaw\. |

Related controls: SUP\-01

Guidance sources (engineering synthesis): [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [NIST\-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final); [OPENSSF\-BASELINE\-202608](https://baseline.openssf.org/versions/2026-08-28); [OPENSSF\-SCORECARD](https://securityscorecards.dev/)

### What remains unknown

- Actual reachability, deployment configuration, upstream validation, data sensitivity, and exploitability require verification\.
- Authentication, authorization, tenant isolation, tool approvals, prompt\-injection resistance, and recovery need runtime or human evidence\.
- Suggested defense layers have not been verified as deployed\. There is no calculated residual\-risk score or automatic severity reduction\.
- No dependency CVE feed or live adversarial agent/MCP benchmark was run\. Excluded and unsupported files remain outside the selected scope\.

Guidance catalog version: 1\.0\.0; SHA-256: `dadde42b9b4e7f65d34d897f716649ed0b49b1fc561e5e45a9eadbac43c5eed1`. The catalog is bundled and does not contact external sources during a scan.

## Scan details

Scanned **759 files**; **13 open findings**, **0 suppressed findings**, and **0 coverage gaps**.

| Critical | High | Medium | Low | Info |
|---:|---:|---:|---:|---:|
| 0 | 5 | 3 | 5 | 0 |

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

Weakness mappings: CWE\-502

- [Reference](https://docs.python.org/3/library/security_warnings.html)

<a id="finding-ef0d80173753ef78"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: python/packages/autogen\-ext/src/autogen\_ext/tools/mcp/\_workbench\.py:179–179 · Finding ID: `5d062dd8c013df9eaaebf008`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-aeffdafc90f11c4d"></a>

### AI009 — Application debug mode enabled

**MEDIUM** · Confidence: high · Status: open

Location: python/packages/autogen\-studio/autogenstudio/web/app\.py:60–60 · Finding ID: `8f8e715e8f65d28379ca9bd4`

Debug mode is explicitly enabled in server code or configuration\. Depending on the framework and deployment, error details or a debugger may become externally accessible\.

```text
app = FastAPI(lifespan=lifespan, debug=True)
```

**Remediation:** Disable debug mode in deployed services and return sanitized errors while retaining protected server\-side diagnostics\.

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

Weakness mappings: CWE\-829

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-67eb6d4ab1a7fd8c"></a>

### AI025 — Direct dependency is not exactly pinned

**LOW** · Confidence: low · Status: open

Location: python/packages/autogen\-studio/requirements\.txt:1–1 · Finding ID: `74ba06ff19cb005e43a613c3`

A direct dependency declaration allows version movement\. A lockfile elsewhere may constrain the actual installation; review the effective build process\.

```text
.
```

**Remediation:** Use a committed verified lockfile or exact pins and hashes, scan dependencies for known vulnerabilities, and review updates\.

Weakness mappings: CWE\-1104

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

Category: Identity and authorization · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Use short\-lived scoped credentials where supported, protect refresh tokens, and validate rotation and revocation\.
- [ ] Avoid tokens in query strings, model context, source, child\-process arguments, and diagnostic output\.

Partial static rules: AI010, AI011, AI030, AI034

Open finding IDs: 5d062dd8c013df9eaaebf008
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

Category: Data and privacy · Status: findings\_detected · Validation: static

Partial static coverage only; absence of a finding is not a pass

- [ ] Inspect code, examples, configuration, notebooks, test fixtures, and generated artifacts for secret\-like values\.
- [ ] Verify actual exposures with the owner, rotate real credentials, and remove them from reachable history and artifacts\.

Partial static rules: AI010, AI011, AI030, AI034

Open finding IDs: 5d062dd8c013df9eaaebf008
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

Open finding IDs: 1b457f2ddf5f7bd1f2b8ff83, 9bda7648d4ee61ecefd32bf1, b0db6980d83276c2aae4395b, 6b3993abfce0612f48fb97d5, 74ba06ff19cb005e43a613c3
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
