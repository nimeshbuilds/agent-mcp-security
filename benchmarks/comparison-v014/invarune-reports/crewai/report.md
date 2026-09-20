# Invarune by NimeshBuild

AI agent, MCP and skill security report

Scan ID: `50845125598b57f4c456a73a0ee94510623852219be2ce648fe275f41ea59362`

This is static security triage, not certification or proof that a system is secure.

## Contents

- [Summary and immediate concerns](#executive-assessment)
- [Metrics and calculation](#metrics-and-how-they-are-calculated)
- [Methods, configuration and blind spots](#methods-configuration-and-blind-spots)
- [Editable review and fresh scan](#editable-review-and-fresh-scan)
- [Scan details](#scan-details)

## Executive assessment

### Incomplete scan \- close the coverage gaps

The selected static scope was not fully inspected\. There are 27 open findings, including 25 critical/high findings\. Resolve reported gaps and review existing evidence before relying on this result\.

| Open findings | Critical/high | Affected files | Accepted baseline findings | Coverage gaps |
|---:|---:|---:|---:|---:|
| 27 | 25 | 10 | 0 | 12 |

**66 active controls** still require applicability and effectiveness validation. A completed static scan or optional review cannot establish a control pass.

**Fix guidance:** 27/27 observed findings have a deterministic fix plan and agent/MCP context. Model fix plans: 0/0 finding assessments and 0/0 answered checks. These are proposed changes requiring verification.

**What the scanner found:** Secrets: 20; Tool execution: 3; Output handling: 2; Authentication: 1; Deserialization: 1. These are detected pattern categories, not confirmed attack paths.

**Execution:** exit 2; severity threshold high. The exit threshold does not change the review priorities below.

**Optional model review:** disabled. This overview and the mitigation guidance work offline without a model.

## Immediate concerns and first actions

P0: critical, P1: high, P2: medium, P3: low/info\. These are deterministic review priorities based on detector severity, not incident confirmation, remediation SLAs, likelihood estimates, or residual\-risk scores\. Confidence describes the detected pattern; applicability must be checked\.

**Close scan coverage gaps:** resolve the listed errors or scope limits and rerun on a stable input. Existing findings still need review.

- analysis\_error: ValueError while reading or analyzing file: 1 entries. Examples: lib/crewai/src/crewai/flow/runtime/\_\_init\_\_\.py
- parse\_error: Dynamic tool description at line 765 was not resolved; instruction\-threat checks require literal metadata\.: 1 entries. Examples: lib/crewai/src/crewai/tools/base\_tool\.py
- parse\_error: Instruction\-threat inspection is bounded to 1000000 characters for source metadata; remaining instruction/tool metadata needs review\.: 1 entries. Examples: lib/crewai\-tools/tool\.specs\.json
- parse\_error: JSON could not be parsed at line 2: Extra data; structured configuration checks were skipped\.: 1 entries. Examples: lib/cli/src/crewai\_cli/templates/json\_crew/agent\_settings\.jsonc
- parse\_error: JSON could not be parsed at line 3: Expecting property name enclosed in double quotes; structured configuration checks were skipped\.: 2 entries. Examples: lib/cli/src/crewai\_cli/templates/json\_crew/crew\.jsonc, lib/cli/src/crewai\_cli/templates/json\_crew/task\.jsonc
- parse\_error: JSON could not be parsed at line 5: Expecting property name enclosed in double quotes; structured configuration checks were skipped\.: 1 entries. Examples: lib/cli/src/crewai\_cli/templates/json\_crew/agent\.jsonc
- parse\_error: Python syntax could not be parsed at line 1: invalid syntax; AST\-based checks were skipped\.: 1 entries. Examples: lib/cli/src/crewai\_cli/templates/tool/src/\{\{folder\_name\}\}/\_\_init\_\_\.py
- parse\_error: Python syntax could not be parsed at line 4: invalid syntax; AST\-based checks were skipped\.: 1 entries. Examples: lib/cli/src/crewai\_cli/templates/tool/src/\{\{folder\_name\}\}/tool\.py
- parse\_error: Python syntax could not be parsed at line 7: invalid syntax; AST\-based checks were skipped\.: 2 entries. Examples: lib/cli/src/crewai\_cli/templates/crew/crew\.py, lib/cli/src/crewai\_cli/templates/crew/main\.py
- parse\_error: Python syntax could not be parsed at line 8: invalid syntax; AST\-based checks were skipped\.: 1 entries. Examples: lib/cli/src/crewai\_cli/templates/flow/main\.py

| Priority | What the scanner found | Occurrences | First action | Suggested owner |
|---|---|---:|---|---|
| P1 | [AI001: Dynamic Python code execution](#group-45290f4fa5c7) (source) | 1 | Trace the input to eval/exec and replace it with fixed operations; if generated execution is essential, isolate it before accepting untrusted input\. | Agent/tool developer |
| P1 | [AI005: Executable deserialization requires trusted inputs](#group-9ee5075ce1a1) (source) | 1 | Establish who can produce and replace the input; migrate to a nonexecutable data format or restrict verified legacy artifacts to an isolated conversion path\. | Application/model pipeline owner |
| P1 | [AI010: Credential\-like literal in source or configuration](#group-57a1992f928c) (source) | 20 | Determine whether the value is real without reproducing it; revoke or rotate a real exposed credential and remove retained copies through the incident process\. | Credential/service owner |
| P1 | [AI017: JWT verification explicitly bypassed](#group-7452d035b2dc) (source) | 1 | Verify signatures and an explicit algorithm allowlist, trusted issuer, intended audience, expiry, and required claims before authorization\. | Identity/API owner |
| P1 | [AI036: SQL query constructed with interpolation](#group-beaa8fb2b87e) (source) | 2 | Bind values as parameters and allowlist any dynamic identifiers or operation choices; trace generated and tool\-supplied query fragments\. | Database/tool developer |
| P2 | [AI040: Unsafe HTML rendering boundary](#group-38c699676b2c) (source) | 2 | Render external output as text or apply a maintained, context\-appropriate sanitizer before the sink; verify the final rendering path\. | Frontend/rendering owner |

## What could reduce the risk

The layers below are **proposed and unverified**. They can reduce exposure or impact only when correctly implemented and tested. Fix the underlying issue where applicable. No suggested layer, baseline exception, or model opinion lowers a finding's recorded severity.

Before accepting lower residual risk, record deployment evidence, negative-test results, owner, review date, and expiry. Confirm that requests cannot bypass the control and retest after changes.

<a id="group-45290f4fa5c7"></a>

### AI001: Dynamic Python code execution

**HIGH** · open · 1 occurrences · source

**Observed evidence:** [lib/crewai/src/crewai/flow/runtime/\_actions\.py:309](#finding-fb48dce75aad2d9e)

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

**HIGH** · open · 1 occurrences · source

**Observed evidence:** [lib/crewai/src/crewai/utilities/file\_handler\.py:166](#finding-721c9778039e2499)

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

**HIGH** · open · 20 occurrences · source

**Observed evidence:** [lib/cli/src/crewai\_cli/deploy/validate\.py:86](#finding-b9e811e29e67cd31), [lib/cli/src/crewai\_cli/deploy/validate\.py:89](#finding-4d39f07c6c256b6c), [lib/cli/src/crewai\_cli/deploy/validate\.py:99](#finding-937b7ea36b47ffcf), [lib/cli/src/crewai\_cli/deploy/validate\.py:100](#finding-47fba7aad9d5f54e), [lib/cli/src/crewai\_cli/deploy/validate\.py:101](#finding-6290b1ba85e4d721), [lib/cli/src/crewai\_cli/deploy/validate\.py:102](#finding-a8b5f684aa64dd8c), [lib/cli/src/crewai\_cli/deploy/validate\.py:104](#finding-73c90c7e8d3839c9), [lib/crewai\-tools/src/crewai\_tools/tools/multion\_tool/example\.py:7](#finding-67a2761895c91be2), [lib/crewai\-tools/src/crewai\_tools/tools/multion\_tool/example\.py:9](#finding-9db13f6a1615afda), [lib/crewai\-tools/src/crewai\_tools/tools/stagehand\_tool/\.env\.example:1](#finding-c3c3afaf2349a060), [lib/crewai\-tools/src/crewai\_tools/tools/stagehand\_tool/\.env\.example:2](#finding-95758fa8fa874c43), [lib/crewai\-tools/src/crewai\_tools/tools/stagehand\_tool/\.env\.example:3](#finding-39e13d30708dbcbd), [lib/crewai\-tools/src/crewai\_tools/tools/stagehand\_tool/\.env\.example:4](#finding-59169305d1dafc08), [lib/crewai/src/crewai/llms/providers/openai\_compatible/completion\.py:49](#finding-4b628dbb11c0387e), [lib/crewai/src/crewai/llms/providers/openai\_compatible/completion\.py:56](#finding-e4c868691013e15b), [lib/crewai/src/crewai/llms/providers/openai\_compatible/completion\.py:62](#finding-b7507c0dc9e282bd), [lib/crewai/src/crewai/llms/providers/openai\_compatible/completion\.py:69](#finding-a16475a0bc83a971), [lib/crewai/src/crewai/llms/providers/openai\_compatible/completion\.py:76](#finding-93b95d3abf3878ce), [lib/crewai/src/crewai/llms/providers/openai\_compatible/completion\.py:83](#finding-783350fa2f8411b2), [lib/crewai/src/crewai/llms/providers/openai\_compatible/completion\.py:89](#finding-520153432ed5eec9)

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

<a id="group-7452d035b2dc"></a>

### AI017: JWT verification explicitly bypassed

**HIGH** · open · 1 occurrences · source

**Observed evidence:** [lib/crewai\-core/src/crewai\_core/auth/utils\.py:34](#finding-5d05ccefc9be69fe)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If unverified claims authorize a request, a caller may forge identity or privileges without possessing a valid issuer\-signed token\.

**Address the cause:** Verify signatures and an explicit algorithm allowlist, trusted issuer, intended audience, expiry, and required claims before authorization\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Authenticate and authorize protected requests | Authenticate each protected request and enforce tool, tenant, and target permissions at the service handling the operation\. | Test missing, expired, wrong\-audience, and revoked credentials, plus a valid caller requesting a forbidden target\. | Authentication identifies a caller; it does not make their supplied data safe or grant every authenticated caller equal authority\. |
| Authorize downstream effects separately | For each effect, check caller identity, tenant, operation, and target at the executing service using bounded downstream credentials\. | Try read\-only users against writes, other\-tenant identifiers, and direct tool calls without an agent session\. | Correct token verification alone cannot prevent an authorized but overly broad or harmful business operation\. |

Related controls: AUTH\-03

Guidance sources (engineering synthesis): [CSA\-AGENT\-IAM](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach); [MCP\-AUTH](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization); [MCP\-AUTH\-SEC](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

<a id="group-beaa8fb2b87e"></a>

### AI036: SQL query constructed with interpolation

**HIGH** · open · 2 occurrences · source

**Observed evidence:** [lib/crewai\-tools/src/crewai\_tools/tools/singlestore\_search\_tool/singlestore\_search\_tool\.py:309](#finding-42c394d3f7de71ae), [lib/crewai/src/crewai/memory/storage/kickoff\_task\_outputs\_storage\.py:163](#finding-4bc9303cabd2c37c)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If untrusted values are inserted as SQL syntax, they may alter a query to read or change unintended records within the database identity authority\.

**Address the cause:** Bind values as parameters and allowlist any dynamic identifiers or operation choices; trace generated and tool\-supplied query fragments\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Constrain the database identity and operation set | Use dedicated database credentials with only the required tables, rows, and operations; separate administrative access from agent tools\. | Using the agent identity, attempt schema changes, other\-tenant records, unrestricted exports, and unauthorized writes\. | Database permissions bound damage but cannot make a permitted query correct; query parameters do not safely bind identifiers\. |
| Authorize downstream effects separately | For each effect, check caller identity, tenant, operation, and target at the executing service using bounded downstream credentials\. | Try read\-only users against writes, other\-tenant identifiers, and direct tool calls without an agent session\. | Correct token verification alone cannot prevent an authorized but overly broad or harmful business operation\. |

Related controls: EXEC\-03

Guidance sources (engineering synthesis): [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [CSA\-AGENT\-IAM](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach); [JOINT\-AGENTIC](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools); [OWASP\-OUTPUT2025](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

<a id="group-38c699676b2c"></a>

### AI040: Unsafe HTML rendering boundary

**MEDIUM** · open · 2 occurrences · source

**Observed evidence:** [lib/crewai/src/crewai/flow/visualization/assets/interactive\.js:1467](#finding-a2a6048be9013df6), [lib/crewai/src/crewai/flow/visualization/assets/interactive\.js:2449](#finding-897bf3e80b39f6af)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If unsanitized agent or tool content reaches a raw HTML sink, attacker\-controlled markup may execute in a viewer browser and access that viewer session\.

**Address the cause:** Render external output as text or apply a maintained, context\-appropriate sanitizer before the sink; verify the final rendering path\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Apply browser defenses around rendered output | Render data as text by default; where HTML is essential, use a maintained sanitizer and a restrictive Content Security Policy\. | Exercise active markup, event handlers, URL schemes, and sanitizer bypass regressions in the actual rendering component\. | CSP is an additional layer and can be weakened by unsafe directives; sanitization must match the eventual HTML or URL context\. |
| Isolate untrusted previews from privileged sessions | Place intentionally active external previews on a separate origin or an appropriately restricted sandbox, without application credentials or privileged messaging capabilities\. | Attempt parent\-frame access, navigation, storage access, and privileged postMessage calls from the preview; confirm explicit rejection\. | Sandbox permissions can restore dangerous authority, and origin isolation does not make downloaded content safe to execute elsewhere\. |

Related controls: EXEC\-07

Guidance sources (engineering synthesis): [OWASP\-LLM2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/); [OWASP\-OUTPUT2025](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

### What remains unknown

- Actual reachability, deployment configuration, upstream validation, data sensitivity, and exploitability require verification\.
- Authentication, authorization, tenant isolation, tool approvals, prompt\-injection resistance, and recovery need runtime or human evidence\.
- Suggested defense layers have not been verified as deployed\. There is no calculated residual\-risk score or automatic severity reduction\.
- No dependency CVE feed or live adversarial agent/MCP benchmark was run\. Excluded and unsupported files remain outside the selected scope\.

Guidance catalog version: 1\.0\.0; SHA-256: `c04353ab7c9999ea513de31a48130971509f8a52666745b24d1b726f96a4f374`. The catalog is bundled and does not contact external sources during a scan.

## Metrics and how they are calculated

No defensible universal security percentage can be calculated from static patterns or model opinions. Zero findings and 100% answered checks do not mean secure or compliant.

| Measure | Result | What it means |
|---|---|---|
| Open deterministic findings | 27 | Observed patterns requiring review; 25 critical/high. No severity weights or estimated compromise probability are assigned. |
| Partial deterministic mapping reach | 45.45% (30/66) | Active selected controls with at least one active selected mapped rule. This is available partial coverage, not a pass rate. |
| Optional AI answer coverage | 0.00% (0/132) | Active selected checks with an actual model answer, including concerns and unknowns. This is review completion, not a pass rate. |

**Selected scope:** 46 rules (46 active), 66 controls (66 active), 132 active acceptance checks. The selected static scope is incomplete. Recorded coverage gaps: 12.

**Mapping formula:** 100 × active selected controls with at least one active selected mapped rule / active selected controls\. This describes partial rule availability, not completed tests, passes, or control effectiveness\.

**AI answer formula:** 100 × unique active selected acceptance checks with a received, valid model answer / active selected acceptance checks\. An answer can be a concern or an explicit unknown\. Disabled AI has zero answered checks; an empty denominator is not applicable \(null\), never 100%\.

**Optional AI:** disabled; finding stage disabled; control stage disabled.

| Advisory check outcome | Count |
|---|---:|
| supported\_by\_code | 0 |
| potential\_gap | 0 |
| needs\_runtime\_validation | 0 |
| needs\_human\_review | 0 |
| insufficient\_evidence | 0 |
| not\_applicable\_proposed | 0 |
| not\_reviewed | 132 |

Supported by code and proposed non\-applicability are advisory interpretations\. Runtime/human validation and missing evidence remain unresolved\. AI cannot erase findings, lower their severity, change the severity gate, or turn checks into passes\.

Justified and disabled rules/checks are excluded from active metric denominators without pass credit\. Findings with user decisions or baseline suppressions remain visible outside open\-finding counts\. Selection narrows the requested scope; it does not establish the excluded system is safe\.

The existing CLI gate uses open deterministic findings at or above the configured severity\. Scan/review/export errors can make requested work incomplete\. Coverage percentages and model opinions never dismiss the gate\.

## Methods, configuration and blind spots

Find repeatable security patterns and organize the remaining assurance work for agents, MCP servers, skills and built images\.

| Selected scope measure | Count |
|---|---:|
| Selected deterministic rules | 46 |
| Selected controls with partial static mapping | 30 |
| Selected controls without static mapping | 36 |
| Selected acceptance checks | 132 |
| Rules available in the full catalog | 46 |
| Controls available in the full catalog | 66 |

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

#### Skills and malicious\-tool indicators

**Deterministic:** Bounded skill instructions and tool metadata are inspected for explicit instruction hijacking, sensitive\-data transfer, covert or approval\-bypassing actions, and contradictory read\-only declarations\.

**Optional model review:** A model can review intent, indirect social engineering, skill reference context and tool behavior visible in retrieved evidence, including cases where syntax or supported patterns are inconclusive\.

**Can miss or misclassify:** A pattern is risk evidence, not proof of malicious authorship\. Obfuscation, remote references, external packages, omitted context and runtime behavior can evade either layer\.

**Runtime/human evidence:** Inspect publisher provenance and the exact installed skill/tool; test consequential actions in an authorized isolated environment and verify effective permissions\.

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
    "max_total_bytes": 300000000,
    "requested_scan_ids": [],
    "selected_control_ids": [
      "AGT-01",
      "AGT-02",
      "AGT-03",
      "AGT-04",
      "AGT-05",
      "AGT-06",
      "AGT-07",
      "AUTH-01",
      "AUTH-02",
      "AUTH-03",
      "AUTH-04",
      "AUTH-05",
      "AUTH-06",
      "AUTH-07",
      "AUTH-08",
      "AUTH-09",
      "DATA-01",
      "DATA-02",
      "DATA-03",
      "DATA-04",
      "DATA-05",
      "DATA-06",
      "EXEC-01",
      "EXEC-02",
      "EXEC-03",
      "EXEC-04",
      "EXEC-05",
      "EXEC-06",
      "EXEC-07",
      "GOV-01",
      "GOV-02",
      "GOV-03",
      "GOV-04",
      "GOV-05",
      "GOV-06",
      "MCP-01",
      "MCP-02",
      "MCP-03",
      "MCP-04",
      "MCP-05",
      "MCP-06",
      "MCP-07",
      "MCP-08",
      "MCP-09",
      "MCP-10",
      "OPS-01",
      "OPS-02",
      "OPS-03",
      "OPS-04",
      "OPS-05",
      "OPS-06",
      "SUP-01",
      "SUP-02",
      "SUP-03",
      "SUP-04",
      "SUP-05",
      "SUP-06",
      "TEST-01",
      "TEST-02",
      "TEST-03",
      "TEST-04",
      "TEST-05",
      "TEST-06",
      "TEST-07",
      "TEST-08",
      "TEST-09"
    ],
    "selected_rule_ids": [
      "AI001",
      "AI002",
      "AI003",
      "AI004",
      "AI005",
      "AI006",
      "AI007",
      "AI008",
      "AI009",
      "AI010",
      "AI011",
      "AI012",
      "AI013",
      "AI014",
      "AI015",
      "AI016",
      "AI017",
      "AI018",
      "AI019",
      "AI020",
      "AI021",
      "AI022",
      "AI023",
      "AI024",
      "AI025",
      "AI026",
      "AI027",
      "AI028",
      "AI029",
      "AI030",
      "AI031",
      "AI032",
      "AI033",
      "AI034",
      "AI035",
      "AI036",
      "AI037",
      "AI038",
      "AI039",
      "AI040",
      "AI041",
      "AI042",
      "AI043",
      "AI044",
      "AI045",
      "AI046"
    ]
  }
}
```

## Scan details

Scanned **967 files**; **27 open findings**, **0 suppressed findings**, and **12 coverage gaps**.

| Critical | High | Medium | Low | Info |
|---:|---:|---:|---:|---:|
| 0 | 25 | 2 | 0 | 0 |

Source I/O: **9435467 bytes read**, **9435467 bytes charged** against the budget, including **0 conservatively charged bytes** for failed reads. Each read reserves a sentinel byte to detect growth.

### Analysis depth

File counts describe inspected inputs, not complete semantic coverage. Syntax/read failures remain listed as coverage gaps.

| Profile | Files | Analysis scope |
|---|---:|---|
| configuration\_lexical | 18 | Selected text/configuration patterns; YAML anchors, block\-scalar semantics and dynamic templates are not fully resolved\. |
| generic\_text | 5 | Generic secret/URL signals and bounded recognized skill/instruction directives; language\-specific execution and dataflow are not analyzed\. |
| javascript\_lexical | 1 | Bounded JavaScript/TypeScript tokens, calls and configuration signals; not a full JS/TS parser or control\-flow analysis\. |
| json\_structured | 17 | Parsed JSON/JSONC fields and selected configuration rules; runtime values and referenced files are not resolved\. |
| python\_ast | 926 | Python syntax, bounded local aliases/value tracking and selected security sinks; no whole\-program or interprocedural proof\. |

Severity failure threshold: **high** · Process exit code: **2**.

A clean pattern scan is not a control pass. Validate applicability and exploitability before remediation; runtime and manual checks remain required.

## Findings

<a id="finding-b9e811e29e67cd31"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: lib/cli/src/crewai\_cli/deploy/validate\.py:86–86 · Finding ID: `27c4bdaae215550927b730ae`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-4d39f07c6c256b6c"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: lib/cli/src/crewai\_cli/deploy/validate\.py:89–89 · Finding ID: `9cb95c0ae62712ab0b25af56`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-937b7ea36b47ffcf"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: lib/cli/src/crewai\_cli/deploy/validate\.py:99–99 · Finding ID: `03069aa0f0b7755c360776b2`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-47fba7aad9d5f54e"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: lib/cli/src/crewai\_cli/deploy/validate\.py:100–100 · Finding ID: `42b6334d75c3841a3177e38f`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-6290b1ba85e4d721"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: lib/cli/src/crewai\_cli/deploy/validate\.py:101–101 · Finding ID: `f94ddfd7070ae6062c6520e0`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-a8b5f684aa64dd8c"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: lib/cli/src/crewai\_cli/deploy/validate\.py:102–102 · Finding ID: `b1ad520e337242b37a2142fa`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-73c90c7e8d3839c9"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: lib/cli/src/crewai\_cli/deploy/validate\.py:104–104 · Finding ID: `618cfc06b2b80698c3949796`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-5d05ccefc9be69fe"></a>

### AI017 — JWT verification explicitly bypassed

**HIGH** · Confidence: high · Status: open

Location: lib/crewai\-core/src/crewai\_core/auth/utils\.py:34–36 · Finding ID: `2dccbd60402f0e027708e2f2`

JWT decoding explicitly disables signature verification or selects the none algorithm\. Unverified claims must never authorize agent or MCP operations\.

```text
        _unverified_decoded_token = [REDACTED]
            jwt_token, options={"verify_signature": False}
        )
```

**Remediation:** Verify signature, algorithm allowlist, issuer, audience, expiry, and scopes before using claims for authorization\.

#### Fix plan and agent/MCP relevance

Validate JWT authenticity, required claims and resource authorization before use\.

**Why this matters for agents/MCP:** MCP or agent gateways may use token claims to select tools, users and tenants\. An unverified token can let caller\-controlled claims impersonate authority across those boundaries\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Unverified decoding may be legitimate for diagnostics only if its result never authorizes actions or selects trusted state\.
- Confirm the expected issuer, key source, token type and audience for this service; do not copy a client\-supplied algorithm or key URL into verifier policy\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Restore signature verification | Remove verify\_signature=False and none from accepted signing algorithms\. Configure a fixed algorithm allowlist and trusted key source appropriate to the issuer; reject incompatible key/algorithm combinations\. | Reject an unsigned token, altered payload/signature and unexpected algorithm before the tool handler runs\. |
| 2\. Require and validate claims | Pass the expected issuer and audience to the verifier and validate expiry/not\-before with an explicit clock\-skew policy\. In PyJWT, require mandatory claims such as exp, iss and aud as well as enabling their value checks; a missing claim must not silently bypass a check\. | Test missing exp/iss/aud, wrong issuer/audience, expired and not\-yet\-valid tokens, and key rotation using a trusted test issuer\. |
| 3\. Authorize each resource and operation | After token verification, enforce the required tool scope and tenant/resource ownership on each request\. Do not use a session identifier or decoded JWT alone as permission\. | Use a correctly signed token with insufficient scope or another tenant identifier and confirm denial on a direct MCP/tool call\. |

**Remaining validation:**

- A valid token can be stolen or overprivileged; transport protection, short lifetimes and revocation/rotation behavior still require runtime validation\.

Related controls: AUTH\-03

Fix guidance sources: [REM\-PYJWT](https://pyjwt.readthedocs.io/en/stable/api.html#jwt.decode); [MCP\-AUTH](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

Weakness mappings: CWE\-347

- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-67a2761895c91be2"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: lib/crewai\-tools/src/crewai\_tools/tools/multion\_tool/example\.py:7–7 · Finding ID: `e4660cb2ac019a73596542f5`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-9db13f6a1615afda"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: lib/crewai\-tools/src/crewai\_tools/tools/multion\_tool/example\.py:9–9 · Finding ID: `5a4e61e7d189255221135b22`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-42c394d3f7de71ae"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: lib/crewai\-tools/src/crewai\_tools/tools/singlestore\_search\_tool/singlestore\_search\_tool\.py:309–309 · Finding ID: `85adbedb5e4226054387556e`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
                    cursor.execute(f"SHOW COLUMNS FROM {table}")
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-c3c3afaf2349a060"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: lib/crewai\-tools/src/crewai\_tools/tools/stagehand\_tool/\.env\.example:1–1 · Finding ID: `11afe2a4c39db184aeb86216`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-95758fa8fa874c43"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: lib/crewai\-tools/src/crewai\_tools/tools/stagehand\_tool/\.env\.example:2–2 · Finding ID: `ef165bb2704953926c7774b1`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-39e13d30708dbcbd"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: lib/crewai\-tools/src/crewai\_tools/tools/stagehand\_tool/\.env\.example:3–3 · Finding ID: `9c51c200c7f8eabc394c88e2`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-59169305d1dafc08"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: lib/crewai\-tools/src/crewai\_tools/tools/stagehand\_tool/\.env\.example:4–4 · Finding ID: `fe88374b37fabda0254dd409`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-fb48dce75aad2d9e"></a>

### AI001 — Dynamic Python code execution

**HIGH** · Confidence: medium · Status: open

Location: lib/crewai/src/crewai/flow/runtime/\_actions\.py:309–309 · Finding ID: `79fe0cdc01a7851eca229b09`

eval or exec receives a nonliteral expression\. If agent, user, or tool content can reach it, it can execute arbitrary Python\. Static analysis does not establish the full data flow\.

```text
        exec(compile(module, filename, "exec"), namespace)  # nosec B102 # noqa: S102
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

<a id="finding-4b628dbb11c0387e"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: lib/crewai/src/crewai/llms/providers/openai\_compatible/completion\.py:49–49 · Finding ID: `c36cc7796b9efc531cde6184`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-e4c868691013e15b"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: lib/crewai/src/crewai/llms/providers/openai\_compatible/completion\.py:56–56 · Finding ID: `bf5abd839b9c322d119de7be`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-b7507c0dc9e282bd"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: lib/crewai/src/crewai/llms/providers/openai\_compatible/completion\.py:62–62 · Finding ID: `d1d4da20406596fc58d3a078`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-a16475a0bc83a971"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: lib/crewai/src/crewai/llms/providers/openai\_compatible/completion\.py:69–69 · Finding ID: `4aaab87ae3c2d02524e33f15`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-93b95d3abf3878ce"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: lib/crewai/src/crewai/llms/providers/openai\_compatible/completion\.py:76–76 · Finding ID: `e14a24e8a2e7cfe9b081560c`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-783350fa2f8411b2"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: lib/crewai/src/crewai/llms/providers/openai\_compatible/completion\.py:83–83 · Finding ID: `ce3a76857d4291cf95072f17`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-520153432ed5eec9"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: lib/crewai/src/crewai/llms/providers/openai\_compatible/completion\.py:89–89 · Finding ID: `0463a5facfb23c815036d41e`

A credential\-named field contains a nonplaceholder literal\. It may be a real secret or test data; validate it without disclosing the value\.

```text
[REDACTED: credential-related source evidence; inspect this location locally]
```

**Remediation:** If real, revoke and rotate the credential, remove it from source and history, and load it from a secret manager or environment variable with least privilege\.

#### Fix plan and agent/MCP relevance

Classify the detected credential, rotate real exposure and remove embedded values\.

**Why this matters for agents/MCP:** A hardcoded model, gateway or downstream\-tool key can grant access outside the intended agent session and tenant\. Repository or image readers may obtain the credential independently of the agent approval path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether the value is a real credential, a nonsecret identifier or deliberate test data without copying the value into tickets or model prompts\.
- The detector does not validate the credential with its provider and does not establish prior misuse\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Revoke or rotate confirmed live credentials | Identify the credential owner and permissions using secret\-safe metadata\. Revoke or rotate real exposed credentials with a staged application update and review provider audit records\. | Verify the old credential is rejected and the replacement has only required model/tool scopes; retain redacted rotation evidence\. |
| 2\. Remove literals from delivery artifacts | Replace the literal with a secret\-manager lookup or runtime injection\. Remove it from tracked files, distributed image layers and relevant build artifacts; coordinate any history rewrite with repository owners\. | Rescan the source and every retained image layer, and check logs/build artifacts for the old credential through a protected secret\-scanning workflow\. |
| 3\. Limit future credential reach | Use separate per\-service or per\-tenant credentials where supported and restrict which tool workers receive them\. Exclude local secret files from version control and build contexts\. | Run a tool that does not need the credential and verify it cannot read it; confirm clean builds do not embed injected build secrets\. |

**Remaining validation:**

- Deleting source text does not invalidate a copied credential; rotation and access review remain necessary\.
- Environment injection can still expose secrets through process inheritance or diagnostics\.

Related controls: AUTH\-05, DATA\-01

Fix guidance sources: [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-798

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-4bc9303cabd2c37c"></a>

### AI036 — SQL query constructed with interpolation

**HIGH** · Confidence: medium · Status: open

Location: lib/crewai/src/crewai/memory/storage/kickoff\_task\_outputs\_storage\.py:163–163 · Finding ID: `1c257f99645334875880b6ee`

A database execution call receives an interpolated or concatenated SQL expression\. If untrusted content contributes, it may change the query's meaning\.

```text
                    cursor.execute(query, tuple(values))
```

**Remediation:** Use bound query parameters for values and an explicit allowlist for dynamic SQL identifiers or operations\.

#### Fix plan and agent/MCP relevance

Bind SQL values and authorize the allowed query operation and tenant scope\.

**Why this matters for agents/MCP:** A database MCP tool may interpolate model\-selected filters or generated SQL\. If external text changes SQL structure, the tool can access or modify data beyond the intended user request and tenant\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether interpolation contributes values, identifiers or fixed trusted fragments; this rule does not prove attacker\-controlled SQL\.
- Parameter binding handles values, not arbitrary table names, operators or complete model\-generated query programs\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Parameterize data values | Replace f\-strings, format/percent substitution and concatenated values with the database driver parameter API\. For sqlite3 use placeholders and a separate parameter sequence; use the deployed driver placeholder syntax elsewhere\. | Query for a literal containing SQL\-like punctuation and confirm it remains one value with the expected result set and no additional statement\. |
| 2\. Constrain query structure | Select identifiers, sort directions and operations from explicit server\-owned allowlists\. If a tool supports generated SQL, use a deliberately restricted query service and database permissions rather than assuming parameterization can sanitize the whole query\. | Reject an unapproved table, write operation and multi\-statement request while preserving required read queries\. |
| 3\. Enforce tenant and database authority | Bind the caller to row/resource scope independently of model\-provided filters and use a minimally privileged database account with query time/row limits\. | Use a valid caller with another tenant key and an expensive query; verify data isolation and resource\-limit enforcement at the actual database boundary\. |

**Remaining validation:**

- A parameterized query can still expose every row if authorization predicates are missing; validate the business and tenant constraints separately\.

Related controls: EXEC\-03

Fix guidance sources: [REM\-PY\-SQLITE](https://docs.python.org/3/library/sqlite3.html#sqlite3-placeholders); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-89

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-721c9778039e2499"></a>

### AI005 — Executable deserialization requires trusted inputs

**HIGH** · Confidence: medium · Status: open

Location: lib/crewai/src/crewai/utilities/file\_handler\.py:166–166 · Finding ID: `3f3582d92e63364d20ae13d3`

Pickle\-compatible deserialization can execute code\. This finding identifies a dangerous trust boundary, not proof that the serialized input is attacker controlled\.

```text
                    return pickle.load(file)  # noqa: S301
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

<a id="finding-a2a6048be9013df6"></a>

### AI040 — Unsafe HTML rendering boundary

**MEDIUM** · Confidence: medium · Status: open

Location: lib/crewai/src/crewai/flow/visualization/assets/interactive\.js:1467–1467 · Finding ID: `8b3833f27d56aa534cae0980`

Dynamic content is passed to an HTML rendering bypass\. Agent or tool\-generated content may contain executable browser markup if not sanitized\.

```text
    this.elements.content.innerHTML = content;
```

**Remediation:** Render untrusted output as text or sanitize with a maintained HTML policy before using a raw\-HTML sink; apply a restrictive content security policy\.

#### Fix plan and agent/MCP relevance

Render agent/tool output as text or apply a maintained HTML sanitization policy\.

**Why this matters for agents/MCP:** Agent messages and MCP results may contain attacker\-origin content\. Passing that output to innerHTML, dangerouslySetInnerHTML or a similar raw sink can execute browser markup with access to the application session\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Confirm whether a maintained sanitizer already processes the exact value and whether later transformations can reintroduce markup\.
- Some applications intentionally support rich HTML; a raw sink alone does not prove exploitable XSS\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Use a text\-safe rendering API | Replace the raw\-HTML sink with textContent or the framework default escaped text binding when formatting is unnecessary\. Keep URL and attribute handling appropriate to their specific context\. | Render script tags, event\-handler attributes and HTML\-looking tool output and verify they appear as text without executing\. |
| 2\. Sanitize required rich content | Where HTML is necessary, apply a maintained sanitizer such as DOMPurify with a narrow tag/attribute/URL policy immediately before the sink\. Avoid mutating sanitized HTML through unsafe downstream transformations\. | Test script/event attributes, dangerous URL schemes and SVG/MathML edge cases relevant to the chosen policy in the actual rendering environment\. |
| 3\. Add independent browser controls | Deploy a restrictive Content Security Policy and appropriate frame/session controls, and keep the sanitizer and DOM implementation patched\. Do not use CSP as a substitute for correct rendering\. | Verify representative injected markup cannot execute in the deployed page and legitimate formatting still works; inspect policy violations and sanitizer regression results\. |

**Remaining validation:**

- HTML sanitization does not validate the truth or authorization of generated instructions, links or actions; agent UI still needs explicit action policy\.

Related controls: EXEC\-07

Fix guidance sources: [REM\-DOMPURIFY](https://github.com/cure53/DOMPurify); [OWASP\-OUTPUT2025](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

Weakness mappings: CWE\-79

- [Reference](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)

<a id="finding-897bf3e80b39f6af"></a>

### AI040 — Unsafe HTML rendering boundary

**MEDIUM** · Confidence: medium · Status: open

Location: lib/crewai/src/crewai/flow/visualization/assets/interactive\.js:2449–2449 · Finding ID: `44de396274469bfe8faf7373`

Dynamic content is passed to an HTML rendering bypass\. Agent or tool\-generated content may contain executable browser markup if not sanitized\.

```text
      themeToggle.innerHTML = `<i data-lucide="${iconName}" style="width: 18px; height: 18px;"></i>`;
```

**Remediation:** Render untrusted output as text or sanitize with a maintained HTML policy before using a raw\-HTML sink; apply a restrictive content security policy\.

#### Fix plan and agent/MCP relevance

Render agent/tool output as text or apply a maintained HTML sanitization policy\.

**Why this matters for agents/MCP:** Agent messages and MCP results may contain attacker\-origin content\. Passing that output to innerHTML, dangerouslySetInnerHTML or a similar raw sink can execute browser markup with access to the application session\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Confirm whether a maintained sanitizer already processes the exact value and whether later transformations can reintroduce markup\.
- Some applications intentionally support rich HTML; a raw sink alone does not prove exploitable XSS\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Use a text\-safe rendering API | Replace the raw\-HTML sink with textContent or the framework default escaped text binding when formatting is unnecessary\. Keep URL and attribute handling appropriate to their specific context\. | Render script tags, event\-handler attributes and HTML\-looking tool output and verify they appear as text without executing\. |
| 2\. Sanitize required rich content | Where HTML is necessary, apply a maintained sanitizer such as DOMPurify with a narrow tag/attribute/URL policy immediately before the sink\. Avoid mutating sanitized HTML through unsafe downstream transformations\. | Test script/event attributes, dangerous URL schemes and SVG/MathML edge cases relevant to the chosen policy in the actual rendering environment\. |
| 3\. Add independent browser controls | Deploy a restrictive Content Security Policy and appropriate frame/session controls, and keep the sanitizer and DOM implementation patched\. Do not use CSP as a substitute for correct rendering\. | Verify representative injected markup cannot execute in the deployed page and legitimate formatting still works; inspect policy violations and sanitizer regression results\. |

**Remaining validation:**

- HTML sanitization does not validate the truth or authorization of generated instructions, links or actions; agent UI still needs explicit action policy\.

Related controls: EXEC\-07

Fix guidance sources: [REM\-DOMPURIFY](https://github.com/cure53/DOMPurify); [OWASP\-OUTPUT2025](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

Weakness mappings: CWE\-79

- [Reference](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)

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

Category: Identity and authorization · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Verify signature with trusted keys, allowed algorithms, expected issuer/audience, expiry, and required scopes\.
- [ ] Reject unsigned tokens and tokens minted for another service; decoding a JWT alone is not validation\.

Partial static rules: AI017

Open finding IDs: 2dccbd60402f0e027708e2f2
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

Open finding IDs: 27c4bdaae215550927b730ae, 9cb95c0ae62712ab0b25af56, 03069aa0f0b7755c360776b2, 42b6334d75c3841a3177e38f, f94ddfd7070ae6062c6520e0, b1ad520e337242b37a2142fa, 618cfc06b2b80698c3949796, e4660cb2ac019a73596542f5, 5a4e61e7d189255221135b22, 11afe2a4c39db184aeb86216, ef165bb2704953926c7774b1, 9c51c200c7f8eabc394c88e2, fe88374b37fabda0254dd409, c36cc7796b9efc531cde6184, bf5abd839b9c322d119de7be, d1d4da20406596fc58d3a078, 4aaab87ae3c2d02524e33f15, e14a24e8a2e7cfe9b081560c, ce3a76857d4291cf95072f17, 0463a5facfb23c815036d41e
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

Category: MCP protocol and tools · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Inspect descriptions, schemas, resources, icons, and results for instructions that cross tool or user boundaries\.
- [ ] Never let readOnlyHint, destructiveHint, or other server claims replace independent authorization and approval policy\.

Partial static rules: AI043, AI044, AI046
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [Source](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)

### MCP\-04: Detect tool substitution and metadata changes

Category: MCP protocol and tools · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Bind tool approval to verified server identity and the reviewed tool definition or version\.
- [ ] Revalidate changes after reconnect/list updates; disambiguate collisions across servers without trusting display names\.

Partial static rules: AI046
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

Partial static rules: AI031, AI045
- [Source](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)

### AGT\-03: Separate untrusted content from authoritative instructions

Category: Agent behavior and context · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Track origin and trust level for web pages, documents, messages, OCR, tool results, and repository instructions\.
- [ ] Test direct and indirect goal hijacking; formatting delimiters and prompt warnings alone are not access controls\.

Partial static rules: AI032, AI043
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

Category: Agent behavior and context · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Inventory skill files, prompts, hooks, memory seed files, MCP configuration, and other executable workflow inputs\.
- [ ] Require review for changes that add commands, access, or persistence; external repository text cannot become trusted policy\.

Partial static rules: AI043, AI044, AI045
- [Source](https://github.com/mitre-atlas/atlas-data)
- [Source](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development)
- [Source](https://agentskills.io/specification)

### AGT\-07: Prevent sensitive context leaving through legitimate tools

Category: Agent behavior and context · Status: no\_pattern\_detected · Validation: dynamic

Partial static coverage only; absence of a finding is not a pass

- [ ] Apply destination and data policies to URLs, searches, tickets, messages, uploads, and telemetry generated by agents\.
- [ ] Use canary data to test encoded leakage and combinations of otherwise permitted tools\.

Partial static rules: AI044
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

Open finding IDs: 79fe0cdc01a7851eca229b09
- [Source](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)

### EXEC\-03: Parameterize database and query operations

Category: Execution and application security · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Use bound query parameters and allowed query shapes; inspect SQL, NoSQL, graph, and search\-language construction\.
- [ ] Separate read/write database identities and test whether generated queries can escape permitted objects or operations\.

Partial static rules: AI036

Open finding IDs: 85adbedb5e4226054387556e, 1c257f99645334875880b6ee
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

Open finding IDs: 3f3582d92e63364d20ae13d3
- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)

### EXEC\-07: Render model and tool output safely

Category: Execution and application security · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Use context\-specific escaping for HTML/Markdown, avoid unsafe DOM sinks, and validate links and embedded media\.
- [ ] Test active SVG/HTML, malicious URLs, terminal escapes, and spreadsheet formulas in exported reports\.

Partial static rules: AI039, AI040

Open finding IDs: 8b3833f27d56aa534cae0980, 44de396274469bfe8faf7373
- [Source](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

### DATA\-01: Detect and remove embedded credentials

Category: Data and privacy · Status: findings\_detected · Validation: static

Partial static coverage only; absence of a finding is not a pass

- [ ] Inspect code, examples, configuration, notebooks, test fixtures, and generated artifacts for secret\-like values\.
- [ ] Verify actual exposures with the owner, rotate real credentials, and remove them from reachable history and artifacts\.

Partial static rules: AI010, AI011, AI030, AI034

Open finding IDs: 27c4bdaae215550927b730ae, 9cb95c0ae62712ab0b25af56, 03069aa0f0b7755c360776b2, 42b6334d75c3841a3177e38f, f94ddfd7070ae6062c6520e0, b1ad520e337242b37a2142fa, 618cfc06b2b80698c3949796, e4660cb2ac019a73596542f5, 5a4e61e7d189255221135b22, 11afe2a4c39db184aeb86216, ef165bb2704953926c7774b1, 9c51c200c7f8eabc394c88e2, fe88374b37fabda0254dd409, c36cc7796b9efc531cde6184, bf5abd839b9c322d119de7be, d1d4da20406596fc58d3a078, 4aaab87ae3c2d02524e33f15, e14a24e8a2e7cfe9b081560c, ce3a76857d4291cf95072f17, 0463a5facfb23c815036d41e
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

### DATA\-02: Minimize data sent to models and gateways

Category: Data and privacy · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Map which prompts, tool outputs, memory, and code leave the environment and identify the receiving provider/gateway\.
- [ ] Document allowed data classes, processing location, retention, and training use; redact before transmission where required\.
- [Source](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)

### DATA\-03: Protect logs, traces, and error responses

Category: Data and privacy · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Redact secrets and sensitive payloads before logs, traces, exception strings, and dashboards persist them\.
- [ ] Test the failure paths and provider errors as well as success paths; restrict access and export destinations\.

Partial static rules: AI009, AI033
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

Category: Supply chain · Status: no\_pattern\_detected · Validation: static

Partial static coverage only; absence of a finding is not a pass

- [ ] Review lockfiles and exact versions or immutable digests for packages, images, MCP servers, models, and plugins\.
- [ ] Flag runtime installs, floating tags, remote scripts, and dependency sources outside approved registries\.

Partial static rules: AI018, AI024, AI025
- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)

### SUP\-02: Check vulnerability and maintenance exposure

Category: Supply chain · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Run appropriate package/container advisory tools against resolved dependencies and save database date and tool version\.
- [ ] Triage reachability, fix availability, support status, and transitive dependencies; source pattern scans do not establish CVE coverage\.
- [Source](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development)

### SUP\-03: Verify artifact identity and provenance

Category: Supply chain · Status: no\_pattern\_detected · Validation: manual

Partial static coverage only; absence of a finding is not a pass

- [ ] Verify publisher identity, hashes/signatures, build provenance, and intended origin before enabling artifacts\.
- [ ] Review model loading and serialization behavior; an integrity hash cannot make an untrusted publisher safe\.

Partial static rules: AI019, AI024, AI035
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

Dependency manifests: 12; agent/MCP signal files: 745.

Dependency manifests are inventoried, not checked against a vulnerability database.

### Scan errors

- lib/cli/src/crewai\_cli/templates/crew/crew\.py: Python syntax could not be parsed at line 7: invalid syntax; AST\-based checks were skipped\.
- lib/cli/src/crewai\_cli/templates/crew/main\.py: Python syntax could not be parsed at line 7: invalid syntax; AST\-based checks were skipped\.
- lib/cli/src/crewai\_cli/templates/flow/main\.py: Python syntax could not be parsed at line 8: invalid syntax; AST\-based checks were skipped\.
- lib/cli/src/crewai\_cli/templates/json\_crew/agent\.jsonc: JSON could not be parsed at line 5: Expecting property name enclosed in double quotes; structured configuration checks were skipped\.
- lib/cli/src/crewai\_cli/templates/json\_crew/agent\_settings\.jsonc: JSON could not be parsed at line 2: Extra data; structured configuration checks were skipped\.
- lib/cli/src/crewai\_cli/templates/json\_crew/crew\.jsonc: JSON could not be parsed at line 3: Expecting property name enclosed in double quotes; structured configuration checks were skipped\.
- lib/cli/src/crewai\_cli/templates/json\_crew/task\.jsonc: JSON could not be parsed at line 3: Expecting property name enclosed in double quotes; structured configuration checks were skipped\.
- lib/cli/src/crewai\_cli/templates/tool/src/\{\{folder\_name\}\}/\_\_init\_\_\.py: Python syntax could not be parsed at line 1: invalid syntax; AST\-based checks were skipped\.
- lib/cli/src/crewai\_cli/templates/tool/src/\{\{folder\_name\}\}/tool\.py: Python syntax could not be parsed at line 4: invalid syntax; AST\-based checks were skipped\.
- lib/crewai\-tools/tool\.specs\.json: Instruction\-threat inspection is bounded to 1000000 characters for source metadata; remaining instruction/tool metadata needs review\.
- lib/crewai/src/crewai/flow/runtime/\_\_init\_\_\.py: ValueError while reading or analyzing file
- lib/crewai/src/crewai/tools/base\_tool\.py: Dynamic tool description at line 765 was not resolved; instruction\-threat checks require literal metadata\.

### Excluded or skipped paths

| Path | Reason | Coverage gap |
|---|---|---|
| lib/crewai/src/crewai/flow/visualization/assets/style\.css | unsupported\_extension | outside scope |

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
      "binding_sha256": "513db3602cb2e8e332c6a65c8f789417c151d4b12e02d7d4789e876bfe537cd8",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:27c4bdaae215550927b730ae",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 lib/cli/src/crewai_cli/deploy/validate.py:86"
    },
    {
      "binding_sha256": "7aa49655478a771ee6771d4c54cde36f2f1ee2f11759c220cc5049248e422604",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:9cb95c0ae62712ab0b25af56",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 lib/cli/src/crewai_cli/deploy/validate.py:89"
    },
    {
      "binding_sha256": "1e20227c7a8d8310b2d1dd47b30b32aad34598db2e9a035f51bcda8af1c1ef06",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:03069aa0f0b7755c360776b2",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 lib/cli/src/crewai_cli/deploy/validate.py:99"
    },
    {
      "binding_sha256": "292f106261cd3018f2f4647ede2125acd9a8bc6449bd3ea8ab376a24450192dc",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:42b6334d75c3841a3177e38f",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 lib/cli/src/crewai_cli/deploy/validate.py:100"
    },
    {
      "binding_sha256": "b3c92c8d16a5e9c4a2a79083500b8b2381597915c59fe99f88b26f16c67ee21e",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:f94ddfd7070ae6062c6520e0",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 lib/cli/src/crewai_cli/deploy/validate.py:101"
    },
    {
      "binding_sha256": "8f0025ace90fbb04e41a4be608609f80b7a69b81d23e1baa5e73a83dc8f9c4e2",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:b1ad520e337242b37a2142fa",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 lib/cli/src/crewai_cli/deploy/validate.py:102"
    },
    {
      "binding_sha256": "faab585401c96b476d7784aa2c3cd2a5bf7527675b0ba0c170508f8983b5a5cf",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:618cfc06b2b80698c3949796",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 lib/cli/src/crewai_cli/deploy/validate.py:104"
    },
    {
      "binding_sha256": "7108f18cf62022d9d2091a267503ed2b7a491b05dbd1c95d9dcad2cf03f60f57",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:2dccbd60402f0e027708e2f2",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI017 JWT verification explicitly bypassed \u2014 lib/crewai-core/src/crewai_core/auth/utils.py:34"
    },
    {
      "binding_sha256": "175ae18a8f3d209778bcd31f107b7468e6b4c00e5c56cd8878d49faab53416df",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:e4660cb2ac019a73596542f5",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 lib/crewai-tools/src/crewai_tools/tools/multion_tool/example.py:7"
    },
    {
      "binding_sha256": "612191c2a75d7748acb0a3b7ca4c1c3a6b683c901acb0919b628bbd17299d3cd",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:5a4e61e7d189255221135b22",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 lib/crewai-tools/src/crewai_tools/tools/multion_tool/example.py:9"
    },
    {
      "binding_sha256": "2077500c7abb41397d6c878a2178ffda9d711f9e0d6b9cd3b536291abbf0a5f4",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:85adbedb5e4226054387556e",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 lib/crewai-tools/src/crewai_tools/tools/singlestore_search_tool/singlestore_search_tool.py:309"
    },
    {
      "binding_sha256": "e2d2d23e017601da929242497908f1dcbad0b683cd73b37a908caf781a5ccf8f",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:11afe2a4c39db184aeb86216",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 lib/crewai-tools/src/crewai_tools/tools/stagehand_tool/.env.example:1"
    },
    {
      "binding_sha256": "09c63aebbcefc339c9b6088d010f98a70096e0fcfb674c7f22b30f41d376d6f3",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:ef165bb2704953926c7774b1",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 lib/crewai-tools/src/crewai_tools/tools/stagehand_tool/.env.example:2"
    },
    {
      "binding_sha256": "3fc93c6cdc306552e6c6e7321c71d7a8fc43b6692706c6de46c8a361a4873095",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:9c51c200c7f8eabc394c88e2",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 lib/crewai-tools/src/crewai_tools/tools/stagehand_tool/.env.example:3"
    },
    {
      "binding_sha256": "9f85f9405945039fbfa75feb646e2c24f22f07cdd5a9d2c7a99bf97351998f8a",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:fe88374b37fabda0254dd409",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 lib/crewai-tools/src/crewai_tools/tools/stagehand_tool/.env.example:4"
    },
    {
      "binding_sha256": "a43551159192b05079b32f2b84d9aee197aef3a33ccf25b0d74fdddf02e2bbc5",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:79fe0cdc01a7851eca229b09",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI001 Dynamic Python code execution \u2014 lib/crewai/src/crewai/flow/runtime/_actions.py:309"
    },
    {
      "binding_sha256": "330e477045dd308fa82a1826a9dfc08665077bc2713a00623ef49999075965f1",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:c36cc7796b9efc531cde6184",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 lib/crewai/src/crewai/llms/providers/openai_compatible/completion.py:49"
    },
    {
      "binding_sha256": "6957dcdbc0daba99dcb1f3b5ccc17b8199b27afb9a02868805246a40dc5ebb96",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:bf5abd839b9c322d119de7be",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 lib/crewai/src/crewai/llms/providers/openai_compatible/completion.py:56"
    },
    {
      "binding_sha256": "b14f4e0b50ef2e0859bf4e22e1a881c616a1db3265197d248e86124d349b7046",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:d1d4da20406596fc58d3a078",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 lib/crewai/src/crewai/llms/providers/openai_compatible/completion.py:62"
    },
    {
      "binding_sha256": "ff4028494da3d50bf64e93b2bab4b4fa1296665f1138a814c904c7a14940b46d",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:4aaab87ae3c2d02524e33f15",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 lib/crewai/src/crewai/llms/providers/openai_compatible/completion.py:69"
    },
    {
      "binding_sha256": "ff206aecfa0b9ef6c8dd997f0fd3ef534f569adb59cb90f29d450b9333411583",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:e14a24e8a2e7cfe9b081560c",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 lib/crewai/src/crewai/llms/providers/openai_compatible/completion.py:76"
    },
    {
      "binding_sha256": "cfcea8e868dbca1d44dea3f3f2b332c2e98f8ec5d85f7757caa688b37e897431",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:ce3a76857d4291cf95072f17",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 lib/crewai/src/crewai/llms/providers/openai_compatible/completion.py:83"
    },
    {
      "binding_sha256": "4abf780d98cab96fcd1d08ea835367bc657346d91356e0d1a8976689bb719f70",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:0463a5facfb23c815036d41e",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 lib/crewai/src/crewai/llms/providers/openai_compatible/completion.py:89"
    },
    {
      "binding_sha256": "8e9273bb70b8dd59317f49aa977792cba54280b9371926d07d4bec621fa98281",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:1c257f99645334875880b6ee",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI036 SQL query constructed with interpolation \u2014 lib/crewai/src/crewai/memory/storage/kickoff_task_outputs_storage.py:163"
    },
    {
      "binding_sha256": "dd4219af9859ac126871f95ccc7997df6e27579d032ea114e1d366ad519190fd",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:3f3582d92e63364d20ae13d3",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI005 Executable deserialization requires trusted inputs \u2014 lib/crewai/src/crewai/utilities/file_handler.py:166"
    },
    {
      "binding_sha256": "42cc189520ba8e10479f026f4eeb5d149dfe2f8c24f8f5de048fed33cdc14dec",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:8b3833f27d56aa534cae0980",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI040 Unsafe HTML rendering boundary \u2014 lib/crewai/src/crewai/flow/visualization/assets/interactive.js:1467"
    },
    {
      "binding_sha256": "f9601d334447868db20f3527cedf50d5f33aae738cf45d966e089d5e95075db2",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:44de396274469bfe8faf7373",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI040 Unsafe HTML rendering boundary \u2014 lib/crewai/src/crewai/flow/visualization/assets/interactive.js:2449"
    },
    {
      "binding_sha256": "4e731e29d6da12ae57c3b4d778654245d31d977ac4b7d5b624195adef63cf848",
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
      "binding_sha256": "07486f5b07827265ef319e2d4b429d37063304dd87788c6b70eb30894b6cf236",
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
      "binding_sha256": "c418e425e2c02729e4f4423a91dbf2af0877aeaebe12be6bf4aa7cdbdcd79252",
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
      "binding_sha256": "5907faf075a7ced2d3e8faa7c1f4c55f2770e1bbd267e339595f70e4b88b3758",
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
      "binding_sha256": "f65a94492cf3838f3f061052d1587b5eb6604bf78d5235b33dab42443e362b49",
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
      "binding_sha256": "2769dab314ba3ae44474eed4655496ab8adbbdf5fe110e1350b91b10dc270b12",
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
      "binding_sha256": "b3981a7c48e77bafba856e51d6f7931dbcfce27724fbbcc80bd5cbec59d50520",
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
      "binding_sha256": "0a2bc38ce075848810e2a1ceeae2cb1237e383e275bc57caa7bba25bde2b3104",
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
      "binding_sha256": "426a63d1c51157823aaea4dc3dced093ebf3f89ba19d9eb11811c4cd5f396c13",
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
      "binding_sha256": "d69e8f13a4a8623ebb0bd8bf7e3a895d722e242ca0ee7da6e2f6aac83db624eb",
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
      "binding_sha256": "1091deac5c106f11cc4b1a2f31df9e96900a1bef7b446a47084fb09e9c9d34c9",
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
      "binding_sha256": "b5aefa0e9e881b84b51ad4ce6105f6c8f203642d148281718f50a602181194c4",
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
      "binding_sha256": "e4acb134195fbfbeccb450d08fa71059b59ee1a838987cc2d6b31b2acb4e389d",
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
      "binding_sha256": "04901e8318174f3fcab6c9b649cb845d8177fc1b8f5f99545bdaf8a2168f3e30",
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
      "binding_sha256": "3b17e236d6ed3dfdfc0c988e3abf70176ef0ae0782d7508df9f1bd0da68686e2",
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
      "binding_sha256": "8631ae1e0ca96fea527226d2bdd298dbdfa0e09095be2d26b14794e71127f4fa",
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
      "binding_sha256": "2006d6604bbc46754774c16cd1c830fdc5bde128fcccd27fa6c903b917a93bb9",
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
      "binding_sha256": "d94ebef554665a01cb7385b7afe45201d838ca93649a1531b69f784e8666ba83",
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
      "binding_sha256": "9c8767db35e00c615fc9ccff4ebd3e67b5f95706a09f6b32acdb3813d7f94efb",
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
      "binding_sha256": "6ce0158ba24262f31e42679f82d5dd59b31fd9c19eb265e8cbdd7741a1500f03",
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
      "binding_sha256": "c42717f239130583983bf689a688872fae6e2bfc9b70b429ad316f1b5beff515",
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
      "binding_sha256": "385e71703b6dbdfcc613c789bf5e4e81c99163017701220d9d443ef92a4e2e6c",
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
      "binding_sha256": "1eeaaf824c4eca663f425a508c91fbb570c74f8929659ccb73b04334322d8ad3",
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
      "binding_sha256": "179b46519dc177484a41996cc8ad17489b3d5c13137c68224e957db26670c3db",
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
      "binding_sha256": "c5722fcf851925a9b9a74242f62c759475f598713e2cecaf87201e2116b8f9b3",
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
      "binding_sha256": "16046f8bf384477f9969fc2f41933a885d926a2dac7c31dd54e31e8d15689527",
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
      "binding_sha256": "70f5c93646c5121279ccce5783355c5d3a2b73ece17e143626b2e9a853cd3895",
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
      "binding_sha256": "3b3034b6d826a71aa4e1bcd39b1f05ecbbd8dde4d22346578a17953f36aa87d4",
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
      "binding_sha256": "43cf38b52fd69c4426eb733d2f22324d6d0897ac52695f40baab2e61f36dbe8f",
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
      "binding_sha256": "82f61468b8875f32b20f74f9c9a9ff660df74b4e8b33062217ead837ea1ce36e",
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
      "binding_sha256": "93bed15cc36433df997112813f2465f70075c168ed8bbc8f04c7ed364f978ccc",
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
      "binding_sha256": "9c5b2405caeca5f8107f923220310840783c083ac08001258e0591a9a6fa99c2",
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
      "binding_sha256": "27946b8b4d98e5321e906e4016e3361422989e28b8b9f162cced7a07f93ef442",
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
      "binding_sha256": "c5f90506884f06efd57f947fb2691f0638d1117d949beb24d783c48388d33eaf",
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
      "binding_sha256": "822bf6bb1e1c70c6a388d21a5dc9391e6a51f5e67d570a96fc43190e9b22d010",
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
      "binding_sha256": "47f4805cd01a92d9f1564f7fa0f00498663e386b9d5fa99f271bb58e5c6672c8",
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
      "binding_sha256": "f111d28428f9215c8339710f6aaa685b2a729f15476f416a932742fad336eabb",
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
      "binding_sha256": "b7df8643bbf56b80ec4caada0dca2c435b2e572928d5f90a5e737956010b1f72",
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
      "binding_sha256": "f4ff570c559080f2cf24cd54b05ec14deb86a01ca5a8b6490a4de76b0edc1957",
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
      "binding_sha256": "197ef973eaef8b617e20f77f11830eb1d333a0171e99025095986d2e3cafc961",
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
      "binding_sha256": "86a7400afb7d3aaa4f991e92ab9a4a7e9e5449269ec234a041a91e7989a221c3",
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
      "binding_sha256": "0947241bcf5b4d55c1beecd9835f940f3656335f22d09fa34a7772ff0b7b35b6",
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
      "binding_sha256": "71e8276970ea4c01a8cf9f41537de308ab618dde24e023d73b96471d51def81f",
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
      "binding_sha256": "7f1dbb34b4cd512be75f4e508eb02507ff8ffd4659456a05559c9d6b0682f6e7",
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
      "binding_sha256": "5421f14bb2ca10cee9642f4fed3d36d836e874c84e61bc24d14ac6345d7d7f5e",
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
      "binding_sha256": "de6599411edac70d5c022e45d8f3ffc77f2b60f38cf75a11b2428f46016e11ac",
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
      "binding_sha256": "3f96a3646077da1283f6f045555fee5b38d1d8cabe71fcbef6f5846cad5bc335",
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
      "binding_sha256": "baa317f74218dee261dde13cd6bfe176a29186450f7720998e66cacf3bdada2b",
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
      "binding_sha256": "3468033d762b215756cdf0bbb130917170c611e1cb8032c8553de0adc034151f",
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
      "binding_sha256": "e18f2a75d5890fddec04568618ee9419e4a055da32e915d835d97b1fa966527a",
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
      "binding_sha256": "0855f3967302875ac99fcc0493d24d921cf7b7828c34ace6684bfafbc230a3aa",
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
      "binding_sha256": "9ea2fb7adf5bd6fa129bdf8af3118465062eed35735e9ddc06556b4305aaa229",
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
      "binding_sha256": "3c2381ea6778761bf1118e55d0c92a553662b94661748e0e6a4beba79beb3084",
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
      "binding_sha256": "2572231066dffbf2ed8f95fa1f22c864219a40b297344c74398f0f690cb4da6f",
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
      "binding_sha256": "4991e43a5e4154e3f0d6380a8a7c62ce0349665b71a77186ae3548381681aeef",
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
      "binding_sha256": "09657be73af4b931d6eb14a27677ef1476f3c642a7b4830ededd6f462de213df",
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
      "binding_sha256": "770d446cbeca8f3440192a046a532c82d4eb3c9cee967707620ae87da5dff22d",
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
      "binding_sha256": "7b422289e690f0eb737c1b654d778cada64bb02617fbb1713e4e9f1fc254e15c",
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
      "binding_sha256": "e72d7fa29e508b6973f1352f12d28c0ab234a073f205731b12a9261e080000bf",
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
      "binding_sha256": "8946bec724d9ac1fcef88a594c4e2ddb79143499deab2f834bab390f0f763f1a",
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
      "binding_sha256": "e852dda7107cae07fbb03bed04b88c73ba794f2973af8e78ea53b2eaafa1ae49",
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
      "binding_sha256": "8e8ffb569c0e4c064af26a766c22bf9b8fec33ae3a0fe40601e34bf011f6abab",
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
      "binding_sha256": "8c1217e0924fa27187e45166b2fe312eb9031f4f655353f009bdf3f6f3046c1b",
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
      "binding_sha256": "6032a17925a7cd3ec716a707bfadaab2dd1e75226c86f8f8780788baaf9fa893",
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
      "binding_sha256": "e6134ad8876367675c4f51cedd32354d443e85aadcdaac248e97f0a150ea96b8",
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
      "binding_sha256": "0a6018126c3f8fb7e34b57f80fd50f9cd579203dce935d2dde0052239a1fff98",
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
      "binding_sha256": "29b1d4701d2989db12c42ad1825ad46b2ce3113658dcda68c5b00f51d1ca1a8c",
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
      "binding_sha256": "76a011900727a5eabd79d64b36963fd346c61efd84141d4ee77e76c93b2f0eb6",
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
      "binding_sha256": "ec05dd4cfcae4481ede0545469c86d7193883a36f7c1d64429ae38174a58908e",
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
      "binding_sha256": "00f85cc9b749bbde63d5b052bd04611e317946bde3700d4fcefde789076b75a5",
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
      "binding_sha256": "45aa7bdfa6a02a8b6f1731079fa76b9bb1f6d6ddc6fde326328491b977ff968a",
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
      "binding_sha256": "dd1d250af8bd3255c8758f1d57cd90e6a0c1ca0dbb2295eff9eec936cc33e96c",
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
      "binding_sha256": "a85eb40675e875960a71c2ba32131aa5427e75990091780d428ff943755774a8",
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
      "binding_sha256": "e8bc581daec5f736fb12f11a7d9232c62d9aed1805c78f66055d8160ba027d86",
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
      "binding_sha256": "e1296514af3451e763fe9902c27569a716d0ec3021e20f28de77da405801a191",
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
      "binding_sha256": "0ca640efb4224b4f3af7842e537ffe3ab0b7ce4e00624cabd52578624ab95113",
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
      "binding_sha256": "ffa6df3a75a256245429066f76f09bd4cf1a9fc67d53ff7f752fe89f56b3bf16",
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
      "binding_sha256": "7c88e26f7004de72ca3d91f9eb4de38b35377b70d11658a6818616300b593bfe",
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
      "binding_sha256": "e0fb809de4fb66c6aa45c6e541030d746a43511e8574ac7ec8026358f28f14c2",
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
      "binding_sha256": "7be17b43ad34d6b63899af34805e802a88161988f43b08932f1907333055bca2",
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
      "binding_sha256": "04e14efb50404af5e5be713285b1b10a3c52dd9f53c91cdc1bb449e385cb43df",
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
      "binding_sha256": "34f60aef48e2418e0de34660c026482c4dc91badc7af54238c2c03fd4b83fe70",
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
      "binding_sha256": "e3b89f2093ef6a1ec6c2696641ef1a24522467255e8af870430bffadb3976216",
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
      "binding_sha256": "0a5d884eb02fdd5d314c1aa2266fa821f859f95ca7823f11cad1aac2637c55a2",
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
      "binding_sha256": "c3ed3b6b04353423fd4901dae494e597f644e00fb111fbe71b8011ae101e5be4",
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
      "binding_sha256": "f4e7eed5f57b594974b6b6fce1d734aaded42d1db7c8d3d72c20635cdf3d0ec9",
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
      "binding_sha256": "25b14de594f3bea2a42dfd15a6a8c51d755c43d1ca2ee110f7be4db61bcbd50e",
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
      "binding_sha256": "64089db3afdda086b8c8cf0c5e5fce1f7028b104ddf556f6600d9268049d1f49",
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
      "binding_sha256": "a9ffc04dc41add165d609880d263962de5d66f8e0c8eeed0545123f52242a66a",
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
      "binding_sha256": "63b0688d07806ce7d696de8aa002ebaecc706986146f71e6b0419378f93c8265",
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
      "binding_sha256": "3415eeb794c0a13c6740d2f480c14d8ee5481ee0a1a82cedde915895af9c1e7f",
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
      "binding_sha256": "b51cf345631c81b023d5ace447ebcd5acda47f1b3ec9a1c2a4cb732719eb01bf",
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
      "binding_sha256": "acecfa89008fba63a0bbd0ff4bfb7deb61ce5f2a33a7465baa38bd264e14d7a0",
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
      "binding_sha256": "5cfdd834fcb3b4d73d6eaa295fc59da60ca2528539ac801f9db408cb2c3596b0",
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
      "binding_sha256": "7e41aca9dbe134d858b91ef4e54eef6cbac365c9038dd1ad750c08cb8cfd0eb0",
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
      "binding_sha256": "eb58a463a7cda9adca154ed86120c7bf6f46f84179b4a5dbc57701473c7af17e",
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
      "binding_sha256": "fdb3768de767fbca956700a518efe2c0c351ea726c8b6e0128f42ecf9198cd67",
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
      "binding_sha256": "88d65c951d0427410c33c8062c17f6accb263e599938187ed2e391c058660824",
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
      "binding_sha256": "e3e85c7f0611a9799d32d5a066fdccb01c92977f8a18d6c60b1e67b662e68d04",
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
      "binding_sha256": "900e340548f6495bd92879b8ca7e91aa5cc75b70b56426a81f7fdb50a9e49e59",
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
      "binding_sha256": "d591c536876c90afbdeb7b1763ddb2c30bc04606ca1482f7b891c50febc618ec",
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
      "binding_sha256": "8f891cf69352ebb13ca1301b43a282a224f53227e4f37eeaf96475b1a7f56344",
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
      "binding_sha256": "7882395abcc2bc35b7d2e2f326876ac5e5cc3a19b397c8e2fdc99bf544e8b686",
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
      "binding_sha256": "9547af93a5e352af5a024f01e858fbcdfc3e9e453c58332a500473c59da91385",
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
      "binding_sha256": "e33e5714ea659cc4b78f74aab443428f181a06b5dae6d8abc47863cca2bf1ea4",
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
      "binding_sha256": "4d5c48be2c25d87402e41487fa9893135e12e04d5c06742659d55b1ee1e5a060",
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
      "binding_sha256": "19c514224166b2225bedd520f9f071f244d7b369737a0964fbb87e58cd2842cf",
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
      "binding_sha256": "19c2ff10fdb97b503178791e23906532ab1e67eab0dfd5470bb344bb4ec95440",
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
      "binding_sha256": "1cbc48c87a59be3b6f9beefc52b6375803e109ecf564aed1998b507db9fb1bf2",
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
      "binding_sha256": "9ccf2a13ef392d5cc7ff3bd896f2cf5acf9dfc33ba408a1fac891e217caff0cf",
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
      "binding_sha256": "52b0a4661ddad26f09f83ca6afe314795ae4189bd461018b6995cfeca6a7a550",
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
      "binding_sha256": "3f5133507a429f9bdef349a2ac16c9b1ba556530bf02b0d516caadc012729ffd",
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
      "binding_sha256": "a1488a4a1339277504635ab5e63d8bfdb2f6100bb5aa209e9575c16f1cfc3e54",
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
      "binding_sha256": "664eb79138ceb8316ee50ffd7f61801dae960b02fd5516f149bb2338621434b4",
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
      "binding_sha256": "e290b6b33501430022d2b12ae314120611859ec54061d4f26f052a783ef49616",
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
      "binding_sha256": "5153051b8242376305a61043606535bfa2ab075b1e457f7e885ca0dd54e058bb",
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
      "binding_sha256": "5b864ed289f803d6dfe9723f2d5555964f7d65f62f0af7bd0655f8e3a8091df4",
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
      "binding_sha256": "be7402e41892e42f2f6e6217c2275bed607b0f36f819c2804e0f3f52407e4dd0",
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
      "binding_sha256": "624e7cfa2a46bd586ac8360379d4aac851930116866ead04631c853e88a84237",
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
      "binding_sha256": "1c932d037ff91b13213059d19fc7d9493f49b0fb19d6100bcfad0896d82ccfd8",
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
      "binding_sha256": "315d739ade6c66c3a07fe48cffacdfef0215e89093532cc6691afa7c198c2da0",
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
      "binding_sha256": "d6fb0823c46b2d50ffbe5914182e59dd199fecaf33c6af64f619192a04ed0f8b",
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
      "binding_sha256": "5261132ca61f9cb92ea7d75d816ba92fda34565b53335e7d79a9bb51321261de",
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
      "binding_sha256": "cacdd7e78c615c1f51b7cae4ebf0479c53112b271ba717511a24c0c2c951feb9",
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
      "binding_sha256": "7b9cfe7f1e184b0d6d09e39014afbccffe05f351574cc0ddc0c648598efaa8ca",
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
      "binding_sha256": "58416e995e50b5a30c3629f06c2cf88ab1cf1dabf7fd018fc7a605c68ad29c72",
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
      "binding_sha256": "c4336c320830ac6fafc006e3e7d3d1ecdae91775b494f2140f7dfcaa4d739229",
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
      "binding_sha256": "0cc642809199e82b29b72299137a9b7500ada969ab2d6370d251a615eaa4c40b",
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
      "binding_sha256": "fc297d99493c6bc8af34e2584fa291e25f4c4b6a6d7ba5c8da643be1f49a83d4",
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
      "binding_sha256": "5e273a74fd28c3dd3146e5bbae2460beecd1313d386a92f69e0476efc2bf6c96",
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
      "binding_sha256": "29962970d7e6a0e796d5d3f5231e23a899240ddaa7c1c43830ccc7166ce080bd",
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
      "binding_sha256": "e53d48e0c9ee8e7052dbe810e81dd2fec0f67f00bd1154f2dbd969973e6f5338",
      "decision": "",
      "evidence_ref": "",
      "id": "check:TEST-09:2",
      "kind": "check",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "TEST-09:2 Retest acquired or retrained models and adapters before release; document measured failures, model identity, coverage limits, and accepted residual risk."
    },
    {
      "binding_sha256": "afa5300b0ca0cfd9e60f2b93961d1757e830104d61d99eaaed3b12cf8d26fe61",
      "decision": "",
      "evidence_ref": "",
      "id": "gap:9e467de8a307d1c78533c0b00e5cf26e8f87808f1bdc4e0a7be1d772b27776c0",
      "kind": "gap",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "lib/cli/src/crewai_cli/templates/crew/crew.py: Python syntax could not be parsed at line 7: invalid syntax; AST-based checks were skipped."
    },
    {
      "binding_sha256": "315b045ee0d7840b18ab9964a670879c6bfbdb693cb3e9973219d6069ec5e572",
      "decision": "",
      "evidence_ref": "",
      "id": "gap:1e5e1bfa0f6f3201f6baedc3905d41b92f2a5b8c0cd635f5ce4e3333c74fbcf5",
      "kind": "gap",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "lib/cli/src/crewai_cli/templates/crew/main.py: Python syntax could not be parsed at line 7: invalid syntax; AST-based checks were skipped."
    },
    {
      "binding_sha256": "954ac846fad7b2a4690edd0c87fc3d869000b276c614c8ad7543198958e782e1",
      "decision": "",
      "evidence_ref": "",
      "id": "gap:a53988c9322c0cb49de6a06671da7dfb5927549f0eb0a3d7b933b588295d4994",
      "kind": "gap",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "lib/cli/src/crewai_cli/templates/flow/main.py: Python syntax could not be parsed at line 8: invalid syntax; AST-based checks were skipped."
    },
    {
      "binding_sha256": "8d332af9a970667934cf8d7ff6ab524c670b0ac716bb163b958fb510affc7aaa",
      "decision": "",
      "evidence_ref": "",
      "id": "gap:2a57642e5f5ec096aca6d8c2dae46f3131ff8438376a5bbe7c61fdf10deca670",
      "kind": "gap",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "lib/cli/src/crewai_cli/templates/json_crew/agent.jsonc: JSON could not be parsed at line 5: Expecting property name enclosed in double quotes; structured configuration checks were skipped."
    },
    {
      "binding_sha256": "beb59fe66f741c6edb59ac9f59dc03383a028fe7b42367afa290d6b3c35f84ee",
      "decision": "",
      "evidence_ref": "",
      "id": "gap:b72576014fbdfcc67af1feb0b67afc321e709d10522037550a45df7a392a3dd9",
      "kind": "gap",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "lib/cli/src/crewai_cli/templates/json_crew/agent_settings.jsonc: JSON could not be parsed at line 2: Extra data; structured configuration checks were skipped."
    },
    {
      "binding_sha256": "4f0ebbac064af4210edf41b54aa2a2450af0b43135a9c92d9ee5a471b20a983b",
      "decision": "",
      "evidence_ref": "",
      "id": "gap:66dbb164c0c63e98243707b9877cdcf3ce8118ed8669a64c7e2f3846ca4a7c2d",
      "kind": "gap",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "lib/cli/src/crewai_cli/templates/json_crew/crew.jsonc: JSON could not be parsed at line 3: Expecting property name enclosed in double quotes; structured configuration checks were skipped."
    },
    {
      "binding_sha256": "9e7471c7b6a5b6014856beedb7af274f7309ad7ef79c93b772da6a26a02aaef7",
      "decision": "",
      "evidence_ref": "",
      "id": "gap:754ff3708eff187e24c6ff6b3a8868e4a2766e2f3ab611676f5ef3d6b8c1fbe7",
      "kind": "gap",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "lib/cli/src/crewai_cli/templates/json_crew/task.jsonc: JSON could not be parsed at line 3: Expecting property name enclosed in double quotes; structured configuration checks were skipped."
    },
    {
      "binding_sha256": "1180f86c114b2f55bab195244a75cf331adc784ecd25f5da49ef4aff03e504a4",
      "decision": "",
      "evidence_ref": "",
      "id": "gap:46f2f6ef8dcfcba3356224b60c65f3fa61813a7c0680fb51cc3a654740b42bf9",
      "kind": "gap",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "lib/cli/src/crewai_cli/templates/tool/src/{{folder_name}}/__init__.py: Python syntax could not be parsed at line 1: invalid syntax; AST-based checks were skipped."
    },
    {
      "binding_sha256": "30ce8ca3efa046b26910a76405656847bbeded6e705fde858426393f13271757",
      "decision": "",
      "evidence_ref": "",
      "id": "gap:740d01b61e447122a019ec0ac907f4fe8c604cee43039ca91cf174bcb736116e",
      "kind": "gap",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "lib/cli/src/crewai_cli/templates/tool/src/{{folder_name}}/tool.py: Python syntax could not be parsed at line 4: invalid syntax; AST-based checks were skipped."
    },
    {
      "binding_sha256": "222f365bf92d18f52f31ad1a8dd99fc488332e5cc9b63a040ce29692e2c3b003",
      "decision": "",
      "evidence_ref": "",
      "id": "gap:dc1b084e1fe073598b1e102746b1e3abaf1a931d38876078be15b6cc5efd758b",
      "kind": "gap",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "lib/crewai-tools/tool.specs.json: Instruction-threat inspection is bounded to 1000000 characters for source metadata; remaining instruction/tool metadata needs review."
    },
    {
      "binding_sha256": "c8d981c398692afb0695a58af1bd96e9bc9774d385f23ce071b40fdb2e5f02c7",
      "decision": "",
      "evidence_ref": "",
      "id": "gap:b0606b63e34521587fe229956c9f4f14ebb3552b7172b12602f24d1e3e4a224a",
      "kind": "gap",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "lib/crewai/src/crewai/flow/runtime/__init__.py: ValueError while reading or analyzing file"
    },
    {
      "binding_sha256": "b237cc403ac2e93928a22e06c1f9c89fc4ae84d84af451d60c21335a2bdee9dc",
      "decision": "",
      "evidence_ref": "",
      "id": "gap:4687faf82fa3dc3365f2e0ffd2830f1d9d12762b75cd99109874dd9dd6375e02",
      "kind": "gap",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "lib/crewai/src/crewai/tools/base_tool.py: Dynamic tool description at line 765 was not resolved; instruction-threat checks require literal metadata."
    }
  ],
  "kind": "invarune_review",
  "origin": {
    "catalog_sha256": "6cf14d276defd895985dc521fc4538e717c5cd7d576123e5c600da047aacab8f",
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
      "max_total_bytes": 300000000,
      "requested_scan_ids": [],
      "selected_control_ids": [
        "AGT-01",
        "AGT-02",
        "AGT-03",
        "AGT-04",
        "AGT-05",
        "AGT-06",
        "AGT-07",
        "AUTH-01",
        "AUTH-02",
        "AUTH-03",
        "AUTH-04",
        "AUTH-05",
        "AUTH-06",
        "AUTH-07",
        "AUTH-08",
        "AUTH-09",
        "DATA-01",
        "DATA-02",
        "DATA-03",
        "DATA-04",
        "DATA-05",
        "DATA-06",
        "EXEC-01",
        "EXEC-02",
        "EXEC-03",
        "EXEC-04",
        "EXEC-05",
        "EXEC-06",
        "EXEC-07",
        "GOV-01",
        "GOV-02",
        "GOV-03",
        "GOV-04",
        "GOV-05",
        "GOV-06",
        "MCP-01",
        "MCP-02",
        "MCP-03",
        "MCP-04",
        "MCP-05",
        "MCP-06",
        "MCP-07",
        "MCP-08",
        "MCP-09",
        "MCP-10",
        "OPS-01",
        "OPS-02",
        "OPS-03",
        "OPS-04",
        "OPS-05",
        "OPS-06",
        "SUP-01",
        "SUP-02",
        "SUP-03",
        "SUP-04",
        "SUP-05",
        "SUP-06",
        "TEST-01",
        "TEST-02",
        "TEST-03",
        "TEST-04",
        "TEST-05",
        "TEST-06",
        "TEST-07",
        "TEST-08",
        "TEST-09"
      ],
      "selected_rule_ids": [
        "AI001",
        "AI002",
        "AI003",
        "AI004",
        "AI005",
        "AI006",
        "AI007",
        "AI008",
        "AI009",
        "AI010",
        "AI011",
        "AI012",
        "AI013",
        "AI014",
        "AI015",
        "AI016",
        "AI017",
        "AI018",
        "AI019",
        "AI020",
        "AI021",
        "AI022",
        "AI023",
        "AI024",
        "AI025",
        "AI026",
        "AI027",
        "AI028",
        "AI029",
        "AI030",
        "AI031",
        "AI032",
        "AI033",
        "AI034",
        "AI035",
        "AI036",
        "AI037",
        "AI038",
        "AI039",
        "AI040",
        "AI041",
        "AI042",
        "AI043",
        "AI044",
        "AI045",
        "AI046"
      ]
    },
    "evidence_sha256": "338ae7037b75af88735fcc0a3eed2ff15948b9a58c152f2c8f990595f523736d",
    "image_limits": {},
    "manifest_sha256": "b55fab47fcd8f9c75051da21ea7b76b4c175f1ed80798f48178cdebe5ffc6b58",
    "scan_id": "50845125598b57f4c456a73a0ee94510623852219be2ce648fe275f41ea59362",
    "scope_sha256": "efcfb2ab970ccb377a9f43575e8ceba85dead1517d2ffa271f89c511785704f6",
    "target": {
      "description": "Selected source directory; paths are relative.",
      "kind": "source",
      "platform": ""
    },
    "tool": {
      "implementation_sha256": "a10cff2be83ee83ef7f016e0d9644b42b2cc9869528a91763840970dc87765f1",
      "name": "agent-mcp-security-scan",
      "version": "0.14.0"
    }
  },
  "schema_version": "1.0"
}
```
<!-- INVARUNE_REVIEW_END -->

