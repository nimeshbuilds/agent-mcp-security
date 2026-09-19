# Invarune by NimeshBuild

AI agent and MCP security report

Scan ID: `c0c0f6762caca66aa1694ccc9c8c93dc9356bfc0ee3244903cfbc814791d88ea`

This is static security triage, not certification or proof that a system is secure.

## Contents

- [Summary and immediate concerns](#executive-assessment)
- [Methods, configuration and blind spots](#methods-configuration-and-blind-spots)
- [Editable review and fresh scan](#editable-review-and-fresh-scan)
- [Scan details](#scan-details)

## Executive assessment

### Critical/high findings need prompt review

The scanner found 8 open critical/high patterns among 11 open findings\. Confirm exposure and prioritize the actions below\. Detector severity is not proof of exploitability or deployed risk\.

| Open findings | Critical/high | Affected files | Accepted baseline findings | Coverage gaps |
|---:|---:|---:|---:|---:|
| 11 | 8 | 3 | 0 | 0 |

**66 active controls** still require applicability and effectiveness validation. A completed static scan or optional review cannot establish a control pass.

**Fix guidance:** 11/11 observed findings have a deterministic fix plan and agent/MCP context. Model fix plans: 0/0 finding assessments and 0/0 answered checks. These are proposed changes requiring verification.

**What the scanner found:** Tool execution: 3; Supply chain: 2; Transport security: 2; Agent permissions: 1; Deserialization: 1; Sandboxing: 1; Secrets: 1. These are detected pattern categories, not confirmed attack paths.

**Execution:** exit 2; severity threshold high. The exit threshold does not change the review priorities below.

**Optional model review:** error. Model advice is separate from the deterministic assessment and cannot lower these priorities.

Control-review status: **error**; 0/66 controls answered, 132 unanswered checks. An answered check is not a passed check.

**Requested work is incomplete.** Inspect scan gaps and optional-review errors below; retain the static findings even when a model request failed.

## Immediate concerns and first actions

P0: critical, P1: high, P2: medium, P3: low/info\. These are deterministic review priorities based on detector severity, not incident confirmation, remediation SLAs, likelihood estimates, or residual\-risk scores\. Confidence describes the detected pattern; applicability must be checked\.

| Priority | What the scanner found | Occurrences | First action | Suggested owner |
|---|---|---:|---|---|
| P1 | [AI001: Dynamic Python code execution](#group-45290f4fa5c7) (source) | 1 | Trace the input to eval/exec and replace it with fixed operations; if generated execution is essential, isolate it before accepting untrusted input\. | Agent/tool developer |
| P1 | [AI002: Dynamic command executed through a shell](#group-66e04ed7d9ac) (source) | 1 | Remove shell interpretation, select a fixed executable, and validate each argument and permitted option\. | Agent/tool developer |
| P1 | [AI003: Dynamic os shell command](#group-f0e53150bfd5) (source) | 1 | Replace os\.system/os\.popen with a fixed executable and validated argument list; trace all contributing values\. | Agent/tool developer |
| P1 | [AI005: Executable deserialization requires trusted inputs](#group-9ee5075ce1a1) (source) | 1 | Establish who can produce and replace the input; migrate to a nonexecutable data format or restrict verified legacy artifacts to an isolated conversion path\. | Application/model pipeline owner |
| P1 | [AI006: TLS certificate verification disabled](#group-08a6f7f32c94) (source) | 1 | Enable certificate and hostname verification; install the intended CA for a private gateway and test rejection of an untrusted certificate\. | Application and gateway owner |
| P1 | [AI010: Credential\-like literal in source or configuration](#group-57a1992f928c) (source) | 1 | Determine whether the value is real without reproducing it; revoke or rotate a real exposed credential and remove retained copies through the incident process\. | Credential/service owner |
| P1 | [AI029: Remote MCP URL uses plaintext HTTP](#group-b69c379f05c4) (source) | 1 | Use HTTPS with verified certificates; if a separate protected transport is intentional, document and test every network hop and termination boundary\. | MCP/gateway owner |
| P1 | [AI031: Agent approval or sandbox safeguard explicitly bypassed](#group-0a77dbbc61c4) (source) | 1 | Review the effective permission policy and restore bounded tools and runtime isolation; require independent approval for the specific sensitive effects\. | Agent/platform owner |
| P2 | [AI018: MCP package runner resolves an unpinned artifact](#group-964934e5a62a) (source) | 1 | Resolve and approve exact executable and transitive artifacts, enforce the lock at launch, and minimize inherited environment secrets\. | MCP integration/build owner |
| P2 | [AI021: Container explicitly runs as root](#group-f42ebc88841c) (source) | 1 | Verify the final build stage and deployed user, then run with a dedicated nonroot identity unless a documented operation requires otherwise\. | Container/platform owner |
| P3 | [AI024: Container image is not digest pinned](#group-0cc3d39352a0) (source) | 1 | Identify the approved image digest and enforce it in the effective build or deployment while preserving a reviewed update process\. | Container/release owner |

## What could reduce the risk

The layers below are **proposed and unverified**. They can reduce exposure or impact only when correctly implemented and tested. Fix the underlying issue where applicable. No suggested layer, baseline exception, or model opinion lowers a finding's recorded severity.

Before accepting lower residual risk, record deployment evidence, negative-test results, owner, review date, and expiry. Confirm that requests cannot bypass the control and retest after changes.

<a id="group-45290f4fa5c7"></a>

### AI001: Dynamic Python code execution

**HIGH** · open · 1 occurrences · source

**Observed evidence:** [agent\.py:16](#finding-af20d1e161ca5c4a)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If external or generated content reaches this expression, it could execute Python with the process identity and access its files, credentials, and network\.

**Address the cause:** Trace the input to eval/exec and replace it with fixed operations; if generated execution is essential, isolate it before accepting untrusted input\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Enforce action policy outside the model | Have an execution service allow only named operations, permitted argument values, and caller\-owned target resources before invoking a tool\. | Exercise disallowed operations, additional arguments, cross\-tenant identifiers, and direct calls that bypass the agent planner\. | Authorized operations can still be harmful when business constraints are incomplete; prompt instructions cannot enforce this boundary\. |
| Isolate tool execution | Run the risky tool in a separate, disposable identity with no host mounts, ambient credentials, or unnecessary outbound access\. | In a test environment, attempt reads outside the workspace, forbidden network connections, and resource exhaustion; retain policy and denial evidence\. | Isolation limits reachable assets; it does not make injected code trustworthy or rule out a runtime escape\. |

Related controls: EXEC\-02

Guidance sources (engineering synthesis): [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools); [OWASP\-AGENT\-CS](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html); [OWASP\-LLM2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/); [TECH\-PYTHON\-SECURITY](https://docs.python.org/3/library/security_warnings.html)

<a id="group-66e04ed7d9ac"></a>

### AI002: Dynamic command executed through a shell

**HIGH** · open · 1 occurrences · source

**Observed evidence:** [agent\.py:9](#finding-193f30b4480af19a)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If a caller or agent controls command content, shell syntax could alter the intended operation and execute with the tool process permissions\.

**Address the cause:** Remove shell interpretation, select a fixed executable, and validate each argument and permitted option\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Enforce action policy outside the model | Have an execution service allow only named operations, permitted argument values, and caller\-owned target resources before invoking a tool\. | Exercise disallowed operations, additional arguments, cross\-tenant identifiers, and direct calls that bypass the agent planner\. | Authorized operations can still be harmful when business constraints are incomplete; prompt instructions cannot enforce this boundary\. |
| Isolate tool execution | Run the risky tool in a separate, disposable identity with no host mounts, ambient credentials, or unnecessary outbound access\. | In a test environment, attempt reads outside the workspace, forbidden network connections, and resource exhaustion; retain policy and denial evidence\. | Isolation limits reachable assets; it does not make injected code trustworthy or rule out a runtime escape\. |

Related controls: EXEC\-01

Guidance sources (engineering synthesis): [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools); [OWASP\-AGENT\-CS](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html); [OWASP\-LLM2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/); [OWASP\-MCP10](https://owasp.org/projects/mcp-top-10); [OWASP\-OUTPUT2025](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/); [TECH\-PYTHON\-SECURITY](https://docs.python.org/3/library/security_warnings.html)

<a id="group-f0e53150bfd5"></a>

### AI003: Dynamic os shell command

**HIGH** · open · 1 occurrences · source

**Observed evidence:** [agent\.py:10](#finding-61b51e1ee40425bd)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If external values contribute to the command string, the shell could execute additional commands with the server identity\.

**Address the cause:** Replace os\.system/os\.popen with a fixed executable and validated argument list; trace all contributing values\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Enforce action policy outside the model | Have an execution service allow only named operations, permitted argument values, and caller\-owned target resources before invoking a tool\. | Exercise disallowed operations, additional arguments, cross\-tenant identifiers, and direct calls that bypass the agent planner\. | Authorized operations can still be harmful when business constraints are incomplete; prompt instructions cannot enforce this boundary\. |
| Isolate tool execution | Run the risky tool in a separate, disposable identity with no host mounts, ambient credentials, or unnecessary outbound access\. | In a test environment, attempt reads outside the workspace, forbidden network connections, and resource exhaustion; retain policy and denial evidence\. | Isolation limits reachable assets; it does not make injected code trustworthy or rule out a runtime escape\. |

Related controls: EXEC\-01

Guidance sources (engineering synthesis): [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools); [OWASP\-AGENT\-CS](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html); [OWASP\-LLM2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/); [OWASP\-MCP10](https://owasp.org/projects/mcp-top-10); [OWASP\-OUTPUT2025](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/); [TECH\-PYTHON\-SECURITY](https://docs.python.org/3/library/security_warnings.html)

<a id="group-9ee5075ce1a1"></a>

### AI005: Executable deserialization requires trusted inputs

**HIGH** · open · 1 occurrences · source

**Observed evidence:** [agent\.py:12](#finding-41a2872c0a4408e8)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If an attacker can supply or replace the serialized input, loading it may execute code even before the application examines the returned object\.

**Address the cause:** Establish who can produce and replace the input; migrate to a nonexecutable data format or restrict verified legacy artifacts to an isolated conversion path\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Verify artifact identity before use | Require reviewed artifact provenance plus a digest or signature checked against an independently trusted identity or manifest\. | Substitute bytes, producer identity, or verification metadata in a controlled test and confirm the consumer rejects the artifact\. | Authenticity establishes the producer and bytes; an approved producer can still ship vulnerable or malicious content\. |
| Separate artifact conversion from production | Perform necessary conversion of legacy serialized artifacts in a disposable environment without production data or credentials\. | Demonstrate that a conversion job cannot reach production services and only approved output formats are promoted\. | Conversion output still needs integrity, format, and downstream behavior review; isolation is not proof of benign content\. |

Related controls: EXEC\-06

Guidance sources (engineering synthesis): [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely); [NIST\-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final); [OPENSSF\-MODEL\-SIGNING](https://openssf.org/blog/2025/04/04/launch-of-model-signing-v1-0-openssf-ai-ml-working-group-secures-the-machine-learning-supply-chain/); [SLSA\-12](https://slsa.dev/spec/v1.2/); [TECH\-PYTHON\-SECURITY](https://docs.python.org/3/library/security_warnings.html); [TECH\-PYTORCH\-SERIAL](https://pytorch.org/docs/stable/notes/serialization.html)

<a id="group-08a6f7f32c94"></a>

### AI006: TLS certificate verification disabled

**HIGH** · open · 1 occurrences · source

**Observed evidence:** [agent\.py:11](#finding-b0fb0bf3edd91686)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If a network intermediary can impersonate the destination, disabled verification may expose or alter credentials, prompts, and tool responses\.

**Address the cause:** Enable certificate and hostname verification; install the intended CA for a private gateway and test rejection of an untrusted certificate\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Require authenticated encrypted transport | Use verified TLS on every relevant network hop, with an appropriate public or private CA and validated service hostname\. | Present an untrusted, expired, or wrong\-host certificate and verify rejection; inspect backend traffic after TLS termination\. | TLS does not protect data from an authorized endpoint, compromised gateway, or plaintext segments beyond termination\. |
| Restrict outbound destinations independently | Enforce an outbound policy outside the application that permits only required destinations and services; include IPv6 and proxy paths\. | From the deployed identity, test direct IP, DNS, redirect, metadata\-service, and proxy\-mediated attempts to prohibited destinations\. | Allowed destinations may themselves accept leaked data; destination rules do not replace content and action authorization\. |

Related controls: MCP\-01

Guidance sources (engineering synthesis): [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely); [MCP\-AUTH](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization); [MCP\-AUTH\-SEC](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations); [MCP\-HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="group-57a1992f928c"></a>

### AI010: Credential\-like literal in source or configuration

**HIGH** · open · 1 occurrences · source

**Observed evidence:** [mcp\.json:6](#finding-905bdaaa0ff6de85)

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

<a id="group-b69c379f05c4"></a>

### AI029: Remote MCP URL uses plaintext HTTP

**HIGH** · open · 1 occurrences · source

**Observed evidence:** [mcp\.json:10](#finding-972bd4a450d55cd8)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If remote traffic traverses an unprotected link, observers or intermediaries may read or modify MCP credentials, requests, and responses\.

**Address the cause:** Use HTTPS with verified certificates; if a separate protected transport is intentional, document and test every network hop and termination boundary\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Require authenticated encrypted transport | Use verified TLS on every relevant network hop, with an appropriate public or private CA and validated service hostname\. | Present an untrusted, expired, or wrong\-host certificate and verify rejection; inspect backend traffic after TLS termination\. | TLS does not protect data from an authorized endpoint, compromised gateway, or plaintext segments beyond termination\. |
| Limit credentials available to the workload | Give this component a distinct identity and only the downstream scopes and lifetime needed for its approved operations\. | Use its runtime identity to attempt forbidden service operations, then revoke it and confirm subsequent access fails\. | A compromised component can still use its allowed permissions until credentials expire or revocation takes effect\. |

Related controls: MCP\-01

Guidance sources (engineering synthesis): [JOINT\-AGENTIC](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services); [MCP\-AUTH](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization); [MCP\-AUTH\-SEC](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations); [MCP\-HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="group-0a77dbbc61c4"></a>

### AI031: Agent approval or sandbox safeguard explicitly bypassed

**HIGH** · open · 1 occurrences · source

**Observed evidence:** [mcp\.json:7](#finding-023509c337313312)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If unrestricted execution or disabled approval is effective, malicious context or an erroneous plan may reach sensitive actions with the agent identity\.

**Address the cause:** Review the effective permission policy and restore bounded tools and runtime isolation; require independent approval for the specific sensitive effects\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Enforce action policy outside the model | Have an execution service allow only named operations, permitted argument values, and caller\-owned target resources before invoking a tool\. | Exercise disallowed operations, additional arguments, cross\-tenant identifiers, and direct calls that bypass the agent planner\. | Authorized operations can still be harmful when business constraints are incomplete; prompt instructions cannot enforce this boundary\. |
| Bind sensitive actions to explicit approval | Require an independent approval for the exact actor, tool, normalized arguments, target, and expiry before irreversible effects occur\. | Change arguments after approval, replay the approval, and call after expiry; each attempt must be denied before a side effect\. | Approval cannot compensate for misleading previews, excessive approver authority, or actions that happen before the check\. |
| Isolate tool execution | Run the risky tool in a separate, disposable identity with no host mounts, ambient credentials, or unnecessary outbound access\. | In a test environment, attempt reads outside the workspace, forbidden network connections, and resource exhaustion; retain policy and denial evidence\. | Isolation limits reachable assets; it does not make injected code trustworthy or rule out a runtime escape\. |

Related controls: AGT\-01, AGT\-02, MCP\-09, SUP\-05

Guidance sources (engineering synthesis): [ASD\-HARNESS](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools); [OWASP\-AGENT\-CS](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html); [OWASP\-LLM2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/); [OWASP\-MCP\-CS](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)

<a id="group-964934e5a62a"></a>

### AI018: MCP package runner resolves an unpinned artifact

**MEDIUM** · open · 1 occurrences · source

**Observed evidence:** [mcp\.json:4](#finding-62e5f603bc805d76)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If the package runner resolves a changed or malicious artifact, the next MCP launch could execute different code with the client environment permissions\.

**Address the cause:** Resolve and approve exact executable and transitive artifacts, enforce the lock at launch, and minimize inherited environment secrets\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Resolve and install reviewed dependency bytes | Use a committed lock or approved artifact manifest, enforce it during installation, and retain the resolved dependency inventory\. | Build in a clean environment and compare resolved bytes; modify a lock or artifact and verify the release gate rejects it\. | An exact version or digest can still identify a vulnerable artifact; mutable transitive dependencies must also be constrained\. |
| Verify artifact identity before use | Require reviewed artifact provenance plus a digest or signature checked against an independently trusted identity or manifest\. | Substitute bytes, producer identity, or verification metadata in a controlled test and confirm the consumer rejects the artifact\. | Authenticity establishes the producer and bytes; an approved producer can still ship vulnerable or malicious content\. |
| Limit credentials available to the workload | Give this component a distinct identity and only the downstream scopes and lifetime needed for its approved operations\. | Use its runtime identity to attempt forbidden service operations, then revoke it and confirm subsequent access fails\. | A compromised component can still use its allowed permissions until credentials expire or revocation takes effect\. |

Related controls: MCP\-09, SUP\-01

Guidance sources (engineering synthesis): [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [JOINT\-AGENTIC](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices); [NIST\-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final); [OPENSSF\-BASELINE\-202608](https://baseline.openssf.org/versions/2026-08-28); [OPENSSF\-MODEL\-SIGNING](https://openssf.org/blog/2025/04/04/launch-of-model-signing-v1-0-openssf-ai-ml-working-group-secures-the-machine-learning-supply-chain/); [OWASP\-MCP\-CS](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html); [SLSA\-12](https://slsa.dev/spec/v1.2/)

<a id="group-f42ebc88841c"></a>

### AI021: Container explicitly runs as root

**MEDIUM** · open · 1 occurrences · source

**Observed evidence:** [Dockerfile:2](#finding-9f45cdff486fe6c7)

Source evidence: deployment reachability and active use have not been established\.

**Possible impact:** If this is the effective runtime user, a tool compromise may gain more authority within the container; host impact depends on mounts, capabilities, user mappings, and kernel isolation\.

**Address the cause:** Verify the final build stage and deployed user, then run with a dedicated nonroot identity unless a documented operation requires otherwise\.

| Additional defense | How it could help | Evidence needed | Remaining limitation |
|---|---|---|---|
| Apply runtime isolation controls together | Use a dedicated nonroot identity, minimal capabilities, no privilege escalation, and an enforced syscall and mandatory\-access policy where supported\. | Inspect the effective workload and attempt privileged operations, prohibited syscalls, and access to protected host resources\. | Nonroot alone is insufficient; writable mounts, added capabilities, host namespaces, and kernel flaws can weaken isolation\. |
| Separate risky tools from sensitive workloads | Place tools needing exceptional privileges in a separate environment with narrow interfaces and no unrelated tenant data\. | Test cross\-workload network and filesystem access and confirm the privileged component cannot impersonate the requesting agent\. | Shared kernels or administrative infrastructure may retain common failure paths; a container is not automatically a strong hostile\-code boundary\. |

Related controls: SUP\-05

Guidance sources (engineering synthesis): [CIS\-CONTROLS\-81](https://www.cisecurity.org/controls/v8-1); [CISA\-SECURE\-BY\-DESIGN](https://www.cisa.gov/resources-tools/resources/secure-by-design); [CSA\-CCM](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1); [JOINT\-AGENTIC](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

<a id="group-0cc3d39352a0"></a>

### AI024: Container image is not digest pinned

**LOW** · open · 1 occurrences · source

**Observed evidence:** [Dockerfile:1](#finding-0ca23a2f487902a4)

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
        "max_seconds": 600.0
      },
      "cli_login": "never",
      "cli_timeout_seconds": 120.0,
      "effective_transport": {
        "max_request_bytes": 524288,
        "max_response_bytes": 1048576,
        "model": "opus",
        "provider": "claude_cli",
        "timeout_seconds": 120.0
      },
      "enabled": true,
      "findings_limit": 100,
      "include_finding_source": true,
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
        "sarif",
        "pdf"
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
    "max_file_bytes": 1000000,
    "max_files": 20000,
    "max_total_bytes": 50000000
  }
}
```

## Scan details

Scanned **3 files**; **11 open findings**, **0 suppressed findings**, and **0 coverage gaps**.

| Critical | High | Medium | Low | Info |
|---:|---:|---:|---:|---:|
| 0 | 8 | 2 | 1 | 0 |

Source I/O: **796 bytes read**, **796 bytes charged** against the budget, including **0 conservatively charged bytes** for failed reads. Each read reserves a sentinel byte to detect growth.

### Analysis depth

File counts describe inspected inputs, not complete semantic coverage. Syntax/read failures remain listed as coverage gaps.

| Profile | Files | Analysis scope |
|---|---:|---|
| configuration\_lexical | 1 | Selected text/configuration patterns; YAML anchors, block\-scalar semantics and dynamic templates are not fully resolved\. |
| json\_structured | 1 | Parsed JSON/JSONC fields and selected configuration rules; runtime values and referenced files are not resolved\. |
| python\_ast | 1 | Python syntax, bounded local aliases/value tracking and selected security sinks; no whole\-program or interprocedural proof\. |

Severity failure threshold: **high** · Process exit code: **2**.

### Advisory security analyst

Review status: **error** · Controls reviewed: **0/66** · Unanswered checks: **132** · Control requests: **0/12**.

Every active control is routed for review because static patterns cannot establish completion. Review completion means an answer was received for every active check; it does not mean the checks passed. User-justified and disabled checks are excluded from review counts. The model is nondeterministic. Evidence selection, schema checks, and exact-quote validation are deterministic. Runtime execution and model tools are disabled.

| Advisory check status | Count |
|---|---:|
| insufficient\_evidence | 132 |

A clean pattern scan is not a control pass. Validate applicability and exploitability before remediation; runtime and manual checks remain required.

## Findings

<a id="finding-193f30b4480af19a"></a>

### AI002 — Dynamic command executed through a shell

**HIGH** · Confidence: medium · Status: open

Location: agent\.py:9–9 · Finding ID: `979d192981c1785a2394fe19`

A subprocess call enables a shell, invokes a shell\-specific API, or passes a dynamic command to an explicit shell executable\. Shell metacharacters in agent or external input may become executable syntax\.

```text
    subprocess.run(user_command, shell=True)
```

**Remediation:** Pass an argument list with shell=False, allowlist executable names and options, and enforce working\-directory and resource restrictions\.

#### Fix plan and agent/MCP relevance

Remove shell parsing and constrain the actual executable and its arguments\.

**Why this matters for agents/MCP:** An agent or MCP tool often translates model\-selected operations into subprocess commands\. Untrusted arguments embedded in a shell string can turn one permitted tool action into additional commands\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Determine whether each dynamic component can be influenced by user, retrieval, model or tool content\.
- shell=False is insufficient when the selected program is itself sh, bash, cmd, PowerShell or another interpreter receiving generated code\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Use a fixed process invocation | Replace shell=True and shell\-specific helpers with subprocess\.run using an argument list, shell=False, a fixed executable path and an explicit timeout\. Replace pipelines with separate bounded calls or native library operations\. | Submit spaces, quotes and shell metacharacters as data to a harmless test executable; assert the expected argument vector and that no additional process starts\. |
| 2\. Validate argument meaning | Allowlist flags and resource identifiers, reject caller\-selected executables, and use an end\-of\-options delimiter only where the chosen utility supports it\. Do not treat shlex\.split or shell quoting as authorization\. | Test leading\-dash filenames, unexpected flags and an interpreter executable; verify policy blocks them before process creation\. |
| 3\. Constrain process authority | Set a permitted working directory and minimal environment, bound output and runtime, and apply a separate low\-privilege execution identity where required\. Review Windows batch\-file behavior on the actual platform\. | Run denial tests for forbidden files, inherited credentials and excessive output on each deployed operating system\. |

**Remaining validation:**

- Argument arrays prevent shell parsing but cannot prevent dangerous valid options or harmful allowed operations\.
- Process timeouts do not by themselves establish descendant\-process cleanup or OS isolation\.

Related controls: EXEC\-01

Fix guidance sources: [REM\-PY\-SUBPROCESS](https://docs.python.org/3/library/subprocess.html#security-considerations); [OWASP\-AGENT\-CS](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)

Weakness mappings: CWE\-78

- [Reference](https://docs.python.org/3/library/security_warnings.html)
- [Reference](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)

<a id="finding-61b51e1ee40425bd"></a>

### AI003 — Dynamic os shell command

**HIGH** · Confidence: medium · Status: open

Location: agent\.py:10–10 · Finding ID: `0fa7e450cd583d78646ef397`

os\.system or os\.popen executes a dynamically constructed command through the shell\. Review the command's trust boundary\.

```text
    os.system(user_command)
```

**Remediation:** Use subprocess with a fixed executable and argument list, shell=False, and explicit allowed options\.

#### Fix plan and agent/MCP relevance

Replace os\.system/os\.popen with a fixed executable and validated argument list\.

**Why this matters for agents/MCP:** An MCP command tool may interpolate planner output into os\.system or os\.popen\. Those APIs introduce a shell boundary that can expand attacker\-controlled syntax into the server account privileges\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Inspect the command construction and upstream validation at the reported call; this rule does not prove an attacker can supply the value\.
- If the operation is file copying, listing or parsing, a dedicated library API often removes the shell requirement entirely\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Remove os shell APIs | Replace the operation with a native library call or subprocess\.run\(\[fixed\_executable, validated\_argument\], shell=False, timeout=\.\.\.\)\. Split intentional pipelines into explicit stages with bounded output\. | Use a harmless fixture containing shell metacharacters and assert it is processed as one argument or rejected, without a second command\. |
| 2\. Restrict operations before execution | Bind the tool name to a fixed executable and authorized workspace; validate flags and resource ownership independently of the prompt and of shell escaping\. | Call the server directly with an unauthorized path, extra option and different executable; verify rejection even without the agent planner\. |
| 3\. Close inherited authority | Supply a minimal environment, avoid carrying gateway/cloud credentials into the child, and enforce cancellation plus output limits\. | Inspect the test child environment and attempt an overlong operation; confirm sensitive variables are absent and the process is stopped\. |

**Remaining validation:**

- A correctly formed command can still modify the wrong tenant resource; policy enforcement and runtime identity remain necessary\.

Related controls: EXEC\-01

Fix guidance sources: [REM\-PY\-SUBPROCESS](https://docs.python.org/3/library/subprocess.html#security-considerations); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-78

- [Reference](https://docs.python.org/3/library/security_warnings.html)
- [Reference](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)

<a id="finding-b0fb0bf3edd91686"></a>

### AI006 — TLS certificate verification disabled

**HIGH** · Confidence: high · Status: open

Location: agent\.py:11–11 · Finding ID: `07fc5f6fd7699fd0194dc479`

Certificate verification is explicitly disabled\. A network intermediary may impersonate the remote service and capture prompts, credentials, or tool results\.

```text
    data = requests.get(remote_url, verify=False)
```

**Remediation:** Enable certificate verification and install the correct CA bundle; use a trusted private CA for custom gateways\.

#### Fix plan and agent/MCP relevance

Restore certificate and hostname verification, including custom gateways\.

**Why this matters for agents/MCP:** The affected connection can carry model credentials, prompts, MCP tool requests or retrieved evidence\. Disabling TLS verification lets a reachable intermediary impersonate that peer and influence both data and agent decisions\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Confirm which client and effective session settings apply; the detected literal does not prove this connection is used in production\.
- A private gateway CA is a trust\-distribution requirement, not a reason to disable peer verification\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Restore authenticated TLS | Remove verify=False, CERT\_NONE and hostname\-check bypasses\. Use the client default trust store or supply an approved CA bundle through its supported verification setting\. | Against a test endpoint, reject an untrusted certificate and wrong hostname while accepting the intended certificate chain\. |
| 2\. Provision gateway trust explicitly | Distribute the private CA through the runtime trust configuration, verify the configured gateway hostname, and document CA rotation\. Keep credentials out of URL query strings and diagnostics\. | Exercise certificate renewal and CA rollover in a staging environment; confirm the client never retries with verification disabled\. |
| 3\. Inspect effective runtime overrides | Check environment variables, shared HTTP sessions, proxies and image/deployment configuration for remaining bypasses on model and MCP clients\. | Run the actual deployment client through the intended proxy/gateway and retain handshake results plus redacted configuration evidence\. |

**Remaining validation:**

- Valid TLS authenticates the endpoint name, not the endpoint operator trustworthiness or its data\-retention practices\.

Related controls: MCP\-01

Fix guidance sources: [REM\-REQUESTS\-TLS](https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-295

- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-41a2872c0a4408e8"></a>

### AI005 — Executable deserialization requires trusted inputs

**HIGH** · Confidence: medium · Status: open

Location: agent\.py:12–12 · Finding ID: `d2d09fb2875db72f18779bfc`

Pickle\-compatible deserialization can execute code\. This finding identifies a dangerous trust boundary, not proof that the serialized input is attacker controlled\.

```text
    return pickle.loads(serialized_data), data.text
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

<a id="finding-af20d1e161ca5c4a"></a>

### AI001 — Dynamic Python code execution

**HIGH** · Confidence: medium · Status: open

Location: agent\.py:16–16 · Finding ID: `b1b0f0a3f33fe93875fcb58a`

eval or exec receives a nonliteral expression\. If agent, user, or tool content can reach it, it can execute arbitrary Python\. Static analysis does not establish the full data flow\.

```text
    return eval(model_response)
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

<a id="finding-905bdaaa0ff6de85"></a>

### AI010 — Credential\-like literal in source or configuration

**HIGH** · Confidence: medium · Status: open

Location: mcp\.json:6–6 · Finding ID: `afb2bdb94696690028650faf`

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

<a id="finding-023509c337313312"></a>

### AI031 — Agent approval or sandbox safeguard explicitly bypassed

**HIGH** · Confidence: high · Status: open

Location: mcp\.json:7–7 · Finding ID: `592fbfc9b7dab062dc97906c`

An agent configuration or command explicitly disables approvals or enables unrestricted execution\. The impact depends on the process identity, tools, and sandbox\.

```text
      "autoApprove": ["*"]
```

**Remediation:** Use bounded tool permissions and an isolated runtime; require deliberate approval for destructive, external, financial, or credential\-bearing actions\.

#### Fix plan and agent/MCP relevance

Restore task\-bound execution permissions and meaningful approval boundaries\.

**Why this matters for agents/MCP:** Disabling agent approval or sandbox safeguards lets model\-driven actions inherit the full process authority\. Prompt injection or a mistaken plan can then modify files, send data or invoke credentials without the intended review boundary\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Confirm the exact agent/runtime setting and the environment it affects; dedicated controlled evaluation environments may intentionally bypass prompts\.
- Approval dialogs alone do not create OS isolation, and a sandbox alone does not establish user consent for external effects\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Replace unrestricted mode with explicit permissions | Remove bypass flags and configure the agent runtime permitted tools, workspace roots and network destinations for the task\. Keep privileged administration in a separate identity/session\. | Attempt a tool outside the task allowlist and a workspace/egress escape; verify the enforcement layer denies it without relying on model compliance\. |
| 2\. Bind approvals to concrete actions | Require deliberate approval for relevant destructive, external, credential\-bearing or financial effects, displaying target and material arguments\. Expire approvals and recheck changed arguments\. | Test a denied action, replayed approval and target substitution after approval; verify no unapproved side effect occurs\. |
| 3\. Enforce isolation independently | Run tool workers with limited OS credentials, mounts, resource budgets and network rights\. Propagate reduced authority to subagents and connectors\. | Launch a delegated task and confirm it cannot acquire broader permissions, read host secrets or exceed the configured runtime budget\. |

**Remaining validation:**

- Users may approve misleading actions and allowed operations may be composed harmfully; adversarial workflow tests and audit trails remain needed\.

Related controls: AGT\-01, AGT\-02, MCP\-09, SUP\-05

Fix guidance sources: [OWASP\-AGENT\-CS](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html); [MCP\-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

Weakness mappings: CWE\-862

- [Reference](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)
- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-972bd4a450d55cd8"></a>

### AI029 — Remote MCP URL uses plaintext HTTP

**HIGH** · Confidence: high · Status: open

Location: mcp\.json:10–10 · Finding ID: `d841174f55e032505f8136b9`

An MCP configuration points to a nonloopback HTTP URL\. Credentials, tool requests, and results may be exposed in transit; network\-layer protection is not established by this scan\.

```text
      "url": "http://mcp.example.invalid/mcp"
```

**Remediation:** Use HTTPS with certificate verification for remote MCP endpoints\. Reserve plaintext HTTP for explicitly controlled local development or a documented protected transport\.

#### Fix plan and agent/MCP relevance

Use verified HTTPS for remote MCP endpoints and inspect every transport hop\.

**Why this matters for agents/MCP:** Remote MCP requests can contain access tokens, task context and tool output\. Plain HTTP exposes those bytes and allows modification by parties able to observe or influence the network path\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Confirm that the address is actually remote and identify TLS termination, tunnels and any plaintext backend hop\.
- Controlled loopback development and documented protected transport have different exposure; a URL alone cannot prove the effective network protections\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Configure an HTTPS endpoint | Replace the nonloopback HTTP MCP URL with the approved HTTPS service URL and require certificate/hostname verification\. Provision a private CA when needed\. | Use the actual MCP client to reject a wrong\-host or untrusted certificate and accept the approved endpoint\. |
| 2\. Check proxy\-to\-backend protection | Inspect all hops after TLS termination and restrict any plaintext backend segment to an explicitly controlled boundary, or use TLS/mTLS between components\. | Verify the deployment path, listeners and policy prevent an unauthorized peer from observing or reaching the backend segment\. |
| 3\. Remove insecure fallback and redirects | Ensure client retries and redirects cannot downgrade to HTTP or send credentials to another origin\. Update environment/configuration overrides alongside the launch manifest\. | Make the secure test endpoint fail or redirect to HTTP and confirm the client does not transmit an authenticated plaintext request\. |

**Remaining validation:**

- TLS does not validate tool results or protect secrets deliberately sent to an untrusted MCP server\.

Related controls: MCP\-01

Fix guidance sources: [MCP\-HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http); [MCP\-AUTH](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization); [JOINT\-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

Weakness mappings: CWE\-319

- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

<a id="finding-9f45cdff486fe6c7"></a>

### AI021 — Container explicitly runs as root

**MEDIUM** · Confidence: high · Status: open

Location: Dockerfile:2–3 · Finding ID: `20771a324af20de316ec34f9`

The default final Dockerfile stage explicitly selects or inherits a literal root user\. Build\-target selection, external image defaults, variable expansion and runtime overrides require separate validation\.

```text
USER root
COPY . /app
```

**Remediation:** Use a dedicated nonroot runtime user and minimal capabilities; verify the final build stage and deployment security context\.

#### Fix plan and agent/MCP relevance

Use a dedicated nonroot runtime identity and verify effective permissions\.

**Why this matters for agents/MCP:** An injected or overbroad agent/MCP tool action inherits the container process identity\. Root can increase access to mounted data and the impact of an isolation failure, although container root is not automatically host root\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- The finding concerns an explicit image/build default; deployment runAsUser, rootless runtimes and user namespaces may alter its effect\.
- Review the final selected build stage and actual running UID rather than assuming every build\-stage root command runs in production\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Set the runtime user | Create a dedicated service account during build and select it with USER in the final runtime stage\. In Kubernetes, configure runAsNonRoot and an appropriate numeric runAsUser where required\. | Inspect the built image user and the running process UID under the actual deployment; test startup fails rather than silently switching to root\. |
| 2\. Provision only required writable paths | Set ownership for explicit runtime/cache/workspace directories, avoid broad chmod permissions, and use a read\-only root filesystem where compatible\. | Run normal tool operations and verify they work only in approved writable directories; confirm system and other\-tenant paths are denied\. |
| 3\. Remove adjacent privilege paths | Drop unnecessary capabilities, disable privilege escalation and avoid host mounts/runtime sockets\. Ensure an entrypoint does not restore privilege\. | Inspect effective capabilities, mounts and deployment overrides and perform denied\-access tests as the worker identity\. |

**Remaining validation:**

- Nonroot execution reduces authority but does not establish tenant isolation or eliminate kernel/runtime escapes\.

Related controls: SUP\-05

Fix guidance sources: [REM\-K8S\-PODS](https://kubernetes.io/docs/concepts/security/pod-security-standards/); [REM\-DOCKER\-SECURITY](https://docs.docker.com/engine/security/)

Weakness mappings: CWE\-250

- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-62e5f603bc805d76"></a>

### AI018 — MCP package runner resolves an unpinned artifact

**MEDIUM** · Confidence: high · Status: open

Location: mcp\.json:4–4 · Finding ID: `6b77081a826c4c6833edc47f`

An MCP launch configuration uses npx, uvx, or a similar ephemeral package runner without an exact package version\. The executable artifact can change between launches\.

```text
      "command": "npx",
```

**Remediation:** Pin an exact audited package version and lock or verify transitive artifacts\. Prefer preinstalled verified tools in a controlled environment\.

#### Fix plan and agent/MCP relevance

Pin MCP launch artifacts and make the effective installation reproducible\.

**Why this matters for agents/MCP:** An MCP client often launches a package with its local user permissions and injected credentials\. Unpinned npx/uvx resolution can replace the tool implementation between launches without a reviewed configuration change\.

Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan\. The scan does not establish that this code is on an active agent or MCP request path\.

**Confirm applicability:**

- Inspect the actual package runner, registry and cache/lock behavior; a project lockfile may not govern an independent ephemeral runner\.
- An exact version reduces movement but does not prove package integrity or constrain all transitive dependencies\.

| Step | Concrete change | Verify it |
|---|---|---|
| 1\. Pin the selected package | For npm execution specify an exact package version, including scope where applicable; for uvx use an exact package version or explicit \-\-from package==version\. Keep the chosen package identity distinct from its executable name\. | Start from a clean controlled cache and record the resolved package/version; verify the MCP launch command selects that exact artifact\. |
| 2\. Verify the complete runtime artifact | Prefer a preinstalled tool built from a reviewed lockfile or verified artifact, with an approved registry and integrity data for dependencies\. Audit additional \-\-with packages and executable\-search paths\. | Compare fresh installations in controlled environments and investigate any dependency/artifact digest differences\. |
| 3\. Limit launch credentials and updates | Run the server with only task\-required credentials and workspace permissions\. Propose version updates through review, provenance checks and regression tests rather than enabling automatic latest resolution\. | Verify the launched process identity/environment and exercise a required tool after a reviewed update without expanding its permissions\. |

**Remaining validation:**

- Package cache isolation is not an operating\-system sandbox; a pinned compromised package still executes with its granted authority\.

Related controls: MCP\-09, SUP\-01

Fix guidance sources: [REM\-UV\-TOOLS](https://docs.astral.sh/uv/concepts/tools/); [REM\-NPM\-EXEC](https://docs.npmjs.com/cli/v11/commands/npm-exec/); [MCP\-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

Weakness mappings: CWE\-829

- [Reference](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- [Reference](https://www.cisa.gov/resources-tools/resources/secure-by-design)

<a id="finding-0ca23a2f487902a4"></a>

### AI024 — Container image is not digest pinned

**LOW** · Confidence: low · Status: open

Location: Dockerfile:1–1 · Finding ID: `055ed29e5f56926f1827a0b8`

A container base or deployment image uses a mutable reference rather than a content digest\. The bytes can change between builds or deployments\.

```text
FROM python:latest
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

**Advisory analyst:** not\_reviewed. Deterministic control status remains manual\_review\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10)

### GOV\-02: Model trust boundaries and attack paths

Category: Governance · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Diagram user, model, memory, tool, server, gateway, and downstream service boundaries with their credentials\.
- [ ] Identify who controls each input and the highest\-impact action reachable if that input is malicious\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains manual\_review\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://github.com/mitre-atlas/atlas-data)
- [Source](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)

### GOV\-03: Define authorized use and accountable owners

Category: Governance · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Assign an owner to each autonomous action and document permitted purposes, forbidden outcomes, and escalation routes\.
- [ ] Record impact, reversibility, approval requirements, and accepted residual risk before production use\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains manual\_review\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10)
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services)

### GOV\-04: Maintain evidence and risk exceptions

Category: Governance · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Give each control an owner, evidence link, validation date, result, and next review date\.
- [ ] Time\-limit exceptions and require a compensating control; distinguish untested behavior from demonstrated failure\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains manual\_review\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)
- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)

### GOV\-05: Reassess changes in autonomy and integrations

Category: Governance · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Review security impact when adding a model, tool, server, data source, skill, or broader permission\.
- [ ] Require deployment evidence for the complete configured system; a model\-only score is insufficient\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains manual\_review\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development)

### GOV\-06: Assign shared security responsibilities across AI providers

Category: Governance · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] For each model, gateway, orchestrator, MCP service, and cloud provider, document which party implements each applicable safeguard and which customer configuration it depends on\.
- [ ] Obtain current supplier evidence for inherited safeguards, identify unowned gaps, and record reassessment triggers in the service review\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains manual\_review\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1)
- [Source](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1)

### AUTH\-01: Authenticate protected operations on every request

Category: Identity and authorization · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Trace authentication to every protected HTTP entry point, including tool calls, subscriptions, and retries\.
- [ ] Verify missing, expired, revoked, or malformed credentials cannot invoke a protected operation\.

Partial static rules: AI026, AI041

**Advisory analyst:** not\_reviewed. Deterministic control status remains no\_pattern\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

### AUTH\-02: Authorize the exact action and target

Category: Identity and authorization · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Check user/agent identity, tenant, tool, target object, and requested operation immediately before execution\.
- [ ] Deny by default; test read\-only callers against write tools and object identifiers owned by another user\.

Partial static rules: AI027

**Advisory analyst:** not\_reviewed. Deterministic control status remains no\_pattern\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services)
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

### AUTH\-03: Validate access\-token cryptography and claims

Category: Identity and authorization · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Verify signature with trusted keys, allowed algorithms, expected issuer/audience, expiry, and required scopes\.
- [ ] Reject unsigned tokens and tokens minted for another service; decoding a JWT alone is not validation\.

Partial static rules: AI017

**Advisory analyst:** not\_reviewed. Deterministic control status remains no\_pattern\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)

### AUTH\-04: Prevent token passthrough and confused deputy use

Category: Identity and authorization · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Use audience\-bound MCP credentials and separately authorized downstream credentials; never forward arbitrary caller tokens\.
- [ ] Ensure a proxy cannot use its broader service identity to perform an action the caller cannot authorize\.

Partial static rules: AI028

**Advisory analyst:** not\_reviewed. Deterministic control status remains no\_pattern\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [Source](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

### AUTH\-05: Constrain credential lifetime and exposure

Category: Identity and authorization · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Use short\-lived scoped credentials where supported, protect refresh tokens, and validate rotation and revocation\.
- [ ] Avoid tokens in query strings, model context, source, child\-process arguments, and diagnostic output\.

Partial static rules: AI010, AI011, AI030, AI034

Open finding IDs: afb2bdb94696690028650faf

**Advisory analyst:** not\_reviewed. Deterministic control status remains findings\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

### AUTH\-06: Bind OAuth flows and validate redirects

Category: Identity and authorization · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Test PKCE support and S256, exact registered redirects, transaction binding, and authorization\-response issuer validation\.
- [ ] Reject replayed codes, mismatched issuers, unsafe redirect schemes, and unsolicited callback transactions\.

Partial static rules: AI038

**Advisory analyst:** not\_reviewed. Deterministic control status remains no\_pattern\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

### AUTH\-07: Secure OAuth discovery and registration

Category: Identity and authorization · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Validate discovered metadata and client metadata URLs before fetching; constrain schemes, destinations, redirects, and response sizes\.
- [ ] Document trust policy for client registration and prevent discovery from reaching internal metadata or privileged network services\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains review\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

### AUTH\-08: Bind delegation to identity, scope, and expiry

Category: Identity and authorization · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Carry authenticated initiator and delegation identity through multi\-agent calls instead of trusting identity fields in text\.
- [ ] Prevent agents from granting themselves privileges; limit delegation scope, depth, lifetime, and downstream audiences\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains review\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)

### AUTH\-09: Manage agent identity enrollment and retirement

Category: Identity and authorization · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Enroll agents under an accountable sponsor and approved workload identity; verify identity claims before issuing credentials or granting discovery and execution access\.
- [ ] Test retirement, sponsor departure, redeployment, and identity compromise; remove stale credentials, cached grants, registrations, and downstream access\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains runtime\_validation\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach)
- [Source](https://www.nccoe.nist.gov/publications/other/accelerating-adoption-software-and-ai-agent-identity-and-authorization-concept)

### MCP\-01: Validate transport exposure and origin

Category: MCP protocol and tools · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] For HTTP, reject invalid Origin values and verify local deployments bind only to intended interfaces\.
- [ ] Use TLS for remote protected endpoints; test DNS rebinding and proxy/header behavior in deployment\.

Partial static rules: AI006, AI007, AI008, AI029

Open finding IDs: 07fc5f6fd7699fd0194dc479, d841174f55e032505f8136b9

**Advisory analyst:** not\_reviewed. Deterministic control status remains findings\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)

### MCP\-02: Validate tool arguments and results

Category: MCP protocol and tools · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Apply schemas and semantic bounds before executing every tool; reject unknown properties where appropriate\.
- [ ] Bound sizes and nesting; validate declared structured output and render errors without leaking secrets\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains review\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)

### MCP\-03: Treat descriptions and annotations as untrusted

Category: MCP protocol and tools · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Inspect descriptions, schemas, resources, icons, and results for instructions that cross tool or user boundaries\.
- [ ] Never let readOnlyHint, destructiveHint, or other server claims replace independent authorization and approval policy\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains review\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [Source](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)

### MCP\-04: Detect tool substitution and metadata changes

Category: MCP protocol and tools · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Bind tool approval to verified server identity and the reviewed tool definition or version\.
- [ ] Revalidate changes after reconnect/list updates; disambiguate collisions across servers without trusting display names\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains review\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://owasp.org/projects/mcp-top-10)

### MCP\-05: Protect state handles and legacy sessions

Category: MCP protocol and tools · Status: no\_pattern\_detected · Validation: dynamic

Partial static coverage only; absence of a finding is not a pass

- [ ] Authorize every state handle against its owner and tenant; enforce expiry, unpredictability, and replay boundaries\.
- [ ] For older sessionful protocol versions, test session hijacking and cross\-user resumption; a session ID is not authentication\.

Partial static rules: AI038

**Advisory analyst:** not\_reviewed. Deterministic control status remains no\_pattern\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [Source](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

### MCP\-06: Constrain sampling and returned model context

Category: MCP protocol and tools · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Apply host policy and user control to sampling requests, context sharing, model selection, and associated tool access\.
- [ ] Test whether an untrusted server can induce disclosure from unrelated conversations or recursively consume model budget\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains runtime\_validation\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://modelcontextprotocol.io/specification/2026-07-28/client/sampling)

### MCP\-07: Secure elicitation and URL interactions

Category: MCP protocol and tools · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Keep sensitive credential collection out of form\-mode elicitation; validate and visibly identify URL destinations\.
- [ ] Test cancellation, phishing URLs, unsolicited interactions, and replayed completion state against the selected protocol version\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains review\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)

### MCP\-08: Enforce filesystem isolation independently of roots

Category: MCP protocol and tools · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Treat declared roots as scoped information, not an operating\-system sandbox or complete authorization mechanism\.
- [ ] Enforce allowed paths at file access and test traversal, symlinks, alternate encodings, and writes outside the workspace\.

Partial static rules: AI015

**Advisory analyst:** not\_reviewed. Deterministic control status remains no\_pattern\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://modelcontextprotocol.io/specification/2026-07-28/client/roots)

### MCP\-09: Constrain local server launch and inherited environment

Category: MCP protocol and tools · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Approve executable and package identity before starting a stdio server; use argument arrays and a minimal environment\.
- [ ] Restrict proxy process\-spawn APIs and child filesystem/network permissions; separate stdout protocol traffic from logs\.

Partial static rules: AI018, AI031

Open finding IDs: 592fbfc9b7dab062dc97906c, 6b77081a826c4c6833edc47f

**Advisory analyst:** not\_reviewed. Deterministic control status remains findings\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)
- [Source](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)

### MCP\-10: Apply version\-aware metadata, caching, and cancellation

Category: MCP protocol and tools · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Record supported revisions and test their capability, metadata, header consistency, stream, and cancellation rules\.
- [ ] Prevent caches and request continuations from crossing authorization contexts; do not apply legacy handshake assumptions universally\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains runtime\_validation\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports)
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)

### AGT\-01: Enforce action policy outside the model

Category: Agent behavior and context · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Place allow/deny decisions at the execution boundary using trusted policy inputs and constrained tool capabilities\.
- [ ] Show that an injected instruction cannot disable policy, choose privileged credentials, or bypass approval\.

Partial static rules: AI027, AI031

Open finding IDs: 592fbfc9b7dab062dc97906c

**Advisory analyst:** not\_reviewed. Deterministic control status remains findings\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses)

### AGT\-02: Bind approval to the action executed

Category: Agent behavior and context · Status: findings\_detected · Validation: dynamic

Partial static coverage only; absence of a finding is not a pass

- [ ] Present actual recipient, target, arguments, data disclosure, and consequences for high\-impact approval\.
- [ ] Invalidate approval if arguments or target change; test races, delayed retries, and approval reuse\.

Partial static rules: AI031

Open finding IDs: 592fbfc9b7dab062dc97906c

**Advisory analyst:** not\_reviewed. Deterministic control status remains findings\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)

### AGT\-03: Separate untrusted content from authoritative instructions

Category: Agent behavior and context · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Track origin and trust level for web pages, documents, messages, OCR, tool results, and repository instructions\.
- [ ] Test direct and indirect goal hijacking; formatting delimiters and prompt warnings alone are not access controls\.

Partial static rules: AI032

**Advisory analyst:** not\_reviewed. Deterministic control status remains no\_pattern\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/)

### AGT\-04: Protect retrieval and persistent memory

Category: Agent behavior and context · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Enforce document and memory ACLs at retrieval and update time, including vector search metadata filters\.
- [ ] Test poisoned memory persistence, cross\-tenant retrieval, provenance loss, deletion, and stale privileged context\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains review\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

### AGT\-05: Keep objectives and authority bounded across agents

Category: Agent behavior and context · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Constrain delegated tasks and verify messages against authenticated senders, expected schemas, and allowed transitions\.
- [ ] Test impersonation, conflicting instructions, cascading failure, and privilege growth across handoffs\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains runtime\_validation\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

### AGT\-06: Protect agent configuration and skills

Category: Agent behavior and context · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Inventory skill files, prompts, hooks, memory seed files, MCP configuration, and other executable workflow inputs\.
- [ ] Require review for changes that add commands, access, or persistence; external repository text cannot become trusted policy\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains review\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://github.com/mitre-atlas/atlas-data)
- [Source](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development)

### AGT\-07: Prevent sensitive context leaving through legitimate tools

Category: Agent behavior and context · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Apply destination and data policies to URLs, searches, tickets, messages, uploads, and telemetry generated by agents\.
- [ ] Use canary data to test encoded leakage and combinations of otherwise permitted tools\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains runtime\_validation\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)

### EXEC\-01: Prevent shell and command injection

Category: Execution and application security · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Find shell execution and constructed command strings; use fixed executables, argument arrays, and allowed argument values\.
- [ ] Test untrusted tool inputs containing shell syntax, option injection, command substitution, and hostile filenames\.

Partial static rules: AI002, AI003, AI012

Open finding IDs: 979d192981c1785a2394fe19, 0fa7e450cd583d78646ef397

**Advisory analyst:** not\_reviewed. Deterministic control status remains findings\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://owasp.org/projects/mcp-top-10)
- [Source](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

### EXEC\-02: Constrain generated\-code execution

Category: Execution and application security · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Locate eval, exec, dynamic imports, templates, notebooks, and interpreter tools accepting model or user content\.
- [ ] Run required code execution in a disposable restricted environment with explicit filesystem, network, CPU, and time limits\.

Partial static rules: AI001, AI013

Open finding IDs: b1b0f0a3f33fe93875fcb58a

**Advisory analyst:** not\_reviewed. Deterministic control status remains findings\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)

### EXEC\-03: Parameterize database and query operations

Category: Execution and application security · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Use bound query parameters and allowed query shapes; inspect SQL, NoSQL, graph, and search\-language construction\.
- [ ] Separate read/write database identities and test whether generated queries can escape permitted objects or operations\.

Partial static rules: AI036

**Advisory analyst:** not\_reviewed. Deterministic control status remains no\_pattern\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

### EXEC\-04: Constrain file and archive access

Category: Execution and application security · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Resolve and enforce allowed paths at access time; constrain uploads, downloads, extraction, temporary files, and permissions\.
- [ ] Test symlink races, archive traversal, absolute paths, overwrite attempts, and secret\-directory reads\.

Partial static rules: AI015, AI016, AI037

**Advisory analyst:** not\_reviewed. Deterministic control status remains no\_pattern\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://modelcontextprotocol.io/specification/2026-07-28/client/roots)
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

### EXEC\-05: Prevent SSRF and unsafe network destinations

Category: Execution and application security · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Restrict destinations and schemes at connection time; revalidate DNS resolution and each redirect\.
- [ ] Test loopback, private/link\-local IPv4 and IPv6, cloud metadata, alternate encodings, and redirect\-to\-private cases\.

Partial static rules: AI014

**Advisory analyst:** not\_reviewed. Deterministic control status remains no\_pattern\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)

### EXEC\-06: Reject unsafe parsing and deserialization

Category: Execution and application security · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Inspect pickle, unsafe YAML, object deserialization, XML entity expansion, and unconstrained recursive parsers\.
- [ ] Use data\-only formats with byte, nesting, and type limits; test malformed input and expansion attacks\.

Partial static rules: AI004, AI005, AI035

Open finding IDs: d2d09fb2875db72f18779bfc

**Advisory analyst:** not\_reviewed. Deterministic control status remains findings\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)

### EXEC\-07: Render model and tool output safely

Category: Execution and application security · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Use context\-specific escaping for HTML/Markdown, avoid unsafe DOM sinks, and validate links and embedded media\.
- [ ] Test active SVG/HTML, malicious URLs, terminal escapes, and spreadsheet formulas in exported reports\.

Partial static rules: AI039, AI040

**Advisory analyst:** not\_reviewed. Deterministic control status remains no\_pattern\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

### DATA\-01: Detect and remove embedded credentials

Category: Data and privacy · Status: findings\_detected · Validation: static

Partial static coverage only; absence of a finding is not a pass

- [ ] Inspect code, examples, configuration, notebooks, test fixtures, and generated artifacts for secret\-like values\.
- [ ] Verify actual exposures with the owner, rotate real credentials, and remove them from reachable history and artifacts\.

Partial static rules: AI010, AI011, AI030, AI034

Open finding IDs: afb2bdb94696690028650faf

**Advisory analyst:** not\_reviewed. Deterministic control status remains findings\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

### DATA\-02: Minimize data sent to models and gateways

Category: Data and privacy · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Map which prompts, tool outputs, memory, and code leave the environment and identify the receiving provider/gateway\.
- [ ] Document allowed data classes, processing location, retention, and training use; redact before transmission where required\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains manual\_review\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)

### DATA\-03: Protect logs, traces, and error responses

Category: Data and privacy · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Redact secrets and sensitive payloads before logs, traces, exception strings, and dashboards persist them\.
- [ ] Test the failure paths and provider errors as well as success paths; restrict access and export destinations\.

Partial static rules: AI009, AI033

**Advisory analyst:** not\_reviewed. Deterministic control status remains no\_pattern\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://owasp.org/projects/mcp-top-10)

### DATA\-04: Track provenance and integrity of AI data

Category: Data and privacy · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Record source, owner, version, transformation history, and integrity evidence for datasets, retrieval corpora, and memory seeds\.
- [ ] Quarantine unexpected changes and test how poisoned or stale data is detected, removed, and replaced\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains manual\_review\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/)

### DATA\-05: Enforce retention and deletion across copies

Category: Data and privacy · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Apply expiry and deletion to prompts, embeddings, caches, memory, tool artifacts, backups, and provider\-held data\.
- [ ] Verify deleting a source record removes or invalidates dependent retrieval content and access grants\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains runtime\_validation\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)

### DATA\-06: Protect stored data and keys

Category: Data and privacy · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Check transport verification, storage access controls, encryption settings, key separation, and backup permissions\.
- [ ] Validate key rotation and denied access using a principal outside the authorized tenant or operational role\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains review\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/)
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

### SUP\-01: Pin and inventory executable dependencies

Category: Supply chain · Status: findings\_detected · Validation: static

Partial static coverage only; absence of a finding is not a pass

- [ ] Review lockfiles and exact versions or immutable digests for packages, images, MCP servers, models, and plugins\.
- [ ] Flag runtime installs, floating tags, remote scripts, and dependency sources outside approved registries\.

Partial static rules: AI018, AI024, AI025

Open finding IDs: 6b77081a826c4c6833edc47f, 055ed29e5f56926f1827a0b8

**Advisory analyst:** not\_reviewed. Deterministic control status remains findings\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)

### SUP\-02: Check vulnerability and maintenance exposure

Category: Supply chain · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Run appropriate package/container advisory tools against resolved dependencies and save database date and tool version\.
- [ ] Triage reachability, fix availability, support status, and transitive dependencies; source pattern scans do not establish CVE coverage\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains manual\_review\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development)

### SUP\-03: Verify artifact identity and provenance

Category: Supply chain · Status: findings\_detected · Validation: manual

Partial static coverage only; absence of a finding is not a pass

- [ ] Verify publisher identity, hashes/signatures, build provenance, and intended origin before enabling artifacts\.
- [ ] Review model loading and serialization behavior; an integrity hash cannot make an untrusted publisher safe\.

Partial static rules: AI019, AI024, AI035

Open finding IDs: 055ed29e5f56926f1827a0b8

**Advisory analyst:** not\_reviewed. Deterministic control status remains findings\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/)
- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)

### SUP\-04: Protect build, release, and configuration changes

Category: Supply chain · Status: no\_pattern\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Restrict CI credentials and workflow permissions; review actions, build scripts, and release provenance\.
- [ ] Prevent untrusted contributions from executing with deployment secrets or changing approved agent policies\.

Partial static rules: AI020

**Advisory analyst:** not\_reviewed. Deterministic control status remains no\_pattern\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)

### SUP\-05: Harden runtime isolation and deployment defaults

Category: Supply chain · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Review root/privileged containers, host mounts, Docker sockets, unrestricted egress, debug mode, and public management endpoints\.
- [ ] Separate agent execution from control\-plane credentials and audit storage; test isolation in the deployed environment\.

Partial static rules: AI021, AI022, AI023, AI031, AI042

Open finding IDs: 592fbfc9b7dab062dc97906c, 20771a324af20de316ec34f9

**Advisory analyst:** not\_reviewed. Deterministic control status remains findings\_detected.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely)

### SUP\-06: Separate and protect model development environments

Category: Supply chain · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] When training or fine\-tuning, isolate development, evaluation, and production identities, data access, registries, and release permissions\.
- [ ] Protect datasets, weights, adapters, and configuration separately; monitor modifications and demonstrate that an untrusted training job cannot replace an approved production artifact\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains runtime\_validation\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://csrc.nist.gov/pubs/sp/800/218/a/final)

### OPS\-01: Produce attributable audit events

Category: Operations and resilience · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Record initiating identity, delegated identity, tool/server/version, approved arguments, decision, outcome, and correlation identifiers\.
- [ ] Protect log integrity and clock consistency; ensure agents cannot erase their own action history\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains review\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://owasp.org/projects/mcp-top-10)

### OPS\-02: Bound work, spending, and concurrency

Category: Operations and resilience · Status: review\_required · Validation: hybrid

Not established by this static scan

- [ ] Set server\-enforced limits for iterations, tokens, tool calls, recursion, parallelism, bytes, cost, and elapsed time\.
- [ ] Exercise stuck loops and amplification paths; verify limits apply across retries and child agents\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains review\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses)

### OPS\-03: Make cancellation and shutdown effective

Category: Operations and resilience · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Provide a tested stop mechanism that revokes work, credentials, queued actions, and child tasks\.
- [ ] Measure stop latency and verify cancelled or disconnected requests cannot later commit prohibited side effects\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains runtime\_validation\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services)

### OPS\-04: Fail safely and prevent duplicate side effects

Category: Operations and resilience · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Deny or escalate when policy, identity, or approval checks fail; prevent fallback paths from widening privilege\.
- [ ] Test outages, partial failures, timeouts, retries, idempotency, and recovery of transactions with external effects\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains runtime\_validation\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses)

### OPS\-05: Monitor behavior and support rollback

Category: Operations and resilience · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Alert on unusual tool use, new destinations, scope growth, repeated denials, cost spikes, and unexpected state changes\.
- [ ] Validate alerts with seeded events and test rollback of models, prompts, tools, policies, and poisoned memory\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains runtime\_validation\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development)

### OPS\-06: Practice incident response and disclosure

Category: Operations and resilience · Status: manual\_review\_required · Validation: manual

Not established by this static scan

- [ ] Maintain procedures to isolate agents, revoke credentials, preserve evidence, notify owners, and recover trusted state\.
- [ ] Exercise an AI\-specific incident and define approved vulnerability/intelligence\-sharing channels without exposing sensitive evidence\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains manual\_review\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://www.cisa.gov/news-events/alerts/2025/01/14/cisa-releases-jcdc-ai-cybersecurity-collaboration-playbook-and-fact-sheet)

### TEST\-01: Measure prompt\-injection security and useful task completion

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Run paired benign and adversarial workflows with representative tools and attacker\-controlled external content\.
- [ ] Record attacker success, authorized task success, blocked benign actions, and the observed unauthorized side effect\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains runtime\_validation\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://github.com/ethz-spylab/agentdojo)
- [Source](https://github.com/uiuc-kang-lab/InjecAgent)

### TEST\-02: Test adaptively and repeat scenarios

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Vary payload wording, placement, modality, attacker knowledge, and attempts; rerun after changing defenses\.
- [ ] Report per\-scenario outcomes, sample counts, attack budget, uncertainty, and model/harness versions instead of only an average\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains runtime\_validation\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations)

### TEST\-03: Exercise MCP authentication and protocol abuse

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] In an isolated test environment, exercise invalid tokens, wrong audiences, origin abuse, malicious servers, and protocol fuzzing\.
- [ ] Adapt scenarios to the deployed MCP revision and transports; preserve request/response evidence with secrets removed\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains runtime\_validation\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://github.com/AIS2Lab/MCPSecBench)
- [Source](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)

### TEST\-04: Verify cross\-tenant and cross\-agent isolation

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Create two principals and attempt cross\-access to objects, memory, caches, handles, subscriptions, and execution results\.
- [ ] Repeat after reconnect, delegation, failed authentication, concurrent requests, and privilege revocation\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains runtime\_validation\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://github.com/agiresearch/ASB)

### TEST\-05: Test approval, policy, and sandbox bypass

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Use explicit forbidden\-action canaries to verify enforcement survives hostile content, tool substitution, and delayed execution\.
- [ ] Confirm paths through retries, fallback models, alternate tools, and child agents enforce the same boundary\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains runtime\_validation\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)

### TEST\-06: Verify conventional application security

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Run language\-aware SAST, dependency review, secret scanning, and authorized integration tests for exposed services\.
- [ ] Exercise reachable injection, XSS, SSRF, path traversal, deserialization, and access\-control risks with safe fixtures\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains runtime\_validation\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://csrc.nist.gov/pubs/sp/800/218/final)
- [Source](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

### TEST\-07: Validate resource exhaustion and observability

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Simulate oversized messages, slow peers, streaming floods, repeated errors, runaway agents, and unavailable dependencies\.
- [ ] Verify quotas, shutdown, telemetry, and alerts work together without leaking payloads or losing attribution\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains runtime\_validation\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses)

### TEST\-08: Evaluate the optional security judge itself

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Treat repository text and model verdicts as untrusted; test prompt injection, fabricated locations, invalid JSON, and timeouts\.
- [ ] Compare against labeled cases, retain deterministic results, document model variability, and never equate a judge approval with control validation\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains runtime\_validation\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

- [Source](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations)
- [Source](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)

### TEST\-09: Evaluate model\-layer attacks for hosted or customized models

Category: Security validation · Status: runtime\_validation\_required · Validation: dynamic

Not established by this static scan

- [ ] Where applicable, assess suspicious triggers, model extraction, and disclosure of private training examples under an explicit attacker access and query budget\.
- [ ] Retest acquired or retrained models and adapters before release; document measured failures, model identity, coverage limits, and accepted residual risk\.

**Advisory analyst:** not\_reviewed. Deterministic control status remains runtime\_validation\_required.

**Check 1: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

**Check 2: insufficient\_evidence**

Control review was not started because finding triage or judge configuration failed\.

No model assessment was received for this check.

Verification still required:
- Collect the required evidence and review this check with its responsible owner\.

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

Dependency manifests: 0; agent/MCP signal files: 1.

Dependency manifests are inventoried, not checked against a vulnerability database.

### Scan errors

None.

### Excluded or skipped paths

| Path | Reason | Coverage gap |
|---|---|---|

## Optional LLM judge

Advisory, non-deterministic output. It cannot dismiss deterministic findings, establish compliance, or change the deterministic CI gate.

```text
{
  "advisory_only": true,
  "enabled": true,
  "error": "CLI sign-in is missing or expired. Run invarune --login with the selected provider, or use an interactive scan for automatic login. Deterministic results are preserved.",
  "mode": "full",
  "omitted_open_findings": 0,
  "selected_findings": 11,
  "source_context_sent_count": 11,
  "source_context_skipped": [],
  "status": "error"
}
```

## Analyst evidence and request audit

Only bounded excerpts were submitted. Missing evidence may reflect collection limits, exclusions, or retrieval misses. A verified quote establishes its presence in an excerpt, not the truth of the model's interpretation. Verification steps are proposals and have not been executed.

Evidence selection and review coverage:

```text
{
  "attempted_controls": 0,
  "call_budget": 12,
  "calls_made": 0,
  "catalog_checks": 132,
  "catalog_controls": 66,
  "disabled_checks": 0,
  "disabled_controls": 0,
  "evidence": {
    "collection_status": "not_started"
  },
  "excluded_checks": 0,
  "excluded_controls": 0,
  "justified_checks": 0,
  "justified_controls": 0,
  "omitted_checks": 132,
  "reviewed_controls": 0,
  "total_checks": 132,
  "total_controls": 66,
  "unreviewed_control_ids": [
    "GOV-01",
    "GOV-02",
    "GOV-03",
    "GOV-04",
    "GOV-05",
    "GOV-06",
    "AUTH-01",
    "AUTH-02",
    "AUTH-03",
    "AUTH-04",
    "AUTH-05",
    "AUTH-06",
    "AUTH-07",
    "AUTH-08",
    "AUTH-09",
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
    "AGT-01",
    "AGT-02",
    "AGT-03",
    "AGT-04",
    "AGT-05",
    "AGT-06",
    "AGT-07",
    "EXEC-01",
    "EXEC-02",
    "EXEC-03",
    "EXEC-04",
    "EXEC-05",
    "EXEC-06",
    "EXEC-07",
    "DATA-01",
    "DATA-02",
    "DATA-03",
    "DATA-04",
    "DATA-05",
    "DATA-06",
    "SUP-01",
    "SUP-02",
    "SUP-03",
    "SUP-04",
    "SUP-05",
    "SUP-06",
    "OPS-01",
    "OPS-02",
    "OPS-03",
    "OPS-04",
    "OPS-05",
    "OPS-06",
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
  "validated_controls": 0
}
```

- Analyst error: Control review was not started because finding triage or judge configuration failed\.

Request receipts (payload hashes and model identifiers):

```text
[]
```

The JSON report includes redacted evidence excerpts, original file hashes, complete per-check assessments, and deterministic provenance.
## Editable review and fresh scan

Edit only decision, reason, reviewer, reviewed_at and evidence_ref in the JSON block below. Keep IDs, bindings, subjects and origin unchanged. Save this Markdown file and pass it to a fresh scan with --review-report. JSON and SARIF expose the same editable fields; HTML provides a Download reviewed HTML button and optional PDF provides fillable fields.

Allowed decisions: empty (no decision), justified, disabled, note, needs_runtime_validation, needs_human_review. Nonempty decisions need a reason; justified/disabled decisions also need a reviewer. Evidence references are plain text, never fetched or executed. Gap records cannot waive scan failures.

Justifications are user exceptions, not validated passes. They are excluded from active counts without positive or negative credit. Evidence changes leave decisions unapplied and visible for re-review. Explicit pending runtime/human validation remains incomplete. A finding not detected on a fresh complete scan is not proof that a vulnerability was fixed.

Example: invarune /explicit/path/to/repository --review-report ./reviewed-report.md --output ./new-report

### Review fields

<!-- INVARUNE_REVIEW_BEGIN -->
```json
{
  "items": [
    {
      "binding_sha256": "18f1fa5798453e2d846e3bdff8d0bc73e207e6a48155c7b9b99c4f17a2158e6f",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:979d192981c1785a2394fe19",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI002 Dynamic command executed through a shell \u2014 agent.py:9"
    },
    {
      "binding_sha256": "9640699000a7ba1eac1ba86126456f6201c7c03853b23d5f3454718cc55f0c71",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:0fa7e450cd583d78646ef397",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI003 Dynamic os shell command \u2014 agent.py:10"
    },
    {
      "binding_sha256": "04afd8d9ed3908ec13dfab9c00854dd10405e1bcddc5de253ec71ac538d0322b",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:07fc5f6fd7699fd0194dc479",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI006 TLS certificate verification disabled \u2014 agent.py:11"
    },
    {
      "binding_sha256": "18fa4a5c4cb2cb5b4d1c8cdee11aa13d0cebdd1af1c2281f98e47a42aaa348c7",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:d2d09fb2875db72f18779bfc",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI005 Executable deserialization requires trusted inputs \u2014 agent.py:12"
    },
    {
      "binding_sha256": "f42fa2af2e0f69ddaee4e29866720fe7b117f85fe0c26c393cc1f0424427ea75",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:b1b0f0a3f33fe93875fcb58a",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI001 Dynamic Python code execution \u2014 agent.py:16"
    },
    {
      "binding_sha256": "4c93b01e8e290a4802d5ff969d089ac0676489544c36e6e07f1ffe8dc0fb2926",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:afb2bdb94696690028650faf",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI010 Credential-like literal in source or configuration \u2014 mcp.json:6"
    },
    {
      "binding_sha256": "cedc07f0c0134c2c7f693002f85413e02442332ea2ef06faaeacbe6ee1c75ca4",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:592fbfc9b7dab062dc97906c",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI031 Agent approval or sandbox safeguard explicitly bypassed \u2014 mcp.json:7"
    },
    {
      "binding_sha256": "8e063824dd5daac130db1685bff47b0a1d48982eb5b67cb19038dfab681cda53",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:d841174f55e032505f8136b9",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI029 Remote MCP URL uses plaintext HTTP \u2014 mcp.json:10"
    },
    {
      "binding_sha256": "66cae5bbd131da660808a9864a08a69684d51e1f109c97fff33dd97b3359eab4",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:20771a324af20de316ec34f9",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI021 Container explicitly runs as root \u2014 Dockerfile:2"
    },
    {
      "binding_sha256": "ee0dc14ec4ab14eb2fdd60b08cf19c11a75fe807e9b85d74b7b1fca4fe95f46a",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:6b77081a826c4c6833edc47f",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI018 MCP package runner resolves an unpinned artifact \u2014 mcp.json:4"
    },
    {
      "binding_sha256": "a51f7ee8cd57f60aef6d8e524ae704a619518dec510c2f45ca50d3377c933541",
      "decision": "",
      "evidence_ref": "",
      "id": "finding:055ed29e5f56926f1827a0b8",
      "kind": "finding",
      "reason": "",
      "reviewed_at": "",
      "reviewer": "",
      "subject": "AI024 Container image is not digest pinned \u2014 Dockerfile:1"
    },
    {
      "binding_sha256": "f6a3643abe18f47815dc145dc3917bf0bb204902e7fc9cc8213202377a1d3ba8",
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
      "binding_sha256": "e317796f9a2732b8a09bde89a34756a049ab502f85f448a57d0c5dab2bdf247c",
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
      "binding_sha256": "2367479e150bf143cf926ff76493cf93435e894002ef8452e6a106b695602882",
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
      "binding_sha256": "368eda76c844b2a7ddf54dbe9712e7e7087750af8b455081197e42bcaa21108a",
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
      "binding_sha256": "2aec6915d58be768b0980cf93bedb38270244354517ace014278cda3b3589e2a",
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
      "binding_sha256": "100894c8d384dd0531c1cf8ed98f7029a459d03204ceaacac4a7a22f63bd90c8",
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
      "binding_sha256": "d584f2beeaa1bdf34364513877910ea9f522e7dee038b59ec95124b42d00fb83",
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
      "binding_sha256": "2ac2ac0903ae3df4fdc28b6b792a6818146f111e5e2555e629010c42f99a7e75",
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
      "binding_sha256": "2949aab9292fb7c1f8c3a896b63acbabe0921adcaac6112b1ff84eb2a25aa264",
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
      "binding_sha256": "55602f834be85e4104f4471a2d7fa2a85e7210184a68589ed985ef1baf07da6e",
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
      "binding_sha256": "a5ec1c39571f45768527a04452838d794697f045a0176f93830a16e989e2d3d6",
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
      "binding_sha256": "fe28567530ea13443345edd2f4419f8eff71a34a4040989328853d694c2fcf57",
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
      "binding_sha256": "37b381f2c510e6f9fe38557a0401b6603af2e8a491c46decf933f8367141297c",
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
      "binding_sha256": "cb20a2499b59244f9146e062e76c66b99e91c39e3b212d4511968ccb634b213b",
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
      "binding_sha256": "9d99907518e6c60decea4bfa85fc8e1bf467d2692e8f5bbe8cef12fe4715df91",
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
      "binding_sha256": "623d05a2113dfbac538e1a6e013a8689fd16bfb4a75fe1ff95675cdadc34d993",
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
      "binding_sha256": "652b96d6140a7bbb74c94c35ee584c8cb7205ceaada8fc241c65231e373f3558",
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
      "binding_sha256": "cad3d4ad10d448dcefa72ec25148133c98b70798af41572d89fa7d732bd86c04",
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
      "binding_sha256": "7a7b860554831cfdd36a80a5cb4a0bfedf7419063dd24e8505ad39cf42eea4bb",
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
      "binding_sha256": "2f2681b054fbc34a3859557c774bab666193bf41e3ab3f2cd27215b0ca1d8c3f",
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
      "binding_sha256": "1826ff3c1c17ad48d38d62be48ad77bf6afc8308e0b6e5258915fc2b931451dd",
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
      "binding_sha256": "fd3d49ae577178ca1b76f7b6238e8702bb91ee5e5c0d65cd2d2cb9fde3ef6472",
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
      "binding_sha256": "dca1356faad6c33ca8dbf2947c76aa9c38222c959f4e36eb69bddbb82226d956",
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
      "binding_sha256": "4e37848dcade64261d548b1fe96ad4e69ef7f6a44da4e5cd5c53349cefe1d4d0",
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
      "binding_sha256": "96c56570e7e9b12e4701c4211a566beb43ad7a060c0f70eba573ab90219e9365",
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
      "binding_sha256": "1d6c85d22dc8d43080c098fa5e1229ed7109717f580d5fd2c7d0a29e8f72e6c1",
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
      "binding_sha256": "5286651654bcb7da4f5dc0749431d7915cd6730bac459ab750ee7f0bbf43bfcb",
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
      "binding_sha256": "be8c89bde29ce229329dd72a3aafb1a1b81cc6d7c8e92ad4843076c974d5e82f",
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
      "binding_sha256": "0dfaf5ae2360297d1460bb6a10d93daf39694ad2c361d8bd3353954c12f75c76",
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
      "binding_sha256": "d5563f4fba77cd33dc97abbc56dfa6d39237c7fe40983c27d607531ecf04e0be",
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
      "binding_sha256": "ef96ebcf96dc5c293d24ca080fa101d43f199f04e40f45babd5e0607c89dd5a3",
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
      "binding_sha256": "6784a4a99641de2d83cf8f52e1e112043dbf74652a586af30a6048738a4319db",
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
      "binding_sha256": "592ae83cd25affd6bea7c13b407e5f87b96fc6ca9a21241820cbc33703780825",
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
      "binding_sha256": "91351da7a9860ce4afa0cb58dd77a1317e3fb884559d2ad69a67d9e8929049f7",
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
      "binding_sha256": "62eae80afd3678e88e958ac8eedc37664655c6683f61d88c9d5ccb4da0294dce",
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
      "binding_sha256": "7ead0870bfe726739d543dc0f6509be2061f13d4685c3de8da38bb53567e2cde",
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
      "binding_sha256": "78a5192f21bd5b085a907d81de2c1c0cd4ba008dd5bd8bdcf11fca431a9d7385",
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
      "binding_sha256": "9c51d5cf62949410a1d25828e0931150458ebafb94d343ecacfe8af1610099cd",
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
      "binding_sha256": "80259690c226c9459a54f636e2f276bd5d210f45e401dc7ad086920f34c8a242",
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
      "binding_sha256": "45706d29e94d0cbecebf6f11d208a45a929662314e3043a6ed286435c390a38e",
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
      "binding_sha256": "c11dc0037a25b0452eadb396751cfdc0a13afacfc0218bf8d8860c3f9afd8584",
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
      "binding_sha256": "7612e172be148792402abbda7216ffbce564b6ae2fb4d3625012699e6ebcc33d",
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
      "binding_sha256": "ff464c2cf9ee54d05e3065bf52711ea424e13c8890725badcf844beb7304376d",
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
      "binding_sha256": "040f5118b0b968c408716e566022d5f667088d68e24cbcf7fb3f9ae3cf451e8c",
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
      "binding_sha256": "778dda4abfc68a54f32674d21f6242b8e17fd7633a9769e3a24de6af75423099",
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
      "binding_sha256": "05fb9f7d546d1607048bc3edab06e0aa663137618efe36f3401f75786ee12a38",
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
      "binding_sha256": "08063e21075108cd959ed4b6da576d071f2b0ac8542c176c27f6998bfe04dd51",
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
      "binding_sha256": "f3e7d79b25122c853eb241bdb9ccf758fc1b86a5caa3b9028dde5cea7a7f13f9",
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
      "binding_sha256": "f2e96e76caafd7a7bf96167fa285814fb0a9d5df29231107232e3fabb7c3216b",
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
      "binding_sha256": "7b452d521f9ee0f7e1293078b8594af1d1c6ca77975defd561771da9dda45b45",
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
      "binding_sha256": "fdd7f279674b5f55810fd01fbfbc96072e1fc6c3f7fae464b5fe0ac9a4392622",
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
      "binding_sha256": "0b0ec5dde2c7a8625c86b02f57a9c5f59f75da3f9987d91510616284446d6d4e",
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
      "binding_sha256": "50c0fba9f81e66a5211942df8bcc09ca22e06bf55877f7c1070f005c989d21c3",
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
      "binding_sha256": "a033289bf0decaa47d3cf02dd423685f55011d698a08c5d7dea90d1bbeecf4cb",
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
      "binding_sha256": "3694aae1d2c1a53d78df03733dbe73139445ae4e28e6c29131d29b8ebee3888f",
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
      "binding_sha256": "aa328d7ce19c1c7bf1e21a7986023e44ddb2264e97dc47f2610949e4ea65cc49",
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
      "binding_sha256": "d9a65b0964b4a4b2520418a945349ec7826ba333b201fa0479c55582eef75864",
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
      "binding_sha256": "6d8292e9ae63443a27cb272554ed789857435676667705dc72f2ac253a9a5dd3",
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
      "binding_sha256": "c9694e0f44191da1fc971c978826d6965acd1f559d787b504cdb2983e6a41871",
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
      "binding_sha256": "36fc882a773a28de1736889c3fa8e13f83ee0705fabe8151511c5f1ef3d7e161",
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
      "binding_sha256": "459c725f7c341d1cc4f07544e0666b06e31a41ae0a5cbb52303b2494fc681382",
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
      "binding_sha256": "da2872a59d34ab7462d72e77a2e5c7ee9d3ffd593442dee72cc65044c5d44898",
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
      "binding_sha256": "7ccd26e6d6e78edfdc5c3fc004f9f9e2bc52e9dc8769ccb4b7acf882debd8086",
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
      "binding_sha256": "5280e9deb7cbd42e68849631ca600b0b7918c020ae54d9c53bee784f4c8463ca",
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
      "binding_sha256": "748252c7c5de84fcc342f7fcf6abc3cf17630f576ca218d5a71fb5b28e66e44a",
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
      "binding_sha256": "bcc19b097b6e4795b9d87fb01fa66b066adb808c3b5245ec2afcad90ab9bc413",
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
      "binding_sha256": "e708b0fa1c1ee6c7886cc324fe2f9f44ebececb80adc06790c04ffb80895a341",
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
      "binding_sha256": "bdedacd9af717506e4c066cd61850a6bf0290a6e7cb5428ab012a119bc9c3db7",
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
      "binding_sha256": "6f43fc7f5288013383d9ba8986c2cb49222256f3d3b29a457336d1f390a396ad",
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
      "binding_sha256": "e93e59031043d939c04abc8ec71070baa9c219a25a4538d4dd9d857a433c2063",
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
      "binding_sha256": "c254897b606e90a4ab81813578fd3581d73f98862a2f0b50fbf37ae33dfbada9",
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
      "binding_sha256": "f9821d26e1be5a7d479b0e9b9fe0d2d6392ee18bc4ae0238647d96a2b6d9cd36",
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
      "binding_sha256": "a7d440b28567e5f3ae7ce0f4d2c89cc428cf5a5e75d4525d666aac4f9d5c4bea",
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
      "binding_sha256": "46bbfaed7947f05f8dc9089d3362aee1ea514f3f8909e940ffd10dccbadf2bf2",
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
      "binding_sha256": "5e4bae567a6502af0818497f8e75844c06a2c40f63f9c1134d81c4702e883966",
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
      "binding_sha256": "3a4afd7e92bf09ae2c52df9a12fb2ebaf2d29a993af4744c3dc13a6986e5606a",
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
      "binding_sha256": "3aa65b09c03449a7e33c9b43e4c8f93c2f3649c6a0fe3477d322c17464726d33",
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
      "binding_sha256": "018358808b7c3b30bb22f14d3650f7c244258143c5f042897663a60f7d35179f",
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
      "binding_sha256": "06ca4af74dd55d15717fd32b73793ea4eba83889f8193010dcc86d4e6384ae87",
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
      "binding_sha256": "50b747cee4c9bcf4eb046e2c0bece3335d757dc82c61374e5d5e5356cc1558f1",
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
      "binding_sha256": "0b83b380d7936dc0c9a84f2f5f0f2112a2ab282f7a33a026884aff14abcbb8f4",
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
      "binding_sha256": "1c827af6950f896a43f2e4d657d3d55ed8e81171ec7ceb7ec5f5ae7c63455b22",
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
      "binding_sha256": "f9ad33c1610f40288e134c47684ec0652884abbff6114a1367b3e77c908a06ab",
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
      "binding_sha256": "7b15c09b541fd9132e0dd0b565fcc814686efb2c2a89ebb75cd5b8eb9074ae2c",
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
      "binding_sha256": "6810b0bda52aae3c7de919c64065c95f86eddc8526c6f996dc4a0d2e5e957ad9",
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
      "binding_sha256": "b0184b827f1297616c18573afd97cf9fdba0e29373c07cff3971ac9ddb0815e0",
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
      "binding_sha256": "63a6cccc1b8e75442f7c49ab080b32ca926b3c9aba61e109156201d3a72e9b7b",
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
      "binding_sha256": "b42da36760680be315b0512e8ec82c590706628c8da9f6428047af388a2070d7",
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
      "binding_sha256": "fa363630ba43c44dceb65b509c2e7068d130766566461a0f5137f4dfcec3e459",
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
      "binding_sha256": "f6c505f3b6e994aa0da8bb1e24af30f40cf12398823e37d2dda9c7cdd48115a6",
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
      "binding_sha256": "ae3614c84482a4caf8d121758cccfecbce85cd4f36c6fa18a1ec8a13eb4c1041",
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
      "binding_sha256": "07ec72c8407fca29a62a67c9ca5e37bf2c7ebd36e7aa587288b87a414fc1ebb9",
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
      "binding_sha256": "03ac7d319f696a434e04289b93383016cff90dd915903bb9f3f9e324cb899595",
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
      "binding_sha256": "e2f32d838f4c530915380e7a0207ef3c36aa681775bfef581c4c19bd8038d25d",
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
      "binding_sha256": "1b79229a537075f83e0da26a11fe1d08b2359b4ae4ae6e0378fd684b9b3d4b52",
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
      "binding_sha256": "f00b36235b3209b14d0fd701ff1a8c46de02ad0124b7bb52a2c55acb531c2d72",
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
      "binding_sha256": "c0b01e58a0a30319956be6ae1dbb2faa7dcf03d2bec6400bd519fdb6d95a63a6",
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
      "binding_sha256": "d10805f1729e1255cb0b9809c20a3abc99d76a1854f0f0f0f0198e475ce5813c",
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
      "binding_sha256": "93aaa21160aabf0569b1c0100fdad14a2fe4e57bd48e0e9324371af23120c810",
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
      "binding_sha256": "e20deb392512e4e56cf47a3ea75e6533faf2c6bb0391e9c87d79f83db19cd298",
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
      "binding_sha256": "57801b39893ee7b3f425f00b9385768e4e1d3be1d57d5367fac1c5ca4e214580",
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
      "binding_sha256": "fe4b9fcfff5d1b2f8491386fc9c1dc1c7ec4204234291a1e1d0c2efe63736533",
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
      "binding_sha256": "8129f9f52de1eb06c616d98e03f1c0a0f1a053d3841ef7845b8413e47a2c13b8",
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
      "binding_sha256": "929facc50148a0f7041468e419a582764e9e4a355efb9a3a816056bfb96404eb",
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
      "binding_sha256": "122760eb99465a59c26b029c5f12675f384ec9bf0887f1b4b6ebd3aa91b98639",
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
      "binding_sha256": "58951162858aee96ddb14d88109ed77f5967ff7cc620ded6afcf28c0d16b0ab2",
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
      "binding_sha256": "ad2c8d5b4a126859024c6f6d70cfba1843584aa1cdd88c8e482e17d2d1336b75",
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
      "binding_sha256": "c4b6ed77ff59d06aaec1d8fd7f4349b5eff6be7b9abd04cec263ef099ce3d1da",
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
      "binding_sha256": "d884152659d9b3a496ac2c544f09f2cb368dd50b9837c9ea1a2b1d69ff0ed0e5",
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
      "binding_sha256": "10ceb58552bde6238796266f956ce58e45fe795410a91a449b4084d164a27514",
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
      "binding_sha256": "8796ed55d368dad33fd86e93b33b99eb7672bf12680536700f571fdbf9e15ea8",
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
      "binding_sha256": "7e53026b9ea410f4cdf10690bd578dae60fed4895793f7f1a7ee1d531e2a8147",
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
      "binding_sha256": "d742f8d7abeec21d740eb71d69f7530b97ce4f9581eec93bd6e263cbc2a793ee",
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
      "binding_sha256": "e24b985cdc28276fbe86ff4acfe584847257ce5617d9c0644b9399cc81a3512c",
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
      "binding_sha256": "aa18ec98a71cfe795661cb69d7121b9a377755bf524832518a4b51e7b219933d",
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
      "binding_sha256": "68e86b429c5f071aafe3eac565f4ee8214b527affb79f61b6ad4e6ebd882f9f1",
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
      "binding_sha256": "bf764da8d89e32342a635819f05d34ec395dcac89451c4eebcc0d276a415b1f5",
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
      "binding_sha256": "92f390a0b0e770e7409fb747164149dfb0627faff7a6802456983990b6c61e08",
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
      "binding_sha256": "4b3be909731e83ab58581ed721c03edf85d2ee36075af7da699f4f40ba6e73b2",
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
      "binding_sha256": "09d1848c75a291dcc5607679169b18a4421f6999e0c991bfa33cbf5f0a8c4a25",
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
      "binding_sha256": "450e2d885c172fe7a6f2296e850a665df0e147e34b0494940ea7d3a1661afe83",
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
      "binding_sha256": "26efe2261b1f172310b8015317e2e5a37e41691f39e21875469365f7f663310a",
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
      "binding_sha256": "4580b4a3978ca37059ad506ea98e5591a3aeb18e16a0196816aaa0b3dfc74e17",
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
      "binding_sha256": "0fd65d2e620dd143417cdc499f34148719480cc349b215fd07e2f7aa66ec7c50",
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
      "binding_sha256": "691dd8e8b071e292fab096b610cdd9a1d42f115af4918521e40dcaccefe6b044",
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
      "binding_sha256": "fa5139b80aa204928eeb4483db7e0c19d943f1140583aef2d8917016dd280c12",
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
      "binding_sha256": "b05f93cbe1797a75b32c733f6d827bffab42a8a02475fa04a11155fd24a1053b",
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
      "binding_sha256": "9a340d9997faaf3639260fb081320b7112e12c09c8cb5c93dcdb40f5f3d1052a",
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
      "binding_sha256": "630e7762b29377c89dd7cf19ef63489378c89b103489785930f3408f935047d0",
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
      "binding_sha256": "a14660a8dab7b5d918d6d632c04a25cf5d947a3a6d3cbffb0dda5600e11ac68a",
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
      "binding_sha256": "4353cd7a7563d21919b165d7e06c0c83b9bcb795fd2cde8a29cd8392a050d946",
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
      "binding_sha256": "7f4480ff912210f658e5df351610cb8e3b941eb86f375ddeb1a26aacad484d25",
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
    "catalog_sha256": "9c105536952accf2198facf75f7d36cf6488ba5f89de4b85c686ae380fc2114d",
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
      "max_file_bytes": 1000000,
      "max_files": 20000,
      "max_total_bytes": 50000000
    },
    "evidence_sha256": "06b8a5dc3bf9eb896f0c7fa003611ed70edfc92f1c5f6c43676f8efd67c0ccd0",
    "image_limits": {},
    "manifest_sha256": "408f19361fd5303c4d0346b18befdc6b7219a39c396e272d43d37b5602114277",
    "scan_id": "c0c0f6762caca66aa1694ccc9c8c93dc9356bfc0ee3244903cfbc814791d88ea",
    "scope_sha256": "4e01c10d5d5388f1f301cc1f81742dd37a375e51af210210aac226ee08ee3bbc",
    "target": {
      "description": "Selected source directory; paths are relative.",
      "kind": "source",
      "platform": ""
    },
    "tool": {
      "implementation_sha256": "b2ed4a3b8f476586fd723d45c68c388d13874b09ab451d9a61c74cf57874d426",
      "name": "agent-mcp-security-scan",
      "version": "0.10.0"
    }
  },
  "schema_version": "1.0"
}
```
<!-- INVARUNE_REVIEW_END -->

