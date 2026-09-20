# Invarune by NimeshBuild

AI agent and MCP security report

Scan ID: `c1ba5410b8710dd9fbed73894eb74c7c7813cf78b6e3cecf80054db70682104c`

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

**Fix guidance:** 11/11 observed findings have a deterministic fix plan and agent/MCP context. Model fix plans: 2/2 finding assessments and 0/0 answered checks. These are proposed changes requiring verification.

**What the scanner found:** Tool execution: 3; Supply chain: 2; Transport security: 2; Agent permissions: 1; Deserialization: 1; Sandboxing: 1; Secrets: 1. These are detected pattern categories, not confirmed attack paths.

**Execution:** exit 1; severity threshold high. The exit threshold does not change the review priorities below.

**Optional model review:** completed. Model advice is separate from the deterministic assessment and cannot lower these priorities.

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
        "max_seconds": 180
      },
      "cli_login": "never",
      "cli_timeout_seconds": 180.0,
      "effective_transport": {
        "max_request_bytes": 524288,
        "max_response_bytes": 1048576,
        "model": "gpt-6-astra",
        "provider": "codex_cli",
        "timeout_seconds": 180.0,
        "token_optimizer": "headroom"
      },
      "enabled": true,
      "findings_limit": 2,
      "include_finding_source": true,
      "mode": "findings",
      "provider": "codex_cli",
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

Severity failure threshold: **high** · Process exit code: **1**.

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

**Optional finding review:** likely\_true\_positive. run\_tool passes user\_command directly to subprocess\.run with shell=True, allowing shell syntax to execute\. The snippet establishes the dangerous sink, but not whether an untrusted caller can reach it or what isolation applies\. Trace callers and command construction to verify the trust boundary\.

**Model-proposed fix guidance (unverified):**

**Agent/MCP relevance:** If agent\-generated commands or MCP arguments reach user\_command, external content could influence shell execution with the tool process's privileges\. MCP exposure is not established\.

**When this applies:** Applies when user\_command can be influenced by an agent or another caller lacking authority to execute arbitrary shell commands\.

1. Replace command strings with structured operation arguments mapped to fixed executable paths; call subprocess\.run\(argv, shell=False\), validating each operation's permitted options and operands\.
2. If arbitrary shell execution is an intended capability, document that contract and enforce authorization and an isolated execution environment with restricted credentials, filesystem access, network access, and execution time\.

**How to verify:**

- Trace run\_tool callers to identify who controls user\_command and which authorization or isolation controls apply\.
- In an isolated test environment, verify that shell metacharacters are rejected or passed literally and that supported operations retain their intended behavior\.

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

**Optional finding review:** likely\_true\_positive. os\.system\(user\_command\) directly sends the function argument to a shell\. Untrusted influence would permit shell command injection, although caller provenance and runtime privileges are unknown\. The preceding subprocess\.run also executes the same command, so verify whether this second invocation is intentional\.

**Model-proposed fix guidance (unverified):**

**Agent/MCP relevance:** An agent or MCP caller controlling user\_command could cross from tool input into process execution\. The supplied context does not establish actual agent or MCP reachability\.

**When this applies:** Applies if callers are intended to request bounded operations rather than unrestricted shell execution\.

1. Replace os\.system with subprocess\.run using a fixed executable, validated argument list, and shell=False\.
2. Determine whether both execution calls are required; if duplication is accidental, consolidate into one validated subprocess\.run call while preserving required output and failure behavior\.

**How to verify:**

- Review callers and the tool contract to establish permitted operations and whether duplicate execution is expected\.
- Use an isolated test with a harmless observable operation to check invocation count, argument handling, output, and failure behavior\.

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

Open finding IDs: afb2bdb94696690028650faf
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

Category: MCP protocol and tools · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] For HTTP, reject invalid Origin values and verify local deployments bind only to intended interfaces\.
- [ ] Use TLS for remote protected endpoints; test DNS rebinding and proxy/header behavior in deployment\.

Partial static rules: AI006, AI007, AI008, AI029

Open finding IDs: 07fc5f6fd7699fd0194dc479, d841174f55e032505f8136b9
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

Category: MCP protocol and tools · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Approve executable and package identity before starting a stdio server; use argument arrays and a minimal environment\.
- [ ] Restrict proxy process\-spawn APIs and child filesystem/network permissions; separate stdout protocol traffic from logs\.

Partial static rules: AI018, AI031

Open finding IDs: 592fbfc9b7dab062dc97906c, 6b77081a826c4c6833edc47f
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

Category: Agent behavior and context · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Place allow/deny decisions at the execution boundary using trusted policy inputs and constrained tool capabilities\.
- [ ] Show that an injected instruction cannot disable policy, choose privileged credentials, or bypass approval\.

Partial static rules: AI027, AI031

Open finding IDs: 592fbfc9b7dab062dc97906c
- [Source](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses)

### AGT\-02: Bind approval to the action executed

Category: Agent behavior and context · Status: findings\_detected · Validation: dynamic

Partial static coverage only; absence of a finding is not a pass

- [ ] Present actual recipient, target, arguments, data disclosure, and consequences for high\-impact approval\.
- [ ] Invalidate approval if arguments or target change; test races, delayed retries, and approval reuse\.

Partial static rules: AI031

Open finding IDs: 592fbfc9b7dab062dc97906c
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

Category: Execution and application security · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Find shell execution and constructed command strings; use fixed executables, argument arrays, and allowed argument values\.
- [ ] Test untrusted tool inputs containing shell syntax, option injection, command substitution, and hostile filenames\.

Partial static rules: AI002, AI003, AI012

Open finding IDs: 979d192981c1785a2394fe19, 0fa7e450cd583d78646ef397
- [Source](https://owasp.org/projects/mcp-top-10)
- [Source](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/)

### EXEC\-02: Constrain generated\-code execution

Category: Execution and application security · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Locate eval, exec, dynamic imports, templates, notebooks, and interpreter tools accepting model or user content\.
- [ ] Run required code execution in a disposable restricted environment with explicit filesystem, network, CPU, and time limits\.

Partial static rules: AI001, AI013

Open finding IDs: b1b0f0a3f33fe93875fcb58a
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

Open finding IDs: d2d09fb2875db72f18779bfc
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

Open finding IDs: afb2bdb94696690028650faf
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

Category: Supply chain · Status: findings\_detected · Validation: static

Partial static coverage only; absence of a finding is not a pass

- [ ] Review lockfiles and exact versions or immutable digests for packages, images, MCP servers, models, and plugins\.
- [ ] Flag runtime installs, floating tags, remote scripts, and dependency sources outside approved registries\.

Partial static rules: AI018, AI024, AI025

Open finding IDs: 6b77081a826c4c6833edc47f, 055ed29e5f56926f1827a0b8
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

Open finding IDs: 055ed29e5f56926f1827a0b8
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

Category: Supply chain · Status: findings\_detected · Validation: hybrid

Partial static coverage only; absence of a finding is not a pass

- [ ] Review root/privileged containers, host mounts, Docker sockets, unrestricted egress, debug mode, and public management endpoints\.
- [ ] Separate agent execution from control\-plane credentials and audit storage; test isolation in the deployed environment\.

Partial static rules: AI021, AI022, AI023, AI031, AI042

Open finding IDs: 592fbfc9b7dab062dc97906c, 20771a324af20de316ec34f9
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

Dependency manifests: 0; agent/MCP signal files: 1.

Dependency manifests are inventoried, not checked against a vulnerability database.

### Scan errors

None.

### Excluded or skipped paths

| Path | Reason | Coverage gap |
|---|---|---|

## Optional LLM judge

### Evidence-JSON optimization

All evidence values and exact source/citation strings are preserved. These byte counts exclude instructions, response schemas and provider wrappers; tokenizer savings and billing reductions were not measured.

| Request | Requested | Actual engine | Status / fallback | Before bytes | After bytes | Bytes saved |
|---|---|---|---|---:|---:|---:|
| Finding triage | headroom | headroom | optimized | 3558 | 3430 | 128 |

Advisory, non-deterministic output. It cannot dismiss deterministic findings, establish compliance, or change the deterministic CI gate.

```text
{
  "adapter_version": "1.3.0",
  "additional_concern_actions": [
    {
      "concern_index": 1,
      "recommended_actions": {
        "agent_mcp_relevance": "If agent or MCP input reaches serialized_data, deserialization could execute code with server privileges. Input provenance is unverified.",
        "applicability": "Applies when serialized_data crosses a trust boundary from an untrusted or compromiseable producer.",
        "steps": [
          "For untrusted input, replace pickle.loads with json.loads and explicit schema validation; define a compatible data representation for any currently required Python-specific types.",
          "If trusted pickle support is required, establish and enforce the trusted-producer boundary before retaining it; do not treat post-deserialization validation as protection."
        ],
        "verification": [
          "Trace serialized_data through all callers and storage or transport paths.",
          "Verify that the replacement accepts required legitimate payloads and rejects malformed or unsupported data without invoking pickle.loads."
        ]
      }
    },
    {
      "concern_index": 2,
      "recommended_actions": {
        "agent_mcp_relevance": "Intercepted responses could feed altered data or instructions into an agent if data.text is consumed downstream; that downstream use is unverified.",
        "applicability": "Applies when remote_url uses HTTPS and authenticated server identity is required.",
        "steps": [
          "Remove verify=False to use Requests' default certificate verification, or set verify to an approved CA bundle path for private certificates.",
          "If the tool requires authenticated encrypted transport, validate that remote_url and followed redirects use HTTPS."
        ],
        "verification": [
          "Verify that a server with a trusted certificate succeeds and servers with an untrusted certificate or hostname mismatch fail.",
          "Check private-CA deployments against the configured CA bundle to preserve intended connectivity."
        ]
      }
    },
    {
      "concern_index": 3,
      "recommended_actions": {
        "agent_mcp_relevance": "Caller-controlled URLs could make an agent tool or MCP server access resources unavailable to the caller directly. Exposure and effective network access are unknown.",
        "applicability": "Applies if remote_url is influenced by untrusted input and destinations are intended to be restricted.",
        "steps": [
          "Define permitted schemes, hosts, and ports; parse remote_url with urllib.parse.urlsplit and enforce that policy before requests.get.",
          "Set allow_redirects=False or revalidate each redirect destination, and enforce destination restrictions through an egress proxy or network policy covering resolved addresses."
        ],
        "verification": [
          "Trace URL provenance and inspect existing validation and egress controls before changing behavior.",
          "In a controlled environment, check permitted destinations and denial of disallowed destinations, redirects, IPv6 addresses, and DNS changes."
        ]
      }
    }
  ],
  "additional_concerns": [
    "pickle.loads(serialized_data) can execute code during deserialization. It is unknown whether serialized_data is attacker-controlled or restricted to trusted producers; trace its origin and integrity protections.",
    "requests.get(remote_url, verify=False) explicitly disables TLS certificate verification. Interception risk depends on HTTPS use and network conditions; establish URL schemes and the intended certificate trust configuration.",
    "requests.get(remote_url, ...) may permit server-side request forgery if an untrusted caller controls remote_url and the process can reach sensitive destinations. URL validation, redirect handling, and network restrictions are not shown."
  ],
  "advisory_only": true,
  "assessments": [
    {
      "finding_id": "979d192981c1785a2394fe19",
      "reason": "run_tool passes user_command directly to subprocess.run with shell=True, allowing shell syntax to execute. The snippet establishes the dangerous sink, but not whether an untrusted caller can reach it or what isolation applies. Trace callers and command construction to verify the trust boundary.",
      "recommended_actions": {
        "agent_mcp_relevance": "If agent-generated commands or MCP arguments reach user_command, external content could influence shell execution with the tool process's privileges. MCP exposure is not established.",
        "applicability": "Applies when user_command can be influenced by an agent or another caller lacking authority to execute arbitrary shell commands.",
        "steps": [
          "Replace command strings with structured operation arguments mapped to fixed executable paths; call subprocess.run(argv, shell=False), validating each operation's permitted options and operands.",
          "If arbitrary shell execution is an intended capability, document that contract and enforce authorization and an isolated execution environment with restricted credentials, filesystem access, network access, and execution time."
        ],
        "verification": [
          "Trace run_tool callers to identify who controls user_command and which authorization or isolation controls apply.",
          "In an isolated test environment, verify that shell metacharacters are rejected or passed literally and that supported operations retain their intended behavior."
        ]
      },
      "verdict": "likely_true_positive"
    },
    {
      "finding_id": "0fa7e450cd583d78646ef397",
      "reason": "os.system(user_command) directly sends the function argument to a shell. Untrusted influence would permit shell command injection, although caller provenance and runtime privileges are unknown. The preceding subprocess.run also executes the same command, so verify whether this second invocation is intentional.",
      "recommended_actions": {
        "agent_mcp_relevance": "An agent or MCP caller controlling user_command could cross from tool input into process execution. The supplied context does not establish actual agent or MCP reachability.",
        "applicability": "Applies if callers are intended to request bounded operations rather than unrestricted shell execution.",
        "steps": [
          "Replace os.system with subprocess.run using a fixed executable, validated argument list, and shell=False.",
          "Determine whether both execution calls are required; if duplication is accidental, consolidate into one validated subprocess.run call while preserving required output and failure behavior."
        ],
        "verification": [
          "Review callers and the tool contract to establish permitted operations and whether duplicate execution is expected.",
          "Use an isolated test with a harmless observable operation to check invocation count, argument handling, output, and failure behavior."
        ]
      },
      "verdict": "likely_true_positive"
    }
  ],
  "cli": {
    "arguments": [
      "-a",
      "never",
      "exec",
      "--ignore-user-config",
      "--ignore-rules",
      "--ephemeral",
      "--skip-git-repo-check",
      "--sandbox",
      "read-only",
      "--json",
      "--color",
      "never",
      "--disable",
      "shell_tool",
      "--disable",
      "unified_exec",
      "--disable",
      "code_mode",
      "--disable",
      "code_mode_host",
      "--disable",
      "computer_use",
      "--disable",
      "browser_use",
      "--disable",
      "browser_use_external",
      "--disable",
      "browser_use_full_cdp_access",
      "--disable",
      "in_app_browser",
      "--disable",
      "image_generation",
      "--disable",
      "view_image",
      "--disable",
      "artifact",
      "--disable",
      "apps",
      "--disable",
      "plugins",
      "--disable",
      "plugin_sharing",
      "--disable",
      "hooks",
      "--disable",
      "multi_agent",
      "--disable",
      "multi_agent_v2",
      "--disable",
      "skill_search",
      "--disable",
      "workspace_dependencies",
      "--disable",
      "shell_snapshot",
      "--disable",
      "memories",
      "--disable",
      "sleep_tool",
      "--disable",
      "goals",
      "--disable",
      "remote_plugin",
      "--disable",
      "tool_suggest",
      "-c",
      "web_search=\"disabled\"",
      "-c",
      "mcp_servers={}",
      "-c",
      "project_doc_max_bytes=0",
      "-c",
      "skills.include_instructions=false",
      "-c",
      "model_reasoning_effort=\"high\"",
      "--output-schema",
      "<private temporary directory>/response-schema.json",
      "--model",
      "gpt-6-astra",
      "-"
    ],
    "auth_mode": "cli_managed",
    "cli_version": "0.154.0",
    "descendant_termination": "process_group",
    "executable": "codex",
    "isolation": "CLI capability restrictions; installed executable and administrator policy remain trusted",
    "provider": "codex_cli",
    "repository_working_directory": false,
    "request_bytes": 5644,
    "request_sha256": "9bb026f5c15bd9dd66f2dcb09800f62d41e41eb967c43787de8cb813b75793a4",
    "requested_model": "gpt-6-astra",
    "response_bytes": 7817,
    "response_sha256": "73c095f40280411f8fbacbf30a5de880d0bb9919d6d9cfb53d2a853c5b746be7",
    "stage": "findings",
    "startup_warnings": [
      "codex_code_mode_intentionally_disabled"
    ],
    "structured_output_requested": true,
    "token_budget_enforced": false,
    "token_optimization": {
      "bytes_saved": 128,
      "engine": "headroom",
      "evidence_preserved": true,
      "fallback_reason": null,
      "headroom_version": "0.37.0",
      "original_payload_sha256": "1ad9a18de38edb0901b45af07916fb08f1ef5b875d01e4ad53878dee81183257",
      "payload_bytes_after": 3430,
      "payload_bytes_before": 3558,
      "requested": "headroom",
      "schema_version": "1.0",
      "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
      "sent_payload_sha256": "6092d4e472abfc9ba6f6d2567219066dcdd97d1a0c67d9a420be70d440bab691",
      "status": "optimized",
      "token_savings_measured": false
    },
    "tools_policy": "disabled_for_advisory_review",
    "transport": "official_cli"
  },
  "data_policy": "Caller-supplied minimized payload; source excerpts require separate CLI opt-in.",
  "enabled": true,
  "findings_submitted": 2,
  "mode": "findings",
  "model": "gpt-6-astra",
  "nondeterministic": true,
  "omitted_assessments": 0,
  "omitted_open_findings": 9,
  "provider": "codex_cli",
  "selected_findings": 2,
  "source_context_requested": true,
  "source_context_sent_count": 2,
  "source_context_skipped": [],
  "status": "completed",
  "token_optimization": {
    "bytes_saved": 128,
    "engine": "headroom",
    "evidence_preserved": true,
    "fallback_reason": null,
    "headroom_version": "0.37.0",
    "original_payload_sha256": "1ad9a18de38edb0901b45af07916fb08f1ef5b875d01e4ad53878dee81183257",
    "payload_bytes_after": 3430,
    "payload_bytes_before": 3558,
    "requested": "headroom",
    "schema_version": "1.0",
    "scope": "Evidence JSON only; excludes instructions, response schemas and provider wrappers",
    "sent_payload_sha256": "6092d4e472abfc9ba6f6d2567219066dcdd97d1a0c67d9a420be70d440bab691",
    "status": "optimized",
    "token_savings_measured": false
  }
}
```
### Additional model concern 1 (unverified)

pickle\.loads\(serialized\_data\) can execute code during deserialization\. It is unknown whether serialized\_data is attacker\-controlled or restricted to trusted producers; trace its origin and integrity protections\.

**Model-proposed fix guidance (unverified):**

**Agent/MCP relevance:** If agent or MCP input reaches serialized\_data, deserialization could execute code with server privileges\. Input provenance is unverified\.

**When this applies:** Applies when serialized\_data crosses a trust boundary from an untrusted or compromiseable producer\.

1. For untrusted input, replace pickle\.loads with json\.loads and explicit schema validation; define a compatible data representation for any currently required Python\-specific types\.
2. If trusted pickle support is required, establish and enforce the trusted\-producer boundary before retaining it; do not treat post\-deserialization validation as protection\.

**How to verify:**

- Trace serialized\_data through all callers and storage or transport paths\.
- Verify that the replacement accepts required legitimate payloads and rejects malformed or unsupported data without invoking pickle\.loads\.

### Additional model concern 2 (unverified)

requests\.get\(remote\_url, verify=False\) explicitly disables TLS certificate verification\. Interception risk depends on HTTPS use and network conditions; establish URL schemes and the intended certificate trust configuration\.

**Model-proposed fix guidance (unverified):**

**Agent/MCP relevance:** Intercepted responses could feed altered data or instructions into an agent if data\.text is consumed downstream; that downstream use is unverified\.

**When this applies:** Applies when remote\_url uses HTTPS and authenticated server identity is required\.

1. Remove verify=False to use Requests' default certificate verification, or set verify to an approved CA bundle path for private certificates\.
2. If the tool requires authenticated encrypted transport, validate that remote\_url and followed redirects use HTTPS\.

**How to verify:**

- Verify that a server with a trusted certificate succeeds and servers with an untrusted certificate or hostname mismatch fail\.
- Check private\-CA deployments against the configured CA bundle to preserve intended connectivity\.

### Additional model concern 3 (unverified)

requests\.get\(remote\_url, \.\.\.\) may permit server\-side request forgery if an untrusted caller controls remote\_url and the process can reach sensitive destinations\. URL validation, redirect handling, and network restrictions are not shown\.

**Model-proposed fix guidance (unverified):**

**Agent/MCP relevance:** Caller\-controlled URLs could make an agent tool or MCP server access resources unavailable to the caller directly\. Exposure and effective network access are unknown\.

**When this applies:** Applies if remote\_url is influenced by untrusted input and destinations are intended to be restricted\.

1. Define permitted schemes, hosts, and ports; parse remote\_url with urllib\.parse\.urlsplit and enforce that policy before requests\.get\.
2. Set allow\_redirects=False or revalidate each redirect destination, and enforce destination restrictions through an egress proxy or network policy covering resolved addresses\.

**How to verify:**

- Trace URL provenance and inspect existing validation and egress controls before changing behavior\.
- In a controlled environment, check permitted destinations and denial of disallowed destinations, redirects, IPv6 addresses, and DNS changes\.

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
      "binding_sha256": "ad323b53f43885ee298748c1c0dca72a8775a896d27339f85938dde712c9033b",
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
      "binding_sha256": "7b31e7426d77846d34fa7ea50bfbb1812199f7b46b77f66dfbce6916d84b1c0b",
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
      "binding_sha256": "43e4fb0bc303f559503786c0d031d75caf50e783334bf8f7e506ebcace6562b0",
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
      "binding_sha256": "a6fad86a94e19280ea1f4e0f5a5ec93d0f1d4e8721e6867fcbe5deb6812f2278",
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
      "binding_sha256": "6cfe08cd084a25f525beb10bae3b13c4f19c08c83b2c4e8272179d8e126e40ce",
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
      "binding_sha256": "65cc927d0508512609f62156a7445a5a831c0404b3604e29055218e5051a770f",
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
      "binding_sha256": "29f7b1c20cd10e5c51251056a936ea507968141601cbe924c7b3b24eb49ea82b",
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
      "binding_sha256": "63eb3bc958513eda7ab13ff8bba677c0dc060b5b69338567b34f0de21c8cdf9c",
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
      "binding_sha256": "39b14c45874e0192767a9355a9851d3cc06428b3fac7a7dd8171dda0f5374570",
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
      "binding_sha256": "689a1ce34a336fa017539d5c165bf90b946e101d2944ed9e363b7cee9efa1859",
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
      "binding_sha256": "d59094d946b365f7f2cf4a2de8a505faa7b81ecbb9c95bb6d16596ce64982c2a",
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
      "binding_sha256": "d17d3bf5d5e65464ce450440469a34be8feb001e378d760bacb5afadfbe336f4",
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
      "binding_sha256": "8788f9edc5cda4fdc4381c296bf450da420c6ebc67d031426cc36045bb15fabb",
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
      "binding_sha256": "a793286f30809f96a61251636c2851492989087543faab505e32e1152b23b8f5",
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
      "binding_sha256": "2b3e240099b65535ff170539b4462365f2abd016beca9340652d74cb8c951817",
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
      "binding_sha256": "640f656e29c66a1dc7b90e0d5f4753ff2c1da78780df44d14876d9aede40ecbd",
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
      "binding_sha256": "61e3a4c300e167272ce7a3db92a7d019ce0203d566ed010f9fa653c0bfd4dda2",
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
      "binding_sha256": "c399f44fd8e6586be3300f66f2cfec24817ea8a95e958eb20ba17b06bb2d2ed6",
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
      "binding_sha256": "4fa252aebf25bc2fe97a81a92fc40541286a9c48b2210ed48c0c1dd16c72534a",
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
      "binding_sha256": "a2eebc08b3796ef1aeaf20c887f4de356912bc033dca32f7ca62af8c3b0e3be7",
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
      "binding_sha256": "71e55658a25132ddc613768311985e5b03c51bb2fbd3e7680f59c5994a9b57c6",
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
      "binding_sha256": "e5a48bdbd45cc6043e42c7202f51fe7a201f636a23b4a76f280d2de9bd6d7d42",
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
      "binding_sha256": "747df9207d276d14b6ac05aebf869a3dd744aee601b6d78950a726f30df9508f",
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
      "binding_sha256": "dd394938243bb592947b7056854151748dc3d4c3094086f61ee3a273cc1346be",
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
      "binding_sha256": "6f7110a0a687f8a6b2d83f92d38d86a081801de55c59d2621bc121adbdb2bff0",
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
      "binding_sha256": "bee6ac6d208787e971e66588383dff9bd4539d915ace92715d6c7f7abd6953d0",
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
      "binding_sha256": "50ae3169049ec47d0cad16ac76bae706ad8b2e45aee2c2f615a288d36c0c8854",
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
      "binding_sha256": "027b8a1f23b0f27366f3e679a77c895f364167d38314cb981598d7406b03d3e4",
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
      "binding_sha256": "98636b7e58176c9363228be718a92836813d216049589c1ef434781c325a3749",
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
      "binding_sha256": "5cfdcf9753fb80426ce1291fb70329a5209110492bd915be351c076cdb940fd9",
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
      "binding_sha256": "95c722df4dc1003422acc93fc0687273a91e6e799dffaf56df1d7640644b0009",
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
      "binding_sha256": "fdf49b28bb715742444692108031a224804c31eb3f3c78e3b23a6d7a88f5e925",
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
      "binding_sha256": "c5487fcbcb78d2b73f38f27d2d54907b14d87f41f6a262fde9ce2e8e2f242b6e",
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
      "binding_sha256": "fa0240e4e32a115d1a63e5482b298b96d39827bf6d336e44398f7c40a322208b",
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
      "binding_sha256": "184da87c488a085b88379b9b8db40ad528cda228225a16d6af2acabcbaa51b26",
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
      "binding_sha256": "9f25e4da9e4b1989edfeb6261414703f9004602a1565af592684bda8d3ca627d",
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
      "binding_sha256": "c39836603491f3ad1d87069c9c07400da590017d2199b7b653ccafc4a38ceca1",
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
      "binding_sha256": "2be937651597c75907a66d86ddaeaca2e9090cb2f43fe927e7f6be151ddf5693",
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
      "binding_sha256": "0fa4c78c23b5c5e342317c68ee99217b912e9d50f501673706caf048269f8055",
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
      "binding_sha256": "cd2e0fbecac10fa8ed678296d7cd358c27ec81e911b345168c28a89d89c0590b",
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
      "binding_sha256": "fb8fb6d77005a72b888005ada9754afc6a1f6c7ee7d9eebef345f6a81e8614bc",
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
      "binding_sha256": "7a968dbddbe47f88057c347b6bde74650d48ed8c1e0b16278ec04aaf327fef03",
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
      "binding_sha256": "b216ce951e81bf618e41c850da984b79d3dbd1db2549a8548217a6aedebbd4db",
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
      "binding_sha256": "fe1d545408aa2433bb89ad4f1e3631ba41a55617e9b344d8adfe0aca4d6dd18a",
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
      "binding_sha256": "7c376ac9305f4b3116e4f1166adfcd69cbca2ca000175202c9bcb2d832528712",
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
      "binding_sha256": "e485b99b6b2bd9e94c270942bf3b5efd6183f613908865fb466338a10250769a",
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
      "binding_sha256": "577eab77534da467a8200350f2fa6e67501f6a416b0bdcea057f9d34c0d96bbf",
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
      "binding_sha256": "83ec409671cd7d13a8be41ad170c7a048ee6a0e83e19f9d514b2c184f2d69a67",
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
      "binding_sha256": "06baa39aeab29563793aee1c3091d4748df21ce666fbd3ad9529d32966ba7d7c",
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
      "binding_sha256": "81e1826a8889199bcd9d4a6493149925a05998d6b61a5f986cc6d9a5d2c8f8f9",
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
      "binding_sha256": "637c6cc7deec65e06999f64b988bc542ebcdf55ff854bb18a50639f2473a2b6b",
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
      "binding_sha256": "20b1042de5f2e4fc7f3be61390c534562b7640e600ec3c3dceeaf2ebdd21a5e8",
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
      "binding_sha256": "f4d9d9e26035c5a9a69d428225dbae417777cf19eff82584f19323a3eda9731f",
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
      "binding_sha256": "9adee9a893c10eb1eb3428d6a55d426e546b72cc0c2b1428f9436f3f43e312bb",
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
      "binding_sha256": "bc9b9d01be078c48ebc887830e99a5c6c7d04c20d1c8a9b048fca91fab0ba0e3",
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
      "binding_sha256": "7bf2861b5b65114113de24ceba857189478056fb227065b49c67f2b665782049",
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
      "binding_sha256": "2f608c853384425ed3269398b459c8ff875b7320e65234dd8c8c170e342f7257",
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
      "binding_sha256": "e505e18b74aded3b3b23d843c3117cc8252dd375312e8b37f7f29f5496d468d5",
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
      "binding_sha256": "bcbfab96b8572375f71371a9ae8600c81c8b8c2fd5684ebc220f0eb86bbc44a9",
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
      "binding_sha256": "51870ff24b2149d09c7faef293afa44e589df86299329a9a277fd94a211cf1da",
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
      "binding_sha256": "721fd73761510f9bf3673d679e59baf482d1b14c636409a152767bff8afaa51d",
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
      "binding_sha256": "ae3e23c88aa438e35dd22fff43b02286cc057f80bf681f64d671c713fc102279",
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
      "binding_sha256": "3a80da5818c1640be054f32cf0503317ef4444404b217a598f1bda866fa4ed90",
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
      "binding_sha256": "506513744b03b738a8a9cd1c9dd2272c7d59f581904ea2cca259c4d2f2e7a1f2",
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
      "binding_sha256": "f8c317658f83648fe25b42b08b89c675823b90c0359c108f862c907e95e7ec22",
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
      "binding_sha256": "8c0a1a7ef63f2372ec15fb7788126440d9b72155f696ffae062ae51be403535a",
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
      "binding_sha256": "f0c07e018277a9a065635e8bf184fe16377cbd78df311c12491b7562d2040dfc",
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
      "binding_sha256": "56a3c2a139e1cb833df692fd7792b35ec628fb83bda6c84931590f827a1c1be5",
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
      "binding_sha256": "a6e73347f399ac10c258b743ace16fccf97e06e3597ad84f911b6d411c57a7aa",
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
      "binding_sha256": "593b38597332334723686b039604db41efdaa30c215da288182df38b38897411",
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
      "binding_sha256": "e0567b94ae88b616ef6731b4d60f0f5aaa7088608ad9d729543465157a18af4c",
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
      "binding_sha256": "2deef867951af652da87e9d8d1897258bd4727d10d7123cb570d38edbc4f2c14",
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
      "binding_sha256": "6be922e74d0f8db0681402037eeaa65a425678871694e57c2fef1f21834e882b",
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
      "binding_sha256": "3754d4af9537af5cc6a5c51c198016f5140e715c31e88e18f4415335898fcee1",
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
      "binding_sha256": "afa367a4c58a9e708f3bb724cfd2edcb769e78ea2d07c1763e008c3297f7fbf3",
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
      "binding_sha256": "b3e02275f808024846e5412d78bdf07e86625d7a6032166ef56639cdb9495f4a",
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
      "binding_sha256": "b84f2a1d9df60d7abadfffc5d645a989020cc37d4198a2d19afed5eed29f9a73",
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
      "binding_sha256": "f6ba6239a9012ebb95711b6a4192bc6e244ae7393a1846fbac6faebed2784c36",
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
      "binding_sha256": "0edc068d6802f9eeeac09cb5165f7079534c366f123f9b3c5f4576ed60975fd1",
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
      "binding_sha256": "e3fb24ab5628a9a6fcaef68bb32cd839199de5747e77dde2a60cf73eebe3e9d4",
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
      "binding_sha256": "47b83832d8063049296af5fd2554c9007176b15da1a094b381333117d9fdb47a",
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
      "binding_sha256": "1a8ee0a45400f1a6ddc59202b71080e409e97d5b45db390c6a2cce37d4528b80",
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
      "binding_sha256": "c09e0759b46ca80cbd8871d80b0aa2f4357b9e5317c088bfb213807fbc3da317",
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
      "binding_sha256": "fbb54ff114866869054bdfea1dd9f0751f6fe3d16e140adb24646f8a32064664",
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
      "binding_sha256": "9d96bb1b18796bfb17e6191a0265fcee430b7e2570b00392cd57501183f00ec0",
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
      "binding_sha256": "ec8a610135f933bc44861d4d37456a52f38212741b731babfd9ea67d5b761d47",
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
      "binding_sha256": "0629d7e9d855759d45c25c27c51742f34cfd025169f693f2460a0d0f21d94239",
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
      "binding_sha256": "497d070e92b46568b0649b44024ed80a14576fcff01e5c0f819ecd33a3a613c0",
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
      "binding_sha256": "1f0f8c4e2b66916a9776e96fc37ee284c99e70a9adca78c6a947e364215f63ca",
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
      "binding_sha256": "a17298608828636ce35b9cfe50f6a8977ed30b8bf91b4f7360e223a59f366e7e",
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
      "binding_sha256": "bb470525fe4e9e7b574c36e9fdd49c0a8280addc3e4ff41a06964ae0c70de980",
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
      "binding_sha256": "45917920e8022ae22caa64c63b07819dc3037290e41601b2b187162bb92a33ba",
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
      "binding_sha256": "b258baf3fed4a129ba02295cf0ff41f344dc74a06d8d69445006370f443e55bd",
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
      "binding_sha256": "8aeb7d5fcd7aae802edbdab6be3f315f1163021a3300f1837ebabc62c9ac7169",
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
      "binding_sha256": "c59fc4dd29b78028f5f3d99ea3c2798e2683b4609434b3ddf2c9187d7d374f10",
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
      "binding_sha256": "e8810731657051177b81687fe263b62eeaf108e572a4d68d5c9cdcbd1da675f6",
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
      "binding_sha256": "831a5d7ca75c02e4a1809b94ebd1f8a8c806396b665a7613e946ccfd64025e1f",
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
      "binding_sha256": "1ba64de342585b7e79fe82ce9909d9c94a79a49b1802fab1e3eee6caa3189503",
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
      "binding_sha256": "ba1603bb548cdcc0e3ec02f973f8c049cab01cc007a170de05445373710a4e39",
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
      "binding_sha256": "d2bac2d1b0994acb9203f489d557eb71cee36c2f95d3c67e298725d5f2c528d7",
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
      "binding_sha256": "48c065b94d61b3c2fc361dacccb0eccd1aa50d09f8a3ac0aca0ca35f7fe900fd",
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
      "binding_sha256": "d6f326b5b7d2f0fd18be13a0826f57394f46ac5e15756fb4d117415c11371872",
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
      "binding_sha256": "478e64d0b395bcfd06ac50d1a6b61c96364548e9aa8474e594f3059b7e4d347f",
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
      "binding_sha256": "942788e5d0a9d8be35f0efdf4ec6d08e58a264533a8623a47185d1844e24f562",
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
      "binding_sha256": "98384bac5b1d0b0a2f7e4e41cb94595e8769bc80b039f32ae24bee862f14a08a",
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
      "binding_sha256": "f8f81e545c74c92d4159c63ffd39e48df02a2b9b4ea4e7ec30d8b01376a83c60",
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
      "binding_sha256": "69d05589800207120e3c2e0ffd4c9d4a82baf93dfdd908a40fa5909482e8e237",
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
      "binding_sha256": "146c0d137766403739a06310f0fb84e7ff8b6b0ed1fe5135963cf5dc24f7379c",
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
      "binding_sha256": "43a9d43739c68a0d61943767c5bcbb403ace9b18b1992cb34a9987ddc3ad413f",
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
      "binding_sha256": "1eff4f34e8d100989763c7fe2fcc1915bc4017be3df9e95fc43b97d7c531622d",
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
      "binding_sha256": "3f097778b443f0d9a80ed034492f472e7a276ca8c3cce69c821dc5de7a1672ab",
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
      "binding_sha256": "e99d5dc82974607dcdc8ce33a063a94680f3a95cecc144e8abb0cad90cda04f1",
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
      "binding_sha256": "85c95bd8ef53d516d92ea55bd8044e7d365531838aad4385db087c1fd8412fa1",
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
      "binding_sha256": "46ee52511946054027e8cc96f5f5661630908437a8b82da8517f9fce79edc7e6",
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
      "binding_sha256": "43885cb737dd368eeb607fc15ba15ab498fb745a81627c68fe771375ae0aa8d3",
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
      "binding_sha256": "af779331be978db541317dc384124a8252137af339ec59c6b64fa69c85176502",
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
      "binding_sha256": "9a4813608a9ff998d310a91f44ec7a2fc2cbf9e564452e7cb33758d275a6ca4d",
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
      "binding_sha256": "0173335269b99e8b6ef202e915e213e0410116ba73afab0cc3976d0c70a4d937",
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
      "binding_sha256": "cb22bd284b9dde9452e9d9e0e78dbbc49f730e69a6bea27192931aa99fbe3131",
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
      "binding_sha256": "97694a8c58a3678e88324025e24b131ac7511d058eb4efb17f4524f2bfa4dc9c",
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
      "binding_sha256": "89fd8caefe218d5f770fd6a34746353901abb505d4d6de6d60c2dcd8ad5caae8",
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
      "binding_sha256": "3a32b1fa923fa3577d5977b79754b8c2859374e0fc1d98fdee25e54453f0d6fc",
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
      "binding_sha256": "b6faa15647282b3b52520db993510792ee2829572bd136d53eb3c4a47dd61923",
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
      "binding_sha256": "697a557c42236ff2eb2dee66b8dd7b2e54c2e33e1db2dcf706c5a71a01036e13",
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
      "binding_sha256": "fc8e05eb2ba11573ee8217e74475cafbe02bfb33d022462035bca46c1fd1002a",
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
      "binding_sha256": "263ae976ae9a721fba40e5c03ec673a5d8faca0f46fc5e0052dbb3b0bab857a3",
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
      "binding_sha256": "997e0c9c4f79669c00ddb510f026c064ce6883fc82f28f50ca945a53b1cee441",
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
      "binding_sha256": "4f290230aa9151a4f5386c6d5a4cbbf47a1a33b3c6622cb51fadc62ae7554040",
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
      "binding_sha256": "e9f97842c8d9f2e6c1352e4403fba368fd769df2ed153f279ac7cdbcb1901738",
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
      "binding_sha256": "6dd535fa9cdde2e5bb92356d6cb44b57ca5ec54441395f90f8f009efa41972c7",
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
      "binding_sha256": "fde20d30e7d298cd112cd56eb705d9fb5ac8d860bd1ec9f3f36190b2a2d5ffe4",
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
      "binding_sha256": "4b288a454d6163a7fff9dfbbc6fbd25ef16a7f4ea7c68dd7895e29954d22df77",
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
      "binding_sha256": "908e1656e451dbbb85a3a1ba43954a9578fe148b2d1a36ff9a2faa5adb9662c9",
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
      "binding_sha256": "7cfc0e07af20be8a7b849d9e13f249a74acf2f70747dcff5b01381918c547bf2",
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
      "binding_sha256": "cd7dcad15fe08451d01f21130aa33deb6c00e915a38a27c581d28e0e4642cf23",
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
      "binding_sha256": "f30dc2cc497cdaf613c63284edd73969113e4bda628fb45a5914da9cbc48a370",
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
      "binding_sha256": "b87f952ef7c7a44511e42295a0ad0996305f0d5a4e38fc744f239a64936a9c40",
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
      "binding_sha256": "64dd93ddd1b2f63e5b51f201a5b3242cc9d9a6dc0e4f47029ad3343381229e3e",
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
      "binding_sha256": "28a598466ebc1f653b1a45c16bc6113035be7a9ad062f0a1a2de88597ee34e31",
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
      "binding_sha256": "dbde2022a9883c0afbcd18ad4a9b4987b48a1fbcb36e1fff2dedf7f9bc61b194",
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
      "binding_sha256": "257e1aabfad7d4a45608dbba985f324dca5ac5fb2a9f6f87e46c01d4c16250a9",
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
      "binding_sha256": "c44021ff83413f4c95806c565be68a7b10274a8af06a2b137daf084085604f8e",
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
      "binding_sha256": "47ccf984558751144ca862ef181b99d3ec8d62ad20e037723173f2ce60db2168",
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
    "scan_id": "c1ba5410b8710dd9fbed73894eb74c7c7813cf78b6e3cecf80054db70682104c",
    "scope_sha256": "4e01c10d5d5388f1f301cc1f81742dd37a375e51af210210aac226ee08ee3bbc",
    "target": {
      "description": "Selected source directory; paths are relative.",
      "kind": "source",
      "platform": ""
    },
    "tool": {
      "implementation_sha256": "993d77b77bac8f0f4758ce931da596ce03eb31a36a4fec4302efb2da601ffb80",
      "name": "agent-mcp-security-scan",
      "version": "0.11.0"
    }
  },
  "schema_version": "1.0"
}
```
<!-- INVARUNE_REVIEW_END -->

