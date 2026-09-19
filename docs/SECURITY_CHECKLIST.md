# Invarune AI agent and MCP security checklist

**Invarune by NimeshBuild** - Evidence for agent security.

Research snapshot: **2026-09-19**. This catalog contains **66 controls and 132 acceptance checks**. These are original engineering review questions synthesized from the sources in [RESEARCH.md](RESEARCH.md), [CSA_AND_CLOUD.md](CSA_AND_CLOUD.md), and [BENCHMARK_LANDSCAPE.md](BENCHMARK_LANDSCAPE.md). This is not an official NSA, CISA, CSA, NIST, MITRE, OWASP, MCP, CIS, or ISO certification checklist.

Source links explain provenance or thematic alignment; they do not claim that every test is a verbatim requirement of that source. All referenced publications, versions, limitations, and control alignments appear in [SOURCE_MAP.md](SOURCE_MAP.md). The complete machine-readable source registry is [sources.json](../ai_security_scan/data/sources.json).

## How to use this list

For every applicable control, record **owner, scope, evidence, result, exception, and review date**. Use `validated`, `failed`, `not_applicable` with rationale, or `not_validated` for the human assessment. Keep this separate from scanner statuses. Prioritize reachable high-impact operations, exposed remote MCP endpoints, secrets, and cross-tenant access.

A missing source-code pattern is not a passed control. The optional LLM judge supplies advisory hypotheses, not deterministic evidence or authorization. Validation labels below identify the required review method, not implemented automation coverage:

- **static**: source/configuration evidence can reveal a risk; absence remains inconclusive.
- **hybrid**: inspect source and verify effective behavior in a controlled deployment.
- **dynamic**: execute authorized tests against a representative isolated system.
- **manual**: assess architecture, operating procedures, and external evidence.

The 42 implemented rules provide partial coverage of 26 controls. An empty `automated_rule_ids` list means no mapped static rule. A rule match does not establish that all acceptance checks under that control failed.

## Version and applicability

HTTP OAuth checks apply to protected HTTP implementations. Stdio uses local process/credential controls. Record the actual MCP revision; 2026-07-28 and older session-based transports differ. Model instructions, tool annotations, advertised roots, and the judge are not enforcement boundaries. Verify host, server, operating-system, and downstream controls.

## Controls


### Governance

#### GOV-01 - Inventory every agent, MCP server, tool, and model

Validation: **manual**.

- [ ] Record owner, deployment, model/version, MCP transport/version, exposed tools, data classes, and external endpoints.
- [ ] Reconcile approved inventory with deployed configurations; investigate unregistered agents and servers.

Primary context: [NIST-RMF: Artificial Intelligence Risk Management Framework (AI RMF 1.0)](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10).

Additional thematic alignment: CSA-AICM, CSA-AISMM, CIS-AGENTS-2026, CIS-MCP-2026. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### GOV-02 - Model trust boundaries and attack paths

Validation: **manual**.

- [ ] Diagram user, model, memory, tool, server, gateway, and downstream service boundaries with their credentials.
- [ ] Identify who controls each input and the highest-impact action reachable if that input is malicious.

Primary context: [MITRE-ATLAS: ATLAS tactics, techniques, mitigations and case-study data](https://github.com/mitre-atlas/atlas-data); [NIST-AML: Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations](https://csrc.nist.gov/pubs/ai/100/2/e2025/final).

Additional thematic alignment: CSA-MAESTRO, MITRE-ATLAS-202609. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### GOV-03 - Define authorized use and accountable owners

Validation: **manual**.

- [ ] Assign an owner to each autonomous action and document permitted purposes, forbidden outcomes, and escalation routes.
- [ ] Record impact, reversibility, approval requirements, and accepted residual risk before production use.

Primary context: [NIST-RMF: Artificial Intelligence Risk Management Framework (AI RMF 1.0)](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10); [JOINT-AGENTIC: Careful adoption of agentic AI services](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services).

Additional thematic alignment: CSA-AICM, CSA-SCOPING, CSA-AISMM, AIUC1-Q3-2026. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### GOV-04 - Maintain evidence and risk exceptions

Validation: **manual**.

- [ ] Give each control an owner, evidence link, validation date, result, and next review date.
- [ ] Time-limit exceptions and require a compensating control; distinguish untested behavior from demonstrated failure.

Primary context: [NIST-GENAI: Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf); [NIST-SSDF: Secure Software Development Framework (SSDF) Version 1.1](https://csrc.nist.gov/pubs/sp/800/218/final).

Additional thematic alignment: CSA-AICM, CSA-AISMM, NIST-SSDF-AI. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### GOV-05 - Reassess changes in autonomy and integrations

Validation: **manual**.

- [ ] Review security impact when adding a model, tool, server, data source, skill, or broader permission.
- [ ] Require deployment evidence for the complete configured system; a model-only score is insufficient.

Primary context: [NCSC-SECURE-AI: Guidelines for secure AI system development](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development).

Additional thematic alignment: CSA-AICM, CSA-SCOPING. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### GOV-06 - Assign shared security responsibilities across AI providers

Validation: **manual**.

- [ ] For each model, gateway, orchestrator, MCP service, and cloud provider, document which party implements each applicable safeguard and which customer configuration it depends on.
- [ ] Obtain current supplier evidence for inherited safeguards, identify unowned gaps, and record reassessment triggers in the service review.

Primary context: [CSA-AICM: AI Controls Matrix v1.1](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1); [CSA-CCM: Cloud Controls Matrix and CAIQ v4.1](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1).

Partial static rules: none; review/runtime evidence required.


### Identity and authorization

#### AUTH-01 - Authenticate protected operations on every request

Validation: **hybrid**.

- [ ] Trace authentication to every protected HTTP entry point, including tool calls, subscriptions, and retries.
- [ ] Verify missing, expired, revoked, or malformed credentials cannot invoke a protected operation.

Primary context: [MCP-AUTH: MCP: Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).

Additional thematic alignment: CSA-AGENT-IAM, CIS-MCP-2026, OWASP-AISVS-C10. See the source map for limits; these are not exact external clause mappings.

Partial static rules: AI026, AI041.

#### AUTH-02 - Authorize the exact action and target

Validation: **hybrid**.

- [ ] Check user/agent identity, tenant, tool, target object, and requested operation immediately before execution.
- [ ] Deny by default; test read-only callers against write tools and object identifiers owned by another user.

Primary context: [JOINT-AGENTIC: Careful adoption of agentic AI services](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services); [MCP-TOOLS: MCP: Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools).

Additional thematic alignment: CSA-AICM, CSA-AGENT-IAM, CSA-SCOPING, CIS-MCP-2026, OWASP-AISVS-C9, OWASP-AISVS-C10. See the source map for limits; these are not exact external clause mappings.

Partial static rules: AI027.

#### AUTH-03 - Validate access-token cryptography and claims

Validation: **hybrid**.

- [ ] Verify signature with trusted keys, allowed algorithms, expected issuer/audience, expiry, and required scopes.
- [ ] Reject unsigned tokens and tokens minted for another service; decoding a JWT alone is not validation.

Primary context: [MCP-AUTH-SEC: MCP: Authorization Security Considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations).

Additional thematic alignment: CIS-MCP-2026, OWASP-AISVS-C10. See the source map for limits; these are not exact external clause mappings.

Partial static rules: AI017.

#### AUTH-04 - Prevent token passthrough and confused deputy use

Validation: **hybrid**.

- [ ] Use audience-bound MCP credentials and separately authorized downstream credentials; never forward arbitrary caller tokens.
- [ ] Ensure a proxy cannot use its broader service identity to perform an action the caller cannot authorize.

Primary context: [MCP-AUTH: MCP: Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization); [MCP-SECURITY: MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices).

Additional thematic alignment: CIS-MCP-2026, OWASP-AISVS-C10. See the source map for limits; these are not exact external clause mappings.

Partial static rules: AI028.

#### AUTH-05 - Constrain credential lifetime and exposure

Validation: **hybrid**.

- [ ] Use short-lived scoped credentials where supported, protect refresh tokens, and validate rotation and revocation.
- [ ] Avoid tokens in query strings, model context, source, child-process arguments, and diagnostic output.

Primary context: [MCP-AUTH-SEC: MCP: Authorization Security Considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations); [JOINT-DEPLOY: Deploying AI Systems Securely: Best Practices for Deploying Secure and Resilient AI Systems](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely).

Additional thematic alignment: CSA-AGENT-IAM, CIS-AGENTS-2026, CIS-MCP-2026, OWASP-AISVS-C9. See the source map for limits; these are not exact external clause mappings.

Partial static rules: AI010, AI011, AI030, AI034.

#### AUTH-06 - Bind OAuth flows and validate redirects

Validation: **hybrid**.

- [ ] Test PKCE support and S256, exact registered redirects, transaction binding, and authorization-response issuer validation.
- [ ] Reject replayed codes, mismatched issuers, unsafe redirect schemes, and unsolicited callback transactions.

Primary context: [MCP-AUTH-SEC: MCP: Authorization Security Considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations); [MCP-AUTH: MCP: Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).

Partial static rules: AI038.

#### AUTH-07 - Secure OAuth discovery and registration

Validation: **hybrid**.

- [ ] Validate discovered metadata and client metadata URLs before fetching; constrain schemes, destinations, redirects, and response sizes.
- [ ] Document trust policy for client registration and prevent discovery from reaching internal metadata or privileged network services.

Primary context: [MCP-SECURITY: MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices).

Partial static rules: none; review/runtime evidence required.

#### AUTH-08 - Bind delegation to identity, scope, and expiry

Validation: **hybrid**.

- [ ] Carry authenticated initiator and delegation identity through multi-agent calls instead of trusting identity fields in text.
- [ ] Prevent agents from granting themselves privileges; limit delegation scope, depth, lifetime, and downstream audiences.

Primary context: [OWASP-AGENT-CS: AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html).

Additional thematic alignment: CSA-AGENT-IAM, NIST-AGENT-IDENTITY-DRAFT, CIS-AGENTS-2026, CIS-MCP-2026, OWASP-AISVS-C9. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### AUTH-09 - Manage agent identity enrollment and retirement

Validation: **dynamic**.

- [ ] Enroll agents under an accountable sponsor and approved workload identity; verify identity claims before issuing credentials or granting discovery and execution access.
- [ ] Test retirement, sponsor departure, redeployment, and identity compromise; remove stale credentials, cached grants, registrations, and downstream access.

Primary context: [CSA-AGENT-IAM: Agentic AI Identity and Access Management: A New Approach](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach); [NIST-AGENT-IDENTITY-DRAFT: Accelerating the Adoption of Software and AI Agent Identity and Authorization Concept Paper](https://www.nccoe.nist.gov/publications/other/accelerating-adoption-software-and-ai-agent-identity-and-authorization-concept).

Partial static rules: none; review/runtime evidence required.


### MCP protocol and tools

#### MCP-01 - Validate transport exposure and origin

Validation: **hybrid**.

- [ ] For HTTP, reject invalid Origin values and verify local deployments bind only to intended interfaces.
- [ ] Use TLS for remote protected endpoints; test DNS rebinding and proxy/header behavior in deployment.

Primary context: [MCP-HTTP: MCP: Streamable HTTP transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http).

Additional thematic alignment: OWASP-AISVS-C10. See the source map for limits; these are not exact external clause mappings.

Partial static rules: AI006, AI007, AI008, AI029.

#### MCP-02 - Validate tool arguments and results

Validation: **hybrid**.

- [ ] Apply schemas and semantic bounds before executing every tool; reject unknown properties where appropriate.
- [ ] Bound sizes and nesting; validate declared structured output and render errors without leaking secrets.

Primary context: [MCP-TOOLS: MCP: Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools).

Additional thematic alignment: CIS-MCP-2026, OWASP-AISVS-C9, OWASP-AISVS-C10. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### MCP-03 - Treat descriptions and annotations as untrusted

Validation: **hybrid**.

- [ ] Inspect descriptions, schemas, resources, icons, and results for instructions that cross tool or user boundaries.
- [ ] Never let readOnlyHint, destructiveHint, or other server claims replace independent authorization and approval policy.

Primary context: [MCP-TOOLS: MCP: Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools); [OWASP-MCP-CS: MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html).

Additional thematic alignment: OWASP-AISVS-C10. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### MCP-04 - Detect tool substitution and metadata changes

Validation: **hybrid**.

- [ ] Bind tool approval to verified server identity and the reviewed tool definition or version.
- [ ] Revalidate changes after reconnect/list updates; disambiguate collisions across servers without trusting display names.

Primary context: [OWASP-MCP10: OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10).

Additional thematic alignment: OWASP-AISVS-C10. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### MCP-05 - Protect state handles and legacy sessions

Validation: **dynamic**.

- [ ] Authorize every state handle against its owner and tenant; enforce expiry, unpredictability, and replay boundaries.
- [ ] For older sessionful protocol versions, test session hijacking and cross-user resumption; a session ID is not authentication.

Primary context: [MCP-TOOLS: MCP: Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools); [MCP-SECURITY: MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices).

Partial static rules: AI038.

#### MCP-06 - Constrain sampling and returned model context

Validation: **dynamic**.

- [ ] Apply host policy and user control to sampling requests, context sharing, model selection, and associated tool access.
- [ ] Test whether an untrusted server can induce disclosure from unrelated conversations or recursively consume model budget.

Primary context: [MCP-SAMPLING: MCP: Sampling](https://modelcontextprotocol.io/specification/2026-07-28/client/sampling).

Partial static rules: none; review/runtime evidence required.

#### MCP-07 - Secure elicitation and URL interactions

Validation: **hybrid**.

- [ ] Keep sensitive credential collection out of form-mode elicitation; validate and visibly identify URL destinations.
- [ ] Test cancellation, phishing URLs, unsolicited interactions, and replayed completion state against the selected protocol version.

Primary context: [MCP-ELICITATION: MCP: Elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation).

Partial static rules: none; review/runtime evidence required.

#### MCP-08 - Enforce filesystem isolation independently of roots

Validation: **hybrid**.

- [ ] Treat declared roots as scoped information, not an operating-system sandbox or complete authorization mechanism.
- [ ] Enforce allowed paths at file access and test traversal, symlinks, alternate encodings, and writes outside the workspace.

Primary context: [MCP-ROOTS: MCP: Roots](https://modelcontextprotocol.io/specification/2026-07-28/client/roots).

Partial static rules: AI015.

#### MCP-09 - Constrain local server launch and inherited environment

Validation: **hybrid**.

- [ ] Approve executable and package identity before starting a stdio server; use argument arrays and a minimal environment.
- [ ] Restrict proxy process-spawn APIs and child filesystem/network permissions; separate stdout protocol traffic from logs.

Primary context: [MCP-SECURITY: MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices); [OWASP-MCP-CS: MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html).

Additional thematic alignment: OWASP-AISVS-C10. See the source map for limits; these are not exact external clause mappings.

Partial static rules: AI018, AI031.

#### MCP-10 - Apply version-aware metadata, caching, and cancellation

Validation: **dynamic**.

- [ ] Record supported revisions and test their capability, metadata, header consistency, stream, and cancellation rules.
- [ ] Prevent caches and request continuations from crossing authorization contexts; do not apply legacy handshake assumptions universally.

Primary context: [MCP-TRANSPORTS: MCP: Transport overview](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports); [MCP-HTTP: MCP: Streamable HTTP transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http).

Partial static rules: none; review/runtime evidence required.


### Agent behavior and context

#### AGT-01 - Enforce action policy outside the model

Validation: **hybrid**.

- [ ] Place allow/deny decisions at the execution boundary using trusted policy inputs and constrained tool capabilities.
- [ ] Show that an injected instruction cannot disable policy, choose privileged credentials, or bypass approval.

Primary context: [ASD-HARNESS: Agentic AI harnesses: The layer above the model](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses).

Additional thematic alignment: CIS-MCP-2026, OWASP-AISVS-C9, AIUC1-Q3-2026. See the source map for limits; these are not exact external clause mappings.

Partial static rules: AI027, AI031.

#### AGT-02 - Bind approval to the action executed

Validation: **dynamic**.

- [ ] Present actual recipient, target, arguments, data disclosure, and consequences for high-impact approval.
- [ ] Invalidate approval if arguments or target change; test races, delayed retries, and approval reuse.

Primary context: [OWASP-AGENT-CS: AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html).

Additional thematic alignment: CSA-SCOPING, OWASP-AISVS-C9. See the source map for limits; these are not exact external clause mappings.

Partial static rules: AI031.

#### AGT-03 - Separate untrusted content from authoritative instructions

Validation: **hybrid**.

- [ ] Track origin and trust level for web pages, documents, messages, OCR, tool results, and repository instructions.
- [ ] Test direct and indirect goal hijacking; formatting delimiters and prompt warnings alone are not access controls.

Primary context: [OWASP-LLM2026: OWASP GenAI LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/).

Partial static rules: AI032.

#### AGT-04 - Protect retrieval and persistent memory

Validation: **hybrid**.

- [ ] Enforce document and memory ACLs at retrieval and update time, including vector search metadata filters.
- [ ] Test poisoned memory persistence, cross-tenant retrieval, provenance loss, deletion, and stale privileged context.

Primary context: [OWASP-AGENTIC: OWASP Top 10 for Agentic Applications for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).

Additional thematic alignment: CSA-MAESTRO, CIS-AGENTS-2026. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### AGT-05 - Keep objectives and authority bounded across agents

Validation: **dynamic**.

- [ ] Constrain delegated tasks and verify messages against authenticated senders, expected schemas, and allowed transitions.
- [ ] Test impersonation, conflicting instructions, cascading failure, and privilege growth across handoffs.

Primary context: [OWASP-AGENTIC: OWASP Top 10 for Agentic Applications for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).

Additional thematic alignment: CSA-MAESTRO, OWASP-AISVS-C9. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### AGT-06 - Protect agent configuration and skills

Validation: **hybrid**.

- [ ] Inventory skill files, prompts, hooks, memory seed files, MCP configuration, and other executable workflow inputs.
- [ ] Require review for changes that add commands, access, or persistence; external repository text cannot become trusted policy.

Primary context: [MITRE-ATLAS: ATLAS tactics, techniques, mitigations and case-study data](https://github.com/mitre-atlas/atlas-data); [NCSC-SECURE-AI: Guidelines for secure AI system development](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development).

Additional thematic alignment: AIUC1-Q3-2026. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### AGT-07 - Prevent sensitive context leaving through legitimate tools

Validation: **dynamic**.

- [ ] Apply destination and data policies to URLs, searches, tickets, messages, uploads, and telemetry generated by agents.
- [ ] Use canary data to test encoded leakage and combinations of otherwise permitted tools.

Primary context: [OWASP-MCP-CS: MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html).

Partial static rules: none; review/runtime evidence required.


### Execution and application security

#### EXEC-01 - Prevent shell and command injection

Validation: **hybrid**.

- [ ] Find shell execution and constructed command strings; use fixed executables, argument arrays, and allowed argument values.
- [ ] Test untrusted tool inputs containing shell syntax, option injection, command substitution, and hostile filenames.

Primary context: [OWASP-MCP10: OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10); [OWASP-OUTPUT2025: LLM05:2025 Improper Output Handling](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/).

Partial static rules: AI002, AI003, AI012.

#### EXEC-02 - Constrain generated-code execution

Validation: **hybrid**.

- [ ] Locate eval, exec, dynamic imports, templates, notebooks, and interpreter tools accepting model or user content.
- [ ] Run required code execution in a disposable restricted environment with explicit filesystem, network, CPU, and time limits.

Primary context: [OWASP-AGENT-CS: AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html).

Additional thematic alignment: OWASP-AISVS-C9, AIUC1-Q3-2026. See the source map for limits; these are not exact external clause mappings.

Partial static rules: AI001, AI013.

#### EXEC-03 - Parameterize database and query operations

Validation: **hybrid**.

- [ ] Use bound query parameters and allowed query shapes; inspect SQL, NoSQL, graph, and search-language construction.
- [ ] Separate read/write database identities and test whether generated queries can escape permitted objects or operations.

Primary context: [OWASP-OUTPUT2025: LLM05:2025 Improper Output Handling](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/).

Partial static rules: AI036.

#### EXEC-04 - Constrain file and archive access

Validation: **hybrid**.

- [ ] Resolve and enforce allowed paths at access time; constrain uploads, downloads, extraction, temporary files, and permissions.
- [ ] Test symlink races, archive traversal, absolute paths, overwrite attempts, and secret-directory reads.

Primary context: [MCP-ROOTS: MCP: Roots](https://modelcontextprotocol.io/specification/2026-07-28/client/roots); [JOINT-DEPLOY: Deploying AI Systems Securely: Best Practices for Deploying Secure and Resilient AI Systems](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely).

Partial static rules: AI015, AI016, AI037.

#### EXEC-05 - Prevent SSRF and unsafe network destinations

Validation: **hybrid**.

- [ ] Restrict destinations and schemes at connection time; revalidate DNS resolution and each redirect.
- [ ] Test loopback, private/link-local IPv4 and IPv6, cloud metadata, alternate encodings, and redirect-to-private cases.

Primary context: [MCP-SECURITY: MCP Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices).

Partial static rules: AI014.

#### EXEC-06 - Reject unsafe parsing and deserialization

Validation: **hybrid**.

- [ ] Inspect pickle, unsafe YAML, object deserialization, XML entity expansion, and unconstrained recursive parsers.
- [ ] Use data-only formats with byte, nesting, and type limits; test malformed input and expansion attacks.

Primary context: [NIST-SSDF: Secure Software Development Framework (SSDF) Version 1.1](https://csrc.nist.gov/pubs/sp/800/218/final).

Partial static rules: AI004, AI005, AI035.

#### EXEC-07 - Render model and tool output safely

Validation: **hybrid**.

- [ ] Use context-specific escaping for HTML/Markdown, avoid unsafe DOM sinks, and validate links and embedded media.
- [ ] Test active SVG/HTML, malicious URLs, terminal escapes, and spreadsheet formulas in exported reports.

Primary context: [OWASP-OUTPUT2025: LLM05:2025 Improper Output Handling](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/).

Partial static rules: AI039, AI040.


### Data and privacy

#### DATA-01 - Detect and remove embedded credentials

Validation: **static**.

- [ ] Inspect code, examples, configuration, notebooks, test fixtures, and generated artifacts for secret-like values.
- [ ] Verify actual exposures with the owner, rotate real credentials, and remove them from reachable history and artifacts.

Primary context: [JOINT-DEPLOY: Deploying AI Systems Securely: Best Practices for Deploying Secure and Resilient AI Systems](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely).

Additional thematic alignment: AIUC1-Q3-2026. See the source map for limits; these are not exact external clause mappings.

Partial static rules: AI010, AI011, AI030, AI034.

#### DATA-02 - Minimize data sent to models and gateways

Validation: **manual**.

- [ ] Map which prompts, tool outputs, memory, and code leave the environment and identify the receiving provider/gateway.
- [ ] Document allowed data classes, processing location, retention, and training use; redact before transmission where required.

Primary context: [NIST-GENAI: Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf).

Additional thematic alignment: CSA-AICM, CIS-AGENTS-2026, AIUC1-Q3-2026. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### DATA-03 - Protect logs, traces, and error responses

Validation: **hybrid**.

- [ ] Redact secrets and sensitive payloads before logs, traces, exception strings, and dashboards persist them.
- [ ] Test the failure paths and provider errors as well as success paths; restrict access and export destinations.

Primary context: [OWASP-MCP10: OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10).

Additional thematic alignment: CIS-AGENTS-2026, CIS-MCP-2026, AIUC1-Q3-2026. See the source map for limits; these are not exact external clause mappings.

Partial static rules: AI009, AI033.

#### DATA-04 - Track provenance and integrity of AI data

Validation: **manual**.

- [ ] Record source, owner, version, transformation history, and integrity evidence for datasets, retrieval corpora, and memory seeds.
- [ ] Quarantine unexpected changes and test how poisoned or stale data is detected, removed, and replaced.

Primary context: [NSA-DATA: AI Data Security: Best Practices for Securing Data Used to Train & Operate AI Systems (NSA announcement)](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/).

Additional thematic alignment: CSA-AICM, NIST-SSDF-AI. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### DATA-05 - Enforce retention and deletion across copies

Validation: **dynamic**.

- [ ] Apply expiry and deletion to prompts, embeddings, caches, memory, tool artifacts, backups, and provider-held data.
- [ ] Verify deleting a source record removes or invalidates dependent retrieval content and access grants.

Primary context: [NIST-GENAI: Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf).

Additional thematic alignment: CIS-AGENTS-2026. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### DATA-06 - Protect stored data and keys

Validation: **hybrid**.

- [ ] Check transport verification, storage access controls, encryption settings, key separation, and backup permissions.
- [ ] Validate key rotation and denied access using a principal outside the authorized tenant or operational role.

Primary context: [NSA-DATA: AI Data Security: Best Practices for Securing Data Used to Train & Operate AI Systems (NSA announcement)](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/); [JOINT-DEPLOY: Deploying AI Systems Securely: Best Practices for Deploying Secure and Resilient AI Systems](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely).

Additional thematic alignment: CSA-CCM, CIS-AGENTS-2026. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.


### Supply chain

#### SUP-01 - Pin and inventory executable dependencies

Validation: **static**.

- [ ] Review lockfiles and exact versions or immutable digests for packages, images, MCP servers, models, and plugins.
- [ ] Flag runtime installs, floating tags, remote scripts, and dependency sources outside approved registries.

Primary context: [NIST-SSDF: Secure Software Development Framework (SSDF) Version 1.1](https://csrc.nist.gov/pubs/sp/800/218/final).

Additional thematic alignment: NIST-SSDF-AI, AIUC1-Q3-2026. See the source map for limits; these are not exact external clause mappings.

Partial static rules: AI018, AI024, AI025.

#### SUP-02 - Check vulnerability and maintenance exposure

Validation: **manual**.

- [ ] Run appropriate package/container advisory tools against resolved dependencies and save database date and tool version.
- [ ] Triage reachability, fix availability, support status, and transitive dependencies; source pattern scans do not establish CVE coverage.

Primary context: [NCSC-SECURE-AI: Guidelines for secure AI system development](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development).

Additional thematic alignment: CSA-AISMM, CIS-MCP-2026, OPENSSF-BASELINE-202608. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### SUP-03 - Verify artifact identity and provenance

Validation: **manual**.

- [ ] Verify publisher identity, hashes/signatures, build provenance, and intended origin before enabling artifacts.
- [ ] Review model loading and serialization behavior; an integrity hash cannot make an untrusted publisher safe.

Primary context: [NSA-DATA: AI Data Security: Best Practices for Securing Data Used to Train & Operate AI Systems (NSA announcement)](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/); [NIST-SSDF: Secure Software Development Framework (SSDF) Version 1.1](https://csrc.nist.gov/pubs/sp/800/218/final).

Additional thematic alignment: CSA-AICM, CSA-MAESTRO, NIST-SSDF-AI, OWASP-AISVS-C10, SLSA-12, OPENSSF-MODEL-SIGNING. See the source map for limits; these are not exact external clause mappings.

Partial static rules: AI019, AI024, AI035.

#### SUP-04 - Protect build, release, and configuration changes

Validation: **hybrid**.

- [ ] Restrict CI credentials and workflow permissions; review actions, build scripts, and release provenance.
- [ ] Prevent untrusted contributions from executing with deployment secrets or changing approved agent policies.

Primary context: [NIST-SSDF: Secure Software Development Framework (SSDF) Version 1.1](https://csrc.nist.gov/pubs/sp/800/218/final).

Additional thematic alignment: NIST-SSDF-AI, CIS-MCP-2026, OPENSSF-BASELINE-202608, SLSA-12. See the source map for limits; these are not exact external clause mappings.

Partial static rules: AI020.

#### SUP-05 - Harden runtime isolation and deployment defaults

Validation: **hybrid**.

- [ ] Review root/privileged containers, host mounts, Docker sockets, unrestricted egress, debug mode, and public management endpoints.
- [ ] Separate agent execution from control-plane credentials and audit storage; test isolation in the deployed environment.

Primary context: [JOINT-DEPLOY: Deploying AI Systems Securely: Best Practices for Deploying Secure and Resilient AI Systems](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely).

Additional thematic alignment: CSA-CCM, CSA-MAESTRO. See the source map for limits; these are not exact external clause mappings.

Partial static rules: AI021, AI022, AI023, AI031, AI042.

#### SUP-06 - Separate and protect model development environments

Validation: **dynamic**.

- [ ] When training or fine-tuning, isolate development, evaluation, and production identities, data access, registries, and release permissions.
- [ ] Protect datasets, weights, adapters, and configuration separately; monitor modifications and demonstrate that an untrusted training job cannot replace an approved production artifact.

Primary context: [NIST-SSDF-AI: SP 800-218A: Secure Software Development Practices for Generative AI and Dual-Use Foundation Models](https://csrc.nist.gov/pubs/sp/800/218/a/final).

Partial static rules: none; review/runtime evidence required.


### Operations and resilience

#### OPS-01 - Produce attributable audit events

Validation: **hybrid**.

- [ ] Record initiating identity, delegated identity, tool/server/version, approved arguments, decision, outcome, and correlation identifiers.
- [ ] Protect log integrity and clock consistency; ensure agents cannot erase their own action history.

Primary context: [OWASP-MCP10: OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10).

Additional thematic alignment: CSA-CCM, CSA-AGENT-IAM, CIS-AGENTS-2026, CIS-MCP-2026, OWASP-AISVS-C9. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### OPS-02 - Bound work, spending, and concurrency

Validation: **hybrid**.

- [ ] Set server-enforced limits for iterations, tokens, tool calls, recursion, parallelism, bytes, cost, and elapsed time.
- [ ] Exercise stuck loops and amplification paths; verify limits apply across retries and child agents.

Primary context: [ASD-HARNESS: Agentic AI harnesses: The layer above the model](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses).

Additional thematic alignment: CSA-SCOPING, OWASP-AISVS-C9, OWASP-AISVS-C10. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### OPS-03 - Make cancellation and shutdown effective

Validation: **dynamic**.

- [ ] Provide a tested stop mechanism that revokes work, credentials, queued actions, and child tasks.
- [ ] Measure stop latency and verify cancelled or disconnected requests cannot later commit prohibited side effects.

Primary context: [JOINT-AGENTIC: Careful adoption of agentic AI services](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services).

Additional thematic alignment: CSA-AGENT-IAM, OWASP-AISVS-C9. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### OPS-04 - Fail safely and prevent duplicate side effects

Validation: **dynamic**.

- [ ] Deny or escalate when policy, identity, or approval checks fail; prevent fallback paths from widening privilege.
- [ ] Test outages, partial failures, timeouts, retries, idempotency, and recovery of transactions with external effects.

Primary context: [ASD-HARNESS: Agentic AI harnesses: The layer above the model](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses).

Partial static rules: none; review/runtime evidence required.

#### OPS-05 - Monitor behavior and support rollback

Validation: **dynamic**.

- [ ] Alert on unusual tool use, new destinations, scope growth, repeated denials, cost spikes, and unexpected state changes.
- [ ] Validate alerts with seeded events and test rollback of models, prompts, tools, policies, and poisoned memory.

Primary context: [NCSC-SECURE-AI: Guidelines for secure AI system development](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development).

Additional thematic alignment: CSA-CCM, CSA-AISMM. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### OPS-06 - Practice incident response and disclosure

Validation: **manual**.

- [ ] Maintain procedures to isolate agents, revoke credentials, preserve evidence, notify owners, and recover trusted state.
- [ ] Exercise an AI-specific incident and define approved vulnerability/intelligence-sharing channels without exposing sensitive evidence.

Primary context: [CISA-JCDC: JCDC AI Cybersecurity Collaboration Playbook and Fact Sheet (release notice)](https://www.cisa.gov/news-events/alerts/2025/01/14/cisa-releases-jcdc-ai-cybersecurity-collaboration-playbook-and-fact-sheet).

Additional thematic alignment: CSA-AICM, CSA-CCM, CSA-AISMM, OPENSSF-BASELINE-202608. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.


### Security validation

#### TEST-01 - Measure prompt-injection security and useful task completion

Validation: **dynamic**.

- [ ] Run paired benign and adversarial workflows with representative tools and attacker-controlled external content.
- [ ] Record attacker success, authorized task success, blocked benign actions, and the observed unauthorized side effect.

Primary context: [BENCH-AGENTDOJO: AgentDojo](https://github.com/ethz-spylab/agentdojo); [BENCH-INJECAGENT: InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent).

Additional thematic alignment: MITRE-ATLAS-202609. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### TEST-02 - Test adaptively and repeat scenarios

Validation: **dynamic**.

- [ ] Vary payload wording, placement, modality, attacker knowledge, and attempts; rerun after changing defenses.
- [ ] Report per-scenario outcomes, sample counts, attack budget, uncertainty, and model/harness versions instead of only an average.

Primary context: [NIST-HIJACK-EVAL: Technical Blog: Strengthening AI Agent Hijacking Evaluations](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations).

Additional thematic alignment: MITRE-ATLAS-202609. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### TEST-03 - Exercise MCP authentication and protocol abuse

Validation: **dynamic**.

- [ ] In an isolated test environment, exercise invalid tokens, wrong audiences, origin abuse, malicious servers, and protocol fuzzing.
- [ ] Adapt scenarios to the deployed MCP revision and transports; preserve request/response evidence with secrets removed.

Primary context: [BENCH-MCPSECBENCH: MCPSecBench](https://github.com/AIS2Lab/MCPSecBench); [MCP-AUTH: MCP: Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).

Additional thematic alignment: CIS-MCP-2026. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### TEST-04 - Verify cross-tenant and cross-agent isolation

Validation: **dynamic**.

- [ ] Create two principals and attempt cross-access to objects, memory, caches, handles, subscriptions, and execution results.
- [ ] Repeat after reconnect, delegation, failed authentication, concurrent requests, and privilege revocation.

Primary context: [BENCH-ASB: Agent Security Bench (ASB)](https://github.com/agiresearch/ASB).

Partial static rules: none; review/runtime evidence required.

#### TEST-05 - Test approval, policy, and sandbox bypass

Validation: **dynamic**.

- [ ] Use explicit forbidden-action canaries to verify enforcement survives hostile content, tool substitution, and delayed execution.
- [ ] Confirm paths through retries, fallback models, alternate tools, and child agents enforce the same boundary.

Primary context: [OWASP-AGENT-CS: AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html).

Additional thematic alignment: CIS-MCP-2026. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### TEST-06 - Verify conventional application security

Validation: **dynamic**.

- [ ] Run language-aware SAST, dependency review, secret scanning, and authorized integration tests for exposed services.
- [ ] Exercise reachable injection, XSS, SSRF, path traversal, deserialization, and access-control risks with safe fixtures.

Primary context: [NIST-SSDF: Secure Software Development Framework (SSDF) Version 1.1](https://csrc.nist.gov/pubs/sp/800/218/final); [OWASP-OUTPUT2025: LLM05:2025 Improper Output Handling](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/).

Additional thematic alignment: NIST-SSDF-AI, CIS-MCP-2026, AIUC1-Q3-2026. See the source map for limits; these are not exact external clause mappings.

Partial static rules: none; review/runtime evidence required.

#### TEST-07 - Validate resource exhaustion and observability

Validation: **dynamic**.

- [ ] Simulate oversized messages, slow peers, streaming floods, repeated errors, runaway agents, and unavailable dependencies.
- [ ] Verify quotas, shutdown, telemetry, and alerts work together without leaking payloads or losing attribution.

Primary context: [ASD-HARNESS: Agentic AI harnesses: The layer above the model](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses).

Partial static rules: none; review/runtime evidence required.

#### TEST-08 - Evaluate the optional security judge itself

Validation: **dynamic**.

- [ ] Treat repository text and model verdicts as untrusted; test prompt injection, fabricated locations, invalid JSON, and timeouts.
- [ ] Compare against labeled cases, retain deterministic results, document model variability, and never equate a judge approval with control validation.

Primary context: [NIST-HIJACK-EVAL: Technical Blog: Strengthening AI Agent Hijacking Evaluations](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations); [NIST-GENAI: Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf).

Partial static rules: none; review/runtime evidence required.

#### TEST-09 - Evaluate model-layer attacks for hosted or customized models

Validation: **dynamic**.

- [ ] Where applicable, assess suspicious triggers, model extraction, and disclosure of private training examples under an explicit attacker access and query budget.
- [ ] Retest acquired or retrained models and adapters before release; document measured failures, model identity, coverage limits, and accepted residual risk.

Primary context: [CSA-MAESTRO: Agentic AI Threat Modeling Framework: MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro); [NIST-SSDF-AI: SP 800-218A: Secure Software Development Practices for Generative AI and Dual-Use Foundation Models](https://csrc.nist.gov/pubs/sp/800/218/a/final).

Partial static rules: none; review/runtime evidence required.
