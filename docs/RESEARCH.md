# Research basis for AI agent and MCP security review

**Verified on 2026-09-19.** This research uses government publications, official protocol documentation, official OWASP/MITRE resources, and benchmark authors' repositories. Publication dates below come from the source, rather than search-engine crawl dates. Living pages can change after this snapshot.

The expanded edition also includes [CSA/cloud assurance](CSA_AND_CLOUD.md), [additional standards and benchmarks](BENCHMARK_LANDSCAPE.md), and a [source-to-control map](SOURCE_MAP.md).

The actionable result is [66 controls with 132 acceptance checks](SECURITY_CHECKLIST.md), also available as [machine-readable JSON](../ai_security_scan/data/controls.json). These are this project's engineering checks. They are neither an official government checklist nor a claim of certification, compliance, comprehensive vulnerability coverage, or benchmark completion.

## What the different references establish

| Kind | Examples | What it provides | What it does not establish |
|---|---|---|---|
| Government guidance | NSA/CISA/ASD joint publications | Deployment, identity, governance, data, and operational practices | A score proving a repository is secure |
| Risk-management framework | NIST AI RMF and GenAI Profile | A structure for ownership, assessment, measurement, and risk treatment | A prescriptive universal implementation checklist |
| Threat taxonomy | MITRE ATLAS, NIST AML, OWASP Top 10 | A vocabulary for attack paths and review scope | Evidence that a particular attack is exploitable or prevented |
| Protocol specification | MCP versioned specification | Conditional interoperability and security requirements | A sandbox, downstream permissions, or trustworthy tool behavior |
| Executable research benchmark | AgentDojo, InjecAgent, ASB, MCPSecBench | Repeatable scenarios and metrics under a defined harness | Production assurance across all tools, models, transports, and deployments |
| Source-code scanner | This project | Repeatable evidence about selected local patterns and review gaps | A replacement for runtime tests, a CVE database, or a complete taint-analysis engine |

An important distinction for the requested “benchmarks”: **NSA and CISA primarily supply guidance here, not an executable agent/MCP pass-fail benchmark**. The proposed review combines that guidance with protocol checks, attack taxonomies, and separate behavioral evaluation.

## Government and standards sources

| Source and verified date/version | Role in this review | Applicability and limits |
|---|---|---|
| [Careful Adoption of Agentic AI Services — NSA announcement](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4475134/nsa-joins-the-asds-acsc-and-others-to-release-guidance-on-agentic-artificial-in/), **2026-04-30**; [CISA bulletin](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/41544ff), **2026-05-01**; [full joint guidance hosted by ASD](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services) | Directly addresses agent autonomy, identity, privilege, interconnectedness, oversight, and accountability. | The most directly relevant NSA/CISA agent guidance located. Apply recommendations to the actual operational risk and preserve human responsibility. |
| [Agentic AI harnesses — ASD](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/agentic-ai-harnesses), **2026-09-11** | Focuses attention on the software that controls tools, context, memory, and execution. | Supports enforcing security in the harness and connected systems. This is ASD guidance; do not attribute it to NSA/CISA as joint authors. |
| [Deploying AI Systems Securely: Best Practices for Deploying Secure and Resilient AI Systems — joint NSA/CISA/partners](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely), **April 2024**, ASD page **2024-04-16**; [NSA version record](https://www.nsa.gov/Press-Room/Digital-Media-Center/Document-Gallery/igphoto/2003439257/), **v1.0** | Deployment, infrastructure protection, monitoring, and secure operation. | The document concentrates on operating externally developed AI, particularly on-premises/private-cloud deployments. Hosted API users must adapt its infrastructure guidance. |
| [AI Data Security: Best Practices for Securing Data Used to Train & Operate AI Systems — NSA announcement](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4192332/nsas-aisc-releases-joint-guidance-on-the-risks-and-best-practices-in-ai-data-se/), **2025-05-22** | Data provenance, integrity, protection, and changes across the lifecycle. | Applies to retrieval and operational data as well as training data; a source scan cannot inspect provider data practices or corpus integrity. |
| [Guidelines for secure AI system development — NCSC/CISA/international partners](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development), **2023-11-27, v1.0** | Organizes the lifecycle into design, development, deployment, and operation. | Complements runtime controls with supply-chain, ownership, and maintenance evidence. |
| [JCDC AI Cybersecurity Collaboration Playbook — CISA](https://www.cisa.gov/news-events/alerts/2025/01/14/cisa-releases-jcdc-ai-cybersecurity-collaboration-playbook-and-fact-sheet), **2025-01-14** | Incident collaboration and voluntary information sharing. | An operational playbook, not a code-scanning standard or requirement to disclose every finding. |
| [NIST AI RMF 1.0 / AI 100-1](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-ai-rmf-10), **2023-01-26**; [current program status](https://www.nist.gov/itl/ai-risk-management-framework) | Risk ownership, context, measurement, and treatment. | Voluntary, adaptable framework. At the review date, NIST says revision work is underway; this project cites the released 1.0 rather than inventing a replacement. |
| [NIST AI 600-1, Generative Artificial Intelligence Profile](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf), **July 2024**; [NIST release-date reference](https://www.nist.gov/itl/ai-risk-management-framework/ai-risk-management-framework-resources), **2024-07-26** | Expands assessment to GenAI information security, privacy, data, and human interaction risks. | Broader than agent/MCP security. The checklist selects security-relevant issues, not the entire profile. |
| [NIST AI 100-2e2025, Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations](https://csrc.nist.gov/pubs/ai/100/2/e2025/final), **2025-03-24** | Consistent terminology for attacker capabilities, goals, poisoning, privacy, and injection. | A taxonomy. The official page includes a **2025-06-03 potential-updates note**; use the source when relying on exact taxonomy identifiers. |
| [NIST SP 800-218, SSDF v1.1](https://csrc.nist.gov/pubs/sp/800/218/final), **2022-02-03** | Conventional secure development, release, and vulnerability-management practices remain applicable. | Referenced for engineering lifecycle context, not as an exhaustive or clause-by-clause compliance mapping. |
| [NIST technical blog: Strengthening AI Agent Hijacking Evaluations](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations), **2025-01-17** | Supports adaptive tests, scenario-level reporting, and repeated attacker attempts. | Research methodology, not an agent security certification. |

## Protocol sources and important version differences

Use the [MCP specification dated 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) as the current reference snapshot in this project, and record the actual version deployed. Do not silently apply it to a server implementing an older revision.

| Official source | What to check |
|---|---|
| [Authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) and [authorization security considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations) | Token audience and issuer, per-request validation, scope, protected-resource discovery, PKCE, redirect handling, response binding, and separate downstream credentials. |
| [Transport overview](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports) and [Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http) | Origin validation, exposure, request metadata, streams, capabilities, and version-specific cancellation. |
| [Tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools) | Input/output validation, untrusted annotations, unambiguous server/tool identity, access controls, rates, and explicit state handles. |
| [Sampling](https://modelcontextprotocol.io/specification/2026-07-28/client/sampling) | Host control over model requests, tool access, and shared context. |
| [Elicitation](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation) | Sensitive data handling, phishing exposure, user control, and correlation of responses. |
| [Roots](https://modelcontextprotocol.io/specification/2026-07-28/client/roots) | File scope signals and actual filesystem enforcement. |
| [Security Best Practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) | Confused deputy, token forwarding, discovery SSRF, state handles, local launch, URL handling, and registration trust. The page moved out of the old specification path. |

Three qualifications matter in reviews:

1. HTTP authorization is optional in the protocol; protected applications need an appropriate control design. Stdio does not use the HTTP OAuth flow. Do not label every absence of OAuth a specification violation. [Authorization scope](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
2. The 2026-07-28 core uses per-request metadata and no protocol-level session or `initialize` handshake. Earlier revisions differ. A blanket requirement for session IDs or a blanket ban on old handshake code would be wrong. [Transport compatibility](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports)
3. Tool descriptions, annotations, advertised roots, and model compliance do not by themselves provide a security boundary. Our engineering interpretation is to enforce authority in the host, server, runtime, and downstream service and test the complete path. [Tool trust](https://modelcontextprotocol.io/specification/2026-07-28/server/tools), [roots](https://modelcontextprotocol.io/specification/2026-07-28/client/roots)

## Threat catalogs and newer community work

| Primary source | Verified status | Use and limitation |
|---|---|---|
| [OWASP Top 10 for Agentic Applications for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | Published **2025-12-09** | Agent-specific threat prioritization, including compromised goals, tools, memory, identities, and interacting agents. A risk list, not executable benchmark results. |
| [OWASP GenAI LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) | Published **2026-08-03** | Current edition verified at the review date. Some rule references may intentionally retain named 2025 categories; those are historical references, not claims to current numbering. |
| [OWASP MCP Top 10](https://owasp.org/projects/mcp-top-10) | Living page, **2025 labels**; roadmap still describes **beta/pilot stage** when checked | MCP-oriented concerns including token exposure, tool poisoning, scope growth, injection, auditing, and shadow servers. Do not present its maturity or conformance as stronger than the source does. |
| [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) | Living document, accessed **2026-09-19** | Practical implementation context; verify version-sensitive advice against the actual MCP specification. |
| [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) | Living document, accessed **2026-09-19** | Application-level policies, isolation, tools, context, and operational testing. |
| [OWASP LLM05:2025 Improper Output Handling](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/) | Explicitly a **2025 category** | Technical context for conventional interpreter/output sinks; retained as a dated reference. |
| [MITRE ATLAS data repository](https://github.com/mitre-atlas/atlas-data) | Living official repository, accessed **2026-09-19** | Threat-model and attack-scenario vocabulary. Content versions and schema format versions differ; pin the data release before relying on exact IDs. No ATLAS score is calculated here. |
| [OWASP Agent Control Standard](https://genai.owasp.org/resource/agent-control-standard-acs/) | OWASP resource dated **2026-09-01** | Emerging runtime hook and policy-enforcement work. Identified for architecture review; this project does not claim ACS implementation. |
| [OWASP GenAI Security Industry Framework Crosswalk](https://genai.owasp.org/resource/genai-security-industry-framework-crosswalk/) | Resource dated **2026-09-01** | Useful future crosswalk reference. This project's mappings are independently scoped and do not claim exhaustive adoption. |

The recently published resources are recorded so the review does not freeze at older 2024–2025 advice. Their presence is not evidence that a codebase implements them.

## Actual executable benchmarks to run separately

These repositories are the authors' original projects, not similarly named forks. None is installed, executed, or incorporated as a benchmark result by this source scanner. Review and pin them before use in a disposable test environment with synthetic credentials and controlled network access.

| Benchmark and primary repository | Research date/context | Useful measurement | Practical limitation |
|---|---|---|---|
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) | NeurIPS **2024** benchmark; [paper](https://arxiv.org/abs/2406.13352) | Indirect prompt-injection attacks and defenses while agents carry out legitimate tool workflows; track security and utility together. | Simulated suites need adaptation to your actual tools and policies. The repository notes its API is evolving. |
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | **2024** research; [paper](https://arxiv.org/abs/2403.02691) | A focused set of malicious tool-result scenarios for tool-integrated agents. | Useful for regression coverage, but a fixed dataset is not an adaptive attacker or a production permission test. |
| [Agent Security Bench (ASB)](https://github.com/agiresearch/ASB) | ICLR **2025**; [paper](https://arxiv.org/abs/2410.02644) | Broader agent attack/defense scenarios and evaluation dimensions. | Requires matching its agent and tool harness to the system under review. Published aggregate scores do not transfer automatically. |
| [MCPSecBench](https://github.com/AIS2Lab/MCPSecBench) | **2025** technical report; [paper](https://arxiv.org/abs/2508.13220) | MCP-specific security scenarios, malicious-server playgrounds, and some automated checks. | Research implementation includes environment/UI-specific workflows and attack scripts. It is not a turnkey audit of arbitrary repositories or a current-spec conformance suite. |

### Suggested evaluation protocol

This is our proposed implementation plan, not a procedure mandated by any one source:

1. Pin code, configurations, model identifiers, gateway behavior, MCP versions, benchmark commit, datasets, attack budget, and test identity permissions.
2. Start with benign workflows and record authorized task completion. This catches a “secure” defense that blocks every useful action.
3. Exercise representative attacker-controlled surfaces: tool descriptions, tool results, retrieved files, web content, memory, and agent handoffs.
4. Use explicit canaries and safe side-effect sinks. Judge security by observed actions, data access, or policy violations where possible, rather than only the model's explanation.
5. Repeat scenarios, add adaptive attacks, and publish per-scenario results with sample sizes and confidence intervals when meaningful. Preserve both successes and failures. This is consistent with [NIST's agent-hijacking evaluation findings](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations).
6. Independently test tokens, object authorization, origins, SSRF, isolation, quotas, cancellation, approval binding, and audit integrity. These deployment properties are not established by prompt-only benchmarks.
7. Gate release on predefined risk tolerances and evidence for critical controls. Re-run after changes to model, prompts, memory, tool definitions, gateway, or permissions.

Suggested metrics include attack success per scenario and attempt budget; unauthorized action rate; sensitive-data leakage rate; benign task completion; false blocking; approval-bypass rate; revocation/cancellation latency; cross-tenant access attempts blocked; and budget/timeout enforcement. Define each numerator, denominator, and adjudication rule before running tests.

## How research is translated into scanner results

Each catalog control has a stable project ID, context sources, required validation method, and a list of applicable automated rules. Rule-to-control links are partial coverage only. Source findings, review gaps, and optional model opinions must remain distinct.

The deterministic layer should preserve file/line evidence, stable rule identifiers, severity, confidence, remediation, and scan limitations. A “no finding” result means the configured patterns did not find an issue in the inspected material. It does not mean a control is implemented. Runtime/manual controls stay in the report as explicit follow-up work.

The optional security judge can reason about ambiguous code patterns and suggest investigation. Its input includes untrusted source material, so it is itself a prompt-injection target. Require a bounded response schema, validate locations, redact likely secrets, record provider/model configuration and errors, and retain the original deterministic findings. Temperature zero does not make a remote model deterministic.

For external LLMs or custom gateways, document exactly what content is sent, how authentication is supplied, transport verification, request timeouts, retry limits, model identifier, and data-handling expectations. A common HTTP adapter can cover many APIs; protocol compatibility, vendor authentication, streaming, and provider-specific options still need explicit adapters and testing. Universal provider support should not be inferred merely from accepting an arbitrary URL.
