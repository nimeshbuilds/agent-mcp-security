# CSA, cloud assurance, and AI development guidance

Research snapshot: **19 September 2026**. These are primary publisher sources. The Invarune controls are independent engineering checks informed by these publications; they are not a reproduction of the CSA catalogs or an assertion of CSA certification.

## Verified source register

| Reference | Verified publication | Why it belongs in an agent and MCP assessment | Boundary |
| --- | --- | --- | --- |
| CSA-AICM | [AI Controls Matrix v1.1](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1), 22 June 2026 | The release identifies **247 controls across 18 domains**, with responsibility across model, orchestration, application, infrastructure, and customer roles. Use its AI-CAIQ companion for supplier evidence. | This review verified the release page, not every workbook control. No exact AICM control-ID crosswalk is claimed. |
| CSA-AICM-MACHINE | [AICM Machine Readable Bundle](https://cloudsecurityalliance.org/artifacts/aicm-machine-readable-bundle-json-yaml-oscal), 4 August 2026 | The publisher offers JSON, YAML, and OSCAL resources for downstream assessment integration. | The release page was verified; the downloadable catalog was not imported. Check its version and reuse terms before integration. |
| CSA-CCM | [Cloud Controls Matrix and CAIQ v4.1](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1), 27 January 2026 | The release describes **207 controls across 17 domains** for the cloud infrastructure hosting agents, gateways, and MCP services. | Cloud assurance complements application testing. A provider questionnaire does not prove that a customer's configured agent is secure. |
| CSA-MAESTRO | [Agentic AI Threat Modeling Framework: MAESTRO](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro), 6 February 2025 | Provides a seven-layer threat-modeling lens, including attacks that cross architectural layers. | A threat-modeling method, not an executable benchmark or certification standard. |
| CSA-AGENT-IAM | [Agentic AI Identity and Access Management: A New Approach](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach), 18 August 2025 | Informs agent identity enrollment, accountable ownership, lifecycle changes, and revocation. | Architectural proposals such as decentralized identifiers are options, not a requirement for every deployment. |
| CSA-SCOPING | [Enhancing the Agentic AI Security Scoping Matrix](https://cloudsecurityalliance.org/blog/2025/12/16/enhancing-the-agentic-ai-security-scoping-matrix-a-multi-dimensional-approach), 16 December 2025 | Separates access capability and risk exposure when selecting controls and review depth. | CSA commentary extends an AWS scoping approach; neither is an empirical security score. |
| CSA-AISMM | [AI Security Maturity Model](https://cloudsecurityalliance.org/artifacts/ai-security-maturity-model), 19 May 2026 | Helps sequence an enterprise AI security program across deployment patterns and operational responsibilities. | Program maturity indicators are not project-level pass/fail evidence. |
| NIST-SSDF-AI | [NIST SP 800-218A](https://csrc.nist.gov/pubs/sp/800/218/a/final), final, 26 July 2024; [publication PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218A.pdf) | Extends SSDF 1.1 for model producers, AI-system producers, and acquirers. Adds model/data development safeguards. | Use alongside SP 800-218; apply training-specific practices where the organization trains or fine-tunes models. |
| NIST-AGENT-IDENTITY-DRAFT | [Software and AI Agent Identity and Authorization concept paper](https://www.nccoe.nist.gov/publications/other/accelerating-adoption-software-and-ai-agent-identity-and-authorization-concept), 5 February 2026 | Identifies open implementation questions for agent identity, authorization, and delegation. | The official page still labels this publication **Draft**. It is not a completed practice guide or mandatory standard. |

Prefer versioned release pages: CSA's general CCM landing page still contains an older control count. Do not mix AICM v1.0's 243 objectives with v1.1's 247, or present CSA lab drafts as adopted controls.

## Engineering alignment with the existing checklist

The relationships below are NimeshBuild's synthesis, not an official crosswalk. Exact third-party control identifiers are omitted unless their source text was reviewed.

| Source family | Relevant Invarune checks | Assessment use |
| --- | --- | --- |
| AICM / AI-CAIQ | GOV-01 through GOV-05; DATA; SUP; OPS; GOV-06 | Determine applicable responsibilities and request evidence for inherited safeguards. |
| CCM / CAIQ | DATA-06; SUP-05; OPS-01, OPS-05, OPS-06 | Review cloud configuration and provider/customer responsibility boundaries. |
| MAESTRO | GOV-02; AGT-04, AGT-05; SUP; TEST | Trace how initial compromise can move between the model, data, framework, infrastructure, evaluation, security, and agent ecosystem. |
| Agentic IAM research | AUTH-01 through AUTH-08; OPS-01, OPS-03; AUTH-09 | Associate an action with an enrolled agent and its sponsor, then verify deactivation propagates. |
| Scoping matrix | GOV-03, GOV-05; AUTH-02; AGT-02; OPS-02 | Assess read/write capabilities and business impact separately from autonomy level. |
| AISMM | GOV-04; OPS-05, OPS-06; TEST | Establish accountable processes, evidence, and a realistic improvement cadence. |

## Additional checks adopted after gap review

The original 62 controls already cover policy enforcement, least privilege, data provenance, dependency integrity, memory poisoning, incident response, and benchmark testing. The canonical catalog includes the following distinct additions:

- **GOV-06 — Assign shared security responsibilities:** identify which organization supplies and demonstrates each safeguard; record provider evidence and customer configuration duties. This adds supplier-boundary accountability beyond assigning an internal control owner.
- **AUTH-09 — Manage agent identity enrollment and retirement:** validate identity issuance, sponsor changes, decommissioning, and stale credential cleanup. Existing delegation checks primarily address individual handoffs.
- **SUP-06 — Separate model development environments:** isolate training, fine-tuning, evaluation, and production access. NIST SP 800-218A **PO.5.1, PO.5.3, PS.1.2, and PS.1.3** informed this check (publication pages 10–12).
- **TEST-09 — Evaluate model-layer attacks where applicable:** assess model tampering/backdoors, extraction, and private-data leakage using a defined attacker capability. This extends agent workflow tests to hosted or customized model artifacts. NIST SP 800-218A **PW.4.4 and PW.8.2** support pre-use testing and retesting (publication pages 15–17); MAESTRO identifies the model-layer attack classes.

These additional controls are manual or dynamic checks. None acquires deterministic scanner coverage merely by being added to the checklist. Training-specific controls may be marked not applicable with an explanation for API-only consumers; vendor evidence may still be required.

## What a defensible assessment retains

Retain the source edition, applicability decision, deployment architecture, responsible organization, evidence owner, test conditions, observed result, and residual risk. For each inherited safeguard, record whether the evidence demonstrates provider operation, customer configuration, or both. Keep untested controls visible. A clean source scan, questionnaire response, or LLM judgment alone does not establish control effectiveness.
