# Invarune mitigation guidance and source rationale

Reviewed: **19 September 2026**. Catalog version: **1.0.0**.

[The mitigation catalog](../ai_security_scan/data/mitigations.json) adds a treatment plan for every one of Invarune's 46 deterministic rules. It contains proposed, source-linked defense layers for each rule. Each rule includes conditional impact, an immediate action, a suggested owner role, relevant Invarune controls, and registered primary sources. Each additional layer explains how it helps, how to test it, and what remains exposed.

These are independently written engineering recommendations. Source mappings explain the technical rationale or the relevant control family; they do not imply that a source publishes these exact recipes, endorses Invarune, or certifies the scanned system. The [source registry](../ai_security_scan/data/sources.json) retains each registered source's version, scope, and limitations.

## How to use the recommendations

The report's finding is evidence of a pattern. The conditional impact describes what could follow **if** the relevant input, credential, listener, or runtime setting is exposed. The immediate action directs the owner to confirm that boundary and correct or contain the problem. A suggested owner is a role to assign, not a claim about who owns the scanned system.

Additional layers start as **suggested and unverified**. Record the deployment, exact policy, owner, test results, and date before treating one as a compensating control. Confirm the denied path as well as the allowed path. A configuration file that mentions authentication, sandboxing, or a gateway does not establish that every relevant operation passes through it.

No recommendation automatically changes a finding's severity, asserts exploitability, or applies a numerical risk discount. If a temporary exception is accepted, document the remaining exposure and its expiry. Monitoring can shorten response time but may only observe a harmful effect after it has happened. A model's favorable opinion is not enforcement evidence.

The scanner does not execute these deployment tests. Run them in an authorized, controlled environment with representative identities and synthetic data. The optional analyst may suggest further context-dependent work, while the deterministic report and these recipes remain available without any model API.

## Source rationale

| Area | Registered primary sources | How the catalog uses them |
| --- | --- | --- |
| Agent authority and trust boundaries | [JOINT-AGENTIC](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services), [OWASP-AGENT-CS](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) | Basis for bounded tool authority, independent execution policy, human oversight of sensitive effects, and separation of untrusted context. |
| Deployment containment | [JOINT-DEPLOY](https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/deploying-ai-systems-securely), [CSA-CCM](https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4-1) | Defense in depth across workload, identity, network, operational monitoring, and response responsibilities. |
| MCP authentication and downstream delegation | [MCP-AUTH](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), [MCP-AUTH-SEC](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations), [MCP-SECURITY](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices) | Resource/audience boundaries, token validation, separation of downstream credentials, and SSRF review. |
| MCP transport and tools | [MCP-HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http), [MCP-TOOLS](https://modelcontextprotocol.io/specification/2026-07-28/server/tools), [MCP-ROOTS](https://modelcontextprotocol.io/specification/2026-07-28/client/roots) | Origin enforcement, limited local listeners, tool input validation, caller authorization, and filesystem boundaries enforced independently of root declarations. |
| Executable input and archives | [TECH-PYTHON-SECURITY](https://docs.python.org/3/library/security_warnings.html), [TECH-PYTHON-TAR](https://docs.python.org/3/library/tarfile.html#extraction-filters), [TECH-NODE-PROCESS](https://nodejs.org/api/child_process.html), [TECH-PYYAML](https://pyyaml.org/wiki/PyYAMLDocumentation) | Language-specific rationale for treating shell/code execution and deserialization as trust boundaries; archive filters require separate resource and filesystem controls. |
| Artifact trust and updates | [NIST-SSDF](https://csrc.nist.gov/pubs/sp/800/218/final), [SLSA-12](https://slsa.dev/spec/v1.2/), [OPENSSF-MODEL-SIGNING](https://openssf.org/blog/2025/04/04/launch-of-model-signing-v1-0-openssf-ai-ml-working-group-secures-the-machine-learning-supply-chain/) | Reviewed artifact identity, integrity, provenance, and continuing maintenance. A stable digest is not evidence that its contents are secure. |
| CI authority | [TECH-GITHUB-ACTIONS](https://docs.github.com/en/actions/reference/security/secure-use) | Full commit references, narrowly scoped job permissions, separation of untrusted workflows, and caution around shared runners and runtime sockets. |
| Safe rendering | [OWASP-OUTPUT2025](https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/) | Treat model and tool output as untrusted at SQL, template, HTML, and other downstream interpretation boundaries. |
| Evidence and continued assurance | [NIST-GENAI](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf), [NCSC-SECURE-AI](https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development), [NIST-HIJACK-EVAL](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations), [CISA-JCDC](https://www.cisa.gov/news-events/alerts/2025/01/14/cisa-releases-jcdc-ai-cybersecurity-collaboration-playbook-and-fact-sheet) | Evidence retention, change review, representative evaluation, and a tested incident-response route. Selected successful exercises do not prove universal resistance. |

## Technical checks and qualifications

The following primary implementation references were also consulted for these recipes. They supplement the 76-source control registry; this change does not present them as additional benchmark coverage or claim that the scanner implements their complete requirements.

- **Container privileges:** [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) distinguishes privileged execution, host namespaces, user identity, capabilities, privilege escalation, and syscall controls. Consequently, `USER nonroot` alone is not treated as proof of containment. A source Dockerfile must be reconciled with its final build stage and effective deployment.
- **SQL:** [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) supports bound values, explicit choices for identifiers that cannot be bound as values, and least-privileged database access. Application authorization and database privileges remain different enforcement points.
- **HTML and browser rendering:** [OWASP Cross Site Scripting Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) distinguishes safe text sinks, context-specific escaping, sanitization, and supplementary browser controls. Authentication does not neutralize an XSS payload. The catalog therefore pairs safe rendering with isolation of intentionally active previews, rather than claiming that login prevents script execution.
- **TLS:** [Requests advanced usage](https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification) explains certificate verification and custom CA configuration. The recommendation is to validate the expected server, including private gateways, and examine all termination boundaries. An egress allowlist cannot substitute for server authentication.
- **Model deserialization:** [PyTorch `torch.load`](https://docs.pytorch.org/docs/stable/generated/torch.load) warns about untrusted inputs. Restricted loading, artifact provenance, isolated conversion, resource bounds, and a maintained runtime address different failure paths. [PyTorch's security policy](https://github.com/pytorch/pytorch/security/policy) also makes clear that subsequent use of loaded objects requires validation. The catalog does not certify a checkpoint merely because `weights_only=True` is set.
- **Archive extraction:** [Python's extraction-filter guidance](https://docs.python.org/3/library/tarfile.html#extraction-filters) says filters do not cover every dangerous feature or denial of service. Recommendations include member validation, a fresh destination, and external resource limits; the deployment's supported filter behavior must be checked.

Other qualifications are attached directly to the relevant rules: wildcard CORS is not proof of anonymous access; local stdio may use an operating-system trust boundary; a security-named random value may actually be a nonsecurity identifier; an exact dependency version can still be vulnerable; a removed image file can remain in earlier distributed layers; a read-only socket mount does not make the socket's API read-only; rotation cannot undo prior disclosure.

## Data contract

The UTF-8 JSON catalog has `schema_version`, `catalog_version`, `reviewed_at`, `interpretation`, and `rules` fields. The `rules` array contains exactly one entry per deterministic rule ID.

Each entry contains:

- `rule_id`: stable existing deterministic rule ID.
- `plausible_impact`: conditional impact, without inventing confirmed exploitability.
- `immediate_action`: the first confirmation, containment, or remediation step.
- `suggested_owner`: a role for the consuming organization to assign.
- `control_ids`: existing Invarune controls associated with this rule.
- `source_ids`: registered source IDs supporting the rule, its control family, or the recommended layers.
- `defense_layers`: two to three recommendations with `id`, `title`, `how_it_helps`, `verification`, `residual_limit`, `control_ids`, and `source_ids`.

Layer IDs are reused when the same recipe applies to several rules. This allows a renderer to group repeated work while preserving the original rule-to-layer relationship. Consumers should retain the conditional impact and residual limitation when displaying a recommendation; a layer title by itself is not a complete risk treatment.
