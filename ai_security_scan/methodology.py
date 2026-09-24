"""Deterministic explanations of scan methods and their assurance boundaries."""
from .rules import RULES


AREAS = (
    ("Execution and data flow",
     "Python AST checks propagate selected registered-tool inputs and same-file arguments/returns, retain aliases and exact literal constraints, and check selected execution/file/network sinks. JavaScript tokens support narrow registerTool callbacks and direct-return named/arrow wrappers. Explicit world-writable chmod modes are checked.",
     "A model can form a trust-boundary hypothesis, request bounded captured source ranges to inspect callers or guards, seek counterevidence and explain what the supplied code still cannot establish.",
     "Cross-file flows, unknown decorators/methods, complex JavaScript wrappers, dynamic imports, reflection, generated code and runtime values can hide a risk. Recognized resource/binding failures remain gaps. A dangerous API can be intentional and correctly constrained.",
     "Exercise actual entry points with authorized negative tests; verify input provenance, execution privileges and sandbox boundaries."),
    ("MCP identity, authorization and tools",
     "Selected configuration/code signals flag insecure transport, explicit authentication bypass, token passthrough, broad tool grants and unpinned server launch packages.",
     "A model can review supplied authorization logic, tool descriptions and trust-boundary evidence for missing assumptions or inconsistent checks.",
     "Configuration may differ from deployment. External gateways, identity providers, token audience checks and tenant boundaries may be absent from retrieved evidence.",
     "Test expired/wrong-audience tokens, cross-tenant access, per-tool authorization, consent binding and the deployed MCP transport."),
    ("Prompt injection, retrieval and memory",
     "Selected patterns identify external content placed in privileged model messages and explicit approval/sandbox bypass. This is not an attack simulation.",
     "A model can reason about untrusted-content handling, persistent memory, tool-output influence and missing approval boundaries in the supplied excerpts.",
     "Adaptive attacks, multi-turn interactions and tool chains depend on runtime behavior. Retrieval can omit the relevant code; a model can overlook an attack or be influenced by hostile evidence.",
     "Run isolated adversarial agent/MCP evaluations with attack-success and legitimate-task measurements, plus human review of consequential actions."),
    ("Secrets and data handling",
     "Selected literal credentials, plausible private-key material, credential-bearing URLs, logging patterns and browser credential exposure are flagged and redacted best-effort.",
     "A model can identify sensitive data flows and retention concerns when the supplied evidence explains their context.",
     "Encoded, split or runtime-fetched credentials can be missed; labels/test values can resemble secrets. Neither layer establishes whether a credential is live or redaction is complete.",
     "Verify secret stores, credential rotation, logging/retention policy, egress destinations and actual data-access permissions."),
    ("Skills and malicious-tool indicators",
     "Bounded skill/tool/schema descriptions are checked for instruction hijacking, sensitive-data transfer, covert or approval-bypassing actions. Selected Spanish/French/German overrides and paired authority claims supplement English predicates. Python read-only tool annotations are compared with recognized direct write witnesses.",
     "A model can review intent, indirect social engineering, skill reference context and tool behavior visible in retrieved evidence, including cases where syntax or supported patterns are inconclusive.",
     "A pattern is risk evidence, not proof of malicious authorship. Obfuscation, remote references, external packages, omitted context and runtime behavior can evade either layer.",
     "Inspect publisher provenance and the exact installed skill/tool; test consequential actions in an authorized isolated environment and verify effective permissions."),
    ("Built images and supply chain",
     "Image archives are reconstructed without starting containers; supported packaged source, metadata, retained credentials, stored permissions and package inventories are inspected.",
     "A model can interpret supplied image/source evidence, flag missing deployment context and propose verification work.",
     "Compiled logic, live deployment overrides, signature trust and dependency CVEs are not assessed. Package inventory and archive consistency do not establish safety or publisher identity.",
     "Use vulnerability/advisory analysis, provenance/signature verification and deployment testing alongside the static image assessment."),
    ("Operations and control effectiveness",
     "The catalog retains governance, monitoring, recovery, approval and isolation checks even where no deterministic rule maps to them.",
     "Full review queues every active acceptance check and can identify evidence gaps or propose runtime/human validation; it can cite exact submitted source text.",
     "A valid citation proves that a quote exists, not that the model's interpretation is correct. Policies, external services, incident procedures and production outcomes may be unavailable.",
     "Record owner-reviewed evidence, operational exercises and runtime results. A written justification remains an accepted exception, never an automatically validated pass."),
)


def build_methodology(report):
    from .scanner import load_controls
    controls = report.get("controls", [])
    selected_ids = set(report.get("configuration", {}).get("selected_rule_ids", [rule["id"] for rule in RULES]))
    selected_rules = [rule for rule in RULES if rule["id"] in selected_ids]
    mapped = sum(bool(c.get("automated_rule_ids")) for c in controls)
    return {
        "schema_version": "1.0",
        "purpose": "Find repeatable security patterns and organize the remaining assurance work for agents, MCP servers, skills and built images.",
        "catalog": {"rules": len(selected_rules), "controls": len(controls),
                    "available_rules": len(RULES), "available_controls": len(load_controls()),
                    "checks": sum(len(c.get("checks", [])) for c in controls),
                    "statically_mapped_controls": mapped, "controls_without_static_mapping": len(controls) - mapped},
        "interpretation": "Mapping counts describe available checks, not percent secure, detection accuracy or validated control effectiveness.",
        "workflow": [
            "Choose an explicit code/image target and scan configuration; no target code or container is started.",
            "Collect bounded deterministic evidence, record hashes, rule matches, exclusions and coverage gaps.",
            "When explicitly enabled, select bounded evidence for finding triage and every active control check; findings-only mode narrows this step.",
            "Run advisory requests under fixed limits. The default full analyst may request only validated file-ID/line ranges from an already captured, hash-verified snapshot; no arbitrary file reads or target tools execute. Validate response schemas, known identifiers and exact quotes.",
            "Retain unsupported claims and runtime/human requirements; record user review decisions separately from model advice.",
            "Import an explicitly selected reviewed report with a fresh target scan; revalidate evidence bindings, retain stale decisions for audit and recompute the result.",
        ],
        "areas": [{"area": area, "deterministic": deterministic, "optional_review": optional,
                   "can_miss_or_misclassify": misses, "runtime_or_human_validation": validation}
                  for area, deterministic, optional, misses, validation in AREAS],
        "rule_inventory": [{"id": rule["id"], "title": rule["title"], "severity": rule["severity"], "category": rule["category"]}
                           for rule in sorted(selected_rules, key=lambda value: value["id"])],
    }
