"""Executable scan inventory and honest coverage contracts, without model calls.

Rule metadata is deliberately explicit: adding a detector without documenting its
predicate and blind spots fails inventory generation instead of claiming coverage.
The catalog provides control/source relationships; this module adds execution scope.
"""
import copy
import re

from .catalog import describe_catalog
from .rules import RULESET_VERSION


# profiles, algorithm, recognized predicate, principal limit. These are descriptions
# of implementation support, not new detectors or implied compliance requirements.
_DETAILS = {
    "AI001": ("python_ast", "AST call resolution and bounded local constant/alias tracking", "Nonliteral eval/exec calls, including recognized builtins aliases and constant getattr names.", "Dynamic imports, computed attributes and cross-function input flow are not completely resolved; a dynamic argument alone does not prove attacker control."),
    "AI002": ("python_ast", "AST call/argument matching and bounded local tracking", "Dynamic subprocess shell=True, asyncio.create_subprocess_shell, or an explicit recognized shell executable with its command option.", "Does not establish command reachability, input sanitization across functions, executable trust, or sandbox effectiveness."),
    "AI003": ("python_ast", "AST resolved-API matching and constant exclusion", "Dynamic os.system/os.popen arguments through recognized imports and aliases.", "A dangerous shell boundary is identified, not complete upstream taint or production exploitability."),
    "AI004": ("python_ast", "AST loader allowlist", "Recognized YAML load/load_all/unsafe_load calls without an explicitly recognized SafeLoader, CSafeLoader, BaseLoader or CBaseLoader.", "User-defined wrapper safety and every third-party YAML API are outside the allowlist; the actual input's trust is not established."),
    "AI005": ("python_ast", "AST executable-deserializer API matching", "pickle/dill/cloudpickle load/loads and joblib.load calls.", "Authenticated trusted artifacts may be intentional; this does not inspect serialized objects or prove attacker control."),
    "AI006": ("python_ast,javascript_lexical,json_structured,configuration_lexical", "Typed literal and recognized network/configuration API checks", "Explicit TLS verification bypass in supported Python HTTP clients/SSL, JavaScript rejectUnauthorized, NODE_TLS_REJECT_UNAUTHORIZED and supported configuration fields.", "Does not establish effective CA trust, hostname validation, gateway behavior or an override supplied at deployment."),
    "AI007": ("python_ast,javascript_lexical,json_structured", "Literal origin-list matching", "Wildcard origins in supported Python CORS calls, JavaScript fields and structured configuration.", "Does not infer authentication, browser reachability, credential mode or framework-specific CORS response behavior."),
    "AI008": ("python_ast,javascript_lexical,json_structured,configuration_lexical", "Literal listener/bind matching", "Wildcard host bindings such as 0.0.0.0 or :: in supported calls and configuration keys.", "Binding is an exposure review signal; ingress restrictions, authentication and actual remote reachability require deployment evidence."),
    "AI009": ("python_ast,json_structured,configuration_lexical", "Explicit debug-setting matching", "Recognized debug=True calls/assignments and supported debug/FLASK_DEBUG configuration values.", "A setting may be development-only; environment, framework defaults and production overrides are not proven."),
    "AI010": ("python_ast,json_structured,generic_text", "Credential-name/value heuristics and bounded token patterns", "Nonplaceholder credential-named literals, supported token formats and literal bearer credentials; explicit environment-variable-name fields are excluded.", "May miss unusual secret formats and may flag realistic test data; never validates credentials remotely or proves they are live."),
    "AI011": ("generic_text", "PEM marker plus plausible encoded-material check", "Private-key PEM headers accompanied by plausible encoded key data.", "Does not establish cryptographic validity, key use or test-versus-production ownership."),
    "AI012": ("javascript_lexical", "Tokenized child-process imports/calls with bounded alias handling", "Dynamic Node child-process shell execution APIs in supported import and call forms.", "Not a full JavaScript/TypeScript parser or interprocedural taint engine; computed wrappers and dynamic imports may be missed."),
    "AI013": ("javascript_lexical", "Balanced token call matching and literal exclusion", "Dynamic JavaScript eval or Function constructor arguments.", "Wrapper calls, runtime bindings, reachability and input provenance may remain unknown."),
    "AI014": ("python_ast,javascript_lexical", "Registered input boundaries, call-site propagation and exact literal constraints", "Recognized HTTP sinks with external influence, including supported Python FastMCP/LangChain tool parameters, conventional unbound mcp/server.tool registration forms, local function aliases and argument/return flow. Literal JavaScript server/mcp.registerTool callbacks seed simple inputs and direct-return named/arrow wrappers propagate to fetch/axios. Exact Python string equality or literal tuple/set guards constrain destination selection.", "Python calls are bounded to depth 8 and 512 expansions; splats, recursion, indirect coroutine/generator execution and global/nonlocal side effects leave gaps while retaining findings. Unknown decorators, methods, cross-file flow and dynamic dispatch remain unresolved. JS requires narrow literal registration and direct-return wrappers. Conventional receiver names indicate a declared boundary, not verified SDK identity. Fixed destinations do not prove DNS/redirect safety."),
    "AI015": ("python_ast,javascript_lexical", "Registered input boundaries and bounded filesystem argument propagation", "Supported filesystem operations receiving external data through Python tool parameters/local calls or literal JavaScript registerTool callbacks/direct-return wrappers with recognized filesystem imports. Python literal finite string maps can constrain a selected path; aliases, mutations and unknown-call escapes invalidate that local proof.", "Canonicalization, symlink races, unknown decorators/methods, cross-file validation and effective confinement need review. A finite map does not prove tenant authorization. Named callback references, complex JS callbacks/wrappers and unmodeled dispatch remain outside this bounded analysis; unsupported call binding and exhausted budgets leave gaps."),
    "AI016": ("python_ast", "Resolved AST API matching", "tempfile.mktemp usage, which returns a name without atomically creating the file.", "Does not prove a concurrent attacker, downstream file permissions or whether the path is subsequently used."),
    "AI017": ("python_ast,javascript_lexical", "JWT decode and literal algorithm/verification checks", "Recognized Python JWT decode verification bypasses and JavaScript algorithms containing none.", "Does not establish a complete issuer/audience/scope policy or that unverified claims reach authorization."),
    "AI018": ("json_structured", "Structured MCP command/argument package-version check", "MCP launch configurations using supported ephemeral package runners without an exact package version.", "Does not resolve the registry, verify provenance or inspect transitive dependencies; non-JSON launch formats may not receive this predicate."),
    "AI019": ("configuration_lexical,generic_text", "Bounded shell token/command-substitution and pipeline patterns", "curl/wget output directly piped to a shell or used as shell -c command text in supported shell/configuration contexts.", "Not a complete shell interpreter; complex expansion, wrappers, runtime fetch destinations and remote artifact contents are not resolved."),
    "AI020": ("configuration_lexical", "GitHub workflow uses-reference pattern and full-SHA check", "Remote action uses references lacking a reviewed full commit SHA in recognized workflow files.", "Pinning alone does not establish the action is safe, signed, reviewed or minimally privileged."),
    "AI021": ("configuration_lexical", "Dockerfile final-stage user tracking plus built-image user inspection", "Explicit/inherited literal root USER in the default final Dockerfile stage; built-image configured user/default UID 0 is separately checked.", "External Dockerfile base defaults, variables and selected build targets may be unresolved; deployed user overrides require runtime configuration."),
    "AI022": ("json_structured,configuration_lexical", "Exact privilege-setting predicates", "Explicit privileged or allowPrivilegeEscalation settings in supported configuration.", "Not a complete container capability or admission-policy audit; missing settings are not treated as proof of isolation."),
    "AI023": ("json_structured,configuration_lexical", "Known runtime-socket path matching", "Recognized Docker/containerd runtime socket paths in supported configuration.", "Presence does not prove the mount is active or writable; read-only filesystem mounts do not necessarily restrict socket API operations."),
    "AI024": ("json_structured,configuration_lexical", "Container reference parsing and digest-presence check", "Mutable Dockerfile FROM or supported deployment image references rather than content digests.", "No registry lookup, signature verification, CVE database or guarantee of safe pinned content."),
    "AI025": ("json_structured,configuration_lexical", "Direct manifest dependency version-shape checks", "Recognized package.json dependency declarations and requirements-style entries permitting version movement; a local '.' self-install is excluded.", "Lockfile inventory does not resolve the effective build or transitive graph; this is not a CVE, dependency-confusion or integrity assessment."),
    "AI026": ("python_ast,javascript_lexical,json_structured,configuration_lexical", "Explicit authentication-disable field matching", "Supported authentication fields with the actual false value in code/configuration, including bounded supported YAML aliases.", "Local stdio may rely on the OS boundary; absent authentication code or custom middleware is not automatically classified."),
    "AI027": ("python_ast,javascript_lexical,json_structured,configuration_lexical", "Literal tool/resource wildcard matching", "Supported tool, permission and resource allowlists granting '*', including bounded supported YAML aliases.", "Does not enumerate effective IAM permissions or validate argument/resource policy and approval at runtime."),
    "AI028": ("python_ast,javascript_lexical,json_structured,configuration_lexical", "Explicit token-forwarding field matching", "Supported token-passthrough/forwarding settings explicitly enabled.", "Does not trace actual downstream token audiences, exchange flows or proxy behavior."),
    "AI029": ("json_structured", "Structured MCP URL scheme and loopback classification", "Nonloopback plaintext HTTP endpoints in recognized MCP configuration.", "Transport encryption outside the application, DNS trust and deployment-specific tunnels are unverified; other endpoint formats may be missed."),
    "AI030": ("javascript_lexical,json_structured", "Explicit browser-SDK opt-in field matching", "dangerouslyAllowBrowser enabled in supported JavaScript/JSON fields.", "Does not establish that a privileged long-lived credential actually reaches a browser bundle."),
    "AI031": ("python_ast,javascript_lexical,json_structured,configuration_lexical,generic_text", "Known bypass flags and typed unrestricted-approval settings", "Supported unrestricted agent approval/sandbox configuration and recognized dangerous CLI flags in applicable contexts.", "Cannot determine effective process permissions, external approval enforcement or whether the command actually runs."),
    "AI032": ("python_ast,javascript_lexical", "Privileged message-role plus local external-input matching", "Supported system/developer message objects with obviously external content.", "Does not detect every prompt injection, prove a model follows it or trace a prompt assembled across functions/services."),
    "AI033": ("python_ast,javascript_lexical", "Logging sink and credential-name matching", "Supported logging calls directly referencing credential-named variables, attributes or fields.", "Variable names can be misleading; sanitizers, custom loggers, downstream formatters and unusual secret names may be missed."),
    "AI034": ("generic_text", "URL query credential-name/value patterns", "URLs embedding a nonplaceholder credential-like query value.", "Cannot establish live credential validity, deployed URL use or all custom query parameter names."),
    "AI035": ("python_ast", "Explicit model-loader safety opt-out checks", "torch.load(weights_only=False) and recognized load_model(..., safe_mode=False).", "Does not inspect model bytes, evaluate architecture behavior or infer unsafe defaults across every framework/version."),
    "AI036": ("python_ast,javascript_lexical", "SQL execution sink plus interpolation/concatenation tracking", "Supported database execution calls with interpolated or concatenated query text.", "Dynamic SQL identifiers may be intentionally allowlisted; cross-function parameterization and database-specific wrappers need review."),
    "AI037": ("python_ast", "Tar object/API tracking and explicit extraction-filter check", "Recognized tar extract/extractall calls without filter='data' or selecting a fully trusted filter.", "Runtime-version defaults, custom safe filters and member-validation wrappers may need review; this does not audit every archive format."),
    "AI038": ("python_ast", "Security-named assignment plus random API matching", "Credential-, nonce-, token- or secret-named assignments using the general-purpose random module.", "Name heuristics do not prove security use or entropy requirements; custom weak generators and JS randomness are not comprehensively analyzed."),
    "AI039": ("python_ast", "Recognized template-source sink and constant exclusion", "Dynamic Flask render_template_string or Jinja2 Template source.", "Template contents, sandbox configuration, wrapper calls and actual attacker control require context."),
    "AI040": ("javascript_lexical", "Raw-HTML sink and dynamic-value matching", "Supported innerHTML, insertAdjacentHTML and dangerouslySetInnerHTML dynamic assignments.", "Does not validate a sanitizer, framework escaping, browser CSP or DOM behavior at runtime."),
    "AI041": ("python_ast,javascript_lexical,json_structured,configuration_lexical", "Inspector environment/configuration nonempty-value semantics", "Recognized DANGEROUSLY_OMIT_AUTH assignments with a nonempty value; strings 'false' and '0' still disable the safeguard.", "Does not determine Inspector reachability or runtime environment overrides; an empty string alone is not treated as enabled."),
    "AI042": ("json_structured,configuration_lexical", "Explicit host namespace setting checks", "hostPID/hostNetwork enabled or supported pid/network_mode values set to host.", "Does not inventory all namespace, seccomp, capability or kernel-isolation behavior in a running deployment."),
    "AI043": ("instruction_text,tool_metadata", "Bounded directive predicates and conflicting authority claims", "Recognized instructions and literal tool/schema descriptions asking to override trusted instructions; selected Spanish/French/German override forms; paired authority invalidation/replacement; and a supported conditional conflict resolved in favor of the current tool or skill.", "Limited lexical language forms are not translation coverage. Other languages, paraphrases, reordered authority claims, unsupported encodings and dynamic descriptions can evade detection. Evidence does not prove intent or successful injection."),
    "AI044": ("instruction_text,tool_metadata", "Sensitive-object, transfer-action, local negation and explicit-destination predicates", "Recognized English transfer instructions naming credentials, sensitive files, a credential store or login/password vault; nearest-operative-read to pronoun/file/attachment references; and include/append bundle forms with an explicit URL/email destination in the bounded segment.", "Local explicit transfer negation is respected where recognized. A later public-object retrieval does not inherit an earlier sensitive referent. Implicit destinations, multi-file staging and natural-language ambiguity remain unresolved; actual access, authorization, transfer and destination ownership are unverified."),
    "AI045": ("instruction_text,tool_metadata", "Action/concealment, audit-erasure and approval-bypass predicates", "Recognized instructions pairing an action with concealment from the user, explicitly erasing audit evidence to prevent user inspection, or directing approval/sandbox bypass.", "Cannot establish deceptive intent from all natural-language variations; legitimate quoted security examples are excluded only where the bounded parser recognizes them."),
    "AI046": ("tool_metadata,python_ast", "Read-only annotation consistency with description or direct write witness", "Literal readOnlyHint=true conflicting with a destructive instruction in the same description, or a top-level Python @tool handler containing an unambiguously resolved os/shutil write call or inline pathlib.Path write operation. Literal annotation dictionaries and ToolAnnotations calls are recognized.", "Python effects are bounded to 20000 inspected handler AST nodes; nested/class bindings leave gaps. Shadowed/conditional imports, uncalled nested bodies and recognized dead branches are excluded. Helper calls, variable-held Path objects, arbitrary writes, runtime registration, authorization and actual branch execution are not proven."),
    "AI047": ("python_ast", "Resolved chmod API plus bounded integer/permission-bit evaluation", "Recognized os.chmod/fchmod/lchmod and pathlib chmod/lchmod calls whose literal, propagated integer, stat flag or bounded bitwise mode explicitly contains the other-write bit (0o002).", "Only explicit supported chmod calls are checked. Owner-only/group-only writes are not this rule. Platform behavior, ACLs, ownership, umask, reachability and live permissions remain unverified; a sticky bit does not erase the other-write signal."),
}

_IMAGE_EXTRA = {
    "AI006": ["runtime_configuration"],
    "AI010": ["runtime_configuration", "retained_layer", "build_history"],
    "AI011": ["runtime_configuration", "retained_layer", "build_history"],
    "AI019": ["build_history"],
    "AI021": ["runtime_configuration"],
    "AI031": ["runtime_configuration", "build_history"],
    "AI034": ["runtime_configuration", "retained_layer", "build_history"],
    "AI041": ["runtime_configuration"],
}

_ALGORITHM_LIMITS = {
    "python_ast": "Bounded local aliases/constants plus selected same-file argument/return propagation and exact literal branch constraints; no whole-program proof. Unsupported call binding or exhausted flow bounds are explicit gaps.",
    "javascript_lexical": "Balanced tokens, selected imports/calls/configuration and bounded direct-return wrapper summaries; not a complete JS/TS parser, type checker or flow graph.",
    "json_structured": "Parsed JSON/JSONC with selected typed-field predicates; dynamic values and referenced configuration are not resolved.",
    "configuration_lexical": "Selected literal configuration and shell patterns; limited YAML scalar/alias support, not full template or YAML semantics.",
    "generic_text": "Applicable generic patterns only; supported file selection is not full language-specific analysis.",
    "instruction_text": "Supplementary detector path for recognized agent/skill documents; bounded English predicates and selected Spanish/French/German override forms, not general translation or model execution. The manifest retains its ordinary source profile.",
    "tool_metadata": "Supported literal tool descriptions and recognized JSON input-schema description subtrees; bounded Python read-only/write witnesses. Dynamic descriptions, helpers and runtime output need separate evidence. The manifest retains its ordinary source profile.",
}


def _control_review(control):
    validation = control["validation"]
    required = {"dynamic": "needs_runtime_validation", "manual": "needs_human_review"}.get(validation)
    return {
        "enabled_by": "--judge-config or --judge-cli with --judge-mode full (the default when enabled)",
        "review_plan": "Review every active selected acceptance check against bounded submitted source excerpts, including zero-hit and inconclusive checks. By default the model may request validated file-ID/line ranges from an already captured manifest snapshot, then submit a risk hypothesis, boundary, counterevidence and conclusion limits. Set --analyst-investigation-rounds 0 for seed-excerpt review only.",
        "checks": copy.deepcopy(control["checks"]),
        "validation_method": validation,
        "code_support_normalized_to": required or "supported_by_code (advisory only)",
        "cannot_establish": "Runtime effectiveness, complete call paths, real-world malicious intent, compliance, or a validated pass from model reasoning alone.",
    }


def _scan(rule, controls):
    key = rule["id"]
    if key not in _DETAILS:
        raise ValueError("Missing executable scan coverage metadata for " + key)
    profiles, algorithm, predicate, limit = _DETAILS[key]
    mapped = [item for item in controls if key in item["automated_rule_ids"]]
    sources = {}
    for control in mapped:
        for source in control["sources"]:
            sources.setdefault((source["id"], source["relationship"]), copy.deepcopy(source))
    for source in rule["technical_references"]:
        sources.setdefault((source.get("id", source["url"]), source["relationship"]), copy.deepcopy(source))
    return {
        "id": key,
        "title": rule["title"],
        "severity": rule["severity"],
        "category": rule["category"],
        "what_it_detects": predicate,
        "description": rule["description"],
        "why_it_matters": rule.get("implementation_guidance", {}).get("agent_mcp_relevance", rule["description"]),
        "deterministic": {"status": "implemented_pattern_check", "algorithm": algorithm,
                          "analysis_profiles": profiles.split(","), "limits": limit},
        "applicable_surfaces": ["agent", "mcp", "skill", "image"],
        "surface_meaning": "Runs on matching supported content wherever packaged: agent/MCP implementation, skill instructions or bundled scripts, and image files. This is not a claim that every rule applies to every target or file type.",
        "image_contexts": ["final_filesystem"] + list(_IMAGE_EXTRA.get(key, [])),
        "controls": [{"id": item["id"], "title": item["title"], "relationship": "partial_control_mapping"} for item in mapped],
        "optional_ai_review": {
            "finding_triage": "Can explain applicability and suggest follow-up evidence for detected patterns; cannot remove or downgrade a deterministic finding.",
            "full_control_review": [_control_review(item) | {"control_id": item["id"]} for item in mapped],
            "broader_review": "Full mode reviews selected active controls even with zero rule matches. Optional bounded investigation can request additional ranges from the captured, hash-verified manifest snapshot and seek counterevidence before proposing a gap. It cannot execute target tools or validate runtime behavior.",
            "limits": "Evidence collection, excerpts, request/context limits and model mistakes can leave a check inconclusive. Exact citation validation verifies quoted text, not correctness of interpretation.",
        },
        "remediation": rule["remediation"],
        "implementation_guidance": copy.deepcopy(rule.get("implementation_guidance", {})),
        "sources": list(sources.values()),
        "commands": {"explain": "invscan --explain-scan " + key,
                     "select": "invscan TARGET --scans " + key,
                     "report": "invscan TARGET --scans " + key + " --output ./scan-report"},
    }


def describe_scans(scan_id=None):
    """Return an isolated JSON-serializable inventory or one rule/control explanation."""
    rule_catalog = describe_catalog("rules")
    control_catalog = describe_catalog("controls")
    controls = control_catalog["controls"]
    scans = [_scan(rule, controls) for rule in rule_catalog["rules"]]
    plans = [{**copy.deepcopy(control), "optional_ai_review": _control_review(control),
              "scan_selection": {"id": control["id"], "deterministic_rule_ids": list(control["automated_rule_ids"]),
                                 "command": "invscan TARGET --scans " + control["id"],
                                 "empty_mapping_meaning": "No mapped deterministic detector. Retain an explicit review requirement; do not substitute all detectors or infer a pass."}}
             for control in controls]
    result = {
        "schema_version": "1.0", "mode": "deterministic_scan_inventory", "status": "ok",
        "ruleset_version": RULESET_VERSION,
        "counts": {"scans": len(scans), "controls": len(plans),
                   "acceptance_checks": sum(len(item["checks"]) for item in controls),
                   "partially_mapped_controls": sum(bool(item["automated_rule_ids"]) for item in controls)},
        "execution": "Offline bundled metadata lookup. No target scan, model, credential, subprocess or network access.",
        "selection": "--scans accepts rule IDs and control IDs, comma-separated or repeated. Rule IDs select deterministic predicates and mapped control review; control IDs select their mapped rules and acceptance-check review. Other rules are outside the requested result scope. File parsing and coverage safety checks remain active.",
        "algorithm_limits": copy.deepcopy(_ALGORITHM_LIMITS),
        "assurance": "An implemented pattern check is partial coverage, not proof of security, maliciousness, exploitability, or any benchmark/control pass. Source links are Invarune-authored relationships, not an official clause-level compliance crosswalk.",
    }
    if scan_id is None:
        result.update(scans=scans, controls=plans)
        return result
    if not isinstance(scan_id, str) or len(scan_id) > 80 or not re.fullmatch(r"(?:AI[0-9]{3}|[A-Z]+-[0-9]{2})", scan_id.strip().upper()):
        raise ValueError("Scan ID must be a known rule such as AI002 or control such as AUTH-01.")
    identifier = scan_id.strip().upper()
    for key, items in (("scan", scans), ("control", plans)):
        selected = next((item for item in items if item["id"] == identifier), None)
        if selected is not None:
            result[key] = selected
            return result
    raise ValueError("Unknown scan ID: " + identifier + ". Use invscan --list-scans.")


def render_scans(data):
    """Human-readable inventory; exact per-rule explanations stay available offline."""
    counts = data["counts"]
    lines = ["Invarune scan coverage", "", "%d deterministic rules; %d controls; %d acceptance checks." %
             (counts["scans"], counts["controls"], counts["acceptance_checks"]), data["assurance"], ""]
    if "scan" in data:
        item = data["scan"]
        lines.extend((item["id"] + " — " + item["title"], "Severity: " + item["severity"],
                      "Detects: " + item["what_it_detects"], "Why it matters: " + item["why_it_matters"],
                      "Algorithm: " + item["deterministic"]["algorithm"],
                      "Profiles: " + ", ".join(item["deterministic"]["analysis_profiles"]),
                      "Limits: " + item["deterministic"]["limits"],
                      "Image evidence: " + ", ".join(item["image_contexts"]),
                      "Mapped controls: " + (", ".join(control["id"] for control in item["controls"]) or "none"),
                      "Optional AI: " + item["optional_ai_review"]["broader_review"],
                      "AI limit: " + item["optional_ai_review"]["limits"],
                      "Fix: " + item["remediation"], "", "Sources:"))
        for source in item["sources"]:
            lines.append("  " + str(source.get("id") or "Technical reference") + " — " + str(source.get("organization") or "Primary documentation") +
                         " — " + source["relationship"] + "\n    " + source["url"])
        lines += ["", "Try: " + item["commands"]["select"]]
    elif "control" in data:
        item = data["control"]
        lines += [item["id"] + " — " + item["title"], item["what_it_is"], "Why: " + item["why_it_matters"],
                  "Validation: " + item["validation"], "Deterministic rules: " + (", ".join(item["automated_rule_ids"]) or "none"),
                  item["deterministic_coverage"]["meaning"], "Optional AI: " + item["optional_ai_review"]["review_plan"],
                  "Code support becomes: " + item["optional_ai_review"]["code_support_normalized_to"], "Acceptance checks:"]
        lines += ["  " + check["id"] + " " + check["text"] for check in item["checks"]]
        lines += ["Sources:"]
        lines += ["  " + source["id"] + " — " + source["organization"] + " — " + source["relationship"] + "\n    " + source["url"] for source in item["sources"]]
        lines += ["", "Try: " + item["scan_selection"]["command"]]
    else:
        lines += ["Deterministic scan IDs (use --explain-scan ID for predicate, fix and sources):"]
        for item in data["scans"]:
            lines.append("  " + item["id"] + " [" + item["severity"] + "] " + item["title"])
            lines.append("    " + item["what_it_detects"])
        lines += ["", "Control review plans (partial mapped rules; all active checks can receive optional AI review):"]
        for item in data["controls"]:
            lines.append("  " + item["id"] + " " + item["title"])
            lines.append("    " + item["validation"] + "; rules: " + (", ".join(item["automated_rule_ids"]) or "none; human/runtime evidence required"))
        lines += ["", data["selection"], "", "Examples:", "  invscan TARGET", "  invscan TARGET --scans AI002,AI043",
                  "  invscan TARGET --scans AUTH-01 --judge-cli claude", "  invscan --explain-scan AI043", "  invscan --list-scans --catalog-format json"]
    return "\n".join(lines) + "\n"
