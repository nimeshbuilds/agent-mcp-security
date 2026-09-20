"""Offline, deterministic exploration of the existing security control catalog.

This module loads only bundled catalogs. It never scans a user target, contacts
an endpoint, runs a model, or treats source alignment as a compliance crosswalk.
"""
import copy
from functools import lru_cache
import json
from pathlib import Path
import re
import unicodedata

from .rules import RULES, RULESET_VERSION


MAX_QUERY_CHARS = 1000
SEARCH_LIMIT = 8
_TOPICS = (
    ("governance", "Governance", ("governance", "risk management", "inventory")),
    ("identity-authorization", "Identity and authorization", ("identity and authorization", "identity", "iam")),
    ("mcp-protocol-tools", "MCP protocol and tools", ("mcp", "model context protocol", "mcp tools", "mcp security")),
    ("agent-behavior-context", "Agent behavior and context", ("agents", "ai agents", "agent behavior", "agent context")),
    ("execution-application-security", "Execution and application security", ("application security", "execution security", "injection")),
    ("data-privacy", "Data and privacy", ("data security", "data privacy", "privacy")),
    ("supply-chain", "Supply chain", ("supply chain", "dependencies", "software supply chain")),
    ("operations-resilience", "Operations and resilience", ("operations", "resilience", "operational security")),
    ("security-validation", "Security validation", ("testing", "security testing", "validation")),
)
_ORGANIZATIONS = (
    ("csa", "cloud security alliance"),
    ("nsa", "national security agency"),
    ("cisa", "cybersecurity and infrastructure security agency"),
    ("cis", "center for internet security"),
    ("nist", "national institute of standards and technology"),
    ("mitre", "mitre"),
    ("owasp", "open worldwide application security project"),
    ("openssf", "open source security foundation"),
    ("mcp", "model context protocol"),
)
_STOP_WORDS = frozenset("a an and are as at be by can could do does for from how i in into is it me my no of on or our should tell that the their these this to us we what when which who why with would you your versus vs".split())
_WORD_EQUIVALENTS = {"authenticate": "authentication", "authenticated": "authentication",
                      "authenticating": "authentication", "authorize": "authorization",
                      "authorized": "authorization", "authorizing": "authorization"}
_SOURCE_ALIASES = {
    "BENCH-MCPSECBENCH": ("mcp security benchmark", "mcp benchmark", "mcpsecbench"),
    "BENCH-MSB": ("mcp security benchmark", "mcp benchmark", "msb"),
    "BENCH-MCP-SAFETY": ("mcp safety benchmark", "mcp security benchmark", "mcp safetybench"),
}


def _normalize(value):
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def _words(value):
    words = re.findall(r"[^\W_]+", _normalize(value), flags=re.UNICODE)
    return {_WORD_EQUIVALENTS.get(word, word[:-1] if len(word) > 4 and word.endswith("s") else word)
            for word in words if word not in _STOP_WORDS}


def _input(value, label="Query", maximum=MAX_QUERY_CHARS):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(label + " must be a nonempty string.")
    if len(value) > maximum:
        raise ValueError(label + " must contain at most " + str(maximum) + " characters.")
    if any(not char.isprintable() or unicodedata.category(char).startswith("C") for char in value):
        raise ValueError(label + " must not contain control, formatting or invalid Unicode characters.")
    normalized = _normalize(value)
    if len(normalized) > maximum:
        raise ValueError(label + " exceeds the normalized character limit.")
    return value.strip(), normalized


@lru_cache(maxsize=1)
def _catalog():
    data = Path(__file__).parent / "data"
    controls = json.loads((data / "controls.json").read_text(encoding="utf-8"))
    sources = json.loads((data / "sources.json").read_text(encoding="utf-8"))
    explanations = json.loads((data / "control_explanations.json").read_text(encoding="utf-8"))
    remediations = json.loads((data / "remediations.json").read_text(encoding="utf-8"))
    control_by_id = {item["id"]: item for item in controls}
    explanation_by_id = {item["id"]: item for item in explanations["controls"]}
    if len(explanation_by_id) != len(explanations["controls"]) or set(explanation_by_id) != set(control_by_id):
        raise ValueError("Bundled control explanations must cover every control exactly once.")
    for item in explanation_by_id.values():
        for field in ("what_it_is", "why_it_matters", "agent_mcp_context"):
            if not isinstance(item.get(field), str) or not item[field].strip():
                raise ValueError("Bundled control explanation is incomplete.")
        if not isinstance(item.get("aliases"), list) or not all(isinstance(alias, str) and alias.strip() for alias in item["aliases"]):
            raise ValueError("Bundled control explanation aliases are invalid.")
    source_by_id = {item["id"]: item for item in sources}
    rules = {item["id"]: item for item in RULES}
    for control in controls:
        if set(control.get("source_ids", [])) & set(control.get("alignment_source_ids", [])):
            raise ValueError("Bundled source relationship is ambiguous.")
        if any(key not in source_by_id for key in control.get("source_ids", []) + control.get("alignment_source_ids", [])):
            raise ValueError("Bundled control references an unknown source.")
        if any(key not in rules for key in control["automated_rule_ids"]):
            raise ValueError("Bundled control references an unknown rule.")
    urls = {}
    for source in sources:
        for field in ("url", "document_url", "resolved_url", "paper_url", "supporting_urls"):
            values = source.get(field, [])
            if isinstance(values, str):
                values = [values]
            for url in values:
                if isinstance(url, str):
                    urls.setdefault(url, []).append(source["id"])
    return {"controls": controls, "control_by_id": control_by_id, "sources": sources,
            "source_by_id": source_by_id, "rules": rules, "explanations": explanation_by_id,
            "explanation_version": explanations["catalog_version"], "source_urls": urls,
            "remediations": {item["rule_id"]: item for item in remediations["rules"]},
            "remediation_references": {item["id"]: item for item in remediations["references"]}}


def _counts():
    catalog = _catalog()
    return {"controls": len(catalog["controls"]), "checks": sum(len(item["checks"]) for item in catalog["controls"]),
            "rules": len(catalog["rules"]), "sources": len(catalog["sources"]),
            "statically_mapped_controls": sum(bool(item["automated_rule_ids"]) for item in catalog["controls"]),
            "topics": len(_TOPICS), "ruleset_version": RULESET_VERSION,
            "explanation_version": catalog["explanation_version"]}


def _envelope(action):
    return {"schema_version": "1.0", "mode": "deterministic_catalog", "action": action, "status": "ok",
            "catalog": _counts(), "assurance": {
                "execution": "Offline catalog lookup only: no target scan, model call, endpoint probe or runtime validation.",
                "authorship": "Invarune-authored engineering explanations and acceptance checks; source links provide provenance and context.",
                "source_mapping": "primary_control_source identifies the catalog's original source context; thematic_alignment is broader relevance; rule_technical_reference supports a detector or remediation. None is an official clause-level compliance crosswalk.",
                "automation": "Mapped rules offer partial source/configuration pattern coverage of a control, not proof of any individual acceptance check. No finding does not mean pass.",
                "built_images": "Image scans inspect packaged source/configuration, image metadata and supported retained-layer evidence. Binary-only logic, deployed controls, CVE exposure and publisher trust are not established.",
            }, "scan_guidance": {
                "source": "invscan TARGET --output ./scan-report",
                "image_archive": "invscan --image-archive ./agent-image.tar --output ./image-report",
                "meaning": "These scan commands run the applicable deterministic rules within selected scope. Catalog search does not scan or select rules. User exceptions and scope limits remain explicit.",
                "more": "invscan --list-topics; invscan --list-controls --catalog-format text; invscan --help",
            }}


def _source_reference(source_id, relationship):
    return {**copy.deepcopy(_catalog()["source_by_id"][source_id]), "relationship": relationship}


def _rule_detail(rule_id):
    catalog = _catalog()
    rule = copy.deepcopy(catalog["rules"][rule_id])
    rule["mapped_controls"] = [{"id": item["id"], "title": item["title"], "relationship": "partial_control_mapping"}
                               for item in catalog["controls"] if rule_id in item["automated_rule_ids"]]
    rule["control_ids"] = [item["id"] for item in rule["mapped_controls"]]
    rule["assurance"] = "A recognized source pattern is a review signal, not proof of reachable exploitation, complete data flow, runtime protection or an acceptance-check pass."
    rule["technical_references"] = []
    for url in rule["references"]:
        matches = catalog["source_urls"].get(url, [])
        if matches:
            rule["technical_references"].extend(_source_reference(key, "rule_technical_reference") for key in matches)
        else:
            rule["technical_references"].append({"url": url, "relationship": "rule_technical_reference",
                "organization": None, "title": "Technical reference URL from the rule catalog",
                "limitations": "No additional registry metadata is recorded for this exact URL; consult the linked primary documentation."})
    guidance = copy.deepcopy(catalog["remediations"].get(rule_id, {}))
    if guidance:
        guidance["source_references"] = []
        for source_id in guidance.get("source_ids", []):
            if source_id in catalog["source_by_id"]:
                guidance["source_references"].append(_source_reference(source_id, "rule_technical_reference"))
            elif source_id in catalog["remediation_references"]:
                reference = copy.deepcopy(catalog["remediation_references"][source_id])
                reference["mapping_notes"] = reference.pop("relationship", "")
                reference["relationship"] = "rule_technical_reference"
                guidance["source_references"].append(reference)
        rule["implementation_guidance"] = guidance
    return rule


def _control_detail(control_id):
    catalog = _catalog()
    original = catalog["control_by_id"][control_id]
    explanation = catalog["explanations"][control_id]
    rules = [_rule_detail(key) for key in original["automated_rule_ids"]]
    return {"id": original["id"], "title": original["title"], "category": original["category"],
            "validation": original["validation"], **copy.deepcopy(explanation),
            "checks": [{"id": control_id + ":" + str(index), "index": index, "text": text,
                        "validation": original["validation"], "static_check_proof": "not_established_by_rule_mapping"}
                       for index, text in enumerate(original["checks"], 1)],
            "automated_rule_ids": list(original["automated_rule_ids"]),
            "deterministic_coverage": {"status": "partial" if rules else "not_automated", "rules": rules,
                "meaning": ("Mapped rules identify the specific patterns described below. Their absence does not validate this control or either acceptance check."
                            if rules else "No deterministic rule is mapped to this control. Establish it using the listed checks and human, deployment or runtime evidence."),
                "limits": "Control-level mapping only; no per-check automated pass is inferred. A built image can omit source and does not reveal deployed identity, policy or runtime behavior."},
            "sources": ([_source_reference(key, "primary_control_source") for key in original.get("source_ids", [])] +
                        [_source_reference(key, "thematic_alignment") for key in original.get("alignment_source_ids", [])])}


def _check_detail(check_id):
    control_id, index_text = check_id.rsplit(":", 1)
    control = _control_detail(control_id)
    index = int(index_text)
    return {**control["checks"][index - 1], "control_id": control_id, "control": control,
            "assurance": "This is an acceptance criterion to validate. Listed rules map to its parent control and are not proof that this individual check is automated or satisfied."}


def _source_detail(source_id):
    catalog = _catalog()
    source = copy.deepcopy(catalog["source_by_id"][source_id])
    source["related_controls"] = []
    for control in catalog["controls"]:
        for field, relationship in (("source_ids", "primary_control_source"), ("alignment_source_ids", "thematic_alignment")):
            if source_id in control.get(field, []):
                source["related_controls"].append({"id": control["id"], "title": control["title"], "relationship": relationship})
    source["related_rules"] = []
    for rule in RULES:
        roles = []
        if any(source_id in catalog["source_urls"].get(url, []) for url in rule["references"]):
            roles.append("detector_reference")
        if source_id in catalog["remediations"].get(rule["id"], {}).get("source_ids", []):
            roles.append("remediation_reference")
        if roles:
            source["related_rules"].append({"id": rule["id"], "title": rule["title"],
                "relationship": "rule_technical_reference", "reference_roles": roles})
    source["mapping_assurance"] = "Backlinks use only existing control mappings, exact-URL detector references and explicit remediation source IDs. Suggested catalog mappings remain suggestions; announcements, drafts and catalog-only listings retain their recorded limitations."
    return source


def _topics():
    catalog = _catalog()
    result = []
    for topic_id, category, aliases in _TOPICS:
        controls = [{"id": item["id"], "title": item["title"],
                     "what_it_is": catalog["explanations"][item["id"]]["what_it_is"],
                     "automated_rule_ids": list(item["automated_rule_ids"]),
                     "checks": len(item["checks"]), "command": "invscan --explain-control " + item["id"]}
                    for item in catalog["controls"] if item["category"] == category]
        result.append({"id": topic_id, "title": category, "aliases": list(aliases), "controls": controls,
                       "control_count": len(controls), "check_count": sum(item["checks"] for item in controls),
                       "example_queries": ["What is " + controls[0]["id"] + "?", aliases[0]]})
    return result


def _known_id(value):
    catalog = _catalog()
    key = value.upper()
    for kind, field in (("control", "control_by_id"), ("rule", "rules"), ("source", "source_by_id")):
        if key in catalog[field]:
            return kind, key
    if re.fullmatch(r"[A-Z]+-\d{2}:[1-9][0-9]*", key):
        control, index = key.rsplit(":", 1)
        if control in catalog["control_by_id"] and len(index) <= 5 and int(index) <= len(catalog["control_by_id"][control]["checks"]):
            return "check", key
    return None


def _detail(kind, identifier):
    return {"control": _control_detail, "check": _check_detail, "rule": _rule_detail, "source": _source_detail}[kind](identifier)


def _org_aliases(organization):
    normalized = _normalize(organization)
    words = _words(normalized)
    aliases = []
    for short, full in _ORGANIZATIONS:
        if short in words or full in normalized:
            aliases.extend((short, full))
    return aliases


@lru_cache(maxsize=1)
def _search_documents():
    catalog = _catalog()
    documents = []
    for control in catalog["controls"]:
        explanation = catalog["explanations"][control["id"]]
        source_records = [catalog["source_by_id"][key] for key in control.get("source_ids", [])]
        alignment_records = [catalog["source_by_id"][key] for key in control.get("alignment_source_ids", [])]
        fields = {"title": control["title"], "category": control["category"],
                  "aliases": " ".join(explanation["aliases"]), "what_it_is": explanation["what_it_is"],
                  "why_it_matters": explanation["why_it_matters"], "agent_mcp_context": explanation["agent_mcp_context"],
                  "checks": " ".join(control["checks"]),
                  "primary_sources": " ".join(source["title"] + " " + source["organization"] + " " + " ".join(_org_aliases(source["organization"])) for source in source_records),
                  "thematic_sources": " ".join(source["title"] + " " + source["organization"] + " " + " ".join(_org_aliases(source["organization"])) for source in alignment_records)}
        documents.append({"kind": "control", "id": control["id"], "title": control["title"], "fields": fields,
                          "aliases": explanation["aliases"]})
    for rule in RULES:
        documents.append({"kind": "rule", "id": rule["id"], "title": rule["title"],
                          "fields": {key: rule[key] for key in ("title", "description", "remediation", "category")}, "aliases": []})
    for source in catalog["sources"]:
        aliases = _org_aliases(source["organization"])
        aliases += [source["title"], source["id"]]
        aliases += list(_SOURCE_ALIASES.get(source["id"], ()))
        fields = {key: source.get(key, "") for key in ("title", "organization", "scope", "kind", "limitations")}
        fields["aliases"] = " ".join(aliases)
        documents.append({"kind": "source", "id": source["id"], "title": source["title"], "fields": fields, "aliases": aliases})
    return documents


def _overview_query(normalized):
    words = _words(normalized)
    broad = {"all", "ai", "agent", "mcp", "server", "security", "invscan", "invarune", "scan", "scanning", "check", "thing", "cover", "coverage", "support", "supported", "capability", "available"}
    return bool(words) and bool(words & {"scan", "scanning", "check", "thing", "coverage", "capability"}) and words <= broad


def _search_result(kind, identifier, title, score, fields):
    return {"kind": kind, "id": identifier, "title": title, "score": score,
            "matched_fields": sorted(fields), "command": "invscan --explain-" + kind + " " + identifier,
            "detail": _detail(kind, identifier)}


def _ask(value):
    query, normalized = _input(value)
    response = _envelope("ask")
    response.update(query=query, normalized_query=normalized, limit=SEARCH_LIMIT, results=[],
                    search_method="Deterministic literal words and curated aliases; stable weighted field ranking, not an LLM answer or vulnerability assessment.")
    exact = _known_id(normalized)
    mentioned_ids = list(dict.fromkeys(known for word in re.findall(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?::[a-z0-9]+)?", normalized)
                                      for known in [_known_id(word)] if known))
    if exact:
        kind, key = exact
        detail = _detail(kind, key)
        title = detail.get("title", detail.get("text", key))
        response["results"] = [_search_result(kind, key, title, 1000, ["id"])]
        total = 1
    elif (re.fullmatch(r"(?:AI\d+|(?:GOV|AUTH|MCP|AGT|EXEC|DATA|SUP|OPS|TEST)-\d+(?::\S+)?)", normalized.upper())
          or re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)+-\d+", normalized)):
        total = 0
    elif mentioned_ids:
        total = len(mentioned_ids)
        for kind, key in mentioned_ids[:SEARCH_LIMIT]:
            detail = _detail(kind, key)
            response["results"].append(_search_result(kind, key, detail.get("title", detail.get("text", key)), 1000, ["id"]))
    elif _overview_query(normalized):
        response["results"] = [{"kind": "topics", "id": "all-topics", "title": "AI agent and MCP security catalog overview",
            "score": 1000, "matched_fields": ["overview_intent"], "command": "invscan --list-topics",
            "detail": {"topics": _topics()}}]
        total = 1
    elif any(normalized == topic["id"] or normalized in topic["aliases"] for topic in _topics()):
        topic = next(topic for topic in _topics() if normalized == topic["id"] or normalized in topic["aliases"])
        response["results"] = [{"kind": "topic", "id": topic["id"], "title": topic["title"], "score": 1000,
            "matched_fields": ["topic"], "command": "invscan --list-topics", "detail": topic}]
        total = 1
    else:
        terms = _words(normalized)
        substantive = terms - {"check", "scan", "scanning", "thing", "explain", "mean", "meaning", "help", "question", "need"}
        if substantive:
            terms = substantive
        weights = {"title": 24, "aliases": 24, "organization": 24, "category": 5, "what_it_is": 8,
                   "why_it_matters": 6, "agent_mcp_context": 7, "checks": 10, "primary_sources": 4,
                   "thematic_sources": 2, "description": 10, "remediation": 7, "scope": 8, "kind": 3, "limitations": 2}
        ranked = []
        for document in _search_documents():
            matches = {key: terms & _words(text) for key, text in document["fields"].items()}
            matched = {key: words for key, words in matches.items() if words}
            if not matched:
                continue
            covered = set().union(*matched.values())
            if len(covered) * 2 < len(terms):
                continue
            score = sum(weights[key] * len(words) for key, words in matched.items())
            score += 30 * len(covered)
            if normalized in [_normalize(alias) for alias in document["aliases"]]:
                score += 120
            if normalized == _normalize(document["title"]):
                score += 150
            if terms == {"benchmark"} and document["kind"] == "source" and "benchmark" in _words(document["fields"]["kind"]):
                score += 200
            ranked.append((score, len(covered), document, matched))
        ranked.sort(key=lambda item: (-item[1], -item[0], {"control": 0, "source": 1, "rule": 2}[item[2]["kind"]], item[2]["id"]))
        total = len(ranked)
        response["results"] = [{**_search_result(document["kind"], document["id"], document["title"], score, matched),
                                "matched_terms": sorted(set().union(*matched.values())),
                                "unmatched_terms": sorted(terms - set().union(*matched.values()))}
                               for score, _, document, matched in ranked[:SEARCH_LIMIT]]
    response.update(total_matches=total, returned_matches=len(response["results"]), truncated=total > len(response["results"]))
    if not total:
        response["status"] = "no_match"
        response["message"] = "No catalog entry matched this query. This is not a scan result or a claim that a risk is absent. Try a control/check/source/rule ID, a topic or an organization, or use invscan --list-topics."
    return response


def describe_catalog(action, value=None):
    """Return a fresh JSON-serializable answer; invalid explicit IDs raise ValueError."""
    if action == "ask":
        return _ask(value)
    if action not in {"topics", "controls", "rules", "sources", "control", "check", "rule", "source"}:
        raise ValueError("Unknown catalog action.")
    response = _envelope(action)
    if action in {"topics", "controls", "rules", "sources"}:
        if value is not None:
            raise ValueError("Catalog list actions do not accept a value.")
        if action == "topics":
            response["topics"] = _topics()
        elif action == "controls":
            response["controls"] = [_control_detail(item["id"]) for item in _catalog()["controls"]]
        elif action == "rules":
            response["rules"] = [_rule_detail(item["id"]) for item in RULES]
        else:
            response["sources"] = [_source_detail(item["id"]) for item in _catalog()["sources"]]
    else:
        _, normalized = _input(value, "Catalog ID", 128)
        known = _known_id(normalized)
        if not known or known[0] != action:
            raise ValueError("Unknown " + action + " ID. Use invscan --list-topics, --list-controls, --list-rules or --list-sources to inspect the catalog.")
        response[action] = _detail(action, known[1])
    return response


def _text(value):
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True, ensure_ascii=False)


def _render_source(source, lines, compact=False):
    label = source.get("id", "Technical URL") + " — " + source.get("title", "Source")
    lines.append(label)
    for field in ("relationship", "organization", "version", "kind", "date", "accessed", "url", "document_url", "resolved_url", "paper_url", "scope", "limitations", "mapping_notes"):
        if source.get(field) is not None:
            lines.append("  " + field.replace("_", " ").capitalize() + ": " + _text(source[field]))
    if source.get("supporting_urls"):
        lines.append("  Supporting URLs: " + _text(source["supporting_urls"]))
    if not compact:
        links = source.get("related_controls", [])
        lines.append("  Existing control mappings: " + (", ".join(item["id"] + " [" + item["relationship"] + "]" for item in links) or "none recorded"))
        if source.get("related_rules"):
            lines.append("  Rule technical references: " + ", ".join(item["id"] + " [" + ", ".join(item["reference_roles"]) + "]" for item in source["related_rules"]))
        if source.get("suggested_control_ids") or source.get("suggested_control_mappings"):
            lines.append("  Registry suggestions (not promoted to accepted mappings): " + _text(source.get("suggested_control_mappings") or source["suggested_control_ids"]))
        if source.get("mapping_assurance"):
            lines.append("  " + source["mapping_assurance"])


def _render_rule(rule, lines, include_guidance=True):
    lines.extend([rule["id"] + " — " + rule["title"] + " [" + rule["severity"] + "]",
                  "  Detects: " + rule["description"], "  Remediation: " + rule["remediation"],
                  "  CWE: " + ", ".join(rule["cwe"]), "  " + rule["assurance"],
                  "  Partial control mappings: " + (", ".join(rule["control_ids"]) or "none")])
    guidance = rule.get("implementation_guidance", {})
    if include_guidance and guidance:
        lines.append("  Agent/MCP relevance: " + guidance["agent_mcp_relevance"])
        for item in guidance.get("applicability", []):
            lines.append("  Applicability: " + item)
        for step in guidance.get("steps", []):
            lines.extend(["  Fix — " + step["title"] + ": " + step["action"], "  Verify: " + step["verification"]])
        for item in guidance.get("residual_risk", []):
            lines.append("  Remaining risk: " + item)
    for source in rule["technical_references"]:
        _render_source(source, lines, compact=True)
    if include_guidance:
        for source in guidance.get("source_references", []):
            _render_source(source, lines, compact=True)


def _render_control(control, lines):
    lines.extend([control["id"] + " — " + control["title"], "Category: " + control["category"],
                  "What it is: " + control["what_it_is"], "Why it matters: " + control["why_it_matters"],
                  "AI agent / MCP context: " + control["agent_mcp_context"],
                  "Acceptance checks (" + control["validation"] + "; not automated passes):"])
    for check in control["checks"]:
        lines.append("  " + check["id"] + " — " + check["text"])
    coverage = control["deterministic_coverage"]
    lines.extend(["Deterministic coverage: " + coverage["status"], coverage["meaning"], coverage["limits"]])
    for rule in coverage["rules"]:
        _render_rule(rule, lines, include_guidance=False)
    lines.append("Control sources and thematic alignments:")
    for source in control["sources"]:
        _render_source(source, lines, compact=True)


def _render_topics(topics, lines):
    for topic in topics:
        lines.append(topic["id"] + " — " + topic["title"] + " (" + str(topic["control_count"]) + " controls, " + str(topic["check_count"]) + " checks)")
        for control in topic["controls"]:
            coverage = "partial static patterns: " + ", ".join(control["automated_rule_ids"]) if control["automated_rule_ids"] else "human/runtime evidence; no mapped rule"
            lines.append("  " + control["id"] + " — " + control["title"] + " [" + coverage + "]")
        for question in topic["example_queries"]:
            lines.append("  Try: invscan --ask '" + question + "'")


def _render_detail(kind, detail, lines):
    if kind == "control":
        _render_control(detail, lines)
    elif kind == "rule":
        _render_rule(detail, lines)
    elif kind == "source":
        _render_source(detail, lines)
    elif kind == "check":
        lines.extend([detail["id"] + " — " + detail["text"], detail["assurance"], "Parent control context:"])
        _render_control(detail["control"], lines)
    elif kind == "topic":
        _render_topics([detail], lines)
    else:
        _render_topics(detail["topics"], lines)


def render_catalog(data):
    """Render plain offline reference text with explicit provenance and limitations."""
    counts = data["catalog"]
    lines = ["Invarune security explorer — offline deterministic catalog", "",
             str(counts["controls"]) + " controls / " + str(counts["checks"]) + " acceptance checks / " + str(counts["rules"]) + " rules / " + str(counts["sources"]) + " sources",
             str(counts["statically_mapped_controls"]) + " controls have partial static rule mappings; no control or check is declared passed.", ""]
    lines.extend([data["assurance"]["execution"], ""])
    action = data["action"]
    if action == "ask":
        lines.extend(["Query: " + data["query"], data["search_method"]])
        if data["status"] == "no_match":
            lines.append(data["message"])
        else:
            lines.append("Showing " + str(data["returned_matches"]) + " of " + str(data["total_matches"]) + " catalog matches.")
            for match in data["results"]:
                lines.extend(["", "Match " + match["id"] + " [" + match["kind"] + "; fields: " + ", ".join(match["matched_fields"]) + "]",
                              "Explore: " + match["command"]])
                if match.get("unmatched_terms"):
                    lines.append("Partial word match; unmatched query terms: " + ", ".join(match["unmatched_terms"]))
                _render_detail(match["kind"], match["detail"], lines)
            if data["truncated"]:
                lines.append("Narrow the literal query or select an exact ID to explore other matches.")
    elif action == "topics":
        _render_topics(data["topics"], lines)
    elif action in {"controls", "rules", "sources"}:
        for detail in data[action]:
            _render_detail(action[:-1], detail, lines)
            lines.append("")
    else:
        _render_detail(action, data[action], lines)
    lines.extend(["", "Interpretation and source relationships:"])
    lines.extend(value for key, value in data["assurance"].items() if key != "execution")
    lines.extend(["", "Run a scan separately:", "  " + data["scan_guidance"]["source"],
                  "  " + data["scan_guidance"]["image_archive"], data["scan_guidance"]["meaning"],
                  "More: " + data["scan_guidance"]["more"]])
    return "\n".join(lines) + "\n"
