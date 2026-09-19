"""Versioned engineering guidance; never alter findings or infer exploitability.

Only the packaged catalog selects advice. Finding/model text is not executable
configuration and does not select alternative commands, links, or fixes.
"""
import copy
import hashlib
import json
from pathlib import Path


_CONTEXT = {
    "source": "Inspect the reported source location and its callers, change the implementation or effective configuration, then rebuild and rescan. The scan does not establish that this code is on an active agent or MCP request path.",
    "final_filesystem": "This location is a packaged file in the final image filesystem. Identify its owning source/package, fix and rebuild the image, then rescan the new digest. Packaged presence does not prove runtime execution; a running-container edit is not a reproducible image fix.",
    "runtime_configuration": "This location records image configuration defaults. Change the image build or deployment configuration as applicable, rebuild if needed, and verify the effective running settings; deployment overrides may differ from image defaults.",
    "retained_layer": "This location is retained historical layer content. Fix the producing build step and rebuild without copying the affected content into any distributed layer. Deleting it in a later layer is insufficient. Rotate real exposed credentials; historical code presence does not prove current execution.",
    "build_history": "This location is image build-history metadata. Correct the producing build command and rebuild; verify any exposed real credential is rotated. History alone does not establish that an operation executes in the deployed container.",
}


def _load_catalog():
    directory = Path(__file__).parent / "data"
    raw = (directory / "remediations.json").read_bytes()
    catalog = json.loads(raw)
    registry = {source["id"]: source for source in json.loads((directory / "sources.json").read_text(encoding="utf-8"))}
    for source in catalog["references"]:
        if source["id"] in registry:
            raise ValueError("Remediation reference identifier conflicts with the source catalog")
        registry[source["id"]] = source
    entries = {entry["rule_id"]: entry for entry in catalog["rules"]}
    if len(entries) != len(catalog["rules"]):
        raise ValueError("Duplicate remediation rule identifier")
    return catalog, entries, registry, hashlib.sha256(raw).hexdigest()


def build_remediation(report):
    """Return independent per-finding guidance, including exempt/baseline findings.

    Guidance and verification steps are proposals, never completed tests or a
    risk downgrade. The mapping is stable for stable report/catalog input, does
    not read scanned files, and does not contact or execute any external tool.
    """
    catalog, entries, registry, digest = _load_catalog()
    result = {}
    for finding in report.get("findings", []):
        identifier, rule_id = finding["id"], finding["rule_id"]
        if identifier in result:
            raise ValueError("Duplicate finding identifier in remediation input")
        if rule_id not in entries:
            raise ValueError("No versioned remediation guidance for rule " + str(rule_id))
        entry = copy.deepcopy(entries[rule_id])
        context = finding.get("image_context", "source")
        source_ids = entry.pop("source_ids")
        sources = [{"id": source_id, "title": registry[source_id]["title"], "url": registry[source_id]["url"],
                    "relationship": registry[source_id].get("relationship", "Supporting engineering guidance; the rule mapping and remediation plan are authored by Invarune.")}
                   for source_id in source_ids]
        result[identifier] = {"schema_version": catalog["schema_version"], "catalog_version": catalog["catalog_version"],
                              "catalog_sha256": digest, **entry, "sources": sources,
                              "location": {"path": finding.get("path", ""), "line": finding.get("line"), "image_context": context},
                              "scope_note": _CONTEXT.get(context, "Confirm this image evidence's provenance, locate the owning build or deployment configuration, and verify actual use before applying the proposed changes.")}
    return result
