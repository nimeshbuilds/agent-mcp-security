"""Deterministic report interpretation; no model decisions or risk downgrades."""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path


SEVERITY_ORDER = {name: rank for rank, name in enumerate(("critical", "high", "medium", "low", "info"))}
PRIORITIES = {"critical": "P0", "high": "P1", "medium": "P2", "low": "P3", "info": "P3"}
CONTEXT_NOTES = {
    "source": "Source evidence: deployment reachability and active use have not been established.",
    "final_filesystem": "Packaged file in the final image filesystem; whether it executes in deployment is unverified.",
    "runtime_configuration": "Image configuration defaults; actual deployment settings may override them.",
    "retained_layer": "Historical layer content remains in the distributed archive even if removed from the final filesystem. This does not mean the file currently executes. Real credentials can remain exposed through the retained layer.",
    "build_history": "Image build-history evidence; this is not proof that the recorded operation runs in the deployed container.",
}


def _load_guidance():
    data = Path(__file__).parent / "data"
    raw = (data / "mitigations.json").read_bytes()
    source_raw = (data / "sources.json").read_bytes()
    catalog = json.loads(raw)
    sources = {source["id"]: source for source in json.loads(source_raw)}
    rules = {rule["rule_id"]: rule for rule in catalog["rules"]}
    return catalog, rules, sources, hashlib.sha256(raw).hexdigest(), hashlib.sha256(source_raw).hexdigest()


def _sources(ids, registry):
    return [{"id": identifier, "title": registry[identifier]["title"], "url": registry[identifier]["url"]}
            for identifier in sorted(set(ids))]


def _group_order(group):
    return (group["status"] != "open", SEVERITY_ORDER.get(group["severity"], 5),
            group["rule_id"], group["image_context"], group["id"])


def build_assessment(report):
    """Derive a review plan from findings and scope, without altering either.

    The model's verdict and the selected exit threshold are intentionally absent.
    Guidance is a proposal. No suggested layer is credited as an existing control.
    """
    catalog, guidance, registry, digest, source_digest = _load_guidance()
    grouped = defaultdict(list)
    for finding in report["findings"]:
        context = finding.get("image_context", "source")
        grouped[(finding["rule_id"], finding["status"], context)].append(finding)
    groups = []
    for (rule_id, status, context), findings in sorted(grouped.items()):
        findings = sorted(findings, key=lambda f: (f["path"], f["line"], f["id"]))
        first = min(findings, key=lambda f: (SEVERITY_ORDER.get(f["severity"], 5), f["id"]))
        advice = guidance[rule_id]
        layers = []
        for layer in advice["defense_layers"]:
            layers.append({**layer, "status": "proposed_not_verified", "sources": _sources(layer["source_ids"], registry)})
        key = json.dumps([rule_id, status, context], ensure_ascii=True, separators=(",", ":"))
        groups.append({
            "id": "group-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:12],
            "rule_id": rule_id, "title": first["title"], "severity": first["severity"],
            "status": status, "image_context": context,
            "context_note": CONTEXT_NOTES.get(context, "Image evidence; confirm its provenance and deployment applicability before drawing conclusions."),
            "priority": (PRIORITIES.get(first["severity"], "P3") if status == "open"
                         else {"justified": "Justified", "disabled": "Disabled"}.get(status, "Accepted")),
            "finding_ids": [finding["id"] for finding in findings],
            "locations": [{"finding_id": f["id"], "path": f["path"], "line": f["line"], "end_line": f.get("end_line", f["line"])} for f in findings],
            "count": len(findings), "confidence_counts": dict(sorted(Counter(f["confidence"] for f in findings).items())),
            "plausible_impact": advice["plausible_impact"], "immediate_action": advice["immediate_action"],
            "suggested_owner": advice["suggested_owner"], "control_ids": sorted(advice["control_ids"]),
            "source_ids": sorted(advice["source_ids"]), "sources": _sources(advice["source_ids"], registry),
            "defense_layers": layers,
        })
    groups.sort(key=_group_order)
    open_findings = [f for f in report["findings"] if f["status"] == "open"]
    suppressed = [f for f in report["findings"] if f["status"] == "suppressed"]
    justified = [f for f in report["findings"] if f["status"] == "justified"]
    disabled = [f for f in report["findings"] if f["status"] == "disabled"]
    policy = report.get("review_policy", {})
    counts = policy.get("counts", {}) if policy.get("enabled") else {}
    has_exceptions = bool(justified or disabled or any(counts.get(key, 0) for key in (
        "justified_rules", "disabled_rules", "justified_checks", "disabled_checks")))
    categories = defaultdict(list)
    for finding in open_findings:
        categories[finding.get("category", "other")].append(finding)
    themes = [{"category": category, "name": category.replace("_", " ").capitalize(),
               "open_findings": len(items), "rule_ids": sorted({f["rule_id"] for f in items})}
              for category, items in sorted(categories.items(), key=lambda item: (-len(item[1]), item[0]))]
    urgent = sum(f["severity"] in ("critical", "high") for f in open_findings)
    summary = report["summary"]
    complete = bool(summary["scan_complete_within_selected_scope"])
    gaps = summary["coverage_gaps"]
    imported_review = report.get("review_import", {})
    review_counts = imported_review.get("counts", {})
    if not complete or gaps:
        posture = {"code": "incomplete_scope", "title": "Incomplete scan - close the coverage gaps",
                   "explanation": f"The selected static scope was not fully inspected. There are {len(open_findings)} open findings, including {urgent} critical/high findings. Resolve reported gaps and review existing evidence before relying on this result."}
    elif imported_review.get("incomplete"):
        posture = {"code": "review_followup_required", "title": "Reviewed report needs further validation",
                   "explanation": f"The fresh scan found {len(open_findings)} open findings, including {urgent} critical/high patterns. Imported review has {review_counts.get('stale', 0)} stale decisions, {review_counts.get('out_of_scope', 0)} items without comparable coverage and {review_counts.get('unresolved', 0)} explicit runtime/human follow-ups. These are not accepted passes; resolve them before treating the requested review as complete."}
    elif report.get("review_workspace_unavailable") or report.get("export_errors"):
        posture = {"code": "report_export_incomplete", "title": "Scan evidence retained; requested report work incomplete",
                   "explanation": f"The static scan retained {len(open_findings)} open findings, including {urgent} critical/high patterns. An editable review capsule or requested PDF could not be exported. Inspect the report diagnostics and use a supported bounded report before relying on the review workflow."}
    elif urgent:
        posture = {"code": "urgent_review", "title": "Critical/high findings need prompt review",
                   "explanation": f"The scanner found {urgent} open critical/high patterns among {len(open_findings)} open findings. Confirm exposure and prioritize the actions below. Detector severity is not proof of exploitability or deployed risk."}
    elif open_findings:
        posture = {"code": "open_findings_review", "title": "Open findings need investigation",
                   "explanation": f"The scanner found {len(open_findings)} open patterns, with no open critical/high detections. Review applicability, address the causes, and validate the proposed defenses."}
    elif has_exceptions:
        posture = {"code": "configured_exceptions", "title": "No open findings; configured exceptions apply",
                   "explanation": f"User configuration marks {len(justified)} observed findings justified and {len(disabled)} disabled; {len(suppressed)} baseline findings remain suppressed. Exempt rules and acceptance checks do not count toward active totals or establish a pass. Review the recorded reasons and preserved evidence."}
    elif suppressed:
        posture = {"code": "suppressed_findings_only", "title": "Only accepted baseline findings remain",
                   "explanation": f"All {len(suppressed)} detected findings were suppressed by the supplied baseline. They remain observed risk patterns; acceptance does not establish remediation or effective compensating controls."}
    else:
        posture = {"code": "no_patterns_detected", "title": "No configured risk patterns detected",
                   "explanation": "The selected static scope completed without a detector match. This is not a security pass. Review the unassessed boundaries and validate the controls below."}
    gap_groups = defaultdict(list)
    for entry in report["coverage"]["errors"]:
        gap_groups[entry.get("kind", "scan_error") + ": " + entry["error"]].append(entry["path"])
    for entry in report["coverage"]["skipped"]:
        if entry["coverage_gap"]:
            gap_groups[entry["reason"]].append(entry["path"])
    attention = [{"reason": reason, "count": len(paths), "examples": sorted(set(paths))[:3]}
                 for reason, paths in sorted(gap_groups.items())]
    if not complete and not attention:
        attention.append({"reason": "The selected scope was not completed; inspect the detailed coverage record.", "count": 1, "examples": []})
    unknowns = [
        "Actual reachability, deployment configuration, upstream validation, data sensitivity, and exploitability require verification.",
        "Authentication, authorization, tenant isolation, tool approvals, prompt-injection resistance, and recovery need runtime or human evidence.",
        "Suggested defense layers have not been verified as deployed. There is no calculated residual-risk score or automatic severity reduction.",
        "No dependency CVE feed or live adversarial agent/MCP benchmark was run. Excluded and unsupported files remain outside the selected scope.",
    ]
    if report.get("image"):
        image = report["image"]
        unknowns.insert(0, f"Image scope: {image.get('analysis_scope', 'unknown')}; {image.get('packaged_source_files_inspected', 0)} packaged source files inspected. The container was not started. Compiled application behavior and runtime overrides are unassessed.")
        if not image.get("packaged_source_files_inspected", 0):
            unknowns.insert(0, "No packaged application source was inspected. A complete metadata scan does not establish application-code security.")
    return {
        "schema_version": "1.0", "method": "deterministic_guidance",
        "guidance": {"catalog_version": catalog["catalog_version"], "reviewed_at": catalog["reviewed_at"],
                     "sha256": digest, "source_registry_sha256": source_digest},
        "posture": posture,
        "priority_basis": "P0: critical, P1: high, P2: medium, P3: low/info. These are deterministic review priorities based on detector severity, not incident confirmation, remediation SLAs, likelihood estimates, or residual-risk scores. Confidence describes the detected pattern; applicability must be checked.",
        "metrics": {"open_findings": len(open_findings), "suppressed_findings": len(suppressed),
                    "justified_findings": len(justified), "disabled_findings": len(disabled),
                    "urgent_findings": urgent, "affected_files": len({f["path"] for f in open_findings}),
                    "files_scanned": summary["files_scanned"], "coverage_gaps": gaps,
                    "controls_total": len(report["controls"]), "controls_requiring_validation": counts.get("active_controls", len(report["controls"])),
                    "checks_total": sum(len(c.get("checks", [])) for c in report["controls"]),
                    "active_checks": counts.get("active_checks", sum(len(c.get("checks", [])) for c in report["controls"])),
                    "active_rules": counts.get("active_rules", len(report["coverage"].get("rules_enabled", []))),
                    "justified_rules": counts.get("justified_rules", 0), "disabled_rules": counts.get("disabled_rules", 0),
                    "justified_checks": counts.get("justified_checks", 0), "disabled_checks": counts.get("disabled_checks", 0),
                    "justified_controls": counts.get("justified_controls", 0), "disabled_controls": counts.get("disabled_controls", 0),
                    "excluded_controls": counts.get("excluded_controls", 0),
                    "mixed_excluded_controls": counts.get("mixed_excluded_controls", 0)},
        "themes": themes, "finding_groups": groups, "immediate_actions": [g for g in groups if g["status"] == "open"],
        "coverage_attention": attention, "unknowns": unknowns,
    }
