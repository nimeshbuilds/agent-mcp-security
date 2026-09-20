"""Transparent scope and review metrics, never a synthetic security grade.

Counts are derived from selected evidence, not provider summary claims. A model
answer can improve review coverage without establishing that a control passed.
"""
from collections import Counter, defaultdict

from .rules import RULES


SEVERITIES = ("critical", "high", "medium", "low", "info")
EXCLUDED = {"justified", "disabled"}
ADVISORY_STATUSES = ("supported_by_code", "potential_gap", "needs_runtime_validation",
                     "needs_human_review", "insufficient_evidence", "not_applicable_proposed")


def _ratio(numerator, denominator):
    return {"numerator": numerator, "denominator": denominator,
            "percent": round(100 * numerator / denominator, 2) if denominator else None}


def build_scoring(report):
    """Return auditable metrics without mutating findings, controls or CI policy.

    Selected rules are not proven applicable merely because they were enabled.
    The mapping metric therefore reports potential reach only. The number of
    passed controls is deliberately absent; neither layer validates deployment.
    """
    configuration, coverage = report.get("configuration", {}), report.get("coverage", {})
    known_rules = {rule["id"] for rule in RULES}
    selected_rules = set(configuration.get("selected_rule_ids", known_rules)) & known_rules
    policy = report.get("review_policy", {}).get("entries", {})
    rule_decisions = policy.get("rules", {})
    rule_states = {identifier: rule_decisions.get(identifier, {}).get("status", "active")
                   for identifier in selected_rules}
    # Respect source/image-selected rule sets when supplied, including [] rather
    # than silently restoring the entire catalog for an intentionally empty set.
    if "rules_enabled" in coverage:
        enabled_rules = set(coverage["rules_enabled"]) & selected_rules
    else:
        enabled_rules = selected_rules
    active_rules = {identifier for identifier in enabled_rules if rule_states[identifier] not in EXCLUDED}
    selected_controls = configuration.get("selected_control_ids")
    controls = [control for control in report.get("controls", [])
                if selected_controls is None or control["id"] in selected_controls]
    active_checks, excluded_checks, active_controls = {}, Counter(), []
    for control in controls:
        dispositions = {entry["check_index"]: entry for entry in control.get("check_dispositions", [])}
        count = 0
        for index, _ in enumerate(control.get("checks", []), 1):
            state = dispositions.get(index, {}).get("status", "active")
            if state in EXCLUDED:
                excluded_checks[state] += 1
            else:
                active_checks[(control["id"], index)] = control
                count += 1
        if count:
            active_controls.append(control)
    mapped_controls = [control for control in active_controls
                       if set(control.get("automated_rule_ids", [])) & active_rules]
    findings = [finding for finding in report.get("findings", []) if finding["rule_id"] in selected_rules]
    findings_by_status = Counter(finding.get("status", "open") for finding in findings)
    severity = Counter(finding["severity"] for finding in findings if finding.get("status", "open") == "open")
    judge, analyst = report.get("judge", {}), report.get("analyst", {})
    answers = defaultdict(list)
    ignored = 0
    if analyst.get("enabled"):
        for control in analyst.get("control_assessments", []):
            for check in control.get("check_assessments", []):
                key = (control.get("control_id"), check.get("check_index"))
                if check.get("model_supplied") is not True:
                    continue
                if (key not in active_checks or check.get("status") not in ADVISORY_STATUSES
                        or type(check.get("check_index")) is not int):
                    ignored += 1
                    continue
                answers[key].append(check)
    # Conflicting/duplicated answers receive no completion credit. Production
    # schema validation rejects them; this also keeps library usage conservative.
    duplicates = sum(len(items) for items in answers.values() if len(items) != 1)
    actual = [items[0] for items in answers.values() if len(items) == 1]
    statuses = Counter(item["status"] for item in actual)
    unreviewed = len(active_checks) - len(actual)
    advisory = {status: statuses[status] for status in ADVISORY_STATUSES}
    advisory["not_reviewed"] = unreviewed
    return {
        "schema_version": "1.0",
        "overall_security_score": None,
        "overall_security_score_reason": "No defensible universal security percentage can be calculated from static patterns or model opinions. Zero findings and 100% answered checks do not mean secure or compliant.",
        "deterministic": {
            "selected_rules": len(selected_rules), "active_rules": len(active_rules),
            "justified_rules": sum(state == "justified" for state in rule_states.values()),
            "disabled_rules": sum(state == "disabled" for state in rule_states.values()),
            "selected_controls": len(controls), "active_controls": len(active_controls),
            "active_checks": len(active_checks), "justified_checks": excluded_checks["justified"],
            "disabled_checks": excluded_checks["disabled"],
            "open_findings": findings_by_status["open"],
            "open_by_severity": {name: severity[name] for name in SEVERITIES},
            "urgent_findings": severity["critical"] + severity["high"],
            "justified_findings": findings_by_status["justified"],
            "disabled_findings": findings_by_status["disabled"],
            "suppressed_findings": findings_by_status["suppressed"],
            "mapping_reach": _ratio(len(mapped_controls), len(active_controls)),
            "mapping_reach_formula": "100 × active selected controls with at least one active selected mapped rule / active selected controls. This describes partial rule availability, not completed tests, passes, or control effectiveness.",
            "selected_scope_complete": bool(report.get("summary", {}).get("scan_complete_within_selected_scope", False)),
            "coverage_gaps": report.get("summary", {}).get("coverage_gaps", 0),
        },
        "optional_ai": {
            "enabled": bool(judge.get("enabled") or analyst.get("enabled")),
            "finding_review_status": judge.get("status", "unknown") if judge.get("enabled") else "disabled",
            "control_review_status": analyst.get("status", "unknown") if analyst.get("enabled") else "disabled",
            "answer_coverage": _ratio(len(actual), len(active_checks)),
            "answer_coverage_formula": "100 × unique active selected acceptance checks with a received, valid model answer / active selected acceptance checks. An answer can be a concern or an explicit unknown. Disabled AI has zero answered checks; an empty denominator is not applicable (null), never 100%.",
            "check_outcomes": advisory,
            "additional_concerns": len(judge.get("additional_concerns", [])) if judge.get("enabled") else 0,
            "ignored_answer_records": ignored + duplicates,
            "changes_deterministic_result": False,
            "interpretation": "Supported by code and proposed non-applicability are advisory interpretations. Runtime/human validation and missing evidence remain unresolved. AI cannot erase findings, lower their severity, change the severity gate, or turn checks into passes.",
        },
        "exclusions": "Justified and disabled rules/checks are excluded from active metric denominators without pass credit. Findings with user decisions or baseline suppressions remain visible outside open-finding counts. Selection narrows the requested scope; it does not establish the excluded system is safe.",
        "gate": "The existing CLI gate uses open deterministic findings at or above the configured severity. Scan/review/export errors can make requested work incomplete. Coverage percentages and model opinions never dismiss the gate.",
    }


def format_ratio(metric):
    """One consistent human-readable representation for every report renderer."""
    value = "not applicable" if metric["percent"] is None else "{:.2f}%".format(metric["percent"])
    return "{} ({}/{})".format(value, metric["numerator"], metric["denominator"])
