"""Portable JSON, Markdown, and SARIF output; repository strings are escaped."""
import html
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from urllib.parse import quote, quote_from_bytes

from . import DISPLAY_NAME
from .assessment import build_assessment
from .scoring import build_scoring, format_ratio


def _unicode_text(value):
    # JSON strings and POSIX surrogate-escaped filenames can contain unpaired
    # surrogates. Display them explicitly instead of failing report generation.
    return str(value).encode("utf-8", "backslashreplace").decode("utf-8")


def md(value):
    text = html.escape(_unicode_text(value), quote=False).replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\`*_{\[\]}()#+.!|>~-])", r"\\\1", text)


def codeblock(value):
    text = _unicode_text(value)
    longest = max((len(m.group()) for m in re.finditer(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{text}\n{fence}"


def recommended_actions_markdown(actions):
    if not actions:
        return []
    lines = ["**Model-proposed fix guidance (unverified):**", "",
             "**Agent/MCP relevance:** " + md(actions["agent_mcp_relevance"]), "",
             "**When this applies:** " + md(actions["applicability"]), ""]
    lines += [str(index) + ". " + md(step) for index, step in enumerate(actions["steps"], 1)]
    lines += ["", "**How to verify:**", ""]
    lines += ["- " + md(step) for step in actions["verification"]]
    return lines + [""]


def remediation_markdown(advice):
    if not advice:
        return []
    lines = ["#### Fix plan and agent/MCP relevance", "", md(advice["summary"]), "",
             "**Why this matters for agents/MCP:** " + md(advice["agent_mcp_relevance"]), "",
             md(advice["scope_note"]), "", "**Confirm applicability:**", ""]
    lines += ["- " + md(item) for item in advice["applicability"]]
    lines += ["", "| Step | Concrete change | Verify it |", "|---|---|---|"]
    for index, step in enumerate(advice["steps"], 1):
        lines.append("| " + md(str(index) + ". " + step["title"]) + " | " + md(step["action"]) + " | " + md(step["verification"]) + " |")
    lines += ["", "**Remaining validation:**", ""] + ["- " + md(item) for item in advice["residual_risk"]]
    lines += ["", "Related controls: " + ", ".join(md(item) for item in advice["control_ids"]), "",
              "Fix guidance sources: " + "; ".join("[" + md(item["id"]) + "](" + quote(item["url"], safe=':/#?=&%') + ")" for item in advice["sources"]), ""]
    return lines


def advice_coverage(report):
    judge, analyst = report.get("judge", {}), report.get("analyst", {})
    findings = judge.get("assessments", [])
    checks = [check for control in analyst.get("control_assessments", [])
              for check in control.get("check_assessments", []) if check.get("model_supplied")]
    omitted = judge.get("omitted_assessments", 0)
    return {"static_findings": len(report["findings"]), "static_fix_plans": len(report.get("remediation", {})),
            "finding_assessment_slots": len(findings), "omitted_finding_assessments": omitted,
            "finding_assessments": len(findings) - omitted, "finding_fix_plans": sum(bool(item.get("recommended_actions")) for item in findings),
            "additional_concerns": len(judge.get("additional_concerns", [])), "additional_concern_fix_plans": len(judge.get("additional_concern_actions", [])),
            "model_check_assessments": len(checks), "model_check_fix_plans": sum(bool(item.get("recommended_actions")) for item in checks),
            "interpretation": "Fix plans are proposals, not executed patches or validated safeguards. Finding/check assessment counts include actual model answers only; synthesized omitted slots are separate. Missing model advice remains absent; static guidance stays available."}


def finding_anchor(identifier):
    return "finding-" + hashlib.sha256(_unicode_text(identifier).encode("utf-8")).hexdigest()[:16]


def review_policy_markdown(report):
    policy = report.get("review_policy", {})
    if not policy.get("enabled"):
        return []
    counts = policy.get("counts", {})
    lines = ["## User review decisions", "",
             "`justified` records the user's rationale; `disabled` excludes a check from active assessment. Neither state means pass, earns positive credit, or counts against active totals. Observed evidence remains available. Rule decisions and imported individual-finding decisions exclude related findings from the severity gate; control and individual-check decisions affect checklist review only. Scan errors and coverage gaps remain unresolved.", "",
             "| Scope | Active | Justified | Disabled | Excluded with mixed check decisions | Catalog total |",
             "|---|---:|---:|---:|---:|---:|"]
    for scope in ("rules", "controls", "checks"):
        lines.append(f"| {scope.capitalize()} | {counts.get('active_' + scope, 0)} | {counts.get('justified_' + scope, 0)} | {counts.get('disabled_' + scope, 0)} | {counts.get('mixed_excluded_controls', 0) if scope == 'controls' else 0} | {counts.get('catalog_' + scope, 0)} |")
    lines += ["", "### Configured decisions and reasons", "", "| Scope | Identifier | Decision | User reason |", "|---|---|---|---|"]
    for scope in ("rules", "controls", "checks", "findings"):
        for identifier, entry in sorted(policy.get("entries", {}).get(scope, {}).items()):
            lines.append(f"| {scope} | {md(identifier)} | {md(entry['status'])} | {md(entry.get('reason') or 'No reason supplied.')} |")
    lines += ["", "Review configuration SHA-256: `" + md(policy.get("sha256", "")) + "`.", "",
              md(policy.get("assurance", "User decisions are recorded without verifying the stated safeguards.")), ""]
    return lines


def executive_markdown(report, assessment):
    posture, metrics = assessment["posture"], assessment["metrics"]
    lines = ["## Executive assessment", "", "### " + md(posture["title"]), "", md(posture["explanation"]), "",
             "| Open findings | Critical/high | Affected files | Accepted baseline findings | Coverage gaps |",
             "|---:|---:|---:|---:|---:|",
             f"| {metrics['open_findings']} | {metrics['urgent_findings']} | {metrics['affected_files']} | {metrics['suppressed_findings']} | {metrics['coverage_gaps']} |", "",
             f"**{metrics['controls_requiring_validation']} active controls** still require applicability and effectiveness validation. A completed static scan or optional review cannot establish a control pass.", ""]
    if report.get("review_policy", {}).get("enabled"):
        lines += [f"**User review decisions:** {metrics['active_rules']} active rules; {metrics['active_checks']} active acceptance checks. Separately recorded: {metrics['justified_rules']} justified / {metrics['disabled_rules']} disabled rules; {metrics['justified_checks']} justified / {metrics['disabled_checks']} disabled checks; {metrics['justified_findings']} justified / {metrics['disabled_findings']} disabled observed findings.", "",
                  "Justified and disabled items are excluded from active totals without positive or negative credit. These are user decisions, not validated control passes. The complete reasons appear in **User review decisions** below.", ""]
    if report.get("advice_coverage"):
        advice = report["advice_coverage"]
        lines += [f"**Fix guidance:** {advice['static_fix_plans']}/{advice['static_findings']} observed findings have a deterministic fix plan and agent/MCP context. Model fix plans: {advice['finding_fix_plans']}/{advice['finding_assessments']} finding assessments and {advice['model_check_fix_plans']}/{advice['model_check_assessments']} answered checks. These are proposed changes requiring verification.", ""]
    if assessment["themes"]:
        lines += ["**What the scanner found:** " + "; ".join(f"{md(theme['name'])}: {theme['open_findings']}" for theme in assessment["themes"]) + ". These are detected pattern categories, not confirmed attack paths.", ""]
    if metrics["suppressed_findings"]:
        lines += ["Accepted baseline findings are still detected patterns. Confirm their owner, expiry, justification, and compensating-control evidence; they are excluded from the severity gate, not proven fixed.", ""]
    execution = report.get("execution", {})
    if execution:
        lines += [f"**Execution:** exit {execution['exit_code']}; severity threshold {md(execution['failure_threshold'])}. The exit threshold does not change the review priorities below.", ""]
    judge, analyst = report.get("judge", {}), report.get("analyst", {})
    if judge.get("enabled"):
        lines += ["**Optional model review:** " + md(judge.get("status", "unknown")) + ". Model advice is separate from the deterministic assessment and cannot lower these priorities.", ""]
        if analyst.get("enabled"):
            coverage = analyst.get("coverage", {})
            lines += [f"Control-review status: **{md(analyst.get('status', 'unknown'))}**; {coverage.get('reviewed_controls', 0)}/{coverage.get('total_controls', len(report['controls']))} controls answered, {coverage.get('omitted_checks', 0)} unanswered checks. An answered check is not a passed check.", ""]
        if execution.get("exit_code") == 2:
            lines += ["**Requested work is incomplete.** Inspect scan gaps and optional-review errors below; retain the static findings even when a model request failed.", ""]
    else:
        lines += ["**Optional model review:** disabled. This overview and the mitigation guidance work offline without a model.", ""]
    lines += ["## Immediate concerns and first actions", "", md(assessment["priority_basis"]), ""]
    if assessment["coverage_attention"]:
        lines += ["**Close scan coverage gaps:** resolve the listed errors or scope limits and rerun on a stable input. Existing findings still need review.", ""]
        for gap in assessment["coverage_attention"]:
            lines.append(f"- {md(gap['reason'])}: {gap['count']} entries. Examples: " + ", ".join(md(path) for path in gap["examples"]))
        lines.append("")
    if assessment["immediate_actions"]:
        lines += ["| Priority | What the scanner found | Occurrences | First action | Suggested owner |", "|---|---|---:|---|---|"]
        for group in assessment["immediate_actions"]:
            lines.append(f"| {group['priority']} | [{md(group['rule_id'])}: {md(group['title'])}](#{group['id']}) ({md(group['image_context'])}) | {group['count']} | {md(group['immediate_action'])} | {md(group['suggested_owner'])} |")
    else:
        lines.append("There are no open pattern findings to prioritize. This does not close the coverage, runtime, or accepted-risk follow-up work.")
    lines += ["", "## What could reduce the risk", "",
              "The layers below are **proposed and unverified**. They can reduce exposure or impact only when correctly implemented and tested. Fix the underlying issue where applicable. No suggested layer, baseline exception, or model opinion lowers a finding's recorded severity.", "",
              "Before accepting lower residual risk, record deployment evidence, negative-test results, owner, review date, and expiry. Confirm that requests cannot bypass the control and retest after changes.", ""]
    for group in assessment["finding_groups"]:
        lines += [f'<a id="{group["id"]}"></a>', "", f"### {md(group['rule_id'])}: {md(group['title'])}", "",
                  f"**{md(group['severity'].upper())}** · {md(group['status'])} · {group['count']} occurrences · {md(group['image_context'])}", "",
                  "**Observed evidence:** " + ", ".join(f"[{md(item['path'])}:{item['line']}](#{finding_anchor(item['finding_id'])})" for item in group["locations"]), "",
                  md(group["context_note"]), "", "**Possible impact:** " + md(group["plausible_impact"]), "",
                  "**Address the cause:** " + md(group["immediate_action"]), "",
                  "| Additional defense | How it could help | Evidence needed | Remaining limitation |",
                  "|---|---|---|---|"]
        for layer in group["defense_layers"]:
            lines.append(f"| {md(layer['title'])} | {md(layer['how_it_helps'])} | {md(layer['verification'])} | {md(layer['residual_limit'])} |")
        lines += ["", "Related controls: " + ", ".join(md(identifier) for identifier in group["control_ids"]), "",
                  "Guidance sources (engineering synthesis): " + "; ".join(f"[{md(source['id'])}]({quote(source['url'], safe=':/#?=&%')})" for source in group["sources"]), ""]
    if not assessment["finding_groups"]:
        lines += ["No finding-specific mitigation was selected because no configured pattern was detected. Use the full control checklist to validate identity and authorization, tool execution boundaries, isolation, secrets, monitoring, and incident response.", ""]
    lines += ["### What remains unknown", ""]
    lines += ["- " + md(unknown) for unknown in assessment["unknowns"]]
    lines += ["", "Guidance catalog version: " + md(assessment["guidance"]["catalog_version"]) + "; SHA-256: `" + assessment["guidance"]["sha256"] + "`. The catalog is bundled and does not contact external sources during a scan.", ""]
    return lines


def scoring_markdown(report):
    scoring = report.get("scoring") or build_scoring(report)
    static, ai = scoring["deterministic"], scoring["optional_ai"]
    lines = ["## Metrics and how they are calculated", "", scoring["overall_security_score_reason"], "",
             "| Measure | Result | What it means |", "|---|---|---|",
             "| Open deterministic findings | " + str(static["open_findings"]) + " | Observed patterns requiring review; " + str(static["urgent_findings"]) + " critical/high. No severity weights or estimated compromise probability are assigned. |",
             "| Partial deterministic mapping reach | " + format_ratio(static["mapping_reach"]) + " | Active selected controls with at least one active selected mapped rule. This is available partial coverage, not a pass rate. |",
             "| Optional AI answer coverage | " + format_ratio(ai["answer_coverage"]) + " | Active selected checks with an actual model answer, including concerns and unknowns. This is review completion, not a pass rate. |", "",
             "**Selected scope:** " + str(static["selected_rules"]) + " rules (" + str(static["active_rules"]) + " active), " + str(static["selected_controls"]) + " controls (" + str(static["active_controls"]) + " active), " + str(static["active_checks"]) + " active acceptance checks. " +
             ("The selected static scope completed." if static["selected_scope_complete"] else "The selected static scope is incomplete.") + " Recorded coverage gaps: " + str(static["coverage_gaps"]) + ".", "",
             "**Mapping formula:** " + md(static["mapping_reach_formula"]), "",
             "**AI answer formula:** " + md(ai["answer_coverage_formula"]), "",
             "**Optional AI:** " + ("enabled" if ai["enabled"] else "disabled") + "; finding stage " + md(ai["finding_review_status"]) + "; control stage " + md(ai["control_review_status"]) + ".", "",
             "| Advisory check outcome | Count |", "|---|---:|"]
    for state, count in ai["check_outcomes"].items():
        lines.append("| " + md(state) + " | " + str(count) + " |")
    lines += ["", md(ai["interpretation"]), "", md(scoring["exclusions"]), "", md(scoring["gate"]), ""]
    return lines


def methodology_markdown(report):
    from .methodology import build_methodology
    method = report.get("methodology") or build_methodology(report)
    catalog = method["catalog"]
    lines = ["## Methods, configuration and blind spots", "", md(method["purpose"]), "",
             "| Selected scope measure | Count |", "|---|---:|",
             f"| Selected deterministic rules | {catalog['rules']} |",
             f"| Selected controls with partial static mapping | {catalog['statically_mapped_controls']} |",
             f"| Selected controls without static mapping | {catalog['controls_without_static_mapping']} |",
             f"| Selected acceptance checks | {catalog['checks']} |",
             f"| Rules available in the full catalog | {catalog.get('available_rules', catalog['rules'])} |",
             f"| Controls available in the full catalog | {catalog.get('available_controls', catalog['controls'])} |", "", md(method["interpretation"]), "",
             "### How the layers operate", ""]
    lines += [str(index) + ". " + md(step) for index, step in enumerate(method["workflow"], 1)]
    lines += ["", "### What each layer can and cannot establish", ""]
    for area in method["areas"]:
        lines += ["#### " + md(area["area"]), "", "**Deterministic:** " + md(area["deterministic"]), "",
                  "**Optional model review:** " + md(area["optional_review"]), "",
                  "**Can miss or misclassify:** " + md(area["can_miss_or_misclassify"]), "",
                  "**Runtime/human evidence:** " + md(area["runtime_or_human_validation"]), ""]
    lines += ["### Recorded scan configuration", "",
              "These are settings and limits, not proof of completed coverage. Current CLI flags select a fresh scan; imported reports do not execute commands, select targets, restore credentials or enable model review.", "",
              codeblock(json.dumps({"source_and_packaged_file_scope": report.get("configuration", {}),
                                   "invocation": report.get("run_configuration", {}),
                                   "image_limits": report.get("image", {}).get("limits", {})}, indent=2, sort_keys=True, ensure_ascii=True)), ""]
    if report.get("export_errors"):
        lines += ["**Report export incomplete:**", "", codeblock(json.dumps(report["export_errors"], indent=2)), ""]
    return lines


def workspace_markdown(report):
    from .review_workspace import build_workspace
    if report.get("review_workspace_unavailable"):
        return ["## Editable review and fresh scan", "", "**Editable review unavailable:** " +
                md(report["review_workspace_unavailable"]["reason"]), "",
                "The complete static findings are retained. Narrow the explicitly selected scan scope to create a bounded editable report. No partial review capsule is exported.", ""]
    workspace = report.get("review_workspace") or build_workspace(report)
    raw = json.dumps(workspace, indent=2, sort_keys=True, ensure_ascii=True).replace("<", "\\u003c").replace(">", "\\u003e")
    # Encode Markdown link delimiters only inside JSON strings. Structural array
    # brackets remain intact and decoding preserves the exact evidence subjects.
    raw = re.sub(r'"(?:\\.|[^"\\])*"',
                 lambda match: match.group().replace("[", "\\u005b").replace("]", "\\u005d"), raw)
    fence = "`" * max(3, max((len(m.group()) + 1 for m in re.finditer(r"`+", raw)), default=3))
    lines = ["## Editable review and fresh scan", "",
             "Edit only decision, reason, reviewer, reviewed_at and evidence_ref in the JSON block below. Keep IDs, bindings, subjects and origin unchanged. Save this Markdown file and pass it to a fresh scan with --review-report. JSON and SARIF expose the same editable fields; HTML provides a Download reviewed HTML button and optional PDF provides fillable fields.", "",
             "Allowed decisions: empty (no decision), justified, disabled, note, needs_runtime_validation, needs_human_review. Nonempty decisions need a reason; justified/disabled decisions also need a reviewer. Evidence references are plain text, never fetched or executed. Gap records cannot waive scan failures.", "",
             "Justifications are user exceptions, not validated passes. They are excluded from active counts without positive or negative credit. Evidence changes leave decisions unapplied and visible for re-review. Explicit pending runtime/human validation remains incomplete. A finding not detected on a fresh complete scan is not proof that a vulnerability was fixed.", "",
             "Example: invscan /explicit/path/to/repository --review-report ./reviewed-report.md --output ./new-report", ""]
    if report.get("review_import"):
        lines += ["### Imported review audit", "", codeblock(json.dumps(report["review_import"], indent=2, sort_keys=True, ensure_ascii=True)), ""]
    lines += ["### Review fields", "", "<!-- INVARUNE_REVIEW_BEGIN -->", fence + "json", raw,
              fence, "<!-- INVARUNE_REVIEW_END -->", ""]
    return lines


def token_optimization_markdown(report):
    requests = []
    finding = report.get("judge", {}).get("token_optimization")
    if isinstance(finding, dict) and finding:
        requests.append(("Finding triage", finding))
    for index, request in enumerate(report.get("analyst", {}).get("requests", []), 1):
        if isinstance(request.get("token_optimization"), dict) and request["token_optimization"]:
            requests.append(("Control request " + str(index), request["token_optimization"]))
    if not requests:
        return []
    lines = ["### Evidence-JSON optimization", "",
             "All evidence values and exact source/citation strings are preserved. These byte counts exclude instructions, response schemas and provider wrappers; tokenizer savings and billing reductions were not measured.", "",
             "| Request | Requested | Actual engine | Status / fallback | Before bytes | After bytes | Bytes saved |",
             "|---|---|---|---|---:|---:|---:|"]
    for label, item in requests:
        values = [label, item.get("requested", "unknown"), item.get("engine", "unknown"),
                  str(item.get("status", "unknown")) + (" / " + str(item["fallback_reason"]) if item.get("fallback_reason") else ""),
                  item.get("payload_bytes_before", 0), item.get("payload_bytes_after", 0), item.get("bytes_saved", 0)]
        lines.append("| " + " | ".join(md(str(value)) for value in values) + " |")
    return lines + [""]


def markdown(report):
    summary = report["summary"]
    assessment = report.get("assessment") or build_assessment(report)
    lines = ["# " + md(report["tool"].get("display_name", DISPLAY_NAME)), "", "AI agent, MCP and skill security report", "", f"Scan ID: `{report['scan_id']}`", "", "This is static security triage, not certification or proof that a system is secure.", ""]
    lines += ["## Contents", "", "- [Summary and immediate concerns](#executive-assessment)",
              "- [Metrics and calculation](#metrics-and-how-they-are-calculated)",
              "- [Methods, configuration and blind spots](#methods-configuration-and-blind-spots)",
              "- [Editable review and fresh scan](#editable-review-and-fresh-scan)",
              "- [Scan details](#scan-details)", ""]
    lines += executive_markdown(report, assessment)
    lines += scoring_markdown(report)
    lines += review_policy_markdown(report)
    lines += methodology_markdown(report)
    lines += ["## Scan details", "", f"Scanned **{summary['files_scanned']} files**; **{summary['open_findings']} open findings**, **{summary['suppressed_findings']} suppressed findings**, and **{summary['coverage_gaps']} coverage gaps**.", "", "| Critical | High | Medium | Low | Info |", "|---:|---:|---:|---:|---:|"]
    lines.append("| " + " | ".join(str(summary["severity_counts"][s]) for s in ("critical", "high", "medium", "low", "info")) + " |")
    if "bytes_charged" in summary:
        lines += ["", f"Source I/O: **{summary['bytes_read']} bytes read**, **{summary['bytes_charged']} bytes charged** against the budget, including **{summary['failed_read_bytes_charged']} conservatively charged bytes** for failed reads. Each read reserves a sentinel byte to detect growth."]
    if report["coverage"].get("analysis_profiles"):
        lines += ["", "### Analysis depth", "", "File counts describe inspected inputs, not complete semantic coverage. Syntax/read failures remain listed as coverage gaps.", "", "| Profile | Files | Analysis scope |", "|---|---:|---|"]
        for name, profile in sorted(report["coverage"]["analysis_profiles"].items()):
            if profile["files"]:
                lines.append(f"| {md(name)} | {profile['files']} | {md(profile['scope'])} |")
    if report.get("execution"):
        execution = report["execution"]
        lines += ["", f"Severity failure threshold: **{md(execution['failure_threshold'])}** · Process exit code: **{execution['exit_code']}**."]
    if report.get("image"):
        container = report["image"]
        identity = container["identity"]
        lines += ["", "## Container image", "",
                  f"Input: **{md(container['display_target'])}** · Format: **{md(identity.get('format', 'unknown'))}** · Platform: **{md(identity.get('platform', 'unknown'))}**.", "",
                  "Image config digest: " + md(identity.get("config_digest", "unknown")), "",
                  "Analysis scope: **" + md(container.get("analysis_scope", "unknown")) + "** · Packaged source files inspected: **" + str(container.get("packaged_source_files_inspected", 0)) + "**.", "",
                  "The container was not started. Paths under `rootfs/` refer to the image filesystem; `.image-metadata/` contains generated evidence from the image configuration, history, and retained layers. Packaged supported code is inspected directly. Native binary logic is not decompiled, and package inventory is not a CVE scan.", "",
                  "Image inventory:", "", codeblock(json.dumps(container.get("inventory", {}), indent=2, sort_keys=True, ensure_ascii=True)), ""]
    analyst = report.get("analyst", {})
    analyst_controls = {}
    if analyst.get("enabled"):
        coverage = analyst["coverage"]
        analyst_controls = {item["control_id"]: item for item in analyst["control_assessments"]}
        lines += ["", "### Advisory security analyst", "",
                  f"Review status: **{md(analyst['status'])}** · Controls reviewed: **{coverage['reviewed_controls']}/{coverage['total_controls']}** · Unanswered checks: **{coverage['omitted_checks']}** · Control requests: **{coverage['calls_made']}/{coverage['call_budget']}**.", "",
                  "Every active control is routed for review because static patterns cannot establish completion. Review completion means an answer was received for every active check; it does not mean the checks passed. User-justified and disabled checks are excluded from review counts. The model is nondeterministic. Evidence selection, schema checks, and exact-quote validation are deterministic. Runtime execution and model tools are disabled.", "",
                  "| Advisory check status | Count |", "|---|---:|"]
        for status, count in analyst.get("check_status_counts", {}).items():
            lines.append(f"| {md(status)} | {count} |")
        if analyst.get("investigation"):
            investigation = analyst["investigation"]
            lines += ["", "### Bounded evidence investigation", "",
                      "The model may request exact ranges from verified, redacted snapshots; the controller enforces file IDs, scope, shared budgets and quote validation. No target tools or code execute. Requests do not resolve runtime uncertainty.", "",
                      "Follow-up rounds: **{}**; requests served / denied: **{} / {}**; captured files offered: **{}**.".format(investigation.get("rounds_completed", 0), investigation.get("requests_served", 0), investigation.get("requests_denied", 0), investigation.get("snapshot_files_offered", 0)), "",
                      codeblock(json.dumps(investigation, indent=2, sort_keys=True, ensure_ascii=True)), ""]
    lines += ["", "A clean pattern scan is not a control pass. Validate applicability and exploitability before remediation; runtime and manual checks remain required.", "", "## Findings", ""]
    if not report["findings"]:
        lines.append("No configured risk patterns were detected in the selected files.")
    for f in report["findings"]:
        lines += [f'<a id="{finding_anchor(f["id"])}"></a>', ""]
        lines += [f"### {md(f['rule_id'])} — {md(f['title'])}", "", f"**{md(f['severity'].upper())}** · Confidence: {md(f['confidence'])} · Status: {md(f['status'])}", "", f"Location: {md(f['path'])}:{f['line']}–{f.get('end_line', f['line'])} · Finding ID: `{f['id']}`", "", md(f["description"]), "", codeblock(f.get("evidence", "")), "", "**Remediation:** " + md(f["remediation"]), ""]
        lines += remediation_markdown(report.get("remediation", {}).get(f["id"]))
        for advisory in report.get("judge", {}).get("assessments", []):
            if advisory.get("finding_id") == f["id"]:
                lines += ["**Optional finding review:** " + md(advisory["verdict"]) + ". " + md(advisory["reason"]), ""]
                lines += recommended_actions_markdown(advisory.get("recommended_actions"))
        if f.get("suppression_reason"):
            lines += ["**Suppression reason:** " + md(f["suppression_reason"]), ""]
        if f.get("disposition"):
            disposition = f["disposition"]
            lines += ["**User decision:** " + md(disposition["status"]) + " (" + md(disposition.get("scope", "rule")) + " " + md(disposition.get("id", f["rule_id"])) + "). **Reason:** " + md(disposition.get("reason", "No reason supplied.")), "",
                      "This observed pattern is retained for audit and excluded from active findings and the severity gate. Its recorded severity and evidence are unchanged; the user decision does not prove remediation.", ""]
        if f.get("image_context"):
            lines += ["Image evidence context: **" + md(f["image_context"]) + "**. Provenance: " + md(json.dumps(f.get("image_provenance", {}), sort_keys=True)), ""]
        if f.get("cwe"):
            lines += ["Weakness mappings: " + ", ".join(md(c) for c in f["cwe"]), ""]
        for url in f.get("references", []):
            if url.startswith("https://"):
                lines.append(f"- [Reference]({quote(url, safe=':/#?=&%')})")
        lines.append("")
    lines += ["## Control checklist and coverage", "", "These are project-defined checks mapped to published guidance. They are not official benchmark scores. `no_pattern_detected` means only that the mapped detector did not fire. `findings_detected` requires investigation, not an automatic compliance failure.", ""]
    for c in report["controls"]:
        lines += [f"### {md(c['id'])}: {md(c['title'])}", "", f"Category: {md(c['category'])} · Status: {md(c['status'])} · Validation: {md(c['validation'])}", "", md(c["assurance"]), ""]
        dispositions = {item["check_index"]: item for item in c.get("check_dispositions", [])}
        if c.get("static_status") and c["static_status"] != c["status"]:
            lines += ["Underlying static status: " + md(c["static_status"]) + ". The user decision does not change detector evidence.", ""]
        for index, check in enumerate(c.get("checks", []), 1):
            disposition = dispositions.get(index, {})
            if disposition.get("status") in ("justified", "disabled"):
                lines.append("- **" + md(disposition["status"]) + "** · " + md(disposition.get("check_id", c["id"] + ":" + str(index))) + ": " + md(check) + " — User reason: " + md(disposition.get("reason", "No reason supplied.")))
            else:
                lines.append("- [ ] " + md(check))
        if c["automated_rule_ids"]:
            lines += ["", "Partial static rules: " + ", ".join(md(r) for r in c["automated_rule_ids"])]
        if c["finding_ids"]:
            lines += ["", "Open finding IDs: " + ", ".join(c["finding_ids"])]
        if c.get("suppressed_finding_ids"):
            lines += ["", "Suppressed finding IDs: " + ", ".join(c["suppressed_finding_ids"])]
        for status in ("justified", "disabled"):
            if c.get(status + "_finding_ids"):
                lines += ["", status.capitalize() + " finding IDs: " + ", ".join(md(identifier) for identifier in c[status + "_finding_ids"])]
        if c["id"] in analyst_controls:
            assessment = analyst_controls[c["id"]]
            lines += ["", f"**Advisory analyst:** {md(assessment['review_status'])}. Deterministic control status remains {md(c['status'])}.", ""]
            for check in assessment["check_assessments"]:
                lines += [f"**Check {check['check_index']}: {md(check['status'])}**", "",
                          md(check["reason"]), ""]
                lines += recommended_actions_markdown(check.get("recommended_actions"))
                for key, label in (("risk_hypothesis", "Risk hypothesis"), ("boundary", "Trust boundary"),
                                   ("counterevidence", "Counterevidence considered"), ("conclusion_limits", "Conclusion limits")):
                    if check.get("analysis", {}).get(key):
                        lines += ["**" + label + ":** " + md(check["analysis"][key]), ""]
                if check["status"] in ("justified", "disabled"):
                    lines += ["User decision; excluded from optional review and active check totals.", ""]
                elif not check.get("model_supplied", False):
                    lines += ["No model assessment was received for this check.", ""]
                for citation in check["citations"]:
                    lines += [f"Evidence {md(citation['evidence_id'])}: {md(citation['path'])}:{citation['start_line']}–{citation['end_line']} (exact quote verified).",
                              "", codeblock(citation["quote"]), ""]
                if check.get("verification_steps"):
                    lines.append("Verification still required:")
                for step in check.get("verification_steps", []):
                    lines.append("- " + md(step))
                lines.append("")
        for url in c.get("sources", []):
            if url.startswith("https://"):
                lines.append(f"- [Source]({quote(url, safe=':/#?=&%')})")
        lines.append("")
    lines += ["## Coverage and limitations", ""]
    for limitation in report["coverage"]["limitations"]:
        lines.append("- " + md(limitation))
    lines += ["", "### Inventory", "", f"Dependency manifests: {len(report['inventory']['dependency_manifests'])}; agent/MCP signal files: {len(report['inventory']['agent_mcp_signals'])}.", "", "Dependency manifests are inventoried, not checked against a vulnerability database.", "", "### Scan errors", ""]
    for error in report["coverage"]["errors"]:
        lines.append(f"- {md(error['path'])}: {md(error['error'])}")
    if not report["coverage"]["errors"]:
        lines.append("None.")
    lines += ["", "### Excluded or skipped paths", "", "| Path | Reason | Coverage gap |", "|---|---|---|"]
    for s in report["coverage"]["skipped"]:
        lines.append(f"| {md(s['path'])} | {md(s['reason'])} | {'yes' if s['coverage_gap'] else 'outside scope'} |")
    if report["coverage"]["unmatched_baseline_ids"]:
        lines += ["", "Unused baseline IDs: " + ", ".join(md(i) for i in report["coverage"]["unmatched_baseline_ids"])]
    lines += ["", "## Optional LLM judge", ""]
    lines += token_optimization_markdown(report)
    judge = report["judge"]
    if not judge.get("enabled"):
        lines.append("Disabled. No LLM request was made.")
    else:
        lines += ["Advisory, non-deterministic output. It cannot dismiss deterministic findings, establish compliance, or change the deterministic CI gate.", "", codeblock(json.dumps(judge, indent=2, sort_keys=True, ensure_ascii=True))]
        concern_actions = {item["concern_index"]: item["recommended_actions"] for item in judge.get("additional_concern_actions", [])}
        for index, concern in enumerate(judge.get("additional_concerns", []), 1):
            lines += ["### Additional model concern " + str(index) + " (unverified)", "", md(concern), ""]
            lines += recommended_actions_markdown(concern_actions.get(index))
    if analyst.get("enabled"):
        lines += ["", "## Analyst evidence and request audit", "",
                  "Only bounded excerpts were submitted. Missing evidence may reflect collection limits, exclusions, or retrieval misses. A verified quote establishes its presence in an excerpt, not the truth of the model's interpretation. Verification steps are proposals and have not been executed.", "",
                  "Evidence selection and review coverage:", "", codeblock(json.dumps(analyst["coverage"], indent=2, sort_keys=True, ensure_ascii=True)), ""]
        for error in analyst.get("errors", []):
            lines += ["- Analyst error: " + md(error)]
        lines += ["", "Request receipts (payload hashes and model identifiers):", "",
                  codeblock(json.dumps(analyst["requests"], indent=2, sort_keys=True, ensure_ascii=True)), "",
                  "The JSON report includes redacted evidence excerpts, original file hashes, complete per-check assessments, and deterministic provenance."]
    lines += workspace_markdown(report)
    return "\n".join(lines) + "\n"


def sarif(report):
    from .rules import RULES
    selected_rule_ids = set(report.get("configuration", {}).get("selected_rule_ids", [rule["id"] for rule in RULES]))
    descriptors = []
    for r in sorted(RULES, key=lambda r: r.get("id", r.get("rule_id", ""))):
        rid = r.get("id", r.get("rule_id"))
        if rid not in selected_rule_ids:
            continue
        descriptors.append({"id": rid, "shortDescription": {"text": r["title"]}, "fullDescription": {"text": r["description"]}, "help": {"text": r["remediation"]}, "properties": {"tags": ["security", r["category"]] + r.get("cwe", [])}})
    rule_index = {r["id"]: i for i, r in enumerate(descriptors)}
    results = []
    for f in report["findings"]:
        try:
            path_bytes = os.fsencode(f["path"])
        except UnicodeError:
            path_bytes = _unicode_text(f["path"]).encode("utf-8")
        item = {"ruleId": f["rule_id"], "ruleIndex": rule_index[f["rule_id"]], "level": "error" if f["severity"] in ("critical", "high") else "warning" if f["severity"] == "medium" else "note", "message": {"text": f["description"] + " Remediation: " + f["remediation"]}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": quote_from_bytes(path_bytes, safe="/")}, "region": {"startLine": max(1, f["line"]), "endLine": max(f["line"], f.get("end_line", f["line"]))}}}], "partialFingerprints": {"agentMcpScan/v1": f["id"]}, "properties": {"severity": f["severity"], "confidence": f["confidence"], "status": f["status"]}}
        advice = report.get("remediation", {}).get(f["id"])
        if advice:
            item["properties"]["agentMcpRemediation"] = advice
            item["message"]["text"] += " Agent/MCP relevance: " + advice["agent_mcp_relevance"] + " Fix steps: " + " ".join(
                str(index) + ". " + step["action"] + " Verify: " + step["verification"] for index, step in enumerate(advice["steps"], 1))
        if f["status"] == "suppressed":
            item["suppressions"] = [{"kind": "external", "status": "accepted", "justification": f["suppression_reason"]}]
        elif f["status"] in ("justified", "disabled"):
            disposition = f.get("disposition", {})
            item["suppressions"] = [{"kind": "external", "status": "accepted", "justification": disposition.get("reason") or "Disabled by user review configuration."}]
            item["properties"]["userDisposition"] = disposition
            item["properties"]["originalStatus"] = f.get("original_status", "open")
            if f.get("suppression_reason"):
                item["properties"]["baselineSuppressionReason"] = f["suppression_reason"]
        results.append(item)
    notifications = [{"level": "warning", "message": {"text": e["path"] + ": " + e["error"]}} for e in report["coverage"]["errors"]]
    notifications += [{"level": "warning", "message": {"text": s["path"] + ": " + s["reason"]}} for s in report["coverage"]["skipped"] if s["coverage_gap"]]
    run = {"tool": {"driver": {"name": report["tool"]["name"], "fullName": report["tool"].get("display_name", DISPLAY_NAME), "version": report["tool"]["version"], "rules": descriptors}}, "invocations": [{"executionSuccessful": report["summary"]["scan_complete_within_selected_scope"], "toolExecutionNotifications": notifications}], "results": results}
    from .review_workspace import build_workspace
    run["properties"] = ({"invarune_review_unavailable": report["review_workspace_unavailable"]}
                         if report.get("review_workspace_unavailable") else
                         {"invarune_review": report.get("review_workspace") or build_workspace(report)})
    scoring = report.get("scoring") or build_scoring(report)
    # SARIF remains a deterministic evidence artifact. Optional model judgments
    # belong in JSON/HTML/Markdown/PDF and cannot alter SARIF gate evidence.
    run["properties"]["invarune_metrics"] = {
        "schema_version": scoring["schema_version"], "overall_security_score": None,
        "overall_security_score_reason": scoring["overall_security_score_reason"],
        "deterministic": scoring["deterministic"], "exclusions": scoring["exclusions"], "gate": scoring["gate"],
    }
    if report.get("review_policy", {}).get("enabled"):
        run["properties"]["userReviewPolicy"] = report["review_policy"]
    if report.get("review_import"):
        run["properties"]["invarune_review_import"] = report["review_import"]
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [run]}


def atomic_write(path, text):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Refusing to overwrite a symbolic-link output")
    path.parent.mkdir(parents=True, exist_ok=True)
    if any(p.is_symlink() for p in [path.parent, *path.parent.parents]):
        # Resolve macOS /var aliases before passing paths to this function.
        raise ValueError("Output directory must not traverse symbolic links")
    fd, temporary = tempfile.mkstemp(prefix=".scan-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def prepare_report(report, *, include_workspace=True):
    """Derive all report interpretation in memory, without writing any files."""
    from .methodology import build_methodology
    from .remediation import build_remediation
    from .review_workspace import build_workspace, ReviewWorkspaceLimitError, MAX_ITEMS, MAX_WORKSPACE_BYTES
    report = {**report, "methodology": build_methodology(report), "remediation": build_remediation(report)}
    report["advice_coverage"] = advice_coverage(report)
    if include_workspace:
        try:
            report["review_workspace"] = build_workspace(report)
            report.pop("review_workspace_unavailable", None)
        except ReviewWorkspaceLimitError as exc:
            report.pop("review_workspace", None)
            report["review_workspace_unavailable"] = {"reason": str(exc), "max_items": MAX_ITEMS,
                                                       "max_workspace_bytes": MAX_WORKSPACE_BYTES}
            report["execution"] = {**report.get("execution", {"failure_threshold": "none"}), "exit_code": 2}
    else:
        report.pop("review_workspace", None)
        report.pop("review_workspace_unavailable", None)
    report["assessment"] = build_assessment(report)
    report["scoring"] = build_scoring(report)
    return report


def write_reports(report, output):
    output = Path(output)
    if output.is_symlink():
        raise ValueError("Report directory must not be a symbolic link")
    output = output.resolve()
    report = prepare_report(report)
    from .report_html import html_report
    atomic_write(output / "report.json", json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
    atomic_write(output / "report.md", markdown(report))
    atomic_write(output / "report.sarif", json.dumps(sarif(report), indent=2, sort_keys=True, ensure_ascii=True) + "\n")
    atomic_write(output / "report.html", html_report(report))
    return report
