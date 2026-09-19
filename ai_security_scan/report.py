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


def finding_anchor(identifier):
    return "finding-" + hashlib.sha256(_unicode_text(identifier).encode("utf-8")).hexdigest()[:16]


def review_policy_markdown(report):
    policy = report.get("review_policy", {})
    if not policy.get("enabled"):
        return []
    counts = policy.get("counts", {})
    lines = ["## User review decisions", "",
             "`justified` records the user's rationale; `disabled` excludes a check from active assessment. Neither state means pass, earns positive credit, or counts against active totals. Observed evidence remains available. Only rule decisions exclude related findings from the severity gate; control and individual-check decisions affect checklist review only. Scan errors and coverage gaps remain unresolved.", "",
             "| Scope | Active | Justified | Disabled | Excluded with mixed check decisions | Catalog total |",
             "|---|---:|---:|---:|---:|---:|"]
    for scope in ("rules", "controls", "checks"):
        lines.append(f"| {scope.capitalize()} | {counts.get('active_' + scope, 0)} | {counts.get('justified_' + scope, 0)} | {counts.get('disabled_' + scope, 0)} | {counts.get('mixed_excluded_controls', 0) if scope == 'controls' else 0} | {counts.get('catalog_' + scope, 0)} |")
    lines += ["", "### Configured decisions and reasons", "", "| Scope | Identifier | Decision | User reason |", "|---|---|---|---|"]
    for scope in ("rules", "controls", "checks"):
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


def markdown(report):
    summary = report["summary"]
    assessment = report.get("assessment") or build_assessment(report)
    lines = ["# " + md(report["tool"].get("display_name", DISPLAY_NAME)), "", "AI agent and MCP security report", "", f"Scan ID: `{report['scan_id']}`", "", "This is static security triage, not certification or proof that a system is secure.", ""]
    lines += executive_markdown(report, assessment)
    lines += review_policy_markdown(report)
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
    lines += ["", "A clean pattern scan is not a control pass. Validate applicability and exploitability before remediation; runtime and manual checks remain required.", "", "## Findings", ""]
    if not report["findings"]:
        lines.append("No configured risk patterns were detected in the selected files.")
    for f in report["findings"]:
        lines += [f'<a id="{finding_anchor(f["id"])}"></a>', ""]
        lines += [f"### {md(f['rule_id'])} — {md(f['title'])}", "", f"**{md(f['severity'].upper())}** · Confidence: {md(f['confidence'])} · Status: {md(f['status'])}", "", f"Location: {md(f['path'])}:{f['line']}–{f.get('end_line', f['line'])} · Finding ID: `{f['id']}`", "", md(f["description"]), "", codeblock(f.get("evidence", "")), "", "**Remediation:** " + md(f["remediation"]), ""]
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
    judge = report["judge"]
    if not judge.get("enabled"):
        lines.append("Disabled. No LLM request was made.")
    else:
        lines += ["Advisory, non-deterministic output. It cannot dismiss deterministic findings, establish compliance, or change the deterministic CI gate.", "", codeblock(json.dumps(judge, indent=2, sort_keys=True, ensure_ascii=True))]
    if analyst.get("enabled"):
        lines += ["", "## Analyst evidence and request audit", "",
                  "Only bounded excerpts were submitted. Missing evidence may reflect collection limits, exclusions, or retrieval misses. A verified quote establishes its presence in an excerpt, not the truth of the model's interpretation. Verification steps are proposals and have not been executed.", "",
                  "Evidence selection and review coverage:", "", codeblock(json.dumps(analyst["coverage"], indent=2, sort_keys=True, ensure_ascii=True)), ""]
        for error in analyst.get("errors", []):
            lines += ["- Analyst error: " + md(error)]
        lines += ["", "Request receipts (payload hashes and model identifiers):", "",
                  codeblock(json.dumps(analyst["requests"], indent=2, sort_keys=True, ensure_ascii=True)), "",
                  "The JSON report includes redacted evidence excerpts, original file hashes, complete per-check assessments, and deterministic provenance."]
    return "\n".join(lines) + "\n"


def sarif(report):
    from .rules import RULES
    descriptors = []
    for r in sorted(RULES, key=lambda r: r.get("id", r.get("rule_id", ""))):
        rid = r.get("id", r.get("rule_id"))
        descriptors.append({"id": rid, "shortDescription": {"text": r["title"]}, "fullDescription": {"text": r["description"]}, "help": {"text": r["remediation"]}, "properties": {"tags": ["security", r["category"]] + r.get("cwe", [])}})
    rule_index = {r["id"]: i for i, r in enumerate(descriptors)}
    results = []
    for f in report["findings"]:
        try:
            path_bytes = os.fsencode(f["path"])
        except UnicodeError:
            path_bytes = _unicode_text(f["path"]).encode("utf-8")
        item = {"ruleId": f["rule_id"], "ruleIndex": rule_index[f["rule_id"]], "level": "error" if f["severity"] in ("critical", "high") else "warning" if f["severity"] == "medium" else "note", "message": {"text": f["description"] + " Remediation: " + f["remediation"]}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": quote_from_bytes(path_bytes, safe="/")}, "region": {"startLine": max(1, f["line"]), "endLine": max(f["line"], f.get("end_line", f["line"]))}}}], "partialFingerprints": {"agentMcpScan/v1": f["id"]}, "properties": {"severity": f["severity"], "confidence": f["confidence"], "status": f["status"]}}
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
    if report.get("review_policy", {}).get("enabled"):
        run["properties"] = {"userReviewPolicy": report["review_policy"]}
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


def write_reports(report, output):
    output = Path(output)
    if output.is_symlink():
        raise ValueError("Report directory must not be a symbolic link")
    output = output.resolve()
    report = {**report, "assessment": build_assessment(report)}
    from .report_html import html_report
    atomic_write(output / "report.json", json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
    atomic_write(output / "report.md", markdown(report))
    atomic_write(output / "report.sarif", json.dumps(sarif(report), indent=2, sort_keys=True, ensure_ascii=True) + "\n")
    atomic_write(output / "report.html", html_report(report))
    return report
