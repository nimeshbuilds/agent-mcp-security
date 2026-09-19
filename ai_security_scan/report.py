"""Portable JSON, Markdown, and SARIF output; repository strings are escaped."""
import html
import json
import os
import re
import tempfile
from pathlib import Path
from urllib.parse import quote


def md(value):
    text = html.escape(str(value), quote=False).replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\`*_{\[\]}()#+.!|>~-])", r"\\\1", text)


def codeblock(value):
    text = str(value)
    longest = max((len(m.group()) for m in re.finditer(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{text}\n{fence}"


def markdown(report):
    summary = report["summary"]
    lines = ["# AI agent and MCP security scan", "", f"Scan ID: `{report['scan_id']}`", "", "This is static security triage, not certification or proof that a system is secure.", "", "## Summary", "", f"Scanned **{summary['files_scanned']} files**; **{summary['open_findings']} open findings**, **{summary['suppressed_findings']} suppressed findings**, and **{summary['coverage_gaps']} coverage gaps**.", "", "| Critical | High | Medium | Low | Info |", "|---:|---:|---:|---:|---:|"]
    lines.append("| " + " | ".join(str(summary["severity_counts"][s]) for s in ("critical", "high", "medium", "low", "info")) + " |")
    if report.get("execution"):
        execution = report["execution"]
        lines += ["", f"Severity failure threshold: **{md(execution['failure_threshold'])}** · Process exit code: **{execution['exit_code']}**."]
    lines += ["", "A clean pattern scan is not a control pass. Validate applicability and exploitability before remediation; runtime and manual checks remain required.", "", "## Findings", ""]
    if not report["findings"]:
        lines.append("No configured risk patterns were detected in the selected files.")
    for f in report["findings"]:
        lines += [f"### {md(f['rule_id'])} — {md(f['title'])}", "", f"**{md(f['severity'].upper())}** · Confidence: {md(f['confidence'])} · Status: {md(f['status'])}", "", f"Location: {md(f['path'])}:{f['line']}–{f.get('end_line', f['line'])} · Finding ID: `{f['id']}`", "", md(f["description"]), "", codeblock(f.get("evidence", "")), "", "**Remediation:** " + md(f["remediation"]), ""]
        if f.get("suppression_reason"):
            lines += ["**Suppression reason:** " + md(f["suppression_reason"]), ""]
        if f.get("cwe"):
            lines += ["Weakness mappings: " + ", ".join(md(c) for c in f["cwe"]), ""]
        for url in f.get("references", []):
            if url.startswith("https://"):
                lines.append(f"- [Reference]({quote(url, safe=':/#?=&%')})")
        lines.append("")
    lines += ["## Control checklist and coverage", "", "These are project-defined checks mapped to published guidance. They are not official benchmark scores. `no_pattern_detected` means only that the mapped detector did not fire. `findings_detected` requires investigation, not an automatic compliance failure.", ""]
    for c in report["controls"]:
        lines += [f"### {md(c['id'])}: {md(c['title'])}", "", f"Category: {md(c['category'])} · Status: {md(c['status'])} · Validation: {md(c['validation'])}", "", md(c["assurance"]), ""]
        for check in c.get("checks", []):
            lines.append("- [ ] " + md(check))
        if c["automated_rule_ids"]:
            lines += ["", "Partial static rules: " + ", ".join(md(r) for r in c["automated_rule_ids"])]
        if c["finding_ids"]:
            lines += ["", "Open finding IDs: " + ", ".join(c["finding_ids"])]
        if c.get("suppressed_finding_ids"):
            lines += ["", "Suppressed finding IDs: " + ", ".join(c["suppressed_finding_ids"])]
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
        item = {"ruleId": f["rule_id"], "ruleIndex": rule_index[f["rule_id"]], "level": "error" if f["severity"] in ("critical", "high") else "warning" if f["severity"] == "medium" else "note", "message": {"text": f["description"] + " Remediation: " + f["remediation"]}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": quote(f["path"], safe="/")}, "region": {"startLine": max(1, f["line"]), "endLine": max(f["line"], f.get("end_line", f["line"]))}}}], "partialFingerprints": {"agentMcpScan/v1": f["id"]}, "properties": {"severity": f["severity"], "confidence": f["confidence"], "status": f["status"]}}
        if f["status"] == "suppressed":
            item["suppressions"] = [{"kind": "external", "status": "accepted", "justification": f["suppression_reason"]}]
        results.append(item)
    notifications = [{"level": "warning", "message": {"text": e["path"] + ": " + e["error"]}} for e in report["coverage"]["errors"]]
    notifications += [{"level": "warning", "message": {"text": s["path"] + ": " + s["reason"]}} for s in report["coverage"]["skipped"] if s["coverage_gap"]]
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": report["tool"]["name"], "version": report["tool"]["version"], "rules": descriptors}}, "invocations": [{"executionSuccessful": report["summary"]["scan_complete_within_selected_scope"], "toolExecutionNotifications": notifications}], "results": results}]}


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
    atomic_write(output / "report.json", json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
    atomic_write(output / "report.md", markdown(report))
    atomic_write(output / "report.sarif", json.dumps(sarif(report), indent=2, sort_keys=True, ensure_ascii=True) + "\n")
