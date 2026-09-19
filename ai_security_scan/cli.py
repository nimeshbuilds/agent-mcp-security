import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

from . import __version__
from .fs import read_confined
from .report import atomic_write, write_reports
from .scanner import SEVERITIES, load_baseline, load_controls, scan
from .security import redact, redact_object


class HelpFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    """Keep examples readable while displaying configurable defaults."""


def parser():
    p = argparse.ArgumentParser(
        description="Read-only AI agent and MCP source security scan. Offline unless --judge-config is provided.\n"
                    "Static findings are review signals; a clean scan does not establish security or compliance.",
        allow_abbrev=False, formatter_class=HelpFormatter,
        epilog="""Examples:
  ai-security-scan ./repository --output ./reports
  ai-security-scan ./repository --summary-json --fail-on medium
  ai-security-scan ./repository --quiet --exclude 'tests/*'
  ai-security-scan --explain-rule AI002
  ai-security-scan ./repository --judge-config ./trusted-judge.json
  ai-security-scan ./repository --write-baseline ./accepted.json --baseline-reason 'Reviewed exception'

Exit codes:
  0  Selected scan scope completed and the configured finding gate did not trigger.
  1  Open deterministic findings meet the configured severity threshold.
  2  Invalid input, operational failure, incomplete scan, or incomplete optional review.
     Incompleteness takes precedence over the finding gate, including --fail-on none.

Every completed scan writes report.json, report.md, and report.sarif.
An accepted baseline records review decisions; it does not establish that findings are safe.
Optional LLM judgments remain advisory and cannot suppress deterministic findings.
""")
    p.add_argument("target", nargs="?", help="Repository directory to inspect")
    scope = p.add_argument_group("Scan scope and resource limits")
    scope.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="Additional relative-path exclusion; repeatable")
    scope.add_argument("--max-file-bytes", type=int, default=1_000_000, help="Maximum bytes in one source file; larger files create a coverage gap")
    scope.add_argument("--max-total-bytes", type=int, default=50_000_000, help="Total file-read budget, including rejected/failed reads and growth detection")
    scope.add_argument("--max-files", type=int, default=20_000, help="Maximum source/configuration files to scan")
    scope.add_argument("--max-entries", type=int, default=100_000, help="Maximum traversed file/directory entries")
    output = p.add_argument_group("Reports and CI output")
    output.add_argument("--output", default="scan-report", help="Directory for JSON, Markdown, and SARIF reports")
    display = output.add_mutually_exclusive_group()
    display.add_argument("--quiet", action="store_true", help="Suppress scan progress and human summaries; errors remain on stderr")
    display.add_argument("--summary-json", action="store_true", help="Write one JSON summary to stdout; diagnostics remain on stderr")
    output.add_argument("--fail-on", choices=SEVERITIES + ("none",), default="high", help="Fail on open findings at or above this severity; none disables only this gate")
    baseline = p.add_argument_group("Reviewed finding baselines")
    baseline.add_argument("--baseline", help="Explicitly accepted finding IDs with justification")
    baseline.add_argument("--write-baseline", metavar="PATH", help="Write a baseline candidate; does not suppress this scan")
    baseline.add_argument("--baseline-reason", help="Required justification for --write-baseline")
    judge = p.add_argument_group("Optional advisory LLM review (disabled by default)")
    judge.add_argument("--judge-config", help="Opt in to sending a bounded, redacted assessment payload to this configured LLM endpoint")
    judge.add_argument("--judge-mode", choices=("full", "findings"), default="full", help="Full control analyst plus finding triage, or finding triage only")
    judge.add_argument("--judge-include-source", action="store_true", help="Add neighboring source to finding triage; full analyst separately sends bounded source excerpts")
    judge.add_argument("--judge-max-findings", type=int, default=100, help="Maximum open findings sent to finding triage (1-500)")
    judge.add_argument("--analyst-max-calls", type=int, default=12, help="Control analyst request budget (0-100); finding triage uses one additional request")
    judge.add_argument("--analyst-batch-size", type=int, default=6, help="Controls per analyst request (1-20)")
    judge.add_argument("--analyst-max-files", type=int, default=200, help="Maximum scanned files to read for analyst evidence")
    judge.add_argument("--analyst-max-bytes", type=int, default=2_000_000, help="Maximum source bytes to read for analyst evidence")
    judge.add_argument("--analyst-max-chars", type=int, default=120_000, help="Maximum redacted source characters retained for analyst evidence")
    judge.add_argument("--analyst-time-budget", type=float, default=180, help="Control analyst scheduling/time budget in seconds; not a hard process deadline")
    catalog = p.add_argument_group("Catalog inspection (no scan or network)")
    mode = catalog.add_mutually_exclusive_group()
    mode.add_argument("--list-rules", action="store_true", help="Print all deterministic rule metadata as JSON")
    mode.add_argument("--list-controls", action="store_true", help="Print all control checks, rule mappings, and sources as JSON")
    mode.add_argument("--explain-rule", metavar="ID", help="Print one rule's metadata, mapped controls, and interpretation as JSON")
    p.add_argument("--version", action="version", version=__version__)
    return p


def _rule_explanation(rule_id):
    from .rules import RULE_BY_ID, RULESET_VERSION
    if rule_id not in RULE_BY_ID:
        raise ValueError("Unknown rule ID: " + rule_id + ". Use --list-rules to inspect available IDs.")
    controls = sorted((control for control in load_controls() if rule_id in control.get("automated_rule_ids", [])),
                      key=lambda control: control["id"])
    return {"schema_version": "1.0", "ruleset_version": RULESET_VERSION,
            "rule": RULE_BY_ID[rule_id], "mapped_control_ids": [control["id"] for control in controls],
            "mapped_controls": controls,
            "interpretation": "This deterministic rule identifies a source pattern for review. It does not prove exploitability or establish a mapped control's effectiveness. Absence of a finding is not a security or compliance pass."}


def _json_summary(report, target, report_paths):
    """Keep CI counts and scope tied to the exact report, without judging controls."""
    controls = report["controls"]
    judge = report.get("judge", {"enabled": False})
    analyst = report.get("analyst", {"enabled": False})
    judge_summary = {key: judge[key] for key in ("enabled", "status", "mode", "advisory_only", "selected_findings", "omitted_open_findings", "error") if key in judge}
    analyst_summary = {key: analyst[key] for key in ("enabled", "status", "advisory_only", "coverage") if key in analyst}
    return {"schema_version": "1.0", "type": "scan_summary", "status": "completed" if report["execution"]["exit_code"] != 2 else "incomplete",
            "tool": report["tool"], "scan_id": report["scan_id"], "summary": report["summary"],
            "scope": {"target": redact(str(target.resolve())), "configuration": report["configuration"]},
            "coverage": {**report["coverage"], "total_controls": len(controls),
                         "total_checks": sum(len(control.get("checks", [])) for control in controls),
                         "statically_mapped_controls": sum(bool(control.get("automated_rule_ids")) for control in controls),
                         "control_status_counts": dict(sorted(Counter(control["status"] for control in controls).items()))},
            "optional_review": {"judge": judge_summary, "analyst": analyst_summary},
            "execution": report["execution"], "exit_code": report["execution"]["exit_code"], "reports": report_paths}


def judge_payload(report, root, include_source=False, max_findings=100):
    selected = [f for f in report["findings"] if f["status"] == "open"][:max_findings]
    payload = {"scan_id": report["scan_id"], "summary": report["summary"], "limitations": report["coverage"]["limitations"], "findings": selected, "omitted_open_findings": report["summary"]["open_findings"] - len(selected), "source_context_included": include_source}
    if include_source:
        contexts = []
        hashes = {f["path"]: f["sha256"] for f in report["files"]}
        total = 0
        for f in selected:
            rel = Path(f["path"])
            # The root and all path components must still be confined and unsymlinked.
            path = root / rel
            if rel.is_absolute() or ".." in rel.parts or any(p.is_symlink() for p in [path, *path.parents]) or root not in path.resolve().parents:
                continue
            if path.name.startswith(".env") or path.suffix.lower() in {".pem", ".key"}:
                continue
            try:
                content, _ = read_confined(root, rel, report["configuration"]["max_file_bytes"])
                if hashlib.sha256(content).hexdigest() != hashes.get(f["path"]):
                    continue
                lines = content.decode("utf-8-sig").splitlines()
                start = max(0, f["line"] - 4)
                text = redact("\n".join(lines[start:min(len(lines), f["line"] + 3)]))[:3000]
                if total + len(text) > 30_000:
                    break
                contexts.append({"finding_id": f["id"], "path": f["path"], "start_line": start + 1, "text": text})
                total += len(text)
            except (OSError, UnicodeError):
                continue
        payload["source_context"] = contexts
    return redact_object(payload)


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    catalog_mode = args.list_rules or args.list_controls or args.explain_rule is not None
    if catalog_mode and args.target:
        p.error("catalog inspection does not accept a target directory")
    if catalog_mode and (args.quiet or args.summary_json):
        p.error("--quiet and --summary-json apply to scans; catalog commands already emit JSON")
    if args.list_rules:
        from .rules import RULES
        print(json.dumps(RULES, indent=2, sort_keys=True))
        return 0
    if args.list_controls:
        print(json.dumps(load_controls(), indent=2, sort_keys=True))
        return 0
    if args.explain_rule is not None:
        try:
            print(json.dumps(_rule_explanation(args.explain_rule), indent=2, sort_keys=True))
        except ValueError as exc:
            p.error(str(exc))
        return 0
    if not args.target:
        p.error("target directory is required")
    if args.judge_include_source and not args.judge_config:
        p.error("--judge-include-source requires --judge-config")
    if args.write_baseline and not (args.baseline_reason or "").strip():
        p.error("--write-baseline requires --baseline-reason with a justification")
    if not 1 <= args.judge_max_findings <= 500:
        p.error("--judge-max-findings must be between 1 and 500")
    analyst_limits = dict(max_calls=args.analyst_max_calls, batch_size=args.analyst_batch_size,
                          max_files=args.analyst_max_files, max_bytes=args.analyst_max_bytes,
                          max_chars=args.analyst_max_chars, max_seconds=args.analyst_time_budget)
    from .analyst import validate_limits
    try:
        validate_limits(**analyst_limits)
    except ValueError as exc:
        p.error(str(exc))
    output = Path(args.output).expanduser()
    target = Path(args.target).expanduser()
    if output.resolve() == target.resolve():
        p.error("--output must be separate from the repository root")
    exclusions = [output.absolute()]
    for name in (args.baseline, args.write_baseline, args.judge_config):
        if name:
            exclusions.append(Path(name).expanduser().absolute())
    report_paths = {}
    try:
        baseline = load_baseline(args.baseline) if args.baseline else None
        report = scan(target, exclude=args.exclude, output_paths=exclusions, max_file_bytes=args.max_file_bytes, max_total_bytes=args.max_total_bytes, max_files=args.max_files, max_entries=args.max_entries, baseline=baseline)
        report["analyst"] = {"enabled": False}
        if args.judge_config:
            from .judge import JudgeError, load_config, review, validate_analyst_config
            from .analyst import run_analyst, unreviewed_analyst
            scope_description = "findings and bounded source excerpts for every control" if args.judge_mode == "full" else "findings"
            if not args.quiet:
                print("Optional LLM review enabled: sending redacted " + scope_description + " to the configured endpoint. Redaction is best-effort.", file=sys.stderr)
            payload = judge_payload(report, target.resolve(), args.judge_include_source, args.judge_max_findings)
            judge_scope = {"omitted_open_findings": payload["omitted_open_findings"], "selected_findings": len(payload["findings"]), "source_context_sent_count": len(payload.get("source_context", []))}
            try:
                config = load_config(args.judge_config)
                if args.judge_mode == "full":
                    config = validate_analyst_config(config)
                result = review(config, payload)
                report["judge"] = {**redact_object(result), **judge_scope, "enabled": True, "status": "completed", "advisory_only": True, "source_context_requested": args.judge_include_source}
                if args.judge_mode == "full":
                    report["analyst"] = run_analyst(config, report, target.resolve(), **analyst_limits)
            except JudgeError as exc:
                report["judge"] = {**judge_scope, "enabled": True, "status": "error", "advisory_only": True, "error": redact(str(exc)) + " Deterministic results are preserved."}
                print("Optional LLM review error: " + redact(str(exc)) + " Deterministic results are preserved.", file=sys.stderr)
                if args.judge_mode == "full":
                    report["analyst"] = unreviewed_analyst(report, "Control review was not started because finding triage or judge configuration failed.", max_calls=args.analyst_max_calls)
            report["judge"]["mode"] = args.judge_mode
        gate_triggered = args.fail_on != "none" and any(f["status"] == "open" and SEVERITIES.index(f["severity"]) <= SEVERITIES.index(args.fail_on) for f in report["findings"])
        incomplete = (not report["summary"]["scan_complete_within_selected_scope"]
                      or report["judge"].get("status") == "error"
                      or report["analyst"].get("status") in {"error", "incomplete"})
        report["execution"] = {"failure_threshold": args.fail_on, "finding_gate_triggered": bool(gate_triggered), "exit_code": 2 if incomplete else 1 if gate_triggered else 0}
        write_reports(report, output)
        report_paths = {kind: str(output.resolve() / name) for kind, name in
                        (("json", "report.json"), ("markdown", "report.md"), ("sarif", "report.sarif"))}
        if args.write_baseline:
            path = Path(args.write_baseline).expanduser()
            if path.is_symlink():
                raise ValueError("Baseline output must not be a symbolic link")
            data = {"schema_version": "1.0", "findings": [{"id": f["id"], "reason": args.baseline_reason} for f in report["findings"]]}
            atomic_write(path.resolve(), json.dumps(data, indent=2, sort_keys=True) + "\n")
    except (OSError, ValueError) as exc:
        print("Scan error: " + redact(str(exc)), file=sys.stderr)
        if args.summary_json:
            print(json.dumps({"schema_version": "1.0", "type": "scan_summary", "status": "operational_error",
                              "error": redact(str(exc)), "reports": report_paths, "exit_code": 2}, sort_keys=True))
        return 2
    if not report["summary"]["scan_complete_within_selected_scope"]:
        print("Scan incomplete: " + str(report["summary"]["coverage_gaps"]) + " coverage gaps; see report.json for details.", file=sys.stderr)
    if report["analyst"].get("status") in {"error", "incomplete"}:
        print("Optional control analyst review is incomplete; see report.json for coverage and error details.", file=sys.stderr)
    if args.summary_json:
        print(json.dumps(_json_summary(report, target, report_paths), sort_keys=True))
        return report["execution"]["exit_code"]
    if args.quiet:
        return report["execution"]["exit_code"]
    summary = report["summary"]
    print(f"Scanned {summary['files_scanned']} files; {summary['open_findings']} open findings; {summary['coverage_gaps']} coverage gaps.")
    print("Reports: " + str(output.resolve() / "report.md") + " (also JSON and SARIF)")
    if report["analyst"].get("enabled"):
        coverage = report["analyst"]["coverage"]
        print(f"Advisory analyst: {report['analyst']['status']}; {coverage['reviewed_controls']}/{coverage['total_controls']} controls reviewed; {coverage['omitted_checks']} unanswered checks. Code review does not establish runtime validation.")
    # Operational failure always takes precedence over the finding severity gate.
    return report["execution"]["exit_code"]
