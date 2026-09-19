import argparse
import hashlib
import json
import sys
from pathlib import Path

from . import __version__
from .fs import read_confined
from .report import atomic_write, write_reports
from .scanner import SEVERITIES, load_baseline, load_controls, scan
from .security import redact, redact_object


def parser():
    p = argparse.ArgumentParser(description="Read-only AI agent and MCP source security scan. Offline unless --judge-config is provided.")
    p.add_argument("target", nargs="?", help="Repository directory to inspect")
    p.add_argument("--output", default="scan-report", help="Report directory (default: ./scan-report)")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="Additional relative-path exclusion; repeatable")
    p.add_argument("--max-file-bytes", type=int, default=1_000_000)
    p.add_argument("--max-total-bytes", type=int, default=50_000_000)
    p.add_argument("--max-files", type=int, default=20_000)
    p.add_argument("--max-entries", type=int, default=100_000)
    p.add_argument("--fail-on", choices=SEVERITIES + ("none",), default="high", help="Fail on unsuppressed findings at or above severity (default: high)")
    p.add_argument("--baseline", help="Explicitly accepted finding IDs with justification")
    p.add_argument("--write-baseline", metavar="PATH", help="Write a baseline candidate; does not suppress this scan")
    p.add_argument("--baseline-reason", help="Required justification for --write-baseline")
    p.add_argument("--judge-config", help="Opt in to sending a bounded, redacted assessment payload to this configured LLM endpoint")
    p.add_argument("--judge-include-source", action="store_true", help="Also send bounded redacted source context around findings (requires --judge-config)")
    p.add_argument("--judge-max-findings", type=int, default=100)
    p.add_argument("--list-rules", action="store_true")
    p.add_argument("--list-controls", action="store_true")
    p.add_argument("--version", action="version", version=__version__)
    return p


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
    if args.list_rules:
        from .rules import RULES
        print(json.dumps(RULES, indent=2, sort_keys=True))
        return 0
    if args.list_controls:
        print(json.dumps(load_controls(), indent=2, sort_keys=True))
        return 0
    if not args.target:
        p.error("target directory is required")
    if args.judge_include_source and not args.judge_config:
        p.error("--judge-include-source requires --judge-config")
    if args.write_baseline and not (args.baseline_reason or "").strip():
        p.error("--write-baseline requires --baseline-reason with a justification")
    if not 1 <= args.judge_max_findings <= 500:
        p.error("--judge-max-findings must be between 1 and 500")
    output = Path(args.output).expanduser()
    target = Path(args.target).expanduser()
    if output.resolve() == target.resolve():
        p.error("--output must be separate from the repository root")
    exclusions = [output.absolute()]
    for name in (args.baseline, args.write_baseline, args.judge_config):
        if name:
            exclusions.append(Path(name).expanduser().absolute())
    try:
        baseline = load_baseline(args.baseline) if args.baseline else None
        report = scan(target, exclude=args.exclude, output_paths=exclusions, max_file_bytes=args.max_file_bytes, max_total_bytes=args.max_total_bytes, max_files=args.max_files, max_entries=args.max_entries, baseline=baseline)
        if args.judge_config:
            from .judge import JudgeError, load_config, review
            print("Optional LLM judge enabled: sending redacted findings to the configured endpoint. Redaction is best-effort.", file=sys.stderr)
            payload = judge_payload(report, target.resolve(), args.judge_include_source, args.judge_max_findings)
            judge_scope = {"omitted_open_findings": payload["omitted_open_findings"], "selected_findings": len(payload["findings"]), "source_context_sent_count": len(payload.get("source_context", []))}
            try:
                config = load_config(args.judge_config)
                result = review(config, payload)
                report["judge"] = {**redact_object(result), **judge_scope, "enabled": True, "status": "completed", "advisory_only": True, "source_context_requested": args.judge_include_source}
            except JudgeError as exc:
                report["judge"] = {**judge_scope, "enabled": True, "status": "error", "advisory_only": True, "error": redact(str(exc)) + " Deterministic results are preserved."}
        gate_triggered = args.fail_on != "none" and any(f["status"] == "open" and SEVERITIES.index(f["severity"]) <= SEVERITIES.index(args.fail_on) for f in report["findings"])
        incomplete = not report["summary"]["scan_complete_within_selected_scope"] or report["judge"].get("status") == "error"
        report["execution"] = {"failure_threshold": args.fail_on, "finding_gate_triggered": bool(gate_triggered), "exit_code": 2 if incomplete else 1 if gate_triggered else 0}
        write_reports(report, output)
        if args.write_baseline:
            path = Path(args.write_baseline).expanduser()
            if path.is_symlink():
                raise ValueError("Baseline output must not be a symbolic link")
            data = {"schema_version": "1.0", "findings": [{"id": f["id"], "reason": args.baseline_reason} for f in report["findings"]]}
            atomic_write(path.resolve(), json.dumps(data, indent=2, sort_keys=True) + "\n")
    except (OSError, ValueError) as exc:
        print("Scan error: " + redact(str(exc)), file=sys.stderr)
        return 2
    summary = report["summary"]
    print(f"Scanned {summary['files_scanned']} files; {summary['open_findings']} open findings; {summary['coverage_gaps']} coverage gaps.")
    print("Reports: " + str(output.resolve() / "report.md") + " (also JSON and SARIF)")
    # Operational failure always takes precedence over the finding severity gate.
    return report["execution"]["exit_code"]
