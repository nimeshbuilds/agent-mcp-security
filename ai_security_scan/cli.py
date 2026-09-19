import argparse
import hashlib
import json
import sys
import math
from collections import Counter
from contextlib import ExitStack
from pathlib import Path

from . import __version__
from .cli_help import DESCRIPTION, complete_reference
from .fs import read_confined
from .report import atomic_write, write_reports
from .scanner import SEVERITIES, load_baseline, load_controls, scan
from .security import redact, redact_object


class HelpFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    """Keep examples readable while displaying configurable defaults."""


def parser():
    p = argparse.ArgumentParser(
        description=DESCRIPTION, epilog=complete_reference(), add_help=False,
        allow_abbrev=False, formatter_class=HelpFormatter)
    p.add_argument("-h", "--help", action="help", help="Print this complete offline feature, configuration and example reference, then exit")
    p.add_argument("target", nargs="?", help="Repository directory; choose this OR --image OR --image-archive; omit for help/version/catalog commands")
    images = p.add_argument_group("Container image input (never starts the container)")
    image_input = images.add_mutually_exclusive_group()
    image_input.add_argument("--image", metavar="REFERENCE", help="Inspect a local Docker/Podman image reference without the source checkout")
    image_input.add_argument("--image-archive", metavar="PATH", help="Inspect a Docker-save/OCI tar or tar.gz archive of a Linux image without a container runtime")
    images.add_argument("--image-runtime", choices=("docker", "podman"), default="docker", help="Runtime used only for --image export and optional pull")
    images.add_argument("--pull", action="store_true", help="Explicitly fetch --image before inspection; never implied by a missing image")
    images.add_argument("--image-platform", metavar="OS/ARCH[/VARIANT]", help="Select a platform; ambiguous multi-platform archives require a selection")
    images.add_argument("--image-max-archive-bytes", type=int, default=2_000_000_000, help="Positive integer archive/export byte limit, also bounding expanded outer-archive data")
    images.add_argument("--image-max-unpacked-bytes", type=int, default=4_000_000_000, help="Positive integer expanded-layer byte budget; separately bounds final materialized bytes")
    images.add_argument("--image-max-entries", type=int, default=500_000, help="Positive integer cap on archive/layer headers and implicit-directory expansion")
    images.add_argument("--image-max-layers", type=int, default=200, help="Positive integer maximum selected image layers")
    images.add_argument("--image-timeout", type=float, default=300, help="Shared runtime pull/export deadline in seconds, finite and >0; not an archive-analysis timeout")
    scope = p.add_argument_group("Scan scope and resource limits")
    scope.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="Repeatable case-sensitive relative-path exclusion; quote globs. Image paths are relative to container root")
    scope.add_argument("--max-file-bytes", type=int, default=1_000_000, help="Maximum bytes in one source file; larger files create a coverage gap")
    scope.add_argument("--max-total-bytes", type=int, default=50_000_000, help="Total file-read budget, including rejected/failed reads and growth detection")
    scope.add_argument("--max-files", type=int, default=20_000, help="Maximum source/configuration files to scan")
    scope.add_argument("--max-entries", type=int, default=100_000, help="Maximum traversed file/directory entries")
    output = p.add_argument_group("Reports and CI output")
    output.add_argument("--output", default="scan-report", help="Directory for report.html, report.json, report.md and report.sarif; creates parents and replaces existing report files")
    display = output.add_mutually_exclusive_group()
    display.add_argument("--quiet", action="store_true", help="Suppress scan progress and human summaries; errors remain on stderr")
    display.add_argument("--summary-json", action="store_true", help="Write one JSON summary to stdout; diagnostics remain on stderr")
    output.add_argument("--fail-on", choices=SEVERITIES + ("none",), default="high", help="Fail on open findings at or above this severity; none disables only this gate")
    baseline = p.add_argument_group("Reviewed finding baselines")
    baseline.add_argument("--baseline", metavar="PATH", help="Load reviewed JSON finding IDs and nonempty reasons; matched findings remain in reports as suppressed")
    baseline.add_argument("--write-baseline", metavar="PATH", help="Write a baseline candidate; does not suppress this scan")
    baseline.add_argument("--baseline-reason", metavar="TEXT", help="Required nonempty justification for --write-baseline; quote multiword reasons")
    policy = p.add_argument_group("User review dispositions (disabled by default)")
    policy.add_argument("--review-config", metavar="PATH", help="Explicit trusted JSON rule/control/check exceptions; justified or disabled items are retained for audit and excluded from active counts. Schema and precedence below")
    judge = p.add_argument_group("Optional advisory LLM review (disabled by default)")
    judge_source = judge.add_mutually_exclusive_group()
    judge_source.add_argument("--judge-config", metavar="PATH", help="Trusted JSON API/gateway or CLI config; opt in to model calls and bounded redacted evidence disclosure. Fields and examples below")
    judge_source.add_argument("--judge-cli", choices=("codex", "claude", "grok"), help="Use an installed official CLI and its existing login; mutually exclusive with --judge-config. See required versions and isolation limits below")
    judge.add_argument("--judge-model", metavar="MODEL", help="With --judge-cli only: explicit model override; otherwise Invarune selects its security-review default for that provider")
    judge.add_argument("--judge-executable", metavar="PATH", help="With --judge-cli or --login: trusted vendor executable path/name; otherwise resolve codex, claude or grok on PATH")
    judge.add_argument("--judge-cli-home", metavar="PATH", help="With Grok --judge-cli or --login only: absolute clean GROK_HOME profile; no credentials are copied")
    judge.add_argument("--judge-timeout", type=float, metavar="SECONDS", help="With --judge-cli only: per-invocation deadline including preflight; 0.1..300 seconds, default 60")
    judge.add_argument("--judge-login", choices=("auto", "never"), default="auto", help="auto: signed-out CLI scans launch official login on an interactive terminal, then resume; never: require an existing login. Quiet/JSON/noninteractive scans never prompt")
    judge.add_argument("--login-timeout", type=float, default=300, metavar="SECONDS", help="Official CLI login flow timeout, finite 1..900 seconds; separate from model request and analyst budgets")
    judge.add_argument("--judge-mode", choices=("full", "findings"), default="full", help="full: finding triage plus every active control/check, including zero-finding scans; findings: one finding-triage request only")
    judge.add_argument("--judge-include-source", action="store_true", help="Add neighboring source to finding triage; full analyst separately sends bounded source excerpts")
    judge.add_argument("--judge-max-findings", type=int, default=100, help="Maximum open findings sent to finding triage (1-500)")
    judge.add_argument("--analyst-max-calls", type=int, default=12, help="Full control-review request budget (integer 0-100); triage uses one additional request. Zero leaves active controls unreviewed")
    judge.add_argument("--analyst-batch-size", type=int, default=6, help="Controls per analyst request (1-20)")
    judge.add_argument("--analyst-max-files", type=int, default=200, help="Full analyst evidence file budget (integer 0-20000); zero sends no source excerpts")
    judge.add_argument("--analyst-max-bytes", type=int, default=2_000_000, help="Full analyst evidence read-byte budget (integer 0-50000000); zero sends no source excerpts")
    judge.add_argument("--analyst-max-chars", type=int, default=120_000, help="Retained redacted source-character budget (integer 0-1000000); zero sends no excerpts but may still read files")
    judge.add_argument("--analyst-time-budget", type=float, default=180, help="Full analyst scheduling/time budget in seconds, finite >0 and <=3600; not a hard process deadline")
    catalog = p.add_argument_group("Catalog inspection (no scan or network)")
    mode = catalog.add_mutually_exclusive_group()
    mode.add_argument("--list-rules", action="store_true", help="Print all deterministic rule metadata as JSON")
    mode.add_argument("--list-controls", action="store_true", help="Print all control checks, stable CONTROL:INDEX check IDs, rule mappings, and sources as JSON")
    mode.add_argument("--explain-rule", metavar="ID", help="Print one rule's metadata, mapped controls, and interpretation as JSON")
    authentication = p.add_argument_group("Official CLI authentication (interactive, optional)")
    authentication.add_argument("--login", choices=("codex", "claude", "grok"), help="Sign in through an official CLI directly from Invarune, then exit; requires an interactive terminal and no scan target or reports")
    p.add_argument("--version", action="version", version=__version__, help="Print scanner version and exit without scanning or model calls")
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
    judge_summary = {key: judge[key] for key in ("enabled", "status", "mode", "advisory_only", "provider", "model", "cli", "selected_findings", "omitted_open_findings", "error") if key in judge}
    analyst_summary = {key: analyst[key] for key in ("enabled", "status", "advisory_only", "coverage") if key in analyst}
    policy = report.get("review_policy", {})
    counts = policy.get("counts", {})
    active_controls = [control for control in controls
                       if not policy or any(check["status"] == "active" for check in control.get("check_dispositions", []))]
    return {"schema_version": "1.0", "type": "scan_summary", "status": "completed" if report["execution"]["exit_code"] != 2 else "incomplete",
            "tool": report["tool"], "scan_id": report["scan_id"], "summary": report["summary"],
            "assessment": {key: report["assessment"][key] for key in ("posture", "metrics", "guidance")},
            "scope": {"target": report.get("image", {}).get("display_target", redact(str(target.resolve()))), "configuration": report["configuration"]},
            "coverage": {**report["coverage"], "total_controls": counts.get("active_controls", len(controls)),
                         "total_checks": counts.get("active_checks", sum(len(control.get("checks", [])) for control in controls)),
                         **({"catalog_controls": counts["catalog_controls"], "catalog_checks": counts["catalog_checks"]} if policy else {}),
                         "statically_mapped_controls": sum(bool(control.get("automated_rule_ids")) for control in active_controls),
                         **({"catalog_statically_mapped_controls": sum(bool(control.get("automated_rule_ids")) for control in controls)} if policy else {}),
                         "control_status_counts": dict(sorted(Counter(control["status"] for control in controls).items()))},
            "optional_review": {"judge": judge_summary, "analyst": analyst_summary},
            **({"review_policy": policy} if policy else {}),
            "execution": report["execution"], "exit_code": report["execution"]["exit_code"], "reports": report_paths,
            **({"image": report["image"]} if "image" in report else {})}


def judge_payload(report, root, include_source=False, max_findings=100):
    selected = [f for f in report["findings"] if f["status"] == "open"][:max_findings]
    payload = {"scan_id": report["scan_id"], "summary": report["summary"], "limitations": report["coverage"]["limitations"], "findings": selected, "omitted_open_findings": report["summary"]["open_findings"] - len(selected), "source_context_included": include_source}
    if include_source:
        from .evidence import image_evidence_context, model_evidence_exclusion
        contexts = []
        manifest = {f["path"]: f for f in report["files"]}
        skipped = []
        total = 0
        for f in selected:
            entry = manifest.get(f["path"])
            exclusion = model_evidence_exclusion(entry) if entry else "manifest_entry_missing"
            if exclusion:
                skipped.append({"finding_id": f["id"], "path": f["path"], "reason": exclusion})
                continue
            rel = Path(f["path"])
            # The root and all path components must still be confined and unsymlinked.
            path = root / rel
            if rel.is_absolute() or ".." in rel.parts or any(p.is_symlink() for p in [path, *path.parents]) or root not in path.resolve().parents:
                continue
            try:
                content, _ = read_confined(root, rel, report["configuration"]["max_file_bytes"])
                if hashlib.sha256(content).hexdigest() != entry["sha256"]:
                    continue
                lines = content.decode("utf-8-sig").splitlines()
                start = max(0, f["line"] - 4)
                text = redact("\n".join(lines[start:min(len(lines), f["line"] + 3)]))[:3000]
                if total + len(text) > 30_000:
                    break
                contexts.append({"finding_id": f["id"], "path": f["path"], "start_line": start + 1, "text": text,
                                 **image_evidence_context(entry)})
                total += len(text)
            except (OSError, UnicodeError):
                continue
        payload["source_context"] = contexts
        payload["source_context_skipped"] = skipped
    return redact_object(payload)


def main(argv=None):
    p = parser()
    args = p.parse_args(argv)
    if not math.isfinite(args.login_timeout) or not 1 <= args.login_timeout <= 900:
        p.error("--login-timeout must be finite and between 1 and 900 seconds")
    if args.login:
        if args.target or args.image or args.image_archive or args.judge_cli or args.judge_config or args.list_rules or args.list_controls or args.explain_rule:
            p.error("--login is a standalone command; omit scan input and judge selection")
        if args.quiet or args.summary_json or args.judge_model or args.judge_timeout is not None:
            p.error("--login requires interactive output and does not accept scan/model output options")
        if args.judge_cli_home is not None and args.login != "grok":
            p.error("--judge-cli-home is Grok-only")
        from .cli_judge import CLIJudgeError, login_cli
        try:
            login_cli({"provider": args.login + "_cli", **{key: value for key, value in
                (("executable", args.judge_executable), ("cli_home", args.judge_cli_home)) if value is not None}},
                timeout_seconds=args.login_timeout)
        except CLIJudgeError as exc:
            print("CLI login error: " + redact(str(exc)), file=sys.stderr)
            return 2
        print("Signed in through the official " + args.login + " CLI. Invarune does not store authentication tokens.")
        return 0
    catalog_mode = args.list_rules or args.list_controls or args.explain_rule is not None
    image_mode = args.image is not None or args.image_archive is not None
    if catalog_mode and (args.target or image_mode):
        p.error("catalog inspection does not accept a target directory or image")
    if catalog_mode and (args.quiet or args.summary_json):
        p.error("--quiet and --summary-json apply to scans; catalog commands already emit JSON")
    if args.list_rules:
        from .rules import RULES
        print(json.dumps(RULES, indent=2, sort_keys=True))
        return 0
    if args.list_controls:
        print(json.dumps([{**control, "check_ids": [control["id"] + ":" + str(index)
                         for index in range(1, len(control["checks"]) + 1)]}
                         for control in load_controls()], indent=2, sort_keys=True))
        return 0
    if args.explain_rule is not None:
        try:
            print(json.dumps(_rule_explanation(args.explain_rule), indent=2, sort_keys=True))
        except ValueError as exc:
            p.error(str(exc))
        return 0
    if args.target and image_mode:
        p.error("choose a target directory or an image, not both")
    if not args.target and not image_mode:
        p.error("a target directory, --image, or --image-archive is required")
    if args.pull and not args.image:
        p.error("--pull requires --image")
    if args.image_platform and not image_mode:
        p.error("--image-platform requires an image input")
    if any(value <= 0 for value in (args.image_max_archive_bytes, args.image_max_unpacked_bytes, args.image_max_entries, args.image_max_layers)):
        p.error("image limits must be positive integers")
    if not math.isfinite(args.image_timeout) or args.image_timeout <= 0:
        p.error("--image-timeout must be a positive finite number")
    judge_enabled = bool(args.judge_config or args.judge_cli)
    if args.judge_include_source and not judge_enabled:
        p.error("--judge-include-source requires --judge-config or --judge-cli")
    if any(value is not None for value in (args.judge_model, args.judge_executable, args.judge_timeout, args.judge_cli_home)) and not args.judge_cli:
        p.error("--judge-model, --judge-executable, --judge-timeout and --judge-cli-home require --judge-cli")
    if args.judge_cli_home is not None and args.judge_cli != "grok":
        p.error("--judge-cli-home requires --judge-cli grok")
    if args.judge_timeout is not None and (not math.isfinite(args.judge_timeout) or not 0.1 <= args.judge_timeout <= 300):
        p.error("--judge-timeout must be finite and between 0.1 and 300 seconds")
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
    target = Path(args.target).expanduser() if args.target else Path(".")
    if not image_mode and output.resolve() == target.resolve():
        p.error("--output must be separate from the repository root")
    exclusions = [output.absolute()]
    for name in (args.baseline, args.write_baseline, args.judge_config, args.review_config, args.judge_cli_home):
        if name:
            exclusions.append(Path(name).expanduser().absolute())
    report_paths = {}
    resources = ExitStack()
    try:
        review_config = None
        if args.review_config:
            from .review_policy import apply_review_config, load_review_config
            review_path = Path(args.review_config).expanduser()
            review_config = load_review_config(review_path)
            destinations = [output / name for name in ("report.html", "report.json", "report.md", "report.sarif")]
            if args.write_baseline:
                destinations.append(Path(args.write_baseline).expanduser())
            try:
                for path in destinations:
                    if review_path.resolve() == path.resolve() or (path.exists() and review_path.samefile(path)):
                        raise ValueError("--review-config must not be overwritten by a report or --write-baseline destination")
            except RuntimeError as exc:
                raise ValueError("Review configuration and output paths must not contain symbolic-link loops") from exc
        baseline = load_baseline(args.baseline) if args.baseline else None
        scan_options = dict(exclude=args.exclude, output_paths=exclusions, max_file_bytes=args.max_file_bytes, max_total_bytes=args.max_total_bytes, max_files=args.max_files, max_entries=args.max_entries, baseline=baseline)
        if image_mode:
            from .image_scan import scan_image
            report, target = resources.enter_context(scan_image(archive=args.image_archive, reference=args.image,
                runtime=args.image_runtime, pull=args.pull, platform=args.image_platform,
                max_archive_bytes=args.image_max_archive_bytes, max_unpacked_bytes=args.image_max_unpacked_bytes,
                max_layer_entries=args.image_max_entries, max_layers=args.image_max_layers,
                timeout_seconds=args.image_timeout, **scan_options))
        else:
            report = scan(target, **scan_options)
        if review_config is not None:
            report = apply_review_config(report, review_config)
        report["analyst"] = {"enabled": False}
        if judge_enabled:
            from .judge import JudgeError, JudgeAuthenticationError, load_config, review, validate_analyst_config
            from .analyst import run_analyst, unreviewed_analyst
            scope_description = "open findings and bounded source excerpts for active control checks" if args.judge_mode == "full" else "open findings"
            if not args.quiet:
                recipient = "selected CLI's configured service" if args.judge_cli else "configured provider/service"
                print("Optional LLM review enabled: sending redacted " + scope_description + " to the " + recipient + ". Redaction is best-effort.", file=sys.stderr)
            payload = judge_payload(report, target.resolve(), args.judge_include_source, args.judge_max_findings)
            judge_scope = {"omitted_open_findings": payload["omitted_open_findings"], "selected_findings": len(payload["findings"]), "source_context_sent_count": len(payload.get("source_context", [])),
                           "source_context_skipped": payload.get("source_context_skipped", [])}
            try:
                if args.judge_config:
                    config = load_config(args.judge_config)
                else:
                    config = validate_analyst_config({"provider": args.judge_cli + "_cli",
                        **{key: value for key, value in (("model", args.judge_model),
                           ("executable", args.judge_executable), ("timeout_seconds", args.judge_timeout),
                           ("cli_home", args.judge_cli_home)) if value is not None}})
                if args.judge_mode == "full":
                    config = validate_analyst_config(config)
                interactive_login = config["provider"].endswith("_cli") and args.judge_login == "auto" and not (args.quiet or args.summary_json) and sys.stdin.isatty() and sys.stderr.isatty()
                login_attempted = False

                def authenticate():
                    nonlocal login_attempted
                    if not interactive_login or login_attempted:
                        return False
                    login_attempted = True
                    try:
                        print("Sign-in required. Opening the official CLI login; this scan will resume after sign-in.", file=sys.stderr)
                        login_cli(config, timeout_seconds=args.login_timeout)
                    except CLIJudgeError as exc:
                        raise JudgeError(str(exc)) from None
                    return True

                if interactive_login:
                    from .cli_judge import CLIJudgeError, probe_auth, login_cli
                    try:
                        auth = probe_auth(config)
                        if auth["logged_in"] is False:
                            authenticate()
                    except CLIJudgeError as exc:
                        raise JudgeError(str(exc)) from None
                try:
                    result = review(config, payload)
                except JudgeAuthenticationError:
                    if not authenticate():
                        raise
                    result = review(config, payload)
                report["judge"] = {**redact_object(result), **judge_scope, "enabled": True, "status": "completed", "advisory_only": True, "source_context_requested": args.judge_include_source}
                if args.judge_mode == "full":
                    report["analyst"] = run_analyst(config, report, target.resolve(),
                        **({"on_auth_required": authenticate} if interactive_login else {}), **analyst_limits)
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
        report = write_reports(report, output)
        report_paths = {kind: str(output.resolve() / name) for kind, name in
                        (("html", "report.html"), ("json", "report.json"), ("markdown", "report.md"), ("sarif", "report.sarif"))}
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
    finally:
        resources.close()
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
    if report.get("review_policy"):
        counts = report["review_policy"]["counts"]
        print(f"User dispositions: {summary['justified_findings']} justified and {summary['disabled_findings']} disabled findings; {counts['active_rules']} active rules; {counts['active_checks']} active checks, {counts['justified_checks']} justified, {counts['disabled_checks']} disabled. Excluded items are not passes.")
    if report.get("image"):
        print(f"Image scope: {summary['image_analysis_scope']}; {summary['packaged_source_files_inspected']} packaged source files inspected. Binary logic and package CVEs were not analyzed.")
    print("Reports: " + str(output.resolve() / "report.html") + " (also Markdown, JSON and SARIF)")
    if report["analyst"].get("enabled"):
        coverage = report["analyst"]["coverage"]
        print(f"Advisory analyst: {report['analyst']['status']}; {coverage['reviewed_controls']}/{coverage['total_controls']} controls reviewed; {coverage['omitted_checks']} unanswered checks. Code review does not establish runtime validation.")
    # Operational failure always takes precedence over the finding severity gate.
    return report["execution"]["exit_code"]
