#!/usr/bin/env python3
"""Run pinned external CLIs against exported public source without executing it.

This research harness is separate from Invarune. It does not download tools,
authenticate, execute target programs, or infer accuracy from real-project counts.
Only normalized locations/rule IDs are published; raw CLI output stays local.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai_security_scan import __version__
from ai_security_scan.analyzer import analyze_file, _js_tokens, _js_pairs


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def clean_path(value, root):
    path = Path(value)
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        if path.is_absolute() or path.anchor:
            return "[outside selected source]/" + path.name
    value = path.as_posix()
    return value[2:] if value.startswith("./") else value


def normalize(tool, data, source):
    """Preserve findings and tool failures separately; never call a failure clean."""
    findings, errors, files = [], [], None
    if tool == "semgrep":
        for item in data["results"]:
            findings.append({"rule_id": item["check_id"], "path": clean_path(item["path"], source),
                             "line": item["start"]["line"], "end_line": item["end"]["line"],
                             "severity": item["extra"]["severity"]})
        errors = [{"type": (x["type"][0] if isinstance(x.get("type"), list) and x["type"] else x.get("type", "unknown")),
                   "path": clean_path(x.get("path", ""), source),
                   "level": x.get("level", "unknown")} for x in data.get("errors", [])]
        files = len(data.get("paths", {}).get("scanned", []))
    elif tool == "bandit":
        for item in data["results"]:
            findings.append({"rule_id": item["test_id"], "path": clean_path(item["filename"], source),
                             "line": item["line_number"], "end_line": max(item.get("line_range", []) or [item["line_number"]]),
                             "severity": item["issue_severity"], "confidence": item["issue_confidence"]})
        errors = [{"type": x.get("reason", "unknown"), "path": clean_path(x.get("filename", ""), source)}
                  for x in data.get("errors", [])]
        files = len([x for x in data.get("metrics", {}) if x != "_totals"])
    elif tool == "gitleaks":
        if not isinstance(data, list):
            raise ValueError("Gitleaks report must be a list")
        for item in data:
            findings.append({"rule_id": item["RuleID"], "path": clean_path(item["File"], source),
                             "line": item["StartLine"], "end_line": item["EndLine"],
                             "severity": "not_provided"})
    else:
        raise ValueError("Unknown scanner: " + tool)
    findings.sort(key=lambda x: (x["path"], x["line"], x["rule_id"]))
    return {"findings": findings, "finding_count": len(findings), "errors": errors,
            "files_reported_scanned": files,
            "severity_counts": dict(sorted(Counter(x["severity"] for x in findings).items())),
            "rule_counts": dict(sorted(Counter(x["rule_id"] for x in findings).items()))}


def classify(returncode, timed_out, parse_error, normalized):
    if timed_out:
        return "timeout"
    if returncode not in (0, 1) or parse_error:
        return "execution_error"
    if normalized.get("errors"):
        return "completed_with_analysis_errors"
    return "completed_with_findings" if normalized.get("finding_count", 0) else "completed_no_findings"


def tree_identity(source):
    records = []
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise ValueError("Exported corpus must not contain symlinks")
        if path.is_file():
            raw = path.read_bytes()
            records.append({"path": path.relative_to(source).as_posix(), "size_bytes": len(raw), "sha256": digest(raw)})
    return {"file_count": len(records), "bytes": sum(x["size_bytes"] for x in records),
            "manifest_sha256": digest(json.dumps(records, sort_keys=True, separators=(",", ":")).encode()),
            "python_files": sum(x["path"].endswith(".py") for x in records)}


def commands(args, source, raw_report, support):
    return {
        "semgrep": [str(args.semgrep), "scan", "--config", str(args.semgrep_config), "--metrics=off",
                    "--disable-version-check", "--disable-nosem", "--no-git-ignore", "--no-rewrite-rule-ids", "--json", "--quiet",
                    "--jobs", "2", "--timeout", "10", "--max-target-bytes", "20000000",
                    "--output", str(raw_report), str(source)],
        "bandit": [str(args.bandit), "-r", str(source), "-c", str(support / "bandit.yaml"),
                   "--ignore-nosec", "-f", "json", "-o", str(raw_report), "-q"],
        "gitleaks": [str(args.gitleaks), "dir", str(source), "--config", str(support / "gitleaks.toml"),
                     "--gitleaks-ignore-path", str(support / "empty-ignore"), "--ignore-gitleaks-allow",
                     "--redact=100", "--no-banner", "--no-color", "--report-format", "json",
                     "--report-path", str(raw_report), "--timeout", str(args.timeout),
                     "--max-target-megabytes", "20"]}


def execute(tool, source, args, raw_root, support):
    raw_root.mkdir(parents=True, exist_ok=True)
    raw_report = raw_root / (tool + ".json")
    if raw_report.exists():
        raw_report.unlink()
    command = commands(args, source, raw_report, support)[tool]
    state = support / ("state-" + tool)
    state.mkdir(exist_ok=True)
    env = {"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", ""), "LANG": "en_US.UTF-8", "LC_ALL": "en_US.UTF-8",
           "SEMGREP_SETTINGS_FILE": str(state / "semgrep-settings.yml"),
           "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0", "NO_COLOR": "1"}
    started, timer = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), time.monotonic()
    timed_out, returncode = False, None
    try:
        result = subprocess.run(command, cwd=str(source), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=args.timeout, check=False)
        returncode, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out, stdout, stderr = True, exc.stdout or b"", exc.stderr or b""
    except OSError as exc:
        stdout, stderr = b"", str(exc).encode()
    elapsed = round(time.monotonic() - timer, 6)
    (raw_root / (tool + ".stdout.log")).write_bytes(stdout)
    (raw_root / (tool + ".stderr.log")).write_bytes(stderr)
    raw, error, normalized = b"", None, {"findings": [], "errors": [], "finding_count": None}
    try:
        raw = raw_report.read_bytes()
        normalized = normalize(tool, json.loads(raw), source)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        error = type(exc).__name__
    # Commands are stored with portable placeholders; exact local commands remain in ignored receipts.
    replacements = [(str(source), "{source}"), (str(raw_root), "{raw_output}"), (str(support), "{support}"),
                    (str(args.semgrep_config), "{semgrep_rules}")]
    portable = []
    for arg in command:
        for original, label in replacements:
            arg = arg.replace(original, label)
        portable.append(arg)
    portable[0] = tool
    receipt = {"tool": tool, "command": portable, "started_at_utc": started, "wall_seconds": elapsed,
               "process_exit_code": returncode, "timed_out": timed_out, "output_parse_error": error,
               "raw_report_sha256": digest(raw) if raw else None,
               "stdout_sha256": digest(stdout), "stderr_sha256": digest(stderr), **normalized}
    receipt["status"] = classify(returncode, timed_out, error, normalized)
    if tool == "bandit" and not any(source.rglob("*.py")) and receipt["status"] == "completed_no_findings":
        receipt["status"] = "unsupported_no_python_files"
        receipt["finding_count"] = None
    save(raw_root / (tool + ".receipt.json"), {**receipt, "exact_command": command})
    return receipt


MATCHES = {
    "AI001": {"bandit": ["B307"], "semgrep": ["python.lang.security.audit.eval-detected.eval-detected"]},
    "AI002": {"bandit": ["B602"], "semgrep": ["python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"]},
    "AI004": {"bandit": ["B506"], "semgrep": ["python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load"]},
    "AI005": {"bandit": ["B301"], "semgrep": ["python.lang.security.deserialization.pickle.avoid-pickle"]},
    "AI006": {"bandit": ["B501"], "semgrep": ["python.requests.security.disabled-cert-validation.disabled-cert-validation"]},
}


def score_assertions(cases, findings, tool):
    results, counts = [], Counter()
    for case in cases:
        rule, expected = next(iter(case["expect"].items()))
        mapped = [rule] if tool == "invarune" else MATCHES.get(rule, {}).get(tool)
        if not mapped:
            results.append({"case_id": case["id"], "outcome": "unsupported", "expected": expected})
            counts["unsupported"] += 1
            continue
        observed = [x["rule_id"] for x in findings if x["path"].split("/")[0] == case["id"]]
        actual = bool(set(mapped) & set(observed))
        outcome = ("true_positive" if expected else "false_positive") if actual else ("false_negative" if expected else "true_negative")
        counts[outcome] += 1
        results.append({"case_id": case["id"], "invarune_rule_id": rule, "expected": expected, "detected": actual,
                        "mapped_rule_ids": mapped, "observed_rule_ids": sorted(set(observed)), "outcome": outcome})
    totals = {key: counts[key] for key in ("true_positive", "true_negative", "false_positive", "false_negative", "unsupported")}
    totals["scored_assertions"] = sum(totals[key] for key in ("true_positive", "true_negative", "false_positive", "false_negative"))
    return {"counts": totals, "cases": results}


def synthetic(args, raw_root, support):
    corpus_raw = (ROOT / "benchmarks/static_accuracy.json").read_bytes()
    corpus = json.loads(corpus_raw)
    cases = [case for case in corpus["cases"] if len(case["expect"]) == 1 and next(iter(case["expect"])) in MATCHES]
    source = raw_root / "synthetic-input"
    source.mkdir(exist_ok=True)
    own_findings = []
    for case in cases:
        path = source / case["id"] / case["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(case["source"], encoding="utf-8")
        own_findings += [{**f, "path": case["id"] + "/" + case["path"]} for f in analyze_file(case["path"], case["source"])]
    rows = {"invarune": score_assertions(cases, own_findings, "invarune")}
    receipts = []
    for tool in ("semgrep", "bandit"):
        receipt = execute(tool, source, args, raw_root / "synthetic-raw", support)
        receipts.append(receipt)
        if receipt["status"] not in {"completed_with_findings", "completed_no_findings"}:
            rows[tool] = {"status": "not_scored_execution_incomplete"}
        else:
            rows[tool] = score_assertions(cases, receipt["findings"], tool)
    return {"schema_version": "1.0", "provenance": "Existing project-authored synthetic development fixtures; not independent, held-out, or a production accuracy estimate.",
            "selection": "Every existing assertion for AI001, AI002, AI004, AI005, AI006. Selected by comparable API-level rule semantics before execution.",
            "metric_unit": "Matched API-pattern presence assertion. Other findings are unscored; labels do not establish exploitability.",
            "excluded_tools": {"gitleaks": "Secret detection has a different scope; no artificial true negatives awarded.",
                               "cisco-mcp-scanner": "MCP metadata YARA analysis has a different scope.",
                               "snyk-agent-scan": "Not executed; different runtime/cloud scope and no configured API credential."},
            "parent_corpus_sha256": digest(corpus_raw), "invarune_version": __version__, "case_count": len(cases),
            "rule_mapping": MATCHES, "results": rows, "external_run_receipts": receipts}


def parser():
    out = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    out.add_argument("--manifest", type=Path, default=ROOT / "benchmarks/real-world/manifest.json", help="Pinned public corpus manifest")
    out.add_argument("--tool-lock", type=Path, default=ROOT / "benchmarks/external-tools/tool-lock.json", help="Exact expected tool versions and rule-pack hash")
    out.add_argument("--source-root", type=Path, required=True, help="Directory of exported per-project source trees named by manifest project id")
    out.add_argument("--snapshots", type=Path, default=ROOT / "benchmarks/real-world/snapshots", help="Per-project pinned byte manifests from scan_public_projects.py")
    out.add_argument("--output", type=Path, default=ROOT / "benchmarks/external-tools/results", help="Published normalized JSON outputs")
    out.add_argument("--raw-output", type=Path, default=ROOT / "tmp/benchmark-tools/runs", help="Private local raw CLI outputs (may contain source); keep outside Git")
    out.add_argument("--semgrep", type=Path, required=True, help="Pinned installed Semgrep CE executable")
    out.add_argument("--semgrep-config", type=Path, required=True, help="Locally stored official security-audit pack, verified against tool-lock.json")
    out.add_argument("--bandit", type=Path, required=True, help="Pinned installed Bandit executable")
    out.add_argument("--gitleaks", type=Path, required=True, help="Pinned installed Gitleaks executable")
    out.add_argument("--timeout", type=int, default=300, help="Per-tool wall-time limit in seconds (default: 300)")
    out.add_argument("--only", action="append", default=[], help="Project id to run; repeatable. Default: all pinned projects")
    out.add_argument("--skip-synthetic", action="store_true", help="Skip the separate shared API-pattern fixture comparison")
    out.add_argument("--cisco", type=Path, help="Optional pinned Cisco MCP Scanner CLI for separate offline literal-description track")
    return out


def literal_tool_descriptions(source):
    """Extract a limited TypeScript declaration shape; never evaluate target code."""
    tokens, output = _js_tokens(source), []
    pairs = _js_pairs(tokens)
    for index in range(len(tokens) - 7):
        selected = tokens[index:index + 7]
        if ([x.value for x in selected[:4]] != ["server", ".", "registerTool", "("]
                or selected[0].kind != "identifier" or selected[4].kind != "string"
                or [x.value for x in selected[5:]] != [",", "{"]):
            continue
        closing = pairs.get(index + 6)
        if closing is None:
            continue
        cursor = index + 7
        while cursor < closing:
            if tokens[cursor].value == "description" and cursor + 1 < closing and tokens[cursor + 1].value == ":":
                end = cursor + 2
                while end < closing and tokens[end].value != ",":
                    if end in pairs and pairs[end] > end:
                        end = pairs[end] + 1
                    else:
                        end += 1
                expression = tokens[cursor + 2:end]
                if (len(expression) % 2 == 1 and all(t.kind == "string" if j % 2 == 0 else t.value == "+"
                                                    for j, t in enumerate(expression))):
                    output.append({"name": selected[4].value, "description": "".join(t.value for t in expression[::2]),
                                   "line": source.count("\n", 0, selected[0].start) + 1})
                break
            if cursor in pairs and pairs[cursor] > cursor:
                cursor = pairs[cursor] + 1
            else:
                cursor += 1
    return output


def cisco_metadata(args, support):
    relative = "src/filesystem/index.ts"
    source_file = args.source_root / "mcp-reference" / relative
    raw_source = source_file.read_bytes()
    declarations = literal_tool_descriptions(raw_source.decode("utf-8"))
    if not declarations:
        raise ValueError("No supported literal tool declarations; Cisco track cannot be scored")
    raw_root = args.raw_output / "cisco-metadata"
    raw_root.mkdir(exist_ok=True)
    input_path, output_path = raw_root / "tools.json", raw_root / "output.json"
    save(input_path, {"tools": [{"name": x["name"], "description": x["description"], "inputSchema": {"type": "object"}}
                               for x in declarations]})
    command = [str(args.cisco.resolve()), "--analyzers", "yara", "--format", "raw", "--output", str(output_path),
               "static", "--tools", str(input_path)]
    timer = time.monotonic()
    result = subprocess.run(command, cwd=str(raw_root), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=args.timeout,
                            env={"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", ""), "LANG": "en_US.UTF-8", "NO_COLOR": "1",
                                 "LITELLM_LOCAL_MODEL_COST_MAP": "True", "HF_HUB_OFFLINE": "1"}, check=False)
    (raw_root / "stdout.log").write_bytes(result.stdout)
    (raw_root / "stderr.log").write_bytes(result.stderr)
    raw_result = output_path.read_bytes() if output_path.exists() else result.stdout
    receipt = {"schema_version": "1.0", "tool": "cisco-ai-mcp-scanner", "version": "4.8.4",
               "input_kind": "Partial offline metadata extracted from literal TypeScript declarations; not a captured tools/list response.",
               "project_id": "mcp-reference", "source_path": relative, "source_sha256": digest(raw_source),
               "input_sha256": digest(input_path.read_bytes()), "raw_result_sha256": digest(raw_result),
               "process_exit_code": result.returncode, "wall_seconds": round(time.monotonic() - timer, 6),
               "command": ["mcp-scanner", "--analyzers", "yara", "--format", "raw", "--output", "{output}", "static", "--tools", "{input}"],
               "declarations": [{"name": x["name"], "line": x["line"], "description_sha256": digest(x["description"].encode())} for x in declarations],
               "limitations": ["Only static literal names and descriptions from the filesystem server are extracted.",
                               "Input/output schemas, computed descriptions, other servers, runtime behavior and tools are not assessed.",
                               "An empty object input schema is a format placeholder; no schema safety claim is made.",
                               "YARA only; Cisco API, LLM, behavioral, readiness and malware analyzers are disabled.",
                               "This track is not ranked against source SAST findings or scored as vulnerability accuracy."]}
    try:
        data = json.loads(raw_result)
        save(raw_root / "parsed-output.json", data)
        results = data["scan_results"]
        complete = (result.returncode == 0 and data["requested_analyzers"] == ["yara"]
                    and len(results) == len(declarations)
                    and sorted(x["tool_name"] for x in results) == sorted(x["name"] for x in declarations)
                    and all(x["status"] == "completed" and set(x["findings"]) == {"yara_analyzer"} for x in results))
        receipt["items"] = [{"name": x["tool_name"], "status": x["status"],
                              "severity": x["findings"]["yara_analyzer"]["severity"],
                              "finding_count": x["findings"]["yara_analyzer"]["total_findings"],
                              "threat_names": x["findings"]["yara_analyzer"]["threat_names"]} for x in results]
        receipt["finding_count"] = sum(x["finding_count"] for x in receipt["items"])
        receipt["status"] = ("completed_with_findings" if receipt["finding_count"] else "completed_no_findings") if complete else "incomplete"
    except (ValueError, KeyError, TypeError):
        receipt["status"] = "invalid_output"
    save(args.output / "cisco-metadata.json", receipt)


def main(argv=None):
    args = parser().parse_args(argv)
    if args.timeout < 1:
        raise ValueError("timeout must be positive")
    for key in ("manifest", "tool_lock", "source_root", "snapshots", "output", "raw_output", "semgrep", "semgrep_config", "bandit", "gitleaks"):
        setattr(args, key, getattr(args, key).resolve())
    if not args.semgrep_config.is_file():
        raise ValueError("Semgrep rule pack does not exist")
    lock = json.loads(args.tool_lock.read_bytes())
    if digest(args.semgrep_config.read_bytes()) != lock["semgrep"]["ruleset"]["sha256"]:
        raise ValueError("Semgrep rules do not match the frozen benchmark tool lock")
    for name in ("semgrep", "bandit", "gitleaks"):
        flag = "version" if name == "gitleaks" else "--version"
        version = subprocess.run([str(getattr(args, name)), flag], check=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=30,
                                 env={"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", ""),
                                      "SEMGREP_SETTINGS_FILE": str(args.raw_output / "version-settings.yml"),
                                      "SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off"}).stdout.decode().splitlines()[0]
        expected = ("bandit " if name == "bandit" else "") + lock[name]["version"]
        if version != expected:
            raise ValueError(name + " executable version does not match tool lock")
    manifest = json.loads(args.manifest.read_bytes())
    if set(args.only) - {p["id"] for p in manifest["projects"]}:
        raise ValueError("Unknown project id")
    args.raw_output.mkdir(parents=True, exist_ok=True)
    support = args.raw_output / "support"
    support.mkdir(exist_ok=True)
    (support / "bandit.yaml").write_text("exclude_dirs: []\n", encoding="utf-8")
    (support / "gitleaks.toml").write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
    (support / "empty-ignore").write_text("", encoding="utf-8")
    summary = {"schema_version": "1.0", "corpus_id": manifest["corpus_id"], "manifest_sha256": digest(args.manifest.read_bytes()),
               "semgrep_rules_sha256": digest(args.semgrep_config.read_bytes()), "tool_lock_sha256": digest(args.tool_lock.read_bytes()),
               "host": {"system": platform.system(), "machine": platform.machine()},
               "method": "Same exported public source bytes offered to each tool. Source is never executed. Counts are observations, not confirmed vulnerabilities or accuracy scores.",
               "projects": []}
    for project in manifest["projects"]:
        if args.only and project["id"] not in args.only:
            continue
        if "/" in project["id"] or project["id"] in {".", ".."}:
            raise ValueError("Invalid project id")
        source = args.source_root / project["id"]
        if not source.is_dir():
            raise ValueError("Missing exported source: " + str(source))
        # Reuse the corpus builder's byte verification, including unexpected-file detection.
        from scripts.scan_public_projects import verify_snapshot
        snapshot = json.loads((args.snapshots / (project["id"] + ".json")).read_bytes())
        if snapshot["revision"] != project["revision"] or snapshot["repository"] != project["repository"]:
            raise ValueError("Snapshot identity differs from pinned project manifest")
        verify_snapshot(source, snapshot)
        identity = tree_identity(source)
        rows = []
        for tool in ("semgrep", "bandit", "gitleaks"):
            row = execute(tool, source, args, args.raw_output / project["id"], support)
            save(args.output / project["id"] / (tool + ".json"), row)
            rows.append({key: row[key] for key in ("tool", "status", "finding_count", "wall_seconds", "process_exit_code", "errors", "files_reported_scanned")})
            print(project["id"], tool, row["status"], row["finding_count"], flush=True)
        if tree_identity(source) != identity:
            raise ValueError("Source changed during benchmark: " + project["id"])
        verify_snapshot(source, snapshot)
        summary["projects"].append({"id": project["id"], "repository": project["repository"], "revision": project["revision"],
                                    "source_manifest_sha256": snapshot["source_manifest_sha256"], "input": identity, "tools": rows})
    save(args.output / "summary.json", summary)
    if not args.skip_synthetic:
        save(args.output / "shared-pattern-fixtures.json", synthetic(args, args.raw_output, support))
    if args.cisco:
        cisco_metadata(args, support)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
