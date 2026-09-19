#!/usr/bin/env python3
"""Reproduce pinned public-project scans without executing target code.

Exports Git blobs (never a checkout or archive extraction), verifies exact source
bytes before every run, and invokes only the local Invarune scanner. Network
fetching is opt-in. Report evidence is a static review queue, not an exploit test.
"""
import argparse
import collections
import datetime
import fnmatch
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def safe_relative(value):
    path = pathlib.PurePosixPath(value)
    if (not value or path.is_absolute() or ".." in path.parts or "\\" in value
            or any(ord(c) < 32 for c in value) or ":" in value):
        raise ValueError("Unsafe source path")
    return path


def git(repo, *args):
    return subprocess.check_output(
        ["git", "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=",
         "--git-dir=" + str(repo), *args], stderr=subprocess.PIPE,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1"},
        timeout=180,
    )


def selected(path, project, policy):
    pure = safe_relative(path)
    if any(p in policy["excluded_directory_names"] for p in pure.parts[:-1]):
        return False
    if any(fnmatch.fnmatchcase(pure.name, p) for p in policy["excluded_basename_globs"]):
        return False
    if not (pure.suffix.lower() in policy["text_extensions"]
            or pure.name in policy["text_names"]
            or pure.name.lower().startswith(("dockerfile", ".env", "requirements"))):
        return False
    return (path in project["include_files"]
            or any(path == p or path.startswith(p.rstrip("/") + "/")
                   for p in project["include_prefixes"])
            or any(fnmatch.fnmatchcase(path, p) for p in project["include_globs"]))


def entries(repo, revision):
    if not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise ValueError("Revision must be a full 40-character Git commit ID")
    resolved = git(repo, "rev-parse", "--verify", revision + "^{commit}").decode().strip()
    if resolved != revision:
        raise ValueError("Revision did not resolve exactly")
    raw = git(repo, "ls-tree", "-r", "-z", revision)
    records = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, path = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        path = path.decode("utf-8", errors="strict")
        safe_relative(path)
        records.append({"path": path, "mode": mode, "kind": kind, "git_blob": oid})
    return sorted(records, key=lambda e: e["path"])


def fetch_project(repo, project):
    url = project["repository"]
    if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", url):
        raise ValueError("Corpus fetches support canonical HTTPS GitHub repository URLs only")
    if not re.fullmatch(r"[a-f0-9]{40}", project["revision"]):
        raise ValueError("Fetch requires a pinned full commit ID")
    if not repo.exists():
        repo.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "init", "--bare", str(repo)],
                       check=True, capture_output=True, timeout=30)
    git(repo, "fetch", "--no-tags", "--depth=1", url + ".git", project["revision"])


def prepare_project(repo, destination, project, policy, snapshot_path):
    records = entries(repo, project["revision"])
    selected_records = [r for r in records if selected(r["path"], project, policy)]
    nonregular = [r for r in selected_records if r["mode"] not in ("100644", "100755")
                  or r["kind"] != "blob"]
    chosen = [r for r in selected_records if r not in nonregular]
    if not chosen:
        raise ValueError("Selected project scope is empty")
    files, total = [], 0
    # Read immutable Git object IDs; git-show filters, smudge hooks and target
    # executables are never invoked. No path from a blob becomes an instruction.
    for record in chosen:
        size = int(git(repo, "cat-file", "-s", record["git_blob"]).decode())
        if size > policy["max_export_file_bytes"]:
            raise ValueError("Export file byte limit exceeded: " + record["path"])
        total += size
        if total > policy["max_export_total_bytes"]:
            raise ValueError("Export total byte limit exceeded")
        data = git(repo, "cat-file", "blob", record["git_blob"])
        if len(data) != size:
            raise ValueError("Git blob size changed")
        target = destination / record["path"]
        if destination.is_symlink() or any(p.is_symlink() for p in target.parents
                                                   if p == destination or destination in p.parents):
            raise ValueError("Export path contains a symlink")
        if target.is_symlink():
            raise ValueError("Export destination is a symlink")
        if target.exists():
            if not target.is_file() or target.read_bytes() != data:
                raise ValueError("Existing export differs from pinned source: " + record["path"])
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o644)  # Never make exported target scripts executable.
        files.append({"path": record["path"], "git_blob": record["git_blob"],
                      "git_mode": record["mode"], "bytes": len(data),
                      "sha256": hashlib.sha256(data).hexdigest()})
    snapshot = {"schema_version": "1.0", "project": project["id"],
                "repository": project["repository"], "revision": project["revision"],
                "selection_sha256": digest({"project": project, "policy": policy}),
                "source_manifest_sha256": digest(files), "files": files,
                "files_exported": len(files), "bytes_exported": total,
                "tracked_entries": len(records),
                "entries_outside_selected_scope": len(records) - len(selected_records),
                "selected_nonregular_entries_excluded": nonregular}
    verify_snapshot(destination, snapshot)
    if snapshot_path.exists() and read_json(snapshot_path) != snapshot:
        raise ValueError("Published snapshot manifest differs; do not silently replace corpus")
    write_json(snapshot_path, snapshot)
    return snapshot


def verify_snapshot(destination, snapshot):
    if destination.is_symlink() or not destination.is_dir():
        raise ValueError("Source export must be a real directory")
    if digest(snapshot["files"]) != snapshot["source_manifest_sha256"]:
        raise ValueError("Source manifest digest mismatch")
    expected = {r["path"]: r for r in snapshot["files"]}
    if len(expected) != len(snapshot["files"]):
        raise ValueError("Duplicate source manifest paths")
    actual = set()
    for base, dirs, names in os.walk(destination, followlinks=False):
        for name in dirs + names:
            if (pathlib.Path(base) / name).is_symlink():
                raise ValueError("Source export contains a symlink")
        for name in names:
            path = pathlib.Path(base) / name
            rel = path.relative_to(destination).as_posix()
            safe_relative(rel)
            actual.add(rel)
            if rel not in expected:
                raise ValueError("Unexpected source export file: " + rel)
            if not path.is_file():
                raise ValueError("Source export contains a nonregular file")
            record = expected[rel]
            if path.stat().st_size != record["bytes"]:
                raise ValueError("Source export size drift: " + rel)
            if hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
                raise ValueError("Source export content drift: " + rel)
    if actual != set(expected):
        raise ValueError("Source export is missing files")


def scan_project(source, output, project, snapshot, options, receipt_path, timeout, repeats):
    verify_snapshot(source, snapshot)
    command = [sys.executable, "-m", "ai_security_scan", str(source), "--output", str(output),
               "--summary-json"]
    for key in ("max_file_bytes", "max_total_bytes", "max_files", "max_entries", "fail_on"):
        command += ["--" + key.replace("_", "-"), str(options[key])]
    executions, first_digests = [], None
    for run in range(repeats):
        started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        timer = time.perf_counter()
        proc = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                              encoding="utf-8", timeout=timeout)
        elapsed = time.perf_counter() - timer
        if proc.returncode not in (0, 1, 2):
            raise ValueError("Scanner terminated unexpectedly: " + str(proc.returncode))
        try:
            summary = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise ValueError("Scanner failed to produce a JSON summary") from exc
        report = read_json(output / "report.json")
        if summary.get("scan_id") != report.get("scan_id"):
            raise ValueError("Summary and report scan IDs differ")
        if summary.get("exit_code") != proc.returncode:
            raise ValueError("Summary exit status differs from process")
        hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in sorted(output.glob("report.*"))}
        if set(hashes) != {"report.json", "report.md", "report.html", "report.sarif"}:
            raise ValueError("The four report artifacts were not produced")
        if first_digests is not None and hashes != first_digests:
            raise ValueError("Deterministic report bytes changed between repeated runs")
        first_digests = hashes
        executions.append({"run": run + 1, "started_at_utc": started,
                           "elapsed_seconds": round(elapsed, 6), "exit_code": proc.returncode,
                           "stderr": proc.stderr, "report_sha256": hashes})
    verify_snapshot(source, snapshot)
    def portable(path):
        try:
            return path.resolve().relative_to(ROOT).as_posix()
        except ValueError:
            return str(path.resolve())

    receipt = {"schema_version": "1.0", "project": project["id"],
               "repository": project["repository"], "revision": project["revision"],
               "source_manifest_sha256": snapshot["source_manifest_sha256"],
               "license": project["license"], "source_files": snapshot["files_exported"],
               "source_bytes": snapshot["bytes_exported"],
               "command": ["python3", "-m", "ai_security_scan", portable(source),
                           "--output", portable(output), *command[6:]],
               "actual_python": sys.version, "tool": report["tool"],
               "scan_id": report["scan_id"], "summary": report["summary"],
               "rule_counts": dict(sorted(collections.Counter(f["rule_id"] for f in report["findings"]).items())),
               "analysis_profiles": report.get("coverage", {}).get("analysis_profiles", {}),
               "execution": report["execution"], "repeated_runs": executions,
               "byte_identical_reports": repeats > 1,
               "target_code_executed": False, "optional_judge_enabled": False}
    write_json(receipt_path, receipt)
    return receipt


def render_results(manifest, records_root, output_root):
    rows = []
    for project in manifest["projects"]:
        path = records_root / "receipts" / (project["id"] + ".json")
        if path.exists():
            rows.append((project, read_json(path)))
    if not rows:
        return
    sources = sum(r["source_files"] for _, r in rows)
    scanned = sum(r["summary"]["files_scanned"] for _, r in rows)
    findings = sum(r["summary"]["open_findings"] for _, r in rows)
    gaps = sum(r["summary"]["coverage_gaps"] for _, r in rows)
    lines = ["# Invarune public-project scan results", "",
             "Actual offline scans of **{} pinned projects**, offering **{:,} identical exported files** to each source scanner. Invarune examined **{:,} files**, emitted **{} static review candidates**, and reported **{} coverage gaps** in this run set.".format(len(rows), sources, scanned, findings, gaps), "",
             "These are unverified patterns, not confirmed vulnerabilities or a precision/recall benchmark. A zero-finding result does not prove security. Exit 0 means the configured high-severity gate was not triggered; exit 2 marks incomplete analysis. See [methodology](README.md), [initial manual triage](TRIAGE.md), and the [competitor comparison](../external-tools/README.md).", "",
             "| Project / pinned revision | Exported / examined files | Critical / high / medium / low | Gaps | Exit | Runs / byte identical | Reports |", "|---|---:|---:|---:|---:|---|---|"]
    for project, receipt in rows:
        summary = receipt["summary"]
        severity = summary["severity_counts"]
        rel = pathlib.Path(os.path.relpath(output_root / project["id"], records_root)).as_posix()
        lines.append("| [{}]({}/tree/{}) / `{}` | {} / {} | {} / {} / {} / {} | {} | {} | {} / {} | [HTML]({}/report.html) · [Markdown]({}/report.md) · [JSON]({}/report.json) · [SARIF]({}/report.sarif) |".format(
            project["name"], project["repository"], project["revision"], project["revision"][:12],
            receipt["source_files"], summary["files_scanned"], *[severity[k] for k in ("critical", "high", "medium", "low")],
            summary["coverage_gaps"], receipt["execution"]["exit_code"], len(receipt["repeated_runs"]),
            "yes" if receipt["byte_identical_reports"] else "not verified", rel, rel, rel, rel))
        project_output = output_root / project["id"]
        records_link = pathlib.Path(os.path.relpath(records_root, project_output)).as_posix()
        project_output.mkdir(parents=True, exist_ok=True)
        (project_output / "README.md").write_text("\n".join([
            "# {} — actual Invarune scan".format(project["name"]), "",
            "Source: [{}]({}/tree/{}) at commit `{}`.".format(
                project["name"], project["repository"], project["revision"], project["revision"]), "",
            "**{} static review candidates; {} coverage gaps; exit {}.** These results do not establish exploitable vulnerabilities or certify this project as secure.".format(
                summary["open_findings"], summary["coverage_gaps"], receipt["execution"]["exit_code"]), "",
            "[HTML report](report.html) · [Markdown report](report.md) · [JSON report](report.json) · [SARIF report](report.sarif)", "",
            "[Run receipt]({}/receipts/{}.json) · [Exact source manifest]({}/snapshots/{}.json) · [Methodology]({}/README.md) · [Initial manual triage]({}/TRIAGE.md)".format(
                records_link, project["id"], records_link, project["id"], records_link, records_link), "",
            "No target code, target dependencies or live MCP service was executed. The optional model reviewer was disabled. Scope and language limitations are recorded in the report and methodology.", "",
        ]), encoding="utf-8")
    versions = sorted({r["tool"]["version"] for _, r in rows})
    python_versions = sorted({r["tool"]["python_version"] for _, r in rows})
    lines += ["", "Scanner version(s): **{}**. Python version(s): **{}**. No optional LLM judge, review exceptions, baselines, target builds, target tests, live MCP calls or target dependency installation were used.".format(
        ", ".join(versions), ", ".join(python_versions)), "",
        "## Run receipts", "",
        "Each receipt contains actual run timestamps, elapsed time, exit reason, tool implementation hash, selected-source manifest digest, all four artifact hashes and the normalized command. Wall times include report generation and were collected on a shared development machine; they are reproducibility metadata, not a controlled speed ranking.", ""]
    for project, receipt in rows:
        times = ", ".join("{:.3f}s".format(r["elapsed_seconds"]) for r in receipt["repeated_runs"])
        lines += ["- **{}:** [receipt](receipts/{}.json), [source manifest](snapshots/{}.json), elapsed {}.".format(
            project["name"], project["id"], project["id"], times)]
    lines += ["", "## Coverage interpretation", "",
              "The exported corpus includes languages and file types that individual tools do not analyze. Invarune's Go/C#/other generic-text profile checks selected secrets and text patterns; it does not provide language-specific dataflow for those languages. Python uses bounded local AST analysis; JavaScript/TypeScript uses bounded lexical analysis. Per-project profile counts and skipped-file reasons are in the reports.", "",
              "Production template files remain in scope. They can legitimately fail Python/JSON parsing before template rendering. Large Python modules may exceed deterministic work budgets, and binary/non-UTF-8 or unsupported inputs need another analyzer. The results retain these gaps rather than narrowing the corpus after viewing findings.", ""]
    (records_root / "RESULTS.md").write_text("\n".join(lines), encoding="utf-8")
    gallery = ["# Real-world report gallery", "", "These reports come from actual offline scans of pinned public repositories. [Results and methodology](../../../benchmarks/real-world/README.md) explain scope, coverage gaps and comparison limits.", ""]
    gallery += ["- [{}]({}/README.md)".format(project["name"], project["id"]) for project, _ in rows]
    (output_root / "README.md").write_text("\n".join(gallery) + "\n", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifest", type=pathlib.Path, default=ROOT / "benchmarks/real-world/manifest.json")
    parser.add_argument("--git-root", type=pathlib.Path, default=ROOT / "tmp/real-world-git", help="Trusted bare Git object stores; target code is never checked out or executed.")
    parser.add_argument("--source-root", type=pathlib.Path, default=ROOT / "tmp/real-world-src", help="Prepared byte-verified source exports shared by all scanners.")
    parser.add_argument("--output-root", type=pathlib.Path, default=ROOT / "examples/reports/real-world")
    parser.add_argument("--records-root", type=pathlib.Path, default=ROOT / "benchmarks/real-world")
    parser.add_argument("--project", action="append", help="Manifest project ID; repeat to select a subset. Default: all eight.")
    parser.add_argument("--prepare", action="store_true", help="Export pinned regular Git blobs and verify/create published source manifests; no network.")
    parser.add_argument("--fetch", action="store_true", help="Explicitly fetch pinned public commits from GitHub; implies --prepare. No submodules, hooks, checkout, builds or dependency installs.")
    parser.add_argument("--prepare-only", action="store_true", help="Prepare/verify source exports without scanning; implies --prepare.")
    parser.add_argument("--repeats", type=int, default=2, help="Number of real executions per project; verify all four reports are byte-identical (default: 2).")
    parser.add_argument("--timeout", type=int, default=600, help="Per scanner invocation timeout in seconds (default: 600).")
    args = parser.parse_args(argv)
    if args.repeats < 1 or args.timeout < 1:
        parser.error("--repeats and --timeout must be positive")
    manifest = read_json(args.manifest)
    projects = manifest["projects"]
    requested = set(args.project or [p["id"] for p in projects])
    unknown = requested - {p["id"] for p in projects}
    if unknown:
        parser.error("Unknown project IDs: " + ", ".join(sorted(unknown)))
    for project in projects:
        slug = project["id"]
        if slug not in requested:
            continue
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", slug):
            raise ValueError("Unsafe project ID")
        source, repo = args.source_root / slug, args.git_root / (slug + ".git")
        snapshot_path = args.records_root / "snapshots" / (slug + ".json")
        if args.fetch:
            fetch_project(repo, project)
        if args.prepare or args.fetch or args.prepare_only:
            snapshot = prepare_project(repo, source, project, manifest["scope_policy"], snapshot_path)
        else:
            snapshot = read_json(snapshot_path)
            if (snapshot["revision"] != project["revision"] or snapshot["project"] != slug
                    or snapshot["selection_sha256"] != digest({"project": project, "policy": manifest["scope_policy"]})):
                raise ValueError("Snapshot does not match the pinned corpus definition")
            verify_snapshot(source, snapshot)
        if args.prepare_only:
            print(json.dumps({"project": slug, "prepared_files": snapshot["files_exported"],
                              "source_manifest_sha256": snapshot["source_manifest_sha256"]}), flush=True)
            continue
        receipt = scan_project(source, args.output_root / slug, project, snapshot,
                               manifest["scanner_options"], args.records_root / "receipts" / (slug + ".json"),
                               args.timeout, args.repeats)
        print(json.dumps({"project": slug, "summary": receipt["summary"],
                          "exit_code": receipt["execution"]["exit_code"],
                          "byte_identical_reports": receipt["byte_identical_reports"]}), flush=True)
    if not args.prepare_only:
        render_results(manifest, args.records_root, args.output_root)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print("Public-project reproduction failed: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
