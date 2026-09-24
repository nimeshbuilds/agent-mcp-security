"""Bounded deterministic file traversal and aggregation. No target code is imported."""
import fnmatch
import hashlib
import json
import os
import platform
import stat
from collections import Counter
from pathlib import Path

from . import DISPLAY_NAME, __version__
from .fs import read_confined
from .security import redact

SEVERITIES = ("critical", "high", "medium", "low", "info")
EXCLUDED_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache", ".tox", "dist", "build", "coverage", ".next", ".cache"}
EXTENSIONS = {".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".config", ".env", ".sh", ".bash", ".zsh", ".dockerfile", ".tf", ".hcl", ".pem", ".key", ".md", ".mdc", ".txt", ".xml", ".lock", ".go", ".rs", ".java", ".rb", ".php", ".cs"}
MANIFESTS = {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "requirements.txt", "pyproject.toml", "uv.lock", "poetry.lock", "Pipfile", "Pipfile.lock", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock"}
ANALYSIS_PROFILES = {
    "python_ast": "Python AST, bounded aliases/values, selected same-file argument/return flow, exact literal guards and read-only tool write witnesses; no whole-program or runtime proof.",
    "javascript_lexical": "Bounded JavaScript/TypeScript tokens, calls, configuration and direct-return function-wrapper summaries; not a full JS/TS parser or control-flow analysis.",
    "json_structured": "Parsed JSON/JSONC fields, selected configuration rules and recognized tool/input-schema descriptions; runtime values and referenced files are not resolved.",
    "configuration_lexical": "Selected text/configuration patterns; YAML anchors, block-scalar semantics and dynamic templates are not fully resolved.",
    "generic_text": "Generic secret/URL signals, bounded English skill/instruction directives and selected Spanish/French/German override forms; no general translation. Language-specific execution/dataflow is not analyzed.",
}


def _analysis_profile(path):
    suffix, name = path.suffix.lower(), path.name.lower()
    if suffix in {".py", ".pyi"}:
        return "python_ast"
    if suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        return "javascript_lexical"
    if suffix in {".json", ".jsonc"}:
        return "json_structured"
    if suffix in {".yaml", ".yml", ".toml", ".ini", ".cfg", ".env", ".sh", ".bash", ".zsh", ".ps1"} or name.startswith(("dockerfile", ".env", "requirements")):
        return "configuration_lexical"
    return "generic_text"


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _digest(value):
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _is_supported(path):
    name = path.name.lower()
    return path.suffix.lower() in EXTENSIONS or name.startswith((".env", "dockerfile", "requirements")) or path.name in MANIFESTS or name in {"makefile", "jenkinsfile", ".npmrc", ".pypirc", ".netrc"}


def _excluded(rel, patterns):
    return any(fnmatch.fnmatchcase(rel, p) or fnmatch.fnmatchcase(rel + "/", p) or fnmatch.fnmatchcase("/" + rel, p) for p in patterns)


def _filesystem_identity(info):
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)


def _exclusion_snapshot(paths):
    """Pin explicit existing exclusions, including aliases outside the target.

    Resolving selected paths preserves existing behavior for trusted aliases and
    future output destinations. Device/inode/type matching additionally covers
    case aliases and hardlinks. Only caller-selected paths are resolved; target
    traversal entries are inspected with lstat and are never followed here.
    """
    roots = {Path(path).expanduser().resolve() for path in paths}
    identities = set()
    for path in roots:
        try:
            info = path.lstat()
        except (FileNotFoundError, NotADirectoryError):
            # Report/baseline destinations commonly do not exist until export.
            continue
        if stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode):
            if not info.st_ino:
                raise ValueError("An existing explicit exclusion has no stable filesystem identity")
            identities.add(_filesystem_identity(info))
    return roots, identities


def _matches_exclusion(path, roots, identities):
    if path.absolute() in roots:
        return True, None
    if not identities:
        return False, None
    try:
        info = path.lstat()
    except OSError:
        # Normal traversal records any applicable read failure below. Do not
        # treat unreadable entries as excluded or follow a possible symlink.
        return False, None
    return _filesystem_identity(info) in identities, info


def load_controls():
    path = Path(__file__).parent / "data" / "controls.json"
    if not path.exists():
        raise ValueError("Packaged control catalog is missing")
    value = json.loads(path.read_text(encoding="utf-8"))
    return value["controls"] if isinstance(value, dict) else value


def load_baseline(path):
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema_version") != "1.0" or not isinstance(value.get("findings"), list):
        raise ValueError("Baseline must have schema_version '1.0' and a findings list")
    out = {}
    for item in value["findings"]:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not isinstance(item.get("reason"), str) or not item["reason"].strip():
            raise ValueError("Each baseline entry requires an id and a non-empty reason")
        if item["id"] in out:
            raise ValueError("Duplicate baseline finding id")
        out[item["id"]] = item["reason"]
    return out


def scan(root, *, exclude=(), output_paths=(), max_file_bytes=1_000_000, max_total_bytes=50_000_000, max_files=20_000, max_entries=100_000, baseline=None, default_excluded_directories=None, scans=None):
    from .analyzer import analyze_file, analyze_file_errors
    from .rules import RULES

    from .selection import resolve_scan_selection
    selection = resolve_scan_selection(scans)
    selected_rules = set(selection["selected_rule_ids"])
    selected_controls = set(selection["selected_control_ids"])

    original_root = Path(root).expanduser()
    if original_root.is_symlink():
        raise ValueError("Target root must not be a symbolic link")
    root = original_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Target must be a directory")
    limits = {"max_file_bytes": max_file_bytes, "max_total_bytes": max_total_bytes, "max_files": max_files, "max_entries": max_entries}
    if any(isinstance(v, bool) or not isinstance(v, int) or v <= 0 for v in limits.values()):
        raise ValueError("All scan limits must be positive integers")
    baseline = baseline or {}
    excluded_directories = EXCLUDED_DIRS if default_excluded_directories is None else set(default_excluded_directories)
    if any(not isinstance(name, str) or not name or "/" in name or "\\" in name for name in excluded_directories):
        raise ValueError("Default directory exclusions must be directory names")
    skip_roots, skip_identities = _exclusion_snapshot(output_paths)
    root_stat = root.stat()
    root_identity = (root_stat.st_dev, root_stat.st_ino)
    findings, skipped, errors, files = [], [], [], []
    deferred_documents = {}

    def inspect_source(rel, source, instruction_context=False):
        analysis_errors = []
        detected = analyze_file(rel, source, instruction_context=instruction_context, analysis_errors=analysis_errors)
        analysis_errors.extend(analyze_file_errors(rel, source, instruction_context=instruction_context, include_flow=False))
        for problem in sorted(set(analysis_errors)):
            errors.append({"path": redact(rel), "error": redact(str(problem)), "kind": "parse_error"})
        for finding in detected:
            if finding["rule_id"] not in selected_rules:
                continue
            raw_evidence = finding.get("evidence", "")
            identifier = _digest([finding["rule_id"], rel, finding["line"], raw_evidence])[:24]
            evidence = "[REDACTED: credential-related source evidence; inspect this location locally]" if finding["rule_id"] in {"AI010", "AI011", "AI034"} else redact(raw_evidence)[:2000]
            finding.update({"id": identifier, "finding_id": identifier, "path": redact(rel), "evidence": evidence, "status": "suppressed" if identifier in baseline else "open"})
            if identifier in baseline:
                finding["suppression_reason"] = redact(baseline[identifier])
            findings.append(finding)

    bytes_read, bytes_charged, failed_read_bytes_charged, entries = 0, 0, 0, 0
    interrupted = False
    inventory = {"extensions": Counter(), "dependency_manifests": [], "agent_mcp_signals": []}

    def skip(path, reason, gap=False):
        skipped.append({"path": redact(path), "reason": reason, "coverage_gap": gap})

    def walk_error(exc):
        name = os.path.relpath(exc.filename or root, root)
        errors.append({"path": redact(name), "error": "Directory could not be read", "kind": "read_error"})

    for parent, directories, names in os.walk(root, topdown=True, followlinks=False, onerror=walk_error):
        directories.sort()
        names.sort()
        kept = []
        for name in directories:
            path = Path(parent) / name
            rel = path.relative_to(root).as_posix()
            excluded_path, entry_stat = _matches_exclusion(path, skip_roots, skip_identities)
            if excluded_path:
                continue
            entries += 1
            if entries > max_entries:
                interrupted = True
                break
            is_link = stat.S_ISLNK(entry_stat.st_mode) if entry_stat is not None else path.is_symlink()
            if is_link:
                skip(rel, "symlink_directory", True)
            elif name in excluded_directories:
                skip(rel, "default_excluded_directory")
            elif _excluded(rel, exclude):
                skip(rel, "user_exclusion")
            else:
                kept.append(name)
        directories[:] = kept
        if interrupted:
            break
        for name in names:
            path = Path(parent) / name
            excluded_path, entry_stat = _matches_exclusion(path, skip_roots, skip_identities)
            if excluded_path:
                continue
            entries += 1
            if entries > max_entries:
                interrupted = True
                break
            rel = path.relative_to(root).as_posix()
            is_link = stat.S_ISLNK(entry_stat.st_mode) if entry_stat is not None else path.is_symlink()
            if is_link:
                skip(rel, "symlink_file", True)
                continue
            if _excluded(rel, exclude):
                skip(rel, "user_exclusion")
                continue
            if not _is_supported(path):
                skip(rel, "unsupported_extension")
                continue
            if len(files) >= max_files:
                interrupted = True
                break
            try:
                # lstat and O_NOFOLLOW prevent reading symbolic links/special files.
                st = entry_stat if entry_stat is not None else path.lstat()
                if not stat.S_ISREG(st.st_mode):
                    skip(rel, "non_regular_file", True)
                    continue
                if st.st_size > max_file_bytes:
                    skip(rel, "file_size_limit", True)
                    continue
                # Reserve one sentinel byte to detect growth without exceeding
                # the total I/O budget, including failed or rejected reads.
                if bytes_charged + st.st_size + 1 > max_total_bytes:
                    skip(rel, "total_byte_limit", True)
                    interrupted = True
                    break
                try:
                    data, opened = read_confined(root, rel, st.st_size, root_identity)
                except (OSError, ValueError, RuntimeError):
                    bytes_charged += st.st_size + 1
                    failed_read_bytes_charged += st.st_size + 1
                    raise
                bytes_read += len(data)
                bytes_charged += len(data)
                if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                    skip(rel, "file_changed_during_open", True)
                    continue
                if len(data) > max_file_bytes or bytes_charged > max_total_bytes:
                    skip(rel, "file_grew_beyond_limit", True)
                    continue
                if b"\x00" in data:
                    skip(rel, "binary_content", True)
                    continue
                try:
                    source = data.decode("utf-8-sig")
                except UnicodeDecodeError:
                    skip(rel, "non_utf8_content", True)
                    continue
                files.append({"path": redact(rel), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "analysis_profile": _analysis_profile(path)})
                inventory["extensions"][path.suffix.lower() or "(none)"] += 1
                if name in MANIFESTS:
                    inventory["dependency_manifests"].append(redact(rel))
                signal_terms = ("fastmcp", "modelcontextprotocol", "mcpservers", "langchain", "langgraph", "crewai", "autogen", "agentsdk", "agents.run")
                signals = [term for term in signal_terms if term in source.lower()]
                if signals:
                    inventory["agent_mcp_signals"].append({"path": redact(rel), "signals": signals})
                if path.suffix.lower() in {".md", ".mdc"}:
                    deferred_documents[rel] = source
                else:
                    inspect_source(rel, source)
            except (OSError, ValueError, RuntimeError) as exc:
                errors.append({"path": redact(rel), "error": type(exc).__name__ + " while reading or analyzing file", "kind": "analysis_error"})
        if interrupted:
            break
    from .skill_scope import discover_skill_scope
    contextual, skill_roots, skill_errors = discover_skill_scope(deferred_documents)
    inventory["skill_manifests"] = [redact(path) for path in skill_roots]
    inventory["skill_instruction_files"] = [redact(path) for path in sorted(contextual)]
    errors.extend({**item, "path": redact(item["path"]), "error": redact(item["error"])} for item in skill_errors)
    for rel, source in sorted(deferred_documents.items()):
        try:
            inspect_source(rel, source, instruction_context=rel in contextual)
        except (OSError, ValueError, RuntimeError) as exc:
            errors.append({"path": redact(rel), "error": type(exc).__name__ + " while analyzing skill/text file", "kind": "analysis_error"})
    if interrupted:
        errors.append({"path": ".", "error": "Traversal stopped at configured resource limit; additional files may be unscanned", "kind": "resource_limit"})
    if not files:
        errors.append({"path": ".", "error": "No supported UTF-8 source or configuration files were scanned", "kind": "empty_scope"})
    findings.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["path"], f["line"], f["rule_id"], f["id"]))
    unique = {f["id"]: f for f in findings}
    findings = list(unique.values())
    controls = []
    catalog = load_controls()
    rules_by_id = {r["id"]: r for r in RULES if r["id"] in selected_rules}
    for control in catalog:
        if control["id"] not in selected_controls:
            continue
        mapped = sorted(set(control.get("automated_rule_ids", [])) & set(rules_by_id))
        matches = [f["id"] for f in findings if f["rule_id"] in mapped and f["status"] == "open"]
        suppressed_matches = [f["id"] for f in findings if f["rule_id"] in mapped and f["status"] == "suppressed"]
        status = "review_required"
        if mapped:
            status = "findings_detected" if matches else "findings_suppressed" if suppressed_matches else "no_pattern_detected"
        elif control.get("validation") == "dynamic":
            status = "runtime_validation_required"
        elif control.get("validation") == "manual":
            status = "manual_review_required"
        controls.append({**control, "automated_rule_ids": mapped, "status": status, "finding_ids": matches, "suppressed_finding_ids": suppressed_matches, "assurance": "Partial static coverage only; absence of a finding is not a pass" if mapped else "Not established by this static scan"})
    active = [f for f in findings if f["status"] == "open"]
    counts = {severity: sum(f["severity"] == severity for f in active) for severity in SEVERITIES}
    coverage_gaps = len(errors) + sum(s["coverage_gap"] for s in skipped)
    summary = {"open_findings": len(active), "suppressed_findings": len(findings) - len(active), "severity_counts": counts, "files_scanned": len(files), "bytes_read": bytes_read, "bytes_charged": bytes_charged, "failed_read_bytes_charged": failed_read_bytes_charged, "coverage_gaps": coverage_gaps, "assessment": "static_triage_only", "scan_complete_within_selected_scope": coverage_gaps == 0}
    config = {**limits, **selection, "exclude": sorted(set(exclude)), "default_excluded_directories": sorted(excluded_directories), "generated_outputs_and_judge_config_excluded": True,
              "explicit_exclusion_matching": "resolved_paths_and_snapshot_filesystem_identities",
              "explicit_exclusion_identity_scope": "Existing selected files and directories, including case aliases and file hardlinks; inputs must remain stable during the scan. Device/inode identities are not persisted in reports."}
    implementation = hashlib.sha256()
    for module in sorted(Path(__file__).parent.glob("*.py")):
        implementation.update(module.name.encode())
        implementation.update(module.read_bytes())
    # Keep the machine identifier stable for existing report consumers and SARIF
    # history. The product brand is separate, additive display metadata.
    tool = {"name": "agent-mcp-security-scan", "display_name": DISPLAY_NAME, "version": __version__, "python_version": platform.python_version(), "implementation_sha256": implementation.hexdigest()}
    deterministic_input = {"files": files, "config": config, "rules": RULES, "controls": catalog, "baseline": baseline, "tool": tool, "errors": errors, "skipped": skipped}
    return {"schema_version": "1.0", "tool": tool, "scan_id": _digest(deterministic_input), "mode": "deterministic_static", "target": ".", "summary": summary, "configuration": config, "inventory": inventory, "files": files, "findings": findings, "controls": controls, "coverage": {"analysis_profiles": {name: {"files": sum(item["analysis_profile"] == name for item in files), "scope": description} for name, description in ANALYSIS_PROFILES.items()}, "errors": sorted(errors, key=lambda e: (e["path"], e["error"])), "skipped": sorted(skipped, key=lambda s: (s["path"], s["reason"])), "rules_enabled": sorted(rules_by_id), "selection": {**selection, "catalog_rules": len(RULES), "catalog_controls": len(catalog), "execution": "Selected rule findings and control review only; shared bounded file, syntax, metadata and integrity checks still run and preserve operational gaps."}, "unmatched_baseline_ids": sorted(set(baseline) - set(unique)), "limitations": ["Static pattern and local syntax analysis do not prove exploitability, authentication, isolation, or absence of vulnerabilities.", "Python receives AST-based call checks; other source languages receive selected textual/configuration checks, not whole-program dataflow.", "No dependencies are installed, target code executed, services contacted, or CVE feed queried.", "Default excluded directories and unsupported files remain outside the selected scan scope.", "Prompt injection resistance, authorization, tenant separation, runtime egress, and human approval need adversarial/runtime validation.", "Evidence redaction is best-effort; reports and optional judge payloads can still contain sensitive code or data."]}, "judge": {"enabled": False}}
