#!/usr/bin/env python3
"""Compare observed scanner locations; agreement never supplies a TP label.

Reads actual run outputs and creates an exhaustive observation ledger, conservative
pairwise matches, location-only relations, and explicit unmatched/ambiguous sets.
It neither scans targets nor calls models, and never executes target code.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import itertools
import json
from pathlib import Path
import re
import sys
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from ai_security_scan.rules import RULES
from ai_security_scan.security import redact
from scripts.benchmark_competitors import clean_path, normalize
from scripts.scan_public_projects import verify_snapshot, safe_relative


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes((json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))


FAMILIES = {
    "AI001": "dynamic_code_execution", "AI002": "shell_execution", "AI003": "shell_execution",
    "AI004": "yaml_object_deserialization", "AI005": "pickle_family_api", "AI006": "tls_verification_disabled",
    "AI007": "wildcard_cors", "AI008": "wildcard_listener", "AI009": "debug_enabled",
    "AI010": "credential_literal", "AI011": "private_key_material", "AI012": "shell_execution",
    "AI013": "dynamic_code_execution", "AI014": "dynamic_outbound_url", "AI015": "filesystem_path_input",
    "AI016": "insecure_temporary_name", "AI017": "jwt_signature_bypass", "AI018": "unpinned_package_runner",
    "AI019": "download_to_shell", "AI020": "unpinned_ci_action", "AI021": "container_root_user",
    "AI022": "privileged_container", "AI023": "container_socket", "AI024": "unpinned_container_image",
    "AI025": "dependency_version_range", "AI026": "authentication_disabled", "AI027": "wildcard_permission",
    "AI028": "mcp_token_passthrough", "AI029": "plaintext_mcp_transport", "AI030": "browser_credentials",
    "AI031": "agent_safeguard_bypass", "AI032": "privileged_prompt_input", "AI033": "secret_logging",
    "AI034": "credential_url_query", "AI035": "model_checkpoint_deserialization", "AI036": "sql_construction",
    "AI037": "archive_extraction", "AI038": "security_randomness", "AI039": "template_rendering",
    "AI040": "unsafe_html_rendering", "AI041": "authentication_disabled", "AI042": "host_namespace",
    "AI043": "instruction_hierarchy_override", "AI044": "sensitive_transfer_instruction",
    "AI045": "covert_or_approval_bypass_instruction", "AI046": "readonly_contract_conflict", "AI047": "permissive_file_mode",
}

BANDIT_FAMILIES = {
    "B101": "assert_statement", "B102": "dynamic_code_execution", "B103": "permissive_file_mode",
    "B104": "wildcard_listener", "B105": "credential_literal", "B106": "credential_literal",
    "B107": "credential_literal", "B108": "temporary_directory_literal", "B110": "exception_pass",
    "B112": "exception_continue", "B113": "request_timeout_missing", "B202": "archive_extraction",
    "B301": "pickle_family_api", "B307": "dynamic_code_execution", "B310": "dynamic_outbound_url",
    "B311": "security_randomness", "B314": "xml_parser_api", "B324": "weak_hash_algorithm",
    "B403": "pickle_import", "B404": "subprocess_import", "B405": "xml_parser_import",
    "B413": "cryptography_import", "B501": "tls_verification_disabled", "B506": "yaml_object_deserialization",
    "B602": "shell_execution", "B603": "subprocess_without_shell", "B606": "process_execution_without_shell",
    "B607": "partial_executable_path", "B608": "sql_construction", "B701": "template_autoescape_disabled",
}

SEMGREP_FAMILIES = {
    "go.lang.security.audit.crypto.use_of_weak_crypto.use-of-sha1": "weak_hash_algorithm",
    "python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected": "dynamic_outbound_url",
    "python.lang.security.audit.exec-detected.exec-detected": "dynamic_code_execution",
    "python.lang.security.audit.eval-detected.eval-detected": "dynamic_code_execution",
    "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true": "shell_execution",
    "python.lang.security.deserialization.pickle.avoid-pickle": "pickle_family_api",
    "python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load": "yaml_object_deserialization",
    "python.requests.security.disabled-cert-validation.disabled-cert-validation": "tls_verification_disabled",
    "python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1": "weak_hash_algorithm",
    "python.lang.security.use-defused-xml.use-defused-xml": "xml_parser_api",
}

FAMILY_NOTES = {
    "pickle_family_api": "Pickle/dill-style API surface; Semgrep may flag serialization as well as deserialization. Same location does not establish identical risk semantics.",
    "credential_literal": "Credential-like literal patterns. Scanners use different secret definitions; no live credential validity is inferred.",
    "security_randomness": "Non-cryptographic randomness observation. Some rules warn about every call while others require a security-value context.",
    "dynamic_outbound_url": "Dynamic outbound URL/input surface, including urllib schemes. Dataflow confidence and allowed schemes differ across rules.",
    "sql_construction": "SQL construction/interpolation surface. Parameter binding and identifier provenance require independent review.",
    "dynamic_code_execution": "Dynamic eval/exec-style execution at the same source location; reachability and trust boundaries remain unverified.",
    "shell_execution": "Shell-enabled execution surface at the same location. Calls without a shell/imports are separate families.",
    "archive_extraction": "Archive extraction call at the same location; safe-filter inference differs by rule.",
    "instruction_hierarchy_override": "Declared agent instruction or literal tool description requests overriding higher-trust instructions; static text evidence does not establish runtime compliance or author intent.",
    "sensitive_transfer_instruction": "Agent-facing text combines a transfer directive, sensitive object and explicit destination; intended authorization and actual data disclosure are not established.",
    "covert_or_approval_bypass_instruction": "Agent-facing instruction requests concealment of an action or bypass of an approval/sandbox boundary; no execution or policy bypass is demonstrated.",
    "readonly_contract_conflict": "A literal readOnlyHint=true conflicts with a destructive description or a recognized direct write in a supported Python handler. Metadata and source witnesses do not establish runtime execution or authorization.",
}

PREDICATE_NOTES = {
    "assert_statement": "An assert statement exists; whether it is an authorization/input-validation boundary lost under Python optimization requires context.",
    "exception_pass": "An exception handler contains pass; whether suppressed failure violates a security boundary requires context.",
    "exception_continue": "An exception handler continues iteration; whether ignored failures cause a security issue requires context.",
    "credential_literal": "A literal resembles a credential assignment/argument/token; verify its actual role, excluding placeholders, error labels, public identifiers and examples.",
    "weak_hash_algorithm": "SHA-1 or another flagged hash is used; distinguish non-security identifiers/checksums from authentication, integrity or collision-resistance requirements.",
    "pickle_family_api": "A pickle-family API is invoked; identify whether it serializes or deserializes and whether deserialized bytes cross a trust boundary.",
    "dynamic_code_execution": "Dynamic content reaches eval/exec or equivalent; identify the content source and whether trust/authorization boundaries permit attacker control.",
    "subprocess_without_shell": "A subprocess call runs without shell=True; check executable selection and arguments. This is not itself proof of shell injection.",
    "process_execution_without_shell": "A process-spawning API runs without a shell; executable and argument provenance determine risk.",
    "partial_executable_path": "A command uses an executable name without an absolute path; evaluate PATH control and the execution environment.",
    "subprocess_import": "The subprocess module is imported; import presence alone does not establish a dangerous call or exploitable path.",
    "pickle_import": "A pickle-related module is imported; import presence alone does not establish untrusted deserialization.",
    "xml_parser_import": "A potentially unsafe XML module is imported; determine whether it is used to parse untrusted documents.",
    "xml_parser_api": "An XML parser API is used; entity behavior, runtime safeguards and document provenance determine vulnerability applicability.",
    "cryptography_import": "A flagged cryptography module is imported; review actual supported APIs and cryptographic use before concluding weakness.",
    "sql_construction": "A SQL string is constructed with interpolation/concatenation; inspect identifiers and values separately, binding and helper behavior.",
    "security_randomness": "A non-cryptographic random API is used; determine whether output must be unpredictable or is only sampling/jitter/test data.",
    "dynamic_outbound_url": "An outbound URL is nonliteral; assess attacker influence, permitted schemes/hosts and egress controls.",
    "archive_extraction": "An archive extraction API is called; assess member traversal/link handling, filters and archive trust.",
    "dependency_version_range": "A direct dependency declares a non-exact version; frozen lockfiles and verified install behavior may mitigate the policy concern.",
    "unpinned_container_image": "An image reference lacks a content digest; inspect release/build resolution and provenance. This is a reproducibility policy signal.",
    "unsafe_html_rendering": "An unsafe HTML rendering interface is used; establish input provenance and effective sanitization before concluding XSS.",
    "wildcard_cors": "An origin policy allows any origin; actual authentication, credentials mode and intended endpoint exposure determine risk.",
    "secret_logging": "A logged value has a credential-related role/name; verify the actual emitted value and redaction behavior.",
    "template_autoescape_disabled": "Template autoescape is disabled/omitted; evaluate output content type and attacker-controlled data.",
    "template_rendering": "Template source is constructed dynamically; distinguish template syntax control from ordinary bound template values.",
    "temporary_directory_literal": "A hard-coded shared temporary location is used; evaluate ownership, creation flags and namespace isolation.",
    "permissive_file_mode": "A permission mode grants broad access; assess sensitivity, filesystem location and effective ownership.",
    "request_timeout_missing": "A network call lacks an explicit timeout; assess bounded defaults and denial-of-service exposure.",
    "wildcard_listener": "A service listens on all interfaces; intended exposure, network policy and authentication determine risk.",
    "debug_enabled": "Debug behavior is enabled; evaluate reachable runtime configuration and exposed debugging features.",
    "jwt_signature_bypass": "JWT verification is explicitly bypassed; determine whether decoded data is subsequently trusted or independently verified.",
    "instruction_hierarchy_override": "Verify that the cited text is an operative instruction on a declared agent-facing surface, rather than a negation, quotation or example; separately test the deployed agent's instruction boundary.",
    "sensitive_transfer_instruction": "Verify the transfer directive, sensitive object and explicit destination occur in the same applicable agent instruction; review destination ownership and authorization before interpreting disclosure risk.",
    "covert_or_approval_bypass_instruction": "Verify an operative action-concealment or approval/sandbox-bypass instruction, excluding negation and inert examples; runtime policy enforcement is separate evidence.",
    "readonly_contract_conflict": "Verify the untrusted annotation readOnlyHint=true and the cited description or direct write belong to the same supported literal tool definition; distinguish static source effect from branch execution and write authorization.",
}


def rule_map():
    mapping = {}
    titles = {r["id"]: r["title"] for r in RULES}
    for tool, rules in [("invarune", FAMILIES), ("bandit", BANDIT_FAMILIES), ("semgrep", SEMGREP_FAMILIES),
                        ("gitleaks", {"generic-api-key": "credential_literal", "jwt": "credential_literal"})]:
        for rule, family in rules.items():
            mapping[tool + ":" + rule] = {
                "family": family, "rule_message": titles[rule] if tool == "invarune" else family.replace("_", " ").capitalize(),
                "message_origin": "Invarune rule title" if tool == "invarune" else "Benchmark-authored brief family label; original rule is identified separately",
                "rationale": FAMILY_NOTES.get(family, "A narrowly named API/configuration surface; imports and differently scoped operations are kept separate."),
                "review_predicate": PREDICATE_NOTES.get(family, "Review the named API/configuration predicate, input trust and deployed safeguards; the pattern itself does not establish exploitation."),
            }
    return mapping


def spans_overlap(a, b):
    return a["line_start"] <= b["line_end"] and b["line_start"] <= a["line_end"]


def pairwise(left, right, left_tool, right_tool):
    """Partition every observation, keeping many-to-many and unmapped relations explicit."""
    by_location = defaultdict(list)
    for item in right:
        by_location[(item["project_id"], item["path"])].append(item)
    family_edges, location_edges = [], []
    left_matches, right_matches = defaultdict(set), defaultdict(set)
    for a in left:
        for b in by_location.get((a["project_id"], a["path"]), []):
            if not spans_overlap(a, b):
                continue
            if a["family_mapped"] and b["family_mapped"] and a["family"] == b["family"]:
                family_edges.append({"left_id": a["id"], "right_id": b["id"], "family": a["family"]})
                left_matches[a["id"]].add(b["id"])
                right_matches[b["id"]].add(a["id"])
            else:
                location_edges.append({"left_id": a["id"], "right_id": b["id"],
                                       "reason": "overlapping_location_but_different_or_unmapped_family"})
    exact = [e for e in family_edges if len(left_matches[e["left_id"]]) == 1 and len(right_matches[e["right_id"]]) == 1]
    exact_ids = {(e["left_id"], e["right_id"]) for e in exact}
    ambiguous = [e for e in family_edges if (e["left_id"], e["right_id"]) not in exact_ids]
    result = {"left_tool": left_tool, "right_tool": right_tool, "one_to_one_matches": exact,
              "ambiguous_family_location_edges": ambiguous, "location_only_edges": location_edges,
              "left_without_family_match": [x["id"] for x in left if x["id"] not in left_matches],
              "right_without_family_match": [x["id"] for x in right if x["id"] not in right_matches]}
    result["counts"] = {"left_observations": len(left), "right_observations": len(right),
                        "one_to_one_pairs": len(exact), "ambiguous_edges": len(ambiguous),
                        "left_in_ambiguous_edges": len({x["left_id"] for x in ambiguous}),
                        "right_in_ambiguous_edges": len({x["right_id"] for x in ambiguous}),
                        "location_only_edges": len(location_edges),
                        "left_without_family_match": len(result["left_without_family_match"]),
                        "right_without_family_match": len(result["right_without_family_match"])}
    return result


def observation(project, tool, version, finding, run, raw_hash, mapping, duplicate_index=0):
    rule = finding["rule_id"]
    key = tool + ":" + rule
    meta = mapping.get(key, {})
    line = int(finding["line"])
    end = max(line, int(finding.get("end_line", line)))
    if line < 1 or end - line > 100000:
        raise ValueError("Invalid observation source span")
    path = finding["path"]
    safe_relative(path)
    if path.startswith("[outside"):
        raise ValueError("Observation is outside selected source")
    ident = {"project": project["id"], "revision": project["revision"], "tool": tool, "rule": rule,
             "path": path, "start": line, "end": end, "duplicate_index": duplicate_index}
    item = {"id": "obs-" + sha(canonical(ident))[:24], "project_id": project["id"], "repository": project["repository"],
            "revision": project["revision"], "source_manifest_sha256": run["source_manifest_sha256"],
            "tool": tool, "tool_version": version, "native_finding_id": finding.get("finding_id", finding.get("id")),
            "rule_id": rule, "rule_message": redact(meta.get("rule_message", rule))[:240],
            "message_origin": meta.get("message_origin", "Unmapped native rule identifier"),
            "family": meta.get("family", "unmapped:" + key), "family_mapped": bool(meta),
            "family_rationale": meta.get("rationale", "Unmapped rules are not assumed equivalent to any other tool's rule."),
            "review_predicate": meta.get("review_predicate", "Rule not mapped; inspect its documented predicate before adjudicating."),
            "path": path, "line_start": line, "line_end": end,
            "severity": finding["severity"], "confidence": finding.get("confidence"),
            "status": finding.get("status", "reported"), "run_status": run["status"], "raw_report_sha256": raw_hash,
            "adjudication": "unreviewed", "duplicate_index": duplicate_index,
            "source_url": project["repository"] + "/blob/" + project["revision"] + "/" + quote(path, safe="/") + "#L" + str(line)}
    return item


def verified_invarune_report(raw, receipt):
    """Bind findings to the actual recorded execution bytes, not just metadata."""
    runs = receipt.get("repeated_runs")
    digest = sha(raw)
    if (not isinstance(runs, list) or not runs
            or any(not isinstance(run, dict)
                   or not isinstance(run.get("report_sha256"), dict)
                   or run.get("report_sha256", {}).get("report.json") != digest
                   for run in runs)):
        raise ValueError("Invarune report bytes differ from recorded execution hashes")
    report = json.loads(raw)
    if report["scan_id"] != receipt["scan_id"] or report["tool"] != receipt["tool"]:
        raise ValueError("Invarune report differs from actual receipt")
    return report


def build(args):
    manifest_raw = args.manifest.read_bytes()
    manifest = json.loads(manifest_raw)
    lock = json.loads(args.tool_lock.read_bytes())
    external_summary = json.loads((args.external_results / "summary.json").read_bytes())
    external_projects = {p["id"]: p for p in external_summary["projects"]}
    mapping, observations, runs = rule_map(), [], []
    roots, inputs = {}, []
    for project in manifest["projects"]:
        pid = project["id"]
        # Tool outputs use absolute source paths even when a caller supplies a
        # relative --source-root. Normalize against the same canonical root.
        root = (args.source_root / pid).resolve()
        snapshot = json.loads((args.snapshots / (pid + ".json")).read_bytes())
        verify_snapshot(root, snapshot)
        roots[pid] = str(root.resolve())
        if external_projects[pid]["source_manifest_sha256"] != snapshot["source_manifest_sha256"]:
            raise ValueError("External run source identity mismatch")
        if external_projects[pid]["revision"] != project["revision"]:
            raise ValueError("External run revision mismatch")
        source_hash = snapshot["source_manifest_sha256"]
        inputs.append({"project_id": pid, "revision": project["revision"], "source_manifest_sha256": source_hash,
                       "files": snapshot["files_exported"], "bytes": snapshot["bytes_exported"]})
        receipt = json.loads((args.invarune_receipts / (pid + ".json")).read_bytes())
        if receipt["source_manifest_sha256"] != source_hash or receipt["revision"] != project["revision"]:
            raise ValueError("Invarune run source identity mismatch")
        raw = (args.invarune_reports / pid / "report.json").read_bytes()
        report = verified_invarune_report(raw, receipt)
        own = {"tool": "invarune", "version": report["tool"]["version"], "project_id": pid,
               "source_manifest_sha256": source_hash, "raw_report_sha256": sha(raw),
               "finding_count": report["summary"]["open_findings"], "errors": report["coverage"]["errors"],
               "coverage_gaps": report["summary"]["coverage_gaps"], "files_reported_scanned": report["summary"]["files_scanned"],
               "status": "completed_with_analysis_gaps" if report["summary"]["coverage_gaps"] else "completed",
               "process_exit_code": receipt["execution"]["exit_code"], "implementation_sha256": receipt["tool"]["implementation_sha256"]}
        runs.append(own)
        for f in report["findings"]:
            observations.append(observation(project, "invarune", own["version"], f, own, sha(raw), mapping))
        for tool in ("semgrep", "bandit", "gitleaks"):
            measured = json.loads((args.external_results / pid / (tool + ".json")).read_bytes())
            raw = (args.external_raw / pid / (tool + ".json")).read_bytes()
            if sha(raw) != measured["raw_report_sha256"]:
                raise ValueError("External raw output differs from measured hash")
            normalized = normalize(tool, json.loads(raw), root)
            if normalized["findings"] != measured["findings"] or normalized["errors"] != measured["errors"]:
                raise ValueError("External normalization differs from measured output")
            run = {"tool": tool, "version": lock[tool]["version"], "project_id": pid,
                   "source_manifest_sha256": source_hash, "raw_report_sha256": sha(raw),
                   **{k: measured[k] for k in ("finding_count", "errors", "files_reported_scanned", "status", "process_exit_code")}}
            runs.append(run)
            duplicate_counts = Counter()
            for f in normalized["findings"]:
                fingerprint = canonical(f)
                duplicate_index = duplicate_counts[fingerprint]
                duplicate_counts[fingerprint] += 1
                observations.append(observation(project, tool, run["version"], f, run, sha(raw), mapping, duplicate_index))
        verify_snapshot(root, snapshot)
    observations.sort(key=lambda x: (x["project_id"], x["path"], x["line_start"], x["tool"], x["rule_id"], x["id"]))
    if len({x["id"] for x in observations}) != len(observations):
        raise ValueError("Duplicate normalized observation identity")
    by_tool = {t: [x for x in observations if x["tool"] == t] for t in ("invarune", "semgrep", "bandit", "gitleaks")}
    pairs = [pairwise(by_tool[a], by_tool[b], a, b) for a, b in itertools.combinations(by_tool, 2)]
    ledger = {"schema_version": "1.0", "experiment": getattr(args, "experiment", "comparison-v010"), "manifest_sha256": sha(manifest_raw),
              "family_map_sha256": sha(canonical(mapping)), "observation_count": len(observations),
              "counts_by_tool": {t: len(v) for t, v in by_tool.items()}, "inputs": inputs,
              "label_status": "All observations are unreviewed; overlap is not correctness or exploitability ground truth.",
              "observations": observations}
    overlaps = {"schema_version": "1.0", "observation_ledger_sha256": sha(canonical(ledger)),
                "method": "Same project, pinned path, explicitly mapped compatible family and inclusive intersecting line spans. No line-distance tolerance. Many-to-many edges are ambiguous; location-only edges retain unrelated/unmapped observations.",
                "interpretation": "Without-family-match is an observation difference, not a missed vulnerability. Presence, agreement, and tool severity supply no TP/FP label.",
                "pairs": pairs}
    write(args.output / "observations.json", ledger)
    write(args.output / "overlaps.json", overlaps)
    write(args.output / "rule-family-map.json", mapping)
    write(args.output / "run-status.json", {"schema_version": "1.0", "runs": runs})
    write(args.local_context / "source-roots.json", roots)
    return ledger, overlaps


def adjudication_selection(ledger, overlaps, cap=120, seed="comparison-v010-adjudication-2026-09-19-v1"):
    """Freeze a deterministic selection without reading any adjudication results."""
    observations = ledger["observations"]
    by_id = {x["id"]: x for x in observations}
    locations = defaultdict(list)
    matched = set()
    for pair in overlaps["pairs"]:
        for edge in pair["one_to_one_matches"] + pair["ambiguous_family_location_edges"]:
            matched.update((edge["left_id"], edge["right_id"]))
    for item in observations:
        key = (item["project_id"], item["path"], item["line_start"], item["line_end"])
        locations[key].append(item)
    def strata(items):
        return {(x["tool"], x["project_id"], x["family"]) for x in items}
    def ranking(key):
        return sha(canonical([seed, key]))
    mandatory = {key for key, rows in locations.items() if any(x["tool"] in {"semgrep", "gitleaks"} for x in rows)}
    selected = set(mandatory)
    all_strata = strata(observations)
    covered = strata(x for key in selected for x in locations[key])
    while covered != all_strata:
        candidates = [key for key in locations if key not in selected]
        key = min(candidates, key=lambda k: (-len(strata(locations[k]) - covered), ranking(k)))
        selected.add(key)
        covered.update(strata(locations[key]))
    # Include a no-family-match observation for every tool that has one.
    for tool in sorted({x["tool"] for x in observations}):
        candidates = [key for key, rows in locations.items() if any(x["tool"] == tool and x["id"] not in matched for x in rows)]
        if candidates and not any(key in selected for key in candidates):
            selected.add(min(candidates, key=ranking))
    if len(selected) > cap:
        raise ValueError("Selection cap cannot cover required strata and mandatory observations; do not silently drop coverage")
    candidates = sorted(set(locations) - selected, key=ranking)
    selected.update(candidates[:cap - len(selected)])
    rows = []
    for key in sorted(selected):
        ids = sorted(x["id"] for x in locations[key])
        rows.append({"location_id": "loc-" + sha(canonical(key))[:24], "project_id": key[0], "path": key[1],
                     "line_start": key[2], "line_end": key[3], "observation_ids": ids,
                     "tools": sorted({by_id[x]["tool"] for x in ids}),
                     "families": sorted({by_id[x]["family"] for x in ids}),
                     "mandatory_semgrep_or_gitleaks": key in mandatory,
                     "contains_no_family_match_observation": any(x not in matched for x in ids)})
    ids = sorted({x for row in rows for x in row["observation_ids"]})
    return {"schema_version": "1.0", "selection_id": seed, "selection_status": "Frozen before any model adjudication outputs were read",
            "input_ledger_sha256": sha(canonical(ledger)), "input_observation_count": len(observations),
            "strategy": "All Semgrep and Gitleaks observations mandatory; deterministic greedy coverage of every observed tool/project/family stratum; no-family-match example per tool; hash-ranked fill to 120 exact source spans.",
            "sampling_limitations": "Purposive stratified diagnostic selection, not a random prevalence sample; no population precision estimate without a different sampling design. TP/FP labels are intentionally absent.",
            "cap_locations": cap, "selected_locations": len(rows), "selected_observations": len(ids),
            "total_observed_strata": len(all_strata), "covered_strata": len(covered),
            "selected_counts_by_tool": dict(Counter(by_id[x]["tool"] for x in ids)),
            "selected_observation_ids": ids, "locations": rows}


def render_findings(ledger, overlaps):
    relations = defaultdict(lambda: defaultdict(set))
    for pair in overlaps["pairs"]:
        for kind, edges in [("matched", pair["one_to_one_matches"]), ("ambiguous", pair["ambiguous_family_location_edges"]),
                            ("location-only", pair["location_only_edges"])]:
            for edge in edges:
                relations[edge["left_id"]][kind].add(edge["right_id"])
                relations[edge["right_id"]][kind].add(edge["left_id"])
    lines = ["# Exhaustive observed findings", "", "Every source-scanner observation is retained below. IDs map directly to observations.json. A matched or tool-only observation has no TP/FP label until independently adjudicated. Imports, assertions and audit signals remain visible.", "",
             "| Observation ID | Project | Tool / rule | Severity | Source span | Family | Cross-tool relation |", "|---|---|---|---|---|---|---|"]
    for item in ledger["observations"]:
        related = relations[item["id"]]
        relationship = "; ".join(kind + ": " + ", ".join(sorted(ids)) for kind, ids in sorted(related.items())) or "No overlapping matched-family observation"
        cells = [item["id"], item["project_id"], item["tool"] + " / " + item["rule_id"], item["severity"],
                 "[" + item["path"] + ":" + str(item["line_start"]) + "–" + str(item["line_end"]) + "](" + item["source_url"] + ")",
                 item["family"], relationship]
        lines.append("| " + " | ".join(x.replace("|", "\\|").replace("\n", " ") for x in cells) + " |")
    return "\n".join(lines) + "\n"


def parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--experiment", default="comparison-v010", help="Explicit experiment identity; use a new output directory for a new experiment (default: comparison-v010)")
    p.add_argument("--manifest", type=Path, default=ROOT / "benchmarks/real-world/manifest.json")
    p.add_argument("--snapshots", type=Path, default=ROOT / "benchmarks/real-world/snapshots")
    p.add_argument("--tool-lock", type=Path, default=ROOT / "benchmarks/external-tools/tool-lock.json")
    p.add_argument("--source-root", type=Path, default=ROOT / "tmp/real-world-src")
    p.add_argument("--invarune-reports", type=Path, default=ROOT / "tmp/comparison-v010/invarune-v0100")
    p.add_argument("--invarune-receipts", type=Path, default=ROOT / "benchmarks/comparison-v010/invarune-receipts-v0100")
    p.add_argument("--external-results", type=Path, default=ROOT / "benchmarks/comparison-v010/external-results")
    p.add_argument("--external-raw", type=Path, default=ROOT / "tmp/comparison-v010/external-raw")
    p.add_argument("--output", type=Path, default=ROOT / "benchmarks/comparison-v010")
    p.add_argument("--local-context", type=Path, default=ROOT / "tmp/comparison-v010")
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", args.experiment):
        raise ValueError("Experiment identity must contain only lowercase letters, digits and hyphens")
    ledger, overlaps = build(args)
    selection_path = args.output / "adjudication-selection.json"
    seed = "comparison-v010-adjudication-2026-09-19-v1" if args.experiment == "comparison-v010" else args.experiment + "-adjudication-v1"
    selection = adjudication_selection(ledger, overlaps, seed=seed)
    if selection_path.exists():
        original = json.loads(selection_path.read_bytes())
        if original["selected_observation_ids"] != selection["selected_observation_ids"]:
            raise ValueError("Frozen adjudication selection would change; preserve it and create a new explicitly versioned selection")
        # Keep the original pre-adjudication source digest/time provenance intact.
    else:
        write(selection_path, selection)
    (args.output / "FINDINGS.md").write_bytes(render_findings(ledger, overlaps).encode("utf-8"))
    print(json.dumps({"observations": ledger["observation_count"], "counts_by_tool": ledger["counts_by_tool"],
                      "pair_counts": [{"left_tool": x["left_tool"], "right_tool": x["right_tool"], **x["counts"]} for x in overlaps["pairs"]]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
