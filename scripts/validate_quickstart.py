#!/usr/bin/env python3
"""Exercise the documented quick start in a fresh clone and virtual environment.

This validates inert shipped fixtures, installed commands, PDF review roundtrips,
and loopback HTTP adapters. It never calls a real model, logs in, starts a target
container, or executes fixture source. Installing build/PDF packages may use the
configured Python package index. A sanitized receipt records every assertion.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ("report.html", "report.md", "report.json", "report.sarif")
SNAPSHOT_PATHS = ("ai_security_scan", "examples/skills", "examples/safer", "examples/vulnerable", "examples/images",
                  "examples/judges", "examples/review-config.json", "tests", "scripts", "docs",
                  "scan.py", "pyproject.toml", "README.md", "requirements-qa.txt")
EDIT_PDF = '''import json,sys
from pathlib import Path
from pypdf import PdfReader,PdfWriter
initial,pdf,destination=map(Path,sys.argv[1:])
report=json.loads(initial.read_text(encoding="utf-8"))
workspace=report["review_workspace"]
index=next(i for i,item in enumerate(workspace["items"]) if item["kind"]=="finding")
prefix="ivr."+str(index)+"."
reader=PdfReader(pdf)
writer=PdfWriter(); writer.clone_document_from_reader(reader)
values={prefix+"decision":"justified",prefix+"reason":"TEST ONLY: inert quickstart fixture; this validates no production safeguard.",prefix+"reviewer":"Quickstart validation fixture",prefix+"reviewed_at":"2026-09-19",prefix+"evidence_ref":"scripts/validate_quickstart.py"}
writer.update_page_form_field_values(None,values,auto_regenerate=False)
with destination.open("wb") as stream: writer.write(stream)
assert len(reader.get_fields())==len(workspace["items"])*5
print(json.dumps({"items":len(workspace["items"]),"fields":len(reader.get_fields()),"pages":len(reader.pages),"edited_item_id":workspace["items"][index]["id"]},sort_keys=True))
'''


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def replace_paths(text, replacements):
    """Normalize raw and JSON-escaped Windows paths as well as POSIX paths."""
    for original, placeholder in replacements:
        spellings = {original, original.replace("\\", "/"), original.replace("\\", "\\\\")}
        for spelling in sorted(spellings, key=len, reverse=True):
            text = text.replace(spelling, placeholder)
    return text


def assert_optimizer_receipts(report, captured, expected_engine):
    """Bind actual parsed HTTP evidence to each optimizer's pre-encoding digest."""
    requests = [report["judge"], *report["analyst"]["requests"]]
    require(len(requests) == len(captured), "Optimizer receipts do not cover every captured model request")
    evidence = {item["evidence_id"]: item for item in report["analyst"]["evidence"]}
    for request, sent in zip(requests, captured):
        receipt = request["token_optimization"]
        require(receipt["requested"] == "headroom" and receipt["engine"] == expected_engine,
                "Requested default optimizer did not use the expected installed engine")
        require(receipt["evidence_preserved"] is True, "Optimizer did not preserve evidence")
        payload = sent["payload"]
        original = json.dumps(payload, sort_keys=True, ensure_ascii=True).encode("utf-8")
        require(hashlib.sha256(original).hexdigest() == receipt["original_payload_sha256"],
                "Captured HTTP payload does not equal the original optimizer input")
        require(len(original) == receipt["payload_bytes_before"], "Optimizer input byte count differs from the captured payload")
        if "controls" in payload:
            canonical = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
            require(hashlib.sha256(canonical).hexdigest() == request["payload_sha256"],
                    "Captured control payload differs from the recorded analyst request")
            for item in payload["evidence"]:
                require(evidence.get(item["evidence_id"]) == item, "Captured evidence differs from report evidence")
    return {"requests_verified": len(requests), "requested": "headroom", "engine": expected_engine,
            "captured_payloads_equal_original_inputs": True, "source_evidence_exactly_preserved": True}


def snapshot(source, checkout):
    """Overlay only explicit project inputs, so uncommitted release fixes are tested."""
    records = []
    for name in SNAPSHOT_PATHS:
        source_path, destination = source / name, checkout / name
        if not source_path.exists():
            continue
        paths = [source_path] + list(source_path.rglob("*")) if source_path.is_dir() else [source_path]
        if any(path.is_symlink() for path in paths):
            raise ValueError("Validation snapshot inputs must not contain symbolic links")
        if destination.is_dir():
            shutil.rmtree(destination)
        elif destination.exists():
            destination.unlink()
        if source_path.is_dir():
            shutil.copytree(source_path, destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, destination)
        selected = destination.rglob("*") if destination.is_dir() else [destination]
        for path in selected:
            if path.is_file():
                records.append({"path": path.relative_to(checkout).as_posix(), "sha256": sha256(path)})
    records.sort(key=lambda item: item["path"])
    digest = hashlib.sha256(json.dumps(records, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"basis": "Fresh local Git clone with explicitly listed current-worktree project inputs overlaid",
            "sha256": digest, "files": records}


def validate(args, receipt):
    source = args.source.resolve(strict=True)
    interpreter = str(Path(args.python).resolve()) if Path(args.python).is_file() else args.python
    from_source = importlib.util.spec_from_file_location("invarune_quickstart_redaction", source / "ai_security_scan" / "security.py")
    security = importlib.util.module_from_spec(from_source)
    from_source.loader.exec_module(security)
    with tempfile.TemporaryDirectory(prefix="invarune-quickstart-") as temporary:
        work = Path(temporary).resolve()
        checkout, environment = work / "checkout", work / "venv"
        outside = work / "outside-checkout"
        outside.mkdir()
        replacements = [(interpreter, "<DIRECT_PYTHON>"), (str(source), "<SOURCE>"), (str(environment), "<VENV>"),
                        (str(checkout), "<CHECKOUT>"), (str(work), "<WORK>"),
                        (str(Path(tempfile.gettempdir()).resolve()), "<HOST_TEMP>"),
                        (tempfile.gettempdir(), "<HOST_TEMP>"), (str(Path.home()), "<USER_HOME>")]

        def clean(text):
            return replace_paths(security.redact(str(text)), replacements)

        def run(identifier, command, *, cwd=None, expected=0, timeout=120, env=None):
            child_env = dict(os.environ, PYTHONNOUSERSITE="1", PYTHONUTF8="1",
                             PYTHONDONTWRITEBYTECODE="1", PIP_DISABLE_PIP_VERSION_CHECK="1", PIP_NO_INPUT="1")
            if env:
                child_env.update(env)
            record = {"id": identifier, "command": [clean(part) for part in command],
                      "cwd": clean(cwd or outside), "expected_exit": expected, "status": "running"}
            receipt["steps"].append(record)
            process = subprocess.run([str(part) for part in command], cwd=str(cwd or outside),
                                     env=child_env, capture_output=True, text=True, timeout=timeout)
            record.update(exit_code=process.returncode,
                          stdout=clean(process.stdout[-12000:]), stderr=clean(process.stderr[-12000:]),
                          status="passed" if process.returncode == expected else "failed")
            require(process.returncode == expected, identifier + " returned an unexpected exit: " + clean(process.stderr[-1500:]))
            return process, record

        process, _ = run("source_git_revision", ["git", "rev-parse", "HEAD"], cwd=source)
        receipt["source_git_commit"] = process.stdout.strip()
        process, _ = run("source_git_state", ["git", "status", "--porcelain", "--untracked-files=no"], cwd=source)
        receipt["source_worktree_modified"] = bool(process.stdout.strip())
        run("fresh_clone", ["git", "clone", "--quiet", "--no-hardlinks", "--no-local", str(source), str(checkout)])
        receipt["snapshot"] = snapshot(source, checkout)
        run("create_venv", [interpreter, "-m", "venv", str(environment)], timeout=180)
        bin_dir = environment / ("Scripts" if os.name == "nt" else "bin")
        python = bin_dir / ("python.exe" if os.name == "nt" else "python")
        primary = bin_dir / ("invscan.exe" if os.name == "nt" else "invscan")
        compatible = bin_dir / ("invarune.exe" if os.name == "nt" else "invarune")
        legacy = bin_dir / ("ai-security-scan.exe" if os.name == "nt" else "ai-security-scan")
        run("install_checkout", [str(python), "-m", "pip", "install", "."], cwd=checkout, timeout=300)
        version_code = "import json,sys,platform,ai_security_scan,importlib.metadata as m;print(json.dumps({'python':platform.python_version(),'scanner':ai_security_scan.__version__,'distribution':m.version('agent-mcp-security-scan'),'executable':sys.executable,'module_file':ai_security_scan.__file__,'console_scripts':{e.name:e.value for e in m.distribution('agent-mcp-security-scan').entry_points if e.group=='console_scripts'}},sort_keys=True))"
        process, record = run("installed_versions", [str(python), "-c", version_code])
        receipt["versions"] = json.loads(clean(process.stdout))
        require(receipt["versions"]["scanner"] == receipt["versions"]["distribution"], "Installed version metadata differs from the module")
        require(receipt["versions"]["module_file"].startswith("<VENV>"), "Imported scanner did not come from the new virtual environment")
        require(receipt["versions"]["console_scripts"] == {name: "ai_security_scan.cli:main" for name in ("invscan", "invarune", "ai-security-scan")},
                "Installed metadata does not expose all three compatible CLI entry points")
        record["assertions"] = {"module_and_distribution_versions_match": True, "imported_outside_checkout": True,
                                "all_three_console_entries_match": True}

        def scan_case(identifier, command, target, expected, counts, extra=()):
            destination = work / "reports" / identifier
            process, record = run(identifier, [*command, *target, *extra, "--output", str(destination), "--summary-json"],
                                  cwd=checkout if command[0] == interpreter else outside, expected=expected, timeout=180)
            summary = json.loads(process.stdout)
            report = json.loads((destination / "report.json").read_text(encoding="utf-8"))
            require(report["execution"]["exit_code"] == expected == summary["exit_code"], identifier + ": report/CLI exits differ")
            require(all((destination / name).is_file() for name in ARTIFACTS), identifier + ": a portable report is missing")
            require(report["summary"]["coverage_gaps"] == 0, identifier + ": unexpected scope gap")
            for key, expected_value in counts.items():
                require(report["summary"].get(key) == expected_value, identifier + ": unexpected " + key)
            expected_controls = 1 if "--scans" in extra else 66
            expected_checks = 2 if "--scans" in extra else 132
            require(len(report["controls"]) == expected_controls and sum(len(control["checks"]) for control in report["controls"]) == expected_checks,
                    identifier + ": the selected control catalog was not retained")
            if "--judge-config" not in extra:
                require(not report["judge"]["enabled"] and not report["analyst"]["enabled"], identifier + ": model review was unexpectedly enabled")
            require(not any(finding["status"] == "pass" for finding in report["findings"]), identifier + ": finding became a manual pass")
            record["assertions"] = {"summary": {key: report["summary"].get(key) for key in counts}, "coverage_gaps": 0,
                                    "catalog_controls": expected_controls, "catalog_checks": expected_checks,
                                    "model_enabled": report["judge"]["enabled"], "report_exits_match_process": True}
            record["reports"] = {name: {"sha256": sha256(destination / name), "bytes": (destination / name).stat().st_size} for name in ARTIFACTS}
            return report, destination, record

        direct = [interpreter, str(checkout / "scan.py")]
        safe = [str(checkout / "examples" / "safer")]
        vulnerable = [str(checkout / "examples" / "vulnerable")]
        image = ["--image-archive", str(checkout / "examples" / "images" / "demo-agent.tar")]
        references = []
        for name, command in (("primary", primary), ("compatible", compatible), ("legacy", legacy)):
            outputs = []
            for flag in ("-h", "--help"):
                process, record = run("installed_" + name + "_" + flag.strip("-"), [str(command), flag])
                require(not process.stderr, "Installed help wrote an unexpected diagnostic")
                for text in ("--list-scans", "--explain-scan", "--scans", "--report", "--review-report", "--pdf", "--judge-cli", "--judge-config", "--image-archive", "--help-topic", "--examples", "--token-optimizer", "--ask", "--explain-control", "--catalog-format", "Custom JSON gateway configuration:"):
                    require(text in process.stdout, "Installed help omits " + text)
                outputs.append(process.stdout)
                record["assertions"] = {"all_documented_feature_flags_present": True, "stderr_empty": True}
            require(outputs[0] == outputs[1], "Short and long help differ")
            _, destination, _ = scan_case("installed_" + name + "_safer", [str(command)], safe, 0, {"files_scanned": 2, "open_findings": 0})
            references.append({name: (destination / name).read_bytes() for name in ARTIFACTS})
        require(all(value == references[0] for value in references), "The three CLI aliases produced different reports")
        receipt["assertions"]["installed_alias_artifacts_identical"] = True
        for identifier, arguments, required in (
            ("installed_version", ["--version"], receipt["versions"]["scanner"]),
            ("installed_image_help", ["--help-topic", "images"], "Container images without a source checkout:"),
            ("installed_gateway_help", ["--help-topic", "gateways"], "Custom JSON gateway configuration:"),
            ("installed_examples", ["--examples"], "invscan ./repository --review-report")):
            process, record = run(identifier, [str(primary), *arguments])
            require(required in process.stdout and not process.stderr, "Installed CLI documentation command is incomplete")
            record["assertions"] = {"requested_content_present": True, "stderr_empty": True, "run_outside_checkout": True}
        for identifier, arguments, count in (("installed_rules", ["--list-rules"], 46),
                                              ("installed_controls", ["--list-controls"], 66),
                                              ("installed_rule_explanation", ["--explain-rule", "AI002"], None)):
            process, record = run(identifier, [str(primary), *arguments])
            value = json.loads(process.stdout)
            require(len(value) == count if count is not None else value["rule"]["id"] == "AI002", "Installed catalog differs from the documented catalog")
            record["assertions"] = {"catalog_contract_verified": True, "run_outside_checkout": True}
        for identifier, arguments, result_key, expected_id in (
            ("installed_security_topics", ["--list-topics"], "topics", None),
            ("installed_security_question", ["--ask", "What do you check for prompt injection?"], "results", None),
            ("installed_control_explanation", ["--explain-control", "AUTH-01"], "control", "AUTH-01"),
            ("installed_check_explanation", ["--explain-check", "AUTH-01:1"], "check", "AUTH-01:1"),
            ("installed_source_registry", ["--list-sources"], "sources", None),
            ("installed_source_explanation", ["--explain-source", "MITRE-ATLAS"], "source", "MITRE-ATLAS")):
            process, record = run(identifier, [str(primary), *arguments, "--catalog-format", "json"])
            value = json.loads(process.stdout)
            require(not process.stderr and value["mode"] == "deterministic_catalog" and value["status"] == "ok",
                    identifier + ": catalog lookup failed")
            require(value["catalog"]["controls"] == 66 and value["catalog"]["checks"] == 132
                    and value["catalog"]["rules"] == 46 and value["catalog"]["sources"] == 76,
                    identifier + ": catalog totals changed")
            require(bool(value[result_key]), identifier + ": catalog content missing")
            if expected_id:
                require(value[result_key]["id"] == expected_id, identifier + ": wrong catalog identity")
            record["assertions"] = {"catalog_identity_and_content_verified": True,
                                     "run_outside_checkout": True, "stderr_empty": True}
        for identifier, arguments, required in (
            ("installed_security_help", ["--help-topic", "security"], "--ask"),
            ("installed_security_question_text", ["--ask", "prompt injection"], "AGT-03"),
            ("installed_rule_explanation_text", ["--explain-rule", "AI002", "--catalog-format", "text"], "EXEC-01")):
            process, record = run(identifier, [str(primary), *arguments])
            require(required in process.stdout and not process.stderr, identifier + ": readable explanation missing")
            record["assertions"] = {"requested_content_present": True, "run_outside_checkout": True,
                                     "stderr_empty": True}
        process, record = run("installed_unknown_security_question", [str(primary), "--ask", "zzzinvscannoknowntopiczz", "--catalog-format", "json"])
        value = json.loads(process.stdout)
        require(value["status"] == "no_match" and value["total_matches"] == 0 and not value["results"],
                "Unknown catalog topic must not invent an answer")
        record["assertions"] = {"no_invented_answer": True, "run_outside_checkout": True}
        process, record = run("installed_terminal_default", [str(primary), *safe])
        require("Terminal output only" in process.stdout and "Scanned 2 files" in process.stdout,
                "Default terminal result missing")
        require(not (outside / "scan-report").exists(), "Default invocation unexpectedly wrote reports")
        record["assertions"] = {"terminal_only": True, "no_report_files": True}
        process, record = run("installed_scan_inventory", [str(primary), "--list-scans", "--catalog-format", "json"])
        inventory = json.loads(process.stdout)
        require(len(inventory["scans"]) == 46 and len(inventory["controls"]) == 66, "Installed scan inventory incomplete")
        process, record = run("installed_scan_explanation", [str(primary), "--explain-scan", "AI043"])
        require("AI043" in process.stdout and "Sources:" in process.stdout, "Missing skill scan explanation")
        process, record = run("installed_targeted_terminal", [str(primary), *vulnerable, "--scans", "ai001,AI002", "--summary-json"], expected=1)
        targeted = json.loads(process.stdout)
        require(targeted["scope"]["configuration"]["selected_rule_ids"] == ["AI001", "AI002"] and targeted["reports"] == {}, "Targeted scan scope/output mismatch")
        process, record = run("installed_review_only_control", [str(primary), *vulnerable, "--scan", "GOV-01", "--summary-json"])
        targeted = json.loads(process.stdout)
        require(targeted["scoring"]["deterministic"]["selected_rules"] == 0 and targeted["summary"]["open_findings"] == 0, "Review-only selection restored unselected rules")
        destination = work / "reports" / "explicit-report-flag"
        process, record = run("installed_explicit_report", [str(primary), *safe, "--report", str(destination), "--summary-json"])
        require(len(json.loads(process.stdout)["reports"]) == 4 and (destination / "report.json").is_file(), "Report flag did not write all four formats")
        scan_case("installed_selected_image", [str(primary)], image, 0, {"open_findings": 0}, ["--scans", "AI001"])
        process, record = run("installed_skill_fixture", [str(primary), str(checkout / "examples/skills/risky"), "--scans", "AI043,AI044,AI045,AI046", "--summary-json"], expected=1)
        skill_result = json.loads(process.stdout)
        require(skill_result["summary"]["open_findings"] == 4 and skill_result["summary"]["coverage_gaps"] == 0, "Installed skill fixture did not match its four named risks")
        record["assertions"] = {"four_named_risk_patterns": True, "terminal_only": skill_result["reports"] == {}}
        scan_case("installed_vulnerable", [str(primary)], vulnerable, 1, {"open_findings": 11})
        scan_case("installed_review_config", [str(primary)], vulnerable, 1,
                  {"open_findings": 9, "justified_findings": 1, "disabled_findings": 1},
                  ["--review-config", str(checkout / "examples" / "review-config.json")])
        baseline = work / "reviewed-fixture-baseline.json"
        scan_case("installed_baseline_candidate", [str(primary)], vulnerable, 1, {"open_findings": 11},
                  ["--write-baseline", str(baseline), "--baseline-reason", "TEST ONLY: accepted inert fixture for workflow validation"])
        # The fixture-only acceptance is explicit; production candidates require owner review.
        scan_case("installed_baseline_accepted", [str(primary)], vulnerable, 0, {"open_findings": 0, "suppressed_findings": 11},
                  ["--baseline", str(baseline)])
        scan_case("direct_compatibility_safer", direct, safe, 0, {"files_scanned": 2, "open_findings": 0})
        _, _, record = scan_case("installed_image", [str(primary)], image, 1, {"open_findings": 3})
        record["assertions"]["run_outside_checkout"] = True

        if args.skip_pdf:
            receipt["coverage"]["pdf"] = "skipped_by_flag"
        else:
            run("install_pdf_extra" if args.skip_gateway else "install_ai_pdf_extras",
                [str(python), "-m", "pip", "install", ".[pdf]" if args.skip_gateway else ".[ai,pdf]"], cwd=checkout, timeout=600)
            process, _ = run("pdf_dependency_versions", [str(python), "-c", "import importlib.metadata as m,json;print(json.dumps({n:m.version(n) for n in ['reportlab','pypdf']},sort_keys=True))"])
            receipt["versions"].update(json.loads(process.stdout))
            edit_script = work / "edit_review_pdf.py"
            edit_script.write_text(EDIT_PDF, encoding="utf-8")
            for name, target, initial_count in (("source", vulnerable, 11), ("image", image, 3)):
                report, destination, record = scan_case("pdf_" + name + "_initial", [str(primary)], target, 1, {"open_findings": initial_count}, ["--pdf"])
                require((destination / "report.pdf").is_file(), "Requested PDF was not written")
                record["reports"]["report.pdf"] = {"sha256": sha256(destination / "report.pdf"), "bytes": (destination / "report.pdf").stat().st_size}
                edited = work / ("reviewed-" + name + ".pdf")
                process, edit_record = run("pdf_" + name + "_form_edit", [str(python), str(edit_script), str(destination / "report.json"), str(destination / "report.pdf"), str(edited)])
                edit_record["assertions"] = json.loads(process.stdout)
                first = next(finding for finding in report["findings"] if "finding:" + finding["id"] == edit_record["assertions"]["edited_item_id"])
                expected_exit = int(any(finding["id"] != first["id"] and finding["severity"] in {"critical", "high"} for finding in report["findings"]))
                final, final_destination, final_record = scan_case("pdf_" + name + "_fresh_import", [str(primary)], target, expected_exit,
                                                   {"open_findings": initial_count - 1, "justified_findings": 1}, ["--review-report", str(edited), "--pdf"])
                require((final_destination / "report.pdf").is_file(), "Final reviewed PDF was not written")
                final_record["reports"]["report.pdf"] = {"sha256": sha256(final_destination / "report.pdf"), "bytes": (final_destination / "report.pdf").stat().st_size}
                require(final["review_import"]["counts"]["applied"] == 1 and not final["review_import"]["incomplete"], "PDF user decision was not cleanly reapplied")
                require(final["review_policy"]["counts"]["active_checks"] == 132, "Finding review unexpectedly waived checks")
                require([(finding["id"], finding["severity"], finding["evidence"]) for finding in report["findings"]] ==
                        [(finding["id"], finding["severity"], finding["evidence"]) for finding in final["findings"]], "Fresh PDF review altered evidence or severity")
                final_record["assertions"].update(applied_user_decisions=1, active_checks=132, immutable_evidence_preserved=True)
            receipt["coverage"]["pdf"] = "real_export_form_edit_and_fresh_import_for_source_and_image"

        if args.skip_gateway:
            receipt["coverage"]["gateway"] = "skipped_by_flag"
        else:
            if args.skip_pdf:
                run("install_ai_extra", [str(python), "-m", "pip", "install", ".[ai]"], cwd=checkout, timeout=600)
            version_code = "import importlib.metadata as m,json; print(json.dumps({'headroom-ai':next((d.version for d in m.distributions() if d.metadata['Name'].lower()=='headroom-ai'),None)}))"
            process, version_record = run("ai_dependency_versions", [str(python), "-c", version_code])
            receipt["versions"].update(json.loads(process.stdout))
            supports_headroom = tuple(int(part) for part in receipt["versions"]["python"].split(".")[:2]) >= (3, 10)
            require(receipt["versions"]["headroom-ai"] == ("0.37.0" if supports_headroom else None),
                    "Installed optional AI dependency differs from the documented Python-version policy")
            expected_engine = "headroom" if supports_headroom else "builtin_compact"
            version_record["assertions"] = {"expected_optional_dependency_present": supports_headroom,
                                            "expected_engine": expected_engine}
            spec = importlib.util.spec_from_file_location("invarune_quickstart_gateway", checkout / "tests" / "test_full_gateway_e2e.py")
            fixture = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(fixture)
            total_requests = 0
            for provider in fixture.PROVIDERS:
                with fixture.gateway(provider, lambda payload, number: {"answer": fixture.fixture_answer(payload)}) as (endpoint, captured, errors):
                    config = {"provider": provider, "model": "local-quickstart-fixture", "endpoint": endpoint, "timeout_seconds": 3}
                    if provider == "custom":
                        config.update(request_template={"review_prompt": "${PROMPT}", "deployment": "${MODEL}"}, response_path="data.review")
                    config_path = work / ("gateway-" + provider + ".json")
                    config_path.write_text(json.dumps(config), encoding="utf-8")
                    report, _, record = scan_case("gateway_" + provider, [str(primary)], safe, 0, {"files_scanned": 2, "open_findings": 0},
                                                  ["--judge-config", str(config_path), "--analyst-time-budget", "60"])
                require(not errors and len(captured) == 12, "Loopback gateway did not receive the expected full review")
                require(report["analyst"]["coverage"]["reviewed_controls"] == 66 and report["analyst"]["coverage"]["omitted_checks"] == 0,
                        "Loopback full review omitted active controls/checks")
                require(report["analyst"]["check_status_counts"] == {"insufficient_evidence": 132}, "Fixture review must not create control passes")
                record["assertions"]["token_optimization"] = assert_optimizer_receipts(report, captured, expected_engine)
                record["assertions"].update(loopback_requests=12, control_requests=11, answered_checks=132, validated_controls=0,
                                             service="local HTTP fixture; no real model")
                total_requests += len(captured)
            receipt["coverage"]["gateway"] = {"protocols": list(fixture.PROVIDERS), "loopback_requests": total_requests,
                                               "real_model_calls": 0, "authentication_tested": False}
        receipt["assertions"].update(fresh_clone=True, fresh_venv=True, installed_outside_checkout=True,
                                     target_execution=False, container_execution=False, real_model_calls=0)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT, help="Trusted Invarune checkout to validate; current project files overlay a fresh local Git clone")
    parser.add_argument("--python", default=sys.executable, help="Python 3.9+ executable used for direct commands and the new venv")
    parser.add_argument("--output", type=Path, required=True, help="Receipt directory; receipt.json and README.md are replaced, temporary installs are cleaned up")
    parser.add_argument("--skip-pdf", action="store_true", help="Skip optional PDF packages and form roundtrips; record this limitation")
    parser.add_argument("--skip-gateway", action="store_true", help="Skip local HTTP adapter checks; never enables real model calls")
    args = parser.parse_args(argv)
    receipt = {"schema_version": "1.0", "status": "running", "purpose": "Executed quickstart instructions on inert fixtures; this is workflow validation, not detector accuracy or production assurance.",
               "host": {"platform": platform.system(), "machine": platform.machine(), "driver_python": platform.python_version()},
               "coverage": {"live_provider_login": "not_run; requires explicit separate live-provider validation", "windows_powershell": "This receipt records only its actual host; Windows requires its own executed CI receipt."},
               "assertions": {}, "steps": []}
    try:
        validate(args, receipt)
        receipt["status"] = "passed"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        receipt["status"] = "failed"
        # Process exceptions can retain raw commands, environment paths or output.
        # Recorded commands/diagnostics already pass through the redaction boundary.
        detail = str(exc) if isinstance(exc, (ValueError, RuntimeError)) else "Validation could not finish; inspect the last recorded step."
        receipt["error"] = type(exc).__name__ + ": " + detail
        if receipt["steps"] and receipt["steps"][-1]["status"] == "running":
            receipt["steps"][-1]["status"] = "failed"
    output = args.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
    versions = receipt.get("versions", {})
    lines = ["# Executed quickstart validation", "", "Status: **" + receipt["status"] + "**. Scanner: **" + versions.get("scanner", "unavailable") + "**. Python: **" + versions.get("python", "unavailable") + "**.", "",
             "[Machine-readable receipt](receipt.json) includes sanitized commands, exit codes, asserted fixture counts, report hashes, source snapshot and package versions.", "",
             "The validator uses a new local Git clone with the explicit current-worktree project inputs overlaid, creates a new virtual environment, and executes the documented source/image/exception commands. Installed aliases run outside the checkout. Enabled PDF checks use real form editing and a fresh scan. Gateway checks use loopback fixture responses, never a real model. Login and live provider capability are separate validation work.", "",
             "| Step | Exit | Result |", "|---|---:|---|"]
    lines += ["| " + step["id"] + " | " + str(step.get("exit_code", "not finished")) + " | " + step["status"] + " |" for step in receipt["steps"]]
    lines += ["", "Rerun from this checkout:", "", "```sh", "python3 scripts/validate_quickstart.py --output test-output/quickstart", "```", "",
              "Installation can download Python build/PDF packages. `--skip-pdf` and `--skip-gateway` record explicit skipped coverage. The receipt never claims Windows or live provider validation merely from a macOS/Linux run.", ""]
    (output / "README.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"status": receipt["status"], "steps": len(receipt["steps"]), "receipt": str(output / "receipt.json")}, sort_keys=True))
    return 0 if receipt["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
