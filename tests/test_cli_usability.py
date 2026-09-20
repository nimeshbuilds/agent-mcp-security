"""Public CLI output contracts, catalog traceability, and CI integration."""

import contextlib
import argparse
import io
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from ai_security_scan.cli import main, parser
from ai_security_scan.judge import JudgeError
from ai_security_scan.rules import RULES
from ai_security_scan.scanner import load_controls
from tests.test_analyst_cli import triage_response
from tests.test_analyst_controller import review_response


class CliUsabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "repository"
        self.root.mkdir()
        (self.root / "agent.py").write_bytes(b"import os\nos.system(user_input)\n")
        self.output = self.base / "report"
        self.config = self.base / "judge.json"
        self.config.write_text(json.dumps({"provider": "openai_chat", "model": "test-only-model"}), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, *arguments, scan=True):
        argv = [str(self.root), "--output", str(self.output)] if scan else []
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                code = main([*argv, *arguments])
            except SystemExit as exc:
                code = exc.code
        return code, stdout.getvalue(), stderr.getvalue()

    def report(self):
        return json.loads((self.output / "report.json").read_text(encoding="utf-8"))

    def test_help_describes_defaults_scope_advisory_review_and_exit_codes(self):
        code, stdout, stderr = self.invoke("--help", scan=False)
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        for text in ("Scan scope and resource limits", "Reports and CI output", "Reviewed finding baselines",
                     "Optional advisory LLM review", "Catalog inspection", "Examples:", "Exit codes:",
                     "1000000", "50000000", "static", "--summary-json", "--quiet", "--explain-rule",
                     "does not establish security or compliance", "Incompleteness takes precedence"):
            self.assertIn(text.lower(), stdout.lower())

    def test_help_documents_every_registered_option_and_live_inventory(self):
        from ai_security_scan.judge import ALIASES, DEFAULT_ENDPOINTS, PROVIDERS
        from ai_security_scan.scanner import EXCLUDED_DIRS, EXTENSIONS, MANIFESTS
        from ai_security_scan.image_scan import IMAGE_EXCLUDED_DIRS
        command = parser()
        help_text = command.format_help()
        option_reference = " ".join(help_text.split("Invocation and mode selection:")[0].split())
        self.assertNotIn("(default: None)", option_reference)
        self.assertIn("Omitted inherits the config value or headroom.", option_reference)
        for action in command._actions:
            with self.subTest(option=action.dest):
                self.assertTrue(action.help and action.help != argparse.SUPPRESS)
                for flag in action.option_strings:
                    self.assertIn(flag, option_reference)
                if action.choices:
                    for choice in action.choices:
                        self.assertIn(str(choice), option_reference)
                if action.default is not None and action.default != argparse.SUPPRESS:
                    self.assertIn("(default: " + str(action.default) + ")", option_reference)
        for inventory in (EXTENSIONS, MANIFESTS, EXCLUDED_DIRS, IMAGE_EXCLUDED_DIRS, PROVIDERS):
            for value in inventory:
                self.assertIn(value, help_text)
        for alias, provider in ALIASES.items():
            self.assertIn(alias + " -> " + provider, help_text)
        for endpoint in DEFAULT_ENDPOINTS.values():
            self.assertIn(endpoint, help_text)

    def test_help_topics_are_focused_complete_and_offline(self):
        from ai_security_scan.cli_help import HELP_TOPICS, _TOPIC_SECTIONS
        with mock.patch("ai_security_scan.cli.scan", side_effect=AssertionError("Help must not scan")), \
             mock.patch("ai_security_scan.judge.load_config", side_effect=AssertionError("Help must not load config")), \
             mock.patch("subprocess.Popen", side_effect=AssertionError("Help must not spawn")), \
             mock.patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Help must not use network")):
            full = self.invoke("--help", scan=False)[1]
            for topic in HELP_TOPICS:
                with self.subTest(topic=topic):
                    code, output, error = self.invoke("--judge-config", "does-not-exist.json", "--image", "absent:fixture",
                                                       "--help-topic", topic, scan=False)
                    self.assertEqual((code, error), (0, ""))
                    if topic == "all":
                        self.assertEqual(output, full)
                    else:
                        self.assertLess(len(output), len(full))
                        for heading in _TOPIC_SECTIONS[topic]:
                            self.assertIn(heading, output)
                        self.assertIn("Examples:", output)
                        self.assertIn("invscan ", output)
            code, output, error = self.invoke("--examples", scan=False)
            self.assertEqual((code, error), (0, ""))
            self.assertTrue(output.startswith("Examples:\n"))
            self.assertNotIn("positional arguments:", output)
            self.assertIn(output.strip(), full)
        self.assertFalse(self.output.exists())

    def test_invalid_help_topic_and_optimizer_without_review_are_actionable_errors(self):
        cases = (("--help-topic", "imaginary"), ("--help-topic",),
                 ("--token-optimizer", "compact"), ("--list-rules", "--token-optimizer", "headroom"),
                 ("--login", "claude", "--token-optimizer", "off"))
        with mock.patch("ai_security_scan.cli.scan", side_effect=AssertionError("Invalid mode must not scan")), \
             mock.patch("subprocess.Popen", side_effect=AssertionError("Invalid mode must not spawn")):
            for arguments in cases:
                with self.subTest(arguments=arguments):
                    code, output, error = self.invoke(*arguments, scan=False)
                    self.assertEqual((code, output), (2, ""))
                    self.assertIn("error:", error)
                    self.assertIn(arguments[0], error)

    def test_cookbook_examples_cover_every_public_flag(self):
        from ai_security_scan.cli_help import examples_reference
        examples = examples_reference()
        for action in parser()._actions:
            if action.option_strings:
                self.assertTrue(any(option in examples for option in action.option_strings), action.option_strings)

    def test_source_budget_example_executes_with_expected_findings(self):
        code, output, error = self.invoke("--max-file-bytes", "2000000", "--max-total-bytes", "100000000",
                                           "--max-files", "40000", "--max-entries", "200000", "--summary-json")
        self.assertEqual((code, error), (1, ""))
        summary = json.loads(output)
        self.assertEqual(summary["summary"]["open_findings"], 1)
        self.assertEqual(summary["summary"]["coverage_gaps"], 0)
        self.assertFalse(summary["optional_review"]["judge"]["enabled"])

    def test_optimizer_flag_overrides_http_config_and_cli_defaults(self):
        self.config.write_text(json.dumps({"provider": "openai_chat", "model": "test-model", "token_optimizer": "off"}), encoding="utf-8")
        cases = ((["--judge-config", str(self.config)], "compact"),
                 (["--judge-cli", "codex", "--judge-login", "never"], "off"))
        for provider_arguments, mode in cases:
            with self.subTest(mode=mode), mock.patch("ai_security_scan.judge.review", side_effect=triage_response) as review:
                code, output, error = self.invoke(*provider_arguments, "--token-optimizer", mode, "--judge-mode", "findings", "--summary-json")
            self.assertEqual(code, 1, error)
            self.assertEqual(review.call_args.args[0]["token_optimizer"], mode)
            self.assertEqual(self.report()["run_configuration"]["optional_review"]["effective_transport"]["token_optimizer"], mode)
            self.assertEqual(json.loads(output)["summary"]["open_findings"], 1)

    def test_summary_includes_actual_optimizer_receipt_without_changing_findings(self):
        receipt = {"requested": "headroom", "engine": "builtin_compact", "status": "fallback",
                   "fallback_reason": "headroom_not_installed", "evidence_preserved": True}
        def response(config, payload):
            return {**triage_response(config, payload), "token_optimization": receipt}
        with mock.patch("ai_security_scan.judge.review", side_effect=response):
            code, output, error = self.invoke("--judge-config", str(self.config), "--judge-mode", "findings", "--summary-json")
        self.assertEqual(code, 1, error)
        summary = json.loads(output)
        self.assertEqual(summary["optional_review"]["judge"]["token_optimization"], receipt)
        self.assertEqual(summary["summary"]["open_findings"], 1)

    def test_help_command_examples_parse_and_judge_json_examples_validate(self):
        from ai_security_scan.analyst import validate_limits
        from ai_security_scan.judge import load_config
        help_text = parser().format_help()
        examples = [shlex.split(line.strip())[1:] for line in help_text.split("Examples:\n", 1)[1].splitlines()
                    if line.strip().startswith("invscan ")]
        self.assertGreaterEqual(len(examples), 20)
        for arguments in examples:
            with self.subTest(arguments=arguments):
                try:
                    with contextlib.redirect_stdout(io.StringIO()):
                        args = parser().parse_args(arguments)
                except SystemExit as exc:
                    self.assertEqual(exc.code, 0)
                    self.assertTrue(any(flag in arguments for flag in ("--help", "--help-topic", "--examples", "--version")))
                    continue
                catalog = args.list_rules or args.list_controls or args.explain_rule or args.list_topics or args.ask is not None or args.explain_control or args.explain_check or args.list_sources or args.explain_source or args.login
                self.assertEqual(sum(bool(value) for value in (args.target, args.image, args.image_archive)), 0 if catalog else 1)
                self.assertFalse(args.judge_include_source and not (args.judge_config or args.judge_cli))
                self.assertFalse(args.pull and not args.image)
                validate_limits(max_calls=args.analyst_max_calls, batch_size=args.analyst_batch_size,
                                max_files=args.analyst_max_files, max_bytes=args.analyst_max_bytes,
                                max_chars=args.analyst_max_chars, max_seconds=args.analyst_time_budget)
        for heading, provider in (("OpenAI-compatible gateway configuration:", "openai_chat"),
                                  ("Custom JSON gateway configuration:", "custom")):
            value, _ = json.JSONDecoder().raw_decode(help_text.split(heading, 1)[1].lstrip())
            self.config.write_text(json.dumps(value), encoding="utf-8")
            loaded = load_config(self.config)
            self.assertEqual(loaded["provider"], provider)
            self.assertEqual(loaded["endpoint"], value["endpoint"])
        baseline, _ = json.JSONDecoder().raw_decode(help_text.split("Baseline JSON shape:", 1)[1].lstrip())
        self.config.write_text(json.dumps(baseline), encoding="utf-8")
        from ai_security_scan.scanner import load_baseline
        self.assertEqual(load_baseline(self.config), {"FINDING_ID": "Reviewed exception"})

    def test_short_and_long_help_are_identical_and_have_no_external_side_effects(self):
        with mock.patch("ai_security_scan.cli.scan", side_effect=AssertionError("Help must not scan")), \
             mock.patch("ai_security_scan.judge.load_config", side_effect=AssertionError("Help must not load judge config")), \
             mock.patch("ai_security_scan.image_runtime.export_image", side_effect=AssertionError("Help must not export")), \
             mock.patch("ai_security_scan.image_archive.materialize_image", side_effect=AssertionError("Help must not unpack")), \
             mock.patch("subprocess.Popen", side_effect=AssertionError("Help must not spawn")), \
             mock.patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Help must not use network")):
            outputs = []
            for option in ("-h", "--help"):
                code, stdout, stderr = self.invoke("--image", "unavailable:fixture", "--judge-config", "missing.json", option, scan=False)
                self.assertEqual((code, stderr), (0, ""))
                outputs.append(stdout)
            self.assertEqual(outputs[0], outputs[1])
            self.assertFalse(self.output.exists())
        project = Path(__file__).resolve().parents[1]
        for entry, directory in (([str(project / "scan.py")], self.base), (["-m", "ai_security_scan"], project)):
            for option in ("-h", "--help"):
                result = subprocess.run([sys.executable, *entry, option], cwd=directory,
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual((result.returncode, result.stderr), (0, ""))
                self.assertIn("Custom JSON gateway configuration:", result.stdout)
                self.assertIn("Container images without a source checkout:", result.stdout)
        self.assertFalse((self.base / "scan-report").exists())

    def test_abbreviations_are_rejected_without_scanning(self):
        with mock.patch("ai_security_scan.cli.scan", side_effect=AssertionError("Must not scan")):
            for option in ("--sum", "--qui", "--max-file", "--judge-conf", "--list-r"):
                with self.subTest(option=option):
                    code, stdout, stderr = self.invoke(option)
                    self.assertEqual(code, 2)
                    self.assertEqual(stdout, "")
                    self.assertIn("unrecognized arguments", stderr)

    def test_invalid_mode_combinations_fail_before_scan_or_network(self):
        cases = [("--quiet", "--summary-json"), ("--list-rules", "--list-controls"),
                 ("--list-rules", "--explain-rule", "AI002"), ("--list-controls", "--explain-rule", "AI002"),
                 ("--list-rules", "--quiet"), ("--list-controls", "--summary-json"),
                 ("--explain-rule", "AI002", "--summary-json"), (str(self.root), "--list-rules")]
        with mock.patch("ai_security_scan.cli.scan", side_effect=AssertionError("Must not scan")), \
             mock.patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Must not use network")):
            for arguments in cases:
                with self.subTest(arguments=arguments):
                    code, stdout, stderr = self.invoke(*arguments, scan=False)
                    self.assertEqual(code, 2)
                    self.assertEqual(stdout, "")
                    self.assertIn("error:", stderr)

    def test_explain_rule_exposes_metadata_sources_and_all_catalog_mappings(self):
        controls = load_controls()
        with mock.patch("ai_security_scan.cli.scan", side_effect=AssertionError("Must not scan")), \
             mock.patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Must not use network")):
            for rule in RULES:
                with self.subTest(rule=rule["id"]):
                    code, stdout, stderr = self.invoke("--explain-rule", rule["id"], scan=False)
                    self.assertEqual(code, 0)
                    self.assertEqual(stderr, "")
                    data = json.loads(stdout)
                    self.assertEqual(data["rule"], rule)
                    expected = sorted(control["id"] for control in controls if rule["id"] in control["automated_rule_ids"])
                    self.assertEqual(data["mapped_control_ids"], expected)
                    self.assertEqual([control["id"] for control in data["mapped_controls"]], expected)
                    self.assertTrue(data["rule"]["references"])
                    self.assertTrue(data["rule"]["remediation"])
                    self.assertIn("does not prove exploitability", data["interpretation"])
                    self.assertIn("not a security or compliance pass", data["interpretation"])

    def test_explain_unknown_rule_is_a_useful_input_error(self):
        code, stdout, stderr = self.invoke("--explain-rule", "AI999", scan=False)
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("Unknown rule ID: AI999", stderr)
        self.assertIn("--list-rules", stderr)

    def test_output_modes_preserve_all_report_bytes_and_finding_gate_offline(self):
        artifacts = []
        with mock.patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Default scan is offline")):
            for arguments in ((), ("--quiet",), ("--summary-json",)):
                code, stdout, stderr = self.invoke(*arguments)
                self.assertEqual(code, 1)
                self.assertEqual(stderr, "")
                artifacts.append({name: (self.output / name).read_bytes() for name in ("report.html", "report.json", "report.md", "report.sarif")})
                if arguments == ("--quiet",):
                    self.assertEqual(stdout, "")
                elif arguments == ("--summary-json",):
                    self.assertEqual(json.loads(stdout)["exit_code"], 1)
                else:
                    self.assertIn("Scanned 1 files", stdout)
                    self.assertIn("Reports:", stdout)
        self.assertEqual(artifacts[0], artifacts[1])
        self.assertEqual(artifacts[0], artifacts[2])

    def test_json_summary_matches_report_counts_scope_coverage_and_artifacts(self):
        (self.root / "ignore.py").write_bytes(b"exec(external_input)\n")
        code, stdout, stderr = self.invoke("--summary-json", "--exclude", "ignore.py", "--fail-on", "none")
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        data, report = json.loads(stdout), self.report()
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["summary"], report["summary"])
        self.assertEqual(data["assessment"], {key: report["assessment"][key] for key in ("posture", "metrics", "guidance")})
        self.assertEqual(data["execution"], report["execution"])
        self.assertEqual(data["scope"]["configuration"], report["configuration"])
        self.assertEqual(data["scope"]["target"], str(self.root))
        self.assertEqual(data["coverage"]["total_controls"], len(report["controls"]))
        self.assertEqual(data["coverage"]["total_checks"], 132)
        self.assertEqual(sum(data["coverage"]["control_status_counts"].values()), 66)
        self.assertNotIn("pass", data["coverage"]["control_status_counts"])
        self.assertIn({"path": "ignore.py", "reason": "user_exclusion", "coverage_gap": False}, data["coverage"]["skipped"])
        self.assertFalse(data["optional_review"]["judge"]["enabled"])
        self.assertFalse(data["optional_review"]["analyst"]["enabled"])
        self.assertEqual(data["reports"], {"html": str(self.output / "report.html"), "json": str(self.output / "report.json"), "markdown": str(self.output / "report.md"), "sarif": str(self.output / "report.sarif")})
        self.assertTrue(all(Path(path).is_file() for path in data["reports"].values()))
        repeated = self.invoke("--summary-json", "--exclude", "ignore.py", "--fail-on", "none")
        self.assertEqual(repeated, (code, stdout, stderr))

    def test_json_summary_reports_incompleteness_even_when_finding_gate_is_disabled(self):
        (self.root / "broken.py").write_bytes(b"def broken(:\n")
        code, stdout, _ = self.invoke("--summary-json", "--fail-on", "none")
        self.assertEqual(code, 2)
        data = json.loads(stdout)
        self.assertEqual(data["status"], "incomplete")
        self.assertEqual(data["exit_code"], 2)
        self.assertGreater(data["summary"]["open_findings"], 0)
        self.assertFalse(data["summary"]["scan_complete_within_selected_scope"])
        self.assertTrue(any(error["kind"] == "parse_error" for error in data["coverage"]["errors"]))
        self.assertTrue(all(Path(path).exists() for path in data["reports"].values()))

    def test_quiet_incomplete_source_scan_still_explains_failure_on_stderr(self):
        (self.root / "broken.py").write_bytes(b"def broken(:\n")
        code, stdout, stderr = self.invoke("--quiet", "--fail-on", "none")
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("Scan incomplete:", stderr)
        self.assertIn("coverage gaps", stderr)
        self.assertTrue(self.report()["findings"])

    def test_json_summary_distinguishes_suppressed_findings_from_zero_findings(self):
        baseline = self.base / "baseline.json"
        self.assertEqual(self.invoke("--write-baseline", str(baseline), "--baseline-reason", "Accepted fixture")[0], 1)
        code, stdout, _ = self.invoke("--summary-json", "--baseline", str(baseline))
        self.assertEqual(code, 0)
        data = json.loads(stdout)
        self.assertEqual(data["summary"]["open_findings"], 0)
        self.assertGreater(data["summary"]["suppressed_findings"], 0)
        self.assertIn("findings_suppressed", data["coverage"]["control_status_counts"])

    def test_quiet_keeps_errors_on_stderr_and_json_error_has_no_fake_report_paths(self):
        self.root = self.base / "does-not-exist"
        for option in ("--quiet", "--summary-json"):
            with self.subTest(option=option):
                code, stdout, stderr = self.invoke(option)
                self.assertEqual(code, 2)
                self.assertIn("Scan error:", stderr)
                if option == "--quiet":
                    self.assertEqual(stdout, "")
                else:
                    data = json.loads(stdout)
                    self.assertEqual(data["status"], "operational_error")
                    self.assertEqual(data["exit_code"], 2)
                    self.assertEqual(data["reports"], {})

    def test_quiet_optional_review_suppresses_progress_but_keeps_errors_and_reports(self):
        with mock.patch("ai_security_scan.judge.review", side_effect=JudgeError("Fixture endpoint failure")):
            code, stdout, stderr = self.invoke("--quiet", "--judge-config", str(self.config))
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertNotIn("sending redacted", stderr)
        self.assertIn("Fixture endpoint failure", stderr)
        report = self.report()
        self.assertTrue(report["findings"])
        self.assertTrue((self.output / "report.sarif").is_file())

    def test_json_summary_tracks_complete_and_budget_limited_full_analyst(self):
        for calls, expected_code, expected_status, reviewed in ((12, 1, "completed", 66), (1, 2, "incomplete", 6)):
            with self.subTest(calls=calls), \
                 mock.patch("ai_security_scan.judge.review", side_effect=triage_response), \
                 mock.patch("ai_security_scan.judge.review_controls", side_effect=review_response):
                code, stdout, stderr = self.invoke("--summary-json", "--judge-config", str(self.config), "--analyst-max-calls", str(calls))
            data = json.loads(stdout)
            self.assertEqual(code, expected_code)
            self.assertEqual(data["exit_code"], expected_code)
            self.assertTrue(data["summary"]["open_findings"])
            self.assertTrue(data["execution"]["finding_gate_triggered"])
            self.assertEqual(data["optional_review"]["judge"]["status"], "completed")
            self.assertEqual(data["optional_review"]["analyst"]["status"], expected_status)
            self.assertEqual(data["optional_review"]["analyst"]["coverage"]["reviewed_controls"], reviewed)
            if expected_status == "incomplete":
                self.assertIn("review is incomplete", stderr)

    def test_json_summary_handles_finding_only_review_and_judge_failure(self):
        with mock.patch("ai_security_scan.judge.review", side_effect=triage_response):
            code, stdout, _ = self.invoke("--summary-json", "--judge-config", str(self.config), "--judge-mode", "findings")
        data = json.loads(stdout)
        self.assertEqual(code, 1)
        self.assertEqual(data["optional_review"]["judge"]["mode"], "findings")
        self.assertFalse(data["optional_review"]["analyst"]["enabled"])
        with mock.patch("ai_security_scan.judge.review", side_effect=JudgeError("Fixture response invalid")):
            code, stdout, stderr = self.invoke("--summary-json", "--judge-config", str(self.config))
        data = json.loads(stdout)
        self.assertEqual(code, 2)
        self.assertEqual(data["optional_review"]["judge"]["status"], "error")
        self.assertEqual(data["optional_review"]["analyst"]["coverage"]["reviewed_controls"], 0)
        self.assertEqual(data["optional_review"]["analyst"]["coverage"]["omitted_checks"], 132)
        self.assertIn("Fixture response invalid", stderr)
        self.assertTrue(data["summary"]["open_findings"])

    def test_module_json_stdout_is_one_parseable_document_and_exit_matches_report(self):
        result = subprocess.run([sys.executable, "-m", "ai_security_scan", str(self.root), "--output", str(self.output), "--summary-json"],
                                cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual(data["exit_code"], result.returncode)
        self.assertEqual(data["execution"], self.report()["execution"])
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
