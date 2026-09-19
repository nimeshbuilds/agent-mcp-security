"""Public CLI output contracts, catalog traceability, and CI integration."""

import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from ai_security_scan.cli import main
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
                artifacts.append({name: (self.output / name).read_bytes() for name in ("report.json", "report.md", "report.sarif")})
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
        self.assertEqual(data["reports"], {"json": str(self.output / "report.json"), "markdown": str(self.output / "report.md"), "sarif": str(self.output / "report.sarif")})
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
