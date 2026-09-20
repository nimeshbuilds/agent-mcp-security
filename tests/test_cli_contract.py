"""Public command-line policy boundaries and module invocation."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from ai_security_scan.rules import RULES
from unittest import mock

from ai_security_scan.cli import main


class CliContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "source"
        self.root.mkdir()
        (self.root / "agent.py").write_text("import os\nos.system(user_input)\n", encoding="utf-8")
        self.output = self.base / "report"

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, arguments):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main(arguments)

    def test_all_severity_gates_preserve_the_same_findings(self):
        reports = []
        with mock.patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Network forbidden")):
            for gate, expected in [("critical", 0), ("high", 1), ("medium", 1), ("low", 1), ("info", 1), ("none", 0)]:
                with self.subTest(gate=gate):
                    self.assertEqual(self.invoke([str(self.root), "--output", str(self.output), "--fail-on", gate]), expected)
                    report = json.loads((self.output / "report.json").read_text())
                    self.assertEqual(report["execution"]["exit_code"], expected)
                    reports.append(report)
        for report in reports[1:]:
            for key in ("scan_id", "findings", "controls", "summary", "assessment"):
                self.assertEqual(report[key], reports[0][key])

    def test_operational_incompleteness_takes_precedence_for_every_gate(self):
        (self.root / "broken.py").write_text("def broken(:\n", encoding="utf-8")
        for gate in ("critical", "high", "medium", "low", "info", "none"):
            with self.subTest(gate=gate):
                code = self.invoke([str(self.root), "--output", str(self.output), "--fail-on", gate])
                self.assertEqual(code, 2)
                report = json.loads((self.output / "report.json").read_text())
                self.assertTrue(report["findings"])
                self.assertFalse(report["summary"]["scan_complete_within_selected_scope"])
                self.assertTrue((self.output / "report.sarif").exists())

    def test_invalid_cli_combinations_fail_before_scanning_or_network(self):
        cases = [[], [str(self.root), "--output", str(self.root)],
                 [str(self.root), "--judge-include-source"],
                 [str(self.root), "--write-baseline", str(self.base / "baseline.json")],
                 [str(self.root), "--judge-max-findings", "0"],
                 [str(self.root), "--judge-max-findings", "501"],
                 [str(self.root), "--analyst-time-budget", "nan"],
                 [str(self.root), "--analyst-time-budget", "inf"],
                 [str(self.root), "--analyst-max-calls", "101"],
                 [str(self.root), "--analyst-batch-size", "0"]]
        with mock.patch("ai_security_scan.cli.scan", side_effect=AssertionError("Unexpected scan")), \
             mock.patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Unexpected request")):
            for arguments in cases:
                with self.subTest(arguments=arguments), self.assertRaises(SystemExit) as caught:
                    self.invoke(arguments)
                self.assertEqual(caught.exception.code, 2)

    def test_invalid_target_and_scan_limits_return_operational_failure(self):
        for target, flags in [(self.base / "missing", []), (self.root / "agent.py", []),
                              (self.root, ["--max-files", "0"]), (self.root, ["--max-total-bytes", "-1"]),
                              (self.root, ["--max-file-bytes", "0"]), (self.root, ["--max-entries", "0"])]:
            with self.subTest(target=target, flags=flags):
                self.assertEqual(self.invoke([str(target), "--output", str(self.output), *flags]), 2)
                self.assertFalse(self.output.exists())

    def test_catalog_and_version_commands_do_not_scan(self):
        for arguments, count in [(["--list-rules"], len(RULES)), (["--list-controls"], 66)]:
            out = io.StringIO()
            with mock.patch("ai_security_scan.cli.scan", side_effect=AssertionError("Unexpected scan")), contextlib.redirect_stdout(out):
                self.assertEqual(main(arguments), 0)
            self.assertEqual(len(json.loads(out.getvalue())), count)
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as caught:
            main(["--version"])
        self.assertEqual(caught.exception.code, 0)

    def test_module_entrypoint_produces_reports_and_expected_exit(self):
        project = Path(__file__).resolve().parents[1]
        result = subprocess.run([sys.executable, "-m", "ai_security_scan", str(self.root), "--output", str(self.output)],
                                cwd=project, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        for filename in ("report.html", "report.json", "report.md", "report.sarif"):
            self.assertTrue((self.output / filename).is_file())

    def test_deeply_nested_gateway_config_preserves_static_report(self):
        nested = "${PROMPT}"
        for _ in range(600):
            nested = [nested]
        config = self.base / "judge.json"
        config.write_text(json.dumps({"provider": "custom", "model": "fixture",
                                      "endpoint": "https://example.test/review",
                                      "request_template": {"prompt": nested}, "response_path": ""}), encoding="utf-8")
        with mock.patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Unexpected request")):
            code = self.invoke([str(self.root), "--output", str(self.output), "--judge-config", str(config)])
        self.assertEqual(code, 2)
        report = json.loads((self.output / "report.json").read_text())
        self.assertTrue(report["findings"])
        self.assertEqual(report["judge"]["status"], "error")
        self.assertEqual(report["analyst"]["coverage"]["omitted_checks"], 132)
        self.assertIn("nesting", report["judge"]["error"])
        self.assertTrue((self.output / "report.sarif").exists())


if __name__ == "__main__":
    unittest.main()
