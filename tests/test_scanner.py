import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ai_security_scan.cli import main, judge_payload
from ai_security_scan.report import markdown, sarif
from ai_security_scan.scanner import scan, load_baseline
from ai_security_scan.security import redact


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve() / "repo"
        self.root.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, source):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        return path

    def test_repeatable_reports_without_network_or_target_execution(self):
        self.write("agent.py", 'import os\nos.system(user_input)\nraise RuntimeError("MUST NOT EXECUTE")\n')
        with patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Network forbidden")):
            a, b = scan(self.root), scan(self.root)
        self.assertEqual(a, b)
        self.assertEqual(markdown(a), markdown(b))
        self.assertEqual(sarif(a), sarif(b))
        self.assertTrue(a["findings"])
        self.assertTrue(a["summary"]["scan_complete_within_selected_scope"])
        self.assertTrue(all(c["status"] != "pass" for c in a["controls"]))

    def test_symlink_binary_parse_and_size_gaps_are_explicit(self):
        outside = Path(self.temp.name) / "secret.py"
        outside.write_text("os.system(secret)")
        (self.root / "link.py").symlink_to(outside)
        self.write("invalid.py", "def broken(:\n")
        self.write("large.py", "a" * 101)
        (self.root / "binary.py").write_bytes(b"abc\x00def")
        report = scan(self.root, max_file_bytes=100)
        reasons = {s["reason"] for s in report["coverage"]["skipped"]}
        self.assertTrue({"symlink_file", "file_size_limit", "binary_content"} <= reasons)
        self.assertGreaterEqual(report["summary"]["coverage_gaps"], 4)
        self.assertFalse(report["summary"]["scan_complete_within_selected_scope"])
        self.assertFalse(any(f["path"] == "link.py" for f in report["findings"]))

    def test_resource_limits_and_exclusions(self):
        self.write("a.py", "x=1")
        self.write("b.py", "x=2")
        self.write("node_modules/evil.py", "os.system(x)")
        report = scan(self.root, max_files=1)
        self.assertEqual(report["summary"]["files_scanned"], 1)
        self.assertTrue(any(e["kind"] == "resource_limit" for e in report["coverage"]["errors"]))
        report = scan(self.root, exclude=["b.py"])
        self.assertEqual(report["summary"]["files_scanned"], 1)

    def test_baseline_preserves_findings_and_reports_stale_ids(self):
        self.write("agent.py", "import os\nos.system(user_input)\n")
        first = scan(self.root)
        baseline = {f["id"]: "Accepted fixture risk" for f in first["findings"]}
        baseline["stale"] = "Old finding"
        second = scan(self.root, baseline=baseline)
        self.assertEqual(second["summary"]["open_findings"], 0)
        self.assertEqual(len(second["findings"]), len(first["findings"]))
        self.assertEqual(second["coverage"]["unmatched_baseline_ids"], ["stale"])
        self.assertTrue(any(c["status"] == "findings_suppressed" for c in second["controls"]))
        self.assertTrue(all(r["suppressions"][0]["justification"] for r in sarif(second)["runs"][0]["results"]))

    def test_no_known_secret_in_report(self):
        secret = "sk-proj-" + "A" * 40
        self.write("agent.py", f'API_KEY = "{secret}"\npassword = "unittest-password-123"\n')
        report = scan(self.root)
        self.assertNotIn(secret, json.dumps(report))
        self.assertNotIn("unittest-password-123", json.dumps(report))

    def test_source_context_requires_opt_in_and_unchanged_hash(self):
        self.write("agent.py", 'import os\n# CONTEXT_MARKER\nos.system(user_input)\n')
        report = scan(self.root)
        self.assertNotIn("source_context", judge_payload(report, self.root))
        payload = judge_payload(report, self.root, True)
        self.assertIn("CONTEXT_MARKER", json.dumps(payload["source_context"]))
        self.write("agent.py", "modified_after_scan=True\n")
        self.assertEqual(judge_payload(report, self.root, True)["source_context"], [])

    def test_cli_exit_codes_and_report_formats(self):
        self.write("agent.py", "import os\nos.system(user_input)\n")
        output = Path(self.temp.name) / "out"
        with contextlib.redirect_stdout(io.StringIO()):
            result = main([str(self.root), "--output", str(output)])
            clean_gate = main([str(self.root), "--output", str(output), "--fail-on", "none"])
        self.assertEqual(result, 1)
        self.assertEqual(clean_gate, 0)
        self.assertEqual({p.name for p in output.iterdir()}, {"report.md", "report.json", "report.sarif"})
        self.write("bad.py", "def broken(:\n")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(self.root), "--output", str(output), "--fail-on", "none"]), 2)

    def test_bad_judge_does_not_erase_deterministic_report(self):
        self.write("agent.py", "import os\nos.system(user_input)\n")
        output = Path(self.temp.name) / "out"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = main([str(self.root), "--output", str(output), "--judge-config", str(self.root / "missing.json")])
        self.assertEqual(result, 2)
        report = json.loads((output / "report.json").read_text())
        self.assertEqual(report["judge"]["status"], "error")
        self.assertTrue(report["findings"])

    def test_markdown_escapes_repository_markup(self):
        self.write("<script>alert(1)</script>.txt".replace("/", "_"), "x")
        report = scan(self.root)
        report["coverage"]["errors"].append({"path": "[click](https://evil.example)", "error": "<img src=x onerror=alert(1)>", "kind": "test"})
        text = markdown(report)
        self.assertNotIn("<img", text)
        self.assertNotIn("[click](https://evil.example)", text)

    def test_invalid_baseline_rejected(self):
        p = self.write("baseline.json", '{"schema_version":"1.0","findings":[{"id":"1","reason":""}]}')
        with self.assertRaises(ValueError):
            load_baseline(p)

    def test_reports_inside_target_do_not_change_next_run(self):
        self.write("agent.py", "value = 1\n")
        output = self.root / "scan-report"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(self.root), "--output", str(output)]), 0)
            first = (output / "report.json").read_bytes()
            self.assertEqual(main([str(self.root), "--output", str(output)]), 0)
        self.assertEqual(first, (output / "report.json").read_bytes())

    def test_empty_scope_is_not_a_success(self):
        self.assertFalse(scan(self.root)["summary"]["scan_complete_within_selected_scope"])

    def test_scan_identity_includes_coverage_gaps(self):
        self.write("ok.py", "value = 1\n")
        initial = scan(self.root, max_file_bytes=100)
        self.write("oversize.py", "x" * 101)
        second = scan(self.root, max_file_bytes=100)
        self.assertNotEqual(initial["scan_id"], second["scan_id"])

    def test_generated_output_does_not_consume_entry_budget(self):
        self.write("ok.py", "value = 1\n")
        output = self.root / "report"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(self.root), "--output", str(output), "--max-entries", "1"]), 0)
            first = (output / "report.json").read_bytes()
            self.assertEqual(main([str(self.root), "--output", str(output), "--max-entries", "1"]), 0)
        self.assertEqual(first, (output / "report.json").read_bytes())

    def test_truncated_secret_in_nonsecret_finding_is_redacted(self):
        secret = "CANARY_TRUNCATED_SECRET_" + "a" * 1200
        self.write("client.py", 'import requests\nrequests.get("https://example.test", verify=False, auth_token="' + secret + '")\n')
        report = scan(self.root)
        self.assertTrue(any(f["rule_id"] == "AI006" for f in report["findings"]))
        self.assertNotIn("CANARY_TRUNCATED_SECRET_", json.dumps(report))
        self.assertNotIn("CANARY_TRUNCATED_SECRET_", json.dumps(judge_payload(report, self.root, True)))

    def test_secret_rule_evidence_is_fully_hidden(self):
        secret = "CANARY_4e91_gateway_credential"
        self.write(".env", "OPENAI_API_KEY=" + secret)
        self.write("agent.py", 'private_key = "' + secret + '"\n')
        report = scan(self.root)
        self.assertTrue(report["findings"])
        self.assertNotIn(secret, json.dumps(report))
        self.assertNotIn(secret, json.dumps(judge_payload(report, self.root, True)))

    def test_redaction_common_formats(self):
        for sample, secret in [('Authorization: Bearer ABCDEFGHIJK', 'ABCDEFGHIJK'), ('postgres://admin:secretpass@example.com/db', 'secretpass'), ('api_key="privatevalue"', 'privatevalue'), ('https://x.example/?token=privatevalue', 'privatevalue'), ('OPENAI_API_KEY=CANARY_4e91_gateway_credential', 'CANARY_4e91_gateway_credential'), ('private_key = "CANARY_4e91_gateway_credential"', 'CANARY_4e91_gateway_credential')]:
            self.assertNotIn(secret, redact(sample))

    def test_normalized_output_path_is_excluded(self):
        self.write("agent.py", "value = 1\n")
        output = self.root / "unused" / ".." / "report"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main([str(self.root), "--output", str(output)]), 0)
            first = (output.resolve() / "report.json").read_bytes()
            self.assertEqual(main([str(self.root), "--output", str(output)]), 0)
        self.assertEqual(first, (output.resolve() / "report.json").read_bytes())

    def test_directory_swap_cannot_read_outside_root(self):
        self.write("child/config.py", "value = 1\n")
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        (outside / "config.py").write_text('API_KEY = "OUTSIDE_CANARY_MUST_NOT_READ"\n')
        import os
        original_walk = os.walk

        def racing_walk(*args, **kwargs):
            for parent, directories, names in original_walk(*args, **kwargs):
                if Path(parent).name == "child":
                    (self.root / "child").rename(self.root / "saved")
                    (self.root / "child").symlink_to(outside, target_is_directory=True)
                yield parent, directories, names

        with patch("ai_security_scan.scanner.os.walk", side_effect=racing_walk):
            report = scan(self.root)
        self.assertFalse(report["findings"])
        self.assertFalse(report["summary"]["scan_complete_within_selected_scope"])


if __name__ == "__main__":
    unittest.main()
