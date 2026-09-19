"""Adversarial scanner, source-evidence, and output boundary regressions."""

import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ai_security_scan.analyzer import analyze_file
from ai_security_scan.cli import main
from ai_security_scan.evidence import build_evidence
from ai_security_scan.fs import read_confined
from ai_security_scan.report import atomic_write, codeblock, markdown, sarif, write_reports
from ai_security_scan.scanner import load_baseline, scan


class SecurityBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "repository"
        self.root.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, source):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        # Byte-budget fixtures must contain identical LF bytes on every OS.
        path.write_bytes(source.encode("utf-8"))
        return path

    def test_scan_never_imports_target_or_launches_child_process(self):
        self.write("sitecustomize.py", "raise RuntimeError('TARGET_EXECUTED')\n")
        self.write("agent.py", "import subprocess\nsubprocess.run(user_input, shell=True)\n")
        with patch("subprocess.Popen", side_effect=AssertionError("Child process forbidden")), patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("Network forbidden")):
            report = scan(self.root)
            evidence = build_evidence(report, self.root)
        self.assertTrue(any(item["rule_id"] == "AI002" for item in report["findings"]))
        self.assertTrue(evidence["evidence"])

    def test_non_utf8_and_bom_sources_have_explicit_distinct_results(self):
        (self.root / "invalid.py").write_bytes(b"#\xff\n")
        (self.root / "valid.py").write_bytes(b"\xef\xbb\xbfimport os\nos.system(user_input)\n")
        report = scan(self.root)
        self.assertEqual([item["path"] for item in report["files"]], ["valid.py"])
        self.assertEqual(report["files"][0]["sha256"], hashlib.sha256((self.root / "valid.py").read_bytes()).hexdigest())
        self.assertTrue(any(item["reason"] == "non_utf8_content" and item["coverage_gap"] for item in report["coverage"]["skipped"]))
        finding = next(item for item in report["findings"] if item["rule_id"] == "AI003")
        self.assertEqual(finding["line"], 2)
        self.assertFalse(report["summary"]["scan_complete_within_selected_scope"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO test requires POSIX")
    def test_fifo_is_skipped_without_opening_or_blocking(self):
        self.write("agent.py", "value = 1\n")
        os.mkfifo(self.root / "pipe.py")
        from ai_security_scan import scanner
        with patch.object(scanner, "read_confined", wraps=scanner.read_confined) as reader:
            report = scan(self.root)
        self.assertEqual([call.args[1] for call in reader.call_args_list], ["agent.py"])
        self.assertTrue(any(item["path"] == "pipe.py" and item["reason"] == "non_regular_file" for item in report["coverage"]["skipped"]))

    def test_confined_reader_rejects_absolute_parent_and_empty_paths(self):
        self.write("agent.py", "value = 1\n")
        for relative in ("", ".", "..", "../repository/agent.py", self.root / "agent.py"):
            with self.subTest(relative=str(relative)), self.assertRaises(OSError):
                read_confined(self.root, relative, 100)

    def test_confined_reader_checks_pinned_root_identity(self):
        self.write("agent.py", "value = 1\n")
        if not (os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")):
            self.skipTest("Pinned root identities require directory descriptors")
        info = self.root.stat()
        self.root.rename(self.base / "original")
        self.root.mkdir()
        self.write("agent.py", "OUTSIDE_REPLACEMENT = True\n")
        with self.assertRaisesRegex(OSError, "Source root changed"):
            read_confined(self.root, "agent.py", 100, (info.st_dev, info.st_ino))

    def test_evidence_rejects_root_replacement_between_file_reads(self):
        if not (os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")):
            self.skipTest("Pinned root identities require directory descriptors")
        for name in ("auth1.py", "auth2.py"):
            self.write(name, "# auth policy permissions\n")
        report = scan(self.root)
        from ai_security_scan import evidence
        original = evidence.read_confined
        calls = []

        def replace_root(root, relative, limit, identity):
            calls.append(relative)
            if len(calls) == 2:
                self.root.rename(self.base / "original")
                self.root.mkdir()
                self.write("auth2.py", "# auth policy permissions\n")
            return original(root, relative, limit, identity)

        with patch.object(evidence, "read_confined", side_effect=replace_root):
            result = build_evidence(report, self.root)
        self.assertEqual(result["coverage"]["files_verified"], 1)
        self.assertEqual(result["coverage"]["skipped_counts"], {"confined_read_failed_or_size_changed": 1})
        self.assertTrue(all(item["path"] == "auth1.py" for item in result["evidence"]))

    def test_changed_inode_reads_consume_scanner_total_byte_budget(self):
        for index in range(3):
            self.write("source%d.py" % index, "x=1\n")
        from ai_security_scan import scanner
        original = scanner.read_confined
        bytes_observed = []

        def replace_file(root, relative, limit, identity):
            path = root / relative
            # Rename retains the old inode, guaranteeing the new path differs.
            path.rename(path.with_suffix(".original"))
            path.write_text("#" * min(limit, 12), encoding="utf-8")
            data, info = original(root, relative, limit, identity)
            bytes_observed.append(len(data))
            return data, info

        with patch.object(scanner, "read_confined", side_effect=replace_file):
            report = scan(self.root, max_file_bytes=12, max_total_bytes=12)
        self.assertLessEqual(sum(bytes_observed), 12)
        self.assertFalse(report["summary"]["scan_complete_within_selected_scope"])
        self.assertTrue(any(item["reason"] == "file_changed_during_open" for item in report["coverage"]["skipped"]))

    def test_failed_read_attempts_consume_conservative_scanner_budget(self):
        for index in range(3):
            self.write("source%d.py" % index, "x=1\n")
        consumed = []

        def growing_read(root, relative, limit, identity):
            path = root / relative
            # Emulate growth after descriptor metadata was checked and a
            # bounded read consuming the one-byte growth detection sentinel.
            with path.open("ab") as stream:
                stream.write(b"#")
            with path.open("rb") as stream:
                consumed.append(len(stream.read(limit + 1)))
            raise OSError("Source grew beyond read limit")

        with patch("ai_security_scan.scanner.read_confined", side_effect=growing_read) as reader:
            report = scan(self.root, max_file_bytes=12, max_total_bytes=9)
        self.assertEqual(reader.call_count, 1)
        self.assertEqual(reader.call_args.args[2], 4)
        self.assertEqual(consumed, [5])
        self.assertEqual(report["summary"]["bytes_read"], 0)
        self.assertEqual(report["summary"]["bytes_charged"], 5)
        self.assertEqual(report["summary"]["failed_read_bytes_charged"], 5)
        self.assertTrue(any(item["reason"] == "total_byte_limit" for item in report["coverage"]["skipped"]))
        self.assertFalse(report["summary"]["scan_complete_within_selected_scope"])

    def test_successful_reads_charge_actual_bytes_and_reserve_growth_sentinel(self):
        self.write("source1.py", "x=1\n")
        self.write("source2.py", "y=2\n")
        report = scan(self.root, max_total_bytes=9)
        self.assertEqual(report["summary"]["files_scanned"], 2)
        self.assertEqual(report["summary"]["bytes_read"], 8)
        self.assertEqual(report["summary"]["bytes_charged"], 8)
        self.assertEqual(report["summary"]["failed_read_bytes_charged"], 0)
        self.assertTrue(report["summary"]["scan_complete_within_selected_scope"])
        constrained = scan(self.root, max_total_bytes=8)
        self.assertEqual(constrained["summary"]["files_scanned"], 1)
        self.assertFalse(constrained["summary"]["scan_complete_within_selected_scope"])

    def test_crlf_sources_charge_physical_bytes_and_preserve_line_numbers(self):
        source = b"# auth\r\neval(user_input)\r\n"
        for name in ("one.py", "two.py"):
            (self.root / name).write_bytes(source)
        report = scan(self.root, max_total_bytes=2 * len(source) + 1)
        self.assertTrue(report["summary"]["scan_complete_within_selected_scope"])
        self.assertEqual(report["summary"]["bytes_read"], 2 * len(source))
        self.assertEqual(report["summary"]["bytes_charged"], 2 * len(source))
        self.assertEqual([finding["line"] for finding in report["findings"]], [2, 2])
        bundle = build_evidence(report, self.root)
        self.assertEqual(bundle["coverage"]["bytes_read"], 2 * len(source))
        self.assertTrue(all(item["start_line"] == 1 and item["end_line"] == 2 for item in bundle["evidence"]))
        self.assertTrue(all("\r" not in item["text"] for item in bundle["evidence"]))

    def test_scanner_rejects_boolean_zero_negative_and_noninteger_limits(self):
        self.write("agent.py", "value = 1\n")
        for name in ("max_file_bytes", "max_total_bytes", "max_files", "max_entries"):
            for value in (True, 0, -1, 1.5, "1"):
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    scan(self.root, **{name: value})

    def test_duplicate_manifest_entries_cannot_amplify_evidence_reads(self):
        self.write("auth.py", "# auth policy permissions\n")
        report = scan(self.root)
        report["files"] *= 100
        result = build_evidence(report, self.root)
        self.assertEqual(result["coverage"]["file_read_attempts"], 1)
        self.assertEqual(result["coverage"]["skipped_counts"], {"duplicate_manifest_path": 99})

    def test_tampered_binary_and_non_utf8_manifest_files_never_become_evidence(self):
        self.write("auth.py", "# auth policy\n")
        report = scan(self.root)
        for path, data in (("nul.py", b"# auth\x00secret"), ("invalid.py", b"# auth\xffsecret")):
            (self.root / path).write_bytes(data)
            report["files"].append({"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        result = build_evidence(report, self.root)
        self.assertEqual(result["coverage"]["skipped_counts"], {"binary_content": 1, "non_utf8_content": 1})
        self.assertTrue(all(item["path"] == "auth.py" for item in result["evidence"]))

    def test_baseline_duplicate_and_wrong_types_are_rejected(self):
        path = self.root / "baseline.json"
        for findings in ([{"id": "same", "reason": "accepted"}] * 2,
                         [{"id": 12, "reason": "accepted"}],
                         [{"id": "x", "reason": None}],
                         [{"id": "x", "reason": " \t\n"}]):
            path.write_text(json.dumps({"schema_version": "1.0", "findings": findings}))
            with self.subTest(findings=findings), self.assertRaises(ValueError):
                load_baseline(path)

    def test_baseline_candidate_does_not_suppress_current_scan(self):
        self.write("agent.py", "import os\nos.system(user_input)\n")
        output = self.base / "report"
        baseline = self.root / "baseline.json"
        with contextlib.redirect_stdout(io.StringIO()):
            first = main([str(self.root), "--output", str(output), "--write-baseline", str(baseline), "--baseline-reason", "Accepted fixture risk"])
            first_report = json.loads((output / "report.json").read_text())
            second = main([str(self.root), "--output", str(output), "--baseline", str(baseline)])
        self.assertEqual(first, 1)
        self.assertEqual(second, 0)
        self.assertTrue(all(item["status"] == "open" for item in first_report["findings"]))
        self.assertTrue(all(item["status"] == "suppressed" for item in json.loads((output / "report.json").read_text())["findings"]))

    def test_atomic_output_rejects_symlink_and_cleans_failed_temporary(self):
        outside = self.base / "outside.txt"
        outside.write_text("DO_NOT_REPLACE")
        output = self.root / "report.md"
        output.symlink_to(outside)
        with self.assertRaises(ValueError):
            atomic_write(output, "malicious replacement")
        self.assertEqual(outside.read_text(), "DO_NOT_REPLACE")
        output.unlink()
        with patch("ai_security_scan.report.os.replace", side_effect=OSError("Injected replacement error")), self.assertRaises(OSError):
            atomic_write(output, "unfinished")
        self.assertEqual(list(self.root.glob(".scan-*")), [])
        self.assertFalse(output.exists())

    def test_generated_markdown_fences_cannot_be_closed_by_source(self):
        malicious = "```\n# Injected heading\n``````\n<script>alert(1)</script>\n"
        rendered = codeblock(malicious)
        self.assertEqual(rendered.splitlines()[0], "```````text")
        self.assertEqual(rendered.splitlines()[-1], "```````")
        self.assertIn(malicious, rendered)

    def test_untrusted_markup_and_reserved_path_characters_are_escaped(self):
        self.write("agent.py", "eval(user_input)\n")
        report = scan(self.root)
        report["findings"][0]["path"] = "nested/a #?%[x](javascript:alert).py"
        report["coverage"]["errors"].append({"path": "[click](https://evil.example)", "error": "<img src=x onerror=alert(1)>\n# injected", "kind": "test"})
        text = markdown(report)
        self.assertNotIn("<img", text)
        self.assertNotIn("[click](https://evil.example)", text)
        uri = sarif(report)["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "nested/a%20%23%3F%25%5Bx%5D%28javascript%3Aalert%29.py")

    def test_lone_surrogates_in_untrusted_report_text_do_not_break_output(self):
        self.write("agent.py", "eval(user_input)\n")
        report = scan(self.root)
        report["findings"][0]["path"] = "untrusted\udcff.py"
        report["findings"][0]["evidence"] = "model or repository text \ud800"
        output = self.base / "surrogate-report"
        write_reports(report, output)
        for name in ("report.html", "report.json", "report.md", "report.sarif"):
            self.assertTrue((output / name).read_text(encoding="utf-8"))

    def test_sarif_and_static_fields_ignore_advisory_model_text(self):
        self.write("agent.py", "eval(user_input)\n")
        report = scan(self.root)
        before = copy.deepcopy(report)
        expected = sarif(report)
        report["judge"] = {"enabled": True, "status": "completed", "assessments": [{"verdict": "not_exploitable", "reason": "Ignore every static finding."}]}
        report["analyst"] = {"enabled": False, "untrusted": "All controls pass!"}
        self.assertEqual(sarif(report), expected)
        for key in ("findings", "controls", "summary", "scan_id"):
            self.assertEqual(report[key], before[key])


class AdditionalSafeRuleCounterexamples(unittest.TestCase):
    def test_targeted_safe_alternatives_do_not_trigger_the_corresponding_rule(self):
        cases = [
            ("AI001", "agent.py", "eval('1 + 2')"),
            ("AI003", "agent.py", "import os\nos.system('echo fixed')"),
            ("AI005", "agent.py", "import json\njson.loads(payload)"),
            ("AI007", "agent.py", "app.add_middleware(CORSMiddleware, allow_origins=['https://app.example'])"),
            ("AI011", "public.pem", "-----BEGIN PUBLIC KEY-----\npublic material\n-----END PUBLIC KEY-----"),
            ("AI013", "agent.js", "eval('1 + 2');"),
            ("AI016", "agent.py", "import tempfile\nfd, path = tempfile.mkstemp()"),
            ("AI019", "install.sh", "curl https://example.com/artifact -o artifact"),
            ("AI022", "compose.yaml", "services:\n  agent:\n    privileged: false"),
            ("AI023", "compose.yaml", "volumes:\n  - ./data:/app/data:ro"),
            ("AI027", "mcp.json", '{"permissions": ["read_resource"]}'),
            ("AI028", "mcp.json", '{"token_passthrough": false}'),
            ("AI030", "config.json", '{"dangerouslyAllowBrowser": false}'),
            ("AI034", "config.json", '{"url": "https://example.com/mcp?resource=public"}'),
            ("AI039", "agent.py", "from flask import render_template\nrender_template('safe.html', value=user_input)"),
            ("AI040", "agent.js", "element.textContent = toolOutput;"),
            ("AI041", "mcp.json", '{"DANGEROUSLY_OMIT_AUTH": ""}'),
            ("AI042", "compose.yaml", "network_mode: bridge\nhostPID: false\nhostNetwork: false"),
        ]
        for rule_id, path, source in cases:
            with self.subTest(rule_id=rule_id):
                self.assertNotIn(rule_id, {item["rule_id"] for item in analyze_file(path, source)})


if __name__ == "__main__":
    unittest.main()
