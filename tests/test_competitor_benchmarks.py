"""Contract checks for the independent research harness (no tool installs)."""
import importlib.util
import json
from pathlib import Path, PureWindowsPath
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("competitor_benchmark", ROOT / "scripts/benchmark_competitors.py")
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


class BenchmarkContractTests(unittest.TestCase):
    def test_windows_rooted_and_drive_paths_normalize_without_disclosing_outside_paths(self):
        cases = [
            ("/input/a.py", "/input", "a.py"),
            ("/private/a.py", "/input", "[outside selected source]/a.py"),
            ("C:/input/a.py", "C:/input", "a.py"),
            ("D:/private/a.py", "C:/input", "[outside selected source]/a.py"),
            ("a.py", "/input", "a.py"),
        ]
        with mock.patch.object(BENCH, "Path", PureWindowsPath):
            for value, root, expected in cases:
                with self.subTest(value=value, root=root):
                    self.assertEqual(BENCH.clean_path(value, PureWindowsPath(root)), expected)

    def test_findings_exit_is_not_an_execution_failure(self):
        self.assertEqual(BENCH.classify(1, False, None, {"finding_count": 1}), "completed_with_findings")
        self.assertEqual(BENCH.classify(0, False, None, {"finding_count": 1}), "completed_with_findings")

    def test_errors_timeouts_and_missing_json_never_become_clean(self):
        for code, timeout, parse, data, status in [
            (2, False, None, {"finding_count": 0}, "execution_error"),
            (None, True, None, {}, "timeout"),
            (0, False, "ValueError", {}, "execution_error"),
            (0, False, None, {"errors": [{"type": "parse"}], "finding_count": 0}, "completed_with_analysis_errors"),
        ]:
            with self.subTest(status=status):
                self.assertEqual(BENCH.classify(code, timeout, parse, data), status)

    def test_semgrep_nested_error_paths_and_source_are_not_published(self):
        root = Path("/private/export")
        raw = {"results": [{"check_id": "python.rule", "path": str(root / "a.py"),
                            "start": {"line": 1}, "end": {"line": 2},
                            "extra": {"severity": "ERROR", "message": "LICENSED RULE TEXT", "lines": "sensitive source"}}],
               "errors": [{"type": ["PartialParsing", [{"path": "/private/username/a.py"}]], "path": str(root / "a.py")}],
               "paths": {"scanned": [str(root / "a.py")]}}
        result = BENCH.normalize("semgrep", raw, root)
        self.assertEqual(result["findings"][0]["path"], "a.py")
        self.assertEqual(result["errors"][0]["type"], "PartialParsing")
        for private in ("username", "sensitive source", "LICENSED RULE TEXT", "/private"):
            self.assertNotIn(private, json.dumps(result))

    def test_gitleaks_does_not_publish_secret_or_matched_text(self):
        result = BENCH.normalize("gitleaks", [{"RuleID": "jwt", "File": "/input/a.txt", "StartLine": 2,
                                                 "EndLine": 3, "Secret": "REAL_SECRET", "Match": "SECRET_MATCH"}], Path("/input"))
        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(result["files_reported_scanned"], None)
        self.assertNotIn("SECRET", json.dumps(result))

    def test_bandit_coverage_and_parse_errors_remain_visible(self):
        result = BENCH.normalize("bandit", {"results": [], "metrics": {"_totals": {}, "a.py": {}},
                                             "errors": [{"filename": "/input/b.py", "reason": "syntax error"}]}, Path("/input"))
        self.assertEqual(result["files_reported_scanned"], 1)
        self.assertEqual(result["errors"], [{"path": "b.py", "type": "syntax error"}])

    def test_rule_mapping_does_not_turn_unrelated_matches_into_positives(self):
        cases = [{"id": "positive", "expect": {"AI002": True}}, {"id": "negative", "expect": {"AI002": False}}]
        findings = [{"path": "positive/a.py", "rule_id": "B404"}, {"path": "negative/a.py", "rule_id": "B603"}]
        result = BENCH.score_assertions(cases, findings, "bandit")
        self.assertEqual(result["counts"]["false_negative"], 1)
        self.assertEqual(result["counts"]["true_negative"], 1)
        self.assertEqual(result["counts"]["false_positive"], 0)

    def test_unsupported_tools_receive_no_true_negatives(self):
        result = BENCH.score_assertions([{"id": "negative", "expect": {"AI002": False}}], [], "gitleaks")
        self.assertEqual(result["counts"]["unsupported"], 1)
        self.assertEqual(result["counts"]["scored_assertions"], 0)
        self.assertEqual(result["counts"]["true_negative"], 0)

    def test_source_identity_detects_modification_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / "a.py"
            file.write_text("a")
            first = BENCH.tree_identity(root)
            file.write_text("b")
            self.assertNotEqual(first["manifest_sha256"], BENCH.tree_identity(root)["manifest_sha256"])
            link = root / "link.py"
            try:
                link.symlink_to(file)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks unavailable")
            with self.assertRaisesRegex(ValueError, "symlink"):
                BENCH.tree_identity(root)

    def test_literal_metadata_extracts_only_top_level_static_descriptions(self):
        source = '''server.registerTool("read", {description: "Read " + "a file", inputSchema: schema}, handler);
server.registerTool("dynamic", {description: prefix + "a file", inputSchema: schema}, handler);
server.registerTool("template", {description: `Read ${filename}`, inputSchema: schema}, handler);
server.registerTool("nested", {inputSchema: {description: "Nested value"}}, handler);
'''
        self.assertEqual(BENCH.literal_tool_descriptions(source), [{"name": "read", "description": "Read a file", "line": 1}])

    def test_comments_strings_and_regex_do_not_fabricate_tool_inventory(self):
        source = '''// server.registerTool("fake", {description: "Fake"}, handler);
const sample = 'server.registerTool("fake", {description: "Fake"}, handler)';
/* server.registerTool("fake", {description: "Fake"}, handler); */
const pattern = /server.registerTool("fake", {description: "Fake"}, handler)/;
'''
        self.assertEqual(BENCH.literal_tool_descriptions(source), [])

    def test_commands_disable_remote_metrics_and_use_explicit_configuration(self):
        args = BENCH.parser().parse_args(["--source-root", "/input", "--semgrep", "/semgrep", "--semgrep-config", "/rules.yaml",
                                         "--bandit", "/bandit", "--gitleaks", "/gitleaks"])
        commands = BENCH.commands(args, Path("/input"), Path("/report"), Path("/support"))
        self.assertIn("--metrics=off", commands["semgrep"])
        self.assertIn("--no-rewrite-rule-ids", commands["semgrep"])
        self.assertIn("--redact=100", commands["gitleaks"])
        self.assertIn(str(Path("/support") / "gitleaks.toml"), commands["gitleaks"])
        self.assertIn("--ignore-nosec", commands["bandit"])

    def test_lock_records_exact_pack_and_versions(self):
        lock = json.loads((ROOT / "benchmarks/external-tools/tool-lock.json").read_text())
        self.assertEqual(len(lock["semgrep"]["ruleset"]["sha256"]), 64)
        self.assertGreater(lock["semgrep"]["ruleset"]["rule_count"], 0)
        self.assertFalse(lock["semgrep"]["ruleset"]["redistributed"])
        self.assertTrue(lock["gitleaks"]["checksum_verified"])


if __name__ == "__main__":
    unittest.main()
