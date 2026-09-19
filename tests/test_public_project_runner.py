"""Corpus reproduction boundaries: immutable bytes and no target execution."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("public_project_runner", Path(__file__).resolve().parents[1] / "scripts/scan_public_projects.py")
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class PublicProjectRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.project = {"id": "fixture", "revision": "a" * 40,
                        "repository": "https://github.com/example/fixture",
                        "license": {"summary": "MIT"}, "include_prefixes": ["src"],
                        "include_globs": [], "include_files": ["pyproject.toml"]}
        self.policy = {"excluded_directory_names": ["tests", "docs", "vendor"],
                       "excluded_basename_globs": ["test_*.py", "README*"],
                       "text_extensions": [".py", ".toml", ".md"], "text_names": ["Dockerfile"],
                       "max_export_file_bytes": 10000, "max_export_total_bytes": 10000}

    def snapshot(self, text="value = 1\n"):
        data = text.encode("utf-8")
        (self.source / "agent.py").write_bytes(data)
        files = [{"path": "agent.py", "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}]
        return {"files": files, "source_manifest_sha256": runner.digest(files),
                "files_exported": 1, "bytes_exported": len(data)}

    def test_scope_keeps_production_prompts_and_templates_but_removes_test_docs_vendor(self):
        for path in ["src/agent.py", "src/prompts/system.md", "src/templates/agent.py", "pyproject.toml"]:
            self.assertTrue(runner.selected(path, self.project, self.policy), path)
        for path in ["src/tests/agent.py", "src/test_agent.py", "src/docs/a.md", "src/vendor/tool.py", "src/README.md", "src/logo.png", "outside/agent.py"]:
            self.assertFalse(runner.selected(path, self.project, self.policy), path)

    def test_rejects_escaping_and_ambiguous_paths(self):
        for path in ["", "../x", "/x", "a/../../b", "C:\\x", "a\\b", "a\x00b", "a\nb", "C:/x"]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                runner.safe_relative(path)

    def test_verification_rejects_modified_missing_and_added_files(self):
        snapshot = self.snapshot()
        runner.verify_snapshot(self.source, snapshot)
        (self.source / "agent.py").write_bytes(b"value = 2\n")
        with self.assertRaisesRegex(ValueError, "content drift"):
            runner.verify_snapshot(self.source, snapshot)
        self.snapshot()
        (self.source / "extra.py").write_text("pass")
        with self.assertRaisesRegex(ValueError, "Unexpected"):
            runner.verify_snapshot(self.source, snapshot)
        (self.source / "extra.py").unlink()
        (self.source / "agent.py").unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            runner.verify_snapshot(self.source, snapshot)

    def test_verification_rejects_manifest_tampering_and_duplicate_paths(self):
        snapshot = self.snapshot()
        snapshot["files"][0]["bytes"] += 1
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            runner.verify_snapshot(self.source, snapshot)
        snapshot = self.snapshot()
        snapshot["files"].append(snapshot["files"][0].copy())
        snapshot["source_manifest_sha256"] = runner.digest(snapshot["files"])
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            runner.verify_snapshot(self.source, snapshot)

    def test_verification_rejects_symlink_files_and_directories(self):
        snapshot = self.snapshot()
        for directory in (False, True):
            link = self.source / "link"
            try:
                link.symlink_to(self.root if directory else self.source / "agent.py", target_is_directory=directory)
            except OSError:
                self.skipTest("Symlink creation unavailable")
            with self.assertRaisesRegex(ValueError, "symlink"):
                runner.verify_snapshot(self.source, snapshot)
            link.unlink()

    def test_invalid_revisions_and_fetch_urls_never_invoke_git(self):
        with mock.patch.object(runner.subprocess, "check_output") as call:
            for revision in ["HEAD", "--upload-pack=evil", "a" * 39]:
                with self.assertRaises(ValueError):
                    runner.entries(self.root, revision)
            for url in ["file:///tmp/repo", "https://evil.example/x/y", "https://github.com/a/b?x=y"]:
                with self.assertRaises(ValueError):
                    runner.fetch_project(self.root, {**self.project, "repository": url})
            call.assert_not_called()

    def test_export_reads_only_regular_blobs_without_target_execution(self):
        data = b"raise RuntimeError('must never execute')\n"
        records = [
            {"path": "src/agent.py", "mode": "100755", "kind": "blob", "git_blob": "b" * 40},
            {"path": "src/link.py", "mode": "120000", "kind": "blob", "git_blob": "c" * 40},
        ]
        def git_reply(repo, *args):
            self.assertIn(args, [("cat-file", "-s", "b" * 40), ("cat-file", "blob", "b" * 40)])
            return str(len(data)).encode() if args[1] == "-s" else data
        with mock.patch.object(runner, "entries", return_value=records), mock.patch.object(runner, "git", side_effect=git_reply):
            snapshot = runner.prepare_project(self.root, self.source, self.project, self.policy, self.root / "snapshot.json")
        self.assertEqual((self.source / "src/agent.py").read_bytes(), data)
        if os.name != "nt":
            self.assertEqual((self.source / "src/agent.py").stat().st_mode & 0o111, 0)
        self.assertFalse((self.source / "src/link.py").exists())
        self.assertEqual(len(snapshot["selected_nonregular_entries_excluded"]), 1)

    def test_real_scanner_repeats_four_artifacts_and_never_executes_target(self):
        marker = self.root / "executed.txt"
        snapshot = self.snapshot("from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('bad')\n")
        options = {"max_file_bytes": 1000000, "max_total_bytes": 1000000,
                   "max_files": 100, "max_entries": 1000, "fail_on": "high"}
        receipt = runner.scan_project(self.source, self.root / "reports", self.project, snapshot,
                                      options, self.root / "receipt.json", 60, 2)
        self.assertTrue(receipt["byte_identical_reports"])
        self.assertEqual(len(receipt["repeated_runs"]), 2)
        self.assertIn("--summary-json", receipt["command"])
        self.assertFalse(marker.exists())
        self.assertEqual(len(receipt["repeated_runs"][0]["report_sha256"]), 4)


if __name__ == "__main__":
    unittest.main()
