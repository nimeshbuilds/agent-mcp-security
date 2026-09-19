"""Explicit configuration/output exclusions survive filesystem aliases."""

import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from ai_security_scan.cli import main
from ai_security_scan.evidence import build_evidence
from ai_security_scan import scanner
from ai_security_scan.scanner import scan
from tests.test_analyst_cli import triage_response
from tests.test_analyst_controller import review_response


class ExclusionIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "source"
        self.root.mkdir()
        (self.root / "agent.py").write_bytes(b'name = "ordinary agent"\n')

    def hardlink(self, source, destination):
        try:
            os.link(str(source), str(destination))
        except OSError:
            self.skipTest("Hardlinks are unavailable on this filesystem")

    def require_case_alias(self, actual, alias):
        if actual == alias or not alias.exists() or not actual.samefile(alias):
            self.skipTest("Case-alias regression requires a case-insensitive filesystem")

    def test_inside_and_outside_trusted_file_hardlinks_are_not_read_or_sent(self):
        trusted = self.base / "trusted"
        trusted.mkdir()
        paths = []
        for name in ("review", "judge", "baseline"):
            # Retrieval-keyword text makes accidental evidence selection visible.
            content = ("# authentication authorization private_" + name + "_fixture\n").encode()
            actual = (self.root if name == "review" else trusted) / (name + ".py")
            actual.write_bytes(content)
            paths.append(actual)
            self.hardlink(actual, self.root / ("0_auth_" + name + "_alias.py"))
        snapshots = []
        for _ in range(2):
            with mock.patch("ai_security_scan.scanner.read_confined", wraps=scanner.read_confined) as reader:
                report = scan(self.root, output_paths=paths, max_files=1, max_entries=1)
            self.assertEqual([call.args[1] for call in reader.call_args_list], ["agent.py"])
            self.assertEqual([entry["path"] for entry in report["files"]], ["agent.py"])
            self.assertEqual(report["summary"]["files_scanned"], 1)
            self.assertEqual(report["summary"]["coverage_gaps"], 0)
            self.assertEqual(report["summary"]["bytes_read"], len((self.root / "agent.py").read_bytes()))
            self.assertEqual(report["coverage"]["skipped"], [])
            evidence = build_evidence(report, self.root)
            self.assertNotIn("private_", json.dumps(evidence))
            snapshots.append(report)
        self.assertEqual(snapshots[0], snapshots[1])

    def test_case_alias_review_config_is_absent_from_full_model_pipeline(self):
        marker = "AUTHENTICATION_AUTHORIZATION_PRIVATE_OWNER_REASON_123"
        actual = self.root / "REVIEW.JSON"
        actual.write_text(json.dumps({"schema_version": "1.0", "controls": {
            "GOV-01": {"status": "justified", "reason": marker}}}), encoding="utf-8")
        alias = self.root / "review.json"
        self.require_case_alias(actual, alias)
        judge_path = self.base / "judge.json"
        judge_path.write_text(json.dumps({"provider": "openai_chat", "model": "test-only-model"}), encoding="utf-8")
        output = self.base / "reports"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
             mock.patch("ai_security_scan.judge.review", side_effect=triage_response) as triage, \
             mock.patch("ai_security_scan.judge.review_controls", side_effect=review_response) as analyst:
            code = main([str(self.root), "--review-config", str(alias), "--judge-config", str(judge_path),
                         "--output", str(output), "--quiet"])
        self.assertEqual(code, 0)
        report = json.loads((output / "report.json").read_text(encoding="utf-8"))
        self.assertEqual([item["path"] for item in report["files"]], ["agent.py"])
        self.assertEqual(report["review_policy"]["entries"]["controls"]["GOV-01"]["reason"], marker)
        self.assertGreater(analyst.call_count, 0)
        payloads = [call.args[1] for call in triage.call_args_list + analyst.call_args_list]
        self.assertNotIn(marker, json.dumps(payloads))
        self.assertNotIn("REVIEW.JSON", json.dumps(report["analyst"]["evidence"]))

    def test_external_case_alias_excludes_its_in_target_hardlink(self):
        actual = self.base / "TRUSTED.JSON"
        actual.write_bytes(b'{"authentication":"private_configuration_fixture"}')
        alias = self.base / "trusted.json"
        self.require_case_alias(actual, alias)
        self.hardlink(actual, self.root / "auth_config.json")
        with mock.patch("ai_security_scan.scanner.read_confined", wraps=scanner.read_confined) as reader:
            report = scan(self.root, output_paths=[alias])
        self.assertEqual([call.args[1] for call in reader.call_args_list], ["agent.py"])
        self.assertEqual([item["path"] for item in report["files"]], ["agent.py"])
        self.assertEqual(report["summary"]["coverage_gaps"], 0)

    def test_hardlinked_judge_config_is_absent_from_full_model_pipeline(self):
        marker = "AUTHENTICATION_AUTHORIZATION_PRIVATE_GATEWAY_MODEL"
        judge_path = self.base / "trusted-judge.json"
        judge_path.write_text(json.dumps({"provider": "openai_chat", "model": marker}), encoding="utf-8")
        self.hardlink(judge_path, self.root / "auth_design.json")
        output = self.base / "reports"
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
             mock.patch("ai_security_scan.judge.review", side_effect=triage_response) as triage, \
             mock.patch("ai_security_scan.judge.review_controls", side_effect=review_response) as analyst:
            code = main([str(self.root), "--judge-config", str(judge_path), "--output", str(output), "--quiet"])
        self.assertEqual(code, 0)
        report = json.loads((output / "report.json").read_text(encoding="utf-8"))
        self.assertEqual([item["path"] for item in report["files"]], ["agent.py"])
        payloads = [call.args[1] for call in triage.call_args_list + analyst.call_args_list]
        self.assertNotIn(marker, json.dumps(payloads))
        self.assertNotIn("auth_design.json", json.dumps(report["analyst"]["evidence"]))

    def test_generated_output_directory_case_alias_is_pruned_before_read(self):
        parent = self.root / "REPORTING"
        actual = parent / "REPORTS"
        actual.mkdir(parents=True)
        (actual / "prior.py").write_bytes(b"eval(untrusted_input)\n")
        (parent / "ordinary.py").write_bytes(b"value = 1\n")
        alias = self.root / "reporting" / "reports"
        self.require_case_alias(actual, alias)
        with mock.patch("ai_security_scan.scanner.read_confined", wraps=scanner.read_confined) as reader:
            report = scan(self.root, output_paths=[alias])
        self.assertEqual([item["path"] for item in report["files"]], ["agent.py", "REPORTING/ordinary.py"])
        self.assertEqual([call.args[1] for call in reader.call_args_list], ["agent.py", "REPORTING/ordinary.py"])
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["coverage"]["skipped"], [])

    def test_new_output_paths_and_ordinary_source_remain_supported(self):
        for name in ("ordinary.py", "nested/ordinary.py"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"value = 1\n")
        report = scan(self.root, output_paths=[self.root / "future-reports", self.base / "future-baseline.json"])
        self.assertEqual([item["path"] for item in report["files"]], ["agent.py", "ordinary.py", "nested/ordinary.py"])
        self.assertEqual(report["summary"]["coverage_gaps"], 0)
        self.assertEqual(report["configuration"]["explicit_exclusion_matching"], "resolved_paths_and_snapshot_filesystem_identities")
        self.assertIn("must remain stable", report["configuration"]["explicit_exclusion_identity_scope"])

    def test_target_symlink_is_not_followed_to_match_excluded_file(self):
        actual = self.base / "trusted.py"
        actual.write_bytes(b"# authentication private_fixture\n")
        link = self.root / "alias.py"
        try:
            link.symlink_to(actual)
        except OSError:
            self.skipTest("Creating symlinks requires platform permission")
        with mock.patch("ai_security_scan.scanner.read_confined", wraps=scanner.read_confined) as reader:
            report = scan(self.root, output_paths=[actual])
        self.assertEqual([call.args[1] for call in reader.call_args_list], ["agent.py"])
        self.assertEqual([item["path"] for item in report["files"]], ["agent.py"])
        self.assertEqual(report["coverage"]["skipped"], [{"path": "alias.py", "reason": "symlink_file", "coverage_gap": True}])


if __name__ == "__main__":
    unittest.main()
