"""End-to-end review/import workflows, independent of any model service."""
import contextlib
import copy
import io
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest
from ai_security_scan.rules import RULES
from unittest.mock import patch

from ai_security_scan import cli
from ai_security_scan.review_workspace import load_review_report


HAS_PDF = all(importlib.util.find_spec(name) is not None for name in ("reportlab", "pypdf"))
ARTIFACTS = ("report.html", "report.md", "report.json", "report.sarif")
PROJECT = Path(__file__).resolve().parents[1]


class ReviewRoundtripCLITests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.source = self.base / "target"
        self.source.mkdir()
        (self.source / "agent.py").write_bytes(b"import os\nos.system(user_input)\nos.system(other_input)\n")
        self.initial = self.base / "initial"
        code, _ = self.invoke(str(self.source), "--output", str(self.initial))
        self.assertEqual(code, 1)

    def tearDown(self):
        self.temporary.cleanup()

    def invoke(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main(list(args))
            except SystemExit as exc:
                code = exc.code
        return code, (out.getvalue(), err.getvalue())

    def workspace(self):
        return copy.deepcopy(json.loads((self.initial / "report.json").read_text())["review_workspace"])

    def edit(self, workspace, suffix):
        original = self.initial / ("report." + suffix)
        text = original.read_text()
        encoded = json.dumps(workspace, indent=2, sort_keys=True).replace("<", "\\u003c").replace(">", "\\u003e")
        if suffix == "json":
            value = json.loads(text)
            value["review_workspace"] = workspace
            text = json.dumps(value)
        elif suffix == "sarif":
            value = json.loads(text)
            value["runs"][0]["properties"]["invarune_review"] = workspace
            text = json.dumps(value)
        elif suffix == "md":
            text = re.sub(r"(?<=<!-- INVARUNE_REVIEW_BEGIN -->)[\s\S]*?(?=<!-- INVARUNE_REVIEW_END -->)",
                          lambda _: "\n```json\n" + encoded + "\n```\n", text)
        else:
            text = re.sub(r'(<script type="application/json" id="invarune-review">)[\s\S]*?(</script>)',
                          lambda match: match.group(1) + encoded + match.group(2), text)
        path = self.base / ("reviewed." + suffix)
        path.write_text(text, encoding="utf-8")
        return path

    def decision(self, workspace, kind="finding", decision="justified"):
        item = next(value for value in workspace["items"] if value["kind"] == kind)
        item.update(decision=decision, reason="Owner reviewed the explicit demo boundary.",
                    reviewer="Demo reviewer", reviewed_at="2026-09-19", evidence_ref="TEST-123")
        return item

    def test_all_four_formats_import_only_one_finding_without_waiving_its_rule(self):
        workspace = self.workspace()
        item = self.decision(workspace)
        for suffix in ("html", "md", "json", "sarif"):
            with self.subTest(suffix=suffix):
                reviewed = self.edit(workspace, suffix)
                self.assertEqual(load_review_report(reviewed), workspace)
                output = self.base / ("final-" + suffix)
                code, _ = self.invoke(str(self.source), "--review-report", str(reviewed), "--output", str(output))
                self.assertEqual(code, 1)
                report = json.loads((output / "report.json").read_text())
                self.assertEqual(report["summary"]["open_findings"], 1)
                self.assertEqual(report["summary"]["justified_findings"], 1)
                self.assertEqual(report["review_policy"]["counts"]["active_rules"], len(RULES))
                self.assertEqual(report["review_import"]["counts"]["applied"], 1)
                self.assertFalse(report["review_import"]["incomplete"])
                saved = next(value for value in report["review_workspace"]["items"] if value["id"] == item["id"])
                self.assertEqual(saved["reviewer"], "Demo reviewer")

    def test_check_exception_changes_only_active_check_denominator(self):
        workspace = self.workspace()
        self.decision(workspace, "check")
        path = self.edit(workspace, "json")
        output = self.base / "check-result"
        code, _ = self.invoke(str(self.source), "--review-report", str(path), "--output", str(output), "--summary-json")
        report = json.loads((output / "report.json").read_text())
        self.assertEqual(code, 1)
        self.assertEqual(report["summary"]["open_findings"], 2)
        self.assertEqual(report["review_policy"]["counts"]["active_checks"], 131)
        self.assertEqual(report["review_policy"]["counts"]["justified_checks"], 1)

    def test_explicit_runtime_requirement_is_incomplete_even_with_finding_gate_off(self):
        workspace = self.workspace()
        self.decision(workspace, "check", "needs_runtime_validation")
        path = self.edit(workspace, "md")
        output = self.base / "runtime-result"
        code, (_, stderr) = self.invoke(str(self.source), "--review-report", str(path), "--output", str(output), "--fail-on", "none")
        report = json.loads((output / "report.json").read_text())
        self.assertEqual(code, 2)
        self.assertEqual(report["assessment"]["posture"]["code"], "review_followup_required")
        self.assertEqual(report["review_import"]["counts"]["unresolved"], 1)
        self.assertIn("follow-up", stderr)

    def test_changed_source_invalidates_prior_exception_and_preserves_reason(self):
        workspace = self.workspace()
        self.decision(workspace)
        path = self.edit(workspace, "sarif")
        with (self.source / "agent.py").open("ab") as stream:
            stream.write(b"# source context changed\n")
        output = self.base / "stale-result"
        code, _ = self.invoke(str(self.source), "--review-report", str(path), "--output", str(output), "--fail-on", "none")
        report = json.loads((output / "report.json").read_text())
        self.assertEqual(code, 2)
        self.assertEqual(report["summary"]["open_findings"], 2)
        self.assertEqual(report["summary"]["justified_findings"], 0)
        self.assertEqual(report["review_import"]["counts"]["stale"], 1)
        self.assertIn("Owner reviewed", report["review_import"]["stale"][0]["reason"])

    def test_missing_target_and_input_overwrite_never_scan_or_enable_model(self):
        with patch.object(cli, "scan") as scan:
            code, _ = self.invoke("--review-report", str(self.initial / "report.json"))
            self.assertEqual(code, 2)
            code, _ = self.invoke(str(self.source), "--review-report", str(self.initial / "report.html"), "--output", str(self.initial))
            self.assertEqual(code, 2)
            scan.assert_not_called()

    def test_capsule_cannot_be_combined_with_separate_policy_or_manually_passed(self):
        workspace = self.workspace()
        item = self.decision(workspace)
        item["decision"] = "pass"
        path = self.edit(workspace, "json")
        with patch.object(cli, "scan") as scan:
            code, _ = self.invoke(str(self.source), "--review-report", str(path), "--output", str(self.base / "invalid"))
            self.assertEqual(code, 2)
            code, _ = self.invoke(str(self.source), "--review-report", str(path), "--review-config", "unused.json")
            self.assertEqual(code, 2)
            scan.assert_not_called()

    def test_review_notes_do_not_leak_into_finding_payload(self):
        workspace = self.workspace()
        item = self.decision(workspace, decision="note")
        item["reason"] = "PRIVATE-REVIEW-TICKET-887123"
        item["reviewer"] = "Private Reviewer"
        path = self.edit(workspace, "json")
        output = self.base / "note-result"
        code, _ = self.invoke(str(self.source), "--review-report", str(path), "--output", str(output))
        self.assertEqual(code, 1)
        report = json.loads((output / "report.json").read_text())
        payload = cli.judge_payload(report, self.source)
        self.assertNotIn("PRIVATE-REVIEW-TICKET", json.dumps(payload))
        self.assertNotIn("Private Reviewer", json.dumps(payload))
        self.assertFalse(report["judge"]["enabled"])

    def test_missing_optional_pdf_dependency_preserves_reports_and_reports_failure(self):
        output = self.base / "pdf-error"
        with patch.dict("sys.modules", {"ai_security_scan.report_pdf": None}):
            code, (stdout, _) = self.invoke(str(self.source), "--pdf", "--output", str(output), "--summary-json")
        self.assertEqual(code, 2)
        summary = json.loads(stdout)
        self.assertEqual(set(summary["reports"]), {"html", "json", "markdown", "sarif"})
        report = json.loads((output / "report.json").read_text())
        self.assertEqual(report["execution"]["exit_code"], 2)
        self.assertEqual(report["summary"]["open_findings"], 2)
        self.assertEqual(report["export_errors"][0]["format"], "pdf")

    def assert_unavailable_reports(self, output, expected_findings):
        self.assertTrue(all((output / name).is_file() for name in ARTIFACTS))
        report = json.loads((output / "report.json").read_text())
        self.assertEqual(report["execution"]["exit_code"], 2)
        self.assertEqual(report["summary"]["open_findings"], expected_findings)
        self.assertTrue(all(finding["status"] == "open" for finding in report["findings"]))
        self.assertTrue(report["summary"]["scan_complete_within_selected_scope"])
        self.assertIn("review_workspace_unavailable", report)
        self.assertNotIn("review_workspace", report)
        sarif = json.loads((output / "report.sarif").read_text())
        self.assertEqual(len(sarif["runs"][0]["results"]), expected_findings)
        self.assertNotIn("invarune_review", sarif["runs"][0].get("properties", {}))
        self.assertNotIn("<!-- INVARUNE_REVIEW_BEGIN -->", (output / "report.md").read_text())
        self.assertNotIn('type="application/json" id="invarune-review"', (output / "report.html").read_text())
        for filename in ARTIFACTS:
            with self.subTest(filename=filename), self.assertRaises(ValueError):
                load_review_report(output / filename)
        return report

    def test_initial_workspace_item_and_byte_limits_retain_all_static_reports(self):
        for name, value in (("MAX_ITEMS", 1), ("MAX_WORKSPACE_BYTES", 1)):
            output = self.base / ("limit-" + name)
            with self.subTest(limit=name), patch("ai_security_scan.review_workspace." + name, value):
                code, (stdout, _) = self.invoke(str(self.source), "--output", str(output), "--summary-json", "--fail-on", "none")
            self.assertEqual(code, 2)
            summary = json.loads(stdout)
            self.assertEqual(summary["exit_code"], 2)
            self.assertEqual(set(summary["reports"]), {"html", "json", "markdown", "sarif"})
            report = self.assert_unavailable_reports(output, 2)
            self.assertIn("limit", report["review_workspace_unavailable"]["reason"])

    def test_oversized_fresh_rescan_retains_unapplied_decisions_without_any_exemption(self):
        workspace = self.workspace()
        decided = self.decision(workspace)
        reviewed = self.edit(workspace, "json")
        # The prior capsule still fits. Only the fresh scan crosses each limit.
        (self.source / "new.py").write_text("import os\nos.system(new_input)\n", encoding="utf-8")
        byte_size = len(json.dumps(workspace, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("utf-8"))
        for name, value in (("MAX_ITEMS", len(workspace["items"])), ("MAX_WORKSPACE_BYTES", byte_size)):
            output = self.base / ("fresh-limit-" + name)
            with self.subTest(limit=name), patch("ai_security_scan.review_workspace." + name, value):
                code, _ = self.invoke(str(self.source), "--review-report", str(reviewed), "--output", str(output), "--fail-on", "none")
            self.assertEqual(code, 2)
            report = self.assert_unavailable_reports(output, 3)
            self.assertNotIn("review_policy", report)
            audit = report["review_import"]
            self.assertTrue(audit["incomplete"])
            self.assertEqual(audit["counts"]["applied"], 0)
            self.assertEqual(audit["counts"]["decisions"], 1)
            self.assertEqual(audit["unapplied_decisions"], [decided])

    @unittest.skipUnless(HAS_PDF, "Optional PDF extra is not installed")
    def test_source_and_image_pdf_export_edit_and_fresh_cli_import_with_full_catalog(self):
        import pypdf
        cases = [("source", [str(self.source)]),
                 ("image", ["--image-archive", str(PROJECT / "examples" / "images" / "demo-agent.tar")])]
        for name, target_args in cases:
            with self.subTest(target=name):
                initial = self.base / (name + "-pdf-initial")
                code, (stdout, stderr) = self.invoke(*target_args, "--pdf", "--output", str(initial), "--summary-json")
                self.assertEqual(code, 1, stderr)
                summary = json.loads(stdout)
                self.assertIn("pdf", summary["reports"])
                report = json.loads((initial / "report.json").read_text())
                workspace = report["review_workspace"]
                self.assertEqual(sum(item["kind"] == "check" for item in workspace["items"]), 132)
                self.assertEqual(len(report["controls"]), 66)
                reader = pypdf.PdfReader(initial / "report.pdf")
                self.assertEqual(len(reader.get_fields()), len(workspace["items"]) * 5)
                finding_index = next(index for index, item in enumerate(workspace["items"]) if item["kind"] == "finding")
                selected = workspace["items"][finding_index]
                prefix = "ivr." + str(finding_index) + "."
                values = {prefix + "decision": "justified", prefix + "reason": "Reviewed fixture deployment boundary.",
                          prefix + "reviewer": "PDF security reviewer", prefix + "reviewed_at": "2026-09-19",
                          prefix + "evidence_ref": "PDF-REVIEW-42"}
                writer = pypdf.PdfWriter()
                writer.clone_document_from_reader(reader)
                writer.update_page_form_field_values(None, values, auto_regenerate=False)
                reviewed = self.base / (name + "-reviewed.pdf")
                with reviewed.open("wb") as stream:
                    writer.write(stream)
                loaded = load_review_report(reviewed)
                self.assertEqual(loaded["items"][finding_index]["decision"], "justified")
                self.assertEqual(loaded["items"][finding_index]["binding_sha256"], selected["binding_sha256"])
                final = self.base / (name + "-pdf-final")
                code, (stdout, stderr) = self.invoke(*target_args, "--review-report", str(reviewed), "--output", str(final), "--summary-json")
                self.assertIn(code, (0, 1), stderr)
                result = json.loads((final / "report.json").read_text())
                final_summary = json.loads(stdout)
                expected_exit = int(any(finding["status"] == "open" and finding["severity"] in {"critical", "high"}
                                        for finding in result["findings"]))
                self.assertEqual(code, expected_exit)
                self.assertEqual(result["summary"]["open_findings"], report["summary"]["open_findings"] - 1)
                self.assertEqual(result["summary"]["justified_findings"], 1)
                self.assertEqual(final_summary["summary"], result["summary"])
                self.assertEqual(result["review_import"]["counts"]["applied"], 1)
                self.assertFalse(result["review_import"]["incomplete"])
                self.assertEqual(result["review_policy"]["counts"]["active_checks"], 132)
                self.assertEqual([(finding["id"], finding["severity"], finding["evidence"]) for finding in result["findings"]],
                                 [(finding["id"], finding["severity"], finding["evidence"]) for finding in report["findings"]])
                self.assertTrue(all(finding["status"] != "pass" for finding in result["findings"]))
                self.assertTrue(all(control["status"] != "pass" for control in result["controls"]))
                retained = next(item for item in result["review_workspace"]["items"] if item["id"] == selected["id"])
                self.assertEqual(retained["reviewer"], "PDF security reviewer")
                self.assertFalse(result["judge"]["enabled"])


if __name__ == "__main__":
    unittest.main()
