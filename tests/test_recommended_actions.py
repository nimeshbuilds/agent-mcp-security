"""Actionable advisory guidance stays bounded, separate and non-executable."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from ai_security_scan import judge
from ai_security_scan.cli_judge import _schema
from ai_security_scan.report import advice_coverage, write_reports
from ai_security_scan.scanner import scan


def actions():
    return {"agent_mcp_relevance": "A model-controlled tool argument could reach the shell.",
            "applicability": "Confirm the argument can contain untrusted text and is not isolated by the caller.",
            "steps": ["Replace shell command composition with an argument list and shell=False; allowlist the executable."],
            "verification": ["Submit an argument containing a semicolon and verify it remains one literal argument."]}


class RecommendedActionTests(unittest.TestCase):
    def answer(self):
        return {"assessments": [{"finding_id": "f-1", "verdict": "needs_review", "reason": "Trace the tool input.",
                                 "recommended_actions": actions()}],
                "additional_concerns": ["The deployment's tool approvals were not supplied."],
                "additional_concern_actions": [{"concern_index": 1, "recommended_actions": actions()}]}

    def test_finding_and_additional_concern_advice_survive_normalization(self):
        value = self.answer()
        result = judge._normalize(value, ["f-1"], set())
        self.assertEqual(result["assessments"], value["assessments"])
        self.assertEqual(result["additional_concern_actions"], value["additional_concern_actions"])
        self.assertEqual(result["assessments"][0]["verdict"], "needs_review")

    def test_legacy_responses_do_not_get_invented_model_guidance(self):
        value = self.answer()
        del value["assessments"][0]["recommended_actions"]
        del value["additional_concern_actions"]
        result = judge._normalize(value, ["f-1", "f-2"], set())
        self.assertNotIn("recommended_actions", result["assessments"][0])
        self.assertNotIn("recommended_actions", result["assessments"][1])
        self.assertEqual(result["omitted_assessments"], 1)

    def test_coverage_excludes_synthesized_omissions_from_model_answer_count(self):
        value = self.answer()
        result = judge._normalize(value, ["f-1", "f-2"], set())
        coverage = advice_coverage({"findings": [], "judge": result})
        self.assertEqual(coverage["finding_assessment_slots"], 2)
        self.assertEqual(coverage["finding_assessments"], 1)
        self.assertEqual(coverage["omitted_finding_assessments"], 1)
        self.assertEqual(coverage["finding_fix_plans"], 1)
        from ai_security_scan.report_html import _advisory
        html = _advisory({"analyst": {"enabled": True}, "advice_coverage": coverage})
        self.assertIn("Fix guidance coverage and omissions", html)

    def test_malformed_or_oversized_action_fields_are_rejected(self):
        cases = [None, {}, {**actions(), "execute": True}, {**actions(), "steps": "run this"},
                 {**actions(), "steps": []}, {**actions(), "steps": ["x"] * 6},
                 {**actions(), "steps": [None]}, {**actions(), "steps": ["x" * 1001]},
                 {**actions(), "verification": []}, {**actions(), "agent_mcp_relevance": "x" * 1201},
                 {**actions(), "applicability": " "}]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(judge.JudgeError):
                judge._recommended_actions(case, set())

    def test_concern_indices_are_unique_and_bound_to_existing_concerns(self):
        for index in (0, 2, True, "1", None):
            value = self.answer()
            value["additional_concern_actions"][0]["concern_index"] = index
            with self.subTest(index=index), self.assertRaises(judge.JudgeError):
                judge._normalize(value, ["f-1"], set())
        value = self.answer()
        value["additional_concern_actions"] *= 2
        with self.assertRaises(judge.JudgeError):
            judge._normalize(value, ["f-1"], set())

    def test_known_secrets_are_redacted_from_every_advice_field(self):
        value = {key: ["secretvalue"] if isinstance(item, list) else "secretvalue" for key, item in actions().items()}
        normalized = judge._recommended_actions(value, {"secretvalue"})
        self.assertNotIn("secretvalue", json.dumps(normalized))
        self.assertIn("[REDACTED]", json.dumps(normalized))

    def test_control_advice_does_not_override_grounding_or_runtime_requirement(self):
        controls = {"AUTH-01": {"checks": ["Verify live authorization"], "validation": "dynamic", "evidence_ids": ["E1"]}}
        evidence = {"E1": {"text": "require_permission(user)", "path": "agent.py", "start_line": 1, "end_line": 1, "source_sha256": "a" * 64}}
        output = {"control_assessments": [{"control_id": "AUTH-01", "check_assessments": [{
            "check_index": 1, "status": "supported_by_code", "reason": "A permission function is called.",
            "citations": [{"evidence_id": "E1", "quote": "require_permission(user)"}],
            "verification_steps": ["Test unauthorized requests."], "recommended_actions": actions()}]}]}
        result = judge._normalize_controls(output, controls, evidence, set())
        check = result["control_assessments"][0]["check_assessments"][0]
        self.assertEqual(check["status"], "needs_runtime_validation")
        self.assertEqual(check["recommended_actions"], actions())
        output["control_assessments"][0]["check_assessments"][0]["citations"] = []
        with self.assertRaises(judge.JudgeError):
            judge._normalize_controls(output, controls, evidence, set())

    def test_official_cli_schemas_request_actionable_guidance_in_both_stages(self):
        finding = _schema("findings")["properties"]["assessments"]["items"]
        control = _schema("controls")["properties"]["control_assessments"]["items"]["properties"]["check_assessments"]["items"]
        for item in (finding, control):
            self.assertIn("recommended_actions", item["required"])
            self.assertFalse(item["properties"]["recommended_actions"]["additionalProperties"])
        self.assertIn("additional_concern_actions", _schema("findings")["properties"])

    def test_reports_show_fix_details_escape_advice_and_keep_sarif_static(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source"
            source.mkdir()
            (source / "agent.py").write_text("import os\nos.system(user_input)\n")
            initial = write_reports(scan(source), root / "initial")
            report = copy.deepcopy(initial)
            value = self.answer()
            value["assessments"][0]["finding_id"] = report["findings"][0]["id"]
            value["assessments"][0]["recommended_actions"]["steps"] = ['Replace <script>alert(1)</script> & [link](https://evil.example) as literal text.']
            report["judge"] = {**judge._normalize(value, [report["findings"][0]["id"]], set()), "enabled": True, "status": "completed"}
            final = write_reports(report, root / "final")
            self.assertEqual(initial["findings"], final["findings"])
            self.assertEqual((root / "initial/report.sarif").read_bytes(), (root / "final/report.sarif").read_bytes())
            html = (root / "final/report.html").read_text()
            markdown = (root / "final/report.md").read_text()
            self.assertIn("Fix plan and agent/MCP relevance", html)
            self.assertIn("Model-proposed fix guidance", html)
            self.assertNotIn("<script>alert(1)</script>", html)
            self.assertIn("Model-proposed fix guidance", markdown)
            self.assertEqual(final["advice_coverage"]["static_fix_plans"], 1)
            self.assertEqual(final["advice_coverage"]["finding_fix_plans"], 1)
            self.assertIn("agentMcpRemediation", json.loads((root / "final/report.sarif").read_text())["runs"][0]["results"][0]["properties"])

    @unittest.skipUnless(importlib.util.find_spec("pypdf") and importlib.util.find_spec("reportlab"), "Optional PDF extra is not installed")
    def test_pdf_contains_static_and_optional_fix_guidance(self):
        from pypdf import PdfReader
        from ai_security_scan.report_pdf import render_pdf
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source"
            source.mkdir()
            (source / "agent.py").write_text("import os\nos.system(user_input)\n")
            report = scan(source)
            report["controls"] = report["controls"][:1]
            value = self.answer()
            value["assessments"][0]["finding_id"] = report["findings"][0]["id"]
            report["judge"] = {**judge._normalize(value, [report["findings"][0]["id"]], set()), "enabled": True, "status": "completed"}
            report = write_reports(report, root / "report")
            render_pdf(report, root / "report.pdf")
            text = " ".join(page.extract_text() for page in PdfReader(root / "report.pdf").pages)
            self.assertIn("Fix plan and agent/MCP relevance", text)
            self.assertIn("Model-proposed fix guidance", text)
            self.assertIn("shell=False", text)
            self.assertIn("Additional model concern", text)


if __name__ == "__main__":
    unittest.main()
