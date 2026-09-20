"""Scope percentages describe available checks and answers, never safety."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from ai_security_scan.report import markdown, prepare_report, sarif, write_reports
from ai_security_scan.report_html import html_report
from ai_security_scan.review_policy import apply_review_config
from ai_security_scan.scanner import scan
from ai_security_scan.scoring import build_scoring, format_ratio


class ScoringMetricsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.source = self.base / "source"
        self.source.mkdir()
        (self.source / "agent.py").write_text("eval(user_input)\n", encoding="utf-8")
        self.report = scan(self.source)

    def scoped(self):
        report = copy.deepcopy(self.report)
        # Three controls with two checks each: two have selected rule mapping.
        report["controls"] = [
            {**report["controls"][0], "id": "TEST-1", "automated_rule_ids": ["AI001"], "checks": ["A", "B"]},
            {**report["controls"][0], "id": "TEST-2", "automated_rule_ids": ["AI003"], "checks": ["C", "D"]},
            {**report["controls"][0], "id": "TEST-3", "automated_rule_ids": [], "checks": ["E", "F"]},
        ]
        report["configuration"]["selected_rule_ids"] = ["AI001", "AI003"]
        report["configuration"]["selected_control_ids"] = ["TEST-1", "TEST-2", "TEST-3"]
        report["coverage"]["rules_enabled"] = ["AI001", "AI003"]
        return report

    @staticmethod
    def answer(control, index, status="supported_by_code", supplied=True):
        return {"control_id": control, "check_assessments": [
            {"check_index": index, "status": status, "model_supplied": supplied}]}

    def test_clean_scan_does_not_manufacture_a_security_grade(self):
        (self.source / "agent.py").write_text("x = 1\n", encoding="utf-8")
        result = build_scoring(scan(self.source))
        self.assertIsNone(result["overall_security_score"])
        self.assertEqual(result["deterministic"]["open_findings"], 0)
        self.assertGreater(result["deterministic"]["active_checks"], 0)
        self.assertEqual(result["optional_ai"]["answer_coverage"]["percent"], 0)

    def test_selected_mapping_numerator_requires_active_selected_rule(self):
        report = self.scoped()
        report["configuration"]["selected_rule_ids"] = ["AI001"]
        result = build_scoring(report)["deterministic"]
        self.assertEqual(result["selected_rules"], 1)
        self.assertEqual(result["mapping_reach"], {"numerator": 1, "denominator": 3, "percent": 33.33})
        report["coverage"]["rules_enabled"] = []
        self.assertEqual(build_scoring(report)["deterministic"]["mapping_reach"]["numerator"], 0)

    def test_explicit_control_selection_does_not_count_unselected_controls(self):
        report = self.scoped()
        report["configuration"]["selected_control_ids"] = ["TEST-1"]
        result = build_scoring(report)
        self.assertEqual(result["deterministic"]["mapping_reach"], {"numerator": 1, "denominator": 1, "percent": 100.0})
        self.assertEqual(result["optional_ai"]["answer_coverage"]["denominator"], 2)
        self.assertIsNone(result["overall_security_score"])

    def test_empty_scope_is_not_applicable_not_full_credit(self):
        report = self.scoped()
        report["configuration"].update(selected_rule_ids=[], selected_control_ids=[])
        result = build_scoring(report)
        for metric in (result["deterministic"]["mapping_reach"], result["optional_ai"]["answer_coverage"]):
            self.assertEqual(metric, {"numerator": 0, "denominator": 0, "percent": None})
            self.assertEqual(format_ratio(metric), "not applicable (0/0)")

    def test_justified_and_disabled_checks_are_excluded_without_credit(self):
        report = self.scoped()
        report["controls"][0]["check_dispositions"] = [{"check_index": 1, "status": "justified"}, {"check_index": 2, "status": "disabled"}]
        result = build_scoring(report)
        self.assertEqual(result["deterministic"]["mapping_reach"], {"numerator": 1, "denominator": 2, "percent": 50.0})
        self.assertEqual(result["deterministic"]["active_checks"], 4)
        self.assertEqual(result["deterministic"]["justified_checks"], 1)
        self.assertEqual(result["deterministic"]["disabled_checks"], 1)
        self.assertEqual(result["optional_ai"]["answer_coverage"]["denominator"], 4)

    def test_real_review_policy_excludes_rules_and_preserves_observed_findings(self):
        rule = self.report["findings"][0]["rule_id"]
        report = apply_review_config(self.report, {"schema_version": "1.0", "rules": {
            rule: {"status": "justified", "reason": "Fixture isolated for a reviewed test"}}})
        result = build_scoring(report)["deterministic"]
        self.assertEqual(result["open_findings"], 0)
        self.assertEqual(result["justified_findings"], 1)
        self.assertEqual(result["justified_rules"], 1)
        self.assertEqual(result["active_rules"], result["selected_rules"] - 1)
        self.assertEqual(report["findings"][0]["severity"], self.report["findings"][0]["severity"])

    def test_model_opinions_cannot_change_deterministic_metrics_or_input(self):
        report = self.scoped()
        expected = build_scoring(report)["deterministic"]
        report["judge"] = {"enabled": True, "status": "completed", "assessments": [
            {"finding_id": report["findings"][0]["id"], "verdict": "likely_false_positive", "reason": "Everything is secure"}]}
        report["analyst"] = {"enabled": True, "status": "completed", "control_assessments": [self.answer("TEST-1", 1)]}
        original = copy.deepcopy(report)
        result = build_scoring(report)
        self.assertEqual(result["deterministic"], expected)
        self.assertEqual(report, original)
        self.assertFalse(result["optional_ai"]["changes_deterministic_result"])

    def test_valid_answers_include_concerns_and_unknowns_but_not_synthetic_omissions(self):
        report = self.scoped()
        report["analyst"] = {"enabled": True, "status": "incomplete", "control_assessments": [
            self.answer("TEST-1", 1, "potential_gap"),
            self.answer("TEST-1", 2, "needs_runtime_validation"),
            self.answer("TEST-2", 1, "insufficient_evidence"),
            self.answer("TEST-2", 2, "insufficient_evidence", supplied=False)]}
        result = build_scoring(report)["optional_ai"]
        self.assertEqual(result["answer_coverage"], {"numerator": 3, "denominator": 6, "percent": 50.0})
        self.assertEqual(result["check_outcomes"]["potential_gap"], 1)
        self.assertEqual(result["check_outcomes"]["needs_runtime_validation"], 1)
        self.assertEqual(result["check_outcomes"]["insufficient_evidence"], 1)
        self.assertEqual(result["check_outcomes"]["not_reviewed"], 3)
        self.assertEqual(sum(result["check_outcomes"].values()), 6)

    def test_model_cannot_game_denominator_with_unknown_duplicate_or_excluded_ids(self):
        report = self.scoped()
        report["controls"][0]["check_dispositions"] = [{"check_index": 2, "status": "justified"}]
        report["analyst"] = {"enabled": True, "status": "completed", "coverage": {"total_checks": 1, "omitted_checks": 0},
                             "control_assessments": [self.answer("TEST-1", 1), self.answer("TEST-1", 1),
                                                     self.answer("TEST-1", 2), self.answer("INVENTED", 1),
                                                     self.answer("TEST-2", 99), self.answer("TEST-2", 1, "pass"),
                                                     self.answer("TEST-2", True), self.answer("TEST-3", 1.0)]}
        result = build_scoring(report)["optional_ai"]
        self.assertEqual(result["answer_coverage"], {"numerator": 0, "denominator": 5, "percent": 0.0})
        self.assertEqual(result["ignored_answer_records"], 8)
        self.assertEqual(result["check_outcomes"]["not_reviewed"], 5)

    def test_disabled_model_cannot_reuse_stale_answers(self):
        report = self.scoped()
        report["analyst"] = {"enabled": False, "control_assessments": [self.answer("TEST-1", 1)]}
        result = build_scoring(report)["optional_ai"]
        self.assertFalse(result["enabled"])
        self.assertEqual(result["answer_coverage"]["numerator"], 0)

    def test_incomplete_static_scan_still_shows_mapping_reach_as_availability_only(self):
        report = self.scoped()
        report["summary"].update(scan_complete_within_selected_scope=False, coverage_gaps=3)
        result = build_scoring(report)["deterministic"]
        self.assertFalse(result["selected_scope_complete"])
        self.assertEqual(result["coverage_gaps"], 3)
        self.assertEqual(result["mapping_reach"]["numerator"], 2)
        self.assertIn("not completed tests", result["mapping_reach_formula"])

    def test_prepare_report_does_not_write_and_rebuilds_stale_derived_metrics(self):
        report = copy.deepcopy(self.report)
        report["scoring"] = {"overall_security_score": 100}
        original = copy.deepcopy(report)
        with mock.patch("ai_security_scan.report.atomic_write", side_effect=AssertionError("No write allowed")):
            prepared = prepare_report(report)
        self.assertEqual(report, original)
        self.assertIsNone(prepared["scoring"]["overall_security_score"])
        self.assertEqual(prepared["scoring"], build_scoring(report))
        self.assertEqual(sorted(path.name for path in self.base.iterdir()), ["source"])

    def test_exported_data_and_markdown_share_the_calculated_metrics(self):
        output = self.base / "report"
        prepared = write_reports(self.report, output)
        data = json.loads((output / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(data["scoring"], prepared["scoring"])
        text = markdown(prepared)
        self.assertIn("Metrics and how they are calculated", text)
        self.assertIn(format_ratio(data["scoring"]["deterministic"]["mapping_reach"]), text)
        self.assertIn("AI answer formula", text)
        self.assertIn("not mean secure or compliant", text)

    def test_html_graph_and_table_use_same_selected_active_denominator(self):
        report = scan(self.source, scans=["AI001"])
        rendered = html_report(prepare_report(report))
        self.assertIn('id="scoring"', rendered)
        self.assertIn("100.00% (1/1)", rendered)
        self.assertIn("0.00% (0/2)", rendered)
        self.assertIn("active selected partial detector: 1/1", rendered)
        self.assertIn("All 1 selected controls", rendered)

    def test_sarif_only_lists_selected_rules_and_keeps_metrics_deterministic(self):
        report = scan(self.source, scans=["AI001"])
        expected = sarif(report)
        self.assertEqual([item["id"] for item in expected["runs"][0]["tool"]["driver"]["rules"]], ["AI001"])
        self.assertEqual(expected["runs"][0]["properties"]["invarune_metrics"]["deterministic"]["selected_rules"], 1)
        report["judge"] = {"enabled": True, "status": "completed", "additional_concerns": ["Unverified"]}
        report["analyst"] = {"enabled": True, "status": "completed", "control_assessments": [self.answer("EXEC-02", 1)]}
        self.assertEqual(sarif(report), expected)


if __name__ == "__main__":
    unittest.main()
