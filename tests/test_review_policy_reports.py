"""User decisions must remain visible without masquerading as control passes."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from ai_security_scan.analyst import run_analyst
from ai_security_scan.assessment import build_assessment
from ai_security_scan.image_scan import scan_image
from ai_security_scan.report import markdown, sarif, write_reports
from ai_security_scan.report_html import html_report
from ai_security_scan.review_policy import apply_review_config
from ai_security_scan.rules import RULES
from ai_security_scan.scanner import scan
from tests.image_fixtures import docker_archive
from tests.test_report_html import Document, assert_trusted_script_boundary


class ReviewPolicyReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "source"
        self.root.mkdir()
        (self.root / "agent.py").write_text("import os\nos.system(user_input)\neval(user_input)\n", encoding="utf-8")
        (self.root / "key.pem").write_text("-----BEGIN PRIVATE KEY-----\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n", encoding="utf-8")
        self.report = scan(self.root)
        self.assertEqual({f["rule_id"] for f in self.report["findings"]}, {"AI001", "AI003", "AI011"})
        self.policy = {"schema_version": "1.0", "rules": {
            "AI003": {"status": "justified", "reason": "Deployment exception with owner review."},
            "AI001": {"status": "disabled", "reason": "Excluded from this review scope."}},
            "controls": {"GOV-01": {"status": "justified", "reason": "Policy recorded in the external register."}},
            "checks": {"GOV-02:1": {"status": "justified", "reason": "Review approved outside this repository."},
                       "GOV-02:2": {"status": "disabled", "reason": "Not included in this assessment."},
                       "GOV-03:1": {"status": "disabled", "reason": "Review deferred by scope owner."}}}

    def test_mixed_dispositions_exclude_counts_and_priorities_but_retain_severity(self):
        report = apply_review_config(self.report, self.policy)
        original = copy.deepcopy(report)
        assessment = build_assessment(report)
        self.assertEqual(report, original)
        metrics = assessment["metrics"]
        self.assertEqual((metrics["open_findings"], metrics["justified_findings"], metrics["disabled_findings"]), (1, 1, 1))
        self.assertEqual(metrics["suppressed_findings"], 0)
        self.assertEqual(metrics["urgent_findings"], 1)
        self.assertEqual((metrics["active_rules"], metrics["justified_rules"], metrics["disabled_rules"]), (len(RULES) - 2, 1, 1))
        self.assertEqual((metrics["active_checks"], metrics["justified_checks"], metrics["disabled_checks"]), (127, 3, 2))
        self.assertEqual((metrics["controls_requiring_validation"], metrics["justified_controls"], metrics["disabled_controls"], metrics["excluded_controls"]), (64, 1, 0, 2))
        self.assertEqual(metrics["mixed_excluded_controls"], 1)
        self.assertEqual(metrics["controls_total"], 66)
        self.assertEqual(metrics["checks_total"], 132)
        self.assertEqual([g["rule_id"] for g in assessment["immediate_actions"]], ["AI011"])
        self.assertEqual({g["rule_id"]: g["priority"] for g in assessment["finding_groups"]}, {"AI011": "P0", "AI003": "Justified", "AI001": "Disabled"})
        self.assertEqual(sum(t["open_findings"] for t in assessment["themes"]), 1)
        before = {f["id"]: f for f in self.report["findings"]}
        for finding in report["findings"]:
            for field in ("severity", "confidence", "path", "line", "evidence"):
                self.assertEqual(finding[field], before[finding["id"]][field])

    def test_all_exempt_and_baseline_states_are_not_clean_or_pass(self):
        critical = next(f for f in self.report["findings"] if f["rule_id"] == "AI011")
        raw = scan(self.root, baseline={critical["id"]: "Accepted synthetic fixture."})
        report = apply_review_config(raw, self.policy)
        assessment = build_assessment(report)
        self.assertEqual(assessment["posture"]["code"], "configured_exceptions")
        self.assertEqual(assessment["metrics"]["open_findings"], 0)
        self.assertEqual(assessment["metrics"]["urgent_findings"], 0)
        self.assertEqual(assessment["metrics"]["suppressed_findings"], 1)
        self.assertEqual(assessment["immediate_actions"], [])
        self.assertEqual(assessment["themes"], [])
        self.assertNotIn("no_patterns_detected", json.dumps(assessment["posture"]))
        for output in (markdown(report), " ".join(Document(html_report(report)).text)):
            self.assertIn("configured exceptions", output)
            self.assertIn("justified", output)
            self.assertIn("disabled", output)
            self.assertIn("without positive or negative credit", output)
            self.assertIn("Deployment exception with owner review", output)
        priorities = {g["rule_id"]: g["priority"] for g in assessment["finding_groups"]}
        self.assertEqual(priorities["AI011"], "Accepted")

    def test_incomplete_scope_still_wins_over_every_exception(self):
        policy = {"schema_version": "1.0", "rules": {f["rule_id"]: {"status": "justified", "reason": "Recorded exception."} for f in self.report["findings"]}}
        raw = copy.deepcopy(self.report)
        raw["summary"].update(coverage_gaps=1, scan_complete_within_selected_scope=False)
        raw["coverage"]["errors"].append({"path": "unreadable.py", "error": "Fixture denied read", "kind": "read_error"})
        report = apply_review_config(raw, policy)
        assessment = build_assessment(report)
        self.assertEqual(assessment["posture"]["code"], "incomplete_scope")
        self.assertEqual(assessment["metrics"]["coverage_gaps"], 1)
        self.assertEqual(assessment["metrics"]["justified_findings"], 3)
        self.assertEqual(sarif(report)["runs"][0]["invocations"][0]["executionSuccessful"], False)
        self.assertIn("Fixture denied read", html_report(report))

    def test_zero_match_policy_is_audited_and_active_denominators_are_explicit(self):
        (self.root / "agent.py").write_text("agent_name = 'fixture'\n", encoding="utf-8")
        (self.root / "key.pem").unlink()
        report = apply_review_config(scan(self.root), self.policy)
        self.assertEqual(report["findings"], [])
        self.assertEqual(build_assessment(report)["posture"]["code"], "configured_exceptions")
        md = markdown(report)
        doc = Document(html_report(report))
        summary = " ".join(doc.sections["summary"])
        self.assertIn(str(len(RULES) - 2) + " active rules", summary)
        self.assertIn("127 active acceptance checks", summary)
        self.assertIn("64 active controls require validation", summary)
        self.assertIn("not validated passes", summary)
        self.assertIn("review-policy", doc.sections)
        self.assertIn("Deployment exception with owner review.", " ".join(doc.sections["review-policy"]))
        self.assertIn("| Rules | " + str(len(RULES) - 2) + " | 1 | 1 | 0 | " + str(len(RULES)) + " |", md)
        self.assertIn("| Controls | 64 | 1 | 0 | 1 | 66 |", md)
        self.assertIn("| Checks | 127 | 3 | 2 | 0 | 132 |", md)
        for content in (md, " ".join(doc.text)):
            self.assertIn("control and individual-check decisions affect checklist review only", content.lower())
        run = sarif(report)["runs"][0]
        self.assertEqual(run["results"], [])
        self.assertEqual(run["properties"]["userReviewPolicy"], report["review_policy"])

    def test_sarif_retains_all_evidence_and_distinguishes_user_decisions_from_baseline(self):
        critical = next(f for f in self.report["findings"] if f["rule_id"] == "AI011")
        report = apply_review_config(scan(self.root, baseline={critical["id"]: "Baseline fixture."}), self.policy)
        run = sarif(report)["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], self.report["tool"]["name"])
        self.assertEqual(len(run["results"]), 3)
        originals = {f["rule_id"]: f for f in self.report["findings"]}
        for result in run["results"]:
            self.assertEqual(result["partialFingerprints"]["agentMcpScan/v1"], originals[result["ruleId"]]["id"])
            self.assertEqual(result["level"], "error")
            self.assertEqual(result["suppressions"][0]["kind"], "external")
            self.assertEqual(result["suppressions"][0]["status"], "accepted")
            self.assertTrue(result["suppressions"][0]["justification"])
            if result["ruleId"] == "AI011":
                self.assertNotIn("userDisposition", result["properties"])
            else:
                self.assertEqual(result["properties"]["userDisposition"]["status"], result["properties"]["status"])
                self.assertEqual(result["properties"]["originalStatus"], "open")
        self.assertEqual(run["properties"]["userReviewPolicy"]["sha256"], report["review_policy"]["sha256"])

    def test_hostile_reasons_are_text_in_summary_audit_findings_and_checks(self):
        payload = '<img src="https://attacker.test/leak" onerror="alert(1)"><script>run()</script> [link](javascript:run) | table `code`\nnext'
        policy = copy.deepcopy(self.policy)
        for entries in (policy["rules"], policy["controls"], policy["checks"]):
            for entry in entries.values():
                entry["reason"] = payload
        report = apply_review_config(self.report, policy)
        page = html_report(report)
        md = markdown(report)
        self.assertNotIn(payload, page)
        self.assertNotIn('<img src=', md)
        # The reusable JSON capsule is code-fenced data; its text is not a link.
        prose = md.split('<!-- INVARUNE_REVIEW_BEGIN -->', 1)[0]
        self.assertNotIn('[link](javascript:run)', prose)
        self.assertIn('\\| table', md)
        doc = Document(page)
        self.assertIn(payload, " ".join(doc.text))
        self.assertNotIn("img", [tag for tag, _ in doc.tags])
        assert_trusted_script_boundary(self, page)
        for _, attrs in doc.tags:
            self.assertFalse(any(name.startswith("on") for name in attrs))
            self.assertNotEqual(attrs.get("href"), "javascript:run")

    def test_exempt_checklist_entries_show_reason_without_pending_checkbox(self):
        report = apply_review_config(self.report, self.policy)
        md = markdown(report)
        first = report["controls"][0]
        section = md.split("### GOV\\-01:", 1)[1].split("### GOV\\-02:", 1)[0]
        self.assertNotIn("- [ ]", section)
        self.assertEqual(section.count("- **justified**"), 2)
        self.assertIn("Policy recorded in the external register", section)
        self.assertIn("Underlying static status", section)
        doc = Document(html_report(report))
        self.assertIn(first["checks"][0], " ".join(doc.sections["controls"]))
        self.assertIn("Excluded from active review totals without positive or negative credit", " ".join(doc.sections["controls"]))
        self.assertIn("Justified finding IDs", " ".join(doc.sections["controls"]))
        self.assertIn("Disabled finding IDs", " ".join(doc.sections["controls"]))

    def test_all_acceptance_checks_excluded_are_not_unanswered_model_work(self):
        policy = {"schema_version": "1.0", "controls": {
            control["id"]: {"status": "justified" if index % 2 else "disabled", "reason": "External scope decision."}
            for index, control in enumerate(self.report["controls"])}}
        report = apply_review_config(self.report, policy)
        with mock.patch("ai_security_scan.analyst.judge.review_controls", side_effect=AssertionError("No active checks")):
            report["analyst"] = run_analyst({}, report, self.root)
        report["judge"] = {"enabled": True, "status": "completed"}
        self.assertEqual(report["analyst"]["status"], "completed")
        self.assertEqual(report["analyst"]["coverage"]["omitted_checks"], 0)
        self.assertEqual(report["analyst"]["coverage"]["total_checks"], 0)
        self.assertEqual(build_assessment(report)["metrics"]["controls_requiring_validation"], 0)
        self.assertEqual(build_assessment(report)["metrics"]["open_findings"], 3)
        md = markdown(report)
        doc = Document(html_report(report))
        self.assertIn("0 active controls require validation", " ".join(doc.sections["summary"]))
        for output in (md, " ".join(doc.sections["controls"])):
            self.assertNotIn("No model assessment was received for this check", output)
            self.assertIn("User decision; excluded from optional review and active check totals", output)
        self.assertEqual(md.count("- [ ]"), 0)

    def test_source_and_image_four_formats_are_repeatable_and_preserve_audit(self):
        archive = self.base / "image.tar"
        docker_archive(archive, [[("app/agent.py", "import os\nos.system(user_input)\n")]], config={"config": {"User": "1000"}})
        with scan_image(archive=archive) as (image, _):
            image = copy.deepcopy(image)
        for kind, raw in (("source", self.report), ("image", image)):
            with self.subTest(kind=kind):
                report = apply_review_config(raw, self.policy)
                original = copy.deepcopy(report)
                snapshots = []
                for attempt in range(2):
                    output = self.base / (kind + str(attempt))
                    exported = write_reports(report, output)
                    snapshots.append({p.name: p.read_bytes() for p in output.iterdir()})
                    self.assertEqual(set(snapshots[-1]), {"report.html", "report.json", "report.md", "report.sarif"})
                    self.assertEqual(exported["review_policy"], report["review_policy"])
                    self.assertEqual(exported["assessment"]["metrics"]["justified_findings"], sum(f["status"] == "justified" for f in report["findings"]))
                self.assertEqual(snapshots[0], snapshots[1])
                self.assertEqual(report, original)
                for finding in raw["findings"]:
                    preserved = next(f for f in report["findings"] if f["id"] == finding["id"])
                    self.assertEqual(preserved["evidence"], finding["evidence"])
                    if kind == "image":
                        self.assertEqual(preserved["image_provenance"], finding["image_provenance"])


if __name__ == "__main__":
    unittest.main()
