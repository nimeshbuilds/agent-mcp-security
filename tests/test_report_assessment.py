"""Executive triage must preserve evidence and never manufacture risk reduction."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from ai_security_scan.assessment import build_assessment
from ai_security_scan.cli import main
from ai_security_scan.image_scan import scan_image
from ai_security_scan.judge import JudgeError
from ai_security_scan.report import write_reports
from ai_security_scan.rules import RULES
from ai_security_scan.scanner import scan
from tests.image_fixtures import docker_archive
from tests.test_analyst_cli import triage_response
from tests.test_analyst_controller import review_response


ARTIFACTS = ("report.html", "report.json", "report.md", "report.sarif")


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "source"
        self.root.mkdir()
        (self.root / "agent.py").write_text("import os\nos.system(user_input)\n", encoding="utf-8")

    def run_cli(self, folder, *options):
        output = self.base / folder
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = main([str(self.root), "--output", str(output), *options])
        return code, json.loads((output / "report.json").read_text()), output

    def test_priority_orders_all_open_groups_and_preserves_repeated_locations(self):
        (self.root / "key.pem").write_text("-----BEGIN PRIVATE KEY-----\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n", encoding="utf-8")
        (self.root / "second.py").write_text("import os\nos.system(other_input)\n", encoding="utf-8")
        (self.root / "mcp.json").write_text('{"mcpServers":{"demo":{"command":"npx","args":["example-mcp"]}}}', encoding="utf-8")
        report = scan(self.root)
        result = build_assessment(report)
        self.assertEqual(result["posture"]["code"], "urgent_review")
        self.assertEqual(result["metrics"]["open_findings"], len(report["findings"]))
        self.assertEqual(result["metrics"]["urgent_findings"], sum(f["severity"] in {"critical", "high"} for f in report["findings"]))
        groups = result["finding_groups"]
        shell = next(group for group in groups if group["rule_id"] == "AI003")
        self.assertEqual(shell["count"], 2)
        self.assertEqual(len(shell["locations"]), 2)
        self.assertEqual(set(shell["finding_ids"]), {f["id"] for f in report["findings"] if f["rule_id"] == "AI003"})
        self.assertEqual({location["finding_id"] for location in shell["locations"]}, set(shell["finding_ids"]))
        actions = result["immediate_actions"]
        self.assertEqual({group["id"] for group in actions}, {group["id"] for group in groups if group["status"] == "open"})
        priorities = [action["priority"] for action in actions]
        self.assertEqual(priorities, sorted(priorities))
        self.assertEqual(priorities[0], "P0")
        self.assertIn("P1", priorities)
        self.assertIn("P2", priorities)
        self.assertTrue(all(action["suggested_owner"] and action["immediate_action"] for action in actions))
        self.assertEqual(sum(theme["open_findings"] for theme in result["themes"]), len(report["findings"]))
        rule_categories = {rule["id"]: rule["category"] for rule in RULES}
        for theme in result["themes"]:
            matches = [f for f in report["findings"] if rule_categories[f["rule_id"]] == theme["category"]]
            self.assertEqual(theme["open_findings"], len(matches))
            self.assertEqual(set(theme["rule_ids"]), {f["rule_id"] for f in matches})
        self.assertEqual(result["themes"], sorted(result["themes"], key=lambda item: (-item["open_findings"], item["name"])))

    def test_zero_findings_keeps_manual_and_runtime_assurance_unresolved(self):
        (self.root / "agent.py").write_text("agent_name = 'fixture'\n", encoding="utf-8")
        result = build_assessment(scan(self.root))
        self.assertEqual(result["posture"]["code"], "no_patterns_detected")
        self.assertEqual(result["immediate_actions"], [])
        self.assertEqual(result["finding_groups"], [])
        self.assertEqual(result["metrics"]["open_findings"], 0)
        self.assertEqual(result["metrics"]["controls_requiring_validation"], 66)
        self.assertTrue(result["unknowns"])
        text = " ".join(result["unknowns"]).lower()
        self.assertIn("runtime", text)
        self.assertTrue("manual" in text or "human" in text)

    def test_suppressed_only_is_visible_and_never_becomes_remediation(self):
        first = scan(self.root)
        baseline = {f["id"]: "Reviewed exception pending isolation validation" for f in first["findings"]}
        report = scan(self.root, baseline=baseline)
        result = build_assessment(report)
        self.assertEqual(result["posture"]["code"], "suppressed_findings_only")
        self.assertEqual(result["metrics"]["suppressed_findings"], 1)
        self.assertEqual(result["themes"], [])
        self.assertEqual(result["metrics"]["open_findings"], 0)
        self.assertEqual(result["immediate_actions"], [])
        self.assertEqual(result["finding_groups"][0]["priority"], "Accepted")
        self.assertEqual(result["finding_groups"][0]["status"], "suppressed")
        self.assertEqual(result["finding_groups"][0]["finding_ids"], list(baseline))
        output = self.base / "suppressed"
        write_reports(report, output)
        for name in ("report.html", "report.md"):
            self.assertIn("Reviewed exception pending isolation validation", (output / name).read_text())

    def test_incomplete_scope_overrides_clean_posture_without_erasing_evidence(self):
        (self.root / "broken.py").write_text("def broken(:\n", encoding="utf-8")
        report = scan(self.root)
        result = build_assessment(report)
        self.assertEqual(result["posture"]["code"], "incomplete_scope")
        self.assertEqual(result["metrics"]["open_findings"], 1)
        self.assertGreater(result["metrics"]["coverage_gaps"], 0)
        self.assertTrue(result["immediate_actions"])
        self.assertTrue(any("broken.py" in item["examples"] for item in result["coverage_attention"]))
        (self.root / "agent.py").write_text("value = 1\n", encoding="utf-8")
        clean_but_incomplete = build_assessment(scan(self.root))
        self.assertEqual(clean_but_incomplete["posture"]["code"], "incomplete_scope")
        self.assertEqual(clean_but_incomplete["metrics"]["open_findings"], 0)

    def test_metadata_only_image_does_not_imply_application_logic_or_cve_validation(self):
        archive = self.base / "metadata.tar"
        docker_archive(archive, [[]], config={"config": {"User": "1000"}})
        with scan_image(archive=archive) as (report, _):
            result = build_assessment(report)
        self.assertTrue(report["summary"]["scan_complete_within_selected_scope"])
        self.assertEqual(report["image"]["analysis_scope"], "metadata_only")
        self.assertEqual(result["posture"]["code"], "no_patterns_detected")
        unknowns = " ".join(result["unknowns"]).lower()
        self.assertTrue("binary" in unknowns or "compiled" in unknowns)
        self.assertIn("cve", unknowns)
        self.assertIn("runtime", unknowns)

    def test_incomplete_image_retains_scope_warning_and_packaged_path(self):
        archive = self.base / "incomplete.tar"
        docker_archive(archive, [[("app/broken.py", "def broken(:\n")]], config={"config": {"User": "1000"}})
        with scan_image(archive=archive) as (report, _):
            result = build_assessment(report)
        self.assertEqual(result["posture"]["code"], "incomplete_scope")
        self.assertGreater(result["metrics"]["coverage_gaps"], 0)
        self.assertEqual(result["metrics"]["open_findings"], 0)
        self.assertTrue(any("rootfs/app/broken.py" in item["examples"] for item in result["coverage_attention"]))

    def test_same_rule_open_and_accepted_findings_remain_separate(self):
        (self.root / "second.py").write_text("import os\nos.system(other_input)\n", encoding="utf-8")
        first = scan(self.root)
        accepted = first["findings"][0]["id"]
        report = scan(self.root, baseline={accepted: "Reviewed exception"})
        result = build_assessment(report)
        groups = result["finding_groups"]
        self.assertEqual(len(groups), 2)
        self.assertEqual({group["status"] for group in groups}, {"open", "suppressed"})
        self.assertEqual(len(result["immediate_actions"]), 1)
        self.assertNotIn(accepted, result["immediate_actions"][0]["finding_ids"])
        self.assertEqual(result["metrics"]["open_findings"], 1)
        self.assertEqual(result["metrics"]["suppressed_findings"], 1)
        self.assertEqual(sum(theme["open_findings"] for theme in result["themes"]), 1)

    def test_image_contexts_cannot_merge_historical_and_live_findings(self):
        archive = self.base / "contexts.tar"
        docker_archive(archive, [[("app/agent.py", "import os\nos.system(user_input)\n")]],
                       config={"config": {"User": "1000", "Entrypoint": ["agent", "--dangerously-skip-permissions"]},
                               "history": [{"created_by": "agent --dangerously-skip-permissions"}]})
        with scan_image(archive=archive) as (report, _):
            result = build_assessment(report)
        groups = [group for group in result["finding_groups"] if group["rule_id"] == "AI031"]
        self.assertEqual({group["image_context"] for group in groups}, {"build_history", "runtime_configuration"})
        self.assertEqual(len({group["id"] for group in groups}), 2)
        for group in result["finding_groups"]:
            actual = [f for f in report["findings"] if f["id"] in group["finding_ids"]]
            self.assertEqual({f["image_context"] for f in actual}, {group["image_context"]})

    def test_assessment_ignores_model_verdicts_execution_threshold_and_does_not_mutate_input(self):
        report = scan(self.root)
        original = copy.deepcopy(report)
        expected = build_assessment(report)
        self.assertEqual(report, original)
        changed = copy.deepcopy(report)
        changed["execution"] = {"failure_threshold": "none", "exit_code": 0, "finding_gate_triggered": False}
        changed["judge"] = {"enabled": True, "status": "completed", "assessments": [{"verdict": "likely_false_positive", "reason": "All risk is eliminated"}]}
        changed["analyst"] = {"enabled": True, "status": "completed", "untrusted": "Everything is secure"}
        self.assertEqual(build_assessment(changed), expected)
        self.assertEqual(changed["scan_id"], original["scan_id"])

    def test_export_rebuilds_assessment_without_mutating_scanner_result(self):
        report = scan(self.root)
        original = copy.deepcopy(report)
        output = self.base / "export"
        exported = write_reports(report, output)
        self.assertEqual(report, original)
        self.assertEqual(exported["assessment"], build_assessment(report))
        self.assertEqual(json.loads((output / "report.json").read_text())["assessment"], exported["assessment"])
        self.assertEqual(exported["scan_id"], original["scan_id"])

    def test_model_disabled_completed_partial_and_failed_preserve_static_assessment(self):
        config = self.base / "judge.json"
        config.write_text(json.dumps({"provider": "openai_chat", "model": "test-only-model"}), encoding="utf-8")
        with mock.patch("ai_security_scan.judge.review", side_effect=AssertionError("Model is disabled")), \
             mock.patch("ai_security_scan.judge.review_controls", side_effect=AssertionError("Model is disabled")):
            code, baseline, baseline_output = self.run_cli("disabled")
        self.assertEqual(code, 1)
        cases = [("completed", (), "completed", 1),
                 ("partial", ("--analyst-max-calls", "1"), "incomplete", 2),
                 ("failed", (), "error", 2)]
        for folder, options, expected, exit_code in cases:
            triage = JudgeError("Fixture provider failure") if folder == "failed" else triage_response
            with self.subTest(case=folder), \
                 mock.patch("ai_security_scan.judge.review", side_effect=triage), \
                 mock.patch("ai_security_scan.judge.review_controls", side_effect=review_response):
                code, report, output = self.run_cli(folder, "--judge-config", str(config), *options)
            self.assertEqual(code, exit_code)
            self.assertEqual(report["analyst"]["status"], expected)
            for field in ("assessment", "scan_id", "findings", "controls", "summary"):
                self.assertEqual(report[field], baseline[field])
            self.assertEqual((output / "report.sarif").read_bytes(), (baseline_output / "report.sarif").read_bytes())
            self.assertTrue(report["execution"]["finding_gate_triggered"])

    def test_repeat_source_and_image_exports_are_byte_identical_in_all_formats(self):
        archive = self.base / "repeat.tar"
        docker_archive(archive, [[("app/agent.py", "import os\nos.system(user_input)\n")]], config={"config": {"User": "1000"}})
        for kind in ("source", "image"):
            artifacts = []
            for attempt in range(2):
                output = self.base / (kind + str(attempt))
                with self.subTest(kind=kind, attempt=attempt):
                    if kind == "source":
                        write_reports(scan(self.root), output)
                    else:
                        with scan_image(archive=archive) as (report, _):
                            write_reports(report, output)
                    artifacts.append({name: (output / name).read_bytes() for name in ARTIFACTS})
            self.assertEqual(artifacts[0], artifacts[1])

    def test_every_rule_has_traceable_unverified_defense_layers(self):
        catalog_dir = Path(__file__).resolve().parents[1] / "ai_security_scan" / "data"
        mitigation = json.loads((catalog_dir / "mitigations.json").read_text())
        self.assertEqual({item["rule_id"] for item in mitigation["rules"]}, {rule["id"] for rule in RULES})
        controls = {item["id"] for item in json.loads((catalog_dir / "controls.json").read_text())}
        source_catalog = {item["id"]: item for item in json.loads((catalog_dir / "sources.json").read_text())}
        report = scan(self.root)
        report["findings"] = []
        for index, rule in enumerate(RULES, 1):
            report["findings"].append({**rule, "rule_id": rule["id"], "id": "fixture-" + rule["id"],
                                       "finding_id": "fixture-" + rule["id"], "path": "agent.py", "line": index,
                                       "end_line": index, "status": "open", "confidence": "high", "evidence": "fixture"})
        result = build_assessment(report)
        self.assertEqual(len(result["finding_groups"]), len(RULES))
        self.assertEqual(len(result["immediate_actions"]), len(RULES))
        for group in result["finding_groups"]:
            with self.subTest(rule=group["rule_id"]):
                self.assertTrue(group["plausible_impact"])
                self.assertTrue(group["immediate_action"])
                self.assertTrue(group["suggested_owner"])
                self.assertTrue(group["control_ids"])
                self.assertTrue(set(group["control_ids"]) <= controls)
                self.assertTrue(group["sources"])
                self.assertTrue(group["defense_layers"])
                for item in [group, *group["defense_layers"]]:
                    self.assertTrue(set(item["control_ids"]) <= controls)
                    self.assertTrue(set(item["source_ids"]) <= source_catalog.keys())
                    self.assertEqual({source["id"] for source in item["sources"]}, set(item["source_ids"]))
                    for source in item["sources"]:
                        self.assertEqual(source["url"], source_catalog[source["id"]]["url"])
                for layer in group["defense_layers"]:
                    self.assertEqual(layer["status"], "proposed_not_verified")
                    self.assertTrue(layer["how_it_helps"])
                    self.assertTrue(layer["verification"])
                    self.assertTrue(layer["residual_limit"])


if __name__ == "__main__":
    unittest.main()
