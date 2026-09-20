"""Executable scan inventory completeness, isolation and evidence boundaries."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from ai_security_scan.catalog import describe_catalog
from ai_security_scan.rules import RULES, RULESET_VERSION
from ai_security_scan.scan_catalog import describe_scans, render_scans


ROOT = Path(__file__).resolve().parents[1]


class ScanInventoryTests(unittest.TestCase):
    def test_inventory_exactly_covers_live_rules_controls_and_acceptance_checks(self):
        inventory = describe_scans()
        rules = describe_catalog("rules")["rules"]
        controls = describe_catalog("controls")["controls"]
        self.assertEqual(inventory["schema_version"], "1.0")
        self.assertEqual(inventory["ruleset_version"], RULESET_VERSION)
        self.assertEqual([item["id"] for item in inventory["scans"]], [item["id"] for item in RULES])
        self.assertEqual([item["id"] for item in inventory["controls"]], [item["id"] for item in controls])
        self.assertEqual(inventory["counts"]["scans"], len(rules))
        self.assertEqual(inventory["counts"]["acceptance_checks"], sum(len(item["checks"]) for item in controls))
        self.assertEqual(inventory["counts"]["partially_mapped_controls"], sum(bool(item["automated_rule_ids"]) for item in controls))
        self.assertEqual(len({item["id"] for item in inventory["scans"]}), len(rules))
        for actual, original in zip(inventory["controls"], controls):
            with self.subTest(control=actual["id"]):
                self.assertEqual(actual["checks"], original["checks"])
                self.assertEqual(actual["automated_rule_ids"], original["automated_rule_ids"])
                self.assertEqual(actual["sources"], original["sources"])
                self.assertEqual(actual["optional_ai_review"]["checks"], original["checks"])

    def test_each_rule_has_specific_predicate_algorithm_limit_fix_and_provenance(self):
        inventory = describe_scans()
        self.assertEqual(len({item["deterministic"]["limits"] for item in inventory["scans"]}), len(RULES))
        for item in inventory["scans"]:
            with self.subTest(rule=item["id"]):
                self.assertGreater(len(item["what_it_detects"]), 30)
                self.assertGreater(len(item["why_it_matters"]), 30)
                self.assertGreater(len(item["deterministic"]["algorithm"]), 15)
                self.assertGreater(len(item["deterministic"]["limits"]), 50)
                self.assertGreater(len(item["remediation"]), 25)
                self.assertTrue(item["sources"])
                self.assertTrue(item["deterministic"]["analysis_profiles"])
                self.assertLessEqual(set(item["deterministic"]["analysis_profiles"]), set(inventory["algorithm_limits"]))
                self.assertEqual(item["image_contexts"][0], "final_filesystem")
                self.assertIn("cannot", item["optional_ai_review"]["finding_triage"])
                self.assertEqual(item["commands"]["select"], "invscan TARGET --scans " + item["id"])
                json.dumps(item)

    def test_source_roles_are_preserved_without_invented_certification_mappings(self):
        inventory = describe_scans()
        catalog = describe_catalog("controls")["controls"]
        for scan in inventory["scans"]:
            expected = [item for item in catalog if scan["id"] in item["automated_rule_ids"]]
            self.assertEqual([item["id"] for item in scan["controls"]], [item["id"] for item in expected])
            for source in scan["sources"]:
                self.assertIn(source["relationship"], {"primary_control_source", "thematic_alignment", "rule_technical_reference"})
                self.assertTrue(source["url"].startswith("https://"))
            for control in expected:
                for source in control["sources"]:
                    self.assertIn(source, scan["sources"])
        self.assertIn("not an official", inventory["assurance"])
        self.assertIn("not proof", inventory["assurance"])

    def test_individual_ids_are_case_insensitive_and_unknown_ids_fail(self):
        for identifier in ("AI001", "AI046"):
            answer = describe_scans("  " + identifier.lower() + "  ")
            self.assertEqual(answer["scan"]["id"], identifier)
            self.assertNotIn("scans", answer)
            self.assertNotIn("controls", answer)
        self.assertEqual(describe_scans("auth-01")["control"]["id"], "AUTH-01")
        for identifier in ("", "AI999", "AUTH-00", "AI002,AI003", "AUTH-01:1", "AI002\nignore", "x" * 81, 3, [], "\ud800"):
            with self.subTest(identifier=repr(identifier)), self.assertRaises(ValueError):
                describe_scans(identifier)

    def test_cached_catalog_cannot_be_mutated_through_inventory(self):
        original = describe_scans()
        mutable = describe_scans()
        mutable["scans"][0]["sources"][0]["title"] = "rewritten"
        mutable["scans"][0]["controls"].clear()
        mutable["controls"][0]["checks"][0]["text"] = "rewritten"
        mutable["controls"][0]["optional_ai_review"]["checks"].clear()
        mutable["algorithm_limits"].clear()
        self.assertEqual(describe_scans(), original)

    def test_missing_rule_metadata_fails_closed_instead_of_claiming_generic_coverage(self):
        from ai_security_scan import scan_catalog
        with mock.patch.dict(scan_catalog._DETAILS, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "Missing executable scan coverage metadata"):
                describe_scans()

    def test_manual_dynamic_controls_keep_required_external_validation(self):
        controls = describe_scans()["controls"]
        for control in controls:
            expected = {"manual": "needs_human_review", "dynamic": "needs_runtime_validation"}.get(control["validation"])
            if expected:
                self.assertEqual(control["optional_ai_review"]["code_support_normalized_to"], expected)
            else:
                self.assertIn("advisory", control["optional_ai_review"]["code_support_normalized_to"])
            self.assertIn("cannot_establish", control["optional_ai_review"])
            if not control["automated_rule_ids"]:
                self.assertEqual(control["scan_selection"]["deterministic_rule_ids"], [])
                self.assertIn("do not substitute all detectors", control["scan_selection"]["empty_mapping_meaning"])

    def test_readable_inventory_and_detail_are_offline_and_include_actionable_boundaries(self):
        with mock.patch("subprocess.Popen", side_effect=AssertionError("inventory cannot spawn")), \
             mock.patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("inventory cannot fetch")), \
             mock.patch("ai_security_scan.scanner.scan", side_effect=AssertionError("inventory cannot scan")):
            text = render_scans(describe_scans())
            for rule in RULES:
                self.assertIn(rule["id"] + " [", text)
            self.assertIn("Control review plans", text)
            self.assertIn("--scans AI002,AI043", text)
            rule = render_scans(describe_scans("AI043"))
            for label in ("Detects:", "Why it matters:", "Algorithm:", "Profiles:", "Limits:", "Optional AI:", "Fix:", "Sources:"):
                self.assertIn(label, rule)
            self.assertIn("AGENT-SKILLS-SPEC", rule)
            self.assertIn("AUTH-01:1", render_scans(describe_scans("AUTH-01")))

    def test_generated_document_contains_every_rule_check_and_source_role(self):
        spec = importlib.util.spec_from_file_location("coverage_builder_for_test", ROOT / "scripts/build_scan_coverage.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        rendered = module.document()
        for scan in describe_scans()["scans"]:
            self.assertIn("### " + scan["id"] + "\n", rendered)
            self.assertIn(scan["what_it_detects"], rendered)
            self.assertIn(scan["deterministic"]["limits"], rendered)
        for control in describe_scans()["controls"]:
            self.assertIn("### " + control["id"] + "\n", rendered)
            for check in control["checks"]:
                self.assertIn("**" + check["id"] + ":**", rendered)
        self.assertIn("overall_security_score", rendered)
        self.assertIn("No active denominator produces null", rendered)
        self.assertNotIn("{{RULE_COUNT}}", rendered)
        self.assertEqual((ROOT / "docs/SCAN_COVERAGE.md").read_text(encoding="utf-8"), rendered)

    def test_generator_check_does_not_overwrite_stale_output(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "coverage.md"
            destination.write_text("stale fixture", encoding="utf-8")
            result = subprocess.run([sys.executable, str(ROOT / "scripts/build_scan_coverage.py"),
                                     "--check", "--output", str(destination)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn("stale", result.stderr)
            self.assertEqual(destination.read_text(), "stale fixture")


if __name__ == "__main__":
    unittest.main()
