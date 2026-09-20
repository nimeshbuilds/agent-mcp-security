"""Comparative agreement is a location relation, never vulnerability ground truth."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("scanner_comparison", Path(__file__).resolve().parents[1] / "scripts/compare_scanner_findings.py")
COMPARE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMPARE)


def obs(ident, line=10, end=10, family="dynamic_code_execution", mapped=True, path="agent.py", project="project"):
    return {"id": ident, "project_id": project, "path": path, "line_start": line, "line_end": end,
            "family": family, "family_mapped": mapped}


class ScannerComparisonTests(unittest.TestCase):
    def test_new_experiment_identity_and_selection_seed_leave_legacy_defaults_intact(self):
        self.assertEqual(COMPARE.parser().parse_args([]).experiment, "comparison-v010")
        self.assertEqual(COMPARE.parser().parse_args(["--experiment", "comparison-v013"]).experiment, "comparison-v013")
        ledger = {"observations": [{**obs("s1"), "tool": "semgrep"}]}
        legacy = COMPARE.adjudication_selection(ledger, {"pairs": []})
        new = COMPARE.adjudication_selection(ledger, {"pairs": []}, seed="comparison-v013-adjudication-v1")
        self.assertEqual(legacy["selection_id"], "comparison-v010-adjudication-2026-09-19-v1")
        self.assertEqual(new["selection_id"], "comparison-v013-adjudication-v1")
        self.assertEqual(new["selected_observation_ids"], legacy["selected_observation_ids"])

    def test_invalid_experiment_identity_is_rejected_before_reading_inputs(self):
        with mock.patch.object(COMPARE, "build", side_effect=AssertionError("Inputs must not be read")):
            for identifier in ("../old", "", "comparison v013", "comparison_V013"):
                with self.subTest(identifier=identifier), self.assertRaisesRegex(ValueError, "Experiment identity"):
                    COMPARE.main(["--experiment", identifier])

    def test_report_bytes_must_match_every_recorded_execution(self):
        report = {"scan_id": "same", "tool": {"version": "0.14.0"}, "findings": []}
        raw = json.dumps(report).encode()
        receipt = {"scan_id": "same", "tool": report["tool"], "repeated_runs": [
            {"report_sha256": {"report.json": COMPARE.sha(raw)}},
            {"report_sha256": {"report.json": COMPARE.sha(raw)}}]}
        self.assertEqual(COMPARE.verified_invarune_report(raw, receipt), report)
        altered = json.dumps({**report, "findings": [{"rule_id": "AI001"}]}).encode()
        with self.assertRaisesRegex(ValueError, "recorded execution hashes"):
            COMPARE.verified_invarune_report(altered, receipt)
        for runs in ([], None, [{}], [{"report_sha256": []}], receipt["repeated_runs"] + [{}]):
            with self.subTest(runs=runs), self.assertRaisesRegex(ValueError, "recorded execution hashes"):
                COMPARE.verified_invarune_report(raw, {**receipt, "repeated_runs": runs})

    def test_exact_family_and_inclusive_overlap_matches(self):
        result = COMPARE.pairwise([obs("a", 10, 12)], [obs("b", 12, 14)], "a", "b")
        self.assertEqual(result["counts"]["one_to_one_pairs"], 1)
        self.assertFalse(result["left_without_family_match"])
        self.assertFalse(result["right_without_family_match"])
        self.assertNotIn("true_positive", str(result))

    def test_no_nearby_line_matching_or_cross_file_project_matching(self):
        variants = [obs("b", 11, 11), obs("b", path="other.py"), obs("b", project="other")]
        for item in variants:
            with self.subTest(item=item):
                result = COMPARE.pairwise([obs("a")], [item], "a", "b")
                self.assertEqual(result["counts"]["one_to_one_pairs"], 0)
                self.assertEqual(result["left_without_family_match"], ["a"])
                self.assertEqual(result["right_without_family_match"], ["b"])

    def test_different_or_unmapped_families_remain_location_only(self):
        for other in (obs("b", family="subprocess_import"), obs("b", mapped=False)):
            with self.subTest(other=other):
                result = COMPARE.pairwise([obs("a")], [other], "a", "b")
                self.assertEqual(len(result["location_only_edges"]), 1)
                self.assertEqual(result["left_without_family_match"], ["a"])
                self.assertEqual(result["counts"]["one_to_one_pairs"], 0)

    def test_many_to_one_is_ambiguous_instead_of_greedily_matching(self):
        result = COMPARE.pairwise([obs("a1", 10, 10), obs("a2", 12, 12)], [obs("b", 10, 12)], "a", "b")
        self.assertEqual(result["counts"]["one_to_one_pairs"], 0)
        self.assertEqual(result["counts"]["ambiguous_edges"], 2)
        self.assertEqual(result["counts"]["left_in_ambiguous_edges"], 2)
        self.assertEqual(result["counts"]["right_in_ambiguous_edges"], 1)
        self.assertFalse(result["left_without_family_match"])
        self.assertFalse(result["right_without_family_match"])

    def test_every_observation_is_accounted_for_without_deduplication(self):
        left = [obs("a1"), obs("a2"), obs("a3", 25, 25), obs("a4", 40, 40)]
        right = [obs("b1"), obs("b2", 25, 25), obs("b3", 50, 50)]
        result = COMPARE.pairwise(left, right, "a", "b")
        for side, rows in (("left", left), ("right", right)):
            seen = set(result[side + "_without_family_match"])
            seen.update(x[side + "_id"] for x in result["one_to_one_matches"])
            seen.update(x[side + "_id"] for x in result["ambiguous_family_location_edges"])
            self.assertEqual(seen, {x["id"] for x in rows})

    def test_empty_tool_is_unmatched_without_awarding_true_negatives(self):
        result = COMPARE.pairwise([obs("a")], [], "a", "b")
        self.assertEqual(result["left_without_family_match"], ["a"])
        self.assertNotIn("true_negative", str(result))

    def test_mapping_keeps_imports_and_calls_and_shell_modes_separate(self):
        mapping = COMPARE.rule_map()
        self.assertNotEqual(mapping["bandit:B403"]["family"], mapping["bandit:B301"]["family"])
        self.assertNotEqual(mapping["bandit:B404"]["family"], mapping["bandit:B602"]["family"])
        self.assertNotEqual(mapping["bandit:B603"]["family"], mapping["invarune:AI002"]["family"])
        self.assertEqual(mapping["bandit:B301"]["family"], mapping["invarune:AI005"]["family"])

    def test_instruction_metadata_families_do_not_imply_runtime_exploitation(self):
        mapping = COMPARE.rule_map()
        families = {mapping["invarune:" + rule]["family"] for rule in ("AI043", "AI044", "AI045", "AI046")}
        self.assertEqual(len(families), 4)
        external = {item["family"] for key, item in mapping.items() if not key.startswith("invarune:")}
        self.assertFalse(families & external)
        self.assertIn("author intent", mapping["invarune:AI043"]["rationale"])
        self.assertIn("not established", mapping["invarune:AI044"]["rationale"])
        self.assertIn("no execution", mapping["invarune:AI045"]["rationale"])
        self.assertIn("untrusted annotation", mapping["invarune:AI046"]["review_predicate"])

    def test_identity_stable_across_version_with_provenance_retained(self):
        project = {"id": "p", "repository": "https://github.com/example/repo", "revision": "a" * 40}
        finding = {"rule_id": "AI001", "line": 1, "path": "agent.py", "severity": "high", "finding_id": "native"}
        run = {"source_manifest_sha256": "s" * 64, "status": "completed"}
        a = COMPARE.observation(project, "invarune", "0.9.0", finding, run, "x" * 64, COMPARE.rule_map())
        b = COMPARE.observation(project, "invarune", "0.10.0", finding, run, "y" * 64, COMPARE.rule_map())
        self.assertEqual(a["id"], b["id"])
        self.assertNotEqual(a["tool_version"], b["tool_version"])
        self.assertNotEqual(a["raw_report_sha256"], b["raw_report_sha256"])
        self.assertEqual(a["adjudication"], "unreviewed")
        self.assertEqual(a["native_finding_id"], "native")
        duplicate = COMPARE.observation(project, "invarune", "0.9.0", finding, run, "x" * 64, COMPARE.rule_map(), 1)
        self.assertNotEqual(a["id"], duplicate["id"])

    def test_outside_source_and_invalid_spans_rejected(self):
        project = {"id": "p", "repository": "https://github.com/example/repo", "revision": "a" * 40}
        run = {"source_manifest_sha256": "s" * 64, "status": "completed"}
        for fields in ({"path": "../outside.py"}, {"path": "/outside.py"}, {"path": "[outside selected source]/a.py"}, {"line": 0}):
            finding = {"rule_id": "AI001", "line": 1, "path": "agent.py", "severity": "high", **fields}
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                COMPARE.observation(project, "invarune", "1", finding, run, "x" * 64, COMPARE.rule_map())

    def test_selection_keeps_all_mandatory_tools_and_strata_without_labels(self):
        rows = [
            {**obs("s1", 1, 1), "tool": "semgrep"},
            {**obs("s2", 2, 2), "tool": "semgrep"},
            {**obs("s3", 3, 3), "tool": "semgrep"},
            {**obs("g1", 4, 4, family="credential_literal"), "tool": "gitleaks"},
            {**obs("i1", 5, 5, family="sql_construction"), "tool": "invarune"},
            {**obs("b1", 6, 6, family="assert_statement"), "tool": "bandit"},
            {**obs("b2", 7, 7, family="assert_statement"), "tool": "bandit"},
        ]
        ledger = {"observations": rows}
        selected = COMPARE.adjudication_selection(ledger, {"pairs": []}, cap=6)
        self.assertEqual(selected["selected_locations"], 6)
        self.assertTrue({"s1", "s2", "s3", "g1", "i1"}.issubset(selected["selected_observation_ids"]))
        self.assertEqual(selected["covered_strata"], selected["total_observed_strata"])
        reversed_selection = COMPARE.adjudication_selection({"observations": rows[::-1]}, {"pairs": []}, cap=6)
        self.assertEqual(selected["selected_observation_ids"], reversed_selection["selected_observation_ids"])
        with self.assertRaisesRegex(ValueError, "cap"):
            COMPARE.adjudication_selection(ledger, {"pairs": []}, cap=3)


if __name__ == "__main__":
    unittest.main()
