"""Charts must retain fixture denominators and bind source observations to receipts."""
from argparse import Namespace
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from scripts import build_benchmark_dashboard as B


class BenchmarkDashboardTests(unittest.TestCase):
    def current_args(self):
        root = B.ROOT / 'benchmarks/comparison-v014'
        return Namespace(comparison=root, before=root / 'accuracy-before.json',
                         after=root / 'accuracy-after.json', corpus=B.ROOT / 'benchmarks/static_accuracy.json', preview=False)

    def test_current_skill_chart_preserves_separate_denominators(self):
        data = B.inputs_for(self.current_args())
        self.assertEqual(data['current']['overall']['assertions'], 113)
        self.assertEqual(data['skills']['overall']['assertions'], 331)
        self.assertEqual(data['skills']['overall']['false_negative'], 3)
        chart = B.skills_svg(data['skills'])
        ET.fromstring(chart)
        self.assertIn('81 cases / 331', chart)
        self.assertIn('not added to the 113', chart)
        self.assertEqual(data['catalog_counts'], {'rules': 46, 'controls': 66, 'checks': 132, 'mapped_controls': 30})
        self.assertIn('46 deterministic rules map partially to 30 of 66 controls', B.page_text(data))
        historical = B.ROOT / 'benchmarks/comparison-v013'
        old = B.inputs_for(Namespace(comparison=historical, before=historical / 'accuracy-before.json',
                                    after=historical / 'accuracy-after.json', corpus=self.corpus_path, preview=False))
        self.assertEqual(old['catalog_counts'], {'rules': 42, 'controls': 66, 'checks': 132, 'mapped_controls': 26})
        self.assertIn('42 deterministic rules map partially to 26 of 66 controls', B.page_text(old))

    def test_skill_receipt_cannot_switch_hash_or_hide_misses(self):
        original = B.load
        for changed in ['implementation', 'report_hash', 'false_negative', 'source_report_hash', 'catalog_scope']:
            def corrupt(path, inputs):
                value = original(path, inputs)
                if path.name == 'skills-tools-evaluation-receipt.json' and changed in {'implementation', 'report_hash', 'false_negative'}:
                    value = copy.deepcopy(value)
                    if changed == 'implementation':
                        value['implementation_sha256'] = '0' * 64
                    elif changed == 'report_hash':
                        value['report']['sha256'] = '0' * 64
                    else:
                        value['overall']['false_negative'] = 0
                elif changed == 'source_report_hash' and path.parent.name == 'invarune-receipts-after':
                    value = copy.deepcopy(value)
                    value['repeated_runs'][0]['report_sha256']['report.json'] = '0' * 64
                elif changed == 'catalog_scope' and path.name == 'report.json' and path.parent.name == 'mcp-reference':
                    value = copy.deepcopy(value)
                    value['coverage']['rules_enabled'].pop()
                return value
            with self.subTest(changed=changed), patch.object(B, 'load', side_effect=corrupt), self.assertRaises(ValueError):
                B.inputs_for(self.current_args())

    @classmethod
    def setUpClass(cls):
        cls.comparison = B.ROOT / "benchmarks/comparison-v010"
        cls.corpus_path = B.ROOT / "benchmarks/static_accuracy.json"
        cls.accuracy_path = B.ROOT / "benchmarks/accuracy-current.json"
        cls.corpus = json.loads(cls.corpus_path.read_text(encoding="utf-8"))
        cls.corpus_hash = B.sha(cls.corpus_path.read_bytes())
        cls.accuracy = json.loads(cls.accuracy_path.read_text(encoding="utf-8"))
        cls.ledger = json.loads((cls.comparison / "observations.json").read_text(encoding="utf-8"))
        cls.overlaps = json.loads((cls.comparison / "overlaps.json").read_text(encoding="utf-8"))
        cls.runs = json.loads((cls.comparison / "run-status.json").read_text(encoding="utf-8"))["runs"]

    def test_actual_fixture_counts_include_every_challenge_label(self):
        counts = B.check_accuracy(self.accuracy, self.corpus, self.corpus_hash)
        self.assertEqual(counts, {"true_positive": 55, "true_negative": 51, "false_positive": 2, "false_negative": 5})
        self.assertEqual(sum(counts.values()), 113)

    def test_corpus_digest_change_rejected(self):
        with self.assertRaisesRegex(ValueError, "corpus bytes"):
            B.check_accuracy(self.accuracy, self.corpus, "0" * 64)

    def test_omitted_case_rejected_even_if_case_count_is_reduced(self):
        report = copy.deepcopy(self.accuracy)
        report["cases"].pop()
        report["case_count"] -= 1
        with self.assertRaisesRegex(ValueError, "case identities"):
            B.check_accuracy(report, self.corpus, self.corpus_hash)

    def test_changed_label_and_hidden_analysis_error_rejected(self):
        for change in ("label", "error"):
            with self.subTest(change=change):
                report = copy.deepcopy(self.accuracy)
                if change == "label":
                    report["cases"][0]["assertions"][0]["expected"] = False
                else:
                    report["cases"][0]["analysis_errors"] = ["unparsed input"]
                with self.assertRaises(ValueError):
                    B.check_accuracy(report, self.corpus, self.corpus_hash)

    def test_summary_count_and_rate_tampering_rejected(self):
        for field, value in (("false_negative", 0), ("assertions", 108), ("precision", 1.0)):
            with self.subTest(field=field):
                report = copy.deepcopy(self.accuracy)
                report["overall"][field] = value
                with self.assertRaisesRegex(ValueError, "summary"):
                    B.check_accuracy(report, self.corpus, self.corpus_hash)

    def test_actual_source_overlap_and_run_receipts_are_accepted(self):
        B.check_comparison(self.ledger, self.overlaps, self.runs)

    def test_unsupported_and_null_results_are_not_completed_zero_findings(self):
        counts = B.run_categories(self.runs, "bandit")
        self.assertEqual(counts, {"completed": 5, "partial": 1, "unsupported": 2, "other": 0})
        self.assertEqual(sum(counts.values()), 8)
        null_run = {"tool": "bandit", "status": "completed", "finding_count": None, "errors": []}
        self.assertEqual(B.run_categories([null_run], "bandit")["other"], 1)

    def test_stale_overlap_ledger_binding_rejected(self):
        ledger = copy.deepcopy(self.ledger)
        ledger["observations"][0]["path"] = "changed.py"
        with self.assertRaisesRegex(ValueError, "bind the current observation ledger"):
            B.check_comparison(ledger, self.overlaps, self.runs)

    def test_rehashed_ledger_cannot_change_source_or_run_identity(self):
        for field, value in (("revision", "0" * 40), ("source_manifest_sha256", "0" * 64),
                             ("raw_report_sha256", "0" * 64), ("tool_version", "99.0.0")):
            with self.subTest(field=field):
                ledger, overlaps = copy.deepcopy(self.ledger), copy.deepcopy(self.overlaps)
                ledger["observations"][0][field] = value
                overlaps["observation_ledger_sha256"] = B.sha(B.canonical(ledger))
                with self.assertRaisesRegex(ValueError, "pinned source and tool run"):
                    B.check_comparison(ledger, overlaps, self.runs)

    def test_missing_unmatched_observation_or_tool_pair_rejected(self):
        for kind in ("observation", "pair"):
            with self.subTest(kind=kind):
                overlaps = copy.deepcopy(self.overlaps)
                if kind == "observation":
                    pair = overlaps["pairs"][0]
                    pair["left_without_family_match"].pop()
                    pair["counts"]["left_without_family_match"] -= 1
                else:
                    overlaps["pairs"].pop()
                with self.assertRaises(ValueError):
                    B.check_comparison(self.ledger, overlaps, self.runs)

    def test_after_version_cannot_label_a_different_source_run(self):
        args = Namespace(comparison=self.comparison, before=self.accuracy_path,
                         after=B.ROOT / "benchmarks/comparison-v013/accuracy-before.json",
                         corpus=self.corpus_path, preview=False)
        with self.assertRaisesRegex(ValueError, "different Invarune versions"):
            B.inputs_for(args)

    def paired_input(self):
        # Repeated identical historical evidence is a valid zero-change pair.
        # This tests receipt binding without fabricating a published after result.
        implementation = next(row["implementation_sha256"] for row in self.runs if row["tool"] == "invarune")
        report_hash = B.sha(self.accuracy_path.read_bytes())
        pair = {
            "corpus": {"path": "benchmarks/static_accuracy.json", "version": self.corpus["version"],
                       "sha256": self.corpus_hash, "case_count": 113},
            "input_invariants": {"identical_corpus_sha256": True, "identical_case_ids_and_labels": True},
            "changes": [],
            "remaining_mismatches": [{"case_id": case["id"], **{key: assertion[key] for key in ("rule_id", "expected", "detected", "outcome")}}
                                     for case in self.accuracy["cases"] for assertion in case["assertions"]
                                     if assertion["outcome"] in ("false_positive", "false_negative")],
        }
        for side in ("before", "after"):
            pair[side] = {key: copy.deepcopy(self.accuracy[key]) for key in ("tool_version", "overall", "by_suite", "failed_case_ids", "analysis_error_cases")}
            pair[side].update(implementation_sha256=implementation, accuracy_report="accuracy-" + side + ".json", accuracy_report_sha256=report_hash)
        baseline = {"scanner_version": self.accuracy["tool_version"], "corpus_sha256": self.corpus_hash,
                    "corpus_version": self.corpus["version"], "cases": 113, "implementation_sha256": implementation}
        return pair, baseline, report_hash

    def test_complete_pair_binds_both_report_bytes_and_remaining_mismatches(self):
        pair, baseline, report_hash = self.paired_input()
        B.check_pair(pair, self.accuracy, self.accuracy, report_hash, report_hash,
                     "benchmarks/static_accuracy.json", baseline, self.runs)
        self.assertEqual(len(pair["remaining_mismatches"]), 7)

    def test_paired_hash_summary_implementation_or_mismatch_tampering_rejected(self):
        for change in ("before_hash", "after_hash", "summary", "implementation", "remaining", "changes"):
            with self.subTest(change=change):
                pair, baseline, report_hash = self.paired_input()
                if change.endswith("_hash"):
                    pair[change.split("_")[0]]["accuracy_report_sha256"] = "0" * 64
                elif change == "summary":
                    pair["after"]["overall"]["false_negative"] = 0
                elif change == "implementation":
                    pair["after"]["implementation_sha256"] = "0" * 64
                elif change == "remaining":
                    pair["remaining_mismatches"].clear()
                else:
                    pair["changes"] = [{"case_id": "fabricated", "rule_id": "AI001"}]
                with self.assertRaises(ValueError):
                    B.check_pair(pair, self.accuracy, self.accuracy, report_hash, report_hash,
                                 "benchmarks/static_accuracy.json", baseline, self.runs)

    def test_preview_is_explicit_and_charts_are_deterministic_passive_svg(self):
        args = Namespace(comparison=self.comparison, before=self.accuracy_path,
                         after=None, corpus=self.corpus_path, preview=True)
        data = B.inputs_for(args)
        rendered = B.outputs(data)
        self.assertEqual(rendered, B.outputs(data))
        page = rendered[B.PAGE]
        self.assertIn("Design preview", page)
        self.assertIn("after run is pending", page)
        self.assertIn("5 false-negative labels", page)
        provenance = json.loads(rendered[B.ASSETS / "dashboard-data.json"])
        self.assertIsNone(provenance["after"])
        self.assertIsNone(provenance["catalog_counts"])
        self.assertIn('Exact catalog totals are omitted', page)
        self.assertNotIn('__RECORDED_CATALOG_CONTEXT__', page)
        self.assertEqual(provenance["observations_by_tool"], self.ledger["counts_by_tool"])
        for path, content in rendered.items():
            if path.suffix == ".svg":
                svg = ET.fromstring(content)
                self.assertEqual(svg.attrib["role"], "img")
                self.assertTrue(svg.find("{http://www.w3.org/2000/svg}title").text)
                self.assertFalse(any(element.tag.endswith(("script", "image", "foreignObject")) for element in svg.iter()))
                self.assertEqual(provenance["charts"][path.name]["sha256"], B.sha(content.encode("utf-8")))

    def test_duplicate_json_keys_and_outside_repository_inputs_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "ambiguous.json"
            path.write_text('{"count":0,"count":1}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "inside the repository"):
                B.load(path, {})
            with patch.object(B, "ROOT", root):
                with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
                    B.load(path, {})


if __name__ == "__main__":
    unittest.main()
